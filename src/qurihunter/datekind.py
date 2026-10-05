"""What does a date on a page *mean*? published | launched | last_updated | effective | unknown.
Rules first; the local LLM only when a date is present but its role is ambiguous.
'Last update', 'effective date' and 'renewal' are never launch dates."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from . import dates
from .logs import log

MONTHS = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
_MON = r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
DATE_RX = re.compile(
    rf"(?P<iso>\d{{4}}-\d{{2}}-\d{{2}})"
    rf"|(?P<dmy>\b\d{{1,2}}[/.]\d{{1,2}}[/.]\d{{4}}\b)"
    rf"|(?P<mdy>\b(?P<mon1>{_MON[1:-1]})\.?\s+(?P<d1>\d{{1,2}})(?:st|nd|rd|th)?(?:,?\s+(?P<y1>\d{{4}}))?\b)"
    rf"|(?P<dmony>\b(?P<d2>\d{{1,2}})(?:st|nd|rd|th)?\s+(?P<mon2>{_MON[1:-1]})\.?(?:,?\s+(?P<y2>\d{{4}}))?\b)", re.I)

UPDATED = re.compile(r"(last[\s-]*(updated?|modified|revised|reviewed|changed)|updated?|revised|modified|amended|renewal|"
                     r"renew(ed|ing)?|extended)", re.I)
EFFECTIVE = re.compile(r"(effective(\s+date)?|valid\s+from|comes?\s+into\s+(force|effect)|in\s+effect)", re.I)
LAUNCHED = re.compile(r"(launch(ed|ing)?|goes\s+live|went\s+live|now\s+live|kick(s|ed)?\s*off|opened|starts?|started)", re.I)
PUBLISHED = re.compile(r"(published|posted|announc(ed|ing)|released|introduc(ed|ing)|created|added)", re.I)

KINDS = ("published", "launched", "last_updated", "effective", "unknown")


@dataclass
class Evidence:
    kind: str
    date: str | None  # UTC ISO
    snippet: str = ""
    by: str = "rules"  # rules | llm | provider


def _to_dt(m: re.Match, today: datetime) -> datetime | None:
    try:
        if m.group("iso"):
            y, mo, d = map(int, m.group("iso").split("-"))
        elif m.group("dmy"):
            d, mo, y = map(int, re.split(r"[/.]", m.group("dmy")))
        else:
            g = m.groupdict()
            if g.get("d1"):
                mon, d, y = g["mon1"], int(g["d1"]), g.get("y1")
            else:
                mon, d, y = g["mon2"], int(g["d2"]), g.get("y2")
            mo = MONTHS[mon[:3].lower()]
            if y:
                y = int(y)
            else:  # "03 Oct" -> the most recent such day that is not in the future
                y = today.year
                if datetime(y, mo, d, 12) > today.replace(tzinfo=None):
                    y -= 1
        return datetime(int(y), mo, d, 12, tzinfo=dates.local_tz())  # noon: stays on the same day in UTC
    except (ValueError, KeyError, TypeError):
        return None


def _role(before: str, after: str) -> str:
    """Role of a date from the words next to it. 'Updated/effective/renewal' always beat 'launched/published'."""
    b, a = before[-45:], after[:70]
    for rx, kind in ((UPDATED, "last_updated"), (EFFECTIVE, "effective")):
        if rx.search(b) or rx.search(a):
            return kind
    for rx, kind in ((LAUNCHED, "launched"), (PUBLISHED, "published")):
        if rx.search(b) or rx.search(a[:40]):
            return kind
    return "unknown"


def find(text: str, *, today: datetime | None = None) -> list[Evidence]:
    """Every date in `text` with its role as far as the rules can tell."""
    today = today or datetime.now()
    out: list[Evidence] = []
    for m in DATE_RX.finditer(text or ""):
        dt = _to_dt(m, today)
        if not dt or dt > dates.utcnow() + dates.timedelta(days=2):
            continue
        before = re.split(r"[.!?]\s", text[max(0, m.start() - 60):m.start()])[-1]
        after = text[m.end():m.end() + 80]
        role = _role(before, after)
        if role == "unknown" and m.start() <= 3 or role == "unknown" and re.match(r"^\W*$", text[:m.start()]):
            # search-engine snippet convention: "3 Oct 2026 — text…" = publication date
            if re.match(r"\s*[-–—:·|]", after):
                role = "published"
        out.append(Evidence(role, dates.iso(dt), text[max(0, m.start() - 20):m.end() + 30].strip()))
    return out


def analyse(title: str, snippet: str, published: str | None = None, llm=None) -> list[Evidence]:
    """Date evidence for one search hit, best first (published/launched, then updated/effective)."""
    ev = find(f"{title}. {snippet}")
    if published:  # provider-supplied page date: published unless the text says it is an update
        if not any(e.date and e.date[:10] == published[:10] for e in ev):
            ev.append(Evidence("published", published, "provider date", "provider"))
        else:
            for e in ev:
                if e.date[:10] == published[:10] and e.kind == "unknown":
                    e.kind, e.by = "published", "provider"
    unknown = [e for e in ev if e.kind == "unknown"]
    if unknown and llm is not None and hasattr(llm, "date_kind"):
        for e in unknown[:2]:
            try:
                e.kind, e.by = llm.date_kind(f"{title}. {snippet}", e.date[:10]), "llm"
            except Exception as ex:  # noqa: BLE001 — never let dating break classification
                log.debug("date_kind LLM failed: %s", ex)
    order = {"published": 0, "launched": 0, "last_updated": 1, "effective": 1, "unknown": 2}
    return sorted(ev, key=lambda e: (order.get(e.kind, 3), e.date or ""), reverse=False)


def summarise(ev: list[Evidence]) -> dict:
    """Collapse evidence into program columns: launched_at (published/launched only), updated_at, date_kind."""
    launch = next((e for e in ev if e.kind in ("published", "launched")), None)
    upd = next((e for e in sorted(ev, key=lambda e: e.date or "", reverse=True)
                if e.kind in ("last_updated", "effective")), None)
    kind = launch.kind if launch else (upd.kind if upd else "unknown")
    return {"launched_at": launch.date if launch else None, "launched_via": "page_date" if launch else None,
            "updated_at": upd.date if upd else None, "date_kind": kind}
