"""LLM-invented dorks. The LLM only *proposes*; code validates (allowlist, blocklist, operators, similarity)
before anything is stored. Candidates can only aim at official disclosure/bounty pages."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import dates, dorkstore
from .llm import LLMError, parse_json
from .logs import log
from .paths import home
from .search.dorkparse import parse
from .sources import dorks as legacy

DATA = Path(__file__).parent / "data"
MAX_LEN = 160
ALLOWED_OPS = {"site", "intitle", "inurl", "intext"}


def _read(name: str) -> list[str]:
    out: list[str] = []
    for f in (DATA / name, home() / name):  # user additions live in ~/.qurihunter/<name>
        try:
            out += [l.strip().lower() for l in f.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
        except OSError:
            pass
    return out


def blocklist() -> list[str]:
    return _read("dork_blocklist.txt")


def allowlist() -> list[str]:
    return _read("dork_allowlist.txt")


def _tokens(text: str) -> frozenset:
    return frozenset(re.findall(r"\w+", text.lower()))


def validate(text: str, existing: list[tuple[frozenset, str]] | None = None, *, similarity: float = 0.8) -> tuple[bool, str]:
    """Returns (ok, normalised_text | reason). Pure code — the LLM cannot bypass it."""
    if not isinstance(text, str):
        return False, "not a string"
    t = dorkstore.DATE_RE.sub("", text.replace("“", '"').replace("”", '"'))
    t = " ".join(t.split())
    if len(t) < 8:
        return False, "too short"
    if len(t) > MAX_LEN:
        return False, "too long"
    if re.search(r"[\x00-\x1f]|https?://|\\\\", t):
        return False, "contains control characters or URLs"
    low = t.lower()
    for bad in blocklist():
        hit = re.search(rf"\b{re.escape(bad)}\b", low) if re.fullmatch(r"[a-z ]{1,8}", bad) else bad in low
        if hit:  # short words match whole words only ("rce" must not block "resource")
            return False, f"blocked term '{bad}' (dorks must only target program pages)"
    for m in re.finditer(r"(?<![\w-])(-?)([a-z]+):", low):
        if m.group(2) not in ALLOWED_OPS:
            return False, f"operator '{m.group(2)}:' is not allowed"
    pd = parse(t)
    if pd.include_domains:
        return False, "site: may only be a country/sector TLD like site:.ch (no specific domains)"
    if not any(a in low for a in allowlist()):
        return False, "no vulnerability-disclosure / bug-bounty term"
    if len(low.split()) > 24:
        return False, "too many terms"
    if not pd.terms():
        return False, "no search terms"
    toks, tld = _tokens(re.sub(r"site:\S+|-site:\S+", " ", low)), pd.tld
    for et, etld in existing or []:
        if etld == tld and et and toks and len(toks & et) / len(toks | et) >= similarity:
            return False, "duplicate / near-duplicate of an existing dork"
    return True, t


def _existing(db) -> list[tuple[frozenset, str]]:
    out = []
    for r in db.c.execute("SELECT text FROM dorks"):
        low = r["text"].lower()
        out.append((_tokens(re.sub(r"site:\S+|-site:\S+", " ", low)), parse(r["text"]).tld))
    return out


@dataclass
class GenReport:
    requested: int = 0
    proposed: int = 0
    accepted: int = 0
    rejected: Counter = field(default_factory=Counter)
    accepted_texts: list = field(default_factory=list)
    error: str = ""
    parsed_via: str = ""

    def text(self) -> str:
        if self.error:
            return f"AI dork generation failed: {self.error}"
        rej = ", ".join(f"{n}× {r.split('(')[0].strip()}" for r, n in self.rejected.most_common(4))
        return (f"AI dorks: asked for {self.requested}, LLM proposed {self.proposed}, {self.accepted} accepted"
                + (f" [parsed via {self.parsed_via}]" if self.parsed_via and "attempt 1" not in self.parsed_via else "")
                + (f"; rejected: {rej}" if rej else ""))


def _context(cfg, db, provider) -> str:
    winners = db.c.execute("SELECT id,text,new_programs_found FROM dorks WHERE new_programs_found>0 "
                           "ORDER BY new_programs_found DESC LIMIT 8").fetchall()
    existing = db.c.execute("SELECT text FROM dorks ORDER BY id DESC LIMIT 60").fetchall()
    recent = db.c.execute("SELECT name,country,kind,url FROM programs WHERE source='web' AND verdict='official_program' "
                          "ORDER BY id DESC LIMIT 40").fetchall()
    ccs = Counter((r["country"] or "?") for r in recent)
    words = Counter(w for r in recent for w in re.findall(r"[a-zà-ÿ]{4,}", (r["name"] or "").lower()))
    have_tlds = {parse(r["text"]).tld for r in db.c.execute("SELECT text FROM dorks")} - {""}
    uncovered = [c for c in legacy.DEFAULT_COUNTRIES if c not in have_tlds][:15]
    low = " ".join(r["text"].lower() for r in db.c.execute("SELECT text FROM dorks"))
    langs = [lang for lang, kw in (("German", "schwachstelle"), ("French", "vulnérabilité"), ("Spanish", "vulnerabilidad"),
                                   ("Portuguese", "vulnerabilidade"), ("Italian", "vulnerabilità"), ("Dutch", "kwetsbaarheid"),
                                   ("Swedish", "sårbarhet"), ("Polish", "podatność"), ("Japanese", "脆弱性"),
                                   ("Turkish", "güvenlik açığı")) if kw not in low]
    caps = {"tavily": "Natural-language keyword/phrase queries ONLY. No operators work (site:, inurl:, intitle: are ignored).",
            "brave": "Supports site:, \"quoted phrases\" and -minus. inurl:/intitle:/OR are NOT supported.",
            "google": "Supports full operators: intitle:, inurl:, site:, quotes, -minus, OR."}.get(
                provider.id if provider else "", "Prefer quoted phrases; operators may not be supported.")
    lines = [
        f"PROVIDER CAPABILITIES: {caps}",
        "EXISTING DORKS (do not repeat or lightly reword): " + " || ".join(r["text"] for r in existing),
        "WINNING DORKS (found new programs; vary these, set parent_id to their id): "
        + (" || ".join(f"[{w['id']}] {w['text']} (found {w['new_programs_found']})" for w in winners) or "none yet"),
        f"RECENTLY FOUND PROGRAMS — countries: {dict(ccs.most_common(6))}; common name words: "
        f"{[w for w, _ in words.most_common(10)]}",
        f"REGIONS (ccTLDs) NOT YET COVERED: {uncovered or 'none'}",
        f"LANGUAGES NOT YET COVERED: {langs or 'none'}",
    ]
    return "\n".join(lines)


STRICT = ("Return ONLY a JSON array of {n} strings, each one a search query. No object wrapper, no explanation, no "
          "markdown, no code fences. Example: [\"query one\", \"query two\"]")
_LINE = re.compile(r"^\s*(?:[-*•]+|\d+[.)])?\s*[\"'`]?(.+?)[\"'`]?[,;]?\s*$")


def parse_lines(raw: str) -> list[str]:
    """Last-resort parser: one query per line, bullets/numbers/quotes stripped, prose and headings ignored."""
    raw = re.sub(r"(?is)<think(?:ing)?>.*?</think(?:ing)?>", " ", raw or "")
    out = []
    for line in raw.splitlines():
        if not line.strip() or line.strip().startswith(("```", "{", "}", "[", "]", "#")):
            continue
        m = _LINE.match(line)
        t = m.group(1).strip() if m else ""
        if t and 3 <= len(t.split()) <= 24 and not t.endswith(":") and any(a in t.lower() for a in allowlist()):
            out.append(t)
    return out


def _items_from(data):
    items = data.get("dorks") if isinstance(data, dict) else data if isinstance(data, list) else None
    if isinstance(items, list) and items:
        return items
    if isinstance(data, dict):  # {"queries": [...]} / {"results": [...]}: first list value
        for v in data.values():
            if isinstance(v, list) and v:
                return v
    return None


def _ask(llm, prompt: str, n: int, rep: GenReport):
    """Up to three attempts: JSON as asked, a stricter 'ONLY a JSON array of strings' retry, then a line-by-line
    parse of the plain-text answer. Sets rep.error with the real reason when all fail."""
    last = ""
    for attempt, (p, jm) in enumerate(((prompt, True), (prompt + "\n\n" + STRICT.format(n=n), False)), 1):
        try:
            raw = llm.generate(p, json_mode=jm, timeout=240)
        except LLMError as e:
            rep.error = f"LLM error: {e}"
            return None, ""
        last = raw or ""
        data = parse_json(last)
        items = _items_from(data)
        if items is None and isinstance(data, dict) and isinstance(data.get("dorks"), list):
            items = []  # a well-formed "no ideas" answer: valid, not a failure
        if items is not None:
            return items, f"json (attempt {attempt})"
        lines = parse_lines(last)
        if len(lines) >= 1 and attempt == 2:
            return lines, "line parser"
    rep.error = ("the model returned no usable dorks after 2 JSON attempts and the line fallback "
                 f"(last answer started: {re.sub(chr(10), ' ', last[:80])!r}). Try a larger model (/model).")
    return None, ""


def generate(cfg: dict, db, llm, provider, n: int) -> GenReport:
    from .llmreg import role_view
    llm = role_view(llm, "dork_gen")
    rep = GenReport(requested=n)
    prompt = (
        "You help a defensive security tool discover OFFICIAL vulnerability-disclosure and bug-bounty program pages "
        "of organisations (never exposed data, never exploitation).\n"
        f"Invent {n} NEW, DIFFERENT search queries that would surface such program pages — new wording, other "
        "languages, other regions (site:.cc), other sectors. Every query MUST contain a disclosure/bounty term "
        "(e.g. responsible disclosure, bug bounty, security.txt, vulnerability reward) and must not contain dates.\n\n"
        + _context(cfg, db, provider) + "\n\n"
        'Reply with JSON only: {"dorks": [{"text": "<query>", "rationale": "<why it may find new programs>", '
        '"parent_id": <id of a winning dork you varied, or null>}]}'
    )
    db.commit()  # the (slow) LLM call below must not run inside a write transaction
    items, how = _ask(llm, prompt, n, rep)
    if items is None:
        return rep
    rep.parsed_via = how
    existing = _existing(db)
    pids = {r[0] for r in db.c.execute("SELECT id FROM dorks")}
    for it in items[: max(n * 2, 1)]:
        text = it.get("text") if isinstance(it, dict) else it
        rep.proposed += 1
        ok, res = validate(text, existing)
        if not ok:
            rep.rejected[res] += 1
            continue
        parent = it.get("parent_id") if isinstance(it, dict) else None
        parent = parent if isinstance(parent, int) and parent in pids else None
        rationale = re.sub(r"\s+", " ", str(it.get("rationale", "") if isinstance(it, dict) else ""))[:300]
        did = dorkstore.add_dork(db, res, "ai", parent=parent, rationale=rationale)
        if did is None:
            rep.rejected["duplicate / near-duplicate of an existing dork"] += 1
            continue
        existing.append((_tokens(re.sub(r"site:\S+|-site:\S+", " ", res.lower())), parse(res).tld))
        rep.accepted += 1
        rep.accepted_texts.append(res)
        if rep.accepted >= n:
            break
    db.set_meta("ai_last_generated", dates.now_iso())
    db.commit()
    return rep


def maybe_generate(cfg: dict, db, llm, provider) -> list[str]:
    """Periodic generation inside a scan cycle (the scan lock is already held)."""
    last = db.meta("ai_last_generated")
    every = float(cfg["dorks"]["ai_generate_every_days"])
    if last and dates.parse_date(last) and (dates.utcnow() - dates.parse_date(last)).total_seconds() < every * 86400:
        return []
    try:
        rep = generate(cfg, db, llm, provider, int(cfg["dorks"]["ai_per_generation"]))
    except Exception as e:  # noqa: BLE001 — AI dorks are optional; never break a scan
        log.exception("AI dork generation crashed")
        return [f"[yellow]AI dork generation skipped: {e}[/yellow]"]
    if rep.error:  # try again next cycle rather than waiting a week
        return [f"[yellow]{rep.text()}[/yellow]"]
    return [rep.text()]
