"""Alert delivery. Telegram: HTML with everything escaped, plain-text fallback, <=4096-char messages split between
programs (never inside a link), 429 retry_after handling. A program is recorded as delivered on a channel only after
that channel confirmed the send (Telegram `ok: true`); failures stay pending and are logged (secrets redacted)."""
from __future__ import annotations

import html
import re
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from email.message import EmailMessage

import requests

from . import alerts, config
from .http import redact, request
from .logs import log

TG_LIMIT = 3900  # Telegram's hard limit is 4096 characters of *parsed* text; keep a margin for markup
_sleep = time.sleep
SECTION = {"new": ("🆕", "NEW"), "new_weak": ("🆕", "NEW (weak evidence)"),
           "new_unverified": ("❔", "NEW — age unverified"), "updated": ("♻️", "RECENTLY UPDATED"),
           "old": ("📦", "OLD, SKIPPED")}


def section_of(r, kind: str, unverified=()) -> str:
    if kind != "new":
        return kind
    if r["id"] in unverified:
        return "new_unverified"
    return "new_weak" if alerts.basis(r)[1] else "new"


class NotifyError(Exception):
    pass


@dataclass
class Message:
    html: str
    plain: str
    items: list = field(default_factory=list)  # [(program_id, kind)] fully contained in this message


# ───────────────────────────── message building ─────────────────────────────
def _clip(s, n):
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def block(r, kind: str, days: float | None, sample: bool = False, unverified: bool = False) -> tuple[str, str]:
    """(html, plain) for ONE program."""
    name = _clip(r["name"] or r["url"], 150)
    if sample:
        name = f"SAMPLE — {name}"
    reward = f"up to {r['reward_max']:,.0f} {r['currency'] or ''}".strip() if r["reward_max"] else (
        "bounty (amount n/a)" if r["kind"] == "bounty" else "")
    cat = " (security.txt only)" if r["kind"] == "security.txt" else ""
    meta = " · ".join(x for x in (f"{r['kind']}{cat}", reward, (r["country"] or "").upper(), f"via {r['source']}") if x)
    url = _clip(r["url"], 600)
    ev = alerts.evidence_line(r, days)
    if kind == "new":
        ev += f"\nBasis: {'age unverified' if unverified else alerts.basis(r)[0]}"
    return (f"<b>{html.escape(name)}</b>\n{html.escape(meta)}\n{html.escape(url, quote=False)}\n<i>{html.escape(ev)}</i>",
            f"{name}\n{meta}\n{url}\n{ev}")


def _header(kind: str, n: int | None, cont: bool, sample: bool) -> tuple[str, str]:
    icon, label = SECTION[kind]
    text = f"{label} ({n})" if n is not None and not cont else (f"{label} — continued" if cont else label)
    if sample:
        text = "SAMPLE " + text
    return f"{icon} <b>{html.escape(text)}</b>", f"{icon} {text}"


def build(items: list[tuple], days: float | None, *, limit: int = TG_LIMIT, sample: bool = False,
          unverified=()) -> list[Message]:
    """items: [(row, kind)] ordered NEW first. Packs section headers + one block per program into as few messages as
    fit `limit`; messages are only ever cut between programs."""
    counts: dict[str, int] = {}
    secs = [section_of(r, k, unverified) for r, k in items]
    for sk in secs:
        counts[sk] = counts.get(sk, 0) + 1
    msgs: list[Message] = []
    H: list[str] = []
    P: list[str] = []
    done: list = []
    kind = None
    shown: set[str] = set()

    def size(parts):
        return sum(map(len, parts)) + 2 * max(0, len(parts) - 1)

    def flush():
        nonlocal H, P, done, kind
        if H:
            msgs.append(Message("\n\n".join(H), "\n\n".join(P), done))
        H, P, done, kind = [], [], [], None
    for (r, k), sk in zip(items, secs):
        bh, bp = block(r, k, days, sample, unverified=sk == "new_unverified")
        hdr = _header(sk, counts[sk], sk in shown, sample) if (kind != sk or not H) else None
        if H and size(H) + (len(hdr[0]) + 2 if hdr else 0) + len(bh) + 2 > limit:
            flush()
            hdr = _header(sk, counts[sk], sk in shown, sample)
        if hdr:
            H.append(hdr[0])
            P.append(hdr[1])
            shown.add(sk)
            kind = sk
        H.append(bh)
        P.append(bp)
        done.append((r["id"] if "id" in r.keys() else None, k))
    flush()
    return msgs


def _strip(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text))


# ───────────────────────────── Telegram ─────────────────────────────
def _tg_json(r) -> dict:
    try:
        j = r.json()
        return j if isinstance(j, dict) else {}
    except ValueError:
        return {}


def tg_post(token: str, chat_id: str, text: str, *, parse_mode: str | None = "HTML", cap: float = 60,
            plain: str | None = None) -> None:
    """One sendMessage. Returns only when Telegram answered ok:true, otherwise raises NotifyError."""
    if not token or not chat_id:
        raise NotifyError("Telegram token/chat id missing")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for attempt in range(4):
        body = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        if parse_mode:
            body["parse_mode"] = parse_mode
        try:
            r = request("POST", url, retries=2, timeout=20, retry_429=False, json=body)
        except requests.RequestException as e:
            raise NotifyError(f"network error: {redact(e)}") from e
        j = _tg_json(r)
        if r.status_code == 200 and j.get("ok") is True:
            return
        desc = redact(j.get("description") or r.text[:150])
        if r.status_code == 429:
            wait = float((j.get("parameters") or {}).get("retry_after") or r.headers.get("Retry-After") or 5)
            if wait > cap or attempt == 3:
                raise NotifyError(f"Telegram rate limit: retry_after {wait:.0f}s ({desc})")
            log.warning("Telegram 429, waiting %.0fs", wait)
            _sleep(wait + 1)
            continue
        if r.status_code == 400 and parse_mode and "parse" in desc.lower():
            log.warning("Telegram could not parse HTML (%s) — resending as plain text", desc)
            text, parse_mode = plain if plain is not None else _strip(text), None
            continue
        raise NotifyError(f"Telegram: {desc}")


def send_telegram(token: str, chat_id: str, text: str) -> None:
    """Send arbitrary (HTML) text, split on line boundaries if it exceeds the limit."""
    chunks, cur = [], ""
    for line in text.split("\n"):
        if cur and len(cur) + len(line) + 1 > TG_LIMIT:
            chunks.append(cur)
            cur = ""
        cur += ("\n" if cur else "") + line
    chunks.append(cur)
    for c in chunks:
        tg_post(token, chat_id, c, plain=_strip(c))


def send_messages_telegram(cfg: dict, msgs: list[Message], on_ok=None) -> tuple[int, str | None]:
    """Send messages in order; stop at the first failure. Returns (sent, error)."""
    t = cfg["notify"]["telegram"]
    cap = float(cfg["alerts"].get("retry_cap_s", 60))
    sent = 0
    for i, m in enumerate(msgs):
        try:
            tg_post(t["token"], t["chat_id"], m.html, cap=cap, plain=m.plain)
        except NotifyError as e:
            log.error("telegram send failed (message %d/%d): %s", i + 1, len(msgs), e)
            return sent, str(e)
        sent += 1
        if on_ok:
            on_ok(m)
        if i + 1 < len(msgs):
            _sleep(1.1)  # Telegram allows ~1 message/second per chat
    return sent, None


# ───────────────────────────── email ─────────────────────────────
def send_email(address: str, app_password: str, to: str, subject: str, text: str, html_body: str = "") -> None:
    if not address or not app_password:
        raise NotifyError("Gmail address/app password missing")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = address, to or address, subject
    msg.set_content(text)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=30) as s:
            s.login(address, app_password.replace(" ", ""))
            s.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        raise NotifyError("Gmail rejected the login — use a 16-char *App Password* "
                          "(Google Account → Security → 2-Step Verification → App passwords)") from e
    except (smtplib.SMTPException, OSError) as e:
        raise NotifyError(f"SMTP error: {redact(e)}") from e


# ───────────────────────────── delivery of due alerts ─────────────────────────────
def deliver(cfg: dict, db, items: list[tuple], *, only: list[str] | None = None, unverified=()) -> dict[str, str]:
    """Send every due (row, kind) on each configured channel that still lacks it. Returns {channel: 'ok'|error}.
    Delivery is recorded per (program, kind, channel) only after the channel confirmed it."""
    days = config.recency_days(cfg)
    res: dict[str, str] = {}
    for ch in only or [c for c in cfg["notify"]["channels"] if c in alerts.REAL_CHANNELS]:
        todo = [(r, k) for r, k in items if not db.c.execute(
            "SELECT 1 FROM deliveries WHERE program_id=? AND kind=? AND channel=?", (r["id"], k, ch)).fetchone()]
        if not todo:
            continue
        if ch == "telegram":
            msgs = build(todo, days, unverified=unverified)

            def ok(m, ch=ch):
                db.record_delivery(m.items, ch)
                db.commit()
            sent, err = send_messages_telegram(cfg, msgs, on_ok=ok)
            n = sum(len(m.items) for m in msgs[:sent])
            db.log_alert(ch, err is None, err or "", n, sent, "+".join(sorted({k for _, k in todo})))
            res[ch] = "ok" if err is None else err
        elif ch == "email":
            e = cfg["notify"]["email"]
            groups = {k: [r for r, kk in todo if kk == k] for k in ("new", "updated")}
            subject = "[qurihunter] " + ", ".join(f"{len(v)} {k}" for k, v in groups.items() if v) + " bug bounty / VDP program(s)"
            body = "\n\n".join(m.plain for m in build(todo, days, limit=10**9, unverified=unverified))
            try:
                send_email(e["address"], e["app_password"], e.get("to") or e["address"], subject, body)
                db.record_delivery([(r["id"], k) for r, k in todo], ch)
                db.log_alert(ch, True, "", len(todo), 1, "")
                res[ch] = "ok"
            except NotifyError as ex:
                log.error("email send failed: %s", ex)
                db.log_alert(ch, False, str(ex), 0, 0, "")
                res[ch] = str(ex)
        db.commit()
    return res


def send_summary(cfg: dict, text: str) -> str | None:
    """One-line scan summary on Telegram. Returns an error string or None."""
    if "telegram" not in cfg["notify"]["channels"]:
        return None
    t = cfg["notify"]["telegram"]
    try:
        tg_post(t["token"], t["chat_id"], html.escape(text), cap=float(cfg["alerts"].get("retry_cap_s", 60)),
                plain=text)
    except NotifyError as e:
        log.error("scan summary failed: %s", e)
        return str(e)
    return None


def samples() -> list[tuple[dict, str]]:
    """Two clearly fake programs for /alerts test."""
    base = {"id": 0, "kind": "bounty", "reward_max": 5000, "currency": "USD", "country": "ch", "source": "sample",
            "verdict": "official_program", "filtered": 0, "baseline": 0, "wayback_first": None}
    now = __import__("qurihunter.dates", fromlist=["x"]).now_iso()
    new = dict(base, name="Example Corp — Bug Bounty", url="https://example.com/security/bug-bounty", launched_at=now,
               launched_at_source="page_date", date_kind="published", updated_at=None, wayback_state="none", first_seen=now)
    upd = dict(base, id=0, name="Example Org — Responsible Disclosure", url="https://example.org/responsible-disclosure",
               kind="vdp", reward_max=None, launched_at=None, date_kind="last_updated", updated_at=now,
               wayback_state="old", wayback_first="2023-04-01T00:00:00+00:00", first_seen=now, country="sk")
    weak = dict(base, id=-1, name="Example Inc — Vulnerability Disclosure", url="https://example.net/vdp", kind="vdp",
                reward_max=None, launched_at=None, launched_at_source="unknown", date_kind="unknown", updated_at=None,
                wayback_state="none", first_seen=now, country="se")
    return [(new, "new"), (weak, "new"), (upd, "updated")]
