"""Alert decisions: which kind of alert (if any) a stored program deserves, the one-line evidence shown with it, and
what is still due per channel. One alert per kind per channel; chat never counts as an alert channel."""
from __future__ import annotations

from . import dates
from .config import recency_days

KINDS = ("new", "updated")
REAL_CHANNELS = ("telegram", "email")


def _in(d, days) -> bool:
    return bool(d) and dates.in_window(d, days)


def classify(r, days: float | None) -> tuple[str, str]:
    """(class, reason). class: new | updated | old | baseline | hidden. `reason` is a stable machine word used by
    /why and the per-reason counts."""
    if r["verdict"] != "official_program":
        return "hidden", "classified not_program"
    if r["filtered"]:
        return "hidden", "excluded by your filters"
    if r["baseline"]:
        return "baseline", "first-run baseline (not launched inside the window)"
    la, up, wb = r["launched_at"], r["updated_at"], r["wayback_state"]
    if la:
        if _in(la, days):
            return "new", "launch/publish date inside the window"
        return ("updated", "updated inside the window") if _in(up, days) else ("old", "launch date older than the window")
    if wb == "old":
        return ("updated", "updated inside the window, first archived earlier") if _in(up, days) \
            else ("old", "Wayback first capture is older than the window")
    if wb in ("none", "recent"):
        return "new", "likely new (Wayback: " + ("no capture" if wb == "none" else "first captured inside the window") + ")"
    if up and r["date_kind"] in ("last_updated", "effective"):
        return ("updated", "only a last-updated/effective date, inside the window") if _in(up, days) \
            else ("old", "only an update date, older than the window")
    if _in(r["first_seen"], days):
        return "new", "first seen inside the window"
    return "old", "first seen before the window"


def evidence_line(r, days: float | None = None) -> str:
    """e.g. 'published 03 Oct | first archived: none | likely new'."""
    cls, _ = classify(r, days)
    d = lambda s: _fmt(s)  # noqa: E731
    if r["launched_at"]:
        first = f"{r['date_kind'] if r['date_kind'] in ('published', 'launched') else 'launched'} {d(r['launched_at'])}"
    elif r["updated_at"]:
        first = f"{'effective' if r['date_kind'] == 'effective' else 'last updated'} {d(r['updated_at'])}"
    else:
        first = f"first seen {d(r['first_seen'])}"
    wb = r["wayback_state"]
    arch = {"none": "first archived: none", "unchecked": "archive: not checked", "error": "archive: lookup failed",
            "old": f"first archived {(r['wayback_first'] or '')[:7]}",
            "recent": f"first archived {(r['wayback_first'] or '')[:7]}"}.get(wb, "archive: not checked")
    tail = {"new": "likely new" if not r["launched_at"] else "new", "updated": "age unknown" if wb in ("unchecked", "error")
            else "older program, recently updated", "old": "older than window"}.get(cls, "")
    return " | ".join(x for x in (first, arch, tail) if x)


def basis(r) -> tuple[str, bool]:
    """Strongest evidence behind a NEW alert: (label, weak). Weak = no date from the page or the source."""
    la, via = r["launched_at"], r["launched_at_source"] if "launched_at_source" in r.keys() else "unknown"
    if la:
        if via == "page_date":
            return "published date", False
        if via == "source_first_seen":
            return "first seen by source crawler (weak)", True
        return "launch date from source", False
    if r["wayback_state"] == "recent":
        return "first archived inside window", False
    return "first seen by this tool (weak)", True


def _fmt(iso: str | None) -> str:
    d = dates.parse_date(iso) if iso else None
    return d.astimezone(dates.local_tz()).strftime("%d %b") if d else "?"


def due(db, cfg: dict, channels: list[str] | None = None) -> list[tuple]:
    """[(row, kind)] that still need sending on at least one channel in `channels` (default: the configured real
    channels). Each (program, kind, channel) is delivered at most once; update-after-new is only allowed for a
    genuinely later update date, and a program alerted as updated is never re-alerted as new on a vague signal."""
    days = recency_days(cfg)
    chans = [c for c in (channels if channels is not None else cfg["notify"]["channels"]) if c in REAL_CHANNELS] \
        or ["telegram"]
    allow_upd = bool(cfg["alerts"]["alert_updated_only_pages"])
    allow_weak = bool(cfg["alerts"].get("alert_weak_evidence", True))
    out = []
    for r in db.c.execute("SELECT * FROM programs WHERE baseline=0 AND filtered=0 AND verdict='official_program'"):
        cls, _ = classify(r, days)
        if cls not in KINDS or (cls == "updated" and not allow_upd):
            continue
        if cls == "new" and not allow_weak and basis(r)[1]:
            continue  # weak-evidence NEW items switched off (alerts.alert_weak_evidence)
        done = {(k, c): ts for k, c, ts in db.c.execute(
            "SELECT kind, channel, ts FROM deliveries WHERE program_id=?", (r["id"],))}
        for ch in chans:
            if (cls, ch) in done:
                continue
            if cls == "new" and ("updated", ch) in done and not _in(r["launched_at"], days):
                continue  # already told as 'updated'; only a real launch/publish date can make it 'new' later
            if cls == "updated" and ("new", ch) in done and (r["updated_at"] or "") <= (done[("new", ch)] or ""):
                continue  # the update predates the NEW alert we already sent
            out.append((r, cls))
            break
    out.sort(key=lambda x: (x[1] != "new", x[1] == "new" and basis(x[0])[1], x[0]["first_seen"] or ""))
    return out


def reason_counts(db, cfg: dict, days: float | None = None) -> dict[str, int]:
    """Per-reason counts for programs seen in the last `days` (default: the recency window) — the answer to
    'why did nothing reach my Telegram?'."""
    days = recency_days(cfg) if days is None else days
    chans = [c for c in cfg["notify"]["channels"] if c in REAL_CHANNELS] or ["telegram"]
    cut = dates.cutoff_iso(days)
    out: dict[str, int] = {}

    def bump(k):
        out[k] = out.get(k, 0) + 1
    for r in db.c.execute("SELECT * FROM programs WHERE first_seen>=? OR COALESCE(launched_at,'')>=? OR COALESCE(updated_at,'')>=?",
                          (cut or "", cut or "", cut or "")):
        cls, why = classify(r, days)
        if cls == "hidden":
            bump(("filtered: " if r["filtered"] else "") + why)
        elif cls in KINDS:
            have = {c for (c,) in db.c.execute("SELECT channel FROM deliveries WHERE program_id=? AND kind=?", (r["id"], cls))}
            if all(c in have for c in chans):
                bump(f"{cls}: delivered")
            elif cls == "updated" and not cfg["alerts"]["alert_updated_only_pages"]:
                bump("updated: suppressed (alert_updated_only_pages is off)")
            else:
                bump(f"{cls}: PENDING (not yet delivered on {'/'.join(c for c in chans if c not in have)})")
            if "chat" in {c for (c,) in db.c.execute("SELECT channel FROM deliveries WHERE program_id=?", (r["id"],))} \
                    and not have:
                bump("  of which shown in /chat only (does not count as delivered)")
        else:
            bump(f"{cls}: {why}")
    return dict(sorted(out.items()))


def awaiting_archive(r, cfg) -> bool:
    """An undated web row that still needs its Wayback verdict (and on_error is 'wait')."""
    wb = cfg.get("wayback", {})
    return bool(r["source"] == "web" and not r["launched_at"] and not r["baseline"] and wb.get("enabled", True)
                and r["wayback_state"] in ("unchecked", "error") and wb.get("on_error", "wait") == "wait")


def pending_reasons(db, cfg: dict) -> dict[str, int]:
    """Why each due alert has not gone out yet."""
    last = db.c.execute("SELECT ok FROM alert_log ORDER BY id DESC LIMIT 1").fetchone()
    failed = bool(last and not last["ok"])
    from . import validation
    out: dict[str, int] = {}
    manual_off = not cfg.get("alerts", {}).get("alert_manual_check", True)
    can_validate = validation.configured(cfg)  # without a model the next scan sends them as 'not validated' right away
    for r, k in due(db, cfg):
        # (validation reasons deliberately do not start with "waiting": the delivery-retry worker cannot validate)
        key = ("waiting for archive (Wayback) verification" if awaiting_archive(r, cfg)
               else "validation pending (LLM page check: next scan or background worker)" if can_validate and validation.needs(r, cfg)
               else "needs manual check - held (alerts.alert_manual_check is off)" if manual_off and validation.is_manual(r)
               else "last send failed - will retry" if failed else "ready - goes out on the next scan/retry")
        out[key] = out.get(key, 0) + 1
    return out
