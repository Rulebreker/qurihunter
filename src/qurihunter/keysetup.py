"""Per-key setup with ONE question: requests per day. Quota type and allowance come from the internal defaults table
(search/defaults.py) or, when the provider offers it, from its own account endpoint / rate-limit headers."""
from __future__ import annotations

from . import ui
from .search import defaults, make, provider_cfg
from .search.pool import ensure_lifetime_start, key_id


def apply_defaults(cfg: dict, pid: str) -> dict:
    """First key of a provider: quota type + allowance from the defaults table (never asked), only if not set before."""
    pc = provider_cfg(cfg, pid)
    d = defaults.default_for(pid)
    if d and not pc.get("quota_type"):
        pc["quota_type"] = d.quota_type
        if d.allowance is not None:
            pc["limit"] = d.allowance
    return pc


def configure_key(cfg: dict, pid: str, key: str, db=None, ask=None) -> dict:
    """Detect the real remaining quota (silent fallback to the default), propose a per-day cap and ask the single question.
    Returns {daily, remaining, qtype, days, source}."""
    ask = ask or (lambda q, d: ui.ask(q, d))
    pc = apply_defaults(cfg, pid)
    prov = make(cfg, pid)
    kid = key_id(pid, key)
    qtype = prov.quota_type()
    det = None
    try:
        det = prov.detect_quota(key)
    except Exception:  # noqa: BLE001 - detection is a bonus; fall back silently to the default allowance
        det = None
    used = db.quota_used(kid, prov.period_label()) if db is not None else 0
    if det and isinstance(det.get("remaining"), int):
        pc.setdefault("key_limit", {})[kid] = det["remaining"] + used  # remaining counts from the detected value
        remaining, source = det["remaining"], det.get("source", "account")
    else:
        remaining, source = (None if qtype == "unlimited" else max(0, int(pc.get("limit") or prov.default_limit) - used)), "default"
    if qtype == "lifetime" and db is not None:
        ensure_lifetime_start(db, pid)  # recorded once, at key-add time (so planning stays read-only)
    rec = defaults.recommended_daily(qtype, remaining, int(cfg.get("lifetime_target_days", 365)))
    out = {"daily": None, "remaining": remaining, "qtype": qtype, "days": None, "source": source}
    if rec is None:
        return out
    raw = (ask(f"How many requests per day for this key? (recommended {rec})", str(rec)) or str(rec)).strip()
    n = int(raw) if raw.isdigit() and int(raw) >= 1 else rec
    pc.setdefault("daily", {})[kid] = n
    out.update(daily=n, days=defaults.days_estimate(qtype, remaining, n))
    return out


def describe(res: dict) -> str:
    if res["daily"] is None:
        return "no daily cap (unlimited)"
    d = f", about {res['days']:.0f} days" if res["days"] else ""
    return f"{res['daily']} per day{d} ({'detected from your account' if res['source'] != 'default' else 'default allowance'})"


def total_per_day(cfg: dict, pid: str) -> int | None:
    pc = cfg["search"]["providers"].get(pid) or {}
    caps = [int(pc["daily"][key_id(pid, k)]) for k in pc.get("keys", []) if (pc.get("daily") or {}).get(key_id(pid, k))]
    return sum(caps) if caps else None
