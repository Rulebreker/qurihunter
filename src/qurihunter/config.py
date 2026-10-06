from __future__ import annotations

import copy
import json
import os
import tempfile
from typing import Any

from .paths import config_path

PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy", "disclose.io", "selfhosted", "web"]
CATEGORIES = ["bounty", "vdp", "security.txt"]
ROLES = ["classify", "summarize", "dork_gen", "chat", "date_kind", "validate"]
CONFIG_VERSION = 8

DEFAULTS: dict[str, Any] = {
    "version": CONFIG_VERSION,
    "setup_done": False,
    "mode": "auto",
    "llm": {"enabled": False, "host": "http://localhost:11434", "model": "",
            "backend": "ollama",  # ollama | openai (any OpenAI-compatible API)
            "base_url": "", "api_key": "", "max_classify_per_cycle": 60, "max_summaries_per_cycle": 10},
    # v7: how far back the PROVIDER looks (its native date parameter) is a separate setting from the alert window above.
    # First run of a dork: "any" (static policy pages are rarely dated this week); later runs: past month (new pages).
    "dork_search_recency": {"first": "any", "later": "month", "sweep": "week", "sweep_share": 0.10},
    "pages_per_dork": 1,  # results pages per query (where the provider paginates)
    "recency_days": 7,  # only programs whose effective date is inside this window alert; null = any
    "dorks": {"source": "default",  # default | custom | both
              "cooldown_days": 7, "ai_share": 0.2, "ai_prune_runs": 5, "ai_generate_every_days": 7,
              "ai_per_generation": 10, "prune_after_runs": 5,
              "unfiltered_share": 0.10,  # share of the batch run WITHOUT the provider date filter (0-0.30)
              # v8: evidence-based promotion of AI dorks into the default list (decided by code on counts, never by the LLM)
              "ai_auto_promote": "ask",  # on | ask | off
              "promote_min_runs": 3, "promote_min_verified": 2, "promote_min_precision": 0.3,
              "promote_similarity": 0.8,  # token-set similarity at/above which a candidate duplicates a default dork
              "demote_after_runs": 10, "demote_below_precision": 0.1},
    "alerts": {"alert_updated_only_pages": True,  # also alert pages whose only date is a last-updated/effective date
               "alert_weak_evidence": True,  # NEW alerts whose only evidence is "first seen by this tool/crawler": own section
               "show_skipped_in_digest": False,  # list "OLD, skipped" items in the digest
               "telegram_scan_summary": "changes_only",  # off | changes_only | daily
               "retry_cap_s": 60,  # longest we wait on a Telegram 429 retry_after
               "alert_manual_check": True},  # v8: send low-confidence / unverifiable finds in a NEEDS MANUAL CHECK section
    "reclassify": {"pages_per_cycle": 20},  # LLM/page-fetch judgements per background cycle
    # v8: LLM validation of a candidate's own page before it alerts (dork / self-hosted finds; platform feeds are skipped)
    "validate": {"enabled": True, "min_confidence": 0.7, "max_chars": 6000, "per_scan_cap": 40,
                 "background_per_cycle": 5, "use_feedback_examples": True, "max_examples": 4,
                 "skip_sources": ["hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy"]},  # platform feeds vouch themselves
    "pending": {"retry_enabled": True,  # background retry of waiting/failed alerts (REPL and /watch)
                "retry_max_per_day": 24, "backoff_base_min": 5, "backoff_max_min": 360, "check_every_s": 60},
    "wayback": {"enabled": True, "max_per_scan": 40, "timeout": 20, "min_interval_s": 1.0, "concurrency": 1,
                "on_error": "wait"},  # undated legacy rows the archive cannot verify: wait | alert (as "likely new")
    # v5: ordered provider sequence. Entries are {provider, enabled, role}; keys/allowance/quota_type live once in
    # search.providers[<id>] (see sequence_entries()). Empty list = default order of the configured providers.
    "background_workers": True,  # pending-retry + reclassify workers (REPL and /watch); /background pause|resume
    "search_sequence": [],
    "search_mode": "failover",  # failover | cascade | sweep (sweep needs the confirmation stored in sweep_confirmed)
    "cascade_min_results": 3,
    "sweep_confirmed": False,
    "lifetime_target_days": 365,  # one-time allowances are spread over this many days (2500 credits -> 6 per day)
    # v5: model registry. Empty = legacy single `llm` block. Entries: id, type local|api|claude|claude_cli, base_url,
    # model, key, roles, enabled, order, price_in, price_out (USD per million tokens, user supplied or None)
    "models": [],
    "llm_budget": {"daily_usd": 1.0, "monthly_usd": 10.0, "warn_pct": 80},
    "claude_cli": {"calls_per_hour": 12, "calls_per_day": 80, "min_interval_s": 20, "timeout_s": 180, "batch_size": 10},
    "claude_cli_allow_bulk": False,
    "features": {"ai_dorks": True, "chat": True},
    "chat": {"max_steps": 5, "max_queries_per_day": 10},
    "notify": {
        "channels": [],
        "telegram": {"token": "", "chat_id": ""},
        "email": {"address": "", "app_password": "", "to": ""},
        "digest_threshold": 8,  # more new programs than this -> one digest message
    },
    "search": {
        "pages": 1,
        "max_age": "month",  # only favour results newer than this on repeat dork runs: day|week|month|year
        "providers": {},  # {"brave": {"keys": [...], "limit": 1000}, "google": {"keys": [...], "cx": "...", "limit": 100}}
    },
    "filters": {"platforms": [], "countries": [], "min_reward": 0, "categories": []},
    "schedule": {"platform_interval_min": 15, "dork_interval_min": 1440},
    "custom_feeds": [],  # [{"name": "...", "url": "...", "format": "json|rss"}]
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _migrate(raw: dict) -> dict:
    """v0 configs had a single top-level `google` block; v1 had 30/60-minute interval defaults."""
    if raw.get("version", 1) < 2:
        s = raw.setdefault("schedule", {})
        if s.get("platform_interval_min", 30) == 30:  # still the old default -> new default
            s["platform_interval_min"] = 15
        if s.get("dork_interval_min", 60) == 60:
            s["dork_interval_min"] = 1440
        raw["version"] = 2
    if raw.get("version", 1) < 7:
        _backup_config(raw.get("version", 1))
        old = (raw.get("dorks") or {}).get("unfiltered_share")  # v7: the old "unfiltered sweep" became the recent-only sweep
        if old is not None:
            raw.setdefault("dork_search_recency", {}).setdefault("sweep_share", old)
    if raw.get("version", 1) < 6:
        # v6: new defaults apply only where the user never changed the old ones
        if raw.get("lifetime_target_days") == 60:
            raw["lifetime_target_days"] = 365
        cc = raw.get("claude_cli")
        if isinstance(cc, dict) and (cc.get("calls_per_hour"), cc.get("calls_per_day"), cc.get("min_interval_s")) == (6, 30, 30):
            cc.update(calls_per_hour=12, calls_per_day=80, min_interval_s=20, batch_size=10)
    if raw.get("version", 1) < 5:
        if not raw.get("models"):  # the single legacy LLM becomes model #1 (the legacy `llm` block stays: reversible)
            m = _legacy_model(raw.get("llm") or {})
            if m:
                raw["models"] = [m]
    if raw.get("version", 1) < 7:
        raw["version"] = 7  # v3-v7 only add keys / refresh untouched defaults; the rest is filled in by the defaults
    if raw.get("version", 1) < 8:
        _backup_config(raw.get("version", 1))
        _assign_validate(raw)
        raw["version"] = 8
    g = raw.pop("google", None)
    if g is not None and "search" not in raw:
        age = {"d": "day", "w": "week", "m": "month", "y": "year"}.get(str(g.get("max_age", "m"))[:1], "month")
        raw["search"] = {"pages": g.get("pages", 1), "max_age": age, "providers": {
            "google": {"keys": g.get("keys", []), "cx": g.get("cx", ""), "limit": g.get("daily_limit", 100)}}}
    return raw


def _assign_validate(raw: dict) -> None:
    """v8: the new 'validate' role goes to the first enabled LOCAL model (m1 in the usual setup). Paid and Claude-CLI models
    are never given it silently; /model roles <id> ... validate does that on request. Idempotent."""
    ms = sorted([m for m in raw.get("models") or [] if isinstance(m, dict)], key=lambda m: m.get("order", 99))
    if any("validate" in (m.get("roles") or []) for m in ms):
        return
    first = next((m for m in ms if m.get("enabled", True) and m.get("type") == "local"), None)
    if first is not None:
        first.setdefault("roles", []).append("validate")


def _backup_config(old_version) -> None:
    """Copy config.json aside once before the v5 upgrade rewrites it (restore = copy it back)."""
    p = config_path()
    b = p.with_name(f"config.json.bak-v{old_version}")
    try:
        if p.exists() and not b.exists():
            b.write_bytes(p.read_bytes())
            os.chmod(b, 0o600)
    except OSError:
        pass


def _legacy_model(l: dict) -> dict | None:
    if not l.get("enabled") or not l.get("model"):
        return None
    api = l.get("backend") == "openai"
    return {"id": "m1", "type": "api" if api else "local", "base_url": l.get("base_url", "") if api else l.get("host", ""),
            "model": l["model"], "key": l.get("api_key", "") if api else "", "roles": list(ROLES), "enabled": True,
            "order": 1, "price_in": None, "price_out": None}


def load() -> dict:
    p = config_path()
    if not p.exists():
        return copy.deepcopy(DEFAULTS)
    try:
        return _merge(DEFAULTS, _migrate(json.loads(p.read_text())))
    except (json.JSONDecodeError, OSError) as e:
        bad = p.with_suffix(".json.corrupt")
        p.replace(bad)
        raise RuntimeError(f"Config file was unreadable ({e}); moved to {bad}. Re-run setup.") from e


def save(cfg: dict) -> None:
    p = config_path()
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".config-")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)  # holds tokens / app passwords
    os.replace(tmp, p)


def mask(secret: str) -> str:
    return "…" + secret[-4:] if len(secret) > 6 else "***"


def recency_days(cfg: dict) -> float | None:
    from .dates import parse_window
    try:
        return parse_window(cfg.get("recency_days"))
    except ValueError:
        return 7.0


def search_recency_days(cfg: dict, which: str = "later") -> float | None:
    """Provider-side recency for a dork run: which = first | later | sweep. None = any. NEVER the alert window."""
    from .dates import parse_window
    spec = (cfg.get("dork_search_recency") or {}).get(which, {"first": "any", "later": "month", "sweep": "week"}[which])
    try:
        return parse_window({"week": "7d", "month": "31d", "year": "365d", "day": "1d"}.get(str(spec).lower(), spec))
    except ValueError:
        return {"first": None, "later": 31.0, "sweep": 7.0}[which]


def pages_per_dork(cfg: dict) -> int:
    return max(1, int(cfg.get("pages_per_dork") or cfg.get("search", {}).get("pages", 1) or 1))


def enabled_platforms(cfg: dict) -> list[str]:
    sel = cfg["filters"]["platforms"]
    return [p for p in PLATFORMS if not sel or p in sel]
