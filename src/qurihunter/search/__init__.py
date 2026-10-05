from __future__ import annotations

from . import defaults  # noqa: F401
from .base import FRESHNESS, Page, Provider, ProviderError, SearchResult, Unexpressible
from .brave import Brave
from .google import Google
from .pool import KeyRing, QuotaExhausted, SearchPool, key_id
from .exa import Exa
from .searxng import SearXNG
from .serper import Serper
from .serpapi import SerpAPI
from .tavily import Tavily

PROVIDERS: dict[str, type[Provider]] = {c.id: c for c in (Serper, SerpAPI, Tavily, Brave, Google, Exa, SearXNG)}
DEFAULT_ORDER = ["serper", "serpapi", "tavily", "brave", "google", "exa", "searxng"]  # used until the user orders them


def provider_cfg(cfg: dict, pid: str) -> dict:
    return cfg["search"]["providers"].setdefault(pid, {"keys": [], "limit": PROVIDERS[pid].default_limit})


def make(cfg: dict, pid: str) -> Provider:
    return PROVIDERS[pid](provider_cfg(cfg, pid))


def sequence_order(cfg: dict) -> list[str]:
    """All known provider ids in the user's order (config `search_sequence`), unlisted ones after, in default order."""
    seq = [e["provider"] for e in cfg.get("search_sequence") or [] if e.get("provider") in PROVIDERS]
    seq = list(dict.fromkeys(seq))
    return seq + [p for p in DEFAULT_ORDER if p not in seq] + [p for p in PROVIDERS if p not in seq and p not in DEFAULT_ORDER]


def seq_entry(cfg: dict, pid: str) -> dict:
    return next((e for e in cfg.get("search_sequence") or [] if e.get("provider") == pid), {})


def is_enabled(cfg: dict, pid: str) -> bool:
    e = seq_entry(cfg, pid)
    return bool(e.get("enabled", (cfg["search"]["providers"].get(pid) or {}).get("enabled", True)))


def is_configured(cfg: dict, pid: str) -> bool:
    """A usable provider: has a key (or none is needed) and every required option."""
    cls = PROVIDERS[pid]
    pc = cfg["search"]["providers"].get(pid) or {}
    if cls.needs_key and not pc.get("keys"):
        return False
    return not make(cfg, pid).missing_options()


def configured(cfg: dict, include_disabled: bool = False) -> list[str]:
    """Usable provider ids in the user's sequence order (disabled ones left out unless asked)."""
    return [p for p in sequence_order(cfg) if is_configured(cfg, p) and (include_disabled or is_enabled(cfg, p))]


def sequence_entries(cfg: dict) -> list[dict]:
    """The ordered sequence as the spec describes it: {provider, enabled, keys, allowance, quota_type, role, configured}.
    Keys/allowance/quota_type are stored once, under search.providers[<id>]."""
    out = []
    order = sequence_order(cfg)
    first_real = next((p for p in order if is_configured(cfg, p) and is_enabled(cfg, p)), None)
    for p in order:
        pc = provider_cfg(cfg, p) if (cfg["search"]["providers"].get(p) or PROVIDERS[p].needs_key is False) else {}
        e = seq_entry(cfg, p)
        out.append({"provider": p, "enabled": is_enabled(cfg, p), "configured": is_configured(cfg, p),
                    "keys": list(pc.get("keys", [])), "allowance": pc.get("limit") or PROVIDERS[p].default_limit,
                    "quota_type": make(cfg, p).quota_type() if p in cfg["search"]["providers"] or not PROVIDERS[p].needs_key
                    else PROVIDERS[p]({}).quota_type(),
                    "role": e.get("role") or ("primary" if p == first_real else "fallback")})
    return out


def save_sequence(cfg: dict, order: list[str], enabled: dict | None = None) -> None:
    cur = {e["provider"]: e for e in cfg.get("search_sequence") or []}
    cfg["search_sequence"] = [{"provider": p, "enabled": (enabled or {}).get(p, cur.get(p, {}).get("enabled", is_enabled(cfg, p))),
                               "role": cur.get(p, {}).get("role", "")} for p in order]


def build_pool(cfg: dict, db) -> SearchPool | None:
    rings = []
    for pid in configured(cfg):
        pc = provider_cfg(cfg, pid)
        keys = pc["keys"] if PROVIDERS[pid].needs_key else [pid]  # key-less providers use one pseudo key
        from .pool import key_id
        rings.append(KeyRing(make(cfg, pid), keys, int(pc.get("limit") or PROVIDERS[pid].default_limit), db,
                             target_days=int(cfg.get("lifetime_target_days", 365)),
                             key_limit={k: int(v) for k, v in (pc.get("key_limit") or {}).items()},
                             daily={k: int(v) for k, v in (pc.get("daily") or {}).items() if v}))
    return SearchPool(rings, db) if rings else None
