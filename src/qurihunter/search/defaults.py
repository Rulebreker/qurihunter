"""Internal per-provider quota defaults (the wizard no longer asks about quota types or allowances) and the daily-pacing
arithmetic. Every entry carries a source note and a date and is flagged `verified` only if a document was actually read."""
from __future__ import annotations

import math
from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Default:
    quota_type: str  # monthly | daily | lifetime | unlimited
    allowance: int | None
    verified: bool
    source: str
    date: str


DEFAULTS: dict[str, Default] = {
    "serper": Default("lifetime", 2500, False, "serper.dev sign-up bucket of free credits (one-time); the amount is from "
                      "memory of their pricing page - not verifiable from the docs we could read", "2026-10-05"),
    "serpapi": Default("monthly", 250, True, "serpapi.com/pricing.md: Free plan 250 searches/month, 50 successful searches/hour",
                       "2026-10-05"),
    "tavily": Default("monthly", 1000, False, "Tavily free plan credits per month; the usage endpoint reports the real value, "
                      "the docs we read do not state the number", "2026-10-05"),
    "brave": Default("monthly", 1000, False, "Brave plan header example shows 15000/month on a paid plan; the free amount is "
                     "'about 1000' and changes - the real value is read from the X-RateLimit headers", "2026-10-05"),
    "exa": Default("monthly", 1000, False, "Exa free credits; plans change, no usage endpoint found in the docs", "2026-10-05"),
    "google": Default("daily", 100, False, "Google Custom Search free tier: 100 queries/day (legacy, closed to new customers, "
                      "sunset 2027-01-01)", "2026-10-05"),
    "searxng": Default("unlimited", None, True, "self-hosted: no quota, only the engines' own limits", "2026-10-05"),
}


def default_for(pid: str) -> Default | None:
    return DEFAULTS.get(pid)


def days_left_in_month(now: datetime | None = None) -> int:
    n = now or datetime.now(timezone.utc)
    return max(1, monthrange(n.year, n.month)[1] - n.day + 1)  # including today


def recommended_daily(qtype: str, remaining: int | None, target_days: int = 365, now: datetime | None = None) -> int | None:
    """Requests per day that spread `remaining` sensibly: lifetime -> remaining / target_days (2500 -> 6), monthly ->
    remaining / days left in the cycle, daily -> the allowance itself. Minimum 1. None = no cap (unlimited)."""
    if qtype == "unlimited" or remaining is None:
        return None
    if qtype == "daily":
        return max(1, int(remaining))
    if qtype == "monthly":
        return max(1, remaining // days_left_in_month(now))
    return max(1, remaining // max(1, int(target_days)))


def days_estimate(qtype: str, remaining: int | None, per_day: int | None, now: datetime | None = None) -> float | None:
    if not per_day or remaining is None or qtype == "unlimited":
        return None
    if qtype == "daily":
        return None  # refills every day
    d = remaining / per_day
    return min(d, days_left_in_month(now)) if qtype == "monthly" else d


def label(d: Default | None) -> str:
    return "-" if d is None else f"{d.quota_type} {d.allowance if d.allowance is not None else ''}".strip() + \
        ("" if d.verified else " (unverified)")
