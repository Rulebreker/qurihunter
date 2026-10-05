"""First-capture check against the Internet Archive CDX API. A page first archived long before the recency window is
an old page we merely discovered late; a page with no capture is probably new. Results are cached forever, the API is
rate limited, every call has a short timeout and a failure never blocks (or fails) a scan."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import requests

from . import dates
from .db import DB, url_hash
from .http import redact
from .logs import log

CDX = "https://web.archive.org/cdx/search/cdx"
_last_call = 0.0
BREAKER = 3  # consecutive failures after which the archive is skipped for the rest of the scan
_fails = 0


def reset() -> None:
    global _fails
    _fails = 0


def lookup(url: str, timeout: float = 8) -> str | None:
    """Earliest capture timestamp (YYYYMMDDhhmmss) or None. Raises requests.RequestException on failure."""
    from .urls import normalize_url
    r = requests.get(CDX, params={"url": normalize_url(url).split("://", 1)[-1], "limit": 1, "output": "json",
                                  "fl": "timestamp", "filter": "statuscode:200", "collapse": "timestamp:8"},
                     timeout=timeout, headers={"User-Agent": "qurihunter (bug bounty discovery)"})
    if r.status_code != 200:
        raise requests.RequestException(f"CDX HTTP {r.status_code}")
    rows = r.json() if r.text.strip() else []
    return rows[1][0] if len(rows) > 1 else None


AVAIL = "https://archive.org/wayback/available"


def available(url: str, timeout: float = 10) -> str | None:
    """Lighter second check: the availability API returns the snapshot closest to a very early date (≈ earliest).
    Returns a timestamp or None; raises requests.RequestException on failure."""
    from .urls import normalize_url
    r = requests.get(AVAIL, params={"url": normalize_url(url).split("://", 1)[-1], "timestamp": "19960101"},
                     timeout=timeout, headers={"User-Agent": "qurihunter (bug bounty discovery)"})
    if r.status_code != 200:
        raise requests.RequestException(f"availability HTTP {r.status_code}")
    snap = ((r.json() or {}).get("archived_snapshots") or {}).get("closest") or {}
    return snap.get("timestamp")


def _check(url: str, timeout: float) -> tuple[str | None, str]:
    """(timestamp-or-None, how). CDX first; if the archive is slow, the availability API as a lighter fallback.
    Raises when both fail."""
    from . import dblock
    dblock.flush()
    try:
        return lookup(url, timeout), "cdx"
    except Exception as e1:  # noqa: BLE001
        try:
            return available(url, min(timeout, 10)), "availability"
        except Exception as e2:  # noqa: BLE001
            raise requests.RequestException(f"cdx: {e1}; availability: {e2}") from e2


def prefetch(urls: list[str], cfg: dict) -> dict:
    """Run lookups for `urls` with wayback.concurrency workers (default 1 = sequential, polite). Pure network, no DB
    access, so it is safe in threads. Returns {url: ('ok', ts|None, how) | ('err', message)}."""
    from concurrent.futures import ThreadPoolExecutor
    wb = cfg.get("wayback", {})
    n = max(1, min(8, int(wb.get("concurrency", 1))))
    to = float(wb.get("timeout", 20))

    def one(u):
        try:
            ts, how = _check(u, to)
            return u, ("ok", ts, how)
        except Exception as e:  # noqa: BLE001
            return u, ("err", str(e))
    with ThreadPoolExecutor(max_workers=n) as ex:
        return dict(ex.map(one, urls))


def first_capture(db: DB, url: str, cfg: dict, *, budget: dict | None = None, pre: dict | None = None) -> tuple[str, str | None]:
    """(state, first_capture_iso). state: none | old | recent | error | skipped. `old` = first archived before the
    recency window. Cached forever when conclusive."""
    global _last_call, _fails
    wb = cfg.get("wayback", {})
    if not wb.get("enabled", True):
        return "skipped", None
    from .config import recency_days
    h = url_hash(url)
    row = db.c.execute("SELECT * FROM wayback WHERE url_hash=?", (h,)).fetchone()
    if row and row["status"] in ("none", "found"):
        return _state(row["first_capture"], recency_days(cfg))
    if budget is not None and budget.get("left", 1) <= 0:
        return "skipped", None
    if _fails >= BREAKER:
        return "skipped", None  # archive is down: stop burning time this scan
    if budget is not None:
        budget["left"] = budget.get("left", 0) - 1
    try:
        if pre is not None and url in pre:
            res = pre[url]
            if res[0] == "err":
                raise requests.RequestException(res[1])
            ts = res[1]
        else:
            wait = float(wb.get("min_interval_s", 1.0)) - (time.time() - _last_call)
            if wait > 0:
                time.sleep(wait)
            _last_call = time.time()
            ts, _how = _check(url, float(wb.get("timeout", 20)))
    except Exception as e:  # noqa: BLE001 — Wayback is best-effort
        log.warning("wayback lookup failed for %s: %s", redact(url), redact(e))
        db.net_stat("wayback", ok=False, error=str(e))
        db.commit()
        _fails += 1
        return "error", None
    _fails = 0
    db.net_stat("wayback", ok=True)
    first = None
    if ts:
        try:
            first = dates.iso(datetime.strptime(ts[:14].ljust(14, "0"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc))
        except ValueError:
            first = None
    db.c.execute("INSERT OR REPLACE INTO wayback VALUES(?,?,?,?,?)",
                 (h, url, first, "found" if first else "none", dates.now_iso()))
    db.commit()  # short transaction: committed before the next lookup
    return _state(first, recency_days(cfg))


def _state(first: str | None, days) -> tuple[str, str | None]:
    if not first:
        return "none", None
    return ("recent" if dates.in_window(first, days) else "old"), first
