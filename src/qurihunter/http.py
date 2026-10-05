from __future__ import annotations

import re
import time

import requests

from . import __version__
from .logs import log

_session = requests.Session()
_session.headers["User-Agent"] = f"qurihunter/{__version__} (+bug bounty program discovery)"

RETRY_STATUS = {429, 500, 502, 503, 504, 529}  # 529 = Anthropic 'overloaded'
_SECRETS = [(re.compile(r"(bot)\d{5,}:[A-Za-z0-9_-]{20,}"), r"\1***"),
            (re.compile(r"((?:api[_-]?key|key|token|access_token)=)[^&\s'\"]+", re.I), r"\1***"),
            (re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.I), r"\1***"),
            (re.compile(r"\b(sk|tvly|BSA)[-_][A-Za-z0-9_-]{10,}"), r"\1-***")]


def redact(text) -> str:
    """Strip tokens/keys from any string before it is logged or shown (Telegram tokens live in URLs)."""
    t = str(text)
    for rx, rep in _SECRETS:
        t = rx.sub(rep, t)
    return t


_STATS: dict[str, dict] = {}


def _stat(url: str, key: str, err=None) -> None:
    from urllib.parse import urlsplit
    host = (urlsplit(url).hostname or "?").removeprefix("api.").removeprefix("web.")
    st = _STATS.setdefault(host, {"ok": 0, "retries": 0, "failures": 0, "last_error": None})
    st[key] += 1
    if err is not None:
        st["last_error"] = redact(err)[:200]


def drain_stats() -> dict[str, dict]:
    """Per-host counters since the last drain (ok / retries / failures); scan() persists them for /status."""
    out = {k: dict(v) for k, v in _STATS.items()}
    _STATS.clear()
    return out


def request(method: str, url: str, *, retries: int = 4, timeout: float = 30,
            backoff: float = 1.5, retry_429: bool = True, **kw) -> requests.Response:
    """HTTP with exponential backoff; honours Retry-After. Returns the last response
    for HTTP errors (caller decides), raises only on persistent network failure."""
    from . import dblock
    dblock.flush()  # never hold a database write lock across a network call
    delay = backoff
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            r = _session.request(method, url, timeout=timeout, **kw)
        except requests.RequestException as e:
            last_exc = e
            _stat(url, "retries", e)
            log.warning("%s %s failed (%s), attempt %d", method, redact(url), redact(e), attempt + 1)
        else:
            if r.status_code not in RETRY_STATUS or (r.status_code == 429 and not retry_429):
                _stat(url, "ok" if r.status_code < 400 else "failures", None if r.status_code < 400 else f"HTTP {r.status_code}")
                return r
            if attempt == retries:
                _stat(url, "failures", f"HTTP {r.status_code}")
                return r
            _stat(url, "retries", f"HTTP {r.status_code}")
            ra = r.headers.get("Retry-After", "")
            wait = float(ra) if ra.replace(".", "", 1).isdigit() else delay
            log.warning("%s %s -> %d, retrying in %.1fs", method, redact(url), r.status_code, wait)
            time.sleep(min(wait, 60))
            delay *= 2
            continue
        if attempt == retries:
            break
        time.sleep(delay)
        delay *= 2
    _stat(url, "failures", last_exc)
    raise last_exc or RuntimeError("request failed")


def get(url: str, **kw) -> requests.Response:
    return request("GET", url, **kw)
