"""One shared token-bucket limiter per provider, used by EVERY thread (foreground commands, background workers, AI dork
generation) because it lives at module level and is taken inside Provider.search(). 429 / Retry-After push the bucket back."""
from __future__ import annotations

import threading
import time

ENABLED = True
_now = time.monotonic
_sleep = time.sleep
_lock = threading.Lock()
_buckets: dict[str, "Bucket"] = {}


class Bucket:
    """Classic token bucket: `rate` tokens/second, capacity `burst` (default 1: strictly spaced requests)."""

    def __init__(self, rate: float, burst: float = 1.0):
        self.rate, self.capacity = float(rate), float(burst)
        self.tokens, self.stamp, self.blocked_until = float(burst), _now(), 0.0

    def take(self) -> float:
        """Reserve one token; returns how long the caller must wait before it may go (0 = now)."""
        with _lock:
            t = _now()
            self.tokens = min(self.capacity, self.tokens + (t - self.stamp) * self.rate)
            self.stamp = t
            wait = max(0.0, self.blocked_until - t)
            if self.tokens >= 1 and wait == 0:
                self.tokens -= 1
                return 0.0
            need = max(0.0, 1 - self.tokens) / self.rate
            self.tokens -= 1  # reserve now; the debt is paid by waiting
            return max(wait, need)


def bucket(pid: str, qps: float) -> Bucket:
    with _lock:
        b = _buckets.get(pid)
        if b is None or b.rate != qps:
            b = _buckets[pid] = Bucket(qps)
        return b


def acquire(pid: str, qps: float) -> float:
    """Block until `pid` may send another request. Returns the time waited."""
    if not ENABLED or not qps or qps <= 0:
        return 0.0
    w = bucket(pid, qps).take()
    if w > 0:
        _sleep(w)
    return w


def penalize(pid: str, seconds: float) -> None:
    """A 429 / Retry-After: nobody (any thread) sends to this provider for `seconds`."""
    with _lock:
        b = _buckets.get(pid)
        if b is not None:
            b.blocked_until = max(b.blocked_until, _now() + float(seconds))


def reset() -> None:
    with _lock:
        _buckets.clear()
