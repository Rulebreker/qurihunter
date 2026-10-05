from __future__ import annotations

import contextlib
import hashlib
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .. import dates
from ..db import DB
from ..logs import log
from .base import Page, Provider, ProviderError, Unexpressible


class QuotaExhausted(Exception):
    """No configured provider/key can serve a query right now."""


BREAKER_FAILS = 3  # consecutive failures that open a provider's circuit breaker
BREAKER_OPEN_MIN = {"rate": 5, "blocked": 15, "transient": 10}
LOW_PCT = 15  # warn when a lifetime allowance falls below this share
UNLIMITED = 10**9
UNLIMITED_PER_CYCLE = 200  # rate-limit-only providers: a polite per-cycle cap


def key_id(provider: str, key: str) -> str:
    return hashlib.sha256(f"{provider}:{key}".encode()).hexdigest()[:12]  # raw keys are never stored


@dataclass
class KeyRing:
    """Any number of keys for one provider, used IN THE ORDER ADDED (the next key only when the current one is
    exhausted or invalid), with per-key quota tracking of the provider's quota type."""
    provider: Provider
    keys: list[str]
    limit: int
    db: DB
    allowance: int = 10**9  # per-cycle spending cap set by SearchPool.plan()
    invalid: dict = field(default_factory=dict)
    cooldown: dict = field(default_factory=dict)
    target_days: int = 365  # lifetime allowances are spread over this many days
    key_limit: dict = field(default_factory=dict)  # key_id -> allowance detected from the provider's account endpoint
    daily: dict = field(default_factory=dict)  # key_id -> requests per day (user cap; local midnight reset)

    def __post_init__(self):
        self.keys = list(dict.fromkeys(k.strip() for k in self.keys if k.strip()))

    def _kid(self, key): return key_id(self.provider.id, key)

    @property
    def qtype(self) -> str:
        return self.provider.quota_type()

    @staticmethod
    def day_label() -> str:
        """Local date: a daily cap resets at LOCAL midnight (the same counter table, separate label)."""
        return "D:" + dates.utcnow().astimezone(dates.local_tz()).strftime("%Y-%m-%d")

    def daily_left(self, key: str) -> int | None:
        cap = self.daily.get(self._kid(key))
        if not cap:
            return None
        return max(0, int(cap) - self.db.quota_used(self._kid(key), self.day_label()))

    def period_remaining(self, key: str) -> int:
        kid = self._kid(key)
        if self.qtype == "unlimited":
            return UNLIMITED
        lim = int(self.key_limit.get(kid, self.limit))
        return max(0, lim - self.db.quota_used(kid, self.provider.period_label()))

    def remaining(self, key: str) -> int:
        kid = self._kid(key)
        if kid in self.invalid or self.cooldown.get(kid, 0) > time.time():
            return 0
        r = self.period_remaining(key)
        dl = self.daily_left(key)
        return r if dl is None else min(r, dl)  # a reached daily cap = exhausted until local midnight

    def total_remaining(self) -> int:
        return sum(self.remaining(k) for k in self.keys)

    def pick(self) -> str | None:
        """First key (in the order added) that still has quota."""
        for k in self.keys:
            if self.remaining(k) > 0:
                return k
        return None

    def share_left(self) -> float | None:
        """Fraction of the (lifetime / periodic) allowance still unused, None for unlimited."""
        if self.qtype == "unlimited" or not self.keys:
            return None
        total = sum(int(self.key_limit.get(self._kid(k), self.limit)) for k in self.keys)
        used = sum(self.db.quota_used(self._kid(k), self.provider.period_label()) for k in self.keys)
        return max(0.0, 1 - used / total) if total else 0.0

    def low_warning(self) -> str | None:
        if self.qtype != "lifetime":
            return None
        left = self.share_left()
        if left is not None and left * 100 < LOW_PCT:
            return (f"{self.provider.label}: only {left * 100:.0f}% of the one-time allowance is left "
                    f"({self.total_remaining()} queries) - it never resets")
        return None

    def lifetime_start(self) -> datetime:
        """READ-ONLY (it is called from planning, which must never need the write lock). The marker is written once, at
        key-add time or at scan start, by ensure_lifetime_start(); until then 'now' is used."""
        v = self.db.meta(f"lifetime_start:{self.provider.id}")
        return (dates.parse_date(v) if v else None) or dates.utcnow()


def ensure_lifetime_start(db, provider_id: str) -> None:
    """Idempotent: record when a one-time allowance started being spent."""
    key = f"lifetime_start:{provider_id}"
    if not db.meta(key):
        db.set_meta(key, dates.now_iso())
        db.commit()


class SearchPool:
    def __init__(self, rings: list[KeyRing], db: DB):
        self.rings, self.db = rings, db
        self.fails: dict[str, int] = {}  # consecutive failures per provider (circuit breaker input)
        self.best_effort = False  # /dorks test, /sequence test: bookkeeping writes may be skipped if the DB is busy

    @property
    def n_keys(self) -> int:
        return sum(len(r.keys) for r in self.rings)

    def total_remaining(self) -> int:
        return sum(min(r.total_remaining(), UNLIMITED) if r.qtype != "unlimited" else UNLIMITED_PER_CYCLE
                   for r in self.rings)

    def ring(self, pid: str) -> KeyRing | None:
        return next((r for r in self.rings if r.provider.id == pid), None)

    # ── health / circuit breaker ────────────────────────────────────────────────
    def health(self, pid: str):
        return self.db.c.execute("SELECT * FROM provider_health WHERE provider=?", (pid,)).fetchone()

    def breaker_open(self, pid: str) -> str | None:
        h = self.health(pid)
        if h and h["open_until"] and h["open_until"] > dates.now_iso():
            return h["open_until"]
        return None

    def _record(self, pid: str, ok: bool, error: str = "", kind: str = "") -> None:
        if self.best_effort:
            try:
                from .. import dblock
                with dblock.wait_limit(2.0):  # bookkeeping of a test query: never wait 30 s for it
                    return self._record_now(pid, ok, error, kind)
            except Exception as e:  # noqa: BLE001 - a diagnostic query must not fail because the DB is busy
                log.warning("provider health not recorded (database busy): %s", e)
                return
        return self._record_now(pid, ok, error, kind)

    def _record_now(self, pid: str, ok: bool, error: str = "", kind: str = "") -> None:
        self.db.c.execute("INSERT OR IGNORE INTO provider_health(provider) VALUES(?)", (pid,))
        if ok:
            self.fails[pid] = 0
            self.db.c.execute("UPDATE provider_health SET ok=ok+1, consecutive_fails=0, open_until=NULL, last_ok=? "
                              "WHERE provider=?", (dates.now_iso(), pid))
        else:
            self.fails[pid] = self.fails.get(pid, 0) + 1
            self.db.c.execute("UPDATE provider_health SET failures=failures+1, consecutive_fails=consecutive_fails+1, "
                              "last_error=? WHERE provider=?", (error[:200], pid))
            n = self.db.c.execute("SELECT consecutive_fails FROM provider_health WHERE provider=?", (pid,)).fetchone()[0]
            if kind in BREAKER_OPEN_MIN and n >= BREAKER_FAILS:  # counted in the DB, so it survives new pools/processes
                until = dates.iso(dates.utcnow() + timedelta(minutes=BREAKER_OPEN_MIN[kind]))
                self.db.c.execute("UPDATE provider_health SET open_until=? WHERE provider=?", (until, pid))
        self.db.commit()

    def available(self, pid: str) -> tuple[bool, str]:
        """(usable now?, reason if not)."""
        r = self.ring(pid)
        if r is None:
            return False, "not configured"
        until = self.breaker_open(pid)
        if until:
            return False, f"circuit breaker open until {dates.to_local(until)}"
        if r.pick() is None:
            if r.keys and all(r.period_remaining(k) > 0 and r.daily_left(k) == 0 for k in r.keys if r._kid(k) not in r.invalid):
                return False, "daily cap reached (resumes at local midnight)"
            return False, "no key with quota left" if not r.invalid or len(r.invalid) < len(r.keys) else "all keys invalid"
        if r.allowance <= 0:
            return False, "this cycle's budget is spent"
        return True, ""

    def current(self) -> Provider | None:
        """The provider the next query will go to (first ring that is usable)."""
        for r in self.rings:
            if self.available(r.provider.id)[0]:
                return r.provider
        return None

    def chain(self, dork: str) -> list[Provider]:
        """Providers (in sequence order) that can run `dork` at all, usable or not."""
        return [r.provider for r in self.rings if r.provider.express(dork)[0] != "parked"]

    def plan(self, interval_min: int) -> int:
        """Per-cycle allowance for every ring: remaining quota spread over the cycles left in its window. Lifetime
        allowances are spread over `target_days` (never burned in the first week); unlimited ones get a polite cap."""
        total = 0
        for r in self.rings:
            rem = r.total_remaining()
            if any(r.daily.get(r._kid(k)) for k in r.keys):  # user daily caps: spend today's allowance over today's cycles
                left_today = sum(r.daily_left(k) if r.daily_left(k) is not None else 0 for k in r.keys if r.pick() is not None)
                now_l = dates.utcnow().astimezone(dates.local_tz())
                mins = max(1.0, ((now_l.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)) - now_l).total_seconds() / 60)
                cycles = max(1, math.ceil(mins / max(1, interval_min)))
                r.allowance = min(rem, max(1, math.ceil(left_today / cycles))) if rem and left_today else 0
                total += r.allowance
                w = r.low_warning()
                if w:
                    log.warning(w)
                continue
            if r.qtype == "unlimited":
                r.allowance = UNLIMITED_PER_CYCLE if rem else 0
            elif r.qtype == "lifetime":
                elapsed = (dates.utcnow() - r.lifetime_start()).total_seconds() / 86400
                left_days = max(1.0, r.target_days - elapsed)
                cycles = max(1, math.ceil(left_days * 1440 / max(1, interval_min)))
                r.allowance = min(rem, max(1, math.ceil(rem / cycles))) if rem else 0
            else:
                now = datetime.now(r.provider.period_end().tzinfo)
                mins = max(1.0, (r.provider.period_end() - now).total_seconds() / 60)
                cycles = max(1, math.ceil(mins / max(1, interval_min)))
                r.allowance = min(rem, max(1, math.ceil(rem / cycles))) if rem else 0
            total += r.allowance
            w = r.low_warning()
            if w:
                log.warning(w)
        return total

    def warnings(self) -> list[str]:
        return [w for w in (r.low_warning() for r in self.rings) if w]

    def search(self, dork: str, *, page: int = 0, fresh: str = "", days: float | None = None,
               prefer: str | None = None) -> tuple[Page, str]:
        """Run one query on the first provider with budget, rotating keys. Returns (page, provider_id)."""
        skipped = 0
        for ring in self.rings:
            if prefer and ring.provider.id != prefer:
                continue
            if ring.provider.express(dork)[0] == "parked":
                skipped += 1  # this provider cannot run it; a capable one later in the list may
                continue
            if self.breaker_open(ring.provider.id):
                continue
            while ring.allowance > 0:
                key = ring.pick()
                if not key:
                    break
                kid, period = ring._kid(key), ring.provider.period_label()
                try:
                    res = ring.provider.search(key, dork, page=page, fresh=fresh, days=days)
                except ProviderError as e:
                    log.warning("%s key …%s: %s %s", ring.provider.id, key[-4:], e.kind, e.msg)
                    if e.kind == "rate":
                        from .. import ratelimit
                        ratelimit.penalize(ring.provider.id, e.retry_after or 5.0)  # all threads back off together
                    if e.kind == "quota":
                        self.db.quota_set_exhausted(kid, period, ring.limit)
                    elif e.kind == "invalid":
                        ring.invalid[kid] = e.msg
                    else:
                        ring.cooldown[kid] = time.time() + 120
                    self._record(ring.provider.id, False, e.msg, e.kind if e.kind in BREAKER_OPEN_MIN else "")
                    self.db.commit()
                    continue
                if ring.qtype != "unlimited" or ring.daily.get(kid):
                    try:
                        from .. import dblock
                        with (dblock.wait_limit(2.0) if self.best_effort else contextlib.nullcontext()):
                            if ring.qtype != "unlimited":
                                self.db.quota_add(kid, period)
                            if ring.daily.get(kid):
                                self.db.quota_add(kid, ring.day_label())
                    except Exception as e:  # noqa: BLE001
                        if not self.best_effort:
                            raise
                        log.warning("quota counter not updated (database busy): %s", e)
                self._record(ring.provider.id, True)
                ring.allowance -= 1
                return res, ring.provider.id
        if skipped and skipped == len([r for r in self.rings if not prefer or r.provider.id == prefer]):
            raise Unexpressible("no configured provider can express this dork")
        raise QuotaExhausted("no search provider has budget left")
