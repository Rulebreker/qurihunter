"""Write discipline for the shared SQLite file.

Root cause of the "database is locked" errors seen in v0.4: a background worker updated a row and then called the LLM / the
network *before committing*. Python's sqlite3 opens an implicit write transaction at the first INSERT/UPDATE/DELETE and keeps it
(and SQLite's single write lock) until commit(), so every other connection - the foreground command, the worker's own usage
logger, the pending-retry worker - waited out the 30 s busy timeout and failed.

Defences, in layers:
 1. every connection: WAL, synchronous=NORMAL, busy_timeout 30 s (set per connection);
 2. `Conn` proxy: ONE in-process write gate (a transaction-level lock with foreground priority), automatic retry with jittered
    backoff on "locked/busy", and a friendly DatabaseBusy (who holds it, for how long) instead of a traceback;
 3. `flush()`: any pending write transaction of the current thread is committed before every network / LLM / subprocess call
    (http.request, the model router, the Claude CLI, Wayback), so a transaction can never straddle slow I/O."""
from __future__ import annotations

import random
import sqlite3
import threading
import time
import weakref

LOCK_WAIT_S = 30.0
WRITE_WORDS = {"INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP", "ALTER", "BEGIN", "VACUUM", "REINDEX"}
_tls = threading.local()
_REGISTRY: "weakref.WeakSet[Conn]" = weakref.WeakSet()
_sleep = time.sleep  # patched in tests


class DatabaseBusy(sqlite3.OperationalError):
    """The database stayed locked past the retry window. The message names the holder."""


import contextlib


def _limit() -> float:
    """Longest wait for the lock in THIS thread: LOCK_WAIT_S unless a caller asked for less (best-effort bookkeeping)."""
    v = getattr(_tls, "limit", None)
    return min(LOCK_WAIT_S, v) if v is not None else LOCK_WAIT_S


@contextlib.contextmanager
def wait_limit(seconds: float):
    """Bookkeeping that is nice-to-have (a test query's quota counter) must fail fast instead of waiting 30 s."""
    old = getattr(_tls, "limit", None)
    _tls.limit = seconds
    try:
        yield
    finally:
        _tls.limit = old


def mark_background(on: bool = True) -> None:
    _tls.bg = on


def is_background() -> bool:
    return bool(getattr(_tls, "bg", False)) or threading.current_thread().name.startswith("qurihunter-bg")


class WriteGate:
    """Transaction-level mutex: taken at a connection's first write, released at its commit/rollback. Foreground callers
    take priority over background ones. Statistics feed /background status."""

    def __init__(self):
        self.cv = threading.Condition(threading.Lock())
        self.owner: Conn | None = None
        self.info: tuple[str, bool, float] | None = None  # thread name, background?, since
        self.fg_waiting = 0
        self.waits = 0
        self.longest_wait = 0.0
        self.busy_errors = 0

    def acquire(self, conn: "Conn", timeout: float) -> bool:
        bg = is_background()
        start = time.monotonic()
        with self.cv:
            if not bg:
                self.fg_waiting += 1
            try:
                while True:
                    o = self.owner
                    if o is not None and o is not conn and (o.owner_thread == threading.get_ident() or not o.owner_alive()):
                        o._force_release()  # same thread (idle) or dead thread: never wait on ourselves
                        o = self.owner
                    free = o is None or o is conn
                    if free and (not bg or self.fg_waiting == 0):
                        self.owner, self.info = conn, (threading.current_thread().name, bg, time.monotonic())
                        waited = time.monotonic() - start
                        if waited > 0.05:
                            self.waits += 1
                            self.longest_wait = max(self.longest_wait, waited)
                        return True
                    left = timeout - (time.monotonic() - start)
                    if left <= 0:
                        self.busy_errors += 1
                        return False
                    self.cv.wait(min(left, 0.25))
            finally:
                if not bg:
                    self.fg_waiting -= 1

    def release(self, conn: "Conn") -> None:
        with self.cv:
            if self.owner is conn:
                self.owner, self.info = None, None
                self.cv.notify_all()

    def holder_text(self) -> str:
        with self.cv:
            if self.owner is not None and self.info:
                name, bg, since = self.info
                kind = "a background worker" if bg else "a foreground command"
                return f"{kind} in this program (thread '{name}') has held it for {time.monotonic() - since:.0f} s"
        return other_process_text()


GATE = WriteGate()


def other_process_text() -> str:
    """Who else has the DB file open (another qurihunter process)?"""
    try:
        import os

        import psutil
        from .paths import db_path
        me, path = os.getpid(), str(db_path())
        pids = []
        for p in psutil.process_iter(["pid"]):
            if p.pid == me:
                continue
            try:
                if any(f.path == path for f in p.open_files()):
                    pids.append(p.pid)
            except (psutil.Error, OSError):
                continue
        if pids:
            return "another process has the database open (pid " + ", ".join(map(str, pids)) + ")"
    except Exception:  # noqa: BLE001
        pass
    return "no holder identified (an external tool may have it open)"


def busy_message(conn: "Conn | None" = None) -> str:
    """Who holds the lock. If it is OUR connection that owns the in-process gate, the blocker is another process."""
    if conn is not None and GATE.owner is conn:
        return f"the database is busy: {other_process_text()}"
    return f"the database is busy: {GATE.holder_text()}"


def _locked(e: Exception) -> bool:
    s = str(e).lower()
    return "locked" in s or "busy" in s


class Conn:
    """sqlite3.Connection proxy. Everything not overridden is delegated, so `db.c.execute(...)` works unchanged."""

    def __init__(self, raw: sqlite3.Connection):
        self._c = raw
        self._bt = 30000
        self._holding = False
        self.owner_thread = threading.get_ident()
        self._thread = threading.current_thread()
        _REGISTRY.add(self)

    # ── helpers ────────────────────────────────────────────────────────────────
    def owner_alive(self) -> bool:
        return self._thread.is_alive()

    def _force_release(self) -> None:
        try:
            if self._c.in_transaction:
                self._c.commit()
        except sqlite3.Error:
            pass
        self._holding = False
        GATE.owner, GATE.info = (None, None) if GATE.owner is self else (GATE.owner, GATE.info)

    def _take(self) -> None:
        if not self._holding:
            if not GATE.acquire(self, _limit()):
                raise DatabaseBusy(busy_message(self))
            self._holding = True

    def _done(self) -> None:
        if self._holding:
            self._holding = False
            GATE.release(self)

    def _sync_timeout(self) -> None:
        ms = int(_limit() * 1000)
        if ms != self._bt:  # LOCK_WAIT_S (30 s in production) is the single knob for sqlite's busy timeout too
            self._c.execute(f"PRAGMA busy_timeout={ms}")
            self._bt = ms

    def _retry(self, fn):
        self._sync_timeout()
        deadline = time.monotonic() + _limit()
        delay = 0.05
        while True:
            try:
                return fn()
            except sqlite3.OperationalError as e:
                if not _locked(e) or isinstance(e, DatabaseBusy):
                    raise
                if time.monotonic() >= deadline:
                    GATE.busy_errors += 1
                    raise DatabaseBusy(busy_message(self)) from e
                _sleep(delay + random.uniform(0, delay))  # jittered exponential backoff
                delay = min(delay * 2, 1.0)

    @staticmethod
    def _is_write(sql: str) -> bool:
        w = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        return w in WRITE_WORDS or (w == "PRAGMA" and "=" in sql)

    # ── statements ─────────────────────────────────────────────────────────────
    def execute(self, sql, params=()):
        write = self._is_write(sql)
        if write:
            self._take()
        try:
            return self._retry(lambda: self._c.execute(sql, params))
        except BaseException:
            if write and not self._c.in_transaction:
                self._done()
            raise

    def executemany(self, sql, seq):
        self._take()
        try:
            return self._retry(lambda: self._c.executemany(sql, seq))
        except BaseException:
            if not self._c.in_transaction:
                self._done()
            raise

    def executescript(self, script):
        self._take()
        try:
            return self._retry(lambda: self._c.executescript(script))
        finally:
            if not self._c.in_transaction:
                self._done()

    def commit(self):
        try:
            self._retry(self._c.commit)
        finally:
            if not self._c.in_transaction:
                self._done()

    def rollback(self):
        try:
            self._c.rollback()
        finally:
            self._done()

    def close(self):
        try:
            if self._c.in_transaction:
                self._c.rollback()
        except sqlite3.Error:
            pass
        self._done()
        self._c.close()

    def backup(self, target, **kw):
        return self._c.backup(target, **kw)

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        self.commit() if et is None else self.rollback()
        return False

    @property
    def in_transaction(self) -> bool:
        return self._c.in_transaction

    @property
    def row_factory(self):
        return self._c.row_factory

    @row_factory.setter
    def row_factory(self, v):
        self._c.row_factory = v

    def __getattr__(self, name):  # cursor(), total_changes, create_function ...
        return getattr(self._c, name)


def flush() -> int:
    """Commit every pending write transaction of the CURRENT thread. Called before network / LLM / subprocess I/O so a write
    lock is never held across slow work. Returns how many connections were flushed."""
    n = 0
    me = threading.get_ident()
    for c in list(_REGISTRY):
        try:
            if c.owner_thread == me and c._c.in_transaction:
                c.commit()
                n += 1
        except sqlite3.Error:
            pass
    return n
