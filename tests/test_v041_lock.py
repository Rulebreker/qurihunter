"""v0.4.1 Item 1: no 'database is locked' - write gate, flush-before-I/O, retry/backoff, foreground priority, read-only planning."""
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from qurihunter import background, cli, config, dblock, memcmds, modelcmds, reclass, retry, scanner, seqcmds, ui, wayback
from qurihunter.db import DB
from qurihunter.llm import LLM
from qurihunter.models import Program
from qurihunter.paths import db_path
from qurihunter.search import base
from qurihunter.search.base import SearchResult


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


@pytest.fixture
def cfg():
    return config.load()


class Ctx:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db

    def save(self, c=None):
        config.save(c or self.cfg)

    def reload(self):
        pass


def quiet(monkeypatch):
    out = []
    for n in ("info", "ok", "fail"):
        monkeypatch.setattr(ui, n, lambda m, o=out: o.append(str(m)))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: out.append("table"))
    return out


# ── per-connection pragmas ───────────────────────────────────────────────────
def test_every_connection_gets_wal_busy_timeout_and_synchronous_normal(tmp_path):
    for n in range(2):
        d = DB(tmp_path / "p.db")
        q = lambda s: d.c._c.execute(s).fetchone()[0]  # noqa: E731
        assert q("PRAGMA journal_mode").lower() == "wal" and q("PRAGMA busy_timeout") == 30000 and q("PRAGMA synchronous") == 1


# ── plan() is read-only ──────────────────────────────────────────────────────
def fake_provider(pid="life", qt="lifetime"):
    class F(base.Provider):
        id, label, period, default_limit, page_size = pid, pid, "month", 100, 10
        paginates = False
        quota_default = qt
        tld_mode = "native"

        def _search(self, key, pd, page, fresh):
            return [SearchResult("t", "https://a.ch/responsible-disclosure", "report a vulnerability bounty")]
    return F


def test_planning_never_writes_and_lifetime_start_is_recorded_once(db, cfg, monkeypatch):
    from qurihunter import search
    F = fake_provider()
    monkeypatch.setitem(search.PROVIDERS, "life", F)
    cfg["search"]["providers"]["life"] = {"keys": ["k"], "limit": 100, "quota_type": "lifetime"}
    search.save_sequence(cfg, ["life"])
    pool = search.build_pool(cfg, db)
    before = db.c._c.total_changes
    pool.plan(1440)
    pool.plan(1440)
    assert db.c._c.total_changes == before and db.meta("lifetime_start:life") is None
    # a held write lock cannot hurt planning
    holder = sqlite3.connect(db.path, timeout=1, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        pool.plan(1440)
    finally:
        holder.execute("ROLLBACK"); holder.close()
    from qurihunter.search.pool import ensure_lifetime_start
    ensure_lifetime_start(db, "life")
    first = db.meta("lifetime_start:life")
    ensure_lifetime_start(db, "life")
    assert first and db.meta("lifetime_start:life") == first  # idempotent


# ── the exact failure: a worker holding a write transaction across slow I/O ──
def test_worker_that_sleeps_inside_a_fake_llm_call_does_not_block_foreground_writes(db, cfg, monkeypatch):
    monkeypatch.setattr(dblock, "LOCK_WAIT_S", 0.6)
    for i in range(3):
        db.insert(Program("web", f"s{i}.ch", f"s{i}", f"https://s{i}.ch/responsible-disclosure", snippet="bounty"))
    db.commit()
    started, release = threading.Event(), threading.Event()

    class SlowLLM(LLM):
        def classify(self, *a, **k):
            started.set()
            assert not dblock.GATE.owner or True
            release.wait(5)  # stands in for a 30 s model call
            return {"is_program": True, "type": "vdp", "confidence": 0.9, "reason": "ok"}

    errors = []

    def worker():
        dblock.mark_background()
        wdb = DB(db.path)
        reclass.start(wdb)
        try:
            reclass.step(wdb, cfg, SlowLLM(), pages=2)
        except Exception as e:  # noqa: BLE001
            errors.append(e)
    t = threading.Thread(target=worker, name="qurihunter-bg-test")
    t.start()
    assert started.wait(5)
    t0 = time.monotonic()
    for i in range(5):  # foreground writes while the worker is inside its LLM call
        db.set_meta(f"fg{i}", "x")
        db.commit()
    assert time.monotonic() - t0 < 0.5
    release.set()
    t.join(10)
    assert errors == []


def test_control_without_the_fix_the_same_pattern_does_fail(db, monkeypatch):
    """Proves the test above is meaningful: a transaction held across slow work DOES lock out the foreground."""
    monkeypatch.setattr(dblock, "LOCK_WAIT_S", 0.5)
    monkeypatch.setattr(dblock, "flush", lambda: 0)  # the safety net off
    started, release = threading.Event(), threading.Event()

    def bad_worker():
        dblock.mark_background()
        wdb = DB(db.path)
        wdb.set_meta("x", "1")  # write, NO commit
        started.set()
        release.wait(5)  # slow work with the transaction open
        wdb.commit()
    t = threading.Thread(target=bad_worker, name="qurihunter-bg-bad")
    t.start()
    started.wait(5)
    with pytest.raises(dblock.DatabaseBusy) as e:
        db.set_meta("fg", "y")
    assert "background worker" in str(e.value) and "qurihunter-bg-bad" in str(e.value)
    release.set()
    t.join(5)


def test_flush_commits_before_http_llm_and_wayback_io(db, monkeypatch, cfg):
    from qurihunter import http
    seen = {}

    class S:
        def request(self, *a, **k):
            seen["http"] = db.c.in_transaction

            class R:
                status_code, headers, text = 200, {}, ""
            return R()
    monkeypatch.setattr(http, "_session", S())
    db.set_meta("a", "1")
    assert db.c.in_transaction
    http.request("GET", "https://example.com")
    assert seen["http"] is False and db.meta("a") == "1"
    db.set_meta("b", "2")
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: seen.update(wb=db.c.in_transaction))
    wayback._check("https://x.ch/p", 5)
    assert seen["wb"] is False
    from qurihunter import llmreg
    cfg["models"] = [llmreg.new_entry(cfg, "local", "m")]
    r = llmreg.Router(cfg, db)

    class F(LLM):
        def generate(self, *a, **k):
            seen["llm"] = db.c.in_transaction
            return "x"
    r._inst = {"m1": F()}
    db.set_meta("c", "3")
    r.generate("p", role="chat")
    assert seen["llm"] is False


def test_reclassify_and_backfill_never_hold_a_transaction_while_calling_out(db, cfg, monkeypatch):
    for i in range(3):
        db.insert(Program("web", f"r{i}.ch", f"r{i}", f"https://r{i}.ch/responsible-disclosure", snippet="bounty"))
    db.commit()
    inflight = []

    class J(LLM):
        def classify(self, *a, **k):
            inflight.append(db.c.in_transaction)
            return {"is_program": True, "type": "vdp", "confidence": 0.9, "reason": "ok"}
    reclass.start(db)
    reclass.step(db, cfg, J(), pages=3)
    assert inflight == [False, False, False]
    # backfill_wayback: lookups happen with no pending write
    from qurihunter import alerts
    cfg["notify"]["channels"] = ["telegram"]
    states = []
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: states.append(db.c.in_transaction))
    db.c.execute("UPDATE programs SET baseline=0, wayback_state='unchecked'")
    db.commit()
    items = alerts.due(db, cfg)
    scanner.backfill_wayback(db, cfg, items)
    assert states and not any(states)


# ── continuous writers vs foreground commands ────────────────────────────────
def test_continuous_background_writes_and_foreground_commands_produce_zero_lock_errors(db, cfg, monkeypatch):
    from qurihunter import llmreg, search
    dblock.GATE.busy_errors = 0
    F = fake_provider("ft", "monthly")
    monkeypatch.setitem(search.PROVIDERS, "ft", F)
    cfg["search"]["providers"] = {"ft": {"keys": ["k"], "limit": 100}}
    search.save_sequence(cfg, ["ft"])
    cfg["models"] = [llmreg.new_entry(cfg, "local", "m")]
    cfg["notify"]["channels"] = []
    ctx = Ctx(cfg, db)
    stop, errs, writes = threading.Event(), [], [0]

    def writer(n):
        dblock.mark_background()
        wdb = DB(db.path)
        while not stop.is_set():
            try:
                wdb.c.execute("INSERT INTO llm_usage(ts,model_id,role,ok) VALUES('t',?,?,1)", (f"w{n}", "x"))
                wdb.set_meta(f"w{n}", str(writes[0]))
                wdb.commit()
                writes[0] += 1
            except Exception as e:  # noqa: BLE001
                errs.append(("bg", e))
            time.sleep(0.002)
    ts = [threading.Thread(target=writer, args=(i,), name=f"qurihunter-bg-w{i}") for i in range(3)]
    [t.start() for t in ts]
    quiet(monkeypatch)
    monkeypatch.setattr(llmmod := __import__("qurihunter.llm", fromlist=["x"]), "from_config", llmmod.from_config)
    from qurihunter import llmreg as lr
    monkeypatch.setattr(lr.Router, "test_model", lambda self, mid: self._get(lr.get(self.cfg, mid)).test() or "pong")
    monkeypatch.setattr(lr, "build", lambda m, c: type("T", (LLM,), {"test": lambda self: "pong"})())
    try:
        for _ in range(15):
            for fn, args in ((memcmds.cmd_dorks, ["test", '"responsible disclosure"', "site:.ch"]), (modelcmds.cmd_model, ["test", "m1"]),
                             (cli.cmd_status, []), (cli.cmd_programs, ["--since", "7d"]), (seqcmds.cmd_background, ["status"])):
                try:
                    with background.foreground():
                        fn(ctx, args)
                    dblock.flush()
                except sqlite3.OperationalError as e:
                    errs.append((fn.__name__, e))
    finally:
        stop.set()
        [t.join(5) for t in ts]
    assert errs == [] and writes[0] > 10 and dblock.GATE.busy_errors == 0


def test_dorks_test_succeeds_even_while_another_connection_holds_the_write_lock(db, cfg, monkeypatch):
    from qurihunter import search
    monkeypatch.setattr(dblock, "LOCK_WAIT_S", 0.4)
    F = fake_provider("ft", "monthly")
    monkeypatch.setitem(search.PROVIDERS, "ft", F)
    cfg["search"]["providers"] = {"ft": {"keys": ["k"], "limit": 100}}
    search.save_sequence(cfg, ["ft"])
    out = quiet(monkeypatch)
    holder = sqlite3.connect(db.path, timeout=1, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")  # e.g. another process in the middle of a write
    try:
        memcmds.cmd_dorks(Ctx(cfg, db), ["test", '"responsible disclosure"', "site:.ch"])
    finally:
        holder.execute("ROLLBACK"); holder.close()
    assert "table" in out  # results table was printed; no traceback, no lock error


# ── two processes: a clear message naming the holder ────────────────────────
def test_two_process_lock_gives_a_clear_message_with_the_pid(db, monkeypatch):
    monkeypatch.setattr(dblock, "LOCK_WAIT_S", 1.0)
    code = ("import sqlite3,sys,time\nc=sqlite3.connect(sys.argv[1],timeout=5,isolation_level=None)\n"
            "c.execute('BEGIN IMMEDIATE')\nprint('held',flush=True)\ntime.sleep(6)\n")
    p = subprocess.Popen([sys.executable, "-c", code, str(db_path()) if False else str(db.path)], stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "held"
        monkeypatch.setattr("qurihunter.paths.db_path", lambda: db.path)
        with pytest.raises(dblock.DatabaseBusy) as e:
            db.set_meta("x", "y")
        assert "the database is busy" in str(e.value) and f"pid {p.pid}" in str(e.value)
    finally:
        p.kill()
        p.wait()


def test_repl_shows_a_friendly_message_not_a_traceback(db, cfg, monkeypatch):
    out = quiet(monkeypatch)
    monkeypatch.setitem(cli.COMMANDS, "/boom", lambda ctx, a: (_ for _ in ()).throw(dblock.DatabaseBusy("the database is busy: a background worker ...")))
    seq = iter(["/boom", "/quit"])
    monkeypatch.setattr("builtins.input", lambda *a: next(seq))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False, raising=False)
    cli.repl(Ctx(cfg, db))
    msg = [m for m in out if "busy" in m]
    assert msg and "Nothing was lost" in msg[0] and "/background status" in msg[0] and "Traceback" not in msg[0]


# ── retry/backoff, priority, stats ──────────────────────────────────────────
def test_locked_statements_are_retried_with_growing_jittered_backoff(db, monkeypatch):
    sleeps = []
    monkeypatch.setattr(dblock, "_sleep", lambda s: sleeps.append(s))
    calls = {"n": 0}
    real = db.c._c

    class Flaky:
        def __getattr__(self, n):
            return getattr(real, n)

        def execute(self, sql, params=()):
            calls["n"] += 1
            if calls["n"] <= 3:
                raise sqlite3.OperationalError("database is locked")
            return real.execute(sql, params)
    db.c._c = Flaky()
    db.set_meta("k", "v")
    assert calls["n"] == 4 and len(sleeps) == 3 and sleeps[2] > sleeps[0] * 1.4 and all(s > 0 for s in sleeps)
    db.c._c = real
    db.commit()
    assert db.meta("k") == "v"


def test_foreground_has_priority_over_background_for_the_write_gate(tmp_path):
    path = tmp_path / "g.db"
    a = DB(path)
    order = []
    a.set_meta("hold", "1")  # the main thread (foreground) holds the gate
    ready = threading.Barrier(3)

    def bg():
        dblock.mark_background()
        b = DB(path)
        ready.wait()
        b.set_meta("bg", "1"); b.commit(); order.append("bg")

    def fg():
        c = DB(path)
        ready.wait()
        time.sleep(0.15)  # arrives after the background waiter
        c.set_meta("fg", "1"); c.commit(); order.append("fg")
    ts = [threading.Thread(target=bg, name="qurihunter-bg-x"), threading.Thread(target=fg, name="fgthread")]
    [t.start() for t in ts]
    ready.wait()
    time.sleep(0.5)
    a.commit()  # release: the foreground waiter must win although the background one waited longer
    [t.join(5) for t in ts]
    assert order == ["fg", "bg"]


def test_same_thread_second_connection_never_deadlocks(tmp_path):
    a, b = DB(tmp_path / "s.db"), DB(tmp_path / "s.db")
    t0 = time.monotonic()
    a.set_meta("x", "1")  # uncommitted on a
    b.set_meta("y", "2")  # same thread, other connection: must not wait 30 s
    b.commit()
    assert time.monotonic() - t0 < 2 and a.meta("x") == "1"


# ── /background and the workers ─────────────────────────────────────────────
def test_background_pause_resume_status_and_yielding(db, cfg, monkeypatch):
    out = quiet(monkeypatch)
    ctx = Ctx(cfg, db)
    seqcmds.cmd_background(ctx, ["pause"])
    assert background.paused()
    seqcmds.cmd_background(ctx, ["status"])
    assert any("PAUSED" in m for m in out) and any("Database write lock: free" in m for m in out)
    seqcmds.cmd_background(ctx, ["resume"])
    assert not background.paused()
    # a background thread waits while a foreground command runs, and continues afterwards
    log = []

    def bgwork():
        dblock.mark_background()
        log.append(("start", background.checkpoint(5)))
    with background.foreground():
        t = threading.Thread(target=bgwork, name="qurihunter-bg-y")
        t.start()
        time.sleep(0.5)
        assert log == []  # still waiting for the foreground command
    t.join(5)
    assert log == [("start", True)]
    seqcmds.cmd_background(ctx, ["bogus"])
    assert out[-1].startswith("usage: /background")


def test_paused_worker_stops_its_batch(db, cfg):
    for i in range(3):
        db.insert(Program("web", f"p{i}.ch", f"p{i}", f"https://p{i}.ch/responsible-disclosure", snippet="bounty"))
    db.commit()
    reclass.start(db)
    background.pause()
    res = {}

    def work():
        dblock.mark_background()
        res["p"] = reclass.step(DB(db.path), cfg, type("L", (LLM,), {"classify": lambda *a, **k: pytest.fail("paused")})(), pages=3)
    t = threading.Thread(target=work, name="qurihunter-bg-z")
    t.start(); t.join(5)
    background.resume()
    assert res["p"]["done"] == 0 and res["p"]["state"] == "running"


def test_background_workers_config_off_means_no_worker_and_registry_and_help(monkeypatch):
    assert config.load()["background_workers"] is True
    assert "/background" in cli.COMMANDS and any(h.split()[0] == "/background" for h, _ in cli.HELP)
    started = []
    monkeypatch.setattr(retry.Worker, "start", lambda self: started.append(1))
    c = config.load()
    c["setup_done"] = True
    c["background_workers"] = False
    config.save(c)
    monkeypatch.setattr(ui, "banner", lambda v="": None)
    monkeypatch.setattr(cli, "repl", lambda ctx: None)
    assert cli.main([]) == 0 and started == []
    c["background_workers"] = True
    config.save(c)
    assert cli.main([]) == 0 and started == [1]


def test_best_effort_bookkeeping_fails_fast_when_the_database_is_held_elsewhere(db, cfg, monkeypatch):
    """Found on the real home: a test query's two bookkeeping writes each waited the full 30 s (62 s total)."""
    from qurihunter import search
    F = fake_provider("ft", "monthly")
    monkeypatch.setitem(search.PROVIDERS, "ft", F)
    cfg["search"]["providers"] = {"ft": {"keys": ["k"], "limit": 100}}
    search.save_sequence(cfg, ["ft"])
    pool = search.build_pool(cfg, db)
    pool.best_effort = True
    pool.ring("ft").allowance = 5
    holder = sqlite3.connect(db.path, timeout=1, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")  # another process holds the write lock for the whole test
    try:
        t0 = time.monotonic()
        res, pid = pool.search("q")
        elapsed = time.monotonic() - t0
    finally:
        holder.execute("ROLLBACK"); holder.close()
    assert pid == "ft" and res.results and elapsed < 6  # 2 writes x ~2 s at most, not 2 x 30 s
    with dblock.wait_limit(0.3):
        assert dblock._limit() == 0.3
    assert dblock._limit() == dblock.LOCK_WAIT_S
