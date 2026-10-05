"""v0.3.1: provider capabilities + country rewrites, robust AI dork parsing, pending retry/backoff, evidence strength,
background reclassify, status cleanup, single-instance lock."""
import json
from datetime import timedelta

import pytest
import requests

from qurihunter import (aidorks, alertcmds, alerts, cli, config, countries, dates, dorkstore, instance, memcmds, notify,
                        reclass, retry, scanner, search, ui, wayback)
from qurihunter.db import DB
from qurihunter.llm import LLMError, parse_json
from qurihunter.models import Program
from qurihunter.search import base
from qurihunter.search.dorkparse import parse
from qurihunter.search.pool import KeyRing, SearchPool, Unexpressible
from test_v3 import Ctx, Resp, ago, prog  # noqa: F401  (shared helpers)


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


@pytest.fixture
def cfg():
    c = config.load()
    c["notify"]["channels"] = ["telegram"]
    c["notify"]["telegram"] = {"token": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", "chat_id": "42"}
    return c


@pytest.fixture
def ctx(tmp_path, cfg):
    c = Ctx(tmp_path)
    c.cfg = cfg
    return c


class NoTld(base.Provider):  # behaves like Tavily
    id, label, period, default_limit, page_size = "notld", "NoTLD", "month", 1000, 20
    tld_mode = "none"
    paginates = False

    def __init__(self, results=None):
        super().__init__({})
        self.results, self.queries = results or [], []

    def _search(self, key, pd, page, fresh):
        self.queries.append(" ".join(pd.terms()))
        return list(self.results)


class WithTld(NoTld):
    id, label, tld_mode = "withtld", "WithTLD", "native"


# ── 1. capabilities and country dorks ───────────────────────────────────────
def test_capability_table():
    caps = {pid: cls({}).capabilities() for pid, cls in search.PROVIDERS.items()}
    assert caps["tavily"]["supports_tld_filter"] == "no" and caps["brave"]["supports_tld_filter"] == "partial"
    assert caps["google"]["supports_tld_filter"] == "yes" and caps["google"]["supports_inurl"] == "yes"
    assert caps["tavily"]["results_per_query"] == 20 and caps["google"]["results_per_query"] == 10
    for c in caps.values():
        assert {"supports_tld_filter", "supports_site", "supports_inurl", "supports_date_filter", "results_per_query"} <= set(c)


def test_country_dork_is_rewritten_to_natural_language_for_tavily():
    t = search.PROVIDERS["tavily"]({})
    st, q = t.express('"responsible disclosure" site:.ch')
    assert st == "rewritten" and "site:" not in q and "Schweiz" in q and "Schwachstelle melden" in q
    assert "responsible disclosure" in q
    st, q = t.express('"responsible disclosure" site:.se')
    assert q.startswith("Sweden") and "ansvarsfull rapportering sårbarhet" in q
    assert t.translate('"responsible disclosure" site:.ch') != t.translate('"responsible disclosure" site:.de')


def test_capable_providers_run_country_dorks_as_written_and_unknown_tld_is_parked():
    assert search.PROVIDERS["google"]({}).express('"bug bounty" site:.ch')[0] == "ok"
    assert search.PROVIDERS["brave"]({}).express('"bug bounty" site:.ch')[0] == "ok"
    st, why = search.PROVIDERS["tavily"]({}).express('"bug bounty" site:.eu')
    assert st == "parked" and "cannot express site:.eu" in why
    assert search.PROVIDERS["tavily"]({}).express('"bug bounty"')[0] == "ok"


def test_rewritten_search_filters_client_side_on_domain_or_page_text():
    p = NoTld([base.SearchResult("Swiss VDP", "https://acme.ch/vdp", "x"),
               base.SearchResult("Acme", "https://acme.com/security", "Our offices in Switzerland and Austria"),
               base.SearchResult("Other", "https://other.com/vdp", "Report a vulnerability")])
    out = p.search("k", '"responsible disclosure" site:.ch')
    assert [r.url for r in out.results] == ["https://acme.ch/vdp", "https://acme.com/security"]
    assert "site" not in p.queries[0] and "Schweiz" in p.queries[0]
    assert countries.match("ch", "https://x.ch/a") and not countries.match("ch", "https://x.com", "Sweden only")


def test_parked_dork_raises_and_costs_no_quota(db):
    p = NoTld()
    ring = KeyRing(p, ["k"], 10, db)
    with pytest.raises(Unexpressible):
        SearchPool([ring], db).search('"bug bounty" site:.eu')
    assert db.quota_used(ring._kid("k"), p.period_label()) == 0 and p.queries == []


def test_selection_parks_inexpressible_dorks_and_runs_them_when_a_capable_provider_exists(db, cfg):
    dorkstore.add_dork(db, '"responsible disclosure" site:.eu', "default")
    dorkstore.add_dork(db, '"responsible disclosure" site:.ch', "default")
    cfg["dorks"]["source"] = "default"
    sel = dorkstore.select(db, cfg, NoTld(), 500)
    texts = {r["text"] for r in sel.chosen}
    assert sel.parked == 1 and sel.rewritten == 1
    assert '"responsible disclosure" site:.eu' not in texts and '"responsible disclosure" site:.ch' in texts
    sel2 = dorkstore.select(db, cfg, WithTld(), 500)  # a capable provider appears -> parked ones run automatically
    assert sel2.parked == 0 and '"responsible disclosure" site:.eu' in {r["text"] for r in sel2.chosen}


def test_dorks_stats_lists_capabilities_rewritten_and_parked(ctx, monkeypatch):
    dorkstore.ensure_default(ctx.db)
    dorkstore.add_dork(ctx.db, '"responsible disclosure" site:.eu', "default")
    dorkstore.add_dork(ctx.db, '"responsible disclosure" site:.ch', "default")
    ctx.cfg["search"]["providers"] = {"tavily": {"keys": ["tvly-abcdef123456"], "limit": 1000}}
    out, tables = [], []
    monkeypatch.setattr(ui, "info", lambda m: out.append(m))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    memcmds.cmd_dorks(ctx, ["stats"])
    text = " ".join(out)
    assert "1 rewritten" in text and "1 parked" in text and "no quota used" in text
    titles = [getattr(t, "title", "") for t in tables]
    assert "Search provider capabilities" in titles and "Dorks the active provider cannot run verbatim" in titles


def test_scan_does_not_spend_quota_on_parked_dorks_and_reports_them(db, cfg, monkeypatch):
    from rich.progress import Progress
    dorkstore.ensure_default(db)
    db.c.execute("UPDATE dorks SET enabled=0")
    dorkstore.add_dork(db, '"responsible disclosure" site:.eu', "custom")
    cfg["dorks"]["source"] = "custom"
    p = NoTld()
    cfg["search"]["providers"] = {"notld": {"keys": ["k1"], "limit": 1000}}
    monkeypatch.setitem(search.PROVIDERS, "notld", NoTld)
    with Progress() as pr:
        lines = scanner.run_dorks(cfg, db, None, pr, budget=5)
    assert any("1 parked" in l for l in lines)
    assert db.c.execute("SELECT COALESCE(SUM(used),0) FROM quota").fetchone()[0] == 0


# ── 2. AI dork generation reliability ───────────────────────────────────────
def test_parse_json_strips_thinking_and_fences_and_finds_arrays():
    assert parse_json('<think>hmm {"a":1}</think>\n```json\n["x y z","q"]\n```') == ["x y z", "q"]
    assert parse_json('Sure! Here you go:\n[\n "a bug bounty", "b"]\nHope it helps') == ["a bug bounty", "b"]
    assert parse_json('blah {"dorks": [{"text": "t"}]} trailing') == {"dorks": [{"text": "t"}]}
    assert parse_json("no json here") is None


class Seq:
    """LLM returning scripted answers in order; records prompts and json_mode."""
    def __init__(self, *answers):
        self.answers, self.prompts, self.modes = list(answers), [], []

    def generate(self, prompt, *, json_mode=False, timeout=0, system=None):
        self.prompts.append(prompt)
        self.modes.append(json_mode)
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def test_ai_generation_retries_with_strict_prompt(db, cfg):
    llm = Seq("I think you should search for security stuff", json.dumps(["responsible disclosure Schwachstelle melden site:.ch"]))
    rep = aidorks.generate(cfg, db, llm, None, 3)
    assert rep.accepted == 1 and not rep.error
    assert "ONLY a JSON array of 3 strings" in llm.prompts[1] and llm.modes == [True, False]


def test_ai_generation_falls_back_to_line_parser(db, cfg):
    answer = "Here are ideas:\n1. \"bug bounty program\" site:.nl\n- 'vulnerability disclosure policy' inurl:security\n* hello there"
    rep = aidorks.generate(cfg, db, Seq("garbage", answer), None, 3)
    assert rep.accepted == 2 and rep.parsed_via == "line parser" and "parsed via line parser" in rep.text()


def test_ai_generation_failure_message_is_clear_and_scan_survives(db, cfg):
    rep = aidorks.generate(cfg, db, Seq("nope", "still nope"), None, 3)
    assert "no usable dorks after 2 JSON attempts" in rep.error and "JSON list" not in rep.error
    msgs = aidorks.maybe_generate(cfg, db, Seq("x", "y"), None)
    assert msgs and "AI dork generation failed" in msgs[0]
    crash = aidorks.maybe_generate(cfg, db, Seq(RuntimeError("boom")), None)
    assert "skipped" in crash[0]  # never raises into the scan


def test_validator_blocklist_and_budget_still_apply_to_ai_dorks(db, cfg):
    bad = json.dumps(["bug bounty open positions jobs", "exploit database bug bounty", "bug bounty program site:example.com"])
    rep = aidorks.generate(cfg, db, Seq(bad), None, 5)
    assert rep.accepted == 0 and rep.proposed == 3
    from qurihunter.dorkstore import select
    for i in range(10):
        dorkstore.add_dork(db, f"bug bounty program variant{i} word{i}", "ai")
    cfg["features"]["ai_dorks"] = True
    prov = NoTld()
    sel = select(db, cfg, prov, 10)
    assert sel.explore <= int(cfg["dorks"]["ai_share"] * 10)


# ── 3. pending retry, backoff, pending-by-reason ────────────────────────────
def waiting_row(db, key="a"):
    return prog(db, key)  # undated web row, wayback 'unchecked'


def test_pending_reasons_split_waiting_failed_and_ready(db, cfg):
    waiting_row(db, "w")
    prog(db, "r", launched=ago(1), date_kind="published")
    r = alerts.pending_reasons(db, cfg)
    assert r == {"waiting for archive (Wayback) verification": 1, "ready - goes out on the next scan/retry": 1}
    db.log_alert("telegram", False, "boom", 0, 0)
    assert "last send failed - will retry" in alerts.pending_reasons(db, cfg)


def test_retry_backoff_is_exponential_resets_on_progress_and_respects_daily_cap(db, cfg, monkeypatch):
    waiting_row(db)
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: (_ for _ in ()).throw(requests.ConnectionError("down")))
    monkeypatch.setattr(notify, "request", lambda *a, **k: Resp(200))
    now = dates.utcnow()
    assert "no progress; next in 10 min" in retry.tick(db, cfg, now)  # streak 1 -> 5*2
    assert retry.tick(db, cfg, now + timedelta(minutes=5)) is None  # still backing off
    wayback.reset()
    assert "next in 20 min" in retry.tick(db, cfg, now + timedelta(minutes=11))
    assert db.meta("retry_count") == "2"
    # archive recovers -> progress, streak reset
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: None)
    wayback.reset()
    msg = retry.tick(db, cfg, now + timedelta(minutes=40))
    assert "made progress" in msg and db.meta("retry_streak") == "0"
    assert db.c.execute("SELECT COUNT(*) FROM deliveries WHERE channel='telegram'").fetchone()[0] == 1
    # nothing pending anymore -> no retry
    assert retry.tick(db, cfg, now + timedelta(hours=2)) is None


def test_retry_daily_cap_and_off_switch(db, cfg, monkeypatch):
    waiting_row(db)
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: (_ for _ in ()).throw(requests.ConnectionError("down")))
    cfg["pending"]["retry_max_per_day"] = 1
    now = dates.utcnow()
    assert retry.tick(db, cfg, now)
    assert retry.tick(db, cfg, now + timedelta(hours=12)) is None  # cap reached
    cfg["pending"]["retry_enabled"] = False
    assert retry.tick(db, cfg, now + timedelta(days=1)) is None


def test_retry_skips_while_a_scan_holds_the_lock(db, cfg, monkeypatch):
    waiting_row(db)
    monkeypatch.setattr(scanner, "retry_pending", lambda c, d: (_ for _ in ()).throw(scanner.ScanLocked("busy")))
    assert retry.tick(db, cfg) is None and db.meta("retry_count") == "0"


def test_worker_thread_runs_ticks_and_survives_errors(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(retry, "tick", lambda db, cfg, now=None: calls.append(1) or (_ for _ in ()).throw(RuntimeError("x")))
    cfgd = config.load()
    cfgd["pending"]["check_every_s"] = 0.01
    monkeypatch.setattr(config, "load", lambda: cfgd)
    w = retry.Worker(extra=[lambda db, cfg: calls.append("job")])
    w.start()
    import time
    for _ in range(100):
        if len(calls) >= 4:
            break
        time.sleep(0.02)
    w.stop()
    assert 1 in calls  # ticked and kept going after an exception


def test_baseline_legacy_dry_run_confirm_and_sample(ctx, monkeypatch):
    db = ctx.db
    ids = [prog(db, f"l{i}") for i in range(14)]
    db.c.execute("UPDATE programs SET legacy_migrated=1")
    keep = prog(db, "dated", launched=ago(1), date_kind="published")
    db.c.execute("UPDATE programs SET legacy_migrated=1 WHERE id=?", (keep,))
    db.commit()
    tables = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    monkeypatch.setattr(ui, "yn", lambda q, d=True: pytest.fail("dry run must not ask"))
    alertcmds.cmd_alerts(ctx, ["baseline-legacy", "--dry-run"])
    assert tables[0].row_count == 10 and "14 legacy" in tables[0].title
    assert db.c.execute("SELECT COUNT(*) FROM programs WHERE baseline=1").fetchone()[0] == 0
    monkeypatch.setattr(ui, "yn", lambda q, d=True: False)
    alertcmds.cmd_alerts(ctx, ["baseline-legacy"])
    assert db.c.execute("SELECT COUNT(*) FROM programs WHERE baseline=1").fetchone()[0] == 0
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    alertcmds.cmd_alerts(ctx, ["baseline-legacy"])
    assert db.c.execute("SELECT COUNT(*) FROM programs WHERE baseline=1").fetchone()[0] == 14  # dated row untouched
    assert [r["id"] for r, _ in alerts.due(db, ctx.cfg)] == [keep]


def test_release_pending_sends_labelled_unverified_after_confirmation(ctx, monkeypatch):
    for k in "abc":
        waiting_row(ctx.db, k)
    sent = []
    monkeypatch.setattr(notify, "request", lambda m, u, **k: sent.append(k["json"]["text"]) or Resp(200))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    monkeypatch.setattr(ui, "yn", lambda q, d=True: False)
    alertcmds.cmd_alerts(ctx, ["release-pending", "2"])
    assert sent == []
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    alertcmds.cmd_alerts(ctx, ["release-pending", "2"])
    assert len(sent) == 1 and "NEW — age unverified (2)" in sent[0] and "Basis: age unverified" in sent[0]
    assert ctx.db.c.execute("SELECT COUNT(*) FROM deliveries WHERE channel='telegram'").fetchone()[0] == 2
    assert len(alerts.due(ctx.db, ctx.cfg)) == 1  # the third still waits


def test_on_error_default_is_defer(cfg):
    assert cfg["wayback"]["on_error"] == "wait" and cfg["wayback"]["concurrency"] == 1 and cfg["wayback"]["timeout"] == 20


def test_wayback_availability_api_is_the_lighter_second_check(db, cfg, monkeypatch):
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: (_ for _ in ()).throw(requests.ConnectionError("cdx slow")))
    monkeypatch.setattr(wayback, "available", lambda url, timeout=10: "20190305000000")
    assert wayback.first_capture(db, "https://a.ch/p", cfg)[0] == "old"
    monkeypatch.setattr(wayback, "available", lambda url, timeout=10: None)  # 'no snapshot' answer is conclusive too
    assert wayback.first_capture(db, "https://b.ch/p", cfg) == ("none", None)
    monkeypatch.setattr(wayback, "available", lambda url, timeout=10: (_ for _ in ()).throw(requests.ConnectionError("down")))
    wayback.reset()
    assert wayback.first_capture(db, "https://c.ch/p", cfg)[0] == "error"
    assert wayback.first_capture(db, "https://a.ch/p", cfg)[0] == "old"  # cached forever


def test_wayback_concurrency_prefetches_in_parallel(db, cfg, monkeypatch):
    import threading
    cfg["wayback"]["concurrency"] = 4
    seen = set()
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: seen.add(threading.current_thread().name) or "20180101000000")
    ids = [waiting_row(db, f"c{i}") for i in range(6)]
    monkeypatch.setattr(notify, "request", lambda *a, **k: Resp(200))
    scanner.reset_run()
    scanner.enrich_and_notify(cfg, db, None)
    assert all(db.program(i)["wayback_state"] == "old" and db.program(i)["baseline"] == 1 for i in ids)
    assert len(seen) >= 1


# ── 4. honest evidence ──────────────────────────────────────────────────────
def test_basis_labels(db):
    r = prog(db, "p", launched=ago(1), date_kind="published")
    db.c.execute("UPDATE programs SET launched_at_source='page_date' WHERE id=?", (r,))
    assert alerts.basis(db.program(r)) == ("published date", False)
    db.c.execute("UPDATE programs SET launched_at_source='source' WHERE id=?", (r,))
    assert alerts.basis(db.program(r)) == ("launch date from source", False)
    db.c.execute("UPDATE programs SET launched_at_source='source_first_seen' WHERE id=?", (r,))
    assert alerts.basis(db.program(r)) == ("first seen by source crawler (weak)", True)
    w = prog(db, "w", wayback=("recent", ago(2)))
    assert alerts.basis(db.program(w)) == ("first archived inside window", False)
    n = prog(db, "n", wayback=("none", None))
    assert alerts.basis(db.program(n)) == ("first seen by this tool (weak)", True)


def test_weak_evidence_gets_its_own_section_and_can_be_switched_off(db, cfg):
    strong = prog(db, "s", launched=ago(1), date_kind="published")
    db.c.execute("UPDATE programs SET launched_at_source='page_date' WHERE id=?", (strong,))
    weak = prog(db, "w", wayback=("none", None))
    db.commit()
    due = alerts.due(db, cfg)
    assert [r["id"] for r, _ in due] == [strong, weak]  # strong first
    m = notify.build(due, 7)[0].plain
    assert m.index("NEW (1)") < m.index("NEW (weak evidence) (1)")
    assert "Basis: published date" in m and "Basis: first seen by this tool (weak)" in m
    cfg["alerts"]["alert_weak_evidence"] = False
    assert [r["id"] for r, _ in alerts.due(db, cfg)] == [strong]
    assert "NOT alerted: alert_weak_evidence is off" in "\n".join(alertcmds.explain(db, cfg, db.program(weak)))
    cfg["alerts"]["alert_weak_evidence"] = True
    assert "basis: first seen by this tool (weak)" in "\n".join(alertcmds.explain(db, cfg, db.program(weak)))


# ── 5. background reclassify ────────────────────────────────────────────────
class Judge:
    def __init__(self, verdicts):
        self.v, self.n = verdicts, 0

    def classify(self, url, title, snippet, page_text=""):
        self.n += 1
        ok = self.v.get(url, True)
        return {"is_program": ok, "type": "vdp", "confidence": 0.9, "reason": "official page" if ok else "an article"}


def seed_web(db, n_good=3, n_llm_bad=1, n_hard_bad=2):
    for i in range(n_good):
        db.insert(Program("web", f"good{i}.ch", f"good{i}", f"https://good{i}.ch/responsible-disclosure",
                          snippet="report a vulnerability bounty"))
    for i in range(n_llm_bad):
        db.insert(Program("web", f"meh{i}.ch", f"meh{i}", f"https://meh{i}.ch/security/bug-bounty-explained",
                          snippet="report a vulnerability bounty"))
    for i in range(n_hard_bad):
        db.insert(Program("web", f"news{i}.com", f"news{i}", f"https://news{i}.com/news/bug-bounty-{i}"))
    db.commit()


def test_reclassify_is_resumable_capped_alert_free_and_needs_no_scan_lock(db, cfg, monkeypatch):
    seed_web(db)
    monkeypatch.setattr(notify, "request", lambda *a, **k: pytest.fail("reclassify must never send anything"))
    judge = Judge({"https://meh0.ch/security/bug-bounty-explained": False})
    assert reclass.start(db) == 6
    p = reclass.step(db, cfg, judge, pages=2)  # hard rules are free; 2 LLM judgements this cycle
    assert judge.n == 2 and p["done"] == 2 + 2 and p["state"] == "running" and p["rejected"] == 2
    # a scan holds the lock: reclassify still advances (it never takes it)
    from qurihunter.paths import lock_path
    lock_path().write_text(str(__import__("os").getpid()))
    p = reclass.step(db, cfg, judge, pages=2)
    lock_path().unlink()
    assert judge.n == 4 and p["state"] == "done" and p["done"] == 6 and p["rejected"] == 3
    assert db.c.execute("SELECT COUNT(*) FROM programs WHERE verdict='not_program'").fetchone()[0] == 0  # nothing hidden yet
    assert reclass.apply(db) == 3 and reclass.state(db) == "applied"
    assert db.seen("https://meh0.ch/security/bug-bounty-explained")["verdict"] == "not_program"


def test_reclassify_resumes_after_restart_and_uses_cap_from_config(tmp_path, cfg):
    d1 = DB(tmp_path / "r.db")
    seed_web(d1, n_good=5, n_llm_bad=0, n_hard_bad=0)
    cfg["reclassify"]["pages_per_cycle"] = 2
    reclass.start(d1)
    reclass.step(d1, cfg, Judge({}))
    d1.c.close()
    d2 = DB(tmp_path / "r.db")  # "restart"
    assert reclass.progress(d2)["done"] == 2 and reclass.state(d2) == "running"
    reclass.step(d2, cfg, Judge({}))
    reclass.step(d2, cfg, Judge({}))
    assert reclass.progress(d2)["state"] == "done"


def test_reclassify_command_background_status_review_and_finish_report(ctx, monkeypatch):
    seed_web(ctx.db)
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    info = []
    monkeypatch.setattr(ui, "info", lambda m: info.append(m))
    monkeypatch.setattr(memcmds, "report_if_finished", memcmds.report_if_finished)
    import qurihunter.llm as llmmod
    monkeypatch.setattr(llmmod, "from_config", lambda c, db=None: None)
    memcmds.cmd_memory(ctx, ["reclassify"])
    assert any("Queued 6" in m and "never sends alerts" in m for m in info)
    assert reclass.state(ctx.db) == "done"  # no LLM: hard rules judged some, the rest kept instantly
    info.clear()
    memcmds.report_if_finished(ctx.db)
    assert any("finished" in m for m in info)
    info.clear()
    memcmds.report_if_finished(ctx.db)  # reported once only
    assert info == []
    monkeypatch.setattr(ui, "yn", lambda q, d=True: False)
    memcmds.cmd_memory(ctx, ["reclassify", "review"])
    assert ctx.db.c.execute("SELECT COUNT(*) FROM programs WHERE verdict='not_program'").fetchone()[0] == 0
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    memcmds.cmd_memory(ctx, ["reclassify", "apply"])
    assert ctx.db.c.execute("SELECT COUNT(*) FROM programs WHERE verdict='not_program'").fetchone()[0] == 2


def test_reclassify_progress_appears_in_status(ctx, monkeypatch):
    seed_web(ctx.db)
    reclass.start(ctx.db)
    reclass.step(ctx.db, ctx.cfg, None, pages=0)
    out = []
    monkeypatch.setattr(ui, "info", lambda m: out.append(m))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    cli.cmd_status(ctx, [])
    assert any(m.startswith("Reclassify (background)") for m in out)


# ── 6. /status cleanup ──────────────────────────────────────────────────────
def test_status_network_table_shows_only_api_hosts_unless_all_hosts(ctx, monkeypatch):
    for name, fails in (("tavily.com", 1), ("telegram.org", 0), ("wayback", 2), ("search.brave.com", 0), ("localhost", 0),
                        ("random-blog.com", 1), ("another.io", 0)):
        ctx.db.c.execute("INSERT INTO net_stats(name,ok,retries,failures,last_error,last_at) VALUES(?,?,?,?,?,?)",
                         (name, 3, 1, fails, "boom" if fails else None, dates.now_iso()))
    tables = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    monkeypatch.setattr(ui, "info", lambda m: None)
    cli._network_table(ctx, False)
    t = tables[-1]
    names = [c for c in t.columns[0]._cells]
    assert any("Tavily" in n for n in names) and any("Wayback" in n for n in names) and any("2 other hosts" in n for n in names)
    assert not any("random-blog" in n for n in names)
    assert [c.header for c in t.columns] == ["Service", "OK", "Retries", "Failures", "Last error"]
    cli._network_table(ctx, True)
    assert any("random-blog.com" in n for n in tables[-1].columns[0]._cells)


# ── 7. single instance ──────────────────────────────────────────────────────
def test_instance_lock_refuses_second_live_instance_ignores_stale_and_force_overrides(monkeypatch):
    import os
    monkeypatch.setattr(instance, "_alive", lambda pid: pid == 4242)
    ok, msg = instance.acquire()
    assert ok and instance.holder() is None  # we hold it; holder() excludes ourselves
    instance.instance_path().write_text(json.dumps({"pid": 4242, "started": "2026-10-05T10:00:00+00:00"}))
    ok, msg = instance.acquire()
    assert not ok and "pid 4242" in msg and "--force" in msg
    ok, _ = instance.acquire(force=True)
    assert ok and json.loads(instance.instance_path().read_text())["pid"] == os.getpid()
    instance.instance_path().write_text(json.dumps({"pid": 999999, "started": "x"}))  # stale
    assert instance.holder() is None and instance.acquire()[0]
    instance.release()
    assert not instance.instance_path().exists()


def test_other_processes_produce_a_startup_warning(monkeypatch):
    monkeypatch.setattr(instance, "others", lambda: [(161121, "2026-10-05T17:10:00+00:00")])
    w = instance.warnings()
    assert w and "161121" in w[0] and "OLD code" in w[0]
    monkeypatch.setattr(instance, "others", lambda: [])
    assert instance.warnings() == []


def test_main_refuses_to_start_when_another_instance_holds_the_lock(monkeypatch, tmp_path):
    monkeypatch.setattr(instance, "holder", lambda: {"pid": 77, "started": "t"})
    cfgd = config.load()
    cfgd["setup_done"] = True
    config.save(cfgd)
    out = []
    monkeypatch.setattr(ui, "fail", lambda m: out.append(m))
    monkeypatch.setattr(ui, "banner", lambda v="": None)
    monkeypatch.setattr(retry.Worker, "start", lambda self: pytest.fail("must not start"))
    assert cli.main([]) == 1
    assert any("already running" in m and "pid 77" in m for m in out)
    assert cli.main(["status"]) == 0  # one-shot commands don't need the instance lock


# ── help / registry ─────────────────────────────────────────────────────────
def test_help_mentions_new_subcommands():
    txt = " ".join(f"{c} {d}" for c, d in cli.HELP)
    for w in ("baseline-legacy", "release-pending", "status | pending | resend", "reclassify"):
        assert w in txt or w in alertcmds.USAGE
