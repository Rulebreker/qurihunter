"""v0.4 Parts A+B: Serper/SearXNG/Exa, quota types, ordered sequence, failover/cascade/sweep, resumable cursor."""
import json
from datetime import timedelta

import pytest
import requests
from rich.progress import Progress

from qurihunter import config, dates, dorkstore, scanner, search, seqcmds, sequence, ui
from qurihunter.db import DB
from qurihunter.search import base, exa, searxng, serper
from qurihunter.search.base import ProviderError, SearchResult
from qurihunter.search.dorkparse import parse
from qurihunter.search.pool import KeyRing, SearchPool, UNLIMITED_PER_CYCLE


class Resp:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code, self._b, self.headers = status, body if body is not None else {}, headers or {}
        self.text = text if text is not None else json.dumps(self._b)

    def json(self):
        if isinstance(self._b, Exception):
            raise self._b
        return self._b


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


@pytest.fixture
def cfg():
    c = config.load()
    c["dork_search_recency"]["first"] = "month"
    return c


class Ctx:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db

    def save(self, c=None):
        config.save(c or self.cfg)


# ── A1 Serper ────────────────────────────────────────────────────────────────
def test_serper_recency_maps_to_tbs():
    t = serper.tbs_for
    assert t(1) == "qdr:d" and t(7) == "qdr:w" and t(31) == "qdr:m" and t(365) == "qdr:y" and t(None) is None
    custom = t(10)
    assert custom.startswith("cdr:1,cd_min:") and ",cd_max:" in custom
    assert t(None, "2026-09-01", "2026-09-30") == "cdr:1,cd_min:9/1/2026,cd_max:9/30/2026"


def test_serper_request_passes_operators_through_and_maps_results(monkeypatch):
    seen = {}

    def fake(method, url, **kw):
        seen.update(method=method, url=url, **kw)
        return Resp(200, {"organic": [
            {"title": "T1", "link": "https://a.ch/vdp", "snippet": "s", "date": "Oct 3, 2026"},
            {"title": "T2", "link": "https://b.ch/vdp", "snippet": "s", "date": "3 days ago"},
            {"title": "T3", "link": "https://c.ch/vdp", "snippet": "s"}]})
    monkeypatch.setattr(serper, "request", fake)
    p = serper.Serper({})
    page = p.search("KEY123", 'inurl:security intitle:"bug bounty" site:.ch -site:x.com after:2026-09-01', days=7)
    assert seen["method"] == "POST" and seen["url"] == "https://google.serper.dev/search"
    assert seen["headers"]["X-API-KEY"] == "KEY123"
    assert seen["json"]["q"] == 'inurl:security intitle:"bug bounty" site:.ch -site:x.com'  # operators untouched, date token moved
    assert seen["json"]["num"] == 10 and seen["json"]["page"] == 1 and seen["json"]["tbs"].startswith("cdr:1")
    assert [r.url for r in page.results] == ["https://a.ch/vdp", "https://b.ch/vdp", "https://c.ch/vdp"]
    assert page.results[0].published.startswith("2026-10-03") and page.results[1].published and page.results[2].published is None


@pytest.mark.parametrize("status,body,kind", [(401, {}, "invalid"), (403, {}, "invalid"),
                                              (400, {"message": "Not enough credits"}, "quota"),
                                              (429, {}, "rate"), (500, {}, "transient")])
def test_serper_error_classification(monkeypatch, status, body, kind):
    monkeypatch.setattr(serper, "request", lambda *a, **k: Resp(status, body))
    with pytest.raises(ProviderError) as e:
        serper.Serper({})._search("K", parse("x"), 0, None)
    assert e.value.kind == kind


def test_serper_defaults_to_lifetime_quota_and_full_operators():
    p = serper.Serper({})
    assert p.quota_type() == "lifetime" and p.capabilities()["operators"] == "full" and p.page_size == 10
    assert p.express('"bug bounty" site:.ch')[0] == "ok"


# ── A3 Exa ───────────────────────────────────────────────────────────────────
def test_exa_request_and_country_rewrite(monkeypatch):
    seen = {}
    monkeypatch.setattr(exa, "request", lambda m, u, **kw: seen.update(url=u, **kw) or Resp(
        200, {"results": [{"title": "x", "url": "https://acme.ch/vdp", "publishedDate": "2026-10-02T00:00:00.000Z"}]}))
    page = exa.Exa({}).search("EXAKEY", '"responsible disclosure" site:.ch', days=7)
    assert seen["url"] == "https://api.exa.ai/search" and seen["headers"] == {"x-api-key": "EXAKEY"}
    assert seen["json"]["numResults"] == 10 and "startPublishedDate" in seen["json"]
    assert "Schweiz" in seen["json"]["query"] and "site:" not in seen["json"]["query"]
    assert page.results[0].published.startswith("2026-10-02")


@pytest.mark.parametrize("status,kind", [(401, "invalid"), (402, "quota"), (429, "rate"), (503, "transient")])
def test_exa_errors(monkeypatch, status, kind):
    monkeypatch.setattr(exa, "request", lambda *a, **k: Resp(status, {}))
    with pytest.raises(ProviderError) as e:
        exa.Exa({})._search("K", parse("bug bounty"), 0, None)
    assert e.value.kind == kind


# ── A2 SearXNG ───────────────────────────────────────────────────────────────
def sx(**opts):
    return searxng.SearXNG({"base_url": "http://localhost:8080", **opts})


def test_searxng_json_disabled_explains_how_to_fix(monkeypatch):
    monkeypatch.setattr(searxng, "request", lambda *a, **k: Resp(403, text="Forbidden"))
    with pytest.raises(ProviderError) as e:
        sx()._search("", parse("bug bounty"), 0, None)
    assert e.value.kind == "invalid" and "formats" in e.value.msg and "json" in e.value.msg and "settings.yml" in e.value.msg
    monkeypatch.setattr(searxng.requests, "get", lambda *a, **k: Resp(403))
    ok, msg = sx().probe()
    assert not ok and "json" in msg


def test_searxng_probe_ok_and_not_json(monkeypatch):
    monkeypatch.setattr(searxng.requests, "get", lambda *a, **k: Resp(200, {"results": [1, 2], "unresponsive_engines": [["bing", "CAPTCHA"]]}))
    ok, msg = sx().probe()
    assert ok and "2 results" in msg and "bing: CAPTCHA" in msg
    monkeypatch.setattr(searxng.requests, "get", lambda *a, **k: Resp(200, ValueError("html"), text="<html>"))
    assert not sx().probe()[0]


def test_searxng_captcha_everywhere_is_a_failure_not_zero_results(monkeypatch):
    monkeypatch.setattr(searxng, "request", lambda *a, **k: Resp(200, {"results": [], "unresponsive_engines": [["google", "CAPTCHA"], ["bing", "access denied"]]}))
    with pytest.raises(ProviderError) as e:
        sx()._search("", parse("bug bounty"), 0, None)
    assert e.value.kind == "blocked" and "google: CAPTCHA" in e.value.msg
    # a genuine empty answer (no engine complained) is a real 0-result run
    monkeypatch.setattr(searxng, "request", lambda *a, **k: Resp(200, {"results": [], "unresponsive_engines": []}))
    assert sx()._search("", parse("bug bounty"), 0, None) == []


def test_searxng_engine_circuit_breaker(monkeypatch):
    p = sx(engines="google,bing")
    bad = {"results": [{"title": "t", "url": "https://x.ch", "content": "c", "engine": "bing"}],
           "unresponsive_engines": [["google", "CAPTCHA"]]}
    sent = []
    monkeypatch.setattr(searxng, "request", lambda m, u, **kw: sent.append(kw["params"].get("engines")) or Resp(200, bad))
    for _ in range(searxng.ENGINE_BREAKER):
        assert p._search("", parse("bug bounty"), 0, None)  # partial answers still return results
    assert p._open() == {"google"}
    p._search("", parse("bug bounty"), 0, None)
    assert sent[-1] == "bing"  # the CAPTCHA'd engine is set aside


def test_searxng_time_range_unlimited_quota_and_no_key_needed():
    p = sx()
    assert p.quota_type() == "unlimited" and not p.needs_key and p.missing_options() == []
    assert searxng.SearXNG({}).missing_options() == ["base_url"]


def test_searxng_time_range_param_and_client_side_date_filter(monkeypatch):
    got = {}
    old = dates.iso(dates.utcnow() - timedelta(days=200))
    monkeypatch.setattr(searxng, "request", lambda m, u, **kw: got.update(kw["params"]) or Resp(200, {"results": [
        {"title": "old", "url": "https://o.ch", "content": "", "publishedDate": old, "engine": "x"},
        {"title": "undated", "url": "https://u.ch", "content": "", "engine": "x"}]}))
    page = sx().search("", "bug bounty", days=7)
    assert got["time_range"] == "month" and got["format"] == "json"
    assert [r.url for r in page.results] == ["https://u.ch"]  # undated kept, old dated dropped client-side


# ── quota model ──────────────────────────────────────────────────────────────
def fake_cls(pid, qt="monthly", tld="native", needs_key=True):
    class F(base.Provider):
        id, label, period, default_limit, page_size = pid, pid.title(), "month", 100, 10
        paginates = False
        quota_default = qt
        tld_mode = tld

        def _search(self, key, pd, page, fresh):
            return F.respond(self, key, pd)
        respond = staticmethod(lambda self, key, pd: [])
    F.needs_key = needs_key
    return F


def test_lifetime_quota_never_resets_warns_below_15_percent_and_spreads_over_target(db):
    P = fake_cls("life", "lifetime")
    p = P({"quota_type": "lifetime"})
    ring = KeyRing(p, ["k"], 1000, db, target_days=60)
    assert p.period_label() == "lifetime" and "reset" not in p.reset_text() and p.reset_text().startswith("never")
    pool = SearchPool([ring], db)
    pool.plan(1440)  # one cycle per day
    assert ring.allowance == 17  # 1000 / 60 days, not 1000 in the first week
    db.quota_add(ring._kid("k"), "lifetime", 800)
    assert ring.low_warning() is None  # 20% left
    db.quota_add(ring._kid("k"), "lifetime", 100)
    w = ring.low_warning()
    assert w and "10%" in w and "never resets" in w
    assert ring.remaining("k") == 100 and pool.warnings() == [w]
    # a later day does not refill it
    assert KeyRing(P({"quota_type": "lifetime"}), ["k"], 1000, db).remaining("k") == 100


def test_unlimited_ring_has_polite_cap_and_never_counts_quota(db):
    P = fake_cls("unl", "unlimited")
    ring = KeyRing(P({"quota_type": "unlimited"}), ["unl"], 10**9, db)
    pool = SearchPool([ring], db)
    assert pool.plan(60) == UNLIMITED_PER_CYCLE
    P.respond = staticmethod(lambda self, key, pd: [SearchResult("t", "https://a.ch", "s")])
    pool.search("q")
    assert db.c.execute("SELECT COUNT(*) FROM quota").fetchone()[0] == 0


def test_monthly_and_daily_labels_and_user_override_of_default():
    P = fake_cls("m", "monthly")
    assert len(P({}).period_label()) == 7 and len(P({"quota_type": "daily"}).period_label()) == 10
    assert P({"quota_type": "bogus"}).quota_type() == "monthly"
    assert P({"quota_type": "lifetime"}).quota_type() == "lifetime"  # the user's setting beats the class default


def test_keys_are_used_in_the_order_added_next_only_when_exhausted_or_invalid(db):
    P = fake_cls("ord")
    used = []
    P.respond = staticmethod(lambda self, key, pd: used.append(key) or (_ for _ in ()).throw(ProviderError("invalid", "bad"))
                             if key == "K1" else used.append(key) or [SearchResult("t", "https://a.ch", "s")])
    ring = KeyRing(P({}), ["K1", "K2", "K3"], 2, db)
    pool = SearchPool([ring], db)
    for _ in range(4):
        pool.search("q")
    assert used == ["K1", "K2", "K2", "K3", "K3"]  # K1 invalid once; K2 until its 2 queries are gone; then K3


# ── capability table & default order ─────────────────────────────────────────
def test_capability_table_has_all_columns_for_every_provider():
    for pid, cls in search.PROVIDERS.items():
        c = cls({}).capabilities()
        assert {"operators", "supports_site", "supports_tld_filter", "supports_date_filter", "results_per_query",
                "needs_key", "quota_type"} <= set(c), pid
    assert set(search.PROVIDERS) == {"serper", "serpapi", "tavily", "brave", "google", "exa", "searxng"}
    c = {p: cls({}).capabilities() for p, cls in search.PROVIDERS.items()}
    assert c["serper"]["operators"] == "full" and c["tavily"]["operators"] == "none" and c["searxng"]["needs_key"] == "no"
    assert c["searxng"]["quota_type"] == "unlimited" and c["serper"]["quota_type"] == "lifetime" and c["exa"]["supports_tld_filter"] == "no"


def test_default_order_and_user_order(cfg):
    assert search.DEFAULT_ORDER == ["serper", "serpapi", "tavily", "brave", "google", "exa", "searxng"]
    for pid in ("serper", "tavily", "brave", "exa"):
        cfg["search"]["providers"][pid] = {"keys": ["k-" + pid], "limit": 100}
    cfg["search"]["providers"]["searxng"] = {"base_url": "http://localhost:8080"}
    assert search.configured(cfg) == ["serper", "tavily", "brave", "exa", "searxng"]
    search.save_sequence(cfg, ["exa", "searxng", "tavily"])
    assert search.configured(cfg)[:3] == ["exa", "searxng", "tavily"]
    assert search.sequence_order(cfg)[:3] == ["exa", "searxng", "tavily"] and len(search.sequence_order(cfg)) == 7
    entries = search.sequence_entries(cfg)
    assert entries[0]["provider"] == "exa" and entries[0]["role"] == "primary" and entries[1]["role"] == "fallback"
    assert {"provider", "enabled", "keys", "allowance", "quota_type", "role"} <= set(entries[0])


def test_parked_dorks_are_released_when_a_capable_provider_is_added(db, cfg):
    dorkstore.ensure_default(db)
    db.c.execute("UPDATE dorks SET enabled=0")
    dorkstore.add_dork(db, '"security reward" site:.eu', "custom")
    cfg["dorks"]["source"] = "custom"
    tav = search.PROVIDERS["tavily"]({})
    sel = dorkstore.select(db, cfg, [tav], 10)
    assert sel.parked == 1 and sel.chosen == []
    sel = dorkstore.select(db, cfg, [tav, search.PROVIDERS["serper"]({})], 10)  # Serper passes site:.eu through
    assert sel.parked == 0 and len(sel.chosen) == 1


# ── Part B: sequence engine ──────────────────────────────────────────────────
def setup_chain(cfg, db, monkeypatch, specs, dorks=3, mode="failover"):
    """specs: [(pid, behaviour)]; behaviour(self, key, pd) -> list | raises ProviderError. Returns calls list."""
    calls = []
    cfg["search"]["providers"] = {}
    order = []
    for pid, beh in specs:
        P = fake_cls(pid)
        P.respond = staticmethod(lambda self, key, pd, beh=beh, pid=pid: calls.append((pid, pd.raw)) or beh(self, key, pd))
        monkeypatch.setitem(search.PROVIDERS, pid, P)
        cfg["search"]["providers"][pid] = {"keys": ["k-" + pid], "limit": 1000, "quota_type": "monthly"}
        order.append(pid)
    search.save_sequence(cfg, order)
    cfg["search_mode"] = mode
    dorkstore.ensure_default(db)
    db.c.execute("UPDATE dorks SET enabled=0")
    cfg["dorks"]["source"] = "custom"
    cfg["dorks"]["unfiltered_share"] = 0
    cfg["features"]["ai_dorks"] = False
    for i in range(dorks):
        dorkstore.add_dork(db, f'"responsible disclosure" topic{i} word{i}', "custom", priority=10 - i)
    db.commit()
    return calls


def hits(tag, n):
    return lambda self, key, pd: [SearchResult(f"Responsible disclosure | {tag}{i}-{abs(hash(pd.raw)) % 997}",
                                               f"https://{tag}{i}-{abs(hash(pd.raw)) % 997}.ch/responsible-disclosure",
                                               "report a vulnerability bounty") for i in range(n)]


def boom(kind, msg="x"):
    def f(self, key, pd):
        raise ProviderError(kind, msg)
    return f


def run(cfg, db, budget=50):
    with Progress() as pr:
        return scanner.run_dorks(cfg, db, None, pr, budget=budget)


def test_failover_uses_the_first_provider_and_falls_to_the_next_on_failure(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", hits("a", 1)), ("p2", hits("b", 1))], dorks=2)
    run(cfg, db)
    assert {c[0] for c in calls} == {"p1"} and len(calls) == 2  # p2 never touched while p1 works
    # p1 starts failing -> p2 answers
    calls.clear()
    db.c.execute("DELETE FROM queries")
    db.c.execute("UPDATE search_steps SET status='expired'")
    db.set_meta("seq_batch", "")
    search.PROVIDERS["p1"].respond = staticmethod(lambda self, key, pd: calls.append(("p1", pd.raw)) or boom("invalid")(self, key, pd))
    run(cfg, db)
    assert {c[0] for c in calls} == {"p1", "p2"} and [c[0] for c in calls].count("p2") == 2
    assert db.c.execute("SELECT COUNT(*) FROM queries WHERE provider='p2' AND status='ok'").fetchone()[0] == 2


def test_circuit_breaker_opens_after_repeated_failures_and_sequence_moves_on(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", boom("blocked", "captcha")), ("p2", hits("b", 1))], dorks=1)
    for _ in range(3):  # three failed attempts open the breaker
        pool = search.build_pool(cfg, db)
        for r in pool.rings:
            r.allowance = 10
        with pytest.raises(search.QuotaExhausted):
            pool.search("q", prefer="p1")
        db.c.execute("UPDATE provider_health SET open_until=open_until")  # noqa
        pool.ring("p1").cooldown.clear()
    pool = search.build_pool(cfg, db)
    assert pool.breaker_open("p1") and pool.available("p1")[1].startswith("circuit breaker open")
    calls.clear()
    run(cfg, db)
    assert [c[0] for c in calls] == ["p2"]  # p1 is skipped while its breaker is open


def test_all_providers_down_stops_batch_records_step_and_does_not_block_scan(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", boom("quota")), ("p2", boom("invalid"))], dorks=3)
    msgs = run(cfg, db)
    pr = sequence.progress(db)
    assert pr["done"] == 0 and pr["total"] == 3 and "every provider is exhausted, down or disabled" in pr["stopped"]
    assert any("STOPPED" in m for m in msgs) and any("deferred" in m for m in msgs)
    assert db.c.execute("SELECT COUNT(*) FROM dorks WHERE run_count>0").fetchone()[0] == 0  # nothing marked as 'ran'
    assert db.c.execute("SELECT COUNT(*) FROM queries WHERE status='ok'").fetchone()[0] == 0


def test_cursor_resumes_after_crash_without_respending_finished_steps(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", hits("a", 1))], dorks=5)
    real = scanner._handle_result
    n = {"c": 0}

    def crashing(*a, **k):
        n["c"] += 1
        if n["c"] == 3:
            raise KeyboardInterrupt  # Ctrl+C in the middle of step 3
        return real(*a, **k)
    monkeypatch.setattr(scanner, "_handle_result", crashing)
    with pytest.raises(KeyboardInterrupt):
        run(cfg, db)
    pr = sequence.progress(db)
    assert pr["batch"] and pr["done"] == 2 and pr["next"]["pos"] == 3
    spent_before = len(calls)
    monkeypatch.setattr(scanner, "_handle_result", real)
    msgs = run(cfg, db)
    texts = [c[1] for c in calls[spent_before:]]
    assert len(texts) == 3 and len(set(texts)) == 3  # only steps 3,4,5; steps 1,2 never re-spent
    assert any("resumed batch" in m for m in msgs)
    assert sequence.pending_batch(db) is None and sequence.progress(db)["done"] == 5


def test_stale_batches_expire_and_reset_cursor_drops_unfinished(cfg, db, monkeypatch):
    setup_chain(cfg, db, monkeypatch, [("p1", boom("transient"))], dorks=2)
    run(cfg, db)
    assert sequence.pending_batch(db)
    db.set_meta("seq_batch_created", dates.iso(dates.utcnow() - timedelta(hours=60)))
    assert sequence.pending_batch(db) is None  # older than 48h
    run(cfg, db)
    assert sequence.pending_batch(db)
    assert sequence.reset_cursor(db) == 2 and sequence.pending_batch(db) is None


def test_cascade_adds_providers_until_enough_new_results(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", hits("a", 1)), ("p2", hits("b", 2)), ("p3", hits("c", 5))],
                        dorks=1, mode="cascade")
    cfg["cascade_min_results"] = 3
    run(cfg, db)
    assert [c[0] for c in calls] == ["p1", "p2"]  # 1 + 2 new results = 3 -> stop before p3
    calls.clear()
    db.c.execute("DELETE FROM queries"); db.c.execute("DELETE FROM programs"); db.c.execute("DELETE FROM seen_urls")
    db.set_meta("seq_batch", "")
    cfg["cascade_min_results"] = 100
    run(cfg, db)
    assert [c[0] for c in calls] == ["p1", "p2", "p3"]  # never reaches the threshold: every provider is tried


def test_sweep_needs_confirmation_then_runs_every_dork_on_every_provider(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", hits("a", 1)), ("p2", hits("b", 1))], dorks=2, mode="sweep")
    assert sequence.mode_of(cfg) == "failover"  # unconfirmed sweep falls back
    msgs = run(cfg, db)
    assert any("not confirmed" in m for m in msgs) and {c[0] for c in calls} == {"p1"}
    calls.clear()
    db.c.execute("DELETE FROM queries"); db.set_meta("seq_batch", "")
    cfg["sweep_confirmed"] = True
    run(cfg, db)
    assert sorted(calls) == sorted({(p, c[1]) for p in ("p1", "p2") for c in calls})
    assert len(calls) == 4 and {c[0] for c in calls} == {"p1", "p2"}


def test_identical_query_cooldown_still_prevents_respend(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", hits("a", 1))], dorks=2)
    run(cfg, db)
    first = len(calls)
    db.set_meta("seq_batch", "")
    run(cfg, db)
    assert len(calls) == first  # same (provider, query, window) inside its cooldown costs nothing


def test_same_url_from_two_providers_is_one_program_and_one_alert(cfg, db, monkeypatch):
    same = lambda self, key, pd: [SearchResult("Responsible disclosure | acme", "https://acme.ch/responsible-disclosure", "report a vulnerability bounty")]
    setup_chain(cfg, db, monkeypatch, [("p1", same), ("p2", same)], dorks=1, mode="sweep")
    cfg["sweep_confirmed"] = True
    run(cfg, db)
    assert db.c.execute("SELECT COUNT(*) FROM programs WHERE source='web'").fetchone()[0] == 1
    from qurihunter import alerts
    cfg["notify"]["channels"] = ["telegram"]
    assert len(alerts.due(db, cfg)) == 1


def test_failed_searxng_style_query_is_not_recorded_as_a_run_with_zero_results(cfg, db, monkeypatch):
    setup_chain(cfg, db, monkeypatch, [("p1", boom("blocked", "no engine answered (google: CAPTCHA)"))], dorks=1)
    run(cfg, db)
    assert db.c.execute("SELECT COUNT(*) FROM queries WHERE status='ok'").fetchone()[0] == 0
    assert db.c.execute("SELECT run_count FROM dorks WHERE grp='custom'").fetchone()[0] == 0


def test_lifetime_credits_dont_burn_in_one_cycle(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", hits("a", 1))], dorks=40)
    cfg["search"]["providers"]["p1"].update(limit=60, quota_type="lifetime")
    cfg["schedule"]["dork_interval_min"] = 1440
    with Progress() as pr:
        scanner.run_dorks(cfg, db, None, pr)  # no explicit budget -> planned allowance
    assert len(calls) <= 2  # 60 credits over 60 days at one cycle/day = 1 per cycle


# ── commands ─────────────────────────────────────────────────────────────────
def test_sequence_commands_move_enable_disable_mode_and_show(cfg, db, monkeypatch):
    for pid in ("serper", "tavily", "exa"):
        cfg["search"]["providers"][pid] = {"keys": ["k-" + pid], "limit": 100}
    ctx = Ctx(cfg, db)
    out, tables = [], []
    monkeypatch.setattr(ui, "ok", lambda m: out.append(m))
    monkeypatch.setattr(ui, "fail", lambda m: out.append("FAIL " + m))
    monkeypatch.setattr(ui, "info", lambda m: out.append(m))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    seqcmds.cmd_sequence(ctx, ["move", "exa", "1"])
    assert search.configured(cfg)[0] == "exa" and "exa" in out[-1]
    seqcmds.cmd_sequence(ctx, ["disable", "exa"])
    assert "exa" not in search.configured(cfg) and "exa" in search.configured(cfg, include_disabled=True)
    seqcmds.cmd_sequence(ctx, ["enable", "exa"])
    seqcmds.cmd_sequence(ctx, ["mode", "cascade"])
    assert cfg["search_mode"] == "cascade"
    monkeypatch.setattr(ui, "yn", lambda q, d=True: False)
    seqcmds.cmd_sequence(ctx, ["mode", "sweep"])
    assert cfg["search_mode"] == "cascade" and not cfg["sweep_confirmed"]
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    seqcmds.cmd_sequence(ctx, ["mode", "sweep"])
    assert cfg["search_mode"] == "sweep" and cfg["sweep_confirmed"]
    seqcmds.cmd_sequence(ctx, ["move", "nope", "1"])
    assert out[-1].startswith("FAIL")
    seqcmds.cmd_sequence(ctx, ["show"])
    t = [x for x in tables if hasattr(x, "row_count")][-1]
    assert t.row_count == 7 and [c.header for c in t.columns] == ["#", "Provider", "Status", "Keys", "Remaining", "Quota", "Role", "Health"]
    assert json.loads(config.config_path().read_text())["search_sequence"][0]["provider"] == "exa"  # persisted


def test_sequence_show_reports_resume_point_and_lifetime_warning(cfg, db, monkeypatch):
    calls = setup_chain(cfg, db, monkeypatch, [("p1", boom("quota"))], dorks=2)
    run(cfg, db)
    cfg["search"]["providers"]["p1"].update(quota_type="lifetime", limit=100)
    db.quota_add(KeyRing(search.make(cfg, "p1"), ["k-p1"], 100, db)._kid("k-p1"), "lifetime", 95)
    info = []
    monkeypatch.setattr(ui, "info", lambda m: info.append(m))
    monkeypatch.setattr(ui, "fail", lambda m: info.append("FAIL " + m))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    seqcmds.cmd_sequence(Ctx(cfg, db), ["show"])
    assert any("resume point: step 1" in m and "STOPPED" in m for m in info)
    assert any(m.startswith("FAIL") and "5%" in m for m in info)


def test_sequence_test_dry_run_reports_provider_and_cost(cfg, db, monkeypatch):
    setup_chain(cfg, db, monkeypatch, [("p1", boom("invalid")), ("p2", hits("b", 2))], dorks=0)
    tables = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    monkeypatch.setattr(ui, "info", lambda m: tables.append(m))
    seqcmds.cmd_sequence(Ctx(cfg, db), ["test"])
    t = [x for x in tables if hasattr(x, "row_count")][0]
    cells = [c._cells for c in t.columns]
    assert "answered" in cells[1][-1] and cells[3][-1] == "1" and cells[2][-1] == "2"
    assert db.c.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == 0  # nothing stored


def test_providers_status_and_searxng_setup_never_runs_commands(cfg, db, monkeypatch, tmp_path):
    setup_chain(cfg, db, monkeypatch, [("p1", boom("blocked", "captcha"))], dorks=0)
    pool = search.build_pool(cfg, db)
    pool.ring("p1").allowance = 5
    for _ in range(3):
        with pytest.raises(search.QuotaExhausted):
            pool.search("q")
        pool.ring("p1").cooldown.clear()
    tables = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    monkeypatch.setattr(ui, "info", lambda m: None)
    seqcmds.cmd_providers(Ctx(cfg, db), ["status"])
    t = [x for x in tables if hasattr(x, "row_count")][0]
    assert "open until" in t.columns[2]._cells[0] and t.columns[3]._cells[0] == "3"
    # /searxng setup: prints/writes files, never executes anything, secret key masked on screen
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must not run commands"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("must not run commands"))
    monkeypatch.setattr(ui, "ask", lambda q, d="", password=False: str(tmp_path / "stack"))
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    printed = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: printed.append(str(a[0]) if a else ""))
    seqcmds.cmd_searxng(Ctx(cfg, db), ["setup"])
    settings = (tmp_path / "stack" / "searxng" / "settings.yml").read_text()
    compose = (tmp_path / "stack" / "docker-compose.yml").read_text()
    import re
    key = re.search(r'secret_key: "([0-9a-f]{64})"', settings).group(1)
    assert "json" in settings and "limiter: false" in settings and settings.count("disabled: false") >= 4
    assert "127.0.0.1:8080:8080" in compose and oct((tmp_path / "stack" / "searxng" / "settings.yml").stat().st_mode & 0o777) == "0o600"
    assert not any(key in p for p in printed)  # the generated secret is never shown
    assert cfg["search"]["providers"]["searxng"]["base_url"] == "http://localhost:8080"
    assert any("docker compose up -d" in p for p in printed)


def test_config_migration_adds_search_keys_idempotently(cfg):
    for k in ("search_sequence", "search_mode", "cascade_min_results", "lifetime_target_days", "sweep_confirmed"):
        assert k in cfg
    assert cfg["search_mode"] == "failover" and cfg["cascade_min_results"] == 3 and cfg["lifetime_target_days"] == 365
