"""v0.4.1 Items 2-5: one-question key wizard + daily caps, SerpAPI, per-provider rate limiter, minimal model wizards,
batched classification for call-limited backends, /llm limits, /providers commands."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests
from rich.progress import Progress

from qurihunter import (checks, claudecli, classify, config, dates, dorkstore, keysetup, llmreg, modelcmds, ratelimit, reclass, scanner,
                        search, seqcmds, ui, wizard)
from qurihunter.db import DB
from qurihunter.llm import ChatReply, LLM, LLMError, parse_json
from qurihunter.models import Program
from qurihunter.search import base, brave, defaults, serpapi, tavily
from qurihunter.search.base import ProviderError, SearchResult
from qurihunter.search.dorkparse import parse
from qurihunter.search.pool import KeyRing, SearchPool, key_id


class Resp:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code, self._b, self.headers = status, body if body is not None else {}, headers or {}
        self.text = text if text is not None else json.dumps(self._b)

    def json(self):
        return self._b


class Ctx:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db

    def save(self, c=None):
        config.save(c or self.cfg)


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


@pytest.fixture
def cfg():
    return config.load()


class Script:
    def __init__(self, monkeypatch, answers):
        self.answers, self.shown, self.asked = list(answers), [], []
        monkeypatch.setattr(ui, "choose", lambda q, o, d=None: self._next(q))
        monkeypatch.setattr(ui, "ask", lambda q, d="", password=False: self._next(q, password))
        monkeypatch.setattr(ui, "yn", lambda q, d=True: self._next(q))
        for n in ("info", "ok", "fail"):
            monkeypatch.setattr(ui, n, lambda m: self.shown.append(str(m)))
        monkeypatch.setattr(ui.console, "print", lambda *a, **k: self.shown.append(" ".join(str(x) for x in a)))

    def _next(self, q, password=False):
        self.asked.append((q, password))
        a = self.answers.pop(0)
        return a(q) if callable(a) else a

    @property
    def text(self):
        return "\n".join(self.shown + [q for q, _ in self.asked])


# ── Item 2: defaults, detection, the single question ────────────────────────
def test_defaults_table_has_source_date_and_unverified_flags():
    assert set(defaults.DEFAULTS) == {"serper", "serpapi", "tavily", "brave", "exa", "google", "searxng"}
    d = defaults.DEFAULTS
    assert (d["serper"].quota_type, d["serper"].allowance, d["serper"].verified) == ("lifetime", 2500, False)
    assert (d["tavily"].quota_type, d["tavily"].allowance) == ("monthly", 1000)
    assert (d["brave"].quota_type, d["exa"].quota_type, d["exa"].allowance) == ("monthly", "monthly", 1000)
    assert (d["google"].quota_type, d["google"].allowance) == ("daily", 100) and d["searxng"].quota_type == "unlimited"
    assert d["serpapi"].verified and d["serpapi"].allowance == 250
    assert all(x.source and x.date == "2026-10-05" for x in d.values())
    for pid, cls in search.PROVIDERS.items():  # the provider classes agree with the table
        assert cls({}).quota_type() == d[pid].quota_type and (d[pid].allowance is None or cls.default_limit == d[pid].allowance)


def test_recommended_daily_values():
    r = defaults.recommended_daily
    assert r("lifetime", 2500, 365) == 6 and r("lifetime", 10, 365) == 1  # minimum 1
    jan1 = datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert r("monthly", 1000, now=jan1) == 32  # 1000 / 31 days left
    assert r("monthly", 1000, now=datetime(2026, 10, 31, tzinfo=timezone.utc)) == 1000  # last day
    assert r("daily", 100) == 100 and r("unlimited", None) is None
    assert defaults.days_estimate("lifetime", 2500, 6) == pytest.approx(416.67, abs=0.1)
    assert config.load()["lifetime_target_days"] == 365


def test_keysetup_asks_one_question_serper_recommends_6_per_day_and_enter_accepts(cfg, db):
    q = []
    res = keysetup.configure_key(cfg, "serper", "SERPER-KEY-1234", db, ask=lambda text, d: q.append((text, d)) or d)
    assert q == [("How many requests per day for this key? (recommended 6)", "6")]
    pc = cfg["search"]["providers"]["serper"]
    assert pc["quota_type"] == "lifetime" and pc["limit"] == 2500 and pc["daily"][key_id("serper", "SERPER-KEY-1234")] == 6
    assert res["daily"] == 6 and res["days"] == pytest.approx(416.67, abs=0.1) and "6 per day, about 417 days" in keysetup.describe(res)
    assert db.meta("lifetime_start:serper")  # recorded once, at key-add time
    keysetup.configure_key(cfg, "serper", "SERPER-KEY-5678", db, ask=lambda text, d: "10")  # teammate's own cap
    pc["keys"] = ["SERPER-KEY-1234", "SERPER-KEY-5678"]
    assert keysetup.total_per_day(cfg, "serper") == 16


def test_wizard_serper_has_no_quota_or_allowance_questions_and_keeps_the_add_another_key_loop(cfg, db, monkeypatch):
    monkeypatch.setattr(search.PROVIDERS["serper"], "test", lambda self, key: (True, "query OK (10 results)"))
    s = Script(monkeypatch, ["KEY-AAAA1111", "",  # key + Enter accepts the recommended per-day
                             True, "KEY-BBBB2222", "9",  # teammate: "Add another API key?" y, key, own daily cap 9
                             False])  # add another? no
    wizard.setup_keys(cfg, "serper", db)
    qs = [q for q, _ in s.asked]
    assert sum("How many requests per day" in q for q in qs) == 2 and "Add another API key?" in qs
    assert not any(w in q.lower() for q in qs for w in ("quota type", "allowance", "queries per key", "per key per"))
    assert [p for q, p in s.asked if "API key" in q and "Add another" not in q] == [True, True]  # hidden input
    pc = cfg["search"]["providers"]["serper"]
    assert pc["keys"] == ["KEY-AAAA1111", "KEY-BBBB2222"] and keysetup.total_per_day(cfg, "serper") == 15
    t = s.text
    assert "6 per day" in t and "9 per day" in t and "15 requests per day in total" in t and "lifetime" in t and "(unverified)" in t
    assert "KEY-AAAA1111" not in t and "…1111" in t  # masked everywhere


def test_provider_account_endpoints_detect_the_real_remaining_quota(cfg, db, monkeypatch):
    seen = []
    monkeypatch.setattr(serpapi.requests, "get", lambda url, **kw: seen.append((url, kw)) or Resp(200, {
        "total_searches_left": 180, "plan_searches_left": 180, "searches_per_month": 250, "account_rate_limit_per_hour": 50}))
    d = serpapi.SerpAPI({}).detect_quota("SKEY")
    assert seen[0][0] == "https://serpapi.com/account.json" and seen[0][1]["params"] == {"api_key": "SKEY"}
    assert d["remaining"] == 180 and d["limit"] == 250 and d["type"] == "monthly"
    monkeypatch.setattr(tavily.requests, "get", lambda url, **kw: seen.append((url, kw)) or Resp(200, {
        "key": {"usage": 120, "limit": 1000}, "account": {"plan_usage": 300, "plan_limit": 1000}}))
    t = tavily.Tavily({}).detect_quota("TKEY")
    assert seen[-1][0] == "https://api.tavily.com/usage" and seen[-1][1]["headers"]["Authorization"] == "Bearer TKEY"
    assert t["remaining"] == 880
    monkeypatch.setattr(tavily.requests, "get", lambda url, **kw: Resp(200, {"key": {"usage": 5, "limit": None},
                                                                               "account": {"plan_usage": 300, "plan_limit": 1000}}))
    assert tavily.Tavily({}).detect_quota("TKEY")["remaining"] == 700  # falls to the plan numbers
    monkeypatch.setattr(tavily.requests, "get", lambda *a, **k: Resp(401, {}))
    assert tavily.Tavily({}).detect_quota("TKEY") is None  # silent fallback


def test_brave_quota_comes_from_the_documented_rate_limit_headers():
    h = {"X-RateLimit-Limit": "1, 15000", "X-RateLimit-Remaining": "1, 14321", "X-RateLimit-Reset": "1, 1419704"}
    q = brave.parse_quota_headers(h)
    assert q["remaining"] == 14321 and q["limit"] == 15000 and q["source"].startswith("Brave")
    assert brave.parse_quota_headers({}) is None and brave.parse_quota_headers({"X-RateLimit-Limit": "x"}) is None


def test_detected_quota_replaces_the_default_and_sets_the_daily_recommendation(cfg, db, monkeypatch):
    monkeypatch.setattr(search.PROVIDERS["serpapi"], "detect_quota", lambda self, key: {"remaining": 62, "limit": 250, "type": "monthly",
                                                                                         "source": "SerpAPI account.json"})
    asked = []
    res = keysetup.configure_key(cfg, "serpapi", "SP-KEY", db, ask=lambda q, d: asked.append(q) or d)
    kid = key_id("serpapi", "SP-KEY")
    assert cfg["search"]["providers"]["serpapi"]["key_limit"][kid] == 62 and res["source"] == "SerpAPI account.json"
    assert "recommended" in asked[0] and "detected from your account" in keysetup.describe(res)
    pool = search.build_pool({**cfg, "search": {**cfg["search"], "providers": {"serpapi": {**cfg["search"]["providers"]["serpapi"], "keys": ["SP-KEY"]}}}}, db)
    assert pool.ring("serpapi").total_remaining() <= 62


def test_unlimited_provider_gets_no_per_day_question(cfg, db):
    q = []
    res = keysetup.configure_key(cfg, "searxng", "searxng", db, ask=lambda t, d: q.append(t) or d)
    assert q == [] and res["daily"] is None


def test_daily_cap_reached_means_exhausted_until_local_midnight_and_the_sequence_moves_on(cfg, db, monkeypatch):
    calls = []

    def mk(pid):
        class P(base.Provider):
            id, label, period, default_limit, page_size = pid, pid, "month", 1000, 10
            paginates = False
            tld_mode = "native"

            def _search(self, key, pd, page, fresh):
                calls.append(pid)
                return [SearchResult("t", f"https://{pid}{len(calls)}.ch/responsible-disclosure", "report a vulnerability bounty")]
        return P
    for pid in ("capped", "backup"):
        monkeypatch.setitem(search.PROVIDERS, pid, mk(pid))
        cfg["search"]["providers"][pid] = {"keys": ["k-" + pid], "limit": 1000, "quota_type": "monthly"}
    cfg["search"]["providers"]["capped"]["daily"] = {key_id("capped", "k-capped"): 2}
    search.save_sequence(cfg, ["capped", "backup"])
    cfg["search_mode"] = "failover"
    dorkstore.ensure_default(db)
    db.c.execute("UPDATE dorks SET enabled=0")
    cfg["dorks"]["source"] = "custom"
    cfg["dorks"]["unfiltered_share"] = 0
    cfg["features"]["ai_dorks"] = False
    for i in range(5):
        dorkstore.add_dork(db, f'"responsible disclosure" topic{i} w{i}', "custom", priority=10 - i)
    db.commit()
    with Progress() as pr:
        scanner.run_dorks(cfg, db, None, pr, budget=10)
    assert calls == ["capped", "capped", "backup", "backup", "backup"]  # cap of 2/day, then the sequence moves to the next provider
    pool = search.build_pool(cfg, db)
    ok, why = pool.available("capped")
    assert not ok and "daily cap reached (resumes at local midnight)" in why
    # tomorrow (local): the same key works again - it was never permanently exhausted
    ring = pool.ring("capped")
    kid = key_id("capped", "k-capped")
    db.c.execute("UPDATE quota SET day=? WHERE key_id=? AND day LIKE 'D:%'", ("D:2000-01-01", kid))
    db.commit()
    assert pool.available("capped")[0] and ring.daily_left("k-capped") == 2
    assert ring.period_remaining("k-capped") == 998  # the monthly counter still reflects the 2 spent queries


def test_daily_cap_spreads_todays_allowance_over_todays_cycles(db):
    P = type("P", (base.Provider,), {"id": "pp", "label": "pp", "period": "month", "default_limit": 1000, "page_size": 10,
                                      "_search": lambda self, k, pd, p, f: []})
    ring = KeyRing(P({}), ["k"], 1000, db, daily={key_id("pp", "k"): 12})
    pool = SearchPool([ring], db)
    assert pool.plan(60) in range(1, 13) and ring.allowance <= 12
    db.quota_add(key_id("pp", "k"), ring.day_label(), 12)
    assert ring.remaining("k") == 0 and pool.plan(60) == 0


def test_providers_show_set_and_daily_commands(cfg, db, monkeypatch):
    cfg["search"]["providers"]["serper"] = {"keys": ["AAAA-1111", "BBBB-2222"], "limit": 2500, "quota_type": "lifetime"}
    ctx = Ctx(cfg, db)
    tables, out = [], []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    for n in ("info", "ok", "fail"):
        monkeypatch.setattr(ui, n, lambda m: out.append(str(m)))
    seqcmds.cmd_providers(ctx, ["daily", "serper", "6"])
    assert keysetup.total_per_day(cfg, "serper") == 12 and "total 12 per day" in out[-1] and "AAAA-1111" not in out[-1]
    seqcmds.cmd_providers(ctx, ["daily", "serper", "2", "4"])  # key #2 only
    assert keysetup.total_per_day(cfg, "serper") == 10
    seqcmds.cmd_providers(ctx, ["daily", "serper", "1111", "0"])  # by last chars; 0 removes the cap
    assert keysetup.total_per_day(cfg, "serper") == 4
    seqcmds.cmd_providers(ctx, ["daily", "serper", "99", "5"])
    assert out[-1].startswith("no such key") or "no such key" in out[-1]
    seqcmds.cmd_providers(ctx, ["set", "serper", "allowance", "1800"])
    seqcmds.cmd_providers(ctx, ["set", "serper", "type", "monthly"])
    assert cfg["search"]["providers"]["serper"]["limit"] == 1800 and cfg["search"]["providers"]["serper"]["quota_type"] == "monthly"
    seqcmds.cmd_providers(ctx, ["set", "serper", "type", "weekly"])
    assert "type must be" in out[-1]
    saved = json.loads(config.config_path().read_text())["search"]["providers"]["serper"]
    assert saved["limit"] == 1800 and len(saved["daily"]) == 1
    seqcmds.cmd_providers(ctx, ["show"])
    t = [x for x in tables if hasattr(x, "row_count")][-1]
    assert t.row_count == 7 and [c.header for c in t.columns][:4] == ["Provider", "Quota", "Allowance", "Source"]
    rows = {c.header: c._cells for c in t.columns}
    assert "SerpAPI (Google results)" in rows["Provider"] and "(unverified)" in " ".join(rows["Source"])
    assert rows["Total/day"][rows["Provider"].index("Serper (Google results)")] == "4"
    seqcmds.cmd_providers(ctx, ["bogus"])
    assert out[-1].startswith("usage: /providers")


# ── Item 3: SerpAPI ──────────────────────────────────────────────────────────
def test_serpapi_request_mapping_and_results(monkeypatch):
    seen = {}

    def fake(method, url, **kw):
        seen.update(method=method, url=url, **kw)
        return Resp(200, {"organic_results": [{"title": "T", "link": "https://a.ch/vdp", "snippet": "s", "date": "Oct 3, 2026"},
                                              {"title": "U", "link": "https://b.ch/vdp", "snippet": "s"}]})
    monkeypatch.setattr(serpapi, "request", fake)
    p = serpapi.SerpAPI({})
    page = p.search("SPKEY", 'inurl:security "bug bounty" site:.ch after:2026-09-01', page=1, days=7)
    prm = seen["params"]
    assert seen["url"] == "https://serpapi.com/search.json" and prm["engine"] == "google" and prm["api_key"] == "SPKEY"
    assert prm["q"] == 'inurl:security "bug bounty" site:.ch' and prm["num"] == 10 and prm["start"] == 10
    assert prm["tbs"].startswith("cdr:1,cd_min:9/1/2026")
    assert [r.url for r in page.results] == ["https://a.ch/vdp", "https://b.ch/vdp"] and page.results[0].published.startswith("2026-10-03")
    seen.clear()
    p.search("SPKEY", '"bug bounty"', days=7)
    assert seen["params"]["tbs"] == "qdr:w"
    assert p.capabilities()["operators"] == "full" and p.capabilities()["supports_tld_filter"] == "yes" and p.capabilities()["max_qps"] == 1.0


@pytest.mark.parametrize("status,body,kind", [
    (401, {"error": "Invalid API key. Your API key should be here: https://serpapi.com/manage-api-key"}, "invalid"),
    (429, {"error": "Your account has run out of searches."}, "quota"),
    (429, {"error": "Your hourly throughput limit has been exceeded"}, "rate"),
    (200, {"error": "Something odd"}, "transient"), (500, {}, "transient")])
def test_serpapi_error_classification_and_key_redaction(monkeypatch, status, body, kind):
    monkeypatch.setattr(serpapi, "request", lambda *a, **k: Resp(status, body))
    with pytest.raises(ProviderError) as e:
        serpapi.SerpAPI({})._search("SECRET-KEY-VALUE-123456", parse("bug bounty"), 0, None)
    assert e.value.kind == kind and "SECRET-KEY-VALUE" not in str(e.value)


def test_serpapi_no_results_is_a_real_empty_answer(monkeypatch):
    monkeypatch.setattr(serpapi, "request", lambda *a, **k: Resp(200, {"error": "Google hasn't returned any results for this query."}))
    assert serpapi.SerpAPI({})._search("K", parse("bug bounty"), 0, None) == []


def test_serpapi_sits_right_after_serper_in_the_default_sequence(cfg):
    assert search.DEFAULT_ORDER[:3] == ["serper", "serpapi", "tavily"]
    for pid in ("serper", "serpapi", "tavily"):
        cfg["search"]["providers"][pid] = {"keys": ["k-" + pid], "limit": 10}
    assert search.configured(cfg) == ["serper", "serpapi", "tavily"]
    assert search.PROVIDERS["serpapi"]({}).quota_type() == "monthly" and search.PROVIDERS["serpapi"].default_limit == 250


# ── Item 4: limiter ──────────────────────────────────────────────────────────
class FakeClock:
    def __init__(self):
        self.t, self.lock, self.sleeps = 0.0, threading.Lock(), []

    def now(self):
        with self.lock:
            return self.t

    def sleep(self, s):
        with self.lock:
            self.sleeps.append(s)
            self.t += s


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(ratelimit, "ENABLED", True)
    monkeypatch.setattr(ratelimit, "_now", c.now)
    monkeypatch.setattr(ratelimit, "_sleep", c.sleep)
    ratelimit.reset()
    return c


def test_exa_max_qps_is_6_and_in_the_capability_table():
    assert search.PROVIDERS["exa"].max_qps == 6.0
    assert all(search.PROVIDERS[p].max_qps > 0 for p in search.PROVIDERS)
    assert search.PROVIDERS["exa"]({}).capabilities()["max_qps"] == 6.0 and search.PROVIDERS["brave"].max_qps == 1.0


def test_token_bucket_spaces_requests_at_the_rate(clock):
    waits = [ratelimit.acquire("exa", 6.0) for _ in range(13)]
    assert waits[0] == 0.0 and all(w == pytest.approx(1 / 6) for w in waits[1:])
    assert clock.t == pytest.approx(12 / 6)  # 12 spaced requests = 2 s: never more than 6 per second


def test_limiter_is_shared_by_all_threads_and_never_exceeds_the_rate(clock):
    stamps, lock = [], threading.Lock()

    def work():
        for _ in range(10):
            ratelimit.acquire("exa", 6.0)
            with lock:
                stamps.append(clock.now())
    ts = [threading.Thread(target=work) for _ in range(6)]  # 6 threads (foreground, workers, AI dork generation ...)
    [t.start() for t in ts]
    [t.join(10) for t in ts]
    assert len(stamps) == 60
    stamps.sort()
    for i in range(len(stamps)):  # any window of 1 second holds at most 6 (+1 for the burst token) requests
        in_window = [s for s in stamps if stamps[i] <= s < stamps[i] + 1.0]
        assert len(in_window) <= 7


def test_429_retry_after_pauses_every_thread_for_that_provider(clock, db):
    P = type("P", (base.Provider,), {"id": "rl", "label": "rl", "period": "month", "default_limit": 100, "page_size": 10, "max_qps": 6.0,
                                      "paginates": False, "_search": lambda self, k, pd, p, f: (_ for _ in ()).throw(
                                          ProviderError("rate", "429", retry_after=7.0))})
    ring = KeyRing(P({}), ["k"], 100, db)
    pool = SearchPool([ring], db)
    ratelimit.acquire("rl", 6.0)
    with pytest.raises(search.QuotaExhausted):
        pool.search("q")
    before = clock.t
    ratelimit.acquire("rl", 6.0)
    assert clock.t - before >= 6.5  # honoured Retry-After: 7 s
    ratelimit.acquire("other", 6.0)  # another provider is unaffected
    assert clock.t - before < 8


def test_provider_search_goes_through_the_shared_limiter(clock, monkeypatch):
    from qurihunter.search import exa
    monkeypatch.setattr(exa, "request", lambda *a, **k: Resp(200, {"results": []}))
    p = exa.Exa({})
    for _ in range(4):
        p.search("K", "bug bounty")
    assert clock.t == pytest.approx(3 / 6)


def test_retry_after_header_parsing():
    assert base.retry_after(Resp(429, headers={"Retry-After": "12"})) == 12.0
    assert base.retry_after(Resp(429, headers={"Retry-After": "soon"})) is None and base.retry_after(Resp(429)) is None


# ── Item 5: batching ─────────────────────────────────────────────────────────
class BatchLLM(LLM):
    """Records calls; answers batches from a script. batch_size > 1 like the Claude CLI."""
    def __init__(self, batch=10, batch_answer=None):
        self.batch_size, self.prompts, self.single, self.batch_answer = batch, [], [], batch_answer

    def generate(self, prompt, *, json_mode=False, timeout=0, system=None):
        self.prompts.append(prompt)
        return self.batch_answer(prompt) if self.batch_answer else "[]"

    def classify(self, url, title, snippet, page_text=""):
        self.single.append(url)
        return {"is_program": "good" in url, "type": "vdp", "confidence": 0.9, "reason": "single"}


def good_answer(prompt):
    import re
    n = len(re.findall(r"^\[\d+\] URL:", prompt, re.M))
    return json.dumps([{"id": i, "is_program": i % 2 == 0, "type": "vdp", "confidence": 0.9, "reason": f"b{i}"} for i in range(n)])


def pages(n):
    return [{"url": f"https://good{i}.ch/responsible-disclosure", "title": f"t{i}", "snippet": "s", "page": ""} for i in range(n)]


def test_classify_batch_sends_one_call_per_batch_size_pages_and_maps_ids():
    m = BatchLLM(batch=10, batch_answer=good_answer)
    out = m.classify_batch(pages(25))
    assert len(m.prompts) == 3 and m.single == []  # 10 + 10 + 5 pages -> 3 calls, no single calls
    assert [o["is_program"] for o in out[:4]] == [True, False, True, False] and out[2]["reason"] == "b2"
    assert "ONLY a JSON array" in m.prompts[0] and "untrusted web data" in m.prompts[0] and "<<<DATA" in m.prompts[0]


def test_classify_batch_retries_failed_items_individually_and_survives_garbage():
    def partial(prompt):  # answers only id 0 and 2, with one malformed entry
        return 'sure! [{"id": 0, "is_program": true, "confidence": 0.9, "reason": "r"}, {"id": "x"}, {"id": 2, "is_program": false, "confidence": 0.8}]'
    m = BatchLLM(batch=4, batch_answer=partial)
    out = m.classify_batch(pages(4))
    assert len(m.prompts) == 1 and m.single == ["https://good1.ch/responsible-disclosure", "https://good3.ch/responsible-disclosure"]
    assert out[0]["reason"] == "r" and out[1]["reason"] == "single" and out[2]["is_program"] is False
    junk = BatchLLM(batch=3, batch_answer=lambda p: "no json at all")
    out = junk.classify_batch(pages(3))
    assert len(junk.single) == 3 and all(o is not None for o in out)  # every item still got a verdict
    wrapped = BatchLLM(batch=2, batch_answer=lambda p: json.dumps({"results": [{"id": 0, "is_program": True, "confidence": 1}, {"id": 1, "is_program": True, "confidence": 1}]}))
    assert [o["is_program"] for o in wrapped.classify_batch(pages(2))] == [True, True] and wrapped.single == []


def test_batch_size_one_means_plain_per_page_calls():
    m = BatchLLM(batch=1)
    m.classify_batch(pages(3))
    assert len(m.single) == 3 and m.prompts == []


def test_prepare_batch_dedupes_before_any_call_and_attaches_verdicts(db, monkeypatch):
    monkeypatch.setattr(classify, "fetch_text", lambda url, limit=4000: "")
    db.remember_url("https://seen.ch/responsible-disclosure", "official_program")
    db.insert(Program("web", "known.ch", "k", "https://known.ch/responsible-disclosure"))
    items = [SearchResult("Responsible disclosure | " + d, f"https://{d}/responsible-disclosure", "report a vulnerability bounty")
             for d in ("a.ch", "b.ch", "a.ch", "seen.ch", "known.ch")]
    items.append(SearchResult("Top 10 bug bounty tips", "https://blog.example.com/blog/top-10", "bug bounty"))  # hard reject
    items.append(SearchResult("hello", "https://c.ch/x", "nothing relevant"))  # hopeless heuristic
    m = BatchLLM(batch=10, batch_answer=good_answer)
    n = classify.prepare_batch(items, m, db)
    assert n == 2 and len(m.prompts) == 1 and m.prompts[0].count("] URL:") == 2  # only a.ch and b.ch, once each
    assert items[0].verdict and items[1].verdict and items[3].verdict is None
    one = [SearchResult("Responsible disclosure | z.ch", "https://z.ch/responsible-disclosure", "report a vulnerability bounty")]
    assert classify.prepare_batch(one, m, db) == 0 and len(m.prompts) == 1  # a single page: normal path, no batch call
    assert classify.prepare_batch(items, BatchLLM(batch=1), db) == 0  # single-page backends: untouched


def test_batched_verdict_is_used_without_a_second_call_in_the_dork_flow(db, cfg, monkeypatch):
    monkeypatch.setattr(classify, "fetch_text", lambda url, limit=4000: "")
    m = BatchLLM(batch=10, batch_answer=lambda p: json.dumps([{"id": i, "is_program": True, "type": "vdp", "confidence": 0.9, "reason": "b"} for i in range(2)]))
    items = [SearchResult("Responsible disclosure | " + d, f"https://{d}/responsible-disclosure", "report a vulnerability bounty") for d in ("a.ch", "b.ch")]
    budget = {"left": 60}
    assert classify.prepare_batch(items, m, db) == 2
    for it in items:
        scanner._handle_result(db, cfg, m, it, windowed=True, first_run=False, budget=budget)
    assert m.single == [] and len(m.prompts) == 1 and budget["left"] == 60  # no per-page calls, no double charge
    assert db.c.execute("SELECT COUNT(*) FROM programs WHERE source='web'").fetchone()[0] == 2


def test_reclassify_batches_pages_per_call_with_caps_and_stays_resumable(db, cfg, monkeypatch):
    monkeypatch.setattr(classify, "fetch_text", lambda url, limit=4000: "")
    for i in range(25):
        db.insert(Program("web", f"d{i}.ch", f"d{i}", f"https://d{i}.ch/responsible-disclosure", snippet="report a vulnerability bounty"))
    db.commit()
    m = BatchLLM(batch=10, batch_answer=good_answer)
    reclass.start(db)
    p = reclass.step(db, cfg, m, pages=20)  # cap 20 pages -> 2 calls of 10
    assert len(m.prompts) == 2 and p["done"] == 20 and p["state"] == "running" and m.single == []
    p = reclass.step(db, cfg, m, pages=20)
    assert len(m.prompts) == 3 and p["state"] == "done" and p["done"] == 25
    assert 0 < p["rejected"] < 25  # the script rejects odd ids


def test_reclassify_without_batching_is_unchanged(db, cfg):
    for i in range(3):
        db.insert(Program("web", f"e{i}.ch", f"e{i}", f"https://e{i}.ch/responsible-disclosure", snippet="bounty"))
    db.commit()
    m = BatchLLM(batch=1)
    reclass.start(db)
    reclass.step(db, cfg, m, pages=3)
    assert len(m.single) == 3 and m.prompts == []


# ── Item 5: limits, info, prices, router with batching ───────────────────────
def test_claude_cli_default_limits_and_llm_limits_command(cfg, db, monkeypatch):
    assert cfg["claude_cli"] == {"calls_per_hour": 12, "calls_per_day": 80, "min_interval_s": 20, "timeout_s": 180, "batch_size": 10}
    out = []
    monkeypatch.setattr(ui, "info", lambda m: out.append(m)); monkeypatch.setattr(ui, "fail", lambda m: out.append("FAIL " + m))
    ctx = Ctx(cfg, db)
    modelcmds.cmd_llm(ctx, ["limits"])
    assert "12 calls/hour, 80 calls/day, 20 s between calls, 10 pages per classification call" in out[-1]
    modelcmds.cmd_llm(ctx, ["limits", "hour", "5", "day", "40", "interval", "45", "batch", "6"])
    assert cfg["claude_cli"]["calls_per_hour"] == 5 and cfg["claude_cli"]["batch_size"] == 6 and "5 calls/hour" in out[-1]
    assert json.loads(config.config_path().read_text())["claude_cli"]["min_interval_s"] == 45
    modelcmds.cmd_llm(ctx, ["limits", "hour", "zero"])
    assert out[-1].startswith("FAIL usage")
    modelcmds.cmd_llm(ctx, ["limits", "bogus", "1"])
    assert out[-1].startswith("FAIL usage")


def test_router_uses_the_cli_batch_size_and_falls_over_silently_on_a_limit(cfg, db, monkeypatch):
    cfg["claude_cli_allow_bulk"] = True
    cfg["claude_cli"]["min_interval_s"] = 0
    cli = llmreg.new_entry(cfg, "claude_cli", "claude (CLI)", roles=config.ROLES, consent=True)
    llmreg.add_model(cfg, cli, 1)
    loc = llmreg.new_entry(cfg, "local", "qwen")
    llmreg.add_model(cfg, loc)
    r = llmreg.Router(cfg, db)
    inst_cli, inst_loc = BatchLLM(batch=10, batch_answer=good_answer), BatchLLM(batch=1)
    r._inst = {cli["id"]: inst_cli, loc["id"]: inst_loc}
    assert r.batch_size == 10
    out = r.classify_batch(pages(10))
    assert len(inst_cli.prompts) == 1 and len(out) == 10
    inst_cli.generate = lambda *a, **k: (_ for _ in ()).throw(LLMError("Claude usage limit reached", kind="limit"))
    out = r.classify_batch(pages(4))  # limit hit: the local model answers, no error reaches the caller
    assert len(inst_loc.single) == 4 and all(o is not None for o in out)
    assert r.batch_size == 1 and "stopped until" in r.blocked(cli, "classify")  # stopped for the window; batch size follows the model that answers
    assert db.c.execute("SELECT COUNT(*) FROM llm_usage WHERE ok=0").fetchone()[0] >= 1


def test_llm_prices_and_model_info_commands(cfg, db, monkeypatch):
    e = llmreg.new_entry(cfg, "api", "gpt-x", base_url="https://r/v1", key="K" * 20)
    llmreg.add_model(cfg, e)
    out = []
    monkeypatch.setattr(ui, "ok", lambda m: out.append(m)); monkeypatch.setattr(ui, "fail", lambda m: out.append("FAIL " + m))
    monkeypatch.setattr(ui, "info", lambda m: out.append(m)); monkeypatch.setattr(ui.console, "print", lambda *a, **k: out.append(str(a[0])))
    ctx = Ctx(cfg, db)
    modelcmds.cmd_llm(ctx, ["prices", e["id"], "2.5", "10"])
    assert llmreg.get(cfg, e["id"])["price_in"] == 2.5 and "2.5/10.0" in out[-1]
    modelcmds.cmd_llm(ctx, ["prices", e["id"], "free"])
    assert llmreg.get(cfg, e["id"])["free"] is True
    modelcmds.cmd_llm(ctx, ["prices", "m9", "1", "2"])
    assert out[-1].startswith("FAIL usage")
    monkeypatch.setattr(claudecli, "binary", lambda: "/bin/claude")
    monkeypatch.setattr(claudecli, "auth_info", lambda b: {"kind": "subscription", "plan": "pro", "how": "claude.ai"})
    modelcmds.cmd_model(ctx, ["info"])
    t = "\n".join(out)
    assert "Anthropic's terms and billing" in t and "support.claude.com" in t and "login: subscription (pro)" in t and "12 calls/hour" in t
    assert "K" * 20 not in t


def test_checks_models_do_not_call_the_cli(cfg):
    e = llmreg.new_entry(cfg, "claude_cli", "claude (CLI)", roles=["chat"], consent=True)
    llmreg.add_model(cfg, e)
    res = checks.models(cfg)
    assert res[0][1] and "not called by /test" in res[0][2]


def test_auth_status_uses_the_official_cli_exit_code_and_never_reads_credentials(monkeypatch):
    calls = []

    class R:
        def __init__(self, rc, out):
            self.returncode, self.stdout, self.stderr = rc, out, ""
    monkeypatch.setattr(claudecli, "help_text", lambda b: "Commands:\n  auth    Manage authentication\n")

    def fake(argv, timeout=20):
        calls.append(argv)
        if argv[1:] == ["auth", "--help"]:
            return R(0, "Commands:\n  login [options]  Sign in\n  logout  Log out\n  status [options]  Show authentication status\n")
        return R(0, json.dumps({"loggedIn": True, "authMethod": "claude.ai", "email": "secret@example.com"}))
    monkeypatch.setattr(claudecli, "_run", fake)
    assert claudecli.auth_commands("/bin/claude") == {"status": True, "login": True}
    ok, how = claudecli.auth_status("/bin/claude")
    assert ok is True and how == "claude.ai" and "secret@example.com" not in how
    assert ["/bin/claude", "auth", "status"] in calls
    monkeypatch.setattr(claudecli, "_run", lambda argv, timeout=20: R(1, "{}") if argv[-1] == "status" else R(0, "  status\n  login\n"))
    assert claudecli.auth_status("/bin/claude")[0] is False
    monkeypatch.setattr(claudecli, "help_text", lambda b: "Commands:\n  mcp  Configure\n")
    assert claudecli.auth_status("/bin/claude")[0] is None  # no status command in this version: unknown, never guessed


def test_run_login_passes_the_terminal_through_and_captures_nothing(monkeypatch):
    seen = {}
    monkeypatch.setattr(claudecli, "auth_commands", lambda b: {"status": True, "login": True})
    monkeypatch.setattr(claudecli.subprocess, "run", lambda argv, **kw: seen.update(argv=argv, kw=kw) or type("R", (), {"returncode": 0})())
    assert claudecli.run_login("/bin/claude") is True
    assert seen["argv"] == ["/bin/claude", "auth", "login"] and seen["kw"] == {}  # no capture, no stdin/stdout redirection
    monkeypatch.setattr(claudecli, "auth_commands", lambda b: {"status": True, "login": False})
    assert claudecli.run_login("/bin/claude") is False


def test_cli_argv_still_contains_every_isolation_flag_and_no_credential_access():
    f = claudecli.detect_flags("-p, --print\n--tools\n--output-format\n--no-session-persistence\n--strict-mcp-config\n"
                               "--disable-slash-commands\n--system-prompt\n--safe-mode")
    a = claudecli.build_args("/bin/claude", f, system="S")
    for flag in ("-p", "--tools", "--safe-mode", "--no-session-persistence", "--strict-mcp-config", "--disable-slash-commands"):
        assert flag in a
    assert a[a.index("--output-format") + 1] == "json" and a[a.index("--tools") + 1] == ""


def test_config_v6_refreshes_only_untouched_old_defaults_with_a_backup():
    raw = {"version": 5, "lifetime_target_days": 60, "claude_cli": {"calls_per_hour": 6, "calls_per_day": 30, "min_interval_s": 30}}
    config.config_path().write_text(json.dumps(raw))
    c = config.load()
    assert c["version"] == config.CONFIG_VERSION == 8 and c["lifetime_target_days"] == 365
    assert (c["claude_cli"]["calls_per_hour"], c["claude_cli"]["calls_per_day"], c["claude_cli"]["batch_size"]) == (12, 80, 10)
    assert json.loads(config.config_path().with_name("config.json.bak-v5").read_text()) == raw
    user = {"version": 5, "lifetime_target_days": 90, "claude_cli": {"calls_per_hour": 3, "calls_per_day": 9, "min_interval_s": 60}}
    config.config_path().write_text(json.dumps(user))
    c = config.load()
    assert c["lifetime_target_days"] == 90 and c["claude_cli"]["calls_per_hour"] == 3  # the user's own values stay
