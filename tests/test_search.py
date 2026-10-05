import json
from datetime import datetime, timezone

import pytest

from qurihunter import config, scanner, search
from qurihunter.db import DB
from qurihunter.search import brave, google, tavily
from qurihunter.search.base import Provider, ProviderError, SearchResult
from qurihunter.search.dorkparse import parse
from qurihunter.search.pool import KeyRing, QuotaExhausted, SearchPool
from qurihunter.sources import dorks

DORK = 'intitle:"responsible disclosure" "report a vulnerability" site:.ch -site:hackerone.com -site:github.com'
OR_DORK = 'inurl:"responsible-disclosure" OR inurl:"vulnerability-disclosure" OR inurl:"bug-bounty" site:.se'


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._b, self.headers = status, body or {}, headers or {}
        self.text = json.dumps(self._b)

    def json(self):
        return self._b


# ── dork translation ───────────────────────────────────────────────────────
def test_parse_dork():
    pd = parse(DORK)
    assert pd.tld == "ch" and pd.exclude_domains == ["hackerone.com", "github.com"]
    assert pd.title_terms == ["responsible disclosure"] and pd.phrases == ["report a vulnerability"]
    pd = parse(OR_DORK)
    assert pd.url_terms == ["responsible-disclosure", "vulnerability-disclosure", "bug-bounty"] and pd.tld == "se"


def test_every_builtin_dork_translates_for_every_provider():
    for q in dorks.build([]) + dorks.build(["ch"]):
        pd = parse(q)
        assert pd.terms(), q
        bq = brave.to_brave_query(pd)
        assert bq and "inurl:" not in bq and "intitle:" not in bq and " OR " not in bq and len(bq) <= 400, q
        assert tavily.to_tavily_query(pd) and ":" not in tavily.to_tavily_query(pd).replace("security.txt", "")


def test_brave_keeps_documented_operators():
    q = brave.to_brave_query(parse(DORK))
    assert '"responsible disclosure"' in q and "-site:hackerone.com" in q and "site:.ch" not in q


# ── providers (HTTP mocked) ─────────────────────────────────────────────────
def test_brave_normalises_and_filters_tld(monkeypatch):
    seen = {}

    def fake(method, url, **kw):
        seen.update(kw)
        return Resp(200, {"web": {"results": [
            {"title": "A", "url": "https://acme.ch/vdp", "description": "d1"},
            {"title": "B", "url": "https://other.com/vdp", "description": "d2"}]}})
    monkeypatch.setattr(brave, "request", fake)
    page = brave.Brave().search("KEY", DORK, fresh="week")
    assert page.results == [SearchResult("A", "https://acme.ch/vdp", "d1")]  # .com dropped client-side
    assert seen["headers"]["X-Subscription-Token"] == "KEY"
    assert seen["params"]["country"] == "CH" and seen["params"]["freshness"] == "pw"


def test_tavily_normalises_and_excludes_domains(monkeypatch):
    seen = {}

    def fake(method, url, **kw):
        seen.update(kw)
        return Resp(200, {"results": [{"title": "T", "url": "https://x.se/p", "content": "c"}]})
    monkeypatch.setattr(tavily, "request", fake)
    page = tavily.Tavily().search("K", OR_DORK, fresh="month")
    assert page.results == [SearchResult("T", "https://x.se/p", "c")] and not page.has_more
    assert seen["headers"]["Authorization"] == "Bearer K" and seen["json"]["time_range"] == "month"
    assert tavily.Tavily().search("K", OR_DORK, page=1).results == []  # no pagination


def test_google_passes_dork_through(monkeypatch):
    seen = {}

    def fake(method, url, **kw):
        seen.update(kw)
        return Resp(200, {"items": [{"title": "G", "link": "https://g.ch/a", "snippet": "s"}]})
    monkeypatch.setattr(google, "request", fake)
    page = google.Google({"cx": "CX"}).search("K", DORK, page=1, fresh="week")
    assert page.results[0] == SearchResult("G", "https://g.ch/a", "s")
    assert seen["params"]["q"] == DORK and seen["params"]["start"] == 11 and seen["params"]["cx"] == "CX"
    with pytest.raises(ProviderError):
        google.Google().search("K", DORK)  # missing cx


@pytest.mark.parametrize("mod,cls,status,kind", [
    (brave, brave.Brave, 401, "invalid"), (brave, brave.Brave, 402, "quota"),
    (tavily, tavily.Tavily, 401, "invalid"), (tavily, tavily.Tavily, 432, "quota"),
    (tavily, tavily.Tavily, 500, "transient"), (google, lambda: google.Google({"cx": "c"}), 429, "quota"),
    (google, lambda: google.Google({"cx": "c"}), 403, "invalid")])
def test_error_mapping_and_test_call(monkeypatch, mod, cls, status, kind):
    monkeypatch.setattr(mod, "request", lambda *a, **k: Resp(status, {"error": {"message": "x"}}))
    with pytest.raises(ProviderError) as e:
        cls().search("K", "security.txt")
    assert e.value.kind == kind
    ok, detail = cls().test("K")
    assert ok is False and kind in detail


def test_brave_429_distinguishes_rate_limit_from_quota(monkeypatch):
    monkeypatch.setattr(brave.time, "sleep", lambda s: None)
    monkeypatch.setattr(brave, "request", lambda *a, **k: Resp(429, {}, {"X-RateLimit-Remaining": "0, 0"}))
    with pytest.raises(ProviderError) as e:
        brave.Brave().search("K", "x")
    assert e.value.kind == "quota"
    monkeypatch.setattr(brave, "request", lambda *a, **k: Resp(429, {}, {"X-RateLimit-Remaining": "0, 500"}))
    with pytest.raises(ProviderError) as e:
        brave.Brave().search("K", "x")
    assert e.value.kind == "rate"


# ── pool: rotation, quota, failover ────────────────────────────────────────
class Fake(Provider):
    id, label, period = "fake", "Fake", "day"

    def __init__(self, behaviour):
        super().__init__({})
        self.behaviour, self.calls = behaviour, []

    def _search(self, key, pd, page, fresh):
        self.calls.append(key)
        err = self.behaviour(key, len(self.calls))
        if err:
            raise ProviderError(*err)
        return [SearchResult("t", "https://a.com", "s")]


def test_rotation_exhaustion_and_per_key_quota(db):
    p = Fake(lambda k, n: ("quota", "spent") if k == "K1" and n > 2 else None)
    pool = SearchPool([KeyRing(p, ["K1", "K2", "K3"], 4, db)], db)
    for _ in range(8):
        pool.search("q")
    assert {"K1", "K2", "K3"} == set(p.calls)
    with pytest.raises(QuotaExhausted):
        for _ in range(10):
            pool.search("q")
    assert len(p.calls) == 11  # keys are used in the order added: K1: 2 ok + 1 quota error, K2: 4, K3: 4
    assert pool.total_remaining() == 0


def test_invalid_and_transient_keys_are_skipped(db):
    p = Fake(lambda k, n: ("invalid", "bad") if k == "BAD" else ("transient", "5xx") if k == "FLAKY" else None)
    ring = KeyRing(p, ["BAD", "FLAKY", "GOOD"], 10, db)
    pool = SearchPool([ring], db)
    page, pid = pool.search("q")
    assert page.results and pid == "fake"
    assert ring.remaining("BAD") == 0 and ring.remaining("FLAKY") == 0 and ring.remaining("GOOD") == 9


def test_provider_failover_and_prefer(db):
    a = Fake(lambda k, n: ("quota", "x")); a.id = "a"
    b = Fake(lambda k, n: None); b.id = "b"
    pool = SearchPool([KeyRing(a, ["A"], 5, db), KeyRing(b, ["B"], 5, db)], db)
    assert pool.search("q")[1] == "b"
    with pytest.raises(QuotaExhausted):
        pool.search("q", prefer="a")


def test_monthly_period_and_budget_plan(db):
    class Monthly(Fake):
        period = "month"
    m = Monthly(lambda k, n: None)
    assert m.period_label() == datetime.now(timezone.utc).strftime("%Y-%m")
    assert m.period_end() > datetime.now(timezone.utc)
    pool = SearchPool([KeyRing(m, ["K"], 1000, db)], db)
    budget = pool.plan(60)
    assert 1 <= budget < 20  # ~1000 / (hours left this month), not the whole month at once
    assert pool.rings[0].allowance == budget


def test_quota_keys_are_per_provider(db):
    assert search.key_id("brave", "k") != search.key_id("tavily", "k")


# ── config / wiring ──────────────────────────────────────────────────────────
def test_legacy_google_config_migrates(tmp_path, monkeypatch):
    monkeypatch.setenv("QURIHUNTER_HOME", str(tmp_path))
    (tmp_path / "config.json").write_text(json.dumps(
        {"google": {"cx": "CX", "keys": ["A", "B"], "daily_limit": 100, "max_age": "w2", "pages": 2}}))
    cfg = config.load()
    assert cfg["search"]["providers"]["google"] == {"keys": ["A", "B"], "cx": "CX", "limit": 100}
    assert cfg["search"]["max_age"] == "week" and cfg["search"]["pages"] == 2 and "google" not in cfg


def test_configured_requires_keys_and_options():
    cfg = config.load()
    cfg["search"]["providers"] = {"google": {"keys": ["k"], "cx": ""}, "brave": {"keys": ["b"]}, "tavily": {"keys": []}}
    assert search.configured(cfg) == ["brave"]  # google lacks cx, tavily has no keys


def test_dork_cycle_uses_pool_and_alerts(db, monkeypatch):
    cfg = config.load()
    cfg["dork_search_recency"]["first"] = "month"
    cfg["search"]["providers"] = {"tavily": {"keys": ["T"], "limit": 100}}
    cfg["filters"]["countries"] = ["ch"]
    for q in dorks.build(["ch"]):
        db.dork_record(dorks.qhash(q), q, 0, 0)  # not a first run -> alerts enabled
    monkeypatch.setattr(tavily, "request", lambda *a, **k: Resp(200, {"results": [
        {"title": "Responsible disclosure | Acme", "url": "https://www.acme.ch/responsible-disclosure",
         "content": "Report a vulnerability, bounty"}, {"title": "x", "url": "https://foo.com/vdp", "content": ""}]}))
    from rich.progress import Progress
    with Progress() as prog:
        lines = scanner.run_dorks(cfg, db, None, prog, budget=1)
    assert "tavily: 1" in lines[0] and "1 new" in lines[0]
    assert [r["source"] for r in db.pending()] == ["web"]
