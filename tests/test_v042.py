"""v0.4.2: search recency decoupled from the alert window, relevance gate + spam rules, safe fetching, TLD guards, /dorks test
transparency, Serper country targeting, Claude CLI role confirmation."""
import json
import logging
from datetime import timedelta

import pytest
from rich.progress import Progress

from qurihunter import (alerts, classify, cli, config, countries, dates, dorkstore, llmreg, memcmds, modelcmds, relevance, scanner,
                        search, tlds, ui)
from qurihunter.db import DB
from qurihunter.llm import LLM
from qurihunter.models import Program
from qurihunter.search import base, serper, serpapi
from qurihunter.search.base import SearchResult
from qurihunter.search.dorkparse import parse


class Resp:
    def __init__(self, status=200, body=None, headers=None, text=None, chunks=None, encoding="utf-8"):
        self.status_code, self._b, self.headers, self.encoding = status, body if body is not None else {}, headers or {}, encoding
        self.text = text if text is not None else json.dumps(self._b)
        self._chunks, self.closed = chunks, False

    def json(self):
        return self._b

    def iter_content(self, n):
        yield from (self._chunks or [self.text.encode()])

    def close(self):
        self.closed = True


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


def ago(n):
    return dates.iso(dates.utcnow() - timedelta(days=n))


# ── fake provider that records the date parameter it received ────────────────
def fake_provider(monkeypatch, cfg, results=None, pid="ft"):
    seen = []

    class F(base.Provider):
        id, label, period, default_limit, page_size = pid, "Fake", "month", 1000, 10
        paginates = False
        tld_mode = "native"

        def _search(self, key, pd, page, fresh):
            seen.append(fresh or None)
            body = {"q": pd.raw, "page": page + 1}
            if fresh:
                body["tbs"] = f"d{fresh:g}"
            self._send(lambda m, u, **k: None, "POST", "https://fake.example/search", json=body, headers={"X-API-KEY": key})
            return list(results or [])
    monkeypatch.setitem(search.PROVIDERS, pid, F)
    cfg["search"]["providers"] = {pid: {"keys": ["SECRETKEY1234"], "limit": 1000, "quota_type": "monthly"}}
    search.save_sequence(cfg, [pid])
    return seen


def setup_dorks(db, cfg, n=3):
    dorkstore.ensure_default(db)
    db.c.execute("UPDATE dorks SET enabled=0")
    cfg["dorks"]["source"] = "custom"
    cfg["features"]["ai_dorks"] = False
    for i in range(n):
        dorkstore.add_dork(db, f'"responsible disclosure" topic{i} word{i}', "custom", priority=10 - i)
    db.commit()


def run(cfg, db, budget=20):
    with Progress() as pr:
        return scanner.run_dorks(cfg, db, None, pr, budget=budget)


# ── Item 1: decoupled settings ───────────────────────────────────────────────
def test_defaults_are_first_any_later_month_and_the_alert_window_is_separate(cfg):
    assert cfg["dork_search_recency"] == {"first": "any", "later": "month", "sweep": "week", "sweep_share": 0.10}
    assert cfg["recency_days"] == 7 and cfg["pages_per_dork"] == 1
    assert config.search_recency_days(cfg, "first") is None and config.search_recency_days(cfg, "later") == 31.0
    assert config.search_recency_days(cfg, "sweep") == 7.0
    cfg["recency_days"] = 3  # the alert window changes...
    assert config.search_recency_days(cfg, "first") is None and config.search_recency_days(cfg, "later") == 31.0  # ...search does not


@pytest.mark.parametrize("alert", [1, 3, 7, 30, None])
def test_the_alert_window_never_reaches_the_providers_time_parameter(db, cfg, monkeypatch, alert):
    seen = fake_provider(monkeypatch, cfg)
    setup_dorks(db, cfg, 4)
    cfg["recency_days"] = alert
    cfg["dork_search_recency"]["sweep_share"] = 0
    run(cfg, db)
    assert seen == [None] * 4  # first run: no date filter whatever the alert window is
    db.c.execute("DELETE FROM queries"); db.set_meta("seq_batch", ""); db.commit()
    seen.clear()
    run(cfg, db)
    assert seen == [31.0] * 4  # later runs: past month - never 1, 3, 7 or 30 from the alert window
    assert not any(f in (1.0, 3.0, 30.0) for f in seen)


def test_first_run_any_then_past_month_with_a_small_week_sweep(db, cfg, monkeypatch):
    seen = fake_provider(monkeypatch, cfg)
    setup_dorks(db, cfg, 10)
    cfg["dork_search_recency"]["sweep_share"] = 0.20
    run(cfg, db)
    assert seen == [None] * 10
    db.c.execute("DELETE FROM queries"); db.set_meta("seq_batch", ""); db.commit()
    seen.clear()
    run(cfg, db)
    assert seen.count(7.0) == 2 and seen.count(31.0) == 8 and None not in seen  # 20% recent-only sweep


def test_sweep_can_be_switched_off_and_old_unfiltered_share_migrates(db, cfg, monkeypatch):
    seen = fake_provider(monkeypatch, cfg)
    setup_dorks(db, cfg, 5)
    run(cfg, db)
    db.c.execute("DELETE FROM queries"); db.set_meta("seq_batch", ""); db.commit()
    seen.clear()
    cfg["dork_search_recency"]["sweep_share"] = 0
    run(cfg, db)
    assert 7.0 not in seen
    config.config_path().write_text(json.dumps({"version": 6, "dorks": {"unfiltered_share": 0.25}}))
    c = config.load()
    assert c["version"] == config.CONFIG_VERSION == 7 and c["dork_search_recency"]["sweep_share"] == 0.25
    assert c["dork_search_recency"]["first"] == "any"


def hit(domain, snippet="report a vulnerability bounty", pub=None):
    return SearchResult(f"Responsible disclosure | {domain}", f"https://{domain}/responsible-disclosure", snippet, pub)


def test_discovery_then_alert_window_first_run_is_silent_baseline_later_run_alerts_new_pages(db, cfg, monkeypatch):
    cfg["notify"]["channels"] = ["telegram"]
    fake_provider(monkeypatch, cfg, [hit("old.ch"), hit("dated.ch", pub=ago(1))])
    setup_dorks(db, cfg, 1)
    run(cfg, db)  # first run, any date: old.ch is stored silently; dated.ch has a publish date inside the alert window
    rows = {r["dedupe_key"]: r for r in db.c.execute("SELECT * FROM programs")}
    assert rows["web:old.ch"]["baseline"] == 1 and rows["web:dated.ch"]["baseline"] == 0
    assert [r["dedupe_key"] for r, _ in alerts.due(db, cfg)] == ["web:dated.ch"]
    db.c.execute("DELETE FROM queries"); db.set_meta("seq_batch", ""); db.commit()
    fake_provider(monkeypatch, cfg, [hit("old.ch"), hit("fresh.ch")])
    run(cfg, db)  # later run (past month): a never-seen page is candidate-new; the known one stays what it was
    assert db.c.execute("SELECT baseline FROM programs WHERE dedupe_key='web:fresh.ch'").fetchone()[0] == 0
    assert db.c.execute("SELECT baseline FROM programs WHERE dedupe_key='web:old.ch'").fetchone()[0] == 1
    assert {r["dedupe_key"] for r, _ in alerts.due(db, cfg)} == {"web:dated.ch", "web:fresh.ch"}


def test_chat_search_uses_the_search_recency_not_the_alert_window(db, cfg, monkeypatch):
    from test_chat import FakeProv, Scripted, final, mk, tool
    from qurihunter import chat as chatmod
    from qurihunter.search.pool import KeyRing, SearchPool
    cfg["recency_days"] = 7
    got = []
    prov = FakeProv()
    orig = SearchPool.search
    monkeypatch.setattr(SearchPool, "search", lambda self, d, **k: got.append(k.get("days")) or orig(self, d, **k))
    cfg["search"]["providers"] = {"fake": {"keys": ["K"], "limit": 100}}
    monkeypatch.setattr(chatmod, "build_pool", lambda c, d: SearchPool([KeyRing(prov, ["K"], 100, d)], d))
    mk(db, cfg, Scripted([tool("search_web", query='"responsible disclosure" site:.ch'), final("ok")])).turn("search swiss")
    assert got == [None]  # "any": the 7-day alert window was not sent


# ── Item 1/4: /dorks test ────────────────────────────────────────────────────
def test_dorks_test_prints_exact_request_kept_and_dropped_tables_and_stores_nothing(db, cfg, monkeypatch):
    junk = [SearchResult("Mandora X Move Infinity pres. KNTRLVRLST & Nyra",
                         "https://it.ticketswap.ch/concert-tickets/kntrlvrlst-zurich-2026", "Tickets for the concert in Zurich"),
            SearchResult("Datenschutz - Ubivo", "https://ubivo.ch/datenschutz", "Privacy policy")]
    good = SearchResult("Responsible Disclosure Policy", "https://www.post.ch/responsible-disclosure", "Report a vulnerability to us")
    fake_provider(monkeypatch, cfg, junk + [good])
    out, tables = [], []
    monkeypatch.setattr(ui, "info", lambda m: out.append(str(m)))
    monkeypatch.setattr(ui, "fail", lambda m: out.append("FAIL " + str(m)))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    memcmds.cmd_dorks(Ctx(cfg, db), ["test", '"responsible', 'disclosure"', "site:.ch"])
    titles = [getattr(t, "title", "") for t in tables if hasattr(t, "row_count")]
    assert any(t.startswith("Request actually sent to ft (page 1)") for t in titles)
    kept = next(t for t in tables if hasattr(t, "title") and str(t.title).startswith("KEPT"))
    dropped = next(t for t in tables if hasattr(t, "title") and str(t.title).startswith("DROPPED"))
    assert kept.row_count == 1 and "post.ch" in kept.columns[1]._cells[0] and dropped.row_count == 2
    assert all(c for c in dropped.columns[2]._cells) and any("spam" in c or "not relevant" in c for c in dropped.columns[2]._cells)
    req = next(t for t in tables if str(getattr(t, "title", "")).startswith("Request actually sent"))
    cells = dict(zip(req.columns[0]._cells, req.columns[1]._cells))
    assert cells["query string"] == '"responsible disclosure" site:.ch' and cells["time parameter"].startswith("none")
    assert cells["page"] == "page=1" and cells["country / language"] == "none"
    assert "SECRETKEY1234" not in "".join(map(str, req.columns[1]._cells))
    text = "\n".join(out)
    assert "alert window (7d) is NOT used as the search filter" in text and "search recency for this test: any" in text
    assert "Spent 1 query" in text and "remaining on ft:" in text
    assert db.c.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == 0 and db.c.execute("SELECT COUNT(*) FROM queries").fetchone()[0] == 0
    assert db.c.execute("SELECT COUNT(*) FROM seen_urls").fetchone()[0] == 0


def test_dorks_test_recency_and_pages_options(db, cfg, monkeypatch):
    seen = fake_provider(monkeypatch, cfg, [hit("a.ch")])
    monkeypatch.setattr(ui, "info", lambda m: None); monkeypatch.setattr(ui, "fail", lambda m: None)
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    ctx = Ctx(cfg, db)
    memcmds.cmd_dorks(ctx, ["test", '"bug', 'bounty"', "--recency", "week"])
    memcmds.cmd_dorks(ctx, ["test", '"bug', 'bounty"', "--recency", "14d"])
    memcmds.cmd_dorks(ctx, ["test", '"bug', 'bounty"', "--recency", "any"])
    assert seen == [7.0, 14.0, None]
    out = []
    monkeypatch.setattr(ui, "fail", lambda m: out.append(m))
    memcmds.cmd_dorks(ctx, ["test", '"bug', 'bounty"', "--recency", "fortnight"])
    assert "--recency must be" in out[0] and len(seen) == 3


def test_dry_run_shows_the_translated_request_and_spends_nothing(db, cfg, monkeypatch):
    seen = fake_provider(monkeypatch, cfg)
    tables, out = [], []
    monkeypatch.setattr(ui, "info", lambda m: out.append(str(m)))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    memcmds.cmd_dorks(Ctx(cfg, db), ["test", '"responsible', 'disclosure"', "site:.ch", "--dry-run", "--recency", "week"])
    assert seen == [7.0] and db.c.execute("SELECT COUNT(*) FROM quota").fetchone()[0] == 0  # _search ran in preview: nothing sent, no quota
    t = next(x for x in tables if str(getattr(x, "title", "")).startswith("DRY RUN"))
    cells = dict(zip(t.columns[0]._cells, t.columns[1]._cells))
    assert cells["time parameter"] == "tbs=d7" and "NOT used" in "\n".join(out)


def test_unknown_tld_warns_before_spending_and_asks(db, cfg, monkeypatch):
    seen = fake_provider(monkeypatch, cfg)
    out = []
    monkeypatch.setattr(ui, "info", lambda m: out.append(str(m))); monkeypatch.setattr(ui, "fail", lambda m: out.append("FAIL " + str(m)))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    asked = []
    monkeypatch.setattr(ui, "yn", lambda q, d=True: asked.append(q) or False)
    memcmds.cmd_dorks(Ctx(cfg, db), ["test", '"responsible', 'disclosure"', "site:.du"])
    assert seen == [] and asked and "spend 1 query" in asked[0]
    assert any(".du is not a real top-level domain" in m and ".de" in m for m in out) and any("cancelled" in m for m in out)
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    memcmds.cmd_dorks(Ctx(cfg, db), ["test", '"responsible', 'disclosure"', "site:.du"])
    assert len(seen) == 1  # the user said yes
    seen.clear()
    memcmds.cmd_dorks(Ctx(cfg, db), ["test", '"responsible', 'disclosure"', "site:.du", "--dry-run"])
    assert len(seen) == 1 and db.c.execute("SELECT COUNT(*) FROM quota").fetchone()[0] == 1  # dry run: no prompt, no extra spend


def test_unknown_tld_dorks_are_parked_in_scans_and_cost_nothing(db, cfg, monkeypatch):
    seen = fake_provider(monkeypatch, cfg)
    dorkstore.ensure_default(db)
    db.c.execute("UPDATE dorks SET enabled=0"); cfg["dorks"]["source"] = "custom"; cfg["features"]["ai_dorks"] = False
    dorkstore.add_dork(db, '"responsible disclosure typo" site:.du', "custom")
    db.commit()
    msgs = run(cfg, db)
    assert seen == [] and any("parked" in m for m in msgs)
    st, why = search.PROVIDERS["serper"]({}).express('"x" site:.du')
    assert st == "parked" and "unknown TLD .du" in why and ".de" in why
    assert tlds.is_known("ch") and tlds.is_known(".eu") and tlds.is_known("io") and not tlds.is_known("du") and "de" in tlds.suggest("du")


# ── Item 4: Serper / SerpAPI country targeting ───────────────────────────────
def test_serper_sends_gl_and_hl_with_a_tld_dork_and_not_without(monkeypatch):
    sent = []
    monkeypatch.setattr(serper, "request", lambda m, u, **kw: sent.append(kw["json"]) or Resp(200, {"organic": []}))
    p = serper.Serper({})
    p.search("K", '"responsible disclosure" site:.ch', days=None)
    assert sent[-1]["gl"] == "ch" and sent[-1]["hl"] == "de" and sent[-1]["q"] == '"responsible disclosure" site:.ch' and "tbs" not in sent[-1]
    p.search("K", '"responsible disclosure"', days=7)
    assert "gl" not in sent[-1] and sent[-1]["tbs"] == "qdr:w"
    p.search("K", '"bounty" site:.io')
    assert "gl" not in sent[-1]  # .io is not a country
    p.search("K", '"bounty" site:.uk')
    assert sent[-1]["gl"] == "gb" and sent[-1]["hl"] == "en"
    serper.Serper({"country_targeting": False}).search("K", '"x" site:.ch')
    assert "gl" not in sent[-1]
    serper.Serper({"language_targeting": False}).search("K", '"x" site:.ch')
    assert sent[-1]["gl"] == "ch" and "hl" not in sent[-1]


def test_serper_tld_style_dot_or_bare(monkeypatch):
    sent = []
    monkeypatch.setattr(serper, "request", lambda m, u, **kw: sent.append(kw["json"]["q"]) or Resp(200, {"organic": []}))
    serper.Serper({}).search("K", '"responsible disclosure" site:.ch')
    serper.Serper({"tld_style": "bare"}).search("K", '"responsible disclosure" site:.ch')
    assert sent == ['"responsible disclosure" site:.ch', '"responsible disclosure" site:ch']


def test_serpapi_gets_the_same_country_targeting(monkeypatch):
    sent = []
    monkeypatch.setattr(serpapi, "request", lambda m, u, **kw: sent.append(kw["params"]) or Resp(200, {"organic_results": []}))
    serpapi.SerpAPI({}).search("K", '"responsible disclosure" site:.ch')
    assert sent[0]["gl"] == "ch" and sent[0]["hl"] == "de" and sent[0]["engine"] == "google"


def test_request_capture_masks_secrets_and_preview_sends_nothing(monkeypatch):
    called = []
    monkeypatch.setattr(serper, "request", lambda *a, **k: called.append(1))
    p = serper.Serper({})
    req = p.preview('"responsible disclosure" site:.ch', days=7)
    assert called == [] and req["json"]["gl"] == "ch" and req["json"]["tbs"] == "qdr:w" and req["headers"]["X-API-KEY"].startswith("…")
    assert "DRY-RUN-KEY-0000" not in json.dumps(req) and req["url"] == "https://google.serper.dev/search"
    assert countries.gl_for("io") is None and countries.gl_for("ch") == "ch" and countries.lang_of("ch") == "de"


# ── Item 2: relevance gate ───────────────────────────────────────────────────
DORK = '"responsible disclosure" site:.ch'
REAL_JUNK = [  # the ten results of the real /dorks test, with the kind of snippet Google shows for them
    ("Anthropic IPO Risks Highlight AI Existential Threats and ...", "https://en.cryptonomist.ch/2026/09/29/anthropic-ipo-risks/", "Crypto news about the IPO."),
    ("Wieland Electric", "https://www.wieland-electric.ch/", "Electrical connection technology."),
    ("Mandora X Move Infinity pres. KNTRLVRLST & Nyra", "https://it.ticketswap.ch/concert-tickets/kntrlvrlst-zurich-zinkbad-2026-10-03-CctMQzuhh91mGx3y4HKAu", "Buy tickets."),
    ("Ferienwohnung Nordsee, Westerland, Firma Könemann GmbH", "https://www.traum-ferienwohnungen.ch/751734/", "Ferienwohnung mieten."),
    ("Operator Alarm- und Einsatzzentrale 100% (m/w/d)", "https://www.jobzueri.ch/job/operator-alarm-und-einsatzzentrale-100-m-w-d/956954", "Jobs in Zürich."),
    ("Ferienwohnung Kreutzer Ferienhaus Greune-Stee, Borkum ...", "https://www.traum-ferienwohnungen.ch/121247/", "Ferienhaus Borkum."),
    ("الشميله من اي شمر", "https://fabs-media.ch/et/exclusive/anthropology/rare-chumuya-sito-politica", "موقع إخباري"),
    ("Ferienhaus Blockhaus 1, Bad Sachsa, Familie Fuchs", "https://www.traum-ferienwohnungen.ch/ferienhaus/80880/", "Ferienhaus mieten."),
    ("Datenschutz - Ubivo", "https://ubivo.ch/datenschutz", "Datenschutzerklärung."),
    ("Untitled", "https://inzh.ch/it/places/rapperswil-zuerichsee/id/1011?redirectFallback=https://jqk-339.com", ""),
]


def test_every_real_junk_result_is_dropped_or_never_survives_the_cheap_rules():
    items = [SearchResult(t, u, s) for t, u, s in REAL_JUNK]
    kept, dropped = relevance.filter_results(DORK, items, log_drops=False)
    assert kept == [] and [d[0].url for d in dropped] == [u for _, u, s in REAL_JUNK] and all(d[1] for d in dropped)
    reasons = {d[0].url: d[1] for d in dropped}
    assert "redirector" in reasons[REAL_JUNK[-1][1]] and "non-Latin" in reasons[REAL_JUNK[6][1]]
    assert all(("spam" in r or "not relevant" in r) for r in reasons.values())
    # without any snippet the same pages may only reach the cheap rules check (no LLM, no fetch) - and the rules reject them
    bare = [SearchResult(t, u, "") for t, u, s in REAL_JUNK[:3]]
    kept2, dropped2 = relevance.filter_results(DORK, bare, log_drops=False)
    assert all(k.rules_only for k in kept2)
    assert all(classify.from_result(k, None)[0] is None for k in kept2)
    spam = relevance.check(DORK, REAL_JUNK[-1][1], "Untitled", "responsible disclosure")  # even WITH the phrase: redirector param
    assert spam[0] == "drop" and "redirector" in spam[1]


def test_spam_rules_urls_titles_words_scripts_and_exemptions():
    chk = lambda url, title="t", snippet="responsible disclosure", dork=DORK: relevance.check(dork, url, title, snippet)  # noqa: E731
    for url in ("https://hackerfunk.ch/get.php?web=http://evil.example/x", "https://a.ch/p?url=https://b.example",
                "https://a.ch/r?redirect=https%3A%2F%2Fb.example", "https://a.ch/go.php?x=1", "https://a.ch/p?goto=http://b"):
        v, why = chk(url)
        assert v == "drop" and "redirector" in why, url
    assert chk("https://a.ch/jobs/security-engineer")[0] == "drop"
    assert chk("https://a.ch/stellenangebote/it")[0] == "drop" and chk("https://a.ch/tickets/123")[0] == "drop"
    assert chk("https://ferienhaus-xyz.ch/")[0] == "drop"
    assert chk("https://a.ch/news", snippet="responsible disclosure and casino bonus")[0] == "drop"
    assert chk("https://a.ch/x", title="Шалаш и интернет магазин")[0] == "drop"
    assert chk("https://a.ch/jobs/responsible-disclosure-policy")[0] == "keep"  # a clear policy path outranks the soft path rule
    assert chk("https://a.ch/security/responsible-disclosure")[0] == "keep"
    assert relevance.check('"脆弱性 報告" site:.jp', "https://a.jp/vdp", "脆弱性報告について", "脆弱性 報告 窓口")[0] == "keep"  # own script is fine
    assert relevance.url_ok("https://a.ch/policy") and not relevance.url_ok("https://a.ch/get.php?web=http://x") \
        and not relevance.url_ok("https://github.com/x/y")


def test_relevance_phrase_terms_synonyms_accents_and_no_snippet():
    k = lambda title, snippet="", url="https://x.ch/security", dork=DORK: relevance.check(dork, url, title, snippet)[0]  # noqa: E731
    assert k("Responsible Disclosure Policy", "x") == "keep"
    assert k("RESPONSIBLE   disclosure", "x") == "keep"  # case and spacing
    assert k("Security", "We run a coordinated vulnerability disclosure programme") == "keep"  # English synonym
    assert k("Sicherheit", "Hier können Sie eine Sicherheitslücke melden") == "keep"  # German synonym, accent folded (.ch -> de)
    assert k("Sicherheit", "Hier koennen Sie eine Sicherheitsluecke melden") == "keep"
    assert k("Security", "Bitte melden Sie Schwachstellen", dork='"responsible disclosure" site:.at') == "keep"
    assert k("Anthropic IPO", "Crypto news") == "drop"
    assert k("Security", "", url="https://x.ch/responsible-disclosure") == "keep"  # phrase found in the URL
    assert k("Security", "") == "rules-only"  # no snippet and nothing in title/URL: only the cheap rules check
    assert k("Bug bounty program", "x", dork='"bug bounty" inurl:security', url="https://x.com/security") == "keep"
    # no quotes: ALL key terms must appear
    nq = 'security reward program site:.ch'
    assert relevance.check(nq, "https://x.ch/a", "Security reward programme", "reward")[0] in ("keep", "drop")
    assert relevance.check('vulnerability reward site:.ch', "https://x.ch/a", "Vulnerability reward scheme", "x")[0] == "keep"
    assert relevance.check('vulnerability reward site:.ch', "https://x.ch/a", "Vulnerability scanner", "x")[0] == "drop"
    assert relevance.fold("Sicherheitslücke – Ünïcode!") == "sicherheitslucke unicode"


def test_spam_rules_file_is_editable_copied_to_the_home_and_drops_are_logged(tmp_path, caplog):
    p = relevance.rules_path()
    assert not p.exists()
    relevance.load_rules()
    assert p.exists() and "redirectors and proxy" in p.read_text()  # copied from the packaged default
    assert relevance.check(DORK, "https://acme.ch/policy", "Responsible disclosure", "x")[0] == "keep"
    p.write_text(p.read_text() + "\nurl: acme\\.ch/policy\nword: loremipsum\nbogus line without colon\nurl: [unclosed\n")
    assert relevance.check(DORK, "https://acme.ch/policy", "Responsible disclosure", "x")[0] == "drop"  # the user's rule fires
    assert relevance.check(DORK, "https://b.ch/x", "Responsible disclosure", "loremipsum")[0] == "drop"
    with caplog.at_level(logging.INFO):
        relevance.filter_results(DORK, [SearchResult("t", "https://hackerfunk.ch/get.php?web=http://x", "responsible disclosure")])
    assert any("relevance drop https://hackerfunk.ch/get.php" in m and "spam" in m for m in caplog.messages)
    assert any("ignored" in m for m in caplog.messages)  # the broken regex line is skipped (logged), never fatal


def test_scan_drops_before_any_llm_call_or_storage_and_remembers_only_spam(db, cfg, monkeypatch):
    class Counting(LLM):
        def __init__(self):
            self.n = 0
            self.batch_size = 1

        def classify(self, *a, **k):
            self.n += 1
            return {"is_program": True, "type": "vdp", "confidence": 0.9, "reason": "x"}
    results = [hit("good.ch"), SearchResult("Anthropic IPO", "https://news.ch/ipo", "crypto news"),
               SearchResult("responsible disclosure", "https://spam.ch/get.php?web=http://x", "responsible disclosure"),
               SearchResult("Tickets", "https://it.ticketswap.ch/concert-tickets/a", "responsible disclosure tickets")]
    fake_provider(monkeypatch, cfg, results)
    setup_dorks(db, cfg, 1)
    llm = Counting()
    with Progress() as pr:
        lines = scanner.run_dorks(cfg, db, llm, pr, budget=5)
    assert llm.n == 1  # only the relevant, clean hit reached the LLM
    assert {r["dedupe_key"] for r in db.c.execute("SELECT dedupe_key FROM programs")} == {"web:good.ch"}
    assert db.seen("https://spam.ch/get.php?web=http://x")["verdict"] == "not_program"  # junk is remembered
    assert db.seen("https://news.ch/ipo") is None  # mere irrelevance is NOT remembered (another dork may match it)
    assert any("dropped by the relevance gate" in l for l in lines)


# ── Item 3: safe fetching ────────────────────────────────────────────────────
@pytest.fixture
def net(monkeypatch):
    """Fake DNS + HTTP for fetch_page. dns: host -> ip."""
    import socket
    dns = {"example.com": "93.184.216.34", "other.org": "93.184.216.35", "evil.test": "10.0.0.5", "metadata.test": "169.254.169.254",
           "local.test": "127.0.0.1", "v6.test": "::1"}
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **k: [(2, 1, 6, "", (dns.get(host) or host, port))]
                        if (host in dns or host.replace(".", "").isdigit()) else (_ for _ in ()).throw(OSError("nxdomain")))
    calls = []
    routes = {}

    def fake_get(url, **kw):
        calls.append((url, kw))
        r = routes[url]
        return r() if callable(r) else r
    monkeypatch.setattr(classify, "get", fake_get)
    return routes, calls


@pytest.mark.parametrize("url,ok", [("https://example.com/a", True), ("http://example.com/a", True), ("file:///etc/passwd", False),
                                    ("ftp://example.com/x", False), ("gopher://example.com", False), ("http://127.0.0.1/", False),
                                    ("http://10.1.2.3/", False), ("http://192.168.0.1/", False), ("http://169.254.169.254/latest", False),
                                    ("http://[::1]/", False), ("http://evil.test/", False), ("http://metadata.test/", False),
                                    ("http://local.test/", False), ("http://v6.test/", False), ("http://user:pw@example.com/", False),
                                    ("http://nonexistent.invalid/", False), ("http://0.0.0.0/", False), ("", False)])
def test_ssrf_guard(net, url, ok):
    assert classify.public_target(url)[0] is ok


def test_fetch_page_happy_path_strips_scripts_and_caps_the_body(net):
    routes, calls = net
    html = b"<html><script>alert(1)</script><style>x{}</style><body><nav>menu</nav><p>Report a vulnerability here</p></body></html>"
    routes["https://example.com/p"] = Resp(200, headers={"content-type": "text/html; charset=utf-8"}, chunks=[html])
    t = classify.fetch_page("https://example.com/p")
    assert t == "Report a vulnerability here"
    kw = calls[0][1]
    assert kw["allow_redirects"] is False and kw["stream"] is True and kw["timeout"] == 12
    big = Resp(200, headers={"content-type": "text/html"}, chunks=iter([b"a" * 100_000] * 50))
    routes["https://example.com/big"] = big
    assert len(classify.fetch_page("https://example.com/big", limit=10**7)) <= classify.MAX_BYTES and big.closed


@pytest.mark.parametrize("headers,status", [({"content-type": "application/pdf"}, 200), ({"content-type": "application/zip"}, 200),
                                            ({"content-type": "text/html", "content-disposition": "attachment; filename=x.html"}, 200),
                                            ({"content-type": "image/png"}, 200), ({"content-type": "text/html"}, 404),
                                            ({"content-type": "text/html", "content-length": str(10**9)}, 200)])
def test_fetch_page_refuses_downloads_and_non_text(net, headers, status):
    routes, _ = net
    routes["https://example.com/f"] = Resp(status, headers=headers, chunks=[b"<p>secret</p>"])
    assert classify.fetch_page("https://example.com/f") == ""


def test_fetch_page_redirects_same_domain_followed_cross_domain_gated_private_refused(net):
    routes, calls = net
    ok = Resp(200, headers={"content-type": "text/html"}, chunks=[b"<p>arrived</p>"])
    routes["https://example.com/a"] = Resp(301, headers={"Location": "/b"})
    routes["https://example.com/b"] = ok
    assert classify.fetch_page("https://example.com/a") == "arrived"  # same domain: followed
    routes["https://example.com/c"] = Resp(302, headers={"Location": "https://other.org/x"})
    routes["https://other.org/x"] = Resp(200, headers={"content-type": "text/html"}, chunks=[b"<p>other domain</p>"])
    assert classify.fetch_page("https://example.com/c") == "other domain"  # a clean different domain passes the gate again
    routes["https://example.com/d"] = Resp(302, headers={"Location": "https://other.org/get.php?web=http://x"})
    assert classify.fetch_page("https://example.com/d") == "" and not any("get.php" in c[0] for c in calls)  # junk target: refused
    routes["https://example.com/e"] = Resp(302, headers={"Location": "http://evil.test/internal"})
    assert classify.fetch_page("https://example.com/e") == "" and not any("evil.test" in c[0] for c in calls)  # private IP: refused
    routes["https://example.com/f"] = Resp(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})
    assert classify.fetch_page("https://example.com/f") == ""
    routes["https://example.com/g"] = Resp(302, headers={"Location": "ftp://example.com/x"})
    assert classify.fetch_page("https://example.com/g") == ""
    routes["https://example.com/loop"] = Resp(302, headers={"Location": "https://example.com/loop"})
    assert classify.fetch_page("https://example.com/loop") == "" and len([c for c in calls if c[0].endswith("/loop")]) == 4
    routes["https://example.com/gh"] = Resp(302, headers={"Location": "https://github.com/a/b"})
    assert classify.fetch_page("https://example.com/gh") == ""  # an ignored/aggregator domain target


def test_spam_urls_are_never_fetched_and_private_targets_never_requested(net):
    routes, calls = net
    assert classify.fetch_page("https://example.com/get.php?web=http://x") == "" and calls == []
    assert classify.fetch_page("http://127.0.0.1:8080/admin") == "" and calls == []
    assert classify.fetch_page("https://github.com/x/readme") == "" and calls == []


def test_classification_uses_the_snippet_first_and_fetches_only_when_needed(monkeypatch):
    fetched, seen = [], []

    class L(LLM):
        def __init__(self, conf):
            self.conf = conf

        def classify(self, url, title, snippet, page_text=""):
            seen.append(page_text)
            return {"is_program": True, "type": "vdp", "confidence": self.conf, "reason": "ok"}
    monkeypatch.setattr(classify, "fetch_text", lambda url, limit=4000: fetched.append(url) or "PAGE TEXT")
    long_snip = "Report a vulnerability to our security team. We run a responsible disclosure programme and reward researchers."
    it = SearchResult("Responsible disclosure | acme", "https://acme.ch/responsible-disclosure", long_snip)
    p, _ = classify.from_result(it, L(0.9))
    assert p is not None and fetched == [] and seen == [""]  # confident from title+snippet: no page fetch
    fetched.clear(); seen.clear()
    p, _ = classify.from_result(it, L(0.5))  # unsure -> now it is worth a fetch and a second look
    assert fetched == ["https://acme.ch/responsible-disclosure"] and seen == ["", "PAGE TEXT"]
    fetched.clear(); seen.clear()
    short = SearchResult("Responsible disclosure | acme", "https://acme.ch/responsible-disclosure", "report")  # thin snippet
    classify.from_result(short, L(0.9))
    assert fetched and seen == ["PAGE TEXT"]


# ── Item 5: roles / bulk ─────────────────────────────────────────────────────
def two_models(cfg):
    loc = llmreg.new_entry(cfg, "local", "qwen")
    llmreg.add_model(cfg, loc)
    cli_m = llmreg.new_entry(cfg, "claude_cli", "claude (CLI)", roles=["chat"], consent=True)
    llmreg.add_model(cfg, cli_m)
    return loc, cli_m


def test_model_roles_asks_for_confirmation_instead_of_refusing(cfg, db, monkeypatch):
    loc, m = two_models(cfg)
    out, asked = [], []
    monkeypatch.setattr(ui, "ok", lambda s: out.append(s)); monkeypatch.setattr(ui, "fail", lambda s: out.append("FAIL " + s))
    monkeypatch.setattr(ui, "info", lambda s: out.append(s))
    monkeypatch.setattr(ui, "yn", lambda q, d=True: asked.append(q) or False)
    ctx = Ctx(cfg, db)
    modelcmds.cmd_model(ctx, ["roles", m["id"], "classify", "date_kind"])
    assert asked and "12 calls/hour" in asked[0] and "80/day" in asked[0] and "batches of 10" in asked[0] and loc["id"] in asked[0]
    assert llmreg.get(cfg, m["id"])["roles"] == ["chat"] and not cfg["claude_cli_allow_bulk"] and out[-1].startswith("FAIL not changed")
    monkeypatch.setattr(ui, "yn", lambda q, d=True: asked.append(q) or True)
    modelcmds.cmd_model(ctx, ["roles", m["id"], "classify", "date_kind"])
    assert llmreg.get(cfg, m["id"])["roles"] == ["classify", "date_kind"] and cfg["claude_cli_allow_bulk"] is True
    assert json.loads(config.config_path().read_text())["claude_cli_allow_bulk"] is True
    asked.clear()
    modelcmds.cmd_model(ctx, ["roles", m["id"], "chat", "summarize", "classify"])  # already on: no second question
    assert asked == [] and "classify" in llmreg.get(cfg, m["id"])["roles"]
    r = llmreg.Router(cfg, db)
    assert r.blocked(llmreg.get(cfg, m["id"]), "classify") != "role 'classify' is excluded for the Claude CLI"


def test_set_roles_without_a_confirm_callback_points_to_llm_bulk(cfg):
    _, m = two_models(cfg)
    assert "/llm bulk on" in llmreg.set_roles(cfg, m["id"], ["classify"])


def test_llm_bulk_is_the_single_switch(cfg, db, monkeypatch):
    _, m = two_models(cfg)
    out = []
    monkeypatch.setattr(ui, "ok", lambda s: out.append(s)); monkeypatch.setattr(ui, "info", lambda s: out.append(s))
    monkeypatch.setattr(ui, "fail", lambda s: out.append("FAIL " + s))
    ctx = Ctx(cfg, db)
    modelcmds.cmd_llm(ctx, ["bulk"])
    assert "OFF" in out[-1]
    asked = []
    monkeypatch.setattr(ui, "yn", lambda q, d=True: asked.append(q) or False)
    modelcmds.cmd_llm(ctx, ["bulk", "on"])
    assert not cfg["claude_cli_allow_bulk"] and "12 calls/hour" in asked[0] and "local model stays as fallback" in asked[0]
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    modelcmds.cmd_llm(ctx, ["bulk", "on"])
    assert cfg["claude_cli_allow_bulk"] is True and json.loads(config.config_path().read_text())["claude_cli_allow_bulk"] is True
    router = llmreg.Router(cfg, db)
    with router.bulk():
        assert router.blocked(m, "chat") is None  # bulk jobs allowed now
    modelcmds.cmd_llm(ctx, ["bulk", "off"])
    assert cfg["claude_cli_allow_bulk"] is False and "OFF" in out[-1]
    r2 = llmreg.Router(cfg, db)
    with r2.bulk():
        assert "bulk jobs are excluded" in r2.blocked(m, "chat")


# ── display of both settings ─────────────────────────────────────────────────
def test_status_config_and_recency_commands_show_both_settings(db, cfg, monkeypatch):
    from rich.console import Console
    out = []
    monkeypatch.setattr(ui, "info", lambda s: out.append(str(s))); monkeypatch.setattr(ui, "ok", lambda s: out.append(str(s)))
    monkeypatch.setattr(ui, "fail", lambda s: out.append("FAIL " + str(s)))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    ctx = Ctx(cfg, db)
    cli.cmd_status(ctx, [])
    t = "\n".join(out)
    assert "Search recency (sent to providers): first run any, later runs 1m" in t.replace("31d", "1m") or "first run any, later runs" in t
    assert "Alert window: 7d (applied after discovery)" in t
    con = Console(record=True, width=200)
    con.print(ui.config_summary(cfg))
    s = con.export_text()
    assert "Alert window" in s and "Search recency" in s and "not the alert window" in s
    out.clear()
    cli.cmd_recency(ctx, ["search"])
    assert "first run any, later runs month" in out[0] and "Alert window: 7d" in out[1]
    cli.cmd_recency(ctx, ["search", "first", "month", "later", "week", "share", "0", "pages", "2"])
    assert cfg["dork_search_recency"]["first"] == "month" and cfg["dork_search_recency"]["later"] == "week" \
        and cfg["dork_search_recency"]["sweep_share"] == 0 and cfg["pages_per_dork"] == 2
    cli.cmd_recency(ctx, ["30d"])
    assert cfg["recency_days"] == 30 and cfg["dork_search_recency"]["first"] == "month"  # alert window change leaves search alone
    assert "does NOT change what the search providers are asked for" in out[-1]
    cli.cmd_recency(ctx, ["search", "first", "never"])
    assert out[-1].startswith("FAIL usage")


def test_help_mentions_the_new_options():
    txt = " ".join(f"{c} {d}" for c, d in cli.HELP)
    assert "--recency" in txt and "--dry-run" in txt and "bulk on|off" in txt


def test_a_typo_tld_never_becomes_a_google_country_parameter():
    assert countries.gl_for("du") is None and countries.gl_for("xx") is None and countries.gl_for("ch") == "ch"
    assert serper.country_params(parse('"x" site:.du'), {}) == {}
