import json
from pathlib import Path

import pytest

from qurihunter import aidorks, config, dorkstore, memcmds, scanner
from qurihunter.db import DB
from qurihunter.search import Tavily, Brave, Google
from qurihunter.search.base import Provider, ProviderError, SearchResult
from qurihunter.search.dorkparse import parse
from qurihunter.search.pool import KeyRing, QuotaExhausted, SearchPool
from qurihunter.sources import dorks as legacy


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


@pytest.fixture
def cfg():
    c = config.load()
    c["dork_search_recency"]["first"] = "month"  # alert-flow tests: the first run must be date-bounded (default is "any")
    return c


def write(tmp_path, text, name="d.txt"):
    p = tmp_path / name
    p.write_text(text)
    return p


# ── default list & import ───────────────────────────────────────────────────
def test_default_list_files_are_in_sync_and_clean():
    assert dorkstore.REPO_DEFAULT.read_text() == dorkstore.BUNDLED_DEFAULT.read_text()
    entries = dorkstore.parse_file(dorkstore.REPO_DEFAULT)
    assert len(entries) >= 100
    assert not any(dorkstore.has_date(e.text) for e in entries)  # no hardcoded dates
    bl = aidorks.blocklist()
    for e in entries:  # the default list contains no exploit / exposed-data dorks
        low = e.text.lower()
        assert not any(b in low for b in ("password", "filetype:", "index of", ".env", "credential", "backup")), e.text


def test_import_strips_dates_for_default_keeps_for_custom_and_never_duplicates(db, tmp_path):
    f = write(tmp_path, "# ---------- Sec A ----------\n\"bug bounty\" after:2026-01-01\n\"bug bounty\"\n# c\n\n"
                        "\"responsible disclosure\" site:.ch\n")
    r = dorkstore.import_file(db, f, "default")
    assert (r.total, r.added, r.duplicates, r.dated) == (3, 2, 1, 1)  # date stripped -> merges with plain line
    assert db.c.execute("SELECT section FROM dorks WHERE text LIKE '%site:.ch%'").fetchone()[0] == "Sec A"
    r2 = dorkstore.import_file(db, f, "default")
    assert r2.added == 0 and r2.duplicates == 3  # re-import adds nothing
    c = write(tmp_path, '"coordinated disclosure" after:2026-02-02\n', "c.txt")
    assert dorkstore.import_file(db, c, "custom").added == 1
    assert "after:2026-02-02" in db.c.execute("SELECT text FROM dorks WHERE grp='custom'").fetchone()[0]


def test_ensure_default_idempotent_and_reset_keeps_custom_and_ai(db, tmp_path):
    r = dorkstore.ensure_default(db)
    n = db.c.execute("SELECT COUNT(*) FROM dorks WHERE grp='default'").fetchone()[0]
    assert r.added == n >= 100 and dorkstore.ensure_default(db) is None
    dorkstore.add_dork(db, '"bug bounty" site:.zz', "custom")
    dorkstore.add_dork(db, '"responsible disclosure" "sehr neu"', "ai")
    db.c.execute("UPDATE dorks SET enabled=0, priority=9 WHERE grp='default'")
    db.c.execute("DELETE FROM dorks WHERE id=(SELECT MIN(id) FROM dorks WHERE grp='default')")
    dorkstore.reset_default(db)
    assert db.c.execute("SELECT COUNT(*) FROM dorks WHERE grp='default' AND enabled=1").fetchone()[0] == n
    assert db.c.execute("SELECT COUNT(*) FROM dorks WHERE grp IN ('custom','ai')").fetchone()[0] == 2


def test_modes_select_groups(db, cfg):
    dorkstore.ensure_default(db)
    dorkstore.add_dork(db, '"bug bounty" site:.zz', "custom")
    dorkstore.add_dork(db, '"bug bounty" "neu"', "ai")
    def groups(mode, ai=True):
        cfg["dorks"]["source"], cfg["features"]["ai_dorks"] = mode, ai
        return {r["grp"] for r in dorkstore.candidates(db, cfg)}
    assert groups("default") == {"default", "ai"} and groups("custom") == {"custom", "ai"}
    assert groups("both") == {"default", "custom", "ai"} and groups("default", ai=False) == {"default"}
    n = db.c.execute("SELECT COUNT(*) FROM dorks").fetchone()[0]
    groups("custom")
    assert db.c.execute("SELECT COUNT(*) FROM dorks").fetchone()[0] == n  # switching never deletes


# ── per-provider merging ─────────────────────────────────────────────────────
def test_tavily_flattening_merges_identical_dorks_but_keeps_distinct_tlds_and_currencies():
    T = Tavily()
    items = [(1, '"bug bounty program" inurl:security', 0), (2, 'inurl:security "bug bounty program"', 5),
             (3, '"bug bounty" "€"', 0), (4, '"bug bounty" "£"', 0),
             (5, '"responsible disclosure" site:.ch', 0), (6, '"responsible disclosure" site:.se', 0)]
    kept, merged = dorkstore.merge_similar(items, T)
    assert merged == [(1, 2)]  # the higher-priority one wins
    assert {k[0] for k in kept} == {2, 3, 4, 5, 6}
    kept, merged = dorkstore.merge_similar(items, Google({"cx": "c"}))
    assert [m[0] for m in merged] == [1] or merged == []  # Google keeps word order significant only via raw text


def test_analysis_report_counts():
    es = [dorkstore.Entry('"a b"'), dorkstore.Entry('"A  B"'), dorkstore.Entry('x after:2026-01-01'), dorkstore.Entry("x")]
    r = dorkstore.analyse(es, Tavily())
    assert r["count"] == 4 and r["exact_duplicates"] == 2 and r["with_dates"] == 1


# ── rotation & budget ────────────────────────────────────────────────────────
def test_rotation_order_and_budget(db, cfg):
    for i, (txt, pr) in enumerate([("bounty a", 0), ("bounty b", 0), ("bounty c", 5), ("bounty d", 0)]):
        dorkstore.add_dork(db, f'"{txt} program" "uniq{i}x"', "custom", priority=pr)
    db.c.execute("UPDATE dorks SET last_run_at='2026-01-02', new_programs_found=1 WHERE text LIKE '%bounty a%'")
    db.c.execute("UPDATE dorks SET last_run_at='2026-01-01', new_programs_found=9 WHERE text LIKE '%bounty b%'")
    cfg["dorks"]["source"], cfg["features"]["ai_dorks"] = "custom", False
    sel = dorkstore.select(db, cfg, Tavily(), budget=3)
    names = [r["text"].split()[0] + r["text"].split()[1] for r in sel.chosen]
    assert len(sel.chosen) == 3 and sel.waiting == 1 and sel.candidates == 4
    assert sel.chosen[0]["text"].startswith('"bounty c')  # priority first
    assert sel.chosen[1]["text"].startswith('"bounty d')  # then never-run, then least recently run
    assert dorkstore.select(db, cfg, Tavily(), budget=100).waiting == 0  # never more than exist
    assert dorkstore.estimate_days(100, 10, 1440) == 10


def test_ai_exploration_share_is_capped(db, cfg):
    for i in range(10):
        dorkstore.add_dork(db, f'"bug bounty" "proven{i}"', "custom")
        dorkstore.add_dork(db, f'"bug bounty" "ai{i}"', "ai")
    cfg["dorks"]["source"], cfg["features"]["ai_dorks"], cfg["dorks"]["ai_share"] = "custom", True, 0.2
    sel = dorkstore.select(db, cfg, None, budget=10)
    assert sel.explore == 2 and sum(r["grp"] == "ai" for r in sel.chosen) == 2  # 20% of 10
    db.c.execute("UPDATE dorks SET new_programs_found=3 WHERE grp='ai' AND text LIKE '%ai0%'")  # a winner is 'proven'
    sel = dorkstore.select(db, cfg, None, budget=10)
    assert sum(r["grp"] == "ai" for r in sel.chosen) == 3  # 2 exploring + 1 winner


def test_country_filter_only_runs_matching_tld_dorks(db, cfg):
    dorkstore.ensure_default(db)
    cfg["filters"]["countries"] = ["ch"]
    dorkstore.ensure_country_dorks(db, cfg["filters"]["countries"])
    rows = dorkstore.candidates(db, cfg)
    assert rows and all(parse(r["text"]).tld == "ch" for r in rows)


# ── noise control ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("url,title", [
    ("https://medium.com/@x/our-bug-bounty", "Our bug bounty program"),
    ("https://apify.com/store/bug-bounty-scraper", "Bug bounty scraper"),
    ("https://github.com/x/awesome-bugbounty/blob/main/README.md", "Awesome bug bounty list"),
    ("https://infosecwriteups.com/top-10-bug-bounty", "Top 10 bug bounty programs"),
    ("https://acme.com/blog/we-launched-a-bug-bounty", "We launched a bug bounty program")])
def test_noise_is_rejected_by_rules(url, title):
    from qurihunter.classify import from_result
    p, reason = from_result(SearchResult(title, url, "bug bounty program report a vulnerability"), None)
    assert p is None, reason


class FakeLLM:
    model, host = "m", "h"

    def __init__(self, verdict):
        self.verdict, self.calls = verdict, 0

    def classify(self, url, title, snippet, page_text=""):
        self.calls += 1
        return self.verdict


def test_every_plausible_hit_goes_through_the_llm_when_available(monkeypatch):
    from qurihunter import classify
    monkeypatch.setattr(classify, "fetch_text", lambda u: "")
    hit = SearchResult("Responsible disclosure | Acme", "https://acme.ch/responsible-disclosure", "report a vulnerability bounty")
    yes = FakeLLM({"is_program": True, "type": "bounty", "confidence": 0.9, "reason": "official"})
    p, _ = classify.from_result(hit, yes)
    assert yes.calls == 1 and p.classified_by == "llm" and p.kind == "bounty"  # even a high-scoring hit is asked
    no = FakeLLM({"is_program": False, "type": "none", "confidence": 0.9, "reason": "it is an article"})
    p, reason = classify.from_result(hit, no)
    assert p is None and reason.startswith("LLM") and no.calls == 1
    p, _ = classify.from_result(hit, None)  # no LLM -> heuristics only
    assert p is not None and p.classified_by == "rules"


# ── seen URLs & rejected memory in the dork pipeline ────────────────────────────
def test_old_and_rejected_urls_are_silently_ignored_next_time(db, cfg):
    hit = SearchResult("Responsible disclosure | Acme", "https://www.acme.ch/responsible-disclosure", "report a vulnerability bounty")
    noise = SearchResult("Top 10 bug bounty tips", "https://foo.ch/blog/top-10-bug-bounty", "")
    calls = {"n": 0}
    def run(item):
        return scanner._handle_result(db, cfg, None, item, windowed=True, first_run=False)
    assert run(hit) == (1, 1) and run(noise) == (0, 0)
    assert db.seen(hit.url)["verdict"] == "official_program" and db.seen(noise.url)["verdict"] == "not_program"
    assert run(hit) == (0, 0) and run(noise) == (0, 0)
    # a *different* page on a domain whose earlier page was rejected is still evaluated (v1 rejected whole domains)
    other = SearchResult("Responsible disclosure | Foo", "https://foo.ch/responsible-disclosure", "report a vulnerability bounty")
    assert run(other) == (1, 1)


def test_first_run_dork_hits_alert_only_when_windowed_or_page_dated(db, cfg):
    from qurihunter import dates
    from datetime import timedelta
    mk = lambda d, pub=None: SearchResult(f"Responsible disclosure | {d}", f"https://{d}/responsible-disclosure",  # noqa: E731
                                           "report a vulnerability bounty", pub)
    # no window enforced by the provider and no page date -> silent baseline
    assert scanner._handle_result(db, cfg, None, mk("a.ch"), windowed=False, first_run=True) == (1, 0)
    # recent page date -> alert even on the very first run
    recent = dates.iso(dates.utcnow() - timedelta(days=1))
    assert scanner._handle_result(db, cfg, None, mk("b.ch", recent), windowed=False, first_run=True) == (1, 1)
    # old page date inside a windowed query -> stored, never alerts (real date beats first_seen)
    old = dates.iso(dates.utcnow() - timedelta(days=500))
    assert scanner._handle_result(db, cfg, None, mk("c.ch", old), windowed=True, first_run=False) == (1, 0)
    pend = [r["name"] for r in db.pending(7)]
    assert any("b.ch" in n for n in pend) and not any("a.ch" in n for n in pend) and not any("c.ch" in n for n in pend)


def test_reclassify_hides_noise_without_alerting(db, cfg):
    from qurihunter.models import Program
    db.insert(Program("web", "good.ch", "good.ch — Responsible disclosure", "https://good.ch/responsible-disclosure",
                      snippet="report a vulnerability bounty"), baseline=False)
    db.insert(Program("web", "bad.ch", "Top 10 bug bounty tips", "https://bad.ch/blog/top-10-bug-bounty"), baseline=True)
    changed, total = scanner.reclassify(db, cfg, None)
    assert (changed, total) == (1, 2)
    assert db.c.execute("SELECT verdict FROM programs WHERE dedupe_key='web:bad.ch'").fetchone()[0] == "not_program"
    assert db.c.execute("SELECT SUM(delivered) FROM programs").fetchone()[0] == 0


# ── self-hosted list source ──────────────────────────────────────────────────
def test_selfhosted_source_registered_and_dedupes_with_disclose_io(db, cfg):
    from qurihunter.sources import platforms
    from qurihunter.models import Program
    assert "selfhosted" in platforms.SOURCES and "selfhosted" in config.PLATFORMS
    a = platforms.parse_selfhosted([{"hosting": "self_hosted", "status": "active", "domain": "acme.ch",
                                     "policy_url": "https://acme.ch/vdp", "first_seen": "2026-10-04", "country": "ch",
                                     "reward": "monetary"}])[0]
    assert a.kind == "bounty" and a.company_key == "acme.ch"
    scanner.ingest(db, cfg, "disclose.io", [Program("disclose.io", "x", "X", "https://x.se/vdp")])
    scanner.ingest(db, cfg, "selfhosted", [Program("selfhosted", "other.ch", "o", "https://other.ch")])
    new, _ = scanner.ingest(db, cfg, "disclose.io", [Program("disclose.io", "https://acme.ch/policy", "Acme", "https://acme.ch/policy")])
    n2, _ = scanner.ingest(db, cfg, "selfhosted", [a])
    assert len(new) == 1 and n2 == []  # same company via another source: enrich, no second alert


# ── cooldown / memory in the batch ───────────────────────────────────────────
class Fake(Provider):
    id, label, period = "fake", "Fake", "day"

    def __init__(self):
        super().__init__({})
        self.calls = []

    def _search(self, key, pd, page, fresh):
        self.calls.append(pd.raw)
        return [SearchResult("t", "https://zz.example", "")]


def run_batch(cfg, db, prov, monkeypatch, budget=3):
    from rich.progress import Progress
    monkeypatch.setattr(scanner, "build_pool", lambda c, d: SearchPool([KeyRing(prov, ["K"], 1000, d)], d))
    monkeypatch.setattr(scanner.time, "sleep", lambda s: None)
    with Progress() as p:
        return scanner.run_dorks(cfg, db, None, p, budget=budget)


def test_cooldown_prevents_respending_quota_and_everything_is_remembered(db, cfg, monkeypatch):
    prov = Fake()
    cfg["search"]["providers"] = {"fake": {"keys": ["K"]}}
    for i in range(5):
        dorkstore.add_dork(db, f'"bug bounty" "term{i}"', "custom")
    cfg["dorks"]["source"], cfg["features"]["ai_dorks"] = "custom", False
    lines = run_batch(cfg, db, prov, monkeypatch, budget=3)
    assert len(prov.calls) == 3 and "3 run, 2 waiting" in lines[1]
    assert db.c.execute("SELECT COUNT(*) FROM queries WHERE origin='custom' AND status='ok'").fetchone()[0] == 3
    run_batch(cfg, db, prov, monkeypatch, budget=3)  # the 3 already-run dorks are inside cooldown -> only the other 2 run
    assert len(prov.calls) == 5
    lines = run_batch(cfg, db, prov, monkeypatch, budget=5)
    assert len(prov.calls) == 5 and any("cooldown" in l for l in lines)  # nothing re-spent
    db.c.execute("UPDATE queries SET run_at='2020-01-01T00:00:00+00:00'")  # cooldown elapsed
    run_batch(cfg, db, prov, monkeypatch, budget=5)
    assert len(prov.calls) == 10
    assert db.c.execute("SELECT run_count FROM dorks LIMIT 1").fetchone()[0] == 2


def test_per_dork_cooldown_override(db, cfg, monkeypatch):
    prov = Fake()
    cfg["search"]["providers"] = {"fake": {"keys": ["K"]}}
    d = dorkstore.add_dork(db, '"bug bounty" "solo"', "custom")
    db.c.execute("UPDATE dorks SET cooldown_days=0.0001 WHERE id=?", (d,))
    cfg["dorks"]["source"], cfg["features"]["ai_dorks"] = "custom", False
    run_batch(cfg, db, prov, monkeypatch, budget=1)
    db.c.execute("UPDATE queries SET run_at='2020-01-01T00:00:00+00:00'")
    run_batch(cfg, db, prov, monkeypatch, budget=1)
    assert len(prov.calls) == 2


def test_dated_dork_is_honoured_and_translated():
    pd = parse('"bug bounty" after:2026-01-01 before:2026-03-01 site:.ch')
    assert (pd.after, pd.before, pd.tld) == ("2026-01-01", "2026-03-01", "ch")
    assert "after" not in " ".join(pd.terms())


# ── AI dork validator ────────────────────────────────────────────────────────
@pytest.mark.parametrize("text,ok", [
    ('"responsible disclosure" "Schwachstelle" site:.at', True),
    ('"security.txt" inurl:.well-known site:.pt', True),
    ('intitle:"bug bounty" "Belohnung"', True),
    ('"bug bounty" password', False), ('"bug bounty" filetype:pdf', False), ('intitle:"index of" "bug bounty"', False),
    ('"vulnerability disclosure" "api key"', False), ('inurl:admin "bug bounty"', False), ('"bug bounty" .env', False),
    ('"vulnerability disclosure" site:acme.com', False), ('cheap pizza near me', False),
    ('"bug bounty" ' + "x" * 200, False), ('cache:"bug bounty"', False), ('"vulnerability disclosure" resources', True),
    ('"bug bounty" rce exploit', False)])
def test_ai_validator(text, ok):
    assert aidorks.validate(text)[0] is ok


def test_ai_validator_strips_dates_and_dedupes():
    ok, t = aidorks.validate('"bug bounty program" after:2026-01-01 site:.ch')
    assert ok and "after" not in t
    ex = [(aidorks._tokens('"bug bounty program"'), "ch")]
    assert aidorks.validate('"bug bounty program" site:.ch', ex)[1].startswith("duplicate")
    assert aidorks.validate('"bug bounty program" site:.se', ex)[0]  # other region = different dork


class GenLLM:
    model, host = "m", "h"

    def __init__(self, payload):
        self.payload, self.prompts = payload, []

    def generate(self, prompt, **kw):
        self.prompts.append(prompt)
        return self.payload


def test_generation_end_to_end_with_validation_and_parent(db, cfg):
    dorkstore.ensure_default(db)
    win = db.c.execute("SELECT id FROM dorks LIMIT 1").fetchone()[0]
    db.c.execute("UPDATE dorks SET new_programs_found=4 WHERE id=?", (win,))
    payload = json.dumps({"dorks": [
        {"text": '"responsible disclosure" "Schwachstelle melden" site:.lu', "rationale": "luxembourg", "parent_id": win},
        {"text": '"bug bounty" passwords leak', "rationale": "bad"},
        {"text": '"vulnerability disclosure" "kwetsbaarheid" site:.nl', "rationale": "dutch"},
        {"text": "totally unrelated", "rationale": ""}, "not even a dict"]})
    llm = GenLLM(payload)
    rep = aidorks.generate(cfg, db, llm, Tavily(), 5)
    assert rep.accepted == 2 and rep.proposed == 5 and sum(rep.rejected.values()) == 3
    r = db.c.execute("SELECT * FROM dorks WHERE grp='ai' ORDER BY id").fetchall()
    assert [x["parent_dork_id"] for x in r] == [win, None] and r[0]["rationale"] == "luxembourg"
    assert "Natural-language" in llm.prompts[0] and "WINNING DORKS" in llm.prompts[0] and f"[{win}]" in llm.prompts[0]
    again = aidorks.generate(cfg, db, GenLLM(payload), Tavily(), 5)
    assert again.accepted == 0  # re-proposed dorks are duplicates now


def test_generation_survives_garbage_and_llm_errors(db, cfg):
    assert "no usable dorks" in aidorks.generate(cfg, db, GenLLM("lol no"), None, 3).error
    from qurihunter.llm import LLMError
    class Boom(GenLLM):
        def generate(self, *a, **k):
            raise LLMError("down")
    assert aidorks.generate(cfg, db, Boom(""), None, 3).error == "LLM error: down"
    assert aidorks.maybe_generate(cfg, db, Boom(""), None)[0].startswith("[yellow]")


def test_periodic_generation_respects_interval(db, cfg):
    llm = GenLLM(json.dumps({"dorks": []}))
    assert aidorks.maybe_generate(cfg, db, llm, None) and len(llm.prompts) == 1
    assert aidorks.maybe_generate(cfg, db, llm, None) == [] and len(llm.prompts) == 1  # not due yet


def test_ai_winners_get_priority_and_losers_auto_disable(db, cfg):
    a = dorkstore.add_dork(db, '"bug bounty" "win"', "ai")
    b = dorkstore.add_dork(db, '"bug bounty" "lose"', "ai")
    c = dorkstore.add_dork(db, '"bug bounty" "custom-lose"', "custom")
    for _ in range(5):
        dorkstore.record_run(db, a, 3, 1)
        dorkstore.record_run(db, b, 3, 0)
        dorkstore.record_run(db, c, 3, 0)
    assert db.c.execute("SELECT priority FROM dorks WHERE id=?", (a,)).fetchone()[0] == 5
    assert dorkstore.auto_disable_unproductive_ai(db, 5) == 1
    r = db.c.execute("SELECT enabled, auto_disabled_reason FROM dorks WHERE id=?", (b,)).fetchone()
    assert r[0] == 0 and "no new programs" in r[1]
    assert db.c.execute("SELECT enabled FROM dorks WHERE id=?", (c,)).fetchone()[0] == 1  # only AI dorks auto-disable
    assert [x["id"] for x in dorkstore.prune_candidates(db, 5)] == [c]  # custom ones need manual, confirmed prune


# ── memory forget ────────────────────────────────────────────────────────────
def test_forget_commands(db, cfg):
    from qurihunter.models import Program
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "a", "A", "https://hackerone.com/a")])
    db.remember_url("https://hackerone.com/a", "official_program")
    db.record_query(provider="p", text="q", nhash="h", dork_id=None, origin="builtin", window="7d", results=1, new=0)
    dorkstore.ensure_default(db)
    pid = db.c.execute("SELECT id FROM programs").fetchone()[0]
    assert memcmds.forget(db, "program", str(pid)) == 1 and db.seen("https://hackerone.com/a") is None
    assert memcmds.forget(db, "query", "all") == 1 and db.history(5) == []
    assert memcmds.forget(db, "dork", "all") > 0 and dorkstore.ensure_default(db).added > 0  # default re-imports
    memcmds.forget(db, "all", None)
    assert db.c.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == 0 and not db.is_seeded("hackerone")


def test_forget_requires_confirmation(db, cfg, monkeypatch, tmp_path):
    from qurihunter import ui
    class Ctx: pass
    ctx = Ctx(); ctx.db, ctx.cfg = db, cfg
    db.record_query(provider="p", text="q", nhash="h", dork_id=None, origin="builtin", window="7d", results=1, new=0)
    monkeypatch.setattr(ui, "yn", lambda *a, **k: False)
    memcmds._mem_forget(ctx, ["query", "all"])
    assert len(db.history(5)) == 1  # declined -> nothing removed
    monkeypatch.setattr(ui, "yn", lambda *a, **k: True)
    memcmds._mem_forget(ctx, ["query", "all"])
    assert db.history(5) == [] and list((db.path.parent / "backups").glob("*before-forget-query*"))  # backup first
    monkeypatch.setattr(ui, "ask", lambda *a, **k: "no")
    db.record_query(provider="p", text="q", nhash="h", dork_id=None, origin="builtin", window="7d", results=1, new=0)
    memcmds._mem_forget(ctx, ["all"])  # 'all' needs the typed phrase on top of y/n
    assert len(db.history(5)) == 1


def test_memory_export_and_stats(db, cfg, tmp_path):
    class Ctx: pass
    ctx = Ctx(); ctx.db, ctx.cfg = db, cfg
    dorkstore.ensure_default(db)
    out = tmp_path / "m.json"
    memcmds._mem_export(ctx, [str(out)])
    data = json.loads(out.read_text())
    assert len(data["dorks"]) >= 100 and "programs" in data
    assert memcmds.memory_stats(db)["dorks"] == len(data["dorks"])
