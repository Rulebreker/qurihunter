import pytest

from qurihunter import config, scanner
from qurihunter.classify import from_result, heuristic
from qurihunter.db import DB
from qurihunter.hardware import Hardware, recommend_model
from qurihunter.models import Program
from qurihunter.search import SearchResult
from qurihunter.sources import dorks, platforms
from qurihunter.urls import normalize_url, registrable_domain


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


def test_url_normalisation():
    assert normalize_url("HTTPS://www.Example.com/security/?utm_source=x&a=1#frag") == "https://example.com/security?a=1"
    assert registrable_domain("security.example.co.uk") == "example.co.uk"
    assert registrable_domain("a.b.example.ch") == "example.ch"


def test_baseline_then_only_new_alerts(db):
    cfg = config.load()
    a, b = Program("hackerone", "a", "A", "https://h/a"), Program("hackerone", "b", "B", "https://h/b")
    new, base = scanner.ingest(db, cfg, "hackerone", [a])
    assert base and new == [] and db.pending() == []
    new, base = scanner.ingest(db, cfg, "hackerone", [a, b])
    assert not base and [p.key for p in new] == ["b"] and len(db.pending()) == 1
    new, _ = scanner.ingest(db, cfg, "hackerone", [a, b])
    assert new == []  # idempotent


def test_filters_mark_filtered_not_pending(db):
    cfg = config.load()
    cfg["filters"]["min_reward"] = 1000
    scanner.ingest(db, cfg, "bugcrowd", [Program("bugcrowd", "x", "X", "u")])
    low = Program("bugcrowd", "low", "L", "u2", "bounty", 50, "USD")
    unknown = Program("bugcrowd", "unk", "U", "u3", "bounty")
    scanner.ingest(db, cfg, "bugcrowd", [low, unknown])
    assert [r["name"] for r in db.pending()] == ["U"]  # unknown reward passes, low is filtered


def test_heuristics():
    s, kind = heuristic("https://acme.ch/responsible-disclosure", "Responsible Disclosure | Acme",
                        "Report a vulnerability and earn a bounty")
    assert s >= 0.8 and kind == "bounty"
    s, _ = heuristic("https://acme.com/blog/top-10-bug-bounty-tips", "Top 10 bug bounty tips", "")
    assert s < 0.5
    p, why = from_result(SearchResult("t", "https://github.com/x/y/security", ""), None)
    assert p is None and why == "ignored-domain"
    p, _ = from_result(SearchResult("Responsible disclosure", "https://www.acme.ch/responsible-disclosure",
                                  "report a vulnerability"), None)
    assert p and p.dedupe_key == "web:acme.ch" and p.country == "ch"


def test_dork_build_and_countries():
    only = dorks.build(["ch"])
    assert all("site:.ch" in q for q in only)
    assert len(dorks.build([])) > len(dorks.TEMPLATES)
    assert dorks.normalize_cc("GB") == "uk"


def test_parsers_tolerate_missing_fields():
    assert platforms.parse_hackerone([{"handle": "h", "submission_state": "open", "offers_bounties": True}])[0].kind == "bounty"
    assert platforms.parse_hackerone([{"handle": "h", "submission_state": "closed"}]) == []
    assert platforms.parse_yeswehack([{"id": "s", "max_bounty": 100}])[0].reward_max == 100
    assert platforms.parse_diodb([{"program_name": "P", "policy_url": "https://a.se/vdp"}])[0].country == "se"
    assert platforms.parse_rss("<rss><channel><item><title>T</title><link>https://x.io/p</link></item></channel></rss>", "f")


def test_model_recommendation():
    assert recommend_model(Hardware(32, "x", 8, "RTX", 12))[0] == "llama3.1:8b"
    assert recommend_model(Hardware(16, "x", 8, "GTX", 6))[0] == "mistral:7b"
    assert recommend_model(Hardware(16, "x", 8))[0] == "phi3:mini"
    assert recommend_model(Hardware(4, "x", 2))[0] == "qwen2.5:1.5b"
