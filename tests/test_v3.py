"""v3: command registry, Telegram delivery path, date evidence, Wayback, per-channel flags, views, reclassify."""
import json
import re
import sqlite3
from datetime import timedelta

import pytest
import requests

from qurihunter import alertcmds, alerts, classify, cli, config, datekind, dates, listing, memcmds, migrations, notify, ui, wayback
from qurihunter import scanner
from qurihunter.db import DB
from qurihunter.models import Program
from qurihunter.search import SearchResult


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._b, self.headers = status, body if body is not None else {"ok": True}, headers or {}
        self.text = json.dumps(self._b)

    def json(self):
        return self._b


class Ctx:
    def __init__(self, tmp_path):
        self.cfg = config.load()
        self.db = DB(tmp_path / "t.db")

    def save(self, cfg=None):
        config.save(cfg or self.cfg)

    def reload(self):
        pass


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


def ago(n):
    return dates.iso(dates.utcnow() - timedelta(days=n))


def prog(db, key="a", *, name=None, url=None, source="web", launched=None, updated=None, kind="vdp", baseline=False,
         date_kind="unknown", wayback=None, first_seen_days_ago=None):
    p = Program(source, f"{key}.ch", name or f"{key} Program", url or f"https://{key}.ch/responsible-disclosure", kind,
                country="ch", launched_at=launched, launched_via="page_date" if launched else None,
                updated_at=updated, date_kind=date_kind)
    rid = db.insert(p, baseline=baseline, wayback=wayback)
    if first_seen_days_ago is not None:
        db.c.execute("UPDATE programs SET first_seen=? WHERE id=?", (ago(first_seen_days_ago), rid))
    db.commit()
    return rid


# ── Phase 1: command registry ───────────────────────────────────────────────
def test_every_help_command_is_registered_and_every_registered_command_is_in_help():
    helped = {c.split()[0] for c, _ in cli.HELP}
    assert helped == set(cli.COMMANDS)
    assert set(alertcmds.SPEC_COMMANDS) <= set(cli.COMMANDS)


def test_spec_commands_include_everything_the_user_asked_for():
    for c in "/scan /watch /config /model /filters /status /test /programs /export /logs /help /quit /recency /dorks " \
             "/memory /history /chat /alerts /why /version".split():
        assert c in cli.COMMANDS and c in alertcmds.SPEC_COMMANDS


def test_typo_alert_runs_alerts_and_unknown_gets_did_you_mean():
    assert alertcmds.suggest("/alert", cli.COMMANDS)[0] == "/alerts"
    assert alertcmds.suggest("/program", cli.COMMANDS)[0] == "/programs"
    target, hints = alertcmds.suggest("/memry", cli.COMMANDS)
    assert target == "/memory"  # distance 1
    target, hints = alertcmds.suggest("/statu", cli.COMMANDS)
    assert target == "/status"
    target, hints = alertcmds.suggest("/xyzzy", cli.COMMANDS)
    assert target is None and hints == []
    t, h = alertcmds.suggest("/dorkz2", cli.COMMANDS)
    assert t is None and "/dorks" in h


def test_memory_without_argument_prints_usage(ctx, monkeypatch):
    out = []
    monkeypatch.setattr(ui, "info", lambda m: out.append(m))
    memcmds.cmd_memory(ctx, [])
    assert out and "usage: /memory" in out[0]


def test_self_check_flags_missing_commands_and_newer_schema(ctx):
    assert alertcmds.self_check(ctx) == []
    assert any("missing:" in w and "/why" in w for w in alertcmds.self_check(ctx, registered=["/scan"]))
    ctx.cfg["version"] = 99
    assert any("config.json is version 99" in w for w in alertcmds.self_check(ctx))
    ctx.db.set_meta("code_version", "9.9.9")
    assert any("last used by qurihunter 9.9.9" in w for w in alertcmds.self_check(ctx))


def test_db_newer_than_code_is_refused(tmp_path):
    p = tmp_path / "n.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE x(a)")
    c.execute("PRAGMA user_version=99")
    c.commit()
    c.close()
    with pytest.raises(RuntimeError, match="NEWER"):
        DB(p)


def test_version_info(ctx):
    v = alertcmds.version_info(ctx)
    assert {"qurihunter", "git commit", "DB schema", "config version", "python", "install path"} <= set(v)
    assert f"code expects {len(migrations.MIGRATIONS)}" in v["DB schema"]


def test_stale_code_warning_when_source_changes_after_start(monkeypatch):
    assert alertcmds.stale_code() is None
    monkeypatch.setattr(alertcmds, "_code_mtime", lambda: alertcmds._STARTED + 100)
    assert "OLD code" in alertcmds.stale_code()


# ── Phase 3: date_kind ──────────────────────────────────────────────────────
@pytest.mark.parametrize("text,kind,day", [
    ("Last Update: September 15, 2026", "last_updated", "2026-09-15"),
    ("Effective Date: June 23, 2025", "effective", "2025-06-23"),
    ("2 Dec 2025 - This is a renewal proposal", "last_updated", "2025-12-02"),
    ("3 Oct 2026 — Acme launches a new bug bounty program", "launched", "2026-10-03"),
    ("Responsible disclosure policy. Published on 2026-10-01", "published", "2026-10-01"),
])
def test_date_kind_rules(text, kind, day):
    ev = datekind.analyse(text, "")
    assert ev[0].kind == kind and ev[0].date[:10] == day


def test_update_effective_renewal_are_never_launch_dates():
    for t in ("Last Update: September 15, 2026", "Effective Date: June 23, 2025", "2 Dec 2025 - renewal proposal"):
        d = datekind.summarise(datekind.analyse(t, ""))
        assert d["launched_at"] is None and d["updated_at"]


def test_provider_date_means_published_and_llm_resolves_ambiguous():
    d = datekind.summarise(datekind.analyse("Acme VDP", "see you", published=ago(1)))
    assert d["date_kind"] == "published" and d["launched_at"]

    class L:
        def date_kind(self, text, date):
            return "last_updated"
    ev = datekind.analyse("Acme", "details from 15/09/2026 here", llm=L())
    assert ev[0].kind == "last_updated" and ev[0].by == "llm"


def test_classify_uses_date_kind_for_launch_vs_update(db, cfg):
    item = SearchResult("Acme — Responsible Disclosure", "https://acme.ch/responsible-disclosure",
                        f"report a vulnerability bounty. Last Update: {(dates.utcnow() - timedelta(days=2)).strftime('%B %d, %Y')}")
    p, _ = classify.from_result(item, None)
    assert p.launched_at is None and p.updated_at and p.date_kind == "last_updated"


# ── alert classes & evidence ────────────────────────────────────────────────
def row(db, rid):
    return db.program(rid)


def test_classes(db, cfg):
    new = prog(db, "n", launched=ago(2), date_kind="published")
    old = prog(db, "o", launched=ago(200), date_kind="published")
    upd = prog(db, "u", updated=ago(3), date_kind="last_updated", wayback=("old", ago(900)))
    upd2 = prog(db, "u2", updated=ago(3), date_kind="last_updated")  # archive not checked
    stale_upd = prog(db, "s", updated=ago(300), date_kind="last_updated")
    arch_old = prog(db, "w", wayback=("old", ago(900)))
    arch_none = prog(db, "z", wayback=("none", None))
    base = prog(db, "b", baseline=True)
    cl = lambda i: alerts.classify(row(db, i), 7)[0]  # noqa: E731
    assert [cl(i) for i in (new, old, upd, upd2, stale_upd, arch_old, arch_none, base)] == \
           ["new", "old", "updated", "updated", "old", "old", "new", "baseline"]


def test_evidence_line_shape(db):
    i = prog(db, "n", launched=ago(2), date_kind="published", wayback=("none", None))
    assert re.fullmatch(r"published \d\d \w{3} \| first archived: none \| new", alerts.evidence_line(row(db, i), 7))
    j = prog(db, "u", updated=ago(3), date_kind="last_updated", wayback=("old", "2024-03-01T00:00:00+00:00"))
    assert alerts.evidence_line(row(db, j), 7).endswith("first archived 2024-03 | older program, recently updated")
    k = prog(db, "k", updated=ago(3), date_kind="last_updated")
    assert "archive: not checked | age unknown" in alerts.evidence_line(row(db, k), 7)


def test_window_applies_to_both_kinds(db, cfg):
    prog(db, "n", launched=ago(2), date_kind="published")
    prog(db, "n2", launched=ago(20), date_kind="published")
    prog(db, "u", updated=ago(2), date_kind="last_updated")
    prog(db, "u2", updated=ago(20), date_kind="last_updated")
    assert sorted(k for _, k in alerts.due(db, cfg)) == ["new", "updated"]
    cfg["recency_days"] = 30
    assert sorted(k for _, k in alerts.due(db, cfg)) == ["new", "new", "updated", "updated"]


def test_updated_flag_off_suppresses_updated(db, cfg):
    prog(db, "u", updated=ago(2), date_kind="last_updated")
    cfg["alerts"]["alert_updated_only_pages"] = False
    assert alerts.due(db, cfg) == []


# ── Phase 2b: Telegram message building ─────────────────────────────────────
def test_message_content_has_all_fields():
    msgs = notify.build(notify.samples(), 7, sample=True)
    t = msgs[0].plain
    for want in ("SAMPLE NEW", "SAMPLE — Example Corp", "bounty", "up to 5,000 USD", "CH", "via sample",
                 "https://example.com/security/bug-bounty", "published", "first archived: none", "RECENTLY UPDATED",
                 "last updated", "first archived 2023-04"):
        assert want in t, want


def test_long_digest_is_split_and_never_cuts_inside_a_link(db, cfg):
    ids = [prog(db, f"c{i}", url=f"https://c{i}.ch/" + "very-long-path-" * 8 + "responsible-disclosure", launched=ago(1),
                date_kind="published") for i in range(80)]
    items = [(db.program(i), "new") for i in ids]
    msgs = notify.build(items, 7)
    assert len(msgs) > 1 and all(len(m.html) <= notify.TG_LIMIT for m in msgs)
    urls = {db.program(i)["url"] for i in ids}
    found = set()
    for m in msgs:
        found |= {u for u in urls if u in m.html}
    assert found == urls  # every link appears whole in exactly the message it belongs to
    assert sum(len(m.items) for m in msgs) == 80
    assert msgs[1].plain.startswith("🆕 NEW — continued")


def test_new_first_then_updated_in_digest(db, cfg):
    a = prog(db, "u", updated=ago(2), date_kind="last_updated")
    b = prog(db, "n", launched=ago(2), date_kind="published")
    due = alerts.due(db, cfg)
    assert [k for _, k in due] == ["new", "updated"]
    assert notify.build(due, 7)[0].plain.index("NEW (1)") < notify.build(due, 7)[0].plain.index("RECENTLY UPDATED (1)")


def test_special_characters_are_escaped_in_html(db):
    i = prog(db, "x", name="Acme_[Corp] *(beta)* <b>&co", url="https://x.ch/a_b[1](2)?q=1&r=<2>", launched=ago(1),
             date_kind="published")
    m = notify.build([(db.program(i), "new")], 7)[0]
    assert "&lt;b&gt;&amp;co" in m.html and "&amp;r=&lt;2&gt;" in m.html
    assert "<b>Acme_[Corp] *(beta)* &lt;b&gt;&amp;co</b>" in m.html  # our own tag is the only live markup
    assert "Acme_[Corp] *(beta)* <b>&co" in m.plain  # plain version is untouched


# ── Phase 2b: sending ───────────────────────────────────────────────────────
def test_429_retry_after_is_honoured(monkeypatch):
    calls, sleeps = [], []
    seq = [Resp(429, {"ok": False, "description": "Too Many Requests", "parameters": {"retry_after": 3}}), Resp(200)]
    monkeypatch.setattr(notify, "request", lambda *a, **k: calls.append(k) or seq.pop(0))
    monkeypatch.setattr(notify, "_sleep", lambda s: sleeps.append(s))
    notify.tg_post("1:abc", "42", "hi")
    assert len(calls) == 2 and sleeps == [4] and calls[0]["retry_429"] is False


def test_429_longer_than_cap_fails_without_waiting(monkeypatch):
    monkeypatch.setattr(notify, "request", lambda *a, **k: Resp(429, {"ok": False, "parameters": {"retry_after": 900}}))
    with pytest.raises(notify.NotifyError, match="retry_after 900"):
        notify.tg_post("1:abc", "42", "hi", cap=60)


def test_html_parse_error_falls_back_to_plain_text(monkeypatch):
    bodies = []
    seq = [Resp(400, {"ok": False, "description": "Bad Request: can't parse entities: Unsupported start tag"}), Resp(200)]
    monkeypatch.setattr(notify, "request", lambda *a, **k: bodies.append(k["json"]) or seq.pop(0))
    notify.tg_post("1:abc", "42", "<b>x_[y]</b>", plain="x_[y]")
    assert bodies[0]["parse_mode"] == "HTML" and "parse_mode" not in bodies[1] and bodies[1]["text"] == "x_[y]"


def test_ok_false_with_http_200_is_not_success(monkeypatch):
    monkeypatch.setattr(notify, "request", lambda *a, **k: Resp(200, {"ok": False, "description": "nope"}))
    with pytest.raises(notify.NotifyError):
        notify.tg_post("1:abc", "42", "hi")


def test_errors_are_redacted(monkeypatch, cfg):
    tok = cfg["notify"]["telegram"]["token"]
    monkeypatch.setattr(notify, "request", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError(f"boom bot{tok}/sendMessage")))
    with pytest.raises(notify.NotifyError) as e:
        notify.tg_post(tok, "42", "hi")
    assert tok not in str(e.value)


def test_delivered_only_after_ok_failed_sends_stay_pending_and_retry(db, cfg, monkeypatch):
    i = prog(db, "n", launched=ago(1), date_kind="published")
    monkeypatch.setattr(notify, "request", lambda *a, **k: Resp(200, {"ok": False, "description": "chat not found"}))
    rows, res = scanner.enrich_and_notify(cfg, db, None)
    assert "chat not found" in res["telegram"]
    assert db.delivered_channels(i) == {} and len(alerts.due(db, cfg)) == 1
    err = db.c.execute("SELECT * FROM alert_log WHERE ok=0").fetchone()
    assert err and "chat not found" in err["error"]
    monkeypatch.setattr(notify, "request", lambda *a, **k: Resp(200))
    rows, res = scanner.enrich_and_notify(cfg, db, None)  # next run retries
    assert res == {"telegram": "ok"} and db.delivered_channels(i) == {"telegram": ["new"]}
    assert alerts.due(db, cfg) == []
    assert db.c.execute("SELECT COUNT(*) FROM alert_log WHERE ok=1").fetchone()[0] == 1


def test_partial_failure_only_marks_sent_messages(db, cfg, monkeypatch):
    ids = [prog(db, f"c{i}", url=f"https://c{i}.ch/" + "p" * 300 + "/responsible-disclosure", launched=ago(1),
                date_kind="published") for i in range(40)]
    n = {"c": 0}

    def fake(*a, **k):
        n["c"] += 1
        return Resp(200) if n["c"] == 1 else Resp(400, {"ok": False, "description": "boom"})
    monkeypatch.setattr(notify, "request", fake)
    scanner.enrich_and_notify(cfg, db, None)
    sent = [i for i in ids if db.delivered_channels(i)]
    assert 0 < len(sent) < 40 and len(alerts.due(db, cfg)) == 40 - len(sent)


# ── Phase 2b: per-channel flags ─────────────────────────────────────────────
def test_chat_never_suppresses_telegram_and_channels_are_independent(db, cfg):
    cfg["notify"]["channels"] = ["telegram", "email"]
    i = prog(db, "n", launched=ago(1), date_kind="published")
    db.record_delivery([(i, "new")], "chat")
    assert len(alerts.due(db, cfg)) == 1
    db.record_delivery([(i, "new")], "telegram")
    assert len(alerts.due(db, cfg)) == 1  # email still lacks it
    db.record_delivery([(i, "new")], "email")
    assert alerts.due(db, cfg) == []


def test_one_alert_per_kind_updated_never_becomes_new_on_vague_signal(db, cfg):
    i = prog(db, "u", updated=ago(2), date_kind="last_updated")
    assert [k for _, k in alerts.due(db, cfg)] == ["updated"]
    db.record_delivery([(i, "updated")], "telegram")
    assert alerts.due(db, cfg) == []
    # archive later says 'no capture' -> would be 'new' by likely-new logic, but we already told them 'updated'
    db.c.execute("UPDATE programs SET wayback_state='none' WHERE id=?", (i,))
    assert alerts.due(db, cfg) == []
    # ...unless a real launch date appears
    db.c.execute("UPDATE programs SET launched_at=? WHERE id=?", (ago(1), i))
    assert [k for _, k in alerts.due(db, cfg)] == ["new"]


def test_updated_after_new_needs_a_later_date(db, cfg):
    i = prog(db, "n", launched=ago(3), date_kind="published", updated=ago(5))
    db.record_delivery([(i, "new")], "telegram")
    assert alerts.due(db, cfg) == []


# ── Phase 2d: summary ───────────────────────────────────────────────────────
@pytest.fixture
def sent_texts(monkeypatch):
    out = []
    monkeypatch.setattr(notify, "tg_post", lambda token, chat, text, **k: out.append(text))
    return out


def test_summary_modes(db, cfg, sent_texts):
    scanner.reset_run()
    scanner.RUN.update(due_new=2, due_updated=1, old=3)
    cfg["alerts"]["telegram_scan_summary"] = "off"
    assert scanner.maybe_summary(cfg, db, quota_left=5) is None
    cfg["alerts"]["telegram_scan_summary"] = "changes_only"
    assert scanner.maybe_summary(cfg, db, quota_left=5) == "Scan finished: 2 new, 1 updated, 3 skipped as old, quota left 5"
    assert len(sent_texts) == 1
    scanner.RUN.update(due_new=0, due_updated=0)
    assert scanner.maybe_summary(cfg, db, quota_left=5) is None  # nothing found -> silent
    cfg["alerts"]["telegram_scan_summary"] = "daily"
    db.set_meta("summary_day", "1999-01-01")
    assert "0 new, 0 updated" in scanner.maybe_summary(cfg, db, quota_left=None)  # heartbeat
    assert scanner.maybe_summary(cfg, db, quota_left=None) is None  # only one heartbeat per day
    assert len(sent_texts) == 2


def test_summary_never_sent_twice_in_one_scan(db, cfg, sent_texts, monkeypatch):
    monkeypatch.setattr(notify, "request", lambda *a, **k: Resp(200))
    prog(db, "n", launched=ago(1), date_kind="published")
    monkeypatch.setattr(scanner, "build_pool", lambda c, d: None)
    monkeypatch.setattr(scanner.platforms, "fetch", lambda s: [])
    cfg["filters"]["platforms"] = []
    rows, lines, res = scanner.scan(cfg, db, do_platforms=False, do_dorks=False)
    assert [t for t in sent_texts if t.startswith("Scan finished")] == ["Scan finished: 1 new, 0 updated, 0 skipped as old, quota left n/a"]
    assert len(sent_texts) == 2  # the digest + exactly one summary


# ── Phase 3: Wayback ────────────────────────────────────────────────────────
def hit(domain="acme.ch", snippet="report a vulnerability bounty"):
    return SearchResult(f"Responsible disclosure | {domain}", f"https://{domain}/responsible-disclosure", snippet)


def test_wayback_old_capture_is_silent_baseline(db, cfg, monkeypatch):
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: "20190305120000")
    assert scanner._handle_result(db, cfg, None, hit(), windowed=True, first_run=False) == (1, 0)
    r = db.c.execute("SELECT * FROM programs").fetchone()
    assert r["baseline"] == 1 and r["wayback_state"] == "old" and r["wayback_first"].startswith("2019-03")
    assert alerts.due(db, cfg) == []


def test_wayback_no_capture_is_likely_new_and_cached(db, cfg, monkeypatch):
    n = {"c": 0}
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: n.__setitem__("c", n["c"] + 1))
    assert scanner._handle_result(db, cfg, None, hit(), windowed=True, first_run=False) == (1, 1)
    assert db.c.execute("SELECT wayback_state FROM programs").fetchone()[0] == "none"
    assert wayback.first_capture(db, "https://acme.ch/responsible-disclosure", cfg) == ("none", None)
    assert n["c"] == 1  # second call came from the cache


def test_wayback_failure_never_blocks(db, cfg, monkeypatch):
    def boom(url, timeout=8):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(wayback, "lookup", boom)
    assert scanner._handle_result(db, cfg, None, hit(), windowed=True, first_run=False) == (1, 1)
    assert db.c.execute("SELECT wayback_state FROM programs").fetchone()[0] == "error"
    assert db.c.execute("SELECT failures FROM net_stats WHERE name='wayback'").fetchone()[0] == 1


def test_wayback_skipped_when_page_has_a_launch_date_and_budget_is_respected(db, cfg, monkeypatch):
    calls = []
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: calls.append(url))
    it = hit()
    it.published = ago(1)
    scanner._handle_result(db, cfg, None, it, windowed=True, first_run=False)
    assert calls == []
    b = {"left": 1}
    scanner._handle_result(db, cfg, None, hit("b.ch"), windowed=True, first_run=False, wb=b)
    scanner._handle_result(db, cfg, None, hit("c.ch"), windowed=True, first_run=False, wb=b)
    assert len(calls) == 1 and b["left"] == 0


def test_wayback_old_but_updated_in_window_alerts_as_updated(db, cfg, monkeypatch):
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: "20190305120000")
    d = (dates.utcnow() - timedelta(days=2)).strftime("%B %d, %Y")
    scanner._handle_result(db, cfg, None, hit(snippet=f"report a vulnerability bounty. Last Update: {d}"),
                           windowed=True, first_run=False)
    assert [k for _, k in alerts.due(db, cfg)] == ["updated"]


def test_known_page_with_new_update_date_becomes_one_updated_alert(db, cfg):
    i = prog(db, "k", baseline=True, url="https://k.ch/responsible-disclosure")
    db.remember_url("https://k.ch/responsible-disclosure", "official_program")
    d = (dates.utcnow() - timedelta(days=1)).strftime("%B %d, %Y")
    scanner._handle_result(db, cfg, None, hit("k.ch", f"Last Update: {d}"), windowed=True, first_run=False)
    assert [k for _, k in alerts.due(db, cfg)] == ["updated"]


# ── unfiltered sweep ────────────────────────────────────────────────────────
def test_search_recency_first_run_any_later_month_and_a_week_sweep(db, cfg, monkeypatch):
    """The provider's date filter is the SEARCH recency policy, never the 7-day alert window."""
    from qurihunter import dorkstore
    from qurihunter.search import base
    dorkstore.ensure_default(db)
    db.c.execute("UPDATE dorks SET enabled=0 WHERE id>10")  # exactly 10 dorks, so the 2nd batch re-runs the same ones
    cfg["dork_search_recency"]["sweep_share"] = 0.30
    assert cfg["recency_days"] == 7  # the alert window stays 7 days...
    seen = []

    class FP(base.Provider):
        id, label, period, default_limit = "fake", "Fake", "month", 1000

        def _search(self, key, pd, page, fresh):
            seen.append(fresh)
            return []
    cfg["search"]["providers"] = {"fake": {"keys": ["k1"], "limit": 1000}}
    from qurihunter import search
    monkeypatch.setitem(search.PROVIDERS, "fake", FP)
    from rich.progress import Progress
    with Progress() as pr:
        scanner.run_dorks(cfg, db, None, pr, budget=10)
    assert len(seen) == 10 and all(not f for f in seen)  # ...but a dork's FIRST run is sent with no date filter at all
    db.c.execute("DELETE FROM queries"); db.set_meta("seq_batch", ""); db.commit()
    seen.clear()
    with Progress() as pr:
        scanner.run_dorks(cfg, db, None, pr, budget=10)
    assert len(seen) == 10 and 7 not in seen[:0] and sum(1 for f in seen if f == 31) >= 6 and sum(1 for f in seen if f == 7) >= 1


# ── Phase 4: views ──────────────────────────────────────────────────────────
def test_programs_filters_are_applied_and_title_says_so(ctx, monkeypatch):
    db = ctx.db
    prog(db, "n", launched=ago(2), date_kind="published")
    prog(db, "u", updated=ago(3), date_kind="last_updated")
    prog(db, "o", launched=ago(100), date_kind="published")
    for i in range(5):
        prog(db, f"b{i}", baseline=True)
    printed = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: printed.append(a[0] if a else None))
    cli.cmd_programs(ctx, ["--since", "7d"])
    tbl = [p for p in printed if hasattr(p, "row_count")][0]
    assert tbl.row_count == 2
    assert "since 7d" in tbl.title and "2 shown" in tbl.title and "5 baseline hidden" in tbl.title
    printed.clear()
    cli.cmd_programs(ctx, ["--since", "7d", "--kind", "updated"])
    assert [p for p in printed if hasattr(p, "row_count")][0].row_count == 1
    printed.clear()
    cli.cmd_programs(ctx, ["--since", "1y", "--include-old"])
    assert [p for p in printed if hasattr(p, "row_count")][0].row_count == 3
    printed.clear()
    cli.cmd_programs(ctx, ["--include-baseline", "--since", "1y"])
    # classified relative to the asked window: the 100-day-old launch is 'new' inside 1y -> all 8 programs
    assert [p for p in printed if hasattr(p, "row_count")][0].row_count == 8


def test_programs_without_filters_still_shows_kind_and_evidence_columns(ctx, monkeypatch):
    prog(ctx.db, "n", launched=ago(2), date_kind="published")
    printed = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: printed.append(a[0] if a else None))
    cli.cmd_programs(ctx, ["25"])
    tbl = [p for p in printed if hasattr(p, "row_count")][-1]
    assert "Last 25" in tbl.title and [c.header for c in tbl.columns][:2] == ["Kind", "Date evidence"]


def test_narrow_terminal_keeps_kind_and_evidence_and_wide_forces_all(db, cfg):
    prog(db, "n", launched=ago(2), date_kind="published")
    rows, _, _ = listing.run(db, listing.parse_args(["--since", "7d"]), cfg=cfg)
    narrow = [c.header for c in listing.table(rows, "t", width=80).columns]
    full = [c.header for c in listing.table(rows, "t", width=200).columns]
    forced = [c.header for c in listing.table(rows, "t", width=80, wide=True).columns]
    assert {"Kind", "Date evidence", "Sent"} <= set(narrow) and "Reward" not in narrow
    assert "Reward" in full and forced == full
    comp = listing.table(rows, "t", width=80, compact=True)
    assert "NEW" in comp.plain and "published" in comp.plain and "unsent" in comp.plain


def test_sent_column_shows_channels(db, cfg):
    i = prog(db, "n", launched=ago(2), date_kind="published")
    db.record_delivery([(i, "new")], "chat")
    db.record_delivery([(i, "new")], "telegram")
    rows, _, _ = listing.run(db, listing.parse_args(["--since", "7d"]), cfg=cfg)
    assert listing.sent_text(rows[0]["_sent"]) == "telegram✓, chat✓"
    assert listing.state(rows[0]).startswith("NEW · sent: telegram✓, chat✓")


def test_date_range_filters_accept_both_formats(db, cfg):
    i = prog(db, "n", launched="2026-09-10T12:00:00+00:00", date_kind="published")
    for a, b in (("2026-09-01", "2026-09-30"), ("01/09/2026", "30/09/2026")):
        rows, _, _ = listing.run(db, listing.parse_args(["--from", a, "--to", b, "--by", "launched", "--kind", "all"]), cfg=cfg)
        assert [r["id"] for r in rows] == [i]


def test_export_includes_kind_evidence_and_channels(ctx, tmp_path):
    import csv
    i = prog(ctx.db, "n", launched=ago(2), date_kind="published")
    ctx.db.record_delivery([(i, "new")], "telegram")
    cli.cmd_export(ctx, [str(tmp_path / "e.csv"), "--since", "7d"])
    r = list(csv.DictReader(open(tmp_path / "e.csv")))[0]
    assert r["_kind"] == "new" and "published" in r["_evidence"] and r["_sent"] == "telegram✓"


def test_category_filter_separates_bare_security_txt(db, cfg):
    prog(db, "p", launched=ago(1), date_kind="published")
    prog(db, "s", launched=ago(1), date_kind="published", kind="security.txt", url="https://s.ch/.well-known/security.txt")
    run = lambda *a: listing.run(db, listing.parse_args(["--since", "7d", *a]), cfg=cfg)[0]  # noqa: E731
    assert len(run()) == 2 and len(run("--category", "program")) == 1 and len(run("--category", "securitytxt")) == 1


# ── Phase 5: reclassify ─────────────────────────────────────────────────────
NOISE = [("https://hackersonlineclub.com/bug-bounty-writeup", "Bug bounty writeup"),
         ("https://industrialcyber.co/news/bug-bounty-launch", "News"),
         ("https://braze.com/resources/articles/bug-bounty-programs", "Bug bounty programs article"),
         ("https://hackyourmom.com/kiberbezpeka/bug-bounty", "Bug bounty"),
         ("https://apify.com/store/bug-bounty-scraper", "Scraper"),
         ("https://github.com/x/awesome-bug-bounty/blob/master/README.md", "awesome-bug-bounty")]


def test_reclassify_plan_flags_noise_and_keeps_real_without_alerting(db, cfg, monkeypatch):
    for i, (u, n) in enumerate(NOISE):
        db.insert(Program("web", f"n{i}.com", n, u, snippet="bug bounty"), baseline=False)
    good = db.insert(Program("web", "good.ch", "good.ch — Responsible Disclosure", "https://good.ch/responsible-disclosure"))
    bare = db.insert(Program("web", "sec.ch", "sec.ch security.txt", "https://sec.ch/.well-known/security.txt",
                             kind="security.txt"))
    sent = []
    monkeypatch.setattr(notify, "request", lambda *a, **k: sent.append(1) or Resp(200))
    plan = scanner.reclassify_plan(db, cfg, None)
    dec = {d["url"]: d for d in plan}
    assert all(dec[u]["decision"] == "reject" and dec[u]["reason"] for u, _ in NOISE)
    assert dec["https://good.ch/responsible-disclosure"]["decision"] == "keep"
    assert "security.txt" in dec["https://sec.ch/.well-known/security.txt"]["reason"]
    assert sent == [] and db.c.execute("SELECT COUNT(*) FROM programs WHERE verdict='official_program'").fetchone()[0] == 8
    assert scanner.reclassify_apply(db, plan) == 6
    assert db.c.execute("SELECT COUNT(*) FROM programs WHERE verdict='not_program'").fetchone()[0] == 6
    assert db.seen(NOISE[0][0])["verdict"] == "not_program"  # remembered per URL
    assert sent == []


def test_reclassify_command_asks_before_hiding(ctx, monkeypatch):
    ctx.db.insert(Program("web", "n.com", "News", NOISE[1][0], snippet="bug bounty"))
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    monkeypatch.setattr(ui, "yn", lambda q, d=True: False)
    memcmds.cmd_memory(ctx, ["reclassify", "--now"])
    assert ctx.db.c.execute("SELECT verdict FROM programs").fetchone()[0] == "official_program"
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    memcmds.cmd_memory(ctx, ["reclassify", "--now"])
    assert ctx.db.c.execute("SELECT verdict FROM programs").fetchone()[0] == "not_program"


# ── Phase 2e: /alerts and /why ──────────────────────────────────────────────
def test_alerts_status_pending_test_and_resend(ctx, monkeypatch):
    i = prog(ctx.db, "n", launched=ago(1), date_kind="published")
    sent = []
    monkeypatch.setattr(notify, "request", lambda m, u, **k: sent.append(k["json"]["text"]) or Resp(200))
    out = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: out.append(a[0] if a else ""))
    s = alertcmds.status_data(ctx)
    assert s["pending_new"] == 1 and s["last_ok"] is None
    alertcmds.cmd_alerts(ctx, ["status"])
    alertcmds.cmd_alerts(ctx, ["pending"])
    alertcmds.cmd_alerts(ctx, ["test"])
    assert len(sent) == 1 and "SAMPLE" in sent[0] and "RECENTLY UPDATED" in sent[0]
    assert ctx.db.c.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0  # samples are never recorded
    scanner.enrich_and_notify(ctx.cfg, ctx.db, None)
    assert alertcmds.status_data(ctx)["last_ok"]["programs"] == 1
    sent.clear()
    monkeypatch.setattr(ui, "yn", lambda q, d=True: False)
    alertcmds.cmd_alerts(ctx, ["resend", "all"])
    assert sent == []  # confirmation declined
    monkeypatch.setattr(ui, "yn", lambda q, d=True: True)
    alertcmds.cmd_alerts(ctx, ["resend", "--since", "7d"])
    assert len(sent) == 1 and ctx.db.delivered_channels(i) == {"telegram": ["new"]}
    sent.clear()
    alertcmds.cmd_alerts(ctx, ["resend", "1"])
    assert len(sent) == 1


def test_why_explains_each_decision(db, cfg):
    n = prog(db, "n", launched=ago(1), date_kind="published")
    b = prog(db, "b", baseline=True)
    o = prog(db, "o", launched=ago(90), date_kind="published")
    t = "\n".join(alertcmds.explain(db, cfg, db.program(n)))
    assert "NEW" in t and "will be alerted on the next scan" in t and "published" in t
    db.record_delivery([(n, "new")], "chat")
    assert "chat: new" in "\n".join(alertcmds.explain(db, cfg, db.program(n))) and "will be alerted" in "\n".join(alertcmds.explain(db, cfg, db.program(n)))
    db.record_delivery([(n, "new")], "telegram")
    assert "already delivered" in "\n".join(alertcmds.explain(db, cfg, db.program(n)))
    assert "BASELINE" in "\n".join(alertcmds.explain(db, cfg, db.program(b)))
    assert "older than the window" in "\n".join(alertcmds.explain(db, cfg, db.program(o)))
    assert alertcmds.find_program(db, "n.ch")["id"] == n and alertcmds.find_program(db, str(b))["id"] == b


def test_reason_counts(db, cfg):
    prog(db, "n", launched=ago(1), date_kind="published")
    prog(db, "o", launched=ago(3), date_kind="published", baseline=False)
    i = prog(db, "d", launched=ago(1), date_kind="published")
    db.record_delivery([(i, "new")], "telegram")
    prog(db, "b", baseline=True)
    c = alerts.reason_counts(db, cfg)
    assert c["new: delivered"] == 1 and any(k.startswith("new: PENDING") for k in c) and any(k.startswith("baseline") for k in c)


# ── Phase 6: network health & quota ─────────────────────────────────────────
def test_http_retries_and_failures_are_counted(monkeypatch):
    from qurihunter import http
    http.drain_stats()
    seq = [requests.ConnectionError("reset by peer"), Resp(200)]

    class S:
        def request(self, *a, **k):
            x = seq.pop(0)
            if isinstance(x, Exception):
                raise x
            return x
    monkeypatch.setattr(http, "_session", S())
    monkeypatch.setattr(http.time, "sleep", lambda s: None)
    http.request("POST", "https://api.tavily.com/search", retries=2)
    st = http.drain_stats()["tavily.com"]
    assert st["retries"] == 1 and st["ok"] == 1 and "reset by peer" in st["last_error"]
    monkeypatch.setattr(http, "_session", type("S2", (), {"request": lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("x"))})())
    with pytest.raises(requests.ConnectionError):
        http.request("GET", "https://api.tavily.com/search", retries=1)
    assert http.drain_stats()["tavily.com"]["failures"] == 1


def test_failed_query_does_not_spend_quota(db, cfg):
    from qurihunter import search
    from qurihunter.search import base
    from qurihunter.search.pool import KeyRing, SearchPool, QuotaExhausted

    class P(base.Provider):
        id, label, period, default_limit = "p", "P", "month", 10

        def _search(self, key, pd, page, fresh):
            raise base.ProviderError("transient", "Connection reset by peer")
    ring = KeyRing(P(), ["k"], 10, db)
    pool = SearchPool([ring], db)
    with pytest.raises(QuotaExhausted):
        pool.search('"x" site:.ch')
    assert db.quota_used(ring._kid("k"), ring.provider.period_label()) == 0


def test_flush_net_persists_counters(db):
    from qurihunter import http
    http.drain_stats()
    http._stat("https://api.tavily.com/x", "retries", "reset")
    scanner._flush_net(db)
    assert db.c.execute("SELECT retries FROM net_stats WHERE name='tavily.com'").fetchone()[0] == 1


# ── migration ───────────────────────────────────────────────────────────────
def test_m3_migration_splits_chat_from_real_deliveries(tmp_path):
    p = tmp_path / "v2.db"
    c = sqlite3.connect(p)
    migrations.m1_base(c)
    migrations.m2_v2(c)
    c.execute("PRAGMA user_version=2")
    for k, via, dl in (("a", "chat", 1), ("b", "telegram", 1), ("c", None, 0)):
        c.execute("INSERT INTO programs(dedupe_key,source,name,url,first_seen,delivered,delivered_via,delivered_at,baseline) "
                  "VALUES(?,?,?,?,?,?,?,?,0)", (f"web:{k}.ch", "web", k, f"https://{k}.ch", ago(1), dl, via, ago(1) if dl else None))
    c.commit()
    c.close()
    db = DB(p)
    assert db.c.execute("PRAGMA user_version").fetchone()[0] == len(migrations.MIGRATIONS)
    assert db.backup_made and db.backup_made.exists()
    rows = {r[0]: (r[1], r[2]) for r in db.c.execute("SELECT program_id, channel, kind FROM deliveries")}
    chans = sorted(r[0] for r in db.c.execute("SELECT channel FROM deliveries"))
    assert chans == ["chat", "telegram"]
    assert db.c.execute("SELECT delivered FROM programs WHERE name='a'").fetchone()[0] == 0  # chat-only is not delivered


def test_config_v3_defaults_and_old_config_upgrade(tmp_path, monkeypatch):
    c = config.load()
    assert c["alerts"] == {"alert_updated_only_pages": True, "alert_weak_evidence": True, "show_skipped_in_digest": False,
                           "telegram_scan_summary": "changes_only", "retry_cap_s": 60}
    assert c["wayback"]["enabled"] and c["version"] == config.CONFIG_VERSION
    config.save({"version": 1, "notify": {"channels": ["telegram"], "telegram": {"token": "t", "chat_id": "1"}}})
    c = config.load()
    assert c["version"] == config.CONFIG_VERSION and c["notify"]["channels"] == ["telegram"] and c["alerts"]["telegram_scan_summary"] == "changes_only"


def test_v1_dork_rows_without_a_seed_entry_are_not_mislabelled_delivered(tmp_path):
    p = tmp_path / "v1.db"
    c = sqlite3.connect(p)
    migrations.m1_base(c)
    c.execute("INSERT INTO seeded_sources VALUES('hackerone','2026-10-05T08:00:00+00:00')")
    for k, src, fs in (("hackerone:a", "hackerone", "2026-10-05T08:00:00+00:00"), ("web:x.ch", "web", "2026-10-05T11:47:58+00:00")):
        c.execute("INSERT INTO programs(dedupe_key,source,name,url,first_seen,last_seen,notified) VALUES(?,?,?,?,?,?,1)",
                  (k, src, k, "https://x/" + k, fs, fs))
    c.commit()
    c.close()
    db = DB(p)
    r = {x["dedupe_key"]: x for x in db.c.execute("SELECT * FROM programs")}
    assert r["hackerone:a"]["baseline"] == 1 and r["hackerone:a"]["delivered"] == 0
    assert r["web:x.ch"]["baseline"] == 0 and r["web:x.ch"]["delivered"] == 0  # v1 swallowed it; no proof of a send


def test_backfill_checks_legacy_rows_defers_when_budget_is_out_and_old_ones_go_silent(db, cfg, monkeypatch):
    a = prog(db, "a")  # legacy undated, will be 'old' per archive
    b = prog(db, "b")  # no capture -> likely new
    c_ = prog(db, "c")  # budget exhausted -> waits
    cfg["wayback"]["max_per_scan"] = 2
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: "20180101000000" if "a.ch" in url else None)
    sent = []
    monkeypatch.setattr(notify, "request", lambda m, u, **k: sent.append(k["json"]["text"]) or Resp(200))
    rows, res = scanner.enrich_and_notify(cfg, db, None)
    assert db.program(a)["baseline"] == 1 and db.program(a)["wayback_state"] == "old"
    assert db.delivered_channels(b) == {"telegram": ["new"]} and db.delivered_channels(c_) == {}
    scanner.enrich_and_notify(cfg, db, None)  # next scan handles the deferred one
    assert db.delivered_channels(c_) == {"telegram": ["new"]}


def test_backfill_defers_legacy_rows_when_archive_is_down(db, cfg, monkeypatch):
    a = prog(db, "a")
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: (_ for _ in ()).throw(requests.ConnectionError("down")))
    sent = []
    monkeypatch.setattr(notify, "request", lambda m, u, **k: sent.append(1) or Resp(200))
    scanner.reset_run()
    scanner.enrich_and_notify(cfg, db, None)
    assert sent == [] and db.delivered_channels(a) == {} and scanner.RUN["deferred"] >= 1
    assert len(alerts.due(db, cfg)) == 1  # still pending, visible in /alerts pending


def test_wayback_circuit_breaker_stops_calls_after_repeated_failures(db, cfg, monkeypatch):
    n = {"c": 0}

    def boom(url, timeout=8):
        n["c"] += 1
        raise requests.ConnectionError("503")
    monkeypatch.setattr(wayback, "lookup", boom)
    wayback.reset()
    states = [wayback.first_capture(db, f"https://x{i}.ch/p", cfg)[0] for i in range(6)]
    assert n["c"] == 3 and states == ["error"] * 3 + ["skipped"] * 3
    wayback.reset()
    assert wayback.first_capture(db, "https://y.ch/p", cfg)[0] == "error"


def test_on_error_alert_lets_unverified_legacy_rows_through_and_why_explains_waiting(db, cfg, monkeypatch):
    a = prog(db, "a")
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: (_ for _ in ()).throw(requests.ConnectionError("down")))
    monkeypatch.setattr(notify, "request", lambda m, u, **k: Resp(200))
    scanner.reset_run()
    scanner.enrich_and_notify(cfg, db, None)
    assert "WAITING" in "\n".join(alertcmds.explain(db, cfg, db.program(a)))
    cfg["wayback"]["on_error"] = "alert"
    wayback.reset()
    scanner.enrich_and_notify(cfg, db, None)
    assert db.delivered_channels(a) == {"telegram": ["new"]}
