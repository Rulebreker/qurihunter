import sqlite3
from datetime import timedelta

import pytest

from qurihunter import config, dates, listing, migrations, scanner
from qurihunter.db import DB
from qurihunter.models import Program
from qurihunter.sources import platforms


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


@pytest.fixture
def cfg():
    return config.load()


def days_ago(n):
    return dates.iso(dates.utcnow() - timedelta(days=n))


# ── migrations & backups ────────────────────────────────────────────────────
def make_v1(path):
    c = sqlite3.connect(path)
    migrations.m1_base(c)
    c.execute("INSERT INTO seeded_sources VALUES('hackerone','2026-01-01T00:00:00+00:00')")
    rows = [("hackerone:a", "hackerone", "2026-01-01T00:00:00+00:00", 1),  # baseline (same run as seeding)
            ("hackerone:b", "hackerone", "2026-02-01T00:00:00+00:00", 1),  # really delivered later
            ("hackerone:c", "hackerone", "2026-02-02T00:00:00+00:00", 2),  # filtered
            ("web:acme.ch", "web", "2026-02-03T00:00:00+00:00", 0)]  # pending
    for k, src, fs, n in rows:
        c.execute("INSERT INTO programs(dedupe_key,source,name,url,first_seen,last_seen,notified) VALUES(?,?,?,?,?,?,?)",
                  (k, src, k, "https://x/" + k, fs, fs, n))
    c.execute("INSERT INTO rejected VALUES('noise.com','blog','2026-01-01')")
    c.execute("INSERT INTO dork_runs VALUES('h','q','2026-01-01',2,5,1)")
    c.commit()
    c.close()


def test_old_db_opens_with_data_intact_and_backup(tmp_path):
    p = tmp_path / "old.db"
    make_v1(p)
    db = DB(p)
    assert db.backup_made and db.backup_made.exists()
    assert db.c.execute("PRAGMA user_version").fetchone()[0] == len(migrations.MIGRATIONS)
    r = {x["dedupe_key"]: x for x in db.c.execute("SELECT * FROM programs")}
    assert len(r) == 4 and r["hackerone:a"]["baseline"] == 1 and r["hackerone:b"]["delivered"] == 1
    assert r["hackerone:c"]["filtered"] == 1 and r["web:acme.ch"]["canonical_key"] == "acme.ch"
    assert db.c.execute("SELECT COUNT(*) FROM seen_urls").fetchone()[0] == 1
    assert db.c.execute("SELECT COUNT(*) FROM queries WHERE status='migrated'").fetchone()[0] == 1
    # backup is a faithful pre-migration copy
    old = sqlite3.connect(db.backup_made)
    assert old.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == 4
    assert "canonical_key" not in {c[1] for c in old.execute("PRAGMA table_info(programs)")}
    db.c.close()
    again = DB(p)  # idempotent: second open does nothing
    assert again.backup_made is None and again.c.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == 4


def test_only_last_five_backups_kept(tmp_path):
    p = tmp_path / "x.db"
    c = sqlite3.connect(p)
    migrations.m1_base(c)
    c.commit()
    for i in range(8):
        d = tmp_path / "backups"
        d.mkdir(exist_ok=True)
        (d / f"x-2026010{i}-000000-v0.db").write_bytes(b"")
    migrations.backup(c, p, "v0")
    assert len(list((tmp_path / "backups").glob("x-*.db"))) == migrations.KEEP_BACKUPS


# ── dedupe across sources / never alert twice ───────────────────────────────
def test_company_on_platform_and_self_hosted_is_one_program(db, cfg):
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "x", "X", "https://hackerone.com/x", website="https://acme.ch")])
    scanner.ingest(db, cfg, "web", [Program("web", "other.ch", "Other", "https://other.ch/vdp")])  # seed web
    n = db.c.execute("SELECT COUNT(*) FROM programs").fetchone()[0]
    new, _ = scanner.ingest(db, cfg, "web", [Program("web", "acme.ch", "Acme", "https://www.acme.ch/security", country="ch")])
    assert new == [] and db.c.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == n
    row = db.c.execute("SELECT * FROM programs WHERE source='hackerone'").fetchone()
    assert row["country"] == "ch"  # enriched, not re-alerted
    assert db.c.execute("SELECT COUNT(*) FROM program_sources WHERE program_id=?", (row["id"],)).fetchone()[0] == 2


def test_same_platform_different_handle_is_a_separate_program(db, cfg):
    mk = lambda h: Program("hackerone", h, h, f"https://hackerone.com/{h}", website="https://acme.com")  # noqa: E731
    scanner.ingest(db, cfg, "hackerone", [mk("acme")])
    new, _ = scanner.ingest(db, cfg, "hackerone", [mk("acme"), mk("acme-partners")])
    assert [p.key for p in new] == ["acme-partners"]


def test_never_alert_twice(db, cfg):
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "a", "A", "u")])
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "b", "B", "u2")])
    assert len(db.pending(7)) == 1
    db.mark_delivered([db.pending(7)[0]["id"]], "telegram")
    assert db.pending(7) == []
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "b", "B", "u2")])  # seen again, even via another URL
    scanner.ingest(db, cfg, "bugcrowd", [Program("bugcrowd", "bb", "B", "u3", website="b.com")])
    assert db.pending(7) == [] and db.c.execute("SELECT alert_count FROM programs WHERE dedupe_key='hackerone:b'").fetchone()[0] == 1


def test_chat_delivery_does_not_prevent_telegram_alert(db, cfg):
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "a", "A", "u")])
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "b", "B", "u2")])
    db.mark_delivered([db.pending(7)[0]["id"]], "chat")
    assert len(db.pending(7)) == 1  # still due on Telegram
    assert db.c.execute("SELECT delivered_via, alert_count FROM programs WHERE dedupe_key='hackerone:b'").fetchone()[:] == ("chat", 0)


# ── 7-day window ────────────────────────────────────────────────────────────
def test_first_run_alerts_only_inside_window(db, cfg):
    fresh = Program("disclose.io", "f", "Fresh", "https://fresh.ch/vdp", launched_at=days_ago(2), launched_via="source")
    old = Program("disclose.io", "o", "Old", "https://old.ch/vdp", launched_at=days_ago(400), launched_via="source")
    undated = Program("disclose.io", "u", "Undated", "https://undated.ch/vdp")
    new, first = scanner.ingest(db, cfg, "disclose.io", [fresh, old, undated])
    assert first and [p.name for p in new] == ["Fresh"]  # first run of a source no longer loses genuinely new programs
    assert [r["name"] for r in db.pending(7)] == ["Fresh"]
    assert [r["name"] for r in db.pending(None)] == ["Fresh"]  # baseline/undated never alert, even with window 'any'
    assert [r["name"] for r in db.pending(1)] == []  # 2 days old is outside a 1-day window


def test_launched_at_old_but_new_to_us_does_not_alert(db, cfg):
    scanner.ingest(db, cfg, "disclose.io", [Program("disclose.io", "a", "A", "https://a.ch/p")])
    scanner.ingest(db, cfg, "disclose.io", [Program("disclose.io", "b", "B", "https://b.ch/p", launched_at=days_ago(900))])
    assert db.pending(7) == []  # effective date = real launch date, which is old


def test_window_boundaries_and_null_handling():
    now = dates.utcnow()
    assert dates.in_window(dates.iso(now - timedelta(hours=23, minutes=59)), 1, now)
    assert not dates.in_window(dates.iso(now - timedelta(hours=24, minutes=1)), 1, now)
    assert dates.in_window(dates.iso(now - timedelta(days=7)), 7, now)  # exactly on the boundary is inside
    assert not dates.in_window(None, 7) and not dates.in_window(None, None)
    assert dates.in_window(days_ago(5000), None)  # window 'any'


def test_effective_date_uses_launch_date_never_fabricates(db, cfg):
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "a", "A", "u")])  # baseline, no launch date
    r = db.c.execute("SELECT * FROM programs").fetchone()
    assert r["launched_at"] is None and r["launched_at_source"] == "unknown" and r["baseline"] == 1
    rows, excl = db.query_programs(since=days_ago(1), by="launched")
    assert rows == [] and excl == 0  # baseline hidden by default
    rows, excl = db.query_programs(by="launched", include_baseline=True)
    assert rows == [] and excl == 1  # unknown launch date: excluded AND counted


# ── date parsing ────────────────────────────────────────────────────────────
def test_date_formats():
    assert dates.parse_date("2026-10-05").date().isoformat() == "2026-10-05"
    d = dates.parse_date("05/10/2026")
    assert (d.day, d.month, d.year) == (5, 10, 2026)  # DD/MM/YYYY
    assert dates.parse_date("05.10.2026").month == 10
    assert dates.parse_date("2026-10-05T10:00:00Z").hour == 10
    assert dates.parse_date("2016") is None and dates.parse_date("garbage") is None and dates.parse_date("") is None
    assert dates.parse_date("31/02/2026") is None  # impossible date
    assert dates.parse_date("2999-01-01", sane=True) is None  # bogus future page metadata
    a, b = dates.parse_range("01/10/2026", "05/10/2026")
    bl = b.astimezone(dates.local_tz())
    assert b - a > timedelta(days=4) and bl.day == 5 and bl.hour == 23  # --to is inclusive of the whole local day


def test_since_and_window_specs():
    now = dates.utcnow()
    assert abs((now - dates.parse_since("24h", now)).total_seconds() - 86400) < 1
    assert abs((now - dates.parse_since("30d", now)) - timedelta(days=30)) < timedelta(seconds=1)
    assert dates.parse_window("any") is None and dates.parse_window("7d") == 7 and dates.parse_window("1y") == 365
    assert dates.parse_window("24h") == 1 and dates.parse_window(14) == 14
    for bad in ("soon", "7x"):
        with pytest.raises(ValueError):
            dates.parse_window(bad)
    with pytest.raises(ValueError):
        dates.parse_since("yesterday")
    with pytest.raises(ValueError):
        dates.parse_range("10/10/2026", "05/10/2026")  # from > to
    with pytest.raises(ValueError):
        dates.parse_range("2026-13-45", None)


def test_listing_filters_and_errors(db, cfg):
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "a", "A", "u")])
    scanner.ingest(db, cfg, "hackerone", [Program("hackerone", "n", "New", "u2", country="ch")])
    o = listing.parse_args(["--since", "7d"])
    rows, excl, _ = listing.run(db, o)
    assert [r["name"] for r in rows] == ["New"]
    rows, _, _ = listing.run(db, listing.parse_args(["--since", "7d", "--include-baseline"]))
    assert len(rows) == 2
    rows, _, _ = listing.run(db, listing.parse_args(["--from", "01/01/2020", "--to", "2099-01-01", "--country", "ch"]))
    assert len(rows) == 1
    rows, excl, _ = listing.run(db, listing.parse_args(["--by", "launched", "--since", "30d"]))
    assert rows == [] and excl == 1
    for bad in (["--by", "x"], ["--bogus"], ["--since"], ["--limit", "abc"]):
        with pytest.raises(ValueError):
            listing.parse_args(bad)
    with pytest.raises(ValueError):
        listing.run(db, listing.parse_args(["--since", "7d", "--from", "2026-01-01"]))


# ── query memory ────────────────────────────────────────────────────────────
def test_query_cooldown(db):
    assert db.query_in_cooldown("h1", 7) is None
    db.record_query(provider="tavily", text="q", nhash="h1", dork_id=None, origin="builtin", window="7d", results=3, new=0)
    assert db.query_in_cooldown("h1", 7) is not None
    assert db.query_in_cooldown("other", 7) is None
    db.c.execute("UPDATE queries SET run_at=?", (days_ago(8),))
    assert db.query_in_cooldown("h1", 7) is None  # cooldown elapsed
    db.record_query(provider="tavily", text="q", nhash="h2", dork_id=None, origin="builtin", window="7d",
                    results=0, new=0, status="error")
    assert db.query_in_cooldown("h2", 7) is None  # failed queries don't count


# ── source launch dates ─────────────────────────────────────────────────────
def test_selfhosted_first_seen_floor_is_ignored():
    data = [{"hosting": "self_hosted", "status": "active", "domain": f"d{i}.ch", "policy_url": f"https://d{i}.ch/p",
             "first_seen": "2026-07-28", "country": "ch", "reward": "none"} for i in range(10)]
    data.append({**data[0], "domain": "new.ch", "policy_url": "https://new.ch/p", "first_seen": "2026-10-03"})
    data.append({**data[0], "domain": "gone.ch", "status": "retired"})
    progs = {p.key: p for p in platforms.parse_selfhosted(data)}
    assert progs["d0.ch"].launched_at is None  # dataset start day carries no information
    assert progs["new.ch"].launched_at.startswith("2026-10-0") and progs["new.ch"].launched_via == "source_first_seen"
    assert "gone.ch" not in progs


def test_disclose_io_launch_dates_only_when_real():
    mk = lambda ld: platforms.parse_diodb([{"program_name": "P", "policy_url": "https://a.se/v", "launch_date": ld}])[0]  # noqa: E731
    assert mk("2020-02-19").launched_at.startswith("2020-02-1")
    assert mk("Updated 2020-08-15").launched_at is None and mk("2016").launched_at is None and mk("").launched_at is None


def test_platform_feeds_never_invent_launch_dates():
    p = platforms.parse_hackerone([{"handle": "h", "submission_state": "open", "website": "https://acme.com"}])[0]
    assert p.launched_at is None and p.company_key == "acme.com"
    assert platforms.parse_rss("<rss><channel><item><title>T</title><link>https://x.io/p</link>"
                               "<pubDate>Mon, 05 Oct 2026 10:00:00 GMT</pubDate></item></channel></rss>", "f")[0].launched_at


def test_seen_view_hides_baseline_even_when_launch_date_known_but_launched_view_shows_it(db, cfg):
    old = Program("selfhosted", "o", "Old", "https://o.ch/p", launched_at=days_ago(40), launched_via="source_first_seen")
    scanner.ingest(db, cfg, "selfhosted", [old])  # first run, outside window -> baseline with a real launch date
    assert db.c.execute("SELECT baseline FROM programs").fetchone()[0] == 1
    rows, _ = db.query_programs(since=days_ago(7), by="seen")
    assert rows == []  # first seen today, but it is baseline: not "new"
    rows, _ = db.query_programs(since=days_ago(60), by="launched")
    assert [r["name"] for r in rows] == ["Old"]  # its real launch date is legitimate
    rows, _ = db.query_programs(since=days_ago(7), by="seen", include_baseline=True)
    assert len(rows) == 1
