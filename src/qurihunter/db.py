from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from datetime import timedelta

from . import dates
from .dblock import Conn
from .migrations import migrate
from .models import Program
from .paths import db_path

now = dates.now_iso

# effective date = launch date if the source gave one, else first-seen — but only for non-baseline rows
EFFECTIVE = "COALESCE(launched_at, CASE WHEN baseline=0 THEN first_seen END)"


def _default_cfg(days, channels):
    """pending() called without a config (legacy callers/tests): window = `days`, channel = telegram."""
    from . import config
    c = config.copy.deepcopy(config.DEFAULTS)
    c["recency_days"] = days
    c["notify"]["channels"] = channels or ["telegram"]
    return c


def url_hash(url: str) -> str:
    from .urls import normalize_url
    return hashlib.sha1(normalize_url(url).encode()).hexdigest()


class DB:
    def __init__(self, path=None):
        self.path = Path(path) if path else db_path()
        raw = sqlite3.connect(str(self.path), timeout=30)  # sets busy_timeout = 30 s on THIS connection
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA busy_timeout=30000")  # per connection, explicitly
        raw.execute("PRAGMA journal_mode=WAL")  # persistent, readers never block the writer
        raw.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, far fewer fsyncs per commit
        self.c = Conn(raw)  # write gate + retry/backoff + flush registry (see dblock.py)
        self.backup_made = migrate(self.c, self.path)

    # ── programs ──────────────────────────────────────────────────────────────
    def known(self, dedupe_key: str) -> bool:
        return self.c.execute("SELECT 1 FROM programs WHERE dedupe_key=?", (dedupe_key,)).fetchone() is not None

    def match(self, p: Program):
        """Existing program row that `p` duplicates: same source+key, or the same company seen via another source
        (a company on HackerOne *and* with its own page is one program). Same-source/different-key stays distinct."""
        r = self.c.execute("SELECT * FROM programs WHERE dedupe_key=?", (p.dedupe_key,)).fetchone()
        if r:
            return r
        ck = p.company_key
        if ck:
            for r in self.c.execute("SELECT * FROM programs WHERE canonical_key=? AND verdict='official_program' "
                                    "ORDER BY id", (ck,)):
                if r["source"] != p.source:
                    return r
        return None

    def touch(self, dedupe_key: str) -> None:
        self.c.execute("UPDATE programs SET last_seen=? WHERE dedupe_key=?", (now(), dedupe_key))

    def enrich(self, row, p: Program) -> None:
        """A later source adds knowledge to an existing record instead of re-alerting."""
        self.c.execute("INSERT OR IGNORE INTO program_sources VALUES(?,?,?,?)", (row["id"], p.source, p.url, now()))
        sets, args = [], []
        for col, val in (("country", p.country), ("website", p.website), ("reward_max", p.reward_max),
                         ("currency", p.currency)):
            if val and not row[col]:
                sets.append(f"{col}=?"); args.append(val)
        if p.launched_at and not row["launched_at"]:
            sets += ["launched_at=?", "launched_at_source=?"]; args += [p.launched_at, p.launched_via or "source"]
        if sets:
            self.c.execute(f"UPDATE programs SET {','.join(sets)}, last_seen=? WHERE id=?", (*args, now(), row["id"]))
        else:
            self.c.execute("UPDATE programs SET last_seen=? WHERE id=?", (now(), row["id"]))

    def insert(self, p: Program, *, baseline: bool = False, filtered: bool = False, delivered_via: str | None = None,
               verdict: str = "official_program", wayback: tuple | None = None) -> int | None:
        cur = self.c.execute(
            "INSERT OR IGNORE INTO programs(dedupe_key,canonical_key,source,name,url,kind,reward_max,currency,scope,"
            "country,summary,confidence,first_seen,last_seen,website,launched_at,launched_at_source,baseline,verdict,"
            "filtered,snippet,delivered,delivered_at,delivered_via,notified) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (p.dedupe_key, p.company_key or p.dedupe_key, p.source, p.name, p.url, p.kind, p.reward_max, p.currency,
             json.dumps(p.scope[:200]), p.country, p.summary, p.confidence, now(), now(), p.website, p.launched_at,
             (p.launched_via or "source") if p.launched_at else "unknown", int(baseline), verdict, int(filtered),
             (p.snippet or "")[:500], int(bool(delivered_via) and delivered_via != "chat"), now() if delivered_via else None,
             delivered_via,
             1 if (baseline or delivered_via) else (2 if filtered else 0)))
        if cur.rowcount != 1:
            return None
        self.c.execute("INSERT OR IGNORE INTO program_sources VALUES(?,?,?,?)", (cur.lastrowid, p.source, p.url, now()))
        self.c.execute("UPDATE programs SET date_kind=?, updated_at=?, wayback_state=?, wayback_first=? WHERE id=?",
                       (p.date_kind or "unknown", p.updated_at, wayback[0] if wayback else "unchecked",
                        wayback[1] if wayback else None, cur.lastrowid))
        if delivered_via:
            self.record_delivery([(cur.lastrowid, "new")], delivered_via)
        return cur.lastrowid

    def pending(self, days: float | None = None, channels: list[str] | None = None, cfg: dict | None = None):
        """Programs still to alert on at least one real channel (see alerts.due). Chat deliveries never count."""
        from . import alerts
        cfg = cfg or _default_cfg(days, channels)
        return [r for r, _ in alerts.due(self, cfg, channels)]

    def record_delivery(self, items: list[tuple[int, str]], channel: str) -> None:
        """items: [(program_id, kind)]. Call ONLY after the channel confirmed the send."""
        ts = now()
        for pid, kind in items:
            self.c.execute("INSERT OR IGNORE INTO deliveries VALUES(?,?,?,?)", (pid, kind, channel, ts))
            if channel == "chat":
                self.c.execute("UPDATE programs SET delivered_via=COALESCE(delivered_via,'chat') WHERE id=?", (pid,))
            else:
                self.c.execute("UPDATE programs SET delivered=1, delivered_at=?, delivered_via=?, notified=1, "
                               "alert_count=alert_count+1 WHERE id=?", (ts, channel, pid))

    def mark_delivered(self, ids: list[int], via: str, kind: str = "new") -> None:
        """Legacy wrapper: via may be 'chat', 'telegram', 'email', 'telegram+email' or 'digest'."""
        chans = [c for c in via.replace("digest", "telegram").split("+") if c]
        for ch in chans or ["telegram"]:
            self.record_delivery([(i, kind) for i in ids], ch)

    def delivered_channels(self, pid: int) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for kind, ch in self.c.execute("SELECT kind, channel FROM deliveries WHERE program_id=? ORDER BY ts", (pid,)):
            out.setdefault(ch, []).append(kind)
        return out

    def log_alert(self, channel: str, ok: bool, error: str, programs: int, messages: int, kind: str = "") -> None:
        self.c.execute("INSERT INTO alert_log(ts,channel,ok,error,programs,messages,kind) VALUES(?,?,?,?,?,?,?)",
                       (now(), channel, int(ok), (error or "")[:300], programs, messages, kind))

    def add_net(self, name: str, st: dict) -> None:
        self.c.execute(
            "INSERT INTO net_stats(name,ok,retries,failures,last_error,last_at) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET ok=ok+?, retries=retries+?, failures=failures+?, "
            "last_error=COALESCE(?,last_error), last_at=?",
            (name, st["ok"], st["retries"], st["failures"], st["last_error"], now(),
             st["ok"], st["retries"], st["failures"], st["last_error"], now()))

    def net_stat(self, name: str, *, ok: bool = True, retries: int = 0, error: str | None = None) -> None:
        self.c.execute(
            "INSERT INTO net_stats(name,ok,retries,failures,last_error,last_at) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET ok=ok+?, retries=retries+?, failures=failures+?, "
            "last_error=COALESCE(?,last_error), last_at=?",
            (name, int(ok), retries, int(not ok), error and error[:200], now(), int(ok), retries, int(not ok),
             error and error[:200], now()))

    def set_summary(self, pid: int, summary: str) -> None:
        self.c.execute("UPDATE programs SET summary=? WHERE id=?", (summary, pid))

    def set_verdict(self, pid: int, verdict: str) -> None:
        self.c.execute("UPDATE programs SET verdict=? WHERE id=?", (verdict, pid))

    def program(self, pid: int):
        return self.c.execute("SELECT * FROM programs WHERE id=?", (pid,)).fetchone()

    def recent(self, limit=20, source=None):
        q, a = "SELECT * FROM programs WHERE verdict='official_program'", []
        if source:
            q += " AND source=?"; a.append(source)
        return self.c.execute(q + " ORDER BY first_seen DESC, id DESC LIMIT ?", (*a, limit)).fetchall()

    def counts(self) -> dict[str, int]:
        return {r[0]: r[1] for r in self.c.execute(
            "SELECT source, COUNT(*) FROM programs WHERE verdict='official_program' GROUP BY source")}

    def all_programs(self):
        return self.c.execute("SELECT * FROM programs WHERE verdict='official_program' ORDER BY first_seen DESC").fetchall()

    def query_programs(self, *, since: str | None = None, until: str | None = None, by: str = "seen",
                       source: str | None = None, country: str | None = None, text: str | None = None,
                       include_baseline: bool = False, limit: int | None = 100):
        """Filtered program listing. Returns (rows, excluded_unknown_launch_count).
        by='seen' filters on first_seen_at; by='launched' filters on launched_at and excludes (and counts) unknowns."""
        where, args = ["verdict='official_program'"], []
        if not include_baseline and by != "launched":
            where.append("baseline=0")  # 'seen' views: first-sight baseline entries are not "new"
        if source:
            where.append("source=?"); args.append(source)
        if country:
            where.append("country=?"); args.append(country.lower())
        if text:
            where.append("(name LIKE ? OR url LIKE ? OR summary LIKE ?)"); args += [f"%{text}%"] * 3
        col = "launched_at" if by == "launched" else "first_seen"
        excluded = 0
        if by == "launched":
            base = " AND ".join(where + ([] if include_baseline else ["baseline=0"]))
            excluded = self.c.execute(f"SELECT COUNT(*) FROM programs WHERE {base} AND launched_at IS NULL",
                                      args).fetchone()[0]
            where.append("launched_at IS NOT NULL")
        if since:
            where.append(f"{col} >= ?"); args.append(since)
        if until:
            where.append(f"{col} <= ?"); args.append(until)
        q = f"SELECT * FROM programs WHERE {' AND '.join(where)} ORDER BY {col} DESC, id DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        return self.c.execute(q, args).fetchall(), excluded

    # ── baseline bookkeeping ─────────────────────────────────────────────────────
    def is_seeded(self, source: str) -> bool:
        return self.c.execute("SELECT 1 FROM seeded_sources WHERE source=?", (source,)).fetchone() is not None

    def mark_seeded(self, source: str) -> None:
        self.c.execute("INSERT OR IGNORE INTO seeded_sources VALUES(?,?)", (source, now()))

    # ── seen URLs (classification memory) ────────────────────────────────────────
    def seen(self, url: str):
        return self.c.execute("SELECT * FROM seen_urls WHERE url_hash=?", (url_hash(url),)).fetchone()

    def remember_url(self, url: str, verdict: str, confidence: float = 0.0, by: str = "rules", reason: str = "") -> None:
        h = url_hash(url)
        self.c.execute(
            "INSERT INTO seen_urls VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(url_hash) DO UPDATE SET last_seen_at=?, "
            "verdict=?, confidence=?, classified_by=?, reason=?",
            (h, url, now(), now(), verdict, confidence, by, reason[:300], now(), verdict, confidence, by, reason[:300]))

    def touch_url(self, url: str) -> None:
        self.c.execute("UPDATE seen_urls SET last_seen_at=? WHERE url_hash=?", (now(), url_hash(url)))

    # legacy API (domain-level rejection cache) kept for callers/tests written against v1
    def is_rejected(self, key: str) -> bool:
        return self.c.execute("SELECT 1 FROM seen_urls WHERE url=? AND verdict='not_program'", (key,)).fetchone() is not None

    def reject(self, key: str, reason: str) -> None:
        self.remember_url(key, "not_program", 0, "rules", reason)

    # ── quota (`day` column holds the provider's period label: a date or YYYY-MM) ─
    def quota_used(self, kid: str, period: str) -> int:
        r = self.c.execute("SELECT used FROM quota WHERE key_id=? AND day=?", (kid, period)).fetchone()
        return r[0] if r else 0

    def quota_add(self, kid: str, period: str, n: int = 1) -> None:
        self.c.execute("INSERT INTO quota VALUES(?,?,?) ON CONFLICT(key_id,day) DO UPDATE SET used=used+?",
                       (kid, period, n, n))

    def quota_set_exhausted(self, kid: str, period: str, limit: int) -> None:
        self.c.execute("INSERT INTO quota VALUES(?,?,?) ON CONFLICT(key_id,day) DO UPDATE SET used=MAX(used,?)",
                       (kid, period, limit, limit))

    # ── query memory ─────────────────────────────────────────────────────────────
    def record_query(self, *, provider: str, text: str, nhash: str, dork_id: int | None, origin: str,
                     window: str, results: int, new: int, status: str = "ok") -> int:
        return self.c.execute(
            "INSERT INTO queries(provider,query_text,normalised_hash,dork_id,origin,recency_window,run_at,results_count,"
            "new_programs_found,status) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (provider, text, nhash, dork_id, origin, window, now(), results, new, status)).lastrowid

    def query_in_cooldown(self, nhash: str, cooldown_days: float):
        """Most recent successful identical query inside its cooldown, else None."""
        cutoff = dates.iso(dates.utcnow() - timedelta(days=cooldown_days))
        return self.c.execute("SELECT * FROM queries WHERE normalised_hash=? AND status='ok' AND run_at>=? "
                              "ORDER BY run_at DESC LIMIT 1", (nhash, cutoff)).fetchone()

    def queries_today(self, origin: str) -> int:
        start = dates.iso(dates.utcnow().astimezone(dates.local_tz()).replace(hour=0, minute=0, second=0, microsecond=0))
        return self.c.execute("SELECT COUNT(*) FROM queries WHERE origin=? AND run_at>=? AND status='ok'",
                              (origin, start)).fetchone()[0]

    def history(self, limit: int = 20):
        return self.c.execute("SELECT * FROM queries ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # legacy dork bookkeeping (v1)
    def dork_state(self, h: str):
        return self.c.execute("SELECT * FROM dork_runs WHERE hash=?", (h,)).fetchone()

    def dork_record(self, h: str, query: str, results: int, new: int) -> None:
        self.c.execute(
            "INSERT INTO dork_runs VALUES(?,?,?,1,?,?) ON CONFLICT(hash) DO UPDATE SET last_run=?, runs=runs+1, "
            "results=?, new_found=new_found+?", (h, query, now(), results, new, now(), results, new))

    # ── meta ─────────────────────────────────────────────────────────────────────
    def meta(self, key: str, default: str | None = None) -> str | None:
        r = self.c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r[0] if r else default

    def set_meta(self, key: str, value: str) -> None:
        self.c.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=?", (key, value, value))

    # ── runs ─────────────────────────────────────────────────────────────────────
    def run_start(self, source: str) -> int:
        return self.c.execute("INSERT INTO runs(started,source,status) VALUES(?,?,'running')", (now(), source)).lastrowid

    def run_end(self, rid: int, status: str, found: int, new: int, error: str = "") -> None:
        self.c.execute("UPDATE runs SET finished=?,status=?,found=?,new=?,error=? WHERE id=?",
                       (now(), status, found, new, error[:500], rid))

    def last_runs(self):
        return self.c.execute(
            "SELECT * FROM runs WHERE id IN (SELECT MAX(id) FROM runs GROUP BY source) ORDER BY source").fetchall()

    def commit(self) -> None:
        self.c.commit()
