"""Versioned SQLite migrations. `PRAGMA user_version` tracks the level. Every step is idempotent, and the DB file
is copied to backups/ before any migration touches an existing database (restore = copy it back)."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

KEEP_BACKUPS = 5


def _cols(c, table):
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


def _add(c, table, col, decl):
    if col not in _cols(c, table):
        c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def m1_base(c: sqlite3.Connection) -> None:
    """The v1 schema shipped earlier (kept verbatim so old databases open unchanged)."""
    c.executescript("""
CREATE TABLE IF NOT EXISTS programs(
  id INTEGER PRIMARY KEY, dedupe_key TEXT UNIQUE NOT NULL, source TEXT NOT NULL,
  name TEXT, url TEXT, kind TEXT, reward_max REAL, currency TEXT, scope TEXT, country TEXT,
  summary TEXT, confidence REAL, first_seen TEXT, last_seen TEXT,
  notified INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS seeded_sources(source TEXT PRIMARY KEY, ts TEXT);
CREATE TABLE IF NOT EXISTS quota(key_id TEXT, day TEXT, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(key_id, day));
CREATE TABLE IF NOT EXISTS dork_runs(hash TEXT PRIMARY KEY, query TEXT, last_run TEXT,
  runs INTEGER NOT NULL DEFAULT 0, results INTEGER DEFAULT 0, new_found INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS rejected(key TEXT PRIMARY KEY, reason TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, started TEXT, finished TEXT,
  source TEXT, status TEXT, found INTEGER, new INTEGER, error TEXT);
""")


def m2_v2(c: sqlite3.Connection) -> None:
    # --- programs: new columns --------------------------------------------------------
    for col, decl in (("canonical_key", "TEXT"), ("website", "TEXT"), ("launched_at", "TEXT"),
                      ("launched_at_source", "TEXT NOT NULL DEFAULT 'unknown'"), ("baseline", "INTEGER NOT NULL DEFAULT 0"),
                      ("verdict", "TEXT NOT NULL DEFAULT 'official_program'"), ("delivered", "INTEGER NOT NULL DEFAULT 0"),
                      ("delivered_at", "TEXT"), ("delivered_via", "TEXT"), ("alert_count", "INTEGER NOT NULL DEFAULT 0"),
                      ("filtered", "INTEGER NOT NULL DEFAULT 0"), ("snippet", "TEXT"), ("legacy_migrated", "INTEGER DEFAULT 0")):
        _add(c, "programs", col, decl)
    # Old `notified`: 0 pending, 1 sent OR baseline (indistinguishable), 2 filtered. A source that was seeded
    # (seeded_sources row): rows stored in that same run are baseline, later notified=1 rows were really delivered.
    # A source with NO seeded row (v1 dork hits) has no evidence of any send -> neither baseline nor delivered, so
    # they stay eligible for alerting (v1 swallowed its first dork batch silently; see README "upgrading").
    seed = "(SELECT ts FROM seeded_sources s WHERE s.source=programs.source)"
    c.execute(f"""UPDATE programs SET legacy_migrated=1,
        baseline = CASE WHEN notified=1 AND {seed} IS NOT NULL AND first_seen <= {seed} THEN 1 ELSE 0 END,
        delivered = CASE WHEN notified=1 AND {seed} IS NOT NULL AND first_seen > {seed} THEN 1 ELSE 0 END,
        delivered_via = CASE WHEN notified=1 AND {seed} IS NOT NULL AND first_seen > {seed} THEN 'legacy' END,
        filtered = CASE WHEN notified=2 THEN 1 ELSE 0 END
        WHERE legacy_migrated IS NULL OR legacy_migrated=0""")
    c.execute("UPDATE programs SET canonical_key=dedupe_key WHERE canonical_key IS NULL")
    c.execute("""UPDATE programs SET canonical_key=substr(dedupe_key,5) WHERE source='web' AND canonical_key=dedupe_key""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_programs_canon ON programs(canonical_key)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_programs_seen ON programs(first_seen)")
    c.executescript("""
CREATE TABLE IF NOT EXISTS program_sources(program_id INTEGER, source TEXT, url TEXT, seen_at TEXT,
  PRIMARY KEY(program_id, source, url));
CREATE TABLE IF NOT EXISTS seen_urls(url_hash TEXT PRIMARY KEY, url TEXT, first_seen_at TEXT, last_seen_at TEXT,
  verdict TEXT, confidence REAL, classified_by TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS dorks(
  id INTEGER PRIMARY KEY, text TEXT NOT NULL, norm TEXT NOT NULL UNIQUE, grp TEXT NOT NULL DEFAULT 'default',
  enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 0, parent_dork_id INTEGER,
  created_at TEXT, last_run_at TEXT, run_count INTEGER NOT NULL DEFAULT 0, hits_total INTEGER NOT NULL DEFAULT 0,
  new_programs_found INTEGER NOT NULL DEFAULT 0, auto_disabled_reason TEXT, rationale TEXT, section TEXT,
  cooldown_days REAL, generated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS queries(
  id INTEGER PRIMARY KEY, provider TEXT, query_text TEXT, normalised_hash TEXT, dork_id INTEGER,
  origin TEXT, recency_window TEXT, run_at TEXT, results_count INTEGER, new_programs_found INTEGER, status TEXT);
CREATE INDEX IF NOT EXISTS ix_queries_hash ON queries(normalised_hash, run_at);
CREATE TABLE IF NOT EXISTS chat_sessions(id INTEGER PRIMARY KEY, created_at TEXT, updated_at TEXT,
  summary TEXT NOT NULL DEFAULT '', summarised_upto INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS chat_messages(id INTEGER PRIMARY KEY, session_id INTEGER, role TEXT, content TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
""")
    # old per-domain rejections and dork run history are kept as memory
    c.execute("""INSERT OR IGNORE INTO seen_urls SELECT 'legacy:'||key, key, ts, ts, 'not_program', 0, 'rules', reason FROM rejected""")
    c.execute("""INSERT INTO queries(provider,query_text,normalised_hash,origin,recency_window,run_at,results_count,new_programs_found,status)
        SELECT 'legacy', query, 'legacy:'||hash, 'builtin', 'unknown', last_run, results, new_found, 'migrated' FROM dork_runs
        WHERE NOT EXISTS (SELECT 1 FROM queries q WHERE q.normalised_hash='legacy:'||dork_runs.hash)""")


def m3_alerts(c: sqlite3.Connection) -> None:
    """Per-channel delivery, date evidence (kind + last-updated), Wayback results, alert log, network stats."""
    for col, decl in (("date_kind", "TEXT NOT NULL DEFAULT 'unknown'"), ("updated_at", "TEXT"),
                      ("wayback_first", "TEXT"), ("wayback_state", "TEXT NOT NULL DEFAULT 'unchecked'")):
        _add(c, "programs", col, decl)
    c.executescript("""
CREATE TABLE IF NOT EXISTS deliveries(program_id INTEGER NOT NULL, kind TEXT NOT NULL, channel TEXT NOT NULL, ts TEXT,
  PRIMARY KEY(program_id, kind, channel));
CREATE TABLE IF NOT EXISTS alert_log(id INTEGER PRIMARY KEY, ts TEXT, channel TEXT, ok INTEGER, error TEXT,
  programs INTEGER, messages INTEGER, kind TEXT);
CREATE TABLE IF NOT EXISTS wayback(url_hash TEXT PRIMARY KEY, url TEXT, first_capture TEXT, status TEXT, checked_at TEXT);
CREATE TABLE IF NOT EXISTS net_stats(name TEXT PRIMARY KEY, ok INTEGER NOT NULL DEFAULT 0,
  retries INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_at TEXT);
""")
    # v2 had one `delivered` flag for every channel. Real sends become telegram deliveries; chat-only ones are
    # recorded as chat and no longer count as delivered (showing something in /chat must not suppress Telegram).
    c.execute("""INSERT OR IGNORE INTO deliveries SELECT id, 'new', 'chat', delivered_at FROM programs
                 WHERE delivered_via='chat'""")
    c.execute("""INSERT OR IGNORE INTO deliveries SELECT id, 'new', 'telegram', delivered_at FROM programs
                 WHERE delivered=1 AND COALESCE(delivered_via,'')!='chat'""")
    c.execute("UPDATE programs SET delivered=0 WHERE delivered_via='chat'")


def m4_reclassify(c: sqlite3.Connection) -> None:
    """Resumable background reclassification: one row per program with the decision reached so far."""
    c.executescript("""
CREATE TABLE IF NOT EXISTS reclassify_queue(program_id INTEGER PRIMARY KEY, status TEXT NOT NULL DEFAULT 'pending',
  decision TEXT, reason TEXT, by TEXT, ts TEXT);
""")


def m5_sequence(c: sqlite3.Connection) -> None:
    """Resumable ordered search queue, per-provider health/circuit-breaker, LLM usage ledger. Purely additive
    (reverse = drop these three tables; the backup taken before migration is the full rollback)."""
    c.executescript("""
CREATE TABLE IF NOT EXISTS search_steps(id INTEGER PRIMARY KEY, batch_id INTEGER NOT NULL, pos INTEGER NOT NULL,
  dork_id INTEGER, dork_text TEXT, provider TEXT, status TEXT NOT NULL DEFAULT 'pending', answered_by TEXT,
  results INTEGER DEFAULT 0, new_found INTEGER DEFAULT 0, spent INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0,
  note TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS ix_steps_batch ON search_steps(batch_id, status, pos);
CREATE TABLE IF NOT EXISTS provider_health(provider TEXT PRIMARY KEY, consecutive_fails INTEGER NOT NULL DEFAULT 0,
  open_until TEXT, last_error TEXT, last_ok TEXT, ok INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
  retries INTEGER NOT NULL DEFAULT 0, engines TEXT);
CREATE TABLE IF NOT EXISTS llm_usage(id INTEGER PRIMARY KEY, ts TEXT, model_id TEXT, role TEXT, ok INTEGER,
  tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0, cost_usd REAL DEFAULT 0, error TEXT);
CREATE INDEX IF NOT EXISTS ix_llm_usage_ts ON llm_usage(ts);
""")


def m6_validation(c: sqlite3.Connection) -> None:
    """v0.5: LLM program validation (cache by URL + content hash, human labels) and AI-dork promotion bookkeeping.
    Additive only: new columns default to NULL/0, so every existing row keeps its behaviour (validity NULL = never assessed;
    such rows are validated only if they become due to alert). Reverse = the backup taken before migration."""
    for col, decl in (("validity", "TEXT"), ("validity_reason", "TEXT"), ("validity_line", "TEXT"), ("validated_at", "TEXT"), ("validation_id", "INTEGER"),
                      ("label", "TEXT"), ("label_note", "TEXT"), ("labeled_at", "TEXT"), ("found_by_dork", "INTEGER")):
        _add(c, "programs", col, decl)
    for col, decl in (("origin", "TEXT"), ("promoted_at", "TEXT"), ("promotion_evidence", "TEXT"), ("demoted_at", "TEXT"),
                      ("kept_total", "INTEGER NOT NULL DEFAULT 0")):
        _add(c, "dorks", col, decl)
    c.execute("UPDATE dorks SET origin = CASE grp WHEN 'default' THEN 'shipped' WHEN 'ai' THEN 'ai' ELSE 'custom' END "
              "WHERE origin IS NULL")
    c.executescript("""
CREATE INDEX IF NOT EXISTS ix_programs_dork ON programs(found_by_dork);
CREATE TABLE IF NOT EXISTS validations(id INTEGER PRIMARY KEY, url_hash TEXT NOT NULL, url TEXT, content_hash TEXT NOT NULL,
  final_url TEXT, http_status INTEGER, model_id TEXT, created_at TEXT, assessment TEXT, checks TEXT, decision TEXT,
  confidence REAL, reason TEXT, parsed_via TEXT, UNIQUE(url_hash, content_hash));
CREATE TABLE IF NOT EXISTS program_labels(id INTEGER PRIMARY KEY, program_id INTEGER, url TEXT, title TEXT, label TEXT,
  note TEXT, ts TEXT, llm_decision TEXT, dork_id INTEGER);
""")


MIGRATIONS = [m1_base, m2_v2, m3_alerts, m4_reclassify, m5_sequence, m6_validation]


def backup(src: sqlite3.Connection, path: Path, tag: str) -> Path:
    d = path.parent / "backups"
    d.mkdir(exist_ok=True)
    dest = d / f"{path.stem}-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{tag}.db"
    src.commit()  # a pending write transaction on the source would make the backup wait forever
    out = sqlite3.connect(dest)
    with out:
        src.backup(out)
    out.close()
    for old in sorted(d.glob(f"{path.stem}-*.db"))[:-KEEP_BACKUPS]:
        old.unlink(missing_ok=True)
    return dest


def migrate(conn: sqlite3.Connection, path: Path | None) -> Path | None:
    cur = conn.execute("PRAGMA user_version").fetchone()[0]
    if cur > len(MIGRATIONS):
        raise RuntimeError(f"database schema v{cur} is NEWER than this qurihunter understands (v{len(MIGRATIONS)}) — "
                           "you are running an old copy of the code; refusing to touch it")
    if cur == len(MIGRATIONS):
        return None
    made = None
    has_data = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] > 0
    if has_data and path is not None:
        made = backup(conn, path, f"v{cur}")
    for i in range(cur, len(MIGRATIONS)):  # each step is idempotent; the backup above is the rollback
        MIGRATIONS[i](conn)
        conn.execute(f"PRAGMA user_version={i + 1}")
        conn.commit()
    return made
