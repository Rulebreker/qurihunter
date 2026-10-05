"""Ordered, resumable search queue. A batch is an ordered list of (dork, provider) steps processed one at a time; every
step's outcome is persisted, so a crash / Ctrl+C / quota stop resumes exactly where it stopped and finished steps are
never re-spent. Modes: failover (first usable provider that can express the dork), cascade (add providers until
`cascade_min_results` new results), sweep (every provider; needs a stored confirmation)."""
from __future__ import annotations

from datetime import timedelta

from . import dates
from .db import DB

MODES = ("failover", "cascade", "sweep")
MAX_ATTEMPTS = 3
BATCH_MAX_AGE_H = 48  # an unfinished batch older than this is dropped (the dork list / window may have changed)


def mode_of(cfg: dict) -> str:
    m = cfg.get("search_mode", "failover")
    if m == "sweep" and not cfg.get("sweep_confirmed"):
        return "failover"  # sweep spends the most quota: it only runs after an explicit confirmation
    return m if m in MODES else "failover"


# ── persistence ──────────────────────────────────────────────────────────────────
def pending_batch(db: DB) -> int | None:
    b = db.meta("seq_batch")
    if not b:
        return None
    left = db.c.execute("SELECT COUNT(*) FROM search_steps WHERE batch_id=? AND status='pending'", (int(b),)).fetchone()[0]
    created = dates.parse_date(db.meta("seq_batch_created") or "")
    if left == 0:
        return None
    if created and dates.utcnow() - created > timedelta(hours=BATCH_MAX_AGE_H):
        expire(db)
        return None
    return int(b)


def expire(db: DB) -> int:
    b = db.meta("seq_batch")
    n = 0
    if b:
        n = db.c.execute("UPDATE search_steps SET status='expired' WHERE batch_id=? AND status='pending'", (int(b),)).rowcount
    db.set_meta("seq_batch", "")
    db.commit()
    return n


def plan_batch(db: DB, rows, provider_ids_for, mode: str) -> int:
    """rows: dork rows in priority order. provider_ids_for(row) -> ordered capable provider ids."""
    bid = (db.c.execute("SELECT COALESCE(MAX(batch_id),0) FROM search_steps").fetchone()[0]) + 1
    pos = 0
    for r in rows:
        chain = provider_ids_for(r)
        if not chain:
            continue
        for pid in (chain if mode == "sweep" else chain[:1]):
            pos += 1
            db.c.execute("INSERT INTO search_steps(batch_id,pos,dork_id,dork_text,provider,ts) VALUES(?,?,?,?,?,?)",
                         (bid, pos, r["id"], r["text"], pid, dates.now_iso()))
    db.set_meta("seq_batch", str(bid))
    db.set_meta("seq_batch_created", dates.now_iso())
    db.set_meta("seq_stopped", "")
    db.commit()
    return bid


def steps(db: DB, bid: int, status: str = "pending"):
    return db.c.execute("SELECT * FROM search_steps WHERE batch_id=? AND status=? ORDER BY pos", (bid, status)).fetchall()


def mark(db: DB, step_id: int, status: str, **f) -> None:
    sets = ["status=?", "ts=?"]
    args: list = [status, dates.now_iso()]
    for k in ("answered_by", "results", "new_found", "spent", "note"):
        if k in f:
            sets.append(f"{k}=?")
            args.append(f[k])
    db.c.execute(f"UPDATE search_steps SET {','.join(sets)} WHERE id=?", (*args, step_id))
    db.commit()


def attempt(db: DB, step_id: int) -> int:
    db.c.execute("UPDATE search_steps SET attempts=attempts+1 WHERE id=?", (step_id,))
    db.commit()
    return db.c.execute("SELECT attempts FROM search_steps WHERE id=?", (step_id,)).fetchone()[0]


def stop(db: DB, reason: str) -> None:
    db.set_meta("seq_stopped", reason)
    db.commit()


def reset_cursor(db: DB) -> int:
    """Drop the unfinished batch: the next scan plans a fresh one (finished steps stay recorded)."""
    db.set_meta("seq_stopped", "")
    return expire(db)


def progress(db: DB) -> dict:
    b = db.meta("seq_batch")
    if not b:
        return {"batch": None, "done": 0, "total": 0, "next": None, "stopped": db.meta("seq_stopped") or ""}
    q = lambda st: db.c.execute("SELECT COUNT(*) FROM search_steps WHERE batch_id=? AND status IN (%s)" % st, (int(b),)).fetchone()[0]  # noqa: E731
    total = db.c.execute("SELECT COUNT(*) FROM search_steps WHERE batch_id=? AND status!='expired'", (int(b),)).fetchone()[0]
    nxt = db.c.execute("SELECT * FROM search_steps WHERE batch_id=? AND status='pending' ORDER BY pos LIMIT 1", (int(b),)).fetchone()
    return {"batch": int(b), "done": q("'done','skipped','error'"), "total": total, "next": nxt,
            "stopped": db.meta("seq_stopped") or ""}


def sweep_estimate(cfg: dict, pool_rings, dorks_per_cycle: int) -> dict:
    """Quota a sweep would spend per cycle: every dork on every enabled provider (pages per query included)."""
    pages = int(cfg["search"].get("pages", 1))
    per = {r.provider.id: dorks_per_cycle * pages for r in pool_rings}
    return {"per_provider": per, "total": sum(per.values()), "dorks": dorks_per_cycle}
