"""Background, resumable re-classification of stored dork entries. A job is a queue in the DB, so it survives restarts.
Each cycle does the free hard-rule checks for everything and at most `reclassify.pages_per_cycle` LLM/page-fetch
judgements. It only records decisions; hiding anything needs `/memory reclassify apply` (after the before/after table).
It never sends alerts and never takes the scan lock."""
from __future__ import annotations

from . import dates
from .classify import from_result, hard_reject
from .logs import log
from .search import SearchResult


def state(db) -> str:
    return db.meta("reclass_state", "idle")


def start(db) -> int:
    """Queue every stored web entry (a finished/applied job is cleared first). Returns the queue size."""
    if state(db) in ("done", "applied", "idle", "cancelled"):
        db.c.execute("DELETE FROM reclassify_queue")
    db.c.execute("INSERT OR IGNORE INTO reclassify_queue(program_id) SELECT id FROM programs "
                 "WHERE source='web' AND verdict='official_program'")
    db.set_meta("reclass_state", "running")
    db.set_meta("reclass_started", dates.now_iso())
    db.set_meta("reclass_reported", "0")
    db.commit()
    return db.c.execute("SELECT COUNT(*) FROM reclassify_queue").fetchone()[0]


def progress(db) -> dict:
    q = lambda sql: db.c.execute(sql).fetchone()[0]  # noqa: E731
    return {"state": state(db), "total": q("SELECT COUNT(*) FROM reclassify_queue"),
            "done": q("SELECT COUNT(*) FROM reclassify_queue WHERE status='done'"),
            "rejected": q("SELECT COUNT(*) FROM reclassify_queue WHERE decision='reject'")}


def step(db, cfg: dict, llm, pages: int | None = None) -> dict:
    """One background cycle. Hard rules are free; LLM judgements are capped at `pages`."""
    if state(db) != "running":
        return progress(db)
    import contextlib
    with (llm.bulk() if hasattr(llm, "bulk") else contextlib.nullcontext()):  # bulk jobs never use the Claude CLI
        return _step(db, cfg, llm, pages)


def _step(db, cfg: dict, llm, pages: int | None) -> dict:
    """Hard rules are free. The LLM judges at most `cap` pages per cycle - in batches of `llm.batch_size` pages per call when
    the backend is call-limited (one call, strict JSON array; unparsable items are retried on their own)."""
    from . import background
    cap = int(pages if pages is not None else cfg.get("reclassify", {}).get("pages_per_cycle", 20))
    used = 0
    rows = db.c.execute("SELECT p.* FROM reclassify_queue q JOIN programs p ON p.id=q.program_id "
                        "WHERE q.status='pending' ORDER BY p.id").fetchall()
    size = int(getattr(llm, "batch_size", 1) or 1) if llm is not None else 1

    def record(r, dec, reason, by):
        if dec == "keep" and r["kind"] == "security.txt":
            reason += " · bare security.txt (filter: --category securitytxt)"
        db.c.execute("UPDATE reclassify_queue SET status='done', decision=?, reason=?, by=?, ts=? WHERE program_id=?",
                     (dec, reason, by, dates.now_iso(), r["id"]))
        db.commit()  # short write transaction, released before the next (slow) LLM call

    def judge(r, item):
        try:
            p, reason = from_result(item, llm, allow_llm=True)
        except Exception as e:  # noqa: BLE001
            log.warning("reclassify judge failed for %s: %s", r["url"], e)
            return False
        if p is None and reason != "ambiguous-skipped":
            record(r, "reject", reason, "llm" if reason.startswith("LLM") else "rules")
        else:
            record(r, "keep", "confirmed" if p is not None else "unverified (LLM unsure)", "llm")
        return True
    pending_llm: list = []

    def flush_batch() -> None:
        nonlocal used
        if not pending_llm:
            return
        chunk, pending_llm[:] = list(pending_llm), []
        items = []
        for r in chunk:
            it = SearchResult(r["name"] or "", r["url"], r["snippet"] or "")
            items.append((r, it))
        db.commit()
        try:  # ONE call for the whole chunk (fetch the pages first, outside any transaction)
            from .classify import fetch_text
            pg = [{"url": it.url, "title": it.title, "snippet": it.snippet, "page": fetch_text(it.url, 600)} for _, it in items]
            for (_, it), v in zip(items, llm.classify_batch(pg)):
                it.verdict = v
        except Exception as e:  # noqa: BLE001 - fall back to one call per page below
            log.warning("batch classification failed (%s); judging page by page", e)
        for r, it in items:
            judge(r, it)
        used += len(items)
    for r in rows:
        db.commit()  # nothing may be pending while we wait for the foreground or call the LLM
        if not background.checkpoint():
            break  # paused / a foreground command is busy for too long: resume next cycle
        why = hard_reject(r["url"], r["name"] or "")
        if why:
            record(r, "reject", why, "rules")
        elif llm is None:
            record(r, "keep", "kept (no LLM to double-check)", "rules")
        elif used + len(pending_llm) < cap:
            if size > 1:
                pending_llm.append(r)
                if len(pending_llm) >= size or used + len(pending_llm) >= cap:
                    flush_batch()
            else:
                used += 1
                judge(r, SearchResult(r["name"] or "", r["url"], r["snippet"] or ""))
        # else: cap reached, next cycle
    if pending_llm and background.checkpoint():
        flush_batch()
    left = db.c.execute("SELECT COUNT(*) FROM reclassify_queue WHERE status='pending'").fetchone()[0]
    if left == 0:
        db.set_meta("reclass_state", "done")
    db.commit()
    return progress(db)


def plan(db) -> list[dict]:
    out = []
    for r in db.c.execute("SELECT q.*, p.name, p.url, p.kind FROM reclassify_queue q JOIN programs p ON p.id=q.program_id "
                          "WHERE q.status='done' ORDER BY p.id"):
        out.append({"id": r["program_id"], "name": r["name"] or "", "url": r["url"], "decision": r["decision"],
                    "reason": r["reason"] or "", "by": r["by"] or "rules", "kind": r["kind"]})
    return out


def apply(db) -> int:
    from .scanner import reclassify_apply
    n = reclassify_apply(db, plan(db))
    db.set_meta("reclass_state", "applied")
    db.commit()
    return n


def cancel(db) -> None:
    db.set_meta("reclass_state", "cancelled")
    db.commit()


def job(llm_factory):
    """Worker hook: advance a running job by one capped cycle."""
    def _job(db, cfg):
        if state(db) == "running":
            from . import background
            background.note("reclassify", job=f"{progress(db)['done']}/{progress(db)['total']}")
            step(db, cfg, llm_factory(cfg, db))  # the worker's own connection: no second connection, no cross-lock
    return _job
