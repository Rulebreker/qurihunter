"""Background retry of pending alerts (archive-verification waits and failed sends) with exponential backoff and a
per-day cap. Runs in a daemon thread inside the REPL and /watch; every tick uses its own DB connection, takes the same
scan lock as /scan (so it never overlaps one) and never blocks the foreground."""
from __future__ import annotations

import threading
from datetime import timedelta

from . import alerts, config, dates
from .logs import log


def _today() -> str:
    return dates.utcnow().astimezone(dates.local_tz()).strftime("%Y-%m-%d")


def tick(db, cfg: dict, now=None) -> str | None:
    """One scheduling decision. Returns a short description when a retry ran, else None."""
    pc = cfg["pending"]
    now = now or dates.utcnow()
    if not pc.get("retry_enabled", True):
        return None
    if db.meta("retry_day") != _today():
        db.set_meta("retry_day", _today())
        db.set_meta("retry_count", "0")
    if int(db.meta("retry_count", "0")) >= int(pc["retry_max_per_day"]):
        return None
    nxt = db.meta("retry_next")
    if nxt and dates.parse_date(nxt) and now < dates.parse_date(nxt):
        return None
    reasons = alerts.pending_reasons(db, cfg)
    if not any(k.startswith(("waiting", "last send failed")) for k in reasons):
        db.set_meta("retry_streak", "0")
        db.commit()
        return None
    from .scanner import ScanLocked, retry_pending
    before = db.c.execute("SELECT COUNT(*) FROM deliveries WHERE channel!='chat'").fetchone()[0]
    wb_before = db.c.execute("SELECT COUNT(*) FROM programs WHERE wayback_state IN ('unchecked','error')").fetchone()[0]
    try:
        retry_pending(cfg, db)
    except ScanLocked:
        return None  # a scan is running; it handles the queue itself
    after = db.c.execute("SELECT COUNT(*) FROM deliveries WHERE channel!='chat'").fetchone()[0]
    wb_after = db.c.execute("SELECT COUNT(*) FROM programs WHERE wayback_state IN ('unchecked','error')").fetchone()[0]
    progress = (after > before) or (wb_after < wb_before)
    streak = 0 if progress else int(db.meta("retry_streak", "0")) + 1
    delay = min(float(pc["backoff_base_min"]) * (2 ** streak), float(pc["backoff_max_min"]))
    db.set_meta("retry_streak", str(streak))
    db.set_meta("retry_next", dates.iso(now + timedelta(minutes=delay)))
    db.set_meta("retry_count", str(int(db.meta("retry_count", "0")) + 1))
    db.commit()
    return f"retry {'made progress' if progress else 'no progress'}; next in {delay:.0f} min"


def status(db, cfg: dict) -> str:
    pc = cfg["pending"]
    if not pc.get("retry_enabled", True):
        return "background retry: off"
    nxt = db.meta("retry_next")
    return (f"background retry: {db.meta('retry_count', '0')}/{pc['retry_max_per_day']} today, backoff streak "
            f"{db.meta('retry_streak', '0')}" + (f", next after {dates.to_local(nxt)}" if nxt else ""))


class Worker(threading.Thread):
    """Daemon thread: wakes every `check_every_s`, runs tick() with its own connection, swallows every error."""

    def __init__(self, extra=None):
        super().__init__(daemon=True, name="qurihunter-bg-retry")
        self.stop_event = threading.Event()
        self.extra = extra or []  # other background jobs: callables (db, cfg)

    def run(self):
        from . import background, dblock
        from .db import DB
        dblock.mark_background()  # lower priority than any foreground command for the write gate
        background.note("retry", alive=True, job="starting")
        try:
            db = DB()
        except Exception:  # noqa: BLE001
            log.exception("retry worker could not open the DB")
            background.note("retry", alive=False, error="could not open the DB")
            return
        while not self.stop_event.is_set():
            try:
                cfg = config.load()
                if cfg.get("background_workers", True) and not background.paused() and background.checkpoint(30):
                    background.note("retry", job="checking pending alerts", last_tick=dates.now_iso())
                    msg = tick(db, cfg)
                    if msg:
                        log.info("pending retry: %s", msg)
                    for job in self.extra:
                        if background.checkpoint(30):
                            job(db, cfg)
                    background.note("retry", job="idle", error="")
            except dblock.DatabaseBusy as e:
                background.note("retry", error=f"database busy, will retry: {e}")
                log.warning("background tick skipped: %s", e)
            except Exception as e:  # noqa: BLE001 — a background helper must never crash the app
                background.note("retry", error=f"{type(e).__name__}: {e}"[:150])
                log.exception("background worker tick failed")
            finally:
                try:
                    dblock.flush()
                except Exception:  # noqa: BLE001
                    pass
            self.stop_event.wait(float(config.load()["pending"].get("check_every_s", 60)))
        background.note("retry", alive=False, job="stopped")

    def stop(self):
        self.stop_event.set()
