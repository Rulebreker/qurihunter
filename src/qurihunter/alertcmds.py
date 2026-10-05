"""/version, /alerts (status|pending|resend|test) and /why — plus the startup self-checks."""
from __future__ import annotations

import difflib
import subprocess
import sys
from pathlib import Path

from rich.table import Table

from . import __version__, alerts, config, dates, listing, notify, ui
from .config import CONFIG_VERSION, recency_days
from .migrations import MIGRATIONS

# Every command the product promises. The registry is checked against this at startup and in the tests.
SPEC_COMMANDS = ["/scan", "/watch", "/config", "/model", "/filters", "/status", "/test", "/programs", "/export",
                 "/logs", "/help", "/quit", "/recency", "/dorks", "/memory", "/history", "/chat", "/alerts", "/why",
                 "/version", "/sequence", "/providers", "/searxng", "/llm", "/background"]
ALIASES = {"/exit": "/quit", "/q": "/quit", "/?": "/help"}


def git_commit() -> str:
    root = Path(__file__).resolve().parents[2]
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                             timeout=3)
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True, timeout=3)
        if out.returncode == 0:
            return out.stdout.strip() + (" (dirty)" if dirty.stdout.strip() else "")
    except (OSError, subprocess.SubprocessError):
        pass
    return "n/a (not a git checkout)"


def version_info(ctx=None) -> dict:
    import qurihunter
    d = {"qurihunter": __version__, "git commit": git_commit(),
         "DB schema": "?", "config version": "?", "python": sys.executable, "install path": str(Path(qurihunter.__file__).parent),
         "entry point": sys.argv[0]}
    if ctx is not None:
        d["DB schema"] = f"{ctx.db.c.execute('PRAGMA user_version').fetchone()[0]} (code expects {len(MIGRATIONS)})"
        d["config version"] = f"{ctx.cfg.get('version')} (code expects {CONFIG_VERSION})"
        d["DB file"] = str(ctx.db.path)
    return d


def cmd_version(ctx, args):
    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(style="bold cyan")
    t.add_column(overflow="fold")
    for k, v in version_info(ctx).items():
        t.add_row(k, str(v))
    ui.console.print(t)
    for w in self_check(ctx):
        ui.fail(w)


# ───────────────────────────── self-checks ─────────────────────────────
def _code_mtime() -> float:
    return max((p.stat().st_mtime for p in Path(__file__).parent.glob("*.py")), default=0.0)


_STARTED = _code_mtime()


def stale_code() -> str | None:
    """The scenario behind 'unknown command /memory': a long-running session keeps the code it started with."""
    if _code_mtime() > _STARTED + 1:
        return ("the qurihunter source on disk changed after this session started — you are running OLD code. "
                "Quit and start `qurihunter` again to load it.")
    return None


def self_check(ctx, registered=None) -> list[str]:
    """Loud warnings: DB/config newer than the code, commands missing from the registry."""
    out = []
    from .cli import COMMANDS
    reg = set(registered if registered is not None else COMMANDS)
    missing = [c for c in SPEC_COMMANDS if c not in reg]
    if missing:
        out.append(f"command registry is missing: {', '.join(missing)} — this is not the full qurihunter")
    cv = ctx.cfg.get("version", 0)
    if isinstance(cv, int) and cv > CONFIG_VERSION:
        out.append(f"config.json is version {cv} but this code only knows {CONFIG_VERSION}: you are running an OLD copy")
    v = ctx.db.c.execute("PRAGMA user_version").fetchone()[0]
    if v > len(MIGRATIONS):
        out.append(f"database schema v{v} is newer than this code (v{len(MIGRATIONS)}): you are running an OLD copy")
    last = ctx.db.meta("code_version")
    if last and _vt(last) > _vt(__version__):
        out.append(f"this database was last used by qurihunter {last}, but you are running {__version__}")
    w = stale_code()
    if w:
        out.append(w)
    return out


def _vt(v: str):
    return tuple(int(x) if x.isdigit() else 0 for x in str(v).split("."))


def stamp(ctx) -> None:
    ctx.db.set_meta("code_version", __version__)
    ctx.db.commit()


def suggest(cmd: str, known) -> tuple[str | None, list[str]]:
    """(auto-run target, hints). Distance-1 unique match runs (e.g. /alert -> /alerts); otherwise just a hint."""
    known = list(known)
    if cmd in ALIASES:
        return ALIASES[cmd], []
    near = [k for k in known if _dist(cmd, k) == 1]
    if len(near) == 1:
        return near[0], []
    close = difflib.get_close_matches(cmd, known, n=3, cutoff=0.6)
    close += [k for k in known if k.startswith(cmd) and k not in close]
    return None, close[:3]


def _dist(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ───────────────────────────── /alerts ─────────────────────────────
USAGE = ("usage: /alerts status | pending | resend [N|all|--since 7d] | test | baseline-legacy [--dry-run] | "
         "release-pending [N]")


def cmd_alerts(ctx, args):
    sub = args[0] if args else ""
    if sub == "status":
        _status(ctx)
    elif sub == "pending":
        _pending(ctx)
    elif sub == "resend":
        _resend(ctx, args[1:])
    elif sub == "test":
        _test(ctx)
    elif sub == "baseline-legacy":
        _baseline_legacy(ctx, args[1:])
    elif sub == "release-pending":
        _release_pending(ctx, args[1:])
    else:
        ui.info(USAGE)
        if not sub:
            _status(ctx)


def status_data(ctx) -> dict:
    db, cfg = ctx.db, ctx.cfg
    q = lambda sql, a=(): db.c.execute(sql, a).fetchone()  # noqa: E731
    last_ok = q("SELECT ts, channel, programs, messages FROM alert_log WHERE ok=1 ORDER BY id DESC LIMIT 1")
    last_err = q("SELECT ts, channel, error FROM alert_log WHERE ok=0 ORDER BY id DESC LIMIT 1")
    per = {}
    for ch, kind, n in db.c.execute("SELECT channel, kind, COUNT(*) FROM deliveries GROUP BY channel, kind"):
        per.setdefault(ch, {})[kind] = n
    due = alerts.due(db, cfg)
    return {"channels": cfg["notify"]["channels"], "last_ok": last_ok, "last_err": last_err, "per_channel": per,
            "pending_new": sum(1 for _, k in due if k == "new"), "pending_updated": sum(1 for _, k in due if k == "updated"),
            "reasons": alerts.pending_reasons(db, cfg),
            "summary_mode": cfg["alerts"]["telegram_scan_summary"], "last_summary": db.meta("last_summary"),
            "window": dates.window_text(recency_days(cfg))}


def _status(ctx):
    s = status_data(ctx)
    t = Table(title="Alerts", show_header=False, box=None, padding=(0, 2))
    t.add_column(style="bold cyan")
    t.add_column(overflow="fold")
    t.add_row("Channels", ", ".join(s["channels"]) or "[red]none configured — nothing can be sent[/red]")
    t.add_row("Window", s["window"])
    lo = s["last_ok"]
    t.add_row("Last successful send", f"{dates.to_local(lo['ts'])} ({lo['channel']}: {lo['programs']} program(s) in "
                                      f"{lo['messages']} message(s))" if lo else "never")
    le = s["last_err"]
    t.add_row("Last error", f"[red]{dates.to_local(le['ts'])} {le['channel']}: {le['error']}[/red]" if le else "none")
    t.add_row("Pending", f"{s['pending_new']} new, {s['pending_updated']} updated (waiting for delivery)")
    for why, n in s["reasons"].items():
        t.add_row("  pending because", f"{n} × {why}")
    from . import retry
    t.add_row("Retry", retry.status(ctx.db, ctx.cfg))
    t.add_row("Delivered", "; ".join(f"{ch}: " + ", ".join(f"{n} {k}" for k, n in d.items())
                                     for ch, d in s["per_channel"].items()) or "nothing yet")
    t.add_row("Scan summary", f"{s['summary_mode']}" + (f" · last: {s['last_summary']}" if s["last_summary"] else ""))
    t.add_row("Updated-only pages", "alert" if ctx.cfg["alerts"]["alert_updated_only_pages"] else "do not alert")
    ui.console.print(t)


def _pending(ctx):
    due = alerts.due(ctx.db, ctx.cfg)
    if not due:
        ui.ok("Nothing pending.")
        return
    rows = listing.decorate(ctx.db, ctx.cfg, [r for r, _ in due], recency_days(ctx.cfg))
    ui.console.print(listing.table(rows, f"Pending alerts — {len(rows)} (sent on the next scan, or /alerts resend)"))


def _resend(ctx, args):
    db, cfg = ctx.db, ctx.cfg
    chans = [c for c in cfg["notify"]["channels"] if c in alerts.REAL_CHANNELS]
    if not chans:
        ui.fail("no alert channel configured (/config)")
        return
    q = ("SELECT d.program_id, d.kind, MAX(d.ts) ts FROM deliveries d WHERE d.channel IN (%s) GROUP BY d.program_id, d.kind"
         % ",".join("?" * len(chans)))
    rows = db.c.execute(q + " ORDER BY ts DESC", chans).fetchall()
    arg = args[0] if args else "all"
    try:
        if arg == "--since":
            cut = dates.iso(dates.parse_since(args[1]))
            rows = [r for r in rows if r["ts"] >= cut]
            label = f"delivered since {args[1]}"
        elif arg == "all":
            label = "every delivered alert"
        else:
            rows = rows[: int(arg)]
            label = f"the last {arg} delivered"
    except (ValueError, IndexError):
        ui.fail("usage: /alerts resend [N | all | --since 7d]")
        return
    if not rows:
        ui.info("Nothing to resend.")
        return
    if not ui.yn(f"Re-send {len(rows)} alert(s) ({label}) to {', '.join(chans)}?", False):
        ui.info("cancelled")
        return
    items = [(db.program(r["program_id"]), r["kind"]) for r in rows]
    items = [(p, k) for p, k in items if p]
    items.sort(key=lambda x: x[1] != "new")
    for p, k in items:
        db.c.execute("DELETE FROM deliveries WHERE program_id=? AND kind=? AND channel IN (%s)" % ",".join("?" * len(chans)),
                     (p["id"], k, *chans))
    db.commit()
    res = notify.deliver(cfg, db, items)
    for ch, r in res.items():
        (ui.ok if r == "ok" else ui.fail)(f"{ch}: {'resent ' + str(len(items)) if r == 'ok' else r + ' — still pending'}")


LEGACY_SQL = ("SELECT * FROM programs WHERE source='web' AND legacy_migrated=1 AND launched_at IS NULL AND updated_at IS NULL "
              "AND baseline=0 AND filtered=0 AND verdict='official_program' AND "
              "id NOT IN (SELECT program_id FROM deliveries WHERE channel!='chat') ORDER BY id")


def _baseline_legacy(ctx, args):
    """Old undated rows from the first v1 dork batch (stored before the v2 migration): mark them baseline so they
    never alert. --dry-run only reports."""
    rows = ctx.db.c.execute(LEGACY_SQL).fetchall()
    if not rows:
        ui.ok("No legacy undated rows are waiting - nothing to baseline.")
        return
    t = Table(title=f"{len(rows)} legacy undated rows (first v1 dork batch, never delivered) - sample of 10", header_style="bold")
    for c in ("ID", "Name", "URL"):
        t.add_column(c, overflow="fold")
    for r in rows[:10]:
        t.add_row(str(r["id"]), (r["name"] or "")[:60], r["url"])
    ui.console.print(t)
    if "--dry-run" in args:
        ui.info("dry run: nothing changed.")
        return
    if not ui.yn(f"Mark these {len(rows)} rows as baseline (they will never alert)?", False):
        ui.info("cancelled")
        return
    ctx.db.c.executemany("UPDATE programs SET baseline=1 WHERE id=?", [(r["id"],) for r in rows])
    ctx.db.commit()
    ui.ok(f"{len(rows)} legacy rows are now baseline.")


def _release_pending(ctx, args):
    """Send items that are waiting for archive verification NOW, clearly labelled 'age unverified'."""
    db, cfg = ctx.db, ctx.cfg
    waiting = [(r, k) for r, k in alerts.due(db, cfg) if alerts.awaiting_archive(r, cfg)]
    if args and args[0].isdigit():
        waiting = waiting[: int(args[0])]
    elif args:
        ui.fail("usage: /alerts release-pending [N]")
        return
    if not waiting:
        ui.info("Nothing is waiting for archive verification.")
        return
    rows = listing.decorate(db, cfg, [r for r, _ in waiting], recency_days(cfg))
    ui.console.print(listing.table(rows, f"Waiting for archive verification — {len(rows)}"))
    if not ui.yn(f"Send {len(waiting)} item(s) now, labelled 'age unverified'?", False):
        ui.info("cancelled")
        return
    res = notify.deliver(cfg, db, waiting, unverified={r["id"] for r, _ in waiting})
    for ch, r in res.items():
        (ui.ok if r == "ok" else ui.fail)(f"{ch}: {'sent ' + str(len(waiting)) if r == 'ok' else r + ' - still pending'}")


def _test(ctx):
    cfg = ctx.cfg
    if not cfg["notify"]["channels"]:
        ui.fail("no alert channel configured (/config)")
        return
    smp = notify.samples()
    msgs = notify.build(smp, recency_days(cfg), sample=True)
    if "telegram" in cfg["notify"]["channels"]:
        sent, err = notify.send_messages_telegram(cfg, msgs)
        (ui.ok if err is None else ui.fail)(f"telegram: {'sent ' + str(sent) + ' SAMPLE message(s)' if err is None else err}")
    if "email" in cfg["notify"]["channels"]:
        e = cfg["notify"]["email"]
        try:
            notify.send_email(e["address"], e["app_password"], e.get("to") or e["address"], "[qurihunter] SAMPLE alert",
                              "\n\n".join(m.plain for m in msgs))
            ui.ok("email: sent SAMPLE alert")
        except notify.NotifyError as ex:
            ui.fail(f"email: {ex}")


# ───────────────────────────── /why ─────────────────────────────
def find_program(db, ref: str):
    if ref.isdigit():
        r = db.program(int(ref))
        if r:
            return r
    like = f"%{ref}%"
    return db.c.execute("SELECT * FROM programs WHERE url=? OR dedupe_key=? OR canonical_key=? OR url LIKE ? OR name LIKE ? "
                        "ORDER BY id DESC LIMIT 1", (ref, ref, ref, like, like)).fetchone()


def explain(db, cfg, r) -> list[str]:
    days = recency_days(cfg)
    cls, why = alerts.classify(r, days)
    chans = [c for c in cfg["notify"]["channels"] if c in alerts.REAL_CHANNELS]
    sent = db.delivered_channels(r["id"])
    due = {(p["id"], k) for p, k in alerts.due(db, cfg)}
    L = [f"{r['name']}  (#{r['id']}, {r['source']})", f"  {r['url']}",
         f"  decision: {cls.upper()} — {why}",
         f"  evidence: {alerts.evidence_line(r, days)}",
         f"  basis: {alerts.basis(r)[0]}" + ("" if cfg['alerts'].get('alert_weak_evidence', True) or not alerts.basis(r)[1]
                                           else "  → NOT alerted: alert_weak_evidence is off"),
         f"  dates: launched {r['launched_at'] or 'unknown'} ({r['launched_at_source']}) · updated {r['updated_at'] or 'unknown'} "
         f"· date kind {r['date_kind']} · first seen {r['first_seen']}",
         f"  wayback: {r['wayback_state']}" + (f" (first capture {r['wayback_first']})" if r["wayback_first"] else ""),
         f"  window: {dates.window_text(days)} · baseline={bool(r['baseline'])} · filtered={bool(r['filtered'])} · "
         f"verdict={r['verdict']}",
         "  delivered: " + ("; ".join(f"{ch}: {', '.join(k)}" for ch, k in sent.items()) or "no channel yet")]
    if r["source"] == "web" and not r["launched_at"] and r["wayback_state"] in ("unchecked", "error") \
            and cfg.get("wayback", {}).get("enabled", True) and not r["baseline"] and cls in alerts.KINDS \
            and cfg["wayback"].get("on_error", "wait") == "wait":
        L.append("  → WAITING: undated page not yet verified against the Wayback Machine (archive unreachable or budget "
                 "spent); retried every scan. Set wayback.on_error to \"alert\" to send unverified ones as 'likely new'.")
    elif (r["id"], cls) in due:
        L.append(f"  → will be alerted on the next scan ({', '.join(chans) or 'NO CHANNEL CONFIGURED'})")
    elif cls in alerts.KINDS:
        if cls == "updated" and not cfg["alerts"]["alert_updated_only_pages"]:
            L.append("  → NOT alerted: alert_updated_only_pages is off")
        else:
            L.append(f"  → nothing due: the {cls} alert was already delivered on every configured channel")
    else:
        L.append(f"  → will not alert: {why}")
    return L


def cmd_why(ctx, args):
    if not args:
        ui.fail("usage: /why <program id | url | name>")
        return
    r = find_program(ctx.db, " ".join(args))
    if not r:
        ui.fail("no such program")
        return
    for line in explain(ctx.db, ctx.cfg, r):
        ui.console.print(line, markup=False)
