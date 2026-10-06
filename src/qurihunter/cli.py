from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime

from rich.table import Table

from . import alertcmds, background, dblock, checks, config, instance, listing, memcmds, modelcmds, retry, seqcmds, ui, valcmds, wizard
from .config import enabled_platforms, mask
from . import __version__
from .db import DB
from .logs import setup as setup_logging
from .scanner import ScanLocked, scan


# ───────────────────────────── commands ─────────────────────────────
def _report(rows, lines, res) -> None:
    for l in lines:
        ui.console.print(f"  {l}")
    if rows:
        ui.console.print(ui.results_table(rows))
    else:
        ui.info("No new programs this run.")
    for ch, r in res.items():
        (ui.ok if r == "ok" else ui.fail)(f"notify {ch}: {'sent' if r == 'ok' else r + ' (will retry next run)'}")


def run_scan(ctx, *, dorks=True, platforms=True, budget=None, interactive=False) -> None:
    use_llm = True
    if interactive and dorks and ctx.cfg.get("models") and ctx.db.c.execute("SELECT COUNT(*) FROM queries").fetchone()[0] == 0:
        from . import llmreg  # first dork run classifies many pages: a paid model must be confirmed first
        n = int(ctx.cfg["llm"].get("max_classify_per_cycle", 60))
        use_llm = llmreg.confirm_bulk(ctx.cfg, "classify", n, "First dork run classification", ui.yn)
        if not use_llm:
            ui.info("continuing without LLM classification (heuristics only) for this scan")
    try:
        _report(*scan(ctx.cfg, ctx.db, do_platforms=platforms, do_dorks=dorks, dork_budget=budget, use_llm=use_llm))
    except ScanLocked as e:
        ui.fail(str(e))
        return
    if interactive and dorks:
        _ask_promotions(ctx)


def _ask_promotions(ctx) -> None:
    """ai_auto_promote = ask: in the REPL, offer each newly eligible AI dork once (asked again only when its evidence grows)."""
    from . import promotion
    if str(ctx.cfg["dorks"].get("ai_auto_promote", "ask")).lower() != "ask":
        return
    for e in promotion.unasked(ctx.db, ctx.cfg):
        d = e.evidence
        if ui.yn(f"AI dork #{e.dork_id} is eligible for the default list ({d['verified']} verified programs, precision "
                 f"{d['precision']:.2f}, {d['runs']} runs): {e.text[:70]} - promote it?", False):
            ok, msg = promotion.promote(ctx.db, ctx.cfg, e.dork_id)
            (ui.ok if ok else ui.fail)(msg)
        else:
            promotion.decline(ctx.db, e)


def cmd_scan(ctx, args):
    run_scan(ctx, dorks="nodorks" not in args, interactive=True)


def cmd_watch(ctx, args):
    s = ctx.cfg["schedule"]
    ui.info(f"Watching: platforms every {s['platform_interval_min']} min, dorks every {s['dork_interval_min']} min. "
            "Ctrl+C to stop.")
    last_dork = 0.0
    try:
        while True:
            do_dork = time.time() - last_dork >= s["dork_interval_min"] * 60
            ui.console.rule(datetime.now().strftime("%Y-%m-%d %H:%M"))
            try:
                run_scan(ctx, dorks=do_dork)
                if do_dork:
                    last_dork = time.time()
            except Exception as e:  # noqa: BLE001 — a daemon must survive transient failures
                ui.fail(f"cycle failed: {e}")
            ctx.reload()
            s = ctx.cfg["schedule"]
            time.sleep(s["platform_interval_min"] * 60)
    except KeyboardInterrupt:
        ui.console.print("\n[dim]watch stopped[/dim]")


def cmd_status(ctx, args):
    t = Table(title="Last run per source", header_style="bold")
    for c in ("Source", "Finished (UTC)", "Status", "Found", "New", "Error"):
        t.add_column(c, overflow="fold")
    for r in ctx.db.last_runs():
        st = "[green]ok[/green]" if r["status"] == "ok" else f"[red]{r['status']}[/red]"
        t.add_row(r["source"], r["finished"] or "—", st, str(r["found"]), str(r["new"]), r["error"] or "")
    ui.console.print(t)
    counts = ctx.db.counts()
    ui.info(f"Stored programs: {sum(counts.values())} ({', '.join(f'{k}: {v}' for k, v in counts.items()) or 'none'})")
    from . import search
    from .search import key_id
    any_keys = False
    for pid in search.sequence_order(ctx.cfg):
        pc = ctx.cfg["search"]["providers"].get(pid) or {}
        prov = search.make(ctx.cfg, pid) if search.is_configured(ctx.cfg, pid) else None
        if prov is None:
            continue
        any_keys = True
        if not prov.needs_key:
            ui.info(f"{prov.label}: {pc.get('base_url', '')} - no key, no quota (rate-limited only)")
            continue
        limit = int(pc.get("limit") or prov.default_limit)
        qt = prov.quota_type()
        q = Table(title=f"{prov.label} — {qt} quota (resets {prov.reset_text()})", header_style="bold")
        for c in ("Key", "Used", "Left"):
            q.add_column(c)
        tot_used = 0
        for k in pc["keys"]:
            u = ctx.db.quota_used(key_id(pid, k), prov.period_label())
            tot_used += u
            q.add_row(mask(k), str(u), str(max(0, limit - u)) if qt != "unlimited" else "unlimited")
        ui.console.print(q)
        if qt == "lifetime" and limit * len(pc["keys"]) and (1 - tot_used / (limit * len(pc["keys"]))) * 100 < 15:
            ui.fail(f"{prov.label}: below 15% of the one-time allowance left - it never resets")
    if not any_keys:
        ui.info("No search provider keys configured — self-hosted dork discovery is off (/config).")
    l = ctx.cfg["llm"]
    from . import dates, dorkstore, sequence as _seq
    from . import search as _search
    order = [p for p in _search.configured(ctx.cfg)]
    if order:
        pr = _seq.progress(ctx.db)
        ui.info(f"Search sequence: {' → '.join(order)} · mode {ctx.cfg.get('search_mode', 'failover')}"
                + (f" · queue batch #{pr['batch']}: {pr['done']}/{pr['total']} steps" if pr["batch"] else "")
                + (f" · STOPPED: {pr['stopped']}" if pr["stopped"] else "") + "  (/sequence show, /providers)")
    if ctx.cfg.get("models"):
        from . import llmreg
        st = llmreg.budget_state(ctx.db, ctx.cfg)
        ui.info("Models: " + "; ".join(f"{m['id']} {llmreg.describe(m)} [{','.join(m['roles'])}]" for m in ctx.cfg["models"]
                                        if m.get("enabled")) + f" · spend today ${st['day']:.4f}/${st['day_limit']:.2f}  (/llm status)")
    elif not l["enabled"]:
        ui.info("LLM: disabled (heuristics only)")
    elif l.get("backend") == "openai":
        ui.info(f"LLM: API {l['model']} @ {l.get('base_url')}")
    else:
        ui.info(f"LLM: local {l['model']} @ {l['host']}")
    sr = {w: config.search_recency_days(ctx.cfg, w) for w in ("first", "later", "sweep")}
    st = lambda d: "any" if d is None else dates.window_text(d)  # noqa: E731
    ui.info(f"Search recency (sent to providers): first run {st(sr['first'])}, later runs {st(sr['later'])}, sweep {st(sr['sweep'])} "
            f"({int(ctx.cfg['dork_search_recency'].get('sweep_share', 0) * 100)}% of the batch) · pages per dork "
            f"{config.pages_per_dork(ctx.cfg)}  — the alert window is separate:")
    ui.info(f"Alert window: {dates.window_text(config.recency_days(ctx.cfg))} (applied after discovery) · platform poll every "
            f"{ctx.cfg['schedule']['platform_interval_min']} min · dork batch every {ctx.cfg['schedule']['dork_interval_min']} min")
    m = memcmds.memory_stats(ctx.db, ctx.cfg)
    ui.info(f"Memory: {m['programs']} programs ({m['baseline']} baseline, {m['delivered']} delivered, "
            f"{m['pending']} waiting to alert), {m['seen_urls']} URLs seen, {m['queries']} queries remembered, "
            f"{m['chat_messages']} chat messages")
    from . import alertcmds
    a = alertcmds.status_data(ctx)
    ui.info(f"Alerts: channels {', '.join(a['channels']) or 'NONE'} · pending {a['pending_new']} new / "
            f"{a['pending_updated']} updated · last successful send "
            + (dates.to_local(a['last_ok']['ts']) if a['last_ok'] else "never")
            + (f" · LAST ERROR {a['last_err']['error']}" if a['last_err'] else "") + "  (details: /alerts status)")
    for why, n in a["reasons"].items():
        ui.info(f"  pending because: {n} x {why}")
    from . import reclass, retry, validation
    vc = validation.counts(ctx.db)
    ui.info(f"Validation: {'on' if ctx.cfg['validate'].get('enabled', True) else 'OFF'} · verified {vc['verified']}, needs manual "
            f"check {vc['needs_check']}, rejected {vc['rejected']}, weak {vc['weak']}, not validated {vc['not_validated']}  "
            "(/validate status)")
    ui.info(retry.status(ctx.db, ctx.cfg))
    rp = reclass.progress(ctx.db)
    if rp["state"] != "idle":
        ui.info(f"Reclassify (background): {rp['state']} - {rp['done']}/{rp['total']} judged, {rp['rejected']} would be rejected")
    _network_table(ctx, "--all-hosts" in args)
    ds = dorkstore.stats(ctx.db)["groups"]
    if ds:
        ui.info("Dorks: " + ", ".join(f"{g}: {d['enabled'] or 0}/{d['n']} on, {d['found'] or 0} found" for g, d in ds.items())
                + f" · mode {ctx.cfg['dorks']['source']} · AI dorks {'on' if ctx.cfg['features']['ai_dorks'] else 'off'}")


API_HOSTS = {"google.serper.dev": "Serper", "exa.ai": "Exa", "tavily.com": "Tavily", "search.brave.com": "Brave", "googleapis.com": "Google CSE",
             "www.googleapis.com": "Google CSE", "telegram.org": "Telegram", "wayback": "Wayback Machine",
             "archive.org": "Wayback Machine", "localhost": "Ollama (localhost)", "smtp.gmail.com": "Gmail SMTP"}


def _network_table(ctx, all_hosts: bool) -> None:
    ns = ctx.db.c.execute("SELECT * FROM net_stats ORDER BY name").fetchall()
    if not ns:
        return
    nt = Table(title="Network health (API providers, Telegram, Wayback)" + (" - all hosts" if all_hosts else ""),
               header_style="bold")
    for c in ("Service", "OK", "Retries", "Failures", "Last error"):
        nt.add_column(c, overflow="fold")
    other = [0, 0, 0, 0]
    for r in ns:
        if r["name"] in API_HOSTS or all_hosts:
            nt.add_row(API_HOSTS.get(r["name"], r["name"]), str(r["ok"]), str(r["retries"]), str(r["failures"]),
                       r["last_error"] or "")
        else:
            other = [other[0] + r["ok"], other[1] + r["retries"], other[2] + r["failures"], other[3] + 1]
    if other[3] and not all_hosts:
        nt.add_row(f"[dim]{other[3]} other hosts (pages fetched for classification) - /status --all-hosts[/dim]",
                   str(other[0]), str(other[1]), str(other[2]), "")
    ui.console.print(nt)


def cmd_test(ctx, args):
    while True:
        with ui.console.status("Running live checks…"):
            res = checks.all_checks(ctx.cfg, enabled_platforms(ctx.cfg))
        ui.console.print(ui.status_table(res, "Connection tests"))
        failed = [r for r in res if not r[1]]
        if not failed:
            ui.ok("All checks passed.")
            return
        ui.fail(f"{len(failed)} check(s) failed.")
        c = ui.choose("(r)etest, (c)onfigure (/config), (m)odel (/model), (q)uit", ["r", "c", "m", "q"], "q")
        if c == "q":
            return
        if c == "c":
            wizard.config_menu(ctx.cfg, ctx.save, ctx.db)
        elif c == "m":
            wizard.model_menu(ctx.cfg)
            ctx.save(ctx.cfg)


def cmd_config(ctx, args):
    wizard.config_menu(ctx.cfg, ctx.save, ctx.db)


def cmd_filters(ctx, args):
    wizard.filters_menu(ctx.cfg)
    ctx.save(ctx.cfg)
    ui.console.print(ui.config_summary(ctx.cfg))


def _programs_menu() -> list[str]:
    ui.console.print("  1) last 24 hours\n  2) last 7 days\n  3) custom date range")
    c = ui.choose("Show programs from", ["1", "2", "3"], "2")
    if c == "1":
        return ["--since", "24h"]
    if c == "2":
        return ["--since", "7d"]
    return ["--from", ui.ask("From (YYYY-MM-DD or DD/MM/YYYY)"), "--to", ui.ask("To (blank = now)", " ").strip() or ""]


def cmd_programs(ctx, args):
    if args and args[0] in ("mark", "revalidate"):
        from . import valcmds
        return (valcmds.mark if args[0] == "mark" else valcmds.revalidate)(ctx, args[1:])
    try:
        if not args:
            args = _programs_menu()
            if args[-1] == "":
                args = args[:-2]
        o = listing.parse_args(args)
        if not listing.has_filters(o):  # plain `/programs [N]` = most recently stored, still with Kind/evidence
            n = o["limit"] or 25
            from . import dates
            rows = listing.decorate(ctx.db, ctx.cfg, ctx.db.recent(n), config.recency_days(ctx.cfg))
            ui.console.print(listing.table(rows, f"Last {n} stored programs (no filter applied — use --since 7d etc.)",
                                           wide=o["wide"], compact=o["compact"]))
            return
        rows, excl, desc = listing.run(ctx.db, o, cfg=ctx.cfg)
    except ValueError as e:
        ui.fail(str(e))
        return
    ui.console.print(listing.table(rows, listing.title(o, len(rows)), wide=o["wide"], compact=o["compact"]))
    if ui.console.width < 130 and not (o["wide"] or o["compact"]):
        ui.info("Narrow terminal: Kind and date evidence are kept, other columns hidden. Use --wide for all columns "
                "or --compact for one line per program.")
    if o["by"] == "launched":
        ui.info(f"{excl} program(s) excluded because their launch date is unknown (most sources do not publish one).")
    if not o["include_baseline"] and not o["kind"]:
        ui.info("Baseline entries (stored at first sight, not launched in the window) are hidden: --include-baseline. "
                "Old ones: --include-old.")


def cmd_recency(ctx, args):
    """/recency [<N|24h|7d|30d|1y|any>]  = the ALERT window.   /recency search [first X] [later Y] [sweep Z] [share 0.1] [pages N]
    = what the PROVIDERS' date parameter gets (a separate setting)."""
    from . import dates
    cur = config.recency_days(ctx.cfg)
    sr = ctx.cfg["dork_search_recency"]
    if args and args[0] == "search":
        rest = args[1:]
        if len(rest) % 2:
            ui.fail("usage: /recency search [first any|day|week|month|year|Nd] [later ...] [sweep ...] [share 0-0.3] [pages N]")
            return
        try:
            for k, v in zip(rest[::2], rest[1::2]):
                if k in ("first", "later", "sweep"):
                    dates.parse_window({"week": "7d", "month": "31d", "year": "365d", "day": "1d"}.get(v.lower(), v))
                    sr[k] = v.lower()
                elif k == "share":
                    sr["sweep_share"] = min(0.3, max(0.0, float(v)))
                elif k == "pages":
                    ctx.cfg["pages_per_dork"] = max(1, int(v))
                else:
                    raise ValueError(k)
        except ValueError:
            ui.fail("usage: /recency search [first any|day|week|month|year|Nd] [later ...] [sweep ...] [share 0-0.3] [pages N]")
            return
        if rest:
            ctx.save(ctx.cfg)
    if not args or args[0] == "search":
        ui.info(f"Search recency (what providers' date filters get): first run {sr['first']}, later runs {sr['later']}, "
                f"sweep {sr['sweep']} ({int(sr.get('sweep_share', 0) * 100)}% of a batch), pages per dork {config.pages_per_dork(ctx.cfg)}")
        ui.info(f"Alert window: {dates.window_text(cur)} - applied AFTER discovery (programs older than this never alert). "
                "Change with /recency <N|24h|7d|30d|1y|any>; search recency with /recency search ...")
        return
    try:
        d = dates.parse_window(args[0])
    except ValueError as e:
        ui.fail(str(e))
        return
    ctx.cfg["recency_days"] = d
    ctx.save(ctx.cfg)
    ui.ok(f"Alert window set to {dates.window_text(d)} (this does NOT change what the search providers are asked for)")


def cmd_export(ctx, args):
    path, rest = "programs.csv", list(args)
    if rest and not rest[0].startswith("--"):
        path, rest = rest[0], rest[1:]
    try:
        o = listing.parse_args(rest)
        if listing.has_filters(o):
            rows, excl, desc = listing.run(ctx.db, o, default_limit=10**6, cfg=ctx.cfg)
        else:
            o["kind"] = "all"
            rows, excl, desc = listing.run(ctx.db, o, default_limit=10**6, cfg=ctx.cfg)
            desc = "all"
    except ValueError as e:
        ui.fail(str(e))
        return
    cols = ("source", "name", "url", "kind", "reward_max", "currency", "country", "first_seen", "launched_at",
            "launched_at_source", "baseline", "delivered", "delivered_via", "_kind", "_evidence", "_sent",
            "_validity", "_vkind", "_vstatus", "_vreward", "_vscope", "_vconf")
    names = {"_validity": "validity", "_vkind": "program_kind", "_vstatus": "program_status", "_vreward": "reward_text",
             "_vscope": "has_scope", "_vconf": "validation_confidence"}
    for r in rows:
        r["_sent"] = listing.sent_text(r["_sent"])
    if path.endswith(".json"):
        with open(path, "w") as f:
            json.dump([{names.get(k, k): r[k] for k in cols} for r in rows], f, indent=2)
    else:
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([names.get(k, k) for k in cols])
            for r in rows:
                w.writerow([r[k] for k in cols])
    ui.ok(f"exported {len(rows)} programs ({desc}) to {path}")
    if o["by"] == "launched":
        ui.info(f"{excl} program(s) excluded: launch date unknown")


def cmd_chat(ctx, args):
    from rich.markdown import Markdown

    from .chat import Chat
    from .llm import from_config
    if not ctx.cfg["features"]["chat"]:
        ui.fail("chat is switched off (set features.chat to true in the config)")
        return
    llm = from_config(ctx.cfg, ctx.db)
    if not llm:
        ui.fail("no working LLM configured — run /model first")
        return
    chat = Chat(ctx.cfg, ctx.db, llm, confirm=lambda q: ui.yn(q, False), show=ui.console.print, new="--new" in args)
    n = ctx.db.c.execute("SELECT COUNT(*) FROM chat_messages WHERE session_id=? AND role IN ('user','assistant')",
                         (chat.session,)).fetchone()[0]
    ui.info(f"Chat with {llm.describe()} — {'resuming a session with ' + str(n) + ' messages' if n else 'new session'}. "
            "/exit or /back to leave. It can read your database and run limited searches; it cannot change settings.")
    while True:
        try:
            text = ui.ask("you").strip()
        except (EOFError, KeyboardInterrupt):
            ui.console.print()
            return
        if text in ("/exit", "/back", "/quit"):
            return
        if not text:
            continue
        try:
            ui.console.print("[dim]thinking…[/dim]")
            t = chat.turn(text)
        except KeyboardInterrupt:
            ui.console.print("[dim]cancelled[/dim]")
            continue
        ui.console.print(Markdown(t.answer))


def cmd_logs(ctx, args):
    from .paths import log_path
    p = log_path()
    lines = p.read_text().splitlines()[-30:] if p.exists() else []
    ui.console.print("\n".join(lines) or "[dim]log is empty[/dim]", markup=False)


HELP = [
    ("/scan", "run one discovery cycle now (add 'nodorks' to skip dork search)"),
    ("/watch", "run continuously on the configured schedule (Ctrl+C to stop)"),
    ("/config", "alert channels, search keys, recency, dorks, LLM, filters, schedule"),
    ("/model [sub]", "models: list | add (wizard: local / API / Claude API key / Claude CLI) | info (Claude CLI warning, status, limits) | remove <id> | test [id] | roles <id> <roles...> | order | enable|disable <id>"),
    ("/llm [sub]", "status (calls, tokens, spend per model/role, budget, Claude-CLI caps) | bulk on|off | limits [hour N] [day N] [interval S] [batch N] | prices <id> <in> <out>|free"),
    ("/filters", "adjust platforms / countries / categories / minimum reward"),
    ("/status [--all-hosts]", "last run per source, memory, alerts + pending reasons, dorks, quota, network health (API hosts; --all-hosts = every host)"),
    ("/test", "re-run every live connection test (keys, Telegram, email, LLM, sources)"),
    ("/programs [N|filters]", "list programs with Kind + date evidence + validity + delivery; no args opens a menu. "
                              "--since 7d | --from/--to | --by seen|launched | --kind new|updated|old|all | "
                              "--include-baseline | --include-old | --category program|securitytxt | "
                              "--validity verified|needs_check|weak|not_validated|none | --wide | --compact"),
    ("/programs mark <id|url> valid|invalid|weak [note]", "your label overrides the model, feeds the dork's statistics and is "
                                                          "kept as a regression/few-shot example"),
    ("/programs revalidate <id|url|--all-weak|--all-manual>", "re-run the LLM page validation, ignoring the cache"),
    ("/validate <sub>", "status (verified / needs check / rejected / not validated, model, calls, cap) | on | off | "
                        "test <url> (whole pipeline on one URL, stores nothing)"),
    ("/export [file] [filters]", "export programs to .csv/.json (same filters as /programs)"),
    ("/logs", "tail the log file"),
    ("/help", "this list"),
    ("/quit", "exit (also /exit, /q)"),
    ("/recency [N|24h|7d|30d|1y|any]", "show or set the alert window (default 7 days)"),
    ("/dorks <sub>", "import|list|enable|disable|priority|stats|test|prune|mode|reset-default|generate; test <dork> [--recency any|week|month|Nd] [--pages N] [--provider id] [--dry-run] shows the exact request + kept/dropped tables"),
    ("/dorks <promotion>", "candidates (AI dorks vs every promotion condition) | promote <id|all-eligible> | demote <id> | "
                           "export-default [--include-promoted] [--to <path>] (diff + confirmation) | "
                           "list --group default|ai|custom --origin shipped|ai_promoted | reset-default [--include-promoted]"),
    ("/memory <sub>", "stats | export <path> | forget program|query|dork|all | reclassify [status|review|apply|cancel|--now] (background, capped, never alerts)"),
    ("/history [N]", "recent queries and what they found"),
    ("/chat [--new]", "talk to the LLM about your data (read-only DB access + limited searches)"),
    ("/alerts <sub>", "status | pending | resend [N|all|--since 7d] | test (SAMPLE alerts) | baseline-legacy [--dry-run] | release-pending [N]"),
    ("/why <id|url|name>", "explain why a program was (or was not) alerted"),
    ("/background <sub>", "status | pause | resume - the pending-retry and reclassify workers (they always yield to foreground commands)"),
    ("/sequence <sub>", "show | move <provider> <pos> | enable|disable <provider> | mode failover|cascade|sweep | test | reset-cursor"),
    ("/providers [sub]", "show (quota, daily caps, sources) | status (health, retries, breaker) | set <provider> allowance|type <v> | daily <provider> [key] <n>"),
    ("/searxng <sub>", "setup (prints docker-compose.yml + settings.yml, never runs docker) | probe [base_url]"),
    ("/version", "code version, git commit, DB schema, config version, python and install path"),
]
COMMANDS = {"/scan": cmd_scan, "/watch": cmd_watch, "/config": cmd_config, "/model": modelcmds.cmd_model, "/llm": modelcmds.cmd_llm,
            "/filters": cmd_filters, "/status": cmd_status, "/test": cmd_test, "/programs": cmd_programs,
            "/recency": cmd_recency, "/chat": cmd_chat, "/dorks": memcmds.cmd_dorks, "/memory": memcmds.cmd_memory,
            "/history": memcmds.cmd_history, "/export": cmd_export, "/logs": cmd_logs,
            "/sequence": seqcmds.cmd_sequence, "/providers": seqcmds.cmd_providers, "/searxng": seqcmds.cmd_searxng,
            "/alerts": alertcmds.cmd_alerts, "/background": seqcmds.cmd_background, "/why": alertcmds.cmd_why, "/version": alertcmds.cmd_version,
            "/validate": valcmds.cmd_validate}


class QuitRepl(Exception):
    pass


def cmd_quit(ctx, args):
    raise QuitRepl


def cmd_help(ctx=None, args=None):
    t = Table(show_header=False, box=None)
    t.add_column(no_wrap=True)
    t.add_column(overflow="fold")
    for c, d in HELP:
        t.add_row(f"[bold cyan]{c}[/bold cyan]", d)
    ui.console.print(t)


COMMANDS["/help"] = cmd_help
COMMANDS["/quit"] = cmd_quit


# ───────────────────────────── context & REPL ─────────────────────────────
class Ctx:
    def __init__(self):
        self.cfg = config.load()
        self.db = DB()

    def save(self, cfg=None):
        config.save(cfg or self.cfg)

    def reload(self):
        self.cfg = config.load()


def repl(ctx: Ctx) -> None:
    try:
        if not sys.stdin.isatty():
            raise OSError
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter
        sess = PromptSession(completer=WordCompleter([c for c, _ in HELP], sentence=True))
        read = lambda: sess.prompt("qurihunter › ")  # noqa: E731
    except Exception:  # noqa: BLE001 — no TTY etc.
        read = lambda: input("qurihunter › ")  # noqa: E731
    while True:
        try:
            memcmds.report_if_finished(ctx.db)
            line = read().strip()
        except (EOFError, KeyboardInterrupt):
            ui.console.print()
            return
        if not line:
            continue
        cmd, *args = line.split()
        stale = alertcmds.stale_code()
        if stale:
            ui.fail(stale)
        target = cmd
        if cmd not in COMMANDS:
            target, hints = alertcmds.suggest(cmd, COMMANDS)
            if target is None:
                ui.fail(f"unknown command {cmd}" + (f" — did you mean {' or '.join(hints)}?" if hints else "")
                        + " (try /help)")
                continue
            ui.console.print(f"[dim]({cmd} → {target})[/dim]")
        try:
            if target in ("/watch", "/chat"):  # long-running: they are not "short foreground commands"
                COMMANDS[target](ctx, args)
            else:
                with background.foreground():  # background workers yield to the command that is running
                    COMMANDS[target](ctx, args)
        except QuitRepl:
            return
        except dblock.DatabaseBusy as e:
            ui.fail(f"{target}: {e}. It was retried for {int(dblock.LOCK_WAIT_S)} s. Nothing was lost - try again in a moment "
                    "(/background status shows what is running; /background pause stops the workers).")
        except KeyboardInterrupt:
            ui.console.print("\n[dim]cancelled[/dim]")
        except Exception as e:  # noqa: BLE001
            from .logs import log
            log.exception("command %s failed", target)
            ui.fail(f"{target} failed: {e} (details in /logs)")
        dblock.flush()  # never leave a write transaction (= the write lock) open while idle at the prompt
        ctx.reload()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="qurihunter", description="Bug bounty / VDP program discovery agent")
    ap.add_argument("command", nargs="?", choices=["scan", "watch", "status", "test", "setup"],
                    help="omit for the interactive shell")
    ap.add_argument("--no-dorks", action="store_true", help="scan: skip Google dork discovery")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--force", action="store_true", help="start even if another instance holds the lock")
    a = ap.parse_args(argv)
    setup_logging(a.verbose)
    try:
        ctx = Ctx()
    except RuntimeError as e:
        ui.fail(str(e))
        return 1
    try:
        ui.banner(__version__)
        for w in alertcmds.self_check(ctx):
            ui.fail("⚠ " + w)
        interactive = a.command in (None, "watch", "setup")
        if interactive:
            ok, msg = instance.acquire(a.force)
            if not ok:
                ui.fail(msg)
                return 1
        for w in instance.warnings():
            ui.fail("⚠ " + w)
        alertcmds.stamp(ctx)
        worker = None
        if interactive and ctx.cfg.get("background_workers", True):
            from .llm import from_config
            from . import reclass, validation
            worker = retry.Worker(extra=[reclass.job(from_config), validation.job(from_config)])
            worker.start()
        if not ctx.cfg["setup_done"] or a.command == "setup":
            wizard.first_run(ctx.cfg, ctx.save)
            ui.info("Taking the initial baseline of all known programs (no alerts for these)…")
            run_scan(ctx, dorks=False)
        if a.command == "scan":
            run_scan(ctx, dorks=not a.no_dorks)
        elif a.command == "watch":
            cmd_watch(ctx, [])
        elif a.command == "status":
            cmd_status(ctx, [])
        elif a.command == "test":
            cmd_test(ctx, [])
        elif a.command != "setup":
            repl(ctx)
        elif a.command == "setup":
            repl(ctx)
    except KeyboardInterrupt:
        ui.console.print("\n[dim]bye[/dim]")
    finally:
        instance.release()
    return 0


if __name__ == "__main__":
    sys.exit(main())
