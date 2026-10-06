"""/dorks, /memory and /history command implementations."""
from __future__ import annotations

import json
import sqlite3

from rich.table import Table

from . import config, dates, dorkstore, ui
from .migrations import backup, MIGRATIONS
from .search import build_pool, configured, make


def _short(t: str, n: int = 70) -> str:
    return t if len(t) <= n else t[: n - 1] + "…"


# ── /dorks ──────────────────────────────────────────────────────────────────────
def cmd_dorks(ctx, args):
    sub = args[0] if args else "stats"
    rest = args[1:]
    fn = {"list": _list, "import": _import, "enable": _toggle(1), "disable": _toggle(0), "priority": _priority,
          "stats": _stats, "test": _test, "prune": _prune, "mode": _mode, "reset-default": _reset,
          "generate": _generate, "ai": _ai, "candidates": _candidates, "promote": _promote, "demote": _demote,
          "export-default": _export_default}.get(sub)
    if not fn:
        ui.fail("usage: /dorks list|import|enable|disable|priority|stats|test|prune|mode|reset-default|generate|ai|"
                "candidates|promote|demote|export-default")
        return
    if sub != "test":  # a test only reads: it must not need the write lock (the default list is imported by other commands)
        dorkstore.ensure_default(ctx.db)
    fn(ctx, rest)


def _list(ctx, a):
    disabled = "--disabled" in a
    grp = None
    if "--group" in a:
        try:
            grp = a[a.index("--group") + 1]
        except IndexError:
            ui.fail("--group needs default|custom|ai")
            return
        if grp not in ("default", "custom", "ai"):
            ui.fail("--group must be default, custom or ai")
            return
    origin = None
    if "--origin" in a:
        try:
            origin = a[a.index("--origin") + 1]
        except IndexError:
            origin = ""
        if origin not in ("shipped", "ai_promoted", "ai", "custom"):
            ui.fail("--origin must be shipped, ai_promoted, ai or custom")
            return
    q, args = "SELECT * FROM dorks WHERE enabled=?", [0 if disabled else 1]
    if grp:
        q += " AND grp=?"; args.append(grp)
    if origin:
        q += " AND COALESCE(origin, 'shipped')=?"; args.append(origin)
    rows = ctx.db.c.execute(q + " ORDER BY priority DESC, id", args).fetchall()
    t = Table(title=f"Dorks ({'disabled' if disabled else 'enabled'}{', ' + grp if grp else ''}"
                    f"{', origin ' + origin if origin else ''}) — {len(rows)}", header_style="bold")
    for c in ("ID", "Group", "Origin", "Pri", "Runs", "Hits", "Found", "Last run", "Dork"):
        t.add_column(c, overflow="fold")
    for r in rows[:200]:
        t.add_row(str(r["id"]), r["grp"], r["origin"] or "shipped", str(r["priority"]), str(r["run_count"]), str(r["hits_total"]),
                  str(r["new_programs_found"]), dates.to_local_day(r["last_run_at"]),
                  _short(r["text"]) + (f"  [dim]({r['auto_disabled_reason']})[/dim]" if r["auto_disabled_reason"] else ""))
    ui.console.print(t)
    if len(rows) > 200:
        ui.info(f"showing 200 of {len(rows)}")


def _import(ctx, a):
    if not a:
        ui.fail("usage: /dorks import <path> [--group custom|default]")
        return
    from pathlib import Path
    path = Path(a[0]).expanduser()
    if not path.exists():
        ui.fail(f"file not found: {path}")
        return
    grp = a[a.index("--group") + 1] if "--group" in a and a.index("--group") + 1 < len(a) else "custom"
    entries = dorkstore.parse_file(path)
    prov = None
    cfg_ids = configured(ctx.cfg)
    if cfg_ids:
        prov = make(ctx.cfg, cfg_ids[0])
    rep = dorkstore.analyse(entries, prov)
    ui.info(f"{path.name}: {rep['count']} dorks, {rep['exact_duplicates']} exact duplicates, "
            f"{rep['with_dates']} with hardcoded dates"
            + (f", {rep['provider_merges']} would merge after {prov.id} flattening" if prov else ""))
    r = dorkstore.import_file(ctx.db, path, grp)
    ui.ok(f"imported into '{grp}': {r.text()}")
    if rep["with_dates"] and grp != "default":
        ui.info("Dorks with after:/before: dates were kept as written and are honoured/translated per provider.")


def _ids(ctx, tok: str) -> list[int] | None:
    if tok == "all":
        return [r[0] for r in ctx.db.c.execute("SELECT id FROM dorks")]
    ids = [int(x) for x in tok.split(",") if x.strip().isdigit()]
    return ids or None


def _toggle(on: int):
    def f(ctx, a):
        ids = _ids(ctx, a[0]) if a else None
        if not ids:
            ui.fail(f"usage: /dorks {'enable' if on else 'disable'} <id[,id…]|all>")
            return
        ctx.db.c.executemany("UPDATE dorks SET enabled=?, auto_disabled_reason=NULL WHERE id=?", [(on, i) for i in ids])
        ctx.db.commit()
        ui.ok(f"{'enabled' if on else 'disabled'} {len(ids)} dork(s)")
    return f


def _priority(ctx, a):
    if len(a) != 2 or not a[0].isdigit() or not a[1].lstrip("-").isdigit():
        ui.fail("usage: /dorks priority <id> <n>   (higher runs first)")
        return
    n = ctx.db.c.execute("UPDATE dorks SET priority=? WHERE id=?", (int(a[1]), int(a[0]))).rowcount
    ctx.db.commit()
    (ui.ok if n else ui.fail)(f"priority of dork {a[0]} set to {a[1]}" if n else f"no dork with id {a[0]}")


def _stats(ctx, a):
    s = dorkstore.stats(ctx.db)
    t = Table(title="Dorks by group", header_style="bold")
    for c in ("Group", "Total", "Enabled", "Runs", "Hits", "New programs"):
        t.add_column(c)
    for g, d in s["groups"].items():
        t.add_row(g, str(d["n"]), str(d["enabled"] or 0), str(d["runs"] or 0), str(d["hits"] or 0), str(d["found"] or 0))
    ui.console.print(t)
    ui.info(f"never run: {s['never_run']} · auto-disabled: {s['auto_disabled']} · mode: {ctx.cfg['dorks']['source']} · "
            f"AI dorks: {'on' if ctx.cfg['features']['ai_dorks'] else 'off'}")
    if s["top"]:
        tt = Table(title="Most productive dorks", header_style="bold")
        for c in ("ID", "Group", "Found", "Runs", "Dork"):
            tt.add_column(c, overflow="fold")
        for r in s["top"]:
            tt.add_row(str(r["id"]), r["grp"], str(r["new_programs_found"]), str(r["run_count"]), _short(r["text"]))
        ui.console.print(tt)
    _quality_table(ctx)
    _capabilities(ctx)
    ai = ctx.db.c.execute("SELECT * FROM dorks WHERE grp='ai' ORDER BY new_programs_found DESC, id DESC LIMIT 10").fetchall()
    if ai:
        tt = Table(title="AI-generated dorks (latest)", header_style="bold")
        for c in ("ID", "On", "Found", "Runs", "Parent", "Dork", "Why"):
            tt.add_column(c, overflow="fold")
        for r in ai:
            tt.add_row(str(r["id"]), "yes" if r["enabled"] else f"no ({r['auto_disabled_reason'] or 'manual'})",
                       str(r["new_programs_found"]), str(r["run_count"]), str(r["parent_dork_id"] or "-"),
                       _short(r["text"], 50), _short(r["rationale"] or "", 50))
        ui.console.print(tt)


def _quality_table(ctx, limit: int = 25) -> None:
    """Per-dork quality: group, origin, runs, kept results, verified-valid new programs, precision, last run."""
    from . import promotion
    rows = ctx.db.c.execute("SELECT * FROM dorks WHERE run_count>0").fetchall()
    if not rows:
        return
    q = [(r, promotion.quality(ctx.db, r)) for r in rows]
    q.sort(key=lambda x: (-x[1]["verified"], -x[1]["precision"], -x[1]["runs"]))
    t = Table(title=f"Dork quality (top {min(limit, len(q))} of {len(q)} that ran; precision = verified-valid / kept)",
              header_style="bold")
    for c in ("ID", "Group", "Origin", "Runs", "Kept", "Verified-valid", "Precision", "Last run", "Dork"):
        t.add_column(c, overflow="fold")
    for r, d in q[:limit]:
        t.add_row(str(r["id"]), r["grp"], r["origin"] or "shipped", str(d["runs"]), str(d["kept"]), str(d["verified"]),
                  f"{d['precision']:.2f}", dates.to_local_day(r["last_run_at"]), _short(r["text"], 55))
    ui.console.print(t)


def capability_table(cfg) -> Table:
    from . import search
    t = Table(title="Search provider capabilities", header_style="bold")
    for c in ("Provider", "TLD filter (site:.cc)", "site:", "inurl:", "Date filter", "Results/query", "Configured"):
        t.add_column(c)
    have = set(search.configured(cfg))
    for pid, cls in search.PROVIDERS.items():
        cap = cls({}).capabilities()
        t.add_row(cls.label, cap["supports_tld_filter"], cap["supports_site"], cap["supports_inurl"],
                  cap["supports_date_filter"], str(cap["results_per_query"]), "[green]yes[/green]" if pid in have else "no")
    return t


def _capabilities(ctx):
    """Which dorks are rewritten / parked / merged for the ACTIVE provider (the first configured one)."""
    from . import search
    ui.console.print(capability_table(ctx.cfg))
    cfgd = search.configured(ctx.cfg)
    if not cfgd:
        ui.info("No search provider configured: nothing runs. Add a key with /config → 2.")
        return
    prov = search.make(ctx.cfg, cfgd[0])
    rows = dorkstore.candidates(ctx.db, ctx.cfg)
    ex = dorkstore.expressibility(rows, prov)
    _, merged = dorkstore.merge_similar([(r["id"], r["text"], r["priority"]) for r in rows if r["id"] not in
                                         {p[0]["id"] for p in ex["parked"]}], prov)
    ui.info(f"Active provider {prov.label}: {len(ex['ok'])} dorks run as written, {len(ex['rewritten'])} rewritten to "
            f"natural language, {len(ex['parked'])} parked (provider cannot express them; no quota used, they run "
            f"automatically once a capable provider such as Brave or Google is added), {len(merged)} merged as near-duplicates.")
    if ex["rewritten"] or ex["parked"]:
        t = Table(title="Dorks the active provider cannot run verbatim", header_style="bold")
        for c in ("Status", "ID", "Dork", "Sent to provider / reason"):
            t.add_column(c, overflow="fold")
        for r, q in ex["rewritten"][:8]:
            t.add_row("rewritten", str(r["id"]), _short(r["text"], 50), _short(q, 70))
        for r, why in ex["parked"][:8]:
            t.add_row("[yellow]parked[/yellow]", str(r["id"]), _short(r["text"], 50), _short(why, 70))
        ui.console.print(t)


TEST_USAGE = ("usage: /dorks test <dork> [--recency any|day|week|month|year|Nd] [--pages N] [--provider <id>] [--dry-run]\n"
              "  --dry-run shows the provider-translated request without sending it (no quota); the ALERT window is never used "
              "as the search filter")
_TIME_KEYS = ("tbs", "freshness", "time_range", "dateRestrict", "startPublishedDate", "start_date", "endPublishedDate", "end_date")
_PAGE_KEYS = ("page", "start", "offset", "pageno")
_GEO_KEYS = ("gl", "hl", "country", "language", "location", "lr", "search_lang")
_QUERY_KEYS = ("q", "query")


def describe_request(req: dict) -> list[tuple[str, str]]:
    """Human summary of a (sanitised) provider request: query, time parameter, page, country/language, the rest."""
    body = {**(req.get("params") or {}), **(req.get("json") or {})}
    rows = [("endpoint", f"{req.get('method', '')} {req.get('url', '')}")]
    pick = lambda keys: [(k, body[k]) for k in keys if k in body]  # noqa: E731
    rows.append(("query string", " | ".join(str(v) for _, v in pick(_QUERY_KEYS)) or "(none)"))
    t = pick(_TIME_KEYS)
    rows.append(("time parameter", ", ".join(f"{k}={v}" for k, v in t) if t else "none (no date filter: any date)"))
    pg = pick(_PAGE_KEYS)
    rows.append(("page", ", ".join(f"{k}={v}" for k, v in pg) if pg else "first page"))
    g = pick(_GEO_KEYS)
    rows.append(("country / language", ", ".join(f"{k}={v}" for k, v in g) if g else "none"))
    used = set(_QUERY_KEYS + _TIME_KEYS + _PAGE_KEYS + _GEO_KEYS)
    rest = [(k, v) for k, v in body.items() if k not in used and k != "api_key"]
    if rest:
        rows.append(("other", ", ".join(f"{k}={v}" for k, v in rest)))
    return rows


def _request_table(title: str, req: dict) -> Table:
    t = Table(title=title, show_header=False, header_style="bold")
    t.add_column(style="bold cyan")
    t.add_column(overflow="fold")
    for k, v in describe_request(req):
        t.add_row(k, str(v))
    return t


def _test(ctx, a):
    from . import tlds
    unknown_ok = False
    pd0 = None
    try:
        from qurihunter.search.dorkparse import parse as _parse
        toks = [t for t in a if not t.startswith("--")]
        pd0 = _parse(" ".join(toks))
    except Exception:  # noqa: BLE001
        pass
    if pd0 is not None and pd0.tld and not tlds.is_known(pd0.tld):
        with tlds.allow_unknown():  # decided inside _test_run (warn first); the flag only lets the chain be built
            return _test_run(ctx, a, True)
    return _test_run(ctx, a, False)


def _test_run(ctx, a, unknown_tld: bool):
    from . import relevance, tlds
    from .config import pages_per_dork, search_recency_days
    toks, opts, i = [], {"recency": None, "pages": None, "provider": None, "dry": False}, 0
    while i < len(a):
        t = a[i]
        if t == "--dry-run":
            opts["dry"] = True
        elif t in ("--recency", "--pages", "--provider") and i + 1 < len(a):
            opts[t[2:]] = a[i + 1]
            i += 1
        elif t.startswith("--"):
            ui.fail(f"unknown option {t}\n{TEST_USAGE}")
            return
        else:
            toks.append(t)
        i += 1
    text = " ".join(toks).strip()
    if not text:
        ui.fail(TEST_USAGE)
        return
    cfg = ctx.cfg
    try:
        spec = opts["recency"]
        days = search_recency_days(cfg, "first") if spec is None else dates.parse_window(
            {"week": "7d", "month": "31d", "year": "365d", "day": "1d"}.get(spec.lower(), spec))
        pages = int(opts["pages"]) if opts["pages"] else pages_per_dork(cfg)
    except ValueError:
        ui.fail("--recency must be any, day, week, month, year or a number of days (e.g. 14d); --pages a whole number")
        return
    from qurihunter.search.dorkparse import parse
    pd = parse(text)
    if pd.tld and unknown_tld:  # stop BEFORE spending quota
        sug = tlds.suggest(pd.tld)
        ui.fail(f".{pd.tld} is not a real top-level domain" + (f" (did you mean {', '.join('.' + x for x in sug)}?)" if sug else "")
                + " - this looks like a typo.")
        if opts["dry"]:
            ui.info("dry run continues (nothing is spent)")
        elif not ui.yn("Run it anyway and spend 1 query?", False):
            ui.info("cancelled - no quota was spent")
            return
    from . import search as _search
    pool = build_pool(cfg, ctx.db)
    if not pool:
        ui.fail("no search provider configured (/config → option 2)")
        return
    pool.best_effort = True  # a test must never fail because a background worker has the database
    pool.plan(cfg["schedule"]["dork_interval_min"])  # read-only
    for r in pool.rings:
        r.allowance = r.total_remaining()
    want = opts["provider"]
    chain = [p for p in pool.chain(text) if not want or p.id == want]
    if not chain:
        ui.fail("no configured provider can express this dork" + (f" (or '{want}' is not configured)" if want else ""))
        return
    window = dates.window_text(config.recency_days(cfg))
    ui.info(f"search recency for this test: {'any' if days is None else dates.window_text(days)} · the alert window ({window}) is "
            "NOT used as the search filter")
    if opts["dry"]:
        prov = chain[0]
        st, sent = prov.express(text)
        req = prov.preview(text, page=0, days=days)
        ui.console.print(_request_table(f"DRY RUN - request that would go to {prov.label} (nothing sent, no quota)", req or {}))
        if st == "rewritten":
            ui.info(f"{prov.label} cannot express site:.{pd.tld}: the dork is rewritten to: {sent}")
        return
    from .search import QuotaExhausted
    results, reqs, pid = [], [], None
    try:
        with ui.console.status("searching…"):
            for p in range(pages):
                res, pid = pool.search(text, page=p, days=days, prefer=chain[0].id if want else None)
                reqs.append((p, pool.ring(pid).provider.last_request or {}))
                results += res.results
                if not res.has_more:
                    break
    except QuotaExhausted:
        if not results:
            ui.fail("no quota left on any key")
            return
    for p, rq in reqs:
        ui.console.print(_request_table(f"Request actually sent to {pid} (page {p + 1})", rq))
    kept, dropped = relevance.filter_results(text, results, log_drops=False)
    t = Table(title=f"KEPT by the relevance gate — {len(kept)} of {len(results)} (nothing stored)", header_style="bold")
    for c in ("Title", "URL", "Page date", "Note"):
        t.add_column(c, overflow="fold")
    for r in kept[:20]:
        t.add_row(r.title[:70], r.url, dates.to_local_day(r.published), "rules check only (no snippet)" if r.rules_only else "")
    ui.console.print(t)
    d = Table(title=f"DROPPED — {len(dropped)}", header_style="bold")
    for c in ("Title", "URL", "Why"):
        d.add_column(c, overflow="fold")
    for r, why, _spam in dropped:
        d.add_row(r.title[:60], r.url, why)
    ui.console.print(d)
    ring = pool.ring(pid)
    if ring.qtype == "unlimited":
        left = "unlimited"
    else:
        per = sum(ring.period_remaining(k) for k in ring.keys)
        today = [ring.daily_left(k) for k in ring.keys if ring.daily_left(k) is not None]
        left = f"{per} {ring.qtype}" + (f", {sum(today)} left under today's per-day cap" if today else "")
    ui.info(f"Spent {len(reqs)} query(ies) on {pid}; remaining on {pid}: {left}. Nothing was stored (no programs, queries or URLs).")


def _prune(ctx, a):
    n = int(ctx.cfg["dorks"]["prune_after_runs"])
    rows = dorkstore.prune_candidates(ctx.db, n)
    if not rows:
        ui.info(f"no enabled dork has run {n}+ times without finding a program")
        return
    for r in rows[:30]:
        ui.console.print(f"  {r['id']:>4} [{r['grp']}] runs={r['run_count']} {_short(r['text'])}")
    if ui.yn(f"Disable these {len(rows)} dork(s) (zero useful hits after {n}+ runs)?", False):
        ctx.db.c.executemany("UPDATE dorks SET enabled=0, auto_disabled_reason=? WHERE id=?",
                             [(f"pruned: no programs after {r['run_count']} runs", r["id"]) for r in rows])
        ctx.db.commit()
        ui.ok(f"disabled {len(rows)}")


def _mode(ctx, a):
    cur = ctx.cfg["dorks"]["source"]
    if not a:
        ui.info(f"dork source: {cur}  (default = built-in list, custom = your imports, both)")
        c = ui.choose("Set mode", list(dorkstore.MODES), cur)
    else:
        c = a[0]
    if c not in dorkstore.MODES:
        ui.fail("mode must be default, custom or both")
        return
    ctx.cfg["dorks"]["source"] = c
    ctx.save(ctx.cfg)
    ui.ok(f"dork source = {c} (no dorks were deleted)")


def _reset(ctx, a):
    inc = "--include-promoted" in a
    pv = dorkstore.reset_preview(ctx.db, inc)
    ui.info(f"{dorkstore.default_path().name}: {pv['file_dorks']} shipped dorks · {pv['added']} would be added · "
            f"{pv['reenabled']} re-enabled · {pv['removed']} default dork(s) no longer in the file removed · "
            f"{pv['promoted']} AI-promoted dork(s) " + ("DEMOTED back to the AI group (history kept)" if inc else
                                                       "kept (use --include-promoted to demote them too)"))
    if not ui.yn("Restore the shipped default list (custom and AI dorks stay untouched)?", True):
        return
    r = dorkstore.reset_default(ctx.db, include_promoted=inc)
    ui.ok(f"default list restored: {r.text()}")


def _ai(ctx, a):
    if not a or a[0] not in ("on", "off"):
        ui.info(f"AI dorks are {'on' if ctx.cfg['features']['ai_dorks'] else 'off'}. Use /dorks ai on|off")
        return
    ctx.cfg["features"]["ai_dorks"] = a[0] == "on"
    ctx.save(ctx.cfg)
    ui.ok(f"AI dorks {a[0]}")


def _generate(ctx, a):
    from . import aidorks
    from .llm import from_config
    from .scanner import ScanLocked, lock
    llm = from_config(ctx.cfg, ctx.db)
    if not llm:
        ui.fail("no working LLM configured (/model)")
        return
    from . import llmreg
    if ctx.cfg.get("models") and not llmreg.confirm_bulk(ctx.cfg, "dork_gen", 2, "AI dork generation", ui.yn):
        ui.info("cancelled")
        return
    ids = configured(ctx.cfg)
    prov = make(ctx.cfg, ids[0]) if ids else None
    n = int(a[0]) if a and a[0].isdigit() else int(ctx.cfg["dorks"]["ai_per_generation"])
    try:
        with lock():  # generation must not overlap a scan
            with ui.console.status("asking the LLM for new dorks…"):
                rep = aidorks.generate(ctx.cfg, ctx.db, llm, prov, n)
    except ScanLocked as e:
        ui.fail(str(e))
        return
    ui.ok(rep.text())
    for t in rep.accepted_texts:
        ui.console.print(f"  + {t}")


def _candidates(ctx, a):
    from . import promotion
    rows = promotion.candidates(ctx.db, ctx.cfg)
    pc = ctx.cfg["dorks"]
    ui.info(f"Promotion needs: >= {pc['promote_min_runs']} runs, >= {pc['promote_min_verified']} verified-valid NEW programs, "
            f"precision >= {pc['promote_min_precision']}, validator + blocklist pass, not a near-duplicate of a default dork "
            f"(similarity < {pc['promote_similarity']}) · ai_auto_promote = {pc['ai_auto_promote']}")
    if not rows:
        ui.info("no AI dork has run yet")
        return
    t = Table(title="AI dorks vs the promotion conditions", header_style="bold")
    for c in ("ID", "Eligible", "Runs", "Kept", "Verified", "Precision", "Missing", "Dork"):
        t.add_column(c, overflow="fold")
    for e in rows[:60]:
        d = e.evidence
        t.add_row(str(e.dork_id), "[green]YES[/green]" if e.eligible else "no", str(d["runs"]), str(d["kept"]),
                  str(d["verified"]), f"{d['precision']:.2f}", "; ".join(e.failed()) or "-", _short(e.text, 50))
    ui.console.print(t)


def _promote(ctx, a):
    from . import promotion
    if not a:
        ui.fail("usage: /dorks promote <id|all-eligible>")
        return
    if a[0] == "all-eligible":
        ids = [e.dork_id for e in promotion.candidates(ctx.db, ctx.cfg, only_eligible=True)]
        if not ids:
            ui.info("no AI dork is eligible right now (/dorks candidates)")
            return
        if not ui.yn(f"Promote {len(ids)} eligible AI dork(s) into the default list?", True):
            return
    elif a[0].isdigit():
        ids = [int(a[0])]
    else:
        ui.fail("usage: /dorks promote <id|all-eligible>")
        return
    for i in ids:
        ok, msg = promotion.promote(ctx.db, ctx.cfg, i)
        (ui.ok if ok else ui.fail)(msg)
    p = promotion.learned_path()
    if p.exists():
        ui.info(f"mirrored to {p} (dorks/default.txt is untouched; /dorks export-default --include-promoted to share them)")


def _demote(ctx, a):
    from . import promotion
    if not a or not a[0].isdigit():
        ui.fail("usage: /dorks demote <id>")
        return
    ok, msg = promotion.demote(ctx.db, int(a[0]), "demoted by you", disable=False)
    (ui.ok if ok else ui.fail)(msg)


def _export_default(ctx, a):
    """/dorks export-default [--include-promoted] [--to <path>]: writes ONLY after showing a diff and a yes."""
    from pathlib import Path
    from . import promotion
    inc = "--include-promoted" in a
    if "--to" in a:
        try:
            target = Path(a[a.index("--to") + 1]).expanduser()
        except IndexError:
            ui.fail("--to needs a path")
            return
    else:
        target = dorkstore.REPO_DEFAULT
        if not target.parent.exists():
            ui.fail("no repository checkout found (dorks/default.txt): use --to <path>")
            return
    why = promotion.refuse_reason(target)
    if why:
        ui.fail(f"not writing {target}: {why}")
        return
    old, new = promotion.export_text(ctx.db, target, inc)
    if old == new:
        ui.info(f"{target}: nothing to change" + ("" if inc else " (add --include-promoted to export the AI-promoted dorks)"))
        return
    d = promotion.diff(old, new, target.name)
    ui.console.print(d, markup=False, highlight=False)
    n = sum(1 for ln in d.splitlines() if ln.startswith("+") and not ln.startswith("+++") and not ln[1:].lstrip().startswith("#")
            and ln[1:].strip())
    if not ui.yn(f"Write these changes to {target} ({n} dork line(s) added)?", False):
        ui.info("not written")
        return
    target.write_text(new, encoding="utf-8")
    ui.ok(f"wrote {target} - review and commit it yourself (git diff {target.name})")


# ── /memory & /history ──────────────────────────────────────────────────────────
def cmd_memory(ctx, args):
    sub = args[0] if args else ""
    if not sub:
        ui.info("usage: /memory stats | export <path> | forget program|query|dork|all [id] | reclassify")
        return
    if sub == "stats":
        _mem_stats(ctx)
    elif sub == "export":
        _mem_export(ctx, args[1:])
    elif sub == "forget":
        _mem_forget(ctx, args[1:])
    elif sub == "reclassify":
        _mem_reclassify(ctx, args[1:])
    else:
        ui.fail("usage: /memory stats | export <path> | forget program|query|dork|all [id] | reclassify")


def memory_stats(db, cfg: dict | None = None) -> dict:
    q = lambda sql: db.c.execute(sql).fetchone()[0]  # noqa: E731
    return {
        "programs": q("SELECT COUNT(*) FROM programs WHERE verdict='official_program'"),
        "baseline": q("SELECT COUNT(*) FROM programs WHERE baseline=1"),
        "delivered": q("SELECT COUNT(*) FROM programs WHERE delivered=1"),
        "pending": len(db.pending(config.recency_days(cfg), cfg=cfg) if cfg else db.pending(None)),
        "not_program": q("SELECT COUNT(*) FROM programs WHERE verdict='not_program'"),
        "with_launch_date": q("SELECT COUNT(*) FROM programs WHERE launched_at IS NOT NULL"),
        "seen_urls": q("SELECT COUNT(*) FROM seen_urls"),
        "rejected_urls": q("SELECT COUNT(*) FROM seen_urls WHERE verdict='not_program'"),
        "queries": q("SELECT COUNT(*) FROM queries"),
        "queries_chat": q("SELECT COUNT(*) FROM queries WHERE origin='chat'"),
        "queries_ai": q("SELECT COUNT(*) FROM queries WHERE origin='ai'"),
        "dorks": q("SELECT COUNT(*) FROM dorks"),
        "chat_sessions": q("SELECT COUNT(*) FROM chat_sessions"),
        "chat_messages": q("SELECT COUNT(*) FROM chat_messages"),
        "schema": q("PRAGMA user_version"),
    }


def _mem_stats(ctx):
    s = memory_stats(ctx.db, ctx.cfg)
    t = Table(title="Memory", show_header=False, box=None, padding=(0, 2))
    t.add_column(style="bold cyan"); t.add_column()
    t.add_row("Programs", f"{s['programs']} ({s['baseline']} baseline, {s['delivered']} delivered, "
                          f"{s['pending']} waiting to alert, {s['with_launch_date']} with a launch date)")
    t.add_row("Rejected / non-program", f"{s['not_program']} programs reclassified, {s['rejected_urls']} URLs remembered")
    t.add_row("Seen URLs", str(s["seen_urls"]))
    t.add_row("Queries run", f"{s['queries']} ({s['queries_ai']} AI, {s['queries_chat']} chat)")
    t.add_row("Dorks", str(s["dorks"]))
    t.add_row("Chat", f"{s['chat_sessions']} session(s), {s['chat_messages']} message(s)")
    try:
        size = ctx.db.path.stat().st_size / 1e6
        nb = len(list((ctx.db.path.parent / "backups").glob("*.db")))
        t.add_row("Database", f"{ctx.db.path} · {size:.1f} MB · schema v{s['schema']} · {nb} backup(s)")
    except OSError:
        pass
    ui.console.print(t)


def _mem_export(ctx, a):
    path = a[0] if a else "qurihunter-memory.json"
    out = {}
    for tbl in ("programs", "program_sources", "seen_urls", "queries", "dorks", "chat_sessions", "chat_messages",
                "seeded_sources", "runs"):
        out[tbl] = [dict(r) for r in ctx.db.c.execute(f"SELECT * FROM {tbl}")]
    with open(path, "w") as f:
        json.dump(out, f, indent=1, default=str)
    ui.ok(f"exported {sum(len(v) for v in out.values())} rows to {path}")


def forget(db, what: str, ident: str | None) -> int:
    """Delete memory. Returns rows removed. (Callers confirm first.)"""
    c = db.c
    n = 0
    if what == "program":
        ids = [r[0] for r in c.execute("SELECT id FROM programs WHERE id=? OR dedupe_key=? OR url LIKE ?",
                                       (ident if str(ident).isdigit() else -1, ident, f"%{ident}%"))]
        for i in ids:
            url = c.execute("SELECT url FROM programs WHERE id=?", (i,)).fetchone()[0]
            c.execute("DELETE FROM seen_urls WHERE url=?", (url,))
            c.execute("DELETE FROM program_sources WHERE program_id=?", (i,))
            n += c.execute("DELETE FROM programs WHERE id=?", (i,)).rowcount
    elif what == "query":
        n = c.execute("DELETE FROM queries" if ident in (None, "all") else "DELETE FROM queries WHERE id=?",
                      () if ident in (None, "all") else (int(ident),)).rowcount
    elif what == "dork":
        if ident in (None, "all"):
            n = c.execute("DELETE FROM dorks").rowcount
            c.execute("DELETE FROM meta WHERE key='default_list_size'")  # default list re-imports on next use
        else:
            n = c.execute("DELETE FROM dorks WHERE id=?", (int(ident),)).rowcount
    elif what == "all":
        for tbl in ("programs", "program_sources", "seen_urls", "queries", "dorks", "chat_messages", "chat_sessions",
                    "seeded_sources", "runs", "dork_runs", "rejected", "meta"):
            n += c.execute(f"DELETE FROM {tbl}").rowcount
    db.commit()
    return n


def _mem_forget(ctx, a):
    what = a[0] if a else ""
    ident = a[1] if len(a) > 1 else None
    if what not in ("program", "query", "dork", "all"):
        ui.fail("usage: /memory forget program <id|url-part> | query <id|all> | dork <id|all> | all")
        return
    if what in ("program",) and not ident:
        ui.fail("which program? give an id or part of its URL")
        return
    if what in ("query", "dork") and ident not in (None, "all") and not str(ident).isdigit():
        ui.fail("give a numeric id or 'all'")
        return
    warn = {"program": "forget this program (it may be found and alerted again)",
            "query": "forget query history (cooldowns reset, quota may be re-spent)",
            "dork": "delete dorks and their statistics",
            "all": "ERASE ALL memory: programs, URLs, queries, dorks, chat. The next scan starts from scratch"}[what]
    if not ui.yn(f"{warn}. Continue?", False):
        ui.info("cancelled")
        return
    if what == "all" and ui.ask("Type 'forget everything' to confirm") != "forget everything":
        ui.info("cancelled")
        return
    b = backup(ctx.db.c, ctx.db.path, f"before-forget-{what}")
    n = forget(ctx.db, what, ident)
    ui.ok(f"removed {n} row(s). Backup of the previous state: {b.name}")


def _reclass_table(plan: list[dict]) -> bool:
    """Before/after table. Returns True when there is something to reject."""
    from collections import Counter
    rej = [d for d in plan if d["decision"] == "reject"]
    keep = [d for d in plan if d["decision"] == "keep"]
    t = Table(title=f"Reclassify - {len(plan)} stored dork entries: {len(keep)} kept, {len(rej)} would be rejected",
              header_style="bold")
    for c in ("Decision", "Name", "URL", "Why"):
        t.add_column(c, overflow="fold")
    for d in rej[:60]:
        t.add_row("[red]reject[/red]", d["name"][:60], d["url"], d["reason"])
    for d in keep[:15]:
        t.add_row("[green]keep[/green]", d["name"][:60], d["url"], d["reason"])
    ui.console.print(t)
    by_reason = Counter(d["reason"].split("(")[0].split(":")[0][:50] for d in rej)
    ui.info("Rejected by reason: " + (", ".join(f"{k} x{v}" for k, v in by_reason.most_common()) or "none"))
    bare = sum(1 for d in keep if d["kind"] == "security.txt")
    if bare:
        ui.info(f"{bare} bare security.txt entries are kept (separable: /programs --category securitytxt).")
    return bool(rej)


def report_if_finished(db) -> None:
    """Called by the REPL before each prompt: print the before/after table once when a background job finishes."""
    from . import reclass
    if reclass.state(db) == "done" and db.meta("reclass_reported") != "1":
        ui.info("Background reclassify finished.")
        if _reclass_table(reclass.plan(db)):
            ui.info("Nothing has been hidden yet. Apply with /memory reclassify apply (reversible: rows are only "
                    "marked not_program).")
        db.set_meta("reclass_reported", "1")
        db.commit()


def _mem_reclassify(ctx, a=()):
    """/memory reclassify [status|review|apply|cancel|--now]. Default: start/resume a background, capped, alert-free job."""
    from . import reclass
    from .llm import from_config
    sub = a[0] if a else ""
    db = ctx.db
    from . import llmreg
    n_pages = db.c.execute("SELECT COUNT(*) FROM programs WHERE source='web' AND verdict='official_program'").fetchone()[0]
    if sub in ("", "--now") and reclass.state(db) != "running" and ctx.cfg.get("models") and \
            not llmreg.confirm_bulk(ctx.cfg, "classify", n_pages, "Reclassify", ui.yn):
        ui.info("cancelled - no paid model call was made")
        return
    if sub == "--now":  # old synchronous behaviour: plan, show, ask, apply
        from .scanner import reclassify_apply, reclassify_plan
        llm = from_config(ctx.cfg, db)
        with ui.console.status("Re-checking stored dork entries..."):
            plan = reclassify_plan(db, ctx.cfg, llm)
        if not _reclass_table(plan):
            ui.ok("Nothing to remove. No alerts were sent.")
            return
        if ui.yn(f"Hide {sum(d['decision'] == 'reject' for d in plan)} entries as not-a-program (remembered per URL)?", False):
            ui.ok(f"{reclassify_apply(db, plan)} entries marked not_program. No alerts were sent.")
        else:
            ui.info("Nothing changed.")
    elif sub == "status":
        p = reclass.progress(db)
        ui.info(f"Reclassify: {p['state']} - {p['done']}/{p['total']} judged, {p['rejected']} would be rejected "
                f"(cap {ctx.cfg['reclassify']['pages_per_cycle']} LLM pages per cycle)")
    elif sub == "review":
        p = reclass.plan(db)
        if not p:
            ui.info("No decisions yet.")
        elif _reclass_table(p) and ui.yn("Apply (hide the rejected entries)?", False):
            ui.ok(f"{reclass.apply(db)} entries marked not_program. No alerts were sent.")
    elif sub == "apply":
        p = reclass.progress(db)
        if p["state"] not in ("done", "running") or not p["done"]:
            ui.fail("nothing to apply yet - start with /memory reclassify")
            return
        if p["state"] == "running" and not ui.yn(f"Only {p['done']}/{p['total']} judged so far. Apply the finished part?", False):
            return
        _reclass_table(reclass.plan(db))
        if ui.yn("Hide the rejected entries?", False):
            ui.ok(f"{reclass.apply(db)} entries marked not_program. No alerts were sent.")
    elif sub == "cancel":
        reclass.cancel(db)
        ui.info("Background reclassify cancelled (decisions so far are kept for /memory reclassify review).")
    else:
        if reclass.state(db) == "running":
            _mem_reclassify(ctx, ["status"])
            return
        n = reclass.start(db)
        llm = from_config(ctx.cfg, db)
        ui.info(f"Queued {n} stored dork entries. A background worker judges at most "
                f"{ctx.cfg['reclassify']['pages_per_cycle']} pages per cycle (hard rules are instant"
                f"{'' if llm else '; no LLM available, ambiguous ones are kept'}). It never sends alerts or blocks /scan. "
                "Progress: /status or /memory reclassify status. When done you get a before/after table.")
        done = reclass.step(db, ctx.cfg, llm, pages=0)  # hard rules right away
        ui.info(f"Instant hard-rule pass: {done['done']}/{done['total']} judged, {done['rejected']} would be rejected.")


def cmd_history(ctx, args):
    n = int(args[0]) if args and args[0].isdigit() else 20
    rows = ctx.db.history(n)
    t = Table(title=f"Last {len(rows)} queries", header_style="bold")
    for c in ("ID", "When", "Provider", "Origin", "Window", "Results", "New", "Status", "Query"):
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(str(r["id"]), dates.to_local(r["run_at"]), r["provider"] or "", r["origin"] or "",
                  r["recency_window"] or "", str(r["results_count"] or 0), str(r["new_programs_found"] or 0),
                  r["status"] or "", _short(r["query_text"] or "", 60))
    ui.console.print(t)
