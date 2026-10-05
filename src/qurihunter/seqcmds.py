"""/sequence, /providers and /searxng."""
from __future__ import annotations

import secrets
from pathlib import Path

from rich.table import Table

from . import config, dates, search, sequence, ui
from .config import mask
from .paths import home

HOSTS = {"serper": "google.serper.dev", "tavily": "tavily.com", "brave": "search.brave.com", "exa": "exa.ai",
         "google": "www.googleapis.com", "searxng": "localhost"}
USAGE = ("usage: /sequence show | move <provider> <position> | enable <provider> | disable <provider> | "
         "mode <failover|cascade|sweep> | test | reset-cursor")


def _state(cfg, db, pool, pid) -> str:
    if not search.is_configured(cfg, pid):
        return "not configured"
    if not search.is_enabled(cfg, pid):
        return "disabled"
    if pool is None:
        return "no pool"
    ok, why = pool.available(pid)
    return "ok" if ok else why


def show_table(ctx) -> Table:
    cfg, db = ctx.cfg, ctx.db
    pool = search.build_pool(cfg, db)
    t = Table(title=f"Search sequence - mode {cfg.get('search_mode', 'failover')}", header_style="bold")
    for c in ("#", "Provider", "Status", "Keys", "Remaining", "Quota", "Role", "Health"):
        t.add_column(c, overflow="fold")
    for i, e in enumerate(search.sequence_entries(cfg), 1):
        pid = e["provider"]
        cls = search.PROVIDERS[pid]
        ring = pool.ring(pid) if pool else None
        if ring is None:
            rem = "-"
        elif ring.qtype == "unlimited":
            rem = "unlimited"
        else:
            left = ring.share_left()
            rem = f"{ring.total_remaining()}" + (f" ({left * 100:.0f}% left)" if left is not None else "")
            if ring.low_warning():
                rem += " [red]LOW[/red]"
        h = db.c.execute("SELECT * FROM provider_health WHERE provider=?", (pid,)).fetchone()
        health = "-" if not h else f"{h['ok']} ok / {h['failures']} failed" + (f", {h['consecutive_fails']} in a row" if h["consecutive_fails"] else "")
        keys = "-" if not cls.needs_key else str(len(e["keys"]))
        t.add_row(str(i), cls.label, _state(cfg, db, pool, pid), keys, rem, e["quota_type"], e["role"], health)
    return t


def cmd_sequence(ctx, args):
    sub = args[0] if args else "show"
    cfg = ctx.cfg
    ids = search.sequence_order(cfg)
    if sub == "show":
        ui.console.print(show_table(ctx))
        pr = sequence.progress(ctx.db)
        if pr["batch"]:
            nx = pr["next"]
            ui.info(f"Queue: batch #{pr['batch']} - {pr['done']}/{pr['total']} steps done"
                    + (f"; resume point: step {nx['pos']} ({nx['provider']}) {nx['dork_text'][:50]}" if nx else "; finished")
                    + (f"; STOPPED: {pr['stopped']}" if pr["stopped"] else ""))
        else:
            ui.info("Queue: no unfinished batch (the next scan plans a new one)")
        for r in (search.build_pool(cfg, ctx.db) or search.SearchPool([], ctx.db)).rings:
            if r.low_warning():
                ui.fail(r.low_warning())
    elif sub == "move" and len(args) == 3:
        pid = args[1].lower()
        if pid not in ids or not args[2].isdigit() or not 1 <= int(args[2]) <= len(ids):
            ui.fail(f"usage: /sequence move <{'|'.join(ids)}> <1-{len(ids)}>")
            return
        ids.remove(pid)
        ids.insert(int(args[2]) - 1, pid)
        search.save_sequence(cfg, ids)
        ctx.save(cfg)
        ui.ok("order: " + " → ".join(ids))
    elif sub in ("enable", "disable") and len(args) == 2:
        pid = args[1].lower()
        if pid not in ids:
            ui.fail(f"unknown provider; choose from {', '.join(ids)}")
            return
        search.save_sequence(cfg, ids, {pid: sub == "enable"})
        ctx.save(cfg)
        ui.ok(f"{pid} {sub}d")
    elif sub == "mode" and len(args) == 2 and args[1] in sequence.MODES:
        _set_mode(ctx, args[1])
    elif sub == "test":
        _sequence_test(ctx)
    elif sub == "reset-cursor":
        n = sequence.reset_cursor(ctx.db)
        ui.ok(f"cursor reset ({n} unfinished steps dropped; finished steps and query memory are kept)")
    else:
        ui.fail(USAGE)


def _set_mode(ctx, mode: str) -> None:
    cfg = ctx.cfg
    if mode == "sweep":
        pool = search.build_pool(cfg, ctx.db)
        n = len(pool.rings) if pool else 0
        per = max(1, int(cfg["schedule"]["dork_interval_min"] and 20))
        est = sequence.sweep_estimate(cfg, pool.rings if pool else [], per)
        ui.info(f"SWEEP runs every dork on every enabled provider ({n}). For a batch of about {per} dorks that is "
                f"~{est['total']} queries per cycle instead of ~{per} ({', '.join(f'{k}: {v}' for k, v in est['per_provider'].items())}). "
                "Lifetime and monthly credits drain {n}x faster.".replace("{n}", str(max(1, n))))
        if not ui.yn("Enable sweep mode?", False):
            ui.info("unchanged")
            return
        cfg["sweep_confirmed"] = True
    cfg["search_mode"] = mode
    ctx.save(cfg)
    extra = f" (cascade_min_results = {cfg['cascade_min_results']})" if mode == "cascade" else ""
    ui.ok(f"search mode: {mode}{extra}")


SAMPLE_DORK = '"responsible disclosure" bug bounty'


def _sequence_test(ctx) -> None:
    """Dry run of ONE harmless dork through the chain: shows which provider answered and what it cost. Nothing is stored."""
    cfg, db = ctx.cfg, ctx.db
    pool = search.build_pool(cfg, db)
    if not pool:
        ui.fail("no usable search provider (/config → 2)")
        return
    pool.best_effort = True
    pool.plan(cfg["schedule"]["dork_interval_min"])
    for r in pool.rings:
        r.allowance = max(1, r.total_remaining()) if r.qtype != "unlimited" else 10**6
    t = Table(title=f"/sequence test - {SAMPLE_DORK}", header_style="bold")
    for c in ("Provider", "Result", "Results", "Quota cost"):
        t.add_column(c, overflow="fold")
    answered = False
    for p in pool.chain(SAMPLE_DORK):
        ok, why = pool.available(p.id)
        if not ok:
            t.add_row(p.label, f"skipped: {why}", "-", "0")
            continue
        ring = pool.ring(p.id)
        before = ring.total_remaining()
        try:
            res, pid = pool.search(SAMPLE_DORK, page=0, days=config.recency_days(cfg), prefer=p.id)
            cost = 0 if ring.qtype == "unlimited" else before - ring.total_remaining()
            t.add_row(p.label, "[green]answered[/green]", str(len(res.results)), str(cost))
            answered = True
            break  # failover semantics: the first provider that answers ends the dry run
        except Exception as e:  # noqa: BLE001
            t.add_row(p.label, f"[red]failed: {e}[/red]", "-", "0")
    ui.console.print(t)
    ui.info("The first provider that answers wins (failover). Nothing was stored; quota counters keep the cost."
            if answered else "No provider answered - see the reasons above.")


PUSAGE = "usage: /providers [show | status | set <provider> allowance|type <value> | daily <provider> [key#|last4] <n>]"


def _find_provider(cfg, pid):
    pid = (pid or "").lower()
    return pid if pid in search.PROVIDERS else None


def cmd_providers(ctx, args):
    sub = args[0] if args else "show"
    if sub == "show":
        return _providers_show(ctx)
    if sub == "set":
        return _providers_set(ctx, args[1:])
    if sub == "daily":
        return _providers_daily(ctx, args[1:])
    if sub != "status":
        ui.fail(PUSAGE)
        return
    cfg, db = ctx.cfg, ctx.db
    pool = search.build_pool(cfg, db)
    t = Table(title="Providers", header_style="bold")
    for c in ("Provider", "State", "Breaker", "In a row", "OK", "Failed", "Retries (http)", "Last error", "Last OK"):
        t.add_column(c, overflow="fold")
    for pid in search.sequence_order(cfg):
        h = db.c.execute("SELECT * FROM provider_health WHERE provider=?", (pid,)).fetchone()
        ns = db.c.execute("SELECT retries FROM net_stats WHERE name=?", (HOSTS.get(pid, ""),)).fetchone()
        br = pool.breaker_open(pid) if pool and pool.ring(pid) else None
        t.add_row(search.PROVIDERS[pid].label, _state(cfg, db, pool, pid),
                  f"[red]open until {dates.to_local(br)}[/red]" if br else "closed",
                  str(h["consecutive_fails"]) if h else "0", str(h["ok"]) if h else "0", str(h["failures"]) if h else "0",
                  str(ns["retries"]) if ns else "0", (h["last_error"] or "") if h else "", dates.to_local(h["last_ok"]) if h else "-")
    ui.console.print(t)
    sx = search.PROVIDERS["searxng"](search.provider_cfg(cfg, "searxng")) if "searxng" in cfg["search"]["providers"] else None
    if sx is not None and sx.engine_fail:
        ui.info("SearXNG engines: " + ", ".join(f"{e} ({n} fails)" for e, (n, _) in sx.engine_fail.items()))


def _providers_show(ctx) -> None:
    from . import keysetup
    from .search.pool import key_id
    cfg, db = ctx.cfg, ctx.db
    pool = search.build_pool(cfg, db)
    t = Table(title="Providers - quota, daily caps and where the numbers come from", header_style="bold")
    for c in ("Provider", "Quota", "Allowance", "Source", "Keys", "Per day (per key)", "Total/day", "Left", "≈ Days"):
        t.add_column(c, overflow="fold")
    for pid in search.sequence_order(cfg):
        cls = search.PROVIDERS[pid]
        pc = cfg["search"]["providers"].get(pid) or {}
        d = search.defaults.default_for(pid)
        prov = search.make(cfg, pid)
        qt = prov.quota_type()
        ring = pool.ring(pid) if pool else None
        det = bool(pc.get("key_limit"))
        src = ("detected from the account" if det else (f"default{'' if d is None or d.verified else ' (unverified)'}: "
                                                        f"{d.source[:60]}" if d else "-"))
        keys = pc.get("keys", [])
        caps = [str((pc.get("daily") or {}).get(key_id(pid, k), "-")) for k in keys]
        tot = keysetup.total_per_day(cfg, pid)
        left = "-" if ring is None else ("unlimited" if qt == "unlimited" else str(ring.total_remaining()))
        rem = None if ring is None or qt == "unlimited" else sum(ring.period_remaining(k) for k in ring.keys)
        days = search.defaults.days_estimate(qt, rem, tot)
        t.add_row(cls.label, qt, "-" if qt == "unlimited" else str(pc.get("limit") or cls.default_limit), src,
                  "-" if not cls.needs_key else str(len(keys)), ", ".join(caps) or "-", str(tot or "-"), left,
                  f"{days:.0f}" if days else "-")
    ui.console.print(t)
    ui.info("Change: /providers set <provider> allowance|type <value> · /providers daily <provider> [key#|last4] <n>")


def _providers_set(ctx, a) -> None:
    cfg = ctx.cfg
    pid = _find_provider(cfg, a[0] if a else "")
    if not pid or len(a) != 3 or a[1] not in ("allowance", "type"):
        ui.fail("usage: /providers set <provider> allowance <number> | type <monthly|daily|lifetime|unlimited>")
        return
    pc = search.provider_cfg(cfg, pid)
    if a[1] == "allowance":
        if not a[2].isdigit() or int(a[2]) < 0:
            ui.fail("allowance must be a whole number")
            return
        pc["limit"] = int(a[2])
    else:
        if a[2] not in ("monthly", "daily", "lifetime", "unlimited"):
            ui.fail("type must be monthly, daily, lifetime or unlimited")
            return
        pc["quota_type"] = a[2]
        if a[2] == "lifetime":
            from .search.pool import ensure_lifetime_start
            ensure_lifetime_start(ctx.db, pid)
    ctx.save(cfg)
    ui.ok(f"{pid}: {a[1]} = {a[2]}")


def _providers_daily(ctx, a) -> None:
    from . import keysetup
    from .search.pool import key_id
    cfg = ctx.cfg
    pid = _find_provider(cfg, a[0] if a else "")
    if not pid or len(a) not in (2, 3) or not a[-1].isdigit():
        ui.fail("usage: /providers daily <provider> [key# | last4] <n>   (n = 0 removes the cap)")
        return
    pc = search.provider_cfg(cfg, pid)
    keys = pc.get("keys", [])
    if not keys:
        ui.fail(f"{pid} has no keys")
        return
    sel = keys
    if len(a) == 3:
        sel = [k for i, k in enumerate(keys, 1) if a[1] == str(i) or k.endswith(a[1])]
        if not sel:
            ui.fail("no such key (give its number or its last characters)")
            return
    n = int(a[-1])
    for k in sel:
        caps = pc.setdefault("daily", {})
        if n:
            caps[key_id(pid, k)] = n
        else:
            caps.pop(key_id(pid, k), None)
    ctx.save(cfg)
    tot = keysetup.total_per_day(cfg, pid)
    ui.ok(f"{pid}: {', '.join(config.mask(k) for k in sel)} -> " + (f"{n} per day" if n else "no cap")
          + (f" (total {tot} per day across keys)" if tot else ""))


# ───────────────────────────── /searxng ─────────────────────────────
COMPOSE = """services:
  searxng:
    image: searxng/searxng:latest
    container_name: qurihunter-searxng
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"        # only reachable from this machine
    volumes:
      - ./searxng:/etc/searxng:rw
    environment:
      - SEARXNG_BASE_URL=http://localhost:8080/
"""
SETTINGS = """use_default_settings: true
server:
  secret_key: "{secret}"
  limiter: false          # localhost only: no bot-detection limiter (turn it on if you expose the port)
  image_proxy: false
search:
  safe_search: 0
  formats:                # json MUST be listed or qurihunter gets HTTP 403
    - html
    - json
outgoing:
  request_timeout: 6.0
engines:                  # several engines so one CAPTCHA does not stop a query
  - name: google
    disabled: false
  - name: bing
    disabled: false
  - name: duckduckgo
    disabled: false
  - name: brave
    disabled: false
  - name: startpage
    disabled: false
  - name: mojeek
    disabled: false
"""


def cmd_searxng(ctx, args):
    sub = args[0] if args else "setup"
    if sub == "probe":
        base = (ctx.cfg["search"]["providers"].get("searxng") or {}).get("base_url", "") or (args[1] if len(args) > 1 else "")
        if not base:
            ui.fail("no base_url configured: /config → 2 → SearXNG, or /searxng probe http://localhost:8080")
            return
        ok, detail = search.PROVIDERS["searxng"]({"base_url": base}).probe()
        (ui.ok if ok else ui.fail)(detail)
    elif sub == "setup":
        _setup(ctx)
    else:
        ui.fail("usage: /searxng setup | probe [base_url]")


def _setup(ctx) -> None:
    secret = secrets.token_hex(32)
    shown = SETTINGS.format(secret=mask(secret).replace("…", "…(64 hex chars, hidden here)…"))
    ui.info("Ready-to-use SearXNG for localhost. qurihunter NEVER runs docker or any command for you.")
    ui.console.print("\n[bold]docker-compose.yml[/bold]\n" + COMPOSE, markup=False)
    ui.console.print("[bold]searxng/settings.yml[/bold] (secret key hidden in this display)\n" + shown, markup=False)
    d = Path(ui.ask("Write these files to which folder? (blank = just print)", str(home() / "searxng-stack")).strip() or "")
    if str(d) not in ("", "."):
        d = d.expanduser()
        (d / "searxng").mkdir(parents=True, exist_ok=True)
        (d / "docker-compose.yml").write_text(COMPOSE)
        (d / "searxng" / "settings.yml").write_text(SETTINGS.format(secret=secret))
        (d / "searxng" / "settings.yml").chmod(0o600)
        ui.ok(f"written to {d} (settings.yml chmod 600)")
        ui.console.print(f"Then run it yourself:\n  cd {d}\n  docker compose up -d\n  qurihunter → /searxng probe", markup=False)
    if ui.yn("Save http://localhost:8080 as your SearXNG base URL in the config?", True):
        pc = search.provider_cfg(ctx.cfg, "searxng")
        pc["base_url"] = "http://localhost:8080"
        pc["quota_type"] = "unlimited"
        pc.setdefault("keys", [])
        ctx.save(ctx.cfg)
        ui.ok("saved. After you start the container, check it with /searxng probe")


# ───────────────────────────── /background ─────────────────────────────
def cmd_background(ctx, args):
    from . import background, dblock, reclass, retry
    sub = args[0] if args else "status"
    if sub == "pause":
        background.pause()
        ui.ok("background workers paused (they finish their current item and wait). /background resume continues.")
    elif sub == "resume":
        background.resume()
        ui.ok("background workers resumed")
    elif sub == "status":
        t = Table(title="Background workers", header_style="bold")
        for c in ("Worker", "Alive", "Doing", "Last tick", "Last problem"):
            t.add_column(c, overflow="fold")
        rows = background.status_rows()
        if not rows:
            t.add_row("-", "no", "no worker in this session" + ("" if ctx.cfg.get("background_workers", True)
                                                                 else " (background_workers is off in the config)"), "-", "")
        for name, d in rows:
            t.add_row(name, "yes" if d.get("alive") else "no", d.get("job", ""), dates.to_local(d.get("last_tick")),
                      d.get("error", ""))
        ui.console.print(t)
        rp = reclass.progress(ctx.db)
        ui.info(f"Switch: background_workers={ctx.cfg.get('background_workers', True)} · "
                f"{'PAUSED' if background.paused() else 'running'} · foreground command active: "
                f"{'yes' if background.foreground_active() else 'no'}")
        ui.info(retry.status(ctx.db, ctx.cfg) + f" · reclassify: {rp['state']} {rp['done']}/{rp['total']}")
        g = dblock.GATE
        ui.info(f"Database write lock: {'free' if g.owner is None else g.holder_text()} · waits >50 ms: {g.waits} "
                f"(longest {g.longest_wait:.1f} s) · gave up after {int(dblock.LOCK_WAIT_S)} s: {g.busy_errors}")
    else:
        ui.fail("usage: /background status | pause | resume")
