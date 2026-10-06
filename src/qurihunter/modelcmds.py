"""The "add model" wizard (used by /model add, /config → 8 and Manual-mode first run), /model subcommands and /llm status."""
from __future__ import annotations

import requests
from rich.table import Table

from . import claudecli, config, hardware, llmreg, ui
from .config import ROLES, mask
from .llm import Anthropic, LLMError, Ollama, OpenAICompat

SUBSCRIPTION_NOTE = (
    "A Claude Free/Pro/Max subscription (claude.ai login) is NOT an API key. qurihunter cannot and will not use "
    "subscription logins or tokens directly: it never reads another tool's login files and never pretends to be "
    "another client. Your options:\n"
    "  - a LOCAL model (free, private; option 1),\n"
    "  - an OpenAI-compatible API: a free-tier provider or your own relay/proxy (option 2),\n"
    "  - an Anthropic Console API key (pay-as-you-go; create one at console.anthropic.com, option 3),\n"
    "  - or, experimental and OFF by default, the official Claude Code CLI on your own machine (option 4).")
STEP1 = ("Which kind of model do you want to use?\n  1) Local LLM on this computer\n  2) API (OpenAI-compatible: base URL + key)\n"
         "  3) Claude API key (Anthropic Console)\n  4) Claude subscription via official Claude Code CLI (experimental)")


# ───────────────────────────── building blocks ─────────────────────────────
def _prices(entry_type: str) -> tuple[float | None, float | None]:
    ui.info("Cost tracking: enter the price per MILLION tokens in USD from your provider's price list, or press Enter to "
            "skip (then spend is not tracked; prices are never assumed).")
    out = []
    for q in ("Input price per million tokens", "Output price per million tokens"):
        v = ui.ask(q, "").strip()
        try:
            out.append(float(v) if v else None)
        except ValueError:
            ui.fail("not a number, skipped")
            out.append(None)
    return out[0], out[1]


def _retry() -> str:
    return ui.choose("(r)e-enter, (k)eep anyway, (s)kip this model", ["r", "k", "s"], "r")


def _local(cfg: dict):
    ui.info("Local models run on this computer. Ollama is the easiest; LM Studio / llama.cpp servers work through their "
            "OpenAI-compatible address.")
    if not ui.yn("Is it an Ollama install (answer n for LM Studio / llama.cpp / another local OpenAI-compatible server)?", True):
        return _api(cfg, local=True)
    from . import wizard
    host = cfg["llm"].get("host") or "http://localhost:11434"
    o = Ollama(host)
    if not wizard._ensure_running(o):
        ui.fail("Ollama is not running")
        return "back"
    installed = o.models()
    model = ""
    if installed:
        ranked = sorted(installed, key=lambda m: next((i for i, p in enumerate(wizard.PREFERRED) if m.startswith(p)), 99))
        ui.info(f"Found a running Ollama with models: {', '.join(installed)}")
        if ui.yn(f"Use this one? ({ranked[0]})", True):
            model = ranked[0]
        else:
            n = ui.ask("Model name (blank = hardware recommendation)", "").strip()
            model = n
    if not model:
        hw = hardware.detect()
        model, why = hardware.recommend_model(hw)
        ui.info(f"Recommended for {hw.describe()}: [bold]{model}[/bold] - {why}")
    if not o.has(model):
        if not ui.yn(f"Download {model} now?", True) or not wizard._pull_with_bar(o, model):
            return "back"
    while True:
        try:
            ui.ok(f"{model} replied: {Ollama(host, model).test()!r}")
            break
        except LLMError as e:
            ui.fail(str(e))
            c = _retry()
            if c == "s":
                return None
            if c == "k":
                break
    return llmreg.new_entry(cfg, "local", model, base_url=host)


def _api(cfg: dict, local: bool = False):
    ui.info("Any OpenAI-compatible endpoint: hosted provider, your own relay/proxy, LM Studio, llama.cpp ...")
    base = ui.ask("Base URL (ending in /v1)", "http://localhost:1234/v1" if local else "").strip().rstrip("/")
    key = ui.ask("API key (hidden; Enter if none)", "", password=True).strip()
    probe = OpenAICompat(base, key, "")
    models = probe.models()
    model = ""
    if models and ui.yn(f"The endpoint lists {len(models)} models. Pick from the list?", True):
        for i, m in enumerate(models[:30], 1):
            ui.console.print(f"  {i}) {m}")
        model = models[int(ui.choose("Model number", [str(i) for i in range(1, min(30, len(models)) + 1)], "1")) - 1]
    if not model:
        model = ui.ask("Model name", "").strip()
    free = bool(local)  # a local server costs nothing; hosted prices are optional: /llm prices <id> <in> <out>
    while True:
        try:
            ui.ok(f"replied: {OpenAICompat(base, key, model).test()!r}")
            break
        except LLMError as e:
            ui.fail(str(e))
            c = _retry()
            if c == "s":
                return None
            if c == "k":
                break
            base = ui.ask("Base URL", base).strip().rstrip("/")
            key = ui.ask("API key", "", password=True).strip() or key
            model = ui.ask("Model name", model).strip()
    return llmreg.new_entry(cfg, "api", model, base_url=base, key=key, free=free)


def _suggest(models: list[dict]) -> tuple[str, str]:
    """(fast model id, strong model id) by family keyword - names come from the account's own list, none are hardcoded."""
    ids = [m["id"] for m in models]
    fast = next((i for i in ids if "haiku" in i.lower()), ids[-1] if ids else "")
    strong = next((i for k in ("opus", "sonnet") for i in ids if k in i.lower()), ids[0] if ids else "")
    return fast, strong


def _claude_api(cfg: dict):
    if not ui.yn("Do you have an Anthropic API key (from the Console, not a Claude.ai subscription)?", False):
        ui.console.print(SUBSCRIPTION_NOTE, markup=False)
        return "back"
    key = ui.ask("Anthropic API key (hidden)", "", password=True).strip()
    if not key:
        return "back"
    try:
        models = Anthropic(key, "").models()
    except LLMError as e:
        ui.fail(str(e))
        return "back"
    if not models:
        ui.fail("the account lists no models")
        return "back"
    fast, strong = _suggest(models)
    for i, m in enumerate(models[:25], 1):
        ui.console.print(f"  {i}) {m['display_name']}  [dim]{m['id']}[/dim]")
    ids = [m["id"] for m in models[:25]]
    ui.info(f"Suggestion: a small, fast model for bulk classification ({fast}) and a stronger one for chat ({strong}).")

    def pick(q, default):
        d = str(ids.index(default) + 1) if default in ids else "1"
        return ids[int(ui.choose(q, [str(i) for i in range(1, len(ids) + 1)], d)) - 1]
    fast_m = pick("Model for classification / summaries / dates (number)", fast)
    ents = [llmreg.new_entry(cfg, "claude", fast_m, key=key, roles=["classify", "summarize", "date_kind"])]
    if ui.yn("Use a stronger model for /chat and AI dorks?", True):
        strong_m = pick("Model for chat / dork generation (number)", strong)
        e2 = llmreg.new_entry(cfg, "claude", strong_m, key=key, roles=["chat", "dork_gen"])
        e2["id"] = _bump(ents[0]["id"])
        ents.append(e2)
    else:
        ents[0]["roles"] = list(ROLES)
    for e in ents:
        while True:
            try:
                ui.ok(f"{e['model']} replied: {Anthropic(key, e['model']).test()!r}")
                break
            except LLMError as ex:
                ui.fail(str(ex))
                c = _retry()
                if c == "s":
                    return None
                if c == "k":
                    break
    return ents


def _bump(mid: str) -> str:
    return "m" + str(int(mid[1:]) + 1)


def _claude_cli(cfg: dict):
    """Claude subscription via the official CLI. Before ANY question: is the binary there, is it signed in with something that
    includes Claude Code? If not, one plain-words message and back to step 1. Then the two-line warning + y/n."""
    b = claudecli.binary()
    if not b:
        ui.console.print(claudecli.WHO_CAN_USE, markup=False)
        return "back"
    flags = claudecli.detect_flags(claudecli.help_text(b))
    try:
        claudecli.build_args(b, flags)
    except LLMError as e:
        ui.fail(str(e))
        return "back"
    info = claudecli.auth_info(b)
    if info["kind"] == "none":
        ui.info("You are not logged in. Log in once with the official Claude Code app.")
        if claudecli.auth_commands(b)["login"]:
            if ui.yn("Launch the official login now (it runs in this terminal; qurihunter never sees what you type)?", True):
                claudecli.run_login(b)
                info = claudecli.auth_info(b)
        else:
            ui.console.print("Run `claude` in a terminal and follow its login prompt, then come back.", markup=False)
    if info["kind"] in ("none", "free"):  # still no login, or an account without Claude Code
        ui.console.print(claudecli.WHO_CAN_USE, markup=False)
        return "back"
    if info["kind"] == "api_key":
        ui.info(claudecli.API_KEY_NOTE)
    ui.console.print("\n" + claudecli.CONSENT_SHORT + "\n", markup=False)
    if not ui.yn("Use it?", False):
        ui.info("Not enabled - nothing was added.")
        return "back"
    cfg["claude_cli_allow_bulk"] = True  # the user said yes: it may take bulk jobs, through batching and caps
    e = llmreg.new_entry(cfg, "claude_cli", "claude (CLI)", roles=list(ROLES), consent=True)
    e["_auto"] = True  # roles = every role, first in the order; no further questions
    return e


def ask_roles(entry: dict) -> list[str]:
    allowed = llmreg.CLI_ROLES if entry["type"] == "claude_cli" else ROLES
    ui.info("Roles: classify (page classification), summarize (alert summaries), dork_gen (AI dorks), chat (/chat), "
            "date_kind (date disambiguation), validate (reads a candidate's page before it alerts; bulk-like, so the Claude CLI "
            "takes it only with /llm bulk on).")
    raw = ui.ask(f"Roles for {entry['model']} (comma separated, Enter = {'all allowed' if entry['type'] != 'claude_cli' else 'chat, summarize, dork_gen'})",
                 "").strip()
    if not raw:
        return list(allowed)
    chosen = [r.strip() for r in raw.replace(" ", ",").split(",") if r.strip()]
    ok = [r for r in chosen if r in allowed]
    for r in chosen:
        if r not in allowed:
            ui.fail(f"ignored '{r}' (not an allowed role)")
    return ok or list(allowed)


def add_model_wizard(cfg: dict, save=None) -> list[dict]:
    """One question at a time. Returns the entries added."""
    while True:
        ui.console.print(STEP1)
        c = ui.choose("Choice", ["1", "2", "3", "4"], "1")
        res = {"1": _local, "2": _api, "3": _claude_api, "4": _claude_cli}[c](cfg)
        if res == "back":
            continue
        if res is None:
            return []
        ents = res if isinstance(res, list) else [res]
        break
    if len(ents) == 1 and ents[0].get("_auto"):  # Claude CLI: no questions about roles or position
        e = ents[0]
        e.pop("_auto")
        llmreg.add_model(cfg, e, 1)  # first for all roles; the existing models stay behind it as fallbacks
        if save:
            save(cfg)
        _finish_cli(cfg, e)
        return ents
    if len(ents) == 1:
        ents[0]["roles"] = ask_roles(ents[0])
    n = len(cfg.get("models", []))
    pos_raw = ui.ask(f"Add to the failover order at which position? (1-{n + 1}, Enter = last, n = keep it out of the order)", "").strip().lower()
    for e in ents:
        pos = int(pos_raw) if pos_raw.isdigit() else None
        if pos_raw == "n":
            e["enabled"] = False
        llmreg.add_model(cfg, e, pos)
    if save:
        save(cfg)
    for e in ents:
        ui.ok(f"added {e['id']}: {llmreg.describe(e)} - roles {', '.join(e['roles'])} - key {llmreg.key_hint(e)}")
    return ents


def limits_text(cfg: dict) -> str:
    c = cfg["claude_cli"]
    return (f"{c['calls_per_hour']} calls/hour, {c['calls_per_day']} calls/day, {c['min_interval_s']} s between calls, "
            f"{c['batch_size']} pages per classification call (change: /llm limits)")


def _finish_cli(cfg: dict, e: dict) -> None:
    """One test call and the active limits, once."""
    r = llmreg.Router(cfg)
    try:
        ui.ok(f"{e['id']} Claude CLI replied: {r.test_model(e['id'])!r}")
    except LLMError as ex:
        ui.fail(f"test call failed: {ex} (it stays added; the local model keeps working as fallback)")
    others = [m for m in cfg["models"] if m["id"] != e["id"] and m.get("enabled")]
    ui.ok(f"added {e['id']}: Claude via official CLI - all roles, first in the order"
          + (f", {', '.join(m['id'] for m in others)} kept as fallback" if others else "") + f". Limits: {limits_text(cfg)}")


def manual_step(cfg: dict, save) -> None:
    """Manual-mode first run: add models until the user stops."""
    while ui.yn("Add a model now (local / API / Claude)?", not cfg.get("models")):
        add_model_wizard(cfg, save)
        if not ui.yn("Add another model?", False):
            break


# ───────────────────────────── /model ─────────────────────────────
def models_table(cfg: dict) -> Table:
    t = Table(title="Models (role order = this order)", header_style="bold")
    for c in ("ID", "#", "Type", "Model", "On", "Roles", "Key", "Price in/out $/Mtok", "Login"):
        t.add_column(c, overflow="fold")
    login = claudecli.login_label(claudecli.binary()) if any(m["type"] == "claude_cli" for m in cfg.get("models", [])) else ""
    for m in sorted(cfg.get("models", []), key=lambda x: x["order"]):
        price = "-" if m.get("price_in") is None and m.get("price_out") is None else f"{m.get('price_in')}/{m.get('price_out')}"
        t.add_row(m["id"], str(m["order"]), m["type"] + (" (free)" if m.get("free") and m["type"] != "local" else ""),
                  m["model"], "yes" if m.get("enabled") else "no", ",".join(m.get("roles", [])), llmreg.key_hint(m), price,
                  login if m["type"] == "claude_cli" else "-")
    return t


USAGE = ("usage: /model [list | add | info | remove <id> | test [id] | roles <id> <roles...> | order [<id> <position>] | "
         "enable|disable <id>]")


def cmd_model(ctx, args):
    cfg = ctx.cfg
    sub = args[0] if args else ""
    if not sub:
        return _manager(ctx)
    if sub == "list":
        ui.console.print(models_table(cfg)) if cfg.get("models") else ui.info("No models configured: /model add")
    elif sub == "add":
        add_model_wizard(cfg, ctx.save)
    elif sub == "remove" and len(args) == 2:
        (ui.ok if llmreg.remove_model(cfg, args[1]) else ui.fail)(f"removed {args[1]}" if get_(cfg, args[1]) is None else "no such model")
        ctx.save(cfg)
    elif sub == "test":
        _test(ctx, args[1] if len(args) > 1 else None)
    elif sub == "roles" and len(args) >= 3:
        err = llmreg.set_roles(cfg, args[1], [r.strip(",") for r in args[2:]], confirm=lambda q: ui.yn(q, False))
        (ui.fail(err) if err else ui.ok(f"{args[1]} roles: {', '.join(llmreg.get(cfg, args[1])['roles'])}"))
        ctx.save(cfg)
    elif sub == "order":
        if len(args) == 3 and args[2].isdigit():
            (ui.ok("order updated") if llmreg.move(cfg, args[1], int(args[2])) else ui.fail("no such model"))
            ctx.save(cfg)
        ui.console.print(models_table(cfg))
    elif sub in ("enable", "disable") and len(args) == 2:
        m = llmreg.get(cfg, args[1])
        if not m:
            ui.fail("no such model")
            return
        m["enabled"] = sub == "enable"
        llmreg.sync_legacy(cfg)
        ctx.save(cfg)
        ui.ok(f"{args[1]} {sub}d")
    elif sub == "info":
        _info(ctx)
    elif sub == "legacy":  # the old Ollama-only menu
        from . import wizard
        wizard.model_menu(cfg)
        ctx.save(cfg)
    else:
        ui.fail(USAGE)


def _info(ctx) -> None:
    cfg = ctx.cfg
    ui.console.print("[bold]Claude subscription via the official Claude Code CLI (experimental, optional, off by default)[/bold]")
    ui.console.print(claudecli.CONSENT_TEXT, markup=False)
    b = claudecli.binary()
    if not b:
        ui.info("Status: the `claude` command is not installed.")
    else:
        ui.info(f"Status: installed; login: {claudecli.login_label(b)}"
                + (" - calls are billed per token by Anthropic; /llm status counts calls only"
                   if claudecli.auth_info(b)["kind"] == "api_key" else ""))
    ui.info("Limits: " + limits_text(cfg) + "; roles: all; bulk jobs allowed through batching: "
            + ("yes" if cfg.get("claude_cli_allow_bulk") else "no (claude_cli_allow_bulk is off)"))


def get_(cfg, mid):
    return llmreg.get(cfg, mid)


def _manager(ctx) -> None:
    cfg = ctx.cfg
    while True:
        if cfg.get("models"):
            ui.console.print(models_table(cfg))
        else:
            ui.info("No models configured yet (heuristics only).")
        ui.console.print("  1) add a model (wizard)  2) remove  3) test  4) roles  5) order  6) local Ollama tools  7) back")
        c = ui.choose("Choice", ["1", "2", "3", "4", "5", "6", "7"], "7")
        try:
            if c == "1":
                add_model_wizard(cfg, ctx.save)
            elif c == "2":
                cmd_model(ctx, ["remove", ui.ask("Model id (e.g. m1)")])
            elif c == "3":
                _test(ctx, ui.ask("Model id (blank = every enabled model, one call each)", "").strip() or None)
            elif c == "4":
                cmd_model(ctx, ["roles", ui.ask("Model id"), *ui.ask("Roles (space separated)").split()])
            elif c == "5":
                cmd_model(ctx, ["order", ui.ask("Model id"), ui.ask("New position")])
            elif c == "6":
                cmd_model(ctx, ["legacy"])
            else:
                return
        except KeyboardInterrupt:
            ui.console.print("[dim]cancelled[/dim]")
        ctx.save(cfg)


def _test(ctx, mid: str | None) -> None:
    """/model test [id]: exactly ONE call per tested model (never a retry loop, never a failover)."""
    cfg = ctx.cfg
    ids = [mid] if mid else [m["id"] for m in cfg.get("models", []) if m.get("enabled")]
    if not ids:
        ui.fail("no model configured: /model add")
        return
    r = llmreg.Router(cfg, ctx.db)
    for i in ids:
        try:
            ui.ok(f"{i}: replied {r.test_model(i)!r}")
        except LLMError as e:
            ui.fail(f"{i}: {e}")


# ───────────────────────────── /llm status ─────────────────────────────
def cmd_llm_bulk(ctx, args):
    """/llm bulk on|off - the single switch (config claude_cli_allow_bulk) for letting the Claude CLI take classify, date_kind and
    bulk jobs. Always runs through batching, caps and the local fallback."""
    cfg = ctx.cfg
    if not args or args[0] not in ("on", "off"):
        ui.info(f"Claude CLI bulk use is {'ON' if cfg.get('claude_cli_allow_bulk') else 'OFF'} - /llm bulk on|off")
        return
    on = args[0] == "on"
    if on and not cfg.get("claude_cli_allow_bulk"):
        c = cfg["claude_cli"]
        if not ui.yn(f"Allow the Claude CLI to take classification, dates and bulk jobs? Caps: {c['calls_per_hour']} calls/hour, "
                     f"{c['calls_per_day']}/day, batches of {c['batch_size']} pages per call; the local model stays as fallback.", False):
            ui.info("unchanged")
            return
    cfg["claude_cli_allow_bulk"] = on
    ctx.save(cfg)
    ui.ok(f"Claude CLI bulk use: {'ON' if on else 'OFF'}"
          + ("" if on else " (classify, date_kind and bulk jobs fall to the next model; roles stay assigned)"))


def cmd_llm(ctx, args):
    if args and args[0] == "bulk":
        return cmd_llm_bulk(ctx, args[1:])
    if args and args[0] == "limits":
        return cmd_llm_limits(ctx, args[1:])
    if args and args[0] == "prices":
        return cmd_llm_prices(ctx, args[1:])
    cfg, db = ctx.cfg, ctx.db
    if not cfg.get("models"):
        ui.info("No models configured (the legacy single LLM block is used, if any). Add one with /model add.")
        return
    rows = llmreg.usage_rows(db, cfg)
    t = Table(title="LLM usage per model", header_style="bold")
    for c in ("ID", "Model", "Calls", "OK", "Failed", "Tokens in/out", "Est. spend", "Today", "Month", "Last error"):
        t.add_column(c, overflow="fold")
    for r in rows:
        m = r["model"]
        tracked = m["type"] in llmreg.PAID_TYPES and not m.get("free") and (m.get("price_in") is not None or m.get("price_out") is not None)
        money = "calls only" if m["type"] == "claude_cli" else (f"${r['usd']:.4f}" if tracked else "-")
        t.add_row(m["id"], f"{m['type']}: {m['model']}", str(r["calls"]), str(r["ok"]), str(r["failed"]),
                  f"{r['tin']}/{r['tout']}", money, f"${r['today_usd']:.4f}" if tracked else "-",
                  f"${r['month_usd']:.4f}" if tracked else "-", r["last_error"])
    ui.console.print(t)
    if cfg.get("models"):  # which model answers each role right now (first unblocked one in the order)
        rt = Table(title="Role routing (order = failover order)", header_style="bold")
        rt.add_column("Role")
        rt.add_column("Models", overflow="fold")
        router = llmreg.Router(cfg, db)
        for role in ROLES:
            ents = router.entries(role)
            cells = []
            for m in ents:
                b = router.blocked(m, role)
                cells.append(m["id"] + (f" [skipped: {b}]" if b else ""))
            rt.add_row(role, " → ".join(cells) or "[yellow]none assigned[/yellow]"
                       + (" (finds go to NEEDS MANUAL CHECK as 'not validated')" if role == "validate" else ""))
        ui.console.print(rt)
    rr = llmreg.role_rows(db)
    if rr:
        t2 = Table(title="Per role", header_style="bold")
        for c in ("Role", "Model", "Calls", "Tokens", "Est. spend"):
            t2.add_column(c)
        for r in rr:
            t2.add_row(r["role"], r["model_id"], str(r["n"]), str(r["tok"]), f"${r['usd']:.4f}")
        ui.console.print(t2)
    st = llmreg.budget_state(db, cfg)
    ui.info(f"Budget: today ${st['day']:.4f} of ${st['day_limit']:.2f} ({st['day_pct']:.0f}%), month ${st['month']:.4f} of "
            f"${st['month_limit']:.2f} ({st['month_pct']:.0f}%) - warn at {st['warn_pct']:.0f}%, hard stop at 100% "
            "(then the next model, or no LLM work).")
    if max(st["day_pct"], st["month_pct"]) >= st["warn_pct"]:
        ui.fail("LLM spend is above the warning level.")
    for m in cfg["models"]:
        if m["type"] == "claude_cli":
            caps = cfg["claude_cli"]
            from datetime import timedelta
            from . import dates
            now = dates.utcnow()
            h = llmreg.calls_since(db, m["id"], dates.iso(now - timedelta(hours=1)))
            d = llmreg.calls_since(db, m["id"], dates.iso(now - timedelta(days=1)))
            stop = db.meta(f"llm_stop:{m['id']}")
            ui.info(f"{m['id']} Claude CLI (bulk use {'ON' if cfg.get('claude_cli_allow_bulk') else 'OFF'}): {h}/{caps['calls_per_hour']} calls this hour, {d}/{caps['calls_per_day']} today"
                    + (f"; STOPPED until {dates.to_local(stop)}" if stop and stop > dates.now_iso() else ""))


LIMIT_KEYS = {"hour": "calls_per_hour", "day": "calls_per_day", "interval": "min_interval_s", "batch": "batch_size"}


def cmd_llm_limits(ctx, args):
    """/llm limits [hour N] [day N] [interval S] [batch N] - the Claude CLI caps (shown and editable)."""
    c = ctx.cfg["claude_cli"]
    i = 0
    while i + 1 < len(args):
        k, v = args[i], args[i + 1]
        if k not in LIMIT_KEYS or not v.isdigit() or int(v) < (1 if k != "interval" else 0):
            ui.fail("usage: /llm limits [hour N] [day N] [interval SECONDS] [batch N]")
            return
        c[LIMIT_KEYS[k]] = int(v)
        i += 2
    if i < len(args) or (args and i == 0):
        ui.fail("usage: /llm limits [hour N] [day N] [interval SECONDS] [batch N]")
        return
    if args:
        ctx.save(ctx.cfg)
    ui.info("Claude CLI limits: " + limits_text(ctx.cfg))


def cmd_llm_prices(ctx, args):
    """/llm prices <id> <in> <out> (USD per million tokens) | /llm prices <id> free|paid - optional cost tracking."""
    m = llmreg.get(ctx.cfg, args[0]) if args else None
    if not m or m["type"] in ("local", "claude_cli"):
        ui.fail("usage: /llm prices <api-or-claude model id> <input $/Mtok> <output $/Mtok>  |  <id> free | paid")
        return
    try:
        if len(args) == 2 and args[1] in ("free", "paid"):
            m["free"] = args[1] == "free"
        elif len(args) == 3:
            m["price_in"], m["price_out"] = float(args[1]), float(args[2])
        else:
            raise ValueError
    except ValueError:
        ui.fail("usage: /llm prices <id> <input $/Mtok> <output $/Mtok>  |  <id> free | paid")
        return
    ctx.save(ctx.cfg)
    ui.ok(f"{m['id']}: " + ("free" if m.get("free") else f"price in/out = {m.get('price_in')}/{m.get('price_out')} $/Mtok"))
