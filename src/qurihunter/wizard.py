from __future__ import annotations

import subprocess
import sys

import requests
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn

from . import checks, config, hardware, modelcmds, search, ui
from .llm import DEFAULT_HOST, LLMError, Ollama
from .sources import dorks as dorklib

PREFERRED = ("llama3.1", "mistral", "phi3", "qwen2.5", "llama3", "gemma")


# ───────────────────────────── local LLM ─────────────────────────────
def _pull_with_bar(o: Ollama, model: str) -> bool:
    ui.info(f"Downloading [bold]{model}[/bold] (this can take a few minutes)…")
    with Progress(TextColumn("{task.description}"), BarColumn(), DownloadColumn(), TransferSpeedColumn(),
                  console=ui.console) as prog:
        task = prog.add_task("starting", total=None)

        def cb(status, done, total):
            prog.update(task, description=status[:28], completed=done, total=total or None)
        try:
            o.pull(model, cb)
        except (LLMError, requests.RequestException) as e:
            ui.fail(f"download failed: {e}")
            return False
    return True


def _ensure_running(o: Ollama) -> bool:
    if o.running():
        return True
    if Ollama.installed():
        ui.info("Ollama is installed but not running — starting it…")
        if o.try_start():
            return True
        ui.fail("could not start `ollama serve`")
        return False
    ui.info("Ollama is not installed.")
    if sys.platform in ("linux", "darwin") and ui.yn("Install Ollama now (runs the official script from ollama.com)?", False):
        subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True)
        if Ollama.installed():
            return o.running() or o.try_start()
    else:
        ui.info("Install manually from https://ollama.com/download, then run /model.")
    return False


def setup_llm(cfg: dict, hw: hardware.Hardware | None = None, *, force_auto: bool = False) -> bool:
    """Detect/choose/download a model. Returns True if an LLM ended up configured and passing."""
    hw = hw or hardware.detect()
    o = Ollama(cfg["llm"]["host"] or DEFAULT_HOST)
    if not _ensure_running(o):
        cfg["llm"]["enabled"] = False
        ui.info("Continuing without a local LLM — classification falls back to heuristics.")
        return False
    model = ""
    installed = o.models()
    if installed and not force_auto:
        ranked = sorted(installed, key=lambda m: next((i for i, p in enumerate(PREFERRED) if m.startswith(p)), 99))
        ui.info(f"Found a running Ollama with models: {', '.join(installed)}")
        if ui.yn(f"Use this one? ({ranked[0]})", True):
            model = ranked[0]
    if not model:
        model, why = hardware.recommend_model(hw)
        ui.info(f"Auto-selected [bold]{model}[/bold] — {why}")
        if not o.has(model) and not _pull_with_bar(o, model):
            cfg["llm"]["enabled"] = False
            return False
    cfg["llm"].update(enabled=True, host=o.host, model=model, backend="ollama")
    return _test_llm_loop(cfg)


def _test_llm_loop(cfg: dict) -> bool:
    while True:
        name, passed, detail = checks.llm_cfg(cfg)
        (ui.ok if passed else ui.fail)(f"{name}: {detail}")
        if passed:
            return True
        c = ui.choose("(r)etry, (m)odel menu, (d)isable LLM", ["r", "m", "d"], "r")
        if c == "d":
            cfg["llm"]["enabled"] = False
            return False
        if c == "m":
            model_menu(cfg)
            if not cfg["llm"]["enabled"]:
                return False


def setup_openai(cfg: dict) -> bool:
    """Any OpenAI-compatible endpoint. The API key is stored in the (chmod 600) config only — never logged or
    placed in prompts. Search-provider keys are separate from this one."""
    l = cfg["llm"]
    ui.info("Enter an OpenAI-compatible endpoint, e.g. https://api.openai.com/v1 or your own relay.")
    while True:
        l["base_url"] = ui.ask("Base URL (ending in /v1)", l.get("base_url", "")).strip().rstrip("/")
        l["api_key"] = ui.ask("API key (Enter to keep / none)", l.get("api_key", ""), password=True).strip()
        l["model"] = ui.ask("Model name", l.get("model", "")).strip()
        l["backend"], l["enabled"] = "openai", True
        name, passed, detail = checks.llm_cfg(cfg)
        (ui.ok if passed else ui.fail)(f"{name}: {detail}")
        if passed:
            return True
        c = ui.choose("(r)e-enter, (k)eep anyway, (d)isable LLM", ["r", "k", "d"], "r")
        if c == "k":
            return False
        if c == "d":
            l["enabled"] = False
            return False


def model_menu(cfg: dict) -> None:
    hw = hardware.detect()
    ui.console.print(f"[dim]{hw.describe()}[/dim]")
    l = cfg["llm"]
    cur = ("disabled" if not l["enabled"] else f"API {l['model']} @ {l.get('base_url', '')}"
           if l.get("backend") == "openai" else f"local {l['model']} @ {l['host']}")
    ui.info(f"Current LLM: {cur}")
    ui.console.print("  1) re-run hardware-based auto selection\n  2) pick from installed models\n"
                     "  3) enter a model name (downloads if missing)\n  4) change Ollama host\n  5) disable LLM\n"
                     "  7) use an OpenAI-compatible API (hosted provider or your own relay/proxy)\n  6) back")
    c = ui.choose("Choice", ["1", "2", "3", "4", "5", "6", "7"], "6")
    if c == "7":
        setup_openai(cfg)
        return
    o = Ollama(cfg["llm"]["host"])
    if c == "1":
        setup_llm(cfg, hw, force_auto=True)
    elif c == "2":
        if not _ensure_running(o):
            return
        ms = o.models()
        if not ms:
            ui.fail("no models installed")
            return
        for i, m in enumerate(ms, 1):
            ui.console.print(f"  {i}) {m}")
        idx = ui.choose("Model number", [str(i) for i in range(1, len(ms) + 1)])
        cfg["llm"].update(enabled=True, model=ms[int(idx) - 1], backend="ollama")
        _test_llm_loop(cfg)
    elif c == "3":
        name = ui.ask("Model name (e.g. llama3.1:8b, mistral:7b, phi3:mini)").strip()
        if not name or not _ensure_running(o):
            return
        if not o.has(name) and not _pull_with_bar(o, name):
            return
        cfg["llm"].update(enabled=True, model=name, backend="ollama")
        _test_llm_loop(cfg)
    elif c == "4":
        cfg["llm"]["host"] = ui.ask("Ollama host URL", cfg["llm"]["host"]).strip()
        if cfg["llm"]["model"]:
            _test_llm_loop(cfg)
    elif c == "5":
        cfg["llm"]["enabled"] = False


# ───────────────────────────── notifications ─────────────────────────────
def _retry_prompt() -> str:
    return ui.choose("(r)e-enter, (k)eep anyway, (s)kip", ["r", "k", "s"], "r")


def setup_telegram(cfg: dict) -> bool:
    t = cfg["notify"]["telegram"]
    ui.info("Create a bot with @BotFather to get a token, then send your bot any message.")
    while True:
        t["token"] = ui.ask("Telegram bot API token", t["token"], password=True).strip()
        t["chat_id"] = ui.ask("Chat ID (leave blank to auto-detect from your latest message to the bot)",
                              t["chat_id"]).strip()
        if not t["chat_id"] and t["token"]:
            try:
                ups = requests.get(f"https://api.telegram.org/bot{t['token']}/getUpdates", timeout=15).json()
                chats = [u["message"]["chat"]["id"] for u in ups.get("result", []) if "message" in u]
                if chats:
                    t["chat_id"] = str(chats[-1])
                    ui.ok(f"detected chat id {t['chat_id']}")
                else:
                    ui.fail("no messages found — send something to your bot first")
            except (requests.RequestException, ValueError, KeyError) as e:
                ui.fail(f"auto-detect failed: {e}")
        name, passed, detail = checks.telegram(t["token"], t["chat_id"])
        (ui.ok if passed else ui.fail)(f"{name}: {detail}")
        if passed:
            return True
        c = _retry_prompt()
        if c == "k":
            return True
        if c == "s":
            return False


def setup_email(cfg: dict) -> bool:
    e = cfg["notify"]["email"]
    ui.info("Gmail needs an App Password (Google Account → Security → 2-Step Verification → App passwords).")
    while True:
        e["address"] = ui.ask("Gmail address", e["address"]).strip()
        e["app_password"] = ui.ask("Gmail app password", e["app_password"], password=True).strip()
        e["to"] = ui.ask("Send alerts to", e["to"] or e["address"]).strip()
        name, passed, detail = checks.email(e["address"], e["app_password"], e["to"])
        (ui.ok if passed else ui.fail)(f"{name}: {detail}")
        if passed:
            return True
        c = _retry_prompt()
        if c == "k":
            return True
        if c == "s":
            return False


def setup_notifications(cfg: dict) -> None:
    choice = ui.choose("Notification channel — (e)mail, (t)elegram or (b)oth", ["e", "t", "b"], "t")
    chans = []
    if choice in ("t", "b") and setup_telegram(cfg):
        chans.append("telegram")
    if choice in ("e", "b") and setup_email(cfg):
        chans.append("email")
    cfg["notify"]["channels"] = chans


# ───────────────────────────── search provider keys ─────────────────────────────
def pick_provider(cfg: dict) -> str | None:
    ui.console.print("\n[bold]Search providers[/bold] (used for self-hosted program discovery)")
    ids = list(search.PROVIDERS)
    for i, pid in enumerate(ids, 1):
        cls = search.PROVIDERS[pid]
        n = len((cfg["search"]["providers"].get(pid) or {}).get("keys", []))
        ui.console.print(f"  {i}) [bold]{cls.label}[/bold]  [dim]{n} key(s)[/dim]\n     [dim]{cls.help}[/dim]")
    ui.console.print(f"  {len(ids) + 1}) back")
    c = ui.choose("Provider", [str(i) for i in range(1, len(ids) + 2)], "1")
    return None if int(c) == len(ids) + 1 else ids[int(c) - 1]


def setup_keys(cfg: dict, pid: str | None = None, db=None) -> None:
    """Add/test/remove keys for a provider. The only per-key question is "requests per day"; quota type and allowance come
    from the internal defaults table or the provider's own account endpoint."""
    from . import keysetup
    pid = pid or pick_provider(cfg)
    if not pid:
        return
    cls = search.PROVIDERS[pid]
    pc = search.provider_cfg(cfg, pid)
    ui.info(f"[bold]{cls.label}[/bold]: {cls.limitations}")
    for opt, prompt in cls.extra_fields.items():  # e.g. Google's cx, SearXNG's base_url
        if not pc.get(opt):
            pc[opt] = ui.ask(prompt).strip()
    if not cls.needs_key:  # SearXNG: no key, no quota - probe the instance instead
        pc.setdefault("keys", [])
        pc["quota_type"] = "unlimited"
        ok, detail = search.make(cfg, pid).probe()
        (ui.ok if ok else ui.fail)(f"{cls.label}: {detail}")
        if not ok:
            ui.info("Need an instance? /searxng setup prints a ready docker-compose.yml + settings.yml (it never runs docker).")
        return
    keysetup.apply_defaults(cfg, pid)
    d = search.defaults.default_for(pid)
    if d:
        ui.info(f"Plan assumed: {d.quota_type} {d.allowance if d.allowance is not None else ''}"
                f"{'' if d.verified else ' (unverified)'} - {d.source} [{d.date}]. Change later: /providers set {pid} allowance|type <value>")
    if pc["keys"]:
        ui.info(f"{len(pc['keys'])} key(s) configured. Retesting them first…")
        for k in list(pc["keys"]):
            n, p, dd = checks.search_key(cfg, pid, k)
            (ui.ok if p else ui.fail)(f"{n}: {dd}")
        if ui.yn("Remove any key?", False):
            for i, k in enumerate(pc["keys"], 1):
                ui.console.print(f"  {i}) {config.mask(k)}")
            n = ui.ask("Numbers to remove (comma separated)").replace(" ", "")
            drop = {int(x) - 1 for x in n.split(",") if x.isdigit()}
            pc["keys"] = [k for i, k in enumerate(pc["keys"]) if i not in drop]
    first = not pc["keys"]
    while True:
        if not first and not ui.yn("Add another API key?", False):  # teammates' keys: each gets its own daily cap
            break
        first = False
        key = ui.ask(f"{cls.label} API key", password=True).strip()
        if not key:
            continue
        if key in pc["keys"]:
            ui.fail("that key is already configured")
            continue
        name, passed, detail = checks.search_key(cfg, pid, key)
        (ui.ok if passed else ui.fail)(f"{name}: {detail}")
        keep = passed
        if not passed:
            c = _retry_prompt()
            keep = c == "k"
            if c == "s" and not pc["keys"] and not ui.yn("Try another key?", True):
                break
        if keep:
            pc["keys"].append(key)
            res = keysetup.configure_key(cfg, pid, key, db)
            ui.ok(f"key {config.mask(key)}: {keysetup.describe(res)}")
    tot = keysetup.total_per_day(cfg, pid)
    ui.info(f"{cls.label}: {len(pc['keys'])} key(s)" + (f" - {tot} requests per day in total" if tot else "")
            + f" ({pc.get('quota_type', cls({}).quota_type())}). Keys are used in the order added; a reached daily cap pauses "
              "that key until local midnight and the sequence moves on. Change: /providers daily " + pid + " [key] <n>")
    if len(search.configured(cfg)) > 1:
        search_order_menu(cfg)


def search_order_menu(cfg: dict) -> None:
    """"Search order": move providers up/down, enable/disable, pick the mode."""
    while True:
        order = search.sequence_order(cfg)
        ui.console.print("\n[bold]Search order[/bold] (searches run top to bottom; mode: "
                         f"{cfg.get('search_mode', 'failover')})")
        for i, e in enumerate(search.sequence_entries(cfg), 1):
            st = "[green]ready[/green]" if e["configured"] and e["enabled"] else ("[dim]disabled[/dim]" if e["configured"] else "[dim]not configured[/dim]")
            ui.console.print(f"  {i}) {search.PROVIDERS[e['provider']].label}  {st}  [dim]{e['role']}[/dim]")
        c = ui.choose("(u)p, (d)own, (t)oggle on/off, (m)ode, (b)ack", ["u", "d", "t", "m", "b"], "b")
        if c == "b":
            return
        if c == "m":
            from .sequence import MODES
            m = ui.choose("Mode: failover (first usable provider), cascade (add providers until enough results), sweep "
                          "(every provider, most quota)", list(MODES), cfg.get("search_mode", "failover"))
            if m == "sweep" and not ui.yn("Sweep spends every provider's quota on every dork. Enable it?", False):
                continue
            cfg["search_mode"] = m
            cfg["sweep_confirmed"] = cfg.get("sweep_confirmed") or m == "sweep"
            continue
        n = ui.ask("Provider number", "1").strip()
        if not n.isdigit() or not 1 <= int(n) <= len(order):
            continue
        i = int(n) - 1
        if c == "t":
            pid = order[i]
            search.save_sequence(cfg, order, {pid: not search.is_enabled(cfg, pid)})
        else:
            j = i - 1 if c == "u" else i + 1
            if 0 <= j < len(order):
                order[i], order[j] = order[j], order[i]
                search.save_sequence(cfg, order)


# ───────────────────────────── filters ─────────────────────────────
def filters_menu(cfg: dict) -> None:
    f = cfg["filters"]
    ui.console.print(f"Platforms available: {', '.join(config.PLATFORMS)}  (web = self-hosted dorks & custom feeds)")
    v = ui.ask("Platforms (comma separated, blank = all)", ",".join(f["platforms"])).lower().replace(" ", "")
    sel = [x for x in v.split(",") if x]
    bad = [x for x in sel if x not in config.PLATFORMS]
    if bad:
        ui.fail(f"ignored unknown platforms: {', '.join(bad)}")
    f["platforms"] = [x for x in sel if x in config.PLATFORMS]
    v = ui.ask("Countries as 2-letter codes, e.g. ch,se (blank = all)", ",".join(f["countries"])).lower()
    ccs = [dorklib.normalize_cc(x) for x in v.replace(" ", "").split(",") if x]
    bad = [c for c in ccs if not dorklib.valid_cc(c)]
    if bad:
        ui.fail(f"ignored invalid codes: {', '.join(bad)}")
    f["countries"] = [c for c in ccs if dorklib.valid_cc(c)]
    v = ui.ask(f"Categories ({', '.join(config.CATEGORIES)}; blank = all)", ",".join(f["categories"])).lower()
    f["categories"] = [c for c in v.replace(" ", "").split(",") if c in config.CATEGORIES]
    while True:
        v = ui.ask("Minimum reward (0 = none; programs with unknown reward always pass)", str(f["min_reward"]))
        try:
            f["min_reward"] = max(0.0, float(v))
            break
        except ValueError:
            ui.fail("enter a number")


def recency_menu(cfg: dict) -> None:
    from . import dates
    cur = dates.window_text(config.recency_days(cfg))
    while True:
        v = ui.ask("Recency window (days, 24h, 7d, 30d, 1y or 'any'; only newer programs alert)", cur)
        try:
            cfg["recency_days"] = dates.parse_window(v)
            break
        except ValueError as e:
            ui.fail(str(e))
    sr = cfg["dork_search_recency"]
    ui.info(f"The alert window is applied AFTER discovery. What the search providers are asked for is separate: first run "
            f"{sr['first']}, later runs {sr['later']}, sweep {sr['sweep']} ({int(sr['sweep_share'] * 100)}% of a batch).")
    if ui.yn("Change the SEARCH recency too?", False):
        for k, label in (("first", "First run of a dork"), ("later", "Later runs"), ("sweep", "Recent-only sweep")):
            v = ui.ask(f"{label} (any, day, week, month, year or Nd)", sr[k]).strip().lower()
            try:
                dates.parse_window({"week": "7d", "month": "31d", "year": "365d", "day": "1d"}.get(v, v))
                sr[k] = v
            except ValueError:
                ui.fail("not understood; unchanged")


def dorks_menu(cfg: dict, db=None) -> None:
    from . import dorkstore
    d = cfg["dorks"]
    ui.info(f"Dork source is '{d['source']}' (default = built-in list, custom = your own file, both). Switching never deletes anything.")
    d["source"] = ui.choose("Dork source", list(dorkstore.MODES), d["source"])
    if d["source"] in ("custom", "both") and ui.yn("Import a custom dork file now?", True):
        from pathlib import Path
        path = Path(ui.ask("Path to dork file").strip()).expanduser()
        if not path.exists():
            ui.fail(f"not found: {path}")
        elif db is not None:
            ui.ok(dorkstore.import_file(db, path, "custom").text())
    cfg["features"]["ai_dorks"] = ui.yn("Let the LLM invent extra dorks (validated, max 20% of quota)?",
                                        cfg["features"]["ai_dorks"])
    cfg["features"]["chat"] = ui.yn("Enable /chat?", cfg["features"]["chat"])


def alerts_menu(cfg: dict) -> None:
    a, w = cfg["alerts"], cfg["wayback"]
    a["alert_updated_only_pages"] = ui.yn("Also alert RECENTLY UPDATED pages (only a last-updated/effective date in the window)?",
                                          a["alert_updated_only_pages"])
    a["show_skipped_in_digest"] = ui.yn("List 'OLD, skipped' items in the digest?", a["show_skipped_in_digest"])
    a["telegram_scan_summary"] = ui.choose("Telegram scan summary (off | changes_only | daily heartbeat)",
                                           ["off", "changes_only", "daily"], a["telegram_scan_summary"])
    w["enabled"] = ui.yn("Check new candidates against the Wayback Machine (first capture)?", w["enabled"])
    try:
        share = float(ui.ask("Share of dork queries run WITHOUT the provider date filter, 0-30 (%)",
                             str(int(cfg["dorks"]["unfiltered_share"] * 100))))
        cfg["dorks"]["unfiltered_share"] = min(0.30, max(0.0, share / 100))
    except ValueError:
        ui.fail("not a number; unchanged")


# ───────────────────────────── /config menu ─────────────────────────────
def config_menu(cfg: dict, save, db=None) -> None:
    while True:
        ui.console.print("\n[bold]/config[/bold]\n  1) Notification channel (Email / Telegram)\n"
                         "  2) Crawling API keys (Brave / Tavily / Google)\n  3) Filters (platforms / countries / reward)\n"
                         "  4) Schedule intervals\n  6) Recency window\n  7) Dorks (source, AI dorks, chat)\n"
                         "  8) LLM (local Ollama or OpenAI-compatible API)\n  9) Alerts (updated pages, summary, Wayback, unfiltered sweep)\n  5) Done")
        c = ui.choose("Choice", ["1", "2", "3", "4", "5", "6", "7", "8", "9"], "5")
        try:
            if c == "1":
                setup_notifications(cfg)
            elif c == "2":
                setup_keys(cfg, db=db)
                if len(search.configured(cfg, include_disabled=True)) > 1 or ui.yn("Change the search order / mode?", False):
                    search_order_menu(cfg)
            elif c == "3":
                filters_menu(cfg)
            elif c == "4":
                s = cfg["schedule"]
                s["platform_interval_min"] = _int("Platform poll interval (minutes)", s["platform_interval_min"], 5)
                s["dork_interval_min"] = _int("Dork batch interval (minutes)", s["dork_interval_min"], 10)
            elif c == "6":
                recency_menu(cfg)
            elif c == "7":
                dorks_menu(cfg, db)
            elif c == "8":
                from types import SimpleNamespace
                modelcmds._manager(SimpleNamespace(cfg=cfg, save=save, db=db))
            elif c == "9":
                alerts_menu(cfg)
        except KeyboardInterrupt:
            ui.console.print("[dim]cancelled[/dim]")
        save(cfg)
        if c == "5":
            break
    ui.console.print(ui.config_summary(cfg))


def _int(q: str, default: int, minimum: int) -> int:
    while True:
        try:
            return max(minimum, int(ui.ask(q, str(default))))
        except ValueError:
            ui.fail("enter a whole number")


# ───────────────────────────── first run ─────────────────────────────
def auto_alert_prompt(cfg: dict) -> None:
    """Auto mode: no channel configured -> one clear warning and ONE optional question (a Telegram bot token)."""
    n = cfg["notify"]
    if n["channels"]:
        return
    ui.console.print("\n[bold yellow]⚠ No alert channel is configured — new programs will be found but you will NOT be "
                     "notified.[/bold yellow]")
    token = ui.ask("Telegram bot token to enable alerts now (Enter to skip; /config can do this later)",
                   password=True).strip()
    if not token:
        ui.info("Skipped. Run /config → 1 to add Telegram or email at any time.")
        return
    t = n["telegram"]
    t["token"], t["chat_id"] = token, ""
    try:
        ups = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=15).json()
        chats = [u["message"]["chat"]["id"] for u in ups.get("result", []) if "message" in u]
        if chats:
            t["chat_id"] = str(chats[-1])
    except (requests.RequestException, ValueError, KeyError):
        pass
    if not t["chat_id"]:
        ui.fail("Token saved, but no chat found yet. Send any message to your bot, then run /config → 1 to finish.")
        t["token"] = ""
        return
    name, passed, detail = checks.telegram(t["token"], t["chat_id"])
    (ui.ok if passed else ui.fail)(f"{name}: {detail}")
    if passed:
        n["channels"] = ["telegram"]
    else:
        t["token"] = t["chat_id"] = ""


def first_run(cfg: dict, save) -> None:
    ui.console.rule("[bold]First-run setup")
    hw = hardware.detect()
    ui.info(hw.describe())
    mode = ui.choose("Setup mode — (a)uto (no more questions) or (m)anual", ["a", "m"], "a")
    if mode == "a":
        setup_llm(cfg, hw)  # Auto: detect Ollama / hardware, no wizard questions
        if cfg["llm"]["enabled"] and not cfg.get("models"):
            m = config._legacy_model(cfg["llm"])
            cfg["models"] = [m] if m else []
        save(cfg)
        cfg["mode"] = "auto"
        cfg["filters"] = {"platforms": [], "countries": [], "min_reward": 0, "categories": []}
        cfg["recency_days"] = 7
        cfg["dorks"]["source"] = "default"
        ui.ok("Auto mode: all platforms, all countries, all categories, no filters, 7-day window, default dorks.")
        save(cfg)
        auto_alert_prompt(cfg)
    else:
        cfg["mode"] = "manual"
        modelcmds.manual_step(cfg, save)  # Manual: the add-model wizard (local / API / Claude ...)
        filters_menu(cfg)
        if ui.yn("Add search API key(s) (Serper / Tavily / Brave / Exa / SearXNG / Google) for self-hosted program discovery?", True):
            setup_keys(cfg)
        cfg["recency_days"] = 7
        recency_menu(cfg)
        dorks_menu(cfg)
        if ui.yn("Set up notifications now?", True):
            setup_notifications(cfg)
    cfg["setup_done"] = True
    save(cfg)
    ui.console.print(ui.config_summary(cfg))
