from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

console = Console()


def banner(version: str = "") -> None:
    console.print(Panel(Text.from_markup(
        f"[bold cyan]qurihunter[/bold cyan] {version} — bug bounty & VDP discovery agent\n"
        "[dim]type /help for commands · /config to set up notifications and API keys[/dim]"),
        border_style="cyan", expand=False))


def yn(question: str, default: bool = True) -> bool:
    return Confirm.ask(f"[bold]{question}[/bold]", default=default, console=console)


def ask(question: str, default: str = "", password: bool = False) -> str:
    return Prompt.ask(f"[bold]{question}[/bold]", default=default or None, password=password,
                      console=console, show_default=bool(default) and not password) or ""


def choose(question: str, options: list[str], default: str | None = None) -> str:
    return Prompt.ask(f"[bold]{question}[/bold]", choices=options, default=default, console=console)


def ok(msg: str) -> None:
    console.print(f"[green]✔[/green] {msg}")


def fail(msg: str) -> None:
    console.print(f"[red]✘[/red] {msg}")


def info(msg: str) -> None:
    console.print(f"[cyan]ℹ[/cyan] {msg}")


def results_table(rows: list, title: str = "Newly found programs") -> Table:
    t = Table(title=title, show_lines=False, header_style="bold magenta", expand=True)
    for c, kw in (("Source", {}), ("Name", {"overflow": "fold"}), ("Type", {}), ("Reward", {}),
                  ("Cty", {}), ("URL", {"overflow": "fold", "style": "blue"})):
        t.add_column(c, **kw)
    for r in rows:
        reward = f"{r['reward_max']:,.0f} {r['currency'] or ''}" if r["reward_max"] else "—"
        t.add_row(r["source"], r["name"] or "", r["kind"] or "", reward, (r["country"] or "").upper(), r["url"])
    return t


def status_table(items: list[tuple[str, bool, str]], title: str) -> Table:
    t = Table(title=title, header_style="bold")
    t.add_column("Check"); t.add_column("Result"); t.add_column("Detail", overflow="fold")
    for name, passed, detail in items:
        t.add_row(name, "[green]PASS[/green]" if passed else "[red]FAIL[/red]", detail)
    return t


def config_summary(cfg: dict) -> Table:
    from .config import enabled_platforms, mask
    n, f, l = cfg["notify"], cfg["filters"], cfg["llm"]
    t = Table(title="Configuration", show_header=False, box=None, padding=(0, 2))
    t.add_column(style="bold cyan"); t.add_column(overflow="fold")
    t.add_row("Mode", cfg["mode"])
    t.add_row("Notifications", ", ".join(n["channels"]) or "[yellow]none[/yellow]")
    if "telegram" in n["channels"]:
        t.add_row("  Telegram", f"token {mask(n['telegram']['token'])} · chat {n['telegram']['chat_id']}")
    if "email" in n["channels"]:
        t.add_row("  Email", f"{n['email']['address']} → {n['email'].get('to') or n['email']['address']}")
    from .search import PROVIDERS
    from . import search as _s
    parts = []
    for pid in _s.sequence_order(cfg):
        cls = PROVIDERS[pid]
        pc = cfg["search"]["providers"].get(pid) or {}
        if not _s.is_configured(cfg, pid):
            continue
        qt = _s.make(cfg, pid).quota_type()
        what = (f"{pc.get('base_url', '')} · no quota" if not cls.needs_key
                else f"{len(pc.get('keys', []))} key(s) · {pc.get('limit', cls.default_limit)} {qt} each")
        parts.append(f"{cls.label}: {what}{'' if _s.is_enabled(cfg, pid) else ' (disabled)'}")
    t.add_row("Search providers", "\n".join(f"{i}. {x}" for i, x in enumerate(parts, 1)) or "[yellow]none (platform polling only)[/yellow]")
    if parts:
        t.add_row("Search mode", cfg.get("search_mode", "failover"))
    if cfg.get("models"):
        from . import llmreg
        t.add_row("Models", "\n".join(f"{m['id']}. {llmreg.describe(m)} · roles {','.join(m['roles'])} · key {llmreg.key_hint(m)}"
                                      f"{'' if m.get('enabled') else ' (off)'}" for m in cfg["models"]))
    elif not l["enabled"]:
        t.add_row("LLM", "[yellow]disabled (heuristics only)[/yellow]")
    elif l.get("backend") == "openai":
        t.add_row("LLM", f"API {l['model']} @ {l.get('base_url', '')} · key {mask(l.get('api_key', '')) if l.get('api_key') else 'none'}")
    else:
        t.add_row("LLM", f"local {l['model']} @ {l['host']}")
    from . import dates
    from .config import recency_days
    t.add_row("Alert window", f"{dates.window_text(recency_days(cfg))} (applied after discovery: only newer programs alert)")
    sr = cfg.get("dork_search_recency", {})
    t.add_row("Search recency", f"first run {sr.get('first', 'any')}, later runs {sr.get('later', 'month')}, sweep {sr.get('sweep', 'week')} "
                                f"({int(float(sr.get('sweep_share', 0)) * 100)}%) · pages per dork {cfg.get('pages_per_dork', 1)} "
                                "(what the providers' date filters get - not the alert window)")
    t.add_row("Dorks", f"source: {cfg['dorks']['source']} · AI dorks: {'on' if cfg['features']['ai_dorks'] else 'off'} · "
                       f"chat: {'on' if cfg['features']['chat'] else 'off'}")
    t.add_row("Platforms", ", ".join(enabled_platforms(cfg)) + ("" if f["platforms"] else "  [dim](all)[/dim]"))
    t.add_row("Countries", ", ".join(c.upper() for c in f["countries"]) or "all")
    t.add_row("Categories", ", ".join(f["categories"]) or "all")
    t.add_row("Min reward", str(f["min_reward"]) if f["min_reward"] else "none")
    t.add_row("Intervals", f"platforms {cfg['schedule']['platform_interval_min']} min · "
                           f"dorks {cfg['schedule']['dork_interval_min']} min")
    return t
