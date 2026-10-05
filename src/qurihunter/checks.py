"""Live verification of every configured parameter. Each check returns (name, passed, detail)."""
from __future__ import annotations

import requests

from . import notify, search
from .config import mask
from .llm import LLMError, Ollama, OpenAICompat
from .sources import platforms

Check = tuple[str, bool, str]


def telegram(token: str, chat_id: str) -> Check:
    try:
        notify.send_telegram(token, chat_id, "✅ <b>qurihunter</b> test message — Telegram is configured.")
        return "Telegram", True, f"test message sent to chat {chat_id}"
    except notify.NotifyError as e:
        return "Telegram", False, str(e).removeprefix("Telegram: ")


def email(address: str, app_password: str, to: str) -> Check:
    try:
        notify.send_email(address, app_password, to or address, "[qurihunter] test email",
                          "qurihunter test email — Gmail is configured correctly.")
        return "Email", True, f"test email sent to {to or address}"
    except notify.NotifyError as e:
        return "Email", False, str(e)


def search_key(cfg: dict, pid: str, key: str) -> Check:
    prov = search.make(cfg, pid)
    miss = prov.missing_options()
    if miss:
        return f"{prov.label} key {mask(key)}", False, f"missing option: {', '.join(miss)}"
    ok, detail = prov.test(key)
    return f"{prov.label} key {mask(key)}", ok, detail


def llm(host: str, model: str) -> Check:
    o = Ollama(host, model)
    if not o.running():
        return "Local LLM", False, f"Ollama not reachable at {host}"
    if not o.has(model):
        return "Local LLM", False, f"model '{model}' is not installed (ollama pull {model})"
    try:
        return f"Local LLM {model}", True, f"replied: {o.test()!r}"
    except LLMError as e:
        return f"Local LLM {model}", False, str(e)


def llm_cfg(cfg: dict) -> Check:
    """Live test of whichever backend is configured (local Ollama or OpenAI-compatible API)."""
    l = cfg["llm"]
    if l.get("backend") != "openai":
        return llm(l["host"], l["model"])
    o = OpenAICompat(l.get("base_url", ""), l.get("api_key", ""), l.get("model", ""))
    name = f"LLM API {l.get('model', '')}"
    if not o.available():
        return name, False, "base URL and model name are required"
    try:
        return name, True, f"replied: {o.test()!r}"
    except LLMError as e:
        return name, False, str(e)


def models(cfg: dict) -> list[Check]:
    """Live test of every enabled model with ONE small call each. The Claude CLI is skipped here on purpose: its only
    test is /model test (a single call), so /test never spends subscription limits."""
    from . import llmreg
    out: list[Check] = []
    r = llmreg.Router(cfg)
    for m in cfg.get("models", []):
        if not m.get("enabled"):
            continue
        name = f"Model {m['id']} ({llmreg.describe(m)})"
        if m["type"] == "claude_cli":
            out.append((name, True, "not called by /test (use /model test: exactly one call)"))
            continue
        try:
            out.append((name, True, f"replied: {r.test_model(m['id'])!r}"))
        except LLMError as e:
            out.append((name, False, str(e)))
    return out


def sources(selected: list[str]) -> list[Check]:
    out = []
    for sid in selected:
        if sid not in platforms.SOURCES:
            continue
        label, url, _ = platforms.SOURCES[sid]
        try:
            r = requests.head(url, timeout=20, allow_redirects=True)
            out.append((f"Source {label}", r.status_code < 400, f"HTTP {r.status_code}"))
        except requests.RequestException as e:
            out.append((f"Source {label}", False, str(e)[:100]))
    return out


def all_checks(cfg: dict, selected_platforms: list[str]) -> list[Check]:
    res: list[Check] = []
    n = cfg["notify"]
    if "telegram" in n["channels"]:
        res.append(telegram(n["telegram"]["token"], n["telegram"]["chat_id"]))
    if "email" in n["channels"]:
        e = n["email"]
        res.append(email(e["address"], e["app_password"], e.get("to", "")))
    if not n["channels"]:
        res.append(("Notifications", False, "no channel configured (/config)"))
    any_keys = False
    for pid, pc in cfg["search"]["providers"].items():
        if pid not in search.PROVIDERS:
            continue
        if not search.PROVIDERS[pid].needs_key:  # SearXNG: probe the instance instead of a key
            if search.is_configured(cfg, pid):
                any_keys = True
                ok, detail = search.make(cfg, pid).probe()
                res.append((f"{search.PROVIDERS[pid].label}", ok, detail))
            continue
        for k in pc.get("keys", []):
            any_keys = True
            res.append(search_key(cfg, pid, k))
    if not any_keys:
        res.append(("Search provider", False, "no API keys configured — dork discovery disabled (/config)"))
    if cfg.get("models"):
        res += models(cfg)
    else:
        res.append(llm_cfg(cfg) if cfg["llm"]["enabled"] else ("LLM", False, "disabled (/model)"))
    res += sources(selected_platforms)
    return res
