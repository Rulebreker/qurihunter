"""EXPERIMENTAL, opt-in backend: the user's own, already installed official Claude Code binary run in non-interactive
print mode as a subprocess, under the user's own login. qurihunter only writes the prompt to its stdin and reads its
stdout. It never sees, stores, copies, refreshes or sends any login material, and presents itself as nobody.

Isolation: empty temp working dir, built-in tools disabled, no MCP servers, no session saved, single turn, text/JSON
output only, timeout, concurrency 1. Flags are NOT guessed: `--help` of the installed binary is parsed and the backend
refuses to run when the options needed for tool-less single-turn output are missing."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import threading

from .llm import LLM, ChatReply, LLMError, parse_json

CONSENT_SHORT = ("This uses your Claude subscription through the official CLI. Anthropic's terms and billing for automated use "
                 "have changed in 2026;\nit can consume your subscription limits, which also affects your own Claude Code use "
                 "(full text: README and /model info).")
CONSENT_TEXT = (
    "This uses your Claude subscription through the official Claude Code CLI. Anthropic's terms and billing for "
    "automated/headless use changed several times in 2026 and may change again. Automated use can consume your "
    "subscription limits (also blocking your own Claude Code work) or be billed differently. You are responsible for "
    "checking Anthropic's current terms (the support.claude.com article 'Use the Claude Agent SDK with your Claude plan' "
    "and the Claude Code legal and compliance page). qurihunter never sees your login.")
INSTALL_HELP = ("The `claude` command was not found. Install Claude Code from Anthropic's official instructions and log in "
                "yourself (run `claude` once and follow its prompts), then retry. qurihunter will not run the installer or "
                "the login for you.")
LIMIT_WORDS = ("limit reached", "usage limit", "rate limit", "rate_limit", "quota", "too many requests", "overloaded",
               "billing", "credit", "subscription", "upgrade", "not logged in", "login", "authenticate", "unauthorized",
               "invalid api key", "please run /login", "429")
_lock = threading.Lock()  # concurrency 1


def binary() -> str | None:
    return shutil.which("claude")


def help_text(bin_: str) -> str:
    try:
        r = subprocess.run([bin_, "--help"], capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
        return (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def _run(argv: list[str], timeout: float = 20):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None


def auth_commands(bin_: str) -> dict:
    """Which login/status commands THIS installed binary offers (read from `claude --help` / `claude auth --help`)."""
    top = help_text(bin_)
    if not re.search(r"(?m)^\s+auth\b", top):
        return {"status": False, "login": False}
    r = _run([bin_, "auth", "--help"])
    sub = ((r.stdout or "") + (r.stderr or "")) if r else ""
    return {"status": bool(re.search(r"(?m)^\s+status\b", sub)), "login": bool(re.search(r"(?m)^\s+login\b", sub))}


def auth_status(bin_: str) -> tuple[bool | None, str]:
    """(logged_in, how). Uses the official `claude auth status` (exit code 0 = logged in) - we read the exit code and the
    non-secret `authMethod` field only, never any credential. None = this version has no status command."""
    cmds = auth_commands(bin_)
    if not cmds["status"]:
        return None, "this Claude Code version has no `auth status` command"
    r = _run([bin_, "auth", "status"])
    if r is None:
        return None, "could not run `claude auth status`"
    method = ""
    try:
        method = str(json.loads(r.stdout or "{}").get("authMethod", ""))
    except ValueError:
        pass
    return r.returncode == 0, method


WHO_CAN_USE = ("This option needs the official Claude Code app, signed in with a paid Claude plan (Pro, Max, Team or Enterprise) or an "
               "Anthropic Console API key. The free Claude account does not include Claude Code, and qurihunter cannot use a free "
               "account directly. Other options: 1) a local model, 2) a free-tier API (any OpenAI-compatible endpoint, for example "
               "Gemini's free tier or your own relay), 3) a Claude API key from the Anthropic Console.")
API_KEY_NOTE = ("You are signed in with an API key: calls will be billed per token by Anthropic, and /llm status will count calls "
                "only (no price table).")


def auth_info(bin_: str) -> dict:
    """Login type from the official `claude auth status` (JSON: loggedIn, authMethod, subscriptionType). Only those two
    non-secret fields are read; the e-mail, org and paths in the same output are never looked at or kept.
    kind: subscription | free | api_key | none | unknown."""
    cmds = auth_commands(bin_)
    if not cmds["status"]:
        return {"kind": "unknown", "plan": "", "how": "this Claude Code version has no `auth status` command"}
    r = _run([bin_, "auth", "status"])
    if r is None:
        return {"kind": "unknown", "plan": "", "how": "could not run `claude auth status`"}
    try:
        d = json.loads(r.stdout or "{}")
    except ValueError:
        d = {}
    method, plan = str(d.get("authMethod", "")), str(d.get("subscriptionType") or "").lower()
    if r.returncode != 0 or not d.get("loggedIn", r.returncode == 0) or method == "none":
        return {"kind": "none", "plan": "", "how": method}
    if method in ("api_key", "api_key_helper"):
        return {"kind": "api_key", "plan": "", "how": method}
    if method == "claude.ai" or method.endswith("_token"):
        if plan in ("free", "none", ""):  # a login without a paid plan does not include Claude Code
            return {"kind": "free" if plan == "free" else "subscription", "plan": plan, "how": method}
        return {"kind": "subscription", "plan": plan, "how": method}
    return {"kind": "unknown", "plan": plan, "how": method}


def login_label(bin_: str | None) -> str:
    """'subscription (pro)' / 'API key' / 'free account (not usable)' / 'not logged in' / 'not installed' - never an e-mail."""
    if not bin_:
        return "not installed"
    i = auth_info(bin_)
    return {"subscription": f"subscription{' (' + i.get('plan', '') + ')' if i.get('plan') else ''}", "api_key": "API key",
            "free": "free account (not usable)", "none": "not logged in"}.get(i["kind"], "unknown")


def run_login(bin_: str) -> bool:
    """Launch the OFFICIAL interactive login with the terminal passed straight through: qurihunter sees nothing."""
    if not auth_commands(bin_)["login"]:
        return False
    try:
        return subprocess.run([bin_, "auth", "login"]).returncode == 0
    except OSError:
        return False


def detect_flags(help_: str) -> dict:
    """Which of the options we need exist in THIS installed version (parsed from its own --help)."""
    has = lambda f: re.search(rf"(?<![\w-]){re.escape(f)}(?![\w-])", help_) is not None  # noqa: E731
    return {"print": has("--print") or has("-p"), "tools": has("--tools"), "output_format": has("--output-format"),
            "no_session": has("--no-session-persistence"), "strict_mcp": has("--strict-mcp-config"),
            "no_slash": has("--disable-slash-commands"), "system_prompt": has("--system-prompt"),
            "safe_mode": has("--safe-mode")}


def build_args(bin_: str, flags: dict, system: str | None = None) -> list[str]:
    """argv for a tool-less single-turn call. Raises LLMError when the installed CLI cannot do it safely."""
    missing = [n for n, k in (("--print", "print"), ("--tools (to disable every tool)", "tools"),
                              ("--output-format", "output_format"),
                              ("--safe-mode (so your personal settings, hooks and CLAUDE.md are not loaded)", "safe_mode"))
               if not flags.get(k)]
    if missing:
        raise LLMError("this Claude Code version lacks the options needed for a tool-less single-turn call ("
                       + ", ".join(missing) + "); refusing to run it. Update Claude Code or use another backend.")
    # --safe-mode: no CLAUDE.md, hooks, skills, plugins, MCP servers or auto memory are loaded; login and model work normally
    a = [bin_, "-p", "--output-format", "json", "--tools", "", "--safe-mode"]
    if flags.get("no_session"):
        a.append("--no-session-persistence")
    if flags.get("strict_mcp"):
        a.append("--strict-mcp-config")  # without --mcp-config this loads no MCP server at all
    if flags.get("no_slash"):
        a.append("--disable-slash-commands")
    if system and flags.get("system_prompt"):
        a += ["--system-prompt", system]
    return a


class ClaudeCLI(LLM):
    model = "claude (CLI)"
    host = "claude CLI"

    def __init__(self, timeout: float = 180, consent: bool = False, batch_size: int = 10):
        self.timeout, self.consent, self.batch_size = timeout, consent, int(batch_size)
        self._flags: dict | None = None

    def available(self) -> bool:
        return binary() is not None

    def describe(self) -> str:
        return "Claude subscription via the official Claude Code CLI (experimental)"

    def flags(self) -> dict:
        b = binary()
        if not b:
            raise LLMError(INSTALL_HELP)
        if self._flags is None:
            self._flags = detect_flags(help_text(b))
        return self._flags

    def generate(self, prompt: str, *, json_mode: bool = False, timeout: float = 0, system: str | None = None) -> str:
        if not self.consent:
            raise LLMError("the Claude CLI backend was not consented to (/model add → type 'I understand')", kind="auth")
        b = binary()
        if not b:
            raise LLMError(INSTALL_HELP)
        argv = build_args(b, self.flags(), system)
        if json_mode:
            prompt += "\n\nReply with the JSON only, no prose and no code fences."
        from . import dblock
        dblock.flush()
        with _lock, tempfile.TemporaryDirectory(prefix="qh-claude-") as cwd:  # empty working dir; one call at a time
            try:
                r = subprocess.run(argv, input=prompt, capture_output=True, text=True, cwd=cwd,
                                   timeout=timeout or self.timeout)
            except subprocess.TimeoutExpired as e:
                raise LLMError("the Claude CLI call timed out", kind="transient") from e
            except OSError as e:
                raise LLMError(f"cannot run the Claude CLI: {e}") from e
        out = (r.stdout or "").strip()
        data = parse_json(out) if out.startswith("{") else None
        text = ""
        err = bool(r.returncode)
        if isinstance(data, dict):
            text = str(data.get("result") or "")
            err = err or bool(data.get("is_error"))
            u = data.get("usage") or {}
            self.last_usage = {"in": u.get("input_tokens", 0), "out": u.get("output_tokens", 0)}
        else:
            text = out
        if err:
            low = (text + " " + (r.stderr or "")).lower()
            kind = "limit" if any(w in low for w in LIMIT_WORDS) else "transient"
            raise LLMError(f"Claude CLI reported a problem ({kind}): {(text or r.stderr or 'exit ' + str(r.returncode))[:160]}",
                           kind=kind)
        return text.strip()

    def chat(self, messages: list[dict], tools: list[dict] | None = None, timeout: float = 0) -> ChatReply:
        """No native tools here (they are disabled on purpose): /chat falls back to its strict JSON-action protocol."""
        if tools:
            raise LLMError("the Claude CLI backend has no native tool calling", no_tools=True)
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in messages if m["role"] != "system")
        return ChatReply(self.generate(convo + "\n\nASSISTANT:", timeout=timeout, system=system or None), [])
