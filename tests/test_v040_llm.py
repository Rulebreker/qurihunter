"""v0.4 Part C: model registry migration, add-model wizard, Anthropic API backend, role routing + failover, cost guard,
and the experimental Claude CLI backend (isolation, consent, caps, no credential access)."""
import json
import re
import stat
from pathlib import Path

import pytest

from qurihunter import claudecli, config, llm as llmmod, llmreg, modelcmds, ui
from qurihunter.db import DB
from qurihunter.llm import Anthropic, ChatReply, LLMError, Ollama, OpenAICompat

SRC = Path(llmmod.__file__).parent
KEY = "sk-ant-api03-SECRETSECRETSECRETSECRET1234"
HELP = "-p, --print  Print response\n--tools <tools...>\n--output-format <format>\n--no-session-persistence\n--strict-mcp-config\n--disable-slash-commands\n--system-prompt <prompt>\n--safe-mode  Start with all customizations disabled"


class Resp:
    def __init__(self, status=200, body=None, text=None, headers=None):
        self.status_code, self._b, self.headers = status, body if body is not None else {}, headers or {}
        self.text = text if text is not None else json.dumps(self._b)
        self.ok = status < 400

    def json(self):
        return self._b


@pytest.fixture
def db(tmp_path):
    return DB(tmp_path / "t.db")


@pytest.fixture
def cfg():
    return config.load()


class Ctx:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db

    def save(self, c=None):
        config.save(c or self.cfg)


class Fake(llmmod.LLM):
    """Scripted backend: records calls, can fail, reports token usage."""
    def __init__(self, name, fail=None, usage=(100, 20)):
        self.name, self.fail, self.usage, self.calls = name, fail, usage, []
        self.model, self.host = name, name
        self.last_usage = {}

    def _go(self, what):
        self.calls.append(what)
        if self.fail:
            raise self.fail
        self.last_usage = {"in": self.usage[0], "out": self.usage[1]}

    def generate(self, prompt, *, json_mode=False, timeout=0, system=None):
        self._go("generate")
        return self.name

    def classify(self, *a, **k):
        self._go("classify")
        return {"is_program": True, "type": "vdp", "confidence": 0.9, "reason": self.name}

    def summarize(self, *a, **k):
        self._go("summarize")
        return self.name

    def chat(self, messages, tools=None, timeout=0):
        self._go("chat")
        return ChatReply(self.name, [])

    def test(self):
        self._go("test")
        return "pong"


def router(cfg, db, **fakes):
    r = llmmod.from_config(cfg, db)
    r._inst = dict(fakes)  # id -> Fake
    return r


def entry(cfg, type_, model, **kw):
    e = llmreg.new_entry(cfg, type_, model, **kw)
    llmreg.add_model(cfg, e)
    return e


# ── migration ────────────────────────────────────────────────────────────────
def test_v4_config_with_local_llm_migrates_to_model_1_and_is_backed_up():
    raw = {"version": 4, "setup_done": True, "llm": {"enabled": True, "host": "http://localhost:11434", "model": "qwen3-coder:30b",
                                                      "backend": "ollama"}}
    config.config_path().write_text(json.dumps(raw))
    c = config.load()
    assert c["version"] == config.CONFIG_VERSION and c["models"][0]["id"] == "m1" and c["models"][0]["type"] == "local"
    assert c["models"][0]["model"] == "qwen3-coder:30b" and set(c["models"][0]["roles"]) == set(config.ROLES)
    assert c["llm"]["model"] == "qwen3-coder:30b"  # the legacy block stays: reversible
    bak = config.config_path().with_name("config.json.bak-v4")
    assert bak.exists() and json.loads(bak.read_text()) == raw and stat.S_IMODE(bak.stat().st_mode) == 0o600
    config.save(c)
    again = config.load()
    assert again["models"] == c["models"] and len(again["models"]) == 1  # idempotent


def test_v4_config_with_openai_backend_becomes_api_model():
    config.config_path().write_text(json.dumps({"version": 4, "llm": {"enabled": True, "backend": "openai", "base_url": "https://r.example/v1",
                                                                       "api_key": KEY, "model": "gpt-x"}}))
    m = config.load()["models"][0]
    assert m["type"] == "api" and m["base_url"] == "https://r.example/v1" and m["key"] == KEY and m["model"] == "gpt-x"


def test_disabled_llm_does_not_create_a_model():
    config.config_path().write_text(json.dumps({"version": 4, "llm": {"enabled": False}}))
    assert config.load()["models"] == []


def test_db_migration_creates_new_tables_and_backs_up(tmp_path):
    p = tmp_path / "old.db"
    import sqlite3
    from qurihunter import migrations
    c = sqlite3.connect(p)
    for m in migrations.MIGRATIONS[:4]:
        m(c)
    c.execute("PRAGMA user_version=4")
    c.commit()
    c.close()
    d = DB(p)
    assert d.backup_made and d.backup_made.exists()
    names = {r[0] for r in d.c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"search_steps", "provider_health", "llm_usage"} <= names
    assert d.c.execute("PRAGMA user_version").fetchone()[0] == len(migrations.MIGRATIONS) == 6
    migrations.m5_sequence(d.c)  # idempotent
    d.c.close()


def test_config_file_permissions_are_600(cfg):
    config.save(cfg)
    assert stat.S_IMODE(config.config_path().stat().st_mode) == 0o600


# ── wizard ───────────────────────────────────────────────────────────────────
class Script:
    """Feeds scripted answers to ui.choose / ui.ask / ui.yn and records everything shown."""
    def __init__(self, monkeypatch, answers):
        self.answers, self.shown, self.asked = list(answers), [], []
        monkeypatch.setattr(ui, "choose", lambda q, o, d=None: self._next(q))
        monkeypatch.setattr(ui, "ask", lambda q, d="", password=False: self._next(q, password))
        monkeypatch.setattr(ui, "yn", lambda q, d=True: self._next(q))
        for n in ("info", "ok", "fail"):
            monkeypatch.setattr(ui, n, lambda m, n=n: self.shown.append(str(m)))
        monkeypatch.setattr(ui.console, "print", lambda *a, **k: self.shown.append(" ".join(str(x) for x in a)))

    def _next(self, q, password=False):
        self.asked.append((q, password))
        a = self.answers.pop(0)
        return a(q) if callable(a) else a

    @property
    def text(self):
        return "\n".join(self.shown + [q for q, _ in self.asked])


def test_wizard_local_ollama_existing_model_roles_and_order(cfg, monkeypatch):
    from qurihunter import wizard
    monkeypatch.setattr(wizard, "_ensure_running", lambda o: True)
    monkeypatch.setattr(Ollama, "models", lambda self: ["llama3.1:8b", "qwen2.5:7b"])
    monkeypatch.setattr(Ollama, "has", lambda self, m: True)
    monkeypatch.setattr(Ollama, "test", lambda self: "pong")
    s = Script(monkeypatch, ["1", True, True, "classify, summarize", ""])  # type, ollama?, use this one?, roles, order
    ents = modelcmds.add_model_wizard(cfg)
    assert len(ents) == 1 and ents[0]["type"] == "local" and ents[0]["model"] == "llama3.1:8b"
    assert cfg["models"][0]["roles"] == ["classify", "summarize"] and cfg["models"][0]["order"] == 1
    assert "Which kind of model" in s.text and "Local LLM" in s.text and "Claude subscription via official Claude Code CLI" in s.text


def test_wizard_api_model_asks_only_url_key_model_then_tests_no_quota_or_price_questions(cfg, monkeypatch):
    monkeypatch.setattr(OpenAICompat, "models", lambda self: ["m-small", "m-big"])
    monkeypatch.setattr(OpenAICompat, "test", lambda self: "pong")
    s = Script(monkeypatch, ["2", "https://relay.example/v1/", KEY, True, "2", "chat", "1"])
    ents = modelcmds.add_model_wizard(cfg)
    e = ents[0]
    assert e["type"] == "api" and e["base_url"] == "https://relay.example/v1" and e["model"] == "m-big" and e["key"] == KEY
    assert e["price_in"] is None and e["price_out"] is None and not e["free"] and e["roles"] == ["chat"]
    assert not any(w in q.lower() for q, _ in s.asked for w in ("price", "quota", "free", "per million"))
    assert [p for q, p in s.asked if "API key" in q] == [True]  # hidden input
    assert KEY not in s.text  # the secret is never displayed


def test_wizard_claude_api_key_lists_models_from_api_and_suggests_without_hardcoding(cfg, monkeypatch):
    listing = [{"id": "zz-opus-9", "display_name": "Zed Opus 9"}, {"id": "zz-sonnet-9", "display_name": "Zed Sonnet 9"},
               {"id": "zz-haiku-9", "display_name": "Zed Haiku 9"}]
    monkeypatch.setattr(Anthropic, "models", lambda self: listing)
    monkeypatch.setattr(Anthropic, "test", lambda self: "pong")
    s = Script(monkeypatch, ["3", True, KEY, "3", True, "1", ""])  # key? key, fast=3 (haiku), stronger? yes, pick 1, order
    ents = modelcmds.add_model_wizard(cfg)
    assert [e["model"] for e in ents] == ["zz-haiku-9", "zz-opus-9"] and all(e["type"] == "claude" for e in ents)
    assert set(ents[0]["roles"]) == {"classify", "summarize", "date_kind"} and set(ents[1]["roles"]) == {"chat", "dork_gen"}
    assert "zz-haiku-9" in s.text and KEY not in s.text
    assert ents[0]["key"] == KEY and llmreg.key_hint(ents[0]) == "…" + KEY[-4:]


def test_wizard_subscription_only_branch_explains_and_loops_back(cfg, monkeypatch):
    monkeypatch.setattr(OpenAICompat, "models", lambda self: [])
    monkeypatch.setattr(OpenAICompat, "test", lambda self: "pong")
    s = Script(monkeypatch, ["3", False,  # "no, I only have a subscription" -> explanation, back to step 1
                             "2", "https://relay/v1", "", "m", "", ""])
    ents = modelcmds.add_model_wizard(cfg)
    assert "NOT an API key" in s.text and "LOCAL model" in s.text and "OpenAI-compatible API" in s.text and "Anthropic Console API key" in s.text
    assert s.text.count("Which kind of model") == 2 and ents[0]["type"] == "api"  # looped back to step 1


def test_wizard_cli_missing_binary_prints_install_help_and_runs_nothing(cfg, monkeypatch):
    monkeypatch.setattr(claudecli, "binary", lambda: None)
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("nothing may run"))
    s = Script(monkeypatch, ["4", "2", "https://r/v1", "", "m", "", ""])
    monkeypatch.setattr(OpenAICompat, "models", lambda self: [])
    monkeypatch.setattr(OpenAICompat, "test", lambda self: "pong")
    modelcmds.add_model_wizard(cfg)
    assert "needs the official Claude Code app" in s.text


def cli_env(monkeypatch, *, help_=HELP, auth=({"kind": "subscription", "plan": "pro", "how": "claude.ai"},), login=True):
    """Pretend the official CLI is installed; returns the list of events (login launches, test calls)."""
    ev = []
    seq = list(auth)
    monkeypatch.setattr(claudecli, "binary", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claudecli, "help_text", lambda b: help_)
    monkeypatch.setattr(claudecli, "auth_info", lambda b: seq.pop(0) if len(seq) > 1 else seq[0])
    monkeypatch.setattr(claudecli, "auth_commands", lambda b: {"status": True, "login": login})
    monkeypatch.setattr(claudecli, "run_login", lambda b: ev.append("login") or True)
    monkeypatch.setattr(llmreg.Router, "test_model", lambda self, mid: ev.append(f"test:{mid}") or "pong")
    return ev


def test_wizard_cli_flow_has_zero_technical_questions_all_roles_first_and_local_kept_as_fallback(cfg, monkeypatch):
    loc = llmreg.new_entry(cfg, "local", "qwen")
    llmreg.add_model(cfg, loc)
    ev = cli_env(monkeypatch)
    s = Script(monkeypatch, ["4", True])  # step 1 = option 4, then ONE plain y/n ("Use it?")
    ents = modelcmds.add_model_wizard(cfg)
    e = ents[0]
    assert [q for q, _ in s.asked[1:]] == ["Use it?"]  # no roles / order / quota / price / consent-typing questions
    assert e["type"] == "claude_cli" and e["consent"] is True and e["roles"] == config.ROLES
    assert cfg["claude_cli_allow_bulk"] is True
    assert [m["id"] for m in cfg["models"]] == [e["id"], loc["id"]] and cfg["models"][0]["order"] == 1  # first; local behind it
    assert ev == [f"test:{e['id']}"]  # exactly one test call
    text = s.text
    assert "uses your Claude subscription through the official CLI" in text and "also affects your own Claude Code use" in text
    assert "kept as fallback" in text and "12 calls/hour" in text and "80 calls/day" in text and "10 pages per classification call" in text
    assert "I understand" not in text


def test_wizard_cli_not_logged_in_offers_the_official_login_then_continues(cfg, monkeypatch):
    ev = cli_env(monkeypatch, auth=({"kind": "none"}, {"kind": "subscription", "plan": "max"}))
    s = Script(monkeypatch, ["4", True, True])  # type 4, launch official login? y, use it? y
    ents = modelcmds.add_model_wizard(cfg)
    assert ev[0] == "login" and ents and "Log in once with the official Claude Code app" in s.text
    assert "Launch the official login now" in s.text


def test_wizard_cli_not_logged_in_and_declined_or_no_login_command_adds_nothing(cfg, monkeypatch):
    ev = cli_env(monkeypatch, auth=({"kind": "none"},))
    s = Script(monkeypatch, ["4", False, "2", "https://r/v1", "", "m", "", ""])  # decline login -> back to step 1 -> API
    monkeypatch.setattr(OpenAICompat, "models", lambda self: [])
    monkeypatch.setattr(OpenAICompat, "test", lambda self: "pong")
    modelcmds.add_model_wizard(cfg)
    assert "login" not in ev and "needs the official Claude Code app" in s.text and not any(m["type"] == "claude_cli" for m in cfg["models"])
    cfg["models"] = []
    cli_env(monkeypatch, auth=({"kind": "none"},), login=False)
    s2 = Script(monkeypatch, ["4", "2", "https://r/v1", "", "m", "", ""])
    modelcmds.add_model_wizard(cfg)
    assert "follow its login prompt" in s2.text and "needs the official Claude Code app" in s2.text and not any(m["type"] == "claude_cli" for m in cfg["models"])


def test_wizard_cli_declined_warning_adds_nothing(cfg, monkeypatch):
    cli_env(monkeypatch)
    s = Script(monkeypatch, ["4", False, "2", "https://r/v1", "", "m", "", ""])
    monkeypatch.setattr(OpenAICompat, "models", lambda self: [])
    monkeypatch.setattr(OpenAICompat, "test", lambda self: "pong")
    modelcmds.add_model_wizard(cfg)
    assert "Not enabled" in s.text and not any(m["type"] == "claude_cli" for m in cfg["models"]) and not cfg["claude_cli_allow_bulk"]


def test_wizard_cli_refuses_when_the_installed_version_lacks_needed_flags(cfg, monkeypatch):
    cli_env(monkeypatch, help_="-p, --print\n--output-format <f>\n--tools\n")  # no --safe-mode
    monkeypatch.setattr(OpenAICompat, "models", lambda self: [])
    monkeypatch.setattr(OpenAICompat, "test", lambda self: "pong")
    s = Script(monkeypatch, ["4", "2", "https://r/v1", "", "m", "", ""])
    modelcmds.add_model_wizard(cfg)
    assert "refusing to run it" in s.text and "--safe-mode" in s.text
    assert not any(m["type"] == "claude_cli" for m in cfg["models"])


def test_wizard_roles_for_cli_exclude_classify_and_date_kind(cfg):
    e = llmreg.new_entry(cfg, "claude_cli", "claude (CLI)", roles=["classify", "chat", "date_kind"], consent=True)
    assert e["roles"] == ["chat"]
    llmreg.add_model(cfg, e)
    assert "may only handle" in llmreg.set_roles(cfg, e["id"], ["classify"])
    cfg["claude_cli_allow_bulk"] = True
    assert llmreg.set_roles(cfg, e["id"], ["classify"]) is None


def test_manual_mode_first_run_uses_the_wizard_and_auto_keeps_old_behaviour(monkeypatch):
    from qurihunter import wizard, hardware
    cfg = config.load()
    calls = []
    monkeypatch.setattr(hardware, "detect", lambda: hardware.Hardware(8, "x", 4))
    monkeypatch.setattr(wizard.modelcmds, "manual_step", lambda c, save: calls.append("wizard"))
    monkeypatch.setattr(wizard, "setup_llm", lambda c, hw, **k: calls.append("auto-llm") or c["llm"].update(enabled=True, model="qwen", host="http://localhost:11434", backend="ollama"))
    monkeypatch.setattr(wizard, "filters_menu", lambda c: None)
    monkeypatch.setattr(wizard, "setup_keys", lambda c: None)
    monkeypatch.setattr(wizard, "recency_menu", lambda c: None)
    monkeypatch.setattr(wizard, "dorks_menu", lambda c, db=None: None)
    monkeypatch.setattr(wizard, "setup_notifications", lambda c: None)
    monkeypatch.setattr(wizard, "auto_alert_prompt", lambda c: None)
    monkeypatch.setattr(ui, "yn", lambda *a, **k: False)
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    monkeypatch.setattr(ui.console, "rule", lambda *a, **k: None)
    monkeypatch.setattr(ui, "choose", lambda *a, **k: "m")
    wizard.first_run(cfg, lambda c: None)
    assert calls == ["wizard"]
    cfg2 = config.load()
    monkeypatch.setattr(ui, "choose", lambda *a, **k: "a")
    wizard.first_run(cfg2, lambda c: None)
    assert calls[-1] == "auto-llm" and cfg2["models"][0]["model"] == "qwen" and cfg2["models"][0]["type"] == "local"


# ── Anthropic API backend ────────────────────────────────────────────────────
def test_anthropic_headers_system_param_usage_and_tool_use(monkeypatch):
    seen = {}

    def fake(method, url, **kw):
        seen.update(method=method, url=url, **kw)
        return Resp(200, {"content": [{"type": "text", "text": "Hello"}, {"type": "tool_use", "id": "t1", "name": "query_programs",
                                                                         "input": {"since": "7d"}}],
                          "usage": {"input_tokens": 11, "output_tokens": 7}})
    monkeypatch.setattr(llmmod, "request", fake)
    a = Anthropic(KEY, "some-model")
    r = a.chat([{"role": "system", "content": "SYS"}, {"role": "user", "content": "hi"}, {"role": "user", "content": "again"},
                {"role": "assistant", "content": "ok"}],
               tools=[{"name": "query_programs", "description": "d", "parameters": {"type": "object", "properties": {}}}])
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["x-api-key"] == KEY and seen["headers"]["anthropic-version"] == "2023-06-01"
    b = seen["json"]
    assert b["system"] == "SYS" and b["model"] == "some-model"
    assert b["messages"] == [{"role": "user", "content": "hi\n\nagain"}, {"role": "assistant", "content": "ok"}]  # merged, alternating
    assert b["tools"][0]["input_schema"] == {"type": "object", "properties": {}}
    assert r.content == "Hello" and r.tool_calls == [{"name": "query_programs", "arguments": {"since": "7d"}}]
    assert a.last_usage == {"in": 11, "out": 7}
    assert a.generate("p", system="S2", json_mode=True) == "Hello"
    assert seen["json"]["system"] == "S2" and "JSON only" in seen["json"]["messages"][0]["content"]


@pytest.mark.parametrize("status,text,kind", [(401, "bad", "auth"), (429, "slow", "rate"), (529, "overloaded", "rate"),
                                              (400, "credit balance is too low", "quota"), (500, "x", "transient")])
def test_anthropic_error_kinds_never_leak_the_key(monkeypatch, status, text, kind):
    monkeypatch.setattr(llmmod, "request", lambda *a, **k: Resp(status, text=f"{text} {KEY}"))
    with pytest.raises(LLMError) as e:
        Anthropic(KEY, "m").generate("p")
    assert e.value.kind == kind and KEY not in str(e.value)


def test_anthropic_backs_off_on_429_and_529_via_the_shared_http_retry():
    from qurihunter import http
    assert 429 in http.RETRY_STATUS and 529 in http.RETRY_STATUS


def test_anthropic_model_list_paginates_and_rejects_bad_key(monkeypatch):
    pages = [Resp(200, {"data": [{"id": "a", "display_name": "A"}], "has_more": True, "last_id": "a"}),
             Resp(200, {"data": [{"id": "b", "display_name": "B"}], "has_more": False, "last_id": "b"})]
    got = []
    monkeypatch.setattr(llmmod.requests, "get", lambda url, **kw: got.append((url, kw)) or pages.pop(0))
    assert [m["id"] for m in Anthropic(KEY, "").models()] == ["a", "b"]
    assert got[0][0] == "https://api.anthropic.com/v1/models" and got[1][1]["params"]["after_id"] == "a"
    assert got[0][1]["headers"]["x-api-key"] == KEY
    monkeypatch.setattr(llmmod.requests, "get", lambda *a, **k: Resp(401, {}))
    with pytest.raises(LLMError, match="Console"):
        Anthropic(KEY, "").models()


def test_no_hardcoded_claude_model_names_in_the_code():
    pat = re.compile(r"claude-(?:opus|sonnet|haiku|fable|[0-9])[\w.-]*", re.I)
    hits = [(f.name, m.group(0)) for f in SRC.glob("*.py") for m in pat.finditer(f.read_text())]
    assert hits == []


# ── router: roles, failover, budget ─────────────────────────────────────────
def test_role_order_and_failover(cfg, db):
    a = entry(cfg, "local", "a", roles=["classify", "chat"])
    b = entry(cfg, "api", "b", key=KEY, roles=["classify", "summarize"], free=True)
    c = entry(cfg, "claude", "c", key=KEY, roles=["chat", "dork_gen"], free=True)
    fa, fb, fc = Fake("a"), Fake("b"), Fake("c")
    r = router(cfg, db, **{a["id"]: fa, b["id"]: fb, c["id"]: fc})
    assert r.classify("u", "t", "s")["reason"] == "a" and fa.calls == ["classify"] and fb.calls == []
    assert r.summarize("n", "u", "s", "k", "r", []) == "b"  # only b has summarize
    assert r.for_role("dork_gen").generate("p") == "c"
    fa.fail = LLMError("down", kind="transient")
    assert r.classify("u", "t", "s")["reason"] == "b"  # classify fails over a -> b
    assert r.chat([{"role": "user", "content": "x"}]).content == "c"  # chat fails over a -> c
    fb.fail = LLMError("down too")
    with pytest.raises(LLMError, match="no model could handle role 'classify'"):
        r.classify("u", "t", "s")
    assert db.c.execute("SELECT COUNT(*) FROM llm_usage WHERE ok=0").fetchone()[0] >= 3


def test_move_roles_and_remove_commands(cfg, db, monkeypatch):
    entry(cfg, "local", "a"); entry(cfg, "local", "b"); entry(cfg, "local", "c")
    ctx = Ctx(cfg, db)
    monkeypatch.setattr(ui, "ok", lambda m: None); monkeypatch.setattr(ui, "fail", lambda m: None)
    monkeypatch.setattr(ui, "info", lambda m: None); monkeypatch.setattr(ui.console, "print", lambda *a, **k: None)
    modelcmds.cmd_model(ctx, ["order", "m3", "1"])
    assert [m["id"] for m in cfg["models"]] == ["m3", "m1", "m2"] and [m["order"] for m in cfg["models"]] == [1, 2, 3]
    modelcmds.cmd_model(ctx, ["roles", "m1", "chat,", "classify"])
    assert llmreg.get(cfg, "m1")["roles"] == ["chat", "classify"]
    modelcmds.cmd_model(ctx, ["disable", "m2"])
    assert not llmreg.get(cfg, "m2")["enabled"] and llmreg.Router(cfg, db).entries("chat")[0]["id"] == "m3"
    modelcmds.cmd_model(ctx, ["remove", "m3"])
    assert [m["id"] for m in cfg["models"]] == ["m1", "m2"] and json.loads(config.config_path().read_text())["models"]
    r = llmreg.Router(cfg, db)
    assert r.entries("chat")[0]["id"] == "m1"


def test_budget_guard_warns_at_80_percent_hard_stops_at_100_and_fails_over(cfg, db, caplog):
    cfg["llm_budget"] = {"daily_usd": 0.10, "monthly_usd": 10.0, "warn_pct": 80}
    paid = entry(cfg, "claude", "paid", key=KEY, roles=["chat"], price_in=1000.0, price_out=0.0)  # $1000/Mtok -> 100 tokens = $0.10
    free = entry(cfg, "local", "free", roles=["chat"])
    fp, ff = Fake("paid", usage=(80, 0)), Fake("free")
    r = router(cfg, db, **{paid["id"]: fp, free["id"]: ff})
    with caplog.at_level("WARNING"):
        assert r.chat([{"role": "user", "content": "x"}]).content == "paid"  # $0.08 = 80%
    assert any("80%" in m or "at 80" in m or "% of its budget" in m for m in caplog.messages)
    assert sum("of its budget" in m for m in caplog.messages) == 1
    r.chat([{"role": "user", "content": "x"}])  # $0.16 -> over 100%
    assert fp.calls == ["chat", "chat"]
    assert r.chat([{"role": "user", "content": "x"}]).content == "free"  # hard stop: paid skipped, next model answers
    assert fp.calls == ["chat", "chat"] and ff.calls == ["chat"]
    assert "daily budget" in r.blocked(paid, "chat")
    st = llmreg.budget_state(db, cfg)
    assert st["day"] == pytest.approx(0.16) and st["day_pct"] > 100
    # only the paid model assigned and over budget: LLM work is skipped (error), never a crash
    cfg["models"] = [paid]
    with pytest.raises(LLMError, match="budget"):
        router(cfg, db, **{paid["id"]: fp}).chat([{"role": "user", "content": "x"}])


def test_cost_needs_a_user_price_and_free_models_never_cost(cfg, db):
    m = llmreg.new_entry(cfg, "claude", "x", key=KEY)
    assert llmreg.cost(m, 1000, 1000) is None  # no price entered -> tracking skipped, nothing assumed
    m.update(price_in=3.0, price_out=15.0)
    assert llmreg.cost(m, 1_000_000, 1_000_000) == pytest.approx(18.0)
    e = entry(cfg, "api", "y", key=KEY, free=True, price_in=5.0)
    r = router(cfg, db, **{e["id"]: Fake("y")})
    r.generate("p", role="chat")
    assert db.c.execute("SELECT cost_usd FROM llm_usage").fetchone()[0] == 0


def test_bulk_estimate_and_confirmation_only_for_paid_models(cfg):
    entry(cfg, "local", "loc", roles=["classify"])
    assert llmreg.confirm_bulk(cfg, "classify", 500, "Reclassify", lambda q: pytest.fail("free model must not ask"))
    cfg["models"] = []
    entry(cfg, "claude", "paid", key=KEY, roles=["classify"], price_in=1.0, price_out=5.0)
    asked = []
    assert not llmreg.confirm_bulk(cfg, "classify", 100, "Reclassify", lambda q: asked.append(q) or False)
    assert "~100 calls" in asked[0] and "about $0.2250" in asked[0]
    e = llmreg.estimate_bulk(cfg, "classify", 100)
    assert e["paid"] and e["usd"] == pytest.approx((150000 * 1.0 + 15000 * 5.0) / 1e6)


def test_reclassify_asks_before_using_a_paid_model_and_cancels_on_no(cfg, db, monkeypatch):
    from qurihunter import memcmds
    from qurihunter.models import Program
    db.insert(Program("web", "a.ch", "a", "https://a.ch/responsible-disclosure", snippet="bounty"))
    entry(cfg, "claude", "paid", key=KEY, roles=["classify"], price_in=1.0, price_out=1.0)
    asked = []
    monkeypatch.setattr(ui, "yn", lambda q, d=True: asked.append(q) or False)
    monkeypatch.setattr(ui, "info", lambda m: None)
    memcmds.cmd_memory(Ctx(cfg, db), ["reclassify"])
    assert asked and "paid model" in asked[0]
    from qurihunter import reclass
    assert reclass.state(db) == "idle"  # nothing was queued or called


def test_llm_status_renders_calls_tokens_spend_per_model_and_role(cfg, db, monkeypatch):
    p = entry(cfg, "claude", "paid", key=KEY, roles=["chat"], price_in=10.0, price_out=10.0)
    entry(cfg, "local", "loc", roles=["classify"])
    r = router(cfg, db, **{p["id"]: Fake("paid", usage=(1000, 500)), "m2": Fake("loc")})
    r.chat([{"role": "user", "content": "x"}])
    r.classify("u", "t", "s")
    tables, info = [], []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    monkeypatch.setattr(ui, "info", lambda m: info.append(m))
    monkeypatch.setattr(ui, "fail", lambda m: info.append(m))
    modelcmds.cmd_llm(Ctx(cfg, db), [])
    t = [x for x in tables if hasattr(x, "row_count")][0]
    assert t.row_count == 2 and "1000/500" in t.columns[5]._cells[0] and t.columns[6]._cells[0] == "$0.0150"
    assert any(x.title == "Per role" for x in tables if hasattr(x, "title"))
    assert any("Budget: today" in m for m in info)
    assert KEY not in json.dumps([str(c._cells) for x in tables if hasattr(x, "columns") for c in x.columns])


# ── Claude CLI (experimental) ────────────────────────────────────────────────


def test_static_no_code_path_touches_claude_credentials_or_spoofs_the_client():
    forbidden = re.compile(r"/\.claude|~/\.claude|\.claude/|\.claude\.json|credentials\.json|keychain|oauth|\.credentials|"
                           r"claude-code|claude_code|x-app|user-agent[^\n]*claude|anthropic-beta|accessToken|refreshToken|"
                           r"CLAUDE_CODE", re.I)
    bad = []
    for f in SRC.glob("*.py"):
        for i, line in enumerate(f.read_text().splitlines(), 1):
            if forbidden.search(line):
                bad.append(f"{f.name}:{i}: {line.strip()[:80]}")
    assert bad == []
    text = (SRC / "claudecli.py").read_text()
    assert "~/" not in text and "expanduser" not in text and "environ" not in text  # never touches home / env secrets
    assert "--bare" not in text  # that mode would bypass the user's own login


def test_cli_args_are_tool_less_single_turn_and_flags_are_detected_not_guessed():
    f = claudecli.detect_flags(HELP)
    assert all(f[k] for k in ("print", "tools", "output_format", "no_session", "strict_mcp", "safe_mode"))
    a = claudecli.build_args("/bin/claude", f, system="S")
    assert a[:7] == ["/bin/claude", "-p", "--output-format", "json", "--tools", "", "--safe-mode"] and a[a.index("--tools") + 1] == ""
    # hardening: personal settings / hooks / CLAUDE.md are not loaded (--safe-mode); without that flag the CLI is refused
    with pytest.raises(LLMError, match="--safe-mode"):
        claudecli.build_args("/bin/claude", claudecli.detect_flags("-p, --print\n--tools\n--output-format"))
    assert "--no-session-persistence" in a and "--strict-mcp-config" in a and "--system-prompt" in a and "--mcp-config" not in a
    f2 = claudecli.detect_flags("--print\n--output-format")
    with pytest.raises(LLMError, match="refusing to run"):
        claudecli.build_args("/bin/claude", f2)
    only = claudecli.build_args("/bin/claude", claudecli.detect_flags("-p, --print\n--tools\n--output-format\n--safe-mode"))
    assert "--no-session-persistence" not in only  # optional flags only when the installed version has them


def test_cli_subprocess_isolation_stdin_cwd_timeout_and_json_parse(monkeypatch):
    seen = {}

    class R:
        returncode, stderr = 0, ""
        stdout = json.dumps({"result": "pong", "is_error": False, "usage": {"input_tokens": 5, "output_tokens": 2}})

    def fake_run(argv, **kw):
        seen.update(argv=argv, **kw)
        seen["cwd_empty"] = list(Path(kw["cwd"]).iterdir()) == []
        return R()
    monkeypatch.setattr(claudecli, "binary", lambda: "/bin/claude")
    monkeypatch.setattr(claudecli, "help_text", lambda b: HELP)
    monkeypatch.setattr(claudecli.subprocess, "run", fake_run)
    c = claudecli.ClaudeCLI(timeout=33, consent=True)
    assert c.generate("hello there", system="SYS") == "pong"
    assert seen["input"] == "hello there" and seen["timeout"] == 33 and seen["capture_output"] is True
    assert seen["cwd_empty"] and not str(seen["cwd"]).startswith(str(Path.cwd()))
    assert "--tools" in seen["argv"] and "env" not in seen  # inherits the environment untouched; we add nothing
    assert c.last_usage == {"in": 5, "out": 2}


def test_cli_consent_missing_binary_and_chat_tools(monkeypatch):
    monkeypatch.setattr(claudecli, "binary", lambda: None)
    with pytest.raises(LLMError, match="not found"):
        claudecli.ClaudeCLI(consent=True).generate("x")
    monkeypatch.setattr(claudecli, "binary", lambda: "/bin/claude")
    with pytest.raises(LLMError, match="consent"):
        claudecli.ClaudeCLI(consent=False).generate("x")
    with pytest.raises(LLMError) as e:
        claudecli.ClaudeCLI(consent=True).chat([{"role": "user", "content": "x"}], tools=[{"name": "t"}])
    assert e.value.no_tools


def test_cli_limit_or_auth_message_is_classified(monkeypatch):
    class R:
        returncode, stderr = 1, ""
        stdout = json.dumps({"result": "Claude usage limit reached. Your limit will reset at 5pm", "is_error": True})
    monkeypatch.setattr(claudecli, "binary", lambda: "/bin/claude")
    monkeypatch.setattr(claudecli, "help_text", lambda b: HELP)
    monkeypatch.setattr(claudecli.subprocess, "run", lambda *a, **k: R())
    with pytest.raises(LLMError) as e:
        claudecli.ClaudeCLI(consent=True).generate("x")
    assert e.value.kind == "limit"


def test_cli_router_excludes_bulk_and_classify_caps_interval_and_stops_on_limit(cfg, db):
    loc = entry(cfg, "local", "loc", roles=["chat", "classify", "summarize"])
    cli = entry(cfg, "claude_cli", "claude (CLI)", roles=["chat", "summarize"], consent=True)
    # claude_cli sits after local by default
    assert [m["id"] for m in cfg["models"]] == [loc["id"], cli["id"]]
    cfg["models"][0]["order"], cfg["models"][1]["order"] = 2, 1  # put it first to exercise the guards
    fl, fc = Fake("loc"), Fake("cli")
    r = router(cfg, db, **{loc["id"]: fl, cli["id"]: fc})
    assert r.summarize("n", "u", "s", "k", "r", []) == "cli"  # allowed role, first in order
    # min interval: a second call right away is refused -> falls to local
    assert r.summarize("n", "u", "s", "k", "r", []) == "loc" and "minimum" in r.blocked(cli, "summarize")
    # classify / date_kind are excluded by role; bulk jobs by context
    assert "excluded" in r.blocked(cli, "classify")
    db.c.execute("DELETE FROM llm_usage")
    with r.bulk():
        assert "bulk" in r.blocked(cli, "chat")
    cfg["claude_cli_allow_bulk"] = True
    with r.bulk():
        assert r.blocked(cli, "chat") is None
    cfg["claude_cli_allow_bulk"] = False
    # caps
    cfg["claude_cli"].update(min_interval_s=0, calls_per_hour=2)
    r.chat([{"role": "user", "content": "x"}]); r.chat([{"role": "user", "content": "x"}])
    assert "hourly call cap" in r.blocked(cli, "chat")
    # a limit/auth message stops the backend for the window and fails over
    db.c.execute("DELETE FROM llm_usage")
    fc.fail = LLMError("limit reached", kind="limit")
    assert r.chat([{"role": "user", "content": "x"}]).content == "loc"
    assert "stopped until" in r.blocked(cli, "chat")
    fc.calls.clear()
    r.chat([{"role": "user", "content": "x"}])
    assert fc.calls == []  # not even tried again during the window


def test_cli_needs_consent_flag_and_test_makes_exactly_one_call(cfg, db):
    cli = entry(cfg, "claude_cli", "claude (CLI)", roles=["chat"], consent=False)
    fc = Fake("cli")
    r = router(cfg, db, **{cli["id"]: fc})
    assert r.blocked(cli, "chat") == "no consent recorded"
    cli["consent"] = True
    assert r.test_model(cli["id"]) == "pong" and fc.calls == ["test"]
    assert db.c.execute("SELECT COUNT(*) FROM llm_usage WHERE model_id=?", (cli["id"],)).fetchone()[0] == 1


def test_cli_cost_guard_counts_calls_not_dollars(cfg, db, monkeypatch):
    cli = entry(cfg, "claude_cli", "claude (CLI)", roles=["chat"], consent=True)
    r = router(cfg, db, **{cli["id"]: Fake("cli")})
    cfg["claude_cli"]["min_interval_s"] = 0
    r.chat([{"role": "user", "content": "x"}])
    assert db.c.execute("SELECT cost_usd FROM llm_usage").fetchone()[0] == 0
    tables = []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    info = []
    monkeypatch.setattr(ui, "info", lambda m: info.append(m)); monkeypatch.setattr(ui, "fail", lambda m: info.append(m))
    modelcmds.cmd_llm(Ctx(cfg, db), [])
    t = [x for x in tables if hasattr(x, "row_count")][0]
    assert t.columns[6]._cells[0] == "calls only" and any("1/12 calls this hour" in m for m in info)


def test_checks_never_calls_the_cli_backend(cfg, db):
    from qurihunter import checks
    entry(cfg, "claude_cli", "claude (CLI)", roles=["chat"], consent=True)
    res = checks.models(cfg)
    assert res[0][1] is True and "not called by /test" in res[0][2]


# ── secrets / registry / help ───────────────────────────────────────────────
def test_secrets_are_masked_in_every_display(cfg, db):
    entry(cfg, "api", "m", base_url="https://r/v1", key=KEY)
    entry(cfg, "claude", "c", key=KEY)
    from qurihunter import ui as _ui
    from rich.console import Console
    con = Console(record=True, width=200)
    con.print(modelcmds.models_table(cfg))
    cfg["search"]["providers"]["serper"] = {"keys": ["SERPERKEY1234567890"], "limit": 100}
    con.print(_ui.config_summary(cfg))
    out = con.export_text()
    assert KEY not in out and "SERPERKEY1234567890" not in out and KEY[-4:] in out
    assert llmreg.describe(cfg["models"][0]).count(KEY) == 0


def test_new_commands_are_registered_and_in_help():
    from qurihunter import cli
    for c in ("/sequence", "/providers", "/searxng", "/llm", "/model"):
        assert c in cli.COMMANDS and any(h.split()[0] == c for h, _ in cli.HELP)
    help_text = " ".join(d for _, d in cli.HELP)
    assert "Claude CLI" in help_text and "local / API / Claude API key / Claude CLI" in help_text


def test_legacy_single_llm_config_still_works_without_models(monkeypatch):
    c = config.load()
    c["llm"].update(enabled=True, model="m", backend="ollama", host="http://localhost:11434")
    monkeypatch.setattr(Ollama, "running", lambda self: True)
    assert isinstance(llmmod.from_config(c), Ollama)
    c["models"] = [llmreg.new_entry(c, "local", "m")]
    assert isinstance(llmmod.from_config(c), llmreg.Router)
