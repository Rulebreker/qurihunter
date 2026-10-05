"""v0.4.3: Claude CLI availability checks and messaging."""
import json

import pytest

from qurihunter import claudecli, config, llmreg, modelcmds, ui
from qurihunter.db import DB
from qurihunter.llm import OpenAICompat

EMAIL = "someone.private@example.com"
FULL = ("This option needs the official Claude Code app, signed in with a paid Claude plan (Pro, Max, Team or Enterprise) or an "
        "Anthropic Console API key. The free Claude account does not include Claude Code, and qurihunter cannot use a free account "
        "directly. Other options: 1) a local model, 2) a free-tier API (any OpenAI-compatible endpoint, for example Gemini's free "
        "tier or your own relay), 3) a Claude API key from the Anthropic Console.")
HELP = "-p, --print\n--tools <t>\n--output-format <f>\n--no-session-persistence\n--strict-mcp-config\n--safe-mode\n"


class Script:
    def __init__(self, mp, answers):
        self.answers, self.shown, self.asked = list(answers), [], []
        mp.setattr(ui, "choose", lambda q, o, d=None: self._n(q))
        mp.setattr(ui, "ask", lambda q, d="", password=False: self._n(q))
        mp.setattr(ui, "yn", lambda q, d=True: self._n(q))
        for n in ("info", "ok", "fail"):
            mp.setattr(ui, n, lambda m: self.shown.append(str(m)))
        mp.setattr(ui.console, "print", lambda *a, **k: self.shown.append(" ".join(str(x) for x in a)))

    def _n(self, q):
        self.asked.append(q)
        return self.answers.pop(0)

    @property
    def text(self):
        return "\n".join(self.shown + self.asked)


@pytest.fixture
def cfg():
    return config.load()


def env(mp, *, binary="/bin/claude", infos=({"kind": "subscription", "plan": "pro", "how": "claude.ai"},), login=True):
    ev, seq = [], list(infos)
    mp.setattr(claudecli, "binary", lambda: binary)
    mp.setattr(claudecli, "help_text", lambda b: HELP)
    mp.setattr(claudecli, "auth_info", lambda b: seq.pop(0) if len(seq) > 1 else seq[0])
    mp.setattr(claudecli, "auth_commands", lambda b: {"status": True, "login": login})
    mp.setattr(claudecli, "run_login", lambda b: ev.append("login") or True)
    mp.setattr(llmreg.Router, "test_model", lambda self, mid: ev.append("test") or "pong")
    mp.setattr(OpenAICompat, "models", lambda self: [])
    mp.setattr(OpenAICompat, "test", lambda self: "pong")
    return ev


def api_branch():  # after returning to step 1: pick 2 (API), url, key, model, roles, order
    return ["2", "https://r/v1", "", "m", "", ""]


def test_binary_missing_prints_exactly_the_message_asks_nothing_and_returns_to_step_1(cfg, monkeypatch):
    env(monkeypatch, binary=None)
    s = Script(monkeypatch, ["4", *api_branch()])
    ents = modelcmds.add_model_wizard(cfg)
    assert FULL in s.shown and s.text.count("Which kind of model") == 2  # message printed, step 1 shown again
    i4 = s.asked.index("Choice") if "Choice" in s.asked else 0
    assert s.asked[1] == "Choice" and not any(w in s.asked[1].lower() for w in ("use it", "login"))  # no question between "4" and step 1
    assert ents[0]["type"] == "api" and not any(m["type"] == "claude_cli" for m in cfg["models"])


def test_not_logged_in_offers_the_official_login_and_declining_returns_to_step_1_with_the_message(cfg, monkeypatch):
    ev = env(monkeypatch, infos=({"kind": "none"},))
    s = Script(monkeypatch, ["4", False, *api_branch()])  # type 4, launch login? no
    modelcmds.add_model_wizard(cfg)
    assert "Launch the official login now" in s.text and ev == [] and FULL in s.shown
    assert not any("Use it?" in q for q in s.asked) and not any(m["type"] == "claude_cli" for m in cfg["models"])


def test_not_logged_in_then_login_works_continues_to_the_warning(cfg, monkeypatch):
    ev = env(monkeypatch, infos=({"kind": "none"}, {"kind": "subscription", "plan": "max", "how": "claude.ai"}))
    s = Script(monkeypatch, ["4", True, True])
    ents = modelcmds.add_model_wizard(cfg)
    assert ev[0] == "login" and ents[0]["type"] == "claude_cli" and "Use it?" in s.asked and FULL not in s.shown


def test_login_launched_but_the_account_has_no_claude_code_shows_the_same_message(cfg, monkeypatch):
    ev = env(monkeypatch, infos=({"kind": "none"}, {"kind": "free", "plan": "free", "how": "claude.ai"}))
    s = Script(monkeypatch, ["4", True, *api_branch()])
    modelcmds.add_model_wizard(cfg)
    assert ev == ["login"] and FULL in s.shown and not any(m["type"] == "claude_cli" for m in cfg["models"])


def test_logged_in_with_a_free_plan_style_account_is_refused_without_questions(cfg, monkeypatch):
    env(monkeypatch, infos=({"kind": "free", "plan": "free", "how": "claude.ai"},))
    s = Script(monkeypatch, ["4", *api_branch()])
    modelcmds.add_model_wizard(cfg)
    assert FULL in s.shown and "Use it?" not in s.asked and s.text.count("Which kind of model") == 2


def test_not_logged_in_and_no_login_command_prints_instructions_then_the_message(cfg, monkeypatch):
    env(monkeypatch, infos=({"kind": "none"},), login=False)
    s = Script(monkeypatch, ["4", *api_branch()])
    modelcmds.add_model_wizard(cfg)
    assert "follow its login prompt" in s.text and FULL in s.shown and "Launch the official login" not in s.text


def test_api_key_login_says_one_line_about_per_token_billing_then_continues(cfg, monkeypatch):
    env(monkeypatch, infos=({"kind": "api_key", "plan": "", "how": "api_key"},))
    s = Script(monkeypatch, ["4", True])
    ents = modelcmds.add_model_wizard(cfg)
    one = [m for m in s.shown if "billed per token by Anthropic" in m]
    assert len(one) == 1 and "/llm status will count calls only (no price table)" in one[0] and "\n" not in one[0]
    assert ents[0]["type"] == "claude_cli" and "Use it?" in s.asked and FULL not in s.shown
    assert llmreg.get(cfg, ents[0]["id"]).get("price_in") is None


def test_subscription_login_continues_straight_to_the_warning(cfg, monkeypatch):
    ev = env(monkeypatch)
    s = Script(monkeypatch, ["4", True])
    ents = modelcmds.add_model_wizard(cfg)
    assert ents[0]["type"] == "claude_cli" and ev == ["test"] and FULL not in s.shown and not any("billed per token" in m for m in s.shown)


# ── auth_info parses the REAL `claude auth status` JSON shape and keeps only two fields ──
class R:
    def __init__(self, rc, out):
        self.returncode, self.stdout, self.stderr = rc, out, ""


def status(monkeypatch, rc, payload):
    monkeypatch.setattr(claudecli, "auth_commands", lambda b: {"status": True, "login": True})
    monkeypatch.setattr(claudecli, "_run", lambda argv, timeout=20: R(rc, json.dumps(payload)))
    return claudecli.auth_info("/bin/claude")


@pytest.mark.parametrize("rc,payload,kind,plan", [
    (0, {"loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "pro", "email": EMAIL}, "subscription", "pro"),
    (0, {"loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "max", "email": EMAIL}, "subscription", "max"),
    (0, {"loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "free", "email": EMAIL}, "free", "free"),
    (0, {"loggedIn": True, "authMethod": "api_key", "email": EMAIL}, "api_key", ""),
    (0, {"loggedIn": True, "authMethod": "api_key_helper"}, "api_key", ""),
    (1, {"loggedIn": False, "authMethod": "none"}, "none", ""),
    (0, {"loggedIn": True, "authMethod": "something_new"}, "unknown", ""),
])
def test_auth_info_kinds_and_no_email_or_credential_in_the_result(monkeypatch, rc, payload, kind, plan):
    i = status(monkeypatch, rc, payload)
    assert i["kind"] == kind and i["plan"] == plan and EMAIL not in json.dumps(i)
    assert set(i) == {"kind", "plan", "how"}
    label = claudecli.login_label("/bin/claude")
    assert EMAIL not in label


def test_login_labels_and_missing_binary(monkeypatch):
    assert claudecli.login_label(None) == "not installed"
    for kind, plan, want in (("subscription", "pro", "subscription (pro)"), ("api_key", "", "API key"), ("none", "", "not logged in"),
                             ("free", "free", "free account (not usable)")):
        monkeypatch.setattr(claudecli, "auth_info", lambda b, k=kind, p=plan: {"kind": k, "plan": p, "how": ""})
        assert claudecli.login_label("/bin/claude") == want


def test_model_list_and_info_show_the_login_type_without_credentials(cfg, monkeypatch):
    e = llmreg.new_entry(cfg, "claude_cli", "claude (CLI)", roles=["chat"], consent=True)
    llmreg.add_model(cfg, e)
    db = None
    tables, out = [], []
    monkeypatch.setattr(ui.console, "print", lambda *a, **k: tables.append(a[0] if a else None))
    monkeypatch.setattr(ui, "info", lambda m: out.append(str(m))); monkeypatch.setattr(ui, "fail", lambda m: out.append(str(m)))
    monkeypatch.setattr(claudecli, "binary", lambda: "/bin/claude")
    monkeypatch.setattr(claudecli, "auth_info", lambda b: {"kind": "api_key", "plan": "", "how": "api_key"})

    class Ctx:
        pass
    ctx = Ctx(); ctx.cfg = cfg
    modelcmds.cmd_model(ctx, ["list"])
    t = [x for x in tables if hasattr(x, "row_count")][0]
    assert t.columns[-1].header == "Login" and t.columns[-1]._cells == ["API key"]
    modelcmds.cmd_model(ctx, ["info"])
    text = "\n".join(out + [str(x) for x in tables if isinstance(x, str)])
    assert "login: API key" in text and "billed per token" in text and "counts calls only" in text and EMAIL not in text
    monkeypatch.setattr(claudecli, "auth_info", lambda b: {"kind": "subscription", "plan": "pro", "how": "claude.ai"})
    out.clear()
    modelcmds.cmd_model(ctx, ["info"])
    assert "login: subscription (pro)" in "\n".join(out)
    monkeypatch.setattr(claudecli, "auth_info", lambda b: {"kind": "none"})
    out.clear()
    modelcmds.cmd_model(ctx, ["info"])
    assert "login: not logged in" in "\n".join(out)


def test_who_can_use_text_is_the_exact_wording_and_readme_has_it():
    assert claudecli.WHO_CAN_USE == FULL
    from pathlib import Path
    readme = (Path(__file__).parent.parent / "README.md").read_text()
    assert "Who can use the Claude CLI backend" in readme and FULL in readme.replace("\n", " ")
    assert "optional, experimental and off by default" in readme and "Claude Free accounts are not supported" in readme
