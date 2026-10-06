"""Model registry, role-based routing with failover, spend/call accounting and the cost guard.

cfg["models"] entries: {id, type local|api|claude|claude_cli, base_url, model, key, roles, enabled, order, free,
price_in, price_out (USD per million tokens, user supplied - never assumed), consent (claude_cli)}.
Keys live only in config.json (chmod 600); every display shows the last 4 characters only."""
from __future__ import annotations

import contextlib
from datetime import timedelta

from . import config, dates
from .claudecli import ClaudeCLI
from .config import ROLES, mask
from .llm import LLM, Anthropic, ChatReply, LLMError, Ollama, OpenAICompat
from .logs import log

TYPES = ("local", "api", "claude", "claude_cli")
CLI_ROLES = ["chat", "summarize", "dork_gen"]  # claude_cli: never classify / date_kind / bulk by default
PAID_TYPES = ("api", "claude")


# ───────────────────────────── registry helpers ─────────────────────────────
def next_id(cfg: dict) -> str:
    ids = {m["id"] for m in cfg.get("models", [])}
    n = 1
    while f"m{n}" in ids:
        n += 1
    return f"m{n}"


def new_entry(cfg: dict, type_: str, model: str, *, base_url: str = "", key: str = "", roles=None, free: bool = False,
              price_in=None, price_out=None, consent: bool = False) -> dict:
    roles = [r for r in (roles or ROLES) if r in ROLES]
    if type_ == "claude_cli" and not cfg.get("claude_cli_allow_bulk"):
        roles = [r for r in roles if r in CLI_ROLES]  # the wizard switches allow_bulk on after the user's explicit yes
    return {"id": next_id(cfg), "type": type_, "base_url": base_url, "model": model, "key": key, "roles": roles,
            "enabled": True, "order": len(cfg.get("models", [])) + 1, "free": free or type_ == "local",
            "price_in": price_in, "price_out": price_out, "consent": consent}


def add_model(cfg: dict, entry: dict, position: int | None = None) -> None:
    ms = cfg.setdefault("models", [])
    ms.append(entry)
    if position:
        ms.sort(key=lambda m: m["order"])
        ms.remove(entry)
        ms.insert(max(0, min(len(ms), position - 1)), entry)
        for i, m in enumerate(ms, 1):
            m["order"] = i
    renumber(cfg)
    sync_legacy(cfg)


def remove_model(cfg: dict, mid: str) -> bool:
    n = len(cfg.get("models", []))
    cfg["models"] = [m for m in cfg.get("models", []) if m["id"] != mid]
    renumber(cfg)
    sync_legacy(cfg)
    return len(cfg["models"]) != n


def renumber(cfg: dict) -> None:
    ms = sorted(cfg.get("models", []), key=lambda m: m.get("order", 99))
    for i, m in enumerate(ms, 1):
        m["order"] = i
    cfg["models"] = ms


def get(cfg: dict, mid: str) -> dict | None:
    return next((m for m in cfg.get("models", []) if m["id"] == mid), None)


def move(cfg: dict, mid: str, position: int) -> bool:
    m = get(cfg, mid)
    if not m:
        return False
    ms = sorted(cfg["models"], key=lambda x: x["order"])
    ms.remove(m)
    ms.insert(max(0, min(len(ms), position - 1)), m)
    for i, x in enumerate(ms, 1):
        x["order"] = i
    cfg["models"] = ms
    renumber(cfg)
    sync_legacy(cfg)
    return True


def set_roles(cfg: dict, mid: str, roles: list[str], confirm=None) -> str | None:
    m = get(cfg, mid)
    if not m:
        return f"no model '{mid}'"
    bad = [r for r in roles if r not in ROLES]
    if bad:
        return f"unknown role(s): {', '.join(bad)} (roles: {', '.join(ROLES)})"
    if m["type"] == "claude_cli":
        excl = [r for r in roles if r not in CLI_ROLES]
        if excl and not cfg.get("claude_cli_allow_bulk"):
            c = cfg.get("claude_cli", {})
            others = [x["id"] for x in cfg.get("models", []) if x["id"] != mid and x.get("enabled")]
            if confirm is None:
                return (f"claude_cli may only handle {', '.join(CLI_ROLES)} (not {', '.join(excl)}) unless bulk use is switched "
                        "on: /llm bulk on")
            if not confirm(f"Allow the Claude CLI for {', '.join(excl)}? Bulk-style work runs through batches of "
                           f"{c.get('batch_size', 10)} pages per call with caps of {c.get('calls_per_hour', 12)} calls/hour and "
                           f"{c.get('calls_per_day', 80)}/day"
                           + (f"; {', '.join(others)} stays as fallback" if others else "") + ". Continue?"):
                return "not changed (bulk use for the Claude CLI was declined)"
            cfg["claude_cli_allow_bulk"] = True  # the single switch: /llm bulk on|off
    m["roles"] = roles
    sync_legacy(cfg)
    return None


def sync_legacy(cfg: dict) -> None:
    """Keep the old single-LLM block meaningful for code that still reads it (reversible migration)."""
    l = cfg["llm"]
    on = [m for m in cfg.get("models", []) if m.get("enabled")]
    l["enabled"] = bool(on)
    first = next((m for m in on if m["type"] in ("local", "api")), None)
    if first:
        l["model"] = first["model"]
        l["backend"] = "openai" if first["type"] == "api" else "ollama"
        if first["type"] == "api":
            l["base_url"], l["api_key"] = first["base_url"], first.get("key", "")
        else:
            l["host"] = first.get("base_url") or l["host"]


def describe(m: dict) -> str:
    return {"local": f"local {m['model']} @ {m['base_url']}", "api": f"API {m['model']} @ {m['base_url']}",
            "claude": f"Claude API {m['model']}", "claude_cli": "Claude via official CLI (experimental)"}[m["type"]]


def key_hint(m: dict) -> str:
    return mask(m["key"]) if m.get("key") else "-"


def build(m: dict, cfg: dict) -> LLM:
    t = m["type"]
    if t == "local":
        return Ollama(m.get("base_url") or cfg["llm"]["host"], m["model"])
    if t == "api":
        return OpenAICompat(m.get("base_url", ""), m.get("key", ""), m["model"])
    if t == "claude":
        return Anthropic(m.get("key", ""), m["model"])
    if t == "claude_cli":
        c = cfg.get("claude_cli", {})
        return ClaudeCLI(timeout=float(c.get("timeout_s", 180)), consent=bool(m.get("consent")),
                         batch_size=int(c.get("batch_size", 10)))
    raise LLMError(f"unknown model type {t}")


# ───────────────────────────── accounting ─────────────────────────────
def _day_start() -> str:
    return dates.iso(dates.utcnow().astimezone(dates.local_tz()).replace(hour=0, minute=0, second=0, microsecond=0))


def _month_start() -> str:
    return dates.iso(dates.utcnow().astimezone(dates.local_tz()).replace(day=1, hour=0, minute=0, second=0, microsecond=0))


def spent(db, since: str, model_id: str | None = None) -> float:
    q, a = "SELECT COALESCE(SUM(cost_usd),0) FROM llm_usage WHERE ts>=?", [since]
    if model_id:
        q += " AND model_id=?"; a.append(model_id)
    return float(db.c.execute(q, a).fetchone()[0])


def calls_since(db, model_id: str, since: str) -> int:
    return db.c.execute("SELECT COUNT(*) FROM llm_usage WHERE model_id=? AND ts>=?", (model_id, since)).fetchone()[0]


def cost(m: dict, tin: int, tout: int) -> float | None:
    """USD from the user's own price table; None when no price was entered (cost tracking skipped, never assumed)."""
    if m.get("price_in") is None and m.get("price_out") is None:
        return None
    return ((tin or 0) * float(m.get("price_in") or 0) + (tout or 0) * float(m.get("price_out") or 0)) / 1e6


def budget_state(db, cfg: dict) -> dict:
    b = cfg.get("llm_budget", {})
    d, mo = spent(db, _day_start()), spent(db, _month_start())
    dl, ml = float(b.get("daily_usd") or 0), float(b.get("monthly_usd") or 0)
    return {"day": d, "month": mo, "day_limit": dl, "month_limit": ml,
            "day_pct": (d / dl * 100) if dl else 0.0, "month_pct": (mo / ml * 100) if ml else 0.0,
            "warn_pct": float(b.get("warn_pct", 80))}


class Router(LLM):
    """Role-based router over cfg["models"]: the first enabled model in the role's order answers; on error/timeout/quota/
    budget the next one is tried. Every call is recorded (tokens, estimated cost) in llm_usage."""

    def __init__(self, cfg: dict, db=None):
        self.cfg = cfg
        self._db = db
        self._inst: dict[str, LLM] = {}
        self._bulk = False
        self.host = "model registry"
        self.last_model_id = ""  # which registry entry answered the most recent successful call (/why shows it)

    # ── plumbing ───────────────────────────────────────────────────────────────
    @property
    def db(self):
        if self._db is None:
            from .db import DB
            self._db = DB()
        return self._db

    def has_models(self) -> bool:
        return any(m.get("enabled") for m in self.cfg.get("models", []))

    def __bool__(self) -> bool:
        return self.has_models()

    @property
    def model(self) -> str:  # type: ignore[override]
        ms = [m for m in self.cfg.get("models", []) if m.get("enabled")]
        return ms[0]["model"] if ms else ""

    def describe(self) -> str:
        return ", ".join(f"{m['id']}:{describe(m)}" for m in sorted(self.cfg.get("models", []), key=lambda x: x["order"])
                         if m.get("enabled")) or "no model"

    def available(self) -> bool:
        return self.has_models()

    def entries(self, role: str) -> list[dict]:
        return [m for m in sorted(self.cfg.get("models", []), key=lambda x: x["order"])
                if m.get("enabled") and role in m.get("roles", [])]

    @contextlib.contextmanager
    def bulk(self):
        """Mark a bulk job: claude_cli is excluded from it unless claude_cli_allow_bulk is on."""
        old, self._bulk = self._bulk, True
        try:
            yield self
        finally:
            self._bulk = old

    def for_role(self, role: str) -> "RoleView":
        return RoleView(self, role)

    def _get(self, m: dict) -> LLM:
        if m["id"] not in self._inst:
            self._inst[m["id"]] = build(m, self.cfg)
        return self._inst[m["id"]]

    # ── guards ─────────────────────────────────────────────────────────────────
    def blocked(self, m: dict, role: str) -> str | None:
        db = self.db
        if m["type"] == "claude_cli":
            caps = self.cfg.get("claude_cli", {})
            if not m.get("consent"):
                return "no consent recorded"
            allow_bulk = bool(self.cfg.get("claude_cli_allow_bulk"))
            if role not in CLI_ROLES and not allow_bulk:
                return f"role '{role}' is excluded for the Claude CLI"
            if self._bulk and not allow_bulk:
                return "bulk jobs are excluded for the Claude CLI (claude_cli_allow_bulk is off)"
            stop = db.meta(f"llm_stop:{m['id']}")
            if stop and stop > dates.now_iso():
                return f"stopped until {dates.to_local(stop)} after a limit/auth message"
            now = dates.utcnow()
            if calls_since(db, m["id"], dates.iso(now - timedelta(hours=1))) >= int(caps.get("calls_per_hour", 6)):
                return "hourly call cap reached"
            if calls_since(db, m["id"], dates.iso(now - timedelta(days=1))) >= int(caps.get("calls_per_day", 30)):
                return "daily call cap reached"
            last = db.c.execute("SELECT MAX(ts) FROM llm_usage WHERE model_id=?", (m["id"],)).fetchone()[0]
            gap = float(caps.get("min_interval_s", 30))
            if last and (now - dates.parse_date(last)).total_seconds() < gap:
                return f"minimum {gap:.0f}s between calls"
        elif m["type"] in PAID_TYPES and not m.get("free"):
            st = budget_state(db, self.cfg)
            if st["day_limit"] and st["day"] >= st["day_limit"]:
                return f"daily budget ${st['day_limit']:.2f} reached"
            if st["month_limit"] and st["month"] >= st["month_limit"]:
                return f"monthly budget ${st['month_limit']:.2f} reached"
        return None

    def _record(self, m: dict, role: str, ok: bool, inst: LLM, err: str = "") -> None:
        u = getattr(inst, "last_usage", None) or {}
        tin, tout = int(u.get("in", 0) or 0), int(u.get("out", 0) or 0)
        c = cost(m, tin, tout) if m["type"] in PAID_TYPES and not m.get("free") else None
        self.db.c.execute("INSERT INTO llm_usage(ts,model_id,role,ok,tokens_in,tokens_out,cost_usd,error) VALUES(?,?,?,?,?,?,?,?)",
                          (dates.now_iso(), m["id"], role, int(ok), tin, tout, c or 0.0, err[:200]))
        inst.last_usage = {}
        self.db.commit()
        if ok and c:
            st = budget_state(self.db, self.cfg)
            top = max(st["day_pct"], st["month_pct"])
            day = dates.now_iso()[:10]
            if top >= st["warn_pct"] and self.db.meta("llm_warn_day") != day:
                self.db.set_meta("llm_warn_day", day)
                self.db.commit()
                log.warning("LLM spend is at %.0f%% of its budget (daily $%.4f/$%.2f, monthly $%.4f/$%.2f)", top,
                            st["day"], st["day_limit"], st["month"], st["month_limit"])

    def _stop_if_limited(self, m: dict, e: LLMError) -> None:
        if m["type"] == "claude_cli" and e.kind in ("limit", "auth", "quota", "rate"):
            hours = 24 if e.kind in ("auth", "quota") else 1
            self.db.set_meta(f"llm_stop:{m['id']}", dates.iso(dates.utcnow() + timedelta(hours=hours)))
            self.db.commit()
            log.warning("Claude CLI backend stopped for %dh: %s", hours, e)

    # ── dispatch ───────────────────────────────────────────────────────────────
    def _dispatch(self, role: str, method: str, *a, **kw):
        from . import dblock
        dblock.flush()  # no write transaction may straddle a (slow) model call
        why: list[str] = []
        for m in self.entries(role):
            b = self.blocked(m, role)
            if b:
                why.append(f"{m['id']}: {b}")
                continue
            inst = self._get(m)
            try:
                out = getattr(inst, method)(*a, **kw)
            except LLMError as e:
                self._record(m, role, False, inst, str(e))
                self._stop_if_limited(m, e)
                if e.no_tools:
                    raise  # same model, no native tools: the caller switches protocol
                why.append(f"{m['id']}: {e}")
                continue
            except Exception as e:  # noqa: BLE001 - a backend bug must not crash a scan
                self._record(m, role, False, inst, f"{type(e).__name__}: {e}")
                why.append(f"{m['id']}: {type(e).__name__}")
                continue
            self._record(m, role, True, inst)
            self.last_model_id = f"{m['id']} ({describe(m)})"
            return out
        raise LLMError(f"no model could handle role '{role}'" + (f" ({'; '.join(why)})" if why else " (none assigned)"))

    def classify(self, url, title, snippet, page_text=""):
        return self._dispatch("classify", "classify", url, title, snippet, page_text)

    @property
    def batch_size(self) -> int:  # type: ignore[override]
        """Pages per classify call for the model that would answer now (1 = no batching)."""
        for m in self.entries("classify"):
            if self.blocked(m, "classify") is None:
                return int(getattr(self._get(m), "batch_size", 1) or 1)
        return 1

    def classify_batch(self, items):
        return self._dispatch("classify", "classify_batch", items)

    def summarize(self, *a, **kw):
        return self._dispatch("summarize", "summarize", *a, **kw)

    def date_kind(self, text, date):
        return self._dispatch("date_kind", "date_kind", text, date)

    def generate(self, prompt, *, json_mode=False, timeout=180, system=None, role="summarize"):
        return self._dispatch(role, "generate", prompt, json_mode=json_mode, timeout=timeout, system=system)

    def chat(self, messages, tools=None, timeout=180, role="chat") -> ChatReply:
        return self._dispatch(role, "chat", messages, tools=tools, timeout=timeout)

    def test_model(self, mid: str) -> str:
        """Exactly ONE call to one model (never failover): for /model test."""
        from . import dblock
        dblock.flush()
        m = get(self.cfg, mid)
        if not m:
            raise LLMError(f"no model '{mid}'")
        b = self.blocked(m, m["roles"][0] if m["roles"] else "chat")
        if b and m["type"] == "claude_cli":
            raise LLMError(f"not allowed right now: {b}")
        inst = self._get(m)
        try:
            out = inst.test()
        except LLMError as e:
            self._record(m, "test", False, inst, str(e))
            self._stop_if_limited(m, e)
            raise
        self._record(m, "test", True, inst)
        return out

    def test(self) -> str:
        return self.generate("Reply with exactly the single word: pong", role="chat")[:60]


class RoleView(LLM):
    """A Router bound to one role, so callers that only know generate()/chat() hit the right model order."""

    def __init__(self, router: Router, role: str):
        self.r, self.role = router, role
        self.host, self.model = router.host, router.model

    @property
    def last_model_id(self) -> str:
        return self.r.last_model_id

    def bulk(self):
        return self.r.bulk()

    def __bool__(self) -> bool:
        return bool(self.r.entries(self.role))

    def available(self) -> bool:
        return bool(self.r.entries(self.role))

    def describe(self) -> str:
        return self.r.describe()

    def generate(self, prompt, *, json_mode=False, timeout=180, system=None):
        return self.r.generate(prompt, json_mode=json_mode, timeout=timeout, system=system, role=self.role)

    def chat(self, messages, tools=None, timeout=180):
        return self.r.chat(messages, tools=tools, timeout=timeout, role=self.role)

    def classify(self, *a, **kw):
        return self.r.classify(*a, **kw)

    @property
    def batch_size(self) -> int:  # type: ignore[override]
        return self.r.batch_size

    def classify_batch(self, items):
        return self.r.classify_batch(items)

    def summarize(self, *a, **kw):
        return self.r.summarize(*a, **kw)

    def date_kind(self, *a, **kw):
        return self.r.date_kind(*a, **kw)

    def test(self):
        return self.r.test()


def role_view(llm, role: str):
    """llm may be a Router (-> role-bound view) or a plain single backend (returned unchanged)."""
    return llm.for_role(role) if hasattr(llm, "for_role") else llm


# ───────────────────────────── bulk estimates ─────────────────────────────
def estimate_bulk(cfg: dict, role: str, calls: int, tok_in: int = 1500, tok_out: int = 150) -> dict:
    """Which model would take a bulk job for `role` and what it would cost: {model, paid, usd (None = unknown)}."""
    ms = [m for m in sorted(cfg.get("models", []), key=lambda x: x["order"]) if m.get("enabled") and role in m.get("roles", [])]
    for m in ms:
        if m["type"] == "claude_cli" and not cfg.get("claude_cli_allow_bulk"):
            continue
        if m["type"] == "local" or (m["type"] in PAID_TYPES and m.get("free")):
            return {"model": m, "paid": False, "usd": 0.0, "calls": calls}
        c = cost(m, tok_in * calls, tok_out * calls)
        return {"model": m, "paid": True, "usd": c, "calls": calls}
    return {"model": None, "paid": False, "usd": 0.0, "calls": calls}


def confirm_bulk(cfg: dict, role: str, calls: int, what: str, ask) -> bool:
    """For a bulk job: free models run without a question; a paid one shows the estimate and asks first."""
    e = estimate_bulk(cfg, role, calls)
    if not e["paid"]:
        return True
    m = e["model"]
    usd = "unknown (no price entered)" if e["usd"] is None else f"about ${e['usd']:.4f}"
    unit = "counted in calls" if m["type"] == "claude_cli" else usd
    return bool(ask(f"{what}: ~{calls} calls on the paid model {m['id']} ({describe(m)}), cost {unit}. Continue?"))


# ───────────────────────────── /llm status ─────────────────────────────
def usage_rows(db, cfg: dict) -> list[dict]:
    out = []
    for m in sorted(cfg.get("models", []), key=lambda x: x["order"]):
        r = db.c.execute("SELECT COUNT(*) n, COALESCE(SUM(ok),0) ok, COALESCE(SUM(tokens_in),0) tin, "
                         "COALESCE(SUM(tokens_out),0) tout, COALESCE(SUM(cost_usd),0) usd FROM llm_usage WHERE model_id=?",
                         (m["id"],)).fetchone()
        last = db.c.execute("SELECT error FROM llm_usage WHERE model_id=? AND ok=0 ORDER BY id DESC LIMIT 1", (m["id"],)).fetchone()
        out.append({"model": m, "calls": r["n"], "ok": r["ok"], "failed": r["n"] - r["ok"], "tin": r["tin"], "tout": r["tout"],
                    "usd": r["usd"], "today_usd": spent(db, _day_start(), m["id"]), "month_usd": spent(db, _month_start(), m["id"]),
                    "last_error": last["error"] if last else ""})
    return out


def role_rows(db) -> list:
    return db.c.execute("SELECT role, model_id, COUNT(*) n, COALESCE(SUM(tokens_in+tokens_out),0) tok, "
                        "COALESCE(SUM(cost_usd),0) usd FROM llm_usage GROUP BY role, model_id ORDER BY role").fetchall()
