from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .dorkparse import ParsedDork, parse

PT = ZoneInfo("America/Los_Angeles")
FRESHNESS = ("day", "week", "month", "year")


@dataclass
class SearchResult:
    """Provider-independent result."""
    title: str
    url: str
    snippet: str = ""
    published: str | None = None  # UTC ISO page date when the provider supplies one (weak launch signal)
    verdict: dict | None = None  # filled by classify.prepare_batch(): a batched LLM verdict (saves a call)
    rules_only: bool = False  # set by the relevance gate: no snippet to confirm relevance -> cheap rules check only


_FRESH_DAYS = {"day": 1, "week": 7, "month": 31, "year": 365}


def fresh_days(fresh) -> float | None:
    """`fresh` is a legacy label ('week') or a number of days; returns days or None."""
    if not fresh:
        return None
    if isinstance(fresh, (int, float)):
        return float(fresh)
    return float(_FRESH_DAYS.get(fresh, 0)) or None


def date_from(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


def retry_after(resp) -> float | None:
    """Seconds from a Retry-After header (numeric form), else None."""
    try:
        v = float((getattr(resp, "headers", {}) or {}).get("Retry-After", ""))
        return v if 0 <= v < 3600 else None
    except (TypeError, ValueError):
        return None


class DryRun(Exception):
    """Raised by _send() in preview mode: carries the (sanitised) request that WOULD have been sent."""

    def __init__(self, req: dict):
        super().__init__("dry run")
        self.req = req


_SECRET_KEYS = {"api_key", "key", "x-api-key", "authorization", "x-subscription-token"}


def _mask(v) -> str:
    v = str(v)
    if v.lower().startswith("bearer "):
        return "Bearer …" + v[-4:]
    return "…" + v[-4:] if len(v) > 6 else "***"


def sanitise_request(method: str, url: str, kw: dict) -> dict:
    """The request as the provider will receive it, with every secret masked to its last 4 characters."""
    clean = lambda d: {k: (_mask(v) if str(k).lower() in _SECRET_KEYS else v) for k, v in (d or {}).items()}  # noqa: E731
    out = {"method": method, "url": url}
    if kw.get("params") is not None:
        out["params"] = clean(kw["params"])
    if kw.get("json") is not None:
        out["json"] = clean(kw["json"])
    if kw.get("headers"):
        out["headers"] = clean(kw["headers"])
    return out


class Unexpressible(Exception):
    """This provider cannot run the dork (no TLD/site support and no rewrite). Not an error; costs no quota."""


class ProviderError(Exception):
    """kind: 'quota' (key spent for this period), 'invalid' (bad key/config),
    'transient' (network / rate limit — try again later)."""

    def __init__(self, kind: str, msg: str, retry_after: float | None = None):
        from ..http import redact  # keys can appear in URLs inside exception text
        msg = redact(msg)
        super().__init__(msg)
        self.kind, self.msg = kind, msg
        self.retry_after = retry_after  # seconds from a 429 Retry-After header, when the server sent one


@dataclass
class Page:
    results: list[SearchResult]
    has_more: bool = False


class Provider:
    id = ""
    label = ""
    period = "day"  # quota window: "day" (Pacific midnight) or "month" (UTC)
    default_limit = 100
    page_size = 10
    paginates = True
    native_tld = False  # True if the engine itself understands `site:.cc`
    tld_mode = "none"  # none (rewrite to natural language) | emulated (country param + client filter) | native
    supports_site = True  # site:<domain> (or include/exclude domains) can be expressed
    supports_inurl = False  # inurl:/intitle: kept as operators (otherwise flattened into plain terms)
    operators = "none"  # none | basic (site:, quotes, -minus) | full (inurl:, intitle:, OR ...)
    needs_key = True
    quota_default = ""  # monthly | daily | lifetime | unlimited ("" = derived from `period`)
    max_qps = 2.0  # requests per second this provider tolerates (shared limiter, all threads)
    native_dates = True  # False -> recency is applied client-side from result `published` dates
    extra_fields: dict[str, str] = {}  # option name -> prompt (e.g. Google's cx)
    help = ""  # one-liner shown in /config
    limitations = ""

    def __init__(self, options: dict | None = None):
        self.options = options or {}

    # --- to implement ---------------------------------------------------------
    def _search(self, key: str, pd: ParsedDork, page: int, fresh: str) -> list[SearchResult]:
        raise NotImplementedError

    def test(self, key: str) -> tuple[bool, str]:
        """Live test of one key with a minimal query."""
        try:
            n = len(self._search(key, parse("security.txt"), 0, ""))
            return True, f"query OK ({n} results)"
        except ProviderError as e:
            return False, f"{e.kind}: {e.msg}"
        except Exception as e:  # noqa: BLE001
            return False, str(e)

    def detect_quota(self, key: str) -> dict | None:
        """The key's real remaining quota from the provider's account/usage endpoint or rate-limit headers, as
        {remaining, limit, type, source}; None when the provider offers nothing verified (the default allowance is used)."""
        return None

    def missing_options(self) -> list[str]:
        return [f for f in self.extra_fields if not self.options.get(f)]

    # --- request capture / preview ---------------------------------------------
    last_request: dict | None = None
    _dry = False

    def _send(self, fn, method: str, url: str, **kw):
        """Every provider sends through here: the request is recorded (secrets masked) so /dorks test can print exactly what
        the provider received, and in preview mode nothing is sent at all."""
        self.last_request = sanitise_request(method, url, kw)
        if self._dry:
            raise DryRun(self.last_request)
        return fn(method, url, **kw)

    def preview(self, dork: str, *, page: int = 0, days: float | None = None) -> dict | None:
        """The request that WOULD be sent (nothing is sent, no quota is used). None if the provider sends nothing."""
        self._dry, self.last_request = True, None
        try:
            self.search("DRY-RUN-KEY-0000", dork, page=page, days=days)
        except DryRun as d:
            return d.req
        except ProviderError as e:
            return {"error": e.msg}
        finally:
            self._dry = False
        return None

    # --- capabilities ---------------------------------------------------------
    def capabilities(self) -> dict:
        return {"operators": self.operators, "needs_key": "yes" if self.needs_key else "no",
                "quota_type": self.quota_type(), "max_qps": self.max_qps,
                "supports_tld_filter": {"native": "yes", "emulated": "partial", "none": "no"}[self.tld_mode],
                "supports_site": "yes" if self.supports_site else "no",
                "supports_inurl": "yes" if self.supports_inurl else "no (flattened)",
                "supports_date_filter": "yes" if self.native_dates else "client-side",
                "results_per_query": self.page_size * (1 if not self.paginates else 1)}

    def express(self, dork: str) -> tuple[str, str]:
        """How this provider can run `dork`: ('ok'|'rewritten'|'parked', text-or-reason). A `site:.cc` dork on a provider
        without TLD support is rewritten to a natural-language country query; if that is impossible it is parked
        (costs no quota) until a capable provider is configured."""
        from . import dorkparse
        from .. import countries
        pd = dorkparse.parse(dork)
        from .. import tlds
        if pd.tld and not tlds.ALLOW_UNKNOWN and not tlds.is_known(pd.tld):  # a typo like site:.du must not spend quota (nor be "rewritten")
            return "parked", f"unknown TLD .{pd.tld} (typo?)" + (f" - did you mean .{tlds.suggest(pd.tld)[0]}?" if tlds.suggest(pd.tld) else "")
        if pd.include_domains and not self.supports_site:
            return "parked", f"{self.label} cannot express site:<domain>"
        if pd.tld and self.tld_mode == "none":
            rw = countries.rewrite(pd)
            if rw:
                return "rewritten", rw
            return "parked", f"{self.label} cannot express site:.{pd.tld} and no country rewrite is known for .{pd.tld}"
        return "ok", dork

    def effective(self, dork: str) -> str:
        st, txt = self.express(dork)
        return txt if st == "rewritten" else dork

    def translate(self, dork: str) -> str:
        """The query text this provider will actually receive (operators it lacks are rewritten)."""
        return " ".join(self.effective(dork).split())

    def fingerprint(self, dork: str) -> tuple[frozenset, str, tuple, tuple]:
        """Identity of a dork *as this provider sees it*: translated word set + site filters.
        Two dorks with a similar fingerprint cost quota for (nearly) the same results."""
        pd = parse(dork)
        toks = frozenset(re.findall(r"\w+|[€£$₹¥]", self.translate(dork).lower()))
        return toks, pd.tld, tuple(sorted(pd.include_domains)), tuple(sorted(pd.exclude_domains))

    def query_hash(self, dork: str, days) -> str:
        """Identity for the cooldown rule: provider + translated query + site filters + recency window."""
        toks, tld, inc, exc = self.fingerprint(dork)
        raw = f"{self.id}|{' '.join(sorted(toks))}|{tld}|{','.join(inc)}|{','.join(exc)}|{self.window_label(days)}"
        return hashlib.sha1(raw.encode()).hexdigest()[:20]

    def window_label(self, days) -> str:
        return "any" if not days else f"{days:g}d"

    # --- public ---------------------------------------------------------------
    def search(self, key: str, dork: str, *, page: int = 0, fresh: str = "", days: float | None = None) -> Page:
        """`days` (recency window) takes precedence over the legacy `fresh` label and is mapped to the provider's
        native date filter; providers without one return `published` dates where possible (see filter_by_date)."""
        pd0 = parse(dork)
        status, text = self.express(dork)
        if status == "parked":
            raise Unexpressible(text)
        pd = parse(text) if status == "rewritten" else pd0
        from .. import ratelimit
        if not self._dry:
            ratelimit.acquire(self.id, self.max_qps)  # one shared token bucket per provider for every thread
        items = self._search(key, pd, page, days if days else fresh)
        raw_n = len(items)
        if days and not self.native_dates:  # undated results are kept and marked unknown, never dropped
            cutoff = date_from(days)
            items = [r for r in items if not r.published or r.published[:10] >= cutoff]
        if status == "rewritten":  # country query in natural language: keep results from that country's domain or text
            from .. import countries
            items = [r for r in items if countries.match(pd0.tld, r.url, r.title, r.snippet)]
        elif pd.tld and not self.native_tld:  # emulate `site:.cc` client-side
            items = [r for r in items if pd.matches_tld(r.url)]
        return Page(items, has_more=self.paginates and raw_n >= self.page_size)

    # --- quota window ---------------------------------------------------------
    def quota_type(self) -> str:
        """monthly | daily | lifetime | unlimited - user-set per provider (plans change; defaults are only a start)."""
        qt = (self.options or {}).get("quota_type") or self.quota_default or ("daily" if self.period == "day" else "monthly")
        return qt if qt in ("monthly", "daily", "lifetime", "unlimited") else "monthly"

    def period_label(self) -> str:
        qt = self.quota_type()
        if qt in ("lifetime", "unlimited"):
            return qt  # never resets
        if qt == "monthly":
            return datetime.now(timezone.utc).strftime("%Y-%m")
        return datetime.now(PT).date().isoformat()

    def period_end(self) -> datetime:
        qt = self.quota_type()
        if qt in ("lifetime", "unlimited"):
            return datetime.now(timezone.utc) + timedelta(days=3650)
        if qt == "monthly":
            n = datetime.now(timezone.utc)
            y, m = (n.year + 1, 1) if n.month == 12 else (n.year, n.month + 1)
            return datetime(y, m, 1, tzinfo=timezone.utc)
        n = datetime.now(PT)
        return (n + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

    def reset_text(self) -> str:
        return {"daily": "midnight Pacific", "monthly": "start of next month (UTC)",
                "lifetime": "never (one-time allowance)", "unlimited": "n/a (rate-limited only)"}[self.quota_type()]
