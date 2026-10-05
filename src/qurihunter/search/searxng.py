from __future__ import annotations

import time

import requests

from ..http import request
from .base import Provider, ProviderError, SearchResult, fresh_days

JSON_HELP = ("SearXNG answered 403: the JSON output format is disabled. In its settings.yml add `json` under "
             "`search: formats:` (formats: [html, json]), then restart the container. `/searxng setup` prints a ready "
             "config.")
BLOCK_WORDS = ("captcha", "access denied", "too many requests", "blocked", "forbidden", "rate")
ENGINE_BREAKER = 3  # consecutive CAPTCHA/denied answers before an engine is set aside
ENGINE_COOLDOWN = 1800  # seconds


def _pub(item: dict) -> str | None:
    from .. import dates
    d = dates.parse_date(str(item.get("publishedDate") or ""), sane=True)
    return dates.iso(d) if d else None


class SearXNG(Provider):
    id = "searxng"
    label = "SearXNG (self-hosted)"
    period = "month"
    quota_default = "unlimited"
    default_limit = 10**9
    page_size = 10
    needs_key = False
    native_tld = False
    max_qps = 2.0  # self-hosted: polite default
    tld_mode = "emulated"  # site:.cc is forwarded to the engines and results are filtered client-side
    operators = "basic"
    native_dates = False  # time_range is coarse (day/month/year): refine client-side from published dates
    extra_fields = {"base_url": "SearXNG base URL (e.g. http://localhost:8080)"}
    help = "Run your own instance (`/searxng setup` prints a docker-compose.yml + settings.yml). No key, no quota."
    limitations = ("Engine-dependent operators (site:/quotes usually work). Public engines may answer CAPTCHA/429; those "
                   "answers are NOT counted as a run with 0 results and each engine has a circuit breaker. JSON output must "
                   "be enabled in settings.yml.")

    def __init__(self, options=None):
        super().__init__(options)
        self.engine_fail: dict[str, tuple[int, float]] = {}  # engine -> (consecutive failures, open_until)

    def capabilities(self) -> dict:
        c = super().capabilities()
        c["supports_inurl"] = "engine-dependent"
        return c

    def missing_options(self) -> list[str]:
        return [] if self.options.get("base_url") else ["base_url"]

    def _open(self) -> set[str]:
        now = time.time()
        return {e for e, (n, until) in self.engine_fail.items() if n >= ENGINE_BREAKER and until > now}

    def _note(self, engine: str, bad: bool) -> None:
        n, _ = self.engine_fail.get(engine, (0, 0.0))
        self.engine_fail[engine] = (n + 1, time.time() + ENGINE_COOLDOWN) if bad else (0, 0.0)

    def test(self, key: str = "") -> tuple[bool, str]:
        try:
            r = self.probe()
            return (r[0], r[1])
        except Exception as e:  # noqa: BLE001
            return False, str(e)

    def probe(self) -> tuple[bool, str]:
        base = self.options.get("base_url", "").rstrip("/")
        if not base:
            return False, "no base_url configured"
        try:
            r = requests.get(f"{base}/search", params={"q": "test", "format": "json"}, timeout=15)
        except requests.RequestException as e:
            return False, f"cannot reach {base}: {e}"
        if r.status_code == 403:
            return False, JSON_HELP
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        try:
            j = r.json()
        except ValueError:
            return False, "answered 200 but not JSON (is `json` enabled under search.formats?)"
        bad = [f"{e[0]}: {e[1]}" for e in j.get("unresponsive_engines", []) if isinstance(e, list) and len(e) >= 2]
        return True, f"OK, {len(j.get('results', []))} results" + (f"; unresponsive engines: {', '.join(bad)}" if bad else "")

    def _search(self, key, pd, page, fresh):
        base = self.options.get("base_url", "").rstrip("/")
        if not base:
            raise ProviderError("invalid", "no base_url configured (/config → option 2)")
        q = pd.raw if not (pd.after or pd.before) else " ".join(
            t for t in pd.raw.split() if not t.startswith(("after:", "before:")))
        params = {"q": q, "format": "json", "pageno": page + 1}
        d = fresh_days(fresh)
        if d:
            params["time_range"] = "day" if d <= 1 else "month" if d <= 31 else "year"
        engines = [e.strip() for e in str(self.options.get("engines", "")).split(",") if e.strip()]
        bad = self._open()
        if engines:
            engines = [e for e in engines if e not in bad]
            if not engines:
                raise ProviderError("blocked", f"all configured engines are set aside by the circuit breaker ({', '.join(sorted(bad))})")
            params["engines"] = ",".join(engines)
        try:
            r = self._send(request, "GET", f"{base}/search", params=params, retries=1, retry_429=False, timeout=40)
        except requests.RequestException as e:
            raise ProviderError("transient", f"cannot reach {base}: {e}") from e
        if r.status_code == 403:
            raise ProviderError("invalid", JSON_HELP)
        if r.status_code == 429:
            raise ProviderError("blocked", "SearXNG limiter answered 429 (bot detection): allow your address in limiter.toml or disable the limiter for localhost")
        if r.status_code != 200:
            raise ProviderError("transient", f"HTTP {r.status_code}: {r.text[:150]}")
        try:
            j = r.json()
        except ValueError:
            raise ProviderError("invalid", "answer is not JSON: " + JSON_HELP) from None
        results = j.get("results", []) or []
        unresp = [e for e in j.get("unresponsive_engines", []) or [] if isinstance(e, list) and len(e) >= 2]
        answered = {eng for res in results for eng in (res.get("engines") or [res.get("engine")] if res.get("engine") or res.get("engines") else [])}
        for eng, reason in unresp:
            self._note(eng, any(w in str(reason).lower() for w in BLOCK_WORDS))
        for eng in answered:
            self._note(eng, False)
        if not results and unresp:  # nobody answered: this is a failure, not "0 results"
            why = "; ".join(f"{e}: {why}" for e, why in unresp[:4])
            raise ProviderError("blocked", f"no engine answered ({why})")
        return [SearchResult(i.get("title", ""), i.get("url", ""), i.get("content", ""), _pub(i)) for i in results]
