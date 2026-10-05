from __future__ import annotations

import requests

from ..http import request
from .base import Provider, ProviderError, SearchResult, retry_after
from .serper import _pub, tbs_for

ENDPOINT = "https://serpapi.com/search.json"
ACCOUNT = "https://serpapi.com/account.json"


class SerpAPI(Provider):
    id = "serpapi"
    label = "SerpAPI (Google results)"
    period = "month"
    quota_default = "monthly"
    default_limit = 250  # Free plan per serpapi.com/pricing.md (fetched 2026-10-05): 250 searches/month, 50 successful/hour
    page_size = 10
    native_tld = True
    tld_mode = "native"
    operators = "full"
    supports_inurl = True
    max_qps = 1.0  # plans limit searches per HOUR (free: 50), not per second; one request at a time is polite
    help = "Get a key at serpapi.com. Real Google results with full operators; the free plan is small (monthly)."
    limitations = ("engine=google: dorks pass through unchanged (inurl:, intitle:, site:, quotes, -, OR). Recency via `tbs`. "
                   "Only successful searches count. The remaining quota is read from the free Account API.")

    def _search(self, key, pd, page, fresh):
        import re
        q = " ".join(re.sub(r"\b(?:after|before):\d{4}-\d{2}-\d{2}", "", pd.raw).split())
        from .serper import apply_tld_style, country_params
        params = {"engine": "google", "q": apply_tld_style(q, pd, self.options.get("tld_style", "dot")), "api_key": key,
                  "num": 10, "start": page * 10}
        params.update(country_params(pd, self.options))
        tbs = tbs_for(fresh, pd.after, pd.before)
        if tbs:
            params["tbs"] = tbs
        try:
            r = self._send(request, "GET", ENDPOINT, params=params, retries=2, retry_429=False, timeout=45)
        except requests.RequestException as e:
            raise ProviderError("transient", f"network error: {e}") from e
        j = {}
        try:
            j = r.json() if r.text.strip() else {}
        except ValueError:
            pass
        err = str(j.get("error", "")) if isinstance(j, dict) else ""
        if r.status_code == 200 and not err:
            return [SearchResult(i.get("title", ""), i.get("link", ""), i.get("snippet", ""), _pub(i))
                    for i in (j.get("organic_results") or [])]
        low = (err or r.text[:200]).lower()
        if "hasn't returned any results" in low or "no results" in low:
            return []  # a real, empty answer
        if r.status_code in (401, 403) or "invalid api key" in low:
            raise ProviderError("invalid", f"HTTP {r.status_code}: invalid API key")
        if "run out of searches" in low or "out of searches" in low or "plan" in low and "limit" in low:
            raise ProviderError("quota", "SerpAPI: out of searches for this plan")
        if r.status_code == 429 or "throughput" in low or "rate" in low:
            raise ProviderError("rate", f"rate limited ({err[:120] or 'HTTP 429'})", retry_after(r) or 60.0)
        raise ProviderError("transient", f"HTTP {r.status_code}: {(err or r.text)[:150]}")

    def detect_quota(self, key: str) -> dict | None:
        """Free Account API (does not use a search): https://serpapi.com/account.json?api_key=... - verified in the docs."""
        try:
            r = requests.get(ACCOUNT, params={"api_key": key}, timeout=15)
            j = r.json() if r.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            return None
        left = j.get("total_searches_left", j.get("plan_searches_left"))
        if not isinstance(left, (int, float)):
            return None
        return {"remaining": int(left), "limit": j.get("searches_per_month"), "type": "monthly",
                "source": "SerpAPI account.json", "hourly": j.get("account_rate_limit_per_hour")}
