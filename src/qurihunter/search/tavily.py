from __future__ import annotations

import requests

from ..http import request
from .base import Provider, ProviderError, retry_after, SearchResult, date_from, fresh_days

ENDPOINT = "https://api.tavily.com/search"


def _pub(item: dict) -> str | None:
    from .. import dates
    d = dates.parse_date(str(item.get("published_date") or ""), sane=True)
    return dates.iso(d) if d else None


def to_tavily_query(pd) -> str:
    """Tavily is a semantic search API with no operators: send plain words only."""
    q = " ".join(pd.terms()).replace(":", "")
    return (q + " vulnerability disclosure").strip() if len(q) < 25 else q


class Tavily(Provider):
    id = "tavily"
    label = "Tavily Search API"
    period = "month"
    default_limit = 1000
    page_size = 20
    paginates = False  # one call returns up to 20 results
    native_tld = False
    operators = "none"
    max_qps = 3.0  # Tavily: no per-second figure in the docs, only 429 + Retry-After; conservative
    tld_mode = "none"
    help = "Get a key at app.tavily.com (free plan is credit-based; 1 basic search = 1 credit)."
    limitations = ("No search operators at all: dorks are flattened into plain keywords (exact-phrase and inurl: "
                   "precision is lost). -site: becomes exclude_domains; `site:.cc` is a client-side TLD filter only. "
                   "No pagination.")

    def detect_quota(self, key):
        """GET https://api.tavily.com/usage (Bearer): key.usage/key.limit or account plan_usage/plan_limit - per the docs."""
        try:
            r = requests.get("https://api.tavily.com/usage", headers={"Authorization": f"Bearer {key}"}, timeout=15)
            j = r.json() if r.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            return None
        k, a = (j.get("key") or {}), (j.get("account") or {})
        for lim, used in ((k.get("limit"), k.get("usage")), (a.get("plan_limit"), a.get("plan_usage"))):
            if isinstance(lim, (int, float)) and isinstance(used, (int, float)):
                return {"remaining": max(0, int(lim - used)), "limit": int(lim), "type": "monthly", "source": "Tavily /usage"}
        return None

    def translate(self, dork):
        from .dorkparse import parse
        return to_tavily_query(parse(self.effective(dork)))

    def _search(self, key, pd, page, fresh):
        if page > 0:
            return []
        body = {"query": to_tavily_query(pd), "max_results": 20, "search_depth": "basic"}
        d = fresh_days(fresh)
        if d:
            label = {1: "day", 7: "week", 31: "month", 365: "year"}.get(round(d)) if abs(d - round(d)) < 1e-9 else None
            if label:
                body["time_range"] = label
            else:
                body["start_date"] = date_from(d)  # native: publish/updated date >= start_date
            body["include_published_date"] = True
        if pd.after:
            body["start_date"] = pd.after
            body.pop("time_range", None)
        if pd.before:
            body["end_date"] = pd.before
        if pd.exclude_domains:
            body["exclude_domains"] = pd.exclude_domains[:150]
        if pd.include_domains:
            body["include_domains"] = pd.include_domains[:300]
        try:
            r = self._send(request, "POST", ENDPOINT, json=body, headers={"Authorization": f"Bearer {key}"},
                        retries=2, timeout=40)
        except requests.RequestException as e:
            raise ProviderError("transient", f"network error: {e}") from e
        if r.status_code == 200:
            return [SearchResult(i.get("title", ""), i.get("url", ""), i.get("content", ""), _pub(i))
                    for i in r.json().get("results", [])]
        msg = r.text[:200]
        if r.status_code in (401, 403):
            raise ProviderError("invalid", f"HTTP {r.status_code}: key rejected")
        if r.status_code == 429:
            raise ProviderError("rate", "rate limited (HTTP 429)", retry_after(r))
        if r.status_code in (432, 433):
            raise ProviderError("quota", f"HTTP {r.status_code}: plan limit reached")
        raise ProviderError("transient", f"HTTP {r.status_code}: {msg}")
