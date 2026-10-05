from __future__ import annotations

import requests

from ..http import request
from .base import Provider, ProviderError, SearchResult, fresh_days

ENDPOINT = "https://www.googleapis.com/customsearch/v1"


def _page_date(item: dict) -> str | None:
    from .. import dates
    meta = ((item.get("pagemap") or {}).get("metatags") or [{}])[0]
    for k in ("article:published_time", "og:published_time", "datepublished", "date", "article:modified_time", "og:updated_time"):
        d = dates.parse_date(meta.get(k, ""), sane=True)
        if d:
            return dates.iso(d)
    return None


class Google(Provider):
    id = "google"
    label = "Google Custom Search (legacy)"
    period = "day"
    default_limit = 100
    page_size = 10
    native_tld = True  # full dork syntax is passed through
    operators = "full"
    max_qps = 2.0  # Google CSE: conservative
    tld_mode = "native"
    supports_inurl = True
    extra_fields = {"cx": "Search engine ID (cx)"}
    help = ("Legacy only: closed to new customers, shuts down 2027-01-01. Needs an existing key and a "
            "search engine ID (cx) set to 'Search the entire web'.")
    limitations = "Closed to new customers; sunsets 2027-01-01. Full operator support."

    def _search(self, key, pd, page, fresh):
        params = {"key": key, "cx": self.options.get("cx", ""), "q": pd.raw, "num": 10, "start": 1 + page * 10}
        d = fresh_days(fresh)
        if d:  # native: d[N] days (also w/m/y) — any whole number of days works
            params["dateRestrict"] = f"d{max(1, round(d))}"
        if not params["cx"]:
            raise ProviderError("invalid", "no Search Engine ID (cx) configured")
        try:
            r = self._send(request, "GET", ENDPOINT, params=params, retries=3, retry_429=False, timeout=30)
        except requests.RequestException as e:
            raise ProviderError("transient", f"network error: {e}") from e
        if r.status_code == 200:
            return [SearchResult(i.get("title", ""), i.get("link", ""), i.get("snippet", ""), _page_date(i))
                    for i in r.json().get("items", []) or []]
        try:
            err = r.json().get("error", {})
            reason = (err.get("errors") or [{}])[0].get("reason", "")
            msg = err.get("message", r.text[:200])
        except ValueError:
            reason, msg = "", r.text[:200]
        if r.status_code == 429 or reason in ("dailyLimitExceeded", "rateLimitExceeded", "quotaExceeded"):
            raise ProviderError("quota", msg)
        if r.status_code in (400, 401, 403):
            raise ProviderError("invalid", f"{reason or r.status_code}: {msg}")
        raise ProviderError("transient", f"HTTP {r.status_code}: {msg}")
