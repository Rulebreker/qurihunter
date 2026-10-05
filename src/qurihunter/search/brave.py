from __future__ import annotations

import time

import requests

from ..http import request
from .base import Provider, ProviderError, retry_after, SearchResult, date_from, fresh_days

ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
FRESH = {"day": "pd", "week": "pw", "month": "pm", "year": "py"}
# Countries Brave's `country` parameter documents; others are filtered client-side only.
COUNTRIES = set("ar au at be br ca cl dk fi fr de hk in id it jp kr my mx nl nz no cn pl pt ph ru sa za es se ch tw tr gb us".split())
MAX_Q = 380  # Brave caps queries at ~400 chars / 50 words


def _age(item: dict) -> str | None:
    """page_age is undocumented but returned for many results; used only as a weak signal."""
    from .. import dates
    d = dates.parse_date(str(item.get("page_age") or ""), sane=True)
    return dates.iso(d) if d else None


def to_brave_query(pd) -> str:
    """Brave documents site:, "quotes" and -minus only. inurl:/intitle:/OR are rewritten as plain terms."""
    terms = []
    for t in pd.terms():
        terms.append(f'"{t}"' if " " in t or ":" in t or "." in t else t)
    q = " ".join(terms)
    for d in pd.include_domains:
        q += f" site:{d}"
    for d in pd.exclude_domains:
        if len(q) + len(d) + 7 > MAX_Q:
            break
        q += f" -site:{d}"
    return q.strip()


def parse_quota_headers(h) -> dict | None:
    """X-RateLimit-Limit/-Remaining/-Reset are 'per-second, per-month' pairs: `1, 15000` (documented by Brave)."""
    try:
        pair = lambda k: [int(x) for x in str(h.get(k, "")).replace(" ", "").split(",") if x]  # noqa: E731
        lim, rem = pair("X-RateLimit-Limit"), pair("X-RateLimit-Remaining")
        if len(rem) >= 2 and len(lim) >= 2:
            return {"remaining": rem[1], "limit": lim[1], "type": "monthly", "source": "Brave X-RateLimit headers"}
    except (TypeError, ValueError, AttributeError):
        pass
    return None


class Brave(Provider):
    id = "brave"
    label = "Brave Search API"
    period = "month"
    default_limit = 1000
    page_size = 20
    native_tld = False
    operators = "basic"
    max_qps = 1.0  # Brave: the plan header example is 1 request per second (X-RateLimit-Limit: 1, 15000)
    tld_mode = "emulated"
    help = "Get a key at api-dashboard.search.brave.com (requires signing up; free credits are limited — set your real monthly allowance)."
    limitations = ("Only site:, quotes and -minus are documented: inurl:/intitle:/OR are rewritten as plain terms. "
                   "`site:.cc` is emulated with the `country` parameter plus a client-side TLD filter.")

    def detect_quota(self, key):
        """Brave documents the remaining quota only in response headers: one minimal query reads them."""
        from .dorkparse import parse
        self.last_quota = None
        try:
            self._search(key, parse("security.txt"), 0, "")
        except ProviderError:
            return None
        return getattr(self, "last_quota", None)

    def translate(self, dork):
        from .dorkparse import parse
        return to_brave_query(parse(self.effective(dork)))

    def _search(self, key, pd, page, fresh):
        params = {"q": to_brave_query(pd), "count": 20, "offset": min(page, 9)}
        d = fresh_days(fresh)
        if d:
            params["freshness"] = {1: "pd", 7: "pw", 31: "pm", 365: "py"}.get(round(d)) if abs(d - round(d)) < 1e-9 else None
            if not params["freshness"]:  # custom range: YYYY-MM-DDtoYYYY-MM-DD
                params["freshness"] = f"{date_from(d)}to{date_from(0)}"
        if pd.after or pd.before:  # dork-level dates override the recency window
            params["freshness"] = f"{pd.after or '1990-01-01'}to{pd.before or date_from(0)}"
        if pd.tld:
            cc = "gb" if pd.tld == "uk" else pd.tld
            if cc in COUNTRIES:
                params["country"] = cc.upper()
        for attempt in range(3):  # free tiers allow ~1 request/second
            try:
                r = self._send(request, "GET", ENDPOINT, params=params, headers={"X-Subscription-Token": key,
                            "Accept": "application/json"}, retries=2, retry_429=False, timeout=30)
            except requests.RequestException as e:
                raise ProviderError("transient", f"network error: {e}") from e
            if r.status_code != 429:
                break
            rem = r.headers.get("X-RateLimit-Remaining", "").split(",")[-1].strip()
            if rem == "0" or "quota" in r.text.lower():
                raise ProviderError("quota", "Brave quota exhausted")
            time.sleep(1.2)
        self.last_quota = parse_quota_headers(r.headers)
        if r.status_code == 200:
            return [SearchResult(i.get("title", ""), i.get("url", ""), i.get("description", ""), _age(i))
                    for i in (r.json().get("web") or {}).get("results", [])]
        msg = r.text[:200]
        if r.status_code in (401, 403):
            raise ProviderError("invalid", f"HTTP {r.status_code}: {msg}")
        if r.status_code == 402:
            raise ProviderError("quota", f"HTTP 402: {msg}")
        if r.status_code == 429:
            raise ProviderError("rate", "rate limited (HTTP 429)", retry_after(r))
        if r.status_code == 422:
            raise ProviderError("invalid", f"rejected request: {msg}")
        raise ProviderError("transient", f"HTTP {r.status_code}: {msg}")
