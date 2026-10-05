from __future__ import annotations

import requests

from ..http import request
from .base import Provider, retry_after, ProviderError, SearchResult, fresh_days, date_from
from .tavily import to_tavily_query

ENDPOINT = "https://api.exa.ai/search"


def _pub(item: dict) -> str | None:
    from .. import dates
    d = dates.parse_date(str(item.get("publishedDate") or ""), sane=True)
    return dates.iso(d) if d else None


class Exa(Provider):
    id = "exa"
    label = "Exa (semantic search)"
    period = "month"
    default_limit = 1000  # a guess: plans change, set your real allowance
    page_size = 10
    paginates = False
    max_qps = 6.0  # Exa: the user-set cap of 6 requests/second (the docs' default for /search is 10, deep variants 5)
    tld_mode = "none"
    operators = "none"
    help = "Get a key at exa.ai. Semantic / natural-language search; no operators."
    limitations = ("Natural-language queries only (operators are flattened to keywords, `site:.cc` dorks are rewritten with "
                   "the country name and local terms). One call returns up to 10 results; text contents are not requested "
                   "(extra cost), so classification relies on title/URL and the page fetch.")

    def translate(self, dork):
        from .dorkparse import parse
        return to_tavily_query(parse(self.effective(dork)))

    def _search(self, key, pd, page, fresh):
        if page > 0:
            return []
        body = {"query": to_tavily_query(pd), "numResults": 10, "type": "auto"}
        d = fresh_days(fresh)
        if d:
            body["startPublishedDate"] = date_from(d) + "T00:00:00.000Z"
        if pd.after:
            body["startPublishedDate"] = pd.after + "T00:00:00.000Z"
        if pd.before:
            body["endPublishedDate"] = pd.before + "T23:59:59.000Z"
        if pd.include_domains:
            body["includeDomains"] = pd.include_domains[:100]
        if pd.exclude_domains:
            body["excludeDomains"] = pd.exclude_domains[:100]
        try:
            r = self._send(request, "POST", ENDPOINT, json=body, headers={"x-api-key": key}, retries=2, retry_429=False, timeout=45)
        except requests.RequestException as e:
            raise ProviderError("transient", f"network error: {e}") from e
        if r.status_code == 200:
            return [SearchResult(i.get("title") or "", i.get("url", ""), (i.get("text") or "")[:300], _pub(i))
                    for i in r.json().get("results", []) or []]
        msg = r.text[:200]
        if r.status_code == 401:
            raise ProviderError("invalid", "HTTP 401: missing or invalid API key")
        if r.status_code == 402:
            raise ProviderError("quota", "Exa: out of credits")
        if r.status_code == 429:
            raise ProviderError("rate", "rate limited (HTTP 429)", retry_after(r))
        if r.status_code == 400:
            raise ProviderError("invalid", f"rejected request: {msg}")
        raise ProviderError("transient", f"HTTP {r.status_code}: {msg}")
