from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import requests

from ..http import request
from .base import Provider, retry_after, ProviderError, SearchResult, fresh_days

ENDPOINT = "https://google.serper.dev/search"
_DATE_TOKENS = re.compile(r"\b(?:after|before):\d{4}-\d{2}-\d{2}")


def _pub(item: dict) -> str | None:
    """Serper's `date` is free text ('Oct 3, 2026' or '3 days ago'); parse what we can, never invent."""
    from .. import datekind, dates
    raw = str(item.get("date") or "").strip()
    if not raw:
        return None
    m = re.match(r"(\d+)\s+(hour|day|week|month|year)s?\s+ago", raw, re.I)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        days = {"hour": n / 24, "day": n, "week": n * 7, "month": n * 30, "year": n * 365}[unit]
        return dates.iso(dates.utcnow() - timedelta(days=days))
    ev = datekind.find(raw)
    return ev[0].date if ev else None


def tbs_for(days, after: str = "", before: str = "") -> str | None:
    """Recency window -> Google's `tbs` parameter (qdr:d/w/m/y, or a custom cdr range)."""
    def us(d: str) -> str:  # YYYY-MM-DD -> M/D/YYYY (what cd_min/cd_max expect)
        y, mo, da = d.split("-")
        return f"{int(mo)}/{int(da)}/{y}"
    if after or before:
        a = us(after) if after else "1/1/1990"
        b = us(before) if before else us(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        return f"cdr:1,cd_min:{a},cd_max:{b}"
    d = fresh_days(days)
    if not d:
        return None
    for limit, code in ((1, "qdr:d"), (7, "qdr:w"), (31, "qdr:m"), (365, "qdr:y")):
        if abs(d - limit) < 1e-9:
            return code
    start = datetime.now(timezone.utc) - timedelta(days=d)
    return f"cdr:1,cd_min:{start.month}/{start.day}/{start.year},cd_max:{datetime.now(timezone.utc).month}/" \
           f"{datetime.now(timezone.utc).day}/{datetime.now(timezone.utc).year}"


def apply_tld_style(q: str, pd, style: str) -> str:
    """`site:.ch` (dot) or `site:ch` (bare): both mean the TLD to Google; which ranks better is an option (tld_style)."""
    if pd.tld and style == "bare":
        return q.replace(f"site:.{pd.tld}", f"site:{pd.tld}")
    return q


def country_params(pd, options: dict) -> dict:
    """Serper's `gl` (country) and `hl` (language) next to a TLD dork, so Google biases toward that country. Both are
    documented request parameters; switch off with country_targeting=false."""
    from .. import countries
    if not pd.tld or options.get("country_targeting", True) is False:
        return {}
    out = {}
    gl = countries.gl_for(pd.tld)
    if gl:
        out["gl"] = gl
        if options.get("language_targeting", True):
            out["hl"] = countries.lang_of(pd.tld)
    return out


class Serper(Provider):
    id = "serper"
    label = "Serper (Google results)"
    period = "month"
    quota_default = "lifetime"  # new accounts get a one-time bucket of credits - set YOUR real allowance
    default_limit = 2500
    page_size = 10  # num > 10 costs extra credits: keep 10
    native_tld = True
    max_qps = 5.0  # Serper: not documented where we could read it; conservative
    tld_mode = "native"
    operators = "full"
    supports_inurl = True
    help = "Get a key at serper.dev. Real Google results with full operators; credits are a one-time bucket, then paid."
    limitations = ("Passes dorks through to Google unchanged (inurl:, intitle:, site:, quotes, -, OR). 10 results per "
                   "query (more costs extra credits). Recency uses the `tbs` parameter. Free signup credits are one-time "
                   "(quota type 'lifetime') and spread over lifetime_target_days.")

    def _search(self, key, pd, page, fresh):
        q = " ".join(_DATE_TOKENS.sub("", pd.raw).split())
        body = {"q": apply_tld_style(q, pd, self.options.get("tld_style", "dot")), "num": 10, "page": page + 1}
        body.update(country_params(pd, self.options))
        tbs = tbs_for(fresh, pd.after, pd.before)
        if tbs:
            body["tbs"] = tbs
        try:
            r = self._send(request, "POST", ENDPOINT, json=body, headers={"X-API-KEY": key, "Content-Type": "application/json"},
                        retries=2, retry_429=False, timeout=30)
        except requests.RequestException as e:
            raise ProviderError("transient", f"network error: {e}") from e
        if r.status_code == 200:
            return [SearchResult(i.get("title", ""), i.get("link", ""), i.get("snippet", ""), _pub(i))
                    for i in r.json().get("organic", []) or []]
        msg = r.text[:200]
        low = msg.lower()
        if r.status_code in (401, 403):
            raise ProviderError("invalid", f"HTTP {r.status_code}: invalid or disabled API key")
        if r.status_code == 400 and ("credit" in low or "quota" in low):
            raise ProviderError("quota", "Serper: not enough credits")
        if r.status_code == 429:
            raise ProviderError("rate", "rate limited (HTTP 429)", retry_after(r))
        if r.status_code == 400:
            raise ProviderError("invalid", f"rejected request: {msg}")
        raise ProviderError("transient", f"HTTP {r.status_code}: {msg}")
