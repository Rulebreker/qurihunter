from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Callable
from urllib.parse import urlsplit

from collections import Counter

from .. import dates
from ..http import get
from ..models import Program
from ..urls import country_of, host_of, is_ignored, registrable_domain

BTD = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
DIODB = "https://raw.githubusercontent.com/disclose/diodb/master/program-list.json"
SELFHOSTED = "https://raw.githubusercontent.com/ashikkunjumon/Self-Hosted-Bug-Bounty-Programs/main/programs.json"


def _scope(item: dict, *keys: str) -> list[str]:
    out = []
    for t in (item.get("targets") or {}).get("in_scope", []) or []:
        for k in keys:
            v = t.get(k)
            if v:
                out.append(str(v)[:200])
                break
    return out


def infer_website(scope: list[str]) -> str | None:
    """Company site guessed from in-scope web assets (most common non-generic registrable domain)."""
    c: Counter = Counter()
    for t in scope:
        t = t.strip().lstrip("*.")
        if not t or " " in t or "/" in t.split("//")[-1].split("/", 1)[0]:
            continue
        h = host_of(t if "//" in t else f"https://{t}")
        if h and "." in h and not is_ignored(h) and not h.endswith((".apk", ".ipa")):
            c[registrable_domain(h)] += 1
    return c.most_common(1)[0][0] if c else None


def _num(v) -> float | None:
    try:
        return float(v) if v else None
    except (TypeError, ValueError):
        return None


def parse_hackerone(data: list) -> list[Program]:
    out = []
    for i in data:
        if i.get("submission_state") not in (None, "open"):
            continue
        h = i.get("handle")
        if not h:
            continue
        sc = _scope(i, "asset_identifier")
        out.append(Program("hackerone", h, i.get("name") or h, i.get("url") or f"https://hackerone.com/{h}",
                           "bounty" if i.get("offers_bounties") else "vdp", scope=sc,
                           website=(i.get("website") or "").strip() or infer_website(sc)))
    return out


def parse_bugcrowd(data: list) -> list[Program]:
    out = []
    for i in data:
        url = i.get("url")
        if not url:
            continue
        mx = _num(i.get("max_payout"))
        sc = _scope(i, "target", "uri")
        out.append(Program("bugcrowd", urlsplit(url).path.strip("/").split("/", 1)[-1] or url, i.get("name", "").strip(),
                           url, "bounty" if mx else "vdp", mx, "USD", sc, website=infer_website(sc)))
    return out


def parse_intigriti(data: list) -> list[Program]:
    out = []
    for i in data:
        if i.get("status") not in (None, "open"):
            continue
        url = i.get("url")
        if not url:
            continue
        mb = i.get("max_bounty") or {}
        mx = _num(mb.get("value"))
        sc = _scope(i, "endpoint")
        out.append(Program("intigriti", i.get("id") or url, i.get("name", ""), url,
                           "bounty" if mx else "vdp", mx, mb.get("currency") or "EUR", sc, website=infer_website(sc)))
    return out


def parse_yeswehack(data: list) -> list[Program]:
    out = []
    for i in data:
        if i.get("disabled"):
            continue
        slug = i.get("id")
        if not slug:
            continue
        mx = _num(i.get("max_bounty"))
        sc = _scope(i, "target")
        out.append(Program("yeswehack", slug, i.get("name", slug), f"https://yeswehack.com/programs/{slug}",
                           "bounty" if mx else "vdp", mx, "EUR", sc, website=infer_website(sc)))
    return out


def parse_federacy(data: list) -> list[Program]:
    return [Program("federacy", i.get("id") or i["url"], i.get("name", ""), i["url"],
                    "bounty" if i.get("offers_awards") else "vdp", scope=_scope(i, "target"),
                    website=infer_website(_scope(i, "target")))
            for i in data if i.get("url")]


def parse_diodb(data: list) -> list[Program]:
    """disclose.io database: mostly self-hosted & national programs worldwide."""
    out = []
    for i in data:
        url = (i.get("policy_url") or "").strip()
        if not url.startswith("http") or i.get("policy_url_status") == "dead":
            continue
        host = host_of(url)
        bounty = str(i.get("offers_bounty", "")).lower() in ("yes", "true")
        ld = str(i.get("launch_date") or "")
        d = None if ld.lower().startswith("updated") else dates.parse_date(ld, sane=True)  # year-only/'Updated …' ≠ launch
        out.append(Program("disclose.io", url, i.get("program_name") or host, url,
                           "bounty" if bounty else "vdp", country=country_of(host),
                           launched_at=dates.iso(d) if d else None, launched_via="source" if d else None))
    return out


def parse_generic_json(data, name: str) -> list[Program]:
    items = data if isinstance(data, list) else data.get("programs", []) if isinstance(data, dict) else []
    out = []
    for i in items:
        url = i.get("url") or i.get("policy_url") or i.get("link")
        if url:
            out.append(Program(name, url, i.get("name") or i.get("title") or url, url, "vdp"))
    return out


def parse_rss(text: str, name: str) -> list[Program]:
    root = ET.fromstring(text)
    out = []
    for it in root.iter():
        tag = it.tag.split("}")[-1]
        if tag not in ("item", "entry"):
            continue
        d = {c.tag.split("}")[-1]: c for c in it}
        title = (d["title"].text or "").strip() if "title" in d else ""
        link = ""
        if "link" in d:
            link = (d["link"].text or d["link"].get("href") or "").strip()
        if link:
            pub = next((d[k].text for k in ("pubDate", "published", "updated", "date") if k in d and d[k].text), "")
            dt = _rfc_date(pub)
            out.append(Program(name, link, title or link, link, "vdp",
                               snippet=(d["description"].text or "")[:300] if "description" in d and d["description"].text else "",
                               launched_at=dates.iso(dt) if dt else None, launched_via="source" if dt else None))
    return out


def _rfc_date(s: str):
    if not s:
        return None
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(s).astimezone(dates.UTC)
    except (TypeError, ValueError):
        return dates.parse_date(s, sane=True)


def parse_selfhosted(data: list) -> list[Program]:
    """Self-Hosted-Bug-Bounty-Programs dataset (rebuilt daily from security.txt files / policy pages).
    Its per-entry `first_seen` is when *that crawler* first saw the program (a weak launch signal). Entries on the
    dataset's first crawl day all share one date and carry no information, so that floor date is ignored."""
    floor = None
    c = Counter(str(i.get("first_seen", ""))[:10] for i in data if i.get("first_seen"))
    if c:
        day, n = c.most_common(1)[0]
        if n > 0.2 * len(data):
            floor = day
    out = []
    for i in data:
        if i.get("hosting") != "self_hosted" or i.get("status", "active") != "active" or i.get("policy_dead"):
            continue
        url = i.get("policy_url") or i.get("security_txt")
        dom = i.get("domain")
        if not url or not dom:
            continue
        fs = str(i.get("first_seen") or "")[:10]
        d = dates.parse_date(fs, sane=True) if fs and (floor is None or fs > floor) else None
        out.append(Program("selfhosted", dom, dom, url,
                           "bounty" if i.get("reward") == "monetary" else
                           ("security.txt" if not i.get("policy_url") else "vdp"),
                           country=(i.get("country") or None) if (i.get("country") or "") not in ("global", "") else country_of(dom),
                           website=dom, launched_at=dates.iso(d) if d else None,
                           launched_via="source_first_seen" if d else None))
    return out


# id -> (label, url, parser)
SOURCES: dict[str, tuple[str, str, Callable]] = {
    "hackerone": ("HackerOne", f"{BTD}/hackerone_data.json", parse_hackerone),
    "bugcrowd": ("Bugcrowd", f"{BTD}/bugcrowd_data.json", parse_bugcrowd),
    "intigriti": ("Intigriti", f"{BTD}/intigriti_data.json", parse_intigriti),
    "yeswehack": ("YesWeHack", f"{BTD}/yeswehack_data.json", parse_yeswehack),
    "federacy": ("Federacy", f"{BTD}/federacy_data.json", parse_federacy),
    "disclose.io": ("disclose.io (self-hosted/national)", DIODB, parse_diodb),
    "selfhosted": ("Self-Hosted-Bug-Bounty-Programs list", SELFHOSTED, parse_selfhosted),
}


def fetch(source_id: str) -> list[Program]:
    _, url, parser = SOURCES[source_id]
    r = get(url, timeout=90)
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        raise ValueError("unexpected payload shape")
    return parser(data)


def fetch_custom(feed: dict) -> list[Program]:
    name = feed["name"]
    r = get(feed["url"], timeout=60)
    r.raise_for_status()
    if feed.get("format", "json") == "rss":
        return parse_rss(r.text, name)
    return parse_generic_json(r.json(), name)
