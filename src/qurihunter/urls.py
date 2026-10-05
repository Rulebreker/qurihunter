from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_TRACKING = re.compile(r"^(utm_|fbclid|gclid|mc_|ref$)")
_SLD = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"}

def _load_blocklist() -> set[str]:
    from pathlib import Path
    out = set()
    for f in (Path(__file__).parent / "data" / "domain_blocklist.txt",):
        try:
            out |= {l.strip().lower() for l in f.read_text().splitlines() if l.strip() and not l.startswith("#")}
        except OSError:
            pass
    return out


# Hosts that are never a company's own disclosure program (blogs, aggregators, tools, social, platforms).
IGNORED_DOMAINS = _load_blocklist() | {
    "github.com", "gitlab.com", "medium.com", "wikipedia.org", "linkedin.com", "twitter.com", "x.com",
    "youtube.com", "reddit.com", "stackoverflow.com", "facebook.com", "instagram.com", "hackerone.com",
    "bugcrowd.com", "intigriti.com", "yeswehack.com", "federacy.com", "owasp.org", "disclose.io",
    "google.com", "microsoft.com", "apple.com"}


def normalize_url(url: str) -> str:
    try:
        s = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    host = (s.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    q = urlencode([(k, v) for k, v in parse_qsl(s.query) if not _TRACKING.match(k)])
    path = s.path.rstrip("/") or ""
    return urlunsplit(((s.scheme or "https").lower(), host, path, q, ""))


def host_of(url: str) -> str:
    try:
        h = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h


def registrable_domain(host: str) -> str:
    """Approximate registrable domain without a public-suffix list."""
    parts = [p for p in host.lower().split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in _SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def country_of(host: str) -> str | None:
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if len(tld) == 2 and tld.isalpha():
        return tld
    return None


def is_ignored(host: str) -> bool:
    """Not a usable company domain: IPs, dotless hosts, or blocklisted sites."""
    if "." not in host or re.fullmatch(r"[\d.:]+", host) or not re.search(r"[a-z]", host):
        return True
    return registrable_domain(host) in IGNORED_DOMAINS
