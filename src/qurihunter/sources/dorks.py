from __future__ import annotations

import hashlib
import re

# Excluded so results are *self-hosted* programs rather than platform pages we already poll.
EXCLUDE = "-site:hackerone.com -site:bugcrowd.com -site:intigriti.com -site:yeswehack.com -site:github.com -site:wikipedia.org"

TEMPLATES = [
    'intitle:"bug bounty" "submit a vulnerability"',
    'intitle:"responsible disclosure" "report a vulnerability"',
    'intitle:"vulnerability disclosure" ("policy" OR "program") "security researchers"',
    'inurl:security.txt "Contact:" "Policy:"',
    'inurl:"responsible-disclosure" OR inurl:"vulnerability-disclosure" OR inurl:"bug-bounty"',
    '"coordinated vulnerability disclosure" "report" "safe harbor"',
    '"hall of fame" "security researchers" "bounty" "report a vulnerability"',
    'intitle:"report a vulnerability" "we reward"',
    '"launching our bug bounty" OR "new bug bounty program" OR "launched a bug bounty"',
    '"security.txt" "Bug Bounty" inurl:.well-known',
]
COUNTRY_TEMPLATES = 4  # number of leading templates also expanded per ccTLD

# Countries covered when the user has not restricted any (auto mode).
DEFAULT_COUNTRIES = ["ch", "se", "de", "fr", "nl", "be", "uk", "no", "dk", "fi", "at", "it", "es", "pl", "ie",
                     "us", "ca", "au", "nz", "jp", "kr", "sg", "in", "br", "il", "ae", "za", "cz", "pt", "ee"]


def normalize_cc(cc: str) -> str:
    cc = cc.strip().lower().lstrip(".")
    return "uk" if cc == "gb" else cc


def valid_cc(cc: str) -> bool:
    return bool(re.fullmatch(r"[a-z]{2}", cc))


def build(countries: list[str]) -> list[str]:
    """Ordered dork list. With a country filter only ccTLD variants are produced."""
    ccs = [normalize_cc(c) for c in countries] or DEFAULT_COUNTRIES
    out = []
    if not countries:
        out += [f"{t} {EXCLUDE}" for t in TEMPLATES]
    for cc in ccs:
        out += [f"{t} site:.{cc} {EXCLUDE}" for t in TEMPLATES[:COUNTRY_TEMPLATES]]
    return out


def qhash(q: str) -> str:
    return hashlib.sha1(q.encode()).hexdigest()[:16]
