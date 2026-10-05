"""Parse Google-style dork strings so each provider can translate them to what it supports."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_TOKEN = re.compile(r'''
    (?P<date>(?P<date_n>after|before):(?P<date_v>\d{4}-\d{2}-\d{2})) |
    (?P<negsite>-site:(?P<negsite_v>\S+)) |
    (?P<site>site:(?P<site_v>\S+)) |
    (?P<op>(?P<op_n>intitle|inurl|inbody|intext|allintitle|allinurl):(?P<op_v>"[^"]*"|[^\s()|]+)) |
    (?P<phrase>"[^"]*") |
    (?P<paren>[()]) |
    (?P<word>[^\s()"|]+) |
    (?P<pipe>\|)
''', re.X)


@dataclass
class ParsedDork:
    raw: str
    tld: str = ""  # from site:.cc
    include_domains: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    phrases: list[str] = field(default_factory=list)  # quoted phrases (in order)
    words: list[str] = field(default_factory=list)
    title_terms: list[str] = field(default_factory=list)  # intitle:
    url_terms: list[str] = field(default_factory=list)  # inurl:
    after: str = ""  # hardcoded after:YYYY-MM-DD (honoured + translated per provider)
    before: str = ""

    def matches_tld(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return host.endswith("." + self.tld)

    def terms(self) -> list[str]:
        """All positive search terms, de-duplicated, operators dropped (inurl hyphens become spaces)."""
        seen, out = set(), []
        for t in [*self.title_terms, *self.phrases, *self.words, *(_url_term(u) for u in self.url_terms)]:
            if t and t.lower() not in seen:
                seen.add(t.lower())
                out.append(t)
        return out


def _url_term(u: str) -> str:
    """inurl:/.well-known/security.txt -> 'security.txt'; inurl:bug-bounty -> 'bug bounty'."""
    u = u.strip().strip("/").replace(".well-known/", "")
    return u.replace("-", " ").replace("/", " ").strip()


def parse(dork: str) -> ParsedDork:
    pd = ParsedDork(raw=dork)
    for m in _TOKEN.finditer(dork):
        if m.group("date"):
            setattr(pd, m.group("date_n"), m.group("date_v"))
        elif m.group("negsite"):
            pd.exclude_domains.append(m.group("negsite_v"))
        elif m.group("site"):
            v = m.group("site_v")
            if v.startswith(".") and v.count(".") == 1:
                pd.tld = v[1:].lower()
            else:
                pd.include_domains.append(v)
        elif m.group("op"):
            v = m.group("op_v").strip('"')
            n = m.group("op_n")
            if n in ("inurl", "allinurl"):
                pd.url_terms.append(v)
            elif n in ("intitle", "allintitle"):
                pd.title_terms.append(v)
            else:  # intext/inbody: ordinary body terms
                pd.phrases.append(v) if " " in v else pd.words.append(v)
        elif m.group("phrase"):
            p = m.group("phrase").strip('"')
            if p:
                pd.phrases.append(p)
        elif m.group("word") and m.group("word") not in ("OR", "AND"):
            pd.words.append(m.group("word"))
    return pd
