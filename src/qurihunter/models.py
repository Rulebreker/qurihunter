from __future__ import annotations

from dataclasses import dataclass, field

KINDS = ("bounty", "vdp", "security.txt")
PLATFORM_SOURCES = {"hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy"}
WEB_SOURCES = {"web", "disclose.io", "selfhosted"}  # url is the company's own page


@dataclass
class Program:
    source: str  # e.g. hackerone, bugcrowd, web
    key: str  # stable id within the source (handle, URL path, registrable domain)
    name: str
    url: str
    kind: str = "vdp"  # bounty | vdp | security.txt
    reward_max: float | None = None
    currency: str | None = None
    scope: list[str] = field(default_factory=list)
    country: str | None = None  # ISO-ish 2-letter code, lowercase
    snippet: str = ""
    summary: str = ""
    confidence: float = 1.0
    website: str | None = None  # the company's own site, when the source tells us
    launched_at: str | None = None  # UTC ISO; ONLY when the source really provides a date
    launched_via: str | None = None  # source | source_first_seen | page_date
    updated_at: str | None = None  # last-updated / effective date found on the page (never a launch date)
    date_kind: str = "unknown"  # published | launched | last_updated | effective | unknown
    classified_by: str = "rules"  # rules | llm (dork hits only)

    @property
    def dedupe_key(self) -> str:
        return f"{self.source}:{self.key}"

    @property
    def company_key(self) -> str | None:
        """Company-level identity used to recognise the same program across sources."""
        from .urls import host_of, is_ignored, registrable_domain
        for u in (self.website, self.url if self.source in WEB_SOURCES else None):
            if u:
                h = host_of(u if "//" in u else f"https://{u}")
                if h and not is_ignored(h):
                    return registrable_domain(h)
        return None

    def reward_text(self) -> str:
        if self.reward_max:
            return f"up to {self.reward_max:,.0f} {self.currency or ''}".strip()
        return "bounty (amount n/a)" if self.kind == "bounty" else "no cash reward listed"
