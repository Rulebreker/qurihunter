"""Real TLDs. A `site:` operator with an unknown TLD (a typo like .du) must not spend a query."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def known() -> frozenset[str]:
    out: set[str] = set()
    for line in (Path(__file__).parent / "data" / "tlds.txt").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            out.update(line.split())
    return frozenset(out)


ALLOW_UNKNOWN = False


import contextlib


@contextlib.contextmanager
def allow_unknown():
    """/dorks test after the user said 'run it anyway': an unknown TLD is allowed through for this one test."""
    global ALLOW_UNKNOWN
    old, ALLOW_UNKNOWN = ALLOW_UNKNOWN, True
    try:
        yield
    finally:
        ALLOW_UNKNOWN = old


def is_known(tld: str) -> bool:
    return (tld or "").lower().lstrip(".") in known()


def _dist(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def suggest(tld: str, n: int = 3) -> list[str]:
    """Likely intended TLDs: one edit away (two for long ones); same first letter and same length first."""
    t = (tld or "").lower().lstrip(".")
    maxd = 1 if len(t) <= 3 else 2
    c = [(x, _dist(t, x)) for x in known()]
    c = [(x, d) for x, d in c if d <= maxd]
    return [x for x, _ in sorted(c, key=lambda p: (p[1], p[0][:1] != t[:1], len(p[0]) != len(t), p[0]))][:n]
