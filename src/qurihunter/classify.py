from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import datekind
from .http import get
from .llm import LLMError, Ollama
from .logs import log
from .models import Program
from .search import SearchResult
from .urls import country_of, host_of, is_ignored, normalize_url, registrable_domain

PATH_POS = re.compile(r"(responsible[-_ ]?disclosure|vulnerability[-_ ]?disclosure|bug[-_ ]?bounty|report[-_ ]?a[-_ ]?vuln|"
                      r"security\.txt|/vdp\b|psirt|coordinated[-_ ]?disclosure|security[-_/]report)", re.I)
TEXT_POS = re.compile(r"(bug bounty|vulnerability disclosure|responsible disclosure|report a vulnerability|"
                      r"submit a vulnerability|coordinated (vulnerability )?disclosure|safe harbou?r)", re.I)
# URL shapes that are never an organisation's program page: blogs, news, articles, wikis, forums, docs-of-tools, files.
HARD_NEG_URL = re.compile(r"(/blogs?/|/news(room)?/|/press|/articles?/|/posts?/|/stor(y|ies)/|/insights?/|/careers?/|"
                          r"/jobs?/|/wiki/|/tutorials?|/forums?/|/questions/|/tag/|/category/|/topics?/|/podcasts?/|"
                          r"/events?/|/awesome|\.pdf$|/readme|/how-to-|/what-is-)", re.I)
# Title shapes of listicles / explainers (soft: "How to report a vulnerability" is a legitimate program title)
SOFT_NEG_TITLE = re.compile(r"(top \d+|best bug bounty|what is (a )?bug bounty|list of|awesome )", re.I)
BOUNTY_WORDS = re.compile(r"(bounty|reward|payout|\$\d|€\d)", re.I)


def heuristic(url: str, title: str, snippet: str) -> tuple[float, str]:
    """Score 0..1 that this is a genuine program page, plus the guessed kind."""
    path = urlsplit(url).path
    text = f"{title} {snippet}"
    score = 0.0
    if PATH_POS.search(path):
        score += 0.5
    if TEXT_POS.search(title):
        score += 0.3
    if TEXT_POS.search(snippet):
        score += 0.2
    if HARD_NEG_URL.search(path):
        return 0.0, "vdp"
    if SOFT_NEG_TITLE.search(title):
        score -= 0.4
    if path.rstrip("/").endswith("security.txt"):
        kind = "security.txt"
        score = min(score, 0.6)  # a bare security.txt is only a contact point -> ambiguous
    elif BOUNTY_WORDS.search(text):
        kind = "bounty"
    else:
        kind = "vdp"
    return max(0.0, min(1.0, score)), kind


def hard_reject(url: str, title: str = "") -> str | None:
    """Deterministic 'this is not a program page' reasons (no LLM needed), else None."""
    host = host_of(url)
    if not host or is_ignored(host):
        return f"ignored domain ({registrable_domain(host) or host}): news / writeup / aggregator / tool site"
    path = urlsplit(url).path
    m = HARD_NEG_URL.search(path)
    if m:
        return f"URL shape {m.group(0).strip('/')!r}: article/news/blog/list page"
    if SOFT_NEG_TITLE.search(title) and not PATH_POS.search(path):
        return "title looks like a listicle/explainer"
    return None


def prepare_batch(items: list, llm, db, *, max_items: int | None = None) -> int:
    """Batch-classify search hits BEFORE they are handled one by one: dedupe first (seen URLs, known domains, duplicate URLs,
    hard-rule rejects, hopeless heuristics), then up to `llm.batch_size` pages per call. Verdicts are attached to the items
    (`item.verdict`), so from_result() makes no second call. Returns the number of pages judged. No-op for single-page
    backends and when the model is unavailable (the per-item path then runs as before)."""
    size = int(getattr(llm, "batch_size", 1) or 1)
    if llm is None or size <= 1 or not items:
        return 0
    todo, seen_urls, seen_dom = [], set(), set()
    for it in items:
        url = it.url
        if not url or it.verdict is not None or url in seen_urls or db.seen(url):
            continue
        host = host_of(url)
        dom = registrable_domain(host) if host else ""
        if not dom or is_ignored(host) or dom in seen_dom or db.known(f"web:{dom}") or hard_reject(url, it.title):
            continue
        if heuristic(url, it.title, it.snippet)[0] < 0.2:
            continue
        seen_urls.add(url)
        seen_dom.add(dom)
        todo.append(it)
        if max_items and len(todo) >= max_items:
            break
    if len(todo) < 2:
        return 0  # a single page costs the same one call either way: leave it to the normal path
    pages = [{"url": it.url, "title": it.title, "snippet": it.snippet,
              "page": fetch_text(it.url, 600) if len((it.snippet or "").strip()) < 80 else ""} for it in todo]  # snippet first
    try:
        verdicts = llm.classify_batch(pages)
    except LLMError as e:
        log.warning("batch classification failed (%s) - falling back to one call per page", e)
        return 0
    for it, v in zip(todo, verdicts):
        it.verdict = v
    return len(todo)


MAX_BYTES = 300_000  # hard cap on what we ever read from a page
ALLOWED_CTYPES = ("text/html", "application/xhtml+xml", "text/plain")


def public_target(url: str) -> tuple[bool, str]:
    """SSRF guard: http(s) only, a real host, and every address it resolves to must be public (no private, loopback,
    link-local, multicast, reserved or unspecified address)."""
    import ipaddress
    import socket
    from urllib.parse import urlsplit
    try:
        s = urlsplit(url)
    except ValueError:
        return False, "unparsable URL"
    if s.scheme not in ("http", "https"):
        return False, f"scheme '{s.scheme}' is not http(s)"
    if not s.hostname or s.username or s.password:
        return False, "no host / credentials in URL"
    try:
        infos = socket.getaddrinfo(s.hostname, s.port or (443 if s.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except OSError:
        return False, "host does not resolve"
    for fam, _, _, _, sa in infos:
        ip = ipaddress.ip_address(sa[0].split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False, f"{ip} is not a public address"
    return True, ""


@dataclass
class PageDoc:
    """One defensively fetched page. `text` is the visible text only (scripts, styles, nav, footers and tags removed)."""
    url: str
    final_url: str = ""
    status: int = 0  # 0 = not fetched (refused / network error / too many redirects)
    title: str = ""
    headings: list = field(default_factory=list)
    text: str = ""
    error: str = ""
    hops: list = field(default_factory=list)  # every URL visited, in order

    @property
    def ok(self) -> bool:
        return self.status == 200 and bool(self.text)


def _visible(html_: str) -> tuple[str, list[str], str]:
    """(title, headings, visible text) from raw HTML. No JavaScript is ever run."""
    import html as _h
    t = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_)
    title = _h.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t.group(1)))).strip()[:200] if t else ""
    heads = [_h.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(2)))).strip()
             for m in re.finditer(r"(?is)<(h[1-3])[^>]*>(.*?)</\1>", html_)]
    body = re.sub(r"(?is)<(script|style|nav|footer|noscript|template)[^>]*>.*?</\1>", " ", html_)
    body = re.sub(r"(?is)<head[^>]*>.*?</head>", " ", body)
    text = _h.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))).strip()
    return title, [h[:160] for h in heads if h][:20], text


def fetch_doc(url: str, *, max_redirects: int = 3) -> PageDoc:
    """The ONE page at `url`, fetched passively and defensively: only URLs that pass the spam rules, http(s) to public
    addresses only, redirects followed by hand (a hop to ANOTHER domain must pass the spam/ignored-domain gate again, every hop
    is SSRF-checked), text/html types only (no downloads), body capped at MAX_BYTES, timeout, no JavaScript. Never follows
    links found on the page, never submits anything."""
    from urllib.parse import urljoin
    from . import relevance
    doc = PageDoc(url=url, final_url=url)
    cur = url
    if not relevance.url_ok(cur):
        doc.error = "URL failed the spam / redirector rules"
        return doc  # a junk/redirector URL is never fetched
    try:
        for _ in range(max_redirects + 1):
            doc.hops.append(cur)
            ok, why = public_target(cur)
            if not ok:
                log.info("fetch refused %s: %s", cur, why)
                doc.error = f"refused: {why}"
                return doc
            r = get(cur, timeout=12, retries=1, allow_redirects=False, stream=True,
                    headers={"Accept": "text/html,text/plain;q=0.8"})
            doc.final_url, doc.status = cur, r.status_code
            if 300 <= r.status_code < 400 and r.headers.get("Location"):
                nxt = urljoin(cur, r.headers["Location"])
                r.close()
                if registrable_domain(host_of(nxt)) != registrable_domain(host_of(cur)) and not relevance.url_ok(nxt):
                    log.info("fetch refused a redirect %s -> %s (gate)", cur, nxt)
                    doc.error, doc.status = f"redirect to {nxt} refused by the spam / ignored-domain gate", 0
                    return doc
                cur = nxt
                continue
            ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
            if r.status_code != 200 or ctype not in ALLOWED_CTYPES or "attachment" in r.headers.get("content-disposition", "").lower():
                r.close()
                doc.error = f"HTTP {r.status_code}" if r.status_code != 200 else f"content type '{ctype or '?'}' is not a page"
                return doc
            try:
                if int(r.headers.get("content-length", 0)) > MAX_BYTES * 5:
                    r.close()
                    doc.error = "page too large"
                    return doc
            except ValueError:
                pass
            buf, n = [], 0
            for chunk in r.iter_content(8192):
                buf.append(chunk)
                n += len(chunk)
                if n >= MAX_BYTES:
                    break
            r.close()
            raw = b"".join(buf).decode(r.encoding or "utf-8", errors="replace")
            if ctype == "text/plain":
                doc.text = re.sub(r"\s+", " ", raw).strip()
            else:
                doc.title, doc.headings, doc.text = _visible(raw)
            return doc
        doc.error, doc.status = "too many redirects", 0
        return doc
    except Exception as e:  # noqa: BLE001
        log.debug("page fetch failed %s: %s", url, e)
        doc.error, doc.status = f"fetch failed: {type(e).__name__}", 0
        return doc


def fetch_page(url: str, limit: int = 4000, *, max_redirects: int = 3) -> str:
    """Page text for classification (see fetch_doc for the safety rules). Empty string when the page is not a 200 text page."""
    doc = fetch_doc(url, max_redirects=max_redirects)
    if doc.status != 200:
        return ""
    if doc.title and not doc.text.startswith(doc.title):  # keep the old behaviour: the <title> text led the stripped body
        return f"{doc.title} {doc.text}".strip()[:limit]
    return doc.text[:limit]


def fetch_text(url: str, limit: int = 4000) -> str:
    return fetch_page(url, limit)


def from_result(item: SearchResult, llm: Ollama | None, *, allow_llm: bool = True) -> tuple[Program | None, str]:
    """Turn one normalised search result into a Program, or (None, reason).
    With an LLM every plausible hit gets the strict "official page of ONE company?" question; heuristics decide
    alone only when no LLM is available. reason 'ambiguous-skipped' means: do not remember this URL yet."""
    url = item.url
    host = host_of(url)
    if not host or is_ignored(host):
        return None, "ignored-domain"
    title, snippet = item.title, item.snippet
    score, kind = heuristic(url, title, snippet)
    domain = registrable_domain(host)
    head = re.split(r"\s[|\-–—:]\s", title)[0].strip()
    name = f"{domain} — {head}" if head and domain not in head.lower() else (head or domain)
    if score < 0.2:
        return None, f"low heuristic score {score:.2f}"
    summary = ""
    by = "rules"
    pre = getattr(item, "verdict", None)
    if pre is not None and (llm and allow_llm):  # already judged in a batch: no second call
        v, err = pre, None
    else:
        v, err = None, None
    if llm and allow_llm:
        try:
            if v is None:
                # classify from the provider's title/snippet first; fetch the page only when that is too thin to judge
                need_page = len((snippet or "").strip()) < 80 or score < 0.5
                v = llm.classify(url, title, snippet, fetch_text(url) if need_page else "")
                if not need_page and 0.35 <= float(v.get("confidence", 0)) < 0.75:  # unsure: now it is worth a fetch
                    page = fetch_text(url)
                    if page:
                        v = llm.classify(url, title, snippet, page)
        except LLMError as e:
            log.warning("LLM classify failed: %s", e)
            if score < 0.8:
                return None, "ambiguous-skipped"
        else:
            if not v["is_program"] or v["confidence"] < 0.5:
                return None, f"LLM: {v['reason']}"
            score = max(score, v["confidence"])
            kind = "bounty" if v["type"] == "bounty" else (kind if kind == "security.txt" else "vdp")
            summary, by = v["reason"], "llm"
    else:
        need = 0.8 if llm else 0.5  # LLM exists but its per-cycle budget is spent -> be conservative
        if score < need:
            return None, "ambiguous-skipped" if llm else f"low heuristic score {score:.2f}"
    p = _mk(domain, name, url, kind, snippet, host, score)
    p.summary = summary
    p.classified_by = by
    # What do the dates on the hit mean? 'Last update' / 'effective date' / 'renewal' are never launch dates.
    ev = datekind.analyse(title, snippet, item.published, llm if (llm and allow_llm) else None)
    d = datekind.summarise(ev)
    p.launched_at, p.launched_via, p.updated_at, p.date_kind = d["launched_at"], d["launched_via"], d["updated_at"], d["date_kind"]
    return p, ""


def _mk(domain, name, url, kind, snippet, host, score) -> Program:
    return Program("web", domain, name, normalize_url(url), kind, snippet=snippet, country=country_of(host),
                   confidence=round(score, 2))
