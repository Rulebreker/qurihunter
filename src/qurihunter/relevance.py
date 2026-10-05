"""Relevance gate + spam rules, applied to every search hit BEFORE any LLM call, page fetch or storage.

A hit survives only if (a) no spam rule fires and (b) at least one quoted phrase of the dork (or ALL key terms when the dork
has no quotes) appears in the title, snippet or URL - case-insensitive, accents folded, with per-language synonyms from the
dork's own language group. A hit without any snippet that fails (b) goes on only to a cheap rules check (no LLM, no fetch).
Spam rules live in an editable file (~/.qurihunter/spam_rules.txt, copied from the packaged default on first use)."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from . import countries
from .logs import log
from .paths import home
from .search.dorkparse import parse

PACKAGED = Path(__file__).parent / "data" / "spam_rules.txt"
STOP = {"the", "and", "for", "with", "site", "inurl", "intitle", "page", "pages", "https", "http", "www", "com", "program"}


def fold(s: str) -> str:
    """Lowercase, accents folded (Sicherheitslücke == sicherheitslucke), punctuation to spaces; non-Latin letters are kept."""
    t = unicodedata.normalize("NFKD", str(s or ""))
    t = "".join(c for c in t if not unicodedata.combining(c)).lower()
    return re.sub(r"[\W_]+", " ", t, flags=re.UNICODE).strip()


def _latinish(s: str) -> bool:
    letters = [c for c in s if c.isalpha()]
    return not letters or sum(1 for c in letters if _is_latin(c)) / len(letters) > 0.5


def _is_latin(c: str) -> bool:
    try:
        return unicodedata.name(c).startswith("LATIN")
    except ValueError:
        return False


# ── synonyms per concept and language (the dork's own language group + English) ─────────────────────
CONCEPTS: list[dict[str, list[str]]] = [
    {"en": ["responsible disclosure", "coordinated vulnerability disclosure", "vulnerability disclosure", "coordinated disclosure",
            "vulnerability disclosure policy", "report a vulnerability", "report vulnerabilities", "security vulnerability", "vdp",
            "security.txt", "report a security"],
     "de": ["verantwortungsvolle offenlegung", "verantwortungsvolle meldung", "schwachstelle melden", "schwachstellen melden",
            "sicherheitslucke melden", "sicherheitsluecke melden", "offenlegung von schwachstellen", "responsible disclosure"],
     "fr": ["divulgation responsable", "signaler une vulnerabilite", "politique de divulgation", "divulgation coordonnee"],
     "es": ["divulgacion responsable", "reportar vulnerabilidad", "divulgacion coordinada", "reporte de vulnerabilidades"],
     "it": ["divulgazione responsabile", "segnalazione vulnerabilita", "segnalare una vulnerabilita"],
     "nl": ["kwetsbaarheid melden", "melden van kwetsbaarheden", "responsible disclosure", "coordinated vulnerability disclosure"],
     "pt": ["divulgacao responsavel", "reportar vulnerabilidade", "divulgacao coordenada"],
     "sv": ["ansvarsfull rapportering", "sarbarhet", "ansvarsfull avslojande"],
     "no": ["ansvarlig varsling", "sarbarhet"], "da": ["ansvarlig offentliggorelse", "sarbarhed"], "fi": ["haavoittuvuus"],
     "pl": ["odpowiedzialne ujawnienie", "zgloszenie podatnosci", "podatnosc"], "cs": ["zranitelnost", "zodpovedne zverejneni"],
     "sk": ["zranitelnost", "zodpovedne zverejnenie"], "tr": ["guvenlik acigi", "sorumlu ifsa"]},
    {"en": ["bug bounty", "bounty program", "vulnerability reward", "reward program", "security reward", "rewards program",
            "hall of fame", "bounty"],
     "de": ["bug bounty", "pramie", "belohnung", "kopfgeld"], "fr": ["prime", "recompense", "bug bounty"],
     "es": ["recompensa", "bug bounty", "programa de recompensas"], "it": ["ricompensa", "bug bounty"],
     "nl": ["beloning", "bug bounty"], "pt": ["recompensa", "bug bounty"]},
]


def language_group(dork: str, tld: str = "") -> str:
    """Language of the dork: from its site:.cc, else guessed from its words, else English."""
    if tld:
        return countries.lang_of(tld)
    f = fold(dork)
    for lang, marks in (("de", ("schwachstelle", "offenlegung", "sicherheitslucke", "melden")), ("fr", ("divulgation", "vulnerabilite", "signaler")),
                        ("es", ("divulgacion", "vulnerabilidad", "reportar")), ("it", ("divulgazione", "vulnerabilita", "segnalazione")),
                        ("nl", ("kwetsbaarheid",)), ("pt", ("divulgacao", "vulnerabilidade"))):
        if any(m in f for m in marks):
            return lang
    return "en"


def alternatives(phrase: str, lang: str) -> list[str]:
    """The phrase itself plus its synonyms in the dork's language group (and English)."""
    p = fold(phrase)
    out = [p]
    for c in CONCEPTS:
        pool = {fold(x) for x in c.get("en", [])} | {fold(x) for x in c.get(lang, [])}
        if p in pool or any(p in x or x in p for x in pool if len(x) > 6 and len(p) > 6):
            out += [fold(x) for x in c.get("en", [])] + [fold(x) for x in c.get(lang, [])]
    return list(dict.fromkeys(out))


def _alt_hit(alt: str, hay: str, literal: bool) -> bool:
    """The phrase as written, or - for synonyms - all its words in any order (German 'melden Sie Schwachstellen' == 'Schwachstellen
    melden'), each word matched by its stem (first letters)."""
    if f" {alt} " in hay:
        return True
    words = alt.split()
    if literal or len(words) < 2:
        return False
    toks = hay.split()
    return all(any(t.startswith(w[: max(5, len(w) - 2)]) or w.startswith(t) and len(t) >= 6 for t in toks) for w in words)


def key_terms(dork: str) -> tuple[list[str], list[str]]:
    """(quoted phrases, key terms) of a dork, operators dropped."""
    pd = parse(dork)
    phrases = [fold(p) for p in pd.phrases if fold(p)]
    words = [*pd.words, *pd.title_terms, *(re.split(r"[/\\-]", u)[-1] if "." in u and "/" in u else u for u in pd.url_terms)]
    terms = [t for t in (fold(w) for w in words) if len(t) >= 3 and t not in STOP]
    return phrases, list(dict.fromkeys(terms))


# ── spam rules (editable file) ────────────────────────────────────────────────────────────────────
@dataclass
class Rules:
    url: list
    host: list
    path: list
    title: list
    words: list
    script: float


_cache: dict = {"mtime": None, "rules": None}


def rules_path() -> Path:
    return home() / "spam_rules.txt"


def ensure_rules_file() -> Path:
    p = rules_path()
    if not p.exists():
        try:
            p.write_text(PACKAGED.read_text())
        except OSError:
            pass
    return p


def load_rules() -> Rules:
    p = ensure_rules_file()
    src = p if p.exists() else PACKAGED
    mt = src.stat().st_mtime
    if _cache["rules"] is not None and _cache["mtime"] == (str(src), mt):
        return _cache["rules"]
    r = Rules([], [], [], [], [], 0.5)
    for n, line in enumerate(src.read_text().splitlines(), 1):
        line = line.split("  #")[0].strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        kind, val = (x.strip() for x in line.split(":", 1))
        try:
            if kind in ("url", "host", "path", "title"):
                getattr(r, kind).append(re.compile(val, re.I))
            elif kind == "word":
                r.words += [w.strip().lower() for w in val.split(",") if w.strip()]
            elif kind == "script":
                r.script = float(val)
        except (re.error, ValueError) as e:
            log.warning("spam_rules.txt line %d ignored (%s)", n, e)
    _cache.update(mtime=(str(src), mt), rules=r)
    return r


def _nonlatin_share(title: str) -> float:
    letters = [c for c in title if c.isalpha()]
    return 0.0 if not letters else sum(1 for c in letters if not _is_latin(c)) / len(letters)


def spam_reason(url: str, title: str = "", snippet: str = "", *, dork_lang: str = "en", soft: bool = True) -> str | None:
    """Which junk rule fires for this hit (None = clean). `soft=False` skips the path/host/script rules (used for the strong-
    positive exemption and for fetch targets)."""
    r = load_rules()
    full = unquote(url or "")
    try:
        s = urlsplit(url)
    except ValueError:
        return "unparsable URL"
    for rx in r.url:
        if rx.search(full):
            return f"redirector/proxy/doorway URL ({rx.pattern[:40]})"
    hay = f" {fold(title)} {fold(snippet)} {fold(full)} "
    for w in r.words:
        if f" {fold(w)} " in hay:
            return f"adult/gambling word '{w}'"
    for rx in r.title:
        if rx.search(title or ""):
            return f"title rule ({rx.pattern[:30]})"
    if soft:
        host = (s.hostname or "")
        for rx in r.host:
            if rx.search(host):
                return f"host looks like jobs/tickets/rentals/classifieds ({rx.pattern[:30]})"
        for rx in r.path:
            if rx.search(s.path or ""):
                return f"jobs/tickets/rentals/classifieds path ({rx.pattern[:30]})"
        if title and dork_lang not in countries.NON_LATIN_LANGS and _nonlatin_share(title) > r.script:
            return "title is mostly non-Latin script for a Latin-script dork"
    return None


def url_ok(url: str) -> bool:
    """For fetch targets / redirect hops: nothing that matches the spam rules and nothing on the ignored-domain list."""
    from .urls import host_of, is_ignored
    return spam_reason(url, soft=False) is None and not is_ignored(host_of(url))


# ── the gate ──────────────────────────────────────────────────────────────────────────────────────
def check(dork: str, url: str, title: str = "", snippet: str = "") -> tuple[str, str]:
    """('keep' | 'rules-only' | 'drop', reason)."""
    from .classify import PATH_POS
    pd = parse(dork)
    lang = language_group(dork, pd.tld)
    strong = bool(PATH_POS.search(urlsplit(url or "").path))
    why = spam_reason(url, title, snippet, dork_lang=lang, soft=not strong)
    if why:
        return "drop", f"spam: {why}"
    phrases, terms = key_terms(dork)
    hay = " " + " ".join([fold(title), fold(snippet), fold(unquote(url or ""))]) + " "
    if phrases:
        ok = any(any(_alt_hit(a, hay, literal=(i == 0)) for i, a in enumerate(alternatives(p, lang))) for p in phrases)
        need = f"none of {', '.join(repr(p) for p in phrases[:3])} (or synonyms)"
    elif terms:
        ok = all(any(f" {a} " in hay or a in hay for a in ([t] + alternatives(t, lang)[1:])) for t in terms)
        need = f"not all of {', '.join(terms[:4])}"
    else:
        return "keep", "dork has no terms to match"
    if ok:
        return "keep", "dork phrase/terms found"
    if not (snippet or "").strip():
        return "rules-only", f"no snippet to confirm relevance ({need}); cheap rules check only"
    return "drop", f"not relevant: {need} in title/snippet/URL"


def filter_results(dork: str, results: list, *, log_drops: bool = True) -> tuple[list, list[tuple]]:
    """(kept, dropped[(item, reason, is_spam)]). Kept items may carry rules_only=True (no LLM, no page fetch)."""
    kept, dropped = [], []
    for it in results:
        verdict, why = check(dork, it.url, it.title, it.snippet)
        if verdict == "drop":
            dropped.append((it, why, why.startswith("spam:")))
            if log_drops:
                log.info("relevance drop %s - %s", it.url, why)
            continue
        if verdict == "rules-only":
            it.rules_only = True
        kept.append(it)
    return kept, dropped
