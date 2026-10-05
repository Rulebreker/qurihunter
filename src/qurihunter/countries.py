"""Country dorks for providers that cannot express `site:.cc`: rewrite them as natural-language queries (country name +
local-language disclosure terms) and filter the results client-side on the result domain / page text."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

# cc -> (name used in the query, [names a page might use], local disclosure terms)
C: dict[str, tuple[str, list[str], str]] = {
    "ch": ("Schweiz", ["Switzerland", "Schweiz", "Suisse", "Svizzera"], "Schwachstelle melden Sicherheitslücke"),
    "de": ("Deutschland", ["Germany", "Deutschland"], "Schwachstelle melden Sicherheitslücke"),
    "at": ("Österreich", ["Austria", "Österreich"], "Schwachstelle melden Sicherheitslücke"),
    "li": ("Liechtenstein", ["Liechtenstein"], "Schwachstelle melden"),
    "fr": ("France", ["France"], "divulgation responsable vulnérabilité signaler"),
    "be": ("Belgique", ["Belgium", "Belgique", "België"], "kwetsbaarheid melden"),
    "nl": ("Nederland", ["Netherlands", "Nederland"], "kwetsbaarheid melden"),
    "lu": ("Luxembourg", ["Luxembourg", "Luxemburg"], "vulnérabilité signaler Schwachstelle"),
    "it": ("Italia", ["Italy", "Italia"], "segnalazione vulnerabilità divulgazione responsabile"),
    "es": ("España", ["Spain", "España"], "divulgación responsable vulnerabilidad reportar"),
    "pt": ("Portugal", ["Portugal"], "divulgação responsável vulnerabilidade reportar"),
    "br": ("Brasil", ["Brazil", "Brasil"], "divulgação responsável vulnerabilidade reportar"),
    "mx": ("México", ["Mexico", "México"], "divulgación responsable vulnerabilidad reportar"),
    "ar": ("Argentina", ["Argentina"], "divulgación responsable vulnerabilidad reportar"),
    "cl": ("Chile", ["Chile"], "divulgación responsable vulnerabilidad reportar"),
    "co": ("Colombia", ["Colombia"], "divulgación responsable vulnerabilidad reportar"),
    "se": ("Sweden", ["Sweden", "Sverige"], "ansvarsfull rapportering sårbarhet"),
    "no": ("Norge", ["Norway", "Norge"], "ansvarlig varsling sårbarhet"),
    "dk": ("Danmark", ["Denmark", "Danmark"], "ansvarlig offentliggørelse sårbarhed"),
    "fi": ("Suomi", ["Finland", "Suomi"], "haavoittuvuus vastuullinen paljastaminen"),
    "is": ("Ísland", ["Iceland", "Ísland"], "veikleiki ábyrg uppljóstrun"),
    "ee": ("Eesti", ["Estonia", "Eesti"], "turvaauk vastutustundlik avalikustamine"),
    "lv": ("Latvija", ["Latvia", "Latvija"], "ievainojamība atbildīga atklāšana"),
    "lt": ("Lietuva", ["Lithuania", "Lietuva"], "pažeidžiamumas atsakingas atskleidimas"),
    "pl": ("Polska", ["Poland", "Polska"], "podatność zgłoszenie odpowiedzialne ujawnienie"),
    "cz": ("Česko", ["Czech", "Česko", "Česká"], "zranitelnost nahlášení zodpovědné zveřejnění"),
    "sk": ("Slovensko", ["Slovakia", "Slovensko"], "zraniteľnosť nahlásenie zodpovedné zverejnenie"),
    "hu": ("Magyarország", ["Hungary", "Magyarország"], "sebezhetőség bejelentés felelős közzététel"),
    "ro": ("România", ["Romania", "România"], "vulnerabilitate raportare divulgare responsabilă"),
    "bg": ("България", ["Bulgaria", "България"], "уязвимост отговорно разкриване"),
    "gr": ("Ελλάδα", ["Greece", "Ελλάδα"], "ευπάθεια υπεύθυνη αποκάλυψη"),
    "si": ("Slovenija", ["Slovenia", "Slovenija"], "ranljivost odgovorno razkritje"),
    "hr": ("Hrvatska", ["Croatia", "Hrvatska"], "ranjivost odgovorno otkrivanje"),
    "rs": ("Srbija", ["Serbia", "Srbija"], "ranjivost odgovorno otkrivanje"),
    "tr": ("Türkiye", ["Turkey", "Türkiye"], "güvenlik açığı sorumlu ifşa"),
    "ru": ("Россия", ["Russia", "Россия"], "уязвимость ответственное раскрытие"),
    "ua": ("Україна", ["Ukraine", "Україна"], "вразливість відповідальне розкриття"),
    "uk": ("United Kingdom", ["United Kingdom", "UK", "Britain"], "report a security vulnerability"),
    "gb": ("United Kingdom", ["United Kingdom", "UK", "Britain"], "report a security vulnerability"),
    "ie": ("Ireland", ["Ireland", "Éire"], "report a security vulnerability"),
    "ca": ("Canada", ["Canada"], "divulgation responsable vulnérabilité"),
    "au": ("Australia", ["Australia"], "report a security vulnerability"),
    "nz": ("New Zealand", ["New Zealand"], "report a security vulnerability"),
    "in": ("India", ["India"], "report a security vulnerability"),
    "jp": ("日本", ["Japan", "日本"], "脆弱性 報告 脆弱性開示"),
    "kr": ("한국", ["Korea", "한국"], "취약점 신고 책임있는 공개"),
    "tw": ("台灣", ["Taiwan", "台灣"], "漏洞 通報 弱點揭露"),
    "hk": ("Hong Kong", ["Hong Kong", "香港"], "漏洞 通報"),
    "sg": ("Singapore", ["Singapore"], "report a security vulnerability"),
    "my": ("Malaysia", ["Malaysia"], "laporkan kerentanan"),
    "id": ("Indonesia", ["Indonesia"], "pelaporan kerentanan"),
    "th": ("ประเทศไทย", ["Thailand", "ไทย"], "ช่องโหว่ แจ้ง"),
    "vn": ("Việt Nam", ["Vietnam", "Việt Nam"], "lỗ hổng bảo mật báo cáo"),
    "ph": ("Philippines", ["Philippines"], "report a security vulnerability"),
    "il": ("Israel", ["Israel"], "report a security vulnerability"),
    "ae": ("UAE", ["United Arab Emirates", "UAE"], "report a security vulnerability"),
    "sa": ("Saudi Arabia", ["Saudi Arabia"], "الإبلاغ عن ثغرة"),
    "za": ("South Africa", ["South Africa"], "report a security vulnerability"),
    "ng": ("Nigeria", ["Nigeria"], "report a security vulnerability"),
    "ke": ("Kenya", ["Kenya"], "report a security vulnerability"),
    "eg": ("Egypt", ["Egypt", "مصر"], "الإبلاغ عن ثغرة"),
}


def known(cc: str) -> bool:
    return cc.lower() in C


def rewrite(pd) -> str | None:
    """`"responsible disclosure" site:.ch` -> `Schweiz responsible disclosure Schwachstelle melden Sicherheitslücke`.
    None when we have no country entry for the TLD."""
    ent = C.get(pd.tld.lower())
    if not ent:
        return None
    name, _, local = ent
    base = [t for t in pd.terms() if t.lower() not in ("security.txt",)][:4]
    parts = [name, *base]
    if not all(w.lower() in " ".join(base).lower().split() for w in local.split()):
        parts.append(local)  # local-language terms, unless the base query already says exactly that
    out, seen = [], set()
    for ph in parts:  # drop repeated phrases (not words, so "report a vulnerability" stays intact)
        if ph.lower() not in seen:
            seen.add(ph.lower())
            out.append(ph)
    return " ".join(out)


def match(cc: str, url: str, title: str = "", snippet: str = "") -> bool:
    """Client-side country filter: result domain ends in .cc, or the page text names the country."""
    cc = cc.lower()
    host = (urlsplit(url).hostname or "").lower()
    if host.endswith("." + cc):
        return True
    ent = C.get(cc)
    if not ent:
        return False
    text = f"{title} {snippet}"
    return any(re.search(rf"(?<!\w){re.escape(n)}(?!\w)", text, re.I) for n in ent[1])


# ── language / script / Google `gl` helpers ─────────────────────────────────
# cc -> primary language (ISO 639-1) used for Google's `hl` and for the relevance gate's language group
LANG = {"ch": "de", "de": "de", "at": "de", "li": "de", "fr": "fr", "be": "fr", "lu": "fr", "it": "it", "es": "es", "pt": "pt",
        "br": "pt", "mx": "es", "ar": "es", "cl": "es", "co": "es", "nl": "nl", "se": "sv", "no": "no", "dk": "da", "fi": "fi",
        "is": "is", "ee": "et", "lv": "lv", "lt": "lt", "pl": "pl", "cz": "cs", "sk": "sk", "hu": "hu", "ro": "ro", "bg": "bg",
        "gr": "el", "si": "sl", "hr": "hr", "rs": "sr", "tr": "tr", "ru": "ru", "ua": "uk", "uk": "en", "gb": "en", "ie": "en",
        "us": "en", "ca": "en", "au": "en", "nz": "en", "in": "en", "jp": "ja", "kr": "ko", "tw": "zh", "hk": "zh", "sg": "en",
        "my": "ms", "id": "id", "th": "th", "vn": "vi", "ph": "en", "il": "he", "ae": "ar", "sa": "ar", "za": "en", "ng": "en",
        "ke": "en", "eg": "ar"}
NON_LATIN_LANGS = {"ru", "uk", "bg", "sr", "el", "ja", "ko", "zh", "th", "he", "ar"}
# TLDs that are not (only) countries: never sent as Google's `gl`
NON_COUNTRY = {"io", "ai", "tv", "me", "co", "cc", "fm", "ly", "gg", "to", "ws", "nu", "su", "eu", "app", "dev", "com", "net",
               "org", "edu", "gov", "mil", "int"}


def lang_of(cc: str) -> str:
    return LANG.get((cc or "").lower(), "en")


def gl_for(cc: str) -> str | None:
    """Google `gl` country code for a ccTLD, or None when the TLD is generic / not a country."""
    from . import tlds
    cc = (cc or "").lower()
    if len(cc) != 2 or cc in NON_COUNTRY or not tlds.is_known(cc):
        return None
    return "gb" if cc == "uk" else cc
