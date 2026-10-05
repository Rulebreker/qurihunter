"""Dork wordlists: import, storage, per-provider merging, rotation and statistics."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import dates
from .db import DB
from .search.dorkparse import parse
from .sources import dorks as legacy

REPO_DEFAULT = Path(__file__).resolve().parents[2] / "dorks" / "default.txt"
BUNDLED_DEFAULT = Path(__file__).parent / "data" / "default_dorks.txt"
DATE_RE = re.compile(r"\s*\b(?:after|before):\S+|\s*\b(?:19|20)\d\d-\d\d-\d\d\b", re.I)
HEADER = re.compile(r"^#\s*-{3,}\s*(.+?)\s*-{3,}\s*$")
MODES = ("default", "custom", "both")


def default_path() -> Path:
    return REPO_DEFAULT if REPO_DEFAULT.exists() else BUNDLED_DEFAULT


def normalise(text: str) -> str:
    t = text.replace("“", '"').replace("”", '"').replace("’", "'")
    t = DATE_RE.sub("", t)
    return " ".join(t.split()).lower()


def has_date(text: str) -> bool:
    return bool(DATE_RE.search(text))


@dataclass
class Entry:
    text: str
    section: str = ""


def parse_file(path: Path) -> list[Entry]:
    out, section = [], ""
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = HEADER.match(line)
            if m:
                section = m.group(1)
            continue
        out.append(Entry(line, section))
    return out


@dataclass
class Report:
    total: int = 0
    added: int = 0
    duplicates: int = 0
    dated: int = 0
    invalid: int = 0
    details: list[str] = field(default_factory=list)

    def text(self) -> str:
        return (f"{self.total} lines → {self.added} added, {self.duplicates} duplicates skipped, "
                f"{self.dated} with hardcoded dates, {self.invalid} invalid")


def analyse(entries: list[Entry], provider=None) -> dict:
    """Pre-import report: count, exact duplicates, hardcoded dates, and how many dorks would merge after the
    given provider flattens operators (Tavily has none)."""
    seen, dup, dated = {}, 0, 0
    for e in entries:
        n = normalise(e.text)
        dated += has_date(e.text)
        if n in seen:
            dup += 1
        seen[n] = e
    merged = len(merge_similar([(i, e.text, 0) for i, e in enumerate({normalise(x.text): x for x in entries}.values())],
                               provider)[1]) if provider else 0
    return {"count": len(entries), "unique": len(seen), "exact_duplicates": dup, "with_dates": dated,
            "provider_merges": merged}


def import_file(db: DB, path: Path, grp: str = "custom", *, strip_dates: bool | None = None,
                priority: int = 0) -> Report:
    """Idempotent: an already-known dork (any group) is skipped, so re-importing never duplicates."""
    strip = (grp == "default") if strip_dates is None else strip_dates
    rep = Report()
    for e in parse_file(path):
        rep.total += 1
        text = DATE_RE.sub("", e.text).strip() if strip else e.text
        if has_date(e.text) and strip:
            rep.dated += 1
        elif has_date(e.text):
            rep.dated += 1
        if not text or len(text) > 300 or not re.search(r"\w", text):
            rep.invalid += 1
            continue
        norm = normalise(text) if strip else " ".join(text.lower().split())
        if db.c.execute("SELECT 1 FROM dorks WHERE norm=?", (norm,)).fetchone():
            rep.duplicates += 1
            continue
        db.c.execute("INSERT INTO dorks(text,norm,grp,priority,created_at,section) VALUES(?,?,?,?,?,?)",
                     (" ".join(text.split()), norm, grp, priority, dates.now_iso(), e.section))
        rep.added += 1
    db.commit()
    return rep


def add_dork(db: DB, text: str, grp: str, *, parent: int | None = None, rationale: str = "", priority: int = 0,
             generated: bool = False) -> int | None:
    norm = " ".join(text.lower().split())
    if db.c.execute("SELECT 1 FROM dorks WHERE norm=?", (norm,)).fetchone():
        return None
    cur = db.c.execute("INSERT INTO dorks(text,norm,grp,priority,created_at,parent_dork_id,rationale,generated) "
                       "VALUES(?,?,?,?,?,?,?,?)", (" ".join(text.split()), norm, grp, priority, dates.now_iso(),
                                                   parent, rationale, int(generated)))
    db.commit()
    return cur.lastrowid


def ensure_default(db: DB) -> Report | None:
    """Make sure the built-in list is in the DB (adds lines new in this release; never resurrects deleted choices
    for existing rows, never duplicates)."""
    p = default_path()
    if not p.exists():
        return None
    known = db.meta("default_list_size")
    size = str(p.stat().st_size)
    if known == size:
        return None
    rep = import_file(db, p, "default")
    db.set_meta("default_list_size", size)
    db.commit()
    return rep


def reset_default(db: DB) -> Report:
    """Restore dorks/default.txt exactly: re-enable, drop default dorks no longer in the file. Custom and AI dorks
    are untouched."""
    p = default_path()
    keep = {normalise(DATE_RE.sub("", e.text).strip()) for e in parse_file(p)}
    for r in db.c.execute("SELECT id, norm, generated FROM dorks WHERE grp='default'").fetchall():
        if r["norm"] not in keep and not r["generated"]:
            db.c.execute("DELETE FROM dorks WHERE id=?", (r["id"],))
    db.c.execute("UPDATE dorks SET enabled=1, auto_disabled_reason=NULL WHERE grp='default'")
    rep = import_file(db, p, "default")
    db.set_meta("default_list_size", str(p.stat().st_size))
    db.commit()
    return rep


def ensure_country_dorks(db: DB, countries: list[str]) -> int:
    """When the user restricts countries, make sure per-ccTLD variants of the core templates exist (generated)."""
    n = 0
    for q in legacy.build(countries) if countries else []:
        if add_dork(db, q, "default", generated=True) is not None:
            n += 1
    return n


# ── similarity / merging ─────────────────────────────────────────────────────────
def _similar(a, b, threshold=0.9) -> bool:
    ta, tb = a[0], b[0]
    if a[1:] != b[1:] or not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= threshold


def merge_similar(items: list[tuple[int, str, int]], provider, threshold: float = 0.9):
    """items: (id, text, priority). Returns (kept, merged) where merged = [(dropped_id, kept_id)].
    Dorks that translate to identical/near-identical queries for `provider` are collapsed (highest priority wins)."""
    if provider is None:
        return items, []
    order = sorted(items, key=lambda x: (-x[2], x[0]))
    kept, fps, merged = [], [], []
    for it in order:
        fp = provider.fingerprint(it[1])
        for k, kfp in zip(kept, fps):
            if kfp == fp or _similar(kfp, fp, threshold):
                merged.append((it[0], k[0]))
                break
        else:
            kept.append(it)
            fps.append(fp)
    return kept, merged


# ── selection ────────────────────────────────────────────────────────────────────
@dataclass
class Selection:
    chosen: list = field(default_factory=list)
    candidates: int = 0
    merged: int = 0
    cooling: int = 0
    waiting: int = 0
    explore: int = 0
    parked: int = 0
    rewritten: int = 0


def candidates(db: DB, cfg: dict):
    mode = cfg["dorks"]["source"] if cfg["dorks"]["source"] in MODES else "default"
    grps = {"default": ["default"], "custom": ["custom"], "both": ["default", "custom"]}[mode]
    if cfg["features"]["ai_dorks"]:
        grps = grps + ["ai"]
    rows = db.c.execute(f"SELECT * FROM dorks WHERE enabled=1 AND grp IN ({','.join('?' * len(grps))})", grps).fetchall()
    ccs = [legacy.normalize_cc(c) for c in cfg["filters"]["countries"]]
    if ccs:  # a country filter means ccTLD dorks only (as in v1)
        rows = [r for r in rows if parse(r["text"]).tld in ccs]
    return rows


def _as_list(provider) -> list:
    return [] if provider is None else list(provider) if isinstance(provider, (list, tuple)) else [provider]


def expressibility(rows, provider) -> dict:
    """Classify dork rows for `provider` (one or an ordered list): ok = some provider runs it as written;
    rewritten = only via a natural-language country rewrite; parked = no provider can express it."""
    provs = _as_list(provider)
    out: dict = {"ok": [], "rewritten": [], "parked": []}
    for r in rows:
        if not provs:
            out["ok"].append(r)
            continue
        res = [p.express(r["text"]) for p in provs]
        if any(st == "ok" for st, _ in res):
            out["ok"].append(r)
        elif any(st == "rewritten" for st, _ in res):
            out["rewritten"].append((r, next(t for st, t in res if st == "rewritten")))
        else:
            out["parked"].append((r, res[0][1]))
    return out


def select(db: DB, cfg: dict, provider, budget: int, skip=None) -> Selection:
    """`provider` may be one provider or the ordered list of the sequence (parked = no provider can express it)."""
    sel = Selection()
    rows = candidates(db, cfg)
    sel.candidates = len(rows)
    provs = _as_list(provider)
    provider = provs[0] if provs else None  # fingerprints/merging follow the first provider
    ex = expressibility(rows, provs)
    parked = {r["id"] for r, _ in ex["parked"]}
    sel.parked = len(parked)  # cannot be expressed on this provider: no quota, no batch slot, run when a capable one exists
    sel.rewritten = len(ex["rewritten"])
    rows = [r for r in rows if r["id"] not in parked]
    kept, merged = merge_similar([(r["id"], r["text"], r["priority"]) for r in rows], provider)
    sel.merged = len(merged)
    keep_ids = {k[0] for k in kept}
    rows = [r for r in rows if r["id"] in keep_ids]
    if skip:  # inside cooldown: would cost nothing, so don't let it occupy a batch slot
        cool = [r for r in rows if skip(r)]
        sel.cooling = len(cool)
        rows = [r for r in rows if r not in cool]

    def key(r):  # priority desc, least recently run (never-run first), most productive
        return (-r["priority"], r["last_run_at"] or "", -r["new_programs_found"])
    rows.sort(key=key)
    explore = [r for r in rows if r["grp"] == "ai" and r["new_programs_found"] == 0]
    proven = [r for r in rows if r not in explore]
    max_explore = int(cfg["dorks"]["ai_share"] * budget)
    picked_explore = explore[:max_explore]
    picked = proven[:max(0, budget - len(picked_explore))] + picked_explore
    picked.sort(key=key)
    sel.chosen, sel.explore = picked, len(picked_explore)
    sel.waiting = len(rows) - len(picked)
    return sel


def estimate_days(total: int, per_cycle: int, interval_min: int) -> float | None:
    if per_cycle <= 0:
        return None
    cycles = -(-total // per_cycle)
    return cycles * interval_min / 1440


# ── bookkeeping ──────────────────────────────────────────────────────────────────
def record_run(db: DB, dork_id: int, results: int, new: int) -> None:
    db.c.execute("UPDATE dorks SET last_run_at=?, run_count=run_count+1, hits_total=hits_total+?, "
                 "new_programs_found=new_programs_found+?, "
                 "priority=CASE WHEN grp='ai' AND ?>0 AND priority<10 THEN priority+1 ELSE priority END WHERE id=?",
                 (dates.now_iso(), results, new, new, dork_id))  # AI winners rise in the rotation


def auto_disable_unproductive_ai(db: DB, after_runs: int) -> int:
    cur = db.c.execute("UPDATE dorks SET enabled=0, auto_disabled_reason=? WHERE grp='ai' AND enabled=1 AND "
                       "run_count>=? AND new_programs_found=0",
                       (f"no new programs after {after_runs} runs", after_runs))
    db.commit()
    return cur.rowcount


def prune_candidates(db: DB, after_runs: int):
    return db.c.execute("SELECT * FROM dorks WHERE enabled=1 AND run_count>=? AND new_programs_found=0 "
                        "ORDER BY run_count DESC", (after_runs,)).fetchall()


def stats(db: DB) -> dict:
    g = {r["grp"]: dict(r) for r in db.c.execute(
        "SELECT grp, COUNT(*) n, SUM(enabled) enabled, SUM(run_count) runs, SUM(hits_total) hits, "
        "SUM(new_programs_found) found FROM dorks GROUP BY grp")}
    top = db.c.execute("SELECT * FROM dorks WHERE new_programs_found>0 ORDER BY new_programs_found DESC LIMIT 10").fetchall()
    never = db.c.execute("SELECT COUNT(*) FROM dorks WHERE enabled=1 AND run_count=0").fetchone()[0]
    auto = db.c.execute("SELECT COUNT(*) FROM dorks WHERE auto_disabled_reason IS NOT NULL").fetchone()[0]
    return {"groups": g, "top": top, "never_run": never, "auto_disabled": auto}
