"""Evidence-based promotion of AI dorks into the default list (v0.5).

An AI dork is promoted only on COUNTS computed by code (never by the LLM): enough runs, enough distinct NEW programs that
ended VERIFIED (validator or your own 'valid' mark), enough precision (verified programs / results kept by the relevance
gate), the dork validator + blocklist pass again, and it is not a near-duplicate of a default dork. Promoted dorks live in
the DB (group 'default', origin 'ai_promoted') and are mirrored to ~/.qurihunter/learned_default.txt so they survive
upgrades and DB resets. The repository file dorks/default.txt is only ever changed by /dorks export-default, after a diff
and an explicit yes."""
from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import dates, dorkstore
from .logs import log
from .paths import home

LEARNED = "learned_default.txt"
SECTION = "AI-promoted"
VERIFIED_SQL = ("SELECT COUNT(*) FROM programs WHERE found_by_dork=? AND verdict='official_program' AND "
                "(label='valid' OR (label IS NULL AND validity='verified'))")


def learned_path() -> Path:
    return home() / LEARNED


def _pc(cfg: dict) -> dict:
    d = cfg.get("dorks", {})
    return {"min_runs": int(d.get("promote_min_runs", 3)), "min_verified": int(d.get("promote_min_verified", 2)),
            "min_precision": float(d.get("promote_min_precision", 0.3)), "similarity": float(d.get("promote_similarity", 0.8)),
            "demote_runs": int(d.get("demote_after_runs", 10)), "demote_precision": float(d.get("demote_below_precision", 0.1)),
            "mode": str(d.get("ai_auto_promote", "ask")).lower()}


def quality(db, r) -> dict:
    """runs, kept results, verified-valid NEW programs and precision of one dork row."""
    verified = db.c.execute(VERIFIED_SQL, (r["id"],)).fetchone()[0]
    kept = int(r["kept_total"] or 0)
    return {"runs": int(r["run_count"] or 0), "kept": kept, "verified": verified,
            "precision": round(verified / kept, 3) if kept else 0.0}


@dataclass
class Eligibility:
    dork_id: int
    text: str
    conditions: list = field(default_factory=list)  # [(name, ok, detail)]
    evidence: dict = field(default_factory=dict)

    @property
    def eligible(self) -> bool:
        return bool(self.conditions) and all(ok for _, ok, _ in self.conditions)

    def failed(self) -> list[str]:
        return [f"{n}: {d}" for n, ok, d in self.conditions if not ok]


def _tokens(text: str) -> frozenset:
    return frozenset(re.findall(r"\w+", re.sub(r"-?site:\S+", " ", text.lower())))


def near_duplicate(db, text: str, threshold: float, exclude_id: int | None = None):
    """The default dork this one duplicates (same TLD and token-set similarity >= threshold), else None."""
    from .search.dorkparse import parse
    toks, tld = _tokens(text), parse(text).tld
    for r in db.c.execute("SELECT id, text FROM dorks WHERE grp='default'"):
        if r["id"] == exclude_id:
            continue
        et = _tokens(r["text"])
        if parse(r["text"]).tld == tld and toks and et and len(toks & et) / len(toks | et) >= threshold:
            return r
    return None


def check(db, cfg: dict, r) -> Eligibility:
    """Every promotion condition, individually (each one is reported, so /dorks candidates shows what is missing)."""
    from . import aidorks
    pc = _pc(cfg)
    q = quality(db, r)
    e = Eligibility(r["id"], r["text"], evidence=dict(q))
    e.conditions.append(("group", r["grp"] == "ai", f"group is '{r['grp']}'" + ("" if r["grp"] == "ai" else " (only AI dorks are promoted)")))
    e.conditions.append(("runs", q["runs"] >= pc["min_runs"], f"{q['runs']} run(s), need {pc['min_runs']}"))
    e.conditions.append(("verified", q["verified"] >= pc["min_verified"],
                         f"{q['verified']} verified-valid new program(s), need {pc['min_verified']}"))
    e.conditions.append(("precision", q["kept"] > 0 and q["precision"] >= pc["min_precision"],
                         f"precision {q['precision']:.2f} ({q['verified']}/{q['kept']} kept results), need {pc['min_precision']:.2f}"))
    ok, why = aidorks.validate(r["text"])  # structure, operators, allowlist AND blocklist - re-run at promotion time
    e.conditions.append(("validator", ok, "passes the dork validator and blocklist" if ok else why))
    dup = near_duplicate(db, r["text"], pc["similarity"], exclude_id=r["id"])
    e.conditions.append(("not_duplicate", dup is None, f"near-duplicate of default dork #{dup['id']}: {dup['text'][:60]}" if dup
                         else "not a near-duplicate of a default dork"))
    return e


def candidates(db, cfg: dict, *, only_eligible: bool = False) -> list[Eligibility]:
    rows = db.c.execute("SELECT * FROM dorks WHERE grp='ai' AND run_count>0 ORDER BY id").fetchall()
    out = [check(db, cfg, r) for r in rows]
    out.sort(key=lambda e: (not e.eligible, -e.evidence["verified"], -e.evidence["precision"]))
    return [e for e in out if e.eligible] if only_eligible else out


def promote(db, cfg: dict, dork_id: int, *, by: str = "you") -> tuple[bool, str]:
    """Re-checks every condition first. Never deletes anything: the row changes group/origin and keeps its history."""
    r = db.c.execute("SELECT * FROM dorks WHERE id=?", (dork_id,)).fetchone()
    if r is None:
        return False, f"no dork with id {dork_id}"
    e = check(db, cfg, r)
    if not e.eligible:
        return False, f"dork #{dork_id} is not eligible: " + "; ".join(e.failed())
    ev = dict(e.evidence, promoted_by=by, runs_at_promotion=e.evidence["runs"], kept_at_promotion=e.evidence["kept"],
              verified_at_promotion=e.evidence["verified"], parent=r["parent_dork_id"])
    db.c.execute("UPDATE dorks SET grp='default', origin='ai_promoted', promoted_at=?, promotion_evidence=?, enabled=1, "
                 "auto_disabled_reason=NULL, demoted_at=NULL WHERE id=?", (dates.now_iso(), json.dumps(ev), dork_id))
    db.commit()
    mirror(db)
    log.info("AI dork #%s promoted into the default list (%s): %s", dork_id, by, ev)
    return True, (f"promoted #{dork_id} into the default list ({e.evidence['verified']} verified programs, precision "
                  f"{e.evidence['precision']:.2f}, {e.evidence['runs']} runs)")


def demote(db, dork_id: int, reason: str, *, disable: bool) -> tuple[bool, str]:
    r = db.c.execute("SELECT * FROM dorks WHERE id=?", (dork_id,)).fetchone()
    if r is None:
        return False, f"no dork with id {dork_id}"
    if r["origin"] != "ai_promoted" or r["grp"] != "default":
        return False, f"dork #{dork_id} is not a promoted AI dork (group {r['grp']}, origin {r['origin']})"
    ev = json.loads(r["promotion_evidence"] or "{}")
    ev["demotion"] = {"at": dates.now_iso(), "reason": reason}
    db.c.execute("UPDATE dorks SET grp='ai', origin='ai', demoted_at=?, promotion_evidence=?, enabled=?, "
                 "auto_disabled_reason=? WHERE id=?",
                 (dates.now_iso(), json.dumps(ev), 0 if disable else r["enabled"], reason if disable else r["auto_disabled_reason"],
                  dork_id))
    db.commit()
    mirror(db)
    return True, f"demoted #{dork_id} to the AI group ({reason})" + (" and disabled it" if disable else "")


def since_promotion(db, r) -> dict:
    ev = json.loads(r["promotion_evidence"] or "{}")
    runs = int(r["run_count"] or 0) - int(ev.get("runs_at_promotion", 0))
    kept = int(r["kept_total"] or 0) - int(ev.get("kept_at_promotion", 0))
    ver = db.c.execute(VERIFIED_SQL, (r["id"],)).fetchone()[0] - int(ev.get("verified_at_promotion", 0))
    return {"runs": runs, "kept": kept, "verified": ver, "precision": round(ver / kept, 3) if kept else 0.0}


def auto_demote(db, cfg: dict) -> list[str]:
    """A promoted dork whose precision SINCE promotion stays under demote_below_precision after demote_after_runs runs goes back
    to the AI group, disabled, with the reason recorded."""
    pc = _pc(cfg)
    out = []
    for r in db.c.execute("SELECT * FROM dorks WHERE grp='default' AND origin='ai_promoted'").fetchall():
        s = since_promotion(db, r)
        if s["runs"] >= pc["demote_runs"] and s["precision"] < pc["demote_precision"]:
            ok, msg = demote(db, r["id"], f"demoted: precision {s['precision']:.2f} after {s['runs']} runs since promotion",
                             disable=True)
            if ok:
                out.append(msg)
    return out


def after_batch(cfg: dict, db) -> list[str]:
    """End of a dork batch: auto-demotion, then ai_auto_promote = on (promote + log) | ask (list) | off."""
    msgs = auto_demote(db, cfg)
    mode = _pc(cfg)["mode"]
    if mode == "off":
        return msgs
    elig = candidates(db, cfg, only_eligible=True)
    if not elig:
        return msgs
    if mode == "on":
        for e in elig:
            ok, m = promote(db, cfg, e.dork_id, by="auto (ai_auto_promote=on)")
            msgs.append(m)
    else:
        msgs.append(f"{len(elig)} AI dork(s) eligible for promotion into the default list: /dorks candidates, "
                    f"/dorks promote <id|all-eligible>")
    return msgs


def unasked(db, cfg: dict) -> list[Eligibility]:
    """Eligible candidates the user has not declined at their current evidence level (ask mode, interactive scans)."""
    out = []
    for e in candidates(db, cfg, only_eligible=True):
        if db.meta(f"promote_declined:{e.dork_id}") != str(e.evidence["verified"]):
            out.append(e)
    return out


def decline(db, e: Eligibility) -> None:
    db.set_meta(f"promote_declined:{e.dork_id}", str(e.evidence["verified"]))  # asked again only when the evidence grows
    db.commit()


# ───────────────────────────── learned_default.txt ─────────────────────────────
def _group(text: str) -> str:
    from .search.dorkparse import parse
    tld = parse(text).tld
    return f".{tld}" if tld else "global"


def promoted_rows(db):
    return db.c.execute("SELECT * FROM dorks WHERE grp='default' AND origin='ai_promoted' ORDER BY id").fetchall()


def render(rows, header: str) -> list[str]:
    """Grouped (by country TLD / global) lines with a comment showing date and evidence above each dork."""
    out: list[str] = []
    by: dict[str, list] = {}
    for r in rows:
        by.setdefault(_group(r["text"]), []).append(r)
    for g in sorted(by, key=lambda x: (x != "global", x)):
        out.append(f"# ---- {header} {g} ----")
        for r in sorted(by[g], key=lambda x: x["text"].lower()):
            ev = json.loads(r["promotion_evidence"] or "{}")
            out.append(f"# promoted {(r['promoted_at'] or '')[:10]} · {ev.get('verified', '?')} verified program(s), precision "
                       f"{float(ev.get('precision', 0)):.2f}, {ev.get('runs', '?')} runs" +
                       (f" · parent #{r['parent_dork_id']}" if r["parent_dork_id"] else "") + f" · id {r['id']}")
            out.append(r["text"])
    return out


def mirror(db) -> Path | None:
    """Rewrite ~/.qurihunter/learned_default.txt from the DB (the file is a mirror; edits are overwritten)."""
    p = learned_path()
    lines = ["# qurihunter: AI dorks promoted into YOUR default list (generated - do not edit; /dorks demote <id> instead).",
             "# Re-imported automatically if the database is reset. Share them with /dorks export-default --include-promoted.",
             ""] + render(promoted_rows(db), SECTION)
    try:
        tmp = p.with_suffix(".tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.replace(tmp, p)
        return p
    except OSError as e:
        log.warning("could not write %s: %s", p, e)
        return None


def ensure_learned(db) -> int:
    """Promoted dorks from learned_default.txt that the DB does not know (fresh / reset DB) come back as promoted defaults."""
    p = learned_path()
    if not p.exists():
        return 0
    n = 0
    for e in dorkstore.parse_file(p):
        norm = " ".join(e.text.lower().split())
        if db.c.execute("SELECT 1 FROM dorks WHERE norm=? OR norm=?", (norm, dorkstore.normalise(e.text))).fetchone():
            continue
        db.c.execute("INSERT INTO dorks(text,norm,grp,origin,created_at,promoted_at,promotion_evidence,section) "
                     "VALUES(?,?,?,?,?,?,?,?)", (" ".join(e.text.split()), norm, "default", "ai_promoted", dates.now_iso(),
                                                 dates.now_iso(), json.dumps({"restored_from": LEARNED}), e.section))
        n += 1
    if n:
        db.commit()
    return n


# ───────────────────────────── export into dorks/default.txt ─────────────────────────────
def strip_sections(lines: list[str]) -> list[str]:
    """Remove earlier exported '# ---- AI-promoted ... ----' sections (until the next section header or the end)."""
    out, skip = [], False
    for ln in lines:
        m = dorkstore.HEADER.match(ln.strip())
        if m:
            skip = m.group(1).startswith(SECTION)
            if skip:
                continue
        if not skip:
            out.append(ln)
    while out and not out[-1].strip():
        out.pop()
    return out


def export_text(db, target: Path, include_promoted: bool) -> tuple[str, str]:
    """(old, new) contents for `target`. Base = the target's current text (or the shipped list when it does not exist yet);
    with include_promoted, one fresh '# ---- AI-promoted <date> <group> ----' block per group is appended, deduplicated
    against everything already in the file."""
    old = target.read_text(encoding="utf-8") if target.exists() else ""
    base = old if target.exists() else dorkstore.default_path().read_text(encoding="utf-8")
    lines = base.splitlines()
    if include_promoted:
        lines = strip_sections(lines)
        have = {dorkstore.normalise(ln) for ln in lines if ln.strip() and not ln.strip().startswith("#")}
        rows = [r for r in promoted_rows(db) if dorkstore.normalise(r["text"]) not in have]
        if rows:
            lines += [""] + render(rows, f"{SECTION} {dates.now_iso()[:10]}")
    return old, "\n".join(lines) + "\n"


def diff(old: str, new: str, name: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{name}", f"b/{name}"))


def refuse_reason(target: Path) -> str | None:
    """Why export-default must not write `target`: not writable, or the git working tree has uncommitted changes in it."""
    parent = target.parent if target.parent.exists() else None
    if parent is None:
        return f"{target.parent} does not exist"
    if (target.exists() and not os.access(target, os.W_OK)) or not os.access(parent, os.W_OK):
        return f"{target} is not writable"
    from . import dblock
    dblock.flush()  # never hold a write transaction across a subprocess
    try:
        r = subprocess.run(["git", "-C", str(parent), "status", "--porcelain", "--", target.name], capture_output=True,
                           text=True, timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None  # no git: nothing to protect
    if r.returncode == 0 and r.stdout.strip():
        return (f"{target.name} has uncommitted changes in the git working tree ({r.stdout.strip()[:60]}); commit or stash "
                "them first so the export is a clean, reviewable change")
    return None
