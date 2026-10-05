"""Shared program-listing logic for /programs, /export and the chat query tool.
Every listed row is a dict carrying `_kind` (new | updated | old | baseline), `_why`, `_evidence` and `_sent`."""
from __future__ import annotations

import shlex
from datetime import timedelta

from rich.table import Table

from . import alerts, dates

HELP = ("filters: --since <24h|7d|30d|YYYY-MM-DD>  --from <date> --to <date> (YYYY-MM-DD or DD/MM/YYYY)  "
        "--by <seen|launched>  --kind new|updated|old|all (default new+updated)  --include-baseline  --include-old  "
        "--category program|securitytxt|all  --source <id>  --country <cc>  --text <word>  --limit <N>  "
        "--wide | --compact")
KINDS = ("new", "updated", "old", "baseline")
VALUE_OPTS = ("--since", "--from", "--to", "--by", "--source", "--country", "--text", "--limit", "--kind", "--category")


def parse_args(args: list[str]) -> dict:
    o = {"since": None, "from": None, "to": None, "by": "seen", "include_baseline": False, "include_old": False,
         "source": None, "country": None, "text": None, "limit": None, "kind": None, "category": "all",
         "wide": False, "compact": False}
    it = iter(args)
    for a in it:
        if a in ("--include-baseline", "--include-old", "--wide", "--compact"):
            o[a[2:].replace("-", "_")] = True
        elif a in VALUE_OPTS:
            try:
                v = next(it)
            except StopIteration:
                raise ValueError(f"{a} needs a value") from None
            o[a[2:]] = v
        elif a.isdigit():
            o["limit"] = a
        else:
            raise ValueError(f"unknown option '{a}'. {HELP}")
    if o["by"] not in ("seen", "launched"):
        raise ValueError("--by must be 'seen' or 'launched'")
    if o["kind"] is not None and o["kind"] not in (*KINDS, "all"):
        raise ValueError("--kind must be new, updated, old, baseline or all")
    if o["category"] not in ("program", "securitytxt", "all"):
        raise ValueError("--category must be program, securitytxt or all")
    if o["limit"] is not None:
        try:
            o["limit"] = max(1, int(o["limit"]))
        except ValueError:
            raise ValueError("--limit must be a whole number") from None
    return o


def has_filters(o: dict) -> bool:
    return bool(o["since"] or o["from"] or o["to"] or o["source"] or o["country"] or o["text"] or o["include_baseline"]
                or o["include_old"] or o["by"] != "seen" or o["kind"] or o["category"] != "all")


def _kinds_wanted(o: dict) -> set[str]:
    if o["kind"] == "all":
        return set(KINDS)
    if o["kind"]:
        return {o["kind"]}
    k = {"new", "updated"}
    if o["include_old"]:
        k.add("old")
    if o["include_baseline"]:
        k.add("baseline")
    return k


def sent_map(db, ids=None) -> dict[int, dict[str, list[str]]]:
    out: dict[int, dict[str, list[str]]] = {}
    for pid, kind, ch in db.c.execute("SELECT program_id, kind, channel FROM deliveries"):
        out.setdefault(pid, {}).setdefault(ch, []).append(kind)
    return out


def sent_text(sent: dict) -> str:
    return ", ".join(f"{ch}✓" for ch in ("telegram", "email", "chat") if ch in sent) or "unsent"


def decorate(db, cfg, rows, days) -> list[dict]:
    sm = sent_map(db)
    out = []
    for r in rows:
        d = dict(r)
        d["_kind"], d["_why"] = alerts.classify(r, days)
        d["_evidence"] = alerts.evidence_line(r, days)
        d["_sent"] = sm.get(r["id"], {})
        out.append(d)
    return out


def run(db, o: dict, *, default_limit: int = 100, cfg: dict | None = None):
    """Returns (rows, excluded_unknown_launch, description); also sets run.info = hidden counts for the title."""
    from . import config
    cfg = cfg or config.copy.deepcopy(config.DEFAULTS)
    if o["since"] and (o["from"] or o["to"]):
        raise ValueError("use either --since or --from/--to, not both")
    since = until = None
    days = config.recency_days(cfg)
    if o["since"]:
        s = dates.parse_since(o["since"])
        since = dates.iso(s)
        days = max(0.01, (dates.utcnow() - s).total_seconds() / 86400)  # classify relative to the window asked for
    else:
        a, b = dates.parse_range(o["from"], o["to"])
        since, until = (dates.iso(a) if a else None), (dates.iso(b) if b else None)
        if a or b:
            days = None
    q = "SELECT * FROM programs WHERE verdict='official_program' AND filtered=0"
    args: list = []
    for col, key in (("source", "source"), ("country", "country")):
        if o[key]:
            q += f" AND {col}=?"
            args.append(o[key].lower() if col == "country" else o[key])
    if o["text"]:
        q += " AND (name LIKE ? OR url LIKE ? OR summary LIKE ?)"
        args += [f"%{o['text']}%"] * 3
    if o["category"] == "securitytxt":
        q += " AND kind='security.txt'"
    elif o["category"] == "program":
        q += " AND kind!='security.txt'"
    allrows = decorate(db, cfg, db.c.execute(q, args).fetchall(), days)
    want = _kinds_wanted(o)
    launched = o["by"] == "launched"

    def when(r):
        # 'updated' rows are placed by their update date; everything else by first-seen / launch date
        if r["_kind"] == "updated" and r["updated_at"]:
            return r["updated_at"]
        return r["launched_at"] if launched else r["first_seen"]
    hidden = {"baseline": 0, "old": 0}
    excluded = 0
    rows = []
    for r in allrows:
        in_range = (not since or (when(r) or "") >= since) and (not until or (when(r) or "") <= until)
        if launched and not r["launched_at"] and r["_kind"] != "updated":
            if r["_kind"] != "baseline" or o["include_baseline"] or o["kind"] in ("baseline", "all"):
                excluded += 1
            continue
        if not in_range:
            continue
        if r["_kind"] in want:
            rows.append(r)
        elif r["_kind"] in hidden:
            hidden[r["_kind"]] += 1
    rows.sort(key=lambda r: (when(r) or "", r["id"]), reverse=True)
    run.info = {"hidden": hidden, "total": len(rows)}
    rows = rows[: (o["limit"] or default_limit)]
    bits = [f"by {o['by']}"]
    if o["since"]:
        bits.insert(0, f"since {o['since']}")
    if o["from"] or o["to"]:
        bits.insert(0, f"{o['from'] or '…'} → {o['to'] or '…'}")
    run.title_bits = bits
    return rows, excluded, ", ".join(bits)


run.info = {"hidden": {"baseline": 0, "old": 0}, "total": 0}
run.title_bits = []


def title(o: dict, shown: int) -> str:
    h = run.info["hidden"]
    kinds = "/".join(sorted(_kinds_wanted(o))) if not o["kind"] else o["kind"]
    win = ""
    if o["since"]:
        win = f" since {o['since']}"
    elif o["from"] or o["to"]:
        win = f" {o['from'] or '…'} → {o['to'] or '…'}"
    return (f"Programs{win} ({kinds}, by {o['by']}) — {shown} shown, {h['baseline']} baseline hidden"
            + (f", {h['old']} old hidden" if h["old"] else ""))


def state(r) -> str:
    """Kind label + per-channel delivery, e.g. 'NEW · sent: telegram✓, chat✓' / 'UPDATED · unsent'."""
    k = (r["_kind"] if "_kind" in r.keys() else "new").upper()
    if k in ("NEW", "UPDATED"):
        return f"{k} · " + ("sent: " + sent_text(r["_sent"]) if r["_sent"] else "unsent")
    return k


def _reward(r):
    return f"{r['reward_max']:,.0f} {r['currency'] or ''}" if r["reward_max"] else "-"


def table(rows, title_text: str, width: int | None = None, *, wide: bool = False, compact: bool = False) -> Table | str:
    """≥130 columns: everything. Narrower: Kind and date evidence are ALWAYS kept; low-value columns drop (use
    --wide to force them, --compact for one line per program)."""
    from .ui import console
    w = width or console.width
    if compact:
        from rich.text import Text
        t = Text(title_text + "\n", style="bold")
        for r in rows:
            t.append(f"{r['_kind'].upper():8}", style="bold magenta")
            t.append(f"{_ev_short(r):24}")
            t.append(f"{(r['name'] or '')[:40]:40} ")
            t.append(f"[{sent_text(r['_sent'])}] ", style="dim")
            t.append(r["url"] + "\n", style="blue")
        return t
    full = wide or w >= 130
    t = Table(title=title_text, header_style="bold magenta", expand=True)
    t.add_column("Kind", no_wrap=True)
    t.add_column("Date evidence", overflow="fold")
    if full:
        t.add_column("First seen", no_wrap=True)
        t.add_column("Source")
    t.add_column("Name", overflow="fold")
    if full:
        t.add_column("Type")
        t.add_column("Reward")
        t.add_column("Cty")
    t.add_column("Sent")
    t.add_column("URL", overflow="fold", style="blue")
    for r in rows:
        cells = [r["_kind"].upper(), _ev_short(r) if not full else r["_evidence"]]
        if full:
            cells += [dates.to_local_day(r["first_seen"]), r["source"]]
        cells.append((r["name"] or "") + ("" if full else f"  [dim]{r['source']}[/dim]"))
        if full:
            cells += [r["kind"] or "", _reward(r), (r["country"] or "").upper() or "-"]
        cells += [sent_text(r["_sent"]), r["url"]]
        t.add_row(*cells)
    return t


def _ev_short(r) -> str:
    """'published 03 Oct' / 'last updated 15 Sep' / 'first seen 05 Oct' — the date evidence without archive detail."""
    return r["_evidence"].split(" | ")[0]


def split(line: str) -> list[str]:
    return shlex.split(line)
