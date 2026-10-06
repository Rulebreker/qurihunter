"""/validate (status | on | off | test <url>) and /programs mark | revalidate."""
from __future__ import annotations

from rich.table import Table

from . import ui, validation


def _llm(ctx):
    from .llm import from_config
    return from_config(ctx.cfg, ctx.db)


def cmd_validate(ctx, args):
    sub = args[0] if args else "status"
    if sub == "status":
        for ln in validation.status(ctx.db, ctx.cfg):
            ui.info(ln)
    elif sub in ("on", "off"):
        ctx.cfg["validate"]["enabled"] = sub == "on"
        ctx.save(ctx.cfg)
        ui.ok(f"LLM program validation {sub.upper()}" + ("" if sub == "on" else
              " - dork / self-hosted finds alert without a page check again (validity line: 'not validated')"))
    elif sub == "test" and len(args) >= 2:
        test(ctx, args[1], cached="--cached" in args)
    else:
        ui.fail("usage: /validate status | on | off | test <url> [--cached]")


def print_result(res: validation.Result) -> None:
    ui.console.print(f"URL: {res.url}", markup=False)
    ui.console.print(f"fetched: HTTP {res.http_status or '-'} · final URL {res.final_url or '-'} · {res.page_chars} chars of "
                     f"visible text · content hash {res.content_hash or '-'}", markup=False)
    t = Table(title="Code checks (authoritative)", header_style="bold")
    for c in ("Check", "Result", "Effect if failed", "Detail"):
        t.add_column(c, overflow="fold")
    for c in res.checks:
        t.add_row(c.name, "[green]pass[/green]" if c.ok else "[red]FAIL[/red]", c.effect, c.detail)
    ui.console.print(t)
    a = res.assessment
    if a:
        at = Table(title="Model assessment" + (" (cached)" if res.cached else ""), header_style="bold")
        at.add_column("Field")
        at.add_column("Value", overflow="fold")
        for k in ("official_program", "program_kind", "status", "has_scope", "scope_summary", "has_reward", "reward_text",
                  "safe_harbor_mentioned", "submission_channel", "language", "organisation", "confidence"):
            at.add_row(k, str(a.get(k)))
        for i, e in enumerate(a.get("evidence") or [], 1):
            at.add_row(f"evidence {i}", e)
        for i, e in enumerate(a.get("reasons") or [], 1):
            at.add_row(f"reason {i}", e)
        ui.console.print(at)
    ui.console.print(f"model: {res.model or '-'} · parsed via: {res.parsed_via or '-'}", markup=False)
    ui.console.print(f"DECISION: {res.decision.upper()} - {res.reason}", markup=False)
    ui.console.print(validation.line(None, res), markup=False)


def test(ctx, url: str, *, cached: bool = False) -> None:
    """Runs the full pipeline on ONE URL and stores nothing (the model call itself is still counted in /llm status)."""
    state, view, why = validation.availability(ctx.cfg, _llm(ctx))
    if state != "ok":
        ui.info(f"no model for the validate role ({why}): only the code checks run")
    with ui.console.status("fetching the page and asking the validate model…"):
        res = validation.assess(ctx.cfg, ctx.db, view, url, force=not cached)
    print_result(res)
    ui.info("Nothing was stored (no program, no cache entry, no label).")


# ── /programs mark | revalidate ─────────────────────────────────────────────────
def mark(ctx, args):
    from .alertcmds import find_program
    if len(args) < 2 or args[1] not in validation.LABELS:
        ui.fail("usage: /programs mark <id|url> valid|invalid|weak [note]")
        return
    r = find_program(ctx.db, args[0])
    if not r:
        ui.fail("no such program")
        return
    validation.mark(ctx.db, r, args[1], " ".join(args[2:]))
    ui.ok(f"#{r['id']} {r['name']} marked {args[1]} (overrides the model; counted for dork #{r['found_by_dork'] or '-'})"
          + (" - hidden and remembered as not a program" if args[1] == "invalid" else ""))


def revalidate(ctx, args):
    """/programs revalidate <id|url> | --all-weak | --all-manual : re-run the page check, ignoring the cache."""
    from .alertcmds import find_program
    if not args:
        ui.fail("usage: /programs revalidate <id|url> | --all-weak | --all-manual")
        return
    if args[0] in ("--all-weak", "--all-manual"):
        vals = ("weak",) if args[0] == "--all-weak" else validation.MANUAL
        rows = ctx.db.c.execute(f"SELECT * FROM programs WHERE label IS NULL AND validity IN ({','.join('?' * len(vals))}) "
                                "ORDER BY id DESC", vals).fetchall()
    else:
        r = find_program(ctx.db, args[0])
        if not r:
            ui.fail("no such program")
            return
        if r["label"]:
            ui.info(f"#{r['id']} carries your label '{r['label']}', which overrides the model; revalidating for information only")
        rows = [r]
    if not rows:
        ui.info("nothing to revalidate")
        return
    state, view, why = validation.availability(ctx.cfg, _llm(ctx))
    if state != "ok":
        ui.fail(f"cannot revalidate: {why}")
        return
    cap = int(ctx.cfg["validate"].get("per_scan_cap", 40))
    if len(rows) > cap:
        ui.info(f"{len(rows)} programs; revalidating the newest {cap} (validate.per_scan_cap) - run again for the rest")
        rows = rows[:cap]
    from . import llmreg
    if ctx.cfg.get("models") and len(rows) > 1 and not llmreg.confirm_bulk(ctx.cfg, "validate", len(rows), "Revalidation", ui.yn):
        ui.info("cancelled")
        return
    t = Table(title="Revalidation", header_style="bold")
    for c in ("ID", "Name", "Before", "After", "Reason"):
        t.add_column(c, overflow="fold")
    for r in rows:
        with ui.console.status(f"validating #{r['id']}…"):
            res = validation.validate_row(ctx.cfg, ctx.db, view, r, force=True)
        if r["label"]:
            t.add_row(str(r["id"]), r["name"] or "", r["validity"] or "-", f"({res.decision}; your label wins)", res.reason)
            continue
        validation.apply(ctx.db, r["id"], res)
        t.add_row(str(r["id"]), r["name"] or "", r["validity"] or "-", res.decision, res.reason)
    ui.console.print(t)


def why_lines(db, r) -> list[str]:
    """The validation part of /why: full assessment, evidence, every code check and the model that judged."""
    from .notify import validity_text
    L = [f"  {validity_text(r)}"]
    if r["label"]:
        L.append(f"  your label: {r['label']}" + (f" ({r['label_note']})" if r["label_note"] else "")
                 + f" at {r['labeled_at']} - overrides the model")
    a, checks, v = validation.assessment_of(db, r)
    if not v:
        if r["validity"] is None:
            L.append("  validation: not assessed (platform feed, validation off, or not yet due to alert)")
        elif r["validity_reason"]:
            L.append(f"  validation: {r['validity']} - {r['validity_reason']}")
        return L
    L.append(f"  validation: {r['validity']} - {r['validity_reason'] or v.get('reason') or ''}")
    L.append(f"  judged by: {v.get('model_id') or '-'} · parsed via {v.get('parsed_via') or '-'} · {v.get('created_at')} · "
             f"HTTP {v.get('http_status')} · final URL {v.get('final_url')}")
    if a:
        L.append(f"  assessment: official_program={a.get('official_program')} kind={a.get('program_kind')} "
                 f"status={a.get('status')} scope={a.get('has_scope')} reward={a.get('has_reward')} "
                 f"({a.get('reward_text') or 'no text'}) safe_harbor={a.get('safe_harbor_mentioned')} "
                 f"channel={a.get('submission_channel')} lang={a.get('language')} model confidence={a.get('confidence')} "
                 f"→ after checks {v.get('confidence')}")
        if a.get("scope_summary"):
            L.append(f"  scope: {a['scope_summary']}")
        for e in a.get("evidence") or []:
            L.append(f"  evidence: \"{e}\"")
        for e in a.get("reasons") or []:
            L.append(f"  model reason: {e}")
    for c in checks:
        L.append(f"  check {'PASS' if c['ok'] else 'FAIL'} {c['name']}: {c['detail']}"
                 + ("" if c["ok"] else f" ({c['effect']})"))
    return L
