from __future__ import annotations

import json
import os
import time

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import alerts, notify, wayback
from . import dorkstore
from .classify import from_result
from . import dates
from .config import enabled_platforms, pages_per_dork, recency_days, search_recency_days
from .db import DB
from .llm import LLMError, Ollama
from .logs import log
from .models import Program
from .search import SearchResult
from .paths import lock_path
from .search import QuotaExhausted, Unexpressible, build_pool
from .sources import dorks as dorklib
from .sources import platforms
from .ui import console


RUN: dict = {"old": 0, "old_ids": [], "wayback_calls": 0, "dropped": 0}


def reset_run() -> None:
    wayback.reset()
    RUN.update({"old": 0, "old_ids": [], "wayback_calls": 0, "deferred": 0, "dropped": 0})


class ScanLocked(Exception):
    pass


class lock:
    """Single-instance guard so `watch` and a manual /scan never overlap."""

    def __enter__(self):
        p = lock_path()
        if p.exists():
            try:
                pid = int(p.read_text())
                os.kill(pid, 0)
                raise ScanLocked(f"another scan is running (pid {pid})")
            except (ValueError, ProcessLookupError, PermissionError):
                pass  # stale
        p.write_text(str(os.getpid()))
        return self

    def __exit__(self, *a):
        try:
            lock_path().unlink()
        except OSError:
            pass


def passes_filters(p: Program, f: dict) -> bool:
    if f["categories"] and p.kind not in f["categories"]:
        return False
    if f["countries"] and p.country and p.country not in [dorklib.normalize_cc(c) for c in f["countries"]]:
        return False
    if f["min_reward"] and p.reward_max is not None and p.reward_max < f["min_reward"]:
        return False
    return True


def llm_from_cfg(cfg: dict, db=None):
    from .llm import from_config
    return from_config(cfg, db)


def ingest(db: DB, cfg: dict, source: str, progs: list[Program]) -> tuple[list[Program], bool]:
    """Diff `progs` against the DB. Returns (newly-added non-baseline programs, was_first_run_of_source).

    First run of a source: everything is stored, but only programs whose launch date is inside the recency window can
    alert; the rest are silent baseline. Later runs: anything unseen is new (effective date = first seen = now).
    A program already known under another source is enriched, never re-alerted."""
    seeded = db.is_seeded(source)
    days = recency_days(cfg)
    new: list[Program] = []
    for p in progs:
        row = db.match(p)
        if row:
            db.enrich(row, p)
            continue
        baseline = (not seeded) and not (p.launched_at and dates.in_window(p.launched_at, days))
        rid = db.insert(p, baseline=baseline, filtered=not passes_filters(p, cfg["filters"]))
        if rid and not baseline:
            new.append(p)
    if progs and not seeded:
        db.mark_seeded(source)
    db.commit()
    return new, (not seeded)


def poll_platforms(cfg: dict, db: DB, prog: Progress) -> list[str]:
    msgs = []
    srcs = [s for s in enabled_platforms(cfg) if s in platforms.SOURCES]
    feeds = cfg.get("custom_feeds", [])
    task = prog.add_task("Polling platforms", total=len(srcs) + len(feeds))
    jobs = [(s, platforms.SOURCES[s][0], lambda s=s: platforms.fetch(s)) for s in srcs]
    if not cfg["filters"]["platforms"] or "web" in cfg["filters"]["platforms"]:
        jobs += [(f["name"], f["name"], lambda f=f: platforms.fetch_custom(f)) for f in feeds]
    for sid, label, fn in jobs:
        prog.update(task, description=f"Polling {label}")
        rid = db.run_start(sid)
        try:
            items = fn()
            new, base = ingest(db, cfg, sid, items)
            db.run_end(rid, "ok", len(items), len(new))
            msgs.append(f"{label}: {len(items)} programs" + (" (baseline stored, no alerts)" if base
                                                              else f", {len(new)} new"))
        except Exception as e:  # noqa: BLE001 — one broken source must not stop the rest
            log.exception("source %s failed", sid)
            db.run_end(rid, "error", 0, 0, str(e))
            msgs.append(f"[red]{label}: failed — {e}[/red]")
        db.commit()
        prog.advance(task)
    return msgs


def run_dorks(cfg: dict, db: DB, llm, prog: Progress, *, budget: int | None = None) -> list[str]:
    """One dork batch as an ordered, resumable queue of (dork, provider) steps (see sequence.py). Picks as many dorks as
    the quota budget allows (never the whole list), never re-spends a finished step or an identical query inside its
    cooldown, and classifies/dedupes every hit against what is already known. If every provider is exhausted or down the
    batch stops where it is and resumes there on the next scan - it never blocks the rest of the scan."""
    from . import sequence
    sc = cfg["search"]
    pool = build_pool(cfg, db)
    if not pool:
        return ["Dork discovery skipped: no search provider with an API key configured (/config → option 2)"]
    if pool.total_remaining() == 0:
        return ["Dork discovery skipped: every key is out of quota until its window resets (/status)"]
    dorkstore.ensure_default(db)
    dorkstore.ensure_country_dorks(db, cfg["filters"]["countries"])
    from .search.pool import ensure_lifetime_start
    for r in pool.rings:
        if r.qtype == "lifetime":
            ensure_lifetime_start(db, r.provider.id)  # the only place planning-related state is written (once)
    allowed = pool.plan(cfg["schedule"]["dork_interval_min"])
    if budget is not None:  # explicit cap (CLI/tests): don't spread over the window
        for r in pool.rings:
            r.allowance = r.total_remaining() if r.qtype != "unlimited" else 10**6
    else:
        budget = allowed
    # SEARCH recency (what the provider's date parameter gets) is NOT the alert window (applied after discovery, in alerts.py):
    # a dork's first run looks at everything; later runs only at the past month; an optional share runs "past week".
    s_first, s_later, s_sweep = (search_recency_days(cfg, w) for w in ("first", "later", "sweep"))
    days = recency_days(cfg)  # the alert window: used only for baseline decisions below, never sent to a provider
    msgs: list[str] = list(pool.warnings())
    mode = sequence.mode_of(cfg)
    if cfg.get("search_mode") == "sweep" and mode != "sweep":
        msgs.append("[yellow]search_mode 'sweep' is not confirmed (/sequence mode sweep) - running failover[/yellow]")
    provs = [r.provider for r in pool.rings]
    prov0 = pool.current() or (provs[0] if provs else None)
    if prov0 and cfg["features"]["ai_dorks"] and llm:
        from . import aidorks
        msgs += aidorks.maybe_generate(cfg, db, llm, prov0)
    default_cd = float(cfg["dorks"]["cooldown_days"])

    def cd(r):
        return float(r["cooldown_days"] if r["cooldown_days"] is not None else default_cd)

    def chain_of(text):
        return [p for p in provs if p.express(text)[0] != "parked"]

    def row_days(r):
        return s_first if r["run_count"] == 0 else s_later

    def cooling(r):
        ch = chain_of(r["text"])
        return bool(ch) and db.query_in_cooldown(ch[0].query_hash(r["text"], row_days(r)), cd(r)) is not None
    bid = sequence.pending_batch(db)
    resumed = bid is not None
    sel = dorkstore.Selection()
    if not resumed:
        n_dorks = max(1, budget // len(provs)) if mode == "sweep" else budget
        sel = dorkstore.select(db, cfg, provs, n_dorks, skip=cooling)
        bid = sequence.plan_batch(db, sel.chosen, lambda r: [p.id for p in chain_of(r["text"])], mode)
    todo = sequence.steps(db, bid)
    dork_rows = {r["id"]: r for r in db.c.execute("SELECT * FROM dorks")}
    task = prog.add_task("Search dorks", total=len(todo))
    total_alertable = used = ran = skipped = 0
    by_provider: dict[str, int] = {}
    llm_budget = {"left": int(cfg["llm"].get("max_classify_per_cycle", 60))}
    wb_budget = {"left": int(cfg.get("wayback", {}).get("max_per_scan", 40))}
    share = min(0.30, max(0.0, float((cfg.get("dork_search_recency") or {}).get("sweep_share", cfg["dorks"].get("unfiltered_share", 0.10)))))
    # optional recent-only sweep (past week) on dorks that already ran once: they were fully covered by the "any" first run
    sweepable = [st for st in todo if (dork_rows.get(st["dork_id"]) or {"run_count": 0})["run_count"] > 0]
    n_sweep = round(len(todo) * share) if s_sweep is not None else 0
    sweep_ids = {st["dork_id"] for st in sweepable[len(sweepable) - n_sweep:]} if n_sweep and sweepable else set()
    stopped = ""
    answered_total: dict[int, int] = {}  # dork_id -> new programs found so far (cascade across steps)
    for st in todo:
        row = dork_rows.get(st["dork_id"])
        if row is None or not row["enabled"]:
            sequence.mark(db, st["id"], "skipped", note="dork removed or disabled")
            prog.advance(task)
            continue
        sweeping = row["id"] in sweep_ids
        qdays = s_sweep if sweeping else row_days(row)  # provider-side recency: first=any, later=month, sweep=week
        chain = pool.chain(row["text"])
        order = [p for p in chain if mode == "sweep" and p.id == st["provider"]] if mode == "sweep" else chain
        first_run = row["run_count"] == 0
        windowed = qdays is not None
        prog.update(task, description=f"Step {st['pos']}/{len(todo)}: {row['text'][:45]}…")
        attempted_any = cooled = False
        seen_tot = found_tot = alert_tot = 0
        answered: list[str] = []
        done = False
        for prov in order:
            ok_av, why = pool.available(prov.id)
            nhash = prov.query_hash(row["text"], qdays)
            if db.query_in_cooldown(nhash, cd(row)):  # identical (provider, query, window) already paid for recently
                if mode == "cascade":
                    cooled = True
                    continue  # contributes nothing now; the next provider may
                skipped += 1
                done = True
                answered.append(prov.id + " (cooldown)")
                break
            if not ok_av:
                continue
            attempted_any = True
            seen = found = alertable = 0
            status = "ok"
            try:
                prefer = None
                for page in range(pages_per_dork(cfg)):
                    res, pid = pool.search(row["text"], page=page, days=qdays, prefer=prov.id)
                    prefer = pid
                    used += 1
                    by_provider[pid] = by_provider.get(pid, 0) + 1
                    seen += len(res.results)
                    from . import relevance
                    kept, dropped = relevance.filter_results(row["text"], res.results)  # before ANY llm call, fetch or storage
                    for it_d, why_d, spam_d in dropped:
                        RUN["dropped"] += 1
                        if spam_d:  # junk is junk for every dork: remember it. Mere irrelevance is NOT remembered.
                            db.remember_url(it_d.url, "not_program", 0.0, "rules", why_d)
                    if llm is not None and llm_budget["left"] > 0:
                        from .classify import prepare_batch
                        n_b = prepare_batch(kept, llm, db, max_items=llm_budget["left"])
                        llm_budget["left"] -= n_b  # a batched page costs one unit of the per-cycle page budget
                    for it in kept:
                        f, a = _handle_result(db, cfg, llm, it, windowed=windowed, first_run=first_run,
                                              budget=llm_budget, wb=wb_budget)
                        found += f
                        alertable += a
                    if not res.has_more:
                        break
                    time.sleep(0.3)
            except Unexpressible:
                continue
            except QuotaExhausted:
                if prefer is None:  # this provider failed/exhausted before answering: NOT a run, try the next one
                    continue
                status = "partial"
            except Exception as e:  # noqa: BLE001
                log.exception("dork failed: %s", row["text"])
                msgs.append(f"[red]dork failed: {e}[/red]")
                db.record_query(provider=prov.id, text=row["text"], nhash=nhash, dork_id=row["id"], origin=_origin(row),
                                window=prov.window_label(qdays), results=0, new=0, status="error")
                db.commit()
                continue
            db.record_query(provider=prov.id, text=row["text"], nhash=nhash, dork_id=row["id"], origin=_origin(row),
                            window=prov.window_label(qdays), results=seen, new=found, status="ok")
            db.commit()
            seen_tot += seen
            found_tot += found
            alert_tot += alertable
            answered.append(prov.id)
            time.sleep(0.4)  # stay well under per-second rate limits
            if mode == "failover" or mode == "sweep":
                done = True
                break
            if found_tot >= int(cfg.get("cascade_min_results", 3)):  # cascade: enough valid new results
                done = True
                break
        if answered and not (len(answered) == 1 and answered[0].endswith("(cooldown)")):
            dorkstore.record_run(db, row["id"], seen_tot, found_tot)
            ran += 1
            total_alertable += alert_tot
        if done or (answered and mode == "cascade"):
            sequence.mark(db, st["id"], "done", answered_by=",".join(answered), results=seen_tot, new_found=found_tot,
                          spent=used)
            prog.advance(task)
        elif not attempted_any and cooled:
            sequence.mark(db, st["id"], "done", answered_by="(cooldown)", note="all providers inside cooldown")
            skipped += 1
            prog.advance(task)
        elif not attempted_any and mode == "sweep":
            prog.advance(task)  # this provider is out; its step stays pending, other providers' steps may still run
        elif not attempted_any:  # nobody could serve this step now: stop here, resume at this step next time
            stopped = f"step {st['pos']}/{len(todo)} ({row['text'][:40]}): every provider is exhausted, down or disabled"
            sequence.stop(db, stopped)
            msgs.append("[yellow]Search budget used up — remaining dorks deferred to the next cycle[/yellow]")
            break
        else:  # tried but all failed
            n = sequence.attempt(db, st["id"])
            if n >= sequence.MAX_ATTEMPTS:
                sequence.mark(db, st["id"], "error", note="all providers failed")
            prog.advance(task)
    dis = dorkstore.auto_disable_unproductive_ai(db, int(cfg["dorks"]["ai_prune_runs"]))
    detail = ", ".join(f"{k}: {v}" for k, v in by_provider.items()) or "none"
    msgs.insert(0, f"Dorks: {used} queries ({detail}), {total_alertable} new; {pool.total_remaining()} queries "
                   f"left across {pool.n_keys} keys")
    left = len(sequence.steps(db, bid))
    per_cycle = max(1, ran)
    est = dorkstore.estimate_days(sel.candidates - sel.merged, per_cycle, cfg["schedule"]["dork_interval_min"]) \
        if not resumed else None
    extra = [f"{ran} run, {sel.waiting + left} waiting"]
    if resumed:
        extra.append(f"resumed batch #{bid}")
    if est is not None:
        extra.append(f"~{est:.0f} day(s) to cycle the full list at this budget")
    if mode != "failover":
        extra.append(f"mode {mode}")
    if sel.parked:
        extra.append(f"{sel.parked} parked (provider cannot express them; no quota used)")
    if sel.rewritten:
        extra.append(f"{sel.rewritten} country dork(s) rewritten to natural language")
    if sel.merged:
        extra.append(f"{sel.merged} merged as near-duplicates for {prov0.id if prov0 else '?'}")
    if skipped or sel.cooling:
        extra.append(f"{skipped + sel.cooling} skipped (cooldown)")
    if dis:
        extra.append(f"{dis} AI dork(s) auto-disabled")
    if RUN.get("dropped"):
        extra.append(f"{RUN['dropped']} hit(s) dropped by the relevance gate (logged with reasons)")
    if stopped:
        extra.append(f"STOPPED at {stopped}")
    msgs.insert(1, "Dork batch: " + ", ".join(extra))
    return msgs


def _origin(row) -> str:
    return {"default": "builtin", "custom": "custom", "ai": "ai"}.get(row["grp"], "builtin")


def _handle_result(db: DB, cfg: dict, llm, item, *, windowed: bool, first_run: bool, budget: dict | None = None,
                   origin_delivered: str | None = None, wb: dict | None = None, sweep: bool = False) -> tuple[int, int]:
    """Classify/dedupe one search hit. Returns (programs_inserted, alertable). Old URLs are ignored silently.
    New candidates without an explicit in-window launch date are checked against the Wayback Machine: first captured
    before the window = an old page found late (stored as silent baseline)."""
    from .urls import host_of, registrable_domain
    url = item.url
    seen = db.seen(url) if url else None
    if url and seen:
        db.touch_url(url)
        if seen["verdict"] == "official_program":
            _refresh_dates(db, cfg, item)
        return 0, 0
    if not url:
        return 0, 0
    domain = registrable_domain(host_of(url))
    if not domain:
        return 0, 0
    if db.known(f"web:{domain}"):
        db.remember_url(url, "official_program", 1.0, "rules", "domain already known")
        _refresh_dates(db, cfg, item)
        return 0, 0
    use_llm = bool(llm) and (budget is None or budget["left"] > 0 or getattr(item, "verdict", None) is not None) \
        and not getattr(item, "rules_only", False)
    p, reason = from_result(item, llm, allow_llm=use_llm)
    if use_llm and budget is not None and getattr(item, "verdict", None) is None \
            and (p is None and reason.startswith("LLM") or p is not None and p.classified_by == "llm"):
        budget["left"] -= 1  # (batched pages were already charged by prepare_batch)
    if p is None:
        if reason != "ambiguous-skipped":
            db.remember_url(url, "not_program", 0.0, "llm" if reason.startswith("LLM") else "rules", reason)
        return 0, 0
    row = db.match(p)
    if row:  # same company already known through another source: enrich, don't re-alert
        db.enrich(row, p)
        db.remember_url(url, "official_program", p.confidence, p.classified_by, "duplicate of existing program")
        return 0, 0
    days = recency_days(cfg)
    in_win = bool(p.launched_at) and dates.in_window(p.launched_at, days)
    upd_win = bool(p.updated_at) and dates.in_window(p.updated_at, days)
    # no provider recency filter bounded this hit -> it can be any age: silent baseline unless its own dates say it is new
    baseline = (first_run or not windowed) and not windowed and not in_win and not upd_win
    wbres = None
    if not in_win and not (p.launched_at and not in_win):
        # no explicit launch date inside (or outside) the window: ask the archive
        wbres = wayback.first_capture(db, p.url, cfg, budget=wb)
        if wbres[0] != "skipped":
            RUN["wayback_calls"] += 1
        if wbres[0] == "old":
            if not (upd_win and cfg["alerts"]["alert_updated_only_pages"]):
                baseline = True  # old page discovered late: silent
        elif sweep and wbres[0] in ("error", "skipped"):
            baseline = True  # unfiltered sweep results are only trusted when the archive vouches for them
        elif sweep and wbres[0] == "none" and not upd_win:
            baseline = False
    elif sweep and not in_win:
        baseline = True
    rid = db.insert(p, baseline=baseline, filtered=not passes_filters(p, cfg["filters"]), delivered_via=origin_delivered,
                    wayback=wbres if wbres and wbres[0] != "skipped" else None)
    db.remember_url(url, "official_program", p.confidence, p.classified_by, p.summary or "")
    if not rid:
        return 0, 0
    row = db.program(rid)
    cls, _ = alerts.classify(row, days)
    if cls == "old" or (baseline and wbres and wbres[0] == "old"):
        RUN["old"] += 1
        RUN["old_ids"].append(rid)
    return 1, (1 if cls in alerts.KINDS else 0)


def _refresh_dates(db: DB, cfg: dict, item) -> None:
    """A page we already know shows a newer last-updated/effective date inside the window: record it so the program
    can alert once as RECENTLY UPDATED (never as new)."""
    if not cfg["alerts"]["alert_updated_only_pages"]:
        return
    from . import datekind
    from .urls import normalize_url
    d = datekind.summarise(datekind.analyse(item.title, item.snippet, item.published))
    up = d["updated_at"]
    if not up or not dates.in_window(up, recency_days(cfg)):
        return
    row = db.c.execute("SELECT * FROM programs WHERE source='web' AND (url=? OR dedupe_key=?)",
                       (normalize_url(item.url), f"web:{__import__('qurihunter.urls', fromlist=['x']).registrable_domain(__import__('qurihunter.urls', fromlist=['x']).host_of(item.url))}")).fetchone()
    if not row or row["verdict"] != "official_program" or (row["updated_at"] or "") >= up:
        return
    db.c.execute("UPDATE programs SET updated_at=?, date_kind=CASE WHEN launched_at IS NULL THEN ? ELSE date_kind END, "
                 "baseline=0 WHERE id=?", (up, d["date_kind"] if d["date_kind"] != "unknown" else "last_updated", row["id"]))


def enrich_and_notify(cfg: dict, db: DB, llm: Ollama | None) -> tuple[list, dict]:
    """Summarise and send everything still due (NEW and RECENTLY UPDATED, per channel). Failed sends stay pending."""
    items = backfill_wayback(db, cfg, alerts.due(db, cfg))
    if not items:
        return [], {}
    budget = int(cfg["llm"].get("max_summaries_per_cycle", 10))  # LLM calls are slow; the rest use a template
    for r, _ in items:
        if llm and not r["summary"] and budget > 0:
            budget -= 1
            try:
                s = llm.summarize(r["name"], r["url"], r["source"], r["kind"],
                                  f"{r['reward_max']} {r['currency']}" if r["reward_max"] else r["kind"],
                                  json.loads(r["scope"] or "[]"))
                db.set_summary(r["id"], s)
            except LLMError as e:
                log.warning("summary failed: %s", e)
    db.commit()
    items = backfill_wayback(db, cfg, alerts.due(db, cfg), check=False)
    channels = [c for c in cfg["notify"]["channels"] if c in alerts.REAL_CHANNELS]
    rows = [r for r, _ in items]
    RUN["due_new"] = sum(1 for _, k in items if k == "new")
    RUN["due_updated"] = sum(1 for _, k in items if k == "updated")
    if not channels:
        return rows, {"none": "no notification channel configured — alerts are waiting (/alerts pending)"}
    return rows, notify.deliver(cfg, db, items)


def backfill_wayback(db: DB, cfg: dict, items: list, check: bool = True) -> list:
    """Undated web rows that never got an archive verdict (legacy v1 rows, or earlier lookups that failed) are checked
    before alerting: first captured before the window = old (silent baseline). When the per-scan budget runs out the
    rest wait for the next scan instead of being alerted unchecked. An archive outage never blocks the scan; unverifiable legacy rows simply wait."""
    wbcfg = cfg.get("wayback", {})
    if not wbcfg.get("enabled", True):
        return items
    budget = {"left": int(wbcfg.get("max_per_scan", 40))}
    days = recency_days(cfg)
    out = []
    pre = None
    if check and int(wbcfg.get("concurrency", 1)) > 1:  # parallel lookups for the rows that will actually be checked
        todo = [r["url"] for r, _ in items if r["source"] == "web" and not r["launched_at"]
                and r["wayback_state"] in ("unchecked", "error")][: budget["left"]]
        pre = wayback.prefetch(todo, cfg) if todo else None
    from . import background
    for r, k in items:
        db.commit()
        if not background.checkpoint():
            break  # a foreground command is running: stop this batch, the next tick continues
        if r["source"] != "web" or r["launched_at"] or r["wayback_state"] not in ("unchecked", "error"):
            out.append((r, k))
            continue
        if not check:  # second pass: anything still unverified keeps waiting
            if wbcfg.get("on_error", "wait") == "alert":
                out.append((r, k))
                continue
            RUN["deferred"] = RUN.get("deferred", 0) + 1
            continue
        st, first = wayback.first_capture(db, r["url"], cfg, budget=budget, pre=pre)
        if st in ("skipped", "error"):
            # budget spent, or the archive is down: an undated legacy row we cannot verify is NOT alerted as "likely
            # new" (it is probably an old page). It stays pending and is retried next scan (/alerts pending, /why).
            if wbcfg.get("on_error", "wait") == "alert":
                out.append((r, alerts.classify(r, days)[0]))  # user opted to alert unverified rows
                continue
            RUN["deferred"] = RUN.get("deferred", 0) + 1
            continue
        upd = bool(r["updated_at"]) and dates.in_window(r["updated_at"], days)
        silent = st == "old" and not (upd and cfg["alerts"]["alert_updated_only_pages"])
        db.c.execute("UPDATE programs SET wayback_state=?, wayback_first=?, baseline=? WHERE id=?",
                     (st, first, 1 if silent else r["baseline"], r["id"]))
        db.commit()
        if silent:
            RUN["old"] += 1
            RUN["old_ids"].append(r["id"])
            continue
        out.append((db.program(r["id"]), alerts.classify(db.program(r["id"]), days)[0]))
    db.commit()
    return [(r, k) for r, k in out if k in alerts.KINDS and (k != "updated" or cfg["alerts"]["alert_updated_only_pages"])]


def retry_pending(cfg: dict, db: DB):
    """Background retry: re-run the archive checks and delivery for what is waiting. Same lock as /scan."""
    with lock():
        reset_run()
        return enrich_and_notify(cfg, db, None)  # no LLM here: retries must be quick


def maybe_summary(cfg: dict, db: DB, *, quota_left: int | None) -> str | None:
    """telegram_scan_summary: off | changes_only | daily. At most ONE summary per scan. Returns what was sent."""
    mode = cfg["alerts"].get("telegram_scan_summary", "changes_only")
    n_new, n_upd, n_old = RUN.get("due_new", 0), RUN.get("due_updated", 0), RUN["old"]
    if mode == "off" or "telegram" not in cfg["notify"]["channels"]:
        return None
    today = dates.utcnow().astimezone(dates.local_tz()).strftime("%Y-%m-%d")
    changes = n_new + n_upd > 0
    if not changes and not (mode == "daily" and db.meta("summary_day") != today):
        return None
    text = (f"Scan finished: {n_new} new, {n_upd} updated, {n_old} skipped as old, "
            f"quota left {quota_left if quota_left is not None else 'n/a'}")
    err = notify.send_summary(cfg, text)
    if err is None:
        db.set_meta("summary_day", today)
        db.set_meta("last_summary", f"{dates.now_iso()} {text}")
        db.commit()
    return text if err is None else None


def scan(cfg: dict, db: DB, *, do_platforms=True, do_dorks=True, dork_budget: int | None = None, use_llm: bool = True):
    """One full cycle. Returns (new_rows, log_lines, notify_results)."""
    llm = llm_from_cfg(cfg, db) if use_llm else None
    lines: list[str] = []
    reset_run()
    RUN["due_new"] = RUN["due_updated"] = 0
    with lock():
        with Progress(SpinnerColumn(), TextColumn("[bold]{task.description}"), BarColumn(),
                      TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(), console=console,
                      transient=True) as prog:
            if do_platforms:
                lines += poll_platforms(cfg, db, prog)
            if do_dorks:
                lines += run_dorks(cfg, db, llm, prog, budget=dork_budget)
            t = prog.add_task("Summarising & notifying", total=None)
            rows, res = enrich_and_notify(cfg, db, llm)
            prog.remove_task(t)
        try:
            pool = build_pool(cfg, db) if do_dorks else None
            sent = maybe_summary(cfg, db, quota_left=pool.total_remaining() if pool else None)
            if sent:
                lines.append(f"Telegram summary sent: {sent}")
        except Exception as e:  # noqa: BLE001 — a summary must never fail a scan
            log.warning("scan summary failed: %s", e)
        _flush_net(db)
    return rows, lines, res


def _flush_net(db: DB) -> None:
    from . import http
    for name, st in http.drain_stats().items():
        db.add_net(name, st)
    db.commit()


def reclassify_plan(db: DB, cfg: dict, llm, progress=None) -> list[dict]:
    """Re-judge every stored dork (web) entry WITHOUT touching or alerting anything. Each result:
    {id, name, url, decision: keep|reject, reason, by}. Hard URL/domain/title rules reject outright; the local LLM
    only judges the rest (without an LLM the ambiguous ones are kept and flagged, never silently dropped)."""
    from .classify import hard_reject
    import contextlib
    with (llm.bulk() if hasattr(llm, "bulk") else contextlib.nullcontext()):
        return _reclassify_plan(db, cfg, llm, progress)


def _reclassify_plan(db: DB, cfg: dict, llm, progress=None) -> list[dict]:
    from .classify import hard_reject
    rows = db.c.execute("SELECT * FROM programs WHERE source='web' AND verdict='official_program' ORDER BY id").fetchall()
    budget = {"left": int(cfg["llm"].get("max_classify_per_cycle", 60)) * 5}
    plan = []
    for i, r in enumerate(rows):
        if progress is not None:
            progress(i + 1, len(rows))
        d = {"id": r["id"], "name": r["name"] or "", "url": r["url"], "decision": "keep", "reason": "", "by": "rules",
             "kind": r["kind"]}
        why = hard_reject(r["url"], r["name"] or "")
        if why:
            d.update(decision="reject", reason=why)
        elif llm and budget["left"] > 0:
            budget["left"] -= 1
            p, reason = from_result(SearchResult(r["name"] or "", r["url"], r["snippet"] or ""), llm, allow_llm=True)
            if p is None and reason != "ambiguous-skipped":
                d.update(decision="reject", reason=reason, by="llm" if reason.startswith("LLM") else "rules")
            else:
                d.update(reason="confirmed" if p is not None else "unverified (LLM unavailable)", by="llm")
        else:
            d["reason"] = "kept (no LLM to double-check)"
        if d["decision"] == "keep" and r["kind"] == "security.txt":
            d["reason"] += " · bare security.txt (filter: --category securitytxt)"
        plan.append(d)
    return plan


def reclassify_apply(db: DB, plan: list[dict]) -> int:
    """Mark rejected entries not_program and remember the URL so it never returns. Nothing is deleted, nothing alerts."""
    n = 0
    for d in plan:
        if d["decision"] == "reject":
            db.set_verdict(d["id"], "not_program")
            db.remember_url(d["url"], "not_program", 0.0, d["by"], d["reason"])
            n += 1
    db.commit()
    return n


def reclassify(db: DB, cfg: dict, llm, progress=None) -> tuple[int, int]:
    """Plan + apply in one go (no confirmation). Returns (rejected, checked)."""
    plan = reclassify_plan(db, cfg, llm)
    return reclassify_apply(db, plan), len(plan)
