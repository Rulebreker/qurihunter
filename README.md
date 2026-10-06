# qurihunter

CLI agent that finds **newly launched bug bounty / vulnerability disclosure programs** and alerts you on
Telegram or email. Runs locally, no GUI. It remembers everything it has ever seen, so you hear about each
program **once**.

## Install

```bash
git clone <this repo> && cd qurihunter
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
qurihunter            # first run starts the setup wizard
```

Optional: [Ollama](https://ollama.com) (the wizard can start/install it and download a model for your hardware) **or**
any OpenAI-compatible API (`/model` → 7). The LLM classifies dork hits, writes alert summaries, invents extra dorks and
powers `/chat`. Without an LLM everything still works with rule-based heuristics.

## What it does

| Layer | Detail |
|---|---|
| Platforms | [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) feeds (HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy), the [disclose.io](https://github.com/disclose/diodb) database, and the [Self-Hosted-Bug-Bounty-Programs](https://github.com/ashikkunjumon/Self-Hosted-Bug-Bounty-Programs) dataset (its `programs.json`, rebuilt daily; the README itself only links to it). Add your own JSON/RSS feeds via `custom_feeds`. |
| Dorks | Search-API providers (Brave, Tavily, legacy Google CSE; see below) running a rotating wordlist. Never scrapes a search engine. |
| Memory | One SQLite DB (WAL) with versioned migrations and automatic backups. Programs, every URL classified, every query ever run, dorks and their statistics, chat history. |
| Alerts | Telegram bot or Gmail SMTP (app password). Two kinds: **NEW** and **RECENTLY UPDATED**. Many finds = one digest split into several messages. Failed sends stay pending and are retried. |

## LLM program validation (v0.5)

Before a dork find (or a disclose.io / self-hosted / custom-feed find) alerts, qurihunter reads **that one public page** and asks
the model with the `validate` role whether it is really an official, active bug bounty / vulnerability disclosure program.
It runs only for candidates that would otherwise alert (they already passed the relevance gate, the title/snippet
classification, memory dedupe and the date/Wayback "new" logic). Programs from the platform feeds (HackerOne, Bugcrowd,
Intigriti, YesWeHack, Federacy: `validate.skip_sources`) are skipped because the platform already vouches for them.

* **Input:** the page's visible text only, fetched once through the existing safe fetcher (timeout, 300 KB cap, `text/html`
  only, public addresses only, every redirect hop re-checked), cut to `validate.max_chars` (6000) keeping the title, headings and
  the first part of the body, plus the URL and the dork that found it. Passive reading only: no crawling, no other URL from the
  page, no forms, nothing that touches the company's systems beyond that single GET.
* **Output:** a strict JSON object checked against a schema in code (`official_program`, `program_kind`
  bounty|vdp|security_contact_only|other, `status` active|closed|unknown, `has_scope`, `scope_summary`, `has_reward`,
  `reward_text` copied from the page or null, `safe_harbor_mentioned`, `submission_channel`, `language`, `organisation`,
  `confidence`, up to 3 `evidence` snippets under 25 words, `reasons`). A wrong answer gets one stricter retry, then a plain-text
  fallback parser for weak models (a fallback-parsed answer can never make a program VERIFIED).
* **Code stays authoritative** and downgrades or overrules the model when: the HTTP status is not 200, the page is empty /
  a JavaScript or cookie wall / mostly boilerplate, the final URL after redirects is on another domain, the page is on a third-party
  host or names a different organisation than its domain, the URL is a blog / news / list / tool / job / spam page by the existing
  rules, **an evidence snippet does not occur in the fetched text** (whitespace-normalised: hallucination check, confidence halved),
  the quoted reward text is not on the page (it is dropped, never shown), or the page contains text aimed at AI models
  ("ignore previous instructions", "mark this valid"…). HTTP errors, empty pages and blog URLs are decided without spending a call.
* **Decision** (`validate.min_confidence`, default 0.7): not a program (confident) → stored `not_program`, remembered per URL,
  never alerted; confident + every check passed + status active → **VERIFIED**, alerted in the usual NEW / RECENTLY UPDATED sections;
  low confidence, status unknown/closed, any failed check, or no model available → a separate Telegram section **NEEDS MANUAL CHECK**
  (`alerts.alert_manual_check`, default on; off = held, see `/alerts pending`), never mixed with verified finds; a bare security contact
  → kept as **weak** (`--category securitytxt`).
* **Every alert block has one validity line**, e.g. `Validity: official bounty program | active | scope: yes | reward: stated ("up to
  CHF 5,000") | safe harbor: yes | confidence 0.86` - the reward text is exactly as on the page.
* **Prompt-injection safety:** the page is untrusted data inside markers it cannot close, the system prompt says so, the model gets
  no tools, its answer only passes through the schema validator, and the code checks above decide.
* **Costs / caps:** the `validate` role's model order with the usual budget guard and failover; for the Claude CLI it counts as bulk
  work (only with `/llm bulk on`). At most `validate.per_scan_cap` (40) model calls per scan; the rest wait for the next scan or the
  background worker (it yields to foreground commands and stands aside while a scan runs). Results are cached forever by URL hash +
  content hash; dates, times, years and long ids/tokens are ignored, so only a material change of the page triggers a new call. No model at
  all → the find goes to NEEDS MANUAL CHECK as "not validated" (a validation never blocks a scan).
* **Your labels win:** `/programs mark <id|url> valid|invalid|weak [note]` overrides the model for that program, counts for the dork
  that found it, and is kept (table `program_labels`) for regression tests and, with `validate.use_feedback_examples`, as at most 4 short
  few-shot examples (title + domain + label only; never your note, e-mail addresses or phone numbers).
* **Commands:** `/validate status` (verified / needs check / rejected / weak / not validated / waiting, model order, calls, cache, cap),
  `/validate on|off`, `/validate test <url> [--cached]` (whole pipeline on one URL; prints every check and the assessment; stores nothing
  except the model-usage counter), `/programs revalidate <id|url|--all-weak|--all-manual>`, `/why` (full assessment, evidence, every
  code check, the model that judged), `/programs` / `/export` columns validity, kind, status, reward, scope, confidence
  (`--validity verified|needs_check|weak|not_validated|none` filters).

**What validation cannot do.** It reads one page. It cannot verify that payouts are real or how much is paid, that the
organisation or program is legitimate beyond what that page says, or that **you are authorised to test** anything: a program page
defines its own scope and rules, and only the page itself (and the organisation behind it) can grant permission. A VERIFIED line
means "this page looks like an official, active program and the quoted evidence is really on it" - the final check, and reading the
rules before testing, is yours.

## AI dork promotion into the default list (v0.5)

AI dorks that keep finding real programs graduate into your default list - decided by **code on counts**, never by the LLM:

* **Eligible** when all of these hold (config `dorks.*`): at least `promote_min_runs` (3) runs; at least `promote_min_verified` (2)
  distinct **new** programs it found that ended VERIFIED (validator, or your `valid` mark; duplicates of programs another dork found first
  do not count, raw hits do not count); precision = verified programs / results kept by the relevance gate ≥ `promote_min_precision` (0.3);
  the dork validator and blocklist pass again; and it is not a near-duplicate (token-set similarity ≥ `promote_similarity`, 0.8, same TLD)
  of a default dork. `/dorks candidates` shows every AI dork against every condition.
* `dorks.ai_auto_promote` = `ask` (default: an interactive `/scan` asks once per dork, again only when its evidence grows; `/watch` lists
  them) | `on` (promote automatically and log it) | `off`. `/dorks promote <id|all-eligible>` re-checks everything first.
* Promoted dorks get group `default`, origin `ai_promoted`, the promotion date, parent dork and evidence. They rotate, count and
  enable/disable like any default dork, and are mirrored to **`~/.qurihunter/learned_default.txt`** (grouped, with date/evidence comments),
  from which they are restored automatically if the database is reset - so they survive upgrades.
* **`dorks/default.txt` in the repository is never changed automatically.** `/dorks export-default [--include-promoted] [--to <path>]`
  shows a unified diff of a `# ---- AI-promoted <date> <group> ----` section (deduplicated, grouped by country TLD) and writes only after
  your yes - and refuses when the file is not writable or has uncommitted changes in the git working tree. Commit it yourself to share it.
* `/dorks reset-default` restores the shipped list and keeps promoted dorks (it prints the counts first); `--include-promoted` demotes them
  back to the AI group (their history is kept). `/dorks demote <id>` does that for one dork.
* **Demotion:** a promoted dork whose precision *since promotion* stays under `demote_below_precision` (0.1) after `demote_after_runs` (10)
  runs is moved back to the AI group and disabled, with the reason recorded. Nothing is deleted.
* `/dorks list --group default|ai|custom --origin shipped|ai_promoted`; `/dorks stats` adds a per-dork quality table (group, origin,
  runs, kept, verified-valid, precision, last run).
* **Poisoning guard:** dork generation sees only dork statistics and the short names / countries of VERIFIED programs - never page text.

## Search recency vs the alert window (v0.4.2)

Two different settings that used to be one:

* **Alert window** (`recency_days`, default 7 days, `/recency <N|24h|7d|any>`): applied **after** discovery. A result alerts only if it is an
  unseen URL/program, survives the relevance gate and its date evidence says it is new (published date, first archived inside the window,
  or the existing likely-new rules); everything else is stored silently as baseline.
* **Search recency** (`dork_search_recency`, `/recency search ...`): what the *provider's* date parameter gets. Static policy pages are rarely
  dated inside the last week, so filtering the search by the alert window hid them and filled the page with freshly indexed junk. Default
  policy: the **first run of each dork uses `any`**; later runs use **past month** (newly indexed pages); an optional recent-only **sweep**
  (past week, 10 % of a batch, `sweep_share`) re-checks dorks that already ran once. `pages_per_dork` (default 1) sets the results pages per
  query where the provider paginates. Both settings are shown in `/status` and `/config`.

**Relevance gate** (before any LLM call, page fetch or storage): at least one quoted phrase of the dork (or all key terms when there are no
quotes) must appear in the title, snippet or URL - case-insensitive, accents folded, with synonyms from the dork's own language group (a `.ch`
dork also accepts "Schwachstelle melden"). A hit with no snippet that fails this goes only to the cheap rules check (no LLM, no fetch).
**Spam rules** (redirector/proxy parameters such as `get.php?web=` or `?url=http`, jobs/tickets/rentals/classifieds paths and hosts,
adult/gambling words, mostly non-Latin titles for a Latin-script dork, doorway patterns) live in the editable `~/.qurihunter/spam_rules.txt`
(copied from the packaged default on first use); every drop is logged with its reason, spam URLs are remembered, mere irrelevance is not
(another dork may match it).

**Safer fetching:** classification starts from the provider's title/snippet; a page is fetched only when the snippet is too thin or the model is
unsure, and never for URLs that matched the spam rules. Fetches have a timeout, a 300 KB cap, `text/html`/`text/plain` only (no downloads, no
JavaScript), http(s) only and **only to public addresses** (private, loopback, link-local, multicast and reserved IPs are refused - SSRF guard),
redirects are followed by hand and every hop is re-checked; a hop to another domain must pass the spam/ignored-domain gate again.

**`/dorks test <dork> [--recency any|day|week|month|year|Nd] [--pages N] [--provider id] [--dry-run]`** prints the exact request the provider
received (query string, time parameter, page, country/language), the line "alert window (7d) is NOT used as the search filter", a KEPT and a
DROPPED table (with reasons) and the remaining quota, and stores nothing. `--dry-run` shows the translated request without sending it. A
`site:` operator with an unknown TLD (`.du`) is stopped **before** it spends quota (y/n; parked in scans). Serper/SerpAPI send `gl` (country)
and `hl` (language) next to a TLD dork; `tld_style` (`dot` = `site:.ch`, `bare` = `site:ch`), `country_targeting` and `language_targeting`
are per-provider options.

## The recency window (default 7 days)

Only programs that are **new to you** *and* whose *effective date* falls inside the window alert. Change it any time:
`/recency 14d`, `/recency 24h`, `/recency any`, or `/config` → 6.

* **Effective date** = the launch date if the source gives one, else the date we first saw it, **but only if the
  program is not a baseline entry**. Baseline entries (the thousands of programs that already existed when a source was
  first polled) have an unknown launch date and are never "new in window" (use `--include-baseline` to list them).
* **First run** of a source or dork no longer silently baselines everything: items whose date is inside the window still
  alert; older/undated ones are baseline. Dork queries are sent with the provider's native recency filter, so a genuinely new
  page found on a dork's very first run is not lost.
* Launch dates are **never invented**. What each source really provides:

| Source | Launch date? |
|---|---|
| HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy feeds | **None** (checked every field). New = first seen by us. |
| disclose.io | `launch_date` for ~2% of entries (only full dates are used; year-only and "Updated …" are ignored) |
| Self-Hosted list | `first_seen` per entry = when *that crawler* first saw it (weak signal, stored as `source_first_seen`); the dataset's first crawl day is ignored because it carries no information |
| Dork hits | Page/published date when the provider returns one (stored as `page_date`, weak); otherwise unknown |
| Custom RSS feeds | `pubDate` |

## Alerts: NEW vs RECENTLY UPDATED

Each alert block shows name, URL, type, reward, country, source and **one evidence line**, e.g.
`published 03 Oct | first archived: none | likely new` or `last updated 15 Sep | first archived 2024-03 | age unknown`.

| Kind | When |
|---|---|
| **NEW** | a published/launched date inside the window, **or** likely new: no Wayback capture / first capture inside the window / a non-baseline platform listing first seen inside the window |
| **RECENTLY UPDATED** | the only date is a *last-updated / effective / renewal* date inside the window (`alerts.alert_updated_only_pages`, default on) |
| OLD | everything else; stored silently, listed in the digest only if `alerts.show_skipped_in_digest` is on |

* **Dates are classified, not assumed** (`date_kind`: published, launched, last_updated, effective, unknown). Rules first; the
  LLM only for ambiguous dates. "Last Update", "Effective Date" and "renewal" are never launch dates.
* **Wayback check** (`wayback.*`): new dork candidates without a launch date get their first Internet Archive capture looked up
  (cached forever, 1 request/s, 8 s timeout, 40 lookups per scan; never blocks a scan; after 3 consecutive failures the archive is skipped for the rest of the scan; `wayback.on_error`: `wait` (default, unverifiable undated legacy rows wait) or `alert`). First captured before the window =
  an old page found late, stored silently. No capture = "likely new".
* **Unfiltered sweep** (`dorks.unfiltered_share`, default 10 %, max 30 %): that share of each dork batch runs *without* the
  provider's date filter so undated pages aren't hidden; hits go through the same date + Wayback + dedupe pipeline and are only
  trusted when the archive vouches for them.
* **At most one alert per kind per channel.** A page alerted as *updated* is never alerted as *new* unless a real launch date
  appears.
* **Delivery is per channel** (`telegram`, `email`, `chat`) and recorded **only after the channel confirms** (Telegram
  `ok: true`). Showing something in `/chat` never suppresses Telegram. Messages are HTML-escaped (names/URLs with `_ * [ ] ( )`
  are safe), fall back to plain text if Telegram rejects the markup, split between programs at ~3900 chars (never inside a link),
  and honour `429 retry_after`. Failures are logged (secrets redacted), shown in `/alerts status` and `/status`, and retried next run.
* **Scan summary** (`alerts.telegram_scan_summary`: `off` | `changes_only` (default) | `daily`): one message per scan,
  `Scan finished: X new, Y updated, Z skipped as old, quota left N`; `daily` also sends one heartbeat per day when nothing was found.
* `/alerts status|pending|resend [N|all|--since 7d]|test` and `/why <id|url|name>` explain and control all of this.
  `/alerts test` sends two clearly marked SAMPLE alerts and records nothing.
* `/version` and the startup banner show the code version; a startup self-check warns loudly if the DB/config is newer than the
  code, if a command from the spec is missing, or (in the REPL) if the source on disk changed after the session started - a
  long-running session keeps the code it started with, so **restart `qurihunter` after upgrading**.

### v0.3.1 additions

* **Provider capabilities** (`/dorks stats` prints the table): Google = full operators and native `site:.cc`; Brave = site:/quotes,
  `site:.cc` emulated (country parameter + client-side filter), results/query 20; Tavily = no operators, **no TLD filter**,
  20 results/query. For a provider without TLD support, `site:.cc` dorks are **rewritten** to natural language with the country name
  and local-language disclosure terms (`Schweiz responsible disclosure Schwachstelle melden Sicherheitslücke`, `Sweden ansvarsfull
  rapportering sårbarhet`) and filtered client-side on the result domain / page text (countries table in `countries.py`). Dorks that
  cannot be expressed at all are **parked**: no quota, no batch slot, and they run automatically once a capable provider is added.
* **AI dorks**: tolerant JSON extraction (strips `<think>` blocks and code fences, finds the first array/object), one retry with a strict
  "ONLY a JSON array of strings" prompt, a line-by-line fallback, a clear failure message. Validator, blocklist and the 20 % exploration
  budget are unchanged; failures never block a scan.
* **Pending queue**: a background worker (REPL and `/watch`) retries waiting/failed alerts with exponential backoff
  (`pending.backoff_base_min`..`backoff_max_min`) and a per-day cap (`pending.retry_max_per_day`); `/alerts status` and `/status` show the
  pending count **by reason**. `/alerts baseline-legacy [--dry-run]` baselines old undated rows from the first v1 dork batch (shows a
  sample of 10, asks first); `/alerts release-pending [N]` sends waiting items now, labelled **NEW — age unverified** (asks first).
  Wayback: `wayback.timeout` (20 s), `wayback.concurrency` (1), the archive.org availability API as a lighter second check, and
  `wayback.on_error` = `wait` by default.
* **Honest NEW alerts**: every NEW block has a `Basis:` line - *published date*, *launch date from source*, *first archived inside window*,
  *first seen by source crawler (weak)*, *first seen by this tool (weak)*. Weak ones go into a separate **NEW (weak evidence)** section;
  `alerts.alert_weak_evidence` (default on) switches them off. `/why` shows the same basis.
* **`/memory reclassify`** is a resumable background job (queue in the DB, `reclassify.pages_per_cycle` = 20 LLM judgements per cycle, hard
  rules are free). It only records decisions, never alerts and never takes the scan lock; progress is in `/status`; when finished the REPL prints
  the before/after table, and `/memory reclassify apply|review` hides the rejected entries (reversible). `--now` keeps the old synchronous mode.
* **`/status`** network health shows Tavily/Brave/Google/Telegram/Wayback/Ollama/Gmail only (retries and failures per service);
  `/status --all-hosts` lists every host.
* **Single instance**: `instance.lock` (PID) refuses a second REPL/`/watch` on the same home (`--force` overrides) and a process scan warns
  about other qurihunter processes - e.g. an old session still running old code.

### Upgrading from an older database

The first v2+ start migrates and backs up the DB. v1 stored its **first dork batch silently as baseline** (`notified=1`
without any send). Those rows are *not* treated as delivered: they are re-judged (`/memory reclassify` removes news/writeup noise,
the Wayback check separates old pages from new ones) and what remains alerts once.

## Memory guarantees

* **Never alerts the same program twice.** Identity is the company domain across *all* sources: a company on HackerOne
  *and* with its own page is one program (the second source enriches the record). Two different programs of the same
  company on the *same* platform stay separate.
* **Never re-spends quota on an identical query** (provider + translated query + site filters + recency window) within its
  cooldown (7 days, per-dork override possible). Every result is compared with previously seen URLs and programs, so old
  results are ignored silently. Rejected/noise URLs are remembered individually (not whole domains).
* `/memory stats`, `/memory export <path>`, `/memory forget program|query|dork|all` (confirmation; backup first),
  `/memory reclassify` (re-checks stored dork entries with the LLM, never alerts), `/history [N]`.
* Before any schema migration the DB is copied to `backups/` (last 5 kept). Restore = copy a backup over the DB.

## Dork wordlist

`dorks/default.txt` (one dork per line, `#` comments, no dates, no exploit/exposed-data dorks) is the built-in list.
Modes: `default`, `custom`, `both` (`/dorks mode`); switching never deletes anything.

* `/dorks import <file>` (no duplicates on re-import), `list [--disabled] [--group g]`, `enable|disable <id|all>`,
  `priority <id> <n>`, `stats`, `test <text>` (runs once, stores nothing), `prune` (confirmation), `reset-default`.
* **Rotation:** each batch runs only what the quota budget allows: priority ↓, least recently run, most productive.
  The batch summary shows run / waiting / estimated days to cycle the list.
* **Per-provider merging:** dorks that translate to identical or ≥90%-similar queries for the active provider are
  collapsed (Tavily flattens operators). Different country TLDs or currencies never merge.
* **Noise control:** blocklist of blogs, news, aggregators and tool sites (`src/qurihunter/data/domain_blocklist.txt`),
  URL-shape rules (`/blog/`, `/news/`, READMEs…), and, when an LLM is available, **every** plausible hit is asked: "official page
  of ONE company, or an article/list/tool?". Page text is treated as untrusted data.
* A dork that contains `after:`/`before:` dates is honoured and translated (Google native, Brave custom freshness range,
  Tavily `start_date`/`end_date`); the default list never contains any.

### AI-generated dorks (`features.ai_dorks`, `/dorks ai on|off`, `/dorks generate [n]`)

The LLM proposes dorks from your existing list, which ones found programs, patterns in recent finds and uncovered
regions/languages, shaped to the provider's capabilities. **Code validates every candidate** before storing it: must contain a
disclosure/bounty term (multi-language allowlist), must not match the blocklist (`data/dork_blocklist.txt`: credentials, `.env`,
backups, `index of`, cameras, logins, `filetype:`, exploit words…), only `site:.tld` is allowed, length cap, dates stripped,
near-duplicates rejected. AI dorks use at most 20% of each batch; winners rise in priority and seed variations; AI dorks with
no finds after 5 runs are auto-disabled. Add your own blocked words in `~/.qurihunter/dork_blocklist.txt`. Proven AI dorks can be
promoted into your default list (see "AI dork promotion" above); the generator only ever sees verified programs.

## `/chat` (`features.chat`)

Talk to the LLM about your data. It acts **only** through nine whitelisted tools: `query_programs`, `get_program`,
`list_dorks`, `dork_stats`, `get_history`, `quota_status`, `search_web`, `add_dork`, `trigger_scan`: max 5 per message,
arguments validated. No shell, files, keys, settings or notifications. `search_web` uses the normal provider pool, quota guard,
cooldown and dork validator and is logged as `origin=chat` (daily cap 10); more than 3 searches in a message, `add_dork` and
`trigger_scan` ask for your confirmation first. Tool results and web text are sanitised, length-limited and wrapped as untrusted
data. Programs first shown in chat are marked `delivered_via=chat`, so Telegram never alerts them again. History persists with a
rolling summary; `/chat --new` starts fresh; `/exit` or `/back` leaves. Native tool-calling is used when the model supports it,
else a strict JSON-action protocol with validation and retries (works with weak local models).

## Search providers (v0.4: six, in an order you choose)

`/config` → option 2 → pick a provider and enter its keys (every key is tested live), then the **Search order** step (move up/down,
on/off, mode). **There are no technical questions**: quota type and allowance come from an internal defaults table (each entry has a source
note and date and is flagged "unverified" unless a document was read) or - where the provider offers it - from its own account endpoint
(SerpAPI `account.json`, Tavily `/usage`, Brave `X-RateLimit-*` headers; silent fallback to the default). The only question per key is
**"How many requests per day for this key? (recommended N)"** - Enter accepts. N = remaining allowance ÷ `lifetime_target_days`
(default 365: 2500 credits → 6 per day; for monthly quotas remaining ÷ days left in the cycle; minimum 1). Add teammates' keys with the
"Add another API key?" loop - each key has its own cap, `/providers show` prints the total per day, keys are used in the order added. A
reached daily cap means *exhausted until local midnight*: the sequence moves on and picks the key up again tomorrow. Adjust any time:
`/providers set <provider> allowance|type <value>`, `/providers daily <provider> [key#|last4] <n>`. Results are normalised to `title / url / snippet / published`. **Plan limits change - the amounts
below are starting points only; set your real allowance per key** (quota type: `monthly`, `daily`, `lifetime` = one-time bucket that
never resets, or `unlimited` = rate-limit only).

Shared **rate limiter** (token bucket per provider, used by every thread incl. background workers and AI dork generation, honours
429 / `Retry-After`): Exa 6 req/s (your cap; the docs' default is 10), Brave 1/s (plan header example), SerpAPI 1/s, Tavily 3/s, Serper 5/s,
Google 2/s, SearXNG 2/s - `max_qps` is in the capability table (`/dorks stats`).

| Provider | Default quota type | Operators | TLD filter | Date filter | Results/query | Caveats |
|---|---|---|---|---|---|---|
| **Serper** (google.serper.dev) | lifetime (placeholder 2500) | full (`inurl:`, `intitle:`, `site:`, quotes, `-`, `OR` pass through) | native | `tbs` (`qdr:d/w/m/y`, custom `cdr` ranges) | 10 (more costs extra credits) | Real Google results. New accounts get free credits once; then paid. |
| **SerpAPI** | monthly (free plan 250, hourly 50 - read from serpapi.com/pricing.md) | full (Google passthrough) | native | `tbs` | 10 | engine=google; `account.json` reports the real remaining quota. 1 request/s polite cap. |
| **Tavily** | monthly (placeholder 1000) | none | no → country rewrite | `time_range` / `start_date` | ≤ 20 | Dorks flattened to keywords; `-site:` → `exclude_domains`. |
| **Brave** | monthly (placeholder 1000) | `site:`, quotes, `-` | partial (`country=` + client filter) | `freshness` | ≤ 20 | `inurl:`/`intitle:`/`OR` become plain terms. |
| **Google CSE** (legacy) | daily (100) | full | native | `dateRestrict` | 10 | Closed to new customers, sunsets 2027-01-01; needs key **and** `cx`. |
| **Exa** | monthly (placeholder 1000) | none (semantic) | no → country rewrite | `startPublishedDate` | 10 | No snippet unless contents are requested (extra cost); the page fetch fills the gap. |
| **SearXNG** (self-hosted) | unlimited | engine-dependent | partial | `time_range` (coarse) + client-side | ~10 | No key. Upstream engines may answer CAPTCHA/429 - see below. JSON output must be enabled. |

Capability table: `/dorks stats`. Dorks a provider cannot express are rewritten (natural-language country queries) or **parked**
(no quota; released automatically when a capable provider is configured). Any number of keys per provider are used **in the order added**
(the next only when the current is exhausted or invalid). Each cycle spends `remaining ÷ cycles left in the window`; **lifetime**
allowances are spread over `lifetime_target_days` (default 60) and a warning appears below 15 % left (`/status`, `/sequence show`).

### Search sequence (`/sequence`, `/providers`)

`search_sequence` is the ordered list (default: Serper, Tavily, Brave, Google, Exa, SearXNG; entries are `{provider, enabled, role}`;
keys, allowance and quota type live once under `search.providers.<id>`). `search_mode`:

* **failover** (default): each dork goes to the FIRST enabled provider that can express it, has quota and is healthy; the next only on
  exhaustion, invalid key, repeated failures or an open circuit breaker.
* **cascade**: run on provider 1; if it yields fewer than `cascade_min_results` (3) new results, also on provider 2, and so on.
* **sweep**: every dork on every provider (most coverage, most quota) - only after a confirmation that shows the estimated cost.

A batch is an ordered list of `(dork, provider)` **steps** processed one at a time; every step is persisted (table `search_steps`), so a crash,
Ctrl+C, restart or quota stop resumes exactly at the next unfinished step and never re-spends a finished one (the query cooldown still
applies). `/sequence show` (table + resume point), `move <provider> <pos>`, `enable|disable <provider>`, `mode ...`, `test` (one harmless
dork through the chain; shows who answered and the quota it cost; stores nothing), `reset-cursor`; `/providers status` (retries,
failures, circuit-breaker state). If every provider is exhausted or down, platform polling and alerts still finish and the stopped step is
shown in `/status`. The same URL from two providers is one result; memory/dedupe rules are unchanged.

### SearXNG

`/searxng setup` **prints** a ready `docker-compose.yml` + `settings.yml` (JSON enabled, limiter off for localhost, several engines on, a
generated secret key that is written to the file but never shown) and offers to write them to a folder and to save
`http://localhost:8080`. It **never runs docker or any command**; start it yourself (`docker compose up -d`) and check with
`/searxng probe`. If the server answers 403 the JSON format is disabled: add `json` under `search: formats:` in `settings.yml`.
CAPTCHA / "access denied" / 429 from upstream engines are failures, **not** "ran with 0 results": a query where no engine answered is
retried later and never marks the dork as run; each engine has a circuit breaker.

## LLM backends and models (v0.4)

`/model add` (also `/config` → 8 and Manual-mode first run) asks ONE question at a time:
1. Local LLM (Ollama, with hardware detection / existing-model reuse / confirmed download; or any local OpenAI-compatible server), 2. API
(OpenAI-compatible: only base URL, hidden key, model + one live test; works with your own relay; prices optional via `/llm prices`), 3. **Claude API key** (Anthropic Console,
pay-as-you-go; the model list is fetched from the API after the key is entered - no model names are hardcoded), 4. Claude subscription
via the official Claude Code CLI (**experimental, off by default**, see below). Then the roles the model handles (`classify`, `summarize`,
`dork_gen`, `chat`, `date_kind`) and its place in the failover order. Per role the first enabled model in the order answers and the next
takes over on error/timeout/quota/budget. Local models first (free); paid ones only for roles you assigned. Auto mode keeps the old behaviour
(detect Ollama/hardware, no questions); existing configs migrate automatically (the single LLM becomes model `m1`; `config.json.bak-v4` is the
backup).

Commands: `/model list|add|remove <id>|test [id]|roles <id> <roles...>|order <id> <pos>|enable|disable <id>`, `/llm status` (calls, tokens,
estimated spend per model and per role). **Cost guard** for `api`/`claude`: `llm_budget` (`daily_usd`, `monthly_usd`, `warn_pct`=80); spend is
estimated from the usage fields and a price table **you** enter (USD per million tokens; no price = no cost tracking, nothing is assumed);
warning at 80 %, hard stop at 100 % (next model, or no LLM work - never a crashed scan). Bulk jobs (`/memory reclassify`, first dork run
classification, AI dork generation) show an estimate and ask before using a paid model. Only snippets and metadata go to a model - never keys,
tokens, config or DB dumps; web text stays data, never instructions (dork validator, blocklist and the `/chat` whitelist/confirmation gates
are unchanged).

**Not supported, by design:** Claude Free/Pro/Max logins, OAuth/subscription tokens, reading another tool's credential files or keychains,
presenting qurihunter as Claude Code, or using the Agent SDK with subscription auth. Use a local model, an OpenAI-compatible API, or an
Anthropic **API key**.

### Who can use the Claude CLI backend

The Claude CLI backend is optional, experimental and off by default; qurihunter works fully without it. Claude Free accounts are not supported.

> This option needs the official Claude Code app, signed in with a paid Claude plan (Pro, Max, Team or Enterprise) or an Anthropic Console API key. The free Claude account does not include Claude Code, and qurihunter cannot use a free account directly. Other options: 1) a local model, 2) a free-tier API (any OpenAI-compatible endpoint, for example Gemini's free tier or your own relay), 3) a Claude API key from the Anthropic Console.

The wizard checks this before asking anything: it looks for the `claude` binary and runs the official `claude auth status` (JSON; only the `authMethod`
and `subscriptionType` fields are read - never the e-mail or anything else). If the binary is missing, you are not logged in (the official login
is offered with a y/n) or the account has no Claude Code, it prints the text above and returns to Step 1. With an API-key login it says, in one
line, that calls are billed per token by Anthropic and that `/llm status` counts calls only. `/model list` and `/model info` show the detected
login type (subscription / API key / not logged in), never the e-mail or a credential.

### Claude CLI backend (experimental, optional, OFF by default)

qurihunter works fully without it. `/model add` → 4 asks **no technical questions**: (1) is `claude` installed? (2) is it logged in? - checked
with the official `claude auth status` (exit code only); if not, one line ("log in once with the official Claude Code app") and a y/n to launch
the official `claude auth login` with your terminal passed straight through (qurihunter never sees what you type), (3) a two-line warning and a
plain y/n, (4) done: **all roles** (classify, summarize, dork_gen, chat, date_kind), **first** in the order, your other models kept behind it as
automatic fallback, one test call, the active limits printed once. Change roles/order later with `/model roles` and `/model order`; `/model roles <id> classify date_kind` asks one y/n (showing the caps) instead of refusing, and `/llm bulk on|off` is the single switch (`claude_cli_allow_bulk`).

It runs **your own installed official Claude Code binary** in non-interactive print mode as a subprocess under **your own login** and reads
only its stdout. qurihunter never sees, stores, copies, refreshes or sends any Claude credential. Full warning (also `/model info`):

> This uses your Claude subscription through the official Claude Code CLI. Anthropic's terms and billing for automated/headless use changed
> several times in 2026 and may change again. Automated use can consume your subscription limits (also blocking your own Claude Code work) or
> be billed differently. You are responsible for checking Anthropic's current terms (the support.claude.com article 'Use the Claude Agent SDK
> with your Claude plan' and the Claude Code legal and compliance page). qurihunter never sees your login.

Isolation: empty temp working dir, built-in tools disabled (`--tools ""`), **`--safe-mode`** (no personal settings, hooks, skills, plugins, MCP
servers, auto memory or CLAUDE.md are loaded; login and model still work), no saved session, one turn, JSON output, prompt on stdin, timeout,
concurrency 1. Flags are detected from the installed binary's own `--help`; if `--print`, `--tools`, `--output-format` or `--safe-mode` is
missing it refuses to run. To make a subscription workable: **batched classification** (up to `batch_size` = 10 pages per call, strict JSON
array, per-item retry on a parse failure, dedupe before any call), minimum interval between calls, caps (default 12 calls/hour, 80/day, 20 s
apart; `/llm limits [hour N] [day N] [interval S] [batch N]`). Any limit/auth/billing message stops the backend for the rest of the window and the
next model answers silently (a notice in `/llm status`). Bulk jobs (`/memory reclassify`, first-run classification) may use it through batching
and caps (`claude_cli_allow_bulk`, switched on by the wizard's "yes"). The cost guard counts calls, not dollars.

## Database locking (v0.4.1)

Every connection uses WAL, `synchronous=NORMAL` and a 30 s busy timeout. All writes go through one in-process write gate with foreground
priority, automatic retry with jittered backoff and a friendly message that names the holder instead of a traceback. A pending write
transaction is committed before every network / LLM / subprocess call, background workers commit after every item and yield to foreground
commands (`/background status|pause|resume`, config `background_workers`), planning is read-only (the lifetime-start marker is written once at
key-add time) and `/dorks test` never needs the write lock. v0.5 validation follows the same rule: read, then fetch + model call with no
write transaction open, then one short write (a regression test asserts it). Cross-process: a second qurihunter still waits politely and then says which process
holds the lock.

## Commands

`/scan` `/watch` `/config` `/model` `/filters` `/status` `/test` `/recency` `/programs [N|filters]` `/export [file] [filters]`
`/dorks …` `/memory …` `/history` `/chat` `/alerts …` `/why` `/version` `/sequence …` `/providers [show|status|set|daily]` `/searxng …` `/llm [status|limits|prices]`
`/model [list|add|info|…]` `/background [status|pause|resume]` `/validate [status|on|off|test <url>]`
`/programs mark|revalidate …` `/logs` `/help` `/quit`
(typos are forgiven: `/alert` runs `/alerts`; unknown commands get a "did you mean" hint)

`/programs` filters: `--since 24h|7d|30d|YYYY-MM-DD`, `--from/--to` (YYYY-MM-DD or DD/MM/YYYY), `--by seen|launched`,
`--kind new|updated|old|all` (default new+updated), `--include-baseline`, `--include-old`, `--category program|securitytxt|all`,
`--validity verified|needs_check|weak|not_validated|none`, `--source`, `--country`, `--text`, `--limit`, `--wide`, `--compact`.
Every row has a **Kind**, **date evidence** and **Validity** column (wide: also status, scope, confidence) plus
per-channel delivery (`telegram✓, chat✓` / `unsent`); narrow terminals drop other columns but never those two. The title states
the filter in use, e.g. `Programs since 7d (new/updated, by seen) — 12 shown, 3300 baseline hidden`. `--by launched` excludes (and counts) programs with unknown
launch dates. Times are shown in your local timezone. `qurihunter [scan|watch|status|test|setup]` also works non-interactively.

Defaults: platforms polled every 15 min, dork batch every 1440 min (`/config` → 4). Old configs migrate automatically (the
`google` block, 30/60-minute intervals if still at the old defaults).

## Security & privacy

Secrets live in `~/.qurihunter/config.json` (chmod 600; dir 700); `.gitignore` excludes configs, DBs and backups. Tokens and
keys are masked (last 4 chars) in the UI and redacted from logs and error messages. Override the data dir with `QURIHUNTER_HOME`.

## Tests

```bash
pip install -e '.[dev]' && pytest
```
