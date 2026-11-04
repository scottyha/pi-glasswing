# pi-glasswing

> Parallel AI agent harness for web vulnerability discovery. Architecture adapted from Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/).

**pi-glasswing** orchestrates parallel [pi](https://github.com/earendil-works/pi-coding-agent) sessions to discover web application vulnerabilities. Each session is a fresh agent with full context window dedicated to one attack pattern — avoiding the context compaction problem where a single agent covering 48 patterns forgets earlier findings by pattern #30.

## Pipeline

```
Intel Harvest (live CVE data from free APIs)
  ↓
Recon (architecture doc + live context injected)
  ↓
Hunt (~48 parallel agents, one per attack pattern)
  ↓
Gapfill (re-queues empty patterns with narrowed scope from recon clues)
  ↓
Validate (adversarial second agent — can only disprove)
  ↓
Dedupe (root cause collapse, variant analysis)
  ↓
Report (JSON + Markdown)
```

| Stage | Model | Thinking | What it does |
|-------|-------|----------|--------------|
| **Intel** | N/A (API queries) | — | Harvests live vulnerabilities from OSV, GitHub Advisories, CISA KEV, NVD, npm audit, Scorecard, cve.now |
| **Recon** | DeepSeek Flash (latest alias) | medium | Single pi session maps trust boundaries, entry points, data flows, auth |
| **Hunt** | DeepSeek Flash (latest alias) | low | 48 parallel pi sessions, each scoped to one attack pattern |
| **Gapfill** | DeepSeek Flash (latest alias) | low | Second pass for patterns that found nothing — uses recon doc clues |
| **Validate** | DeepSeek V4 Pro | high | Adversarial — can only disprove findings, not propose new ones |
| **Dedupe** | Python | — | Same root cause + location → single record with variants |
| **Report** | Python | — | Structured JSON + human-readable Markdown |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Full pipeline
python3 harness.py /path/to/target-repo

# Step-by-step: recon only
python3 harness.py /path/to/target-repo --recon-only

# Specific patterns
python3 harness.py /path/to/target-repo --patterns sql-injection,missing-auth

# Intel harvester standalone
python3 vulnerability_context.py /path/to/target-repo
```

### Requirements

- **pi** (≥0.74) — the coding agent CLI. [Install](https://github.com/earendil-works/pi-coding-agent)
- **Python** ≥3.10 with `requests`
- **Attack patterns** — 48 patterns at `./skill/patterns-*.md`
- **WooYun knowledge base** (optional) — 86MB of real-world bypass techniques at `./wooyun-categories/`. From [tanweai/wooyun-legacy](https://github.com/tanweai/wooyun-legacy) (MIT). Skip or delete — harness degrades gracefully.

## Attack Patterns (48)

### Next.js (12)
`missing-auth`, `middleware-bypass`, `server-component-leak`, `client-secrets`, `fail-open-defaults`, `unvalidated-server-action`, `server-action-no-auth`, `error-state-leak`, `debug-in-prod`, `path-traversal`, `open-redirect`, `ssrf-image-loader`

### PostgreSQL (11)
`sql-injection` 📚WooYun, `dynamic-table-names`, `over-privileged-db-user`, `connection-string-leak`, `embedding-manipulation`, `vector-query-injection`, `unclosed-connections`, `select-star-leak`, `missing-rls`, `race-condition-leads`, `etl-sql-assembly`

### LLM Chat Agent (10)
`prompt-extraction`, `indirect-prompt-injection`, `multi-turn-injection`, `data-injection`, `unauthorized-function-call`, `llm-as-oracle`, `response-leakage`, `expensive-vector-abuse`, `context-exhaustion`, `unsanitised-input`

### Infrastructure (15)
`missing-headers`, `weak-csp`, `permissive-cors`, `missing-cors-public`, `weak-tls`, `mixed-content`, `server-info-disclosure`, `sensitive-files`, `missing-rate-limit`, `proxying-internal`, `insecure-cookies`, `origin-ip-exposed`)`), `unbounded-parsing`, `cache-key-vulnerability`

📚WooYun = supplemented with bypass techniques from the WooYun knowledge base (88,636 real vulnerability cases, 2010–2016)

## Live Intel Sources

All free, no signup required:

| Source | What it provides |
|--------|-----------------|
| **OSV** | Known CVEs for your resolved dependency versions (30+ ecosystems) |
| **GitHub Advisory API** | Fresh advisories modified in last 24h |
| **CISA KEV** | Actively exploited CVEs — the urgency filter |
| **NVD** | Fresh CVEs published in last 24h |
| **npm Audit** | Registry-level npm vulnerability lookup (resolved versions only) |
| **OpenSSF Scorecard** | Project security posture (public repos only) |
| **OpenSSF Malicious Packages** | Confirmed malicious package records (MAL-* IDs via OSV) |
| **cve.now** | Supplementary dependency matching — merged catalog with KEV/EPSS/public-exploit signals (see below) |

### cve.now (supplementary dependency matching)

cve.now merges the CVE List, GitHub Advisory Database, OSV, NVD, ENISA EUVD, CISA KEV,
FIRST EPSS and Exploit-DB into one deduplicated entry per vulnerability, and exposes it
over a documented REST API (`https://cve.now/api/v1/check`). It is used as a **second
opinion on the target's exact dependency versions**, not as a replacement for OSV — it
carries exploitation signals (KEV, EPSS, public exploit) that OSV alone does not.

**What is sent.** Only `{ecosystem, name, version}` triples for dependencies whose
version is **genuinely resolved** — an exact pin in the manifest (`4.17.21` for npm,
`==1.2` for PyPI, or a version read from a lockfile), never the numeric floor of a
range. Exactness is ecosystem-specific: **npm requires complete semver**
(`major.minor.patch`), because `4.17` means `4.17.x` and `=1.2` means `1.2.x` — both
are ranges, not installed versions. **PyPI keeps PEP 440 semantics**, where `==1.2`
names the single release 1.2, `==1` names release 1, and `==1!2.0` names epoch-1
release 2.0 — all exact. A lockfile entry is trusted only
when it too is a complete semver; `file:`, `git+` and partial entries stay unsent.
Max 2,000 packages, deduped
before the cap. Raw lockfiles are deliberately **not** uploaded, even though cve.now
supports it (`lockfile_content` / `POST /api/stack`) — a lockfile additionally carries
every transitive dep, integrity hashes and sometimes registry URLs or credentials, and
the parsed dependency set is already the minimum the API needs. Per the vendor docs,
`/api/v1/check` stores nothing server-side.This is still **third-party disclosure**: package names and versions for the audited
target are sent to cve.now (Sazabi) over HTTPS. Off-network operation is controlled with
`--no-cve-now` (or `no_cve_now=True`), which reports the source as *not queried* rather
than absent.

**Status semantics.** The structured result carries `status`:

| Status | Meaning |
|--------|---------|
| `ok` | Query succeeded. `matches` may legitimately be empty — that is a real "no indexed match". |
| `unavailable` | Timeout, connection error, non-200, unparseable body, a 200 without an `affected` list, `coverage` or integer `checked` (all part of the documented shape), a `checked` count larger than what we sent, or entries that could not be read at all. **Never read this as "no matches"** — the brief says `SOURCE UNAVAILABLE` in capitals and refuses to render a count. |
| `skipped` | Nothing checkable to send (`--no-cve-now`, no deps, or every version was a range). |

`checked` is the number of packages the API acknowledged processing for the request.
`packages_submitted` records the payload size and `packages_checked` mirrors
`checked`, so a partial scan is never labelled with the submitted count. A smaller
`checked` value means the API covered less than the full package list:
`coverage_complete` becomes false, `coverage_gap` states how many went uncovered, and
the brief says so — a partial scan is never presented as clean. The prose `coverage`
field is recorded in the JSON artefact.

**Bounded, not time-limited.** One `POST`, no retries, `timeout=(5, 15)`. Those are
**per-operation socket timeouts, not a wall-clock cap**: the connect timeout applies to
each address attempt while opening the connection, and the read timeout applies to each
individual `recv`, which requests resets on every chunk received. A silent host, a
refused connection or a stalled socket therefore fails fast, but a server that drips
bytes slowly can hold the call open past 15s — there is no watchdog timer. The measured
duration is recorded in `elapsed_seconds`. Because harvesting runs sequentially, treat
that as the one place an unresponsive source can still stretch the intel stage.

**Limitations.**

- Ranges, wildcards and npm partial versions (`^1.2.3`, `>=1.0,<2.0`, `1.x`, `*`,
  `latest`, `4.17`, `=1.2`) are skipped, not sent — matching them against
  affected-version lists would produce false "no match". (`=1.2`/`==1.2` is exact on
  PyPI but a range on npm, so the rule is applied per ecosystem.) Extraction keeps
  the original declaration (`declared`) and a `resolved` flag per dependency;
  `version` is only treated as the installed version when `resolved` is true. A
  `package.json` range with no `package-lock.json` to resolve it is skipped and
  counted. Skipped counts appear in the brief and the JSON artefact.
- Coverage is capped at 2,000 packages; anything beyond the cap is reported as
  `skipped_over_limit`, never silently dropped. Returned entries without a
  vulnerability id are counted in `unreadable_entries` and named in the brief;
  if *none* of the returned entries can be read, the source is reported
  `unavailable` rather than "0 matches".
- KEV attribution is literal: `[CISA KEV]` is only shown when cve.now's `kev` flag
  is set. The broader `activelyExploited` signal is labelled `actively exploited`
  and is **not** presented as a CISA KEV listing.
- The brief lists at most 50 matches; ranking happens **before** grouping, so the 50
  shown are the 50 worst of the whole match set rather than 50 entries of the first
  severity that fills the budget. The full list lives in `results/live-context-*.json`
  under `cve_now.matches`.
- Package matching requires a supported ecosystem and affected-version data. CVE
  presence alone does not imply matching coverage (the vendor states this explicitly),
  so a clean result is **not** evidence of safety.
- npm and PyPI only (`deps["npm"]`, `deps["python"]`). Node/Next.js runtime versions
  are not packages and are not sent.
- Titles come from the entry; some cve.now prose is model-written. Severity, exploitation
  status and affected versions come from source data. Follow `url` before citing.
- Not used: the MCP server, the per-entry endpoint (`/api/v1/entries/<id>`), and the
  lockfile/stack upload endpoints. One endpoint, one round trip.

## Dependency matching: what is sent, what is skipped

OSV, npm audit and cve.now all match **versions**, not constraints. They share one
provenance rule (`_is_resolved_version` in `vulnerability_context.py`):

- A dependency's `version` is treated as an installed version only when extraction
  resolved it — an exact pin (`4.17.21`, `==1.2` or `==1!2.0` on PyPI) or a
  `package-lock.json` entry that is itself a complete semver.
- Everything else — `^4.17.1`, `~2.0.0`, `>=6.0`, `1.x`, `*`, `latest`, npm partials
  such as `4.17` / `=1.2`, `file:`/`git+` lockfile specifiers — is **withheld**.
  Sending the numeric floor of a range (`^4.17.1` → `4.17.1`) would report
  advisories for a release the target may never run and hide those for the release
  it does run.
- Withheld entries are counted per source (`skipped_unpinned`) and stated in the
  brief. A payload never contains a range, and a lockfile is never uploaded — only
  `{name, version}` pairs for that source's ecosystem.

**No false clean.** Each source returns a structured result with `status`:

| Status | Meaning |
|--------|---------|
| `ok` | The source answered for a non-zero number of resolved packages. An empty finding list is a real "no match" for the versions sent. |
| `unavailable` | Timeout, connection error, non-200, unparseable body, a missing/mis-shaped response (OSV `results`, npm `advisories`), a result count that does not match the queries sent, or a response whose records/entries cannot be read at all. **Never read as "no findings"**; the brief says `SOURCE UNAVAILABLE` and refuses a clean header. |
| `skipped` | Nothing checkable to send: the flag was passed, there are no deps, or every version was a range. The brief says `not checked`. |

The brief prints `None found ✅` only when a source answered for at least one
resolved package **and** every submitted package was successfully checked. A target
whose every dependency is a range is reported as `not checked`, not clean. Each
result separates `packages_submitted` (payload size) from `packages_checked` (what
the source demonstrably answered for); OSV malformed per-query results and npm
advisories that cannot be parsed become `coverage_gap`/`unreadable_entries`, and the
section says `partial coverage` rather than mixing the two into a clean result. When
one ecosystem's OSV query fails and another answers, the section says `partial
coverage` too. Both the flat finding lists (`osv`, `npm_advisories`) and the
structured coverage (`osv_checks`, `npm_advisory_check`) are written to
`results/live-context-*.json`.

**npm audit coverage is a tree-size echo, not an acknowledgement.** The endpoint's
real 200 metadata is flat integers — `{"dependencies": 3, "devDependencies": 0,
"optionalDependencies": 0, "totalDependencies": 3}` — not the nested
`metadata.dependencies.total` that `npm audit --json` emits. `totalDependencies`
(the field actually read) is the size of the tree npm built from the submitted
payload, and it counts packages it cannot resolve: a nonexistent name or version
is still counted and still returns an empty `advisories` object. It can therefore
reveal that a submitted entry never reached the tree, but it cannot certify that
each version was evaluated. The brief says `npm reported an N-package dependency
tree`, never `npm acknowledged auditing N packages`; the JSON artefact records
`registry_tree_packages` (the reported size) and `coverage_basis` (`registry
dependency tree size`). A tree larger than the submitted set is transitive
resolution and never inflates `packages_checked`. If a response carries no usable
`totalDependencies`, coverage is `null` (unknown) rather than assumed complete.

**Limitations.**

- Direct dependencies only: the set is what `package.json` / `requirements.txt`
  declares (plus `package-lock.json` resolutions for those same names). Transitive
  packages are covered only where the lockfile surfaces them as entries; there is
  no full lockfile walk.
- `requirements.txt` parsing recognises `name<op>version` lines only — environment
  markers, `-r`/`-e` includes, hashes and URL requirements are not resolved, so
  those packages are simply absent from the Python set.
- OSV answers are advisory matches for the exact version sent. A clean result does
  not mean the package is safe, only that no indexed advisory covers that version.
  The OSV section's `fixed_in` is not populated (OSV expresses fixes as range
  events, which this reader does not walk) — for fix versions use the cve.now
  section (`fixed`) or npm's `patched_versions`, and follow the `url` before citing.
- If an individual OSV advisory record cannot be fetched in full, the match is
  still listed (degraded, `UNRATED`, no summary) and the count appears in the
  brief as `advisory records could not be fetched in full`. Malformed nested
  records (a non-object result, a `vulns` field that is not a list, an advisory
  stub with no usable id, or an npm advisory with mis-shaped fields) are counted
  in `unreadable_entries`; if nothing in the response can be read, the source is
  `unavailable` rather than clean.
- npm audit's payload is a synthetic single-package tree (`harness-scan`), so the
  registry evaluates the listed versions only; it cannot see the target's real
  dependency graph or hoisting. The `totalDependencies` it reports describes that
  synthetic tree, not the target's installed tree.

## CLI Flags

| Flag | Description |
|------|-------------|
| `--batch-size N` | Concurrent pi sessions per batch (default: 8) |
| `--patterns x,y,z` | Comma-separated pattern IDs to run (default: all 48) |
| `--skip-recon` | Skip recon (requires `--recon-file`) |
| `--recon-file PATH` | Use existing recon doc |
| `--hunt-only` | Stop after hunt (skip validate/dedupe/report) |
| `--recon-only` | Run only recon and save architecture doc |
| `--skip-intel` | Skip live vulnerability intel harvesting |
| `--intel-file PATH` | Use existing intel brief (skip harvest) |
| `--intel-hours N` | Lookback for fresh advisories (default: 24h) |
| `--no-gapfill` | Skip gapfill re-queue pass |
| `--list-patterns` | List all attack patterns and exit |

## Offline report rebuilds

`python3 revalidate.py --rebuild-artifacts results/report-…-revalidated.json` only
reads saved evidence and renders reports; it does not run sessions or harvest intel.
Back up both JSON and Markdown before rebuilding. Generated `results/` files stay
on disk and are not version-controlled.

The run-1 rebuild needs the original `report-20261026-153259.json`,
`revalidate-state.json`, and `live-context-20261026-123919.md` in `results/`.
It reads `RUN_LOG` for the original timeout split, falling back to an explicit
unavailable-breakdown note if that log is absent or cannot be reconciled. Legacy
`validated` flags supply missing validation states. Earlier template-cap effects
are restored from the original report before the corrected cap is applied.

Glasswing applies a **deterministic post-validation severity/confidence cap**
(`CRITICAL`→`HIGH`, `CONFIRMED`→`SUSPECTED`) to template-only runtime-configuration
claims instead of a mandatory "verify against the deployed value" step, because a
static repo session cannot read the deployed environment. The cap does not verify
deployment; it ceilings claims that cannot be verified from the repo. It changes
only CRITICAL claims with template config references and no non-template config
references. Code paths alone do not establish runtime values. `secrets-in-source` and `origin-ip-exposed` are exempt because a
committed template can itself prove repository disclosure. Non-CRITICAL findings
are untouched. Missing funnel accounting is explicitly reported as unknown
coverage/reconciliation, not reconstructed from incomplete evidence or presented
as a complete assessment. Dependency intel is rendered from the saved live brief.

Offline regression checks: `python3 test_funnel.py` (stdlib assertions, no LLM calls).

`vulnerability_context.py` also accepts `--no-cve-now` alongside `--no-osv`,

## Project Structure

```
~/projects/pi-glasswing/
├── harness.py                   ← main pipeline orchestrator
├── vulnerability_context.py     ← live intel harvester
├── test_funnel.py               ← funnel/dedupe invariants (stdlib asserts)
├── test_vulnerability_context.py ← dependency-intel invariants (mocked, offline)
├── skill/                       ← 48 attack patterns (patterns-*.md)
│   ├── patterns-nextjs.md
│   ├── patterns-postgres.md
│   ├── patterns-chat-agent.md
│   ├── patterns-infra.md
│   └── ...
├── wooyun-categories/           ← bypass techniques from WooYun (MIT)
├── requirements.txt
├── .gitignore
├── LICENSE
├── README.md
└── results/                     ← output directory (gitignored)
```

## Implicit Contracts

| Contract | Details |
|----------|---------|
| `PATTERNS` dict ↔ skill markdown | Pattern `"name"` values must match `### Pattern: Name` headings in skill files |
| Gapfill keyword mapping | New patterns added to PATTERNS must also be added to `_map_recon_to_patterns()` in gapfill, or they'll never be re-queued |
| Recon doc section #8 | Gapfill expects a "Notable Security-Relevant Findings" section in recon output. The RECON_PROMPT explicitly requests this |
| JSONL parsing | pi `--mode json` output must contain `agent_end` events with assistant messages. If pi's JSONL format changes, findings silently become empty |
| Scorecard for private repos | OpenSSF Scorecard API only covers public GitHub repos. Private repos silently return empty — this is expected |
| WooYun directory | Optional. Missing files are silently skipped |
| cve.now brief headings | The cve.now block uses `### Critical — N` (title case, em dash) and per-group counts cover only the listed (top-50) slice, with the overall total in the section heading. `harness.py` scrapes `CRITICAL (N)` / `HIGH (N)` out of the intel brief into `intel_summary` — a parenthesised upper-case heading here would overwrite the OSV counts |
| Robustness of intel sources | `query_*` helpers return `[]`/`{}` on failure, which is indistinguishable from "nothing found". `query_cve_now` is the exception: it returns an explicit `status` so the brief can say *unavailable*. Its call and its renderer are also individually wrapped in `try/except`, so a failure in this one source degrades to `SOURCE UNAVAILABLE` instead of aborting the harvest or hiding the OSV/KEV/NVD output |

## Architecture Notes

### Why parallel narrow agents over one exhaustive agent

From Cloudflare's Project Glasswing research: a single agent covering 48 patterns covers ~0.1% of a codebase's attack surface before context compaction discards earlier findings. 48 agents with one job each beat 1 agent with 48 jobs.

### Why adversarial validation

The same agent that finds a vulnerability will rationalize confirming it. A separate validator with a different prompt and more capable model that can only *disprove* catches false positives that self-review misses.

### Why gapfill

Agents drift toward attack classes they've already found success in. A hunter that finds a SQL injection will keep going deeper on that file, never reaching the `.env` file for credentials. Gapfill checks the recon doc for flagged areas that patterns missed and re-queues them with narrowed scope.

## Tests

```bash
python3 test_funnel.py                       # funnel accounting + dedupe invariants
python3 test_vulnerability_context.py        # cve.now integration invariants (offline)
```

Both are plain stdlib asserts — no test framework. `test_vulnerability_context.py` swaps
the module-level `requests` binding for a fake, so no test touches the network.

## Attribution

- **Cloudflare Project Glasswing** — harness architecture (recon → hunt → validate → gapfill → trace → feedback)
- **Trail of Bits** — code review methodology adapted into the 48 attack patterns
- **WooYun** — 88,636 real vulnerability cases from [tanweai/wooyun-legacy](https://github.com/tanweai/wooyun-legacy). The sql-injection pattern is supplemented with bypass techniques from this knowledge base.
- **DataDog GuardDog** — supply chain behavior analysis methodology (arXiv 2603.27549)
- **NodeSecure** — AST-level JavaScript analysis methodology
- **OSV** — Open Source Vulnerabilities database (Google/OpenSSF)
- **cve.now** (Sazabi) — merged vulnerability catalog, CC-BY 4.0 summaries
- **CISA KEV** — Known Exploited Vulnerabilities catalog

## License

MIT
