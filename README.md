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
| **Intel** | N/A (API queries) | — | Harvests live vulnerabilities from OSV, GitHub Advisories, CISA KEV, NVD, npm audit, Scorecard |
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
| **OSV** | All known CVEs for your exact dependencies (30+ ecosystems) |
| **GitHub Advisory API** | Fresh advisories modified in last 24h |
| **CISA KEV** | Actively exploited CVEs — the urgency filter |
| **NVD** | Fresh CVEs published in last 24h |
| **npm Audit** | Registry-level npm vulnerability lookup |
| **OpenSSF Scorecard** | Project security posture (public repos only) |
| **OpenSSF Malicious Packages** | Confirmed malicious package records (MAL-* IDs via OSV) |

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

## Project Structure

```
~/projects/pi-glasswing/
├── harness.py                   ← main pipeline orchestrator
├── vulnerability_context.py     ← live intel harvester
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

## Architecture Notes

### Why parallel narrow agents over one exhaustive agent

From Cloudflare's Project Glasswing research: a single agent covering 48 patterns covers ~0.1% of a codebase's attack surface before context compaction discards earlier findings. 48 agents with one job each beat 1 agent with 48 jobs.

### Why adversarial validation

The same agent that finds a vulnerability will rationalize confirming it. A separate validator with a different prompt and more capable model that can only *disprove* catches false positives that self-review misses.

### Why gapfill

Agents drift toward attack classes they've already found success in. A hunter that finds a SQL injection will keep going deeper on that file, never reaching the `.env` file for credentials. Gapfill checks the recon doc for flagged areas that patterns missed and re-queues them with narrowed scope.

## Attribution

- **Cloudflare Project Glasswing** — harness architecture (recon → hunt → validate → gapfill → trace → feedback)
- **Trail of Bits** — code review methodology adapted into the 48 attack patterns
- **WooYun** — 88,636 real vulnerability cases from [tanweai/wooyun-legacy](https://github.com/tanweai/wooyun-legacy). The sql-injection pattern is supplemented with bypass techniques from this knowledge base.
- **DataDog GuardDog** — supply chain behavior analysis methodology (arXiv 2603.27549)
- **NodeSecure** — AST-level JavaScript analysis methodology
- **OSV** — Open Source Vulnerabilities database (Google/OpenSSF)
- **CISA KEV** — Known Exploited Vulnerabilities catalog

## License

MIT
