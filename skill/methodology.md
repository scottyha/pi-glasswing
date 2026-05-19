# Web Vulnerability Audit Methodology

Detailed phase-by-phase workflow for application-level security analysis.

---

## Phase 0: Attack Surface Triage

**Goal:** Map every entry point where untrusted data enters the system, and every exit point where sensitive data leaves.

### 0.1 Enumerate All HTTP Endpoints

```bash
# Next.js API routes
find . -path '*/api/*' -name 'route.ts' -o -name 'route.js'

# Next.js page routes
find . -path '*/app/*' -name 'page.tsx' -o -name 'page.ts'

# Server actions
grep -r "use server" --include="*.ts" --include="*.tsx" -l
```

For each endpoint, document:
- HTTP method(s) accepted
- Auth required? (How enforced — middleware? Per-route check? None?)
- Input sources (query params, body, headers, cookies)
- Output types (JSON, HTML, redirect, file download)
- Data stores accessed (which DB tables, which columns)
- External services called (LLM, CRM, payment, email)

### 0.2 Enumerate All External Integrations

- LLM APIs (Gemini, OpenAI) — what data is sent? What functions can the LLM call?
- CRM APIs (Zoho) — what data is pushed? Who triggers it?
- Payment providers — amount validation, idempotency
- Email services — who controls recipients? Template injection?
- Database connections — which users, which hosts, which databases

### 0.3 Enumerate All User Input Flows

- Form submissions (lead capture, skills review)
- Chat messages (free-text → LLM → DB query → response)
- URL parameters (slug-based routing, search, filters)
- File uploads (if any)
- Webhook callbacks (if any)

### 0.4 Classify Risk

Rate each entry point:

| Risk | Criteria |
|------|----------|
| HIGH | Accepts free-text user input that reaches a DB query, LLM, or external API. Handles auth, sessions, or payment data. |
| MEDIUM | Accepts structured input (selects, checkboxes). Handles business logic. New/untested endpoint. |
| LOW | Static content. Read-only with no user input. Well-tested, established endpoint. |

**Output:** Attack surface map with risk ratings. This drives Phase 1 priorities.

---

## Phase 1: Context Building

**Goal:** For every HIGH RISK component, build deep understanding of data flows, trust boundaries, and security assumptions before hunting for bugs.

**This phase is mandatory. Do not skip it.** Jumping straight to vulnerability hunting produces false positives and misses real bugs.

### 1.1 Trace Data Flows

For each HIGH RISK endpoint:

```
INPUT: [source] → [validation?] → [sanitization?] → [processing] → [storage/external call]
OUTPUT: [storage] → [query?] → [formatting?] → [response]
```

Document:
- Every point where untrusted data is transformed
- Every trust boundary crossed (client → server, server → DB, server → LLM, server → CRM)
- Every validation or sanitization step (and whether it's sufficient)
- Every external call (and what happens if it fails/misbehaves)

### 1.2 Identify Security Assumptions

For each component, explicitly state:
- "This assumes [X]" for every implicit assumption
- What happens when the assumption is violated
- Whether the assumption is enforced in code or merely assumed

Common assumptions to challenge:
- "Users can only access the form through the UI" (they can POST directly)
- "The LLM won't output harmful content" (prompt injection)
- "The DB user can only SELECT" (verify the actual GRANT statements)
- "Nginx blocks direct IP access" (verify firewall rules)
- "Rate limiting prevents abuse" (verify it's actually configured)

### 1.3 Map Privilege Boundaries

```
Public (anonymous) → Chat agent → rplit_public (SELECT only on specific tables)
Public (anonymous) → API routes → rplit_app (broader access?)
Admin (authenticated?) → Admin routes → rplit_admin (full access?)
Chat agent → Gemini API → log_lead function → chat_leads table + Zoho
```

For each boundary, verify:
- Is the boundary enforced at the code level, infra level, or both?
- What happens if one layer's enforcement fails?
- Can a lower-privilege user escalate by calling a higher-privilege endpoint?

### 1.4 Build Component Inventory

For each component, document:

| Component | Type | Input Source | Data Stores | External Calls | Risk |
|-----------|------|-------------|-------------|----------------|------|
| /api/public-chat | API route | Free-text message | PostgreSQL (vector search), Gemini API, chat_leads | Gemini, Zoho | HIGH |
| /api/admin/* | API routes | Various | PostgreSQL (all tables) | None | HIGH |
| /qualifications/[slug] | Page | URL slug | PostgreSQL (read) | None | MEDIUM |
| ... | ... | ... | ... | ... | ... |

---

## Phase 2: Vulnerability Search

**Goal:** Search for vulnerability patterns across each stack layer. Use the pattern files as checklists.

### 2.1 Per-Layer Search

For each stack layer, read the corresponding pattern file and search systematically:

| Layer | Pattern File | Search Focus |
|-------|-------------|-------------|
| Next.js | `patterns-nextjs.md` | API route auth, SSR leaks, env vars, middleware bypass |
| PostgreSQL | `patterns-postgres.md` | SQL injection, privilege escalation, pgvector abuse |
| Chat agent | `patterns-chat-agent.md` | Prompt injection, function calling abuse, data exfil |
| Infrastructure | `patterns-infra.md` | Headers, CORS, TLS, rate limiting |

### 2.2 Search Strategy

For each pattern:

1. **Find instances** using grep/find/read
2. **Classify** as potential finding or safe pattern
3. **Do NOT report yet** — potential findings go to Phase 3 for verification
4. **Document search coverage** — what you searched, what you didn't

### 2.3 Coverage Tracking

Track what you've searched:

| Pattern | Files Searched | Instances Found | Verified (Phase 3) |
|---------|---------------|-----------------|-------------------|
| SQL string interpolation | 12 query files | 3 potential | Pending |
| API route without auth check | 23 route files | 5 potential | Pending |
| ... | ... | ... | ... |

---

## Phase 3: Exploit Proof

**Goal:** For every potential finding from Phase 2, prove or disprove exploitability. A finding is only a vulnerability if you can trace the complete attack path.

### 3.1 Source → Sink Tracing

For each potential finding:

```
SOURCE: Where does attacker-controlled data enter?
  ↓
VALIDATION: What checks exist between source and sink?
  ↓
TRANSFORM: How is the data transformed before reaching the sink?
  ↓
SINK: Where does the dangerous operation occur?
  ↓
IMPACT: What concrete harm results?
```

**Key questions:**
- Can the attacker actually reach this code path? (Is it behind auth? Is it rate-limited?)
- Does the attacker control the data at the source? (Or is it server-generated?)
- Does validation actually prevent the attack? (Trace the logic, don't assume)
- Is there a bypass? (Alternative input path, encoding trick, type confusion)

### 3.2 Attack Scenario Construction

For each confirmed finding, write a concrete attack scenario:

```
ATTACK: [vulnerability type]
ATTACKER: [who — anonymous, authenticated user, admin]
ENTRY POINT: [exact URL/endpoint]
STEPS:
  1. [Specific HTTP request with parameters]
  2. [What happens in the code — reference file:line]
  3. [What the attacker gains]
EVIDENCE: [code references proving the attack path exists]
IMPACT: [specific, measurable — not "could cause issues"]
EXPLOITABILITY: EASY/MEDIUM/HARD
```

### 3.3 False Positive Elimination

For each potential finding, explicitly check:

- [ ] Is the vulnerable code actually reachable? (Dead code is not a finding)
- [ ] Does upstream validation prevent the attack? (Trace the full chain)
- [ ] Is the attacker-controlled data actually controllable? (Internal server data is not)
- [ ] Does the framework provide automatic protection? (Verify it's active, not just available)
- [ ] Is the impact real security harm? (Not just "bad practice")
- [ ] Am I seeing a pattern that "looks dangerous" or an actual vulnerability?

If any check fails → FALSE POSITIVE. Document why and move on.

### 3.4 Confidence Rating

| Confidence | Criteria |
|-----------|----------|
| CONFIRMED | Complete source→sink trace, concrete attack scenario, verified in code |
| LIKELY | Strong evidence but one step unverified (e.g., couldn't test live) |
| POSSIBLE | Suspicious pattern but validation chain unclear |
| UNLIKELY | Pattern exists but evidence suggests it's mitigated |

Only CONFIRMED and LIKELY findings go to the report. POSSIBLE findings go to an appendix.

---

## Phase 4: Variant Analysis

**Goal:** For every confirmed vulnerability, search the entire codebase for the same pattern.

### 4.1 Root Cause Extraction

For each confirmed finding, identify:
- The **root cause** (not the symptom) — e.g., "string interpolation in SQL query" not "SQL injection"
- The **abstract pattern** — what makes this instance vulnerable?
- The **generalization** — what other contexts share this pattern?

### 4.2 Systematic Search

Start with the exact pattern from the confirmed finding:
```bash
# Example: Found string interpolation in SQL
grep -rn "query\|execute\|raw" --include="*.ts" --include="*.js" | grep -i "select\|insert\|update\|delete"
```

Then generalize ONE element at a time:
1. Exact match → verify it finds only the original instance
2. Generalize variable names → find more instances
3. Generalize context → find in different files/modules
4. Stop when false positive rate exceeds ~50%

### 4.3 Triage Variants

For each new instance found:
- Same root cause? → Same vulnerability class
- Same reachability? → May differ (behind auth, different endpoint)
- Same impact? → May differ (different data exposed)
- Classify as: SAME VULNERABILITY | NEW VARIANT | FALSE POSITIVE

### 4.4 Cross-Layer Variants

A vulnerability in one layer may have variants in another:
- SQL injection in Next.js API route → same pattern in chat agent's DB queries?
- Missing auth check on API route → same pattern on Server Actions?
- Prompt injection in chat agent → same pattern in admin-facing LLM features?

---

## Phase 5: Report

**Goal:** Produce a structured, actionable report that a developer can use to fix every finding.

### Report Structure

```markdown
# Web Vulnerability Audit Report
**Date:** [today]
**Target:** [application URL / codebase]
**Scope:** [what was audited — endpoints, components, layers]
**Coverage:** [what was NOT audited — acknowledged gaps]

## Executive Summary
[3-5 sentences: overall posture, most urgent issues, recommended immediate actions]

## 🔴 Critical Findings
[Actively exploitable — attacker can cause real harm RIGHT NOW]

## 🟠 High Priority
[Exploitable under specific conditions — fix before launch]

## 🟡 Medium Priority
[Reduces attack surface — fix in next sprint]

## 🟢 Low Priority / Hardening
[Defense in depth — best practice improvements]

## Findings Detail

### [SEVERITY] [Title]

**Class:** [OWASP category / CWE]
**Location:** [file:line]
**Confidence:** CONFIRMED / LIKELY / POSSIBLE
**Exploitability:** EASY / MEDIUM / HARD

**Description:** [what the vulnerability is, in plain language]

**Attack Scenario:**
[Concrete steps from Phase 3]

**Source → Sink Trace:**
[Data flow from Phase 3]

**Variants:** [N instances found across codebase — see variant table]

**Remediation:**
[Specific fix with code example]

**References:** [CWE, OWASP, relevant docs]

## Variant Analysis Summary

| Original Finding | Variants Found | Locations | Risk |
|-----------------|---------------|-----------|------|

## Coverage & Limitations

| Area | Audited | Not Audited | Reason |
|------|---------|-------------|--------|
| Next.js API routes | 23/23 | — | Full coverage |
| Admin pages | 0/8 | 8 | No admin credentials available |
| ... | ... | ... | ... |

## Methodology
[Which phases completed, strategy used, confidence assessment]
```

### Report File

Save to: `~/web-vuln-audit-YYYY-MM-DD.md`
