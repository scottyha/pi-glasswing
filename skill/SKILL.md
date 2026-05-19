---
name: web-vuln-audit
description: >
  In-depth vulnerability analysis for web applications. Context-first methodology
  adapted from Trail of Bits — maps attack surface, traces data flows source→sink,
  proves exploitability before reporting, and runs variant analysis to find all
  instances of confirmed bugs. Designed for Next.js + PostgreSQL + LLM chat agent
  stacks but applicable to any web application.
---

# Web Vulnerability Audit

Application-level security audit for web applications. Finds real vulnerabilities
by tracing data flows from source to sink, proving exploitability, and hunting
variants — not by pattern-matching on scary-looking code.

## Core Principles

1. **Context before hunting.** Map the attack surface and trace data flows *before* looking for bugs. Blind hunting produces false positives.
2. **Prove exploitability.** A suspicious pattern is not a vulnerability until you trace attacker control, reachability, and impact. Source → sink, end to end.
3. **Variant analysis.** One confirmed bug triggers systematic search for the same pattern everywhere. One SQLi → check every query.
4. **Fail-secure defaults.** `env.get('KEY') or 'default'` is CRITICAL. `env['KEY']` is safe. The difference is whether the app runs insecurely or crashes.
5. **Honest reporting.** Explicitly state coverage limits, confidence level, and what you didn't test. Unconfirmed findings are marked as such.

---

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "This pattern looks dangerous" | Pattern recognition ≠ analysis | Complete data flow tracing before any conclusion |
| "Small change, quick review" | Heartbleed was 2 lines | Classify by RISK, not size |
| "The framework handles it" | Frameworks have gaps, misconfigurations, and bypass paths | Verify the framework protection is actually active |
| "It's behind auth" | Auth has bugs. Sessions can be hijacked. Defense in depth. | Analyze as if auth is compromised |
| "We'll fix it later" | "Later" never comes in production | Document now with severity |
| "I'll just scan for OWASP Top 10" | Checklist compliance ≠ security | Trace actual data flows in THIS codebase |
| "This is probably validated upstream" | "Probably" is not evidence | Trace the full validation chain |
| "The chat agent prompt says not to" | Prompt instructions are not security boundaries | Treat LLM instructions as adversary-resistant, not adversary-proof |
| "It's internal-only" | Internal becomes external. Tailscale route gets exposed. CORS gets opened. | Analyze as if the network boundary will fail |

---

## Quick Reference

### Risk Classification

| Risk Level | Triggers |
|------------|----------|
| HIGH | Auth, session handling, DB queries with user input, LLM function calling, payment/lead data, external API calls |
| MEDIUM | Business logic, state transitions, new public endpoints, CORS, rate limiting |
| LOW | Logging, comments, static assets, UI-only changes |

### Stack Layers

| Layer | Pattern File | Key Risks |
|-------|-------------|-----------|
| Next.js application | `patterns-nextjs.md` | API route auth, SSR data leaks, env var exposure, middleware bypass |
| PostgreSQL | `patterns-postgres.md` | SQL injection, privilege escalation, pgvector abuse, connection leaks |
| LLM chat agent | `patterns-chat-agent.md` | Prompt injection, function calling abuse, data exfiltration, vector search manipulation |
| Infrastructure (nginx, headers, TLS) | `patterns-infra.md` | Missing headers, CORS misconfigs, TLS gaps, rate limiting |

---

## Workflow

```
Phase 0: Attack Surface Triage
    ↓
Phase 1: Context Building (per HIGH RISK component)
    ↓
Phase 2: Vulnerability Search (per stack layer)
    ↓
Phase 3: Exploit Proof (source → sink tracing)
    ↓
Phase 4: Variant Analysis (confirmed bug → systematic search)
    ↓
Phase 5: Report
```

**Phases are a state machine. No skipping.** If Phase 1 reveals no HIGH RISK components, document that and proceed to Phase 2 with MEDIUM risk components. But you must complete each phase.

---

## Decision Tree

```
├─ Starting an audit?
│  └─ Read: methodology.md
│     (All 6 phases: triage → context → search → prove → variants → report)
│
├─ Looking for specific vulnerability patterns?
│  ├─ Next.js app? → Read: patterns-nextjs.md
│  ├─ PostgreSQL? → Read: patterns-postgres.md
│  ├─ LLM chat agent? → Read: patterns-chat-agent.md
│  └─ Infrastructure? → Read: patterns-infra.md
│
├─ Need to verify a suspected finding?
│  └─ Apply Phase 3 (Exploit Proof) from methodology.md
│     Trace source → sink. No shortcuts.
│
└─ Want to understand the reasoning behind the methodology?
   └─ Read: rationalizations.md
```

---

## Quality Checklist

Before delivering:

- [ ] All HIGH RISK components have context built (Phase 1)
- [ ] Every finding traces source → sink with line numbers
- [ ] Every finding has a concrete attack scenario (not theoretical)
- [ ] Variant analysis run for every confirmed finding
- [ ] False positives explicitly identified and documented
- [ ] Coverage limits stated (what you didn't test)
- [ ] Confidence level assigned to each finding
- [ ] Report saved to file

---

## When NOT to Use This Skill

- **Infrastructure security** (VPS, firewall, SSH, Cloudflare zones) — use `security-audit-agent` instead
- **Dependency CVE scanning** — use `npm audit` or Snyk, then apply Phase 3 to confirm exploitability
- **Performance testing** — not a security concern (unless DoS vector)
- **Compliance auditing** (ASQA, PCI-DSS) — different methodology, different output

---

## When to Use This Skill

- Pre-launch security review of a web application
- After significant code changes to auth, payment, or data handling
- When adding a new public-facing endpoint or API route
- When integrating a third-party service (LLM, payment provider, CRM)
- When onboarding to a codebase and need to assess security posture
- After a suspected security incident (how did they get in?)
