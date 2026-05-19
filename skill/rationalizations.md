# Rationalizations to Reject

Adapted from Trail of Bits' approach to preventing AI analysis shortcuts. These are the mental traps that produce false positives (reporting non-vulnerabilities) and false negatives (missing real vulnerabilities).

When performing a web vulnerability audit, explicitly check yourself against these rationalizations. If you catch yourself thinking any of them, stop and apply the required action.

---

## False Positive Rationalizations (Over-Reporting)

These lead to reporting things that aren't actually vulnerabilities.

| # | Rationalization | Why It's Wrong | Required Action |
|---|-----------------|----------------|-----------------|
| 1 | "This pattern looks dangerous" | Pattern recognition is not analysis. A `SELECT *` query on a public table is not a vulnerability. A string-interpolated SQL query on trusted internal data is not exploitable. | Complete data flow tracing from source to sink before concluding anything |
| 2 | "The code doesn't validate input" | Validation may exist upstream — in middleware, in the calling function, in the framework's routing layer | Trace the COMPLETE validation chain, not just the immediate function |
| 3 | "This endpoint has no auth" | Not every endpoint needs auth. Public APIs are public by design. | Verify the endpoint is MEANT to be protected before flagging |
| 4 | "It's using MD5/SHA1" | Not all hashing is security-sensitive. Cache keys, content addressing, and deduplication don't need cryptographic hashes | Check whether the hash is used for security (passwords, signatures, tokens) vs. non-security (caching, dedup, ETags) |
| 5 | "CORS allows any origin" | Public APIs may legitimately need cross-origin access. Internal APIs that are Tailscale-only don't need CORS at all. | Assess CORS in the context of what data the endpoint returns and who should access it |
| 6 | "I found a vulnerability" | LLMs are biased toward finding bugs. The bias is toward ACTION, not accuracy. | Apply Phase 3 (Exploit Proof) rigorously. Prove it or don't report it. |
| 7 | "Similar code was vulnerable elsewhere" | Each context has different validation, callers, and protections. The same pattern in two different endpoints may be safe in one and vulnerable in the other. | Verify this specific instance independently |
| 8 | "The OWASP Top 10 says this is bad" | Checklist compliance without context produces noise. Injection requires attacker control + reachability + impact, not just string concatenation. | Trace the actual data flow in THIS codebase, not generic threat models |

---

## False Negative Rationalizations (Under-Reporting)

These lead to dismissing things that ARE actually vulnerabilities.

| # | Rationalization | Why It's Wrong | Required Action |
|---|-----------------|----------------|-----------------|
| 9 | "The framework handles it" | Frameworks have gaps. Next.js middleware can be bypassed. ORM parameterization doesn't protect dynamic table names. Auto-escaping can be disabled. | Verify the framework protection is actually active and not bypassable |
| 10 | "It's behind authentication" | Auth has bugs. Sessions can be hijacked. Tokens can leak. An auth bypass makes every "behind auth" vulnerability critical. | Analyze HIGH RISK code as if auth is compromised (defense in depth) |
| 11 | "The LLM prompt prevents it" | Prompt instructions are not security boundaries. They are adversary-resistant at best, not adversary-proof. A determined attacker will bypass them. | Treat prompt instructions as a thin layer. The REAL boundary is the DB user, network firewall, and API permissions |
| 12 | "It's internal-only" | Internal becomes external. Network boundaries get relaxed for convenience. Tailscale routes get exposed. CORS gets opened to `*` for "testing." | Analyze as if the network boundary WILL fail. What's the blast radius? |
| 13 | "Nobody would think to attack this" | Attackers are creative and automated. Obfuscation is not security. If it's reachable, assume it will be found. | Evaluate by reachability and exploitability, not by obscurity |
| 14 | "The impact seems low" | Low-impact findings can chain into high-impact attacks. An information leak that reveals admin email + a password reset flow = account takeover. | Assess impact in the context of the full attack surface, not in isolation |
| 15 | "We'll fix it later" | "Later" in production means "never." Findings that are documented get fixed. Findings that are dismissed get exploited. | Document with severity. Even LOW findings go in the report |
| 16 | "I'm probably overthinking this" | You might be. But verify before dismissing. If you've traced the data flow and it's safe, document WHY it's safe (so the next auditor doesn't re-discover it). | If suspicious, trace it. If safe, document it. Never dismiss without evidence |

---

## Process Rationalizations (Cutting Corners)

These lead to incomplete analysis.

| # | Rationalization | Why It's Wrong | Required Action |
|---|-----------------|----------------|-----------------|
| 17 | "I'll just scan for OWASP Top 10" | Checklist scanning finds checklist vulnerabilities. Real vulnerabilities emerge from understanding the specific codebase's data flows and trust boundaries. | Use the pattern files as a starting point, not an ending point. Trace actual data flows |
| 18 | "Context building takes too long" | Rushed context = hallucinated vulnerabilities. The hour you spend understanding data flows saves the day you spend chasing false positives. | Complete Phase 1 for every HIGH RISK component. No exceptions |
| 19 | "Variant analysis is overkill for this one finding" | One SQL injection means every query needs checking. One missing auth check means every route needs checking. The variant is always more important than the original. | Run Phase 4 for every confirmed finding |
| 20 | "I don't need to check the nginx config, the app handles it" | Defense in depth. nginx is the outermost layer. If it's misconfigured, the app's protections may be bypassable (e.g., serving .env files, missing HSTS, no rate limiting) | Check every layer independently |
| 21 | "I'll explain verbally" | No artifact = findings lost. Chat history scrolls away. The next person to look at this needs a written report with line numbers and evidence. | Always write the Phase 5 report. Save it to a file |
| 22 | "The DB user is restricted, so I don't need to check queries" | The DB user restriction is ONE layer. If it's misconfigured (too many GRANTs), or if there's a privilege escalation path, all your assumptions are wrong. | Verify the DB user permissions independently, THEN use them as a defense-in-depth layer |

---

## How to Use This Table

1. **Before starting:** Read the full table once. Internalise the patterns.
2. **During analysis:** When you catch yourself thinking any rationalization, stop, look it up, and apply the required action.
3. **After analysis:** Review your findings against the false-negative rationalizations (9-16). Did you dismiss anything you shouldn't have?
4. **In the report:** If a finding relies on rejecting a common rationalization, note it (e.g., "While this endpoint is behind auth, the auth implementation has known gaps — see Finding #3").

---

## The Meta-Rationalization

> "I don't need to check myself against rationalizations — I'm being careful"

This is the most dangerous rationalization of all. The entire point of this table is that careful people still take shortcuts. The act of explicitly checking yourself IS the safety mechanism.

If you skipped reading this table and jumped to the methodology, go back and read it now.
