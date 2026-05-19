#!/usr/bin/env python3
"""
Vulnerability Discovery Harness

Orchestrates parallel pi sessions for deep vulnerability analysis.
Architecture adapted from Cloudflare's Project Glasswing harness:
  Recon → Hunt (batched parallel) → Validate → Dedupe → Report

Each hunt task is a fresh pi session with full context window dedicated
to one attack pattern. This avoids the context compaction problem where
a single agent covering 44 patterns loses earlier findings by pattern #30.

Usage:
    python3 harness.py <repo-path> [--batch-size 8] [--patterns xss,sql-injection]
    python3 harness.py <repo-path> --validate-only findings.json
    python3 harness.py <repo-path> --full-pipeline

Pi invocation modes:
    - Print mode (pi -p): simplest, returns plain text. Good for recon.
    - JSON mode (pi --mode json): structured event stream. Good for hunt/validate
      where we need to parse the final assistant message from agent_end events.
    - RPC mode (pi --mode rpc): bidirectional JSONL. Overkill for one-shot tasks,
      but useful if we need steering/follow-up control.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

SKILL_DIR = Path(__file__).resolve().parent / "skill"
WOOYUN_DIR = Path(__file__).resolve().parent / "wooyun-categories"
RESULTS_DIR = Path(__file__).resolve().parent / "results"

BATCH_SIZE = 8          # concurrent pi sessions
PI_TIMEOUT = 600        # seconds per session (10 min)
PI_MODE = "json"        # "print" for plain text, "json" for structured events

# Models + thinking — hunters can be cheaper/faster, validators should think deeper
HUNTER_MODEL = "deepseek/deepseek-v4-flash:low"
RECON_MODEL = "deepseek/deepseek-v4-flash:medium"
VALIDATOR_MODEL = "deepseek/deepseek-v4-pro:high"
# Thinking levels: off, minimal, low, medium, high, xhigh
# Model shorthand: "provider/model:thinking" e.g. "deepseek/deepseek-v4-flash:low"

# ── Attack Patterns (from web-vuln-audit skill) ──────────────────────────────

PATTERNS = {
    # Next.js patterns (12)
    "missing-auth":              {"layer": "nextjs",      "name": "Missing Auth Check"},
    "middleware-bypass":          {"layer": "nextjs",      "name": "Middleware Bypass"},
    "server-component-leak":     {"layer": "nextjs",      "name": "Server Component Data Leak"},
    "client-secrets":            {"layer": "nextjs",      "name": "Client-Exposed Secrets"},
    "fail-open-defaults":        {"layer": "nextjs",      "name": "Fallback Default Secrets (Fail-Open)"},
    "unvalidated-server-action": {"layer": "nextjs",      "name": "Unvalidated Server Action Input"},
    "server-action-no-auth":     {"layer": "nextjs",      "name": "Server Action Without Auth"},
    "error-state-leak":          {"layer": "nextjs",      "name": "Error Messages Leaking Internal State"},
    "debug-in-prod":             {"layer": "nextjs",      "name": "Debug Info in Production"},
    "path-traversal":            {"layer": "nextjs",      "name": "Path Traversal via Dynamic Segments"},
    "open-redirect":             {"layer": "nextjs",      "name": "Open Redirect"},
    "ssrf-image-loader":         {"layer": "nextjs",      "name": "SSRF via Next.js Image Loader"},
    # PostgreSQL patterns (10)
    "sql-injection":             {"layer": "postgres",    "name": "String Interpolation in Queries",    "wooyun": "sql-injection.md"},
    "dynamic-table-names":       {"layer": "postgres",    "name": "Dynamic Table/Column Names"},
    "over-privileged-db-user":   {"layer": "postgres",    "name": "Over-Privileged Database Users"},
    "connection-string-leak":    {"layer": "postgres",    "name": "Connection String in Client Bundle"},
    "embedding-manipulation":    {"layer": "postgres",    "name": "Embedding Manipulation"},
    "vector-query-injection":    {"layer": "postgres",    "name": "Vector Query Injection"},
    "unclosed-connections":      {"layer": "postgres",    "name": "Unclosed Connections"},
    "select-star-leak":          {"layer": "postgres",    "name": "SELECT * Leaking Sensitive Columns"},
    "missing-rls":              {"layer": "postgres",    "name": "Missing Row-Level Filtering"},
    "race-condition-leads":     {"layer": "postgres",    "name": "Race Conditions in Lead Capture"},
    # Chat agent patterns (10)
    "prompt-extraction":         {"layer": "chat-agent",  "name": "System Prompt Extraction"},
    "indirect-prompt-injection": {"layer": "chat-agent",  "name": "Indirect Prompt Injection via RAG"},
    "multi-turn-injection":      {"layer": "chat-agent",  "name": "Multi-Turn Prompt Injection"},
    "data-injection":            {"layer": "chat-agent",  "name": "log_lead Data Injection"},
    "unauthorized-function-call":{"layer": "chat-agent",  "name": "Unauthorized Function Invocation"},
    "llm-as-oracle":            {"layer": "chat-agent",  "name": "LLM as Oracle for Database Content"},
    "response-leakage":         {"layer": "chat-agent",  "name": "Response Content Leakage"},
    "expensive-vector-abuse":   {"layer": "chat-agent",  "name": "Expensive Vector Search Abuse"},
    "context-exhaustion":       {"layer": "chat-agent",  "name": "Context Window Exhaustion"},
    "unsanitised-input":        {"layer": "chat-agent",  "name": "Unsanitised Chat Input"},
    # Infrastructure patterns (12)
    "missing-headers":          {"layer": "infra",       "name": "Missing Security Headers"},
    "weak-csp":                 {"layer": "infra",       "name": "Weak Content-Security-Policy"},
    "permissive-cors":          {"layer": "infra",       "name": "Overly Permissive CORS"},
    "missing-cors-public":      {"layer": "infra",       "name": "Missing CORS for Public API"},
    "weak-tls":                 {"layer": "infra",       "name": "Weak TLS Settings"},
    "mixed-content":            {"layer": "infra",       "name": "Mixed Content"},
    "server-info-disclosure":   {"layer": "infra",       "name": "Server Information Disclosure"},
    "sensitive-files":          {"layer": "infra",       "name": "Sensitive Files Accessible"},
    "missing-rate-limit":       {"layer": "infra",       "name": "Missing Rate Limiting"},
    "proxying-internal":        {"layer": "infra",       "name": "Proxying Internal Services"},
    "insecure-cookies":         {"layer": "infra",       "name": "Insecure Cookie Flags"},
    "origin-ip-exposed":        {"layer": "infra",       "name": "Origin IP Exposed"},
}

# Layer → skill pattern file mapping
LAYER_FILES = {
    "nextjs":      SKILL_DIR / "patterns-nextjs.md",
    "postgres":    SKILL_DIR / "patterns-postgres.md",
    "chat-agent":  SKILL_DIR / "patterns-chat-agent.md",
    "infra":       SKILL_DIR / "patterns-infra.md",
}

# ── Pi Invocation Helpers ────────────────────────────────────────────────────

def build_pi_cmd(prompt: str, repo_path: str, mode: str = None, 
                  model: str = None, tools: str = None, 
                  no_session: bool = True, no_context_files: bool = False) -> list[str]:
    """
    Build a pi CLI command.
    
    Modes:
      - "print":  pi -p "prompt" → plain text output, exits immediately
      - "json":   pi --mode json "prompt" → JSONL event stream on stdout
      - "rpc":    pi --mode rpc → bidirectional JSONL (use run_rpc_session instead)
    
    Key flags:
      --no-session:       ephemeral, don't save session files
      --no-context-files:  skip AGENTS.md loading (faster start, but loses project context)
      --tools <list>:      restrict to specific tools only
      --model <pattern>:   model override (e.g. "deepseek/deepseek-v4-flash")
      @<file>:             include file contents in the prompt
    """
    cmd = ["pi"]
    
    # Mode
    m = mode or PI_MODE
    if m == "print":
        cmd.append("-p")
    elif m == "json":
        cmd.extend(["--mode", "json"])
    
    # Session
    if no_session:
        cmd.append("--no-session")
    
    # Context files
    if no_context_files:
        cmd.append("--no-context-files")
    
    # Model (supports provider/model:thinking shorthand)
    if model:
        cmd.extend(["--model", model])
    
    # Tools
    if tools:
        cmd.extend(["--tools", tools])
    
    # The prompt (positional argument — must come last)
    cmd.append(prompt)
    
    return cmd


def run_pi_print(prompt: str, repo_path: str, model: str = None, 
                  tools: str = None, timeout: int = PI_TIMEOUT) -> dict:
    """
    Run pi in print mode (-p). Returns plain text output.
    Simplest invocation — just the response text, no structure.
    """
    cmd = build_pi_cmd(prompt, repo_path, mode="print", model=model, tools=tools)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_path,
        )
        return {
            "success": result.returncode == 0,
            "output": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}
# ── Prompt Templates ─────────────────────────────────────────────────────────

RECON_PROMPT = """You are a security researcher performing reconnaissance on a codebase.

Repository: {repo_path}

Produce an architecture document covering:
1. **Build commands** — how to build/run the project
2. **Trust boundaries** — where untrusted data enters, where trusted data is expected
3. **Entry points** — all public-facing endpoints (API routes, pages, Server Actions, WebSocket handlers)
4. **Attack surface map** — grouped by layer (Next.js app, PostgreSQL, LLM/chat agent, Infrastructure)
5. **Technology stack** — frameworks, databases, external services, LLM integrations
6. **Authentication flows** — how users auth, session management, role system
7. **Data classification** — what sensitive data exists and where it flows
8. **Notable Security-Relevant Findings** — highlight specific files, endpoints, or code paths that seem risky (e.g., exposed .env files, inline SQL, missing auth checks, insecure cookies, proxying internal ports). Gapfill stages depend on this section.

Be exhaustive. This document will be shared with 44+ specialized vulnerability hunters.
Each hunter depends on this context to do their job.

Output as structured markdown."""

HUNT_PROMPT = """You are a vulnerability hunter. You have ONE job: find instances of a specific vulnerability pattern.

## Shared Context (Architecture Recon)
{recon_doc}

## Your Assignment
**Pattern:** {pattern_name}
**Layer:** {layer}

## Pattern Knowledge
{pattern_knowledge}

{wooyun_knowledge}

## Instructions
1. Search the codebase at {repo_path} for this specific vulnerability pattern
2. For each finding, trace the COMPLETE data flow: source → sink
3. Classify confidence: CONFIRMED (full source→sink trace), SUSPECTED (partial trace), or SPECULATIVE (pattern match only)
4. For CONFIRMED findings, describe the concrete attack scenario
5. DO NOT report findings for patterns other than your assigned one
6. If you find nothing, say so explicitly — "No findings" is a valid and valued result

Output as structured JSON:
```json
{{
  "pattern": "{pattern_id}",
  "findings": [
    {{
      "id": "F-{pattern_id}-001",
      "confidence": "CONFIRMED|SUSPECTED|SPECULATIVE",
      "location": "file:line",
      "source": "where attacker input enters",
      "sink": "where the vulnerability triggers",
      "attack_scenario": "concrete attack scenario",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }}
  ]
}}
```"""

VALIDATE_PROMPT = """You are a vulnerability validator. Your job is to DISPROVE findings, not confirm them.

You will receive a vulnerability finding. You must attempt to prove it is FALSE.

## Shared Context
{recon_doc}

## Finding to Validate
{finding}

## Your Task
1. Re-read the code at the specified location
2. Check if the claimed source→sink trace is actually reachable
3. Check if framework protections, middleware, or other safeguards block the attack
4. Check if the "attacker-controlled input" is actually attacker-controlled
5. If you CANNOT disprove it, say "UPHELD" with your reasoning
6. If you CAN disprove it, say "REJECTED" with your reasoning

You are NOT allowed to propose new findings. You can only validate or reject.

Output:
```
VERDICT: UPHELD or REJECTED
REASONING: ...
```"""


# ── Stage Implementations ────────────────────────────────────────────────────

GAPFILL_PROMPT = """You are a vulnerability hunter on a SECOND PASS. Your first pass found nothing for your assigned pattern. You now have narrowed scope from the architecture recon doc.

## Shared Context (Architecture Recon)
{recon_doc}

## Your Assignment
**Pattern:** {pattern_name}
**Layer:** {layer}

## Recon Doc Flagged These Areas for Your Pattern
{recon_clues}

## What Changed From Your First Pass
Your first pass covered the codebase broadly and found nothing. The recon doc above has specific findings that relate to your pattern. Re-examine ONLY the specific files, endpoints, or code paths mentioned in the recon clues. Do not re-scan the entire codebase.

## Pattern Knowledge
{pattern_knowledge}

{wooyun_knowledge}

## Instructions
1. Focus ONLY on the specific areas mentioned in the recon clues above
2. For each finding, trace the COMPLETE data flow: source → sink
3. Classify confidence: CONFIRMED (full source→sink trace), SUSPECTED (partial trace), or SPECULATIVE
4. If you find nothing again, say so explicitly

Output as structured JSON:
```json
{{
  "pattern": "{pattern_id}",
  "findings": [
    {{
      "id": "GF-{pattern_id}-001",
      "confidence": "CONFIRMED|SUSPECTED|SPECULATIVE",
      "location": "file:line",
      "source": "where attacker input enters",
      "sink": "where the vulnerability triggers",
      "attack_scenario": "concrete attack scenario",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }}
  ]
}}
```"""


def stage_intel(repo_path: str, hours: int = 24) -> str:
    """Phase -1: Harvest live vulnerability intel from free APIs.
    Produces a context brief that feeds into recon and hunt stages."""
    from vulnerability_context import harvest
    brief = harvest(repo_path, hours=hours)
    return brief


def stage_recon(repo_path: str, live_context: str = "") -> str:
    """Phase 0-1: Attack surface triage + context building. Single pi session."""
    print("═══ STAGE 0-1: RECON ═══")
    
    # Inject live intel into recon prompt if available
    intel_section = ""
    if live_context:
        intel_section = f"""
## Live Vulnerability Intel (automatically fetched)
{live_context}

Use this intel alongside your architecture analysis. Cross-reference any CVEs
against the codebase's actual dependency versions.
"""
    
    prompt = RECON_PROMPT.format(repo_path=repo_path) + intel_section
    
    # Recon uses print mode — we just want the text. Read-only tools for safety.
    result = run_pi_print(prompt, repo_path, model=RECON_MODEL, tools="read,grep,find,ls", timeout=900)
    
    if not result["success"]:
        print(f"  ✗ Recon failed: {result.get('error', result.get('stderr', 'unknown'))}")
        sys.exit(1)
    
    recon_doc = result["output"]
    
    # Save recon doc
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    recon_path = RESULTS_DIR / f"recon-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    recon_path.write_text(recon_doc)
    print(f"  ✓ Recon complete — saved to {recon_path}")
    print(f"  ✓ Doc size: {len(recon_doc):,} chars")
    
    return recon_doc


def stage_hunt(repo_path: str, recon_doc: str, patterns: list[str] = None, 
               batch_size: int = BATCH_SIZE, live_context: str = "") -> list[dict]:
    """Phase 2: Fan out parallel hunt agents, one per attack pattern."""
    
    # Determine which patterns to run
    if patterns:
        pattern_ids = [p for p in PATTERNS if p in patterns]
        unknown = set(patterns) - set(pattern_ids)
        if unknown:
            print(f"  ⚠ Unknown patterns skipped: {unknown}")
    else:
        pattern_ids = list(PATTERNS.keys())
    
    print(f"\n═══ STAGE 2: HUNT — {len(pattern_ids)} patterns in batches of {batch_size} ═══")
    
    # Load and cache pattern knowledge files by layer
    layer_knowledge_cache = {}
    for pid in pattern_ids:
        pinfo = PATTERNS[pid]
        layer = pinfo["layer"]
        if layer not in layer_knowledge_cache:
            layer_file = LAYER_FILES[layer]
            if not layer_file.exists():
                print(f"  ⚠ WARNING: Knowledge file missing: {layer_file}")
                print(f"             Agents will hunt {layer} patterns without specialized context.")
            layer_knowledge_cache[layer] = layer_file.read_text() if layer_file.exists() else ""
    
    # Build hunt items
    hunt_items = []
    for pid in pattern_ids:
        pinfo = PATTERNS[pid]
        layer = pinfo["layer"]
        
        # Extract just the relevant pattern section from the layer file
        full_layer = layer_knowledge_cache.get(layer, "")
        pattern_section = extract_pattern_section(full_layer, pinfo["name"])
        
        # WooYun supplementary knowledge (excerpt only — these files are huge)
        wooyun_knowledge = ""
        if pinfo.get("wooyun"):
            wooyun_file = WOOYUN_DIR / pinfo["wooyun"]
            if wooyun_file.exists():
                # First 5K chars — enough for the technique overview without blowing context
                wooyun_raw = wooyun_file.read_text()[:5000]
                wooyun_knowledge = (
                    f"\n## Supplementary Bypass Techniques (from WooYun {pinfo['wooyun']})\n"
                    f"{wooyun_raw}\n...(truncated, full file is {wooyun_file.stat().st_size // 1024}KB)\n"
                )
        
        prompt = HUNT_PROMPT.format(
            recon_doc=recon_doc,
            pattern_id=pid,
            pattern_name=pinfo["name"],
            layer=layer,
            pattern_knowledge=pattern_section,
            wooyun_knowledge=wooyun_knowledge,
            repo_path=repo_path,
        )
        
        # Inject live intel if available
        if live_context:
            prompt += f"""\n\n## Live Vulnerability Intel\n{live_context[:8000]}\n\nCross-reference these CVEs against your assigned pattern.\nIf a dependency has a known CVE matching your pattern, verify it's patched.\n"""
        
        hunt_items.append({
            "pattern_id": pid,
            "prompt": prompt,
            "repo": repo_path,
        })
    
    # Run in batches
    hunt_results = run_batch(hunt_items, batch_size)
    
    # Parse findings from each result
    all_findings = []
    for result in hunt_results:
        entry = {"pattern_id": result["pattern_id"], "findings": [], "error": None}
        
        if not result["success"]:
            entry["error"] = result.get("error", "unknown")
        else:
            findings = parse_findings(result["output"], result["pattern_id"])
            entry["findings"] = findings
            count = len(findings)
            status = f"🎯 {count} findings" if count else "✓ clean"
            print(f"    {status}: {result['pattern_id']}")
        
        all_findings.append(entry)
    
    # Save raw hunt results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    hunt_path = RESULTS_DIR / f"hunt-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    hunt_path.write_text(json.dumps(all_findings, indent=2))
    print(f"\n  ✓ Hunt results saved to {hunt_path}")
    
    return all_findings


def stage_gapfill(repo_path: str, recon_doc: str, hunt_results: list[dict],
                  live_context: str = "", batch_size: int = BATCH_SIZE) -> list[dict]:
    """Phase 2.5: Gapfill — re-queue patterns that returned zero findings
    but have relevant coverage in the recon doc's notable findings.
    
    Cloudflare observed that hunters drift toward attack classes they've already
    had success with, leaving other patterns poorly covered. This stage performs
    a second pass with narrowed scope for empty patterns.
    """
    # Find patterns with zero findings
    empty_patterns = [r for r in hunt_results if not r.get("findings") and not r.get("error")]
    if not empty_patterns:
        print("\n═══ STAGE 2.5: GAPFILL — No empty patterns to re-queue ═══")
        return hunt_results
    
    # Extract Notable Security-Relevant Findings from recon doc
    notable_section = _extract_notable_findings(recon_doc)
    if not notable_section:
        print("\n═══ STAGE 2.5: GAPFILL — No notable findings section in recon doc ═══")
        return hunt_results
    
    # Map patterns to relevant recon clues
    pattern_clues = _map_recon_to_patterns(empty_patterns, notable_section)
    patterns_to_requeue = {pid: clues for pid, clues in pattern_clues.items() if clues.strip()}
    
    if not patterns_to_requeue:
        print("\n═══ STAGE 2.5: GAPFILL — No recon clues matched empty patterns ═══")
        return hunt_results
    
    print(f"\n═══ STAGE 2.5: GAPFILL — {len(patterns_to_requeue)} patterns with recon clues ═══")
    for pid in patterns_to_requeue:
        print(f"  → Re-queuing {pid} ({PATTERNS[pid]['name']})")
    
    # Layer file cache
    layer_knowledge_cache = {}
    
    # Build gapfill items
    gapfill_items = []
    for pid in patterns_to_requeue:
        pinfo = PATTERNS[pid]
        layer = pinfo["layer"]
        if layer not in layer_knowledge_cache:
            layer_file = LAYER_FILES[layer]
            if not layer_file.exists():
                print(f"  ⚠ WARNING: Knowledge file missing: {layer_file}")
            layer_knowledge_cache[layer] = layer_file.read_text() if layer_file.exists() else ""
        
        full_layer = layer_knowledge_cache.get(layer, "")
        pattern_section = extract_pattern_section(full_layer, pinfo["name"])
        
        # WooYun knowledge
        wooyun_knowledge = ""
        if pinfo.get("wooyun"):
            wooyun_file = WOOYUN_DIR / pinfo["wooyun"]
            if wooyun_file.exists():
                wooyun_raw = wooyun_file.read_text()[:5000]
                wooyun_knowledge = (
                    f"\n## Supplementary Bypass Techniques (from WooYun {pinfo['wooyun']})\n"
                    f"{wooyun_raw}\n...(truncated)\n"
                )
        
        prompt = GAPFILL_PROMPT.format(
            recon_doc=recon_doc,
            pattern_id=pid,
            pattern_name=pinfo["name"],
            layer=layer,
            pattern_knowledge=pattern_section,
            wooyun_knowledge=wooyun_knowledge,
            recon_clues=patterns_to_requeue[pid],
        )
        
        if live_context:
            prompt += f"""\n\n## Live Vulnerability Intel\n{live_context[:8000]}\n"""
        
        gapfill_items.append({
            "pattern_id": pid,
            "prompt": prompt,
            "repo": repo_path,
        })
    
    # Run gapfill batch
    gapfill_results = run_batch(gapfill_items, batch_size)
    
    # Parse and merge findings into hunt_results
    for result in gapfill_results:
        pid = result["pattern_id"]
        # Find the original entry in hunt_results
        for hr in hunt_results:
            if hr["pattern_id"] == pid:
                if result.get("success"):
                    findings = parse_findings(result["output"], pid)
                    if findings:
                        hr["findings"].extend(findings)
                        print(f"    🎯 Gapfill found {len(findings)} more for {pid}")
                    else:
                        print(f"    ✓ Gapfill confirmed: nothing in {pid}")
                else:
                    print(f"    ⚠ Gapfill failed for {pid}: {result.get('error', 'unknown')}")
                break
    
    return hunt_results


def _extract_notable_findings(recon_doc: str) -> str:
    """Extract the 'Notable Security-Relevant Findings' section from recon doc."""
    markers = [
        "Notable Security-Relevant Findings",
        "Notable Findings",
        "Attack Surface",
        "Security-Relevant",
    ]
    for marker in markers:
        idx = recon_doc.find(marker)
        if idx != -1:
            # Find the next heading or section break
            rest = recon_doc[idx:]
            next_heading = None
            for h in ["\n## ", "\n# ", "\n---\n"]:
                pos = rest.find(h, 1)
                if pos != -1 and (next_heading is None or pos < next_heading):
                    next_heading = pos
            if next_heading:
                return rest[:next_heading].strip()
            return rest.strip()
    return ""


def _map_recon_to_patterns(empty_patterns: list[dict], notable_section: str) -> dict:
    """Match empty patterns to relevant recon clues using keyword mapping.
    NOTE: If new patterns are added to PATTERNS, you MUST add them here too.
    If a pattern is not in this dict, it will never be re-queued during gapfill."""
    # Pattern → keyword mapping for matching recon findings
    pattern_keywords = {
        "sensitive-files": [".env", "credential", "secret", "key", "password", "file", "upload", "CV", "retention", "env.local"],
        "client-secrets": [".env", "credential", "secret", "API key", "OAuth", "token", "env.local"],
        "select-star-leak": ["SELECT *", "all columns", "excessive data", "data leak", "query_database"],
        "embedding-manipulation": ["embedding", "vector", "pgvector", "vector search", "Gemini Embedding"],
        "vector-query-injection": ["vector", "embedding", "pgvector", "cosine similarity", "vector search"],
        "ssrf-image-loader": ["SSRF", "image", "loader", "next/image", "fetch", "external URL"],
        "unclosed-connections": ["connection", "pool", "memory", "cleanup", "in-memory", "session"],
        "missing-rls": ["row-level", "RLS", "user isolation", "multi-tenant", "scoping", "row filtering"],
        "context-exhaustion": ["context", "token limit", "window", "compaction", "overflow", "history"],
        "proxy-internal": ["proxy", "internal", "reverse", "port 3001", "bind", "0.0.0.0"],
        "fail-open-defaults": ["fail-open", "default", "fallback", "env", "guard", "or 'default'"],
        "debug-in-prod": ["debug", "error", "stack", "stderr", "leak", "internal state", "traceback"],
        "prompt-extraction": ["prompt", "system prompt", "instructions", "extract", "repeat"],
        "multi-turn-injection": ["turn", "multi-turn", "conversation", "history", "persuasion"],
        "unauthorized-function-call": ["function calling", "function call", "tool call", "unauthorized", "log_lead", "query_database"],
        "data-injection": ["injection", "lead", "CRM", "Zoho", "junk", "spam"],
        "missing-rate-limit": ["rate limit", "brute", "flood", "spam", "abuse", "CAPTCHA", "no rate"],
        "weak-csp": ["CSP", "Content-Security", "script-src", "unsafe-inline", "XSS protection"],
        "missing-headers": ["security headers", "CSP", "X-Frame", "X-Content", "HSTS"],
        "open-redirect": ["redirect", "callbackUrl", "open redirect", "external URL"],
        "race-condition-leads": ["race", "concurrent", "duplicate", "lead", "skills_review", "chat_leads"],
        "connection-string-leak": ["connection string", "database", "db pool", "credentials"],
        "insecure-cookies": ["cookies", "HttpOnly", "SameSite", "secure flag", "A/B test"],
        "weak-tls": ["TLS", "SSL", "Cloudflare", "Flexible", "encryption", "origin"],
    }
    
    result = {}

    for pattern in empty_patterns:
        pid = pattern["pattern_id"]
        keywords = pattern_keywords.get(pid, [])
        if not keywords:
            result[pid] = ""
            continue
        
        # Find matching lines from the notable section
        matching_lines = []
        for line in notable_section.split("\n"):
            line_lower = line.lower().strip()
            if any(kw.lower() in line_lower for kw in keywords):
                matching_lines.append(line.strip())
        
        if matching_lines:
            result[pid] = "\n".join(matching_lines[:5])  # cap at 5 clues
        else:
            result[pid] = ""
    
    return result


def stage_validate(repo_path: str, recon_doc: str, hunt_results: list[dict], 
                   batch_size: int = BATCH_SIZE) -> list[dict]:
    """Phase 3: Adversarial validation — fresh agents try to DISPROVE each finding."""
    
    # Collect all findings that need validation
    findings_to_validate = []
    for pattern_result in hunt_results:
        for finding in pattern_result.get("findings", []):
            if finding.get("confidence") in ("CONFIRMED", "SUSPECTED"):
                findings_to_validate.append({
                    "pattern_id": pattern_result["pattern_id"],
                    "finding": finding,
                })
    
    if not findings_to_validate:
        print("\n═══ STAGE 3: VALIDATE — No findings to validate ═══")
        return []
    
    print(f"\n═══ STAGE 3: VALIDATE — {len(findings_to_validate)} findings ═══")
    
    # Build validation items
    validate_items = []
    for item in findings_to_validate:
        prompt = VALIDATE_PROMPT.format(
            recon_doc=recon_doc,
            finding=json.dumps(item["finding"], indent=2),
        )
        validate_items.append({
            "pattern_id": item["pattern_id"],
            "finding_id": item["finding"].get("id", "unknown"),
            "prompt": prompt,
            "repo": repo_path,
        })
    
    # Run in batches — validators use a different (stronger) model
    validate_results = run_batch(validate_items, batch_size, model=VALIDATOR_MODEL, tools="read,grep,find,ls")
    
    # Parse verdicts
    for result in validate_results:
        if result.get("success"):
            verdict = parse_verdict(result["output"])
            result["verdict"] = verdict
            status = "✗ REJECTED" if verdict.get("rejected") else "✓ UPHELD"
            print(f"    {status}: {result['finding_id']}")
        else:
            result["verdict"] = {"rejected": False, "reasoning": "validation failed"}
            print(f"    ⚠ ERROR: {result['finding_id']} — {result.get('error', 'unknown')}")
    
    return validate_results


def stage_dedupe(hunt_results: list[dict], validate_results: list[dict]) -> list[dict]:
    """Phase 4: Deduplicate findings by root cause. Collapse variants."""
    
    print("\n═══ STAGE 4: DEDUPE + VARIANT ANALYSIS ═══")
    
    # Build rejection set from validation
    rejected_ids = set()
    for vr in validate_results:
        verdict = vr.get("verdict", {})
        if verdict.get("rejected"):
            rejected_ids.add(vr.get("finding_id"))
    
    # Collect upheld findings
    upheld = []
    for pattern_result in hunt_results:
        for finding in pattern_result.get("findings", []):
            fid = finding.get("id", "")
            if fid not in rejected_ids and finding.get("confidence") in ("CONFIRMED", "SUSPECTED"):
                upheld.append({
                    **finding,
                    "pattern": pattern_result["pattern_id"],
                    "validated": fid not in rejected_ids,
                })
    
    # Group by root cause (same file + same vulnerability class)
    groups = {}
    for f in upheld:
        location = f.get("location", "unknown")
        vuln_class = f.get("pattern", "unknown")
        key = f"{location}::{vuln_class}"
        if key not in groups:
            groups[key] = []
        groups[key].append(f)
    
    # Collapse: each group → one primary + variants
    deduped = []
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for key, group in groups.items():
        primary = max(group, key=lambda f: severity_rank.get(f.get("severity", "LOW"), 1))
        variants = [f for f in group if f is not primary]
        deduped.append({
            **primary,
            "variants": [v.get("id") for v in variants],
            "is_root_cause": True,
        })
    
    print(f"  {len(upheld)} upheld findings → {len(deduped)} unique root causes")
    
    return deduped


def stage_report(deduped_findings: list[dict], repo_path: str, live_context: str = None):
    """Phase 5: Generate structured report."""
    
    print("\n═══ STAGE 5: REPORT ═══")
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "repository": str(repo_path),
        "summary": {
            "total_findings": len(deduped_findings),
            "by_severity": {},
            "by_pattern": {},
        },
        "findings": deduped_findings,
    }
    
    for f in deduped_findings:
        sev = f.get("severity", "UNKNOWN")
        report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1
        pat = f.get("pattern", "unknown")
        report["summary"]["by_pattern"][pat] = report["summary"]["by_pattern"].get(pat, 0) + 1
    
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    
    report_path = RESULTS_DIR / f"report-{ts}.json"
    report_path.write_text(json.dumps(report, indent=2))
    
    # Human-readable markdown
    md_path = RESULTS_DIR / f"report-{ts}.md"
    md_lines = [
        f"# Vulnerability Assessment Report",
        f"",
        f"**Repository:** `{repo_path}`",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Findings:** {len(deduped_findings)}",
        f"",
        f"## Summary",
        f"",
    ]
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = report["summary"]["by_severity"].get(sev, 0)
        if count:
            md_lines.append(f"- **{sev}:** {count}")
    
    # Live intel section — known CVEs in dependencies found during harvest
    if live_context:
        md_lines.append("")
        md_lines.append("## Known Vulnerabilities in Dependencies")
        md_lines.append("")
        md_lines.append("*Discovered during intel harvest phase (OSV, NVD, npm audit). "
                        "These are known CVEs affecting the codebase's dependencies. "
                        "Hunters were aware of these during analysis.*")
        md_lines.append("")
        
        # Extract key sections from the live context brief
        in_section = False
        section_name = ""
        for line in live_context.split("\n"):
            stripped = line.strip()
            if stripped.startswith("## ") and "Hunter Guidance" not in stripped and "Target Dependencies" not in stripped and "OpenSSF Scorecard" not in stripped:
                in_section = True
                # Rewrite heading levels for nesting in the report
                md_lines.append(f"### {stripped.lstrip('# ')}")
                md_lines.append("")
                continue
            elif stripped.startswith("## "):
                in_section = False
                continue
            elif stripped.startswith("# ") and "Live Vulnerability" in stripped:
                continue  # skip title
            
            if in_section and stripped:
                # Add blank line after headings only, not after every line
                if stripped.startswith("#") or stripped.startswith("- ") or stripped.startswith("**"):
                    md_lines.append(stripped)
                else:
                    md_lines.append(stripped)
        
        # Add to JSON report too
        # Extract CVE counts from intel text
        intel_summary = {}
        for line in live_context.split("\n"):
            stripped = line.strip()
            if "Known Vulnerabilities in Dependencies" in stripped:
                match = re.search(r'Known Vulnerabilities in Dependencies[^(]*\((\d+)\)', stripped)
                if match:
                    intel_summary["osv_count"] = int(match.group(1))
            if stripped.startswith("## npm Registry Advisories"):
                match = re.search(r'npm Registry Advisories[^(]*\((\d+)\)', stripped)
                if match:
                    intel_summary["npm_advisory_count"] = int(match.group(1))
            if stripped.startswith("## Actively Exploited") and "KEV" in stripped:
                match = re.search(r'Actively Exploited[^(]*\((\d+)\)', stripped)
                if match:
                    intel_summary["cisa_kev_total"] = int(match.group(1))
            if "(" in stripped and ")" in stripped and any(c.isdigit() for c in stripped.split("(")[1]):
                if "CRITICAL" in stripped:
                    match = re.search(r'CRITICAL\s+\((\d+)\)', stripped)
                    if match:
                        intel_summary["critical_cves"] = int(match.group(1))
                if "HIGH" in stripped:
                    match = re.search(r'HIGH\s+\((\d+)\)', stripped)
                    if match:
                        intel_summary["high_cves"] = int(match.group(1))
        report["intel_summary"] = intel_summary
        md_lines.append("")
    
    md_lines.append("## Findings")
    md_lines.append("")
    
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(deduped_findings, key=lambda x: sev_order.get(x.get("severity", "LOW"), 99)):
        md_lines.extend([
            f"### {f.get('id', '?')} — {f.get('severity', '?')}",
            f"",
            f"**Pattern:** {f.get('pattern', '?')}",
            f"**Location:** `{f.get('location', '?')}`",
            f"**Confidence:** {f.get('confidence', '?')}",
            f"",
            f"**Source:** {f.get('source', 'N/A')}",
            f"**Sink:** {f.get('sink', 'N/A')}",
            f"",
            f"**Attack Scenario:** {f.get('attack_scenario', 'N/A')}",
            f"",
        ])
        if f.get("variants"):
            md_lines.append(f"**Variants:** {', '.join(f['variants'])}")
            md_lines.append("")
    
    md_path.write_text("\n".join(md_lines))
    
    print(f"  ✓ JSON report: {report_path}")
    print(f"  ✓ Markdown report: {md_path}")


# ── Batch Execution ──────────────────────────────────────────────────────────

def run_batch(items: list[dict], batch_size: int = BATCH_SIZE, 
               model: str = None, tools: str = None) -> list[dict]:
    """
    Run pi sessions in batches. Each item has: pattern_id, prompt, repo.
    
    Uses --mode json for structured output.
    Default tools are read-only (read, grep, find, ls).
    """
    results = []
    total = len(items)
    _model = model or HUNTER_MODEL
    _tools = tools or "read,grep,find,ls"  # read-only by default
    
    for i in range(0, total, batch_size):
        batch = items[i:i + batch_size]
        batch_num = i // batch_size + 1
        total_batches = (total + batch_size - 1) // batch_size
        
        print(f"\n{'─' * 60}")
        print(f"  Batch {batch_num}/{total_batches} — {len(batch)} sessions")
        print(f"{'─' * 60}")
        
        # Launch batch concurrently
        processes = []
        for item in batch:
            cmd = build_pi_cmd(
                prompt=item["prompt"],
                repo_path=item["repo"],
                mode="json",
                model=_model,
                tools=_tools,
                no_session=True,
                no_context_files=False,  # keep AGENTS.md — it has project context
            )
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=item["repo"],
                text=True,
            )
            processes.append({"proc": proc, "meta": item})
            print(f"  → Started: {item['pattern_id']}")
        
        # Wait for batch to complete
        # Track batch start time so timeouts don't accumulate across processes
        batch_start = time.time()
        for p in processes:
            pid = p["meta"]["pattern_id"]
            remaining = max(0, PI_TIMEOUT - (time.time() - batch_start))
            if remaining == 0:
                # Batch timeout already exceeded — kill remaining processes
                p["proc"].kill()
                p["proc"].communicate()
                results.append({**p["meta"], "success": False, "error": "timeout"})
                print(f"  ✗ Timeout (batch): {pid}")
                continue
            try:
                stdout, stderr = p["proc"].communicate(timeout=remaining)
                
                # Check exit code
                if p["proc"].returncode != 0:
                    results.append({**p["meta"], "success": False, 
                                     "error": f"exit code {p['proc'].returncode}",
                                     "stderr": stderr.strip()[:500]})
                    print(f"  ✗ Failed (exit {p['proc'].returncode}): {pid}")
                    continue
                
                # Parse JSONL events — extract text from the LAST assistant message only
                last_assistant_text = ""
                for line in stdout.strip().split("\n"):
                    try:
                        event = json.loads(line.strip())
                        if event.get("type") == "agent_end":
                            messages = event.get("messages", [])
                            # Take only the last assistant message (the final answer)
                            for msg in reversed(messages):
                                if msg.get("role") == "assistant":
                                    content = msg.get("content", [])
                                    if isinstance(content, list):
                                        last_assistant_text = "".join(
                                            block.get("text", "") 
                                            for block in content 
                                            if isinstance(block, dict) and block.get("type") == "text"
                                        )
                                    elif isinstance(content, str):
                                        last_assistant_text = content
                                    break
                    except json.JSONDecodeError:
                        continue
                
    # If parsing fails, output is empty but success is True.
                # In that case, keep success=True but we log a warning.
                if p["proc"].returncode == 0 and not last_assistant_text.strip():
                    print(f"  ⚠ Output parse warning (empty assistant msg): {pid}")

                results.append({**p["meta"], "success": True, 
                                 "output": last_assistant_text.strip(),
                                 "stderr": stderr.strip()[:500]})
                print(f"  ✓ Done: {pid}")
                
            except subprocess.TimeoutExpired:
                p["proc"].kill()
                p["proc"].communicate()  # reap the zombie
                results.append({**p["meta"], "success": False, "error": "timeout"})
                print(f"  ✗ Timeout: {pid}")
    
    return results


# ── Utility Functions ─────────────────────────────────────────────────────────

def extract_pattern_section(full_text: str, pattern_name: str) -> str:
    """Extract just the relevant pattern section from a layer patterns file."""
    if not full_text:
        return ""
    marker = f"### Pattern: {pattern_name}"
    idx = full_text.find(marker)
    if idx == -1:
        print(f"  ⚠ WARNING: Pattern '{pattern_name}' not found in knowledge file. Using full layer context.")
        return full_text  # fallback
    
    next_marker = full_text.find("\n### Pattern: ", idx + len(marker))
    if next_marker == -1:
        return full_text[idx:]
    return full_text[idx:next_marker]


def parse_findings(output: str, pattern_id: str) -> list[dict]:
    """Try to extract JSON findings from pi output. Uses last match to avoid
    picking up intermediate tool-use JSON blocks."""
    # Try ```json ... ``` blocks — use the LAST one (the final answer)
    matches = re.findall(r'```json\s*(\{.*?\})\s*```', output, re.DOTALL)
    for match in reversed(matches):
        try:
            data = json.loads(match)
            if "findings" in data:
                return data.get("findings", [])
        except json.JSONDecodeError:
            continue
    
    # No structured findings found
    return []


def parse_verdict(output: str) -> dict:
    """Extract UPHELD/REJECTED verdict from validation output."""
    output_lower = output.lower()
    if "rejected" in output_lower and "upheld" not in output_lower:
        return {"rejected": True, "reasoning": output}
    elif "upheld" in output_lower:
        return {"rejected": False, "reasoning": output}
    else:
        # Ambiguous — default to upheld (conservative: don't reject on uncertainty)
        return {"rejected": False, "reasoning": f"AMBIGUOUS — defaulting to UPHELD\n{output[:500]}"}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Discovery Harness")
    parser.add_argument("repo", nargs="?", help="Path to repository to audit")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE, 
                        help="Concurrent pi sessions per batch (default: 8)")
    parser.add_argument("--patterns", type=str, default=None, 
                        help="Comma-separated pattern IDs to run (default: all)")
    parser.add_argument("--skip-recon", action="store_true", 
                        help="Skip recon stage (use existing recon doc)")
    parser.add_argument("--recon-file", type=str, default=None, 
                        help="Path to existing recon doc")
    parser.add_argument("--validate-only", type=str, default=None, 
                        help="Path to hunt results JSON to validate")
    parser.add_argument("--hunt-only", action="store_true", 
                        help="Stop after hunt stage (skip validation)")
    parser.add_argument("--recon-only", action="store_true",
                        help="Run only the recon stage and save the architecture doc")
    parser.add_argument("--list-patterns", action="store_true",
                        help="List all available attack patterns and exit")
    parser.add_argument("--skip-intel", action="store_true",
                        help="Skip live vulnerability intel harvesting")
    parser.add_argument("--intel-file", type=str, default=None,
                        help="Path to existing live context brief (skip harvest)")
    parser.add_argument("--intel-hours", type=int, default=24,
                        help="Lookback window for fresh advisories (default: 24h)")
    parser.add_argument("--no-gapfill", action="store_true",
                        help="Skip gapfill stage (re-queue empty patterns with narrowed scope)")
    
    args = parser.parse_args()
    
    # List patterns (no repo needed)
    if args.list_patterns:
        print(f"Available patterns ({len(PATTERNS)}):")
        print()
        current_layer = None
        for pid, pinfo in PATTERNS.items():
            if pinfo["layer"] != current_layer:
                current_layer = pinfo["layer"]
                print(f"  [{current_layer}]")
            wooyun_tag = " 📚WooYun" if pinfo.get("wooyun") else ""
            print(f"    {pid:30s}  {pinfo['name']}{wooyun_tag}")
        return
    
    repo_path = str(Path(args.repo).resolve())
    
    if not Path(repo_path).exists():
        print(f"Error: {repo_path} does not exist")
        sys.exit(1)
    
    # Validate-only mode
    if args.validate_only:
        hunt_results = json.loads(Path(args.validate_only).read_text())
        recon_doc = Path(args.recon_file).read_text() if args.recon_file else "No recon context available"
        stage_validate(repo_path, recon_doc, hunt_results, args.batch_size)
        return
    
    # Stage -1: Intel Harvest
    live_context_file = getattr(args, 'intel_file', None)
    skip_intel = getattr(args, 'skip_intel', False)
    live_context = ""
    if not skip_intel:
        if live_context_file:
            live_context = Path(live_context_file).read_text()
            print(f"  ✓ Using existing intel: {live_context_file}")
        else:
            try:
                live_context = stage_intel(repo_path, hours=getattr(args, 'intel_hours', 24))
            except Exception as e:
                print(f"  ⚠ Intel harvest failed: {e}. Continuing without live context.")
                live_context = ""
    
    # Stage 0-1: Recon
    if args.recon_only:
        stage_recon(repo_path, live_context=live_context)
        return
    
    if args.skip_recon:
        if not args.recon_file:
            print("Error: --skip-recon requires --recon-file")
            sys.exit(1)
        recon_doc = Path(args.recon_file).read_text()
        print(f"  ✓ Using existing recon doc: {args.recon_file} ({len(recon_doc):,} chars)")
    else:
        recon_doc = stage_recon(repo_path, live_context=live_context)
    
    # Stage 2: Hunt
    patterns = [p.strip() for p in args.patterns.split(",")] if args.patterns else None
    hunt_results = stage_hunt(repo_path, recon_doc, patterns, args.batch_size, live_context=live_context)
    
    # Stage 3: Gapfill — re-queue empty patterns with narrowed scope
    if not args.hunt_only and not args.no_gapfill:
        hunt_results = stage_gapfill(repo_path, recon_doc, hunt_results, 
                                      live_context=live_context, batch_size=args.batch_size)
    
    if args.hunt_only:
        print(f"\n  Hunt-only mode — skipping validation/dedupe/report.")
        return
    
    # Stage 4: Validate
    validate_results = stage_validate(repo_path, recon_doc, hunt_results, args.batch_size)
    
    # Stage 5: Dedupe
    deduped = stage_dedupe(hunt_results, validate_results)
    
    # Stage 6: Report
    stage_report(deduped, repo_path, live_context=live_context)
    
    total = len(deduped)
    critical = sum(1 for f in deduped if f.get("severity") == "CRITICAL")
    high = sum(1 for f in deduped if f.get("severity") == "HIGH")
    
    print(f"\n{'═' * 60}")
    print(f"  Harness complete.")
    print(f"  {total} validated findings ({critical} CRITICAL, {high} HIGH)")
    print(f"{'═' * 60}")


if __name__ == "__main__":
    main()