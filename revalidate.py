#!/usr/bin/env python3
"""Re-run validation for findings whose validators timed out, then issue a corrected report.

Uses the fixed fail-closed semantics from matter d2f44257 (a242c7b): a validator that
could not speak produces an UNVALIDATED verdict, never an implicit uphold.
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

REPORT_JSON = Path(harness.RESULTS_DIR) / "report-20261026-153259.json"
RECON_DOC = Path(harness.RESULTS_DIR) / "recon-20261026-124355.md"
RUN_LOG = Path("/home/mom/audits/rplit-glasswing-run1.log")


def failed_ids_from_log():
    ids = set()
    validation_started = False
    for line in RUN_LOG.read_text().splitlines():
        if line.startswith("═══ STAGE 3: VALIDATE"):
            validation_started = True
        elif line.startswith("═══ STAGE 4"):
            break
        if validation_started:
            m = re.match(r"\s*⚠ ERROR: (\S+) —", line)
            if m:
                ids.add(m.group(1))
    return ids


def main():
    report = json.loads(REPORT_JSON.read_text())
    failed = failed_ids_from_log()
    print(f"failed validations from log: {len(failed)}")

    items = []
    for finding in report["findings"]:
        if finding.get("id") in failed:
            items.append({
                "pattern_id": finding.get("pattern", "unknown"),
                "finding_id": finding.get("id"),
                "prompt": harness.VALIDATE_PROMPT.format(
                    recon_doc=RECON_DOC.read_text(),
                    finding=json.dumps(finding, indent=2),
                ),
                "repo": "/home/mom/projects/rpl-it-website",
            })
    if not items:
        print("no match between log failures and report findings — nothing to revalidate")
        return
    print(f"revalidating {len(items)} findings with {harness.VALIDATOR_MODEL} (batches of 4)")

    from pathlib import Path as _P
    state_path = Path(harness.RESULTS_DIR) / "revalidate-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"verdicts": {}}
    verdicts = state["verdicts"]
    pending = [it for it in items if it["finding_id"] not in verdicts]
    print(f"{len(pending)} pending of {len(items)} (state file: {state_path.name})")
    for i in range(0, len(pending), 4):
        chunk = pending[i:i + 4]
        results = harness.run_batch(chunk, batch_size=4, model=harness.VALIDATOR_MODEL,
                                    tools="read,grep,find,ls")
        for r in results:
            fid = r["finding_id"]
            if r.get("success"):
                verdicts[fid] = harness.parse_verdict(r["output"])
                print(f"    {'✗ REJECTED' if verdicts[fid].get('rejected') else '✓ UPHELD'}: {fid}")
            else:
                verdicts[fid] = {"failed": True, "rejected": None,
                                 "reasoning": f"validation failed: {r.get('error')}"}
                print(f"    ⚠ UNVALIDATED: {fid} — {r.get('error')}")
        state_path.write_text(json.dumps(state, indent=1))
        print(f"    [checkpoint {i + len(chunk)}/{len(pending)} saved]")

    # Apply to report
    removed = []
    for finding in list(report["findings"]):
        fid = finding.get("id")
        verdict = verdicts.get(fid)
        if verdict is None:
            continue
        if verdict.get("rejected") and not verdict.get("failed"):
            removed.append(fid)
            report["findings"].remove(finding)
            continue
        if verdict.get("failed"):
            finding["validated"] = False
            finding["validation_state"] = "unvalidated"
        else:
            finding["validated"] = True
            finding["validation_state"] = "validated"
    now = datetime.now()
    sev_counts = {}
    pat_counts = {}
    for f in report["findings"]:
        s = f.get("severity", "UNKNOWN")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        p = f.get("pattern", "unknown")
        pat_counts[p] = pat_counts.get(p, 0) + 1
    report["summary"]["validated"] = sum(1 for f in report["findings"] if f.get("validated"))
    report["summary"]["unvalidated"] = sum(1 for f in report["findings"] if not f.get("validated"))
    report["summary"]["revalidated_rejected"] = len(removed)
    report["summary"]["total_findings"] = len(report["findings"])
    report["summary"]["by_severity"] = sev_counts
    report["summary"]["by_pattern"] = pat_counts
    report["revalidation_note"] = (
        f"Revalidated {len(items)} findings whose validators timed out (DeepSeek balance outage "
        f"mid-run). Fixed fail-closed semantics applied. {len(removed)} of the revalidated were "
        f"disproved on the fresh attempt and removed."
    )

    stamp = now.strftime("%Y%m%d-%H%M%S")
    corr_json = Path(harness.RESULTS_DIR) / f"report-{stamp}-revalidated.json"
    corr_md = Path(harness.RESULTS_DIR) / f"report-{stamp}-revalidated.md"
    corr_json.write_text(json.dumps(report, indent=2))

    # Corrected markdown: regenerate summary header from the original, keep body
    orig_md = Path(harness.RESULTS_DIR) / "report-20261026-153259.md"
    md_text = orig_md.read_text()
    header = (
        f"# Vulnerability Assessment Report (REVALIDATED)\n\n"
        f"**Repository:** `/home/mom/projects/rpl-it-website`\n"
        f"**Date:** {now.strftime('%Y-%m-%d %H:%M')}\n"
        f"**Findings:** {len(report['findings'])} (validated: {report['summary']['validated']}, unvalidated: {report['summary']['unvalidated']})\n\n"
        + "".join(f"- **{s.upper()}:** {c}\n" for s, c in report["summary"]["by_severity"].items() if s != "UNKNOWN")
        + f"\n*Original run lost DeepSeek balance mid-validation; 27 validators timed out and the "
        f"pre-fix harness logged them as validated. This corrected report re-ran those "
        f"validators under fail-closed semantics: {len(removed)} were subsequently DISPROVED "
        f"and removed; the rest are marked unvalidated or validated accordingly. "
        f"Original: report-20261026-153259.*\n\n"
        f"## Summary\n\n"
    )
    body_start = md_text.find("## Summary")
    # keep the original body after its summary section header block (severity bullets + intel)
    rest = md_text[body_start:]
    # drop the original severity bullet block to avoid stale counts
    lines = rest.split("\n")
    # find first non-bullet content after "## Summary"
    drop_to = 2
    in_bullets = True
    for i, l in enumerate(lines[2:], start=2):
        if in_bullets and (l.startswith("- **") or l.strip() == ""):
            continue
        else:
            drop_to = i
            in_bullets = False
            break
    corr_md.write_text(header + "\n".join(lines[drop_to:]))
    print(f"\ncorrected report: {corr_md.name} / {corr_json.name}")
    print(f"summary: {report['summary']['total_findings']} findings "
          f"({report['summary']['validated']} validated, {report['summary']['unvalidated']} unvalidated, "
          f"{len(removed)} disproved on revalidation)")


if __name__ == "__main__":
    main()