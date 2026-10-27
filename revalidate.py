#!/usr/bin/env python3
"""Re-run validation for findings whose validators timed out, then issue a corrected report.

Uses the fixed fail-closed semantics from matter d2f44257 (a242c7b): a validator that
could not speak produces an UNVALIDATED verdict, never an implicit uphold.
"""

import argparse
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


def original_failure_breakdown(expected_ids: set[str]) -> tuple[int, int, int] | None:
    """Read the original validation stage, not fresh checkpoint verdicts."""
    try:
        log = RUN_LOG.read_text()
    except (OSError, UnicodeError):
        return None
    start = log.find("═══ STAGE 3: VALIDATE")
    end = log.find("═══ STAGE 4", start)
    if start < 0 or end < 0:
        return None
    stage = log[start:end]
    deadline = len(re.findall(r"^  ✗ (?:Timeout|timeout|timeout-session): \S+", stage, re.M))
    tail = len(re.findall(r"^  ✗ (?:Timeout \(batch\)|timeout-batch-tail): \S+", stage, re.M))
    other = len(re.findall(r"^  ✗ Failed \(exit [^)]+\): \S+", stage, re.M))
    errors = re.findall(r"^\s*⚠ ERROR: (\S+) — (.+)$", stage, re.M)
    # Do not present partial or unrelated log data as an exact breakdown.
    if (len(errors) != len(expected_ids) or {fid for fid, _ in errors} != expected_ids
            or deadline + tail + other != len(errors)
            or sum(reason.strip() in {"timeout", "timeout-session", "timeout-batch-tail"}
                   for _, reason in errors) != deadline + tail):
        return None
    return deadline, tail, other


def rebuild_artifacts(path: Path, report: dict | None = None) -> dict:
    """Offline and idempotent: no session execution and no clock-dependent output."""
    if report is None:
        report = json.loads(path.read_text())
    original = json.loads(REPORT_JSON.read_text())
    state_path = Path(harness.RESULTS_DIR) / "revalidate-state.json"
    verdicts = json.loads(state_path.read_text())["verdicts"]
    original_by_id = {f["id"]: f for f in original["findings"]}
    revalidated = set(verdicts) & original_by_id.keys()
    retained = {f["id"] for f in report["findings"]}
    removed = {fid for fid in revalidated if fid not in retained
               and verdicts[fid].get("rejected") and not verdicts[fid].get("failed")}
    breakdown = original_failure_breakdown(revalidated)
    if breakdown is None:
        detail = ("timeout/other numeric breakdown unavailable: original run log is "
                  "absent or unparseable.")
    else:
        deadline, tail, other = breakdown
        detail = (f"{deadline} timed out after the full {harness.PI_TIMEOUT}s session budget "
                  f"(the log does not record the cause; timeout records discard output). "
                  f"{tail} were batch-tail kills: once one session in a batch hit "
                  f"{harness.PI_TIMEOUT}s, harness.py::run_batch found 0s remaining for every "
                  f"later slot in that batch and killed them without reading their output. "
                  f"{other} failed for any other reason.")
    report["revalidation_note"] = (
        f"Revalidated {len(revalidated)} findings that failed validation in the original run. "
        f"{detail} "
        f"{len(removed)} of the revalidated were disproved on the fresh attempt and removed."
    )
    for finding in report["findings"]:
        # Repair effects of the earlier overbroad template cap from original evidence.
        if finding.get("severity_caveat", "").startswith("⚠ Severity capped at HIGH:"):
            baseline = original_by_id[finding["id"]]
            finding["severity"] = baseline["severity"]
            finding["confidence"] = baseline["confidence"]
            finding.pop("severity_caveat")
        finding.setdefault("validation_state", "validated" if finding.get("validated")
                           else "unvalidated")
        harness.apply_template_severity_cap(finding)
    summary = report["summary"]
    summary.update(total_findings=len(report["findings"]),
                   validated=sum(bool(f.get("validated")) for f in report["findings"]),
                   unvalidated=sum(not f.get("validated") for f in report["findings"]),
                   revalidated_rejected=len(removed))
    for field, key in (("by_severity", "severity"), ("by_pattern", "pattern"),
                       ("by_layer", "layer")):
        counts = {}
        for finding in report["findings"]:
            value = finding.get(key, "UNKNOWN" if key == "severity" else "unknown")
            if key == "layer":
                value = harness.PATTERNS.get(finding.get("pattern"), {}).get("layer", value)
            counts[value] = counts.get(value, 0) + 1
        summary[field] = counts
    live_context = (Path(harness.RESULTS_DIR) / "live-context-20261026-123919.md").read_text()
    harness.write_report_markdown(report, path.with_suffix(".md"), live_context)
    path.write_text(json.dumps(report, indent=2))
    print(f"Rebuilt {path.name}: {summary['total_findings']} findings")
    print(report["revalidation_note"])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebuild-artifacts", nargs="+", type=Path,
                        help="rebuild existing JSON/Markdown artifacts without LLM calls")
    args = parser.parse_args()
    if args.rebuild_artifacts:
        for path in args.rebuild_artifacts:
            rebuild_artifacts(path)
        return
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
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    corr_json = Path(harness.RESULTS_DIR) / f"report-{stamp}-revalidated.json"
    corr_md = corr_json.with_suffix(".md")
    report = rebuild_artifacts(corr_json, report)
    print(f"\ncorrected report: {corr_md.name} / {corr_json.name}")
    print(f"summary: {report['summary']['total_findings']} findings "
          f"({report['summary']['validated']} validated, {report['summary']['unvalidated']} unvalidated, "
          f"{len(removed)} disproved on revalidation)")


if __name__ == "__main__":
    main()