#!/usr/bin/env python3
"""Funnel-accounting and dedupe invariants for harness.py.

No test framework — plain asserts, stdlib only, matching the harness style.

    python3 test_funnel.py                       # synthetic checks only
    python3 test_funnel.py hunt.json run1.log     # + replay of a real run

The replay rebuilds the accounting `stage_hunt`/`stage_validate` would have
produced from a persisted hunt artefact and a run log, then asserts the funnel
reconciles and that no carried-forward finding disappears from the report.
"""

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness as H  # noqa: E402


def _finding(fid, sink, severity="HIGH", validated=True, confidence="CONFIRMED"):
    return {
        "id": fid, "pattern": "demo", "sink": sink, "severity": severity,
        "location": "x.js:1", "confidence": confidence,
        "validated": validated,
        "validation_state": "validated" if validated else "unvalidated",
    }


def check_ids():
    hunt = [{"pattern_id": "demo", "findings": [
        {"id": "F-demo-001", "confidence": "SUSPECTED", "sink": "a", "severity": "LOW"},
        {"id": "F-demo-001", "confidence": "SUSPECTED", "sink": "b", "severity": "LOW"},
        {"confidence": "SUSPECTED", "sink": "c", "severity": "LOW"},
    ]}]
    assert H._ensure_finding_ids(hunt) == 2
    ids = [f["id"] for f in hunt[0]["findings"]]
    assert len(set(ids)) == 3, ids
    # idempotent: a second pass changes nothing
    assert H._ensure_finding_ids(hunt) == 0


def check_dedupe():
    hunt = [{"pattern_id": "demo", "findings": [
        _finding("F-demo-001", "pool.query(sql)"),
        _finding("F-demo-002", "pool.query(sql)"),
        _finding("F-demo-003", "POST /api/chat"),
    ]}]
    acc = {}
    rows = H.stage_dedupe(hunt, [], accounting=acc)
    assert len(rows) == 2, [r["id"] for r in rows]
    merged = next(r for r in rows if r["variant_count"])
    assert merged["variant_details"][0]["id"] == "F-demo-002"
    assert merged["variant_details"][0]["sink"] == "pool.query(sql)"
    assert merged["variant_details"][0]["location"]
    assert (acc["carried_forward"], acc["reported"], acc["collapsed_into_variants"]) == (3, 2, 1)
    assert "is_root_cause" not in merged, "the constant field is gone"


def check_primary_prefers_adjudicated():
    hunt = [{"pattern_id": "demo", "findings": [
        _finding("F-demo-010", "s"), _finding("F-demo-011", "s"),
    ]}]
    verdicts = [
        {"pattern_id": "demo", "finding_id": "F-demo-010",
         "verdict": {"rejected": None, "failed": True}},
        {"pattern_id": "demo", "finding_id": "F-demo-011",
         "verdict": {"rejected": False}},
    ]
    rows = H.stage_dedupe(hunt, verdicts)
    assert rows[0]["id"] == "F-demo-011", rows[0]["id"]
    assert rows[0]["validation_state"] == "validated"
    assert rows[0]["variant_details"][0]["validation_state"] == "unvalidated"


def check_reconcile():
    ok = {"hunt_emitted": 10, "gapfill_emitted": 2, "sent_to_validate": 12,
          "excluded_by_confidence": [],
          "verdicts": {"upheld": 10, "rejected": 2, "unvalidated": 0},
          "carried_forward": 10, "reported": 8, "collapsed_into_variants": 2}
    assert H.reconcile_funnel(ok) == [], H.reconcile_funnel(ok)

    broken = dict(ok, hunt_emitted=999, gapfill_emitted=0,
                  verdicts={"upheld": 9, "rejected": 2, "unvalidated": 0},
                  carried_forward=9, reported=8, collapsed_into_variants=0,
                  expected_reported=9)
    problems = H.reconcile_funnel(broken)
    assert len(problems) == 4, problems

    # an incomplete accounting dict must never read as "reconciled"
    assert H.reconcile_funnel({})[0].startswith("funnel accounting incomplete")


def check_report_paths():
    """accounting=None must produce an explicit 'do not cite' report, not a crash."""
    original = H.RESULTS_DIR
    H.RESULTS_DIR = Path(tempfile.mkdtemp(prefix="funnel-"))
    try:
        rows = H.stage_dedupe([{"pattern_id": "demo", "findings": [_finding("F-demo-001", "s")]}], [])
        H.stage_report(rows, ".")
        md = sorted(H.RESULTS_DIR.glob("report-*.md"))[-1].read_text()
        assert "do NOT reconcile" in md
        rep = json.loads(sorted(H.RESULTS_DIR.glob("report-*.json"))[-1].read_text())
        assert rep["summary"]["funnel"]["reconciles"] is False
    finally:
        shutil.rmtree(H.RESULTS_DIR, ignore_errors=True)
        H.RESULTS_DIR = original


def replay(hunt_path, log_path):
    hunt = json.loads(Path(hunt_path).read_text())
    lines = Path(log_path).read_text().splitlines()

    rejected, unvalidated, in_validate = set(), set(), False
    for line in lines:
        if line.startswith("═══ STAGE 3"):
            in_validate = True
            continue
        if line.startswith("═══ STAGE 4"):
            break
        if not in_validate:
            continue
        m = re.search(r"✗ REJECTED: (\S+)", line)
        if m:
            rejected.add(m.group(1))
        m = re.search(r"⚠ (?:ERROR|UNVALIDATED): (\S+) —", line)
        if m:
            unvalidated.add(m.group(1))

    H._ensure_finding_ids(hunt)
    acc = {
        "patterns_planned": len(hunt),
        "hunt_emitted": sum(len(p["findings"]) for p in hunt),
        "hunt_failed": [{"pattern_id": p["pattern_id"], "error": p["error"]}
                        for p in hunt if p.get("error")],
        "gapfill_emitted": 0,
        "verdicts": {"upheld": 0, "rejected": 0, "unvalidated": 0},
        "excluded_by_confidence": [],
    }
    validate_results = []
    for p in hunt:
        for f in p.get("findings", []):
            if f.get("confidence") not in ("CONFIRMED", "SUSPECTED"):
                acc["excluded_by_confidence"].append(
                    {"id": f["id"], "pattern_id": p["pattern_id"],
                     "confidence": f.get("confidence"), "severity": f.get("severity"),
                     "reason": "confidence gate"})
                continue
            fid = f["id"]
            verdict = ({"rejected": True} if fid in rejected
                       else {"rejected": None, "failed": True} if fid in unvalidated
                       else {"rejected": False})
            validate_results.append({"pattern_id": p["pattern_id"], "finding_id": fid,
                                     "verdict": verdict})
            acc["verdicts"]["unvalidated" if verdict.get("failed")
                            else "rejected" if verdict.get("rejected") else "upheld"] += 1
    acc["sent_to_validate"] = len(validate_results)

    original = H.RESULTS_DIR
    H.RESULTS_DIR = Path(tempfile.mkdtemp(prefix="funnel-replay-"))
    try:
        rows = H.stage_dedupe(hunt, validate_results, accounting=acc)
        H.stage_report(rows, ".", accounting=acc)
        rep = json.loads(sorted(H.RESULTS_DIR.glob("report-*.json"))[-1].read_text())
        md = sorted(H.RESULTS_DIR.glob("report-*.md"))[-1].read_text()
    finally:
        shutil.rmtree(H.RESULTS_DIR, ignore_errors=True)
        H.RESULTS_DIR = original

    funnel = rep["summary"]["funnel"]
    assert funnel["reconciles"] is True, funnel["mismatches"]
    assert funnel["sent_to_validate"] == sum(funnel["verdicts"].values())
    assert funnel["carried_forward"] == (funnel["verdicts"]["upheld"]
                                         + funnel["verdicts"]["unvalidated"])
    assert funnel["carried_forward"] == (funnel["reported"]
                                         + funnel["collapsed_into_variants"])
    assert funnel["reported"] == rep["summary"]["total_findings"]

    # nothing may vanish between hunt and report
    carried = {f["id"] for p in hunt for f in p["findings"]
               if f.get("confidence") in ("CONFIRMED", "SUSPECTED")} - rejected
    seen = set()
    for row in rep["findings"]:
        seen.add(row["id"])
        seen.update(v["id"] for v in row["variant_details"])
    assert seen == carried, f"lost: {carried - seen}"

    assert "FUNNEL MISMATCH" not in md
    if funnel["hunt_failed"]:
        assert "Coverage is incomplete" in md

    print(f"  replay: hunt {funnel['hunt_emitted']} → excluded "
          f"{len(acc['excluded_by_confidence'])} + validated {funnel['sent_to_validate']} "
          f"→ carried {funnel['carried_forward']} → reported {funnel['reported']} "
          f"(+{funnel['collapsed_into_variants']} variants)")
    print(f"  verdicts: {funnel['verdicts']}; no hunt result: "
          f"{[x['pattern_id'] for x in funnel['hunt_failed']]}")


def main():
    for check in (check_ids, check_dedupe, check_primary_prefers_adjudicated,
                  check_reconcile, check_report_paths):
        check()
        print(f"  ✓ {check.__name__}")
    if len(sys.argv) == 3:
        replay(sys.argv[1], sys.argv[2])
    elif len(sys.argv) != 1:
        print("usage: test_funnel.py [hunt.json run.log]", file=sys.stderr)
        return 2
    print("  all funnel invariants hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
