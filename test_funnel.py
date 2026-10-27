#!/usr/bin/env python3
"""Funnel-accounting and dedupe invariants for harness.py.

No test framework — plain asserts, stdlib only, matching the harness style.

    python3 test_funnel.py                       # synthetic checks only
    python3 test_funnel.py hunt.json run1.log     # + replay of a real run

The replay rebuilds the accounting `stage_hunt`/`stage_validate` would have
produced from a persisted hunt artefact and a run log, then asserts the funnel
reconciles and that no carried-forward finding disappears from the report.
"""

import contextlib
import io
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness as H  # noqa: E402
import revalidate as R  # noqa: E402


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


def check_dedupe_template_exemptions():
    hunt = [{"pattern_id": pattern, "findings": [{
        "id": f"F-{pattern}-001", "severity": "CRITICAL", "confidence": "CONFIRMED",
        "location": ".env.example:1", "sink": "runtime setting",
    }]} for pattern in ("secrets-in-source", "sensitive-files")]
    before = json.dumps(hunt)
    rows = {row["pattern"]: row for row in H.stage_dedupe(hunt, [])}
    assert rows["secrets-in-source"]["severity"] == "CRITICAL"
    assert rows["secrets-in-source"]["confidence"] == "CONFIRMED"
    assert "severity_caveat" not in rows["secrets-in-source"]
    assert rows["sensitive-files"]["severity"] == "HIGH"
    assert rows["sensitive-files"]["confidence"] == "SUSPECTED"
    assert rows["sensitive-files"]["severity_caveat"]
    assert json.dumps(hunt) == before, "dedupe must not mutate raw hunter evidence"


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


def check_config_refs():
    templates = [".env.example", ".env.production.example", "config.example.json",
                 "docker-compose.example.yml", "settings.template.yaml", "wrangler.example.toml",
                 ".env.sample", ".env.dist", ".env.default", ".env.defaults", "x.sample.ini",
                 "x.dist.cfg", "x.default.conf", "x.defaults.conf"]
    configs = [".env", ".env.local", "docker-compose.yml", "config.json", "settings.yaml",
               "wrangler.toml", "x.ini", "x.cfg", "x.conf",
               "/etc/nginx/conf.d/default.conf", "config/default.json"]
    ignored = ["sampler.sample", "a.b.example", "views/invoice.template", "x.template.ts",
               "README.example.json", "README.env", "docs/.env.example", "tests/config.json",
               "fixtures/x.template.yaml", "__fixtures__/.env", "test/.env", "doc/.env",
               "http://evil.example:8080", "https://evil.example/config.example.json",
               "//evil.example/config.json", r"C:\docs\.env.example", ".env.example/",
               "config.example.json/", "", "src/a.ts", "x.py", "x.env", "x.defaults.env",
               "process.env", "import.meta.env", "os.environ", "{...process.env",
               "res.json({...})", "req.json()", "NextResponse.json({...})"]
    assert H.normalize_ref(r"C:\docs\.env.example/") == "C:/docs/.env.example"
    print("    PASS normalize Windows path/trailing slash")
    for ref in ("", "/", "//host/.env", "http://host/.env", r"\\host\.env"):
        assert H.normalize_ref(ref) is None, ref
        print(f"    PASS normalize {ref!r}: None")
    for ref in templates + configs:
        assert H.is_config_file(ref), ref
    for ref in templates + configs + ignored:
        assert H.is_template_path(ref) == (ref in templates), ref
        expected = ([ref], []) if ref in templates else ([], [ref]) if ref in configs else ([], [])
        for field in ("location", "source", "sink", "attack_scenario"):
            for suffix in ("", ":123", ":105-123", ":", ":10:20", ":10-12:20:"):
                for text in (ref + suffix, f"UPLOAD_DIR in `{ref}{suffix}` points to a value."):
                    assert H.extract_config_refs({field: text}) == expected, (field, text)
        print(f"    PASS {ref!r}: templates={expected[0]}, configs={expected[1]} "
              "(4 fields × 6 suffixes × bare/quoted)")
    for text, expected in (
        (".env.example:", ([".env.example"], [])),
        (".env.example:10:20", ([".env.example"], [])),
        ("src/config.example.json:10:20", (["src/config.example.json"], [])),
        ("{[(`.env.example:10:20`)]}", ([".env.example"], [])),
        ("res.json ({...})", ([], [])),
        ("req.json() + .env.example:", ([".env.example"], [])),
        ("process.env + .env.example:", ([".env.example"], [])),
        ("/etc/nginx/conf.d/default.conf", ([], ["/etc/nginx/conf.d/default.conf"])),
        ("config/default.json", ([], ["config/default.json"])),
    ):
        assert H.extract_config_refs({"location": text}) == expected, text
        print(f"    PASS {text!r}: templates={expected[0]}, configs={expected[1]}")
    for call in ("res.json({...})", "req.json()", "NextResponse.json({...})"):
        assert not H.is_config_file(call), call
    assert H.extract_config_refs({"location": r"C:\app\.env.example:8"}) == (
        ["C:/app/.env.example"], [])
    assert H.extract_config_refs({"location": ".env.example:8 + .env.local:9"}) == (
        [".env.example"], [".env.local"])
    assert H.extract_config_refs({"evidence": ".env.example"}) == ([], [])
    print("    PASS Windows line-qualified runtime path: templates=['C:/app/.env.example']")
    print("    PASS mixed refs: templates=['.env.example'], configs=['.env.local']")
    print("    PASS evidence field ignored: templates=[], configs=[]")


def check_template_cap():
    finding = _finding("F-demo-001", "s", severity="CRITICAL")
    finding["location"] = ".env.example"
    H.apply_template_severity_cap(finding)
    assert finding["severity"] == "HIGH" and finding["confidence"] == "SUSPECTED"
    assert "not verified against the deployed configuration" in finding["severity_caveat"]
    before = json.dumps(finding)
    with contextlib.redirect_stdout(io.StringIO()) as output:
        assert H.apply_template_severity_cap(finding) is finding
    assert json.dumps(finding) == before and output.getvalue() == ""
    for severity in ("LOW", "MEDIUM", "HIGH", "UNKNOWN"):
        for pattern in ("demo", "secrets-in-source", "origin-ip-exposed"):
            row = dict(finding, severity=severity, pattern=pattern, confidence="CONFIRMED")
            row.pop("severity_caveat")
            before = json.dumps(row)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                H.apply_template_severity_cap(row)
            assert json.dumps(row) == before and output.getvalue() == ""
    for pattern in H.TEMPLATE_CAP_EXEMPT_PATTERNS:
        row = dict(finding, severity="CRITICAL", pattern=pattern, confidence="CONFIRMED")
        row.pop("severity_caveat")
        before = json.dumps(row)
        H.apply_template_severity_cap(row)
        assert json.dumps(row) == before
    for location in (".env.example + .env.local", "x.ts:1 + y.py:3"):
        row = dict(finding, severity="CRITICAL", location=location)
        row.pop("severity_caveat")
        before = json.dumps(row)
        H.apply_template_severity_cap(row)
        assert json.dumps(row) == before


def check_offline_rebuild():
    """Legacy flags, cap repair, missing accounting and live intel all survive rebuild."""
    old_results, old_original, old_log = H.RESULTS_DIR, R.REPORT_JSON, R.RUN_LOG
    try:
        with tempfile.TemporaryDirectory(prefix="rebuild-") as tmp:
            H.RESULTS_DIR = Path(tmp)
            R.REPORT_JSON = Path(tmp) / "original.json"
            R.RUN_LOG = Path(tmp) / "missing.log"
            rows = [_finding("F-demo-001", "s"), _finding("F-demo-002", "s", validated=False)]
            for row in rows:
                row.pop("validation_state")
            report = {"repository": ".", "generated_at": "2026-10-26T00:00:00",
                      "summary": {}, "findings": rows}
            R.REPORT_JSON.write_text(json.dumps(report))
            # Simulate the old cap changing a non-CRITICAL finding.
            rows[0]["confidence"] = "SUSPECTED"
            rows[0]["severity_caveat"] = "⚠ Severity capped at HIGH: legacy cap"
            (Path(tmp) / "revalidate-state.json").write_text('{"verdicts": {}}')
            (Path(tmp) / "live-context-20261026-123919.md").write_text(
                "## Dependency evidence\nRecorded advisory\n")
            out = Path(tmp) / "rebuilt.json"
            out.write_text(json.dumps(report))
            R.rebuild_artifacts(out)
            rebuilt = json.loads(out.read_text())
            assert [f["validation_state"] for f in rebuilt["findings"]] == ["validated", "unvalidated"]
            assert "breakdown unavailable" in rebuilt["revalidation_note"]
            assert rebuilt["findings"][0]["confidence"] == "CONFIRMED"
            assert "severity_caveat" not in rebuilt["findings"][0]
            md = out.with_suffix(".md").read_text()
            assert "No funnel accounting was recorded" in md and "FUNNEL MISMATCH" not in md
            assert "## Known Vulnerabilities in Dependencies" in md and "Recorded advisory" in md
            before = (out.read_bytes(), out.with_suffix(".md").read_bytes())
            R.rebuild_artifacts(out)
            assert before == (out.read_bytes(), out.with_suffix(".md").read_bytes())
            R.RUN_LOG.write_text("═══ STAGE 3: VALIDATE\n  ✗ Timeout: demo\n"
                                 "  ✗ Timeout (batch): demo\n"
                                 "    ⚠ ERROR: A — timeout\n    ⚠ ERROR: B — timeout\n"
                                 "═══ STAGE 4\n")
            assert R.original_failure_breakdown({"A", "B"}) == (1, 1, 0)
            assert R.original_failure_breakdown({"A"}) is None
            R.RUN_LOG.write_text("malformed")
            assert R.original_failure_breakdown({"A", "B"}) is None
    finally:
        H.RESULTS_DIR, R.REPORT_JSON, R.RUN_LOG = old_results, old_original, old_log


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
    for check in (check_ids, check_dedupe, check_dedupe_template_exemptions,
                  check_primary_prefers_adjudicated,
                  check_reconcile, check_report_paths, check_config_refs,
                  check_template_cap, check_offline_rebuild):
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
