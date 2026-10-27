#!/usr/bin/env python3
"""Offline timeout/harvest regressions (matter efb2a228).

Run with python3 test_batch.py. Only stdlib child processes, never real pi.
"""

import json
import os
import signal
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import harness as H
import revalidate as R

EVENT = {"type": "tool_execution_start", "toolName": "read", "args": {"path": "hung.py"}}
ANSWER = {"type": "agent_end", "messages": [{"role": "assistant", "content": [
    {"type": "text", "text": "[]"}]}]}


def emit(event):
    return f"print({json.dumps(event)!r}, flush=True); "


def run(scripts, directory, timeout=0.35, grace=0.1, finding_ids=True):
    items = [{"pattern_id": f"p{i}", "prompt": script, "repo": str(directory),
              **({"finding_id": f"F-{i}"} if finding_ids else {})}
             for i, script in enumerate(scripts)]

    def command(**kwargs):
        return [sys.executable, "-c", kwargs["prompt"]]

    with patch.object(H, "build_pi_cmd", command), patch.object(H, "PI_TIMEOUT", timeout), \
            patch.object(H, "KILL_GRACE", grace), patch.object(H, "RESULTS_DIR", directory):
        started = time.monotonic()
        rows = H.run_batch(items)
        duration = time.monotonic() - started
    assert all(row.get("error") != "timeout" for row in rows)
    assert all(isinstance(row["elapsed_s"], float) for row in rows)
    assert all(row["elapsed_s"] == round(row["elapsed_s"], 1) for row in rows)
    return rows, duration


def check_session_and_persistence():
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        script = ("import sys,time; print('x'*5000, flush=True); "
                  "print('e'*3000, file=sys.stderr, flush=True); "
                  + emit(ANSWER) + emit(EVENT)
                  + "print('incomplete{', flush=True); time.sleep(10)")
        rows, _ = run([script], directory)
        row = rows[0]
        assert row["error"] == "timeout-session", row
        assert "tool_execution_start" in row["partial_stdout"]
        assert row["partial_stdout"].endswith("incomplete{\n")
        assert len(row["partial_stdout"]) == 4000
        assert len(row["partial_stderr"]) == 2000
        assert row["partial_stderr"].endswith("e\n")
        assert "read hung.py" in row["last_event"], row
        assert row["output"] == "[]", "complete agent_end survives partial stream"
        assert 0.25 <= row["elapsed_s"] <= 0.9, row
        assert row["harvest_truncated"] is False
        files = list(directory.glob("validate-*.json"))
        assert len(files) == 1
        persisted = json.loads(files[0].read_text())
        assert persisted[0]["partial_stdout"] == row["partial_stdout"]
        assert persisted[0]["finding_id"] == "F-0"
        assert "prompt" not in persisted[0] and "repo" not in persisted[0]
        # Same-second calls (including hunt without a finding_id) must not overwrite.
        run(["import time; time.sleep(10)"], directory, timeout=0.1, finding_ids=False)
        assert len(list(directory.glob("validate-*.json"))) == 2
        assert json.loads(files[0].read_text()) == persisted


def check_batch_tail():
    with tempfile.TemporaryDirectory() as tmp:
        rows, _ = run(["import time; " + emit(EVENT) + "time.sleep(10)",
                       "import time; " + emit(EVENT) + "time.sleep(10)",
                       emit(ANSWER)], Path(tmp))
        assert rows[0]["error"] == "timeout-session"
        assert rows[1]["error"] == "timeout-batch-tail"
        assert "read hung.py" in rows[1]["last_event"]
        assert rows[1]["partial_stdout"]
        assert rows[2]["success"] is True, rows[2]
        assert rows[2]["output"] == "[]"
        assert rows[2]["harvested_after_batch_deadline"] is True


def check_inherited_pipes():
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        pid_file = directory / "grandchild.pid"
        script = ("import subprocess,sys,time; "
                  "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); "
                  f"open({str(pid_file)!r},'w').write(str(child.pid)); "
                  + emit(EVENT) + "time.sleep(10)")
        try:
            rows, duration = run([script], directory, timeout=0.2)
            assert duration < 1.5, duration
            row = rows[0]
            assert row["error"] == "timeout-session"
            assert row["harvest_truncated"] is True
            assert "read hung.py" in row["last_event"]
            assert "tool_execution_start" in row["partial_stdout"]
            assert json.loads(next(directory.glob("validate-*.json")).read_text())[0][
                "harvest_truncated"] is True
        finally:
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


def check_terminal_paths():
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        rows, _ = run([emit(ANSWER), "import sys; print('bad', file=sys.stderr); sys.exit(3)"],
                      directory)
        assert rows[0]["success"] is True and rows[0]["output"] == "[]"
        assert rows[1]["error"] == "exit code 3" and rows[1]["stderr"] == "bad"
        assert not list(directory.glob("validate-*.json"))
        rows, _ = run(["import time; print('not json', flush=True); time.sleep(10)"],
                      directory, timeout=0.1)
        assert rows[0]["last_event"] == "No parseable JSONL event"


def check_log_vocabulary():
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "run.log"
        for session, tail, reasons in (
            ("Timeout", "Timeout (batch)", ("timeout", "timeout")),
            ("timeout-session", "timeout-batch-tail", ("timeout-session", "timeout-batch-tail")),
            ("timeout", "Timeout (batch)", ("timeout-session", "timeout-batch-tail")),
        ):
            log.write_text(f"═══ STAGE 3: VALIDATE\n  ✗ {session}: demo\n"
                           f"  ✗ {tail}: demo\n    ⚠ ERROR: A — {reasons[0]}\n"
                           f"    ⚠ ERROR: B — {reasons[1]}\n═══ STAGE 4\n")
            with patch.object(R, "RUN_LOG", log):
                assert R.original_failure_breakdown({"A", "B"}) == (1, 1, 0)


def main():
    for check in (check_session_and_persistence, check_batch_tail, check_inherited_pipes,
                  check_terminal_paths, check_log_vocabulary):
        check()
        print(f"  ✓ {check.__name__}")
    print("  all batch observability checks hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
