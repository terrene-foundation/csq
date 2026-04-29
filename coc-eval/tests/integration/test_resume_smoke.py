"""R3-CRIT-02 / FR-13 / AC-35-36 — resume from INTERRUPTED.json.

Synthetic-process variant: writes an INTERRUPTED.json by hand, calls
`runner.parse_resume`, asserts the deletion-of-in-flight semantics + the
returned (completed_pairs, run_dir) tuple.

A real-process resume (SIGINT mid-suite + actual subprocess re-run)
requires a hung test to interrupt, which is fragile in CI. The unit
tests in `tests/lib/test_runner_resume.py` cover the round-trip; this
integration test covers the resume entry point against a real on-disk
state shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lib.run_id import generate_run_id
from lib.runner import parse_resume


@pytest.mark.integration
def test_resume_with_realistic_state(tmp_path: Path) -> None:
    run_id = generate_run_id()
    run_dir = tmp_path / run_id
    run_dir.mkdir()

    # Two completed (suite, cli) pairs + one in-flight.
    payload = {
        "run_id": run_id,
        "interrupted_at": "2026-04-29T10:30:00.000Z",
        "completed_suite_clis": [
            ["capability", "cc"],
            ["compliance", "cc"],
        ],
        "in_flight": ["safety", "cc"],
    }
    (run_dir / "INTERRUPTED.json").write_text(json.dumps(payload), encoding="utf-8")

    # JSONLs from completed runs + the in-flight one.
    completed_jsonl = run_dir / "capability-2026-04-29T10-15-22Z.jsonl"
    completed_jsonl.write_text('{"_header":true}\n', encoding="utf-8")
    in_flight_jsonl = run_dir / "safety-2026-04-29T10-30-00Z.jsonl"
    in_flight_jsonl.write_text('{"_header":true}\n', encoding="utf-8")

    pairs, returned_dir = parse_resume(run_id, base_results_dir=tmp_path)

    assert pairs == {("capability", "cc"), ("compliance", "cc")}
    assert returned_dir == run_dir
    # Resume cleans up the in-flight JSONL — re-running safety/cc must
    # not produce a duplicate header in the same file.
    assert not in_flight_jsonl.exists()
    # Completed JSONL is untouched.
    assert completed_jsonl.exists()
