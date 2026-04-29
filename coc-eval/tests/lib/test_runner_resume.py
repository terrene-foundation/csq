"""Runner resume + INTERRUPTED.json round-trip (R3-CRIT-02 / FR-13)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lib import runner
from lib.run_id import generate_run_id
from lib.runner import (
    RunContext,
    RunSelection,
    parse_resume,
    read_interrupted,
)


def _make_ctx(run_id: str, results_root: Path) -> RunContext:
    sel = RunSelection(
        suites=("capability",),
        clis=("cc",),
        tests=None,
        tags=None,
        skip_clis=frozenset(),
        skip_suites=frozenset(),
    )
    return RunContext(
        run_id=run_id,
        started_at_iso="2026-04-29T10:15:22.000Z",
        started_at_mono=0.0,
        results_root=results_root,
        selection=sel,
        invocation="test",
        token_budget_input=None,
        token_budget_output=None,
    )


def test_write_and_read_interrupted_round_trip(tmp_path: Path) -> None:
    run_id = generate_run_id()
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    ctx = _make_ctx(run_id, run_dir)
    ctx.completed_pairs = {("capability", "cc"), ("compliance", "cc")}
    ctx.in_flight_pair = ("safety", "cc")
    runner._write_interrupted(ctx)
    payload = read_interrupted(run_dir)
    assert payload is not None
    assert payload["run_id"] == run_id
    assert sorted(payload["completed_suite_clis"]) == [
        ["capability", "cc"],
        ["compliance", "cc"],
    ]
    assert payload["in_flight"] == ["safety", "cc"]


def test_read_interrupted_missing_file_returns_none(tmp_path: Path) -> None:
    assert read_interrupted(tmp_path) is None


def test_read_interrupted_bad_json_returns_none(tmp_path: Path) -> None:
    (tmp_path / "INTERRUPTED.json").write_text("not json {", encoding="utf-8")
    assert read_interrupted(tmp_path) is None


def test_parse_resume_returns_completed_pairs(tmp_path: Path) -> None:
    run_id = generate_run_id()
    run_dir = tmp_path / run_id
    run_dir.mkdir()
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
    pairs, returned_dir = parse_resume(run_id, base_results_dir=tmp_path)
    assert pairs == {("capability", "cc"), ("compliance", "cc")}
    assert returned_dir == run_dir


def test_parse_resume_deletes_in_flight_jsonl(tmp_path: Path) -> None:
    """Resume cleans up the partial JSONL from the in-flight (suite, cli)."""
    run_id = generate_run_id()
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    in_flight_jsonl = run_dir / "safety-2026-04-29T10-15-22Z.jsonl"
    in_flight_jsonl.write_text('{"_header":true}\n', encoding="utf-8")
    completed_jsonl = run_dir / "capability-2026-04-29T10-15-22Z.jsonl"
    completed_jsonl.write_text('{"_header":true}\n', encoding="utf-8")
    payload = {
        "run_id": run_id,
        "interrupted_at": "2026-04-29T10:30:00.000Z",
        "completed_suite_clis": [["capability", "cc"]],
        "in_flight": ["safety", "cc"],
    }
    (run_dir / "INTERRUPTED.json").write_text(json.dumps(payload), encoding="utf-8")
    pairs, _ = parse_resume(run_id, base_results_dir=tmp_path)
    assert pairs == {("capability", "cc")}
    assert (
        not in_flight_jsonl.exists()
    ), "resume must delete in-flight jsonl (cleaner than truncating)"
    assert completed_jsonl.exists(), "resume must NOT touch JSONLs from completed pairs"


def test_parse_resume_rejects_malformed_run_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        parse_resume("garbage", base_results_dir=tmp_path)


def test_parse_resume_missing_run_dir(tmp_path: Path) -> None:
    run_id = generate_run_id()
    with pytest.raises(ValueError, match="run dir not found"):
        parse_resume(run_id, base_results_dir=tmp_path)
