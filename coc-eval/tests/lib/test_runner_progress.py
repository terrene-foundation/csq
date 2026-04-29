"""Unit tests for `ProgressEmitter` (pretty + jsonl + monotonic ETA)."""

from __future__ import annotations

import io
import json

from lib.runner import ProgressEmitter
from lib.states import State


def _make(format: str) -> tuple[ProgressEmitter, io.StringIO, dict[str, list[float]]]:
    out = io.StringIO()
    history: dict[str, list[float]] = {}
    emitter = ProgressEmitter(format=format, out=out, runtime_history=history)
    return emitter, out, history


def test_pretty_format_emits_running_then_terminal() -> None:
    emitter, out, _ = _make("pretty")
    emitter.total_tests = 3
    emitter.running("capability", "C1-baseline-root", "cc", "baseline-cc")
    emitter.terminal("capability", "C1-baseline-root", "cc", State.PASS, 4500)
    text = out.getvalue()
    assert "RUNNING" in text
    assert "PASS" in text
    assert "C1-baseline-root" in text
    # AC-34: exactly one RUNNING + one terminal line per test.
    assert text.count("RUNNING") == 1
    assert text.count("\n") >= 2


def test_jsonl_format_emits_one_record_per_event() -> None:
    emitter, out, _ = _make("jsonl")
    emitter.total_tests = 2
    emitter.running("capability", "C1", "cc", "baseline-cc")
    emitter.terminal("capability", "C1", "cc", State.PASS, 1234)
    lines = [line for line in out.getvalue().splitlines() if line]
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "running"
    assert json.loads(lines[1])["event"] == "terminal"
    assert json.loads(lines[1])["state"] == "pass"


def test_eta_monotonic_or_decreasing_across_terminals() -> None:
    """AC-34: ETA never increases between successive terminal events."""
    emitter, out, _ = _make("pretty")
    emitter.total_tests = 5
    etas: list[float] = []
    for i in range(5):
        emitter.running("capability", f"C{i}", "cc", "fix")
        emitter.terminal("capability", f"C{i}", "cc", State.PASS, 4000)
        etas.append(emitter._compute_eta("cc"))
    # Each subsequent ETA should be <= the previous (denominator decreases,
    # rolling avg is bounded). For uniform 4s runtimes the ETA strictly
    # decreases by ~4s per terminal until it hits 0.
    for prev, curr in zip(etas, etas[1:]):
        assert curr <= prev, f"ETA increased: {prev} → {curr}"


def test_eta_zero_when_no_runtime_history() -> None:
    emitter, _out, _ = _make("pretty")
    emitter.total_tests = 1
    assert emitter._compute_eta("cc") == 0.0


def test_json_format_emits_nothing_for_intermediate_events() -> None:
    """`json` format reserves stdout for the final aggregate dict."""
    emitter, out, _ = _make("json")
    emitter.running("capability", "C1", "cc", "fix")
    emitter.terminal("capability", "C1", "cc", State.PASS, 100)
    assert out.getvalue() == ""
