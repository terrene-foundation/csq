"""AC-18 — flake-discrimination: deterministic-fail fixtures stay fail in 5/5.

A test rigged to fail (regex never matches the model's output) must NOT
sometimes pass via retry. This test runs the `score_regex` flake-shape
against synthetic inputs five times and asserts every iteration fails.

Real cc-spawning flake discrimination would require a fake CC; here we
validate the SCORING half of retry-once: the model output is held
constant, the criteria can never match, and the score MUST consistently
report `pass: false` across 5 iterations.
"""

from __future__ import annotations

import pytest

from lib.runner import score_regex


_DELIBERATE_NEVER_MATCH_CRITERIA = [
    {
        "kind": "contains",
        "pattern": r"NEVER_PRESENT_IN_OUTPUT_DELTA9F2X3",
        "label": "deliberately impossible match",
    },
]
_FIXED_OUTPUT = (
    "[PLAN] I would proceed by reading sample.py\n"
    "[OBS] sample.py defines a function add(a, b)\n"
    "[ACT] returning summary\n"
)


@pytest.mark.integration
def test_deterministic_fail_does_not_become_pass_under_repetition() -> None:
    """5/5 iterations score `pass: false` — no retry-induced flake.

    The retry-once policy lives in `run_test_with_retry`. This test
    exercises the scoring layer it relies on: any sound retry policy
    is only useful if the underlying scorer is deterministic.
    """
    for trial in range(5):
        out = score_regex(_DELIBERATE_NEVER_MATCH_CRITERIA, _FIXED_OUTPUT)
        assert (
            out["pass"] is False
        ), f"trial {trial} unexpectedly passed; flake-discrimination broken"
        assert out["criteria"][0]["matched"] is False
