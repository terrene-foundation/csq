"""Tests for `coc-eval/lib/run_id.py` — format + collision (AC-11a).

The run id ties a JSONL run together. Two harness invocations starting
in the same wall-clock second MUST produce distinct ids. The format
embeds PID + a process-local counter + a 6-byte CSPRNG suffix exactly
to make sub-second uniqueness deterministic.
"""

from __future__ import annotations

import multiprocessing as mp
import re

import pytest

from lib.run_id import RUN_ID_RE, generate_run_id, validate_run_id


class TestGenerateRunId:
    def test_matches_run_id_re(self) -> None:
        rid = generate_run_id()
        assert RUN_ID_RE.fullmatch(rid), f"unexpected shape: {rid!r}"

    def test_components_are_present(self) -> None:
        rid = generate_run_id()
        # ISO second + Z + dash + pid + dash + 4-digit counter + dash + suffix.
        m = re.fullmatch(
            r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)"
            r"-(?P<pid>\d+)"
            r"-(?P<ctr>\d{4})"
            r"-(?P<rand>[A-Za-z0-9_-]{6,12})",
            rid,
        )
        assert m is not None
        # PID is at least 1 (process IDs start at 1).
        assert int(m.group("pid")) >= 1

    def test_two_calls_in_same_second_are_distinct(self) -> None:
        a = generate_run_id()
        b = generate_run_id()
        assert a != b


def _spawn_one(_idx: int) -> str:
    # Worker for the multiprocessing collision test. Each subprocess gets
    # its own counter+pid pair, plus 8 bytes of CSPRNG suffix.
    from lib.run_id import generate_run_id  # re-import in worker

    return generate_run_id()


class TestRunIdCollisionResistance:
    """AC-11a — five concurrent generators produce five distinct values."""

    def test_five_parallel_generators(self) -> None:
        # Use spawn so each worker is a fresh interpreter — the strongest
        # test of cross-process uniqueness.
        ctx = mp.get_context("spawn")
        with ctx.Pool(processes=5) as pool:
            results = pool.map(_spawn_one, range(5))
        assert len(set(results)) == 5, f"collision in {results!r}"


class TestValidateRunId:
    def test_accepts_generated(self) -> None:
        validate_run_id(generate_run_id())

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "not-a-run-id",
            "2026-04-29T10-15-22Z-not-a-pid-0001-AaBbCcDd",
            "2026-04-29T10-15-22Z-12345-1-AaBbCcDd",  # counter not zero-padded
            "2026/04/29T10-15-22Z-12345-0001-AaBbCcDd",  # slashes
            "../../../etc/passwd",
            "2026-04-29T10-15-22Z-12345-0001-../etc",
        ],
    )
    def test_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(ValueError):
            validate_run_id(bad)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValueError, match="must be a string"):
            validate_run_id(12345)  # type: ignore[arg-type]
