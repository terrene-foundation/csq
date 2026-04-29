"""Tests for `coc-eval/lib/auth.py` — real probe, caching, mid-run invalidation.

Covers:
- `probe_auth("cc", suite)` round-trip: ok=True on a healthy binary; ok=False
  on missing binary, on subprocess error, on timeout.
- Cache scoping: per-(cli, suite) memoization (INV-AUTH-1).
- Mid-run invalidation: `mark_auth_changed("cc")` clears all suites for cc.
- `is_auth_error_line` classifies the INV-AUTH-3 trigger patterns.
"""

from __future__ import annotations

import shutil
import stat
from collections.abc import Generator
from pathlib import Path

import pytest

from lib.auth import (
    is_auth_error_line,
    mark_auth_changed,
    probe_auth,
    reset_cache,
)


@pytest.fixture(autouse=True)
def clean_cache() -> Generator[None, None, None]:
    """Each test starts with an empty probe cache so tests don't leak state."""
    reset_cache()
    yield
    reset_cache()


def _make_executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class TestProbeMissingBinary:
    def test_returns_skip_when_claude_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "lib.auth.shutil.which",
            lambda name: None if name == "claude" else shutil.which(name),
        )
        result = probe_auth("cc", "capability")
        assert result.ok is False
        assert "binary not found" in (result.reason or "")
        assert result.version == ""


class TestProbeRealCcBinary:
    """When claude IS available on PATH, the probe should return ok=True
    against the user's real credentials. Skips if either is missing — the
    runner uses `skipped_cli_missing` / `skipped_cli_auth` accordingly.
    """

    def test_real_probe_succeeds_or_reports_reason(self) -> None:
        if shutil.which("claude") is None:
            pytest.skip("claude binary not on PATH")
        result = probe_auth("cc", "capability")
        # Either success (auth valid) OR a structured failure reason; in
        # both cases the probe MUST return without raising.
        if result.ok:
            assert result.reason is None
            assert result.version  # version captured opportunistically
        else:
            assert result.reason
            # No partial-state leak — token-shaped substrings should not
            # surface in the reason.
            assert "sk-ant-" not in result.reason

    def test_unknown_cli_returns_failure(self) -> None:
        result = probe_auth("nonexistent_cli", "capability")
        assert result.ok is False
        assert "no probe registered" in (result.reason or "")


class TestProbeTimeout:
    """Synthetic binary that sleeps past the probe timeout MUST surface
    as `ok=False, reason="probe timed out…"`.
    """

    def test_timeout_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Build a fake `claude` that sleeps longer than the test timeout.
        fake = _make_executable(
            tmp_path / "claude",
            "#!/bin/sh\nsleep 5\n",
        )

        # Resolve any `claude` lookup to our fake.
        monkeypatch.setattr(
            "lib.auth.shutil.which",
            lambda name: str(fake) if name == "claude" else shutil.which(name),
        )
        # Tighten the timeout to keep the test cheap (~0.5s).
        monkeypatch.setattr("lib.auth._PROBE_TIMEOUT_SEC", 0.5)
        monkeypatch.setattr("lib.auth._VERSION_TIMEOUT_SEC", 0.5)

        result = probe_auth("cc", "capability")
        assert result.ok is False
        assert "timed out" in (result.reason or "")

    def test_nonzero_exit_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fake `claude` that exits 1 with a stderr message.
        fake = _make_executable(
            tmp_path / "claude",
            '#!/bin/sh\necho "auth required" 1>&2\nexit 1\n',
        )
        monkeypatch.setattr(
            "lib.auth.shutil.which",
            lambda name: str(fake) if name == "claude" else shutil.which(name),
        )
        monkeypatch.setattr("lib.auth._PROBE_TIMEOUT_SEC", 5.0)

        result = probe_auth("cc", "capability")
        assert result.ok is False
        # Non-token-shaped messages bubble through redaction unchanged.
        assert "auth required" in (result.reason or "")

    def test_stderr_token_redacted_in_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """H1 hardening from H3 review: token-shaped strings in cc's stderr
        MUST NOT survive into AuthProbeResult.reason. Defense in depth so a
        downstream JSONL writer that forgets to call redact_tokens can never
        leak a refresh-token prefix.
        """
        # Fake `claude` that echoes a known OAuth-prefix token shape.
        token_shape = "sk-ant-oat01-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        fake = _make_executable(
            tmp_path / "claude",
            f'#!/bin/sh\necho "OAuth: invalid_grant token={token_shape}" 1>&2\nexit 1\n',
        )
        monkeypatch.setattr(
            "lib.auth.shutil.which",
            lambda name: str(fake) if name == "claude" else shutil.which(name),
        )
        monkeypatch.setattr("lib.auth._PROBE_TIMEOUT_SEC", 5.0)

        result = probe_auth("cc", "capability")
        assert result.ok is False
        assert token_shape not in (
            result.reason or ""
        ), f"AuthProbeResult.reason leaked the token shape unredacted: {result.reason!r}"
        # Helpful diagnostic substring should still survive.
        assert "invalid_grant" in (result.reason or "")


class TestCachePerSuite:
    def test_same_suite_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Counter-binary increments a file each call so we can detect cache hits.
        counter = tmp_path / "counter"
        fake = _make_executable(
            tmp_path / "claude",
            f'#!/bin/sh\necho "$$" >> "{counter}"\nexit 0\n',
        )
        monkeypatch.setattr(
            "lib.auth.shutil.which",
            lambda name: str(fake) if name == "claude" else shutil.which(name),
        )
        monkeypatch.setattr("lib.auth._PROBE_TIMEOUT_SEC", 5.0)

        first = probe_auth("cc", "capability")
        second = probe_auth("cc", "capability")
        assert first is second  # cache returns the SAME object

        # The fake binary records two PIDs — one for `--version`, one for
        # the actual probe. So one probe → two file lines.
        if counter.exists():
            line_count = len(counter.read_text(encoding="utf-8").splitlines())
            assert line_count <= 2, "probe re-ran despite cache"

    def test_different_suite_re_probes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_executable(
            tmp_path / "claude",
            "#!/bin/sh\nexit 0\n",
        )
        monkeypatch.setattr(
            "lib.auth.shutil.which",
            lambda name: str(fake) if name == "claude" else shutil.which(name),
        )
        monkeypatch.setattr("lib.auth._PROBE_TIMEOUT_SEC", 5.0)

        first = probe_auth("cc", "capability")
        second = probe_auth("cc", "compliance")
        assert first is not second  # different cache keys


class TestMidRunInvalidation:
    def test_mark_auth_changed_clears_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_executable(
            tmp_path / "claude",
            "#!/bin/sh\nexit 0\n",
        )
        monkeypatch.setattr(
            "lib.auth.shutil.which",
            lambda name: str(fake) if name == "claude" else shutil.which(name),
        )
        monkeypatch.setattr("lib.auth._PROBE_TIMEOUT_SEC", 5.0)

        first = probe_auth("cc", "capability")
        mark_auth_changed("cc")
        second = probe_auth("cc", "capability")
        assert first is not second  # post-invalidation re-probe

    def test_mark_auth_changed_other_cli_isolated(self) -> None:
        # Seed cache with a `nonexistent_cli` no-probe-registered result.
        seed = probe_auth("nonexistent_cli", "capability")
        # Invalidating a different CLI MUST NOT touch this entry.
        mark_auth_changed("cc")
        again = probe_auth("nonexistent_cli", "capability")
        assert seed is again


class TestIsAuthErrorLine:
    @pytest.mark.parametrize(
        "line",
        [
            "401 Unauthorized",
            "OAuth: invalid_grant",
            "API responded: expired_token",
        ],
    )
    def test_matches_known_patterns(self, line: str) -> None:
        assert is_auth_error_line(line) is True

    def test_does_not_match_unrelated_lines(self) -> None:
        assert is_auth_error_line("hello world") is False
        assert is_auth_error_line("rate_limit_exceeded") is False  # different state

    def test_empty_string(self) -> None:
        assert is_auth_error_line("") is False
