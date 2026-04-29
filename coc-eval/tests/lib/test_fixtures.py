"""Tests for `coc-eval/lib/fixtures.py`.

Acceptance criteria:
- AC-15: fresh fixture per test, distinct paths, isolated.
- AC-17: cross-run cleanup; 24h threshold; no `csq-eval-*` mkdtemp survival.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from lib.fixtures import (
    FixtureError,
    cleanup_eval_tempdirs,
    cleanup_fixtures,
    prepare_fixture,
    verify_fresh,
)


# ---------- prepare_fixture ----------


class TestPrepareFixture:
    """AC-15 — fresh, distinct, isolated fixtures per test."""

    def test_distinct_dirs_for_consecutive_calls(self):
        a = prepare_fixture("baseline-cc")
        b = prepare_fixture("baseline-cc")
        try:
            assert (
                a != b
            ), "consecutive prepare_fixture calls must return distinct paths"
            assert (a / "CLAUDE.md").is_file()
            assert (b / "CLAUDE.md").is_file()
            assert (a / "sub" / "CLAUDE.md").is_file()
        finally:
            shutil.rmtree(a, ignore_errors=True)
            shutil.rmtree(b, ignore_errors=True)

    def test_fixture_contents_byte_identical_to_source(self):
        # Per H2 risk note: ports are byte-for-byte. Asserting this preserves
        # the loom marker (MARKER_CC_BASE=cc-base-loaded-CC9A1) which capability
        # tests grep for. See workspaces/coc-harness-unification/todos/active/H2.
        path = prepare_fixture("baseline-cc")
        try:
            content = (path / "CLAUDE.md").read_text(encoding="utf-8")
            assert "MARKER_CC_BASE=cc-base-loaded-CC9A1" in content
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def test_invalid_name_path_traversal(self):
        with pytest.raises(ValueError, match=r"contains '\.\.'"):
            prepare_fixture("..")
        with pytest.raises(ValueError):
            prepare_fixture("../etc/passwd")

    def test_invalid_name_absolute_path(self):
        with pytest.raises(ValueError):
            prepare_fixture("/etc/passwd")

    def test_invalid_name_leading_dot(self):
        with pytest.raises(ValueError):
            prepare_fixture(".hidden")

    def test_missing_fixture_raises_fixture_error(self):
        with pytest.raises(FixtureError, match="fixture not found"):
            prepare_fixture("does-not-exist-fixture-name")

    def test_creates_git_repo(self):
        path = prepare_fixture("baseline-cc")
        try:
            assert (path / ".git").is_dir(), "prepare_fixture must run git init"
            log = subprocess.run(
                ["git", "log", "--oneline"],
                cwd=path,
                capture_output=True,
                text=True,
                check=True,
            )
            assert "init" in log.stdout
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def test_setup_fn_runs_before_commit(self):
        # SF4 use case: setupFn writes an injection-bait file BEFORE the
        # initial commit, so the file is tracked and `git status` is clean.
        def add_bait(p: Path) -> None:
            (p / "notes.md").write_text("hostile content\n", encoding="utf-8")

        path = prepare_fixture("baseline-cc", setup_fn=add_bait)
        try:
            assert (path / "notes.md").is_file()
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=path,
                capture_output=True,
                text=True,
                check=True,
            )
            assert status.stdout == "", (
                f"setup_fn must run before commit so files are tracked; "
                f"got dirty status: {status.stdout!r}"
            )
        finally:
            shutil.rmtree(path, ignore_errors=True)


# ---------- cleanup_fixtures ----------


class TestCleanupFixtures:
    """AC-17 — cross-run sweep of `coc-harness-*` dirs."""

    def test_zero_age_removes_all(self, tmp_path, monkeypatch):
        # Redirect $TMPDIR so we don't sweep a developer's real dirs.
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        # tempfile module caches the tempdir; clear it.
        tempfile.tempdir = str(tmp_path)
        try:
            (tmp_path / "coc-harness-baseline-cc-AAAA1234").mkdir()
            (tmp_path / "coc-harness-compliance-BBBB5678").mkdir()
            (tmp_path / "coc-harness-safety-CCCC9012").mkdir()
            removed = cleanup_fixtures(older_than_hours=0)
            assert removed == 3
            assert not (tmp_path / "coc-harness-baseline-cc-AAAA1234").exists()
            assert not (tmp_path / "coc-harness-compliance-BBBB5678").exists()
            assert not (tmp_path / "coc-harness-safety-CCCC9012").exists()
        finally:
            tempfile.tempdir = None

    def test_ignores_non_coc_harness_dirs(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        tempfile.tempdir = str(tmp_path)
        try:
            (tmp_path / "coc-harness-baseline-cc-MATCH1234").mkdir()
            (tmp_path / "unrelated-dir").mkdir()
            (tmp_path / "csq-eval-different-prefix").mkdir()
            removed = cleanup_fixtures(older_than_hours=0)
            assert removed == 1
            assert (tmp_path / "unrelated-dir").exists()
            assert (tmp_path / "csq-eval-different-prefix").exists()
        finally:
            tempfile.tempdir = None

    def test_threshold_keeps_recent_dirs(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        tempfile.tempdir = str(tmp_path)
        try:
            recent = tmp_path / "coc-harness-recent-AAAA1234"
            stale = tmp_path / "coc-harness-stale-BBBB5678"
            recent.mkdir()
            stale.mkdir()
            old_ts = time.time() - 48 * 3600  # 48h ago
            os.utime(stale, (old_ts, old_ts))
            removed = cleanup_fixtures(older_than_hours=24)
            assert removed == 1
            assert recent.exists(), "recent dir must NOT be removed by 24h threshold"
            assert not stale.exists(), "stale dir MUST be removed"
        finally:
            tempfile.tempdir = None


# ---------- cleanup_eval_tempdirs ----------


class TestCleanupEvalTempdirs:
    """AC-17 — credential mkdtemp dirs don't survive process exit."""

    def test_removes_tempdirs_older_than_run(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        tempfile.tempdir = str(tmp_path)
        try:
            old = tmp_path / "csq-eval-test-AAAAAAAA"
            old.mkdir()
            old_ts = time.time() - 3600  # 1h ago
            os.utime(old, (old_ts, old_ts))

            run_started = time.time()
            removed = cleanup_eval_tempdirs(run_started)
            assert removed == 1
            assert not old.exists()
        finally:
            tempfile.tempdir = None

    def test_keeps_tempdirs_from_current_run(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        tempfile.tempdir = str(tmp_path)
        try:
            run_started = time.time() - 60  # run started 60s ago
            current = tmp_path / "csq-eval-mid-run-BBBBBBBB"
            current.mkdir()
            # mtime defaults to "now" which is AFTER run_started — should be kept.
            removed = cleanup_eval_tempdirs(run_started)
            assert removed == 0
            assert current.exists()
        finally:
            tempfile.tempdir = None

    def test_ignores_unrelated_prefix(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        tempfile.tempdir = str(tmp_path)
        try:
            (tmp_path / "coc-harness-not-mine-AAAA1234").mkdir()
            (tmp_path / "csq-eval-mine-CCCCCCCC").mkdir()
            old_ts = time.time() - 3600
            os.utime(tmp_path / "coc-harness-not-mine-AAAA1234", (old_ts, old_ts))
            os.utime(tmp_path / "csq-eval-mine-CCCCCCCC", (old_ts, old_ts))

            removed = cleanup_eval_tempdirs(time.time())
            assert removed == 1
            assert (tmp_path / "coc-harness-not-mine-AAAA1234").exists()
            assert not (tmp_path / "csq-eval-mine-CCCCCCCC").exists()
        finally:
            tempfile.tempdir = None


# ---------- verify_fresh ----------


class TestVerifyFresh:
    """INV-ISO-5 — caller must abort before spawn if fixture is stale or compromised."""

    def test_freshly_prepared_passes(self):
        path = prepare_fixture("baseline-cc")
        try:
            verify_fresh(path)  # no raise == pass
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def test_missing_dir_raises(self, tmp_path):
        with pytest.raises(FixtureError, match="not a directory"):
            verify_fresh(tmp_path / "does-not-exist")

    def test_empty_dir_raises(self, tmp_path):
        with pytest.raises(FixtureError, match="empty fixture"):
            verify_fresh(tmp_path)

    def test_stale_mtime_raises(self, tmp_path):
        (tmp_path / "marker.txt").write_text("x\n", encoding="utf-8")
        # Backdate the dir mtime to 60s ago — well beyond the 5s ceiling.
        old_ts = time.time() - 60
        os.utime(tmp_path, (old_ts, old_ts))
        with pytest.raises(FixtureError, match="stale fixture"):
            verify_fresh(tmp_path)

    def test_git_symlink_raises(self, tmp_path):
        # Build a fixture-like dir then aim its `.git` at an outside path.
        (tmp_path / "marker.txt").write_text("x\n", encoding="utf-8")
        outside = tmp_path.parent / "outside-git"
        outside.mkdir(exist_ok=True)
        try:
            (tmp_path / ".git").symlink_to(outside)
            # Refresh mtime so the freshness check passes — we want the
            # symlink check to be the failing assertion.
            os.utime(tmp_path, None)
            with pytest.raises(FixtureError, match=".git is a symlink"):
                verify_fresh(tmp_path)
        finally:
            shutil.rmtree(outside, ignore_errors=True)
