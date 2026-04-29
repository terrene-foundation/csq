"""H5-T-9 — `_verify_results_path_gitignored` against a controlled tmp git repo.

Confirms the H5 fix (probe sub-path instead of dir) works for both shapes:
  - results dir IS gitignored via `<dir>/` pattern → no raise
  - results dir NOT in .gitignore → RuntimeError

Tests build a self-contained git repo in `tmp_path` and exercise the check
against it. No coupling to the real repo's .gitignore.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from lib.jsonl import _verify_results_path_gitignored


def _init_repo(repo_root: Path) -> None:
    subprocess.run(
        ["git", "init", "-q"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )


def _need_trusted_git() -> None:
    """Skip if `git` resolves outside the trusted-prefix allowlist.

    The H4 hardening only runs the check when `git` lives in
    `/usr/bin`, `/bin`, `/usr/local/bin`, or `/opt/homebrew/bin`. On a
    pyenv-shim or asdf box, the check skips silently — that's correct
    behavior under the threat model, but it means the test cannot
    exercise the assertion.
    """
    git_bin = shutil.which("git")
    if git_bin is None:
        pytest.skip("git not on PATH")
    if not git_bin.startswith(
        ("/usr/bin/", "/bin/", "/usr/local/bin/", "/opt/homebrew/bin/")
    ):
        pytest.skip(
            f"git binary {git_bin!r} outside trusted prefixes; check skipped by design"
        )


def test_gitignored_results_passes(tmp_path: Path) -> None:
    _need_trusted_git()
    _init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("results/\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    # Should NOT raise — the probe matches `results/` pattern.
    _verify_results_path_gitignored(results_dir)


def test_unignored_results_raises(tmp_path: Path) -> None:
    _need_trusted_git()
    _init_repo(tmp_path)
    # Empty .gitignore — results dir is NOT ignored.
    (tmp_path / ".gitignore").write_text("\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    with pytest.raises(RuntimeError, match="MED-04"):
        _verify_results_path_gitignored(results_dir)


def test_no_gitignore_at_repo_root_raises(tmp_path: Path) -> None:
    """Repo without a `.gitignore` at root: nothing matches → MED-04 fires."""
    _need_trusted_git()
    _init_repo(tmp_path)
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    with pytest.raises(RuntimeError, match="MED-04"):
        _verify_results_path_gitignored(results_dir)


def test_no_repo_skips_check(tmp_path: Path) -> None:
    """Walking up without finding `.git/` is a no-op — best-effort guard."""
    # No `git init` here; `.git/` is absent.
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    # Should NOT raise — the function returns silently when no repo found.
    _verify_results_path_gitignored(results_dir)
