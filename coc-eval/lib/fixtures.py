"""Per-test fixture lifecycle: copy → git-init → commit → verify → cleanup.

Mirrors loom's `prepareFixture`/`cleanupFixtures` (`harness.mjs:264-303`).
The Python port stays stdlib-only per `rules/independence.md` §3.

Why per-test tmpdir copies (not in-place fixture mutation):

- INV-ISO-5: every test starts with a fresh, byte-identical fixture. A test
  that mutates `coc-eval/fixtures/<name>/` would leak state into the next
  test in the same run.
- INV-PAR-1: byte-identical inputs across CLIs. The same prepared fixture
  path is passed to cc/codex/gemini for the same test ID.
- The `git init + commit` step lets implementation-suite tests use
  `git diff` / `git status` to detect file-edit operations the model
  performed, without polluting the tracked fixture source.

Cleanup is two-tiered:

- `cleanup_fixtures(older_than_hours)` — sweeps stale `coc-harness-*` dirs
  in `$TMPDIR` from prior runs that crashed before the per-test finally
  block ran. Default 24h threshold gives an operator a debug window.
- `cleanup_eval_tempdirs(run_started)` — sweeps `csq-eval-*` mkdtemp dirs
  (used by the legacy runner for credential symlinks) older than the
  current run's start time. HIGH-03 #3: credential symlinks MUST NOT
  survive process exit.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable

from .validators import validate_name


_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

# Cleanup regex MUST match the prefix used by `prepare_fixture`. The trailing
# `[A-Za-z0-9_]+` covers `tempfile.mkdtemp`'s 8-char suffix.
_CLEANUP_NAME_RE = re.compile(r"^coc-harness-[A-Za-z0-9._-]+-[A-Za-z0-9_]+$")
_EVAL_TEMPDIR_NAME_RE = re.compile(r"^csq-eval-[A-Za-z0-9._-]+$")

# `verify_fresh` ceiling: a freshly-prepared fixture's mtime must be within
# this window. Five seconds covers slow CI machines + cp+git overhead while
# still catching reuse of a stale path.
_FRESH_MTIME_MAX_AGE_SEC = 5.0


class FixtureError(RuntimeError):
    """Raised when a fixture cannot be prepared, verified, or cleaned up."""


def prepare_fixture(
    name: str,
    setup_fn: Callable[[Path], None] | None = None,
) -> Path:
    """Copy fixture `name` into a fresh `$TMPDIR` dir, git-init, return path.

    Steps:
      1. `validate_name(name)` — rejects path-traversal and odd characters.
      2. Resolve `coc-eval/fixtures/<name>/`; FixtureError if missing.
      3. `tempfile.mkdtemp(prefix=f"coc-harness-{name}-")` — atomic create.
      4. `shutil.copytree(src, dst, dirs_exist_ok=True)` — byte-identical copy.
      5. Optional `setup_fn(dst)` BEFORE git commit so its files get tracked.
      6. `git init -q && git add -A && git -c user.email=... commit -q -m init`
         — every subprocess uses an explicit argv list (`shell=False`).

    Args:
        name: Fixture directory name under `coc-eval/fixtures/`. Validated.
        setup_fn: Optional callable that receives the destination path and
            may mutate the fixture before the initial git commit. Used by
            safety SF4 (write injection-bait file into the fixture).

    Returns:
        Absolute path to the prepared fixture root.

    Raises:
        ValueError: name fails `validate_name`.
        FixtureError: source fixture missing, copy failed, or git failed.
    """
    validate_name(name)
    src = _FIXTURES_DIR / name
    if not src.is_dir():
        raise FixtureError(f"fixture not found: {src}")

    dst = Path(tempfile.mkdtemp(prefix=f"coc-harness-{name}-"))
    try:
        shutil.copytree(src, dst, dirs_exist_ok=True)
    except OSError as e:
        shutil.rmtree(dst, ignore_errors=True)
        raise FixtureError(f"copytree failed: {src} -> {dst}: {e}") from e

    if setup_fn is not None:
        try:
            setup_fn(dst)
        except Exception as e:
            shutil.rmtree(dst, ignore_errors=True)
            raise FixtureError(f"setup_fn failed for {name}: {e}") from e

    git_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "h",
        "GIT_AUTHOR_EMAIL": "h@t",
        "GIT_COMMITTER_NAME": "h",
        "GIT_COMMITTER_EMAIL": "h@t",
    }
    for argv in (
        ["git", "init", "-q"],
        ["git", "add", "-A"],
        ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"],
    ):
        result = subprocess.run(
            argv, cwd=dst, env=git_env, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            shutil.rmtree(dst, ignore_errors=True)
            raise FixtureError(
                f"git step failed: {argv!r} rc={result.returncode} "
                f"stderr={result.stderr.strip()!r}"
            )

    return dst


def cleanup_fixtures(older_than_hours: int = 24) -> int:
    """Remove `coc-harness-*` dirs in `$TMPDIR` older than the threshold.

    Crash-recovery sweep. Returns the count removed (0 on a clean run).

    Args:
        older_than_hours: Age threshold in hours. `0` removes everything
            matching the prefix regardless of mtime.

    Returns:
        Number of directories removed (best-effort; missing/unreadable
        entries are skipped silently per loom parity).
    """
    cutoff = time.time() - older_than_hours * 3600
    base = Path(tempfile.gettempdir())
    removed = 0
    for entry in base.iterdir():
        if not _CLEANUP_NAME_RE.fullmatch(entry.name):
            continue
        try:
            mtime = entry.stat().st_mtime
        except OSError:
            continue
        if mtime <= cutoff:
            shutil.rmtree(entry, ignore_errors=True)
            if not entry.exists():
                removed += 1
    return removed


def cleanup_eval_tempdirs(run_started: float) -> int:
    """Remove legacy `csq-eval-*` mkdtemp dirs older than the current run.

    Credential symlinks created by the legacy runner's `mkdtemp` MUST NOT
    survive process exit (HIGH-03 #3). Run at runner entry AND exit.

    Args:
        run_started: `time.time()` value captured at runner start. Any
            `csq-eval-*` directory whose mtime is strictly older than this
            value is removed.

    Returns:
        Number of directories removed.
    """
    base = Path(tempfile.gettempdir())
    removed = 0
    for entry in base.iterdir():
        if not _EVAL_TEMPDIR_NAME_RE.fullmatch(entry.name):
            continue
        try:
            mtime = entry.stat().st_mtime
        except OSError:
            continue
        if mtime < run_started:
            shutil.rmtree(entry, ignore_errors=True)
            if not entry.exists():
                removed += 1
    return removed


def verify_fresh(path: Path) -> None:
    """INV-ISO-5: assert `path` is a freshly-prepared fixture root.

    Checks:
      - directory exists and is non-empty;
      - mtime is within `_FRESH_MTIME_MAX_AGE_SEC` of now (catches reuse);
      - if `.git/` exists, it is NOT a symlink (catches a `.git` redirected
        outside `$TMPDIR`, which would let a fixture write to repo state).

    Raises:
        FixtureError on any failure. The launcher MUST treat a failure
        here as a hard error — do NOT proceed to spawn the CLI.
    """
    if not path.is_dir():
        raise FixtureError(f"verify_fresh: not a directory: {path}")
    try:
        children = list(path.iterdir())
    except OSError as e:
        raise FixtureError(f"verify_fresh: iterdir failed: {path}: {e}") from e
    if not children:
        raise FixtureError(f"verify_fresh: empty fixture: {path}")

    age = time.time() - path.stat().st_mtime
    if age > _FRESH_MTIME_MAX_AGE_SEC:
        raise FixtureError(
            f"verify_fresh: stale fixture (mtime age {age:.2f}s > "
            f"{_FRESH_MTIME_MAX_AGE_SEC:.0f}s): {path}"
        )

    git_dir = path / ".git"
    if git_dir.exists() and git_dir.is_symlink():
        raise FixtureError(f"verify_fresh: .git is a symlink: {git_dir}")
