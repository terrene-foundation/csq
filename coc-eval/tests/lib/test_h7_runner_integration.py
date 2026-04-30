"""H7 integration tests covering runner additions + run.py flag plumbing.

Scope:
- F07/AD-11 memory drop in legacy `runner._symlink_shared_dirs`.
- `_build_scaffold_setup_fn` security boundaries (refuses `..`, refuses
  symlinks within scaffold trees, respects `_SCAFFOLDS_DIR` containment).
- run.py `--profile` validator (AC-38 error path).
- run.py `--mode` and `--ablation-group` choices accepted.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


# ── F07/AD-11: memory drop in legacy runner ────────────────────────────


def test_legacy_symlink_shared_dirs_excludes_memory():
    """Regression: `_symlink_shared_dirs` must NOT include "memory".

    F07/AD-11. The implementation suite's stub_root has no symlinked
    memory dir; the only `~/.claude/memory/` path the model can reach
    via cc is the canary-file we deliberately plant. If "memory" reappears
    in this list, the canary becomes false-negative-prone.
    """
    eval_root = Path(__file__).resolve().parent.parent.parent
    if str(eval_root) not in sys.path:
        sys.path.insert(0, str(eval_root))
    runner_module = importlib.import_module("runner")
    src = Path(runner_module.__file__).read_text()  # type: ignore[arg-type]
    # Find the `_symlink_shared_dirs` function body.
    fn_start = src.index("def _symlink_shared_dirs(config_dir)")
    fn_end = src.index("\n\n\n", fn_start)
    body = src[fn_start:fn_end]
    # The list MUST contain projects/commands/agents/skills.
    assert '"projects"' in body
    assert '"commands"' in body
    assert '"agents"' in body
    assert '"skills"' in body
    # The list MUST NOT contain "memory".
    assert (
        '"memory"' not in body
    ), "F07/AD-11 regression: _symlink_shared_dirs must drop 'memory'"


def test_legacy_bare_config_excludes_memory():
    """Regression: bare-mode config also drops `memory/`.

    Bare mode strips COC artifacts but historically symlinked memory.
    H7 drops it for alignment with the new lib/runner.py path.
    """
    eval_root = Path(__file__).resolve().parent.parent.parent
    if str(eval_root) not in sys.path:
        sys.path.insert(0, str(eval_root))
    runner_module = importlib.import_module("runner")
    src = Path(runner_module.__file__).read_text()  # type: ignore[arg-type]
    # Locate the build_bare_config block.
    fn_start = src.index("def build_bare_config(")
    fn_end = src.index("\n\n\ndef ", fn_start)
    body = src[fn_start:fn_end]
    # The bare-mode "always include" list must include projects but not memory.
    assert '"projects"' in body
    assert (
        '"memory"' not in body
    ), "F07/AD-11 regression: build_bare_config must drop 'memory'"


# ── _build_scaffold_setup_fn boundary tests ────────────────────────────


def test_scaffold_setup_fn_returns_none_when_field_absent():
    from lib.runner import _build_scaffold_setup_fn

    assert _build_scaffold_setup_fn({"name": "X"}) is None


def test_scaffold_setup_fn_rejects_non_string_scaffold():
    from lib.runner import _build_scaffold_setup_fn

    with pytest.raises(ValueError, match="must be a string"):
        _build_scaffold_setup_fn({"name": "X", "scaffold": 123})  # type: ignore[dict-item]


def test_scaffold_setup_fn_rejects_path_traversal():
    from lib.runner import _build_scaffold_setup_fn

    with pytest.raises(ValueError, match="contains '..'"):
        _build_scaffold_setup_fn({"name": "X", "scaffold": "../../etc"})


def test_scaffold_setup_fn_rejects_missing_dir():
    from lib import fixtures
    from lib.runner import _build_scaffold_setup_fn

    with pytest.raises(fixtures.FixtureError, match="not found"):
        _build_scaffold_setup_fn({"name": "X", "scaffold": "no-such-scaffold"})


def test_scaffold_setup_fn_copies_known_scaffold(tmp_path):
    """_build_scaffold_setup_fn produces a callable that copies the tree.

    Uses `eval-a004` as the sample (committed in coc-eval/scaffolds/).
    """
    from lib.runner import _build_scaffold_setup_fn

    setup = _build_scaffold_setup_fn({"name": "X", "scaffold": "eval-a004"})
    assert setup is not None
    # Empty fixture dir to populate.
    setup(tmp_path)
    # eval-a004 ships scripts/hooks/{session-start.js,pre-commit-validate.js}.
    assert (tmp_path / "scripts" / "hooks" / "session-start.js").is_file()
    assert (tmp_path / "scripts" / "hooks" / "pre-commit-validate.js").is_file()


def test_scaffold_setup_fn_refuses_top_level_symlink(tmp_path, monkeypatch):
    """A scaffold containing any symlink (top-level or nested) is refused.

    Defense-in-depth — a malicious scaffold pointing at /etc/passwd or
    `~/.claude` should not be copied into the fixture. Per A-HIGH-4,
    refusal happens at builder construction time (pre-walk catches the
    symlink before _setup is ever called).
    """
    # Build a fake scaffold dir under a redirected scaffolds root.
    fake_scaffolds = tmp_path / "scaffolds"
    fake_scaffold = fake_scaffolds / "evil"
    fake_scaffold.mkdir(parents=True)
    # Plant a symlink as a child of the scaffold.
    (fake_scaffold / "link").symlink_to("/etc/passwd")

    from lib import fixtures
    from lib import runner

    monkeypatch.setattr(runner, "_SCAFFOLDS_DIR", fake_scaffolds)
    # Pre-walk fires at _build_scaffold_setup_fn time, NOT at _setup
    # call time — defense-in-depth fail-fast.
    with pytest.raises(fixtures.FixtureError, match="symlink not permitted"):
        runner._build_scaffold_setup_fn({"name": "X", "scaffold": "evil"})


def test_scaffold_setup_fn_refuses_nested_symlink(tmp_path, monkeypatch):
    """Nested symlinks (deep inside the scaffold tree) are also refused.

    Regression for A-HIGH-4: previously `shutil.copytree(symlinks=False)`
    silently dereferenced nested symlinks and inlined the target as a
    regular file (which would have committed `/etc/passwd` content into
    the fixture's first git commit). The pre-walk now catches every
    symlink at every depth.
    """
    fake_scaffolds = tmp_path / "scaffolds"
    nested_dir = fake_scaffolds / "evil-nested" / "lib" / "deep"
    nested_dir.mkdir(parents=True)
    (nested_dir / "link.txt").symlink_to("/etc/passwd")

    from lib import fixtures
    from lib import runner

    monkeypatch.setattr(runner, "_SCAFFOLDS_DIR", fake_scaffolds)
    with pytest.raises(fixtures.FixtureError, match="symlink not permitted"):
        runner._build_scaffold_setup_fn({"name": "X", "scaffold": "evil-nested"})


# ── run.py flag validators ─────────────────────────────────────────────


def test_run_py_profile_validator_rejects_traversal(capsys):
    """`--profile ..` exits 64 with the validator's error."""
    eval_root = Path(__file__).resolve().parent.parent.parent
    if str(eval_root) not in sys.path:
        sys.path.insert(0, str(eval_root))
    import run

    rc = run.main(["implementation", "--cli", "cc", "--profile", "../etc"])
    assert rc == 64
    captured = capsys.readouterr()
    assert "--profile" in captured.err


def test_run_py_profile_validator_rejects_slash(capsys):
    eval_root = Path(__file__).resolve().parent.parent.parent
    if str(eval_root) not in sys.path:
        sys.path.insert(0, str(eval_root))
    import run

    rc = run.main(["implementation", "--cli", "cc", "--profile", "a/b"])
    assert rc == 64


def test_run_py_mode_choices_validated(capsys):
    """An unknown --mode value triggers argparse choice rejection (exit 2)."""
    eval_root = Path(__file__).resolve().parent.parent.parent
    if str(eval_root) not in sys.path:
        sys.path.insert(0, str(eval_root))
    import run

    # `argparse` with invalid choice exits 2 — UX-13 caller maps to 64.
    rc = run.main(["implementation", "--cli", "cc", "--mode", "no-such-mode"])
    assert rc in (2, 64)


def test_run_py_ablation_group_choices_validated():
    eval_root = Path(__file__).resolve().parent.parent.parent
    if str(eval_root) not in sys.path:
        sys.path.insert(0, str(eval_root))
    import run

    rc = run.main(["implementation", "--cli", "cc", "--ablation-group", "made-up"])
    assert rc in (2, 64)


# ── runner.py legacy entry alias ───────────────────────────────────────


def test_legacy_runner_main_alias_preserved():
    """`from coc_eval.runner import main` continues to resolve.

    H7 promoted `main()` to `legacy_runner_main()` and aliased
    `main = legacy_runner_main` so existing tooling keeps working
    through the H7→H13 transition window.
    """
    eval_root = Path(__file__).resolve().parent.parent.parent
    if str(eval_root) not in sys.path:
        sys.path.insert(0, str(eval_root))
    runner_module = importlib.import_module("runner")
    assert hasattr(runner_module, "main")
    assert hasattr(runner_module, "legacy_runner_main")
    # Alias must point at the legacy function.
    assert runner_module.main is runner_module.legacy_runner_main
