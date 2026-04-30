"""Unit tests for H10 codex_launcher + auth probe + runner dispatch."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_EVAL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_EVAL_ROOT) not in sys.path:
    sys.path.insert(0, str(_EVAL_ROOT))


# ── codex_launcher argv shape ─────────────────────────────────────────


def test_codex_launcher_capability_argv():
    from lib.launcher import _build_codex_args

    # H10 R1-CRIT-1: `--` argv terminator inserted before the prompt.
    args = _build_codex_args("capability", "ping")
    assert args == ("exec", "--sandbox", "read-only", "--", "ping")


def test_codex_launcher_compliance_argv():
    from lib.launcher import _build_codex_args

    args = _build_codex_args("compliance", "test prompt")
    assert "exec" in args
    assert "--sandbox" in args
    assert "read-only" in args


def test_codex_launcher_safety_argv():
    from lib.launcher import _build_codex_args

    args = _build_codex_args("safety", "test")
    assert "read-only" in args


def test_codex_launcher_implementation_raises():
    """ADR-B: implementation × codex is gated out at the runner. Reaching
    `_build_codex_args` with `implementation` is a programming error.
    """
    from lib.launcher import _build_codex_args

    with pytest.raises(RuntimeError, match="ADR-B"):
        _build_codex_args("implementation", "test")


# ── codex_launcher env shape ──────────────────────────────────────────


def test_codex_launcher_env_sets_codex_home(tmp_path):
    from lib.launcher import LaunchInputs, _build_codex_env

    inputs = LaunchInputs(
        cli="codex",
        suite="capability",
        fixture_dir=tmp_path,
        prompt="ping",
        permission_mode="plan",
        stub_home=tmp_path / "_stub_home",
        home_root=tmp_path / "_stub_root",
    )
    env = _build_codex_env(inputs)
    assert env["CODEX_HOME"] == str(tmp_path / "_stub_home")
    assert env["HOME"] == str(tmp_path / "_stub_root")
    assert "PATH" in env


def test_codex_launcher_env_does_not_set_claude_config_dir(tmp_path):
    """codex env MUST NOT carry CLAUDE_CONFIG_DIR — wrong-CLI key would
    confuse a model that introspects its env.
    """
    from lib.launcher import LaunchInputs, _build_codex_env

    inputs = LaunchInputs(
        cli="codex",
        suite="capability",
        fixture_dir=tmp_path,
        prompt="ping",
        permission_mode="plan",
        stub_home=tmp_path / "_stub_home",
        home_root=tmp_path / "_stub_root",
    )
    env = _build_codex_env(inputs)
    assert "CLAUDE_CONFIG_DIR" not in env


# ── codex_launcher full LaunchSpec ────────────────────────────────────


def test_codex_launcher_full_spec(tmp_path):
    from lib.launcher import LaunchInputs, codex_launcher

    inputs = LaunchInputs(
        cli="codex",
        suite="compliance",
        fixture_dir=tmp_path,
        prompt="test",
        # H10 maps codex/compliance to "read-only" (codex's analogue
        # of cc's "plan"). Mismatch here trips INV-PERM-1.
        permission_mode="read-only",
        stub_home=tmp_path / "_stub_home",
        home_root=tmp_path / "_stub_root",
    )
    spec = codex_launcher(inputs)
    assert spec.cmd.endswith("codex") or spec.cmd == "codex"
    assert spec.args[:3] == ("exec", "--sandbox", "read-only")
    assert spec.args[-1] == "test"
    assert spec.env.get("CODEX_HOME") == str(tmp_path / "_stub_home")
    # No process-level sandbox wrapper for codex (uses --sandbox flag).
    assert spec.sandbox_wrapper == ()


def test_codex_launcher_rejects_wrong_cli(tmp_path):
    from lib.launcher import LaunchInputs, codex_launcher

    inputs = LaunchInputs(
        cli="cc",  # wrong
        suite="capability",
        fixture_dir=tmp_path,
        prompt="ping",
        permission_mode="plan",
    )
    with pytest.raises(ValueError, match="codex_launcher requires"):
        codex_launcher(inputs)


def test_codex_launcher_rejects_sandbox_profile_request(tmp_path):
    """codex uses its built-in --sandbox flag; layering bwrap/sandbox-exec
    on top is a SUITE-table misconfiguration.
    """
    from lib.launcher import LaunchInputs, codex_launcher

    inputs = LaunchInputs(
        cli="codex",
        suite="implementation",  # would map to sandbox_profile=write-confined
        fixture_dir=tmp_path,
        prompt="test",
        permission_mode="write",
        sandbox_profile="write-confined",
    )
    with pytest.raises(RuntimeError):
        codex_launcher(inputs)


# ── CLI_REGISTRY contains codex ───────────────────────────────────────


def test_cli_registry_includes_codex():
    from lib.launcher import CLI_REGISTRY

    assert "codex" in CLI_REGISTRY
    entry = CLI_REGISTRY["codex"]
    assert entry.cli_id == "codex"
    assert entry.binary == "codex"
    # Launcher is the codex_launcher.
    assert callable(entry.launcher)


# ── Auth probe ────────────────────────────────────────────────────────


def test_probe_auth_codex_returns_result_shape():
    """`probe_auth("codex", "default")` returns an `AuthProbeResult`
    regardless of whether codex is authenticated. The probe runs
    `codex exec --sandbox read-only ping` and inspects the result.
    """
    from lib import auth

    auth.reset_cache()
    result = auth.probe_auth("codex", "default")
    # Shape sanity — not asserting ok=True (depends on dev env auth).
    assert hasattr(result, "ok")
    assert hasattr(result, "version")
    assert hasattr(result, "probed_at")


def test_probe_auth_codex_caches_per_suite():
    from lib import auth

    auth.reset_cache()
    a = auth.probe_auth("codex", "suite_a")
    b = auth.probe_auth("codex", "suite_a")
    assert a is b
    c = auth.probe_auth("codex", "suite_b")
    # Different suite scope re-probes; but after invocation it's cached.
    d = auth.probe_auth("codex", "suite_b")
    assert c is d


# ── is_auth_error_line covers codex vocabulary ────────────────────────


def test_is_auth_error_line_catches_codex_unauthorized():
    """H10 R1-HIGH-2: codex auth-error patterns tightened to require
    HTTP-style or error-shape context (not bare 'unauthorized')."""
    from lib.auth import is_auth_error_line

    assert is_auth_error_line("Error: 401 Unauthorized")
    assert is_auth_error_line("Error: Token expired, please re-login")
    assert is_auth_error_line("Please sign in to ChatGPT to continue")
    assert is_auth_error_line("codex login required to continue")


def test_is_auth_error_line_does_not_match_unrelated():
    from lib.auth import is_auth_error_line

    assert not is_auth_error_line("running test")
    assert not is_auth_error_line("Hello world")


# ── Runner dispatches to codex_launcher via CLI_REGISTRY ──────────────


def test_runner_dispatches_to_codex_via_registry():
    """Source-level check: runner._run_one_attempt looks up the
    launcher via CLI_REGISTRY rather than hard-calling cc_launcher.
    Replaces the H7-era 'cli != "cc"' RuntimeError gate.
    """
    src = (_EVAL_ROOT / "lib" / "runner.py").read_text()
    # Old guard removed.
    assert "phase-1 dispatch" not in src
    # New dispatch present.
    assert "CLI_REGISTRY.get(cli)" in src
    assert "cli_entry.launcher(inputs)" in src


# ── build_stub_home plants codex auth files when present ──────────────


def test_build_stub_home_symlinks_codex_auth_when_present(tmp_path, monkeypatch):
    """If `~/.codex/auth.json` exists, build_stub_home symlinks it into
    the per-fixture stub_home.
    """
    from lib import launcher

    # Plant a fake codex auth file in a fake home.
    fake_home = tmp_path / "fake_home"
    (fake_home / ".codex").mkdir(parents=True)
    (fake_home / ".codex" / "auth.json").write_text('{"oauth": "fake"}')
    (fake_home / ".codex" / "config.toml").write_text("# fake")
    # cc creds (build_stub_home requires them).
    fake_creds = fake_home / ".claude" / ".credentials.json"
    fake_creds.parent.mkdir(parents=True)
    fake_creds.write_text("{}")

    monkeypatch.setenv("HOME", str(fake_home))

    fixture = tmp_path / "fixture"
    fixture.mkdir()

    stub_home, _home_root = launcher.build_stub_home(
        "compliance", fixture, credentials_src=fake_creds
    )

    # Codex symlinks present alongside cc creds.
    assert (stub_home / "auth.json").is_symlink()
    assert (stub_home / "config.toml").is_symlink()
    # The cc credential symlink also lands.
    assert (stub_home / ".credentials.json").is_symlink()


def test_build_stub_home_skips_codex_when_absent(tmp_path, monkeypatch):
    """If ~/.codex/ has no auth.json, build_stub_home succeeds without
    planting codex symlinks (codex probe will then `skipped_cli_auth`).
    """
    from lib import launcher

    fake_home = tmp_path / "no_codex_home"
    fake_home.mkdir()
    fake_creds = fake_home / ".claude" / ".credentials.json"
    fake_creds.parent.mkdir(parents=True)
    fake_creds.write_text("{}")

    monkeypatch.setenv("HOME", str(fake_home))

    fixture = tmp_path / "fixture"
    fixture.mkdir()

    stub_home, _home_root = launcher.build_stub_home(
        "compliance", fixture, credentials_src=fake_creds
    )
    assert not (stub_home / "auth.json").exists()
    assert not (stub_home / "config.toml").exists()
