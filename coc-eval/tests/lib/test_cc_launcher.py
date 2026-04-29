"""Tests for `coc-eval/lib/launcher.py` cc-specific entry points (H3).

Covers:
- `cc_launcher` permission-mode mapping per suite (AC-22a coverage at the
  argv level — the spawn-time INV-PERM-1 check is in test_launcher.py).
- `_filter_settings_overlay` positive allowlist (R1-HIGH-02 / AC-22).
- `build_stub_home` layout: credential symlink, onboarding marker, fake
  HOME placeholder dirs (R1-CRIT-02).
- HOME / CLAUDE_CONFIG_DIR env wiring on cc launches.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from lib.launcher import (
    LaunchInputs,
    _ENV_KEY_FORBIDDEN,
    _ENV_KEY_HARNESS_ALLOWED,
    _SETTINGS_KEY_ALLOWLIST,
    _find_user_credentials,
    build_stub_home,
    cc_launcher,
    filter_settings_overlay,
)


@pytest.fixture
def fake_creds(tmp_path: Path) -> Path:
    """Create a throwaway credentials.json in a temp dir.

    The file mode mirrors the real `~/.claude/.credentials.json` (0o600) so
    a future audit hook test can verify symlink targets without surprises.
    """
    creds = tmp_path / ".credentials.json"
    creds.write_text(
        json.dumps(
            {"claudeAiOauth": {"accessToken": "test-only", "refreshToken": "x"}}
        ),
        encoding="utf-8",
    )
    creds.chmod(0o600)
    return creds


@pytest.fixture
def prepared_fixture(tmp_path: Path) -> Path:
    """Stand in for a `prepare_fixture` output. Empty dir is enough — the
    cc launcher's permission-mode tests only inspect args + env + cwd.
    """
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "CLAUDE.md").write_text("# tiny", encoding="utf-8")
    return fixture


class TestPermissionModePerSuite:
    """The per-suite permission_mode mapping is the critical contract for
    INV-PERM-1. cc_launcher MUST emit `--permission-mode plan` for plan-mode
    suites and `--dangerously-skip-permissions` for the implementation suite.
    """

    @pytest.mark.parametrize("suite", ["capability", "compliance", "safety"])
    def test_plan_mode_for_read_only_suites(
        self, prepared_fixture: Path, suite: str
    ) -> None:
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite=suite,  # type: ignore[arg-type]
                fixture_dir=prepared_fixture,
                prompt="hello",
                permission_mode="plan",
            )
        )
        assert "--permission-mode" in spec.args
        idx = spec.args.index("--permission-mode")
        assert spec.args[idx + 1] == "plan"
        # No json output for non-implementation suites.
        assert "--output-format" not in spec.args
        assert "--dangerously-skip-permissions" not in spec.args

    def test_dangerous_for_implementation(self, prepared_fixture: Path) -> None:
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="implementation",
                fixture_dir=prepared_fixture,
                prompt="diagnose",
                permission_mode="write",
            )
        )
        assert "--dangerously-skip-permissions" in spec.args
        # JSON output is mandatory for implementation per spec 08.
        assert "--output-format" in spec.args
        idx = spec.args.index("--output-format")
        assert spec.args[idx + 1] == "json"

    def test_prompt_is_last_positional(self, prepared_fixture: Path) -> None:
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="compliance",
                fixture_dir=prepared_fixture,
                prompt="prompt-marker-K9F2",
                permission_mode="plan",
            )
        )
        # Exact prompt at the end so subprocess sees it as a single arg.
        assert spec.args[-1] == "prompt-marker-K9F2"

    def test_inv_perm_1_blocks_wrong_mode_in_launcher(
        self, prepared_fixture: Path
    ) -> None:
        # AC-22a coverage at the launcher level: building a misaligned
        # spec aborts in `cc_launcher` BEFORE the spec is returned.
        with pytest.raises(RuntimeError, match=r"INV-PERM-1 violation"):
            cc_launcher(
                LaunchInputs(
                    cli="cc",
                    suite="safety",
                    fixture_dir=prepared_fixture,
                    prompt="rm -rf /",
                    permission_mode="write",  # safety MUST be plan
                )
            )

    def test_cc_launcher_rejects_non_cc_cli(self, prepared_fixture: Path) -> None:
        with pytest.raises(ValueError, match=r"requires inputs.cli='cc'"):
            cc_launcher(
                LaunchInputs(
                    cli="codex",
                    suite="capability",
                    fixture_dir=prepared_fixture,
                    prompt="x",
                    permission_mode="read-only",
                )
            )


class TestSettingsAllowlist:
    """R1-HIGH-02: caller-supplied settings overlays are reduced to
    `{env, model, permissions}`. Anything else is dropped.
    """

    def test_rejects_mcp_servers(self) -> None:
        merged = {
            "env": {"ANTHROPIC_MODEL": "claude-opus-4-7"},
            "model": "opus",
            "mcpServers": {"db": {"command": "psql"}},
        }
        out = filter_settings_overlay(merged)
        assert "mcpServers" not in out
        assert out["env"] == {"ANTHROPIC_MODEL": "claude-opus-4-7"}
        assert out["model"] == "opus"

    def test_rejects_hooks(self) -> None:
        merged = {"hooks": {"PreToolUse": [{"command": "/bin/bash"}]}}
        assert filter_settings_overlay(merged) == {}

    def test_rejects_status_line(self) -> None:
        merged = {
            "statusLine": {"command": "/bin/sh -c 'evil'"},
            "env": {"ANTHROPIC_BASE_URL": "https://api.anthropic.com"},
        }
        out = filter_settings_overlay(merged)
        assert "statusLine" not in out
        assert "env" in out

    def test_env_drops_ld_preload_and_dyld(self) -> None:
        merged = {
            "env": {
                "LD_PRELOAD": "/tmp/evil.so",
                "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
                "PATH": "/evil",
                "ANTHROPIC_MODEL": "opus",
            }
        }
        out = filter_settings_overlay(merged)
        assert out["env"] == {"ANTHROPIC_MODEL": "opus"}
        for k in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PATH"):
            assert k not in out["env"]

    def test_env_keeps_anthropic_prefix_and_harness_allowed(self) -> None:
        merged = {
            "env": {
                "ANTHROPIC_API_KEY": "x",
                "CLAUDE_CONFIG_DIR": "/tmp/stub",
                "RANDOM_OTHER": "y",
            }
        }
        out = filter_settings_overlay(merged)
        assert "ANTHROPIC_API_KEY" in out["env"]
        assert "CLAUDE_CONFIG_DIR" in out["env"]
        assert "RANDOM_OTHER" not in out["env"]

    def test_permissions_keys_filtered(self) -> None:
        merged = {
            "permissions": {
                "allow": ["Bash(git *)", "Edit"],
                "deny": ["Read"],
                "defaultMode": "plan",
                "loadFrom": "file:///etc/passwd",  # injection attempt
            }
        }
        out = filter_settings_overlay(merged)
        assert out["permissions"]["allow"] == ["Bash(git *)", "Edit"]
        assert out["permissions"]["deny"] == ["Read"]
        assert out["permissions"]["defaultMode"] == "plan"
        assert "loadFrom" not in out["permissions"]

    def test_permissions_rejects_file_uri_in_allow(self) -> None:
        merged = {"permissions": {"allow": ["Bash(git *)", "file:///tmp/passwd"]}}
        out = filter_settings_overlay(merged)
        assert out["permissions"]["allow"] == ["Bash(git *)"]

    def test_permissions_rejects_object_in_allow(self) -> None:
        merged = {"permissions": {"allow": [{"$ref": "x"}]}}
        out = filter_settings_overlay(merged)
        assert out["permissions"]["allow"] == []

    def test_allowlist_is_canonical_set(self) -> None:
        # If the allowlist drifts, this test pins what's permitted.
        assert _SETTINGS_KEY_ALLOWLIST == frozenset({"env", "model", "permissions"})
        assert "LD_PRELOAD" in _ENV_KEY_FORBIDDEN
        assert "CLAUDE_CONFIG_DIR" in _ENV_KEY_HARNESS_ALLOWED


class TestBuildStubHome:
    def test_layout_has_credentials_symlink(
        self, prepared_fixture: Path, fake_creds: Path
    ) -> None:
        stub_home, _ = build_stub_home(
            "compliance", prepared_fixture, credentials_src=fake_creds
        )
        creds_link = stub_home / ".credentials.json"
        assert creds_link.is_symlink()
        # Symlink resolves to the source.
        assert creds_link.resolve() == fake_creds.resolve()

    def test_onboarding_marker_present(
        self, prepared_fixture: Path, fake_creds: Path
    ) -> None:
        stub_home, _ = build_stub_home(
            "capability", prepared_fixture, credentials_src=fake_creds
        )
        claude_json = stub_home / ".claude.json"
        assert claude_json.is_file()
        body = json.loads(claude_json.read_text(encoding="utf-8"))
        assert body == {"hasCompletedOnboarding": True}

    def test_home_root_has_empty_placeholders(
        self, prepared_fixture: Path, fake_creds: Path
    ) -> None:
        _, home_root = build_stub_home(
            "safety", prepared_fixture, credentials_src=fake_creds
        )
        for sub in (".ssh", ".codex", ".gemini", ".aws", ".gnupg"):
            d = home_root / sub
            assert d.is_dir(), f"{sub} not created"
            # Empty: no real keys / configs leaked.
            assert list(d.iterdir()) == []

    def test_replaces_stale_symlink(
        self, prepared_fixture: Path, fake_creds: Path, tmp_path: Path
    ) -> None:
        # First build: symlink → fake_creds.
        stub_home, _ = build_stub_home(
            "compliance", prepared_fixture, credentials_src=fake_creds
        )
        creds_link = stub_home / ".credentials.json"
        assert creds_link.resolve() == fake_creds.resolve()

        # Second build with a different source: symlink must be replaced
        # without a "file exists" error.
        new_src = tmp_path / "other.json"
        new_src.write_text("{}", encoding="utf-8")
        new_src.chmod(0o600)
        stub_home, _ = build_stub_home(
            "compliance", prepared_fixture, credentials_src=new_src
        )
        assert creds_link.resolve() == new_src.resolve()

    def test_raises_when_no_credentials(
        self, prepared_fixture: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fake out _find_user_credentials by pointing HOME at an empty dir.
        empty_home = prepared_fixture / "_empty_home"
        empty_home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: empty_home)
        with pytest.raises(FileNotFoundError, match=r"no credentials"):
            build_stub_home("capability", prepared_fixture)


class TestCredentialSymlinkContainment:
    """M1 hardening from H3 review: `_find_user_credentials` rejects
    symlinks whose target resolves outside `~/.claude/`.
    """

    def test_rejects_credential_symlink_to_outside(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Build a fake HOME with .claude/.credentials.json -> /tmp/outside.
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".claude").mkdir()

        outside = tmp_path / "outside" / "evil.json"
        outside.parent.mkdir(parents=True)
        outside.write_text("{}", encoding="utf-8")

        link = fake_home / ".claude" / ".credentials.json"
        link.symlink_to(outside)

        monkeypatch.setattr(Path, "home", lambda: fake_home)
        # No accounts dir → only the direct path candidate; containment
        # check rejects it; result is None.
        assert _find_user_credentials() is None

    def test_accepts_credential_symlink_inside_claude_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # csq-shape: ~/.claude/.credentials.json -> ~/.claude/accounts/config-1/.credentials.json
        fake_home = tmp_path / "home"
        accounts_dir = fake_home / ".claude" / "accounts" / "config-1"
        accounts_dir.mkdir(parents=True)
        target = accounts_dir / ".credentials.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)

        link = fake_home / ".claude" / ".credentials.json"
        link.symlink_to(target)

        monkeypatch.setattr(Path, "home", lambda: fake_home)
        found = _find_user_credentials()
        assert found is not None
        assert found.resolve() == target.resolve()

    def test_rejects_config_n_symlink_to_outside(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The config-N walk MUST also enforce containment.
        fake_home = tmp_path / "home"
        config_n = fake_home / ".claude" / "accounts" / "config-1"
        config_n.mkdir(parents=True)

        outside = tmp_path / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        (config_n / ".credentials.json").symlink_to(outside)

        monkeypatch.setattr(Path, "home", lambda: fake_home)
        assert _find_user_credentials() is None


class TestHomeOverrideEnv:
    """Spec 08 §"Stub-HOME": cc launches MUST set BOTH CLAUDE_CONFIG_DIR
    and HOME so a model's tool calls cannot reach the real `~/.claude`.
    """

    def test_both_env_vars_set_when_provided(
        self, prepared_fixture: Path, fake_creds: Path
    ) -> None:
        stub_home, home_root = build_stub_home(
            "compliance", prepared_fixture, credentials_src=fake_creds
        )
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="compliance",
                fixture_dir=prepared_fixture,
                prompt="hi",
                permission_mode="plan",
                stub_home=stub_home,
                home_root=home_root,
            )
        )
        assert spec.env.get("CLAUDE_CONFIG_DIR") == str(stub_home)
        assert spec.env.get("HOME") == str(home_root)

    def test_path_preserved_so_binary_resolves(self, prepared_fixture: Path) -> None:
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="capability",
                fixture_dir=prepared_fixture,
                prompt="x",
                permission_mode="plan",
            )
        )
        # PATH MUST be inherited from the parent so the spawned subprocess
        # can find `claude` if cmd is not absolute.
        assert spec.env.get("PATH") == os.environ.get("PATH", "")

    def test_extra_env_overrides_propagate(self, prepared_fixture: Path) -> None:
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="capability",
                fixture_dir=prepared_fixture,
                prompt="x",
                permission_mode="plan",
                extra_env={"ANTHROPIC_MODEL": "claude-opus-4-7"},
            )
        )
        assert spec.env.get("ANTHROPIC_MODEL") == "claude-opus-4-7"

    def test_cwd_is_fixture_dir(self, prepared_fixture: Path) -> None:
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="capability",
                fixture_dir=prepared_fixture,
                prompt="x",
                permission_mode="plan",
            )
        )
        assert spec.cwd == prepared_fixture

    def test_no_sandbox_wrapper_for_non_implementation(
        self, prepared_fixture: Path
    ) -> None:
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="capability",
                fixture_dir=prepared_fixture,
                prompt="x",
                permission_mode="plan",
            )
        )
        assert spec.sandbox_wrapper == ()

    def test_sandbox_wrapper_for_implementation(self, prepared_fixture: Path) -> None:
        # The wrapper resolution differs by platform; we only assert
        # *something* is set when sandbox_profile=write-confined.
        spec = cc_launcher(
            LaunchInputs(
                cli="cc",
                suite="implementation",
                fixture_dir=prepared_fixture,
                prompt="x",
                permission_mode="write",
                sandbox_profile="write-confined",
            )
        )
        assert spec.sandbox_wrapper, "sandbox wrapper must be non-empty"
        # On macOS the prefix is sandbox-exec; Linux uses bwrap. Either is fine.
        assert spec.sandbox_wrapper[0] in ("sandbox-exec", "bwrap")
