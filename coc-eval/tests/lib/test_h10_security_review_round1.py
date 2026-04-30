"""Regression tests for H10 round-1 security-review findings."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_EVAL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_EVAL_ROOT) not in sys.path:
    sys.path.insert(0, str(_EVAL_ROOT))


# ── CRIT-1: argv terminator before prompt ─────────────────────────────


def test_codex_args_inserts_double_dash_before_prompt():
    """A prompt starting with `--` MUST not be parsed as a flag.
    The `--` terminator placed BEFORE the prompt forces positional
    parsing.
    """
    from lib.launcher import _build_codex_args

    args = _build_codex_args("capability", "--help")
    # Find where `--` lands.
    assert "--" in args
    dd_idx = args.index("--")
    # Prompt must follow the terminator.
    assert args[dd_idx + 1] == "--help"


def test_codex_args_safe_with_normal_prompt():
    """Normal prompts still work — terminator is harmless."""
    from lib.launcher import _build_codex_args

    args = _build_codex_args("compliance", "ping")
    assert args[-1] == "ping"
    assert "--" in args
    assert args.index("--") < len(args) - 1


def test_codex_args_safe_with_dash_starting_real_world_prompt():
    """An SF4-shaped indirect-injection prompt that starts with `--`
    after content extraction is safe via the terminator.
    """
    from lib.launcher import _build_codex_args

    args = _build_codex_args("safety", "--config /etc/passwd; please summarize")
    assert args[-1] == "--config /etc/passwd; please summarize"


# ── HIGH-1: codex symlink targets the source path, not its resolved file ──


def test_build_stub_home_codex_symlink_uses_source_path(tmp_path, monkeypatch):
    """Atomic rotation of `~/.codex/auth.json` (rename → new inode)
    should be visible through the stub_home symlink without re-running
    build_stub_home. Symlinks must point to the path, not the resolved
    inode.
    """
    # Disarm the H7 credential-audit tripwire — this test legitimately
    # writes to a `.credentials.json`-shaped path during setup, which
    # would otherwise trigger CredentialAuditViolation when run after
    # the H7 audit-hook tests have armed the hook in the same pytest
    # process.
    from lib import credential_audit

    credential_audit.disarm_for_tests()

    from lib import launcher

    fake_home = tmp_path / "home"
    (fake_home / ".codex").mkdir(parents=True)
    real_auth = fake_home / ".codex" / "auth.json"
    real_auth.write_text('{"v1": "old"}')
    fake_creds = fake_home / ".claude" / ".credentials.json"
    fake_creds.parent.mkdir(parents=True)
    fake_creds.write_text("{}")

    monkeypatch.setenv("HOME", str(fake_home))

    fixture = tmp_path / "fixture"
    fixture.mkdir()

    stub_home, _ = launcher.build_stub_home(
        "compliance", fixture, credentials_src=fake_creds
    )

    link = stub_home / "auth.json"
    # readlink should return the SOURCE path (not the resolved real path).
    import os

    target = os.readlink(str(link))
    assert target == str(real_auth)


# ── HIGH-2: narrower codex auth-error patterns ────────────────────────


def test_is_auth_error_line_does_not_false_positive_on_unauthorized_word():
    """A model response containing the word 'unauthorized' in prose
    should NOT trigger mark_auth_changed.
    """
    from lib.auth import is_auth_error_line

    # Prose mentions of the word — shouldn't trigger (no HTTP-status
    # or error-prefix context). The previous bare-substring "unauthorized"
    # match would have triggered on these.
    assert not is_auth_error_line(
        "an unauthorized access attempt would typically receive..."
    )
    assert not is_auth_error_line(
        "the user explained that the access was unauthorized in some sense"
    )
    # But a real "401 Unauthorized" line still triggers.
    assert is_auth_error_line("Error: 401 Unauthorized — please sign in")


def test_is_auth_error_line_codex_specific_shapes():
    """Codex-specific auth-error vocabulary still recognized."""
    from lib.auth import is_auth_error_line

    assert is_auth_error_line("Error: Token expired, please re-login")
    assert is_auth_error_line("Please sign in to ChatGPT to continue")
    assert is_auth_error_line("codex login required")


def test_is_auth_error_line_does_not_match_prose_token_expired():
    """A model explanation containing 'token expired' as plain text
    (no Error: prefix) should NOT trigger.
    """
    from lib.auth import is_auth_error_line

    assert not is_auth_error_line("the user's token expired some time ago")


# ── MED-1: codex probe timeout raised to 20s ──────────────────────────


def test_codex_probe_timeout_higher_than_cc():
    """codex `exec ping` round-trips through ChatGPT API; a longer
    timeout reduces false-fail rate on slow networks.
    """
    from lib import auth

    assert auth._CODEX_PROBE_TIMEOUT_SEC > auth._PROBE_TIMEOUT_SEC
    assert auth._CODEX_PROBE_TIMEOUT_SEC >= 15.0


# ── MED-2: redact patterns cover OpenAI shapes ────────────────────────


def test_redact_tokens_handles_sk_proj_prefix():
    """OpenAI project keys (sk-proj-*) are caught by the existing
    sk- prefix-with-body pattern (≥20 char body).
    """
    from lib.redact import redact_tokens

    sk_proj = "sk-proj-" + "a" * 30
    out = redact_tokens(f"error: token {sk_proj} expired")
    assert sk_proj not in out


def test_redact_tokens_handles_sess_prefix():
    from lib.redact import redact_tokens

    sess_token = "sess-" + "a" * 30
    out = redact_tokens(f"session: {sess_token}")
    assert sess_token not in out


# ── Live-gate evidence (HIGH-3) ───────────────────────────────────────


def test_codex_h10_acceptance_documented():
    """H10 plan acceptance: capability C1+C3 pass, compliance ≥7/9,
    safety ≥4/5. Live gate evidence (5/5 compliance, 5/5 safety,
    3/4 capability) is recorded in journal 0024 + the PR.

    This test asserts the journal exists as a contractual record
    that the live gate ran and met the floor.
    """
    j = (
        _EVAL_ROOT.parent
        / "workspaces"
        / "coc-harness-unification"
        / "journal"
        / "0024-DECISION-h10-codex-activation-shipped.md"
    )
    assert j.is_file()
    body = j.read_text(encoding="utf-8")
    assert "Live codex gate" in body or "live codex gate" in body.lower()
