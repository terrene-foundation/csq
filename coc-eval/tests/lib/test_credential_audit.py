"""Unit tests for `lib/credential_audit.py` (H7 audit-hook tripwire)."""

from __future__ import annotations

import pytest

from lib import credential_audit


@pytest.fixture(autouse=True)
def _reset_audit_state():
    """Each test starts with a clean audit-hook state.

    `disarm_for_tests` cannot un-bind the hook from the interpreter
    (sys.addaudithook is permanent), but the module's bookkeeping is
    reset so install-once + extra-paths tests stay deterministic.
    """
    credential_audit.disarm_for_tests()
    yield
    credential_audit.disarm_for_tests()


def test_canonical_suffixes_present():
    suffixes = credential_audit.guarded_suffixes()
    # Must include the cc credential path + at least one cross-CLI sibling.
    assert "/.claude/.credentials.json" in suffixes
    assert any(s.endswith("/.ssh/id_ed25519") for s in suffixes)
    assert any(s.endswith("/.aws/credentials") for s in suffixes)


def test_is_path_guarded_matches_canonical_suffix():
    assert credential_audit.is_path_guarded("/Users/me/.claude/.credentials.json")
    assert credential_audit.is_path_guarded("/home/me/.ssh/id_ed25519")


def test_is_path_guarded_rejects_unrelated_paths():
    assert not credential_audit.is_path_guarded("/etc/hosts")
    assert not credential_audit.is_path_guarded("/Users/me/Documents/notes.md")


def test_is_path_guarded_normalizes_traversal():
    # `..` collapses BEFORE suffix match.
    assert credential_audit.is_path_guarded(
        "/Users/me/foo/../.claude/.credentials.json"
    )


def test_arm_for_implementation_run_idempotent():
    credential_audit.arm_for_implementation_run()
    assert credential_audit.is_installed() is True
    # Second call is a no-op (no duplicate hook installs).
    credential_audit.arm_for_implementation_run()
    assert credential_audit.is_installed() is True


def test_arm_extra_paths_added_to_armed_set():
    credential_audit.arm_for_implementation_run(
        extra_paths=["/.claude/test_extra.json"]
    )
    armed = credential_audit.armed_extra_paths()
    assert "/.claude/test_extra.json" in armed
    # Suffix-match against extra paths works.
    assert credential_audit.is_path_guarded("/Users/me/.claude/test_extra.json")


def test_arm_ignores_non_string_extras():
    credential_audit.arm_for_implementation_run(
        extra_paths=["", None, 42]  # type: ignore[list-item]
    )
    # Only valid string extras are stored.
    armed = credential_audit.armed_extra_paths()
    assert all(isinstance(p, str) and p for p in armed)


def test_audit_hook_raises_on_canonical_suffix_open(tmp_path):
    """If the audit hook is armed and harness Python `open()`s a guarded
    path, `CredentialAuditViolation` is raised. The path doesn't need to
    exist — the hook fires on the open audit event before file resolution.

    Note: writing the file BEFORE arming would itself trigger the hook
    (open-for-write fires the audit event too). Build the path string
    only; the open call below is what we exercise.
    """
    target = tmp_path / "file_at" / ".claude" / ".credentials.json"
    credential_audit.arm_for_implementation_run()
    with pytest.raises(credential_audit.CredentialAuditViolation):
        # Path need not exist — hook fires on the audit event first.
        open(target, "r")


def test_audit_hook_silent_on_unrelated_open(tmp_path):
    """A read of an unrelated file does NOT raise."""
    credential_audit.arm_for_implementation_run()
    target = tmp_path / "harmless.txt"
    target.write_text("ok")
    # Must not raise.
    with open(target, "r") as f:
        assert f.read() == "ok"
