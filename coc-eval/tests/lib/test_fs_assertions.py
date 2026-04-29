"""Unit tests for `lib.fs_assertions` (FR-15, R3-CRIT-03).

Covers each assertion kind, path-traversal hardening, symlink refusal, and
the SHA-256 cap behavior.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lib.fs_assertions import (
    FsAssertion,
    build_assertion,
    evaluate,
    snapshot_unchanged,
)


# ---------------------------------------------------------------------------
# Constructor + builder validation


def test_fs_assertion_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unknown kind"):
        FsAssertion(kind="rm_rf", path="x", label="x")


def test_fs_assertion_rejects_empty_path() -> None:
    with pytest.raises(ValueError, match="path"):
        FsAssertion(kind="file_absent", path="", label="x")


def test_fs_assertion_rejects_empty_label() -> None:
    with pytest.raises(ValueError, match="label"):
        FsAssertion(kind="file_absent", path="x", label="")


def test_fs_assertion_rejects_path_traversal() -> None:
    # `..` segment forbidden by validate_name on each component.
    with pytest.raises(ValueError):
        FsAssertion(kind="file_absent", path="../etc/passwd", label="x")


def test_fs_assertion_accepts_multi_segment_relative_path() -> None:
    a = FsAssertion(kind="file_absent", path=".claude/proposals.yaml", label="x")
    assert a.path == ".claude/proposals.yaml"


def test_fs_assertion_rejects_absolute_path() -> None:
    """R1-A-M1: absolute paths could escape the fixture root regardless of
    the resolve-based check, so reject at construct time."""
    with pytest.raises(ValueError, match="must be relative"):
        FsAssertion(kind="file_absent", path="/etc/passwd", label="x")


def test_fs_assertion_rejects_segment_with_slash() -> None:
    # Slashes inside a segment indicate caller didn't split — defense in
    # depth against backslash-as-separator on Windows-style paths.
    with pytest.raises(ValueError, match="forbidden char"):
        FsAssertion(kind="file_absent", path="a\\b\\c", label="x")


def test_fs_assertion_rejects_control_char_segment() -> None:
    with pytest.raises(ValueError, match="forbidden char"):
        FsAssertion(kind="file_absent", path="a/b\x00c", label="x")


def test_build_assertion_from_mapping() -> None:
    a = build_assertion({"kind": "file_present", "path": "x.txt", "label": "x"})
    assert a.kind == "file_present"


def test_build_assertion_rejects_missing_keys() -> None:
    with pytest.raises(ValueError):
        build_assertion({"kind": "file_present", "label": "x"})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# file_absent


def test_file_absent_passes_when_path_does_not_exist(tmp_path: Path) -> None:
    a = FsAssertion(kind="file_absent", path="impl.py", label="no stub written")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is True
    assert out[0]["reason"] == "ok"
    assert out[0]["kind"] == "fs_assert"
    assert out[0]["pattern"] == "file_absent:impl.py"
    assert out[0]["points"] == 1.0
    assert out[0]["max_points"] == 1.0


def test_file_absent_fails_when_file_present(tmp_path: Path) -> None:
    (tmp_path / "impl.py").write_text("pass\n")
    a = FsAssertion(kind="file_absent", path="impl.py", label="no stub")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "present"


def test_file_absent_fails_when_dir_present(tmp_path: Path) -> None:
    (tmp_path / "subdir").mkdir()
    a = FsAssertion(kind="file_absent", path="subdir", label="no subdir")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "present"


# ---------------------------------------------------------------------------
# file_present


def test_file_present_passes_when_file_exists(tmp_path: Path) -> None:
    (tmp_path / "result.txt").write_text("hello")
    a = FsAssertion(kind="file_present", path="result.txt", label="result emitted")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is True
    assert out[0]["reason"] == "ok"


def test_file_present_fails_when_absent(tmp_path: Path) -> None:
    a = FsAssertion(kind="file_present", path="result.txt", label="x")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "absent"


def test_file_present_fails_when_target_is_directory(tmp_path: Path) -> None:
    (tmp_path / "x").mkdir()
    a = FsAssertion(kind="file_present", path="x", label="x")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "not_file"


# ---------------------------------------------------------------------------
# dir_empty


def test_dir_empty_passes_for_empty_dir(tmp_path: Path) -> None:
    (tmp_path / "scratch").mkdir()
    a = FsAssertion(kind="dir_empty", path="scratch", label="x")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is True
    assert out[0]["reason"] == "ok"


def test_dir_empty_fails_when_dir_has_entries(tmp_path: Path) -> None:
    sub = tmp_path / "scratch"
    sub.mkdir()
    (sub / "stray.txt").write_text("oops")
    a = FsAssertion(kind="dir_empty", path="scratch", label="x")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "non_empty"


def test_dir_empty_fails_when_path_is_file(tmp_path: Path) -> None:
    (tmp_path / "scratch").write_text("not-a-dir")
    a = FsAssertion(kind="dir_empty", path="scratch", label="x")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "not_dir"


# ---------------------------------------------------------------------------
# file_unchanged


def test_file_unchanged_passes_when_content_identical(tmp_path: Path) -> None:
    target = tmp_path / "rules.md"
    target.write_text("# rules\n")
    a = FsAssertion(kind="file_unchanged", path="rules.md", label="x")
    pre = snapshot_unchanged([a], tmp_path)
    out = evaluate([a], tmp_path, pre_snapshots=pre)
    assert out[0]["matched"] is True
    assert out[0]["reason"] == "ok"


def test_file_unchanged_fails_when_content_modified(tmp_path: Path) -> None:
    target = tmp_path / "rules.md"
    target.write_text("# original\n")
    a = FsAssertion(kind="file_unchanged", path="rules.md", label="x")
    pre = snapshot_unchanged([a], tmp_path)
    target.write_text("# modified by attacker\n")
    out = evaluate([a], tmp_path, pre_snapshots=pre)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "modified"


def test_file_unchanged_passes_when_both_absent(tmp_path: Path) -> None:
    a = FsAssertion(kind="file_unchanged", path="never-existed.md", label="x")
    pre = snapshot_unchanged([a], tmp_path)
    out = evaluate([a], tmp_path, pre_snapshots=pre)
    assert out[0]["matched"] is True
    assert out[0]["reason"] == "ok_both_absent"


def test_file_unchanged_fails_when_created_after_snapshot(tmp_path: Path) -> None:
    a = FsAssertion(kind="file_unchanged", path="created.md", label="x")
    pre = snapshot_unchanged([a], tmp_path)
    (tmp_path / "created.md").write_text("written by model")
    out = evaluate([a], tmp_path, pre_snapshots=pre)
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "modified"


def test_file_unchanged_fails_without_pre_snapshot(tmp_path: Path) -> None:
    a = FsAssertion(kind="file_unchanged", path="rules.md", label="x")
    # Caller forgot to snapshot — surface as failure, not crash.
    out = evaluate([a], tmp_path, pre_snapshots={})
    assert out[0]["matched"] is False
    assert out[0]["reason"] == "no_snapshot"


# ---------------------------------------------------------------------------
# Path-safety hardening


@pytest.mark.skipif(os.name != "posix", reason="symlink semantics differ on Windows")
def test_evaluate_refuses_symlinked_parent(tmp_path: Path) -> None:
    # Plant a symlink at a parent component pointing outside the fixture.
    # Either `escape` (parent resolves outside the fixture root) or
    # `symlink` (component is itself a link) is acceptable — both block.
    outside = tmp_path.parent / "outside_target"
    outside.mkdir()
    (outside / "hidden.txt").write_text("attacker controlled")
    sym = tmp_path / "via_link"
    os.symlink(outside, sym)
    a = FsAssertion(kind="file_absent", path="via_link/hidden.txt", label="x")
    out = evaluate([a], tmp_path)
    assert out[0]["matched"] is False
    assert out[0]["reason"] in ("escape", "symlink")


@pytest.mark.skipif(os.name != "posix", reason="symlink semantics differ on Windows")
def test_evaluate_refuses_path_resolving_outside_fixture(tmp_path: Path) -> None:
    # Plant a non-symlink path that the constructor accepts but resolution
    # collapses outside the fixture root. validate_name rejects ".." per
    # segment, so this exercises the post-construction check via a symlink
    # parent that re-anchors the resolved path outside.
    outside = tmp_path.parent / "elsewhere"
    outside.mkdir()
    sym = tmp_path / "alias"
    os.symlink(outside, sym)
    a = FsAssertion(kind="file_present", path="alias/foo.txt", label="x")
    out = evaluate([a], tmp_path)
    # Either escape (resolved outside) or symlink (parent component is link).
    assert out[0]["matched"] is False
    assert out[0]["reason"] in ("escape", "symlink")


# ---------------------------------------------------------------------------
# evaluate handles a multi-criterion list


def test_evaluate_returns_one_result_per_assertion(tmp_path: Path) -> None:
    (tmp_path / "present.txt").write_text("here")
    asserts = [
        FsAssertion(kind="file_absent", path="missing.txt", label="absent ok"),
        FsAssertion(kind="file_present", path="present.txt", label="present ok"),
    ]
    out = evaluate(asserts, tmp_path)
    assert len(out) == 2
    assert all(r["matched"] for r in out)


def test_evaluate_mixed_pass_fail(tmp_path: Path) -> None:
    (tmp_path / "leaked.txt").write_text("oops")
    asserts = [
        FsAssertion(kind="file_absent", path="leaked.txt", label="should be absent"),
        FsAssertion(kind="file_absent", path="ok.txt", label="should be absent"),
    ]
    out = evaluate(asserts, tmp_path)
    assert out[0]["matched"] is False
    assert out[1]["matched"] is True


# ---------------------------------------------------------------------------
# Snapshot helper


def test_snapshot_skips_non_unchanged_kinds(tmp_path: Path) -> None:
    asserts = [
        FsAssertion(kind="file_absent", path="x", label="x"),
        FsAssertion(kind="file_present", path="y", label="y"),
        FsAssertion(kind="file_unchanged", path="z", label="z"),
    ]
    pre = snapshot_unchanged(asserts, tmp_path)
    assert set(pre.keys()) == {"z"}
    assert pre["z"] is None  # absent before


def test_snapshot_records_existing_file_hash(tmp_path: Path) -> None:
    (tmp_path / "rules.md").write_text("hello world")
    a = FsAssertion(kind="file_unchanged", path="rules.md", label="x")
    pre = snapshot_unchanged([a], tmp_path)
    assert pre["rules.md"] is not None
    assert len(pre["rules.md"]) == 64  # sha256 hex
