"""Tests for `coc-eval/lib/jsonl.py` — writer, reader, schema validation,
redaction integration, run-id-scoped paths, companion `.log` writer.

Coverage targets:
- Round-trip: write_header + record_result + read; record validates
  against v1.0.0 schema (AC-6).
- Redaction canary: stderr containing `sk-ant-oat01-AAAA...` produces
  zero matches in the persisted JSONL bytes (AC-20).
- Forward-compat: a record with an unknown future_v2 field validates OK
  (UX-17 / AC-46).
- Schema rejects an invented `state` value (AC-7 closed taxonomy).
- Path-traversal: the writer refuses a malformed `run_id` BEFORE
  creating any directory (AC-21 path-traversal blocked).
- Per-line byte cap rejects oversized records.
- Companion `.log` files exist + mode 0o600 + contain redacted bodies.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest

from lib.jsonl import (
    JSONL_LINE_BYTES_HARD,
    JsonlWriter,
    SCHEMA_VERSION,
    iter_records,
    now_iso8601_ms,
    read_record,
    validate_record,
)
from lib.run_id import generate_run_id
from lib.schema_validator import SchemaValidationError


def _valid_test_record(suite: str, **overrides) -> dict:
    """Helper: build a v1.0.0-conforming test record for round-trip tests."""
    base = {
        "_header": False,
        "suite": suite,
        "test": "C1-baseline-root",
        "tags": ["capability"],
        "cli": "cc",
        "cli_version": "claude-code 2.0.31",
        "rubric": "default",
        "fixture": "baseline-cc",
        "fixture_dir": "/tmp/coc-harness-baseline-cc-abc123",
        "prompt_sha256": "ab12" * 16,
        "cmd_template_id": "cc-plan-v1",
        "cwd": "/tmp/coc-harness-baseline-cc-abc123",
        "stub_home": "/tmp/coc-harness-baseline-cc-abc123/_stub_home",
        "home_root": "/tmp/coc-harness-baseline-cc-abc123/_stub_root",
        "permission_mode": "plan",
        "sandbox_profile": None,
        "home_mode": "stub",
        "effective_timeout_ms": 60000,
        "started_at": now_iso8601_ms(),
        "ended_at": now_iso8601_ms(),
        "runtime_ms": 13333,
        "exit_code": 0,
        "signal": None,
        "timed_out": False,
        "attempts": 1,
        "attempt_states": ["pass"],
        "auth_state_changed": False,
        "state": "pass",
        "scoring_backend": "regex",
        "score": {
            "pass": True,
            "total": 1,
            "max_total": 1,
            "criteria": [
                {
                    "label": "marker present",
                    "kind": "contains",
                    "pattern": "MARKER_CC_BASE",
                    "matched": True,
                    "points": 1,
                    "max_points": 1,
                }
            ],
        },
        "stdout_truncated": "MARKER_CC_BASE=cc-base-loaded-CC9A1\n",
        "stderr_truncated": "",
        "log_path": None,
    }
    base.update(overrides)
    return base


@pytest.fixture
def writer(tmp_path: Path):
    """Yield a JsonlWriter bound to tmp_path. Closed on teardown."""
    rid = generate_run_id()
    w = JsonlWriter.open(
        run_id=rid,
        suite="capability",
        base_dir=tmp_path,
        skip_gitignore_check=True,
    )
    try:
        yield w
    finally:
        w.close()


class TestRoundTripHeader:
    def test_header_writes_and_validates(self, writer: JsonlWriter) -> None:
        rec = writer.write_header(
            started_at=now_iso8601_ms(),
            cli_versions={"cc": "claude-code 2.0.31"},
            auth_probes={
                "cc": {
                    "ok": True,
                    "reason": None,
                    "probed_at": now_iso8601_ms(),
                    "version": "claude 2.0.31",
                }
            },
            selected_clis=["cc"],
            harness_invocation="coc-eval/run.py capability --cli cc",
        )
        # Round-trip: read back, validate.
        lines = writer.path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        validate_record(parsed)
        assert parsed["_header"] is True
        assert parsed["schema_version"] == SCHEMA_VERSION
        assert parsed["run_id"] == writer.run_id
        assert parsed == rec  # writer returns the post-validation record


class TestRoundTripTestRecord:
    def test_record_validates_and_round_trips(self, writer: JsonlWriter) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        original = _valid_test_record("capability")
        wrote = writer.record_result(original)
        validate_record(wrote)

        records = list(iter_records(writer.path))
        # 1 header + 1 test record.
        assert len(records) == 2
        assert records[1]["test"] == "C1-baseline-root"
        assert records[1]["state"] == "pass"

    def test_per_record_byte_cap_rejected(self, writer: JsonlWriter) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        rec = _valid_test_record("capability")
        # Pad stdout_truncated to exceed the 100KB hard cap. The redactor
        # leaves benign filler unchanged, so size is preserved.
        rec["stdout_truncated"] = "x" * (JSONL_LINE_BYTES_HARD + 100)
        with pytest.raises(ValueError, match=r"100000-byte hard cap"):
            writer.record_result(rec)


class TestRedactionCanary:
    """AC-20 — token-shaped substrings in stderr_truncated MUST be absent
    from persisted bytes.
    """

    def test_token_in_stderr_redacted_on_disk(self, writer: JsonlWriter) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        token = "sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAA"
        rec = _valid_test_record(
            "capability",
            state="fail",
            stderr_truncated=f"auth failed: {token}\n",
            score={
                "pass": False,
                "total": 0,
                "max_total": 1,
                "criteria": [
                    {
                        "label": "marker",
                        "kind": "contains",
                        "matched": False,
                        "points": 0,
                        "max_points": 1,
                    }
                ],
            },
        )
        writer.record_result(rec)

        on_disk_bytes = writer.path.read_bytes()
        assert (
            token.encode() not in on_disk_bytes
        ), "AC-20 violation: token substring survived to JSONL on disk"
        assert b"auth failed" in on_disk_bytes

    def test_token_in_stdout_redacted(self, writer: JsonlWriter) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        token = "sk-ant-oat01-BBBBBBBBBBBBBBBBBBBBBBBB"
        rec = _valid_test_record(
            "capability",
            stdout_truncated=f"diag: leaked={token}\n",
        )
        writer.record_result(rec)
        assert token.encode() not in writer.path.read_bytes()


class TestForwardCompat:
    def test_unknown_field_validates(self, writer: JsonlWriter) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        rec = _valid_test_record("capability")
        rec["future_v2_thing"] = "hello-from-the-future"
        # Should NOT raise — unknown keys are allowed (additionalProperties
        # defaults to true at every scope).
        validate_record(rec)

    def test_unknown_score_array_validates(self, writer: JsonlWriter) -> None:
        # AD-05: parallel arrays. A future scoring layer adding
        # `score.judge_results` is a minor bump, not major.
        writer.write_header(started_at=now_iso8601_ms())
        rec = _valid_test_record("capability")
        rec["score"]["judge_results"] = [{"label": "future", "points": 1}]
        validate_record(rec)


class TestSchemaStrictness:
    def test_invented_state_rejected(self, writer: JsonlWriter) -> None:
        # AC-7: closed state taxonomy. New values are a major bump.
        writer.write_header(started_at=now_iso8601_ms())
        rec = _valid_test_record("capability", state="invented")
        with pytest.raises(SchemaValidationError, match="not in enum"):
            validate_record(rec)

    def test_missing_required_rejected(self, writer: JsonlWriter) -> None:
        rec = _valid_test_record("capability")
        rec.pop("state")
        with pytest.raises(
            SchemaValidationError, match=r"missing required key 'state'"
        ):
            validate_record(rec)

    def test_invalid_run_id_in_header_rejected(self) -> None:
        # Build a header with a malformed run_id and try to validate.
        rec = {
            "_header": True,
            "schema_version": SCHEMA_VERSION,
            "harness_version": "1.0.0",
            "run_id": "not-a-run-id",
            "suite": "capability",
            "started_at": now_iso8601_ms(),
            "host": {"platform": "darwin", "arch": "arm64", "python": "3.12"},
            "cli_versions": {},
            "auth_probes": {},
        }
        with pytest.raises(SchemaValidationError, match="pattern"):
            validate_record(rec)


class TestPathTraversalBlocked:
    """AC-21 — the writer MUST refuse a malformed run_id BEFORE creating
    any filesystem path.
    """

    def test_traversal_run_id_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match=r"run_id"):
            JsonlWriter.open(
                run_id="../../etc/passwd",
                suite="capability",
                base_dir=tmp_path,
                skip_gitignore_check=True,
            )
        # No directory created under tmp_path.
        assert list(tmp_path.iterdir()) == []

    def test_unknown_suite_blocked(self, tmp_path: Path) -> None:
        rid = generate_run_id()
        with pytest.raises(ValueError, match=r"unknown suite"):
            JsonlWriter.open(
                run_id=rid,
                suite="../../bad",
                base_dir=tmp_path,
                skip_gitignore_check=True,
            )


class TestCompanionLog:
    def test_log_file_written_with_redaction_and_mode(
        self, writer: JsonlWriter
    ) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        token = "sk-ant-oat01-CCCCCCCCCCCCCCCCCCCCCCCC"
        log_path = writer.write_log(
            cli="cc",
            test="C1-baseline-root",
            stdout="MARKER_CC_BASE=cc-base-loaded-CC9A1",
            stderr=f"warning: token={token}",
            cwd="/tmp/coc-harness",
            exit_code=0,
            runtime_ms=4242,
            timed_out=False,
        )
        assert log_path.exists()
        body = log_path.read_text(encoding="utf-8")
        # Header lines present.
        assert "# cli: cc" in body
        assert "# test: C1-baseline-root" in body
        # Body separators present + redaction applied.
        assert "--- STDOUT ---" in body
        assert "--- STDERR ---" in body
        assert "MARKER_CC_BASE" in body
        assert token not in body
        # Mode 0o600.
        mode = stat.S_IMODE(log_path.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"

    def test_evidence_log_emitted_when_required(self, writer: JsonlWriter) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        log_path = writer.write_log(
            cli="cc",
            test="C1-baseline-root",
            stdout="ok",
            stderr="",
            evidence_required=True,
        )
        evidence_path = log_path.with_suffix(".evidence.log")
        assert evidence_path.exists()
        body = evidence_path.read_text(encoding="utf-8")
        assert "EVIDENCE LOG — DO NOT COMMIT" in body
        assert stat.S_IMODE(evidence_path.stat().st_mode) == 0o600

    def test_log_dir_under_run_id(self, writer: JsonlWriter) -> None:
        # The companion log dir lives next to the JSONL file, under the
        # run_id path.
        assert writer.log_dir.parent == writer.path.parent
        assert writer.log_dir.name == "logs"


class TestNowIsoTimestamp:
    def test_is_iso8601_with_z_suffix(self) -> None:
        ts = now_iso8601_ms()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", ts), ts


class TestReadRecord:
    def test_oversized_line_rejected(self) -> None:
        line = "x" * (JSONL_LINE_BYTES_HARD + 5)
        with pytest.raises(ValueError, match=r"hard cap"):
            read_record(line)

    def test_non_dict_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"did not decode to a dict"):
            read_record("[1, 2, 3]")


class TestExtraKwargRedacted:
    """H4 review H1 — operator-supplied `extra` overrides on the header
    MUST go through token redaction. Same for `auth_probes[*].reason`.
    """

    def test_extra_kwarg_token_redacted(self, writer: JsonlWriter) -> None:
        token = "sk-ant-oat01-DDDDDDDDDDDDDDDDDDDDDDDD"
        writer.write_header(
            started_at=now_iso8601_ms(),
            extra={"diagnostic_blob": f"failure: {token}"},
        )
        assert token.encode() not in writer.path.read_bytes()

    def test_auth_probe_reason_redacted(self, writer: JsonlWriter) -> None:
        token = "sk-ant-oat01-EEEEEEEEEEEEEEEEEEEEEEEE"
        writer.write_header(
            started_at=now_iso8601_ms(),
            auth_probes={
                "cc": {
                    "ok": False,
                    "reason": f"invalid_grant: {token}",
                    "probed_at": now_iso8601_ms(),
                }
            },
        )
        assert token.encode() not in writer.path.read_bytes()


class TestLogFileSymlinkRefused:
    """H4 review M1 — `_write_log_body` refuses to overwrite a symlink at
    the destination path.
    """

    def test_symlink_at_log_path_refused(
        self, writer: JsonlWriter, tmp_path: Path
    ) -> None:
        writer.write_header(started_at=now_iso8601_ms())
        log_path = writer.log_dir / f"cc-{writer.suite}-T1.log"
        # Plant a symlink at the destination path.
        target = tmp_path / "elsewhere"
        target.write_text("decoy", encoding="utf-8")
        log_path.symlink_to(target)
        with pytest.raises(RuntimeError, match=r"refusing to overwrite symlink"):
            writer.write_log(cli="cc", test="T1", stdout="x", stderr="")
        # Symlink target untouched.
        assert target.read_text(encoding="utf-8") == "decoy"


class TestLogFileModeAtCreation:
    """H4 review M2/M3 — the tmp file used by `_write_log_body` MUST be
    0o600 from the FIRST byte written, not only after a post-write chmod.
    """

    def test_creation_uses_excl_mode_0o600(
        self, writer: JsonlWriter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        writer.write_header(started_at=now_iso8601_ms())

        # Wrap os.open and capture the mode flag passed by _write_log_body.
        captured: dict[str, int] = {}
        real_open = os.open

        def spy_open(path, flags, mode=0o777):  # type: ignore[no-untyped-def]
            if str(path).endswith(".log.tmp"):
                captured["flags"] = flags
                captured["mode"] = mode
            return real_open(path, flags, mode)

        monkeypatch.setattr("lib.jsonl.os.open", spy_open)

        writer.write_log(cli="cc", test="T2", stdout="x", stderr="")
        assert captured.get("mode") == 0o600
        # Flags must include O_CREAT|O_EXCL so the file cannot exist
        # at default mode pre-write.
        assert captured["flags"] & os.O_CREAT
        assert captured["flags"] & os.O_EXCL
