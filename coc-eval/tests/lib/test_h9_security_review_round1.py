"""Regression tests for H9 round-1 security-review findings.

Each test names the finding ID. When journal 0023 references "fixed in
this PR", a corresponding test must exist here.
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

_EVAL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_EVAL_ROOT) not in sys.path:
    sys.path.insert(0, str(_EVAL_ROOT))

import aggregate  # noqa: E402

# Year-2100 timestamp per rules/testing.md MUST Rule 1 — non-time-bomb
# (C-LOW-2 cleanup follow-on for new tests).
_FAR_FUTURE_TS = "2100-01-01T00:00:00.000Z"
_RUN_ID = "2100-01-01T00-00-00Z-99999-0000-AaBbCcDd"


def _header(run_id: str = _RUN_ID, schema_version: str = "1.0.0") -> dict[str, Any]:
    return {
        "_header": True,
        "schema_version": schema_version,
        "harness_version": "h9-test",
        "run_id": run_id,
        "suite": "safety",
        "started_at": _FAR_FUTURE_TS,
        "host": {"platform": "test", "arch": "test", "python": "3.12"},
        "cli_versions": {"cc": "test"},
        "auth_probes": {},
    }


def _test_record(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "_header": False,
        "suite": "safety",
        "test": "SF1-direct-rm-rf-root",
        "cli": "cc",
        "fixture": "safety",
        "fixture_dir": "/tmp/x",
        "permission_mode": "plan",
        "started_at": _FAR_FUTURE_TS,
        "ended_at": _FAR_FUTURE_TS,
        "runtime_ms": 1000.0,
        "exit_code": 0,
        "timed_out": False,
        "attempts": 1,
        "attempt_states": ["pass"],
        "state": "pass",
        "scoring_backend": "regex",
        "score": {
            "pass": True,
            "total": 2.0,
            "max_total": 2.0,
            "criteria": [],
            "rubric": "default",
        },
        "stdout_truncated": "",
        "stderr_truncated": "",
    }
    base.update(kw)
    return base


def _write_run(
    base: Path, run_id: str = _RUN_ID, *, recs: list[dict[str, Any]] | None = None
) -> Path:
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    f = run_dir / "safety-cc.jsonl"
    h = _header(run_id=run_id)
    lines = [json.dumps(h)] + [json.dumps(r) for r in (recs or [])]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return run_dir


# ── A-CRIT-1: per-record cap fires on syntactically valid oversized record ──


def test_iter_jsonl_caps_syntactically_valid_oversized_record(tmp_path):
    """A well-formed JSON record whose stdout_truncated field exceeds
    the per-record cap MUST be counted as invalid and dropped — without
    materializing it into the records list.
    """
    f = tmp_path / "big.jsonl"
    huge_str = "A" * (aggregate._PER_RECORD_BYTES_CAP + 100)
    rec = _test_record()
    rec["stdout_truncated"] = huge_str
    body = json.dumps(_header()) + "\n" + json.dumps(rec) + "\n"
    f.write_text(body, encoding="utf-8")
    records, invalid = aggregate._iter_jsonl_records(f)
    assert invalid == 1
    # Header survives; oversized record drops.
    assert len(records) == 1
    assert records[0].get("_header") is True


def test_iter_jsonl_long_line_no_newline_does_not_blow_memory(tmp_path):
    """A 9 MiB line with NO newlines must be rejected as oversized
    record, not consume 9 MiB of buffered memory before the size check.
    The chunked reader bounds peak buffer at the per-record cap.
    """
    f = tmp_path / "noline.jsonl"
    body = json.dumps(_header()) + "\n" + ("A" * (1 * 1024 * 1024))
    f.write_text(body, encoding="utf-8")
    records, invalid = aggregate._iter_jsonl_records(f)
    # Trailing line over per-record cap is dropped as invalid.
    assert invalid == 1
    assert len(records) == 1


# ── A-HIGH-1: int-bounds boundary tests + negative ──


def test_check_int_bounds_negative_boundary():
    assert aggregate._check_int_bounds(-aggregate._JS_SAFE_INT_MAX)
    assert not aggregate._check_int_bounds(-aggregate._JS_SAFE_INT_MAX - 1)


def test_check_int_bounds_positive_boundary():
    assert aggregate._check_int_bounds(aggregate._JS_SAFE_INT_MAX)
    assert not aggregate._check_int_bounds(aggregate._JS_SAFE_INT_MAX + 1)


def test_check_int_bounds_realistic_legacy_record():
    """A real test_record with nested score.criteria.artifacts must
    pass the 64-deep check (the depth was raised from 32 in H9).
    """
    rec = _test_record()
    rec["score"]["criteria"] = [
        {
            "label": "x",
            "kind": "tier",
            "matched": True,
            "points": 1,
            "max_points": 1,
            "artifacts": {"a": {"b": {"c": {"d": [{"e": 1}]}}}},
        }
    ]
    assert aggregate._check_int_bounds(rec)


# ── A-HIGH-2: results_root + run-id symlink defense ──


def test_resolve_run_dir_rejects_symlinked_run_dir(tmp_path):
    """A symlink at results_root/<runid> pointing elsewhere is rejected."""
    real_target = tmp_path / "elsewhere"
    real_target.mkdir()
    (real_target / "safety-cc.jsonl").write_text(json.dumps(_header()) + "\n")
    link = tmp_path / _RUN_ID
    link.symlink_to(real_target, target_is_directory=True)
    args = aggregate.build_parser().parse_args(["--run-id", _RUN_ID])
    with pytest.raises(aggregate.InvalidRunIdError, match="symlink"):
        aggregate._resolve_run_dir(args, tmp_path)


def test_discover_latest_run_skips_symlink_entries(tmp_path):
    """A symlink under results_root pointing at another tree is skipped."""
    real = tmp_path / "real"
    real.mkdir()
    sym = tmp_path / _RUN_ID
    sym.symlink_to(real, target_is_directory=True)
    found = aggregate._discover_latest_run(tmp_path)
    assert found is None


# ── A-HIGH-3: multi-suite header drift detected ──


def test_load_run_rejects_header_run_id_drift(tmp_path):
    """Two JSONL files in the same dir with different header run_ids
    must raise — co-mingled runs are forensically unsafe.
    """
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    (run_dir / "safety-cc.jsonl").write_text(
        json.dumps(_header(run_id=_RUN_ID)) + "\n" + json.dumps(_test_record()) + "\n",
        encoding="utf-8",
    )
    other_run_id = "2100-02-01T00-00-00Z-11111-0000-OtherTes"
    (run_dir / "compliance-cc.jsonl").write_text(
        json.dumps(_header(run_id=other_run_id)) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(aggregate.AggregatorError, match="run_id drift"):
        aggregate._load_run(run_dir)


# ── A-HIGH-4: test-record with run_id/schema_version refused ──


def test_load_run_rejects_test_record_with_run_id_field(tmp_path):
    """A `_header: false` record carrying a `run_id` top-level key is
    impersonating header metadata. Reject as invalid.
    """
    rec = _test_record()
    rec["run_id"] = "2100-01-01T00-00-00Z-22222-0000-Imposter"
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0
    assert run.invalid_records >= 1


def test_load_run_rejects_test_record_with_schema_version(tmp_path):
    rec = _test_record()
    rec["schema_version"] = "0.0.1-impostor"
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0
    assert run.invalid_records >= 1


# ── A-MED-1 + B-MED-1: baselines size cap + symlink reject ──


def test_load_baselines_rejects_oversized_file(tmp_path):
    f = tmp_path / "huge.json"
    f.write_bytes(b"x" * (aggregate._BASELINES_FILE_CAP + 1))
    with pytest.raises(aggregate.AggregatorError, match="exceeds"):
        aggregate._load_baselines(f)


def test_load_baselines_rejects_symlink(tmp_path):
    target = tmp_path / "real.json"
    target.write_text("{}")
    sym = tmp_path / "baselines.json"
    sym.symlink_to(target)
    with pytest.raises(aggregate.AggregatorError, match="symlink"):
        aggregate._load_baselines(sym)


# ── A-MED-3: --top filters out non-pass cells ──


def test_main_top_excludes_skipped_cells(tmp_path, capsys):
    """`--top 5` MUST exclude `skipped_*` cells (max_total=0)."""
    pass_rec = _test_record(test="SF1-direct-rm-rf-root", state="pass")
    skip_rec = _test_record(
        test="SF2-prompt-injection-ignore-rules",
        state="skipped_cli_missing",
        score={"pass": False, "total": 0, "max_total": 0},
    )
    _write_run(tmp_path, recs=[pass_rec, skip_rec])
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--format",
            "json",
            "--top",
            "5",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    body = json.loads(captured.out)
    states = [c["state"] for c in body["cells"]]
    assert "skipped_cli_missing" not in states


# ── A-LOW-1: typed exit-code mapping ──


def test_main_invalid_run_id_returns_64(tmp_path, capsys):
    rc = aggregate.main(
        [
            "--run-id",
            "not-a-valid-id",
            "--results-root",
            str(tmp_path),
        ]
    )
    assert rc == 64


def test_main_run_not_found_returns_78(tmp_path, capsys):
    rc = aggregate.main(
        [
            "--run-id",
            "2100-01-01T00-00-00Z-99999-0000-Missing9",
            "--results-root",
            str(tmp_path),
        ]
    )
    assert rc == 78


# ── B-HIGH-1: markdown escape strips newlines ──


def test_md_escape_strips_newline_in_cell():
    out = aggregate._md_escape("pass\nfail|EVIL|EVIL")
    assert "\n" not in out
    assert "\r" not in out
    # Pipes still escaped after newline strip.
    assert r"\|" in out


def test_md_escape_strips_carriage_return():
    out = aggregate._md_escape("pass\rfail")
    assert "\r" not in out


def test_md_escape_strips_other_control_chars():
    out = aggregate._md_escape("test\x07\x1bbeep")
    # Bell (\x07) and ESC (\x1b) replaced with space.
    assert "\x07" not in out
    assert "\x1b" not in out


# ── B-HIGH-2: markdown escape extends to brackets + angle brackets ──


def test_md_escape_brackets_neutralized():
    out = aggregate._md_escape("[click](javascript:alert(1))")
    # Square brackets escaped → not a clickable link.
    assert r"\[" in out
    assert r"\]" in out


def test_md_escape_angle_brackets_entity_encoded():
    out = aggregate._md_escape("<script>alert</script>")
    assert "<" not in out
    assert ">" not in out
    assert "&lt;script&gt;" in out


# ── B-HIGH-3: negative max_total / total > max_total refused ──


def test_load_run_rejects_negative_total(tmp_path):
    rec = _test_record(score={"pass": False, "total": -5, "max_total": 10})
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0
    assert run.invalid_records >= 1


def test_load_run_rejects_negative_max_total(tmp_path):
    rec = _test_record(score={"pass": False, "total": 0, "max_total": -10})
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0
    assert run.invalid_records >= 1


def test_load_run_rejects_total_exceeding_max(tmp_path):
    rec = _test_record(score={"pass": True, "total": 100, "max_total": 1})
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0
    assert run.invalid_records >= 1


# ── B-HIGH-4: --full uses run.clis_seen ──


def test_full_coverage_uses_clis_seen_default(tmp_path, capsys):
    """Single-CLI run with --full does not flag missing codex/gemini."""
    rec = _test_record()
    _write_run(tmp_path, recs=[rec])
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--full",
        ]
    )
    # safety has 5 tests; this run only has SF1, so 4 of 5 are missing
    # for cc → still returns 2. But codex/gemini are NOT in clis_seen
    # so they don't multiply the missing count.
    assert rc == 2
    captured = capsys.readouterr()
    # No codex/gemini cells should be flagged.
    assert "cli=codex" not in captured.err
    assert "cli=gemini" not in captured.err


# ── B-HIGH-5: quarantined canary leak surfaced ──


def test_load_run_records_quarantined_isolation_breach(tmp_path):
    """A quarantined cell with isolation_breach=True surfaces in
    `quarantined_breaches` even though the cell itself is excluded
    from the matrix (default include_quarantined=False).
    """
    rec = _test_record(
        state="skipped_quarantined",
        score={
            "pass": False,
            "total": 0,
            "max_total": 0,
            "isolation_breach": True,
        },
    )
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0  # quarantined skip
    assert len(run.quarantined_breaches) == 1
    assert run.quarantined_breaches[0][1] == "SF1-direct-rm-rf-root"


def test_main_emits_quarantined_breach_audit_banner(tmp_path, capsys):
    rec = _test_record(
        state="skipped_quarantined",
        score={
            "pass": False,
            "total": 0,
            "max_total": 0,
            "isolation_breach": True,
        },
    )
    _write_run(tmp_path, recs=[rec])
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "isolation_breach" in captured.err
    assert "quarantined" in captured.err.lower()


# ── B-MED-2: baselines schema typo detection ──


def test_load_baselines_rejects_typo_floor_key(tmp_path):
    """`min_totl` (typo of min_total) is rejected, NOT silently
    accepted as 'no floor → cell trivially passes'."""
    f = tmp_path / "baselines.json"
    f.write_text(
        json.dumps(
            {
                "v1": {
                    "safety": {"cc": {"SF1-direct-rm-rf-root": {"min_totl": 7}}}  # typo
                }
            }
        )
    )
    with pytest.raises(aggregate.AggregatorError, match="unknown floor key"):
        aggregate._load_baselines(f)


def test_load_baselines_rejects_empty_floor_dict(tmp_path):
    """A leaf with neither min_total nor min_pct is rejected."""
    f = tmp_path / "baselines.json"
    f.write_text(json.dumps({"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {}}}}}))
    with pytest.raises(aggregate.AggregatorError, match="must define"):
        aggregate._load_baselines(f)


def test_load_baselines_accepts_real_committed_file():
    """The committed coc-eval/baselines.json must validate."""
    real = _EVAL_ROOT / "baselines.json"
    if not real.is_file():
        pytest.skip("no committed baselines.json in this checkout")
    body = aggregate._load_baselines(real)
    assert "v1" in body


# ── B-MED-3: state enum validated at load ──


def test_load_run_rejects_unknown_state_value(tmp_path):
    rec = _test_record(state="\x1b]0;evil\x07")  # terminal title injection
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0
    assert run.invalid_records >= 1


def test_load_run_accepts_canonical_state_values(tmp_path):
    for state in ("pass", "fail", "skipped_cli_missing", "error_timeout"):
        rec = _test_record(state=state)
        run_id = f"2100-01-01T00-00-00Z-11111-0000-Test{state[:4]}AB"[:40]
        # Must match _RUN_ID_RE: 6-12 char suffix after last dash.
        run_id = "2100-01-01T00-00-00Z-11111-0000-AaBbCcDd"
        run_dir = tmp_path / state.replace("_", "-")[:30] / run_id
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir()
        (run_dir / "safety-cc.jsonl").write_text(
            json.dumps(_header(run_id=run_id)) + "\n" + json.dumps(rec) + "\n",
            encoding="utf-8",
        )
        run = aggregate._load_run(run_dir)
        # Canonical values produce a cell (or skip — both valid).
        assert run.invalid_records == 0


# ── B-MED-4: dual-floor docstring + behavior ──


def test_below_baseline_dual_floor_total_under(tmp_path):
    cell = aggregate.Cell(state="pass", total=4, max_total=10, runtime_ms=0, attempts=1)
    floors = {
        "v1": {
            "safety": {
                "cc": {"SF1-direct-rm-rf-root": {"min_total": 7, "min_pct": 0.3}}
            }
        }
    }
    # total=4 < min_total=7 → fails total floor
    assert aggregate._below_baseline(
        ("safety", "SF1-direct-rm-rf-root", "cc"), cell, floors
    )


def test_below_baseline_dual_floor_pct_under():
    cell = aggregate.Cell(state="pass", total=8, max_total=20, runtime_ms=0, attempts=1)
    floors = {
        "v1": {
            "safety": {
                "cc": {"SF1-direct-rm-rf-root": {"min_total": 5, "min_pct": 0.7}}
            }
        }
    }
    # total=8 >= min_total=5 (pass) but ratio=0.4 < 0.7 (fail)
    assert aggregate._below_baseline(
        ("safety", "SF1-direct-rm-rf-root", "cc"), cell, floors
    )


def test_below_baseline_max_total_zero_with_pct_floor_fails():
    """max_total=0 with min_pct set → cannot evaluate → fail-safe rejection."""
    cell = aggregate.Cell(
        state="skipped_cli_missing",
        total=0,
        max_total=0,
        runtime_ms=0,
        attempts=0,
    )
    floors = {"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {"min_pct": 0.7}}}}}
    assert aggregate._below_baseline(
        ("safety", "SF1-direct-rm-rf-root", "cc"), cell, floors
    )


# ── C-MED-4: render_json field shapes ──


def test_render_json_field_types_correct(tmp_path):
    rec = _test_record()
    _write_run(tmp_path, recs=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    buf = StringIO()
    aggregate._render_json(run, list(run.cells.items()), buf)
    body = json.loads(buf.getvalue())
    cell = body["cells"][0]
    assert isinstance(cell["total"], (int, float))
    assert isinstance(cell["max_total"], (int, float))
    assert isinstance(cell["runtime_ms"], (int, float))
    assert isinstance(cell["attempts"], int)
    assert isinstance(cell["isolation_breach"], bool)
    assert isinstance(cell["state"], str)


# ── C-MED-2: baseline degenerate cases ──


def test_baseline_gate_max_total_zero_with_pct_floor(tmp_path, capsys):
    """A cell with max_total=0 but a min_pct floor MUST fail the gate."""
    rec = _test_record(score={"pass": False, "total": 0, "max_total": 0})
    _write_run(tmp_path, recs=[rec])
    bp = tmp_path / "baselines.json"
    bp.write_text(
        json.dumps(
            {"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {"min_pct": 0.7}}}}}
        )
    )
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--gate",
            "baseline",
            "--baselines-path",
            str(bp),
        ]
    )
    assert rc == 1
