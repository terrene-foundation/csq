"""Unit tests for `coc-eval/aggregate.py` (H9).

Synthetic JSONL fixtures only — no live cc spawn. Covers:

- Run discovery (latest + explicit --run-id).
- JSON-bomb defenses (oversized file/record, out-of-range int).
- Render formats (pretty/json/csv/md).
- Markdown-injection escape (R1-HIGH-03 / AC-8a).
- Baseline gate (below-floor exits 1).
- Partial-coverage gate (--full / --allow-partial).
- Stale schema_version handling (default reject + --allow-stale).
- Quarantine skip + --include-quarantined.
- Filters (--failed-only, --regressions-only, --top).
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


# ── Fixture builders ──────────────────────────────────────────────────


_RUN_ID = "2026-04-30T05-00-00Z-99999-0000-AaBbCcDd"


def _header_record(
    suite: str = "safety", schema_version: str = "1.0.0"
) -> dict[str, Any]:
    return {
        "_header": True,
        "schema_version": schema_version,
        "harness_version": "h9-test",
        "run_id": _RUN_ID,
        "suite": suite,
        "started_at": "2026-04-30T05:00:00.000Z",
        "host": {"platform": "test", "arch": "test", "python": "3.12"},
        "cli_versions": {"cc": "test"},
        "auth_probes": {},
    }


def _test_record(
    *,
    suite: str = "safety",
    test: str = "SF1-direct-rm-rf-root",
    cli: str = "cc",
    state: str = "pass",
    total: float = 2.0,
    max_total: float = 2.0,
    runtime_ms: float = 5000.0,
    isolation_breach: bool = False,
) -> dict[str, Any]:
    return {
        "_header": False,
        "suite": suite,
        "test": test,
        "cli": cli,
        "fixture": "safety",
        "fixture_dir": "/tmp/test",
        "permission_mode": "plan",
        "started_at": "2026-04-30T05:00:01.000Z",
        "ended_at": "2026-04-30T05:00:06.000Z",
        "runtime_ms": runtime_ms,
        "exit_code": 0,
        "timed_out": False,
        "attempts": 1,
        "attempt_states": [state],
        "state": state,
        "scoring_backend": "regex",
        "score": {
            "pass": state in ("pass", "pass_after_retry"),
            "total": total,
            "max_total": max_total,
            "criteria": [],
            "rubric": "default",
            "isolation_breach": isolation_breach,
        },
        "stdout_truncated": "",
        "stderr_truncated": "",
    }


def _write_run(
    base: Path,
    run_id: str = _RUN_ID,
    *,
    test_records: list[dict[str, Any]] | None = None,
    header: dict[str, Any] | None = None,
) -> Path:
    """Write a synthetic run dir with one JSONL file.

    If the caller does not supply `header`, a default header is built
    with `run_id` matching the directory name — otherwise the
    discovery + header would reference different ids.
    """
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    jsonl = run_dir / "safety-cc-2026-04-30T05-00-00Z.jsonl"
    if header is None:
        header = _header_record()
        header["run_id"] = run_id
    lines: list[str] = []
    lines.append(json.dumps(header))
    for r in test_records or []:
        lines.append(json.dumps(r))
    jsonl.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return run_dir


# ── Run discovery ─────────────────────────────────────────────────────


def test_discover_latest_run_returns_most_recent(tmp_path):
    older = "2026-04-29T05-00-00Z-11111-0000-AaBbCcDd"
    newer = "2026-04-30T05-00-00Z-22222-0000-AaBbCcDd"
    _write_run(tmp_path, older)
    _write_run(tmp_path, newer)
    found = aggregate._discover_latest_run(tmp_path)
    assert found is not None
    assert found.name == newer


def test_discover_latest_run_returns_none_on_empty(tmp_path):
    assert aggregate._discover_latest_run(tmp_path) is None


def test_discover_latest_run_skips_non_run_id_dirs(tmp_path):
    (tmp_path / "not-a-run-dir").mkdir()
    assert aggregate._discover_latest_run(tmp_path) is None


def test_resolve_run_dir_explicit(tmp_path):
    run_dir = _write_run(tmp_path)
    args = aggregate.build_parser().parse_args(["--run-id", _RUN_ID])
    found = aggregate._resolve_run_dir(args, tmp_path)
    assert found == run_dir


def test_resolve_run_dir_invalid_run_id(tmp_path):
    args = aggregate.build_parser().parse_args(["--run-id", "not-valid"])
    with pytest.raises(aggregate.AggregatorError, match="invalid --run-id"):
        aggregate._resolve_run_dir(args, tmp_path)


# ── JSON-bomb defenses (R1-HIGH-05 / AC-8b) ───────────────────────────


def test_iter_jsonl_rejects_oversized_file(tmp_path):
    big = tmp_path / "huge.jsonl"
    big.write_bytes(b"x" * (aggregate._PER_FILE_BYTES_CAP + 1))
    with pytest.raises(aggregate.AggregatorError, match="exceeds"):
        aggregate._iter_jsonl_records(big)


def test_iter_jsonl_skips_oversized_record(tmp_path):
    """A single line over per-record cap is counted as invalid, not aborting."""
    f = tmp_path / "one.jsonl"
    valid = json.dumps(_header_record())
    huge = "x" * (aggregate._PER_RECORD_BYTES_CAP + 1)
    f.write_text(valid + "\n" + huge + "\n", encoding="utf-8")
    records, invalid = aggregate._iter_jsonl_records(f)
    assert len(records) == 1
    assert invalid == 1


def test_iter_jsonl_skips_malformed_json(tmp_path):
    f = tmp_path / "bad.jsonl"
    f.write_text(json.dumps(_header_record()) + "\n{not json\n", encoding="utf-8")
    records, invalid = aggregate._iter_jsonl_records(f)
    assert len(records) == 1
    assert invalid == 1


def test_iter_jsonl_rejects_out_of_range_int(tmp_path):
    """Integer > 2^53 is rejected as JSON-bomb defense."""
    f = tmp_path / "bigint.jsonl"
    bad = {"_header": False, "runtime_ms": (1 << 60)}
    f.write_text(
        json.dumps(_header_record()) + "\n" + json.dumps(bad) + "\n",
        encoding="utf-8",
    )
    records, invalid = aggregate._iter_jsonl_records(f)
    assert len(records) == 1  # only header survives
    assert invalid == 1


def test_check_int_bounds_within_range():
    assert aggregate._check_int_bounds({"a": 1, "b": [2, 3]})
    assert aggregate._check_int_bounds({"a": aggregate._JS_SAFE_INT_MAX})


def test_check_int_bounds_rejects_oversized():
    assert not aggregate._check_int_bounds({"a": aggregate._JS_SAFE_INT_MAX + 1})
    assert not aggregate._check_int_bounds([1, 2, 1 << 60])


def test_check_int_bounds_rejects_deep_nesting():
    """Stack-bomb defense: refuse JSON nested past max_depth."""
    deep: Any = 1
    for _ in range(40):
        deep = [deep]
    assert not aggregate._check_int_bounds(deep, max_depth=32)


# ── Stale schema_version + quarantine ─────────────────────────────────


def test_load_run_rejects_stale_schema_by_default(tmp_path):
    header = _header_record(schema_version="0.9.0-old")
    _write_run(tmp_path, header=header, test_records=[_test_record()])
    run_dir = tmp_path / _RUN_ID
    with pytest.raises(aggregate.AggregatorError, match="schema_version drift"):
        aggregate._load_run(run_dir)


def test_load_run_accepts_stale_with_override(tmp_path):
    header = _header_record(schema_version="0.9.0-old")
    _write_run(tmp_path, header=header, test_records=[_test_record()])
    run_dir = tmp_path / _RUN_ID
    run = aggregate._load_run(run_dir, allow_stale=True)
    assert run.schema_version == "0.9.0-old"
    assert len(run.cells) == 1


def test_load_run_skips_quarantined_by_default(tmp_path):
    quar = _test_record(state="skipped_quarantined")
    _write_run(tmp_path, test_records=[quar])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 0
    assert run.skipped_records == 1


def test_load_run_includes_quarantined_when_opted_in(tmp_path):
    quar = _test_record(state="skipped_quarantined")
    _write_run(tmp_path, test_records=[quar])
    run = aggregate._load_run(tmp_path / _RUN_ID, include_quarantined=True)
    assert len(run.cells) == 1


# ── Markdown-injection escape (R1-HIGH-03 / AC-8a) ────────────────────


def test_md_escape_pipe_breaks_table():
    """A test name containing `|` would split a markdown table column.
    `_md_escape` must escape the pipe so the rendered cell contains
    a literal pipe inside the column.
    """
    out = aggregate._md_escape("evil|column|injection")
    assert out == r"evil\|column\|injection"


def test_md_escape_backtick_neutralized():
    out = aggregate._md_escape("`code`")
    assert "`" not in out.replace("\\`", "")


def test_md_escape_html_comment_rewritten():
    out = aggregate._md_escape("<!-- evil comment -->")
    assert "<!--" not in out
    assert "&lt;!--" in out


def test_md_render_escapes_evil_test_name(tmp_path):
    rec = _test_record(test="EVIL|`name`")
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    buf = StringIO()
    aggregate._render_md(run, list(run.cells.items()), buf)
    body = buf.getvalue()
    # The evil test name is escaped.
    assert r"EVIL\|" in body
    assert r"\`name\`" in body


# ── Baselines + gate ──────────────────────────────────────────────────


def test_baseline_gate_passes_at_or_above_floor(tmp_path):
    rec = _test_record(total=10, max_total=10)
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    baselines = {"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {"min_pct": 1.0}}}}}
    err = StringIO()
    rc = aggregate._check_baseline_gate(run, baselines, err)
    assert rc == 0


def test_baseline_gate_fails_below_floor(tmp_path):
    rec = _test_record(total=1, max_total=2)  # 50%
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    baselines = {"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {"min_pct": 0.7}}}}}
    err = StringIO()
    rc = aggregate._check_baseline_gate(run, baselines, err)
    assert rc == 1
    assert "baseline-gate violations" in err.getvalue()


def test_baseline_gate_min_total_floor(tmp_path):
    rec = _test_record(total=4, max_total=10)
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    baselines = {"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {"min_total": 7}}}}}
    err = StringIO()
    rc = aggregate._check_baseline_gate(run, baselines, err)
    assert rc == 1


def test_baseline_gate_ignores_unmapped_cells(tmp_path):
    """Cells without baseline entry are not flagged."""
    rec = _test_record(test="SF99-not-in-baselines", total=0, max_total=2)
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    baselines = {"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {"min_pct": 1.0}}}}}
    err = StringIO()
    rc = aggregate._check_baseline_gate(run, baselines, err)
    assert rc == 0


# ── Filters: --failed-only / --regressions-only / --top ───────────────


def test_filter_failed_only(tmp_path):
    pass_rec = _test_record(test="SF1-direct-rm-rf-root", state="pass")
    fail_rec = _test_record(test="SF2-prompt-injection-ignore-rules", state="fail")
    _write_run(tmp_path, test_records=[pass_rec, fail_rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    pairs = aggregate._filter_cells(run, failed_only=True)
    assert len(pairs) == 1
    assert pairs[0][1].state == "fail"


def test_filter_regressions_only_requires_baselines(tmp_path):
    pass_rec = _test_record(test="SF1-direct-rm-rf-root", total=1, max_total=2)  # below
    pass2 = _test_record(test="SF2-prompt-injection-ignore-rules", total=2, max_total=2)
    _write_run(tmp_path, test_records=[pass_rec, pass2])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    baselines = {"v1": {"safety": {"cc": {"SF1-direct-rm-rf-root": {"min_pct": 0.7}}}}}
    pairs = aggregate._filter_cells(run, regressions_only=True, baselines=baselines)
    assert len(pairs) == 1
    assert pairs[0][0][1] == "SF1-direct-rm-rf-root"


# ── Render formats ────────────────────────────────────────────────────


def test_render_json_round_trips(tmp_path):
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    buf = StringIO()
    aggregate._render_json(run, list(run.cells.items()), buf)
    body = json.loads(buf.getvalue())
    assert body["run_id"] == _RUN_ID
    assert len(body["cells"]) == 1
    assert body["cells"][0]["state"] == "pass"


def test_render_csv_header_row(tmp_path):
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    buf = StringIO()
    aggregate._render_csv(run, list(run.cells.items()), buf)
    lines = buf.getvalue().splitlines()
    assert lines[0].startswith("suite,test,cli,state")
    assert "SF1-direct-rm-rf-root" in lines[1]


def test_render_pretty_includes_run_id(tmp_path):
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    buf = StringIO()
    aggregate._render_pretty(run, list(run.cells.items()), buf)
    body = buf.getvalue()
    assert _RUN_ID in body
    assert "OK" in body  # state glyph for pass


# ── Partial coverage ──────────────────────────────────────────────────


def test_check_full_coverage_passes_when_complete(tmp_path):
    recs = []
    for cli in ("cc", "codex", "gemini"):
        for tname in ("SF1-direct-rm-rf-root", "SF2-prompt-injection-ignore-rules"):
            recs.append(_test_record(test=tname, cli=cli))
    _write_run(tmp_path, test_records=recs)
    run = aggregate._load_run(tmp_path / _RUN_ID)
    err = StringIO()
    rc = aggregate._check_full_coverage(
        run,
        suite_test_manifests={
            "safety": ("SF1-direct-rm-rf-root", "SF2-prompt-injection-ignore-rules")
        },
        selected_clis=("cc", "codex", "gemini"),
        err=err,
    )
    assert rc == 0


def test_check_full_coverage_flags_missing_cells(tmp_path):
    """Only cc populated; codex+gemini missing → exit 2."""
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    err = StringIO()
    rc = aggregate._check_full_coverage(
        run,
        suite_test_manifests={"safety": ("SF1-direct-rm-rf-root",)},
        selected_clis=("cc", "codex", "gemini"),
        err=err,
    )
    assert rc == 2
    assert "missing" in err.getvalue()


# ── End-to-end main() ─────────────────────────────────────────────────


def test_main_validate_against_real_run(tmp_path, monkeypatch, capsys):
    """`main(['--run-id', RUN, '--validate', '--results-root', ...])` returns 0."""
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--validate",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "OK:" in captured.out


def test_main_no_runs_returns_78(tmp_path, capsys):
    rc = aggregate.main(["--results-root", str(tmp_path)])
    assert rc == 78
    captured = capsys.readouterr()
    assert "no run directories" in captured.err


def test_main_default_picks_latest(tmp_path, capsys):
    older = "2026-04-29T05-00-00Z-11111-0000-AaBbCcDd"
    newer = "2026-04-30T05-00-00Z-22222-0000-AaBbCcDd"
    _write_run(tmp_path, older, test_records=[_test_record()])
    _write_run(tmp_path, newer, test_records=[_test_record()])
    rc = aggregate.main(
        [
            "--results-root",
            str(tmp_path),
            "--validate",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    # Validate emits OK; the underlying run picked is newer (verified
    # through the run_id printed in JSON output of a non-validate run).
    rc2 = aggregate.main(
        [
            "--results-root",
            str(tmp_path),
            "--format",
            "json",
        ]
    )
    assert rc2 == 0
    captured = capsys.readouterr()
    body = json.loads(captured.out)
    assert body["run_id"] == newer


def test_main_full_partial_returns_2(tmp_path, capsys):
    """--full with a single cc-only run on safety fails coverage."""
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--full",
        ]
    )
    # Safety manifest has 5 tests × 3 CLIs = 15 cells; we provided 1.
    assert rc == 2


def test_main_full_with_allow_partial_returns_0(tmp_path, capsys):
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--full",
            "--allow-partial",
        ]
    )
    assert rc == 0


def test_main_baseline_gate_below_floor_returns_1(tmp_path, capsys):
    rec = _test_record(total=1, max_total=10)  # 10% — below 0.7
    _write_run(tmp_path, test_records=[rec])
    # Use a custom baselines file pointing at SF1.
    baselines_file = tmp_path / "baselines.json"
    baselines_file.write_text(
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
            str(baselines_file),
        ]
    )
    assert rc == 1


def test_main_format_md_output_well_formed(tmp_path, capsys):
    rec = _test_record()
    _write_run(tmp_path, test_records=[rec])
    rc = aggregate.main(
        [
            "--run-id",
            _RUN_ID,
            "--results-root",
            str(tmp_path),
            "--format",
            "md",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "| Suite | Test | CLI |" in captured.out
    assert _RUN_ID in captured.out


# ── Schema fwd-compat (UX-17 / AC-46) ─────────────────────────────────


def test_load_run_tolerates_unknown_fields(tmp_path):
    """Forward-compat: unknown fields in records are ignored, not rejected."""
    header = _header_record()
    header["unknown_future_field"] = "ignored"
    rec = _test_record()
    rec["unknown_future_field"] = {"nested": "data"}
    _write_run(tmp_path, header=header, test_records=[rec])
    run = aggregate._load_run(tmp_path / _RUN_ID)
    assert len(run.cells) == 1
