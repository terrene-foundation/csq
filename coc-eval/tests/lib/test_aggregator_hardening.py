"""Aggregator hardening primitives — markdown injection (AC-8a) +
JSON-bomb defenses (AC-8b).

`results/` is treated as untrusted input. The aggregator's primitives
in `lib.jsonl` close two attack vectors:

1. **Markdown injection** — a crafted JSONL with `<script>` / `|` / `\\n`
   in user-displayed fields could break a Markdown table rendering or
   inject HTML in renderers that pass through. `escape_md` neutralizes
   this.
2. **JSON-bomb DoS** — a crafted JSONL with absurdly long lines or
   billion-digit integers could exhaust memory at parse time. The size
   caps + `parse_int` ceiling close the obvious shapes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lib.jsonl import (
    JSONL_FILE_SIZE_CAP_BYTES,
    JSONL_LINE_BYTES_HARD,
    escape_md,
    iter_records,
    read_record,
)


class TestMarkdownEscape:
    """AC-8a — fields that surface in the Markdown matrix MUST be escaped."""

    def test_pipe_escaped(self) -> None:
        # `|` is the table-cell separator in GFM tables.
        assert escape_md("a|b") == "a\\|b"

    def test_html_angle_brackets_escaped(self) -> None:
        s = "<script>alert(1)</script>"
        out = escape_md(s)
        assert "<" not in out and ">" not in out
        assert "&lt;script&gt;" in out
        assert "&lt;/script&gt;" in out

    def test_javascript_anchor_neutralized(self) -> None:
        # The canonical AC-8a injection canary.
        s = "|<a href=javascript:alert(1)>x</a>|"
        out = escape_md(s)
        assert "<a href" not in out
        assert "|" not in out.replace("\\|", "")  # only escaped pipes survive

    def test_backticks_escaped(self) -> None:
        # Code-fence escape so a Markdown renderer cannot terminate a
        # surrounding code block via injected backticks.
        assert escape_md("`evil`") == "\\`evil\\`"

    def test_newlines_collapsed_to_spaces(self) -> None:
        # Single-line table cell — newlines would split the cell.
        assert escape_md("line1\nline2") == "line1 line2"
        assert escape_md("line1\r\nline2") == "line1 line2"
        assert escape_md("line1\rline2") == "line1 line2"

    def test_non_string_returns_empty(self) -> None:
        assert escape_md(None) == ""  # type: ignore[arg-type]
        assert escape_md(42) == ""  # type: ignore[arg-type]


class TestPerLineByteCap:
    """AC-8b — per-record size cap rejects oversized lines."""

    def test_oversized_line_raises(self) -> None:
        line = "x" * (JSONL_LINE_BYTES_HARD + 100)
        with pytest.raises(ValueError, match=r"hard cap"):
            read_record(line)

    def test_at_cap_passes(self) -> None:
        # Build a small valid record and pad until just under the cap.
        body = '{"_header": false, "padding": "%s"}'
        # Compute the padding length so the final line is under the cap.
        overhead = len(body % "")
        pad = "x" * (JSONL_LINE_BYTES_HARD - overhead - 10)
        line = body % pad
        assert len(line) <= JSONL_LINE_BYTES_HARD
        rec = read_record(line)
        assert rec["padding"] == pad


class TestBoundedIntParsing:
    """AC-8b — integers with absurd digit counts are clamped to 0."""

    def test_normal_int_preserved(self) -> None:
        rec = read_record('{"runtime_ms": 1234, "_header": false}')
        assert rec["runtime_ms"] == 1234

    def test_oversized_int_clamped(self) -> None:
        # 30-digit int exceeds the JSONL_INT_PARSE_DIGITS_MAX = 19 ceiling.
        big = "9" * 30
        rec = read_record(f'{{"runtime_ms": {big}, "_header": false}}')
        assert rec["runtime_ms"] == 0

    def test_short_int_preserved(self) -> None:
        # 18 digits — under the cap; preserved as a regular int.
        n = "9" * 18
        rec = read_record(f'{{"runtime_ms": {n}, "_header": false}}')
        assert rec["runtime_ms"] == int(n)


class TestPerFileSizeCap:
    """AC-8b — JSONL files exceeding the per-file cap are skipped, not
    parsed.
    """

    def test_oversized_file_skipped(self, tmp_path: Path, capsys) -> None:
        big_path = tmp_path / "huge.jsonl"
        # Write a small valid record but pad with junk to exceed the cap.
        # We can't easily produce 10MB of data without bloating CI; emit
        # a tiny file then monkeypatch the cap to a very low value.
        big_path.write_text(
            '{"_header": true, "schema_version": "1.0.0"}\n', encoding="utf-8"
        )
        # Truncate the cap by a custom path: stat is real, so create a
        # file just over the desired cap.
        too_big = tmp_path / "actually_huge.jsonl"
        too_big.write_text("x" * (JSONL_FILE_SIZE_CAP_BYTES + 10), encoding="utf-8")
        records = list(iter_records(too_big))
        assert records == []
        # The skip is announced on stderr.
        captured = capsys.readouterr()
        assert "skipping oversized JSONL" in captured.err
