"""Unit tests for `lib.runner.score_regex` and selection resolution."""

from __future__ import annotations

import pytest

from lib.runner import (
    RunSelection,
    resolve_selection,
    score_regex,
    selected_tests_for_suite,
)
from suites.capability import SUITE as CAPABILITY_SUITE


# ---- score_regex --------------------------------------------------------


def test_score_regex_all_pass() -> None:
    criteria = [
        {"kind": "contains", "pattern": r"FOO", "label": "foo present"},
        {"kind": "absent", "pattern": r"BANNED", "label": "banned absent"},
    ]
    out = score_regex(criteria, "header FOO body")
    assert out["pass"] is True
    assert out["total"] == 2.0
    assert out["max_total"] == 2.0
    assert all(c["matched"] for c in out["criteria"])


def test_score_regex_one_fail() -> None:
    criteria = [
        {"kind": "contains", "pattern": r"FOO", "label": "foo present"},
        {"kind": "contains", "pattern": r"BAR", "label": "bar present"},
    ]
    out = score_regex(criteria, "FOO only")
    assert out["pass"] is False
    assert out["total"] == 1.0
    assert out["max_total"] == 2.0
    matched = [c["matched"] for c in out["criteria"]]
    assert matched == [True, False]


def test_score_regex_absent_kind_fails_when_present() -> None:
    criteria = [
        {"kind": "absent", "pattern": r"BANNED", "label": "no banned"},
    ]
    out = score_regex(criteria, "BANNED appears")
    assert out["pass"] is False
    assert out["criteria"][0]["matched"] is False


def test_score_regex_zero_criteria_does_not_pass() -> None:
    """An empty criteria list MUST NOT count as pass — fail-closed default."""
    out = score_regex([], "anything")
    assert out["pass"] is False
    assert out["max_total"] == 0.0


def test_score_regex_unknown_kind_raises() -> None:
    with pytest.raises(ValueError, match="unknown kind"):
        score_regex(
            [{"kind": "fs_assert", "pattern": "x", "label": "x"}],
            "nope",
        )


def test_score_regex_invalid_regex_raises() -> None:
    with pytest.raises(ValueError, match="invalid regex"):
        score_regex(
            [{"kind": "contains", "pattern": "(unclosed", "label": "bad"}],
            "x",
        )


def test_score_regex_canary_pattern_against_capability_c3() -> None:
    """Canary regex is contains for cc, absent for codex/gemini.

    Sanity-check the capability suite's encoded patterns work the way the
    runner expects — covers a common refactor mistake (e.g. swapping
    contains/absent across CLIs).
    """
    c3 = next(
        t for t in CAPABILITY_SUITE["tests"] if t["name"] == "C3-pathscoped-canary"
    )
    cc_criteria = c3["expect"]["cc"]
    codex_criteria = c3["expect"]["codex"]
    body_with_canary = "summary [INJECTED-PS-CANARY-9K2F3] of sample.py"
    body_without_canary = "summary of sample.py"

    cc_pass = score_regex(cc_criteria, body_with_canary)
    cc_fail = score_regex(cc_criteria, body_without_canary)
    codex_pass = score_regex(codex_criteria, body_without_canary)
    codex_fail = score_regex(codex_criteria, body_with_canary)
    assert cc_pass["pass"] is True
    assert cc_fail["pass"] is False
    assert codex_pass["pass"] is True
    assert codex_fail["pass"] is False


# ---- resolve_selection --------------------------------------------------


def test_resolve_selection_capability_cc() -> None:
    sel = resolve_selection("capability", "cc")
    assert sel.suites == ("capability",)
    assert sel.clis == ("cc",)
    assert sel.tests is None


def test_resolve_selection_all_expands_manifest() -> None:
    sel = resolve_selection("all", "all")
    assert "capability" in sel.suites
    assert "compliance" in sel.suites
    assert "safety" in sel.suites
    assert "implementation" in sel.suites
    assert sel.clis == ("cc", "codex", "gemini")


def test_resolve_selection_skip_clis_validates() -> None:
    with pytest.raises(ValueError):
        resolve_selection("capability", "cc", skip_clis=["nonexistent"])


def test_resolve_selection_invalid_test_name() -> None:
    with pytest.raises(ValueError):
        resolve_selection("capability", "cc", tests=["bad/path/traversal"])


def test_resolve_selection_with_tag() -> None:
    sel = resolve_selection("capability", "cc", tags=["baseline"])
    assert sel.tags == ("baseline",)


# ---- selected_tests_for_suite -------------------------------------------


def test_selected_tests_for_suite_filter_by_test_id() -> None:
    sel = RunSelection(
        suites=("capability",),
        clis=("cc",),
        tests=("C1-baseline-root",),
        tags=None,
        skip_clis=frozenset(),
        skip_suites=frozenset(),
    )
    out = selected_tests_for_suite(CAPABILITY_SUITE, sel)
    assert len(out) == 1
    assert out[0]["name"] == "C1-baseline-root"


def test_selected_tests_for_suite_filter_by_tag() -> None:
    sel = RunSelection(
        suites=("capability",),
        clis=("cc",),
        tests=None,
        tags=("baseline",),
        skip_clis=frozenset(),
        skip_suites=frozenset(),
    )
    out = selected_tests_for_suite(CAPABILITY_SUITE, sel)
    names = [t["name"] for t in out]
    # Both C1 and C2 carry "baseline" tag.
    assert names == ["C1-baseline-root", "C2-baseline-subdir"]


def test_selected_tests_for_suite_no_filter_returns_all() -> None:
    sel = RunSelection(
        suites=("capability",),
        clis=("cc",),
        tests=None,
        tags=None,
        skip_clis=frozenset(),
        skip_suites=frozenset(),
    )
    out = selected_tests_for_suite(CAPABILITY_SUITE, sel)
    assert len(out) == 4
