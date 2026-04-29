"""Runner token-budget circuit breaker (INV-RUN-7)."""

from __future__ import annotations

from pathlib import Path

from lib.runner import RunContext, RunSelection, _check_token_budget


def _make_ctx(input_budget: int | None, output_budget: int | None) -> RunContext:
    sel = RunSelection(
        suites=("capability",),
        clis=("cc",),
        tests=None,
        tags=None,
        skip_clis=frozenset(),
        skip_suites=frozenset(),
    )
    return RunContext(
        run_id="2026-04-29T10-15-22Z-12345-0001-AaBbCcDd",
        started_at_iso="2026-04-29T10:15:22.000Z",
        started_at_mono=0.0,
        results_root=Path("/dev/null"),
        selection=sel,
        invocation="test",
        token_budget_input=input_budget,
        token_budget_output=output_budget,
    )


def test_no_budget_means_no_abort() -> None:
    ctx = _make_ctx(None, None)
    ctx.cumulative_tokens_input = 1_000_000
    ctx.cumulative_tokens_output = 1_000_000
    assert _check_token_budget(ctx) is False


def test_input_budget_breach_aborts() -> None:
    ctx = _make_ctx(1000, None)
    ctx.cumulative_tokens_input = 999
    assert _check_token_budget(ctx) is False
    ctx.cumulative_tokens_input = 1000
    assert _check_token_budget(ctx) is True


def test_output_budget_breach_aborts() -> None:
    ctx = _make_ctx(None, 500)
    ctx.cumulative_tokens_output = 499
    assert _check_token_budget(ctx) is False
    ctx.cumulative_tokens_output = 500
    assert _check_token_budget(ctx) is True


def test_either_budget_breaches_independently() -> None:
    ctx = _make_ctx(1000, 500)
    ctx.cumulative_tokens_input = 999
    ctx.cumulative_tokens_output = 500
    assert _check_token_budget(ctx) is True
