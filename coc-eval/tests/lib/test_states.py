"""Tests for `coc-eval/lib/states.py` — closed taxonomy + precedence ladders.

Verifies:
- All 16 states accounted for.
- Within-test precedence ladder is deterministic.
- pass_after_retry > pass (retry signal preserved per R2-MED-01).
- Across-test states identified correctly.
"""

from __future__ import annotations

from lib.states import (
    ACROSS_TEST_STATES,
    State,
    classify_within_test,
    is_pass,
    is_skip,
)


class TestStateEnum:
    """Closed enum — every state value is recognized."""

    def test_within_test_states_present(self):
        for value in (
            "pass",
            "pass_after_retry",
            "fail",
            "error_fixture",
            "error_invocation",
            "error_json_parse",
            "error_timeout",
            "skipped_sandbox",
            "skipped_artifact_shape",
        ):
            State(value)

    def test_across_test_states_present(self):
        for value in (
            "skipped_cli_missing",
            "skipped_cli_auth",
            "skipped_quota",
            "skipped_quarantined",
            "skipped_user_request",
            "skipped_budget",
            "error_token_budget",
        ):
            State(value)

    def test_unknown_state_rejected(self):
        try:
            State("invented")
        except ValueError:
            return
        raise AssertionError("expected ValueError on unknown state")

    def test_str_inheritance(self):
        # Inherits from str so JSON serialization is automatic.
        assert State.PASS == "pass"
        assert State.PASS_AFTER_RETRY.value == "pass_after_retry"

    def test_total_state_count(self):
        # 9 within + 7 across = 16.
        assert len(list(State)) == 16


class TestWithinTestPrecedence:
    """R2-MED-01 within-test ladder: more-specific predicates win."""

    def test_pass_after_retry_beats_pass(self):
        # If both `pass` and `pass_after_retry` match, retry signal wins.
        result = classify_within_test({"pass": True, "pass_after_retry": True})
        assert result == State.PASS_AFTER_RETRY

    def test_error_fixture_beats_everything(self):
        result = classify_within_test(
            {
                "error_fixture": True,
                "error_invocation": True,
                "error_timeout": True,
                "fail": True,
            }
        )
        assert result == State.ERROR_FIXTURE

    def test_error_invocation_beats_lower(self):
        result = classify_within_test(
            {
                "error_invocation": True,
                "error_timeout": True,
                "fail": True,
            }
        )
        assert result == State.ERROR_INVOCATION

    def test_error_timeout_beats_skips(self):
        result = classify_within_test(
            {
                "error_timeout": True,
                "skipped_sandbox": True,
                "skipped_artifact_shape": True,
            }
        )
        assert result == State.ERROR_TIMEOUT

    def test_skipped_sandbox_beats_artifact_shape(self):
        # Less-specific skip wins over more-specific? No — artifact_shape is
        # MORE specific (per implementation suite gap). Verify the chosen
        # ordering matches the spec.
        result = classify_within_test(
            {
                "skipped_sandbox": True,
                "skipped_artifact_shape": True,
            }
        )
        # Per the ladder: SKIPPED_SANDBOX has higher index than SKIPPED_ARTIFACT_SHAPE.
        assert result == State.SKIPPED_SANDBOX

    def test_pass_alone(self):
        assert classify_within_test({"pass": True}) == State.PASS

    def test_fail_alone(self):
        assert classify_within_test({"fail": True}) == State.FAIL

    def test_no_signals_defaults_to_fail(self):
        # Empty signals = fail (caller error, but deterministic).
        assert classify_within_test({}) == State.FAIL

    def test_unknown_signals_ignored(self):
        result = classify_within_test({"unknown_predicate": True, "pass": True})
        assert result == State.PASS

    def test_deterministic_resolution_5x(self):
        """AC-18: same input → same output across 5 trials."""
        signals = {"error_timeout": True, "fail": True, "pass": False}
        results = [classify_within_test(signals) for _ in range(5)]
        assert all(r == State.ERROR_TIMEOUT for r in results)


class TestAcrossTestStates:
    """R2-MED-01: across-test states are NOT in the within-test ladder."""

    def test_across_test_set_complete(self):
        assert State.SKIPPED_CLI_MISSING in ACROSS_TEST_STATES
        assert State.SKIPPED_CLI_AUTH in ACROSS_TEST_STATES
        assert State.SKIPPED_QUOTA in ACROSS_TEST_STATES
        assert State.SKIPPED_QUARANTINED in ACROSS_TEST_STATES
        assert State.SKIPPED_USER_REQUEST in ACROSS_TEST_STATES
        assert State.SKIPPED_BUDGET in ACROSS_TEST_STATES
        assert State.ERROR_TOKEN_BUDGET in ACROSS_TEST_STATES

    def test_within_test_states_excluded(self):
        for state in (
            State.PASS,
            State.PASS_AFTER_RETRY,
            State.FAIL,
            State.ERROR_FIXTURE,
            State.ERROR_INVOCATION,
            State.ERROR_JSON_PARSE,
            State.ERROR_TIMEOUT,
            State.SKIPPED_SANDBOX,
            State.SKIPPED_ARTIFACT_SHAPE,
        ):
            assert state not in ACROSS_TEST_STATES


class TestPredicateHelpers:
    def test_is_pass(self):
        assert is_pass(State.PASS)
        assert is_pass(State.PASS_AFTER_RETRY)
        assert not is_pass(State.FAIL)
        assert not is_pass(State.ERROR_TIMEOUT)
        assert not is_pass(State.SKIPPED_QUOTA)

    def test_is_skip(self):
        assert is_skip(State.SKIPPED_CLI_MISSING)
        assert is_skip(State.SKIPPED_CLI_AUTH)
        assert is_skip(State.SKIPPED_QUOTA)
        assert is_skip(State.SKIPPED_SANDBOX)
        assert is_skip(State.SKIPPED_ARTIFACT_SHAPE)
        assert is_skip(State.SKIPPED_QUARANTINED)
        assert is_skip(State.SKIPPED_USER_REQUEST)
        assert is_skip(State.SKIPPED_BUDGET)
        assert not is_skip(State.PASS)
        assert not is_skip(State.FAIL)
        assert not is_skip(State.ERROR_TIMEOUT)
        assert not is_skip(State.ERROR_TOKEN_BUDGET)
