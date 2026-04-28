"""State enum + precedence ladders.

Per INV-OUT-3 (`04-nfr-and-invariants.md`), states fall into two ladders:

- Within-test predicate precedence (a single record resolves to one state):
    error_fixture > error_invocation > error_json_parse > error_timeout
    > skipped_sandbox > skipped_artifact_shape > pass_after_retry > pass > fail

- Across-test invariants (set at run-loop boundaries):
    skipped_cli_missing, skipped_cli_auth, skipped_quota,
    skipped_quarantined, error_token_budget, skipped_user_request,
    skipped_budget

The split (R2-MED-01) avoids conflating per-record predicate resolution with
run-loop boundaries. `error_token_budget` firing during an in-flight test
keeps the in-flight predicate; subsequent un-run tests stamp `error_token_budget`.
"""

from __future__ import annotations

from enum import Enum


class State(str, Enum):
    """Closed state taxonomy for test records.

    Inheriting from `str` lets `state.value` serialize to JSONL directly
    via `json.dumps(record)` without a custom encoder.
    """

    # Within-test states (single record resolution).
    PASS = "pass"
    PASS_AFTER_RETRY = "pass_after_retry"
    FAIL = "fail"
    ERROR_FIXTURE = "error_fixture"
    ERROR_INVOCATION = "error_invocation"
    ERROR_JSON_PARSE = "error_json_parse"
    ERROR_TIMEOUT = "error_timeout"
    SKIPPED_SANDBOX = "skipped_sandbox"
    SKIPPED_ARTIFACT_SHAPE = "skipped_artifact_shape"

    # Across-test states (run-loop boundaries).
    SKIPPED_CLI_MISSING = "skipped_cli_missing"
    SKIPPED_CLI_AUTH = "skipped_cli_auth"
    SKIPPED_QUOTA = "skipped_quota"
    SKIPPED_QUARANTINED = "skipped_quarantined"
    SKIPPED_USER_REQUEST = "skipped_user_request"
    SKIPPED_BUDGET = "skipped_budget"
    ERROR_TOKEN_BUDGET = "error_token_budget"


# Precedence ladder for within-test resolution. Higher index = higher priority.
# Used by classify_within_test() when multiple predicates match a single record.
_WITHIN_TEST_LADDER: tuple[State, ...] = (
    State.FAIL,  # lowest precedence
    State.PASS,
    State.PASS_AFTER_RETRY,
    State.SKIPPED_ARTIFACT_SHAPE,
    State.SKIPPED_SANDBOX,
    State.ERROR_TIMEOUT,
    State.ERROR_JSON_PARSE,
    State.ERROR_INVOCATION,
    State.ERROR_FIXTURE,  # highest precedence
)
_WITHIN_TEST_PRIORITY: dict[State, int] = {
    s: idx for idx, s in enumerate(_WITHIN_TEST_LADDER)
}

# Across-test states are not ranked against each other; they apply at distinct
# run-loop boundaries (CLI probe vs auth probe vs quota retry vs budget vs
# quarantine vs operator skip).
ACROSS_TEST_STATES: frozenset[State] = frozenset(
    {
        State.SKIPPED_CLI_MISSING,
        State.SKIPPED_CLI_AUTH,
        State.SKIPPED_QUOTA,
        State.SKIPPED_QUARANTINED,
        State.SKIPPED_USER_REQUEST,
        State.SKIPPED_BUDGET,
        State.ERROR_TOKEN_BUDGET,
    }
)


def classify_within_test(signals: dict[str, bool]) -> State:
    """Resolve a single test record's state from boolean signals.

    `signals` is a flat dict of predicate names → bool. The set of recognized
    keys mirrors the State enum values (lowercase). Unknown keys are ignored.

    The highest-priority True predicate wins per `_WITHIN_TEST_LADDER`. If
    no within-test predicate is True, returns `State.FAIL` as the default
    (caller should never invoke without at least one signal).

    Example:
        >>> classify_within_test({"pass": True, "pass_after_retry": True})
        <State.PASS_AFTER_RETRY: 'pass_after_retry'>
        >>> classify_within_test({"fail": True, "error_timeout": True})
        <State.ERROR_TIMEOUT: 'error_timeout'>
    """
    matched: list[State] = []
    for state in _WITHIN_TEST_LADDER:
        if signals.get(state.value):
            matched.append(state)
    if not matched:
        return State.FAIL
    return max(matched, key=lambda s: _WITHIN_TEST_PRIORITY[s])


def is_pass(state: State) -> bool:
    """Return True if state counts as a pass for aggregation.

    `pass_after_retry` counts as pass (with a flag). All others (including
    error_* and skipped_*) do NOT count toward pass-rate.
    """
    return state in (State.PASS, State.PASS_AFTER_RETRY)


def is_skip(state: State) -> bool:
    """Return True if state is a skip variant excluded from pass-rate."""
    return state.value.startswith("skipped_")
