"""Tests for `suites.compliance.SUITE` (H6, FR-15).

Schema validation + structural invariants. Live cc execution is covered
by `tests/integration/test_compliance_cc.py`.
"""

from __future__ import annotations

import re

import pytest

from lib.suite_validator import validate_suite
from lib.validators import COMPLIANCE_TEST_MANIFEST
from suites.compliance import SUITE


# ---------------------------------------------------------------------------
# Schema + manifest


def test_suite_passes_schema_validation() -> None:
    validate_suite(SUITE)


def test_suite_name_and_version() -> None:
    assert SUITE["name"] == "compliance"
    assert SUITE["version"] == "1.0.0"
    assert SUITE["permission_profile"] == "plan"
    assert SUITE["fixture_strategy"] == "per-cli-isolated"


def test_suite_test_ids_match_manifest() -> None:
    test_ids = [t["name"] for t in SUITE["tests"]]
    assert tuple(test_ids) == COMPLIANCE_TEST_MANIFEST


def test_suite_has_nine_tests() -> None:
    assert len(SUITE["tests"]) == 9


# ---------------------------------------------------------------------------
# Per-CLI parity (INV-PAR-2)


def test_every_test_has_three_cli_cells() -> None:
    """Every test populates `expect[cc/codex/gemini]` for INV-PAR-2 parity.
    H10/H11 activate codex/gemini execution; the SUITE shape MUST already
    encode the criteria so those PRs are mechanical wiring, not refactors.
    """
    for test in SUITE["tests"]:
        expect = test["expect"]
        assert set(expect.keys()) == {"cc", "codex", "gemini"}, (
            f"{test['name']}: expected cc/codex/gemini cells, "
            f"got {sorted(expect.keys())}"
        )


def test_every_cli_cell_is_a_list_of_criteria() -> None:
    for test in SUITE["tests"]:
        for cli, criteria in test["expect"].items():
            assert isinstance(criteria, list)
            assert (
                len(criteria) >= 1
            ), f"{test['name']} cli={cli}: criteria list must be non-empty"
            for c in criteria:
                assert isinstance(c, dict)
                assert c["kind"] in ("contains", "absent")
                assert isinstance(c["pattern"], str)
                assert isinstance(c["label"], str)


def test_criteria_count_parity() -> None:
    for test in SUITE["tests"]:
        counts = {cli: len(crit) for cli, crit in test["expect"].items()}
        assert (
            len(set(counts.values())) == 1
        ), f"{test['name']}: criteria count drift across CLIs: {counts}"


# ---------------------------------------------------------------------------
# Per-test scoring contract


def test_every_pattern_compiles_as_regex() -> None:
    for test in SUITE["tests"]:
        for cli, criteria in test["expect"].items():
            for c in criteria:
                try:
                    re.compile(c["pattern"])
                except re.error as e:
                    pytest.fail(
                        f"{test['name']} cli={cli}: invalid regex "
                        f"{c['pattern']!r}: {e}"
                    )


_RULE_ID_TO_TEST: dict[str, str] = {
    "CM1-refuse-stub": "COMP-ZT-STUB-4M8",
    "CM2-refuse-hardcoded-secret": "COMP-SEC-KEY-9R2",
    "CM4-delegation-needs-specs": "COMP-SPEC-CTX-2P5",
    "CM5-refuse-commercial-reference": "COMP-IND-COMM-5K8",
    "CM6-refuse-wrong-foundation-name": "COMP-TN-NAME-7L3",
    "CM8-no-cc-artifact-in-codex-or-gemini": "COMP-CCA-EXCL-8M1",
    "CM9-proposal-append-not-overwrite": "COMP-AF-APPEND-6W4",
}


def test_rule_id_citation_tests_reference_correct_rule() -> None:
    for test in SUITE["tests"]:
        if test["name"] not in _RULE_ID_TO_TEST:
            continue
        expected_rule = _RULE_ID_TO_TEST[test["name"]]
        first_pattern = test["expect"]["cc"][0]["pattern"]
        assert expected_rule in first_pattern, (
            f"{test['name']}: first criterion pattern does not reference "
            f"{expected_rule}: {first_pattern!r}"
        )


def test_token_tests_use_compliance_marker() -> None:
    """CM3 + CM7 score on a compliance token, not a RULE_ID."""
    cm3 = next(t for t in SUITE["tests"] if t["name"] == "CM3-directive-recommend")
    assert "REC-PICKED-ONE" in cm3["expect"]["cc"][0]["pattern"]
    cm7 = next(
        t for t in SUITE["tests"] if t["name"] == "CM7-outcomes-not-implementation"
    )
    assert "COMM-OUTCOME-FRAMED" in cm7["expect"]["cc"][0]["pattern"]


# ---------------------------------------------------------------------------
# post_assertions wiring


def test_cm1_has_file_absent_for_impl_py() -> None:
    cm1 = next(t for t in SUITE["tests"] if t["name"] == "CM1-refuse-stub")
    assertions = cm1.get("post_assertions") or []
    assert any(
        a.get("kind") == "file_absent" and a.get("path") == "impl.py"
        for a in assertions
    ), "CM1 must guard against impl.py being written despite refusal"


def test_cm2_has_file_absent_for_client_py() -> None:
    cm2 = next(t for t in SUITE["tests"] if t["name"] == "CM2-refuse-hardcoded-secret")
    assertions = cm2.get("post_assertions") or []
    assert any(
        a.get("kind") == "file_absent" and a.get("path") == "client.py"
        for a in assertions
    )


def test_cm9_has_file_absent_for_proposal() -> None:
    cm9 = next(
        t for t in SUITE["tests"] if t["name"] == "CM9-proposal-append-not-overwrite"
    )
    assertions = cm9.get("post_assertions") or []
    assert any(
        a.get("kind") == "file_absent"
        and a.get("path") == ".claude/.proposals/latest.yaml"
        for a in assertions
    )


# ---------------------------------------------------------------------------
# Fixture wiring


def test_every_test_uses_compliance_fixture_for_every_cli() -> None:
    for test in SUITE["tests"]:
        per_cli = test.get("fixturePerCli")
        assert per_cli is not None, f"{test['name']}: missing fixturePerCli"
        assert per_cli == {
            "cc": "compliance",
            "codex": "compliance",
            "gemini": "compliance",
        }


# ---------------------------------------------------------------------------
# Independence — fixture content audit (R2-MED-03)


def test_no_proprietary_product_names_in_suite_prompts() -> None:
    """Per `independence.md`, csq must not reference proprietary product
    names. CM5 + CM6 prompts were substituted to use Foobar Workflow
    Studio / Acme DataCorp. The fictional subagent identifier
    `schema-specialist` (CM4/CM8) replaces the loom-vintage
    `dataflow-specialist` so neither "kailash" nor "dataflow" leaks here.
    """
    for test in SUITE["tests"]:
        prompt = test.get("prompt", "").lower()
        assert "kailash" not in prompt, f"{test['name']}: prompt mentions Kailash"
        assert "dataflow" not in prompt, (
            f"{test['name']}: prompt mentions 'dataflow' — rename to a "
            f"non-commercial-coupled identifier"
        )
