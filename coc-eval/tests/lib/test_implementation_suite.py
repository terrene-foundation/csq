"""Unit tests for `coc-eval/suites/implementation.py` (H7).

Validates the SUITE dict shape and the legacy TEST_DEF → SUITE-entry
adaptation. End-to-end run lives in `tests/integration/test_implementation_cc.py`.
"""

from __future__ import annotations

from suites.implementation import SUITE


def test_suite_top_level_shape():
    assert SUITE["name"] == "implementation"
    assert SUITE["version"] == "1.0.0"
    assert SUITE["permission_profile"] == "write"
    assert SUITE["fixture_strategy"] == "coc-env"


def test_suite_lists_five_eval_tests():
    names = [t["name"] for t in SUITE["tests"]]
    expected = ["EVAL-A004", "EVAL-A006", "EVAL-B001", "EVAL-P003", "EVAL-P010"]
    assert names == expected


def test_every_test_uses_tiered_artifact_backend():
    for t in SUITE["tests"]:
        assert t["scoring_backend"] == "tiered_artifact", t["name"]


def test_every_test_has_scoring_tiers():
    for t in SUITE["tests"]:
        assert "scoring" in t
        tiers = t["scoring"]["tiers"]
        assert isinstance(tiers, list)
        assert len(tiers) > 0
        # Every tier has a points budget.
        for tier in tiers:
            assert tier["points"] > 0, t["name"]


def test_every_test_has_scaffold_dir_name():
    for t in SUITE["tests"]:
        assert "scaffold" in t
        assert t["scaffold"].startswith("eval-"), t["name"]


def test_fixture_per_cli_uses_coc_env_with_phase1_sentinels():
    """cc routes to coc-env; codex/gemini use a sentinel (R1-A-LOW-2).

    The sentinel `_unwired_phase1` forces a future H10/H11 activation
    PR to deliberately wire codex/gemini sandbox + launcher rather
    than silently inheriting the cc fixture path.
    """
    for t in SUITE["tests"]:
        assert t["fixturePerCli"] == {
            "cc": "coc-env",
            "codex": "_unwired_phase1",
            "gemini": "_unwired_phase1",
        }


def test_max_turns_and_timeout_passed_through():
    for t in SUITE["tests"]:
        assert isinstance(t["max_turns"], int)
        assert t["max_turns"] > 0
        assert isinstance(t["timeout_sec"], int)
        assert t["timeout_sec"] > 0


def test_validates_against_schema():
    """The implementation SUITE must validate end-to-end via suite_validator.

    This catches a category of bugs where a legacy TEST_DEF field
    accidentally violates suite-v1.json (e.g. an unknown
    scoring_backend value, a non-string `name`).
    """
    from lib.suite_validator import validate_suite

    validate_suite(SUITE)


def test_test_ids_match_manifest():
    from lib.validators import IMPLEMENTATION_TEST_MANIFEST

    suite_ids = {t["name"] for t in SUITE["tests"]}
    manifest_ids = set(IMPLEMENTATION_TEST_MANIFEST)
    assert suite_ids == manifest_ids
