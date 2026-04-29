"""Tests for `coc-eval/lib/suite_validator.py` — suite-v1.json + parity check.

R3-CRIT-01 fix: AC-1 (every suite validates against schemas/suite-v1.json),
AC-44 (`run.py <suite> --validate`), FR-16. R2-MED-02 carve-out:
`skipped_artifact_shape` cells exempt from INV-PAR-2 parity check.
"""

from __future__ import annotations

import pytest

from lib.suite_validator import SuiteValidationError, validate_suite


def _full_capability_suite():
    """Helper: minimal valid capability suite with all 4 manifest tests."""
    return {
        "name": "capability",
        "version": "1.0.0",
        "permission_profile": "plan",
        "fixture_strategy": "per-cli-isolated",
        "tests": [
            {
                "name": "C1-baseline-root",
                "fixture": "baseline",
                "prompt": "list markers",
                "expect": {
                    "all": [{"label": "marker", "kind": "contains", "pattern": "X"}]
                },
                "scoring_backend": "regex",
            },
            {
                "name": "C2-baseline-subdir",
                "fixture": "baseline",
                "prompt": "list markers",
                "expect": {
                    "all": [{"label": "marker", "kind": "contains", "pattern": "X"}]
                },
                "scoring_backend": "regex",
            },
            {
                "name": "C3-pathscoped-canary",
                "fixture": "pathscoped",
                "prompt": "summarize",
                "expect": {
                    "all": [{"label": "canary", "kind": "contains", "pattern": "Y"}]
                },
                "scoring_backend": "regex",
            },
            {
                "name": "C4-native-subagent",
                "fixture": "subagent",
                "prompt": "invoke",
                "expect": {
                    "all": [{"label": "marker", "kind": "contains", "pattern": "Z"}]
                },
                "scoring_backend": "regex",
            },
        ],
    }


class TestValidateSuite:
    def test_valid_capability(self):
        validate_suite(_full_capability_suite())

    def test_unknown_suite_name(self):
        bad = _full_capability_suite()
        bad["name"] = "smoke"
        with pytest.raises(SuiteValidationError, match="enum"):
            validate_suite(bad)

    def test_missing_required_top_level(self):
        bad = _full_capability_suite()
        del bad["version"]
        with pytest.raises(SuiteValidationError, match="missing required"):
            validate_suite(bad)

    def test_invalid_permission_profile(self):
        bad = _full_capability_suite()
        bad["permission_profile"] = "yolo"
        with pytest.raises(SuiteValidationError, match="enum"):
            validate_suite(bad)

    def test_invalid_fixture_strategy(self):
        bad = _full_capability_suite()
        bad["fixture_strategy"] = "magic"
        with pytest.raises(SuiteValidationError, match="enum"):
            validate_suite(bad)

    def test_duplicate_test_id(self):
        bad = _full_capability_suite()
        # Replace second test with first's name.
        bad["tests"][1]["name"] = "C1-baseline-root"
        with pytest.raises(SuiteValidationError, match="duplicate test id"):
            validate_suite(bad)

    def test_missing_test_from_manifest(self):
        bad = _full_capability_suite()
        bad["tests"] = bad["tests"][:3]  # drop C4.
        with pytest.raises(SuiteValidationError, match="missing tests from manifest"):
            validate_suite(bad)

    def test_extra_test_not_in_manifest(self):
        bad = _full_capability_suite()
        bad["tests"].append(
            {
                "name": "C99-bonus-test",
                "fixture": "x",
                "prompt": "y",
                "expect": {"all": []},
            }
        )
        with pytest.raises(SuiteValidationError, match="extra tests not in manifest"):
            validate_suite(bad)

    def test_invalid_scoring_backend(self):
        bad = _full_capability_suite()
        bad["tests"][0]["scoring_backend"] = "judge_llm"
        # Caught by schema enum check.
        with pytest.raises(SuiteValidationError, match="not in enum"):
            validate_suite(bad)

    def test_inv_par_2_violation(self):
        bad = _full_capability_suite()
        # cc has 1 criterion, codex has 2 — INV-PAR-2 violation.
        bad["tests"][0]["expect"] = {
            "cc": [{"label": "a", "kind": "contains", "pattern": "x"}],
            "codex": [
                {"label": "a", "kind": "contains", "pattern": "x"},
                {"label": "b", "kind": "absent", "pattern": "y"},
            ],
        }
        with pytest.raises(SuiteValidationError, match="INV-PAR-2 violation"):
            validate_suite(bad)

    def test_inv_par_2_carve_out(self):
        """R2-MED-02: skipped_artifact_shape cells (missing expect[cli]) are exempt."""
        ok = _full_capability_suite()
        # Only cc has criteria; codex/gemini implicitly skipped_artifact_shape.
        ok["tests"][0]["expect"] = {
            "cc": [{"label": "a", "kind": "contains", "pattern": "x"}],
        }
        # Should NOT raise — cc-only is valid (parity carve-out).
        validate_suite(ok)

    def test_test_name_validation(self):
        bad = _full_capability_suite()
        bad["tests"][0]["name"] = "C1 baseline root"  # space — invalid.
        with pytest.raises(SuiteValidationError, match="invalid name"):
            validate_suite(bad)


class TestSchemaValidator:
    """Sanity tests of the JSON Schema subset validator.

    The validator was extracted to `lib.schema_validator` in H4; the
    public entry is `validate_against_schema` raising `SchemaValidationError`.
    These tests pin the post-extraction contract.
    """

    def test_minimal_object_passes(self):
        from lib.schema_validator import validate_against_schema

        schema = {
            "type": "object",
            "required": ["x"],
            "properties": {"x": {"type": "string"}},
        }
        validate_against_schema({"x": "hello"}, schema)

    def test_type_mismatch_fails(self):
        from lib.schema_validator import (
            SchemaValidationError,
            validate_against_schema,
        )

        schema = {"type": "string"}
        with pytest.raises(SchemaValidationError, match="expected"):
            validate_against_schema(42, schema, "field")

    def test_enum_violation_fails(self):
        from lib.schema_validator import (
            SchemaValidationError,
            validate_against_schema,
        )

        schema = {"type": "string", "enum": ["a", "b", "c"]}
        with pytest.raises(SchemaValidationError, match="not in enum"):
            validate_against_schema("d", schema, "field")

    def test_cyclic_ref_bounded(self):
        """H4 review M4 — a cyclic $ref MUST NOT recurse unbounded.

        The bundled v1.0.0 schema has no cycles; the validator is
        nonetheless reused as a library, so a maliciously planted
        schema must not exhaust Python's recursion limit.
        """
        from lib.schema_validator import (
            SchemaValidationError,
            validate_against_schema,
        )

        cyclic = {
            "$ref": "#/definitions/A",
            "definitions": {
                "A": {"$ref": "#/definitions/B"},
                "B": {"$ref": "#/definitions/A"},
            },
        }
        with pytest.raises(SchemaValidationError, match="recursion depth"):
            validate_against_schema({}, cyclic)
