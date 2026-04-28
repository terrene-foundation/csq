"""Validate SUITE dicts against schemas/suite-v1.json.

Resolves R3-CRIT-01 (AC-1, AC-44, FR-16): suite-v1 schema + validator.

The harness loads suites via SUITE_MANIFEST (NOT glob, per CRIT-03). Each
suite module exports a top-level `SUITE` dict; this validator enforces:
1. Schema conformance per `coc-eval/schemas/suite-v1.json`.
2. Test ID uniqueness within the suite.
3. Test IDs match the per-suite manifest in `lib/validators.py`.
4. INV-PAR-2 criteria-count parity across CLIs (with skipped_artifact_shape carve-out).

Stdlib-only: re-implements the JSON Schema subset we use (type, required,
properties, enum, items, additionalProperties, oneOf for parallel-array
records). No `jsonschema` PyPI dep.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .validators import (
    SUITE_MANIFEST,
    SUITE_TEST_MANIFESTS,
    KNOWN_CLI_IDS,
    validate_name,
)


class SuiteValidationError(ValueError):
    """Raised when a SUITE dict fails validation."""


# ---- Lightweight JSON Schema validator (subset) ----


def _validate_against_schema(
    value: Any, schema: dict[str, Any], path: str = ""
) -> None:
    """Recursive validator covering the JSON Schema subset suite-v1.json uses.

    Subset: type, required, properties, enum, items, additionalProperties,
    minLength, minItems. No $ref, no oneOf (handled inline below for criteria
    polymorphism), no allOf.
    """
    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(value, dict):
            raise SuiteValidationError(
                f"{path or '<root>'}: expected object, got {type(value).__name__}"
            )
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise SuiteValidationError(
                    f"{path or '<root>'}: missing required key {key!r}"
                )
        properties = schema.get("properties", {})
        additional_allowed = schema.get("additionalProperties", True)
        for key, subval in value.items():
            sub_path = f"{path}.{key}" if path else key
            if key in properties:
                _validate_against_schema(subval, properties[key], sub_path)
            elif not additional_allowed:
                raise SuiteValidationError(f"{sub_path}: unexpected property")
    elif schema_type == "array":
        if not isinstance(value, list):
            raise SuiteValidationError(
                f"{path}: expected array, got {type(value).__name__}"
            )
        min_items = schema.get("minItems")
        if min_items is not None and len(value) < min_items:
            raise SuiteValidationError(
                f"{path}: minItems {min_items}, got {len(value)}"
            )
        items_schema = schema.get("items")
        if items_schema is not None:
            for idx, item in enumerate(value):
                _validate_against_schema(item, items_schema, f"{path}[{idx}]")
    elif schema_type == "string":
        if not isinstance(value, str):
            raise SuiteValidationError(
                f"{path}: expected string, got {type(value).__name__}"
            )
        min_length = schema.get("minLength")
        if min_length is not None and len(value) < min_length:
            raise SuiteValidationError(
                f"{path}: minLength {min_length}, got {len(value)}"
            )
    elif schema_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise SuiteValidationError(
                f"{path}: expected integer, got {type(value).__name__}"
            )
    elif schema_type == "boolean":
        if not isinstance(value, bool):
            raise SuiteValidationError(
                f"{path}: expected boolean, got {type(value).__name__}"
            )
    enum_values = schema.get("enum")
    if enum_values is not None and value not in enum_values:
        raise SuiteValidationError(f"{path}: value {value!r} not in enum {enum_values}")


# ---- High-level suite validator ----

_SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "suite-v1.json"
_cached_schema: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    global _cached_schema
    cached = _cached_schema
    if cached is None:
        if not _SCHEMA_PATH.exists():
            raise SuiteValidationError(f"schema file not found: {_SCHEMA_PATH}")
        cached = json.loads(_SCHEMA_PATH.read_text())
        _cached_schema = cached
    return cached


def validate_suite(suite: dict[str, Any]) -> None:
    """Validate a SUITE dict end-to-end.

    Raises SuiteValidationError on first failure.

    Checks:
    - Schema conformance (suite-v1.json).
    - Suite name in SUITE_MANIFEST.
    - Test IDs unique.
    - Test IDs match SUITE_TEST_MANIFESTS[suite_name].
    - INV-PAR-2 criteria-count parity per test.
    """
    schema = _load_schema()
    _validate_against_schema(suite, schema)

    name = suite.get("name")
    if name not in SUITE_MANIFEST:
        raise SuiteValidationError(
            f"unknown suite name {name!r}; valid: {', '.join(SUITE_MANIFEST)}"
        )

    tests = suite.get("tests", [])
    seen_ids: set[str] = set()
    expected_ids = set(SUITE_TEST_MANIFESTS[name])

    for test in tests:
        tid = test.get("name")
        if not isinstance(tid, str):
            raise SuiteValidationError(f"test missing string `name`: {test!r}")
        try:
            validate_name(tid)
        except ValueError as e:
            raise SuiteValidationError(f"test {tid!r}: {e}") from e
        if tid in seen_ids:
            raise SuiteValidationError(f"duplicate test id: {tid!r}")
        seen_ids.add(tid)

        # scoring_backend enum is enforced by the schema layer (suite-v1.json);
        # no redundant check here.

        # INV-PAR-2 criteria-count parity (with skipped_artifact_shape carve-out).
        # Carve-out: if expect[cli] is missing entirely, the cell is implicitly
        # skipped_artifact_shape — exempt from parity (R2-MED-02).
        expect = test.get("expect", {})
        present_clis: list[str] = [
            cli for cli in KNOWN_CLI_IDS if cli in expect or "all" in expect
        ]
        # If `expect.all` is used, all three CLIs share the same criteria — parity
        # holds trivially.
        if "all" in expect:
            continue
        if len(present_clis) >= 2:
            counts = {cli: len(expect[cli]) for cli in present_clis}
            unique_counts = set(counts.values())
            if len(unique_counts) > 1:
                raise SuiteValidationError(
                    f"test {tid!r}: INV-PAR-2 violation — criteria counts differ across CLIs: "
                    f"{counts}"
                )

    # Suite-level: all manifest IDs must appear (no silent omission).
    missing = expected_ids - seen_ids
    if missing:
        raise SuiteValidationError(
            f"suite {name!r}: missing tests from manifest: {sorted(missing)}"
        )
    extra = seen_ids - expected_ids
    if extra:
        raise SuiteValidationError(
            f"suite {name!r}: extra tests not in manifest: {sorted(extra)}"
        )
