"""Validate SUITE dicts against schemas/suite-v1.json.

Resolves R3-CRIT-01 (AC-1, AC-44, FR-16): suite-v1 schema + validator.

The harness loads suites via SUITE_MANIFEST (NOT glob, per CRIT-03). Each
suite module exports a top-level `SUITE` dict; this validator enforces:
1. Schema conformance per `coc-eval/schemas/suite-v1.json`.
2. Test ID uniqueness within the suite.
3. Test IDs match the per-suite manifest in `lib/validators.py`.
4. INV-PAR-2 criteria-count parity across CLIs (with skipped_artifact_shape carve-out).

Stdlib-only: shares the lightweight JSON Schema validator at
`schema_validator.py`. No `jsonschema` PyPI dep.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema_validator import (
    SchemaValidationError,
    validate_against_schema,
)
from .validators import (
    KNOWN_CLI_IDS,
    SUITE_MANIFEST,
    SUITE_TEST_MANIFESTS,
    validate_name,
)


class SuiteValidationError(ValueError):
    """Raised when a SUITE dict fails validation."""


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
    try:
        validate_against_schema(suite, schema)
    except SchemaValidationError as e:
        # Surface the same exception type callers expected pre-extraction.
        raise SuiteValidationError(str(e)) from e

    name = suite.get("name")
    if name not in SUITE_MANIFEST:
        raise SuiteValidationError(
            f"unknown suite name {name!r}; valid: {', '.join(SUITE_MANIFEST)}"
        )

    tests = suite.get("tests", [])
    seen_ids: set[str] = set()
    if not isinstance(name, str):
        raise SuiteValidationError(f"suite `name` must be a string, got {name!r}")
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

        # R1-A-MED-2: refuse SUITE entries that mix backend signals.
        # tiered_artifact MUST have non-empty `scoring.tiers` and
        # MUST NOT carry per-CLI `expect[cli]` lists. regex MUST have
        # non-empty `expect` and MUST NOT carry `scoring`. Mixing
        # signals is a configuration smell — without this check, a
        # future maintainer who adds `expect` to a tiered_artifact
        # entry sees no error but the data is silently ignored.
        backend = test.get("scoring_backend", "regex")
        if backend == "tiered_artifact":
            scoring_block = test.get("scoring")
            if (
                not isinstance(scoring_block, dict)
                or not isinstance(scoring_block.get("tiers"), list)
                or not scoring_block["tiers"]
            ):
                raise SuiteValidationError(
                    f"test {tid!r}: scoring_backend='tiered_artifact' "
                    f"requires non-empty `scoring.tiers` list"
                )
            expect_block = test.get("expect", {})
            if isinstance(expect_block, dict):
                clis_with_criteria = [
                    cli
                    for cli in KNOWN_CLI_IDS
                    if cli in expect_block
                    and isinstance(expect_block.get(cli), list)
                    and expect_block.get(cli)
                ]
                if clis_with_criteria:
                    raise SuiteValidationError(
                        f"test {tid!r}: scoring_backend='tiered_artifact' "
                        f"must not carry expect[cli] criteria; found: "
                        f"{clis_with_criteria}"
                    )
        elif backend == "regex":
            if "scoring" in test:
                raise SuiteValidationError(
                    f"test {tid!r}: scoring_backend='regex' must not "
                    f"carry a `scoring` block; that field belongs to "
                    f"tiered_artifact"
                )

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
