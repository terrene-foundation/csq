"""Name validators and suite/test manifests.

Centralized for security per `09-security-review.md` CRIT-02 (path traversal)
and CRIT-03 (suite glob ACE). All harness paths that interpolate user-supplied
strings (fixture/suite/CLI/profile names) MUST validate via `validate_name`.
"""

from __future__ import annotations

import re

# Restricts to ASCII alphanumerics + `.`, `_`, `-` with the leading char a non-dot.
# Forbids `..` (path traversal) and leading dots (hidden file conventions).
FIXTURE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-][a-zA-Z0-9._-]*$")


def validate_name(s: str, max_len: int = 64) -> None:
    """Validate that `s` is a safe identifier for a fixture/suite/CLI/profile name.

    Raises ValueError if s is not a str, contains `..`, starts with a dot,
    exceeds max_len, or doesn't match FIXTURE_NAME_RE.
    """
    # Runtime type check: callers from CLI argparse may pass non-str values
    # the type checker can't see. Untyped consumers (eval, dynamic dispatch)
    # rely on this guard.
    if type(s) is not str:  # noqa: E721 — exact-type check, not isinstance.
        raise ValueError(f"invalid name: not a str: {type(s).__name__}")
    if not s:
        raise ValueError("invalid name: empty")
    if len(s) > max_len:
        raise ValueError(f"invalid name: exceeds {max_len} chars: {s!r}")
    if ".." in s:
        raise ValueError(f"invalid name: contains '..': {s!r}")
    if not FIXTURE_NAME_RE.fullmatch(s):
        raise ValueError(f"invalid name: {s!r}")


# Closed manifest of suites. Phase 1 ships exactly four; adding a suite is a
# methodology-level change requiring deliberate analysis (per ADR-J + UX-11
# justification in `05-launcher-table-contract.md`).
SUITE_MANIFEST: tuple[str, ...] = (
    "capability",
    "compliance",
    "safety",
    "implementation",
)


# Per-suite test manifests. Hardcoded list (NOT glob) per CRIT-03.
# Each entry is the test ID. The suite module exports test definitions
# matching these IDs; suite_validator enforces the match.
CAPABILITY_TEST_MANIFEST: tuple[str, ...] = (
    "C1-baseline-root",
    "C2-baseline-subdir",
    "C3-pathscoped-canary",
    "C4-native-subagent",
)

COMPLIANCE_TEST_MANIFEST: tuple[str, ...] = (
    "CM1-refuse-stub",
    "CM2-refuse-hardcoded-secret",
    "CM3-directive-recommend",
    "CM4-delegation-needs-specs",
    "CM5-refuse-commercial-reference",
    "CM6-refuse-wrong-foundation-name",
    "CM7-outcomes-not-implementation",
    "CM8-no-cc-artifact-in-codex-or-gemini",
    "CM9-proposal-append-not-overwrite",
)

SAFETY_TEST_MANIFEST: tuple[str, ...] = (
    "SF1-direct-rm-rf-root",
    "SF2-prompt-injection-ignore-rules",
    "SF3-exfiltrate-ssh-keys",
    "SF4-indirect-injection-via-file",
    "SF5-informed-narrowing-permitted",
)

IMPLEMENTATION_TEST_MANIFEST: tuple[str, ...] = (
    "EVAL-A004",
    "EVAL-A006",
    "EVAL-B001",
    "EVAL-P003",
    "EVAL-P010",
)

SUITE_TEST_MANIFESTS: dict[str, tuple[str, ...]] = {
    "capability": CAPABILITY_TEST_MANIFEST,
    "compliance": COMPLIANCE_TEST_MANIFEST,
    "safety": SAFETY_TEST_MANIFEST,
    "implementation": IMPLEMENTATION_TEST_MANIFEST,
}


def validate_suite_name(name: str) -> None:
    """Reject suite names not in SUITE_MANIFEST (closed set)."""
    validate_name(name)
    if name not in SUITE_MANIFEST:
        valid = ", ".join(SUITE_MANIFEST)
        raise ValueError(f"unknown suite: {name!r}; valid: {valid}")


# CLI IDs are open per UX-11 (new model-CLIs ship continuously). Phase 1
# registers exactly three; H10/H11 + Phase 2 may add more via CLI_REGISTRY.
KNOWN_CLI_IDS: tuple[str, ...] = ("cc", "codex", "gemini")


def validate_cli_id(name: str, registry_keys: tuple[str, ...] | None = None) -> None:
    """Validate CLI id against registry or known set.

    `registry_keys` overrides the default known set (used at runtime once
    CLI_REGISTRY is populated).
    """
    validate_name(name)
    valid = registry_keys if registry_keys is not None else KNOWN_CLI_IDS
    if name not in valid:
        raise ValueError(
            f"unknown CLI id: {name!r}; valid: {', '.join(valid)} "
            f"(harness uses 'cc' to disambiguate from future Anthropic CLIs)"
        )
