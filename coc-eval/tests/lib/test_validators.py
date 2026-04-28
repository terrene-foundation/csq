"""Tests for `coc-eval/lib/validators.py`."""

from __future__ import annotations

import pytest

from lib.validators import (
    FIXTURE_NAME_RE,
    KNOWN_CLI_IDS,
    SUITE_MANIFEST,
    SUITE_TEST_MANIFESTS,
    validate_cli_id,
    validate_name,
    validate_suite_name,
)


class TestValidateName:
    """Acceptance: AC-21 (profile-name path traversal blocked) + R3-CRIT-04 grep guard cousin."""

    def test_valid_simple(self):
        validate_name("good_name")
        validate_name("another-fixture_v2")
        validate_name("1abc")
        validate_name("a")

    def test_valid_with_dots_in_middle(self):
        # Allowed: dots after the leading char.
        validate_name("file.v2.name")

    def test_max_length(self):
        validate_name("a" * 64)
        with pytest.raises(ValueError, match="exceeds 64 chars"):
            validate_name("a" * 65)

    def test_custom_max_length(self):
        validate_name("a" * 32, max_len=32)
        with pytest.raises(ValueError, match="exceeds 16 chars"):
            validate_name("a" * 17, max_len=16)

    def test_reject_path_traversal(self):
        with pytest.raises(ValueError, match=r"contains '\.\.'"):
            validate_name("..")
        with pytest.raises(ValueError, match=r"contains '\.\.'"):
            validate_name("../etc/passwd")
        with pytest.raises(ValueError, match=r"contains '\.\.'"):
            validate_name("foo..bar")

    def test_reject_leading_dot(self):
        with pytest.raises(ValueError, match="invalid name"):
            validate_name(".hidden")

    def test_reject_path_separator(self):
        with pytest.raises(ValueError, match="invalid name"):
            validate_name("foo/bar")

    def test_reject_whitespace(self):
        with pytest.raises(ValueError, match="invalid name"):
            validate_name("foo bar")

    def test_reject_empty(self):
        with pytest.raises(ValueError, match="empty"):
            validate_name("")

    def test_reject_non_str(self):
        with pytest.raises(ValueError, match="not a str"):
            validate_name(123)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="not a str"):
            validate_name(None)  # type: ignore[arg-type]

    def test_reject_special_chars(self):
        for bad in ["foo;bar", "foo$(echo)", "foo\nbar", "foo\x00bar", "foo*bar"]:
            with pytest.raises(ValueError):
                validate_name(bad)


class TestSuiteManifest:
    def test_known_suites(self):
        assert SUITE_MANIFEST == (
            "capability",
            "compliance",
            "safety",
            "implementation",
        )
        assert len(SUITE_MANIFEST) == 4

    def test_validate_suite_name_accepts_known(self):
        for name in SUITE_MANIFEST:
            validate_suite_name(name)

    def test_validate_suite_name_rejects_unknown(self):
        with pytest.raises(ValueError, match="unknown suite"):
            validate_suite_name("smoke")

    def test_per_suite_test_manifests_complete(self):
        assert len(SUITE_TEST_MANIFESTS["capability"]) == 4
        assert len(SUITE_TEST_MANIFESTS["compliance"]) == 9
        assert len(SUITE_TEST_MANIFESTS["safety"]) == 5
        assert len(SUITE_TEST_MANIFESTS["implementation"]) == 5
        assert set(SUITE_TEST_MANIFESTS.keys()) == set(SUITE_MANIFEST)

    def test_test_ids_are_unique_within_suite(self):
        for suite, manifest in SUITE_TEST_MANIFESTS.items():
            assert len(manifest) == len(set(manifest)), f"duplicate test ID in {suite}"


class TestValidateCliId:
    def test_known_clis(self):
        for cli in KNOWN_CLI_IDS:
            validate_cli_id(cli)

    def test_unknown_cli_helpful_error(self):
        with pytest.raises(ValueError, match="unknown CLI id"):
            validate_cli_id("claude")  # binary name, not CLI id.

    def test_explicit_registry_keys(self):
        validate_cli_id("custom_cli", registry_keys=("custom_cli",))
        with pytest.raises(ValueError):
            validate_cli_id("cc", registry_keys=("custom_cli",))


class TestFixtureNameRe:
    """Direct regex tests for completeness."""

    def test_matches(self):
        assert FIXTURE_NAME_RE.fullmatch("baseline-cc")
        assert FIXTURE_NAME_RE.fullmatch("compliance")
        assert FIXTURE_NAME_RE.fullmatch("a1_b2.c3-d4")

    def test_no_match(self):
        assert not FIXTURE_NAME_RE.fullmatch(".hidden")
        assert not FIXTURE_NAME_RE.fullmatch("foo bar")
        assert not FIXTURE_NAME_RE.fullmatch("foo/bar")
