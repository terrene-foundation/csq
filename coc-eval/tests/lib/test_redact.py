"""Tests for `coc-eval/lib/redact.py` — port of `csq-core/src/error.rs:161`.

Mirrors the Rust test fixtures at `csq-core/src/error.rs:686-1013` byte-for-byte
where applicable. Mandatory parity tests:
- AC-20 redaction canary: `sk-ant-oat01-AAAA...` → `[REDACTED]`.
- AC-20a word-boundary parity: `module_sk-...` returns input unchanged
  (matches Rust `is_key_char` predicate, NOT naive Python `\\b`).
"""

from __future__ import annotations

from lib.redact import (
    HEX_MIN_LEN,
    JWT_SEGMENT_MIN_BODY,
    KNOWN_TOKEN_PREFIXES,
    REDACTED,
    TOKEN_PREFIXES_WITH_BODY,
    _is_hex_char,
    _is_key_char,
    redact_pem_blocks,
    redact_tokens,
)


class TestKnownTokenPrefixes:
    """Pattern 1: KNOWN_TOKEN_PREFIXES — always redact body regardless of length."""

    def test_anthropic_oat_short_body_redacts(self):
        # Even with short body, known prefix → redact (per Rust comment line 87-91).
        assert redact_tokens("sk-ant-oat01-LEAKED") == "[REDACTED]"

    def test_anthropic_ort_redacts(self):
        assert redact_tokens("sk-ant-ort01-FOO123") == "[REDACTED]"

    def test_known_prefix_in_context(self):
        out = redact_tokens("foo sk-ant-oat01-XYZ_ABC bar")
        assert out == "foo [REDACTED] bar"
        assert "sk-ant-oat01-" not in out

    def test_known_prefixes_constant(self):
        assert KNOWN_TOKEN_PREFIXES == ("sk-ant-oat01-", "sk-ant-ort01-")


class TestPrefixWithBody:
    """Pattern 2: TOKEN_PREFIXES_WITH_BODY — prefix + min body length."""

    def test_sk_with_long_body(self):
        token = "sk-" + "a" * 20
        assert redact_tokens(token) == "[REDACTED]"

    def test_sk_with_short_body_preserved(self):
        # `sk-short` has 5 body chars; below 20 threshold.
        out = redact_tokens("sk-short")
        assert out == "sk-short"

    def test_sk_ant_api03_long(self):
        token = "sk-ant-api03-" + "a" * 95
        assert redact_tokens(f"key={token} done") == "key=[REDACTED] done"

    def test_rt_long_body(self):
        # rt_ prefix with 87 body chars (Codex refresh token).
        token = "rt_" + "a" * 87
        assert redact_tokens(token) == "[REDACTED]"

    def test_rt_short_preserved(self):
        # `rt_queue_size` is 13 chars total, body 10 — below 20 threshold.
        out = redact_tokens("rt_queue_size_thing")
        # Body is `queue_size_thing` = 16 chars, still < 20.
        assert out == "rt_queue_size_thing"

    def test_aiza_long_redacts(self):
        # Google AI key: AIza + 35 body = 39 total.
        token = "AIza" + "a" * 35
        assert redact_tokens(token) == "[REDACTED]"

    def test_aiza_short_preserved(self):
        # AIza + 25 body = 29 total, below 30 threshold.
        out = redact_tokens("AIza" + "a" * 25)
        assert out == "AIza" + "a" * 25

    def test_token_prefixes_with_body_constant(self):
        assert TOKEN_PREFIXES_WITH_BODY == (
            ("sk-", 20),
            ("sess-", 20),
            ("rt_", 20),
            ("AIza", 30),
        )


class TestWordBoundaryParity:
    """R1-HIGH-01 / AC-20a: word-boundary semantics match Rust `is_key_char`.

    Naive Python `\\b` regex would match `module_sk-...` and redact incorrectly.
    Rust's `is_key_char` includes `_` and `-` as key chars, so the boundary
    BEFORE `sk-` does NOT trigger when preceded by `_`.
    """

    def test_underscore_boundary_no_match(self):
        # `module_sk-1234567890123456789012345` — preceded by `_`, NOT a boundary.
        s = "module_sk-1234567890123456789012345"
        assert redact_tokens(s) == s

    def test_hyphen_boundary_no_match(self):
        s = "prefix-sk-1234567890123456789012345"
        assert redact_tokens(s) == s

    def test_alphanumeric_boundary_no_match(self):
        s = "abcsk-1234567890123456789012345"
        assert redact_tokens(s) == s

    def test_space_boundary_match(self):
        # Space is NOT a key char; word boundary triggers.
        s = "abc sk-1234567890123456789012345"
        assert redact_tokens(s) == "abc [REDACTED]"

    def test_dot_boundary_match(self):
        # Dot is NOT a key char; word boundary triggers.
        s = "abc.sk-1234567890123456789012345"
        assert redact_tokens(s) == "abc.[REDACTED]"

    def test_string_start_boundary_match(self):
        s = "sk-1234567890123456789012345"
        assert redact_tokens(s) == "[REDACTED]"


class TestHexPattern:
    """Pattern 3: long bare hex string ≥32 chars."""

    def test_32_hex_redacts(self):
        token = "a" * 32  # 32 hex digits.
        assert redact_tokens(token) == "[REDACTED]"

    def test_31_hex_preserved(self):
        # Below threshold.
        token = "a" * 31
        assert redact_tokens(token) == token

    def test_long_hex_in_context(self):
        token = "deadbeef" * 4  # 32 chars.
        assert redact_tokens(f"hash={token} ok") == "hash=[REDACTED] ok"

    def test_git_sha_preserved(self):
        # 7-char short SHA.
        out = redact_tokens("commit 1a2b3c4 fixed bug")
        assert "1a2b3c4" in out

    def test_hex_min_len_constant(self):
        assert HEX_MIN_LEN == 32


class TestJwtPattern:
    """Pattern 4: JWT triple-segment `eyJ<b64url>+.eyJ<b64url>+.<b64url>+`."""

    def test_jwt_triple_segment_redacts(self):
        # Each segment ≥ JWT_SEGMENT_MIN_BODY = 17 chars.
        seg1_body = "a" * JWT_SEGMENT_MIN_BODY
        seg2_body = "b" * JWT_SEGMENT_MIN_BODY
        seg3 = "c" * (JWT_SEGMENT_MIN_BODY + 3)
        jwt = f"eyJ{seg1_body}.eyJ{seg2_body}.{seg3}"
        assert redact_tokens(jwt) == "[REDACTED]"

    def test_jwt_short_segment_preserved(self):
        # Segment 1 too short.
        jwt = "eyJabc.eyJ" + "x" * 20 + ".yyy" + "y" * 20
        out = redact_tokens(jwt)
        # Either fully preserved OR partially matched on later patterns;
        # the JWT pattern itself MUST NOT fire.
        assert "[REDACTED]" not in out or out != "[REDACTED]"

    def test_jwt_constant(self):
        assert JWT_SEGMENT_MIN_BODY == 17


class TestPemBlocks:
    """PEM block redaction (pre-pass)."""

    def test_pem_private_key_redacts(self):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAA...\n"
            "-----END PRIVATE KEY-----"
        )
        out = redact_tokens(pem)
        assert out == "[REDACTED]"
        assert "MIIEvQ" not in out

    def test_pem_in_context(self):
        s = (
            "config:\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "secret_data_here\n"
            "-----END RSA PRIVATE KEY-----\n"
            "more text"
        )
        out = redact_tokens(s)
        assert "secret_data_here" not in out
        assert "[REDACTED]" in out
        assert "more text" in out

    def test_pem_unterminated_redacts(self):
        s = "-----BEGIN PRIVATE KEY-----\nLEAKED_PARTIAL"
        out = redact_pem_blocks(s)
        assert out == "[REDACTED]"

    def test_no_pem_no_change(self):
        s = "regular text without any PEM markers"
        assert redact_pem_blocks(s) == s


class TestEdgeCases:
    def test_empty_string(self):
        assert redact_tokens("") == ""

    def test_no_tokens(self):
        s = "Plain text with no secrets at all."
        assert redact_tokens(s) == s

    def test_multiple_tokens(self):
        s = "first sk-ant-oat01-AAA second AIza" + "b" * 35
        out = redact_tokens(s)
        assert out.count("[REDACTED]") == 2

    def test_unicode_preserved(self):
        # Multi-byte characters before tokens.
        s = "日本語 sk-ant-oat01-XYZ done"
        out = redact_tokens(s)
        assert "日本語" in out
        assert "[REDACTED]" in out

    def test_redacted_constant(self):
        assert REDACTED == "[REDACTED]"


class TestHelperPredicates:
    def test_is_key_char(self):
        assert _is_key_char("a")
        assert _is_key_char("Z")
        assert _is_key_char("0")
        assert _is_key_char("-")
        assert _is_key_char("_")
        assert not _is_key_char(".")
        assert not _is_key_char(" ")
        assert not _is_key_char("/")
        assert not _is_key_char("日")

    def test_is_hex_char(self):
        for c in "0123456789abcdefABCDEF":
            assert _is_hex_char(c)
        for c in "ghijklGHIJKL- _.":
            assert not _is_hex_char(c)


class TestNegativeControlCanary:
    """AC-20: a result with `sk-ant-oat01-AAAA...` in stderr produces zero
    matches in the persisted JSONL (post-redaction)."""

    def test_credential_canary(self):
        stderr = (
            "auth failed: invalid_grant; got token "
            "sk-ant-oat01-CANARY_DO_NOT_USE_AAAAAAAAAAAAAAAAAAAA "
            "and refresh sk-ant-ort01-CANARY_BBB"
        )
        out = redact_tokens(stderr)
        assert "sk-ant-oat01-" not in out
        assert "sk-ant-ort01-" not in out
        assert "CANARY_DO_NOT_USE" not in out
        assert "CANARY_BBB" not in out
        assert out.count("[REDACTED]") == 2
