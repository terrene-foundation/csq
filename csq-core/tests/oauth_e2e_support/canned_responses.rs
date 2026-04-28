//! Canned token-endpoint response bodies that match Anthropic's wire
//! shape exactly.
//!
//! Production callers invoke
//! [`csq_core::oauth::exchange_code`] with an `http_post` closure.
//! These fixtures are the response bytes that closure returns.
//!
//! # Why hard-coded literals
//!
//! Anthropic's `/v1/oauth/token` JSON shape is fixed by the OAuth 2.0
//! spec plus Anthropic's per-endpoint additions. The shapes captured
//! here mirror what production responses look like — minus the actual
//! token material, which we replace with deterministic test values.
//!
//! Fixture values are deliberately distinguishable so a leak test
//! (e.g. "the access_token must not appear in this error string") can
//! match on a literal substring.
//!
//! # No time-bomb literals
//!
//! Per `.claude/rules/testing.md` rule 1, every numeric timestamp
//! either uses a far-future literal or is computed from
//! `SystemTime::now()`. The token-endpoint response itself does NOT
//! carry an absolute timestamp — `expires_in` is a relative seconds
//! value (the credential's `expires_at` is computed by `exchange_code`
//! at call time). So the fixtures here use small `expires_in` values
//! freely.

/// Test access token. Distinguishable substring: `LOOPBACK_AT_FIXTURE`.
pub const TEST_ACCESS_TOKEN: &str = "sk-ant-oat01-LOOPBACK_AT_FIXTURE";

/// Test refresh token. Distinguishable substring: `LOOPBACK_RT_FIXTURE`.
pub const TEST_REFRESH_TOKEN: &str = "sk-ant-ort01-LOOPBACK_RT_FIXTURE";

/// Standard expires_in value (5 hours, matches Anthropic's observed
/// default).
pub const TEST_EXPIRES_IN_SECS: u64 = 18_000;

/// Canonical 200 response from Anthropic's `/v1/oauth/token` endpoint
/// when an authorization-code exchange succeeds.
pub fn ok_response() -> Vec<u8> {
    format!(
        r#"{{
            "access_token": "{TEST_ACCESS_TOKEN}",
            "refresh_token": "{TEST_REFRESH_TOKEN}",
            "expires_in": {TEST_EXPIRES_IN_SECS},
            "token_type": "Bearer"
        }}"#
    )
    .into_bytes()
}

/// Anthropic API-style 400 response for a code that has expired or
/// been used twice. Shape:
/// `{"error": {"type": "invalid_grant", "message": "..."}}`.
pub fn invalid_grant_response() -> Vec<u8> {
    br#"{
        "error": {
            "type": "invalid_grant",
            "message": "The authorization code has expired or has already been used"
        }
    }"#
    .to_vec()
}
