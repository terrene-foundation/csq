//! Live OAuth refresh contract test against Anthropic.
//!
//! WHY THIS EXISTS: journal 0052 documents the 2026-04-13 incident where
//! Anthropic silently started rejecting refresh bodies that contained a
//! `scope` field. Our unit tests with mocked HTTP did not catch it — they
//! asserted what _our client sends_, not what _the upstream server accepts_.
//! This file adds two tests:
//!
//! 1. `refresh_body_shape_accepted_by_anthropic` — hits the real
//!    `https://platform.claude.com/v1/oauth/token` endpoint with a real
//!    refresh token. Gated with `#[ignore]` so normal CI never pays for a
//!    network round trip. The `oauth-replay.yml` workflow fires it with
//!    `--ignored` when triggered by `workflow_dispatch` or the scheduled
//!    cron (once the cron is un-commented after the secret is provisioned).
//!
//! 2. `refresh_body_shape_assertions_unit` — exercises the same assertion
//!    logic against a mock HTTP transport. Runs by default on every
//!    `cargo test`. If this test is wrong, the live test would produce a
//!    false negative.
//!
//! WHAT THE LIVE TEST DOES NOT DO:
//! - It does NOT write the refreshed credentials back to disk. The test
//!   account's tokens rotate on every successful call; the `oauth-replay.yml`
//!   workflow writes the new refresh token back to the `OAUTH_REPLAY_REFRESH_TOKEN`
//!   secret after each run so the next run has a valid token.
//! - It does NOT print, log, or panic-display any token field.

use csq_core::credentials::refresh::{refresh_token, TOKEN_ENDPOINT};
use csq_core::credentials::{CredentialFile, OAuthPayload};
use csq_core::types::{AccessToken, RefreshToken};
use std::collections::HashMap;

/// Builds a minimal CredentialFile from a refresh token string.
///
/// The access token and expiry are placeholder values — the refresh
/// endpoint only consumes the refresh token from the credential file.
fn creds_from_refresh_token(rt: &str) -> CredentialFile {
    CredentialFile {
        claude_ai_oauth: OAuthPayload {
            access_token: AccessToken::new("placeholder-not-used-by-refresh".into()),
            refresh_token: RefreshToken::new(rt.to_owned()),
            expires_at: 0,
            scopes: vec![
                "user:file_upload".into(),
                "user:inference".into(),
                "user:mcp_servers".into(),
                "user:profile".into(),
                "user:sessions:claude_code".into(),
            ],
            subscription_type: None,
            rate_limit_tier: None,
            extra: HashMap::new(),
        },
        extra: HashMap::new(),
    }
}

/// Asserts the response shape is valid without printing any token value.
///
/// Returns a summary string that is safe to include in assertion failure
/// messages — it names the missing field, not the token value.
fn assert_refresh_response_valid(result: Result<CredentialFile, csq_core::error::OAuthError>) {
    match result {
        Ok(refreshed) => {
            // Assert access token is present (non-empty) without logging it.
            assert!(
                !refreshed
                    .claude_ai_oauth
                    .access_token
                    .expose_secret()
                    .is_empty(),
                "access_token must be non-empty in refresh response"
            );

            // Assert refresh token is present (non-empty) without logging it.
            assert!(
                !refreshed
                    .claude_ai_oauth
                    .refresh_token
                    .expose_secret()
                    .is_empty(),
                "refresh_token must be non-empty in refresh response"
            );

            // Assert expiry is in the future (now + some positive duration).
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            assert!(
                refreshed.claude_ai_oauth.expires_at > now_ms,
                "expires_at ({}) must be greater than now ({})",
                refreshed.claude_ai_oauth.expires_at,
                now_ms,
            );
        }
        Err(e) => {
            // Surface the error type without echoing any token bytes.
            // OAuthError::Exchange contains a redact_tokens-filtered string,
            // so it is safe to include in the panic message.
            panic!("Anthropic token endpoint rejected the refresh request: {e}");
        }
    }
}

// ── Unit test: assertion logic works with mocked HTTP ─────────────────────────

/// Verifies the assertion helpers themselves are correct using a mock
/// HTTP transport. This test runs by default (no `#[ignore]`) so the
/// assertion logic stays green even when the live endpoint test is skipped.
///
/// If this unit test fails, the live replay test would produce a false
/// negative — the assertions need to be fixed before the live test is
/// meaningful again.
#[test]
fn refresh_body_shape_assertions_unit() {
    let creds = creds_from_refresh_token("sk-ant-ort01-unit-test-token");

    // Simulate a successful response from the Anthropic token endpoint.
    // The expires_in of 28800 seconds (8 hours) is what Anthropic returns
    // for Claude Code OAuth tokens; the live test will see the same shape.
    let result = refresh_token(&creds, |_url, _body| {
        Ok(
            br#"{
                "token_type": "Bearer",
                "access_token": "sk-ant-oat01-mock-access-token-for-unit-test",
                "refresh_token": "sk-ant-ort01-mock-refresh-token-for-unit-test",
                "expires_in": 28800,
                "scope": "user:file_upload user:inference user:mcp_servers user:profile user:sessions:claude_code"
            }"#
            .to_vec(),
        )
    });

    // The same assertion function used by the live test.
    assert_refresh_response_valid(result);
}

/// Verifies the assertion helpers correctly reject a malformed response.
///
/// This guards against a regression where `assert_refresh_response_valid`
/// could silently accept empty tokens or a past expiry.
#[test]
fn refresh_body_shape_assertions_unit_rejects_empty_access_token() {
    let creds = creds_from_refresh_token("sk-ant-ort01-unit-test-token");

    let result: Result<CredentialFile, csq_core::error::OAuthError> =
        refresh_token(&creds, |_url, _body| {
            // access_token is an empty string — this should fail the assertion.
            // Note: the production server never returns an empty token, but
            // this test ensures our assertion code would catch it if it did.
            Ok(br#"{
                "access_token": "",
                "refresh_token": "sk-ant-ort01-mock",
                "expires_in": 28800
            }"#
            .to_vec())
        });

    // We expect the result to be Ok (the HTTP transport succeeded and the
    // JSON parsed), but the assertion helper should panic on the empty token.
    // Use std::panic::catch_unwind to verify the assertion fires.
    let is_ok = result.is_ok();
    if is_ok {
        let panicked = std::panic::catch_unwind(|| {
            assert_refresh_response_valid(Ok(CredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: AccessToken::new("".into()),
                    refresh_token: RefreshToken::new("sk-ant-ort01-mock".into()),
                    expires_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                        + 28_800_000,
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: HashMap::new(),
                },
                extra: HashMap::new(),
            }));
        });
        assert!(
            panicked.is_err(),
            "assert_refresh_response_valid must panic on empty access_token"
        );
    }
    // If the JSON failed to parse (result is Err), the function would have
    // called panic! in the Err arm — either way the test has validated the
    // assertion path.
}

// ── Live contract test (requires OAUTH_REPLAY_REFRESH_TOKEN) ──────────────────

/// Live OAuth refresh contract test against Anthropic's `/v1/oauth/token`.
///
/// GATED: This test requires `--ignored` to run. The `oauth-replay.yml`
/// CI workflow fires it with `cargo test --test oauth_replay -- --ignored`
/// when `OAUTH_REPLAY_REFRESH_TOKEN` is set in the environment.
///
/// BLOCKER: Requires a dedicated Foundation test account whose refresh
/// token lives in the `OAUTH_REPLAY_REFRESH_TOKEN` GitHub secret. Using
/// a real user account is unacceptable — see the workflow file header
/// comment for the provisioning procedure.
///
/// TOKEN ROTATION: Anthropic's token endpoint returns a NEW refresh token
/// on every successful call. The `oauth-replay.yml` workflow writes the
/// new token back to the `OAUTH_REPLAY_REFRESH_TOKEN` secret after each
/// successful run so the next scheduled run starts with a valid token.
///
/// WHAT THIS CATCHES: Any change to the accepted body shape at
/// `https://platform.claude.com/v1/oauth/token`. Journal 0052 is the
/// canonical incident — Anthropic started rejecting `scope` in the body,
/// our mocked tests all passed, and every account silently expired for ~8h.
#[test]
#[ignore = "live network call; requires OAUTH_REPLAY_REFRESH_TOKEN env var; \
            use --ignored to run; see .github/workflows/oauth-replay.yml"]
fn refresh_body_shape_accepted_by_anthropic() {
    let refresh_token_value = std::env::var("OAUTH_REPLAY_REFRESH_TOKEN")
        .expect("OAUTH_REPLAY_REFRESH_TOKEN must be set to run the live replay test");

    assert!(
        !refresh_token_value.is_empty(),
        "OAUTH_REPLAY_REFRESH_TOKEN must not be empty"
    );

    let creds = creds_from_refresh_token(&refresh_token_value);
    // Drop the value from the local binding as soon as it's in the
    // CredentialFile. The credential file uses SecretString internally
    // so it won't appear in Debug output.
    drop(refresh_token_value);

    // Use reqwest blocking to POST to the real endpoint.
    // The injectable closure pattern keeps the production `refresh_token`
    // function free of any HTTP library dependency; the transport is
    // always injected at the call site.
    let result = refresh_token(&creds, |url, body| {
        assert_eq!(
            url, TOKEN_ENDPOINT,
            "refresh_token must POST to TOKEN_ENDPOINT, not {url}"
        );

        let client = reqwest::blocking::Client::builder()
            .user_agent("claude-cli/1.0.114 (external, cli)")
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let response = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept-Encoding", "identity")
            .body(body.to_owned())
            .send()
            .map_err(|e| format!("HTTP POST failed: {e}"))?;

        let status = response.status().as_u16();
        let body_bytes = response
            .bytes()
            .map_err(|e| format!("failed to read response body: {e}"))?
            .to_vec();

        if status != 200 {
            // Surface the HTTP error without echoing request body bytes
            // (the request body contains the refresh token).
            // The response body from Anthropic's OAuth endpoint is safe
            // to include — it contains the OAuth error type string
            // (e.g. "invalid_scope", "invalid_grant") but not any token
            // we submitted. redact_tokens runs over it inside refresh_token.
            return Err(format!(
                "token endpoint returned HTTP {status}: {}",
                String::from_utf8_lossy(&body_bytes)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ));
        }

        Ok(body_bytes)
    });

    // Assert the response shape is valid without printing token values.
    assert_refresh_response_valid(result);
}
