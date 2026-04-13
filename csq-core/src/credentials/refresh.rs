//! OAuth token refresh — exchange a refresh token for new access/refresh tokens.

use super::CredentialFile;
use crate::error::{redact_tokens, OAuthError};
use crate::oauth::constants::{scopes_joined, OAUTH_CLIENT_ID};
use crate::types::{AccessToken, RefreshToken};
use serde::Deserialize;
use std::fmt;

/// Anthropic OAuth token endpoint.
pub const TOKEN_ENDPOINT: &str = "https://platform.claude.com/v1/oauth/token";

/// Extracts a human-readable error from a token endpoint error
/// response. See [`crate::oauth::exchange::extract_oauth_error`]
/// for the full format documentation (handles both API-style and
/// standard OAuth error shapes).
fn extract_oauth_error(body: &[u8]) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error_val = json.get("error")?;

    let detail = if let Some(obj) = error_val.as_object() {
        let err_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        match obj.get("message").and_then(|v| v.as_str()) {
            Some(msg) => format!("{err_type}: {msg}"),
            None => err_type.to_string(),
        }
    } else if let Some(err_str) = error_val.as_str() {
        match json.get("error_description").and_then(|v| v.as_str()) {
            Some(desc) => format!("{err_str}: {desc}"),
            None => err_str.to_string(),
        }
    } else {
        return None;
    };

    Some(redact_tokens(&detail))
}

/// Response from the Anthropic OAuth token endpoint.
///
/// Custom Debug impl masks token values to prevent accidental logging.
#[derive(Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// Token lifetime in seconds (typically 18000 = 5 hours).
    pub expires_in: u64,
    /// Sometimes returned; we ignore it in favor of the existing scopes.
    #[serde(default)]
    pub scope: Option<String>,
}

impl fmt::Debug for RefreshResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshResponse")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Merges a refresh response into an existing credential file.
///
/// Updates access_token, refresh_token, and expires_at. Preserves
/// subscription_type, rate_limit_tier, scopes, and all extra fields
/// (the refresh endpoint does not return these).
pub fn merge_refresh(existing: &CredentialFile, response: &RefreshResponse) -> CredentialFile {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut merged = existing.clone();
    merged.claude_ai_oauth.access_token = AccessToken::new(response.access_token.clone());
    merged.claude_ai_oauth.refresh_token = RefreshToken::new(response.refresh_token.clone());
    merged.claude_ai_oauth.expires_at = now_ms + (response.expires_in * 1000);
    // scopes, subscription_type, rate_limit_tier, extra: preserved from existing
    merged
}

/// Builds the JSON body for a token refresh request.
///
/// Format matches Claude Code's `vw8` function in `cli.js`:
/// ```json
/// {
///   "grant_type": "refresh_token",
///   "refresh_token": "<token>",
///   "client_id": "<CLIENT_ID>",
///   "scope": "<space-joined scopes>"
/// }
/// ```
///
/// Anthropic's `/v1/oauth/token` endpoint rejects form-encoded bodies
/// with `400 invalid_request_error` — it requires JSON. This caused a
/// silent mass broker-failure across every account when the endpoint
/// switched to JSON-only (journal 0034).
pub fn build_refresh_body(refresh_token: &str) -> String {
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
        "scope": scopes_joined(),
    });
    serde_json::to_string(&body).expect("static JSON always serializes")
}

/// Performs a token refresh using the provided HTTP function.
///
/// The `http_post` parameter allows injection of the HTTP transport
/// for testing. In production, pass a function that uses `reqwest`
/// or another HTTP client.
///
/// # Arguments
/// * `existing` — Current credential file
/// * `http_post` — Function that POSTs body to the endpoint and returns
///   the response body as bytes, or an error string.
pub fn refresh_token<F>(
    existing: &CredentialFile,
    http_post: F,
) -> Result<CredentialFile, OAuthError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    let body = build_refresh_body(existing.claude_ai_oauth.refresh_token.expose_secret());

    // Single-shot. We do NOT retry inside this function even on 429.
    // Anthropic's `/v1/oauth/token` rate-limits per IP, and retrying
    // amplifies the very condition we'd be retrying through. The
    // daemon's 5-minute tick + 10-minute cooldown already provides
    // the right cadence to absorb transient throttling without a
    // local retry storm. See journal 0034.
    let response_bytes =
        http_post(TOKEN_ENDPOINT, &body).map_err(|e| OAuthError::Exchange(redact_tokens(&e)))?;

    // Surface a structured error response (e.g. `rate_limit_error`
    // or `invalid_grant`) as a typed OAuthError before attempting to
    // deserialize the success shape. This lets the broker tag the
    // failure correctly (rate-limit → long cooldown, skip sibling
    // recovery) without losing the actual reason.
    if let Some(detail) = extract_oauth_error(&response_bytes) {
        return Err(OAuthError::Exchange(detail));
    }

    // Try to deserialize as a success response.
    let response: RefreshResponse = match serde_json::from_slice(&response_bytes) {
        Ok(r) => r,
        Err(serde_err) => {
            let raw = format!("invalid response JSON: {serde_err}");
            return Err(OAuthError::Exchange(redact_tokens(&raw)));
        }
    };

    Ok(merge_refresh(existing, &response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::OAuthPayload;
    use std::collections::HashMap;

    fn sample_creds() -> CredentialFile {
        CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-old-access".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-old-refresh".into()),
                expires_at: 1000,
                scopes: vec!["user:inference".into(), "user:profile".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: Some("default_claude_max_20x".into()),
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        }
    }

    #[test]
    fn merge_refresh_updates_tokens() {
        let response = RefreshResponse {
            access_token: "sk-ant-oat01-new-access".into(),
            refresh_token: "sk-ant-ort01-new-refresh".into(),
            expires_in: 18000,
            scope: None,
        };

        let merged = merge_refresh(&sample_creds(), &response);

        assert_eq!(
            merged.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-new-access"
        );
        assert_eq!(
            merged.claude_ai_oauth.refresh_token.expose_secret(),
            "sk-ant-ort01-new-refresh"
        );
        assert!(merged.claude_ai_oauth.expires_at > 1000);
    }

    #[test]
    fn merge_refresh_preserves_metadata() {
        let response = RefreshResponse {
            access_token: "new".into(),
            refresh_token: "new".into(),
            expires_in: 18000,
            scope: None,
        };

        let merged = merge_refresh(&sample_creds(), &response);

        assert_eq!(
            merged.claude_ai_oauth.subscription_type.as_deref(),
            Some("max")
        );
        assert_eq!(
            merged.claude_ai_oauth.rate_limit_tier.as_deref(),
            Some("default_claude_max_20x")
        );
        assert_eq!(merged.claude_ai_oauth.scopes.len(), 2);
    }

    #[test]
    fn build_refresh_body_format() {
        let body = build_refresh_body("sk-ant-ort01-test");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["grant_type"], "refresh_token");
        assert_eq!(parsed["refresh_token"], "sk-ant-ort01-test");
        assert_eq!(parsed["client_id"], OAUTH_CLIENT_ID);
        assert!(parsed["scope"].as_str().unwrap().contains("user:inference"));
    }

    #[test]
    fn build_refresh_body_handles_special_chars() {
        // JSON serialization escapes quotes and backslashes; no
        // percent-encoding required because the body isn't form-urlencoded.
        let body = build_refresh_body("token\"with\\special");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["refresh_token"], "token\"with\\special");
    }

    #[test]
    fn refresh_token_with_mock_http() {
        let existing = sample_creds();

        let result = refresh_token(&existing, |_url, _body| {
            Ok(br#"{
                "access_token": "sk-ant-oat01-refreshed",
                "refresh_token": "sk-ant-ort01-refreshed",
                "expires_in": 18000
            }"#
            .to_vec())
        });

        let refreshed = result.unwrap();
        assert_eq!(
            refreshed.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-refreshed"
        );
        // Metadata preserved
        assert_eq!(
            refreshed.claude_ai_oauth.subscription_type.as_deref(),
            Some("max")
        );
    }

    #[test]
    fn refresh_token_http_failure() {
        let existing = sample_creds();

        let result = refresh_token(&existing, |_url, _body| Err("connection refused".into()));

        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(msg.contains("connection refused"));
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn refresh_token_invalid_json_response() {
        let existing = sample_creds();

        let result = refresh_token(&existing, |_url, _body| Ok(b"not json".to_vec()));

        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(msg.contains("invalid response JSON"));
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn refresh_token_surfaces_oauth_error_string_format() {
        let existing = sample_creds();
        let result = refresh_token(&existing, |_url, _body| {
            Ok(br#"{"error":"invalid_grant","error_description":"The refresh token has been revoked"}"#.to_vec())
        });
        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(msg.contains("invalid_grant"), "should surface: {msg}");
                assert!(
                    msg.contains("refresh token has been revoked"),
                    "should surface: {msg}"
                );
                assert!(
                    !msg.contains("missing field"),
                    "should NOT show serde error: {msg}"
                );
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn refresh_token_surfaces_api_style_error_object() {
        let existing = sample_creds();
        let result = refresh_token(&existing, |_url, _body| {
            Ok(
                br#"{"error":{"type":"invalid_grant","message":"Token has been revoked"}}"#
                    .to_vec(),
            )
        });
        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(msg.contains("invalid_grant"), "should surface: {msg}");
                assert!(
                    msg.contains("Token has been revoked"),
                    "should surface: {msg}"
                );
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    #[test]
    fn refresh_token_redacts_tokens_in_error_description() {
        let existing = sample_creds();
        let result = refresh_token(&existing, |_url, _body| {
            Ok(br#"{"error":"invalid_grant","error_description":"bad token sk-ant-ort01-LEAKED-SECRET"}"#.to_vec())
        });
        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(!msg.contains("LEAKED-SECRET"), "must be redacted: {msg}");
                assert!(msg.contains("invalid_grant"));
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    /// Regression test for M8.4 security review HIGH #1.
    ///
    /// If Anthropic returns a malformed body that echoes our
    /// submitted refresh token (observed in the wild as HTML error
    /// pages from upstream proxies or truncated JSON), serde_json's
    /// error Display may include a fragment of the input bytes.
    /// That would carry the token through `OAuthError::Exchange`
    /// into `BrokerError::RefreshFailed` and ultimately into
    /// `tracing::warn!` at the refresher level, leaking the token
    /// to logs.
    ///
    /// The fix is in `refresh_token`: format the serde error, then
    /// run it through `error::redact_tokens` before wrapping.
    #[test]
    fn refresh_token_parse_error_does_not_leak_token() {
        let existing = sample_creds();

        // Craft a body that is malformed JSON AND contains a
        // real-looking Anthropic refresh token prefix. serde_json
        // may include this substring in its error message.
        let leaky_body =
            br#"{"refresh_token":"sk-ant-ort01-LEAKED-SECRET-TOKEN","error":"invalid_grant"#;

        let result = refresh_token(&existing, |_url, _body| Ok(leaky_body.to_vec()));

        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(
                    !msg.contains("LEAKED-SECRET-TOKEN"),
                    "error message must not contain the token fragment: {msg}"
                );
                assert!(
                    !msg.contains("sk-ant-ort01-"),
                    "error message must not contain the ort01 prefix with raw bytes: {msg}"
                );
                // It should still contain a useful diagnostic.
                assert!(msg.contains("invalid response JSON"));
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }

    /// Regression test for H1's second leg: if the transport itself
    /// returns an error string containing a token (which reqwest
    /// doesn't do, but a test mock or future transport might), the
    /// refresh_token function must also scrub that before wrapping.
    #[test]
    fn refresh_token_transport_error_does_not_leak_token() {
        let existing = sample_creds();

        let result = refresh_token(&existing, |_url, _body| {
            Err("connection failed to sk-ant-ort01-LEAKED_IN_TRANSPORT_ERROR".into())
        });

        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(
                    !msg.contains("LEAKED_IN_TRANSPORT_ERROR"),
                    "transport error must not leak tokens: {msg}"
                );
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }
}
