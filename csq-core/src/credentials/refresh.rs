//! OAuth token refresh — exchange a refresh token for new access/refresh tokens.

use super::CredentialFile;
use crate::error::{extract_oauth_error_type, redact_tokens, OAuthError};
use crate::oauth::constants::OAUTH_CLIENT_ID;
use crate::types::{AccessToken, RefreshToken};
use serde::Deserialize;
use std::fmt;

/// Anthropic OAuth token endpoint.
pub const TOKEN_ENDPOINT: &str = "https://platform.claude.com/v1/oauth/token";

/// Extracts a human-readable error from a token endpoint error response.
///
/// Two JSON shapes are handled:
///
/// - **Standard OAuth** (`{"error": "invalid_grant", "error_description": "..."}`):
///   For allowlisted RFC 6749 error types (see [`extract_oauth_error_type`]),
///   the category name is a `&'static str` from the allowlist — immune to
///   prompt injection. The `error_description` is included but passes through
///   `redact_tokens` because it is free-form and may contain echoed token
///   fragments (journal 0007, 0010).
///
/// - **API-style** (`{"error": {"type": "rate_limit_error", "message": "..."}}`)
///   The `type` and `message` strings are both redacted before inclusion.
fn extract_oauth_error(body: &[u8]) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    let json: serde_json::Value = serde_json::from_str(body_str).ok()?;
    let error_val = json.get("error")?;

    let detail = if let Some(obj) = error_val.as_object() {
        // API-style error object: {"error": {"type": "...", "message": "..."}}
        let err_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        match obj.get("message").and_then(|v| v.as_str()) {
            Some(msg) => format!("{err_type}: {msg}"),
            None => err_type.to_string(),
        }
    } else if let Some(err_str) = error_val.as_str() {
        // Standard OAuth error string: {"error": "invalid_grant", ...}
        //
        // Use extract_oauth_error_type to get a &'static str for allowlisted
        // categories. This means the category name in the returned detail is
        // always from the compile-time constant — an attacker who controls
        // the response body cannot inject arbitrary text through this path.
        let category: &str = extract_oauth_error_type(body_str).unwrap_or(err_str);
        match json.get("error_description").and_then(|v| v.as_str()) {
            Some(desc) => format!("{category}: {desc}"),
            None => category.to_string(),
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
    merged.expect_anthropic_mut().claude_ai_oauth.access_token =
        AccessToken::new(response.access_token.clone());
    merged.expect_anthropic_mut().claude_ai_oauth.refresh_token =
        RefreshToken::new(response.refresh_token.clone());
    merged.expect_anthropic_mut().claude_ai_oauth.expires_at =
        now_ms + (response.expires_in * 1000);
    // scopes, subscription_type, rate_limit_tier, extra: preserved from existing
    merged
}

/// Builds the JSON body for a token refresh request.
///
/// Format:
/// ```json
/// {
///   "grant_type": "refresh_token",
///   "refresh_token": "<token>",
///   "client_id": "<CLIENT_ID>"
/// }
/// ```
///
/// **No `scope` parameter.** Per RFC 6749 §6, scope is OPTIONAL on
/// refresh requests and, if omitted, the new token retains the
/// original scope set granted at authorize time. As of 2026-04-14,
/// Anthropic's `/v1/oauth/token` endpoint REJECTS any `scope` field
/// in the refresh body with `400 invalid_scope` — even when the
/// scopes match what was originally granted. Sending it caused a
/// silent mass broker-failure across every account; the daemon's
/// `is_rate_limited` heuristic does not match `invalid_scope`, so
/// failures fell through to recovery, hammered the endpoint, and
/// eventually got the IP rate-limited for real (journal 0052).
///
/// Anthropic's `/v1/oauth/token` endpoint also rejects form-encoded
/// bodies with `400 invalid_request_error` — it requires JSON. This
/// caused a silent mass broker-failure across every account when the
/// endpoint switched to JSON-only (journal 0034).
pub fn build_refresh_body(refresh_token: &str) -> String {
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
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
    let body = build_refresh_body(
        existing
            .expect_anthropic()
            .claude_ai_oauth
            .refresh_token
            .expose_secret(),
    );

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
    use crate::credentials::{AnthropicCredentialFile, OAuthPayload};
    use std::collections::HashMap;

    fn sample_creds() -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
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
        })
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
            merged
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-new-access"
        );
        assert_eq!(
            merged
                .expect_anthropic()
                .claude_ai_oauth
                .refresh_token
                .expose_secret(),
            "sk-ant-ort01-new-refresh"
        );
        assert!(merged.expect_anthropic().claude_ai_oauth.expires_at > 1000);
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
            merged
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
            Some("max")
        );
        assert_eq!(
            merged
                .expect_anthropic()
                .claude_ai_oauth
                .rate_limit_tier
                .as_deref(),
            Some("default_claude_max_20x")
        );
        assert_eq!(merged.expect_anthropic().claude_ai_oauth.scopes.len(), 2);
    }

    #[test]
    fn build_refresh_body_format() {
        let body = build_refresh_body("sk-ant-ort01-test");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["grant_type"], "refresh_token");
        assert_eq!(parsed["refresh_token"], "sk-ant-ort01-test");
        assert_eq!(parsed["client_id"], OAUTH_CLIENT_ID);
    }

    /// Regression test for journal 0052: Anthropic's
    /// `/v1/oauth/token` endpoint returns `400 invalid_scope` when
    /// the refresh body includes a `scope` field, even when the
    /// scopes match what was originally granted at authorize time.
    /// Per RFC 6749 §6, scope is OPTIONAL on refresh — the new token
    /// retains the original scopes when scope is omitted. Sending
    /// scope here previously broke every refresh in the daemon and
    /// every account silently expired until the user manually
    /// re-logged in.
    #[test]
    fn build_refresh_body_omits_scope_field() {
        let body = build_refresh_body("sk-ant-ort01-test");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            parsed.get("scope").is_none(),
            "refresh body must NOT contain `scope` — Anthropic returns \
             invalid_scope; see journal 0052. Got: {body}"
        );
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
            refreshed
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "sk-ant-oat01-refreshed"
        );
        // Metadata preserved
        assert_eq!(
            refreshed
                .expect_anthropic()
                .claude_ai_oauth
                .subscription_type
                .as_deref(),
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
