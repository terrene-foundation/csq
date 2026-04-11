//! OAuth token refresh — exchange a refresh token for new access/refresh tokens.

use super::CredentialFile;
use crate::error::OAuthError;
use crate::types::{AccessToken, RefreshToken};
use serde::Deserialize;
use std::fmt;

/// Anthropic OAuth token endpoint.
pub const TOKEN_ENDPOINT: &str = "https://platform.claude.com/v1/oauth/token";

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

/// Builds the form-encoded body for a token refresh request.
///
/// Format matches v1.x exactly:
/// `grant_type=refresh_token&refresh_token={token}`
pub fn build_refresh_body(refresh_token: &str) -> String {
    format!(
        "grant_type=refresh_token&refresh_token={}",
        urlencoding::encode(refresh_token)
    )
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

    let response_bytes = http_post(TOKEN_ENDPOINT, &body)
        .map_err(|e| OAuthError::Exchange(crate::error::redact_tokens(&e)))?;

    // serde_json::Error's Display may include a fragment of the input
    // bytes when a parse fails partway through. If Anthropic returns
    // an HTML error page or a truncated `invalid_grant` body that
    // echoes our submitted `refresh_token`, that substring could
    // ride into the OAuthError and reach tracing / IPC cache / error
    // logs. Redact known token prefixes before the error escapes.
    let response: RefreshResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
        let raw = format!("invalid response JSON: {e}");
        OAuthError::Exchange(crate::error::redact_tokens(&raw))
    })?;

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
        assert_eq!(
            body,
            "grant_type=refresh_token&refresh_token=sk-ant-ort01-test"
        );
    }

    #[test]
    fn build_refresh_body_encodes_special_chars() {
        let body = build_refresh_body("token+with=special&chars");
        assert!(body.contains("token%2Bwith%3Dspecial%26chars"));
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
