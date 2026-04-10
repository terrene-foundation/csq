//! OAuth token refresh — exchange a refresh token for new access/refresh tokens.

use super::CredentialFile;
use crate::error::OAuthError;
use crate::types::{AccessToken, RefreshToken};
use serde::Deserialize;

/// Anthropic OAuth token endpoint.
pub const TOKEN_ENDPOINT: &str = "https://platform.claude.com/v1/oauth/token";

/// Response from the Anthropic OAuth token endpoint.
#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// Token lifetime in seconds (typically 18000 = 5 hours).
    pub expires_in: u64,
    /// Sometimes returned; we ignore it in favor of the existing scopes.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Merges a refresh response into an existing credential file.
///
/// Updates access_token, refresh_token, and expires_at. Preserves
/// subscription_type, rate_limit_tier, scopes, and all extra fields
/// (the refresh endpoint does not return these).
pub fn merge_refresh(
    existing: &CredentialFile,
    response: &RefreshResponse,
) -> CredentialFile {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut merged = existing.clone();
    merged.claude_ai_oauth.access_token =
        AccessToken::new(response.access_token.clone());
    merged.claude_ai_oauth.refresh_token =
        RefreshToken::new(response.refresh_token.clone());
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
    let body = build_refresh_body(
        existing.claude_ai_oauth.refresh_token.expose_secret(),
    );

    let response_bytes = http_post(TOKEN_ENDPOINT, &body).map_err(|e| {
        OAuthError::Exchange(e)
    })?;

    let response: RefreshResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| OAuthError::Exchange(format!("invalid response JSON: {e}")))?;

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

        let result = refresh_token(&existing, |_url, _body| {
            Err("connection refused".into())
        });

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

        let result = refresh_token(&existing, |_url, _body| {
            Ok(b"not json".to_vec())
        });

        match result {
            Err(OAuthError::Exchange(msg)) => {
                assert!(msg.contains("invalid response JSON"));
            }
            other => panic!("expected Exchange error, got {other:?}"),
        }
    }
}
