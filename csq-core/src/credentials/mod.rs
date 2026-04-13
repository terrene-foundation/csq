//! Credential management — load, save, refresh, keychain integration.
//!
//! Handles the `credentials/N.json` files that store OAuth tokens for
//! each Claude Code account. The file format is owned by Claude Code;
//! csq preserves every field, including unknown ones.

pub mod file;
pub mod keychain;
pub mod refresh;

pub use file::{load, save, save_canonical};
pub use keychain::service_name;

use crate::types::{AccessToken, RefreshToken};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Top-level credential file. CC owns this schema — we must preserve
/// every field, including ones we don't recognize.
///
/// Debug is customized to mask the `extra` HashMap — if CC ever adds a
/// new credential field, the forward-compat flatten would otherwise leak it.
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialFile {
    #[serde(rename = "claudeAiOauth")]
    pub claude_ai_oauth: OAuthPayload,

    /// Forward-compat: preserve unknown top-level keys.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl fmt::Debug for CredentialFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialFile")
            .field("claude_ai_oauth", &self.claude_ai_oauth)
            .field("extra", &format!("<{} unknown fields>", self.extra.len()))
            .finish()
    }
}

/// OAuth token payload within the credential file.
///
/// Debug is customized to mask the `extra` HashMap for the same reason
/// as CredentialFile. Token fields are already masked by their types.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthPayload {
    /// Bearer access token. Prefix: `sk-ant-oat01-`.
    #[serde(rename = "accessToken")]
    pub access_token: AccessToken,

    /// Single-use refresh token. Prefix: `sk-ant-ort01-`.
    #[serde(rename = "refreshToken")]
    pub refresh_token: RefreshToken,

    /// Expiry as Unix milliseconds (NOT seconds).
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,

    /// OAuth scopes granted. Preserved verbatim on refresh.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// Subscription tier. Values observed: "max", "pro", "free".
    /// Preserved verbatim on refresh — never set by csq.
    #[serde(rename = "subscriptionType", skip_serializing_if = "Option::is_none")]
    pub subscription_type: Option<String>,

    /// Rate-limit tier. Values observed: "default_claude_max_20x".
    /// Preserved verbatim on refresh — never set by csq.
    #[serde(rename = "rateLimitTier", skip_serializing_if = "Option::is_none")]
    pub rate_limit_tier: Option<String>,

    /// Forward-compat: preserve unknown fields from CC updates.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl fmt::Debug for OAuthPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthPayload")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("subscription_type", &self.subscription_type)
            .field("rate_limit_tier", &self.rate_limit_tier)
            .field("extra", &format!("<{} unknown fields>", self.extra.len()))
            .finish()
    }
}

impl OAuthPayload {
    /// Returns true if the access token has expired or will expire
    /// within the given buffer (in seconds).
    pub fn is_expired_within(&self, buffer_secs: u64) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.expires_at < now_ms + (buffer_secs * 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
            "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-test-access-token",
                "refreshToken": "sk-ant-ort01-test-refresh-token",
                "expiresAt": 1775726524877,
                "scopes": ["user:inference", "user:profile"],
                "subscriptionType": "max",
                "rateLimitTier": "default_claude_max_20x"
            }
        }"#
    }

    #[test]
    fn deserialize_credential_file() {
        let cf: CredentialFile = serde_json::from_str(sample_json()).unwrap();
        assert_eq!(
            cf.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-test-access-token"
        );
        assert_eq!(cf.claude_ai_oauth.expires_at, 1775726524877);
        assert_eq!(cf.claude_ai_oauth.scopes.len(), 2);
        assert_eq!(cf.claude_ai_oauth.subscription_type.as_deref(), Some("max"));
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let json_with_unknown = r#"{
            "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-test",
                "refreshToken": "sk-ant-ort01-test",
                "expiresAt": 1000,
                "scopes": [],
                "subscriptionType": "max",
                "rateLimitTier": "tier",
                "newField": "should survive"
            },
            "topLevelExtra": true
        }"#;

        let cf: CredentialFile = serde_json::from_str(json_with_unknown).unwrap();
        let output = serde_json::to_string(&cf).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(reparsed["topLevelExtra"], true);
        assert_eq!(reparsed["claudeAiOauth"]["newField"], "should survive");
    }

    #[test]
    fn is_expired_within_detects_expired() {
        let payload = OAuthPayload {
            access_token: AccessToken::new("t".into()),
            refresh_token: RefreshToken::new("r".into()),
            expires_at: 0, // epoch = long expired
            scopes: vec![],
            subscription_type: None,
            rate_limit_tier: None,
            extra: HashMap::new(),
        };
        assert!(payload.is_expired_within(0));
        assert!(payload.is_expired_within(7200));
    }

    #[test]
    fn is_expired_within_detects_valid() {
        let far_future_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 86_400_000; // +24h

        let payload = OAuthPayload {
            access_token: AccessToken::new("t".into()),
            refresh_token: RefreshToken::new("r".into()),
            expires_at: far_future_ms,
            scopes: vec![],
            subscription_type: None,
            rate_limit_tier: None,
            extra: HashMap::new(),
        };
        assert!(!payload.is_expired_within(0));
        assert!(!payload.is_expired_within(7200));
    }
}
