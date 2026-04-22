//! Credential management — load, save, refresh, keychain integration.
//!
//! Handles the on-disk credential files for every refreshable surface:
//! Anthropic's `claudeAiOauth` shape (Claude Code) and OpenAI's Codex
//! `tokens` shape (Codex CLI). The file formats are owned by the upstream
//! CLIs; csq preserves every field it sees, including ones it does not
//! recognise, so that future upstream additions round-trip cleanly.

pub mod file;
pub mod keychain;
pub mod mutex;
pub mod refresh;

pub use file::{load, save, save_canonical, save_canonical_for};
pub use keychain::service_name;
pub use mutex::AccountMutexTable;

use crate::providers::catalog::Surface;
use crate::types::{AccessToken, RefreshToken};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Top-level credential file — surface-dispatched union of the two
/// refreshable shapes csq supports.
///
/// Serde uses the untagged representation, which disambiguates by shape:
///
/// - Anthropic files carry a required `claudeAiOauth` key and parse as
///   [`CredentialFile::Anthropic`].
/// - Codex files carry a required `tokens` key and parse as
///   [`CredentialFile::Codex`].
///
/// Variant order matters: Anthropic is tried first. A hypothetical file
/// carrying both keys (never observed in practice) would parse as
/// Anthropic, which is the safer default for csq's existing
/// Anthropic-only code paths.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialFile {
    /// `claudeAiOauth`-shaped file, as written by `claude` CLI
    /// (including Anthropic OAuth + 3P provider shims that reuse the
    /// Claude Code format).
    Anthropic(AnthropicCredentialFile),
    /// `tokens`-shaped file, as written by `codex` CLI
    /// (`~/.codex/auth.json`).
    Codex(CodexCredentialFile),
}

impl fmt::Debug for CredentialFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialFile::Anthropic(inner) => f.debug_tuple("Anthropic").field(inner).finish(),
            CredentialFile::Codex(inner) => f.debug_tuple("Codex").field(inner).finish(),
        }
    }
}

impl CredentialFile {
    /// Returns the surface this credential file targets.
    pub fn surface(&self) -> Surface {
        match self {
            CredentialFile::Anthropic(_) => Surface::ClaudeCode,
            CredentialFile::Codex(_) => Surface::Codex,
        }
    }

    /// Returns the Anthropic inner if this is the Anthropic variant;
    /// `None` otherwise.
    pub fn anthropic(&self) -> Option<&AnthropicCredentialFile> {
        match self {
            CredentialFile::Anthropic(a) => Some(a),
            _ => None,
        }
    }

    /// Mutable borrow of the Anthropic inner, or `None` if this is not
    /// the Anthropic variant.
    pub fn anthropic_mut(&mut self) -> Option<&mut AnthropicCredentialFile> {
        match self {
            CredentialFile::Anthropic(a) => Some(a),
            _ => None,
        }
    }

    /// Returns the Codex inner if this is the Codex variant; `None`
    /// otherwise.
    pub fn codex(&self) -> Option<&CodexCredentialFile> {
        match self {
            CredentialFile::Codex(c) => Some(c),
            _ => None,
        }
    }

    /// Mutable borrow of the Codex inner, or `None` if this is not the
    /// Codex variant.
    pub fn codex_mut(&mut self) -> Option<&mut CodexCredentialFile> {
        match self {
            CredentialFile::Codex(c) => Some(c),
            _ => None,
        }
    }

    /// Borrows the Anthropic inner, panicking if the variant is not
    /// Anthropic. Use only at call sites that are structurally
    /// Anthropic-only today — e.g. code reachable only via
    /// Anthropic-discovery paths. New code paths that can see either
    /// variant MUST use [`Self::anthropic`] and handle `None` explicitly.
    pub fn expect_anthropic(&self) -> &AnthropicCredentialFile {
        match self {
            CredentialFile::Anthropic(a) => a,
            CredentialFile::Codex(_) => {
                panic!("expect_anthropic called on Codex variant — this call site is structurally Anthropic-only")
            }
        }
    }

    /// Mutable counterpart to [`Self::expect_anthropic`].
    pub fn expect_anthropic_mut(&mut self) -> &mut AnthropicCredentialFile {
        match self {
            CredentialFile::Anthropic(a) => a,
            CredentialFile::Codex(_) => {
                panic!("expect_anthropic_mut called on Codex variant — this call site is structurally Anthropic-only")
            }
        }
    }

    /// Convenience constructor for the Anthropic variant.
    pub fn new_anthropic(claude_ai_oauth: OAuthPayload) -> Self {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth,
            extra: HashMap::new(),
        })
    }
}

/// Anthropic-shape credential file: `claudeAiOauth` OAuth payload plus
/// forward-compat extras.
#[derive(Clone, Serialize, Deserialize)]
pub struct AnthropicCredentialFile {
    #[serde(rename = "claudeAiOauth")]
    pub claude_ai_oauth: OAuthPayload,

    /// Forward-compat: preserve unknown top-level keys.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl fmt::Debug for AnthropicCredentialFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicCredentialFile")
            .field("claude_ai_oauth", &self.claude_ai_oauth)
            .field("extra", &format!("<{} unknown fields>", self.extra.len()))
            .finish()
    }
}

/// OAuth token payload within the Anthropic credential file.
///
/// Debug masks the `extra` HashMap for the same reason as
/// [`AnthropicCredentialFile`]. Token fields are already masked by their
/// types.
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

/// Codex-shape credential file — matches the `~/.codex/auth.json`
/// on-disk layout written by `codex` CLI.
///
/// Observed shape (2026-04-22, codex-cli 0.122.x):
///
/// ```json
/// {
///   "auth_mode": "chatgpt",
///   "OPENAI_API_KEY": null,
///   "tokens": {
///     "account_id": "<uuid>",
///     "access_token": "<jwt>",
///     "refresh_token": "<rt>",
///     "id_token": "<jwt>"
///   },
///   "last_refresh": "2026-04-22T06:16:38.177830Z"
/// }
/// ```
///
/// All fields except `tokens` are optional at parse time — codex-cli
/// omits `last_refresh` on first login, and `OPENAI_API_KEY` is `null`
/// on ChatGPT-subscription accounts. Unknown top-level keys round-trip
/// via `extra` so a future codex-cli version that adds fields does not
/// trip csq's parser (spec 07 F12 mitigation).
#[derive(Clone, Serialize, Deserialize)]
pub struct CodexCredentialFile {
    /// Account mode tag. Observed values: `"chatgpt"` (OAuth-backed
    /// ChatGPT subscription). Absent on pure API-key configurations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,

    /// Raw OpenAI API key for non-OAuth configurations. `null` on
    /// ChatGPT-subscription accounts. Preserved verbatim; csq does not
    /// read or rotate this field.
    #[serde(
        rename = "OPENAI_API_KEY",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub openai_api_key: Option<String>,

    /// OAuth tokens — the refreshable payload.
    pub tokens: CodexTokensFile,

    /// ISO-8601 timestamp of the most recent refresh. Codex-cli writes
    /// this on every refresh; csq preserves but does not rewrite it
    /// (INV-P01 — daemon owns refresh cadence, not last_refresh state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh: Option<String>,

    /// Forward-compat: preserve unknown top-level keys.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl fmt::Debug for CodexCredentialFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodexCredentialFile")
            .field("auth_mode", &self.auth_mode)
            // Mask OPENAI_API_KEY presence but not value.
            .field("openai_api_key", &self.openai_api_key.as_ref().map(|_| "<set>"))
            .field("tokens", &self.tokens)
            .field("last_refresh", &self.last_refresh)
            .field("extra", &format!("<{} unknown fields>", self.extra.len()))
            .finish()
    }
}

/// OAuth token triple carried inside [`CodexCredentialFile::tokens`].
///
/// Separate from [`crate::http::codex::CodexTokens`] (which is
/// `Deserialize`-only and used as a transport type at the HTTP
/// boundary): this struct is the on-disk shape and round-trips via
/// both `Serialize` and `Deserialize`. A refresh flow unpacks the
/// transport type into this struct before persisting.
#[derive(Clone, Serialize, Deserialize)]
pub struct CodexTokensFile {
    /// OpenAI account identifier — present on OAuth-backed accounts.
    /// Less-sensitive than email but still user-identifying; csq does
    /// not emit this to logs or IPC payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,

    /// Bearer access token (JWT). Refreshed on each successful
    /// `/oauth/token` exchange.
    pub access_token: String,

    /// Single-use refresh token. Rotated on every successful refresh
    /// (OpenAI's `#10332` single-use semantics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// OpenID id_token (JWT). Carries account claims including email;
    /// csq does not decode or emit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,

    /// Forward-compat: preserve unknown per-token fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl fmt::Debug for CodexTokensFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // All three token fields are JWT or JWT-like and carry claims
        // with PII. Debug-format them as `<redacted>` regardless of
        // presence. `account_id` is masked symmetrically.
        f.debug_struct("CodexTokensFile")
            .field("account_id", &self.account_id.as_ref().map(|_| "<set>"))
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field("extra", &format!("<{} unknown fields>", self.extra.len()))
            .finish()
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

    fn codex_sample_json() -> &'static str {
        r#"{
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "account_id": "3bf322e8-561c-4349-910e-a79ee0a76fc1",
                "access_token": "eyJhbGciOiJIUzI1NiJ9.test-access.sig",
                "refresh_token": "rt_test_refresh_token",
                "id_token": "eyJhbGciOiJIUzI1NiJ9.test-id.sig"
            },
            "last_refresh": "2026-04-22T06:16:38.177830Z"
        }"#
    }

    #[test]
    fn deserialize_anthropic_credential_file() {
        let cf: CredentialFile = serde_json::from_str(sample_json()).unwrap();
        assert_eq!(cf.surface(), Surface::ClaudeCode);

        let a = cf.anthropic().expect("must parse as Anthropic variant");
        assert_eq!(
            a.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-test-access-token"
        );
        assert_eq!(a.claude_ai_oauth.expires_at, 1775726524877);
        assert_eq!(a.claude_ai_oauth.scopes.len(), 2);
        assert_eq!(a.claude_ai_oauth.subscription_type.as_deref(), Some("max"));

        // Codex accessor yields None.
        assert!(cf.codex().is_none());
    }

    #[test]
    fn deserialize_codex_credential_file() {
        let cf: CredentialFile = serde_json::from_str(codex_sample_json()).unwrap();
        assert_eq!(cf.surface(), Surface::Codex);

        let c = cf.codex().expect("must parse as Codex variant");
        assert_eq!(c.auth_mode.as_deref(), Some("chatgpt"));
        assert!(
            c.openai_api_key.is_none(),
            "null API key must parse as None"
        );
        assert_eq!(
            c.tokens.account_id.as_deref(),
            Some("3bf322e8-561c-4349-910e-a79ee0a76fc1")
        );
        assert!(c.tokens.access_token.starts_with("eyJhbGciOiJIUzI1NiJ9"));
        assert!(c.tokens.refresh_token.is_some());
        assert!(c.tokens.id_token.is_some());
        assert_eq!(
            c.last_refresh.as_deref(),
            Some("2026-04-22T06:16:38.177830Z")
        );

        // Anthropic accessor yields None.
        assert!(cf.anthropic().is_none());
    }

    #[test]
    fn round_trip_preserves_anthropic_unknown_fields() {
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
    fn round_trip_preserves_codex_unknown_fields() {
        let json_with_unknown = r#"{
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": "at",
                "refresh_token": "rt",
                "id_token": "it",
                "account_id": "uuid",
                "nestedExtra": 42
            },
            "last_refresh": "2026-04-22T00:00:00Z",
            "futureTopLevel": "preserved"
        }"#;

        let cf: CredentialFile = serde_json::from_str(json_with_unknown).unwrap();
        let output = serde_json::to_string(&cf).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(reparsed["futureTopLevel"], "preserved");
        assert_eq!(reparsed["tokens"]["nestedExtra"], 42);
    }

    #[test]
    fn untagged_disambiguation_prefers_anthropic_on_shape_collision() {
        // A file carrying BOTH claudeAiOauth and tokens is never observed
        // in practice, but the untagged variant order makes it parse as
        // Anthropic. Document this invariant so a future variant
        // reordering does not silently flip behaviour.
        let pathological = r#"{
            "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-a",
                "refreshToken": "sk-ant-ort01-r",
                "expiresAt": 1000,
                "scopes": []
            },
            "tokens": {
                "access_token": "unrelated"
            }
        }"#;
        let cf: CredentialFile = serde_json::from_str(pathological).unwrap();
        assert_eq!(cf.surface(), Surface::ClaudeCode);
    }

    #[test]
    fn expect_anthropic_on_anthropic_returns_inner() {
        let cf: CredentialFile = serde_json::from_str(sample_json()).unwrap();
        let a = cf.expect_anthropic();
        assert_eq!(a.claude_ai_oauth.expires_at, 1775726524877);
    }

    #[test]
    #[should_panic(expected = "expect_anthropic called on Codex variant")]
    fn expect_anthropic_on_codex_panics() {
        let cf: CredentialFile = serde_json::from_str(codex_sample_json()).unwrap();
        let _ = cf.expect_anthropic();
    }

    #[test]
    fn new_anthropic_constructor_produces_anthropic_variant() {
        let payload = OAuthPayload {
            access_token: AccessToken::new("sk-ant-oat01-x".into()),
            refresh_token: RefreshToken::new("sk-ant-ort01-y".into()),
            expires_at: 1000,
            scopes: vec![],
            subscription_type: None,
            rate_limit_tier: None,
            extra: HashMap::new(),
        };
        let cf = CredentialFile::new_anthropic(payload);
        assert_eq!(cf.surface(), Surface::ClaudeCode);
        assert!(cf.anthropic().is_some());
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
