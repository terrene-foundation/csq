//! Account identity, discovery, and profile management.
//!
//! Resolves which account a CC session is using, discovers all configured
//! accounts, and manages `profiles.json` for email/method mapping.

pub mod discovery;
pub mod identity;
pub mod login;
pub mod logout;
pub mod markers;
pub mod profiles;
pub mod snapshot;
pub mod third_party;

use crate::providers::catalog::Surface;
use serde::{Deserialize, Serialize};

/// Information about a discovered account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Account number (1..999 for Anthropic, synthetic for 3P).
    pub id: u16,
    /// Display label (email for Anthropic, provider name for 3P).
    pub label: String,
    /// Account source.
    pub source: AccountSource,
    /// Upstream surface (`Surface::ClaudeCode` / `Surface::Codex`).
    ///
    /// Added in PR-C1 to let the refresher, usage poller, auto-rotation,
    /// and swap paths dispatch correctly across surfaces. Older serialized
    /// state without this field deserializes to `Surface::ClaudeCode`
    /// per the `Default` derive on `Surface`.
    #[serde(default)]
    pub surface: Surface,
    /// Authentication method.
    pub method: String,
    /// Whether the account has valid credentials.
    pub has_credentials: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PR-C1: AccountInfo deserializes cleanly from JSON that predates
    /// the `surface` field. The missing field falls back to
    /// `Surface::ClaudeCode` via serde's default attribute.
    #[test]
    fn account_info_deserializes_without_surface_field() {
        let legacy = r#"{
            "id": 3,
            "label": "alice@example.com",
            "source": "Anthropic",
            "method": "oauth",
            "has_credentials": true
        }"#;
        let info: AccountInfo = serde_json::from_str(legacy).expect("legacy JSON must parse");
        assert_eq!(info.id, 3);
        assert_eq!(info.surface, Surface::ClaudeCode);
    }

    /// AccountInfo serialises the `surface` field using the `claude-code`
    /// wire name (not `ClaudeCode`) — consumers of the account list in
    /// Tauri IPC and daemon snapshots see the spec-defined tag value.
    #[test]
    fn account_info_serializes_surface_as_kebab_tag() {
        let info = AccountInfo {
            id: 7,
            label: "bob@example.com".into(),
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            has_credentials: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            json.contains(r#""surface":"claude-code""#),
            "expected kebab-case surface tag in JSON: {json}"
        );
    }
}

/// Where an account was discovered from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountSource {
    /// Anthropic OAuth account (`credentials/N.json`).
    Anthropic,
    /// OpenAI Codex OAuth account (`credentials/codex-N.json`). Added
    /// in PR-C3a for the v2.1 Codex surface.
    Codex,
    /// Third-party provider (`settings-*.json`).
    ThirdParty { provider: String },
    /// Manually configured (`dashboard-accounts.json`).
    Manual,
}

impl AccountSource {
    /// Whether the source implies the daemon's OAuth refresher owns
    /// token-rotation cadence for this account. Used by the refresher
    /// to filter out non-refreshable accounts (3P API keys, manually
    /// configured rows) — spec 07 INV-P01.
    pub fn has_oauth_refresh(&self) -> bool {
        matches!(self, AccountSource::Anthropic | AccountSource::Codex)
    }
}
