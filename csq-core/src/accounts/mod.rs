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
    /// Authentication method.
    pub method: String,
    /// Whether the account has valid credentials.
    pub has_credentials: bool,
}

/// Where an account was discovered from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountSource {
    /// Anthropic OAuth account (credentials/N.json).
    Anthropic,
    /// Third-party provider (settings-*.json).
    ThirdParty { provider: String },
    /// Manually configured (dashboard-accounts.json).
    Manual,
}
