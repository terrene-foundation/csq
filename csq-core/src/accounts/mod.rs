//! Account identity, discovery, and profile management.
//!
//! Resolves which account a CC session is using, discovers all configured
//! accounts, and manages `profiles.json` for email/method mapping.

pub mod binding_guard;
pub mod discovery;
// M4-3 (an internal ticket Phase 4): `accounts::identity` retired. Its three
// fallback paths (marker → dir-name → `claude auth status`) violated
// `account-terminal-separation.md` MUST NOT Rule 1 (terminal-derived
// slot-id in credential writers) and MUST NOT Rule 3 (dir-name fallback
// for identity derivation). Callers now read the `.csq-account` marker
// directly — the SOLE authority per spec 02 INV-03.
pub mod identity_store;
pub mod legacy_mirror_cleanup;
pub mod login;
pub mod login_lock;
pub mod logout;
pub mod markers;
pub mod move_slot;
pub mod orphan_identity_gc;
pub mod profiles;
pub mod profiles_lock;
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
    /// May be a user-chosen rename label for Anthropic slots (RN1-D3).
    pub label: String,
    /// OAuth-authenticated email address from the authenticated credential file.
    ///
    /// RN1-D1 / Finding-3d C1+C2 fix: populated by reading
    /// `oauthAccount.emailAddress` from the identity credential file
    /// (`identities/<UUID>/credentials.json`) — the Anthropic-authenticated
    /// record. NEVER sourced from `by_email` reverse-lookup (which is
    /// circular: a polluted `by_email` would return the polluted email,
    /// cementing cross-contamination on re-ingest). Absent for 3P /
    /// pure-legacy slots with no credential file or no `oauthAccount` block.
    ///
    /// Identity-mint Pass-0 MUST use this field (not `label`) as the
    /// `by_email` key. When this field is `None`, Pass-0 skips the slot
    /// with a warn — identity is minted at login time via `mint_for_login`
    /// which carries an explicit OAuth-flow email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_email: Option<String>,
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
    /// Billing-mode classification (Phase A of an internal journal entry).
    ///
    /// Distinguishes subscription billing (Claude Pro/Max/Enterprise/
    /// Team, Codex ChatGPT plans, Gemini Code Assist) from API-key
    /// pay-per-token (Anthropic API, OpenAI API, Gemini AI Studio,
    /// Vertex SA, DeepSeek, MiniMax, Z.AI) from local model servers
    /// (Ollama).
    ///
    /// Drives downstream UI: subscription mode renders 5h/7d quota
    /// progress bars; ApiKey renders "API-key billing — pay per
    /// token"; Local renders "Local provider — no billing".
    ///
    /// Older serialized state without this field deserializes to
    /// `BillingMode::Subscription` per the `Default` derive — that
    /// matches pre-Phase-A csq behavior (every account treated as
    /// subscription).
    #[serde(default)]
    pub billing_mode: BillingMode,
}

/// Billing-mode classification.
///
/// See `internal-design-docs`
/// for the rationale and per-CLI investigation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum BillingMode {
    /// First-party subscription with rolling-window quota
    /// (Anthropic OAuth, ChatGPT subscription via Codex, Gemini Code
    /// Assist). Default for backward compatibility — pre-Phase-A
    /// state is treated as Subscription so existing UI continues to
    /// render quota bars unchanged.
    #[default]
    #[serde(rename = "subscription")]
    Subscription,
    /// Pay-per-token API key (Anthropic API, OpenAI API, Gemini AI
    /// Studio, Vertex SA, plus all 3P bearer providers). No
    /// rolling-window quota; UI renders "API-key billing".
    #[serde(rename = "api-key")]
    ApiKey,
    /// Local model server (Ollama). No billing surface; UI renders
    /// "Local provider — no billing".
    #[serde(rename = "local")]
    Local,
}

impl BillingMode {
    /// Stable string representation matching the `serde rename` tag.
    pub const fn as_str(&self) -> &'static str {
        match self {
            BillingMode::Subscription => "subscription",
            BillingMode::ApiKey => "api-key",
            BillingMode::Local => "local",
        }
    }
}

impl std::fmt::Display for BillingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cloud-Claude routing backend for a `Surface::ClaudeCode` slot (an internal ticket).
///
/// A routing dimension ORTHOGONAL to `Surface` and to the 3P provider axis: it
/// selects WHICH Anthropic-Claude backend the spawned `claude` CLI talks to.
///
/// - [`Backend::Direct`] (default): the ordinary path — Anthropic subscription
///   OAuth, an Anthropic API key, or a 3P base-URL override. No cloud routing.
/// - [`Backend::Vertex`]: Anthropic Claude served via **Google Vertex AI**. The
///   slot's `settings.json` env block carries `CLAUDE_CODE_USE_VERTEX=1` +
///   `ANTHROPIC_VERTEX_PROJECT_ID` + `CLOUD_ML_REGION` (+ GCP ADC creds via
///   `GOOGLE_APPLICATION_CREDENTIALS`); the spawned `claude` authenticates to
///   GCP itself.
/// - [`Backend::Bedrock`]: Anthropic Claude served via **AWS Bedrock**. The
///   slot's `settings.json` env block carries `CLAUDE_CODE_USE_BEDROCK=1` +
///   `AWS_REGION` (+ AWS creds); the spawned `claude` authenticates to AWS
///   itself.
///
/// **This is NOT the `vertex` PROVIDER** (Gemini-on-Vertex via the native
/// Google-`generateContent` client, `providers::catalog` id `"vertex"`). That
/// provider is a distinct entry on the same `ClaudeCode` surface and is never
/// overloaded by this axis (an internal ticket Constraint 2).
///
/// **Not stored on [`AccountInfo`].** The `settings.json` env block is the sole
/// source of truth for what the spawned `claude` will do, so csq DERIVES the
/// backend from it ([`crate::providers::settings::backend_for_slot`]) rather
/// than persisting a duplicate field that could drift from the env block. A
/// non-`Direct` backend is fail-closed-refused at provisioning time on any slot
/// that is not a bare `ClaudeCode` slot with the matching cloud creds (issue
/// an internal ticket Constraint 1).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum Backend {
    /// Ordinary Anthropic/3P path — no cloud routing. Default for backward
    /// compatibility and for every slot that has not been provisioned as a
    /// cloud-Claude slot.
    #[default]
    #[serde(rename = "direct")]
    Direct,
    /// Anthropic Claude via Google Vertex AI (`CLAUDE_CODE_USE_VERTEX`).
    #[serde(rename = "vertex")]
    Vertex,
    /// Anthropic Claude via AWS Bedrock (`CLAUDE_CODE_USE_BEDROCK`).
    #[serde(rename = "bedrock")]
    Bedrock,
}

impl Backend {
    /// Stable string representation matching the `serde rename` tag.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Backend::Direct => "direct",
            Backend::Vertex => "vertex",
            Backend::Bedrock => "bedrock",
        }
    }

    /// True for a cloud-routed backend (Vertex / Bedrock) — the axis that
    /// requires matching cloud credentials and fail-closed provisioning.
    pub const fn is_cloud(&self) -> bool {
        matches!(self, Backend::Vertex | Backend::Bedrock)
    }

    /// Parses a CLI-facing backend token (`direct` | `vertex` | `bedrock`),
    /// case-insensitively. Returns `None` for any other token so callers
    /// fail closed rather than silently defaulting.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(Backend::Direct),
            "vertex" => Some(Backend::Vertex),
            "bedrock" => Some(Backend::Bedrock),
            _ => None,
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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

    /// Phase A: AccountInfo deserializes legacy state (no
    /// `billing_mode` field) cleanly, defaulting to Subscription so
    /// existing UI continues to render quota bars unchanged.
    #[test]
    fn account_info_deserializes_without_billing_mode_field() {
        let legacy = r#"{
            "id": 1,
            "label": "alice@example.com",
            "source": "Anthropic",
            "surface": "claude-code",
            "method": "oauth",
            "has_credentials": true
        }"#;
        let info: AccountInfo =
            serde_json::from_str(legacy).expect("legacy JSON must parse without billing_mode");
        assert_eq!(info.billing_mode, BillingMode::Subscription);
    }

    /// an internal ticket: `Backend` serde tags, parse, defaults, and `is_cloud`.
    #[test]
    fn backend_serde_parse_and_helpers() {
        // serde rename tags
        assert_eq!(
            serde_json::to_string(&Backend::Direct).unwrap(),
            "\"direct\""
        );
        assert_eq!(
            serde_json::to_string(&Backend::Vertex).unwrap(),
            "\"vertex\""
        );
        assert_eq!(
            serde_json::to_string(&Backend::Bedrock).unwrap(),
            "\"bedrock\""
        );
        // round-trip
        for b in [Backend::Direct, Backend::Vertex, Backend::Bedrock] {
            let s = serde_json::to_string(&b).unwrap();
            assert_eq!(serde_json::from_str::<Backend>(&s).unwrap(), b);
            assert_eq!(Backend::parse(b.as_str()), Some(b));
        }
        // default + missing-field deserialize
        assert_eq!(Backend::default(), Backend::Direct);
        assert_eq!(
            serde_json::from_str::<Backend>("\"direct\"").unwrap(),
            Backend::Direct
        );
        // parse is case-insensitive + trims; unknown fails closed
        assert_eq!(Backend::parse("  VERTEX "), Some(Backend::Vertex));
        assert_eq!(Backend::parse("azure"), None);
        assert_eq!(Backend::parse(""), None);
        // is_cloud
        assert!(!Backend::Direct.is_cloud());
        assert!(Backend::Vertex.is_cloud());
        assert!(Backend::Bedrock.is_cloud());
    }

    /// BillingMode serializes via its kebab-case tag.
    #[test]
    fn billing_mode_serializes_as_kebab_tag() {
        assert_eq!(
            serde_json::to_string(&BillingMode::Subscription).unwrap(),
            "\"subscription\""
        );
        assert_eq!(
            serde_json::to_string(&BillingMode::ApiKey).unwrap(),
            "\"api-key\""
        );
        assert_eq!(
            serde_json::to_string(&BillingMode::Local).unwrap(),
            "\"local\""
        );
    }

    /// `BillingMode::as_str` matches the serde wire name on every variant.
    #[test]
    fn billing_mode_as_str_matches_serde_wire_name() {
        for variant in [
            BillingMode::Subscription,
            BillingMode::ApiKey,
            BillingMode::Local,
        ] {
            let serde_form = serde_json::to_string(&variant).unwrap();
            let trimmed = serde_form.trim_matches('"');
            assert_eq!(
                trimmed,
                variant.as_str(),
                "wire name must match for {variant:?}"
            );
        }
    }

    /// AccountInfo serialises the `surface` field using the `claude-code`
    /// wire name (not `ClaudeCode`) — consumers of the account list in
    /// Tauri IPC and daemon snapshots see the spec-defined tag value.
    #[test]
    fn account_info_serializes_surface_as_kebab_tag() {
        let info = AccountInfo {
            id: 7,
            label: "bob@example.com".into(),
            oauth_email: None,
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            has_credentials: true,
            billing_mode: BillingMode::Subscription,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            json.contains(r#""surface":"claude-code""#),
            "expected kebab-case surface tag in JSON: {json}"
        );
    }

    // ── AccountSource::Native (Wave 3, an internal journal entry) ──────────────

    /// `Native` is never oauth-refreshed — the vendor CLI (Kimi/Grok)
    /// owns its own auth lifecycle entirely outside csq's daemon.
    #[test]
    fn account_source_native_is_not_oauth_refreshed() {
        assert!(!AccountSource::Native {
            surface: Surface::Kimi
        }
        .has_oauth_refresh());
        assert!(!AccountSource::Native {
            surface: Surface::Grok
        }
        .has_oauth_refresh());
        // Sanity: the two sources that ARE oauth-refreshed still are.
        assert!(AccountSource::Anthropic.has_oauth_refresh());
        assert!(AccountSource::Codex.has_oauth_refresh());
    }

    /// `is_native()` is true only for `AccountSource::Native`, false for
    /// every other variant.
    #[test]
    fn account_source_is_native_true_only_for_native() {
        assert!(AccountSource::Native {
            surface: Surface::Kimi
        }
        .is_native());
        assert!(AccountSource::Native {
            surface: Surface::Grok
        }
        .is_native());
        assert!(!AccountSource::Anthropic.is_native());
        assert!(!AccountSource::Codex.is_native());
        assert!(!AccountSource::Gemini.is_native());
        assert!(!AccountSource::Manual.is_native());
        assert!(!AccountSource::ThirdParty {
            provider: "MiniMax".into()
        }
        .is_native());
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
    /// Google Gemini binding (`credentials/gemini-N.json`).
    ///
    /// Covers API-key, Vertex SA, and Code Assist OAuth modes — the
    /// binding marker carries the auth-mode tag. Round-7 (this
    /// session): added so Gemini-bound slots appear in the unified
    /// slot list. csq's daemon refresher does NOT own Gemini token
    /// rotation (gemini-cli + google-auth-library handle it), so
    /// `has_oauth_refresh()` returns false for this variant.
    Gemini,
    /// Third-party provider (`settings-*.json`).
    ThirdParty { provider: String },
    /// Manually configured (`dashboard-accounts.json`).
    Manual,
    /// Native-CLI session surface (Kimi, Grok) — Wave 3 (an internal journal entry).
    ///
    /// A native slot is keyed by the credential-less binding marker at
    /// `credentials/{kimi,grok}-<N>.json`
    /// ([`crate::providers::native::marker_path`]). csq stores NO secret
    /// for these slots — the vendor CLI (`kimi` / `grok`) self-
    /// authenticates against its own home directory. `has_credentials`
    /// on the [`AccountInfo`] this source attaches to reflects marker
    /// existence, not credential validity (there is no credential to
    /// validate).
    Native { surface: Surface },
}

impl AccountSource {
    /// Whether the source implies the daemon's OAuth refresher owns
    /// token-rotation cadence for this account. Used by the refresher
    /// to filter out non-refreshable accounts (3P API keys, manually
    /// configured rows, Gemini bindings, native-CLI bindings) — spec 07
    /// INV-P01.
    ///
    /// `Native` is never oauth-refreshed: the vendor CLI owns its own
    /// auth lifecycle (Kimi device-code, Grok OIDC) entirely outside
    /// csq's daemon.
    pub fn has_oauth_refresh(&self) -> bool {
        matches!(self, AccountSource::Anthropic | AccountSource::Codex)
    }

    /// True for the native-CLI session-surface source (Kimi/Grok). Used
    /// by callers that need to skip usage polling, token refresh, and
    /// quota-window rendering for a source that carries no credentials
    /// of csq's own and no OAuth lifecycle — the Wave 3 analogue of
    /// `has_oauth_refresh` for the "definitely not oauth, definitely
    /// not bearer-key" case.
    pub fn is_native(&self) -> bool {
        matches!(self, AccountSource::Native { .. })
    }
}
