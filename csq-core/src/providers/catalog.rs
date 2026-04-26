//! Provider catalog — skeletons for Claude, MiniMax, Z.AI, Ollama, Codex.
//!
//! **Surface** is the architectural dispatch axis introduced in PR-C1 per
//! spec 07 §7.1.1. It tags each provider with the upstream CLI binary
//! (Claude Code vs `codex` vs `gemini`) and controls per-surface
//! behaviour across the daemon, handle-dir, rotation, and refresher
//! paths. See journal 0067 H3 + workspaces/codex/journal/0001.

use serde::{Deserialize, Serialize};

/// Upstream CLI surface the provider speaks to.
///
/// Dispatch for refresh cadence, handle-dir symlink set, usage-poller
/// endpoint, rotation semantics, and quota schema all key off this.
///
/// Current values:
/// - `ClaudeCode` — `claude` CLI. Covers Anthropic (OAuth), MiniMax
///   (Bearer), Z.AI (Bearer), Ollama (keyless). Shares handle-dir model
///   (spec 02) + `CLAUDE_CONFIG_DIR` env contract.
/// - `Codex` — `codex` CLI (OpenAI ChatGPT subscription). OAuth
///   refresh via `auth.openai.com`; quota via `wham/usage`; handle-dir
///   uses `CODEX_HOME` (OPEN-C02 RESOLVED POSITIVE, journal 0005).
///
/// Reserved for future: `Gemini` (per workspaces/gemini plan §PR-G1).
///
/// THRESHOLD — when a 4th variant lands (Bedrock, Vertex AI, etc.),
/// revisit journal 0014 §FD #1: the `provider-integration` skill is
/// 335 lines covering the current 3 surfaces with quick-reference
/// tables fronting the prose. At N=4 surfaces (or when any single
/// surface section grows past ~150 lines on its own), reconsider
/// either splitting the skill at the surface boundary or extracting
/// the per-surface tables into sub-files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Surface {
    /// Claude Code CLI (`claude`). Default for backward compatibility
    /// with serialized state that predates PR-C1 — existing quota.json
    /// and account snapshots without a `surface` field deserialize to
    /// `ClaudeCode`.
    #[default]
    #[serde(rename = "claude-code")]
    ClaudeCode,
    /// OpenAI Codex CLI (`codex`). v2.1 Codex surface — see
    /// `workspaces/codex/02-plans/01-implementation-plan.md`.
    #[serde(rename = "codex")]
    Codex,
    /// Google Gemini CLI (`gemini`). v2.3 Gemini surface — API-key only
    /// (NO OAuth subscription rerouting per Google ToS); event-driven
    /// quota via CLI-durable NDJSON event log; encryption-at-rest via
    /// `platform::secret::Vault`. See
    /// `workspaces/gemini/02-plans/01-implementation-plan.md`.
    #[serde(rename = "gemini")]
    Gemini,
}

impl Surface {
    /// Stable string representation matching the `serde rename` tag.
    /// Use this everywhere a `&'static str` for the surface tag is
    /// needed (e.g. `platform::secret::SlotKey::surface`,
    /// `error::error_kind_tag`) — replaces the const placeholder
    /// `SURFACE_GEMINI` from PR-G2a.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Surface::ClaudeCode => "claude-code",
            Surface::Codex => "codex",
            Surface::Gemini => "gemini",
        }
    }
}

impl std::fmt::Display for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the surface stores the user's model selection.
///
/// Controls how `csq models switch` rewrites the effective model for
/// a provider. Determined by how the upstream CLI reads its model
/// config — Anthropic+3P store in `settings.json` environment
/// variables; Codex stores in `config.toml`; Gemini reads `model.name`
/// from `~/.gemini/settings.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelConfigTarget {
    /// Model written to `env.ANTHROPIC_MODEL` inside a settings.json
    /// file. Applies to Anthropic (OAuth CC), MiniMax, Z.AI, Ollama.
    EnvInSettingsJson,
    /// Model written to the `model = "..."` key at the root of
    /// `config.toml`. Applies to Codex.
    TomlModelKey,
    /// Model written to the `model.name` key in `settings.json` for
    /// the Gemini CLI. Distinct from `EnvInSettingsJson` because
    /// Gemini reads a top-level `model.name` field, not an env block.
    GeminiSettingsModelName,
}

/// Shape of the quota signal the surface exposes.
///
/// Per spec 07 §7.4 and spec 05 §5.7 / §5.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuotaKind {
    /// Percentage (0-100) plus reset timestamp per window. Two windows
    /// (5h + 7d) for Anthropic + Codex per §5.1 and §5.7.
    Utilization,
    /// Spawn-counter + 429 rate-limit parse (Gemini pattern). Event-
    /// driven; no polling endpoint. See spec 05 §5.8.
    Counter,
    /// Surface declines to expose quota (e.g. keyless Ollama) or the
    /// signal is currently unavailable (schema drift / circuit-breaker).
    Unknown,
}

/// A provider definition with defaults for new profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// Short identifier (e.g., "claude", "mm", "zai", "ollama", "codex").
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Upstream CLI surface (PR-C1). Default `ClaudeCode` for serialized
    /// state that predates the surface split.
    #[serde(default)]
    pub surface: Surface,
    /// Where the model selection lives (settings.json env vs config.toml key).
    #[serde(default = "default_model_config_target")]
    pub model_config: ModelConfigTarget,
    /// Quota signal shape.
    #[serde(default = "default_quota_kind")]
    pub quota_kind: QuotaKind,
    /// Auth type: "oauth" (Claude, Codex), "bearer" (MiniMax, Z.AI), "none" (Ollama).
    pub auth_type: AuthType,
    /// Environment variable for the API key (or None for keyless).
    pub key_env_var: Option<&'static str>,
    /// Environment variable for the base URL.
    pub base_url_env_var: Option<&'static str>,
    /// Default base URL for this provider.
    pub default_base_url: Option<&'static str>,
    /// Default model ID.
    pub default_model: &'static str,
    /// Key validation endpoint (for HTTP probe).
    pub validation_endpoint: Option<&'static str>,
    /// Filename for the settings file (relative to base dir).
    pub settings_filename: &'static str,
    /// System prompt primer (non-Claude only, to enable tool use).
    pub system_primer: Option<&'static str>,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Dummy `ANTHROPIC_AUTH_TOKEN` for keyless providers.
    ///
    /// CC's HTTP client requires an auth token header to be present on
    /// outgoing requests. Keyless providers (currently Ollama) accept
    /// any literal — we store a fixed placeholder so `csq setkey
    /// <keyless>` produces a settings file CC can use without error.
    /// `None` for providers that use a real API key.
    pub default_auth_token: Option<&'static str>,
}

const fn default_model_config_target() -> ModelConfigTarget {
    ModelConfigTarget::EnvInSettingsJson
}

const fn default_quota_kind() -> QuotaKind {
    QuotaKind::Utilization
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthType {
    OAuth,
    Bearer,
    None,
}

/// Catalog of known providers. Add new providers here.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "claude",
        name: "Claude",
        surface: Surface::ClaudeCode,
        model_config: ModelConfigTarget::EnvInSettingsJson,
        quota_kind: QuotaKind::Utilization,
        auth_type: AuthType::OAuth,
        key_env_var: Some("ANTHROPIC_API_KEY"),
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("https://api.anthropic.com"),
        default_model: "claude-opus-4-7",
        validation_endpoint: Some("https://api.anthropic.com/v1/messages"),
        settings_filename: "settings.json",
        system_primer: None,
        timeout_secs: 30,
        default_auth_token: None,
    },
    Provider {
        id: "mm",
        name: "MiniMax",
        surface: Surface::ClaudeCode,
        model_config: ModelConfigTarget::EnvInSettingsJson,
        quota_kind: QuotaKind::Utilization,
        auth_type: AuthType::Bearer,
        key_env_var: Some("ANTHROPIC_AUTH_TOKEN"),
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("https://api.minimax.io/anthropic"),
        default_model: "MiniMax-M2.7-highspeed",
        validation_endpoint: Some("https://api.minimax.io/anthropic/v1/messages"),
        settings_filename: "settings-mm.json",
        system_primer: Some(
            "You are a helpful coding assistant with access to tools for editing files and running commands.",
        ),
        timeout_secs: 60,
        default_auth_token: None,
    },
    Provider {
        id: "zai",
        name: "Z.AI",
        surface: Surface::ClaudeCode,
        model_config: ModelConfigTarget::EnvInSettingsJson,
        quota_kind: QuotaKind::Utilization,
        auth_type: AuthType::Bearer,
        key_env_var: Some("ANTHROPIC_AUTH_TOKEN"),
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("https://api.z.ai/api/anthropic"),
        default_model: "glm-5.1",
        validation_endpoint: Some("https://api.z.ai/api/anthropic/v1/messages"),
        settings_filename: "settings-zai.json",
        system_primer: Some(
            "You are a helpful coding assistant with access to tools for editing files and running commands.",
        ),
        timeout_secs: 60,
        default_auth_token: None,
    },
    Provider {
        id: "ollama",
        name: "Ollama",
        surface: Surface::ClaudeCode,
        model_config: ModelConfigTarget::EnvInSettingsJson,
        quota_kind: QuotaKind::Unknown,
        auth_type: AuthType::None,
        key_env_var: None,
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("http://localhost:11434"),
        default_model: "gemma4",
        validation_endpoint: None, // Validated via `ollama list`
        settings_filename: "settings-ollama.json",
        system_primer: Some(
            "You are a helpful coding assistant. Use tools when they would help answer the user.",
        ),
        timeout_secs: 120,
        default_auth_token: Some("ollama"),
    },
    // v2.1 Codex stub. Full orchestration lands in PR-C3 (login) + PR-C4
    // (refresher) + PR-C5 (wham/usage poller). The entry here exists so
    // `Surface::Codex` is reachable via `get_provider("codex")` for the
    // Surface-enum regression tests landed with PR-C1 and for PR-C2's
    // credential-file surface dispatch. `settings_filename` is Codex-
    // irrelevant — Codex writes to `config.toml`, not a settings.json —
    // but the field is required by the Provider struct shape; value is
    // unique to satisfy `settings_filenames_unique` test.
    Provider {
        id: "codex",
        name: "Codex",
        surface: Surface::Codex,
        model_config: ModelConfigTarget::TomlModelKey,
        quota_kind: QuotaKind::Utilization,
        auth_type: AuthType::OAuth,
        key_env_var: None,
        base_url_env_var: None,
        default_base_url: Some("https://chatgpt.com"),
        default_model: "gpt-5.4",
        validation_endpoint: None, // Validated via wham/usage post-refresh in PR-C5
        settings_filename: "codex-config.toml",
        system_primer: None,
        timeout_secs: 30,
        default_auth_token: None,
    },
    // v2.3 Gemini stub. Surface dispatch lands here in PR-G1; the
    // spawn pipeline lands in PR-G2b; the NDJSON event log + daemon
    // consumer in PR-G3; CLI surface dispatch in PR-G4; desktop UI
    // in PR-G5. The entry exists so `Surface::Gemini` is reachable
    // via `get_provider("gemini")` for the dispatch-contract tests.
    //
    // `auth_type` is `None` because the API key never flows through
    // an env var or a Provider field — `csq setkey gemini` writes
    // the key directly into the platform::secret Vault, and the
    // Vault is read at spawn time. The Provider catalog's `key_env_var`
    // contract (read from env at spawn) does not apply to Gemini.
    Provider {
        id: "gemini",
        name: "Gemini",
        surface: Surface::Gemini,
        model_config: ModelConfigTarget::GeminiSettingsModelName,
        quota_kind: QuotaKind::Counter,
        // Auth shape is "Vault-backed API key" — orthogonal to the
        // existing OAuth / Bearer / None taxonomy. Mark as None so
        // `providers_with_keys()` does NOT yield Gemini (the existing
        // env-var key flow does not apply); add a separate predicate
        // (`providers_using_vault`) for the new Vault-backed path.
        auth_type: AuthType::None,
        key_env_var: None,
        base_url_env_var: None,
        default_base_url: Some("https://generativelanguage.googleapis.com"),
        default_model: "gemini-2.5-pro",
        // Gemini ToS guard EP4 forbids relying on a documented
        // validation endpoint URL — silent-downgrade detection lives
        // in csq-cli stderr wrapping per spec 07 §7.2.3.
        validation_endpoint: None,
        // Gemini reads its config from `~/.gemini/settings.json`
        // (system path), not from a csq-managed file. The field is
        // required by the struct shape; value uniquely identifies the
        // Gemini entry to satisfy `settings_filenames_unique`.
        settings_filename: "gemini-settings.json",
        system_primer: None,
        timeout_secs: 30,
        default_auth_token: None,
    },
];

/// Looks up a provider by ID.
pub fn get_provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.id == id)
}

/// Returns all providers that require an API key.
pub fn providers_with_keys() -> impl Iterator<Item = &'static Provider> {
    PROVIDERS.iter().filter(|p| p.auth_type != AuthType::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_providers_defined() {
        assert!(get_provider("claude").is_some());
        assert!(get_provider("mm").is_some());
        assert!(get_provider("zai").is_some());
        assert!(get_provider("ollama").is_some());
    }

    #[test]
    fn unknown_provider_returns_none() {
        assert!(get_provider("unknown").is_none());
    }

    #[test]
    fn claude_auth_type_is_oauth() {
        assert_eq!(get_provider("claude").unwrap().auth_type, AuthType::OAuth);
    }

    #[test]
    fn minimax_auth_type_is_bearer() {
        assert_eq!(get_provider("mm").unwrap().auth_type, AuthType::Bearer);
    }

    #[test]
    fn ollama_auth_type_is_none() {
        assert_eq!(get_provider("ollama").unwrap().auth_type, AuthType::None);
    }

    #[test]
    fn ollama_has_no_key_env() {
        assert!(get_provider("ollama").unwrap().key_env_var.is_none());
    }

    #[test]
    fn bearer_providers_have_primers() {
        for p in PROVIDERS {
            if p.auth_type == AuthType::Bearer {
                assert!(
                    p.system_primer.is_some(),
                    "{} should have a system primer",
                    p.id
                );
            }
        }
    }

    #[test]
    fn providers_with_keys_excludes_ollama() {
        let with_keys: Vec<&str> = providers_with_keys().map(|p| p.id).collect();
        assert!(with_keys.contains(&"claude"));
        assert!(with_keys.contains(&"mm"));
        assert!(with_keys.contains(&"zai"));
        assert!(!with_keys.contains(&"ollama"));
    }

    #[test]
    fn settings_filenames_unique() {
        let mut names: Vec<&str> = PROVIDERS.iter().map(|p| p.settings_filename).collect();
        names.sort();
        names.dedup();
        assert_eq!(
            names.len(),
            PROVIDERS.len(),
            "settings filenames must be unique"
        );
    }

    // ── PR-C1 regressions ────────────────────────────────────────

    /// Surface enum roundtrips through serde JSON using the
    /// `#[serde(rename = ...)]` wire names.
    #[test]
    fn surface_serde_wire_names() {
        let cc = serde_json::to_string(&Surface::ClaudeCode).unwrap();
        let cx = serde_json::to_string(&Surface::Codex).unwrap();
        assert_eq!(cc, "\"claude-code\"");
        assert_eq!(cx, "\"codex\"");
        let back_cc: Surface = serde_json::from_str(&cc).unwrap();
        let back_cx: Surface = serde_json::from_str(&cx).unwrap();
        assert_eq!(back_cc, Surface::ClaudeCode);
        assert_eq!(back_cx, Surface::Codex);
    }

    /// Default is `Surface::ClaudeCode` so serialized state predating
    /// PR-C1 deserializes cleanly without a `surface` field.
    #[test]
    fn surface_default_is_claude_code() {
        let s: Surface = Default::default();
        assert_eq!(s, Surface::ClaudeCode);
    }

    /// Codex stub provider is present and correctly tagged. PR-C2+
    /// extends it with real credential plumbing; for now the catalog
    /// entry just needs to exist so downstream code can call
    /// `get_provider("codex")`.
    #[test]
    fn codex_stub_provider_present() {
        let p = get_provider("codex").expect("codex provider should be registered");
        assert_eq!(p.surface, Surface::Codex);
        assert_eq!(p.model_config, ModelConfigTarget::TomlModelKey);
        assert_eq!(p.quota_kind, QuotaKind::Utilization);
        assert_eq!(p.auth_type, AuthType::OAuth);
    }

    /// All four pre-existing providers must remain `Surface::ClaudeCode`
    /// after the PR-C1 tagging pass.
    #[test]
    fn claude_code_providers_retain_surface() {
        for id in ["claude", "mm", "zai", "ollama"] {
            let p = get_provider(id).expect(id);
            assert_eq!(
                p.surface,
                Surface::ClaudeCode,
                "provider {id} must be ClaudeCode"
            );
        }
    }

    /// `ModelConfigTarget::TomlModelKey` is reserved for Codex per
    /// spec 07 §7.3.3 — no other provider writes models via config.toml.
    #[test]
    fn toml_model_key_used_only_by_codex() {
        let toml_providers: Vec<&str> = PROVIDERS
            .iter()
            .filter(|p| p.model_config == ModelConfigTarget::TomlModelKey)
            .map(|p| p.id)
            .collect();
        assert_eq!(toml_providers, vec!["codex"]);
    }

    // ── PR-G1 regressions ────────────────────────────────────────

    /// Surface::Gemini round-trips through serde with the documented
    /// kebab-case wire name.
    #[test]
    fn surface_gemini_serde_wire_name() {
        let json = serde_json::to_string(&Surface::Gemini).unwrap();
        assert_eq!(json, "\"gemini\"");
        let back: Surface = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Surface::Gemini);
    }

    /// Surface::as_str matches the serde rename on every variant — so
    /// any path that hand-formats the surface tag (audit log,
    /// SlotKey, error_kind_tag) sees the exact same string the wire
    /// format produces.
    #[test]
    fn surface_as_str_matches_serde_wire_name() {
        for variant in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let serde_form = serde_json::to_string(&variant).unwrap();
            let trimmed = serde_form.trim_matches('"');
            assert_eq!(
                trimmed,
                variant.as_str(),
                "as_str() must match serde wire name for {variant:?}"
            );
        }
    }

    /// `Display` writes the same string as `as_str()`. Catches the
    /// regression where someone updates `as_str` and forgets to
    /// update `Display` (or vice-versa).
    #[test]
    fn surface_display_matches_as_str() {
        for variant in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            assert_eq!(format!("{variant}"), variant.as_str());
        }
    }

    /// Gemini stub provider is registered and correctly tagged for
    /// PR-G1's dispatch contract: API-key only path (auth_type =
    /// None), event-driven quota (QuotaKind::Counter), Vault-backed
    /// model writer (GeminiSettingsModelName).
    #[test]
    fn gemini_stub_provider_present_and_tagged() {
        let p = get_provider("gemini").expect("gemini provider should be registered");
        assert_eq!(p.surface, Surface::Gemini);
        assert_eq!(p.model_config, ModelConfigTarget::GeminiSettingsModelName);
        assert_eq!(p.quota_kind, QuotaKind::Counter);
        // Vault-backed key flow: auth_type stays None so
        // `providers_with_keys()` does not yield Gemini (the env-var
        // key flow does not apply).
        assert_eq!(p.auth_type, AuthType::None);
        assert!(
            p.key_env_var.is_none(),
            "Gemini key MUST NOT be env-sourced"
        );
    }

    /// `providers_with_keys()` must NOT yield Gemini — the existing
    /// "key from env var" predicate would mis-route Gemini through
    /// the env path otherwise.
    #[test]
    fn providers_with_keys_excludes_gemini() {
        let with_keys: Vec<&str> = providers_with_keys().map(|p| p.id).collect();
        assert!(
            !with_keys.contains(&"gemini"),
            "Gemini key flows via Vault, not env — must not appear in providers_with_keys"
        );
    }

    /// `ModelConfigTarget::GeminiSettingsModelName` is reserved for
    /// the Gemini surface — no other provider writes to
    /// `~/.gemini/settings.json model.name`.
    #[test]
    fn gemini_settings_model_name_used_only_by_gemini() {
        let providers: Vec<&str> = PROVIDERS
            .iter()
            .filter(|p| p.model_config == ModelConfigTarget::GeminiSettingsModelName)
            .map(|p| p.id)
            .collect();
        assert_eq!(providers, vec!["gemini"]);
    }

    /// Settings filenames remain unique after the Gemini stub lands —
    /// regression for the existing `settings_filenames_unique` test
    /// which would silently pass a duplicate if Gemini reused
    /// `codex-config.toml` or `settings.json`.
    #[test]
    fn gemini_settings_filename_distinct_from_existing_providers() {
        let gemini = get_provider("gemini").unwrap();
        for other in PROVIDERS {
            if other.id != "gemini" {
                assert_ne!(
                    other.settings_filename, gemini.settings_filename,
                    "{} must not share settings_filename with gemini",
                    other.id
                );
            }
        }
    }
}
