//! Provider catalog — skeletons for Claude, MiniMax, Z.AI, Ollama.

use serde::{Deserialize, Serialize};

/// A provider definition with defaults for new profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// Short identifier (e.g., "claude", "mm", "zai", "ollama").
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Auth type: "oauth" (Claude), "bearer" (MiniMax, Z.AI), "none" (Ollama).
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
        auth_type: AuthType::OAuth,
        key_env_var: Some("ANTHROPIC_API_KEY"),
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("https://api.anthropic.com"),
        default_model: "claude-opus-4-6",
        validation_endpoint: Some("https://api.anthropic.com/v1/messages"),
        settings_filename: "settings.json",
        system_primer: None,
        timeout_secs: 30,
    },
    Provider {
        id: "mm",
        name: "MiniMax",
        auth_type: AuthType::Bearer,
        key_env_var: Some("ANTHROPIC_AUTH_TOKEN"),
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("https://api.minimax.chat/anthropic"),
        default_model: "MiniMax-M2",
        validation_endpoint: Some("https://api.minimax.chat/anthropic/v1/messages"),
        settings_filename: "settings-mm.json",
        system_primer: Some(
            "You are a helpful coding assistant with access to tools for editing files and running commands.",
        ),
        timeout_secs: 60,
    },
    Provider {
        id: "zai",
        name: "Z.AI",
        auth_type: AuthType::Bearer,
        key_env_var: Some("ANTHROPIC_AUTH_TOKEN"),
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("https://api.z.ai/api/anthropic"),
        default_model: "glm-4.6",
        validation_endpoint: Some("https://api.z.ai/api/anthropic/v1/messages"),
        settings_filename: "settings-zai.json",
        system_primer: Some(
            "You are a helpful coding assistant with access to tools for editing files and running commands.",
        ),
        timeout_secs: 60,
    },
    Provider {
        id: "ollama",
        name: "Ollama",
        auth_type: AuthType::None,
        key_env_var: None,
        base_url_env_var: Some("ANTHROPIC_BASE_URL"),
        default_base_url: Some("http://localhost:11434"),
        default_model: "llama3.3",
        validation_endpoint: None, // Validated via `ollama list`
        settings_filename: "settings-ollama.json",
        system_primer: Some(
            "You are a helpful coding assistant. Use tools when they would help answer the user.",
        ),
        timeout_secs: 120,
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
}
