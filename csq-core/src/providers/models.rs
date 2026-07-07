//! Model catalog — embedded list of models across providers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCatalog {
    pub models: Vec<ModelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub context_window: Option<u64>,
    pub output_limit: Option<u64>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl ModelCatalog {
    /// Returns the embedded default catalog.
    pub fn default_catalog() -> Self {
        Self {
            models: vec![
                // Claude
                ModelInfo {
                    id: "claude-opus-4-7".into(),
                    name: "Claude Opus 4.7".into(),
                    provider: "claude".into(),
                    context_window: Some(200_000),
                    output_limit: Some(8_192),
                    aliases: vec!["opus".into(), "opus-4-7".into(), "opus-4-6".into()],
                },
                ModelInfo {
                    id: "claude-sonnet-4-6".into(),
                    name: "Claude Sonnet 4.6".into(),
                    provider: "claude".into(),
                    context_window: Some(200_000),
                    output_limit: Some(8_192),
                    aliases: vec!["sonnet".into(), "sonnet-4-6".into()],
                },
                ModelInfo {
                    id: "claude-haiku-4-5-20251001".into(),
                    name: "Claude Haiku 4.5".into(),
                    provider: "claude".into(),
                    context_window: Some(200_000),
                    output_limit: Some(4_096),
                    aliases: vec!["haiku".into(), "haiku-4-5".into()],
                },
                // MiniMax
                ModelInfo {
                    id: "MiniMax-M3".into(),
                    name: "MiniMax M3".into(),
                    provider: "mm".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["m3".into(), "minimax-m3".into(), "mm-m3".into()],
                },
                // Z.AI — `glm-5.2[1m]` is the 1M-context variant (Z.AI docs:
                // append the `[1m]` suffix to enable the 1,000,000-token window).
                // Bracket-free aliases (`glm`, `glm-5.2`) let `csq models switch`
                // resolve it without shell-quoting the `[1m]` glob.
                ModelInfo {
                    id: "glm-5.2[1m]".into(),
                    name: "GLM 5.2 (1M context)".into(),
                    provider: "zai".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["glm".into(), "glm-5.2".into(), "glm-5".into()],
                },
                // Gemini — static list per FR-G-UI-02 / ADR-G08.
                // `auto` is handled as a literal in the
                // `models switch gemini` branch, NOT as a catalog
                // entry — it instructs gemini-cli to pick rather
                // than pinning a specific id.
                ModelInfo {
                    id: "gemini-2.5-pro".into(),
                    name: "Gemini 2.5 Pro".into(),
                    provider: "gemini".into(),
                    context_window: Some(2_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["pro".into(), "2.5-pro".into()],
                },
                ModelInfo {
                    id: "gemini-2.5-flash".into(),
                    name: "Gemini 2.5 Flash".into(),
                    provider: "gemini".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["flash".into(), "2.5-flash".into()],
                },
                ModelInfo {
                    id: "gemini-2.5-flash-lite".into(),
                    name: "Gemini 2.5 Flash Lite".into(),
                    provider: "gemini".into(),
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["flash-lite".into(), "2.5-flash-lite".into()],
                },
                ModelInfo {
                    id: "gemini-3-pro-preview".into(),
                    name: "Gemini 3 Pro (preview)".into(),
                    provider: "gemini".into(),
                    context_window: Some(2_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["3-pro-preview".into(), "3-pro".into()],
                },
                // DeepSeek — Anthropic-API-compatible models exposed via
                // https://api.deepseek.com/anthropic. Tier mapping per
                // DeepSeek docs: pro for opus/sonnet workloads, flash
                // for haiku/subagent/cheap-fast workloads.
                ModelInfo {
                    id: "deepseek-v4-pro".into(),
                    name: "DeepSeek V4 Pro".into(),
                    provider: "deepseek".into(),
                    // DeepSeek V4 Pro ships a 1M-token context window (maintainer-confirmed
                    // 2026-07-05). CONSUMED by the statusline context-% recompute: the CLI
                    // (`statusline.rs`) resolves this window from the slot's settings.json
                    // model id (`providers::settings::model_id_for_slot`) and sets
                    // `StatuslineContext::ctx_window_true`, so `format.rs` recomputes the %
                    // against 1M instead of trusting CC's ~200k assumption for the
                    // Anthropic-compatible endpoint (which rendered 177k → 89% instead of ~18%).
                    context_window: Some(1_000_000),
                    output_limit: Some(8_192),
                    aliases: vec!["ds-pro".into(), "deepseek-pro".into(), "v4-pro".into()],
                },
                ModelInfo {
                    id: "deepseek-v4-flash".into(),
                    name: "DeepSeek V4 Flash".into(),
                    provider: "deepseek".into(),
                    context_window: Some(128_000),
                    output_limit: Some(8_192),
                    aliases: vec![
                        "ds-flash".into(),
                        "deepseek-flash".into(),
                        "v4-flash".into(),
                    ],
                },
            ],
        }
    }

    /// Finds a model by ID or alias.
    pub fn find(&self, query: &str) -> Option<&ModelInfo> {
        let q = query.to_lowercase();
        self.models
            .iter()
            .find(|m| m.id.to_lowercase() == q || m.aliases.iter().any(|a| a.to_lowercase() == q))
    }

    /// Returns all models for a specific provider.
    pub fn by_provider(&self, provider: &str) -> Vec<&ModelInfo> {
        self.models
            .iter()
            .filter(|m| m.provider == provider)
            .collect()
    }

    /// Suggests the closest match for a model query (Levenshtein-ish).
    pub fn suggest(&self, query: &str) -> Option<&ModelInfo> {
        let q = query.to_lowercase();
        self.models.iter().min_by_key(|m| {
            // Simple scoring: prefer prefix matches, then substring matches
            if m.id.to_lowercase().starts_with(&q) {
                0
            } else if m.id.to_lowercase().contains(&q) {
                1
            } else if m.aliases.iter().any(|a| a.to_lowercase().contains(&q)) {
                2
            } else {
                3
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_has_models() {
        let cat = ModelCatalog::default_catalog();
        assert!(!cat.models.is_empty());
        assert!(cat.find("claude-opus-4-7").is_some());
    }

    #[test]
    fn find_by_id() {
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("claude-opus-4-7").unwrap();
        assert_eq!(m.provider, "claude");
    }

    #[test]
    fn find_by_alias() {
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("opus").unwrap();
        assert_eq!(m.id, "claude-opus-4-7");
    }

    #[test]
    fn find_case_insensitive() {
        let cat = ModelCatalog::default_catalog();
        assert!(cat.find("OPUS").is_some());
        assert!(cat.find("Claude-Opus-4-7").is_some());
    }

    #[test]
    fn find_unknown_returns_none() {
        let cat = ModelCatalog::default_catalog();
        assert!(cat.find("nonexistent-model").is_none());
    }

    #[test]
    fn by_provider_filters_correctly() {
        let cat = ModelCatalog::default_catalog();
        let claude = cat.by_provider("claude");
        assert!(claude.iter().all(|m| m.provider == "claude"));
        assert!(claude.len() >= 3);

        let mm = cat.by_provider("mm");
        assert!(mm.iter().all(|m| m.provider == "mm"));
    }

    #[test]
    fn deepseek_v4_pro_context_window_is_1m() {
        // DeepSeek V4 Pro is a 1M-token context model (maintainer-confirmed 2026-07-05);
        // a stale 128k value under-states the true window (and would drive a wrong
        // context-% once the statusline consumes the catalog window).
        let cat = ModelCatalog::default_catalog();
        let m = cat
            .find("deepseek-v4-pro")
            .expect("deepseek-v4-pro in catalog");
        assert_eq!(m.context_window, Some(1_000_000));
        // aliases still resolve to the 1M entry.
        assert_eq!(cat.find("ds-pro").unwrap().context_window, Some(1_000_000));
    }

    #[test]
    fn serialization_round_trip() {
        let cat = ModelCatalog::default_catalog();
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: ModelCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat.models.len(), parsed.models.len());
    }
}
