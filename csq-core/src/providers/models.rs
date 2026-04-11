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
                    id: "claude-opus-4-6".into(),
                    name: "Claude Opus 4.6".into(),
                    provider: "claude".into(),
                    context_window: Some(200_000),
                    output_limit: Some(8_192),
                    aliases: vec!["opus".into(), "opus-4-6".into()],
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
                    id: "MiniMax-M2".into(),
                    name: "MiniMax M2".into(),
                    provider: "mm".into(),
                    context_window: Some(245_760),
                    output_limit: Some(8_192),
                    aliases: vec!["m2".into(), "minimax-m2".into()],
                },
                // Z.AI
                ModelInfo {
                    id: "glm-4.6".into(),
                    name: "GLM 4.6".into(),
                    provider: "zai".into(),
                    context_window: Some(200_000),
                    output_limit: Some(8_192),
                    aliases: vec!["glm".into(), "glm-4".into()],
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
        assert!(cat.find("claude-opus-4-6").is_some());
    }

    #[test]
    fn find_by_id() {
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("claude-opus-4-6").unwrap();
        assert_eq!(m.provider, "claude");
    }

    #[test]
    fn find_by_alias() {
        let cat = ModelCatalog::default_catalog();
        let m = cat.find("opus").unwrap();
        assert_eq!(m.id, "claude-opus-4-6");
    }

    #[test]
    fn find_case_insensitive() {
        let cat = ModelCatalog::default_catalog();
        assert!(cat.find("OPUS").is_some());
        assert!(cat.find("Claude-Opus-4-6").is_some());
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
    fn serialization_round_trip() {
        let cat = ModelCatalog::default_catalog();
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: ModelCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat.models.len(), parsed.models.len());
    }
}
