//! `csq.models.v1` — the model-listing wire payload.
//!
//! The CLI supplies provider/catalog values; this module owns only their public
//! serialized shape. Listing and live-provider discovery remain in the app.

use serde::Serialize;

/// One model row, constructed with [`Self::new`] and optional metadata builders.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ModelEntry {
    /// Provider identifier used by the CLI filter.
    pub provider_id: String,
    /// Human-readable provider name.
    pub provider_name: String,
    /// Provider model identifier, or the app's vendor-selected placeholder.
    pub model_id: String,
    /// Human-readable model name.
    pub model_name: String,
    /// Context capacity in tokens, omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u64>,
    /// Output capacity in tokens, omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_limit: Option<u64>,
    /// Catalog aliases, omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// True for a synthesized provider-default row, not a curated catalog row.
    /// This flag does not assert known context/output limits for that default.
    pub is_default: bool,
}

impl ModelEntry {
    /// Build the five always-present fields; optional metadata starts absent.
    #[must_use]
    pub fn new(
        provider_id: impl Into<String>,
        provider_name: impl Into<String>,
        model_id: impl Into<String>,
        model_name: impl Into<String>,
        is_default: bool,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            provider_name: provider_name.into(),
            model_id: model_id.into(),
            model_name: model_name.into(),
            context_window: None,
            output_limit: None,
            aliases: Vec::new(),
            is_default,
        }
    }

    /// Set the context capacity, accepting a count or an optional count.
    #[must_use]
    pub fn with_context_window(mut self, tokens: impl Into<Option<u64>>) -> Self {
        self.context_window = tokens.into();
        self
    }

    /// Set the output capacity, accepting a count or an optional count.
    #[must_use]
    pub fn with_output_limit(mut self, tokens: impl Into<Option<u64>>) -> Self {
        self.output_limit = tokens.into();
        self
    }

    /// Set the catalog aliases; an empty vector remains absent on the wire.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }
}

/// Success payload flattened into the [`crate::SCHEMA_MODELS_V1`] envelope.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ModelsPayload {
    /// The model rows; the key remains present even for an empty list.
    pub models: Vec<ModelEntry>,
}

impl ModelsPayload {
    /// Build a model-listing payload from app-supplied rows.
    #[must_use]
    pub fn new(models: Vec<ModelEntry>) -> Self {
        Self { models }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, SCHEMA_MODELS_V1};
    use serde_json::json;

    #[test]
    fn model_entry_maximal_preserves_v1_keys_and_u64_counts() {
        let row = ModelEntry::new("provider", "Provider", "model", "Model", false)
            .with_context_window(u64::MAX)
            .with_output_limit(8_192u64)
            .with_aliases(vec!["alias".to_string()]);
        assert_eq!(
            serde_json::to_value(row).unwrap(),
            json!({
                "provider_id": "provider", "provider_name": "Provider",
                "model_id": "model", "model_name": "Model", "is_default": false,
                "context_window": u64::MAX, "output_limit": 8_192,
                "aliases": ["alias"]
            })
        );
    }

    #[test]
    fn model_entry_default_row_omits_unknown_metadata() {
        let row = ModelEntry::new("native", "Native", "default", "Default", true);
        assert_eq!(
            serde_json::to_value(row).unwrap(),
            json!({"provider_id": "native", "provider_name": "Native",
                "model_id": "default", "model_name": "Default", "is_default": true})
        );
    }

    #[test]
    fn model_entry_optional_builders_preserve_zero_and_clear_none() {
        let row = ModelEntry::new("p", "P", "m", "M", false)
            .with_context_window(0u64)
            .with_output_limit(0u64);
        let value = serde_json::to_value(&row).unwrap();
        assert_eq!(value["context_window"], 0);
        assert_eq!(value["output_limit"], 0);
        let cleared = row
            .with_context_window(None)
            .with_output_limit(None)
            .with_aliases(Vec::new());
        let value = serde_json::to_value(cleared).unwrap();
        for key in ["context_window", "output_limit", "aliases"] {
            assert!(value.get(key).is_none(), "{key} must be absent, not null");
        }
    }

    #[test]
    fn models_payload_empty_list_keeps_flattened_models_key() {
        let env = Envelope::success(SCHEMA_MODELS_V1, None, ModelsPayload::new(Vec::new()));
        let value: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(
            value,
            json!({"schema": "csq.models.v1", "ok": true, "models": []})
        );
    }
}
