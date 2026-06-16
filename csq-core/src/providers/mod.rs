//! Provider management — API key storage, model catalog, key validation.

pub mod catalog;
pub mod codex;
pub mod gemini;
pub mod models;
pub mod ollama;
pub mod settings;
pub mod validate;

pub use catalog::{get_provider, id_from_display_name, Provider, PROVIDERS};
pub use models::{ModelCatalog, ModelInfo};
pub use settings::{load_settings, save_settings, ProviderSettings};
