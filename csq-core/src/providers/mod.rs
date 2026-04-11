//! Provider management — API key storage, model catalog, key validation.

pub mod catalog;
pub mod models;
pub mod ollama;
pub mod settings;
pub mod validate;

pub use catalog::{get_provider, Provider, PROVIDERS};
pub use models::{ModelCatalog, ModelInfo};
pub use settings::{load_settings, save_settings, ProviderSettings};
