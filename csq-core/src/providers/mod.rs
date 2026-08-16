//! Provider management — API key storage, model catalog, key validation.

pub mod catalog;
pub mod codex;
pub mod gemini;
pub mod login_capability;
pub mod models;
pub mod native;
pub mod native_login;
pub mod ollama;
pub mod registry;
pub mod settings;
pub mod validate;

pub use catalog::{get_provider, id_from_display_name, Provider, PROVIDERS};
pub use login_capability::{guard_attended_session, login_flow_for, provider_login};
pub use models::{ModelCatalog, ModelInfo};
pub use registry::{ProviderDescriptor, ProviderKind};
pub use settings::{load_settings, save_settings, ProviderSettings};
