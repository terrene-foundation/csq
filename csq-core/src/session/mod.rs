//! Session management — config dir isolation, settings merge, onboarding.
//!
//! Builds an isolated `config-N/` directory per terminal so each CC session
//! has its own credentials, current account marker, and settings, while
//! sharing history/commands/skills via symlinks.

pub mod isolation;
pub mod merge;
pub mod setup;

pub use isolation::isolate_config_dir;
pub use merge::merge_settings;
pub use setup::{cleanup_stale_pid, mark_onboarding_complete};
