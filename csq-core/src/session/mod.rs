//! Session management — config dir isolation, settings merge, onboarding.
//!
//! Builds an isolated `config-N/` directory per terminal so each CC session
//! has its own credentials, current account marker, and settings, while
//! sharing history/commands/skills via symlinks.

pub mod handle_dir;
pub mod isolation;
pub mod merge;
pub mod settings;
pub mod setup;

pub use handle_dir::{
    create_handle_dir, create_handle_dir_codex, create_handle_dir_codex_named,
    create_handle_dir_named, materialize_handle_settings, repoint_handle_dir, spawn_sweep,
    sweep_dead_handles, SweepHandle, EXEC_CODEX_DIR_PREFIX, EXEC_GEMINI_DIR_PREFIX,
};
pub use isolation::isolate_config_dir;
pub use merge::merge_settings;
pub use settings::write_slot_model_with_uuid_routing;
pub use setup::{cleanup_stale_pid, mark_onboarding_complete};
