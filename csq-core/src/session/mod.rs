//! Session management — config dir isolation, settings merge, onboarding.
//!
//! Builds an isolated `config-N/` directory per terminal so each CC session
//! has its own credentials, current account marker, and settings, while
//! sharing history/commands/skills via symlinks.

pub mod handle_dir;
pub mod isolation;
pub mod merge;
pub mod setup;

pub use handle_dir::{
    create_handle_dir, materialize_handle_settings, repoint_handle_dir, spawn_sweep,
    sweep_dead_handles, SweepHandle,
};
pub use isolation::isolate_config_dir;
pub use merge::merge_settings;
pub use setup::{cleanup_stale_pid, mark_onboarding_complete};
