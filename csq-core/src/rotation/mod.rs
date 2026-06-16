//! Account rotation — pick best, auto-rotate.
//!
//! **M4-8 (Phase 4, issue #292):** the `swap` submodule was deleted and
//! `swap_to` retired. The legacy `CLAUDE_CONFIG_DIR=config-N` swap mode
//! is fully gone: every swap now flows through
//! [`crate::session::handle_dir::repoint_handle_dir`] (Anthropic) or
//! [`crate::session::handle_dir::repoint_handle_dir_codex`] (Codex),
//! invoked from `csq/src/cli/commands/swap.rs`. Terminals launched
//! pre-handle-dir (before spec 02) must relaunch with `csq run N` to
//! get a `term-<pid>` handle dir before they can swap.

pub mod config;
pub mod picker;

pub use config::RotationConfig;
pub use picker::{pick_best, suggest, Suggestion};
