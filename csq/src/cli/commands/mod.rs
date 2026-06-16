//! Subcommand handlers for the csq CLI.

pub mod audit;
pub mod classify;
pub mod cli;
pub(crate) mod cli_deps_gate;
pub mod completions;
pub mod daemon;
pub mod dev_identity;
pub mod doctor;
pub mod inspect_coc;
pub mod install;
pub mod listkeys;
pub mod login;
pub mod logout;
pub mod models;
pub mod move_slot;
pub mod probe;
pub mod repair;
pub mod rmkey;
pub mod roster;
pub mod run;
pub mod setkey;
pub mod status;
pub mod statusline;
pub mod suggest;
pub mod swap;
pub mod update;

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Returns the base directory for csq state: `~/.claude/accounts`.
///
/// Honors `CSQ_BASE_DIR` environment variable for testing.
pub fn base_dir() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var("CSQ_BASE_DIR") {
        return Ok(PathBuf::from(override_path));
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".claude").join("accounts"))
}

/// Returns the user's `~/.claude` directory (CC's config home).
pub fn claude_home() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var("CLAUDE_HOME") {
        return Ok(PathBuf::from(override_path));
    }
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".claude"))
}

/// Returns the current config dir from `CLAUDE_CONFIG_DIR` env var.
///
/// **Unvalidated** — for handle-dir-aware callers that do their own
/// validation (see `csq/src/cli/commands/swap.rs::detect_source_handle`).
pub fn current_config_dir() -> Option<PathBuf> {
    std::env::var("CLAUDE_CONFIG_DIR").ok().map(PathBuf::from)
}

// M4-8 (Phase 4 issue #292): `validated_config_dir` and its supporting
// `validate_config_dir` helper were retired with the
// `rotation::swap_to` legacy fallback. The handle-dir model's source
// detection lives in `csq/src/cli/commands/swap.rs::detect_source_handle`
// and rejects non-`term-<pid>` sources directly. There is no other
// production caller that needs the legacy `config-<N>` path-traversal
// validator.
