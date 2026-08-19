//! Subcommand handlers for the csq CLI.

pub mod audit;
pub mod classify;
pub mod cli;
pub(crate) mod cli_deps_gate;
pub mod completions;
pub mod daemon;
pub mod dev_identity;
pub mod doctor;
pub mod exec;
pub mod inspect_coc;
pub mod install;
pub mod keychain_sync;
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
pub mod unlock;
pub mod update;

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Validates a directory override read from the environment.
///
/// An override MUST be non-empty and absolute. `std::env::var` returns
/// `Ok("")` for a variable that is SET BUT EMPTY, so an unvalidated override
/// yields `PathBuf::from("")` — a relative path that resolves against the
/// process CWD (`/` for a Finder-launched app). Callers treat `Err` as their
/// fail-safe ("could not resolve → no-op"), so returning `Ok(garbage)` bypasses
/// the fail-safe entirely rather than triggering it.
///
/// The concrete harm this blocks: with `CLAUDE_HOME=`, the auto-rotator reads
/// its base `settings.json` from the relative path `settings.json`, finds
/// nothing, merges an empty base, and writes a handle-dir `settings.json`
/// containing only the slot overlay — silently dropping the user's global CC
/// config INCLUDING `permissions` deny rules, which is a security control.
fn validated_env_override(var: &str) -> Option<Result<PathBuf>> {
    let raw = std::env::var(var).ok()?;
    Some(validate_dir_override(var, &raw))
}

/// The pure half of [`validated_env_override`], split out so it is testable
/// without mutating process environment (which races across parallel tests).
fn validate_dir_override(var: &str, raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if raw.is_empty() || !path.is_absolute() {
        anyhow::bail!("{var} must be a non-empty absolute path (got {raw:?})");
    }
    Ok(path)
}

/// Returns the base directory for csq state: `~/.claude/accounts`.
///
/// Honors the `CSQ_BASE_DIR` environment variable for testing. The override
/// must be a non-empty absolute path — see [`validated_env_override`].
pub fn base_dir() -> Result<PathBuf> {
    if let Some(overridden) = validated_env_override("CSQ_BASE_DIR") {
        return overridden;
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".claude").join("accounts"))
}

/// Returns the user's `~/.claude` directory (CC's config home).
///
/// Honors the `CLAUDE_HOME` environment variable. The override must be a
/// non-empty absolute path — see [`validated_env_override`].
pub fn claude_home() -> Result<PathBuf> {
    if let Some(overridden) = validated_env_override("CLAUDE_HOME") {
        return overridden;
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

// M4-8 (Phase 4 an internal ticket): `validated_config_dir` and its supporting
// `validate_config_dir` helper were retired with the
// `rotation::swap_to` legacy fallback. The handle-dir model's source
// detection lives in `csq/src/cli/commands/swap.rs::detect_source_handle`
// and rejects non-`term-<pid>` sources directly. There is no other
// production caller that needs the legacy `config-<N>` path-traversal
// validator.

#[cfg(test)]
mod env_override_tests {
    use super::validate_dir_override;

    /// The originating defect: `std::env::var` yields `Ok("")` for a SET BUT
    /// EMPTY variable, so an unvalidated override produced `PathBuf::from("")`
    /// — a relative path — and callers' `Err => no-op` fail-safe never fired.
    /// With `CLAUDE_HOME=` that made the auto-rotator merge an empty base and
    /// drop the user's global CC `permissions` deny rules from every rotated
    /// handle dir.
    #[test]
    fn empty_override_is_rejected() {
        assert!(validate_dir_override("CLAUDE_HOME", "").is_err());
    }

    /// A relative override resolves against the process CWD, which is `/` for
    /// a Finder-launched app and arbitrary for a shell-launched daemon.
    #[test]
    fn relative_override_is_rejected() {
        assert!(validate_dir_override("CSQ_BASE_DIR", "relative/dir").is_err());
        assert!(validate_dir_override("CSQ_BASE_DIR", "./dir").is_err());
    }

    /// What counts as absolute is platform-specific: on Windows a path needs a
    /// drive or UNC prefix, so `/tmp/x` is ROOTED but not absolute and is
    /// correctly rejected there (it resolves against the current drive — the
    /// same ambiguity this validation exists to block).
    #[test]
    fn absolute_override_is_accepted() {
        let raw = if cfg!(windows) {
            r"C:\csq-test"
        } else {
            "/tmp/csq-test"
        };
        let p = validate_dir_override("CSQ_BASE_DIR", raw).expect("absolute is valid");
        assert_eq!(p, std::path::PathBuf::from(raw));
    }

    /// A drive-less rooted path on Windows resolves against the CURRENT drive,
    /// which is exactly the CWD-dependence this rejects. Unix has no such
    /// notion, so `/tmp/x` is genuinely absolute there.
    #[test]
    #[cfg(windows)]
    fn windows_rejects_driveless_rooted_path() {
        assert!(validate_dir_override("CSQ_BASE_DIR", r"\csq-test").is_err());
        assert!(validate_dir_override("CSQ_BASE_DIR", "/csq-test").is_err());
    }

    /// The error names the variable so the operator knows which one to fix.
    #[test]
    fn error_names_the_variable() {
        let e = validate_dir_override("CLAUDE_HOME", "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("CLAUDE_HOME"), "error must name the var: {e}");
    }
}
