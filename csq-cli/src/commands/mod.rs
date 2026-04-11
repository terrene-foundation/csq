//! Subcommand handlers for the csq CLI.

pub mod completions;
pub mod daemon;
pub mod doctor;
pub mod install;
pub mod listkeys;
pub mod login;
pub mod models;
pub mod rmkey;
pub mod run;
pub mod setkey;
pub mod status;
pub mod statusline;
pub mod suggest;
pub mod swap;

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

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
/// **Unvalidated** — callers that use the result for file writes must
/// use [`validated_config_dir`] instead.
pub fn current_config_dir() -> Option<PathBuf> {
    std::env::var("CLAUDE_CONFIG_DIR").ok().map(PathBuf::from)
}

/// Returns the current config dir, validated to be:
/// 1. A descendant of `base_dir` (prevents path traversal)
/// 2. Named `config-N` where N is a valid account number
///
/// Returns an error if `CLAUDE_CONFIG_DIR` is missing, malformed, or
/// escapes the base directory.
pub fn validated_config_dir(base_dir: &Path) -> Result<PathBuf> {
    let raw = std::env::var("CLAUDE_CONFIG_DIR").map_err(|_| {
        anyhow!("CLAUDE_CONFIG_DIR not set — this command must run inside a csq-managed session")
    })?;

    validate_config_dir(base_dir, Path::new(&raw))
}

/// Validates a config dir path against a base directory.
///
/// Separated from [`validated_config_dir`] for testability.
pub fn validate_config_dir(base_dir: &Path, config_dir: &Path) -> Result<PathBuf> {
    // Canonicalize both to resolve symlinks and `..` components.
    // If the config dir doesn't exist yet, canonicalize its parent and
    // append the name.
    let canon_config = if config_dir.exists() {
        config_dir
            .canonicalize()
            .with_context(|| format!("canonicalizing {}", config_dir.display()))?
    } else {
        let parent = config_dir
            .parent()
            .ok_or_else(|| anyhow!("config dir has no parent: {}", config_dir.display()))?;
        let parent_canon = parent
            .canonicalize()
            .with_context(|| format!("canonicalizing parent {}", parent.display()))?;
        let name = config_dir
            .file_name()
            .ok_or_else(|| anyhow!("config dir has no file name"))?;
        parent_canon.join(name)
    };

    let canon_base = base_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing base {}", base_dir.display()))?;

    if !canon_config.starts_with(&canon_base) {
        return Err(anyhow!(
            "CLAUDE_CONFIG_DIR escapes base directory: {} is not under {}",
            canon_config.display(),
            canon_base.display()
        ));
    }

    // Name must be config-N where N is 1..=999
    let name = canon_config
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("config dir has no file name"))?;

    let n_str = name
        .strip_prefix("config-")
        .ok_or_else(|| anyhow!("config dir name must start with 'config-': {name}"))?;

    let n: u16 = n_str
        .parse()
        .map_err(|_| anyhow!("config dir name has invalid account number: {name}"))?;

    if !(1..=999).contains(&n) {
        return Err(anyhow!("account number out of range: {n}"));
    }

    Ok(canon_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn validate_rejects_path_outside_base() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("accounts");
        let outside = dir.path().join("other");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let result = validate_config_dir(&base, &outside);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("escapes"));
    }

    #[test]
    fn validate_rejects_non_config_name() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let bad = base.join("notconfig");
        std::fs::create_dir_all(&bad).unwrap();

        let result = validate_config_dir(&base, &bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("config-"));
    }

    #[test]
    fn validate_rejects_out_of_range() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let bad = base.join("config-1000");
        std::fs::create_dir_all(&bad).unwrap();

        let result = validate_config_dir(&base, &bad);
        assert!(result.is_err());
    }

    #[test]
    fn validate_accepts_valid_config_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let good = base.join("config-3");
        std::fs::create_dir_all(&good).unwrap();

        let result = validate_config_dir(&base, &good);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rejects_traversal_attempt() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        // Try to escape via ../
        let traverse = base.join("../etc");

        let result = validate_config_dir(&base, &traverse);
        assert!(result.is_err());
    }
}
