//! Auto-rotation configuration — load/save from `{base_dir}/rotation.json`.
//!
//! `rotation.json` controls whether the daemon auto-rotation loop is
//! active, the threshold that triggers a swap, the per-config-dir
//! cooldown, and any accounts to exclude from being rotated *into*.
//!
//! # File location
//!
//! `{base_dir}/rotation.json` — same directory as `quota.json`.
//!
//! # Defaults (file absent)
//!
//! - `enabled`: `false` — auto-rotation is opt-in.
//! - `threshold_percent`: `95.0` — swap when 5-hour usage ≥ 95%.
//! - `cooldown_secs`: `300` — 5-minute cooldown per config dir.
//! - `exclude_accounts`: `[]` — no accounts excluded.

use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, unique_tmp_path};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

fn default_false() -> bool {
    false
}

fn default_threshold() -> f64 {
    95.0
}

fn default_cooldown() -> u64 {
    300
}

/// Auto-rotation configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationConfig {
    /// Whether auto-rotation is active. Defaults to `false`.
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// 5-hour usage percentage (0–100) at which a config dir is eligible
    /// for rotation. Defaults to `95.0`.
    #[serde(default = "default_threshold")]
    pub threshold_percent: f64,

    /// Seconds to wait before rotating the same config dir again.
    /// Defaults to `300` (5 minutes).
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,

    /// Account numbers to never rotate *into*. The current account for a
    /// config dir is always excluded from candidate selection via
    /// `pick_best`; this list additionally excludes specific accounts
    /// from ever being selected as rotation targets.
    #[serde(default)]
    pub exclude_accounts: Vec<u16>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            threshold_percent: default_threshold(),
            cooldown_secs: default_cooldown(),
            exclude_accounts: vec![],
        }
    }
}

/// Returns the path to `rotation.json` within a base directory.
pub fn config_path(base_dir: &Path) -> PathBuf {
    base_dir.join("rotation.json")
}

/// Loads `RotationConfig` from `{base_dir}/rotation.json`.
///
/// Returns defaults if the file is absent. Returns an error only if
/// the file exists but cannot be parsed.
pub fn load(base_dir: &Path) -> Result<RotationConfig, ConfigError> {
    let path = config_path(base_dir);
    match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            serde_json::from_str::<RotationConfig>(&content).map_err(|e| ConfigError::InvalidJson {
                path,
                reason: e.to_string(),
            })
        }
        // Missing or empty — return defaults (not an error).
        _ => Ok(RotationConfig::default()),
    }
}

/// Saves `RotationConfig` to `{base_dir}/rotation.json` atomically.
pub fn save(base_dir: &Path, cfg: &RotationConfig) -> Result<(), ConfigError> {
    let path = config_path(base_dir);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let json = serde_json::to_string_pretty(cfg).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("serialization: {e}"),
    })?;

    let tmp = unique_tmp_path(&path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write: {e}"),
    })?;

    atomic_replace(&tmp, &path).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("atomic replace: {e}"),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let cfg = load(dir.path()).unwrap();

        assert!(!cfg.enabled);
        assert_eq!(cfg.threshold_percent, 95.0);
        assert_eq!(cfg.cooldown_secs, 300);
        assert!(cfg.exclude_accounts.is_empty());
    }

    #[test]
    fn round_trip_save_load() {
        let dir = TempDir::new().unwrap();
        let original = RotationConfig {
            enabled: true,
            threshold_percent: 80.0,
            cooldown_secs: 120,
            exclude_accounts: vec![3, 7],
        };

        save(dir.path(), &original).unwrap();
        let loaded = load(dir.path()).unwrap();

        assert_eq!(loaded, original);
    }

    #[test]
    fn partial_json_uses_defaults_for_missing_fields() {
        let dir = TempDir::new().unwrap();
        // Only set `enabled` — rest should use defaults.
        std::fs::write(config_path(dir.path()), r#"{"enabled": true}"#).unwrap();

        let cfg = load(dir.path()).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.threshold_percent, 95.0);
        assert_eq!(cfg.cooldown_secs, 300);
        assert!(cfg.exclude_accounts.is_empty());
    }

    #[test]
    fn exclude_accounts_round_trip() {
        let dir = TempDir::new().unwrap();
        let cfg = RotationConfig {
            enabled: false,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            exclude_accounts: vec![1, 2, 5],
        };

        save(dir.path(), &cfg).unwrap();
        let loaded = load(dir.path()).unwrap();

        assert_eq!(loaded.exclude_accounts, vec![1, 2, 5]);
    }

    #[test]
    fn invalid_json_returns_error() {
        let dir = TempDir::new().unwrap();
        std::fs::write(config_path(dir.path()), b"not-valid-json").unwrap();

        let result = load(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_returns_defaults() {
        let dir = TempDir::new().unwrap();
        std::fs::write(config_path(dir.path()), b"").unwrap();

        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg, RotationConfig::default());
    }
}
