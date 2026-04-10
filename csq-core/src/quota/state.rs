//! Quota state management — load, save, update with payload-hash cursor.

use super::{AccountQuota, QuotaFile, UsageWindow};
use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use crate::platform::lock;
use crate::types::AccountNum;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Returns the path to quota.json within a base directory.
pub fn quota_path(base_dir: &Path) -> PathBuf {
    base_dir.join("quota.json")
}

/// Returns the path to the per-config quota cursor file.
pub fn cursor_path(config_dir: &Path) -> PathBuf {
    config_dir.join(".quota-cursor")
}

/// Loads quota state from disk, auto-clearing expired windows.
///
/// Returns an empty QuotaFile if the file doesn't exist.
pub fn load_state(base_dir: &Path) -> Result<QuotaFile, ConfigError> {
    let path = quota_path(base_dir);
    let mut quota_file = match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => serde_json::from_str::<QuotaFile>(&content)
            .map_err(|e| ConfigError::InvalidJson {
                path: path.clone(),
                reason: e.to_string(),
            })?,
        _ => QuotaFile::empty(),
    };

    // Clear expired windows
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for quota in quota_file.accounts.values_mut() {
        quota.clear_expired(now_secs);
    }

    Ok(quota_file)
}

/// Saves quota state to disk with atomic write.
pub fn save_state(base_dir: &Path, quota_file: &QuotaFile) -> Result<(), ConfigError> {
    let path = quota_path(base_dir);
    let json = serde_json::to_string_pretty(quota_file).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("serialization: {e}"),
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write: {e}"),
    })?;

    secure_file(&tmp).ok();
    atomic_replace(&tmp, &path).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("atomic replace: {e}"),
    })?;

    Ok(())
}

/// Computes a deterministic hash of a rate_limits payload for cursor comparison.
///
/// Used to prevent stale quota data from being applied after a swap.
pub fn payload_hash(payload: &serde_json::Value) -> String {
    let serialized = serde_json::to_string(payload).unwrap_or_default();
    let digest = Sha256::digest(serialized.as_bytes());
    hex::encode(&digest[..16]) // 32 hex chars is enough
}

/// Reads the last-processed payload hash for a config dir.
pub fn read_cursor(config_dir: &Path) -> Option<String> {
    std::fs::read_to_string(cursor_path(config_dir))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Writes the current payload hash to the config dir's cursor file.
pub fn write_cursor(config_dir: &Path, hash: &str) -> Result<(), ConfigError> {
    let path = cursor_path(config_dir);
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, hash.as_bytes()).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write cursor: {e}"),
    })?;
    atomic_replace(&tmp, &path).map_err(|e| ConfigError::InvalidJson {
        path,
        reason: format!("atomic replace: {e}"),
    })?;
    Ok(())
}

/// Updates quota for an account from a CC rate_limits payload.
///
/// Uses file locking on quota.json to prevent concurrent corruption.
/// Uses payload-hash cursor to reject stale data (after swap).
///
/// Returns `true` if quota was updated, `false` if skipped (stale/duplicate).
pub fn update_quota(
    base_dir: &Path,
    config_dir: &Path,
    account: AccountNum,
    rate_limits: &serde_json::Value,
) -> Result<bool, crate::error::CsqError> {
    let new_hash = payload_hash(rate_limits);

    // Check cursor — skip if we already processed this payload
    if let Some(prev) = read_cursor(config_dir) {
        if prev == new_hash {
            debug!(account = %account, "quota cursor unchanged, skipping");
            return Ok(false);
        }
    }

    // Lock quota.json for the duration of the update
    let lock_path = quota_path(base_dir).with_extension("lock");
    let _guard = lock::lock_file(&lock_path)?;

    // Re-read inside lock to prevent races
    let mut quota_file = load_state(base_dir)?;

    let five_hour = parse_window(rate_limits, "five_hour");
    let seven_day = parse_window(rate_limits, "seven_day");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    quota_file.set(
        account.get(),
        AccountQuota {
            five_hour,
            seven_day,
            updated_at: now,
        },
    );

    save_state(base_dir, &quota_file)?;

    // Write cursor after successful save
    write_cursor(config_dir, &new_hash)?;

    debug!(account = %account, "quota updated");
    Ok(true)
}

/// Parses a usage window from a rate_limits JSON object.
fn parse_window(rate_limits: &serde_json::Value, key: &str) -> Option<UsageWindow> {
    let window = rate_limits.get(key)?;
    let used = window.get("used_percentage")?.as_f64()?;
    let resets = window.get("resets_at")?.as_u64()?;
    Some(UsageWindow {
        used_percentage: used,
        resets_at: resets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let state = load_state(dir.path()).unwrap();
        assert!(state.accounts.is_empty());
    }

    #[test]
    fn round_trip_save_load() {
        let dir = TempDir::new().unwrap();
        let mut qf = QuotaFile::empty();
        qf.set(
            1,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: 42.5,
                    resets_at: 9999999999,
                }),
                seven_day: None,
                updated_at: 100.0,
            },
        );

        save_state(dir.path(), &qf).unwrap();
        let loaded = load_state(dir.path()).unwrap();

        assert_eq!(loaded.get(1).unwrap().five_hour_pct(), 42.5);
    }

    #[test]
    fn load_clears_expired_on_read() {
        let dir = TempDir::new().unwrap();
        let mut qf = QuotaFile::empty();
        qf.set(
            1,
            AccountQuota {
                // resets_at in the past → will be cleared on load
                five_hour: Some(UsageWindow {
                    used_percentage: 100.0,
                    resets_at: 1000,
                }),
                seven_day: None,
                updated_at: 0.0,
            },
        );
        save_state(dir.path(), &qf).unwrap();

        let loaded = load_state(dir.path()).unwrap();
        assert!(loaded.get(1).unwrap().five_hour.is_none());
    }

    #[test]
    fn payload_hash_deterministic() {
        let payload = serde_json::json!({
            "five_hour": {"used_percentage": 50, "resets_at": 1000}
        });
        let h1 = payload_hash(&payload);
        let h2 = payload_hash(&payload);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn payload_hash_differs_for_different_data() {
        let a = serde_json::json!({"v": 1});
        let b = serde_json::json!({"v": 2});
        assert_ne!(payload_hash(&a), payload_hash(&b));
    }

    #[test]
    fn update_quota_writes_state() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();
        let account = AccountNum::try_from(1u16).unwrap();

        let payload = serde_json::json!({
            "five_hour": {"used_percentage": 75.0, "resets_at": 9999999999u64},
            "seven_day": {"used_percentage": 30.0, "resets_at": 9999999999u64}
        });

        let updated = update_quota(dir.path(), &config, account, &payload).unwrap();
        assert!(updated);

        let state = load_state(dir.path()).unwrap();
        let q = state.get(1).unwrap();
        assert_eq!(q.five_hour_pct(), 75.0);
        assert_eq!(q.seven_day_pct(), 30.0);
    }

    #[test]
    fn update_quota_cursor_prevents_duplicate() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-2");
        std::fs::create_dir_all(&config).unwrap();
        let account = AccountNum::try_from(2u16).unwrap();

        let payload = serde_json::json!({
            "five_hour": {"used_percentage": 50.0, "resets_at": 9999999999u64}
        });

        // First call writes
        let first = update_quota(dir.path(), &config, account, &payload).unwrap();
        assert!(first);

        // Second call with same payload: cursor rejects
        let second = update_quota(dir.path(), &config, account, &payload).unwrap();
        assert!(!second);
    }

    #[test]
    fn update_quota_new_payload_accepted() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        let payload1 = serde_json::json!({"five_hour": {"used_percentage": 10.0, "resets_at": 9999999999u64}});
        update_quota(dir.path(), &config, account, &payload1).unwrap();

        let payload2 = serde_json::json!({"five_hour": {"used_percentage": 20.0, "resets_at": 9999999999u64}});
        let updated = update_quota(dir.path(), &config, account, &payload2).unwrap();
        assert!(updated);

        let state = load_state(dir.path()).unwrap();
        assert_eq!(state.get(3).unwrap().five_hour_pct(), 20.0);
    }
}
