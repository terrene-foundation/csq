//! Quota state management — load, save, update with payload-hash cursor.

use super::QuotaFile;
use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use std::path::{Path, PathBuf};

#[cfg(test)]
use super::{AccountQuota, UsageWindow};
#[cfg(test)]
use crate::platform::lock;
#[cfg(test)]
use crate::types::AccountNum;
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
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
///
/// VP-final R3: schema_version > 2 degrades to QuotaFile::empty() + WARN
/// instead of hard-erroring. This preserves rollback UX.
///
/// VP-final R5: account keys that are not valid u16 decimal strings are
/// rejected with ConfigError::InvalidJson naming the bad key.
pub fn load_state(base_dir: &Path) -> Result<QuotaFile, ConfigError> {
    let path = quota_path(base_dir);
    let mut quota_file = match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            let parsed: QuotaFile =
                serde_json::from_str(&content).map_err(|e| ConfigError::InvalidJson {
                    path: path.clone(),
                    reason: e.to_string(),
                })?;
            // VP-final R3: tolerate schema_version 1 (absent/default) and 2.
            // schema_version > 2 degrades to empty + WARN (not a hard error).
            if parsed.schema_version > 2 {
                tracing::warn!(
                    path = %path.display(),
                    schema_version = parsed.schema_version,
                    error_kind = "schema_version_newer",
                    "quota.json schema_version {} is newer than this csq binary supports. \
                     Degrading to empty quota state. Upgrade csq to preserve existing quota data.",
                    parsed.schema_version
                );
                return Ok(QuotaFile::empty());
            }
            // VP-final R5 + round-2 L1: validate that every account key is a
            // valid AccountNum (1..=999), not just any u16. Round 1 R5 accepted
            // "0" and "1000"; round 2 tightened to the newtype contract so
            // orphan entries can't accumulate in quota.json through
            // hand-edits or future-schema corruption.
            for key in parsed.accounts.keys() {
                let ok = key
                    .parse::<u16>()
                    .ok()
                    .and_then(|n| crate::types::AccountNum::try_from(n).ok())
                    .is_some();
                if !ok {
                    return Err(ConfigError::InvalidJson {
                        path: path.clone(),
                        reason: format!(
                            "quota.json account key '{}' is not a valid AccountNum \
                             (expected decimal 1..=999).",
                            key
                        ),
                    });
                }
            }
            parsed
        }
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
///
/// PR-C6 (v2.1.0): write path now emits `schema_version = 2` with
/// `surface` + `kind` fields on every record. PR-B8 (v2.0.1) read path
/// tolerates both v1 and v2, so a v2 file written here remains readable
/// if the user rolls back to v2.0.1. See spec 07 §7.4 + §7.6.2 and
/// journal 0018.
pub fn save_state(base_dir: &Path, quota_file: &QuotaFile) -> Result<(), ConfigError> {
    let path = quota_path(base_dir);
    // Write schema_version=2 on disk (PR-C6 write-path flip).
    let mut to_save = quota_file.clone();
    to_save.schema_version = 2;
    let json = serde_json::to_string_pretty(&to_save).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("serialization: {e}"),
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = crate::platform::fs::unique_tmp_path(&path);
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

/// Outcome of a quota.json v1→v2 migration attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// No `quota.json` existed at `base_dir` — nothing to migrate. The
    /// next write by a v2 poller will create a v2 file directly.
    NoFile,
    /// File exists and already carries `schema_version >= 2` — no
    /// rewrite performed.
    AlreadyV2 { schema_version: u32 },
    /// File existed at `schema_version < 2` and was rewritten in place
    /// with `schema_version = 2`. `account_count` is the number of
    /// account records that survived the read (expired windows are
    /// dropped by `load_state::clear_expired` before the rewrite).
    Migrated { account_count: usize },
}

/// Idempotently migrates a v1 `quota.json` to the v2 shape.
///
/// Runs at daemon startup, BEFORE `spawn_refresher` / `spawn_usage_poller`,
/// so live writers never race the migration. Steps:
///
/// 1. Peek at the raw file to read `schema_version`. If ≥ 2, return
///    [`MigrationOutcome::AlreadyV2`] without touching the file.
/// 2. Otherwise call [`load_state`] — serde defaults fill in
///    `surface = "claude-code"` and `kind = "utilization"` on every
///    record that was written by a v1 poller.
/// 3. Call [`save_state`], which now stamps `schema_version = 2` per
///    the PR-C6 write-path flip.
///
/// Crash-safety: [`save_state`] writes via `unique_tmp_path` +
/// `secure_file` + `atomic_replace`. A SIGKILL between tmp write and
/// rename leaves the original `quota.json` intact; the next daemon
/// start retries the migration against the unchanged v1 file. A
/// SIGKILL after rename leaves the new v2 file in place; subsequent
/// starts see `AlreadyV2` and no-op.
///
/// Idempotent: repeat calls against the same file produce no disk I/O
/// after the first successful migration.
///
/// Non-destructive: the round-trip preserves every account's
/// `updated_at`, `rate_limits`, `extras`, and all nested Gemini
/// reserved fields (`counter` / `rate_limit` / etc.) via
/// `#[serde(default)]`. The only intentional drop is windows whose
/// `resets_at` is already in the past (handled by `clear_expired`
/// inside `load_state`).
pub fn migrate_v1_to_v2_if_needed(base_dir: &Path) -> Result<MigrationOutcome, ConfigError> {
    let path = quota_path(base_dir);

    let content = match std::fs::read_to_string(&path) {
        Ok(c) if !c.trim().is_empty() => c,
        Ok(_) => return Ok(MigrationOutcome::NoFile),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(MigrationOutcome::NoFile),
        Err(e) => {
            return Err(ConfigError::InvalidJson {
                path,
                reason: format!("read: {e}"),
            })
        }
    };

    // Peek at schema_version without committing to the typed QuotaFile
    // shape — a v2-only field added later must not cause the peek to
    // panic. Missing/unparseable version is treated as 1.
    let raw: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("peek: {e}"),
        })?;
    let schema_version = raw
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;

    if schema_version >= 2 {
        tracing::debug!(schema_version, "quota.json already at v2 — migration no-op");
        return Ok(MigrationOutcome::AlreadyV2 { schema_version });
    }

    // load_state fills `surface` / `kind` defaults for every account and
    // drops expired windows; save_state writes v2 atomically.
    let parsed = load_state(base_dir)?;
    let account_count = parsed.accounts.len();
    save_state(base_dir, &parsed)?;

    tracing::info!(
        account_count,
        "quota.json migrated v1 → v2 (schema_version 2, surface/kind stamped)"
    );
    Ok(MigrationOutcome::Migrated { account_count })
}

/// Computes a deterministic hash of a rate_limits payload for cursor comparison.
#[cfg(test)]
pub fn payload_hash(payload: &serde_json::Value) -> String {
    let serialized = serde_json::to_string(payload).unwrap_or_default();
    let digest = Sha256::digest(serialized.as_bytes());
    hex::encode(&digest[..16]) // 32 hex chars is enough
}

/// Reads the last-processed payload hash for a config dir.
#[cfg(test)]
pub fn read_cursor(config_dir: &Path) -> Option<String> {
    std::fs::read_to_string(cursor_path(config_dir))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Writes the current payload hash to the config dir's cursor file.
#[cfg(test)]
pub fn write_cursor(config_dir: &Path, hash: &str) -> Result<(), ConfigError> {
    let path = cursor_path(config_dir);
    let tmp = crate::platform::fs::unique_tmp_path(&path);
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
/// **Test-only.** Production quota writes go through the daemon's usage
/// poller, which polls Anthropic's /api/oauth/usage directly per account.
///
/// Uses file locking on quota.json to prevent concurrent corruption.
/// Uses payload-hash cursor to reject stale data (after swap).
///
/// Returns true if quota was updated, false if skipped (stale/duplicate).
#[cfg(test)]
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
            ..Default::default()
        },
    );

    save_state(base_dir, &quota_file)?;

    // Write cursor after successful save
    write_cursor(config_dir, &new_hash)?;

    debug!(account = %account, "quota updated");
    Ok(true)
}

/// Parses a usage window from a rate_limits JSON object.
#[cfg(test)]
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
                updated_at: 100.0,
                ..Default::default()
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
                // resets_at in the past will be cleared on load
                five_hour: Some(UsageWindow {
                    used_percentage: 100.0,
                    resets_at: 1000,
                }),
                ..Default::default()
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

    // ─── PR-C6 migration tests ────────────────────────────────────

    fn write_raw_quota_json(base_dir: &Path, json: &str) {
        let path = quota_path(base_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, json).unwrap();
    }

    #[test]
    fn migrate_no_file_returns_no_file_outcome() {
        let dir = TempDir::new().unwrap();
        let out = migrate_v1_to_v2_if_needed(dir.path()).unwrap();
        assert_eq!(out, MigrationOutcome::NoFile);
        assert!(!quota_path(dir.path()).exists());
    }

    #[test]
    fn migrate_v1_file_rewrites_as_v2() {
        let dir = TempDir::new().unwrap();
        // Pure v1 shape: no schema_version, no surface, no kind.
        let v1 = r#"{
            "accounts": {
                "1": {
                    "five_hour": {"used_percentage": 42.0, "resets_at": 4102444800},
                    "seven_day": {"used_percentage": 10.0, "resets_at": 4102444900},
                    "updated_at": 100.0
                }
            }
        }"#;
        write_raw_quota_json(dir.path(), v1);

        let out = migrate_v1_to_v2_if_needed(dir.path()).unwrap();
        assert_eq!(out, MigrationOutcome::Migrated { account_count: 1 });

        // Re-read the raw file and confirm schema_version=2 + surface/kind
        // are now physically present.
        let raw = std::fs::read_to_string(quota_path(dir.path())).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["schema_version"].as_u64(), Some(2));
        let acct = &value["accounts"]["1"];
        assert_eq!(acct["surface"].as_str(), Some("claude-code"));
        assert_eq!(acct["kind"].as_str(), Some("utilization"));
        // Non-destructive: the original utilization + resets_at survived.
        assert_eq!(acct["five_hour"]["used_percentage"].as_f64(), Some(42.0));
        assert_eq!(acct["five_hour"]["resets_at"].as_u64(), Some(4102444800));
        assert_eq!(acct["updated_at"].as_f64(), Some(100.0));
    }

    #[test]
    fn migrate_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let v1 = r#"{
            "accounts": {
                "2": {
                    "five_hour": {"used_percentage": 5.0, "resets_at": 4102444800},
                    "updated_at": 50.0
                }
            }
        }"#;
        write_raw_quota_json(dir.path(), v1);

        // First call migrates.
        let first = migrate_v1_to_v2_if_needed(dir.path()).unwrap();
        assert!(matches!(first, MigrationOutcome::Migrated { .. }));

        // Capture the post-migration file bytes.
        let after_first = std::fs::read_to_string(quota_path(dir.path())).unwrap();

        // Second call must be a no-op (AlreadyV2) AND must not touch the file.
        let second = migrate_v1_to_v2_if_needed(dir.path()).unwrap();
        assert_eq!(second, MigrationOutcome::AlreadyV2 { schema_version: 2 });

        let after_second = std::fs::read_to_string(quota_path(dir.path())).unwrap();
        assert_eq!(
            after_first, after_second,
            "idempotent migration must not rewrite the file"
        );
    }

    #[test]
    fn migrate_preserves_extras_and_counter_fields() {
        let dir = TempDir::new().unwrap();
        // A v1-ish file that already carries Gemini-reserved fields and
        // an `extras` escape hatch (e.g. a pre-migration write from a
        // Codex prototype build). Migration must not drop them.
        let v1_with_extras = r#"{
            "accounts": {
                "7": {
                    "five_hour": {"used_percentage": 8.0, "resets_at": 4102444800},
                    "updated_at": 60.0,
                    "counter": {"requests_today": 42, "resets_at_tz": "America/Los_Angeles"},
                    "extras": {"codex_plan": "team", "nested": {"x": 42}}
                }
            }
        }"#;
        write_raw_quota_json(dir.path(), v1_with_extras);

        let out = migrate_v1_to_v2_if_needed(dir.path()).unwrap();
        assert_eq!(out, MigrationOutcome::Migrated { account_count: 1 });

        let raw = std::fs::read_to_string(quota_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schema_version"].as_u64(), Some(2));
        assert_eq!(
            v["accounts"]["7"]["counter"]["requests_today"].as_u64(),
            Some(42)
        );
        assert_eq!(
            v["accounts"]["7"]["extras"]["codex_plan"].as_str(),
            Some("team")
        );
        assert_eq!(
            v["accounts"]["7"]["extras"]["nested"]["x"].as_i64(),
            Some(42)
        );
    }

    #[test]
    fn migrate_empty_file_returns_no_file() {
        let dir = TempDir::new().unwrap();
        write_raw_quota_json(dir.path(), "   \n  ");
        let out = migrate_v1_to_v2_if_needed(dir.path()).unwrap();
        // Whitespace-only content is treated as "nothing to migrate"
        // — save_state would have created a schema_version=1 empty
        // file which is still "absent" for migration purposes.
        assert_eq!(out, MigrationOutcome::NoFile);
    }

    #[test]
    fn migrate_malformed_schema_version_propagates_error() {
        let dir = TempDir::new().unwrap();
        // schema_version as a string — the peek falls back to v1 and
        // load_state's typed parse rejects the non-u32 value. Migration
        // returns an error rather than silently rewriting a corrupt
        // file; the operator must fix or delete the bad file.
        let weird = r#"{
            "schema_version": "not-a-number",
            "accounts": {
                "3": {"updated_at": 0.0}
            }
        }"#;
        write_raw_quota_json(dir.path(), weird);
        assert!(migrate_v1_to_v2_if_needed(dir.path()).is_err());
    }

    #[test]
    fn save_state_stamps_schema_version_two() {
        let dir = TempDir::new().unwrap();
        let qf = QuotaFile::empty();
        save_state(dir.path(), &qf).unwrap();

        let raw = std::fs::read_to_string(quota_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schema_version"].as_u64(), Some(2));
    }

    #[test]
    fn update_quota_new_payload_accepted() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        let payload1 =
            serde_json::json!({"five_hour": {"used_percentage": 10.0, "resets_at": 9999999999u64}});
        update_quota(dir.path(), &config, account, &payload1).unwrap();

        let payload2 =
            serde_json::json!({"five_hour": {"used_percentage": 20.0, "resets_at": 9999999999u64}});
        let updated = update_quota(dir.path(), &config, account, &payload2).unwrap();
        assert!(updated);

        let state = load_state(dir.path()).unwrap();
        assert_eq!(state.get(3).unwrap().five_hour_pct(), 20.0);
    }
}
