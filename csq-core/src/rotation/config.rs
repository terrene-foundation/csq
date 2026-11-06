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
//!
//! Defaults apply ONLY to an absent file; any other read failure, including an
//! empty or whitespace-only file, is an error ([`load`]).

use crate::error::ConfigError;
use crate::platform::fs::{
    read_private_regular_nofollow_bounded, write_private_tmp_synced_retained,
};
use crate::platform::lock::{try_lock_file_bounded_nofollow, FileLockGuard};
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

/// Returns the path of the writer lock for `rotation.json`.
pub fn lock_path(base_dir: &Path) -> PathBuf {
    base_dir.join(".rotation.json.lock")
}

/// Upper bound on `rotation.json`; the real file is a few dozen bytes.
const CONFIG_MAX_BYTES: u64 = 64 * 1024;

/// Fixed-vocabulary reason for an unreadable `rotation.json`. Carries the I/O
/// error KIND only, never the OS message (which can embed a path).
fn unreadable(path: &Path, error: &std::io::Error) -> ConfigError {
    ConfigError::InvalidJson {
        path: path.to_path_buf(),
        reason: format!("read: {}", error.kind()),
    }
}

/// Loads `RotationConfig` from `{base_dir}/rotation.json`.
///
/// Defaults are returned ONLY when the file is genuinely absent (a missing
/// file, confirmed by [`crate::platform::fs::confirm_absent`] inside the
/// reader). Every other failure — an empty or whitespace-only file (csq's
/// atomic `save` never produces one, so it is outside truncation that may have
/// dropped `exclude_accounts`), permission denied, a directory or
/// symlink at the path, a foreign-owned or group/other-writable file, a file
/// over 64 KiB, non-UTF-8 bytes, invalid JSON — is an error: the
/// file holds `exclude_accounts`, a refusing policy for credential rebinding,
/// so "cannot read" must never read as "no exclusions"
/// (`guard-reader-writer-parity.md` MUST-2). The read goes through the bounded,
/// no-follow, owner-checked [`read_private_regular_nofollow_bounded`].
pub fn load(base_dir: &Path) -> Result<RotationConfig, ConfigError> {
    let path = config_path(base_dir);
    let bytes = match read_private_regular_nofollow_bounded(&path, CONFIG_MAX_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(RotationConfig::default()),
        Err(e) => return Err(unreadable(&path, &e)),
    };
    let content = std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidJson {
        path: path.clone(),
        reason: "read: not valid UTF-8".to_string(),
    })?;
    if content.trim().is_empty() {
        // `save` is atomic, so csq never produces an empty file: it is outside
        // truncation that may have dropped `exclude_accounts`. Fail closed, the
        // same as every other unreadable form (the rotator rotates nothing and
        // the writers refuse to overwrite it).
        return Err(ConfigError::InvalidJson {
            path,
            reason: "read: empty file".to_string(),
        });
    }
    serde_json::from_str::<RotationConfig>(content).map_err(|e| ConfigError::InvalidJson {
        path,
        reason: e.to_string(),
    })
}

/// How long a writer waits for another writer of `rotation.json`: 100 attempts
/// at 20 ms, an enforced ceiling of about 2 s ([`try_lock_file_bounded_nofollow`]).
const LOCK_ATTEMPTS: u32 = 100;
const LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(20);

/// Takes the exclusive writer lock, creating the base dir if needed. A busy or
/// broken lock is an error and nothing is read or written.
fn lock_for_write(base_dir: &Path) -> Result<FileLockGuard, ConfigError> {
    let lock = lock_path(base_dir);
    std::fs::create_dir_all(base_dir).map_err(|e| ConfigError::InvalidJson {
        path: base_dir.to_path_buf(),
        reason: format!("create dir: {}", e.kind()),
    })?;
    match try_lock_file_bounded_nofollow(&lock, LOCK_ATTEMPTS, LOCK_DELAY) {
        Ok(Some(guard)) => Ok(guard),
        // Busy past the bound, or a refused/damaged lock file: one fixed message
        // that names the lock file to remove.
        Ok(None) | Err(_) => Err(ConfigError::Locked { path: lock }),
    }
}

/// Saves `RotationConfig` to `{base_dir}/rotation.json` atomically.
///
/// The file is staged through [`write_private_tmp_synced_retained`] (owner-only
/// `0o600`, fsynced, creating-writer cleanup on every failure branch) and then
/// published with a rename, so a crash never leaves a torn `rotation.json` and
/// an older world-readable file is replaced by an owner-only one
/// (`rules/security.md` MUST 4, 5, 5a). Every failure is surfaced — nothing is
/// swallowed.
pub fn save(base_dir: &Path, cfg: &RotationConfig) -> Result<(), ConfigError> {
    let path = config_path(base_dir);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::InvalidJson {
            path: parent.to_path_buf(),
            reason: format!("create dir: {e}"),
        })?;
    }

    let json = serde_json::to_string_pretty(cfg).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("serialization: {e}"),
    })?;

    let writer = write_private_tmp_synced_retained(&path, json.as_bytes()).map_err(|e| {
        ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("write: {e}"),
        }
    })?;
    writer
        .replace(&path)
        .map_err(|e| ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("atomic replace: {e}"),
        })?;

    Ok(())
}

/// Inclusive lower bound for `threshold_percent` accepted by [`update`].
pub const THRESHOLD_MIN_PERCENT: f64 = 1.0;
/// Inclusive upper bound for `threshold_percent` accepted by [`update`].
pub const THRESHOLD_MAX_PERCENT: f64 = 100.0;
/// Inclusive lower bound (seconds) for `cooldown_secs` accepted by [`update`].
pub const COOLDOWN_MIN_SECS: u64 = 1;
/// Inclusive upper bound (seconds, 24 h) for `cooldown_secs` accepted by [`update`].
pub const COOLDOWN_MAX_SECS: u64 = 86_400;

/// Fixed refusal text for an out-of-range or non-finite threshold.
pub const THRESHOLD_RANGE_MESSAGE: &str = "threshold must be a number from 1 to 100";
/// Fixed refusal text for an out-of-range cooldown.
pub const COOLDOWN_RANGE_MESSAGE: &str =
    "cooldown must be a whole number of seconds from 1 to 86400";
/// Fixed refusal text for an `update` that changes nothing.
pub const NOTHING_TO_UPDATE_MESSAGE: &str = "give --threshold, --cooldown, or both";

/// Why [`update`] or [`set_enabled`] did not write `rotation.json`.
#[derive(Debug, thiserror::Error)]
pub enum RotationUpdateError {
    /// The requested value was refused before anything was read or written.
    /// The text is one of the fixed `*_MESSAGE` constants — it never embeds
    /// the offending input.
    #[error("{0}")]
    Invalid(&'static str),
    /// `rotation.json` could not be read, parsed or written.
    #[error(transparent)]
    Config(#[from] ConfigError),
}

impl RotationUpdateError {
    /// Message safe to show an operator or send across the desktop IPC
    /// boundary: fixed text for a refusal, the path-redacted config message
    /// otherwise.
    pub fn redacted_message(&self) -> String {
        match self {
            RotationUpdateError::Invalid(message) => (*message).to_string(),
            RotationUpdateError::Config(error) => error.redacted_message(),
        }
    }
}

/// Turns auto-rotation on or off: load `rotation.json`, set `enabled`,
/// save it, and return what was written. The ONE write path shared by
/// `csq rotation on|off` and the desktop `set_rotation_enabled` command.
///
/// An unreadable or unparseable existing file is an error — it is never
/// overwritten with defaults, so the operator's other settings are not silently
/// destroyed. The load-modify-save runs under an exclusive lock on
/// [`lock_path`], so a concurrent CLI or desktop writer cannot interleave and
/// lose an update; a busy lock is an error and nothing is written.
pub fn set_enabled(base_dir: &Path, enabled: bool) -> Result<RotationConfig, ConfigError> {
    let _lock = lock_for_write(base_dir)?;
    let mut cfg = load(base_dir)?;
    cfg.enabled = enabled;
    save(base_dir, &cfg)?;
    Ok(cfg)
}

/// Changes the rotation threshold and/or cooldown, leaving `enabled` and
/// `exclude_accounts` untouched, and returns what was written. Both values
/// are validated BEFORE the file is read; a refusal writes nothing.
///
/// `threshold_percent` must be finite and within
/// [`THRESHOLD_MIN_PERCENT`]..=[`THRESHOLD_MAX_PERCENT`]; `cooldown_secs`
/// within [`COOLDOWN_MIN_SECS`]..=[`COOLDOWN_MAX_SECS`]. Passing neither is
/// refused ([`NOTHING_TO_UPDATE_MESSAGE`]). Locked and unreadable-file
/// behaviour is that of [`set_enabled`].
pub fn update(
    base_dir: &Path,
    threshold_percent: Option<f64>,
    cooldown_secs: Option<u64>,
) -> Result<RotationConfig, RotationUpdateError> {
    if threshold_percent.is_none() && cooldown_secs.is_none() {
        return Err(RotationUpdateError::Invalid(NOTHING_TO_UPDATE_MESSAGE));
    }
    if let Some(t) = threshold_percent {
        if !t.is_finite() || !(THRESHOLD_MIN_PERCENT..=THRESHOLD_MAX_PERCENT).contains(&t) {
            return Err(RotationUpdateError::Invalid(THRESHOLD_RANGE_MESSAGE));
        }
    }
    if let Some(c) = cooldown_secs {
        if !(COOLDOWN_MIN_SECS..=COOLDOWN_MAX_SECS).contains(&c) {
            return Err(RotationUpdateError::Invalid(COOLDOWN_RANGE_MESSAGE));
        }
    }

    let _lock = lock_for_write(base_dir)?;
    let mut cfg = load(base_dir)?;
    if let Some(t) = threshold_percent {
        cfg.threshold_percent = t;
    }
    if let Some(c) = cooldown_secs {
        cfg.cooldown_secs = c;
    }
    save(base_dir, &cfg)?;
    Ok(cfg)
}

/// The one-line auto-rotate summary printed by `csq status` and `csq doctor`
/// (and used by `csq rotation status`), so the surfaces cannot drift apart.
/// Fixed vocabulary: no paths, no raw parse errors.
pub fn summary_line(base_dir: &Path) -> String {
    match load(base_dir) {
        Ok(cfg) if cfg.enabled => format!(
            "Auto-rotate: on (threshold {}%, cooldown {}s)",
            format_percent(cfg.threshold_percent),
            cfg.cooldown_secs
        ),
        Ok(_) => "Auto-rotate: off (turn on with `csq rotation on`)".to_string(),
        Err(_) => {
            "Auto-rotate: unknown (rotation.json is unreadable; fix or remove it)".to_string()
        }
    }
}

/// Renders a percentage without a trailing `.0` for whole numbers.
pub fn format_percent(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
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

    /// N2: an empty or whitespace-only file is an error, never "no exclusions".
    #[test]
    fn empty_or_blank_file_is_an_error_and_writers_refuse_to_overwrite_it() {
        for body in [&b""[..], &b" \n\t "[..]] {
            let dir = TempDir::new().unwrap();
            std::fs::write(config_path(dir.path()), body).unwrap();
            match load(dir.path()).unwrap_err() {
                ConfigError::InvalidJson { reason, .. } => assert_eq!(reason, "read: empty file"),
                other => panic!("unexpected error variant: {other:?}"),
            }
            assert!(set_enabled(dir.path(), true).is_err());
            assert!(update(dir.path(), Some(50.0), None).is_err());
            assert_eq!(std::fs::read(config_path(dir.path())).unwrap(), body);
        }
    }

    // ── set_enabled / update / summary_line (shared CLI + desktop core) ──

    #[test]
    fn set_enabled_writes_and_round_trips() {
        let dir = TempDir::new().unwrap();
        assert!(!load(dir.path()).unwrap().enabled);

        let on = set_enabled(dir.path(), true).unwrap();
        assert!(on.enabled);
        assert!(load(dir.path()).unwrap().enabled, "file must hold `true`");

        let off = set_enabled(dir.path(), false).unwrap();
        assert!(!off.enabled);
        assert!(!load(dir.path()).unwrap().enabled, "file must hold `false`");
    }

    #[test]
    fn set_enabled_preserves_the_other_fields() {
        let dir = TempDir::new().unwrap();
        save(
            dir.path(),
            &RotationConfig {
                enabled: false,
                threshold_percent: 80.0,
                cooldown_secs: 120,
                exclude_accounts: vec![3, 7],
            },
        )
        .unwrap();

        set_enabled(dir.path(), true).unwrap();

        assert_eq!(
            load(dir.path()).unwrap(),
            RotationConfig {
                enabled: true,
                threshold_percent: 80.0,
                cooldown_secs: 120,
                exclude_accounts: vec![3, 7],
            }
        );
    }

    #[test]
    fn set_enabled_refuses_a_corrupt_file_and_leaves_it_untouched() {
        let dir = TempDir::new().unwrap();
        std::fs::write(config_path(dir.path()), b"{not valid json").unwrap();

        assert!(set_enabled(dir.path(), true).is_err());

        assert_eq!(
            std::fs::read(config_path(dir.path())).unwrap(),
            b"{not valid json",
            "a corrupt file must not be replaced by defaults"
        );
    }

    #[test]
    fn update_changes_only_what_was_given() {
        let dir = TempDir::new().unwrap();
        save(
            dir.path(),
            &RotationConfig {
                enabled: true,
                threshold_percent: 90.0,
                cooldown_secs: 600,
                exclude_accounts: vec![2],
            },
        )
        .unwrap();

        let t = update(dir.path(), Some(75.5), None).unwrap();
        assert_eq!((t.threshold_percent, t.cooldown_secs), (75.5, 600));
        let c = update(dir.path(), None, Some(45)).unwrap();
        assert_eq!((c.threshold_percent, c.cooldown_secs), (75.5, 45));

        let on_disk = load(dir.path()).unwrap();
        assert_eq!(on_disk, c);
        assert!(on_disk.enabled);
        assert_eq!(on_disk.exclude_accounts, vec![2]);
    }

    #[test]
    fn update_accepts_the_inclusive_bounds() {
        let dir = TempDir::new().unwrap();
        for (t, c) in [(1.0, 1), (100.0, 86_400)] {
            let cfg = update(dir.path(), Some(t), Some(c)).unwrap();
            assert_eq!((cfg.threshold_percent, cfg.cooldown_secs), (t, c));
        }
    }

    #[test]
    fn update_refuses_out_of_range_with_fixed_text_and_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let bad_threshold = [0.0, 0.99, 100.01, -5.0, f64::NAN, f64::INFINITY];
        for t in bad_threshold {
            let err = update(dir.path(), Some(t), None).unwrap_err();
            assert_eq!(err.to_string(), THRESHOLD_RANGE_MESSAGE, "threshold {t}");
            assert_eq!(err.redacted_message(), THRESHOLD_RANGE_MESSAGE);
        }
        for c in [0u64, 86_401, u64::MAX] {
            let err = update(dir.path(), None, Some(c)).unwrap_err();
            assert_eq!(err.to_string(), COOLDOWN_RANGE_MESSAGE, "cooldown {c}");
        }
        // One valid + one invalid value refuses the whole update.
        assert!(update(dir.path(), Some(50.0), Some(0)).is_err());
        assert!(
            !config_path(dir.path()).exists(),
            "a refused update must not create rotation.json"
        );
    }

    #[test]
    fn update_with_nothing_is_refused() {
        let dir = TempDir::new().unwrap();
        let err = update(dir.path(), None, None).unwrap_err();
        assert_eq!(err.to_string(), NOTHING_TO_UPDATE_MESSAGE);
        assert!(!config_path(dir.path()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only_even_over_a_world_readable_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = config_path(dir.path());
        std::fs::write(&path, br#"{"enabled": false}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        set_enabled(dir.path(), true).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let fresh = TempDir::new().unwrap();
        update(fresh.path(), Some(50.0), None).unwrap();
        let mode = std::fs::metadata(config_path(fresh.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn saving_leaves_no_staging_files_behind() {
        let dir = TempDir::new().unwrap();
        set_enabled(dir.path(), true).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        // `rotation.json` plus, on Unix, the (empty, persistent) writer lock
        // file; no `.tmp` stage. Windows locks are named mutexes and leave no
        // file behind.
        let mut expected = vec!["rotation.json".to_string()];
        if cfg!(unix) {
            expected.insert(0, ".rotation.json.lock".to_string());
        }
        assert_eq!(names, expected);
    }

    #[test]
    fn summary_line_reports_off_on_and_unreadable() {
        let dir = TempDir::new().unwrap();
        assert!(summary_line(dir.path()).starts_with("Auto-rotate: off"));

        update(dir.path(), Some(80.0), Some(120)).unwrap();
        set_enabled(dir.path(), true).unwrap();
        assert_eq!(
            summary_line(dir.path()),
            "Auto-rotate: on (threshold 80%, cooldown 120s)"
        );

        std::fs::write(config_path(dir.path()), b"{not valid json").unwrap();
        let line = summary_line(dir.path());
        assert!(line.starts_with("Auto-rotate: unknown"), "{line}");
        assert!(
            !line.contains(dir.path().to_str().unwrap()),
            "no path: {line}"
        );
    }

    #[test]
    fn format_percent_drops_trailing_zero_only_for_whole_numbers() {
        assert_eq!(format_percent(95.0), "95");
        assert_eq!(format_percent(95.5), "95.5");
    }

    // ── S1: unreadable is an error, never defaults ──

    #[test]
    fn non_utf8_file_is_an_error_not_defaults() {
        let dir = TempDir::new().unwrap();
        std::fs::write(config_path(dir.path()), [0xffu8]).unwrap();
        assert!(
            load(dir.path()).is_err(),
            "a non-UTF-8 file must not read as defaults"
        );
    }

    #[test]
    fn directory_in_place_of_the_file_is_an_error() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(config_path(dir.path())).unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn mode_000_file_is_an_error_not_defaults() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = config_path(dir.path());
        std::fs::write(&path, br#"{"exclude_accounts":[2]}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A superuser can still read a mode-000 file; only assert where the OS refuses.
        if std::fs::read(&path).is_err() {
            assert!(load(dir.path()).is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_file_is_an_error_not_followed() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("elsewhere.json");
        std::fs::write(&target, br#"{"enabled":true}"#).unwrap();
        std::os::unix::fs::symlink(&target, config_path(dir.path())).unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn oversized_file_is_an_error() {
        let dir = TempDir::new().unwrap();
        let mut body = br#"{"exclude_accounts":["#.to_vec();
        body.extend(std::iter::repeat_n(b' ', 128 * 1024));
        body.extend_from_slice(b"]}");
        std::fs::write(config_path(dir.path()), body).unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn set_enabled_and_update_leave_an_unreadable_file_untouched() {
        let dir = TempDir::new().unwrap();
        std::fs::write(config_path(dir.path()), [0xffu8, 0xfe, b'{']).unwrap();

        assert!(set_enabled(dir.path(), true).is_err());
        assert!(update(dir.path(), Some(50.0), None).is_err());

        assert_eq!(
            std::fs::read(config_path(dir.path())).unwrap(),
            vec![0xffu8, 0xfe, b'{'],
            "an unreadable file must not be replaced by defaults"
        );
    }

    #[test]
    fn unreadable_read_error_reason_is_fixed_vocabulary() {
        let dir = TempDir::new().unwrap();
        std::fs::write(config_path(dir.path()), [0xffu8]).unwrap();
        match load(dir.path()).unwrap_err() {
            ConfigError::InvalidJson { reason, .. } => {
                assert_eq!(reason, "read: not valid UTF-8");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        // An I/O failure reports the error KIND only, never the OS message/path.
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(config_path(dir.path())).unwrap();
        match load(dir.path()).unwrap_err() {
            ConfigError::InvalidJson { reason, .. } => {
                assert!(reason.starts_with("read: "), "{reason}");
                assert!(!reason.contains(dir.path().to_str().unwrap()), "{reason}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    // ── S3: one writer at a time ──

    #[test]
    fn writers_refuse_while_another_process_holds_the_lock() {
        let dir = TempDir::new().unwrap();
        // The lock is held on ANOTHER thread: Windows locks are re-entrant on
        // the holding thread, so a same-thread holder never reaches the
        // contended branch there. Same nofollow lock the writers take, so the
        // Unix lock file keeps the mode the writers accept after release.
        let lock = lock_path(dir.path());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let guard = crate::platform::lock::try_lock_file_bounded_nofollow(
                &lock,
                1,
                std::time::Duration::from_millis(1),
            )
            .unwrap()
            .expect("test takes the free lock");
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv();
            drop(guard);
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("holder thread took the lock");

        assert!(matches!(
            set_enabled(dir.path(), true),
            Err(ConfigError::Locked { .. })
        ));
        assert!(update(dir.path(), Some(50.0), None).is_err());
        // N4: fixed text that names the lock file to remove; no "invalid JSON".
        let message = set_enabled(dir.path(), true)
            .unwrap_err()
            .redacted_message();
        assert!(message.contains(".rotation.json.lock"), "{message}");
        assert!(message.contains("remove that file"), "{message}");
        assert!(!message.contains("invalid JSON"), "{message}");
        assert!(
            !config_path(dir.path()).exists(),
            "a writer that could not take the lock must write nothing"
        );

        drop(release_tx);
        holder.join().unwrap();
        assert!(set_enabled(dir.path(), true).unwrap().enabled);
    }

    #[test]
    fn concurrent_writers_do_not_lose_an_update() {
        use std::sync::{Arc, Barrier};
        for round in 0..100 {
            let dir = TempDir::new().unwrap();
            let base = Arc::new(dir.path().to_path_buf());
            let barrier = Arc::new(Barrier::new(2));
            let (b1, p1, b2, p2) = (barrier.clone(), base.clone(), barrier, base.clone());
            let a = std::thread::spawn(move || {
                b1.wait();
                set_enabled(&p1, true).unwrap();
            });
            let b = std::thread::spawn(move || {
                b2.wait();
                update(&p2, Some(50.0), Some(77)).unwrap();
            });
            a.join().unwrap();
            b.join().unwrap();
            let cfg = load(&base).unwrap();
            assert!(cfg.enabled, "round {round}: `enabled` update was lost");
            assert_eq!(
                (cfg.threshold_percent, cfg.cooldown_secs),
                (50.0, 77),
                "round {round}: threshold/cooldown update was lost"
            );
        }
    }
}
