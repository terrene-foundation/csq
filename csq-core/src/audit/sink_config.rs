//! Operator configuration for `LedgerSink` — `audit.sink` + per-sink
//! cadence.  Loaded from `~/.claude/accounts/audit-sink.json`.
//!
//! # On-disk format
//!
//! ```json
//! {
//!   "sink": "rekor",
//!   "rekor": { "cadence": "1d", "cadence_high_impact": "immediate" },
//!   "s3": { "cadence": "1d", "cadence_high_impact": "immediate" }
//! }
//! ```
//!
//! The `sink` field is the active sink name (`"none"` when disabled). Per
//! workspace-owner decision §5 the default is `"none"` — no external sink.
//!
//! # Fail-loud on not-compiled-in sink
//!
//! `validate_sink_compiled_in` returns the canonical error message:
//! ```text
//! csq: requested sink '<name>' was not compiled into this build.
//! Rebuild with --features <name>-sink or install a csq release that includes it.
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

/// Error from sink-config operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SinkConfigError {
    /// The operator requested a sink that was not compiled into this binary.
    #[error(
        "csq: requested sink '{sink}' was not compiled into this build.\n\
        Rebuild with --features {sink}-sink or install a csq release that includes it."
    )]
    NotCompiledIn {
        /// The sink name the operator tried to activate.
        sink: String,
    },
    /// The sink name is not a recognised value.
    #[error("csq: unknown sink name '{name}'; valid values: none, rekor, s3, azure, gcp, azure-sql (also csq-ledger when compiled with --features csq-ledger-sink)")]
    UnknownSink {
        /// The unrecognised value.
        name: String,
    },
    /// An I/O error while reading or writing the config file.
    #[error("audit sink config i/o error: {message}")]
    Io {
        /// Operator-facing reason.
        message: String,
    },
    /// JSON parse / serialisation error.
    #[error("audit sink config json error: {message}")]
    Json {
        /// Operator-facing reason.
        message: String,
    },
}

/// Per-sink cadence configuration.
///
/// `cadence` is an operator-supplied string: `"1d"`, `"6h"`, `"immediate"`,
/// or `"none"`. The daemon scheduler interprets these at runtime; the
/// config layer just stores and validates the raw strings.
///
/// Documented defaults (per workspace-owner decision §5 and spec 15 §15.5):
/// - `rekor`: `cadence = "1d"`, `cadence_high_impact = "immediate"`
/// - `s3`, `azure`, `gcp`: `cadence = "1d"`, `cadence_high_impact = "1d"`
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SinkCadenceConfig {
    /// Regular replication cadence (e.g. `"1d"`, `"6h"`, `"immediate"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cadence: Option<String>,
    /// Cadence for high-impact operations (key rotate, release auth, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cadence_high_impact: Option<String>,
    /// When `true`, a sink failure BLOCKS the corresponding csq operation
    /// (opt-in per workspace-owner decision §5 and For-Discussion #2).
    /// Default: `false` (failures queue to `.pending-<sink>/` for daemon drain).
    #[serde(default, skip_serializing_if = "is_false")]
    pub fail_loud: bool,
}

/// The top-level on-disk sink configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkConfig {
    /// Active sink name. `"none"` = local-only (default).
    #[serde(default = "default_sink_name")]
    pub sink: String,

    /// Rekor cadence when `sink = "rekor"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekor: Option<SinkCadenceConfig>,
    /// S3 Object Lock cadence when `sink = "s3"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<SinkCadenceConfig>,
    /// Azure Immutable Blob cadence when `sink = "azure"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<SinkCadenceConfig>,
    /// GCP Bucket Lock cadence when `sink = "gcp"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp: Option<SinkCadenceConfig>,
    /// Azure SQL ledger-table cadence when `sink = "azure-sql"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "azure-sql")]
    pub azure_sql: Option<SinkCadenceConfig>,
    /// csq-ledger cadence when `sink = "csq-ledger"` (lands in M10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "csq-ledger")]
    pub csq_ledger: Option<SinkCadenceConfig>,
}

fn default_sink_name() -> String {
    "none".to_string()
}

impl Default for AuditSinkConfig {
    fn default() -> Self {
        Self {
            sink: default_sink_name(),
            rekor: None,
            s3: None,
            azure: None,
            gcp: None,
            azure_sql: None,
            csq_ledger: None,
        }
    }
}

/// All recognised sink names (including `none`).
const RECOGNISED_SINK_NAMES: &[&str] = &[
    "none",
    "rekor",
    "s3",
    "azure",
    "gcp",
    "azure-sql",
    "csq-ledger",
];

impl AuditSinkConfig {
    /// Returns the path of the sink config file under `base_dir`.
    pub fn path(base_dir: &Path) -> std::path::PathBuf {
        base_dir.join("audit-sink.json")
    }

    /// Reads the config from disk.  Returns the default (sink = "none")
    /// when the file does not exist.
    pub fn load(base_dir: &Path) -> Result<Self, SinkConfigError> {
        let path = Self::path(base_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| SinkConfigError::Io {
            message: format!("read audit-sink.json: {e}"),
        })?;
        serde_json::from_str(&raw).map_err(|e| SinkConfigError::Json {
            message: format!("parse audit-sink.json: {e}"),
        })
    }

    /// Writes the config to disk atomically (creates or overwrites).
    ///
    /// Uses `unique_tmp_path → write → secure_file(0o600) → atomic_replace`
    /// with `remove_file(&tmp)` on every failure branch per
    /// `rules/security.md §4` (atomic writes) and `§5` (0o600 permissions).
    /// The payload is non-secret, so §5a partial-cleanup is not strictly
    /// required, but the full cleanup pattern is applied for consistency with
    /// `chain_state.rs::save`.
    pub fn save(&self, base_dir: &Path) -> Result<(), SinkConfigError> {
        let path = Self::path(base_dir);

        // Ensure parent directory exists before taking a tmp path.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SinkConfigError::Io {
                message: format!("create parent dir for audit-sink.json: {e}"),
            })?;
        }

        let json = serde_json::to_string_pretty(self).map_err(|e| SinkConfigError::Json {
            message: format!("serialise audit-sink.json: {e}"),
        })?;

        // §4 + §5: unique_tmp_path → write → secure_file → atomic_replace,
        // with remove_file(&tmp) on every failure branch.
        let tmp = unique_tmp_path(&path);

        if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(SinkConfigError::Io {
                message: format!("write tmp for audit-sink.json: {e}"),
            });
        }

        if let Err(e) = secure_file(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(SinkConfigError::Io {
                message: format!("secure_file for audit-sink.json: {e}"),
            });
        }

        if let Err(e) = atomic_replace(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(SinkConfigError::Io {
                message: format!("atomic_replace for audit-sink.json: {e}"),
            });
        }

        Ok(())
    }

    /// Sets `audit.sink = <name>` after validating the name and checking
    /// that the requested sink was compiled into this binary.
    ///
    /// # Errors
    ///
    /// Returns [`SinkConfigError::UnknownSink`] for unrecognised names.
    /// Returns [`SinkConfigError::NotCompiledIn`] for known sinks that
    /// were not compiled in (i.e. their feature flag was off at build time).
    pub fn set_sink(&mut self, name: &str) -> Result<(), SinkConfigError> {
        if !RECOGNISED_SINK_NAMES.contains(&name) {
            return Err(SinkConfigError::UnknownSink {
                name: name.to_string(),
            });
        }
        validate_sink_compiled_in(name)?;
        self.sink = name.to_string();
        Ok(())
    }

    /// Sets the cadence for `sink_name` (e.g. `"rekor"`) from a key=value
    /// string.  Key may be `"cadence"`, `"cadence-high-impact"`, or
    /// `"fail-loud"`.
    ///
    /// # Examples
    ///
    /// ```text
    /// config.set_sink_cadence("rekor", "cadence", "6h")
    /// config.set_sink_cadence("rekor", "cadence-high-impact", "immediate")
    /// config.set_sink_cadence("rekor", "fail-loud", "true")
    /// ```
    pub fn set_sink_cadence(
        &mut self,
        sink_name: &str,
        key: &str,
        value: &str,
    ) -> Result<(), SinkConfigError> {
        if !RECOGNISED_SINK_NAMES.contains(&sink_name) || sink_name == "none" {
            return Err(SinkConfigError::UnknownSink {
                name: sink_name.to_string(),
            });
        }
        let entry = self.cadence_for_mut(sink_name);
        match key {
            "cadence" => entry.cadence = Some(value.to_string()),
            "cadence-high-impact" => entry.cadence_high_impact = Some(value.to_string()),
            "fail-loud" => {
                entry.fail_loud = matches!(value, "true" | "1" | "yes");
            }
            other => {
                return Err(SinkConfigError::UnknownSink {
                    name: format!("unknown cadence key '{}' for sink '{}'", other, sink_name),
                });
            }
        }
        Ok(())
    }

    /// Returns the cadence config for `sink_name`, creating it if absent.
    fn cadence_for_mut(&mut self, sink_name: &str) -> &mut SinkCadenceConfig {
        match sink_name {
            "rekor" => self.rekor.get_or_insert_with(SinkCadenceConfig::default),
            "s3" => self.s3.get_or_insert_with(SinkCadenceConfig::default),
            "azure" => self.azure.get_or_insert_with(SinkCadenceConfig::default),
            "gcp" => self.gcp.get_or_insert_with(SinkCadenceConfig::default),
            "azure-sql" => self
                .azure_sql
                .get_or_insert_with(SinkCadenceConfig::default),
            "csq-ledger" => self
                .csq_ledger
                .get_or_insert_with(SinkCadenceConfig::default),
            _ => unreachable!("caller validated sink name"),
        }
    }

    /// Returns a read-only reference to the cadence config for `sink_name`.
    #[must_use]
    pub fn cadence_for(&self, sink_name: &str) -> Option<&SinkCadenceConfig> {
        match sink_name {
            "rekor" => self.rekor.as_ref(),
            "s3" => self.s3.as_ref(),
            "azure" => self.azure.as_ref(),
            "gcp" => self.gcp.as_ref(),
            "azure-sql" => self.azure_sql.as_ref(),
            "csq-ledger" => self.csq_ledger.as_ref(),
            _ => None,
        }
    }
}

/// Validates that `sink_name` was compiled into this binary.
///
/// Every external-sink feature flag is checked with `#[cfg(feature = "...")]`.
/// When none of the features matching `sink_name` are active, returns
/// [`SinkConfigError::NotCompiledIn`] with the canonical error message.
///
/// `"none"` is always valid (local-only default).
pub fn validate_sink_compiled_in(sink_name: &str) -> Result<(), SinkConfigError> {
    match sink_name {
        "none" => Ok(()),
        #[cfg(feature = "rekor-sink")]
        "rekor" => Ok(()),
        #[cfg(feature = "s3-sink")]
        "s3" => Ok(()),
        #[cfg(feature = "azure-sink")]
        "azure" => Ok(()),
        #[cfg(feature = "gcp-sink")]
        "gcp" => Ok(()),
        #[cfg(feature = "azure-sql-sink")]
        "azure-sql" => Ok(()),
        #[cfg(feature = "csq-ledger-sink")]
        "csq-ledger" => Ok(()),
        name => Err(SinkConfigError::NotCompiledIn {
            sink: name.to_string(),
        }),
    }
}

/// Snapshot used by `csq doctor` to surface active-sink status.
///
/// All fields are `Option` so the doctor can gracefully represent
/// "no active sink" without a separate enum arm.
#[derive(Debug, Clone)]
pub struct SinkDoctorSnapshot {
    /// Active sink name (`"none"` when disabled).
    pub active_sink: String,
    /// ISO-8601 UTC timestamp of the last successful anchor, if any.
    pub last_anchor_ts: Option<String>,
    /// Count of records queued in `.pending-<sink>/` awaiting daemon drain.
    pub pending_count: u64,
    /// Count of drift events detected since last reset.
    pub replication_drift_count: u64,
}

impl SinkDoctorSnapshot {
    /// Reads the doctor snapshot from the on-disk ledger state.
    ///
    /// Called by `csq doctor`; non-fatal on I/O errors (returns zeroed
    /// snapshot so the report still renders without crashing).
    pub fn load(base_dir: &Path, active_sink: &str) -> Self {
        let pending_count = count_pending_dir(base_dir, active_sink);
        let (last_anchor_ts, replication_drift_count) = read_anchor_state(base_dir, active_sink);
        Self {
            active_sink: active_sink.to_string(),
            last_anchor_ts,
            pending_count,
            replication_drift_count,
        }
    }
}

/// Counts files in `.pending-<sink>/` (daemon-drain queue).
fn count_pending_dir(base_dir: &Path, sink_name: &str) -> u64 {
    if sink_name == "none" {
        return 0;
    }
    let dir = base_dir.join(format!(".pending-{sink_name}"));
    if !dir.exists() {
        return 0;
    }
    std::fs::read_dir(&dir)
        .map(|entries| entries.filter_map(|e| e.ok()).count() as u64)
        .unwrap_or(0)
}

/// Reads last-anchor timestamp and drift counter from `anchor-state.json`.
fn read_anchor_state(base_dir: &Path, sink_name: &str) -> (Option<String>, u64) {
    if sink_name == "none" {
        return (None, 0);
    }
    let state_path = base_dir.join(format!("anchor-state-{sink_name}.json"));
    if !state_path.exists() {
        return (None, 0);
    }
    let raw = match std::fs::read_to_string(&state_path) {
        Ok(s) => s,
        Err(_) => return (None, 0),
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return (None, 0),
    };
    let last_anchor = v
        .get("last_anchor_ts")
        .and_then(|s| s.as_str())
        .map(String::from);
    let drift_count = v
        .get("replication_drift_count")
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    (last_anchor, drift_count)
}

/// Serde helper: skip serialising `false` boolean fields.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !b
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn default_sink_is_none() {
        let cfg = AuditSinkConfig::default();
        assert_eq!(cfg.sink, "none");
    }

    #[test]
    fn audit_sink_config_round_trip() {
        let dir = temp_dir();
        let base = dir.path();
        let cfg = AuditSinkConfig::default();
        cfg.save(base).expect("save");
        let loaded = AuditSinkConfig::load(base).expect("load");
        assert_eq!(loaded.sink, "none");
    }

    /// R1-SEC-8: save must produce the file and it must be parseable.
    /// On Unix, the file must have 0o600 permissions (security.md §5).
    #[test]
    fn audit_sink_config_save_produces_file_with_0o600_on_unix() {
        let dir = temp_dir();
        let base = dir.path();
        let mut cfg = AuditSinkConfig::default();
        // Populate a non-trivial value so the round-trip is meaningful.
        cfg.set_sink_cadence("rekor", "cadence", "6h")
            .expect("set cadence");
        cfg.save(base).expect("save");

        // File must exist and be parseable.
        let path = AuditSinkConfig::path(base);
        assert!(path.exists(), "audit-sink.json must exist after save");
        let loaded = AuditSinkConfig::load(base).expect("load after save");
        let cadence = loaded.cadence_for("rekor").expect("rekor cadence present");
        assert_eq!(cadence.cadence.as_deref(), Some("6h"));

        // Unix: permissions must be 0o600 (security.md §5).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).expect("metadata");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "audit-sink.json must have 0o600 permissions, got 0o{mode:o}"
            );
        }
    }

    #[test]
    fn audit_rekor_cadence_config_default_and_override() {
        let mut cfg = AuditSinkConfig::default();
        // Set cadence key before activating sink is fine.
        cfg.set_sink_cadence("rekor", "cadence", "6h")
            .expect("set cadence");
        cfg.set_sink_cadence("rekor", "cadence-high-impact", "immediate")
            .expect("set high-impact");
        let cadence = cfg.cadence_for("rekor").expect("cadence present");
        assert_eq!(cadence.cadence.as_deref(), Some("6h"));
        assert_eq!(cadence.cadence_high_impact.as_deref(), Some("immediate"));
    }

    #[test]
    fn config_set_audit_sink_fails_loud_when_feature_not_compiled() {
        // "rekor" is only valid when --features rekor-sink. In the default
        // (non-feature) build this MUST return NotCompiledIn.
        #[cfg(not(feature = "rekor-sink"))]
        {
            let mut cfg = AuditSinkConfig::default();
            let err = cfg.set_sink("rekor").unwrap_err();
            match err {
                SinkConfigError::NotCompiledIn { ref sink } => {
                    assert_eq!(sink, "rekor");
                    // Canonical error message shape check.
                    let msg = err.to_string();
                    assert!(
                        msg.contains("was not compiled into this build"),
                        "expected canonical error message, got: {msg}"
                    );
                    assert!(
                        msg.contains("--features rekor-sink"),
                        "expected feature flag hint, got: {msg}"
                    );
                }
                other => panic!("expected NotCompiledIn, got: {other:?}"),
            }
        }
        // When the feature IS compiled in, set_sink("rekor") must succeed.
        #[cfg(feature = "rekor-sink")]
        {
            let mut cfg = AuditSinkConfig::default();
            cfg.set_sink("rekor")
                .expect("rekor-sink compiled in, must succeed");
        }
    }

    #[test]
    fn config_set_audit_sink_unknown_name_errors() {
        let mut cfg = AuditSinkConfig::default();
        let err = cfg.set_sink("no-such-sink").unwrap_err();
        assert!(matches!(err, SinkConfigError::UnknownSink { .. }));
    }

    #[test]
    fn audit_azure_sql_cadence_config_default_and_override() {
        // M15: the azure-sql sink wires into the cadence config + round-trips.
        let mut cfg = AuditSinkConfig::default();
        cfg.set_sink_cadence("azure-sql", "cadence", "6h")
            .expect("set cadence");
        cfg.set_sink_cadence("azure-sql", "fail-loud", "true")
            .expect("set fail-loud");
        let cadence = cfg.cadence_for("azure-sql").expect("cadence present");
        assert_eq!(cadence.cadence.as_deref(), Some("6h"));
        assert!(cadence.fail_loud);
        // Survives a save → load round-trip (azure-sql serde rename).
        let dir = temp_dir();
        cfg.save(dir.path()).expect("save");
        let loaded = AuditSinkConfig::load(dir.path()).expect("load");
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn config_set_audit_sink_azure_sql_feature_gated() {
        // azure-sql is a RECOGNISED name (never UnknownSink), gated on the
        // azure-sql-sink feature per spec 15 §15.6.4.
        let mut cfg = AuditSinkConfig::default();
        #[cfg(not(feature = "azure-sql-sink"))]
        {
            let err = cfg.set_sink("azure-sql").unwrap_err();
            match err {
                SinkConfigError::NotCompiledIn { ref sink } => {
                    assert_eq!(sink, "azure-sql");
                    assert!(err.to_string().contains("--features azure-sql-sink"));
                }
                other => panic!("expected NotCompiledIn, got: {other:?}"),
            }
        }
        #[cfg(feature = "azure-sql-sink")]
        {
            cfg.set_sink("azure-sql")
                .expect("azure-sql-sink compiled in, must succeed");
        }
    }
}
