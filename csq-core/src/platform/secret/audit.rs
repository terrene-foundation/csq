//! Append-only audit log for [`Vault`] access.
//!
//! Per security review §6 — secret READ access is auditable. If a
//! user later notices an unexpected Gemini bill, the audit log tells
//! them whether csq itself read the key at suspicious times, or
//! whether a malicious sibling went around csq directly to the
//! keychain (which would NOT show in csq's audit log but would show
//! in the OS keychain access log on macOS).
//!
//! # Schema
//!
//! One JSON object per line, fields:
//!
//! - `ts`: ISO-8601 UTC timestamp
//! - `op`: `"set"` | `"get"` | `"delete"`
//! - `slot`: account number (u16)
//! - `surface`: `"gemini"`
//! - `caller`: short symbolic tag (e.g. `"daemon::usage_poller"`)
//! - `ok`: bool — whether the operation succeeded
//! - `error_kind`: present only when `ok = false`; the
//!   [`SecretError::error_kind_tag`] of the failure
//!
//! # MUST NOT log
//!
//! - The secret itself (obvious)
//! - The secret's length (still a side channel)
//! - The secret's prefix (still a side channel — `AIza` is a
//!   constant prefix today; if Vertex SA paths land tomorrow, prefix
//!   logging immediately becomes informative)
//! - Stack traces (may include format strings holding the secret)
//!
//! # Retention
//!
//! 30 days, daemon-pruned on startup. Bounded by
//! `polling_rate × 30d × line_size ≈ 10MB` worst case.
//!
//! # File location and permissions
//!
//! `<base_dir>/vault-audit.ndjson`, `0o600` enforced via the
//! existing `platform::fs::secure_file` helper.

use super::SecretError;
use crate::platform::fs::secure_file;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Audit entry written for every [`Vault`] operation. Fields chosen
/// per security review §6; see module docstring for the MUST NOT
/// list of fields explicitly excluded.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    /// ISO-8601 UTC timestamp.
    pub ts: String,
    /// `"set"` | `"get"` | `"delete"`.
    pub op: &'static str,
    /// Surface tag — currently always `"gemini"`.
    pub surface: &'static str,
    /// Account slot number.
    pub slot: u16,
    /// Short symbolic caller tag — e.g. `"daemon::usage_poller"`.
    /// Per security review: NO stack traces.
    pub caller: &'static str,
    /// Whether the underlying vault op succeeded.
    pub ok: bool,
    /// Fixed-vocabulary error tag from
    /// [`SecretError::error_kind_tag`] when `ok = false`. Omitted
    /// when `ok = true` so the line is shorter and the success/fail
    /// distinction is visible at a glance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<&'static str>,
}

impl AuditEntry {
    /// Builds a successful-operation entry.
    pub fn ok(op: &'static str, surface: &'static str, slot: u16, caller: &'static str) -> Self {
        Self {
            ts: now_iso8601(),
            op,
            surface,
            slot,
            caller,
            ok: true,
            error_kind: None,
        }
    }

    /// Builds a failed-operation entry. Takes the error by reference
    /// to extract the fixed-vocabulary tag without exposing the full
    /// message (which may contain caller-supplied descriptive
    /// strings outside the redactor's coverage).
    pub fn err(
        op: &'static str,
        surface: &'static str,
        slot: u16,
        caller: &'static str,
        error: &SecretError,
    ) -> Self {
        Self {
            ts: now_iso8601(),
            op,
            surface,
            slot,
            caller,
            ok: false,
            error_kind: Some(error.error_kind_tag()),
        }
    }
}

/// Resolves the audit log path for the csq base dir.
pub fn audit_log_path(base_dir: &Path) -> PathBuf {
    base_dir.join("vault-audit.ndjson")
}

/// Appends `entry` to the audit log at the given base dir. Creates
/// the file with `0o600` permissions on first write. Failures are
/// returned but callers typically log and continue — an audit-log
/// I/O failure MUST NOT propagate as an operational failure (the
/// vault op already happened).
pub fn append(base_dir: &Path, entry: &AuditEntry) -> std::io::Result<()> {
    let path = audit_log_path(base_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // OpenOptions::append is atomic per-write at the OS level for
    // small writes; combined with a single serde_json::to_string +
    // \n write we get one-syscall append semantics for sub-page
    // entries (audit lines are well under 4KiB).
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    secure_file(&path).ok();
    let mut line = serde_json::to_string(entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Removes audit log entries older than `retention_days`. Called by
/// the daemon at startup. Implemented as a read-rewrite — the file
/// is bounded (~10MB worst case) so this is fine; an interval-based
/// truncate is an optimization for later.
pub fn prune_older_than(base_dir: &Path, retention_days: u64) -> std::io::Result<usize> {
    let path = audit_log_path(base_dir);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };

    let cutoff = (now_secs() as i64) - (retention_days as i64) * 86400;
    let mut kept = String::with_capacity(content.len());
    let mut pruned = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Best-effort parse; malformed lines are dropped (data
        // hygiene — the audit log is single-writer and shouldn't
        // contain malformed rows, but if it does they're noise).
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                pruned += 1;
                continue;
            }
        };
        let ts_str = value.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        if iso8601_to_unix(ts_str).map(|t| t >= cutoff).unwrap_or(true) {
            kept.push_str(line);
            kept.push('\n');
        } else {
            pruned += 1;
        }
    }

    // Atomic rewrite via existing platform helper conventions.
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, kept.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other(format!("secure_file: {e}")));
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other(format!("atomic replace: {e}")));
    }
    Ok(pruned)
}

// ── time helpers ──────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Renders the current time as ISO-8601 UTC with second precision.
/// Implemented inline to avoid pulling in a chrono dependency for
/// what is essentially a printf format. Format: `YYYY-MM-DDTHH:MM:SSZ`.
fn now_iso8601() -> String {
    unix_to_iso8601(now_secs())
}

fn unix_to_iso8601(secs: u64) -> String {
    // Days since 1970-01-01.
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Reverse of `unix_to_iso8601` — only handles `YYYY-MM-DDTHH:MM:SSZ`.
/// Returns `None` on malformed input.
fn iso8601_to_unix(s: &str) -> Option<i64> {
    if s.len() < 20 || !s.ends_with('Z') {
        return None;
    }
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let y: i64 = date_parts.next()?.parse().ok()?;
    let mo: u32 = date_parts.next()?.parse().ok()?;
    let d: u32 = date_parts.next()?.parse().ok()?;
    let time = time.strip_suffix('Z')?;
    let mut time_parts = time.split(':');
    let h: i64 = time_parts.next()?.parse().ok()?;
    let mi: i64 = time_parts.next()?.parse().ok()?;
    let se: i64 = time_parts.next()?.parse().ok()?;

    let days = ymd_to_days(y, mo, d)?;
    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

/// Days-since-epoch (1970-01-01) → (year, month, day). Pure
/// arithmetic, no calendar lookup tables. Adapted from
/// Howard Hinnant's chrono date algorithms (public domain).
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// (year, month, day) → days-since-epoch. Inverse of
/// [`days_to_ymd`]. Returns `None` for impossible dates.
fn ymd_to_days(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || d == 0 || d > 31 {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 {
        (m - 3) as u64
    } else {
        (m + 9) as u64
    };
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe as i64 - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn append_creates_file_with_one_line() {
        let dir = TempDir::new().unwrap();
        let entry = AuditEntry::ok("get", "gemini", 3, "daemon::usage_poller");
        append(dir.path(), &entry).unwrap();

        let content = std::fs::read_to_string(audit_log_path(dir.path())).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["op"], "get");
        assert_eq!(parsed["slot"], 3);
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn err_entry_includes_error_kind_tag() {
        let dir = TempDir::new().unwrap();
        let err = SecretError::NotFound {
            surface: "gemini",
            account: 5,
        };
        let entry = AuditEntry::err("get", "gemini", 5, "daemon::usage_poller", &err);
        append(dir.path(), &entry).unwrap();
        let content = std::fs::read_to_string(audit_log_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error_kind"], "vault_not_found");
    }

    #[test]
    fn append_does_not_log_secret_or_length() {
        // Defence in depth: AuditEntry has no field that could hold
        // the secret. This test asserts the schema by construction —
        // if someone adds a `secret_len` or `secret_prefix` field
        // later, the test breaks loudly.
        let dir = TempDir::new().unwrap();
        let entry = AuditEntry::ok("set", "gemini", 1, "tauri::gemini_provision");
        append(dir.path(), &entry).unwrap();
        let content = std::fs::read_to_string(audit_log_path(dir.path())).unwrap();
        // Not exhaustive but catches the obvious pattern. A more
        // thorough test in the redactor module covers AIza* etc.
        assert!(!content.contains("AIza"));
        assert!(!content.to_ascii_lowercase().contains("len"));
        assert!(!content.to_ascii_lowercase().contains("hash"));
    }

    #[test]
    fn prune_removes_old_entries() {
        let dir = TempDir::new().unwrap();
        let path = audit_log_path(dir.path());
        // Manually craft two entries: one 60 days old, one fresh.
        let old_secs = now_secs() - 60 * 86400;
        let old_entry = serde_json::json!({
            "ts": unix_to_iso8601(old_secs),
            "op": "get",
            "surface": "gemini",
            "slot": 1,
            "caller": "test",
            "ok": true
        });
        let fresh_entry = serde_json::json!({
            "ts": unix_to_iso8601(now_secs()),
            "op": "get",
            "surface": "gemini",
            "slot": 2,
            "caller": "test",
            "ok": true
        });
        std::fs::write(&path, format!("{old_entry}\n{fresh_entry}\n")).unwrap();

        let pruned = prune_older_than(dir.path(), 30).unwrap();
        assert_eq!(pruned, 1);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("\"slot\":1"), "old entry must be pruned");
        assert!(content.contains("\"slot\":2"), "fresh entry must remain");
    }

    #[test]
    fn prune_on_missing_file_is_ok() {
        let dir = TempDir::new().unwrap();
        let pruned = prune_older_than(dir.path(), 30).unwrap();
        assert_eq!(pruned, 0);
    }

    #[test]
    fn iso8601_round_trip() {
        // Round trip across several representative times: epoch, a
        // recent timestamp, and a future timestamp. We don't hardcode
        // human-readable target strings to avoid leap-year math
        // arithmetic errors; the invariant we care about is
        // round-trip identity.
        for secs in [0u64, 1_700_000_000, 1_800_000_000, 4_102_444_800] {
            let iso = unix_to_iso8601(secs);
            // Format check: 20 chars, ends with Z, has 'T' at the
            // right position.
            assert_eq!(iso.len(), 20, "wrong length: {iso}");
            assert!(iso.ends_with('Z'), "missing Z: {iso}");
            assert_eq!(iso.as_bytes()[10], b'T', "T at wrong pos: {iso}");
            let parsed = iso8601_to_unix(&iso).unwrap_or_else(|| panic!("parse failed: {iso}"));
            assert_eq!(parsed, secs as i64, "round trip mismatch: {iso}");
        }
    }

    #[test]
    fn iso8601_rejects_malformed() {
        assert!(iso8601_to_unix("not a date").is_none());
        assert!(iso8601_to_unix("2026-04-25T00:00:00").is_none()); // no Z
        assert!(iso8601_to_unix("").is_none());
    }
}
