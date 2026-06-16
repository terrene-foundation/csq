//! Quarantine and pending-provenance custody writers.
//!
//! Neither directory is a chain writer — they provide custody of raw bytes
//! that could not be anchored (malformed → quarantine, unknown version →
//! pending/provenance). Chain records are written only through
//! `audit::persist::write_record_v2_signed`.
//!
//! Both writers are listed in `csq-core/tests/audit_single_writer.rs`
//! as AUTHORIZED WRITE sites for their respective subdirectories:
//! - `.quarantine/` — malformed or frontier-rejected events.
//! - `.pending/provenance/` — well-formed but unknown-version events.
//!
//! Per `rules/security.md §5a`: every tmp write uses the
//! `unique_tmp_path → write → secure_file → atomic_replace` pipeline
//! with `remove_file(&tmp)` on every failure branch.

use std::io;
use std::path::{Path, PathBuf};

use crate::audit::seam::SeamError;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

/// Hard ceiling on per-custody-directory file count.
///
/// When a custody directory has ≥ `CUSTODY_HARD_CAP` files, ingest is
/// refused with [`crate::audit::seam::SeamError::CustodyFull`] and the
/// handler returns 503 `seam_custody_full`. This prevents unbounded disk
/// growth from a misbehaving loom emitter.
const CUSTODY_HARD_CAP: usize = 10_000;

/// Soft warning threshold — `csq doctor` surfaces `seam_pending_backlog_high`
/// when the pending-provenance directory reaches this count.
const CUSTODY_CAP_FILES: usize = 1_000;

/// Maximum total bytes per custody directory before we emit a WARN.
const CUSTODY_CAP_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// Write raw bytes to `.quarantine/<uuid>.json` for events rejected at the
/// frontier (malformed or validation failure).
///
/// The quarantine file lives at 0o600 under `csq-runs/.quarantine/`.
/// It is NOT a chain record; chain records go through `persist.rs`.
///
/// Returns `Err(SeamError::CustodyFull)` when the directory has reached
/// `CUSTODY_HARD_CAP` entries — the caller MUST propagate this as 503.
///
/// Returns the path written on success.
pub fn quarantine_event(
    base: &Path,
    raw: &[u8],
    reason: &'static str,
) -> Result<PathBuf, SeamError> {
    let dir = base.join("csq-runs").join(".quarantine");
    std::fs::create_dir_all(&dir).inspect_err(|_| {
        tracing::warn!(
            error_kind = "seam_quarantine_mkdir_failed",
            "seam: failed to create quarantine dir"
        );
    })?;
    // 0o700 on the directory (matches .pending/ pattern).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    if check_hard_cap_and_warn(&dir, "quarantine")? {
        return Err(SeamError::CustodyFull);
    }

    let filename = format!("{}.json", crate::providers::gemini::event_id::new_uuidv7());
    let path = dir.join(&filename);
    write_custody_file(&path, raw)?;

    tracing::info!(
        error_kind = "seam_quarantined",
        reason = reason,
        "seam: inbound event quarantined"
    );
    Ok(path)
}

/// Park raw bytes in `.pending/provenance/<uuid>.json` for events that are
/// well-formed but carry an unknown `f101_schema_version`.
///
/// Parked events are recoverable: when M18-bind registers the decoder for the
/// version, a drain can replay them. `csq doctor` surfaces the count.
///
/// Returns `Err(SeamError::CustodyFull)` when the directory has reached
/// `CUSTODY_HARD_CAP` entries — the caller MUST propagate this as 503.
///
/// Returns the path written on success.
pub fn park_unknown_version(base: &Path, raw: &[u8], version: &str) -> Result<PathBuf, SeamError> {
    let dir = base.join("csq-runs").join(".pending").join("provenance");
    std::fs::create_dir_all(&dir).inspect_err(|_| {
        tracing::warn!(
            error_kind = "seam_pending_mkdir_failed",
            "seam: failed to create pending/provenance dir"
        );
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    if check_hard_cap_and_warn(&dir, "pending/provenance")? {
        return Err(SeamError::CustodyFull);
    }

    let filename = format!("{}.json", crate::providers::gemini::event_id::new_uuidv7());
    let path = dir.join(&filename);
    write_custody_file(&path, raw)?;

    // Log with fixed-vocab tag so doctor can grep for this class.
    tracing::info!(
        error_kind = "seam_parked_unknown_version",
        // Do NOT log the version string if it could carry attacker-controlled
        // content. The version string comes from the parsed envelope (validated
        // as a JSON string type but not further sanitised). Log a fixed tag only.
        "seam: inbound event parked (unknown f101_schema_version)"
    );
    let _ = version; // consumed for structured-log; not echoed
    Ok(path)
}

/// Map a `PlatformError` into `io::Error` for the custody-write function
/// which returns `io::Result<()>`. `PlatformError::Io` unwraps; all other
/// variants become `io::ErrorKind::Other`.
fn platform_to_io(e: crate::error::PlatformError) -> io::Error {
    match e {
        crate::error::PlatformError::Io(io_err) => io_err,
        other => io::Error::other(other.to_string()),
    }
}

/// Write `raw` to `path` with the §5a tmp-cleanup pipeline.
fn write_custody_file(path: &Path, raw: &[u8]) -> io::Result<()> {
    let tmp = unique_tmp_path(path);
    if let Err(e) = std::fs::write(&tmp, raw) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(platform_to_io(e));
    }
    if let Err(e) = atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(platform_to_io(e));
    }
    Ok(())
}

/// Check custody directory count against hard cap and soft warn threshold.
///
/// Returns `Ok(true)` when the hard cap is reached (caller must refuse write),
/// `Ok(false)` when the write should proceed (soft warn already emitted if
/// the count exceeds `CUSTODY_CAP_FILES`).
///
/// The hard cap is checked before the write — a directory at exactly
/// `CUSTODY_HARD_CAP` refuses the next write, so steady-state max is 10 000 files.
fn check_hard_cap_and_warn(dir: &Path, label: &'static str) -> io::Result<bool> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        // Can't read the directory — not at cap (we just created it).
        return Ok(false);
    };
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    for entry in entries.flatten() {
        count += 1;
        total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }
    if count >= CUSTODY_HARD_CAP {
        tracing::error!(
            error_kind = "seam_custody_full",
            dir = label,
            count = count,
            "seam: custody directory at hard cap; refusing write"
        );
        return Ok(true);
    }
    if count >= CUSTODY_CAP_FILES {
        tracing::warn!(
            error_kind = "seam_custody_cap_files",
            dir = label,
            count = count,
            "seam: custody directory file count near cap; consider draining"
        );
    }
    if total_bytes >= CUSTODY_CAP_BYTES {
        tracing::warn!(
            error_kind = "seam_custody_cap_bytes",
            dir = label,
            bytes = total_bytes,
            "seam: custody directory size at cap; consider draining"
        );
    }
    Ok(false)
}
