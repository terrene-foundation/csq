//! Shared daemon audit-health query.
//!
//! ONE channel, two readers. `csq doctor` and `csq daemon status` must not
//! answer the same question by different routes: a second implementation is
//! exactly how two operator surfaces come to disagree about the same
//! subsystem (`diagnostic-surface-parity.md` — a diagnostic MUST read the
//! same channel the daemon's production path uses).
//!
//! Extracted verbatim from `doctor.rs` on 2026-09-13 when `daemon status`
//! grew the same need. Behaviour is unchanged; only the home moved.

use std::path::Path;

/// Attempts to read the RUNNING daemon's OWN audit-verify result via
/// `GET /api/audit/health` — the channel `diagnostic-surface-parity.md`
/// MUST NOT Rule 4 requires: `csq doctor` reporting what the daemon itself
/// already computed and is gating anchoring/emit on, rather than
/// recomputing a possibly-different answer with doctor's own env-derived
/// `record_limit`. This is the exact shape of an internal ticket (`csq probe`
/// reading `~/.codex/auth.json` while the daemon read the identity store)
/// applied to the audit chain instead of credentials.
///
/// `Ok` only when the daemon is reachable, version-matched (not drifted),
/// and returned a parseable `200`. Every other outcome is `Err(<reason>)`
/// — the caller MUST fall back to a LOCAL `verify_chain` run and mark that
/// fallback as such (`AuditChainSource::LocalOnly`) rather than presenting
/// it as if it were the daemon's own answer.
///
/// Unix-only (`#[cfg(not(unix))]` sibling below), matching the existing
/// `csq status` daemon-delegation pattern (`status.rs::try_daemon_accounts`)
/// — the Windows named-pipe client is async and would require a tokio
/// runtime spun up just for this one diagnostic read; on Windows this
/// always falls back to the local read, with the reason named so the
/// fallback is never presented as if it were the daemon's own answer.
#[cfg(unix)]
pub(crate) fn try_daemon_audit_health(
    base_dir: &Path,
) -> Result<(csq_core::audit::AuditHealth, u64), String> {
    use csq_core::daemon::{
        detect_daemon, http_get_unix, version_drift_reason, AuditHealthResponse, DetectResult,
    };

    let socket_path = match detect_daemon(base_dir) {
        DetectResult::Healthy {
            socket_path,
            daemon_version,
            ..
        } => {
            if let Some(reason) = version_drift_reason(&daemon_version) {
                return Err(format!("daemon version drift: {reason}"));
            }
            socket_path
        }
        other => return Err(format!("daemon not reachable ({other:?})")),
    };

    let resp = http_get_unix(&socket_path, "/api/audit/health")
        .map_err(|e| format!("daemon audit-health request failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!(
            "daemon returned HTTP {} for /api/audit/health",
            resp.status
        ));
    }

    let parsed: AuditHealthResponse = serde_json::from_str(&resp.body)
        .map_err(|e| format!("daemon audit-health response did not parse: {e}"))?;
    Ok((parsed.health, parsed.records_unverified))
}

#[cfg(not(unix))]
pub(crate) fn try_daemon_audit_health(
    _base_dir: &Path,
) -> Result<(csq_core::audit::AuditHealth, u64), String> {
    Err("daemon audit-health query is not implemented on this platform".to_string())
}
