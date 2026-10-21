//! Surface-independent host policy. No native operation runs on module load.
use anyhow::{Context, Result};
#[cfg(any(feature = "cli", target_os = "macos"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(any(target_os = "macos", test))]
pub(crate) mod launchd;

/// The `csq audit verify` startup step's per-record duration floor (ms),
/// measured on an UNLOADED host: `csq audit verify --full` verified an
/// 11,449-record chain in 2462ms (2026-09, exit 0, clean — "11449 v2
/// records verified, 0 v1 skipped"). 2462/11449 ≈ 0.215 ms/record. This is
/// a FLOOR standing in for typical throughput — NOT a bound
/// (`doc-property-claims.md` MUST-2) — and it EXCLUDES the EATP-chain
/// reconciliation the daemon startup path runs inside the SAME
/// `spawn_blocking` (`csq audit verify --full` does not touch the EATP
/// chain), so the daemon's real per-record cost is this number plus an
/// unmeasured EATP margin.
pub(crate) const AUDIT_VERIFY_MS_PER_RECORD_FLOOR: f64 = 0.215;

/// Margin applied to [`AUDIT_VERIFY_MS_PER_RECORD_FLOOR`] to size the
/// DEFAULT verify timeout. ~7x the measured unloaded floor.
///
/// The margin is INFERENCE, not a direct measurement of the loaded case
/// (`evidence-first-claims.md` MUST-4): the only two loaded data points on
/// THIS code path are "5s (the old fixed default) was insufficient under
/// host load ~100-190" and "30s (an operator override of
/// `CSQ_AUDIT_VERIFY_TIMEOUT_SECS`) was sufficient" — a coarse bracket,
/// not the tight healthy/dead pair `HEALTH_TIMEOUT` had. Absent a tight
/// bracket for this code path, the corroborating evidence is
/// `HEALTH_TIMEOUT`'s independently measured ~20x slowdown for a
/// near-zero-cost health read under a comparable load
/// (`csq-core/src/daemon/detect.rs`); 7x is deliberately SMALLER than
/// that because audit verify is CPU-bound crypto work, whose throughput
/// degrades under scheduling contention differently than an IO-wait
/// latency spike does — the two are not the same mechanism, so
/// borrowing the multiplier directly would overstate the case.
pub(crate) const AUDIT_VERIFY_LOAD_MARGIN: f64 = 7.0;

/// Absolute floor for the derived timeout — covers fixed per-run overhead
/// (process/tokio-task spin-up, the EATP-chain check) on a chain too
/// small for the per-record term to dominate. Equal to the ORIGINAL fixed
/// default, which was adequate for small/fresh chains; only a LARGE chain
/// under load exposed the insufficiency this constant no longer has to
/// cover alone.
pub(crate) const AUDIT_VERIFY_TIMEOUT_MIN_SECS: u64 = 5;

/// Absolute ceiling for the derived timeout, independent of how large an
/// operator sets `CSQ_AUDIT_VERIFY_LIMIT`. `csq daemon start` blocks on
/// this step before binding its IPC socket — spec 12 §12.13.5's "never
/// blocks daemon startup" governs the OUTCOME (every result maps to an
/// `AuditHealth` and startup proceeds), not how long the outcome takes to
/// arrive. An unbounded formula would let a large record-limit override
/// turn a genuinely broken chain into a multi-minute "is the daemon even
/// starting?" hang. An operator who needs longer than this for a real
/// (not-hung) verify at their configured limit can still set
/// `CSQ_AUDIT_VERIFY_TIMEOUT_SECS` explicitly — the explicit override
/// always takes full precedence over this formula.
pub(crate) const AUDIT_VERIFY_TIMEOUT_MAX_SECS: u64 = 60;

pub(crate) fn derive_audit_verify_timeout_secs(record_limit: usize) -> u64 {
    let ms = record_limit as f64 * AUDIT_VERIFY_MS_PER_RECORD_FLOOR * AUDIT_VERIFY_LOAD_MARGIN;
    let secs = (ms / 1000.0).ceil() as u64;
    secs.clamp(AUDIT_VERIFY_TIMEOUT_MIN_SECS, AUDIT_VERIFY_TIMEOUT_MAX_SECS)
}
#[cfg(any(feature = "cli", target_os = "macos"))]
pub(crate) fn daemon_log_path(base_dir: &Path) -> PathBuf {
    base_dir.join("csq-daemon.log")
}
fn validate_claude_home(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if raw.is_empty() || !path.is_absolute() {
        anyhow::bail!("CLAUDE_HOME must be a non-empty absolute path (got {raw:?})");
    }
    Ok(path)
}
pub(crate) fn claude_home() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("CLAUDE_HOME") {
        return validate_claude_home(&raw);
    }
    let home =
        csq_core::platform::home::home_dir().context("could not determine home directory")?;
    Ok(home.join(".claude"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_daemon_home_validation_preserves_override_contract() {
        assert!(validate_claude_home("").is_err());
        assert!(validate_claude_home("relative").is_err());
        let absolute = tempfile::tempdir().unwrap();
        assert_eq!(
            validate_claude_home(absolute.path().to_str().unwrap()).unwrap(),
            absolute.path()
        );
    }
    #[test]
    fn shared_daemon_timeout_keeps_default_and_bounds() {
        assert_eq!(derive_audit_verify_timeout_secs(10_000), 16);
        assert_eq!(derive_audit_verify_timeout_secs(0), 5);
        assert_eq!(derive_audit_verify_timeout_secs(100_000), 60);
    }
    #[test]
    fn extracted_cli_daemon_loc_invariant() {
        let source = include_str!("../cli/commands/daemon.rs");
        assert!(
            source.lines().count() <= 7000,
            "shared lifecycle code must stay extracted"
        );
    }
}
