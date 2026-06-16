//! `AuditHealth` — the result of daemon-startup chain verification.
//!
//! The daemon runs `verify_chain` before binding its IPC socket. Regardless
//! of the outcome, the daemon proceeds (token-refresh and quota-polling are
//! decoupled from audit integrity). The outcome is captured as `AuditHealth`
//! and stored in the daemon's shared `RouterState` so it can:
//!
//! - Gate the **audit subsystem** (anchor task + emit IPC route fail-closed
//!   when `Broken`).
//! - Be reported to clients via `csq doctor` / `csq daemon status`.
//!
//! # Variants
//!
//! - [`AuditHealth::Verified`] — clean chain, all records sig-verified.
//! - [`AuditHealth::Degraded`] — historical-key gaps (Option B path):
//!   chain-linking verified end-to-end; some records' signatures were skipped
//!   because the signing key is no longer in the keychain. Non-fatal.
//! - [`AuditHealth::Broken`] — a fatal `LedgerError` was returned (e.g.
//!   `ChainBroken`, `InvalidSignature`, `HistoricalKeyAtHead`). The audit
//!   subsystem fails closed; other daemon subsystems continue normally.
//! - [`AuditHealth::Unknown`] — verification did not complete (timeout or
//!   internal panic). Conservative: treated identically to `Broken` for
//!   audit-subsystem gating.
//!
//! # Design note — why not abort on Broken?
//!
//! A broken audit chain is a forensic signal, not a dependency of
//! token-refresh or quota-polling. Aborting the daemon on `Broken` takes
//! down unrelated subsystems and leaves users without quota data or
//! credential refresh — the harm is not commensurate with the threat.
//! The correct response is loud surfacing (ERROR log + doctor) and
//! audit-subsystem fail-closed (no new appends to a chain that is already
//! broken). See spec 12 §12.13.5.
//!
//! # Start-time-only health
//!
//! **`audit_health` in the daemon's `RouterState` is a snapshot taken at
//! daemon startup — it does NOT update continuously.** Post-startup chain
//! breakage (e.g. a corrupt append by a concurrent writer) is NOT reflected
//! in the in-RAM `AuditHealth` value after the daemon starts.
//!
//! Post-startup protection works through two mechanisms:
//!
//! 1. The **`.chain-broken` sentinel** (below) — set/cleared by every
//!    `verify_chain` caller; also read by `write_record_v2_impl` to gate all
//!    writers. A broken chain discovered during a `csq audit verify` or
//!    `csq doctor` run AFTER daemon start will set the sentinel and block
//!    subsequent writes even while the daemon remains up.
//! 2. The next **`csq doctor` / `csq audit verify` run** — re-runs
//!    `verify_chain` and updates the sentinel accordingly.
//!
//! # `.chain-broken` sentinel
//!
//! The daemon's `audit_health` is computed at startup and held in RAM; it
//! does NOT prevent CLI-side writers (op_emit, rotate, anchor) from appending
//! after the daemon exits or while the daemon is down. The sentinel file
//! `csq-runs/.chain-broken` is the cross-process mechanism that prevents ALL
//! writers (CLI and daemon) from extending a broken chain.
//!
//! - **Set** by every code path that classifies the chain as `Broken` or
//!   `Unknown` after a `verify_chain` call: daemon startup, `csq audit verify`,
//!   `csq doctor`.
//! - **Cleared** by every code path that classifies the chain as `Verified` or
//!   `Degraded` (chain-linking confirmed intact): daemon startup, `csq audit
//!   verify`, `csq doctor`, desktop daemon startup.
//! - **Read** inside `write_record_v2_impl` (INSIDE the `.chain-lock` critical
//!   section) to fail-close ALL writers when the sentinel is present.
//!
//! Content of the sentinel file is the fixed-vocabulary `error_kind` string so
//! `csq doctor` / `csq audit verify` can report WHY the chain is broken.

use crate::audit::verify::KeyGap;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use serde::Serialize;
use std::path::Path;

/// Outcome of the daemon's startup `verify_chain` call.
///
/// Stored in [`crate::daemon::server::RouterState`] so every handler can
/// consult it without re-running verification.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditHealth {
    /// Chain verified clean — all records sig-verified.
    Verified,

    /// Chain verified with historical-key gaps.
    ///
    /// Chain-linking was fully verified end-to-end. Per-record signatures
    /// for records signed by rotated-out keys were skipped because those
    /// keys are no longer in the keychain. The audit subsystem operates
    /// normally (anchoring and emit continue). Non-fatal.
    Degraded {
        /// The specific key-gap ranges that caused the degrade.
        gaps: Vec<KeyGap>,
    },

    /// Fatal `LedgerError` returned by `verify_chain`.
    ///
    /// The audit subsystem fails closed: anchoring is skipped and emit
    /// IPC is rejected. Other daemon subsystems (refresh, polling) continue.
    ///
    /// `error_kind` is a fixed-vocabulary tag matching the daemon's
    /// `tracing::error!(error_kind = ...)` convention. `reason` is a
    /// redacted human-readable description (no host paths; key_ids and
    /// seq numbers are fine).
    Broken { error_kind: String, reason: String },

    /// Verification did not complete (timeout or spawn_blocking panic).
    ///
    /// Treated identically to `Broken` for audit-subsystem gating: when
    /// we cannot verify the chain we must not extend it. `reason` names
    /// the specific cause (e.g. `"audit_verify_timeout"` or
    /// `"audit_verify_task_panicked"`).
    Unknown { reason: String },
}

impl AuditHealth {
    /// Returns `true` when the audit subsystem should operate normally
    /// (anchoring permitted, emit IPC accepted).
    ///
    /// `Verified` and `Degraded` both return `true`. `Broken` and
    /// `Unknown` return `false`.
    pub fn is_operational(&self) -> bool {
        matches!(self, AuditHealth::Verified | AuditHealth::Degraded { .. })
    }

    /// Builds an `AuditHealth` from the `Result` returned by `verify_chain`.
    ///
    /// Convenience method used by CLI surfaces (`csq audit verify`,
    /// `csq doctor`) which hold the `Result` directly rather than
    /// dispatching on it through the daemon's match arms.
    pub fn from_verify_result(
        result: &Result<crate::audit::VerifySummary, crate::audit::LedgerError>,
    ) -> Self {
        match result {
            Ok(summary) if summary.historical_key_gaps.is_empty() => AuditHealth::Verified,
            Ok(summary) => AuditHealth::Degraded {
                gaps: summary.historical_key_gaps.clone(),
            },
            Err(e) => AuditHealth::from_ledger_error(e),
        }
    }

    /// Builds an `AuditHealth` from a `LedgerError`.
    ///
    /// Every `LedgerError` variant maps to a fixed-vocabulary `error_kind`
    /// tag consistent with the daemon's `tracing::error!` logging convention.
    pub fn from_ledger_error(e: &crate::audit::LedgerError) -> Self {
        use crate::audit::LedgerError;

        // TRANSIENT, not durable: a present-but-inaccessible signing key
        // (credential store locked / per-app-ACL prompt a non-interactive
        // process cannot answer) is NOT a chain-integrity failure. Route it to
        // `Unknown` — which gates the audit subsystem closed for the lifetime
        // of this process (in-RAM, `is_operational() == false`) WITHOUT writing
        // the durable `.chain-broken` sentinel. The chain recovers on the next
        // run that can read the store (interactive `csq audit verify`, or the
        // file-based seed store). Mapping this to `Broken` is the conflation
        // bug that bricked the daemon — see `specs/12-audit-trail.md` §12.13.2.
        if matches!(e, LedgerError::KeychainUnavailable { .. }) {
            return AuditHealth::Unknown {
                reason: "audit_keychain_unavailable".to_string(),
            };
        }

        let (error_kind, reason) = match e {
            LedgerError::ChainBroken { seq, .. } => (
                format!("audit_chain_broken_at_seq_{seq}"),
                format!("chain broken at seq {seq}: prev_hash mismatch"),
            ),
            LedgerError::InvalidSignature { record_id, key_id } => (
                "audit_invalid_signature".to_string(),
                format!("invalid signature for record {record_id} key {key_id}"),
            ),
            LedgerError::KeyNotFound { key_id } => (
                "audit_current_key_not_found".to_string(),
                format!("current active signing key {key_id} not found in keychain"),
            ),
            LedgerError::IntegrityBroken { seq, .. } => (
                format!("audit_integrity_broken_at_seq_{seq}"),
                format!("integrity broken at seq {seq}"),
            ),
            LedgerError::UnsignedRecordAfterCutoff { seq, cutoff } => (
                format!("audit_unsigned_after_cutoff_seq_{seq}_cutoff_{cutoff}"),
                format!("unsigned record at seq {seq} after cutoff {cutoff}"),
            ),
            LedgerError::CutoffAnchorMismatch { .. } => (
                "audit_cutoff_anchor_mismatch".to_string(),
                "cutoff anchor mismatch — chain.json may be tampered".to_string(),
            ),
            LedgerError::SigningKeyIdAnchorMismatch { .. } => (
                "audit_signing_key_id_anchor_mismatch".to_string(),
                "signing key id anchor mismatch — chain.json may be tampered".to_string(),
            ),
            LedgerError::MultiSigInvalid { .. } => (
                "audit_multi_sig_invalid".to_string(),
                "multi-sig authorization invalid — chain.jsonl may be tampered".to_string(),
            ),
            LedgerError::HistoricalKeyAtHead { head_seq, key_id } => (
                format!("audit_historical_key_at_head_seq_{head_seq}"),
                format!(
                    "historical-key gap at chain HEAD (seq {head_seq}, key {key_id}): \
                     head must be signed by current key"
                ),
            ),
            LedgerError::GapAfterVerifiedSegment { gap_seq, key_id } => (
                format!("audit_gap_after_verified_segment_seq_{gap_seq}"),
                format!(
                    "historical-key gap record at seq {gap_seq} (key {key_id}) appears \
                     after a signature-verified record: chain topology invalid"
                ),
            ),
            LedgerError::Io { context, .. } => (
                "audit_chain_io_error".to_string(),
                format!("chain I/O error: {context}"),
            ),
            // Catch-all for future variants (LedgerError is #[non_exhaustive]).
            _ => (
                "audit_chain_integrity_failure_other".to_string(),
                "audit chain integrity failure".to_string(),
            ),
        };
        AuditHealth::Broken { error_kind, reason }
    }
}

// ---------------------------------------------------------------------------
// Sentinel helpers — `.chain-broken`
// ---------------------------------------------------------------------------

/// Returns the path of the `.chain-broken` sentinel file.
///
/// The sentinel lives alongside the `.chain-lock` advisory lock, inside
/// `csq-runs/`, so it is co-located with the chain it guards.
fn sentinel_path(base_dir: &Path) -> std::path::PathBuf {
    base_dir.join("csq-runs").join(".chain-broken")
}

/// Sets the `.chain-broken` sentinel to `error_kind`.
///
/// Written via the §5a atomic-write pattern (tmp → secure_file → atomic_replace)
/// so a crash mid-write cannot leave a zero-byte sentinel that clears on the
/// next read.
///
/// MUST be called from every code path that classifies the chain as
/// `AuditHealth::Broken`. `AuditHealth::Unknown` (timeout or `spawn_blocking`
/// panic) MUST NOT set this sentinel — a transient verify failure must not
/// produce a durable write-lockout that blocks lifecycle ops indefinitely.
///
/// Callers:
/// - `csq/src/cli/commands/daemon.rs` — daemon startup verify block
/// - `csq/src/cli/commands/audit.rs` — `handle_verify`
/// - `csq/src/cli/commands/doctor.rs` — `check_audit_chain`
/// - `csq/src/desktop/daemon_supervisor.rs` — desktop `run_daemon` verify block
pub fn set_chain_broken(base_dir: &Path, error_kind: &str) {
    // Ensure csq-runs/ exists (best-effort; if the dir can't be created, the
    // sentinel write will also fail and we fall through silently — the caller
    // has already logged the error).
    let csq_runs = base_dir.join("csq-runs");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&csq_runs);
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::create_dir_all(&csq_runs);
    }

    let path = sentinel_path(base_dir);
    let tmp = unique_tmp_path(&path);
    // §5a: write → secure → replace, clean up tmp on every failure branch.
    if let Err(e) = std::fs::write(&tmp, error_kind.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "chain_broken_sentinel_write_failed",
            "could not write .chain-broken sentinel: {e}"
        );
        return;
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "chain_broken_sentinel_write_failed",
            "could not secure .chain-broken sentinel: {e}"
        );
        return;
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "chain_broken_sentinel_write_failed",
            "could not atomically place .chain-broken sentinel: {e}"
        );
    }
}

/// Clears the `.chain-broken` sentinel (best-effort; ignore ENOENT).
///
/// MUST be called from every code path that classifies the chain as
/// `AuditHealth::Verified` or `AuditHealth::Degraded` (chain-linking intact):
/// - `csq/src/cli/commands/daemon.rs` — daemon startup verify block
/// - `csq/src/cli/commands/audit.rs` — `handle_verify`
/// - `csq/src/cli/commands/doctor.rs` — `check_audit_chain`
/// - `csq/src/desktop/daemon_supervisor.rs` — desktop `run_daemon` verify block
///
/// Also called by the desktop daemon path immediately after any repair that
/// brings the chain to a known-good state.
pub fn clear_chain_broken(base_dir: &Path) {
    let path = sentinel_path(base_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                error_kind = "chain_broken_sentinel_clear_failed",
                "could not remove .chain-broken sentinel: {e}"
            );
        }
    }
}

/// Returns `Some(error_kind)` if the `.chain-broken` sentinel is present,
/// `None` if it is absent or unreadable.
///
/// Used inside `write_record_v2_impl` to fail-close ALL chain writers when
/// the sentinel is present.
pub fn is_chain_broken(base_dir: &Path) -> Option<String> {
    let path = sentinel_path(base_dir);
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(s.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            // Unreadable sentinel (permissions, I/O error) → treat as broken
            // (fail-closed: if we cannot confirm the chain is sound, refuse to
            // extend it).
            Some("audit_sentinel_unreadable".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{KeyId, LedgerError, RecordId};

    fn key_id(hex: &str) -> KeyId {
        KeyId::try_new(format!("ed25519:{hex}")).unwrap()
    }

    fn sha256_genesis() -> crate::audit::types::Sha256Hex {
        crate::audit::types::Sha256Hex::genesis()
    }

    fn record_id() -> RecordId {
        RecordId::try_new("01JZ00000000000000000000R0").unwrap()
    }

    /// `Verified` is operational.
    #[test]
    fn verified_is_operational() {
        assert!(AuditHealth::Verified.is_operational());
    }

    /// `Degraded` is operational.
    #[test]
    fn degraded_is_operational() {
        let h = AuditHealth::Degraded { gaps: vec![] };
        assert!(h.is_operational());
    }

    /// `Broken` is not operational.
    #[test]
    fn broken_is_not_operational() {
        let h = AuditHealth::Broken {
            error_kind: "audit_chain_broken_at_seq_0".to_string(),
            reason: "test".to_string(),
        };
        assert!(!h.is_operational());
    }

    /// `Unknown` is not operational.
    #[test]
    fn unknown_is_not_operational() {
        let h = AuditHealth::Unknown {
            reason: "audit_verify_timeout".to_string(),
        };
        assert!(!h.is_operational());
    }

    /// `should_anchor` (anchor-skip predicate): Broken → false.
    #[test]
    fn should_anchor_false_for_broken() {
        let h = AuditHealth::Broken {
            error_kind: "audit_chain_broken_at_seq_5".to_string(),
            reason: "test".to_string(),
        };
        assert!(!h.is_operational(), "anchor must be skipped when Broken");
    }

    /// `should_anchor` (anchor-skip predicate): Degraded → true.
    #[test]
    fn should_anchor_true_for_degraded() {
        let h = AuditHealth::Degraded {
            gaps: vec![KeyGap {
                key_id: format!("ed25519:{}", "a".repeat(64)),
                first_seq: 0,
                last_seq: 5,
                count: 6,
            }],
        };
        assert!(h.is_operational(), "anchor must proceed when Degraded");
    }

    /// `should_accept_audit_emit`: Broken → false.
    #[test]
    fn should_accept_emit_false_for_broken() {
        let h = AuditHealth::Broken {
            error_kind: "x".to_string(),
            reason: "y".to_string(),
        };
        assert!(!h.is_operational());
    }

    /// `should_accept_audit_emit`: Unknown → false.
    #[test]
    fn should_accept_emit_false_for_unknown() {
        let h = AuditHealth::Unknown {
            reason: "audit_verify_timeout".to_string(),
        };
        assert!(!h.is_operational());
    }

    /// `from_ledger_error` maps `ChainBroken` to a Broken variant.
    #[test]
    fn from_ledger_error_chain_broken() {
        let e = LedgerError::ChainBroken {
            seq: 42,
            expected_prev: sha256_genesis(),
            actual_prev: sha256_genesis(),
        };
        let h = AuditHealth::from_ledger_error(&e);
        assert!(matches!(&h, AuditHealth::Broken { error_kind, .. } if error_kind.contains("42")));
        assert!(!h.is_operational());
    }

    /// `from_ledger_error` maps `InvalidSignature` to a Broken variant.
    #[test]
    fn from_ledger_error_invalid_signature() {
        let e = LedgerError::InvalidSignature {
            record_id: record_id(),
            key_id: key_id(&"b".repeat(64)),
        };
        let h = AuditHealth::from_ledger_error(&e);
        assert!(
            matches!(&h, AuditHealth::Broken { error_kind, .. } if error_kind == "audit_invalid_signature")
        );
    }

    /// `from_ledger_error` maps `KeychainUnavailable` to `Unknown` (transient,
    /// NOT Broken) — the conflation fix. A present-but-inaccessible key must
    /// NOT durably fail the chain or set the `.chain-broken` sentinel.
    #[test]
    fn from_ledger_error_keychain_unavailable_is_unknown() {
        let e = LedgerError::KeychainUnavailable {
            key_id: key_id(&"a".repeat(64)),
        };
        let h = AuditHealth::from_ledger_error(&e);
        assert!(
            matches!(h, AuditHealth::Unknown { .. }),
            "KeychainUnavailable must map to Unknown (transient), got {h:?}"
        );
        assert!(
            !h.is_operational(),
            "Unknown gates the audit subsystem closed"
        );
    }

    /// `from_ledger_error` maps `KeyNotFound` to a Broken variant.
    #[test]
    fn from_ledger_error_key_not_found() {
        let e = LedgerError::KeyNotFound {
            key_id: key_id(&"c".repeat(64)),
        };
        let h = AuditHealth::from_ledger_error(&e);
        assert!(
            matches!(&h, AuditHealth::Broken { error_kind, .. } if error_kind == "audit_current_key_not_found")
        );
    }

    /// `from_ledger_error` maps `HistoricalKeyAtHead` to a Broken variant
    /// containing the head_seq.
    #[test]
    fn from_ledger_error_historical_key_at_head() {
        let e = LedgerError::HistoricalKeyAtHead {
            head_seq: 77,
            key_id: key_id(&"d".repeat(64)),
        };
        let h = AuditHealth::from_ledger_error(&e);
        assert!(matches!(&h, AuditHealth::Broken { error_kind, .. } if error_kind.contains("77")));
        assert!(!h.is_operational());
    }

    /// `from_ledger_error` maps `GapAfterVerifiedSegment` to a Broken variant.
    #[test]
    fn from_ledger_error_gap_after_verified_segment() {
        let e = LedgerError::GapAfterVerifiedSegment {
            gap_seq: 13,
            key_id: key_id(&"e".repeat(64)),
        };
        let h = AuditHealth::from_ledger_error(&e);
        assert!(matches!(&h, AuditHealth::Broken { error_kind, .. } if error_kind.contains("13")));
        assert!(!h.is_operational());
    }

    /// `from_ledger_error` maps `Io` to a Broken variant.
    #[test]
    fn from_ledger_error_io() {
        let e = LedgerError::Io {
            context: crate::audit::types::RedactedString::from_trusted("test io error"),
            source: std::io::Error::other("test"),
        };
        let h = AuditHealth::from_ledger_error(&e);
        assert!(
            matches!(&h, AuditHealth::Broken { error_kind, .. } if error_kind == "audit_chain_io_error")
        );
    }

    /// `AuditHealth` serialises correctly (tag = "status").
    #[test]
    fn audit_health_serializes_with_status_tag() {
        let v = AuditHealth::Verified;
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["status"], "verified");

        let b = AuditHealth::Broken {
            error_kind: "test".to_string(),
            reason: "reason".to_string(),
        };
        let j2 = serde_json::to_value(&b).unwrap();
        assert_eq!(j2["status"], "broken");
        assert_eq!(j2["error_kind"], "test");

        let u = AuditHealth::Unknown {
            reason: "timeout".to_string(),
        };
        let j3 = serde_json::to_value(&u).unwrap();
        assert_eq!(j3["status"], "unknown");
    }

    // -----------------------------------------------------------------------
    // Sentinel helpers — set/clear/is
    // -----------------------------------------------------------------------

    /// `set_chain_broken` + `is_chain_broken` round-trip: content matches.
    #[test]
    fn verify_broken_sets_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        // csq-runs/ must exist for the sentinel write.
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();

        set_chain_broken(base, "audit_invalid_signature");
        let got = is_chain_broken(base);
        assert_eq!(got.as_deref(), Some("audit_invalid_signature"));
    }

    /// `clear_chain_broken` removes the sentinel; `is_chain_broken` returns None.
    #[test]
    fn verify_clean_clears_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();

        set_chain_broken(base, "audit_chain_io_error");
        assert!(is_chain_broken(base).is_some());

        clear_chain_broken(base);
        assert!(is_chain_broken(base).is_none());
    }

    /// When the sentinel is present, `is_chain_broken` returns Some(kind)
    /// (simulates write_record_v2_impl's gate refusing the append).
    #[test]
    fn append_refused_when_chain_broken_sentinel_present() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();

        set_chain_broken(base, "audit_chain_broken_at_seq_5");
        // Simulates what write_record_v2_impl checks:
        let refused = is_chain_broken(base).is_some();
        assert!(refused, "append must be refused when sentinel is present");
    }

    /// When the sentinel is absent, `is_chain_broken` returns None
    /// (simulates write_record_v2_impl's gate allowing the append).
    #[test]
    fn append_proceeds_when_sentinel_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        // Do NOT write a sentinel.
        let refused = is_chain_broken(base).is_some();
        assert!(!refused, "append must proceed when sentinel is absent");
    }

    /// Ok-with-empty-gaps → Verified mapping (used by daemon startup).
    #[test]
    fn ok_clean_maps_to_verified() {
        // Demonstrate the mapping logic used in daemon.rs inline.
        let gaps: Vec<KeyGap> = vec![];
        let health = if gaps.is_empty() {
            AuditHealth::Verified
        } else {
            AuditHealth::Degraded { gaps }
        };
        assert!(matches!(health, AuditHealth::Verified));
    }

    /// Ok-with-gaps → Degraded mapping.
    #[test]
    fn ok_with_gaps_maps_to_degraded() {
        let gaps = vec![KeyGap {
            key_id: format!("ed25519:{}", "f".repeat(64)),
            first_seq: 0,
            last_seq: 2,
            count: 3,
        }];
        let health = if gaps.is_empty() {
            AuditHealth::Verified
        } else {
            AuditHealth::Degraded { gaps: gaps.clone() }
        };
        assert!(matches!(health, AuditHealth::Degraded { .. }));
        assert!(health.is_operational());
    }
}
