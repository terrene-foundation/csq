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
//! - [`AuditHealth::Verified`] — clean chain, all records sig-verified,
//!   scanned back to genesis.
//! - [`AuditHealth::TailVerified`] — the scan hit `record_limit` and only the
//!   tail was examined; the head verified clean but genesis and the
//!   anti-truncation checks were skipped. Operational (see the variant's own
//!   doc for why), but deliberately distinct from `Verified` on every
//!   machine-readable surface.
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
//! # Start-time health, promoted by a bounded retry — never re-monitored after that
//!
//! `audit_health` in the daemon's `RouterState` is held behind
//! [`SharedAuditHealth`] (`Arc<RwLock<AuditHealth>>`), read fresh on every
//! request. It is normally a snapshot taken at daemon startup — but when
//! that startup verify times out or panics (`Unknown`), a bounded background
//! retry (`csq/src/cli/commands/daemon.rs::spawn_audit_verify_retry`) may
//! PROMOTE it in place once verification later succeeds, without a daemon
//! restart. Promotion re-arms the audit subsystem: the four fail-closed gate
//! sites below re-read the shared cell on their very next request, and the
//! anchor task — never started when startup health was not operational — is
//! started at that point if it was still pending.
//!
//! This is still NOT continuous monitoring: once the retry either succeeds
//! or exhausts its bounded attempt budget, nothing re-verifies the chain
//! again for the rest of the daemon's life. Post-promotion chain breakage
//! (e.g. a corrupt append by a concurrent writer) is NOT reflected in the
//! in-RAM value until the next `csq doctor` / `csq audit verify` run or
//! daemon restart.
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
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Daemon-shared, mutable-in-place handle on the current [`AuditHealth`].
///
/// Every live request handler (`csq-core/src/daemon/server.rs`'s four
/// audit-subsystem fail-closed gates + `GET /api/audit/health`) reads this
/// through `RouterState::audit_health` fresh on each request — axum clones
/// `RouterState` per request, so the field itself must carry its own
/// interior mutability for a POST-startup update to ever become visible.
/// A bare `AuditHealth` field (the pre-promotion shape) is cloned by value
/// at router-state-construction time and can never be updated again short
/// of a full daemon restart — which is exactly the defect a bounded retry
/// exists to remove (`csq/src/cli/commands/daemon.rs::spawn_audit_verify_retry`).
///
/// `std::sync::RwLock`, not `tokio::sync::RwLock`: every read here is a
/// single non-blocking `matches!`/clone with no `.await` in between, so a
/// std lock never risks holding across a suspension point.
pub type SharedAuditHealth = Arc<RwLock<AuditHealth>>;

/// Wraps an initial [`AuditHealth`] value in the daemon-shared handle.
pub fn new_shared(health: AuditHealth) -> SharedAuditHealth {
    Arc::new(RwLock::new(health))
}

/// Outcome of the daemon's startup `verify_chain` call.
///
/// Stored in [`crate::daemon::server::RouterState`] so every handler can
/// consult it without re-running verification. `Deserialize` is added
/// alongside `Serialize` so a CLIENT (`csq doctor`) can parse this type
/// back out of the daemon's `GET /api/audit/health` response body —
/// reading the SAME channel the daemon itself gates anchoring/emit on,
/// rather than recomputing a possibly-different answer locally
/// (`diagnostic-surface-parity.md` MUST NOT Rule 4). Purely additive: the
/// wire shape (the `Serialize` impl / JSON produced) is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditHealth {
    /// Chain verified clean — all records sig-verified.
    ///
    /// This means the WHOLE chain, genesis included. When the record limit
    /// truncates the scan the verdict is [`AuditHealth::TailVerified`], never
    /// this — see that variant for why the distinction is security-bearing.
    Verified,

    /// The chain verified, but only its TAIL: `record_limit` truncated the scan
    /// and `skipped` older records — INCLUDING GENESIS — were never examined.
    ///
    /// OPERATIONAL (anchoring and emit continue), because the head IS verified
    /// and a chain that has merely outgrown its limit is not evidence of
    /// tampering. But it is NOT [`AuditHealth::Verified`], and conflating the
    /// two is a security defect, because the two checks `verify_chain` skips
    /// under truncation are exactly the ANTI-TRUNCATION checks:
    ///
    /// - the genesis seq-0 requirement (`verify.rs`, gated on
    ///   `limit_exceeded_count == 0`) — so no record is required to be genesis;
    /// - the first record's `prev_hash` link, which is instead SEEDED FROM THE
    ///   RECORD ITSELF and then counted as verified.
    ///
    /// The surviving window's first record is therefore anchored to nothing, so
    /// an adversary who DELETES the oldest records is undetectable by a verify
    /// that reports `Verified`. Observed live 2026-09-13: 11,660 records against
    /// a 10,000 limit, 1,660 skipped, `audit_chain_state: {"status":"verified"}`.
    ///
    /// The human-facing surfaces already said "PARTIAL" (`csq doctor` text and
    /// the compliance report); the machine-readable ones automation gates on
    /// (`csq doctor --json`, `csq audit verify --json`, `GET /api/audit/health`)
    /// said "verified". This variant is what makes them agree.
    TailVerified {
        /// Count of oldest records excluded from the scan, genesis among them.
        skipped: u64,
    },

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
    /// `Verified`, `TailVerified`, and `Degraded` all return `true`: in each
    /// case the chain's HEAD is confirmed intact, so appending further
    /// records is safe. `TailVerified` skipped the anti-truncation checks on
    /// the records it never scanned (see that variant's doc) and `Degraded`
    /// skipped some per-record signatures — neither defect bears on whether
    /// a NEW record can be safely appended to the verified head. `Broken`
    /// and `Unknown` return `false`: in both cases the daemon cannot vouch
    /// for the head itself, so it must not extend the chain.
    pub fn is_operational(&self) -> bool {
        matches!(
            self,
            AuditHealth::Verified | AuditHealth::TailVerified { .. } | AuditHealth::Degraded { .. }
        )
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
            // Key gaps first: a gap is a stronger caveat than truncation, and
            // `Degraded` already carries the detail an operator acts on.
            Ok(summary) if !summary.historical_key_gaps.is_empty() => AuditHealth::Degraded {
                gaps: summary.historical_key_gaps.clone(),
            },
            // Truncated scan -> NOT `Verified`. Before 2026-09-13 this arm did
            // not exist and `limit_exceeded_count` was never consulted here, so
            // a tail-only scan reported a whole-chain verdict on every
            // machine-readable surface.
            Ok(summary) if summary.limit_exceeded_count > 0 => AuditHealth::TailVerified {
                skipped: summary.limit_exceeded_count,
            },
            Ok(_) => AuditHealth::Verified,
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

/// Returns the path of the `.chain-broken` sentinel file for `runs_subdir`.
///
/// The sentinel lives alongside the `.chain-lock` advisory lock, inside the
/// chain's runs-directory (`csq-runs/` for the op-chain, `eatp-runs/` for the
/// born-canonical EATP attestation chain), so it is co-located with — and
/// scoped to — the chain it guards. The two chains have independent sentinels:
/// a broken op-chain does NOT block EATP attestation writes, and vice versa
/// (separate fault domains, W1 chain-id parameterization).
fn sentinel_path(base_dir: &Path, runs_subdir: &str) -> std::path::PathBuf {
    base_dir.join(runs_subdir).join(".chain-broken")
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
///
/// Targets the op-chain (`csq-runs/`). For the EATP attestation chain use
/// [`set_chain_broken_in`] with the chain's runs-subdir.
pub fn set_chain_broken(base_dir: &Path, error_kind: &str) {
    set_chain_broken_in(base_dir, "csq-runs", error_kind);
}

/// Sets the `.chain-broken` sentinel for the chain whose records live under
/// `<base_dir>/<runs_subdir>/`. See [`set_chain_broken`] for the op-chain
/// (`runs_subdir == "csq-runs"`) convenience wrapper and the §5a write contract.
pub fn set_chain_broken_in(base_dir: &Path, runs_subdir: &str, error_kind: &str) {
    // Ensure the runs-dir exists (best-effort; if the dir can't be created, the
    // sentinel write will also fail and we fall through silently — the caller
    // has already logged the error).
    let csq_runs = base_dir.join(runs_subdir);
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

    let path = sentinel_path(base_dir, runs_subdir);
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
/// `AuditHealth::Verified`, `AuditHealth::TailVerified`, or
/// `AuditHealth::Degraded` (chain-linking intact — a tail-only scan still
/// confirms the surviving window links cleanly, it just cannot vouch for the
/// records the record-limit skipped; see that variant's own doc):
/// - `csq/src/cli/commands/daemon.rs` — daemon startup verify block
/// - `csq/src/cli/commands/audit.rs` — `handle_verify`
/// - `csq/src/cli/commands/doctor.rs` — `check_audit_chain`
/// - `csq/src/desktop/daemon_supervisor.rs` — desktop `run_daemon` verify block
///
/// Also called by the desktop daemon path immediately after any repair that
/// brings the chain to a known-good state.
///
/// Targets the op-chain (`csq-runs/`). For the EATP attestation chain use
/// [`clear_chain_broken_in`].
pub fn clear_chain_broken(base_dir: &Path) {
    clear_chain_broken_in(base_dir, "csq-runs");
}

/// Clears the `.chain-broken` sentinel for the chain under
/// `<base_dir>/<runs_subdir>/` (best-effort; ignore ENOENT).
pub fn clear_chain_broken_in(base_dir: &Path, runs_subdir: &str) {
    let path = sentinel_path(base_dir, runs_subdir);
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
///
/// Targets the op-chain (`csq-runs/`). For the EATP attestation chain use
/// [`is_chain_broken_in`].
pub fn is_chain_broken(base_dir: &Path) -> Option<String> {
    is_chain_broken_in(base_dir, "csq-runs")
}

/// Returns `Some(error_kind)` if the `.chain-broken` sentinel for the chain
/// under `<base_dir>/<runs_subdir>/` is present, `None` if absent. Unreadable
/// → fail-closed `Some("audit_sentinel_unreadable")`.
pub fn is_chain_broken_in(base_dir: &Path, runs_subdir: &str) -> Option<String> {
    let path = sentinel_path(base_dir, runs_subdir);
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

/// Classify a `verify_chain` result and reconcile the `.chain-broken` sentinel
/// for the chain under `<base_dir>/<runs_subdir>/`.
///
/// The reconciliation policy matches every existing verify→sentinel callsite:
/// - `Verified` / `Degraded` (chain-linking intact) → CLEAR the sentinel.
/// - `Broken` (fatal `LedgerError`) → SET the sentinel to the fixed-vocab tag.
/// - `Unknown` (transient `KeychainUnavailable`) → leave the sentinel UNCHANGED
///   (a transient verify failure must not produce a durable write-lockout).
///
/// This is the EATP-attestation-chain analogue of the inline op-chain match in
/// `daemon.rs` / `audit.rs` / `doctor.rs` / `daemon_supervisor.rs`. Callers pass
/// the per-chain runs-subdir (`ChainKind::Eatp.runs_subdir()`); the EATP chain's
/// sentinel is an independent fault domain from the op-chain's (W1).
pub fn reconcile_chain_sentinel(
    base_dir: &Path,
    runs_subdir: &str,
    result: &Result<crate::audit::VerifySummary, crate::audit::LedgerError>,
) {
    match AuditHealth::from_verify_result(result) {
        // TailVerified clears the sentinel alongside Verified/Degraded: a chain
        // that outgrew its record limit is not evidence of tampering, and
        // holding a write-lockout open for it would take the audit subsystem
        // down on every long-lived chain. The verdict is still reported as
        // tail-only everywhere it surfaces — the sentinel is about BROKENNESS,
        // not about coverage.
        AuditHealth::Verified | AuditHealth::TailVerified { .. } | AuditHealth::Degraded { .. } => {
            clear_chain_broken_in(base_dir, runs_subdir);
        }
        AuditHealth::Broken { error_kind, .. } => {
            set_chain_broken_in(base_dir, runs_subdir, &error_kind);
        }
        AuditHealth::Unknown { .. } => {
            // Transient (KeychainUnavailable): leave the sentinel unchanged.
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    /// THE SECURITY DEFECT (2026-09-13). `from_verify_result` never consulted
    /// `limit_exceeded_count`, so a scan that skipped the oldest records —
    /// genesis included — returned a whole-chain `Verified` verdict. Observed
    /// live: 11,660 records against a 10,000 limit, 1,660 skipped, and
    /// `csq doctor --json` reporting `{"status":"verified"}`.
    ///
    /// This matters because the two checks `verify_chain` skips under
    /// truncation are precisely the anti-truncation ones: the genesis seq-0
    /// requirement, and the first record's `prev_hash` link (which is instead
    /// seeded from the record itself and then counted as verified). An
    /// adversary deleting the oldest records is therefore invisible to a verify
    /// that says `Verified`.
    ///
    /// REDs against the pre-fix code, which returned `Verified` here.
    #[test]
    fn truncated_scan_is_not_reported_as_whole_chain_verified() {
        let summary = crate::audit::VerifySummary {
            limit_exceeded_count: 1_660,
            ..Default::default()
        };

        let health = AuditHealth::from_verify_result(&Ok(summary));

        match health {
            AuditHealth::TailVerified { skipped } => assert_eq!(
                skipped, 1_660,
                "the verdict must carry the skipped count, not just the fact"
            ),
            other => panic!("a truncated scan MUST NOT report whole-chain Verified; got {other:?}"),
        }
    }

    /// An untruncated clean scan is still plainly `Verified`. Guards against
    /// over-correcting the fix into never reporting a whole-chain verdict.
    #[test]
    fn untruncated_clean_scan_is_still_verified() {
        let summary = crate::audit::VerifySummary::default();
        assert!(matches!(
            AuditHealth::from_verify_result(&Ok(summary)),
            AuditHealth::Verified
        ));
    }

    /// A truncated chain stays OPERATIONAL. Making it non-operational would
    /// disable audit emit and anchoring on every chain that outgrows its
    /// limit — a worse regression than the disclosure gap being fixed.
    #[test]
    fn tail_verified_remains_operational() {
        assert!(AuditHealth::TailVerified { skipped: 1 }.is_operational());
    }
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

    /// M3 §10.5 (W2a): `reconcile_chain_sentinel` sets the per-chain
    /// `.chain-broken` sentinel on `Broken`, clears it on `Verified`, and leaves
    /// it unchanged on `Unknown` (transient) — and the op-chain and EATP-chain
    /// sentinels are INDEPENDENT fault domains (reconciling one never touches the
    /// other).
    #[test]
    fn reconcile_chain_sentinel_sets_clears_unknown_per_subdir_independent() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let verified: Result<crate::audit::VerifySummary, LedgerError> =
            Ok(crate::audit::VerifySummary::default());
        let broken: Result<crate::audit::VerifySummary, LedgerError> =
            Err(LedgerError::KeyNotFound {
                key_id: key_id(&"a".repeat(64)),
            });
        let unknown: Result<crate::audit::VerifySummary, LedgerError> =
            Err(LedgerError::KeychainUnavailable {
                key_id: key_id(&"b".repeat(64)),
            });

        // Broken on eatp-runs → sentinel set there ONLY (op-chain untouched).
        reconcile_chain_sentinel(base, "eatp-runs", &broken);
        assert_eq!(
            is_chain_broken_in(base, "eatp-runs").as_deref(),
            Some("audit_current_key_not_found")
        );
        assert!(
            is_chain_broken_in(base, "csq-runs").is_none(),
            "op-chain sentinel untouched by EATP reconcile"
        );

        // Unknown (transient) leaves the eatp sentinel UNCHANGED (still set).
        reconcile_chain_sentinel(base, "eatp-runs", &unknown);
        assert_eq!(
            is_chain_broken_in(base, "eatp-runs").as_deref(),
            Some("audit_current_key_not_found"),
            "Unknown must not clear a previously-set sentinel"
        );

        // Verified clears the eatp sentinel.
        reconcile_chain_sentinel(base, "eatp-runs", &verified);
        assert!(is_chain_broken_in(base, "eatp-runs").is_none());

        // Symmetric: Broken on the op-chain sets ONLY the op-chain sentinel.
        reconcile_chain_sentinel(base, "csq-runs", &broken);
        assert!(is_chain_broken_in(base, "csq-runs").is_some());
        assert!(
            is_chain_broken_in(base, "eatp-runs").is_none(),
            "EATP sentinel untouched by op-chain reconcile"
        );
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

        // The truncated verdict's wire shape is documented normatively in
        // specs/12-audit-trail.md §12.13.4 and §12.13.5 as
        // `{"status":"tail_verified","skipped":<u64>}` — for BOTH
        // `csq doctor --json`'s `audit_chain_state` and the body of
        // `GET /api/audit/health`. `rename_all = "snake_case"` renames the
        // VARIANT, not the field, so `skipped` is the wire key; pinned here so
        // the spec's claim is gated rather than merely asserted.
        let t = AuditHealth::TailVerified { skipped: 1_660 };
        let jt = serde_json::to_value(&t).unwrap();
        assert_eq!(jt["status"], "tail_verified");
        assert_eq!(jt["skipped"], 1_660);

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
