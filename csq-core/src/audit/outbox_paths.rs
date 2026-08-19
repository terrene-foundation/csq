//! Shared on-disk contract for the durable audit outboxes: the `csq-runs/`
//! subdir names AND the daemon's last-drain-cycle stamp.
//!
//! These are the single source of truth for the outbox directories that a WRITER
//! creates and a READER (e.g. `csq doctor`, which ships in BOTH editions) scans,
//! plus the drain-liveness stamp the daemon writes after every drain cycle and the
//! community `doctor` reads to decide "stuck" vs "daemon down". The writers for
//! some of these live in `#[cfg(feature = "enterprise")]`-gated modules
//! (`mcp_gate_outbox`), but the community `doctor` must still be able to READ what
//! an enterprise `csq-ee` wrote under a shared `$HOME` — so the constants + the
//! stamp helpers live in this NON-gated module, referenced by both sides.
//!
//! Hand-copying the literal into the reader (the prior state: a `.pending-mcp-gate`
//! string duplicated in `doctor.rs`, only doc-comment-linked to the writer's
//! private `OUTBOX_SUBDIR`) let the two drift silently — change one, forget the
//! other, and the reader scans the wrong (empty) directory while a real backlog
//! accumulates unseen. A single shared `pub const` makes that drift impossible by
//! construction rather than merely detectable by a parity test.
//!
//! The names are format-version-locked by the outbox on-disk contract
//! (`specs/25-pact-coding-session-envelope.md` §25.12.4); changing one is a
//! breaking on-disk change, not a refactor.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::platform::fs::{atomic_replace, unique_tmp_path};

/// Absolute path to the MCP-gate outbox directory under `base`.
///
/// Single-sources the FULL path (`<base>/csq-runs/<MCP_GATE_OUTBOX_SUBDIR>`), not
/// just the leaf name — both the enterprise writer (`mcp_gate_outbox::outbox_dir`)
/// and the community `doctor` reader (`check_mcp_gate_outbox_backlog`) call THIS,
/// so neither the leaf name NOR the `csq-runs/` prefix can drift between them.
pub fn mcp_gate_outbox_dir(base: &Path) -> PathBuf {
    base.join("csq-runs").join(MCP_GATE_OUTBOX_SUBDIR)
}

/// Subdir under `csq-runs/` holding the MCP-gate durable attestation outbox:
/// `csq-runs/.pending-mcp-gate/<nonce>.<seq>.json`. Written by the enterprise
/// MCP-gate proxy (`csq mcp-proxy`) when a gated `tools/call` decision cannot be
/// recorded live; drained onto the audit chain by the daemon. Read by
/// `csq doctor`'s backlog predicate (both editions).
///
/// DISTINCT from the `csq run` `.pending/` audit floor: keeping the MCP-gate
/// outbox in its own subdir means the run-record drain (`pass5_audit_drain`,
/// which expects a v1 `AuditRecord` shape) never sees — and never
/// misclassifies — an MCP-gate decision body.
pub const MCP_GATE_OUTBOX_SUBDIR: &str = ".pending-mcp-gate";

/// Subdir under `csq-runs/` holding the M18 provenance-seam quarantine custody
/// set: `csq-runs/.pending/provenance/`. Written by the seam ingest/quarantine
/// path; counted by `csq doctor`'s `seam_pending_provenance_count`.
pub const SEAM_PROVENANCE_SUBDIR: &str = ".pending/provenance";

/// File under `csq-runs/` holding the daemon's last outbox-drain-cycle time as
/// decimal Unix epoch seconds (M6 an internal ticket shard B).
///
/// The daemon stamps this at the END of every drain cycle — startup reconciler,
/// the periodic refresher-tick backstop, AND the event-driven live-path-recovery
/// drain — regardless of whether any file was actually drained. It is therefore a
/// combined **daemon-liveness + drain-activity** signal: a recent stamp means the
/// daemon is up and its continuous-drain loop is running, so a backlog that
/// persists across several stamps is genuinely STUCK; a stale stamp means the
/// daemon is DOWN, so a backlog is merely PENDING (no false alarm during a
/// maintenance window). Read via [`read_outbox_drain_stamp`] by a `csq doctor`
/// drain-liveness predicate (both editions ship `doctor` — hence NON-gated here).
///
/// Epoch seconds (not ISO-8601) so the reader does no timezone/format parsing —
/// the only consumer does age arithmetic (`now - stamp`).
pub const OUTBOX_DRAIN_STAMP_FILE: &str = ".outbox-drain-stamp";

/// Absolute path to the last-drain-cycle stamp under `base`
/// (`<base>/csq-runs/<OUTBOX_DRAIN_STAMP_FILE>`).
pub fn outbox_drain_stamp_path(base: &Path) -> PathBuf {
    base.join("csq-runs").join(OUTBOX_DRAIN_STAMP_FILE)
}

/// Record "a drain cycle completed now" by writing the current wall-clock as
/// decimal Unix epoch seconds to the stamp file, crash-safely (tmp → atomic
/// rename, tmp cleaned on any failure branch per `security.md` §5a — no secret
/// content, but the discipline stays uniform). Best-effort: the daemon calls this
/// for its side effect only, so a failure is returned for the caller to log with a
/// fixed tag, never propagated into the drain outcome.
///
/// The parent `csq-runs/` is expected to exist (the chain lives there); if it does
/// not this returns `Err` and the caller logs — a drain cycle that found nothing
/// to drain in a base with no `csq-runs/` is a no-op whose missing stamp is
/// harmless (nothing could have been queued either).
pub fn stamp_outbox_drain(base: &Path) -> Result<(), String> {
    let path = outbox_drain_stamp_path(base);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = now.to_string();
    let tmp = unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, body.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write outbox-drain stamp tmp: {e}"));
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("atomic-replace outbox-drain stamp: {e}"));
    }
    Ok(())
}

/// Read the last-drain-cycle time as Unix epoch seconds, or `None` when the stamp
/// is absent (no drain cycle has run yet on this base) or unreadable/unparseable
/// (treated as absent — a corrupt stamp must never be interpreted as a recent
/// drain, which would suppress a genuine STUCK alarm; `None` is the fail-safe that
/// makes a drain-liveness predicate treat the liveness as UNKNOWN).
pub fn read_outbox_drain_stamp(base: &Path) -> Option<u64> {
    let path = outbox_drain_stamp_path(base);
    let text = std::fs::read_to_string(path).ok()?;
    text.trim().parse::<u64>().ok()
}

/// File under `csq-runs/` whose PRESENCE is the durable **attestation-intent**
/// marker (M6 an internal ticket shard C).
///
/// The root-cause problem decision 1 solves: at gate-decision time the live path
/// cannot distinguish a *non-audit host* (a chain will never exist — pre-init
/// decisions MUST drop, or the outbox accumulates forever) from a host where the
/// *operator intends to attest* (`csq audit init` is coming — pre-init decisions
/// MUST be preserved, not lost). This marker is that operator declaration:
///
/// - **Set** (marker present, via `csq audit intent on`): a `NoChain` (uninitialised
///   chain) mcp-gate decision returns 503 so the proxy QUEUES it to the durable
///   outbox instead of dropping (204). The drain then preserves the queued file
///   until the chain is initialised (it defers on an un-appendable chain), and
///   shard B's continuous drain flushes it within one interval of `csq audit init`.
/// - **Unset** (default — marker absent): drop as before (204). A non-audit host
///   never accumulates.
///
/// It is a marker file (presence = set), NOT a per-record intent — DISTINCT from
/// the EATP on-chain intent records scanned by `audit::intent_scan`. NON-gated here
/// because the setter (`csq audit intent`, both editions ship the verb) and the
/// reader (`csq doctor`, both editions) must agree on the path while the live
/// producer (mcp-gate handler) is enterprise-only.
///
/// NOT cleared by `csq audit init`: once an operator has declared attestation
/// intent it holds through any future chain reset/re-init window (a `csq audit
/// repair --apply` backs up + resets the chain, re-opening the NoChain window —
/// intent must survive it). The operator clears it explicitly with
/// `csq audit intent off`.
pub const ATTESTATION_INTENT_FILE: &str = ".attestation-intent";

/// Absolute path to the attestation-intent marker under `base`
/// (`<base>/csq-runs/<ATTESTATION_INTENT_FILE>`).
pub fn attestation_intent_path(base: &Path) -> PathBuf {
    base.join("csq-runs").join(ATTESTATION_INTENT_FILE)
}

/// Whether the operator has declared attestation intent (the marker is present).
/// Any stat error other than "exists" reads as NOT set — the fail-safe direction:
/// an unreadable marker must default to the SAFE non-accumulating behaviour (drop),
/// never to silently queueing on a host that may not intend to attest.
pub fn attestation_intent_is_set(base: &Path) -> bool {
    attestation_intent_path(base).exists()
}

/// Declare attestation intent by creating the durable marker (idempotent — a
/// re-`set` on an existing marker is a no-op success). The parent `csq-runs/` is
/// created if absent (the operator may declare intent BEFORE `csq audit init`
/// materialises the chain dir — that setup-ordering window is the whole point).
/// The marker body is a short human-readable note; only its PRESENCE is load-bearing.
pub fn set_attestation_intent(base: &Path) -> Result<(), String> {
    let dir = base.join("csq-runs");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create csq-runs/ for intent marker: {e}"))?;
    let path = attestation_intent_path(base);
    let tmp = unique_tmp_path(&path);
    let body = b"attestation-intent: on\n";
    if let Err(e) = std::fs::write(&tmp, body) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write attestation-intent tmp: {e}"));
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("atomic-replace attestation-intent: {e}"));
    }
    Ok(())
}

/// Clear attestation intent by removing the marker (idempotent — clearing an
/// absent marker is a no-op success, so the default/unset state is reachable
/// without error). A `NotFound` is success; any other removal error is returned.
pub fn clear_attestation_intent(base: &Path) -> Result<(), String> {
    let path = attestation_intent_path(base);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove attestation-intent marker: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden: these names are the on-disk outbox contract
    /// (`specs/25-pact-coding-session-envelope.md` §25.12.4). A change here is a
    /// breaking on-disk change that also breaks a live daemon mid-drain — it must
    /// be deliberate, reviewed, and spec-synced, never an incidental refactor.
    #[test]
    fn subdir_names_are_the_frozen_on_disk_contract() {
        assert_eq!(MCP_GATE_OUTBOX_SUBDIR, ".pending-mcp-gate");
        assert_eq!(SEAM_PROVENANCE_SUBDIR, ".pending/provenance");
    }

    /// The full-path helper pins the `csq-runs/` prefix too, so the writer and
    /// reader that both call it cannot diverge on the leaf OR the prefix.
    #[test]
    fn mcp_gate_outbox_dir_is_the_full_frozen_path() {
        let base = Path::new("/tmp/csq-test-base");
        assert_eq!(
            mcp_gate_outbox_dir(base),
            base.join("csq-runs").join(".pending-mcp-gate"),
        );
    }

    /// The drain stamp round-trips: write then read returns a recent epoch second.
    #[test]
    fn outbox_drain_stamp_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("csq-runs")).unwrap();

        assert!(
            read_outbox_drain_stamp(dir.path()).is_none(),
            "no stamp before any drain cycle → None"
        );

        stamp_outbox_drain(dir.path()).expect("stamp write");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stamped = read_outbox_drain_stamp(dir.path()).expect("stamp present after write");
        // Within a generous window of "now" (test wall-clock).
        assert!(
            stamped <= now && now - stamped <= 5,
            "stamp {stamped} must be within 5s of now {now}"
        );
    }

    /// A corrupt (non-numeric) stamp reads as `None` — the fail-safe that makes a
    /// drain-liveness predicate treat it as UNKNOWN rather than "recently drained".
    #[test]
    fn outbox_drain_stamp_corrupt_reads_none() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("csq-runs")).unwrap();
        std::fs::write(outbox_drain_stamp_path(dir.path()), b"not-a-number").unwrap();
        assert!(
            read_outbox_drain_stamp(dir.path()).is_none(),
            "corrupt stamp must read as None, never as a recent drain"
        );
    }

    /// `stamp_outbox_drain` leaves no `.tmp.` residue on the happy path (§5a).
    #[test]
    fn outbox_drain_stamp_leaves_no_tmp_residue() {
        let dir = tempfile::TempDir::new().unwrap();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        stamp_outbox_drain(dir.path()).unwrap();
        let residue: Vec<_> = std::fs::read_dir(&csq_runs)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(residue.is_empty(), "§5a: leaked tmp files: {residue:?}");
    }

    // ── attestation-intent marker (shard C) ──────────────────────────────────

    /// Default (no marker) is UNSET; set → is_set; clear → unset. Idempotent both
    /// ways.
    #[test]
    fn attestation_intent_set_clear_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(
            !attestation_intent_is_set(dir.path()),
            "default host has NO attestation intent (drop, don't accumulate)"
        );

        // set creates csq-runs/ if absent (pre-init declaration window).
        set_attestation_intent(dir.path()).expect("set");
        assert!(
            attestation_intent_is_set(dir.path()),
            "after set the marker is present"
        );
        // idempotent set.
        set_attestation_intent(dir.path()).expect("re-set is a no-op success");
        assert!(attestation_intent_is_set(dir.path()));

        clear_attestation_intent(dir.path()).expect("clear");
        assert!(
            !attestation_intent_is_set(dir.path()),
            "after clear the marker is gone"
        );
        // idempotent clear (absent marker → Ok).
        clear_attestation_intent(dir.path()).expect("clearing an absent marker is a no-op success");
    }

    /// `set_attestation_intent` materialises `csq-runs/` when it does not yet
    /// exist — the operator declares intent BEFORE `csq audit init` creates the
    /// chain dir (the setup-ordering window decision 1 targets).
    #[test]
    fn attestation_intent_set_creates_csq_runs_when_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!dir.path().join("csq-runs").exists());
        set_attestation_intent(dir.path()).expect("set before csq-runs exists");
        assert!(
            dir.path().join("csq-runs").exists(),
            "set must create csq-runs/ for the pre-init declaration"
        );
        assert!(attestation_intent_is_set(dir.path()));
    }

    /// The marker leaves no `.tmp.` residue on the happy path (§5a).
    #[test]
    fn attestation_intent_set_leaves_no_tmp_residue() {
        let dir = tempfile::TempDir::new().unwrap();
        set_attestation_intent(dir.path()).unwrap();
        let residue: Vec<_> = std::fs::read_dir(dir.path().join("csq-runs"))
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(residue.is_empty(), "§5a: leaked tmp files: {residue:?}");
    }
}
