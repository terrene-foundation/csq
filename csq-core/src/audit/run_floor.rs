//! M19b — chain-level session floor: a signed `CsqRun` record per `csq run`.
//!
//! ## Why this exists
//!
//! `csq run` emits a schema-v1 [`crate::audit::AuditRecord`] to
//! `csq-runs/<run_id>.jsonl` (the `AuditEmitter` → daemon IPC path). That v1
//! record is UNSIGNED and lives OUTSIDE the v2 signed chain, so an auditor
//! verifying the chain alone sees no per-surface session record — a
//! zero-provenance session reads as silence rather than "attested session +
//! declared-unwired capture" (M19 PRIMARY METHODOLOGICAL DIRECTIVE #2).
//!
//! M19b makes every run a first-class chain citizen: when the daemon ingests a
//! v1 run record it appends a signed, hash-chained [`EventKind::CsqRun`]
//! [`SignedRecord`] carrying the same `run_id`. Because it lives in the v2
//! chain, it is automatically included in the `csq audit export` bundle and
//! verified by `verify_chain` — no separate verification path is required
//! (the AC4 option-(a) resolution; option (b) would have had to retrofit the
//! unsigned v1 records into the bundle with their own commitment scheme).
//!
//! ## Idempotency
//!
//! The emit is keyed `run:<run_id>` in the M20 in-lock dedup index, so the
//! rare double-emit window — a live IPC handler success whose response is lost,
//! the CLI then falling back to `.pending`, and the startup reconciler draining
//! that `.pending` record — appends exactly ONE floor record per run.
//!
//! ## Signing posture
//!
//! The run is an already-committed side effect by the time the daemon sees its
//! record, so emission uses the OUTCOME-phase posture
//! ([`crate::audit::op_emit::emit_observation_deduped`]): signed when the key is
//! available, unsigned when no key is registered (pre-cutoff), and SKIPPED
//! (never unsigned) when a signing cutoff is active but the keychain is
//! unavailable. A skip loses only this run's floor record — it never bricks the
//! chain and never blocks the user's `csq run`.

use std::path::Path;

use crate::audit::key_custody::ChainState;
use crate::audit::op_emit::emit_observation_deduped;
use crate::audit::persist::{AuditV2Error, SeamWriteSpec, AUDIT_SCHEMA_VERSION};
use crate::audit::types::{
    CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
    SignedRecord,
};

/// Build the unsigned skeleton `CsqRun` record. `seq`, `prev_hash`,
/// `canonical_hash`, `chain_id`, `ts`, and `signature` are (re)assigned by the
/// writer inside `.chain-lock`; the placeholder values here are overwritten.
///
/// Rejects an empty `chain_id_str` rather than letting the writer mint a new
/// chain genesis — a floor record MUST NOT trigger chain initialisation (the
/// same fail-closed guard `seam::capture_matrix::build_matrix_record` uses).
fn build_csq_run_record(chain_id_str: &str, run_id: &str) -> Result<SignedRecord, AuditV2Error> {
    if chain_id_str.is_empty() {
        return Err(AuditV2Error::ChainCorrupt {
            reason: "csq-run floor emit called with empty chain_id; chain must be \
                     initialised before emitting an M19b record"
                .to_string(),
        });
    }
    let chain_id =
        RecordId::try_new(chain_id_str.to_string()).map_err(|e| AuditV2Error::ChainCorrupt {
            reason: format!("chain_id '{chain_id_str}' is not a valid RecordId: {e}"),
        })?;
    let record_id = RecordId::try_new(crate::audit::persist::gen_chain_id()).map_err(|e| {
        AuditV2Error::ChainCorrupt {
            reason: format!("gen_chain_id produced invalid record_id: {e}"),
        }
    })?;
    let key_id = KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).map_err(|e| {
        AuditV2Error::ChainCorrupt {
            reason: format!("placeholder KeyId invalid: {e}"),
        }
    })?;
    Ok(SignedRecord {
        schema_version: AUDIT_SCHEMA_VERSION.to_string(),
        record_id,
        chain_id,
        seq: 0,
        prev_hash: Sha256Hex::genesis(),
        kind: EventKind::CsqRun,
        payload: EventPayload::CsqRun(CsqRunPayload {
            run_id: run_id.to_string(),
        }),
        ts: crate::audit::persist::current_iso8601_utc_persist(),
        key_id,
        canonical_hash: Sha256Hex::genesis(),
        signature: Ed25519Signature::new([0u8; 64]),
        actor: None,
        authority: None,
        trust: None,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: None, // STATE/observation record — no intent/outcome envelope
    })
}

/// Emit the signed chain-level session-floor record for one `csq run`.
///
/// Callers (the daemon `audit_record_handler` and the startup reconciler's
/// `.pending` drain) pass the run's `run_id` AFTER the v1 record is durable.
/// This is best-effort + idempotent: the v1 record is already persisted, so a
/// floor-emit failure or skip is NON-fatal and never propagated to the user.
///
/// Returns `Ok(true)` when a floor record was appended, `Ok(false)` when
/// skipped (chain not yet initialised, duplicate run_id, `.chain-broken`
/// sentinel, or cutoff-active + keychain-unavailable), and `Err` only on a hard
/// I/O / chain-loader error the caller should log.
pub fn emit_csq_run_record(base: &Path, run_id: &str) -> Result<bool, AuditV2Error> {
    // Chain must be initialised. If chain.json has no chain_id yet, do NOT emit
    // (a floor record must not mint a genesis). Non-fatal skip.
    let chain_id = ChainState::load(base)
        .map(|s| s.chain_id)
        .unwrap_or_default();
    if chain_id.is_empty() {
        return Ok(false);
    }

    let record = build_csq_run_record(&chain_id, run_id)?;
    let dedup_key = format!("run:{run_id}");
    let spec = SeamWriteSpec {
        dedup_key: &dedup_key,
    };
    emit_observation_deduped(base, record, &spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::persist::write_record_v2;
    use tempfile::TempDir;

    /// Bootstrap a chain genesis via the authorized writer (placeholder key,
    /// unsigned) so `emit_csq_run_record` — which refuses to mint a genesis —
    /// has a chain to append to. Stands in for `csq audit init`.
    fn bootstrap_chain(base: &Path) {
        let rec = build_csq_run_record("01JZ00000000000000000000R0", "bootstrap-genesis")
            .expect("build bootstrap record");
        write_record_v2(rec, Some(base)).expect("bootstrap chain genesis");
    }

    fn chain_jsonl_text(base: &Path) -> String {
        let chain_json = base.join("csq-runs").join("chain.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&chain_json).unwrap()).unwrap();
        let chain_id = v["chain_id"].as_str().unwrap();
        std::fs::read_to_string(base.join("csq-runs").join(format!("{chain_id}.jsonl"))).unwrap()
    }

    /// Count chain lines whose `CsqRun` payload carries `run_id`.
    fn count_csq_run(base: &Path, run_id: &str) -> usize {
        use crate::audit::types::{EventPayload, SignedRecord};
        chain_jsonl_text(base)
            .lines()
            .filter_map(|l| serde_json::from_str::<SignedRecord>(l).ok())
            .filter(|r| matches!(&r.payload, EventPayload::CsqRun(p) if p.run_id == run_id))
            .count()
    }

    /// Production path: a floor record is appended for an initialised chain.
    #[test]
    fn emit_writes_floor_record_for_initialised_chain() {
        let dir = TempDir::new().unwrap();
        bootstrap_chain(dir.path());

        let emitted = emit_csq_run_record(dir.path(), "run-aaa").expect("no hard error");
        assert!(
            emitted,
            "must append a floor record for an initialised chain"
        );
        assert_eq!(
            count_csq_run(dir.path(), "run-aaa"),
            1,
            "exactly one CsqRun floor record for run-aaa"
        );
    }

    /// A floor record MUST NOT mint a chain genesis: uninitialised chain → skip.
    #[test]
    fn emit_skips_when_chain_not_initialised() {
        let dir = TempDir::new().unwrap();
        let emitted = emit_csq_run_record(dir.path(), "run-bbb").expect("no hard error");
        assert!(!emitted, "uninitialised chain must skip (Ok(false))");
        assert!(
            !dir.path().join("csq-runs").join("chain.json").exists(),
            "floor emit must NOT create chain.json (no genesis minting)"
        );
    }

    /// Replay of the same run_id is deduped in-lock: exactly one floor record.
    #[test]
    fn replay_same_run_id_is_deduped() {
        let dir = TempDir::new().unwrap();
        bootstrap_chain(dir.path());

        assert!(
            emit_csq_run_record(dir.path(), "run-ccc").unwrap(),
            "first emit writes"
        );
        let second = emit_csq_run_record(dir.path(), "run-ccc").expect("no hard error");
        assert!(!second, "replay of same run_id must be deduped (Ok(false))");
        assert_eq!(
            count_csq_run(dir.path(), "run-ccc"),
            1,
            "replayed run_id must appear exactly once in the chain"
        );
    }

    // NOTE: the in-lock unsigned-after-cutoff guard (M3) is exercised at the
    // `write_record_v2` level in `persist.rs`
    // (`write_record_v2_refuses_unsigned_at_real_cutoff`), not here. Via the
    // floor path the OUTCOME posture in `emit_observation_deduped` already SKIPS
    // (never writes unsigned) when a REAL cutoff is active and the key is
    // unavailable, so the floor path never reaches the guard in that state. The
    // guard defends the RACE (caller decided unsigned, then chain.json gained
    // cutoff+key before the locked write) — best tested at the writer boundary.

    /// R1-MED-1 regression: in the PARTIAL-INIT state (cutoff written but NO
    /// signing key registered — `key_custody/init.rs` documents this as
    /// reachable), `verify_chain` treats the chain as having NO cutoff and
    /// accepts placeholder records at every seq. The in-lock guard MUST therefore
    /// NOT fire — gating on `signing_active_since_seq` alone would false-refuse
    /// legitimate unsigned writes and abort lifecycle ops. The floor record (and
    /// any unsigned write) MUST succeed in this state.
    #[test]
    fn partial_init_unsigned_floor_allowed() {
        use crate::audit::key_custody::ChainState;

        let dir = TempDir::new().unwrap();
        bootstrap_chain(dir.path());

        // Partial-init: cutoff present, signing_key_id ABSENT.
        let mut cs = ChainState::load(dir.path()).expect("load chain state");
        cs.signing_active_since_seq = Some(1);
        cs.signing_key_id = None;
        cs.save(dir.path()).expect("save partial-init state");

        let emitted = emit_csq_run_record(dir.path(), "run-fff")
            .expect("partial-init unsigned floor MUST NOT be refused");
        assert!(
            emitted,
            "floor record must be written in the partial-init state"
        );
        assert_eq!(count_csq_run(dir.path(), "run-fff"), 1);
    }

    /// Dedup survives a sidecar rebuild: the `.seam-dedup-index` is reconstructed
    /// from the chain (which now indexes `run:<run_id>` per the M19b rebuild arm),
    /// so a replay AFTER the sidecar is dropped is still deduped. This is the
    /// load-bearing guarantee for the Step-9 sidecar-drop-on-failure path.
    #[test]
    fn dedup_survives_index_rebuild() {
        let dir = TempDir::new().unwrap();
        bootstrap_chain(dir.path());

        assert!(
            emit_csq_run_record(dir.path(), "run-ddd").unwrap(),
            "first emit writes"
        );

        // Simulate the Step-9 sidecar-drop: delete the dedup index so the next
        // write rebuilds it from the active chain.
        let idx = dir.path().join("csq-runs").join(".seam-dedup-index");
        assert!(idx.exists(), "dedup index should exist after a seam write");
        std::fs::remove_file(&idx).unwrap();

        let replay = emit_csq_run_record(dir.path(), "run-ddd").expect("no hard error");
        assert!(
            !replay,
            "replay after sidecar rebuild must still be deduped — the rebuild MUST \
             re-collect run:<run_id> from the chain"
        );
        assert_eq!(
            count_csq_run(dir.path(), "run-ddd"),
            1,
            "no double-anchor across a sidecar rebuild"
        );
    }
}
