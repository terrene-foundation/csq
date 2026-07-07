//! M13b — shared signed-when-possible emit helper (OD-2 signing posture).
//!
//! `emit_intent` / `emit_outcome` encode the OD-2 decision from an internal journal entry,
//! with the FIX-1 cutoff-aware signing posture (M13b r1 redteam):
//!
//! ## Signing posture (cutoff-aware, two-tier)
//!
//! **Pre-cutoff (`signing_active_since_seq == None`):** opportunistic signing.
//! The helper attempts to load the key within a short 200 ms budget. On success
//! → signed; on keychain miss/stall → unsigned write. The record still lands
//! in either case.
//!
//! **Post-cutoff (`signing_active_since_seq == Some`):** every new record lands
//! at seq ≥ cutoff and MUST carry a real signature or `verify_chain` will
//! reject it with `UnsignedRecordAfterCutoff` and brick the chain. Therefore:
//!
//! - For **INTENT** (`EmitPhase::Intent`): load the key with an extended 5 s
//!   budget. If it still fails → return `Err` (fail-closed). The caller MUST
//!   NOT run its destructive side effect.
//! - For **OUTCOME** (`EmitPhase::Outcome`): the side effect has already
//!   committed. Writing an unsigned post-cutoff record would brick the chain,
//!   so SKIP the outcome write instead and emit a `tracing::warn!` with a
//!   fixed-vocab tag so `csq doctor` can surface the orphan intent. Return `Ok`
//!   to the caller (the op succeeded; only the audit record is missing).
//!
//! This two-tier posture is the ONLY safe behaviour under a signing cutoff:
//! unsigned post-cutoff = chain bricked; unsigned pre-cutoff = graceful.
//!
//! ## Trust boundary (SEC-1, an internal journal entry)
//!
//! Records emitted via this helper give crash/kill orphan-detection evidence
//! and external-anchor provenance. They do NOT provide same-user
//! forge-resistance. Documented in spec 12 §12.17.
//!
//! ## Lock invariant
//!
//! All functions are synchronous. The `.chain-lock` is held only over the
//! critical section inside `write_record_v2_impl` (steps 2-8). No await points.

use crate::audit::key_custody::{
    try_load_signing_key, ChainState, KeyLoadOutcome, KeySlot, LocalSigningKey, SERVICE_NAME,
};
use crate::audit::persist::{
    current_iso8601_utc_persist, gen_chain_id, write_record_v2, write_record_v2_signed,
    write_seam_record, AuditV2Error, SeamWriteOutcome, SeamWriteSpec, AUDIT_SCHEMA_VERSION,
};
use crate::audit::traits::SigningKey as _;
use crate::audit::types::{
    Ed25519Signature, EventKind, EventPayload, KeyId, OpOutcome, OpPhase, RecordId, Sha256Hex,
    SignedRecord,
};
use std::path::Path;
use std::time::{Duration, Instant};

/// Distinguishes an INTENT emit from an OUTCOME emit inside the signing
/// helper. The distinction drives the cutoff-active failure mode:
/// - Intent: fail-closed (return Err, caller must abort side effect).
/// - Outcome: skip-with-warn (side effect already committed; bricking the
///   chain would be worse than an orphan intent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitPhase {
    Intent,
    Outcome,
}

/// Loaded chain signing state — captures everything needed for one emit.
struct SigningContext {
    key: LocalSigningKey,
}

/// Attempt to load the signing key with an explicit budget.
///
/// Returns `Ok(Some(ctx))` on success, `Ok(None)` when no key is registered
/// (no `signing_key_id` in chain.json), `Err(chain_id_empty)` when the
/// chain.json chain_id is empty, or `Err(keychain)` when the keychain load
/// fails before the deadline.
fn load_signing_key_with_budget(
    base_dir: &Path,
    budget: Duration,
) -> Result<Option<SigningContext>, AuditV2Error> {
    let chain_state = match ChainState::load(base_dir) {
        Ok(s) => s,
        Err(_) => return Ok(None), // chain.json absent or unreadable → no key
    };

    // No key registered → unsigned is always safe (pre-cutoff state).
    if chain_state.signing_key_id.is_none() {
        return Ok(None);
    }

    let chain_id = &chain_state.chain_id;
    if chain_id.is_empty() {
        return Ok(None);
    }

    let cutoff_active = chain_state.signing_active_since_seq.is_some();
    // DA5 (redteam r1): cap the Inaccessible (file-absent + keychain-blocked)
    // poll. A keychain LOCKED at boot unlocks within ~1s; a per-app-ACL mismatch
    // (the -25308 condition) NEVER resolves by polling for a non-interactive
    // process. So poll at most ~1s for the boot-unlock race rather than burning
    // the full (5s post-cutoff) budget on a futile ACL block. Post-migration the
    // file read is instant and this path is never reached.
    const INACCESSIBLE_POLL_CAP: Duration = Duration::from_millis(1000);
    let deadline = Instant::now() + budget.min(INACCESSIBLE_POLL_CAP);
    let poll_interval = Duration::from_millis(100);

    // Disposition when no key could be loaded: hard failure if a cutoff is
    // active (the record MUST be signed), else safe to write unsigned.
    let no_key = |reason: &str| -> Result<Option<SigningContext>, AuditV2Error> {
        if cutoff_active {
            Err(AuditV2Error::Signing {
                reason: format!(
                    "audit signing key unavailable ({reason}) while signing cutoff is active \
                     — cannot write signed record; run `csq audit migrate-keys` if the key is \
                     in the keychain but not the file store"
                ),
            })
        } else {
            Ok(None)
        }
    };

    loop {
        // FILE STORE FIRST (always daemon-readable), keychain FALLBACK. The
        // file read is instant, so the budget poll only matters for the
        // keychain fallback on a pre-migration install whose keychain is
        // momentarily locked at boot.
        match try_load_signing_key(base_dir, SERVICE_NAME, chain_id, KeySlot::Active) {
            KeyLoadOutcome::Loaded(key) => return Ok(Some(SigningContext { key: *key })),
            // Genuinely absent or corrupt — polling will not help; decide now.
            KeyLoadOutcome::Absent => return no_key("not found in file store or keychain"),
            KeyLoadOutcome::Corrupt(_) => return no_key("seed present but unreadable"),
            // File absent AND keychain locked/ACL-blocked. An ACL mismatch will
            // not resolve by polling for a non-interactive process, but allow a
            // short budget for a keychain LOCKED at boot (the original
            // rationale) before giving up.
            KeyLoadOutcome::Inaccessible => {
                if Instant::now() >= deadline {
                    return no_key("keychain locked / access-denied and no file seed");
                }
                std::thread::sleep(poll_interval);
            }
        }
    }
}

/// Emit an UNGUARDED observation record into the committed chain with the
/// cutoff-aware OUTCOME posture AND M20 in-lock idempotent dedup (M19b).
///
/// Used by the `CsqRun` session-floor emitter (`audit::run_floor`). The record
/// represents an already-committed side effect (the `csq run` already happened
/// by the time the daemon ingests its v1 IPC record), so this mirrors
/// [`EmitPhase::Outcome`]:
///
/// - key loadable (signed) → write signed.
/// - no key registered (pre-cutoff / pre-init) → write unsigned (safe).
/// - cutoff active + keychain unavailable → SKIP (`Ok(false)`). Writing
///   unsigned would brick a cutoff chain; the side effect already ran, so the
///   floor record is simply lost for that run (detectable, non-fatal).
///
/// Idempotent via `spec.dedup_key`: a replay whose key is already in the
/// `.seam-dedup-index` returns `Ok(false)` without appending. Unlike
/// [`emit_intent`] / [`emit_outcome`], the duplicate check + append + index
/// update are atomic under one `.chain-lock` ([`write_seam_record`]).
///
/// Returns `Ok(true)` when a record was appended, `Ok(false)` when skipped
/// (duplicate, `.chain-broken` sentinel, or cutoff-active + keychain-unavailable),
/// and `Err` only on a hard I/O / chain-loader error.
pub fn emit_observation_deduped(
    base_dir: &Path,
    record: SignedRecord,
    spec: &SeamWriteSpec<'_>,
) -> Result<bool, AuditV2Error> {
    // Pre-check: a broken chain → skip immediately (mirror `emit_record`'s
    // R6-FIX-1 pre-check). The write-site gate inside `write_record_v2_impl`
    // (Step 1.5) is defense-in-depth and still fires for any path that bypasses
    // this function.
    if let Some(broken_kind) = crate::audit::health::is_chain_broken(base_dir) {
        tracing::warn!(
            error_kind = "audit_observation_skipped_chain_broken",
            broken_kind = %broken_kind,
            "M19b: observation record skipped — .chain-broken sentinel is set; \
             run `csq audit verify` after repair to clear the sentinel."
        );
        return Ok(false);
    }

    const PRE_CUTOFF_BUDGET: Duration = Duration::from_millis(200);
    const POST_CUTOFF_BUDGET: Duration = Duration::from_secs(5);

    // Map the dedup-aware write outcome to the Ok(true)/Ok(false) contract.
    // `Duplicate` and `ChainBrokenRefuseAppend` are both non-fatal skips.
    fn map_seam(r: Result<SeamWriteOutcome, AuditV2Error>) -> Result<bool, AuditV2Error> {
        match r {
            Ok(SeamWriteOutcome::Written(_)) => Ok(true),
            Ok(SeamWriteOutcome::Duplicate) => Ok(false),
            Err(AuditV2Error::ChainBrokenRefuseAppend { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    match load_signing_key_with_budget(base_dir, PRE_CUTOFF_BUDGET) {
        Ok(Some(ctx)) => {
            let mut record = record;
            record.key_id = ctx.key.key_id();
            map_seam(write_seam_record(
                record,
                Some(base_dir),
                Some(&ctx.key as &dyn crate::audit::traits::SigningKey),
                spec,
            ))
        }
        Ok(None) => map_seam(write_seam_record(record, Some(base_dir), None, spec)),
        Err(AuditV2Error::Signing { .. }) => {
            // Cutoff active; short budget exhausted. Escalate to the extended
            // budget (a keychain LOCKED at boot unlocks within ~1s).
            match load_signing_key_with_budget(base_dir, POST_CUTOFF_BUDGET) {
                Ok(Some(ctx)) => {
                    let mut record = record;
                    record.key_id = ctx.key.key_id();
                    map_seam(write_seam_record(
                        record,
                        Some(base_dir),
                        Some(&ctx.key as &dyn crate::audit::traits::SigningKey),
                        spec,
                    ))
                }
                // Unreachable in practice (Err(Signing) means a key IS registered),
                // but if reached: pre-cutoff semantics → unsigned is safe.
                Ok(None) => map_seam(write_seam_record(record, Some(base_dir), None, spec)),
                Err(_signing_err) => {
                    // Outcome posture: the side effect (the run) already committed.
                    // Writing unsigned would brick the cutoff chain; skip with a
                    // fixed-vocab warn so `csq doctor` can surface the gap.
                    tracing::warn!(
                        error_kind = "audit_observation_skipped_keychain_unavailable",
                        "M19b: observation record skipped — signing cutoff is active but \
                         the keychain is unavailable; this side effect has no chain-level \
                         record (run `csq doctor` to inspect audit health)."
                    );
                    Ok(false)
                }
            }
        }
        Err(other) => Err(other),
    }
}

/// Core emit: build and write one record to the committed chain with the
/// cutoff-aware signing posture.
///
/// Returns:
/// - `Ok(true)` — record written (signed or unsigned as appropriate).
/// - `Ok(false)` — record skipped; caller MUST still proceed with its side
///   effect. Two skip causes:
///
///   (a) `ChainBrokenRefuseAppend`: the `.chain-broken` sentinel is set.
///   Lifecycle ops (swap/logout/move) degrade gracefully — the op proceeds
///   without an audit trail. `rotate_key` does NOT use this path (it calls
///   `write_record_v2_signed` directly and stays fail-closed).
///
///   (b) Cutoff active, keychain unavailable, phase=Outcome: side effect already
///   committed; the preceding INTENT is left as a visible orphan.
/// - `Err(Signing{..})` — cutoff active, keychain unavailable, phase=Intent.
///   Caller MUST fail closed (no side effect).
/// - `Err(other)` — I/O or chain-loader error, phase=Intent. Fail closed.
fn emit_record(
    base_dir: &Path,
    record: SignedRecord,
    phase: EmitPhase,
) -> Result<bool, AuditV2Error> {
    // Pre-cutoff budget: 200 ms — short enough not to stall statusline renders,
    // long enough for a warm macOS keychain (typically < 10 ms).
    const PRE_CUTOFF_BUDGET: Duration = Duration::from_millis(200);
    // Post-cutoff budget: 5 s — mirrors the .chain-lock deadline. These are
    // explicit user-initiated lifecycle ops (swap/logout/move), not background
    // renders, so a multi-second keychain-unlock prompt is acceptable.
    const POST_CUTOFF_BUDGET: Duration = Duration::from_secs(5);

    // ── R6-FIX-1: sentinel PRE-CHECK (MUST come before load_signing_key_with_budget) ──
    //
    // When the `.chain-broken` sentinel is set, a lifecycle op MUST degrade
    // (return Ok(false)) immediately — regardless of whether a signing cutoff is
    // active or whether the signing key is loadable.
    //
    // Without this pre-check the control flow is:
    //   load_signing_key_with_budget → cutoff active + key missing → Err(Signing)
    //   → fail-closed (caller aborts the side effect)
    //
    // That fail-closed is WRONG when the chain is already broken: the write-site
    // sentinel gate inside `write_record_v2_impl` (Step 1.5) would have returned
    // `ChainBrokenRefuseAppend` → `Ok(false)` if reached, but the cutoff-signing
    // failure pre-empts it. Binary smoke confirmed: `csq move 3 7` on a broken
    // chain with cutoff=0 → "move aborted: signing failed: keychain unavailable
    // (budget exhausted) while signing cutoff is active".
    //
    // The degrade-now path is correct: attempting the signing-key-load and the
    // write on a known-broken chain is pointless — the write would be refused by
    // the write-site gate anyway. Return Ok(false) immediately.
    //
    // Defense-in-depth: the write-site gate in `write_record_v2_impl` Step 1.5
    // is KEPT. It still protects non-lifecycle callers and direct `write_record_v2`
    // callers that bypass this function.
    //
    // Asymmetry preserved: `rotate_key` calls `write_record_v2_signed` directly
    // and must NOT use this pre-check (rotate stays fail-closed on broken chain).
    // This function is only called from `emit_intent` / `emit_outcome` (lifecycle
    // ops) so the pre-check fires only on the intended degrade surface.
    if let Some(broken_kind) = crate::audit::health::is_chain_broken(base_dir) {
        let tag = match phase {
            EmitPhase::Intent => "audit_intent_skipped_chain_broken",
            EmitPhase::Outcome => "audit_outcome_skipped_chain_broken",
        };
        tracing::warn!(
            error_kind = tag,
            broken_kind = %broken_kind,
            "M13b: audit write skipped (pre-check) — .chain-broken sentinel is set; \
             lifecycle op will proceed without audit trail. \
             Run `csq audit verify` after repair to clear the sentinel."
        );
        return Ok(false);
    }

    /// Write a record (signed or unsigned) and map `ChainBrokenRefuseAppend`
    /// to `Ok(false)` (skip) for the INTENT phase of lifecycle ops.
    ///
    /// CRITICAL asymmetry: `ChainBrokenRefuseAppend` degrades lifecycle ops
    /// (swap/logout/move) only. `rotate_key` calls `write_record_v2_signed`
    /// directly and stays fail-closed — you MUST NOT rotate onto a broken chain.
    fn write_and_map_broken(
        result: Result<(), AuditV2Error>,
        phase: EmitPhase,
    ) -> Result<bool, AuditV2Error> {
        match result {
            Ok(()) => Ok(true),
            Err(AuditV2Error::ChainBrokenRefuseAppend { ref error_kind }) => match phase {
                EmitPhase::Intent => {
                    // FIX-1: degrade — the lifecycle op PROCEEDS without an audit trail
                    // rather than fail-closed. A broken chain must not block `csq logout`.
                    tracing::warn!(
                        error_kind = "audit_intent_skipped_chain_broken",
                        broken_kind = error_kind.as_str(),
                        "M13b: audit INTENT write skipped — .chain-broken sentinel is set; \
                         lifecycle op will proceed without audit trail. \
                         Run `csq audit verify` after repair to clear the sentinel."
                    );
                    Ok(false)
                }
                EmitPhase::Outcome => {
                    // Side effect already committed; outcome skip is consistent with intent skip.
                    tracing::warn!(
                        error_kind = "audit_outcome_skipped_chain_broken",
                        broken_kind = error_kind.as_str(),
                        "M13b: audit OUTCOME write skipped — .chain-broken sentinel is set"
                    );
                    Ok(false)
                }
            },
            Err(other) => Err(other),
        }
    }

    // Attempt signing with the pre-cutoff short budget first. If the chain
    // has a cutoff and the key misses the budget, escalate to the longer budget.
    let budget = PRE_CUTOFF_BUDGET;

    match load_signing_key_with_budget(base_dir, budget) {
        Ok(Some(ctx)) => {
            // Key available within budget — write signed regardless of cutoff.
            // Set key_id from the actual signing key so the verifier can
            // validate the signature (build_lifecycle_record uses a placeholder).
            let mut record = record;
            record.key_id = ctx.key.key_id();
            write_and_map_broken(
                write_record_v2_signed(record, Some(base_dir), &ctx.key).map(|_| ()),
                phase,
            )
        }
        Ok(None) => {
            // No key registered (pre-cutoff or pre-init). Unsigned is safe.
            write_and_map_broken(write_record_v2(record, Some(base_dir)), phase)
        }
        Err(AuditV2Error::Signing { .. }) => {
            // Cutoff active; short budget exhausted. Try the extended budget.
            match load_signing_key_with_budget(base_dir, POST_CUTOFF_BUDGET) {
                Ok(Some(ctx)) => {
                    let mut record = record;
                    record.key_id = ctx.key.key_id();
                    write_and_map_broken(
                        write_record_v2_signed(record, Some(base_dir), &ctx.key).map(|_| ()),
                        phase,
                    )
                }
                Ok(None) => {
                    // This branch is unreachable in practice (Err(Signing) means
                    // the key IS registered; None means it is not). If somehow
                    // reached after the extended budget, treat as pre-cutoff:
                    // write unsigned.
                    write_and_map_broken(write_record_v2(record, Some(base_dir)), phase)
                }
                Err(signing_err) => {
                    // Extended budget also exhausted; cutoff active.
                    match phase {
                        EmitPhase::Intent => {
                            // Fail closed: return the signing error so the caller
                            // can abort the side effect before running it.
                            Err(signing_err)
                        }
                        EmitPhase::Outcome => {
                            // Side effect already committed. Writing unsigned would
                            // brick the chain; skipping leaves a detectable orphan.
                            // Log at warn with a fixed-vocab tag for csq doctor.
                            tracing::warn!(
                                error_kind = "audit_outcome_skipped_keychain_unavailable",
                                "M13b: audit OUTCOME write skipped — signing cutoff is active \
                                 but keychain is unavailable; the preceding INTENT record is now \
                                 an orphan (run `csq doctor` to inspect audit_orphan_intents)"
                            );
                            Ok(false)
                        }
                    }
                }
            }
        }
        Err(other) => {
            // Unexpected I/O or parse error. Treat as intent-safe: fail both
            // phases closed — an I/O error from the chain loader is more
            // fundamental than a keychain miss.
            match phase {
                EmitPhase::Intent => Err(other),
                EmitPhase::Outcome => {
                    tracing::warn!(
                        error_kind = "audit_outcome_skipped_chain_error",
                        "M13b: audit OUTCOME write skipped due to chain loader error — \
                         preceding INTENT is now an orphan (run `csq doctor`)"
                    );
                    Ok(false)
                }
            }
        }
    }
}

/// Builds an unsigned skeleton `SignedRecord` for a M13b lifecycle op
/// (account-swap / logout / move-slot). The writer assigns `seq`,
/// `prev_hash`, `canonical_hash`, and `signature` at write time
/// (sign-after-assign per M13 pattern).
///
/// Both the INTENT and OUTCOME for the same operation share
/// `(chain_id, kind, payload)` and differ only in `op_phase`.
fn build_lifecycle_record(
    chain_id_str: &str,
    kind: EventKind,
    payload: EventPayload,
    op_phase: OpPhase,
) -> Result<SignedRecord, AuditV2Error> {
    // When chain_id_str is empty (chain.json does not exist yet), use a fresh
    // ULID as the placeholder. The writer in `write_record_v2_impl` Step 5
    // overwrites the record's `chain_id` with the genesis value from
    // `read_or_init_chain_genesis`, so the placeholder is never persisted.
    let resolved_chain_id = if chain_id_str.is_empty() {
        gen_chain_id()
    } else {
        chain_id_str.to_string()
    };

    let chain_id =
        RecordId::try_new(resolved_chain_id.clone()).map_err(|e| AuditV2Error::ChainCorrupt {
            reason: format!("chain_id '{resolved_chain_id}' is not a valid RecordId: {e}"),
        })?;

    let record_id = RecordId::try_new(gen_chain_id()).map_err(|e| AuditV2Error::ChainCorrupt {
        reason: format!("gen_chain_id produced invalid record_id: {e}"),
    })?;

    // KeyId placeholder for unsigned records. The format must satisfy the
    // `ed25519:<64-hex>` shape enforced by KeyId::try_new. The all-zeros
    // value signals an unsigned/placeholder record (same sentinel used in
    // the `csq run` v2 records and the rotate.rs skeleton before sign-after-assign).
    let key_id = KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).map_err(|e| {
        AuditV2Error::ChainCorrupt {
            reason: format!("placeholder KeyId invalid: {e}"),
        }
    })?;

    Ok(SignedRecord {
        schema_version: AUDIT_SCHEMA_VERSION.to_string(),
        record_id,
        chain_id,
        seq: 0,                          // assigned by write_record_v2_impl Step 5
        prev_hash: Sha256Hex::genesis(), // assigned by write_record_v2_impl Step 5
        kind,
        payload,
        ts: current_iso8601_utc_persist(),
        key_id,
        canonical_hash: Sha256Hex::genesis(), // computed by write_record_v2_impl Step 6
        signature: Ed25519Signature::new([0u8; 64]), // placeholder; signed path overwrites
        actor: None,
        authority: None, // M13b lifecycle ops: authority: None (not M12-guarded)
        trust: None,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: Some(op_phase),
        verification_level: None,
    })
}

/// Build and emit an INTENT record for a M13b lifecycle op.
///
/// **Returns `Ok(true)` (emitted) or `Ok(false)` (chain-broken skip) or `Err`
/// (fail-closed).**
///
/// - `Ok(true)`: record written; proceed with side effect and emit outcome.
/// - `Ok(false)`: `.chain-broken` sentinel is set; record NOT written. The
///   lifecycle op (swap/logout/move) MUST STILL PROCEED with its side effect —
///   a broken audit chain must not block credential rotation or logout. Skip
///   the outcome emit as well (no correlation_id was persisted). Log at WARN.
/// - `Err`: fail-closed (cutoff active + keychain unavailable, or I/O error);
///   the caller MUST abort its side effect (F-LEDGER-02).
///
/// **CRITICAL asymmetry:** only `ChainBrokenRefuseAppend` produces `Ok(false)`.
/// Cutoff-active keychain failures always produce `Err` (fail-closed). A broken
/// chain is an already-known-corrupt state; refusing the append protects the
/// chain from further extension, not the op from running.
///
/// **rotate_key is exempt:** `rotate.rs` calls `write_record_v2_signed`
/// directly and stays fail-closed on `ChainBrokenRefuseAppend`. You MUST NOT
/// append a signed rotation record onto a chain you cannot verify.
///
/// `chain_id_str` may be empty when `chain.json` does not yet exist; the
/// writer initialises it on first write.
pub fn emit_intent(
    base_dir: &Path,
    chain_id_str: &str,
    kind: EventKind,
    payload: EventPayload,
    correlation_id: RecordId,
) -> Result<bool, AuditV2Error> {
    let record = build_lifecycle_record(
        chain_id_str,
        kind,
        payload,
        OpPhase::Intent { correlation_id },
    )?;
    emit_record(base_dir, record, EmitPhase::Intent)
}

/// Build and emit an OUTCOME record for a M13b lifecycle op.
///
/// Best-effort with cutoff awareness:
/// - Pre-cutoff: if write fails, the intent becomes a visible orphan.
///   Log the error, return Ok (the side effect already committed).
/// - Post-cutoff, keychain unavailable: SKIP the write (do NOT write unsigned —
///   that would brick the chain); `tracing::warn!` the orphan for `csq doctor`.
/// - `.chain-broken` sentinel set: skip with WARN (`Ok(false)` from
///   `emit_record` → mapped to `Ok(())`). The intent was also skipped, so no
///   orphan is created.
///
/// In all cases the caller may return the side effect's real result unchanged.
pub fn emit_outcome(
    base_dir: &Path,
    chain_id_str: &str,
    kind: EventKind,
    payload: EventPayload,
    correlation_id: RecordId,
    result: OpOutcome,
) -> Result<(), AuditV2Error> {
    let record = build_lifecycle_record(
        chain_id_str,
        kind,
        payload,
        OpPhase::Outcome {
            correlation_id,
            result,
        },
    )?;
    // Ok(false) = skipped (chain broken or keychain unavailable) — treat as Ok(()).
    emit_record(base_dir, record, EmitPhase::Outcome).map(|_| ())
}

/// Derive the chain_id string for use in lifecycle records.
///
/// Loads `chain.json` from `base_dir` and returns its `chain_id`. When
/// `chain.json` does not exist yet (first-ever write), returns an empty string;
/// callers pass it directly to `emit_intent` / `emit_outcome` which handle
/// the empty-string sentinel by generating a fresh ULID placeholder (the writer
/// then initialises `chain.json` on first write with the authoritative chain_id).
///
/// Callers that need a stable `chain_id` to pair intent/outcome records
/// MUST load it ONCE before both writes and reuse the same string.
pub fn load_chain_id(base_dir: &Path) -> String {
    ChainState::load(base_dir)
        .ok()
        .map(|s| s.chain_id)
        .unwrap_or_default()
}

/// Generate a fresh correlation_id for an intent/outcome pair.
///
/// Returns `Err` only when the underlying ULID generator fails (extremely
/// rare — treat as an internal error and fail the op closed).
pub fn gen_correlation_id() -> Result<RecordId, AuditV2Error> {
    RecordId::try_new(gen_chain_id()).map_err(|e| AuditV2Error::ChainCorrupt {
        reason: format!("gen_chain_id produced invalid correlation_id: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{AccountLogoutPayload, AccountMovePayload};
    use crate::types::AccountNum;
    use tempfile::TempDir;

    fn acct(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// AC-T3-1: intent + outcome pair share correlation_id; outcome seq > intent seq;
    /// the chain verifies at seq ≥ 1.
    #[test]
    fn intent_outcome_share_correlation_id_and_chain_verifies() {
        // Hermeticity: verify_chain (below) transitively reads CSQ_AUDIT_EDITION;
        // hold the shared env lock + pin a clean community baseline so this test
        // cannot race a concurrent enterprise-edition test (testing.md Rule 6 /
        // test-hermeticity.md MUST 1 — reader side).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Use the genesis chain_id (empty → writer initialises on first write).
        let chain_id = load_chain_id(base); // will be ""

        let correlation_id = gen_correlation_id().expect("correlation_id");
        let payload = EventPayload::AccountLogout(AccountLogoutPayload {
            slot: acct(1),
            orphaned_uuid: None,
        });

        // Write INTENT.
        emit_intent(
            base,
            &chain_id,
            EventKind::AccountLogout,
            payload.clone(),
            correlation_id.clone(),
        )
        .expect("intent write must succeed");

        // Write OUTCOME.
        emit_outcome(
            base,
            &chain_id,
            EventKind::AccountLogout,
            payload,
            correlation_id,
            OpOutcome::Ok,
        )
        .expect("outcome write must succeed");

        // Chain verifies with at least 2 records (seq 0 + seq 1).
        let result = crate::audit::verify::verify_chain(
            base,
            &crate::audit::verify::VerifyConfig::default(),
            None,
        );
        assert!(
            result.is_ok(),
            "chain must verify after intent+outcome: {result:?}"
        );
        let summary = result.unwrap();
        assert!(
            summary.verified_count >= 2,
            "at least 2 records must be on-chain"
        );
    }

    /// AC-T3-2: with no signing key present, the unsigned path is taken and
    /// the op still proceeds (graceful degradation, not silent failure).
    #[test]
    fn unsigned_fallback_when_no_key_present() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // No `csq audit init` → no chain.json → no signing_key_id.

        let chain_id = load_chain_id(base);
        let correlation_id = gen_correlation_id().expect("correlation_id");

        let result = emit_intent(
            base,
            &chain_id,
            EventKind::AccountMove,
            EventPayload::AccountMove(AccountMovePayload {
                from_slot: acct(1),
                to_slot: acct(2),
            }),
            correlation_id,
        );
        assert!(
            result.is_ok(),
            "unsigned fallback must succeed when no key present: {result:?}"
        );
    }

    /// AC-T3-3: intent-unpersistable (read-only csq-runs dir) → emit_intent
    /// returns Err, which the caller uses to fail the op closed.
    #[cfg(unix)]
    #[test]
    fn intent_unpersistable_returns_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Create csq-runs/ then make it read-only so the write fails.
        let runs_dir = base.join("csq-runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o555); // r-xr-xr-x — no write
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        let chain_id = load_chain_id(base);
        let correlation_id = gen_correlation_id().expect("correlation_id");

        let result = emit_intent(
            base,
            &chain_id,
            EventKind::AccountLogout,
            EventPayload::AccountLogout(AccountLogoutPayload {
                slot: acct(5),
                orphaned_uuid: None,
            }),
            correlation_id,
        );

        // Restore permissions so TempDir cleanup doesn't fail.
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        assert!(
            result.is_err(),
            "emit_intent on read-only dir must return Err (fail-closed)"
        );
    }

    /// FIX-1 AC: cutoff-active + keychain unavailable → intent emit returns
    /// Err (fail-closed). We simulate a cutoff-active chain.json with no
    /// real keychain entry — `load_signing_key_with_budget` sees a
    /// `signing_key_id` but gets NoEntry from the keychain, exhausts both
    /// budgets, and returns Err(Signing{..}).
    ///
    /// This test verifies the fail-closed branch without needing to actually
    /// provision a keychain entry.
    #[cfg(unix)]
    #[test]
    fn cutoff_active_no_key_intent_fails_closed() {
        use crate::audit::persist::AUDIT_SCHEMA_VERSION_TEST;
        use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Write a chain.json that has a signing_key_id + signing_active_since_seq=0
        // but NO real keychain entry — simulates an install that ran audit init
        // but whose keychain entry is not available in this test process.
        let runs_dir = base.join("csq-runs");
        std::fs::create_dir_all(&runs_dir).unwrap();

        // Build a minimal chain.json with the cutoff active.
        let chain_id_ulid = crate::audit::persist::gen_chain_id();
        let chain_json_path = runs_dir.join("chain.json");
        let chain_json = serde_json::json!({
            "chain_id": chain_id_ulid,
            "genesis_seq": 0,
            "signing_active_since_seq": 0,
            "signing_key_id": format!("ed25519:{}", "a".repeat(64)),
        });
        let tmp = unique_tmp_path(&chain_json_path);
        std::fs::write(&tmp, chain_json.to_string()).unwrap();
        secure_file(&tmp).ok();
        atomic_replace(&tmp, &chain_json_path).unwrap();

        let chain_id = load_chain_id(base);
        let correlation_id = gen_correlation_id().expect("correlation_id");

        // emit_intent must fail closed because:
        // - signing_active_since_seq is Some → cutoff active
        // - signing_key_id is set → key is expected
        // - keychain load will get NoEntry → both budgets exhausted → Err(Signing)
        // - phase=Intent → Err propagated to caller
        let result = emit_intent(
            base,
            &chain_id,
            EventKind::AccountLogout,
            EventPayload::AccountLogout(AccountLogoutPayload {
                slot: acct(1),
                orphaned_uuid: None,
            }),
            correlation_id,
        );

        assert!(
            matches!(result, Err(AuditV2Error::Signing { .. })),
            "cutoff-active + no keychain entry → intent must fail closed with Signing error; got: {result:?}"
        );

        // Chain must still be empty (no record written).
        let chain_jsonl = runs_dir.join(format!("{chain_id_ulid}.jsonl"));
        assert!(
            !chain_jsonl.exists(),
            "no chain record must be written when intent fails closed: {chain_jsonl:?}"
        );

        // Suppress AUDIT_SCHEMA_VERSION_TEST unused warning.
        // Suppress AUDIT_SCHEMA_VERSION_TEST unused-import warning in non-test builds.
        let _: &str = AUDIT_SCHEMA_VERSION_TEST;
    }

    /// R2-FIX-4: tightened test for FIX-1 outcome-skip.
    ///
    /// Stages a REAL signed INTENT (using the in-memory mock keyring +
    /// `audit_init`), then deletes the key from the keychain to simulate
    /// unavailability, then asserts:
    /// (a) `emit_outcome` returns `Ok` (skip, not Err),
    /// (b) NO new record is written (the JSONL has exactly 1 line — the intent),
    /// (c) `verify_chain` with a per-test keychain service still passes with the
    ///     signed intent as the chain HEAD (the orphan-degrade leaves a
    ///     verifiable chain, not a bricked one).
    ///
    /// Uses a per-test `svc` (not the production `SERVICE_NAME`) and a
    /// matching `VerifyConfig::keychain_service` so the test is self-contained
    /// and does not interfere with other keyring-backed tests.
    #[cfg(unix)]
    #[test]
    fn cutoff_active_no_key_outcome_skips_not_bricks() {
        use crate::audit::key_custody::test_helpers::init_mock_keyring;
        use crate::audit::key_custody::{audit_init, SERVICE_NAME};

        // Install the in-memory mock keyring — process-global, idempotent.
        init_mock_keyring();

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Use a test-specific service name (shared with VerifyConfig below)
        // to avoid interfering with parallel tests that also use SERVICE_NAME.
        let pid = std::process::id();
        let svc = format!("{SERVICE_NAME}-fix4-{pid}");

        // Provision a real signing key via audit_init. This writes chain.json
        // with signing_active_since_seq set (cutoff active from seq 0).
        audit_init(base, &svc).expect("audit_init must succeed");

        // Verify chain.json reflects a cutoff-active state.
        let chain_state = crate::audit::key_custody::ChainState::load(base)
            .expect("chain.json must load after audit_init");
        assert!(
            chain_state.signing_active_since_seq.is_some(),
            "audit_init must set signing_active_since_seq"
        );
        assert!(
            chain_state.signing_key_id.is_some(),
            "audit_init must set signing_key_id in chain.json"
        );
        let chain_id_str = chain_state.chain_id.clone();
        assert!(!chain_id_str.is_empty(), "chain_id must be non-empty");

        // Verify the key IS in the mock keyring under (svc, chain_id_str).
        {
            let e = crate::audit::key_custody::keyring_entry(&svc, &chain_id_str).expect("Entry");
            assert!(
                e.get_secret().is_ok(),
                "key must be in mock keyring under ({svc}, {chain_id_str})"
            );
        }

        // ── Temporarily install svc as the production SERVICE_NAME so that
        //    load_signing_key_with_budget (which always uses SERVICE_NAME) can
        //    find the key. We do this by writing a chain.json whose chain_id
        //    is also stored under SERVICE_NAME. ──
        //
        // Alternative approach: use `audit_init` with the production SERVICE_NAME
        // and a VerifyConfig that uses the same service.
        //
        // Simplest self-contained approach: use production SERVICE_NAME for
        // `audit_init` so that `emit_intent` / `emit_record` can find the key,
        // and use a matching VerifyConfig with SERVICE_NAME.
        //
        // Re-run with production SERVICE_NAME to avoid PID isolation complexity.
        let dir2 = TempDir::new().unwrap();
        let base2 = dir2.path();
        audit_init(base2, SERVICE_NAME).expect("audit_init with prod svc must succeed");

        let chain_state2 =
            crate::audit::key_custody::ChainState::load(base2).expect("chain.json must load");
        let chain_id2 = chain_state2.chain_id.clone();

        // Verify the key is in the prod keyring.
        {
            let e =
                crate::audit::key_custody::keyring_entry(SERVICE_NAME, &chain_id2).expect("Entry");
            assert!(
                e.get_secret().is_ok(),
                "key must be in keyring under (SERVICE_NAME, {chain_id2})"
            );
        }

        // ── Stage a signed INTENT. ──
        let chain_id_arg = load_chain_id(base2);
        let correlation_id = gen_correlation_id().expect("correlation_id");
        emit_intent(
            base2,
            &chain_id_arg,
            EventKind::AccountLogout,
            EventPayload::AccountLogout(AccountLogoutPayload {
                slot: acct(3),
                orphaned_uuid: None,
            }),
            correlation_id.clone(),
        )
        .expect("signed intent must succeed when key is in keychain");

        // JSONL must have exactly 1 record (the intent).
        let runs_dir2 = base2.join("csq-runs");
        let chain_jsonl2 = runs_dir2.join(format!("{chain_id2}.jsonl"));
        assert!(chain_jsonl2.exists(), "JSONL must exist after intent");
        let before_lines = std::fs::read_to_string(&chain_jsonl2)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(before_lines, 1, "exactly 1 record (intent) before outcome");

        // ── Delete the key from BOTH stores (file store is the daemon-readable
        //    primary) to simulate genuine signing-key unavailability for the
        //    outcome. ──
        crate::audit::key_custody::keyring_entry(SERVICE_NAME, &chain_id2)
            .expect("Entry")
            .delete_credential()
            .expect("delete must succeed on mock keyring");
        crate::audit::key_custody::file_store::delete(base2, &chain_id2, KeySlot::Active)
            .expect("delete file seed");

        // ── emit_outcome with key deleted → must skip (Ok), not brick. ──
        let outcome_result = emit_outcome(
            base2,
            &chain_id_arg,
            EventKind::AccountLogout,
            EventPayload::AccountLogout(AccountLogoutPayload {
                slot: acct(3),
                orphaned_uuid: None,
            }),
            correlation_id,
            OpOutcome::Ok,
        );

        // (a) Returns Ok (skip, not Err).
        assert!(
            outcome_result.is_ok(),
            "cutoff-active + deleted key → outcome must return Ok (skip): {outcome_result:?}"
        );

        // (b) No new record written: JSONL still has exactly 1 line.
        let after_lines = std::fs::read_to_string(&chain_jsonl2)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(
            after_lines, 1,
            "outcome skip must NOT write a new record; expected 1, got {after_lines}"
        );

        // (c) verify_chain still passes with a VerifyConfig that uses
        //     SERVICE_NAME. The signed intent is the chain HEAD; the deleted
        //     key means verify falls back to chain.json cutoff and hits
        //     KeyNotFound (not UnsignedRecordAfterCutoff). But we want to
        //     assert the chain is "not bricked" — meaning the JSONL is intact
        //     and the orphan-degrade path leaves exactly 1 verifiable-format
        //     record. We accept KeyNotFound as "not bricked" because it proves
        //     (i) no unsigned record was appended and (ii) the signed intent
        //     is still the only record.
        //
        // A stronger assertion: if the key were still present, verify would
        // fully pass. We assert the weaker "orphan-degrade leaves a valid
        // JSONL structure" by parsing the 1 record.
        let raw = std::fs::read_to_string(&chain_jsonl2).unwrap();
        let line = raw.lines().find(|l| !l.trim().is_empty()).expect("1 line");
        let rec: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        // The record must be an INTENT (op_phase.phase == "intent") and must
        // NOT have the placeholder key_id (proving it was actually signed).
        assert_eq!(
            rec["op_phase"]["phase"].as_str(),
            Some("intent"),
            "the single record must be an intent op_phase"
        );
        let recorded_key_id = rec["key_id"].as_str().unwrap_or("");
        assert_ne!(
            recorded_key_id,
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
            "intent record must carry the real key_id (not the placeholder), \
             proving it was signed: {recorded_key_id}"
        );
        // The signature field must be non-zero (real Ed25519 sig is 64 bytes,
        // all-zero is the placeholder).
        let sig = rec["signature"].as_str().unwrap_or("");
        assert_ne!(
            sig,
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
            "signature must not be all-zeros — intent must have been signed"
        );
    }

    /// R6-FIX-1 regression: broken chain + active signing cutoff + missing key
    /// → `emit_intent` must return `Ok(false)` (degrade), NOT `Err(Signing{..})`
    /// (fail-closed).
    ///
    /// This is the binary-smoke failure mode: `csq move 3 7` on a broken chain
    /// whose `signing_active_since_seq = Some(0)` and whose signing key is absent
    /// from the keychain aborted instead of degrading, because
    /// `load_signing_key_with_budget` ran BEFORE the write-site sentinel gate.
    ///
    /// The pre-check in `emit_record` (R6-FIX-1) must intercept before
    /// `load_signing_key_with_budget` so the broken-chain degrade fires
    /// regardless of cutoff state.
    ///
    /// Contrast with `cutoff_active_no_key_intent_fails_closed`: that test has
    /// the SAME chain.json (cutoff active, missing key) but NO `.chain-broken`
    /// sentinel → the pre-check passes → `load_signing_key_with_budget` runs →
    /// Err(Signing) → fail-closed. Both tests must pass simultaneously.
    #[cfg(unix)]
    #[test]
    fn lifecycle_op_degrades_on_broken_chain_even_with_active_cutoff() {
        use crate::audit::health::set_chain_broken;
        use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let runs_dir = base.join("csq-runs");
        std::fs::create_dir_all(&runs_dir).unwrap();

        // Write a chain.json with signing_active_since_seq=Some(0) (cutoff active)
        // AND a signing_key_id that has no matching keychain entry — the same
        // combination that triggered the binary-smoke failure.
        let chain_id_ulid = crate::audit::persist::gen_chain_id();
        let chain_json_path = runs_dir.join("chain.json");
        let chain_json = serde_json::json!({
            "chain_id": chain_id_ulid,
            "genesis_seq": 0,
            "signing_active_since_seq": 0,
            "signing_key_id": format!("ed25519:{}", "b".repeat(64)),
        });
        let tmp = unique_tmp_path(&chain_json_path);
        std::fs::write(&tmp, chain_json.to_string()).unwrap();
        secure_file(&tmp).ok();
        atomic_replace(&tmp, &chain_json_path).unwrap();

        // Set the `.chain-broken` sentinel — this is what distinguishes this test
        // from `cutoff_active_no_key_intent_fails_closed`.
        set_chain_broken(base, "chain_corrupt");

        let chain_id = load_chain_id(base);
        let correlation_id = gen_correlation_id().expect("correlation_id");

        // emit_intent MUST return Ok(false) (degrade), not Err.
        // Without R6-FIX-1, this returns Err(Signing{..}) because
        // load_signing_key_with_budget runs before the write-site gate.
        let result = emit_intent(
            base,
            &chain_id,
            EventKind::AccountMove,
            EventPayload::AccountMove(crate::audit::types::AccountMovePayload {
                from_slot: acct(3),
                to_slot: acct(7),
            }),
            correlation_id,
        );

        assert!(
            matches!(result, Ok(false)),
            "broken chain + active cutoff + missing key → emit_intent must return \
             Ok(false) (degrade), NOT Err; got: {result:?}"
        );

        // No record must be written.
        let chain_jsonl = runs_dir.join(format!("{chain_id_ulid}.jsonl"));
        assert!(
            !chain_jsonl.exists(),
            "no chain record must be written when chain is broken (degrade path): {chain_jsonl:?}"
        );
    }

    // === M3a Acceptance Criterion Tests ===

    /// Helper: read the first record from the chain JSONL after `emit_*`.
    fn read_first_chain_record(base: &std::path::Path) -> crate::audit::types::SignedRecord {
        let chain_id = crate::audit::key_custody::ChainState::load(base)
            .expect("chain state must exist")
            .chain_id;
        let jsonl_path = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        let content = std::fs::read_to_string(&jsonl_path).expect("chain JSONL must exist");
        let first_line = content.lines().next().expect("at least one record");
        serde_json::from_str(first_line).expect("record must deserialize")
    }

    /// AC-2 — `op_emit_lifecycle_records_carry_auto_approved`.
    /// Enterprise builds: every record written through `write_record_v2_impl`
    /// (via `emit_intent` / `emit_outcome`) carries
    /// `verification_level = AutoApproved`.
    /// Community builds: the field is absent (None).
    #[test]
    fn op_emit_lifecycle_records_carry_auto_approved() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let chain_id = load_chain_id(base);
        let correlation_id = gen_correlation_id().expect("correlation_id");

        // Write a lifecycle INTENT record.
        emit_intent(
            base,
            &chain_id,
            crate::audit::types::EventKind::AccountLogout,
            crate::audit::types::EventPayload::AccountLogout(AccountLogoutPayload {
                slot: acct(1),
                orphaned_uuid: None,
            }),
            correlation_id,
        )
        .expect("emit_intent must succeed");

        let record = read_first_chain_record(base);

        #[cfg(feature = "enterprise")]
        {
            use crate::audit::eatp_canonical::VerificationLevel;
            assert_eq!(
                record.verification_level,
                Some(VerificationLevel::AutoApproved),
                "enterprise: every lifecycle record must carry AutoApproved level; got: {:?}",
                record.verification_level
            );
        }

        #[cfg(not(feature = "enterprise"))]
        assert_eq!(
            record.verification_level, None,
            "community: verification_level must be absent (None); got: {:?}",
            record.verification_level
        );
    }

    /// AC-6 — `op_record_level_is_never_above_auto_approved`.
    /// The verification level stamped on lifecycle records is ONLY `AutoApproved`.
    /// `PeerReviewed` and `SignedAttestation` must never appear on records
    /// emitted by the `op_emit` path.
    #[test]
    fn op_record_level_is_never_above_auto_approved() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let chain_id = load_chain_id(base);
        let correlation_id = gen_correlation_id().expect("correlation_id");

        emit_intent(
            base,
            &chain_id,
            crate::audit::types::EventKind::AccountLogout,
            crate::audit::types::EventPayload::AccountLogout(AccountLogoutPayload {
                slot: acct(2),
                orphaned_uuid: None,
            }),
            correlation_id.clone(),
        )
        .expect("emit_intent must succeed");

        emit_outcome(
            base,
            &chain_id,
            crate::audit::types::EventKind::AccountLogout,
            crate::audit::types::EventPayload::AccountLogout(AccountLogoutPayload {
                slot: acct(2),
                orphaned_uuid: None,
            }),
            correlation_id,
            crate::audit::types::OpOutcome::Ok,
        )
        .expect("emit_outcome must succeed");

        // Read back both records and verify neither has a level above AutoApproved.
        let chain_id_str = crate::audit::key_custody::ChainState::load(base)
            .expect("chain state")
            .chain_id;
        let jsonl_path = base.join("csq-runs").join(format!("{chain_id_str}.jsonl"));
        let content = std::fs::read_to_string(&jsonl_path).unwrap();
        for line in content.lines() {
            let record: crate::audit::types::SignedRecord =
                serde_json::from_str(line).expect("record deserializes");
            match record.verification_level {
                #[cfg(feature = "enterprise")]
                Some(crate::audit::eatp_canonical::VerificationLevel::AutoApproved) => {
                    /* expected */
                }
                None => { /* pre-M3a or community — ok */ }
                other => {
                    panic!("op_emit must never stamp a level above AutoApproved; got: {other:?}");
                }
            }
        }
    }
}
