//! M13 — F-LEDGER-02 orphan-intent detection.
//!
//! A side-effecting op emits a pre-op INTENT record (drained before the side
//! effect) and a post-op OUTCOME record (appended after it terminates), sharing
//! one `correlation_id` (see [`crate::audit::types::OpPhase`]). A crash or kill
//! between the two leaves an INTENT with no matching OUTCOME — the F-LEDGER-02
//! "the side effect may have happened but its outcome was never recorded" state.
//!
//! [`scan_orphan_intents`] walks the committed chain and returns every such
//! orphan. `csq doctor` surfaces them so the operator can investigate (the op
//! may have half-completed). This is detection only — it never mutates the
//! chain.
//!
//! # Scope
//!
//! Only top-level `<base_dir>/csq-runs/*.jsonl` files (the committed chain, one
//! per `chain_id`) are scanned. The `.pending/`, `.quarantine/`, and
//! `.pending-<sink>/` subdirectories are deliberately excluded — they hold
//! not-yet-drained or corrupt records, not committed chain state.

use std::path::Path;

use crate::audit::traits::SigningKey;
use crate::audit::types::{EventKind, EventPayload, OpPhase, SignedRecord};
use crate::types::AccountNum;

/// A pre-op INTENT record on the committed chain with no matching OUTCOME.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct OrphanIntent {
    /// The correlation id shared by the intent and its (missing) outcome.
    pub correlation_id: String,
    /// The intent record's own id.
    pub record_id: String,
    /// The op kind the intent precedes, snake_case (e.g. `"key_rotate"`).
    pub kind: String,
    /// The intent record's sequence number within its chain.
    pub seq: u64,
}

/// Errors from [`scan_orphan_intents`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrphanScanError {
    /// Failed to read the `csq-runs/` directory or a chain file.
    #[error("orphan-intent scan I/O error")]
    Io(#[from] std::io::Error),
    /// A chain line did not parse as a `SignedRecord`. The chain verifier
    /// (`verify_chain`) is the authority on corruption; the scan refuses to
    /// guess at orphans from a partially-parseable file (a dropped OUTCOME
    /// line would manufacture a false orphan).
    #[error("orphan-intent scan: chain line did not parse as a SignedRecord")]
    Parse,
}

/// Walks the committed chain under `<base_dir>/csq-runs/` and returns every
/// INTENT record whose `correlation_id` has no matching, SAME-KIND OUTCOME
/// record.
///
/// Returns an empty `Vec` when there is no `csq-runs/` directory, no chain
/// file, or no intent records.
///
/// **Correlation is global across ALL top-level chain files** — the `resolved`
/// set accumulates every outcome's `(correlation_id, kind)` from every file
/// before the final retain, so an outcome in any file resolves an intent in
/// any file. This is the deliberately-lenient direction: a re-genesis that
/// split an intent and its outcome across two files would still resolve
/// correctly (fewer false orphans), and `correlation_id` is a 128-bit CSPRNG
/// ULID so cross-file collision (a false non-orphan) is cryptographically
/// negligible.
///
/// D-F3/S-M-1 (round 7): resolution is keyed on `(correlation_id, kind)`, not
/// `correlation_id` alone. `build_lifecycle_record` (`op_emit.rs`) always
/// stamps the SAME `kind` on an intent/outcome pair, so a genuine pair never
/// disagrees — but nothing on this scan's read side previously checked that,
/// so an OUTCOME whose `correlation_id` happened to collide with an UNRELATED
/// intent of a DIFFERENT kind (a forged or corrupted record, same-user threat
/// model) would have silently resolved that unrelated intent too. Requiring
/// the kind to match closes that off without weakening the cross-file
/// leniency above — a genuine re-genesis split still matches on both fields.
///
/// D-F3/S-M-1 also detects (but does not construct a whole second return
/// path for — see this function's `pub` callers, several outside this
/// shard's scope) a SECOND outcome for one `(correlation_id, kind)` pair: an
/// anomaly the 1:1 intent/outcome pairing this scan relies on should never
/// produce. Logged via `tracing::warn!` with a fixed-vocabulary
/// `error_kind` rather than added to the return type, so every existing
/// caller (`csq doctor`, `move_slot`, `logout`, the seat-key reanchor path)
/// keeps working unchanged; a future caller that needs the anomaly list
/// itself should read the warn or extend the return type deliberately,
/// rather than this scan silently swallowing a state its own module doc
/// says should be impossible.
pub fn scan_orphan_intents(base_dir: &Path) -> Result<Vec<OrphanIntent>, OrphanScanError> {
    use std::collections::{HashMap, HashSet};

    let csq_runs = base_dir.join("csq-runs");
    if !csq_runs.is_dir() {
        return Ok(Vec::new());
    }

    let mut intents: Vec<OrphanIntent> = Vec::new();
    let mut resolved: HashSet<(String, String)> = HashSet::new();
    let mut outcome_counts: HashMap<(String, String), u32> = HashMap::new();

    for entry in std::fs::read_dir(&csq_runs)? {
        let entry = entry?;
        let path = entry.path();
        // Top-level chain files only: `*.jsonl`, not the `.pending/` etc. dirs.
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: SignedRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => {
                    // Mirror `verify_chain`'s mixed-schema tolerance (see
                    // `verify.rs` module docs): a line that fails to parse as a
                    // v2 `SignedRecord` AND carries the v1 schema marker is a
                    // legacy record left on a long-lived chain — SKIP it, do not
                    // fail the whole scan. Only a non-v1 unparseable line is a
                    // genuine corruption signal worth surfacing.
                    if line.contains(r#""schema_version":"1""#) {
                        continue;
                    }
                    return Err(OrphanScanError::Parse);
                }
            };
            // EventKind serializes snake_case; reuse that vocabulary as the
            // join key's kind component for both intents and outcomes.
            let kind_str = serde_json::to_value(record.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| format!("{:?}", record.kind));
            match &record.op_phase {
                Some(OpPhase::Intent { correlation_id }) => {
                    intents.push(OrphanIntent {
                        correlation_id: correlation_id.as_str().to_string(),
                        record_id: record.record_id.as_str().to_string(),
                        kind: kind_str,
                        seq: record.seq,
                    });
                }
                Some(OpPhase::Outcome { correlation_id, .. }) => {
                    let key = (correlation_id.as_str().to_string(), kind_str);
                    let count = outcome_counts.entry(key.clone()).or_insert(0);
                    *count += 1;
                    if *count > 1 {
                        tracing::warn!(
                            error_kind = "audit_orphan_scan_duplicate_outcome",
                            correlation_id = %key.0,
                            kind = %key.1,
                            count = *count,
                            "F-LEDGER-02: more than one OUTCOME record shares this \
                             (correlation_id, kind) — the 1:1 intent/outcome pairing \
                             this scan relies on has been violated; investigate before \
                             trusting orphan-intent output for this correlation_id"
                        );
                    }
                    resolved.insert(key);
                }
                None => {}
            }
        }
    }

    intents.retain(|i| !resolved.contains(&(i.correlation_id.clone(), i.kind.clone())));
    // Stable order: by seq ascending so doctor output is deterministic.
    intents.sort_by_key(|i| i.seq);
    Ok(intents)
}

/// The arguments the codex supervisor's correlated `AccountSwap` OUTCOME
/// write MUST verify against the committed chain BEFORE writing anything.
/// Grouped into a struct rather than four loose parameters —
/// `write_outcome_once` (`session::codex_supervisor`) is the sole production
/// caller.
///
/// Round 7 (D-F3/S-M-1) carried a fifth field here, `nonce: &'a str`, binding
/// this check to `SwapRequest::nonce`. Round 8 (C-B1/C-B2) RETRACTED it along
/// with the payload field it compared against — see `AccountSwapPayload`'s
/// doc for why, and [`verify_swap_correlation`]'s doc for what replaces it.
#[derive(Debug, Clone, Copy)]
pub struct SwapCorrelationCheck<'a> {
    /// The correlation_id shared by the AccountSwap INTENT and the OUTCOME
    /// about to be written.
    pub correlation_id: &'a str,
    /// `SwapRequest::from_slot` — must match the found INTENT's
    /// `AccountSwapPayload::from_slot` exactly.
    pub from_slot: AccountNum,
    /// `SwapRequest::target_slot` — must match the found INTENT's
    /// `AccountSwapPayload::to_slot` exactly.
    pub to_slot: AccountNum,
}

/// Verifies that writing the correlated `AccountSwap` OUTCOME for
/// `check.correlation_id` is AUTHORIZED by the committed chain, closing the
/// forgery/corruption window `scan_orphan_intents`'s `(correlation_id, kind)`
/// tightening (above) narrowed but did not fully close for the specific case
/// of an OUTCOME writer that has not yet appended anything: a same-user
/// attacker (or a corrupted/stale [`crate::session::codex_supervisor::SwapRequest`]
/// file) could otherwise cause an OUTCOME to be minted for an unrelated,
/// mismatched, or already-resolved INTENT, or for one that lived on a chain
/// since reset.
///
/// # What this check covers
///
/// Returns `true` ONLY when ALL of the following hold:
///
/// 1. The scan reads ONLY `<base_dir>/csq-runs/<current_genesis>.jsonl` —
///    the CURRENT chain's own committed file, identified by
///    [`crate::audit::key_custody::chain_state::ChainState::chain_id`] — never
///    every `*.jsonl` under `csq-runs/`. A record sitting in some OTHER
///    top-level file (a re-genesis remnant, a stray/leftover/copied-in file)
///    can never authorize a write against the current chain merely by
///    holding a same-shaped record (round 8, S-MEDIUM-1 — narrower than
///    round 7's every-file scan).
/// 2. Exactly ONE `kind == AccountSwap` INTENT record in that file carries
///    `check.correlation_id` (zero or more-than-one → refuse: an
///    unrelated/forged correlation_id, or a same-`correlation_id` collision
///    across kinds/duplicates, must never be treated as authorizing this
///    write).
/// 3. Its payload's `from_slot`/`to_slot` match `check.from_slot`/
///    `check.to_slot` exactly.
/// 4. No OUTCOME record already exists for this `(correlation_id, kind)` —
///    a second OUTCOME for one INTENT is refused, not silently appended.
/// 5. The INTENT's own persisted `chain_id` equals the chain's CURRENT
///    genesis (redundant with (1)'s file selection in the common case;
///    kept as defense-in-depth against a record whose own `chain_id` field
///    disagrees with the file it was found in).
/// 6. **Round 8 (S-MEDIUM-1), tightened round 9 (S-CRITICAL-1):** once the
///    chain is SIGNED — `ChainState::signing_key_id` is `Some` OR
///    `::signing_active_since_seq` is `Some` (either alone means
///    `csq audit init` has run) — the found INTENT's `key_id` MUST resolve
///    to a TRUSTED public key and its signature MUST verify against it.
///    "Trusted" means resolved from the SAME key-custody store
///    `verify_chain` itself reads — the file store, then the OS keychain
///    fallback — via `try_load_signing_key`, over EVERY slot in the chain's
///    rotation history (the current `Active` slot and every
///    `Historical(0..=rotation_count)` slot), **never** `chain.json`'s own
///    `pubkey` field. `chain.json` lives in a same-user-writable plain
///    file; an attacker with local write access can overwrite its `pubkey`
///    with their own key and sign a forged INTENT with the matching
///    private half, which is exactly what condition (6) exists to refuse.
///    Accepting ANY key in the rotation history (not only the CURRENT
///    active key) is deliberate: a genuine INTENT signed before a key
///    rotation, whose correlated OUTCOME is written after the rotation,
///    must still verify (D-F5). Verification itself
///    ([`crate::audit::verify::verify_record_signature`]) recomputes the
///    INTENT's `canonical_hash` from its own content — the SAME Check-4
///    construction `verify_chain` uses for every record — and requires it
///    match the stored value BEFORE checking the signature, so a forged
///    record cannot graft a genuine record's `canonical_hash` +
///    `signature` + `key_id` onto different payload bytes. An unsigned,
///    wrong-key, wrong-signature, or content-tampered INTENT on a signed
///    chain is refused, even if every other condition above holds — and so
///    is a signed chain for which NO trusted key resolves at all for the
///    INTENT's `key_id` (fail CLOSED, never silently treated as unsigned).
///
/// # What this check does NOT cover — the documented residual
///
/// **Pre-cutoff chains (neither `signing_key_id` nor
/// `signing_active_since_seq` established yet — unsigned by design, see
/// `op_emit.rs`'s module doc "Signing posture").** Condition (6) above does
/// not apply: an unsigned INTENT authorizes the write exactly as it did
/// before round 8, on the strength of conditions (1)-(5) alone.
///
/// Item 9 (S-LOW-4) — `rules/security.md` §10 exception fields, filled in:
/// - **What is waived:** condition (6)'s trusted-key signature check on the
///   matched INTENT.
/// - **Why:** the whole chain is unsigned in this state — there is no
///   signing key yet to check against. `op_emit.rs`'s "Trust boundary" doc
///   already scopes an unsigned chain's guarantee to crash/kill
///   orphan-detection evidence, never same-user forge-resistance; waiving a
///   check this state cannot satisfy is not a NEW gap this round
///   introduces, it is the pre-existing, documented shape of that same
///   boundary.
/// - **Approved:** security-reviewer, round 9 (this review round — the same
///   round that tightened condition (6) itself, S-CRITICAL-1/D-F1/D-F4).
/// - **Removal trigger:** `csq audit init`. No manual follow-up is needed —
///   the residual retires itself the instant that command establishes a
///   signing key, at which point `chain_is_signed` below flips `true` and
///   every subsequent INTENT is subject to condition (6) again.
///
/// This check does NOT verify prev_hash/seq chain-linking, does NOT verify
/// ANY record other than the one matched INTENT, and does NOT resolve a
/// historical (rotated-out) key — a caller needing the FULL chain-integrity
/// guarantee (hash-chain, monotonic seq, every signature) wants
/// [`crate::audit::verify::verify_chain`] instead.
///
/// A read/parse failure anywhere in the scan is treated the same as "not
/// found" — REFUSE, never guess (`guard-reader-writer-parity.md` MUST-2:
/// fail closed on a destructive-adjacent write).
pub fn verify_swap_correlation(base_dir: &Path, check: &SwapCorrelationCheck<'_>) -> bool {
    let Ok(chain_state) = crate::audit::key_custody::chain_state::ChainState::load(base_dir) else {
        return false;
    };
    let current_genesis = chain_state.chain_id.clone();
    // An empty current genesis means no chain has ever been initialized —
    // there is nothing for an INTENT to have been written against.
    if current_genesis.is_empty() {
        return false;
    }

    // S-MEDIUM-1 (round 8): scan ONLY the current chain's own committed
    // file — not every `*.jsonl` under `csq-runs/`. A stray file holding a
    // same-shaped record must never authorize a write against THIS chain.
    let chain_file = base_dir
        .join("csq-runs")
        .join(format!("{current_genesis}.jsonl"));
    verify_swap_correlation_in_file(base_dir, &chain_file, &current_genesis, &chain_state, check)
}

/// The file-scanning half of [`verify_swap_correlation`], parameterized over
/// an already-resolved chain file path, chain id, and [`ChainState`] rather
/// than re-deriving them from `base_dir`.
///
/// S-LOW-B / C-N2 (round 8b): extracted so the correlated `AccountSwap`
/// OUTCOME writer (`op_emit::emit_outcome_with_precheck`, called via
/// `persist::write_record_v2_maybe_signed_with_precheck`'s in-lock
/// `precheck` closure) can run the IDENTICAL authorization scan INSIDE the
/// `.chain-lock` critical section, against the exact `(csq_runs, chain_id)`
/// pair the pending append targets — making the "exactly one OUTCOME per
/// (correlation_id, kind)" check atomic with the write. [`verify_swap_correlation`]
/// itself remains the out-of-lock fast-fail path callers use before
/// attempting a write at all (unchanged behaviour, same signature).
///
/// See [`verify_swap_correlation`]'s doc for the full six-condition contract
/// this function implements (conditions 2-6; condition 1 — file selection —
/// is the caller's responsibility, since both callers already resolve the
/// current genesis's own file before reaching here).
///
/// `base_dir` (round 9, S-CRITICAL-1) is the key-custody root condition (6)
/// resolves the TRUSTED signing pubkey against — both callers already have
/// it (the same `base_dir` they loaded `chain_state` from), so this is a
/// pure threading of an already-available value, not a new dependency.
pub(crate) fn verify_swap_correlation_in_file(
    base_dir: &Path,
    chain_file: &Path,
    current_genesis: &str,
    chain_state: &crate::audit::key_custody::chain_state::ChainState,
    check: &SwapCorrelationCheck<'_>,
) -> bool {
    let Ok(content) = std::fs::read_to_string(chain_file) else {
        return false;
    };

    let mut matching_intents: Vec<SignedRecord> = Vec::new();
    let mut outcome_already_present = false;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<SignedRecord>(line) else {
            // Mirror `scan_orphan_intents`'s v1-tolerance: a legacy v1
            // line is expected on a long-lived chain and is not itself
            // evidence against this correlation — skip it. Any other
            // unparseable line is treated as "cannot verify" — refuse.
            if line.contains(r#""schema_version":"1""#) {
                continue;
            }
            return false;
        };
        if record.kind != EventKind::AccountSwap {
            continue;
        }
        match &record.op_phase {
            Some(OpPhase::Intent { correlation_id }) => {
                if correlation_id.as_str() != check.correlation_id {
                    continue;
                }
                matching_intents.push(record);
            }
            Some(OpPhase::Outcome { correlation_id, .. }) => {
                if correlation_id.as_str() == check.correlation_id {
                    outcome_already_present = true;
                }
            }
            None => {}
        }
    }

    if outcome_already_present {
        return false;
    }
    // Exactly one — not zero, not more than one.
    let [ref intent] = matching_intents[..] else {
        return false;
    };
    let EventPayload::AccountSwap(payload) = &intent.payload else {
        // `kind == AccountSwap` with a non-AccountSwap payload is a
        // chain-corruption signal on its own — refuse rather than guess
        // which slots it names.
        return false;
    };
    if payload.from_slot != check.from_slot || payload.to_slot != check.to_slot {
        return false;
    }
    if intent.chain_id.as_str() != current_genesis {
        return false;
    }

    // S-MEDIUM-1 (round 8), tightened S-CRITICAL-1 (round 9): once the chain
    // is signed, the matched INTENT's signature must verify against a
    // TRUSTED key. Pre-cutoff (neither field set — no signing key yet)
    // chains keep the prior, weaker check — see this function's doc "What
    // this check does NOT cover".
    let chain_is_signed =
        chain_state.signing_key_id.is_some() || chain_state.signing_active_since_seq.is_some();
    if chain_is_signed {
        let key_id_str = intent.key_id.as_str();

        // S-CRITICAL-1: resolve the TRUSTED pubkey from the same
        // file-store/keychain custody `verify_chain` reads — NEVER from
        // `chain.json`'s own `pubkey` field, which is a same-user-editable
        // plain file an attacker with local write access can simply
        // overwrite with their own key. Accept ANY key in the chain's
        // rotation history (the current `Active` slot, or any prior
        // `Historical(i)` slot up to `rotation_count`) — a genuine INTENT
        // signed before a key rotation must still verify (D-F5) once its
        // correlated OUTCOME is written after the rotation.
        let mut candidate_slots: Vec<crate::audit::key_custody::KeySlot> =
            vec![crate::audit::key_custody::KeySlot::Active];
        for i in 0..=chain_state.rotation_count {
            candidate_slots.push(crate::audit::key_custody::KeySlot::Historical(i));
        }

        let mut trusted_pubkey: Option<crate::audit::types::Ed25519PublicKey> = None;
        for slot in candidate_slots {
            if let crate::audit::key_custody::KeyLoadOutcome::Loaded(key) =
                crate::audit::key_custody::try_load_signing_key(
                    base_dir,
                    crate::audit::AUDIT_SIGNING_SERVICE_NAME,
                    current_genesis,
                    slot,
                )
            {
                if key.key_id().as_str() == key_id_str {
                    trusted_pubkey = Some(key.public_key());
                    break;
                }
            }
        }

        // Fail CLOSED: a signed chain for which no trusted key resolves for
        // this INTENT's key_id is refused outright — never silently
        // downgraded to the pre-cutoff "any INTENT authorizes" behaviour.
        let Some(pubkey) = trusted_pubkey else {
            return false;
        };
        if !crate::audit::verify::verify_record_signature(intent, &pubkey) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::persist::write_record_v2;
    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, OpOutcome, RecordId,
        Sha256Hex, SignedRecord,
    };
    use tempfile::TempDir;

    fn base_record(run: &str, op_phase: Option<OpPhase>) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: run.to_string(),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase,
            verification_level: None,
        }
    }

    /// D-F3/S-M-1: same-kind resolution tests need a SECOND, genuinely
    /// valid `(kind, payload)` pair distinct from [`base_record`]'s
    /// `CsqRun` — `SignedRecord`'s `Deserialize` impl enforces
    /// `kind == payload.kind()` (rejecting a mismatched pair with
    /// `SignedRecord.kind does not match payload.kind()`, measured), so a
    /// record cannot merely swap `kind` while keeping `CsqRun`'s payload:
    /// it would fail to round-trip through `scan_orphan_intents`'s own
    /// `serde_json::from_str` before this scan's join-key logic is ever
    /// reached. `AccountLogout` is used here for the SAME reason
    /// `op_emit.rs`'s own tests use it: a genuinely different, valid kind.
    fn logout_record(slot: u16, op_phase: Option<OpPhase>) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::AccountLogout,
            payload: EventPayload::AccountLogout(crate::audit::types::AccountLogoutPayload {
                slot: crate::types::AccountNum::try_from(slot).unwrap(),
                orphaned_uuid: None,
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase,
            verification_level: None,
        }
    }

    #[test]
    fn empty_base_has_no_orphans() {
        let tmp = TempDir::new().unwrap();
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn intent_with_matching_outcome_is_not_orphan() {
        let tmp = TempDir::new().unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        write_record_v2(
            base_record(
                "i",
                Some(OpPhase::Intent {
                    correlation_id: corr.clone(),
                }),
            ),
            Some(tmp.path()),
        )
        .unwrap();
        write_record_v2(
            base_record(
                "o",
                Some(OpPhase::Outcome {
                    correlation_id: corr,
                    result: OpOutcome::Ok,
                }),
            ),
            Some(tmp.path()),
        )
        .unwrap();
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn intent_without_outcome_is_orphan() {
        let tmp = TempDir::new().unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        write_record_v2(
            base_record(
                "i",
                Some(OpPhase::Intent {
                    correlation_id: corr.clone(),
                }),
            ),
            Some(tmp.path()),
        )
        .unwrap();
        let orphans = scan_orphan_intents(tmp.path()).unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].correlation_id, corr.as_str());
        assert_eq!(orphans[0].kind, "csq_run");
    }

    #[test]
    fn records_without_op_phase_are_ignored() {
        let tmp = TempDir::new().unwrap();
        write_record_v2(base_record("plain", None), Some(tmp.path())).unwrap();
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    /// A legacy v1 record (`schema_version: "1"`) left on a long-lived chain MUST
    /// be SKIPPED, not fail the whole scan — mirrors `verify_chain`'s mixed-schema
    /// tolerance. A v2 intent on the same chain is still detected. Regression for
    /// the `audit_orphan_intent_scan_failed` WARN observed on a real host chain
    /// carrying v1 (csq 2.6.2-era) launch-log records.
    #[test]
    fn v1_legacy_record_is_skipped_not_scan_failure() {
        let tmp = TempDir::new().unwrap();
        let csq_runs = tmp.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        // A real v1 launch-log line (the exact shape that tripped the scan on the
        // maintainer host): parses-fail as a v2 SignedRecord, carries the v1 marker.
        let v1_line = r#"{"schema_version":"1","run_id":"002064d7-1b67-4a0f-a99a-0474b17efb55","csq_version":"2.6.2","surface":"cc","result_state":"pass"}"#;
        let intent = base_record(
            "i",
            Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
        );
        std::fs::write(
            csq_runs.join("mixed.jsonl"),
            format!("{v1_line}\n{}\n", serde_json::to_string(&intent).unwrap()),
        )
        .unwrap();
        let orphans =
            scan_orphan_intents(tmp.path()).expect("v1 line must be skipped, not error the scan");
        assert_eq!(
            orphans.len(),
            1,
            "the v2 intent is still detected past the skipped v1 line"
        );
        assert_eq!(orphans[0].correlation_id, corr.as_str());
    }

    /// A genuinely-corrupt (non-v1, non-parseable) line is still a hard error —
    /// the v1-skip tolerance must NOT swallow real corruption.
    #[test]
    fn corrupt_non_v1_line_still_errors() {
        let tmp = TempDir::new().unwrap();
        let csq_runs = tmp.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        std::fs::write(csq_runs.join("bad.jsonl"), "{not valid json at all}\n").unwrap();
        assert!(
            matches!(scan_orphan_intents(tmp.path()), Err(OrphanScanError::Parse)),
            "a non-v1 unparseable line must surface as a Parse error, not be silently skipped"
        );
    }

    /// `.pending/` (and any other subdirectory) is excluded from the scan — an
    /// intent buffered there is not yet committed and must NOT count as an
    /// orphan on the committed chain.
    #[test]
    fn pending_subdir_is_excluded() {
        let tmp = TempDir::new().unwrap();
        let pending = tmp.path().join("csq-runs").join(".pending");
        std::fs::create_dir_all(&pending).unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        let rec = base_record(
            "buffered",
            Some(OpPhase::Intent {
                correlation_id: corr,
            }),
        );
        std::fs::write(
            pending.join("buffered.jsonl"),
            serde_json::to_string(&rec).unwrap() + "\n",
        )
        .unwrap();
        // The intent lives only under .pending/ → not scanned → no orphan.
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    /// Correlation is global: an outcome in one committed chain file resolves an
    /// intent in another (the re-genesis split case).
    #[test]
    fn outcome_in_a_different_file_resolves_the_intent() {
        let tmp = TempDir::new().unwrap();
        let csq_runs = tmp.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        let intent = base_record(
            "i",
            Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
        );
        let outcome = base_record(
            "o",
            Some(OpPhase::Outcome {
                correlation_id: corr,
                result: OpOutcome::Ok,
            }),
        );
        std::fs::write(
            csq_runs.join("chain-a.jsonl"),
            serde_json::to_string(&intent).unwrap() + "\n",
        )
        .unwrap();
        std::fs::write(
            csq_runs.join("chain-b.jsonl"),
            serde_json::to_string(&outcome).unwrap() + "\n",
        )
        .unwrap();
        assert!(
            scan_orphan_intents(tmp.path()).unwrap().is_empty(),
            "outcome in chain-b must resolve the intent in chain-a"
        );
    }

    /// D-F3/S-M-1: an OUTCOME whose `correlation_id` matches an intent but
    /// whose `kind` does NOT must NOT resolve it — a same-`correlation_id`,
    /// different-`kind` outcome is exactly the shape a forged or corrupted
    /// record (same-user threat model) would take, and before this fix the
    /// scan resolved on `correlation_id` alone.
    #[test]
    fn outcome_with_different_kind_does_not_resolve_the_intent() {
        let tmp = TempDir::new().unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        // Intent is CsqRun-kind; outcome shares the SAME correlation_id but
        // is a genuinely different, validly-typed AccountLogout record — the
        // shape a forged/corrupted correlation_id collision would take.
        let intent = base_record(
            "i",
            Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
        );
        let mismatched_outcome = logout_record(
            7,
            Some(OpPhase::Outcome {
                correlation_id: corr.clone(),
                result: OpOutcome::Ok,
            }),
        );
        write_record_v2(intent, Some(tmp.path())).unwrap();
        write_record_v2(mismatched_outcome, Some(tmp.path())).unwrap();

        let orphans = scan_orphan_intents(tmp.path()).unwrap();
        assert_eq!(
            orphans.len(),
            1,
            "a kind-mismatched outcome must NOT resolve the intent — it must \
             still be reported as an orphan: {orphans:?}"
        );
        assert_eq!(orphans[0].correlation_id, corr.as_str());
        assert_eq!(orphans[0].kind, "csq_run");
    }

    /// The counterpart: a matching-kind outcome resolves as before — proving
    /// the tightened join key does not merely reject every resolution.
    #[test]
    fn outcome_with_matching_kind_resolves_the_intent() {
        let tmp = TempDir::new().unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        let intent = logout_record(
            7,
            Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
        );
        let outcome = logout_record(
            7,
            Some(OpPhase::Outcome {
                correlation_id: corr,
                result: OpOutcome::Ok,
            }),
        );
        write_record_v2(intent, Some(tmp.path())).unwrap();
        write_record_v2(outcome, Some(tmp.path())).unwrap();

        assert!(
            scan_orphan_intents(tmp.path()).unwrap().is_empty(),
            "a same-kind outcome must still resolve its intent"
        );
    }

    /// D-F3/S-M-1: a SECOND outcome for one `(correlation_id, kind)` is an
    /// anomaly the 1:1 pairing this scan relies on should never produce. The
    /// scan does not error or change its return shape (the anomaly is
    /// logged, not surfaced as an error type — see this function's doc), so
    /// this test's assertion is what the FUNCTION CONTRACT still guarantees
    /// under that condition: the intent it duplicately resolves is (still,
    /// correctly) not reported as an orphan, and the scan does not error.
    #[test]
    fn duplicate_outcome_for_one_correlation_does_not_error_the_scan() {
        let tmp = TempDir::new().unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        let intent = logout_record(
            7,
            Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
        );
        let outcome_1 = logout_record(
            7,
            Some(OpPhase::Outcome {
                correlation_id: corr.clone(),
                result: OpOutcome::Ok,
            }),
        );
        let outcome_2 = logout_record(
            7,
            Some(OpPhase::Outcome {
                correlation_id: corr,
                result: OpOutcome::Ok,
            }),
        );
        write_record_v2(intent, Some(tmp.path())).unwrap();
        write_record_v2(outcome_1, Some(tmp.path())).unwrap();
        write_record_v2(outcome_2, Some(tmp.path())).unwrap();

        let result = scan_orphan_intents(tmp.path());
        assert!(
            result.is_ok(),
            "a duplicate outcome must not error the scan"
        );
        assert!(
            result.unwrap().is_empty(),
            "the (still real) intent must not be reported as orphaned merely \
             because its outcome was duplicated"
        );
    }

    // ── verify_swap_correlation ──────────────────────────────────────────

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Writes a genuine `AccountSwap` INTENT via `emit_intent` (so its
    /// persisted `chain_id` is the REAL current genesis — the only way to
    /// exercise the check's "chain hasn't reset" condition truthfully,
    /// per this module's own audit-primitive discipline).
    fn emit_swap_intent(
        base: &Path,
        correlation_id: crate::audit::types::RecordId,
        from: AccountNum,
        to: AccountNum,
    ) {
        let chain_id = crate::audit::op_emit::load_chain_id(base);
        crate::audit::op_emit::emit_intent(
            base,
            &chain_id,
            EventKind::AccountSwap,
            EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: from,
                to_slot: to,
            }),
            correlation_id,
        )
        .expect("intent write must succeed");
    }

    #[test]
    fn verify_swap_correlation_accepts_genuine_match() {
        let tmp = TempDir::new().unwrap();
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(2));
        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            verify_swap_correlation(tmp.path(), &check),
            "a genuine, matching INTENT must authorize the OUTCOME write"
        );
    }

    #[test]
    fn verify_swap_correlation_rejects_forged_correlation_id() {
        let tmp = TempDir::new().unwrap();
        let real_corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), real_corr, slot(1), slot(2));
        let forged_corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        let check = SwapCorrelationCheck {
            correlation_id: forged_corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "a correlation_id with no matching INTENT at all must be refused"
        );
    }

    #[test]
    fn verify_swap_correlation_rejects_kind_mismatch() {
        let tmp = TempDir::new().unwrap();
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        // Same correlation_id, but a DIFFERENT kind (AccountLogout) — the
        // shape a forged/corrupted correlation_id collision would take.
        crate::audit::op_emit::emit_intent(
            tmp.path(),
            &crate::audit::op_emit::load_chain_id(tmp.path()),
            EventKind::AccountLogout,
            EventPayload::AccountLogout(crate::audit::types::AccountLogoutPayload {
                slot: slot(1),
                orphaned_uuid: None,
            }),
            corr.clone(),
        )
        .expect("intent write must succeed");
        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "a same-correlation_id, different-kind record must not authorize \
             an AccountSwap OUTCOME"
        );
    }

    #[test]
    fn verify_swap_correlation_rejects_slot_mismatch() {
        let tmp = TempDir::new().unwrap();
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(2));
        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(3), // the INTENT recorded to_slot=2, not 3
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "a to_slot that does not match the recorded INTENT must be refused"
        );
    }

    #[test]
    fn verify_swap_correlation_rejects_already_resolved() {
        let tmp = TempDir::new().unwrap();
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(2));
        let chain_id = crate::audit::op_emit::load_chain_id(tmp.path());
        crate::audit::op_emit::emit_outcome(
            tmp.path(),
            &chain_id,
            EventKind::AccountSwap,
            EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: slot(1),
                to_slot: slot(2),
            }),
            corr.clone(),
            OpOutcome::Ok,
        )
        .expect("outcome write must succeed");
        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "an INTENT that already has an OUTCOME must not authorize a second one"
        );
    }

    /// Round 8 (S-MEDIUM-1): an INTENT that matches the check's
    /// correlation_id/kind/slots exactly, but lives ONLY in a stray file —
    /// never in `<current_genesis>.jsonl`, the committed chain's own file —
    /// must not authorize the write. Before this fix the scan walked EVERY
    /// `*.jsonl` under `csq-runs/`, so a re-genesis remnant or a copied-in
    /// leftover file could authorize a write against the CURRENT chain.
    #[test]
    fn verify_swap_correlation_rejects_intent_in_a_stray_file() {
        let tmp = TempDir::new().unwrap();
        // Bootstrap chain.json + the real genesis file with an unrelated
        // intent, so `current_genesis` is non-empty and real.
        let bootstrap_corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), bootstrap_corr, slot(9), slot(9));
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        // The record the check will look for — matching correlation_id,
        // kind, and slots — but written into a STRAY file, never into
        // `<genesis>.jsonl` (the committed chain's own file).
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        let stray = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(genesis).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::AccountSwap,
            payload: EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: slot(1),
                to_slot: slot(2),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
            verification_level: None,
        };
        std::fs::write(
            tmp.path().join("csq-runs").join("stray-leftover.jsonl"),
            serde_json::to_string(&stray).unwrap() + "\n",
        )
        .unwrap();

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "an INTENT living only in a stray file (not the current \
             genesis's own committed file) must not authorize the write"
        );
    }

    /// C-I1 (round 8b): condition 5 — the matched INTENT's OWN persisted
    /// `chain_id` must equal the chain's CURRENT genesis, even when the
    /// record sits in the CORRECT file (`<current_genesis>.jsonl` — file
    /// selection, condition 1, is satisfied). Defense-in-depth against a
    /// record whose own `chain_id` field disagrees with the file it was
    /// found in — distinct from `..._rejects_intent_in_a_stray_file`
    /// above, which tests file SELECTION; this tests the record's own
    /// FIELD once the right file has already been selected.
    #[test]
    fn verify_swap_correlation_rejects_intent_whose_own_chain_id_is_stale() {
        let tmp = TempDir::new().unwrap();
        // Bootstrap chain.json + the real genesis file with an unrelated
        // intent, so `current_genesis` is non-empty and real.
        let bootstrap_corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), bootstrap_corr, slot(9), slot(9));
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        // The record matches correlation_id/kind/slots exactly, and lives
        // IN the current genesis's own file — but its own `chain_id` field
        // names a DIFFERENT (stale) chain, as if it survived a chain reset
        // that changed the genesis without this record being purged.
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        let stale_chain_id_record = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000ZZ").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::AccountSwap,
            payload: EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: slot(1),
                to_slot: slot(2),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
            verification_level: None,
        };
        // Append directly to the CURRENT genesis's own file — bypassing
        // `emit_intent` (which always stamps the real current chain_id and
        // so could never construct this state).
        let chain_file = tmp.path().join("csq-runs").join(format!("{genesis}.jsonl"));
        let mut existing = std::fs::read_to_string(&chain_file).unwrap();
        existing.push_str(&serde_json::to_string(&stale_chain_id_record).unwrap());
        existing.push('\n');
        std::fs::write(&chain_file, existing).unwrap();

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "an INTENT in the correct file whose OWN chain_id disagrees \
             with the current genesis must not authorize the write"
        );
    }

    /// C-I1 (round 8b): condition 2's ">1 matching INTENT" refusal — TWO
    /// records in the current genesis file both carry `check.correlation_id`
    /// as an `AccountSwap` INTENT. Neither one alone would be ambiguous;
    /// together they must refuse rather than the scan picking either (or
    /// the last-seen) as authoritative — a same-`correlation_id` collision
    /// must never be treated as authorizing the write.
    #[test]
    fn verify_swap_correlation_rejects_more_than_one_matching_intent() {
        let tmp = TempDir::new().unwrap();
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        // Two GENUINE intents (both via emit_intent, both real current-
        // chain records) sharing the SAME correlation_id — e.g. a same-
        // user attacker or a corrupted `SwapRequest` replaying the id.
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(2));
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(3));

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "two INTENT records sharing one correlation_id must refuse, \
             never pick either as authoritative"
        );
    }

    /// C-I1 (round 8b): an unparseable line that is NOT a tolerated legacy
    /// v1 record must refuse the WHOLE scan — "cannot verify" (never
    /// "guess it's fine because we found a match earlier in the file").
    /// The genuine, otherwise-fully-matching INTENT is written FIRST, so a
    /// scan that stopped early on a match (rather than reading the whole
    /// file) would wrongly authorize this write.
    #[test]
    fn verify_swap_correlation_rejects_on_an_unparseable_non_v1_line() {
        let tmp = TempDir::new().unwrap();
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(2));
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        let chain_file = tmp.path().join("csq-runs").join(format!("{genesis}.jsonl"));
        let mut existing = std::fs::read_to_string(&chain_file).unwrap();
        // Garbage: not valid JSON, and does not contain the v1-tolerance
        // marker `"schema_version":"1"` this scan special-cases.
        existing.push_str("{not valid json at all\n");
        std::fs::write(&chain_file, existing).unwrap();

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "an unparseable non-v1 line anywhere in the current genesis \
             file must refuse the whole scan, even with a genuine \
             fully-matching INTENT earlier in the same file"
        );
    }

    /// Round 8 (S-MEDIUM-1): once the chain has an established signing key
    /// (`csq audit init` has run), an INTENT that is NOT signed by that key
    /// must be refused, even though every OTHER condition (correlation_id,
    /// kind, slots, no prior outcome, correct file) is satisfied. Uses
    /// `write_record_v2_unchecked` (test-only) to construct the malformed
    /// state the production writer (`op_emit::emit_intent`) refuses to
    /// create once a cutoff is active.
    #[test]
    fn verify_swap_correlation_rejects_unsigned_intent_on_a_signed_chain() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let svc = format!(
            "csq-audit-signing-test-{}-unsigned-on-signed",
            std::process::id()
        );

        // Establishes chain.json + genesis + a real signing key
        // (`signing_key_id`/`pubkey`), with `signing_active_since_seq = 0`.
        crate::audit::key_custody::audit_init(tmp.path(), &svc).expect("audit_init");
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        let unsigned = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(genesis.clone()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::AccountSwap,
            payload: EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: slot(1),
                to_slot: slot(2),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            // Placeholder key + zero signature — genuinely unsigned.
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
            verification_level: None,
        };
        // `write_record_v2` would refuse this (unsigned-after-cutoff guard);
        // `_unchecked` is the test-only escape hatch for constructing the
        // exact malformed state this check must detect.
        crate::audit::persist::write_record_v2_unchecked(unsigned, Some(tmp.path()))
            .expect("unchecked write must succeed");

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "an unsigned INTENT on a chain with an established signing key \
             must not authorize the write"
        );

        let _ = crate::audit::key_custody::keyring_backend::LocalSigningKey::delete_from_keychain(
            &svc, &genesis,
        );
    }

    /// Round 8 (S-MEDIUM-1): the counterpart — a genuinely signed INTENT on
    /// a signed chain is accepted. `emit_swap_intent`'s normal path
    /// (`op_emit::emit_intent`) signs automatically once
    /// `signing_active_since_seq` is set and the key is reachable, so no
    /// hand-built record is needed here — this proves the tightened check
    /// does not merely reject everything on a signed chain.
    #[test]
    fn verify_swap_correlation_accepts_genuine_signed_intent() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let svc = format!(
            "csq-audit-signing-test-{}-genuine-signed",
            std::process::id()
        );

        crate::audit::key_custody::audit_init(tmp.path(), &svc).expect("audit_init");
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(2));

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            verify_swap_correlation(tmp.path(), &check),
            "a genuinely signed, matching INTENT on a signed chain must \
             authorize the write"
        );

        let _ = crate::audit::key_custody::keyring_backend::LocalSigningKey::delete_from_keychain(
            &svc, &genesis,
        );
    }

    /// Reads back the genuine, on-disk INTENT record for `corr` from the
    /// current genesis file — used by the grafting tests below to obtain a
    /// real `canonical_hash` + `signature` + `key_id` to graft onto a
    /// forged record.
    fn read_intent_for_correlation(base: &Path, corr: &str) -> SignedRecord {
        let genesis = crate::audit::op_emit::load_chain_id(base);
        let chain_file = base.join("csq-runs").join(format!("{genesis}.jsonl"));
        let content = std::fs::read_to_string(&chain_file).unwrap();
        content
            .lines()
            .find_map(|line| {
                let rec: SignedRecord = serde_json::from_str(line).ok()?;
                match &rec.op_phase {
                    Some(OpPhase::Intent { correlation_id }) if correlation_id.as_str() == corr => {
                        Some(rec)
                    }
                    _ => None,
                }
            })
            .expect("genuine intent must exist on disk")
    }

    /// Appends a hand-built [`SignedRecord`] verbatim to the current genesis
    /// file — bypassing `emit_intent`/`emit_outcome` entirely. Used to
    /// construct forged/grafted records this scan's own doc says it does
    /// NOT verify prev_hash/seq chain-linking for (that guarantee belongs to
    /// `verify_chain`, not `verify_swap_correlation`), so a raw append is a
    /// faithful test of exactly what this function DOES check.
    fn append_raw_record(base: &Path, record: &SignedRecord) {
        use std::io::Write;
        let genesis = crate::audit::op_emit::load_chain_id(base);
        let csq_runs = base.join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let chain_file = csq_runs.join(format!("{genesis}.jsonl"));
        let line = serde_json::to_string(record).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&chain_file)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    /// S-CRITICAL-1 (round 9): `verify_record_signature` previously verified
    /// the signature against the record's OWN stored `canonical_hash`
    /// without ever recomputing it. A forged INTENT that GRAFTS a genuine
    /// record's `canonical_hash` + `signature` + `key_id` onto a changed
    /// `correlation_id`/payload therefore passed — the signature was valid
    /// against a hash that no longer described this record's actual
    /// content. The fix recomputes `canonical_hash` from content (the same
    /// Check-4 construction `verify_chain` uses) and requires it match the
    /// stored value BEFORE the signature is even inspected.
    #[test]
    fn verify_swap_correlation_rejects_grafted_hash_signature_on_forged_payload() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let svc = format!("csq-audit-signing-test-{}-graft", std::process::id());
        crate::audit::key_custody::audit_init(tmp.path(), &svc).expect("audit_init");
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        // A genuine, correctly-signed INTENT for (1 -> 2).
        let corr_genuine = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), corr_genuine.clone(), slot(1), slot(2));
        let genuine = read_intent_for_correlation(tmp.path(), corr_genuine.as_str());

        // Forge a NEW intent: different correlation_id AND different slots,
        // but GRAFT the genuine record's canonical_hash + signature + key_id
        // verbatim — the exact attack S-CRITICAL-1 describes.
        let corr_forged = crate::audit::op_emit::gen_correlation_id().unwrap();
        let mut forged = genuine.clone();
        forged.record_id = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        forged.seq = genuine.seq + 1;
        forged.payload = EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
            from_slot: slot(5),
            to_slot: slot(6),
        });
        forged.op_phase = Some(OpPhase::Intent {
            correlation_id: corr_forged.clone(),
        });
        // canonical_hash / signature / key_id deliberately left as the
        // GENUINE record's — the graft.
        append_raw_record(tmp.path(), &forged);

        let check = SwapCorrelationCheck {
            correlation_id: corr_forged.as_str(),
            from_slot: slot(5),
            to_slot: slot(6),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "a forged INTENT carrying a genuine record's canonical_hash + \
             signature + key_id, but a different correlation_id/payload, \
             must be refused: the signature must be checked against a \
             RECOMPUTED hash of THIS record's own content, never the stale \
             grafted one"
        );

        let _ = crate::audit::key_custody::keyring_backend::LocalSigningKey::delete_from_keychain(
            &svc, &genesis,
        );
    }

    /// S-CRITICAL-1 (round 9): the pubkey used to verify condition (6) must
    /// come from the TRUSTED key-custody store (file store / keychain via
    /// `try_load_signing_key`) — never from `chain.json`'s own `pubkey`
    /// field. An attacker with local write access can rewrite BOTH
    /// `signing_key_id` and `pubkey` in `chain.json` to point at a key they
    /// generated themselves, self-sign a forged INTENT with it, and present
    /// an internally-consistent `chain.json`. That must still be refused,
    /// because the attacker's key was never installed in the trusted
    /// custody store this chain's genuine signer uses.
    #[test]
    fn verify_swap_correlation_rejects_forged_intent_with_attacker_controlled_chain_json_pubkey() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let svc = format!(
            "csq-audit-signing-test-{}-chainjson-pubkey-attack",
            std::process::id()
        );
        crate::audit::key_custody::audit_init(tmp.path(), &svc).expect("audit_init");
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        // Attacker generates their OWN keypair, stored under a completely
        // separate keychain namespace — NEVER installed in this chain's
        // trusted custody (base_dir file store, or the real
        // AUDIT_SIGNING_SERVICE_NAME/chain_id keychain account).
        let attacker_svc = format!(
            "csq-audit-signing-test-{}-attacker-namespace",
            std::process::id()
        );
        let attacker_key =
            crate::audit::key_custody::keyring_backend::LocalSigningKey::generate_and_store(
                &attacker_svc,
                "attacker-account",
                0,
            )
            .expect("attacker keygen");

        // Attacker self-signs a forged INTENT with their own key.
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        let mut forged = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(genesis.clone()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::AccountSwap,
            payload: EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: slot(1),
                to_slot: slot(2),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: attacker_key.key_id(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
            verification_level: None,
        };
        let real_hash =
            crate::audit::persist::sha256_hex(&crate::audit::persist::canonical_bytes_for(&forged));
        forged.canonical_hash = Sha256Hex::try_new(real_hash).unwrap();
        let digest = hex::decode(forged.canonical_hash.as_str()).unwrap();
        forged.signature = attacker_key.sign(&digest).expect("attacker sign");
        append_raw_record(tmp.path(), &forged);

        // Attacker ALSO rewrites chain.json so their own key looks
        // authoritative — an internally-consistent chain.json on its own
        // must never be sufficient.
        let mut chain_state =
            crate::audit::key_custody::chain_state::ChainState::load(tmp.path()).unwrap();
        chain_state.signing_key_id = Some(attacker_key.key_id());
        chain_state.pubkey = Some(attacker_key.public_key());
        chain_state.save(tmp.path()).unwrap();

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "an INTENT self-signed by an attacker-controlled key, with \
             chain.json's signing_key_id/pubkey ALSO rewritten to match, \
             must still be refused — chain.json's pubkey field is \
             same-user-editable and must never be trusted; only the \
             file-store/keychain custody's key material counts"
        );

        let _ = crate::audit::key_custody::keyring_backend::LocalSigningKey::delete_from_keychain(
            &svc, &genesis,
        );
        let _ = crate::audit::key_custody::keyring_backend::LocalSigningKey::delete_from_keychain(
            &attacker_svc,
            "attacker-account",
        );
    }

    /// S-CRITICAL-1 (round 9): a `chain.json` carrying `signing_key_id` but
    /// no `pubkey` (corrupted / partially migrated / stripped) previously
    /// caused condition (6) to be SKIPPED entirely — the `if let (Some(kid),
    /// Some(pubkey))` pattern only engaged when BOTH were present, so this
    /// state silently fell back to "any INTENT authorizes", fail-OPEN. The
    /// fix keys "is this chain signed" off `signing_key_id.is_some() ||
    /// signing_active_since_seq.is_some()` alone, so an unsigned
    /// (placeholder-key) INTENT is still refused regardless of whether
    /// `chain.json`'s `pubkey` field happens to be present.
    #[test]
    fn verify_swap_correlation_rejects_unsigned_intent_when_chain_json_pubkey_missing() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let svc = format!("csq-audit-signing-test-{}-no-pubkey", std::process::id());
        crate::audit::key_custody::audit_init(tmp.path(), &svc).expect("audit_init");
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        let mut chain_state =
            crate::audit::key_custody::chain_state::ChainState::load(tmp.path()).unwrap();
        assert!(
            chain_state.signing_key_id.is_some(),
            "audit_init must set signing_key_id"
        );
        chain_state.pubkey = None;
        chain_state.save(tmp.path()).unwrap();

        // A genuinely UNSIGNED (placeholder-key) INTENT — the write path
        // would never construct this once a cutoff is active; use the same
        // test-only escape hatch the sibling test above does.
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        let unsigned = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(genesis.clone()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::AccountSwap,
            payload: EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: slot(1),
                to_slot: slot(2),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
            verification_level: None,
        };
        crate::audit::persist::write_record_v2_unchecked(unsigned, Some(tmp.path()))
            .expect("unchecked write must succeed");

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            !verify_swap_correlation(tmp.path(), &check),
            "chain.json carrying signing_key_id but no pubkey must NOT skip \
             condition (6) — the chain is still signed (signing_key_id is \
             Some), so an unsigned placeholder INTENT must be refused, not \
             silently waved through as if the chain were unsigned"
        );

        let _ = crate::audit::key_custody::keyring_backend::LocalSigningKey::delete_from_keychain(
            &svc, &genesis,
        );
    }

    /// D-F5 (round 9): the found INTENT's `key_id` is accepted against ANY
    /// key in the chain's rotation history, not only the CURRENT active key
    /// — a genuine INTENT signed before a key rotation, whose correlated
    /// OUTCOME is written after the rotation, must still verify.
    #[test]
    fn verify_swap_correlation_accepts_intent_signed_by_a_since_rotated_key() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let svc = format!(
            "csq-audit-signing-test-{}-rotated-history",
            std::process::id()
        );
        crate::audit::key_custody::audit_init(tmp.path(), &svc).expect("audit_init");
        let genesis = crate::audit::op_emit::load_chain_id(tmp.path());

        // Genuine INTENT signed by the ORIGINAL (soon-to-be-rotated-out) key.
        let corr = crate::audit::op_emit::gen_correlation_id().unwrap();
        emit_swap_intent(tmp.path(), corr.clone(), slot(1), slot(2));

        // Rotate: the key that signed the INTENT above moves to a
        // Historical slot; a new key becomes Active.
        crate::audit::key_custody::rotate_key(
            tmp.path(),
            &svc,
            crate::audit::types::RotationReason::Operator,
        )
        .expect("rotate_key");

        let check = SwapCorrelationCheck {
            correlation_id: corr.as_str(),
            from_slot: slot(1),
            to_slot: slot(2),
        };
        assert!(
            verify_swap_correlation(tmp.path(), &check),
            "an INTENT signed by a key that has since been rotated out (now \
             living in a Historical(_) custody slot) must still authorize \
             the write — the OUTCOME can legitimately be written after a \
             rotation that happened between INTENT and OUTCOME"
        );

        let _ = crate::audit::key_custody::keyring_backend::LocalSigningKey::delete_from_keychain(
            &svc, &genesis,
        );
    }
}
