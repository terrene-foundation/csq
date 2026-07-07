//! Key rotation (`csq audit rotate-key`).
//!
//! Generates a new Ed25519 keypair, stores the new private key in the keychain,
//! and updates `chain.json` with the new `signing_key_id` and `pubkey`. The
//! outgoing private key remains in the keychain (archived under
//! `historical/{rotation_count}`) — it is retained for historical-record
//! verification (per M04 scope).
//!
//! # M13 — F-LEDGER-02 append-FIRST
//!
//! Rotation is a side-effecting op, so it emits TWO chain records (both
//! `KeyRotate`, both signed by the **outgoing** key, both carrying the same
//! multi-sig authority blob, distinguished by `op_phase`):
//!
//! 1. a pre-op INTENT record appended AND drained BEFORE the destructive
//!    keychain mutation — if it cannot be persisted, the op fails closed and
//!    the keychain is left untouched; and
//! 2. a post-op OUTCOME record (`Ok`, or `Failed` on a mutation/save error)
//!    appended after the side effect terminates.
//!
//! A crash between the two leaves a visible "intent without outcome" that
//! `csq doctor` flags. Both records are written via [`write_record_v2_signed`]
//! (sign-after-assign), so each verifies at its assigned `seq`.
//!
//! # Return
//!
//! Returns the new `LocalSigningKey` and the (already-persisted) OUTCOME record.

use std::path::Path;

use crate::audit::key_custody::{
    chain_state::ChainState,
    delete_dual,
    keyring_backend::{load_raw_payload, parse_embedded_cutoff, LocalSigningKey},
    preserve_dual, store_dual, KeyCustodyError, KeySlot,
};
use crate::audit::multi_sig::{authorize_op, resolve_policy};
use crate::audit::persist::AUDIT_SCHEMA_VERSION;
use crate::audit::persist::{current_iso8601_utc_persist, gen_chain_id, write_record_v2_signed};
use crate::audit::traits::SigningKey as _;
use crate::audit::types::{
    EatpAuthority, Ed25519Signature, EventKind, EventPayload, KeyId, KeyRotatePayload, OpOutcome,
    OpPhase, RecordId, RotationReason, Sha256Hex, SignedRecord,
};

/// Performs a signing-key rotation.
///
/// # Arguments
///
/// - `base_dir`         — csq accounts base directory.
/// - `service`          — keychain service name.
/// - `rotation_reason`  — operator-supplied reason; defaults to `Operator`.
///
/// # Returns `(new_key, outcome_record)` on success.
///
/// M13: `rotate_key` appends BOTH the `KeyRotate` INTENT record (drained before
/// the keychain mutation) AND the OUTCOME record (after `chain.json` saves)
/// internally, via [`write_record_v2_signed`]. The returned `outcome_record` is
/// the already-persisted OUTCOME (writer-assigned seq / canonical_hash / real
/// signature). Callers MUST NOT append it again — a second append would land a
/// signature-corrupt third copy and break `verify_chain`.
pub fn rotate_key(
    base_dir: &Path,
    service: &str,
    rotation_reason: RotationReason,
) -> Result<(LocalSigningKey, SignedRecord), KeyCustodyError> {
    rotate_key_inner(base_dir, service, rotation_reason, |state, base| {
        state.save(base)
    })
}

/// Closure-injectable inner for failure-branch testing per
/// `rules/redteam-discipline.md` Rule 5. `save_fn` performs the final
/// `chain.json` save; production calls `|state, base| state.save(base)`,
/// tests inject failure-returning closures to exercise the H-5 rollback
/// path (delete BOTH incoming + historical keychain entries on save
/// failure, per M-13 atomicity discipline).
///
/// R6-TDD-3: visibility narrowed to `pub(super)` so only this module + its
/// parent (`key_custody/mod.rs`) can reach this test-injection seam.
pub(super) fn rotate_key_inner<F>(
    base_dir: &Path,
    service: &str,
    rotation_reason: RotationReason,
    save_fn: F,
) -> Result<(LocalSigningKey, SignedRecord), KeyCustodyError>
where
    F: FnOnce(&ChainState, &Path) -> Result<(), KeyCustodyError>,
{
    let mut state = ChainState::load(base_dir)?;

    // H-1: chain_id must come from chain.json via read_or_init_chain_genesis,
    // not from a "default" fallback. Fail loudly if chain_id is empty.
    if state.chain_id.is_empty() {
        return Err(KeyCustodyError::ChainParse(
            "chain_id is empty — run `csq audit init` or ensure chain.json is present".to_string(),
        ));
    }
    let account = state.chain_id.clone();

    // Outgoing key must exist.
    let outgoing_key_id = state
        .signing_key_id
        .clone()
        .ok_or(KeyCustodyError::NoKeyToRotate)?;

    // H-7 runtime check: chain_id in state must match account we derived.
    if state.chain_id != account {
        return Err(KeyCustodyError::ChainParse(format!(
            "chain_id mismatch: state has '{}', expected '{}'",
            state.chain_id, account
        )));
    }

    // Load the outgoing key (FILE store FIRST, keychain FALLBACK) ONCE: the same
    // raw payload yields BOTH the signing key (to sign the rotation records) AND
    // the embedded cutoff (rotation never changes the cutoff). An inaccessible
    // or absent outgoing key fails the rotation cleanly — `rotate_key` is an
    // interactive WRITE op, so the operator can unlock the store or run
    // `csq audit migrate-keys` and retry.
    let outgoing_raw = load_raw_payload(base_dir, service, &account, KeySlot::Active)?
        .ok_or(KeyCustodyError::NoKeyToRotate)?;
    let outgoing = LocalSigningKey::load_from_str(outgoing_raw.as_str())?;

    // H-7: runtime check instead of debug_assert_eq!
    if outgoing.key_id().as_str() != outgoing_key_id.as_str() {
        return Err(KeyCustodyError::ChainParse(format!(
            "keychain account key_id mismatch: store has '{}', chain.json has '{}'",
            outgoing.key_id().as_str(),
            outgoing_key_id.as_str()
        )));
    }

    // M-hardening: the cutoff is embedded in the outgoing key's payload.
    // Rotation does NOT change the cutoff — only `audit init` establishes it.
    // (a) New JSON seed → embedded cutoff present → use it.
    // (b) Legacy bare-hex seed → no embedded cutoff → fall back to chain.json's
    //     `signing_active_since_seq` (or 0). Warn so operators upgrade.
    let (cutoff_for_incoming, floor_for_incoming): (u64, Option<u64>) =
        match parse_embedded_cutoff(outgoing_raw.as_str())? {
            Some(ec) => (ec.signing_active_since_seq, ec.roster_version_floor),
            None => {
                tracing::warn!(
                    audit_cutoff_legacy_seed_no_embedded = true,
                    account = %account,
                    "rotate_key: outgoing seed is legacy bare-hex (pre-M-hardening); \
                     cutoff taken from chain.json — re-run `csq audit init` to upgrade"
                );
                (
                    state.signing_active_since_seq.unwrap_or(0),
                    state.roster_version_floor,
                )
            }
        };

    // M-13 + M11 ordering invariant: AUTHORIZE the rotation BEFORE any
    // destructive keychain mutation.
    //
    // The incoming key's IDENTITY (key_id + pubkey) is named in the rotation
    // payload, so it must exist before the multi-sig authorization is collected.
    // We therefore generate the incoming keypair IN MEMORY first
    // (`generate_keypair` — no keychain write), build the payload, and collect
    // the authorization. ONLY if authorization succeeds do we mutate the
    // keychain: archive the outgoing key (`preserve_outgoing_key`) then commit
    // the incoming seed to the head slot (`store_generated`).
    //
    // Why this order is load-bearing (M11): if authorization fails — e.g.
    // enterprise edition whose threshold exceeds the available signers (no
    // roster yet) — the keychain MUST be left exactly as it was. Archiving /
    // overwriting the head slot before the authorization check would leave a
    // rotated head slot that chain.json does not reference, tripping the
    // SigningKeyIdAnchorMismatch guard on the next verify and bricking the chain.
    let historical_slot = KeySlot::Historical(state.rotation_count);

    // Generate the incoming keypair IN MEMORY (no keychain side effect yet).
    let (incoming_seed, incoming_key_id, incoming_pubkey) = LocalSigningKey::generate_keypair()?;

    // Build the chain_id RecordId — H-3: no silent ULID fallback.
    let chain_id_record = RecordId::try_new(account.clone()).map_err(|_| {
        KeyCustodyError::ChainParse(format!(
            "chain_id '{}' does not satisfy RecordId shape (26-char ULID or 36-char UUIDv7)",
            account
        ))
    })?;

    // M13 append-FIRST: one correlation id ties the pre-op INTENT record to its
    // post-op OUTCOME record. Both records carry the SAME (chain_id, kind,
    // payload) and the SAME multi-sig authority blob — the M11 authorization
    // (intent-hash over chain_id/kind/payload, op_phase EXCLUDED) covers both.
    let correlation_id = RecordId::try_new(gen_chain_id()).map_err(|e| {
        KeyCustodyError::Signing(format!("gen_chain_id produced invalid correlation_id: {e}"))
    })?;

    // H-11: use crate::audit::persist::current_iso8601_utc_persist() instead of hand-rolled math.
    let ts = current_iso8601_utc_persist();

    // Build the KeyRotate record payload (names the IN-MEMORY incoming identity).
    let payload = EventPayload::KeyRotate(KeyRotatePayload {
        previous_key_id: outgoing_key_id.clone(),
        new_key_id: incoming_key_id,
        incoming_pubkey,
        rotation_reason,
    });

    // M11: collect the multi-sig authorization over the rotation intent BEFORE
    // touching the keychain. The intent is computed over (chain_id, kind,
    // payload) — not over canonical_hash (which would be circular: authority
    // contains the sigs, canonical_hash covers authority).
    //
    // Community 1-of-1: the outgoing key self-authorizes (threshold = 1).
    // Enterprise: threshold > the available signers (M11 default: outgoing only)
    // FAILS CLOSED here — and because this runs BEFORE preserve/store, the
    // keychain is left untouched on failure.
    let multi_sig_authority = {
        let policy = resolve_policy();
        // Build the signer list: for M11, the outgoing key is the only signer.
        // M12's AuthorityRegistry will expand this to include roster members.
        // SEC-3: pass account (= chain_id) so the intent hash is bound to this
        // chain and cannot be replayed on a different chain.
        let signers: &[&dyn crate::audit::traits::SigningKey] = &[&outgoing];
        authorize_op(&account, &EventKind::KeyRotate, &payload, signers, &policy).map_err(
            |ms_err| {
                // M11 LOW-2: when the failure is insufficient signatures (the
                // enterprise-without-roster case — under M11 only the outgoing key
                // is available), give the operator the actionable next step rather
                // than a bare count. Other variants keep the plain message.
                let hint = match &ms_err {
                    crate::audit::multi_sig::MultiSigError::InsufficientSignatures { .. } => {
                        " — enterprise multi-sig needs one signer per required \
                         signature; only the current signing key is available under \
                         this edition. Set CSQ_AUDIT_EDITION=community for \
                         single-operator rotation, or provide additional enrolled \
                         signers (a multi-signer roster ships with the authority \
                         registry)."
                    }
                    _ => "",
                };
                KeyCustodyError::Signing(format!(
                    "multi-sig authorization failed for KeyRotate: {ms_err}{hint}"
                ))
            },
        )?
    };

    // ── F-LEDGER-02 append-FIRST: INTENT before any keychain mutation ──────────
    //
    // Append AND drain (durably persist) the intent record BEFORE touching the
    // keychain. `write_record_v2_signed` signs over the FINAL canonical hash
    // (sign-after-assign), so the intent verifies at any seq. If the intent
    // cannot be persisted the op FAILS CLOSED here — no keychain mutation runs.
    // F-LEDGER-02 invariant: no side effect without a durable prior intent.
    {
        let intent = build_keyrotate_record(
            &chain_id_record,
            &payload,
            &outgoing_key_id,
            &ts,
            multi_sig_authority.clone(),
            OpPhase::Intent {
                correlation_id: correlation_id.clone(),
            },
        )?;
        write_record_v2_signed(intent, Some(base_dir), &outgoing).map_err(|e| {
            KeyCustodyError::Signing(format!(
                "audit intent record could not be persisted — rotation aborted, \
                 keychain left untouched: {e}"
            ))
        })?;
    }

    // Best-effort emitter for the OUTCOME:failed record on the mutation error
    // paths below. If even the outcome write fails the intent is left as a
    // visible orphan (detected by `csq doctor`); we still return the original
    // error. The reason is routed through `redact_tokens` (security.md §2).
    let emit_failed_outcome = |reason: &str| {
        if let Ok(rec) = build_keyrotate_record(
            &chain_id_record,
            &payload,
            &outgoing_key_id,
            &ts,
            multi_sig_authority.clone(),
            OpPhase::Outcome {
                correlation_id: correlation_id.clone(),
                result: OpOutcome::Failed {
                    reason: crate::audit::types::RedactedString::from_untrusted(reason),
                },
            },
        ) {
            let _ = write_record_v2_signed(rec, Some(base_dir), &outgoing);
        }
    };

    // Authorization + intent succeeded — NOW perform the destructive keychain
    // mutation.
    // (a) Archive the outgoing key from the head slot (R1 M-5). Nothing has been
    //     overwritten yet, so a preserve failure needs no rollback.
    if let Err(e) = preserve_dual(
        base_dir,
        service,
        &account,
        KeySlot::Active,
        historical_slot,
    ) {
        emit_failed_outcome(&format!("preserve_outgoing_key failed: {e}"));
        return Err(e);
    }

    // (b) Commit the incoming seed to the head slot with the SAME cutoff embedded
    //     (M-hardening: cutoff shares fate with the key material). This OVERWRITES
    //     the outgoing key, already archived above. On failure, roll back the
    //     historical copy so a retry starts clean.
    let incoming_key = match store_dual(
        base_dir,
        service,
        &account,
        KeySlot::Active,
        &incoming_seed,
        cutoff_for_incoming,
        // #694 item 2: the roster floor rides the same payload — rotation
        // preserves it (a 3-field write here would silently drop the anchor).
        floor_for_incoming,
    ) {
        Ok(k) => k,
        Err(e) => {
            let _ = delete_dual(base_dir, service, &account, historical_slot);
            emit_failed_outcome(&format!("store_generated failed: {e}"));
            return Err(e);
        }
    };

    // Update chain.json.
    state.signing_key_id = Some(incoming_key.key_id());
    state.pubkey = Some(incoming_key.public_key());
    // R1 M-6 anti-replay: bump the monotonic rotation counter atomically
    // with the new key identity. The historical slot name picked above
    // already reflects the pre-bump value of `rotation_count`.
    state.rotation_count = state.rotation_count.saturating_add(1);
    // MED-2: Ensure chain.json carries signing_active_since_seq so the
    // next verify_chain cross-check does not self-inflict CutoffAnchorMismatch.
    // Rotation never changes the cutoff; it only propagates the same value
    // into the new key's embedded payload AND into chain.json if it was None.
    if state.signing_active_since_seq.is_none() {
        state.signing_active_since_seq = Some(cutoff_for_incoming);
    }
    if let Err(e) = save_fn(&state, base_dir) {
        // H-5 (corrected — review finding H-1): RESTORE the pre-rotate state.
        //
        // At this point head = K_new (store_generated) and historical/{N} = K_old
        // (preserve_outgoing_key). chain.json was NOT written (save failed), so it
        // still references id(K_old). The prior rollback deleted BOTH slots, which
        // erased K_old entirely → chain.json pointed at a key that existed nowhere
        // and the chain bricked on the next verify (KeyNotFound). The correct
        // rollback copies the archived K_old back into the head slot (restoring it
        // WITH its embedded cutoff) and then drops the historical archive, leaving
        // head = K_old in agreement with the unchanged chain.json.
        //
        // DA1 (redteam round 1): the FILE restore is AUTHORITATIVE — if it fails
        // (disk full / EIO), K_old survives ONLY in the historical archive, so we
        // MUST NOT delete that archive (deleting it would leave chain.json pointing
        // at a K_old that exists nowhere → fatal KeyNotFound brick on the next
        // verify). On restore failure: keep the archive and set the `.chain-broken`
        // sentinel so the operator runs `csq audit repair`.
        match preserve_dual(
            base_dir,
            service,
            &account,
            historical_slot,
            KeySlot::Active,
        ) {
            Ok(()) => {
                // Active FILE now holds K_old in agreement with chain.json; the
                // archive is redundant — drop it (best-effort).
                let _ = delete_dual(base_dir, service, &account, historical_slot);
            }
            Err(restore_err) => {
                // K_old is preserved ONLY in the historical archive — do NOT
                // delete it. Flag the chain so the operator repairs it.
                crate::audit::health::set_chain_broken(
                    base_dir,
                    "audit_rotate_rollback_incomplete",
                );
                tracing::error!(
                    error_kind = "audit_rotate_rollback_incomplete",
                    "rotate_key: rollback could not restore the outgoing key to the head slot \
                     ({restore_err}) — the outgoing key is preserved in the historical archive; \
                     run `csq audit repair`"
                );
            }
        }
        emit_failed_outcome(&format!("chain.json save failed: {e}"));
        return Err(e);
    }

    // ── F-LEDGER-02 append-FIRST: OUTCOME after the side effect committed ──────
    //
    // The keychain mutation + chain.json save committed. Append the OUTCOME:ok
    // record, signed by the (in-memory) OUTGOING key — its pubkey is archived at
    // `historical/{rotation_count_pre_bump}` and resolvable by the verifier. Both
    // intent and outcome share the multi-sig authority blob (the M11 intent-hash
    // covers (chain_id, kind, payload), which is identical for both).
    //
    // `write_record_v2_signed` signs over the FINAL canonical hash, so the
    // outcome verifies at its assigned seq (the latent seq>0 signing bug that the
    // pre-M13 in-place ceremony carried is closed). If the outcome write FAILS,
    // the rotation has still committed and the intent is now a visible ORPHAN
    // (intent without outcome) that `csq doctor` flags — we surface the audit gap
    // loudly rather than swallow it.
    let outcome_unsigned = build_keyrotate_record(
        &chain_id_record,
        &payload,
        &outgoing_key_id,
        &ts,
        multi_sig_authority,
        OpPhase::Outcome {
            correlation_id,
            result: OpOutcome::Ok,
        },
    )?;
    // The returned record is the FINALIZED outcome (writer-assigned seq /
    // prev_hash / canonical_hash / real signature) — the caller echoes THIS,
    // not the pre-write skeleton.
    let outcome =
        write_record_v2_signed(outcome_unsigned, Some(base_dir), &outgoing).map_err(|e| {
            KeyCustodyError::Signing(format!(
                "rotation committed but the audit OUTCOME record could not be persisted — \
                 the chain now has an orphan intent (run `csq doctor`): {e}"
            ))
        })?;

    Ok((incoming_key, outcome))
}

/// Builds an UNSIGNED `KeyRotate` record for the M13 append-FIRST intent /
/// outcome pair. `seq`, `prev_hash`, `canonical_hash`, and `signature` are
/// assigned by [`write_record_v2_signed`] (sign-after-assign); `record_id` is
/// freshly minted per record. Both phases carry the SAME `(kind, payload)` and
/// the SAME multi-sig `authority` blob — the only field that differs is
/// `op_phase`.
fn build_keyrotate_record(
    chain_id: &RecordId,
    payload: &EventPayload,
    signing_key_id: &KeyId,
    ts: &str,
    authority: EatpAuthority,
    op_phase: OpPhase,
) -> Result<SignedRecord, KeyCustodyError> {
    let record_id = RecordId::try_new(gen_chain_id()).map_err(|e| {
        KeyCustodyError::Signing(format!("gen_chain_id produced invalid record_id: {e}"))
    })?;
    Ok(SignedRecord {
        schema_version: AUDIT_SCHEMA_VERSION.to_string(),
        record_id,
        chain_id: chain_id.clone(),
        seq: 0,                          // assigned by write_record_v2_signed Step 5
        prev_hash: Sha256Hex::genesis(), // assigned by write_record_v2_signed Step 5
        kind: EventKind::KeyRotate,
        payload: payload.clone(),
        ts: ts.to_string(),
        key_id: signing_key_id.clone(),
        canonical_hash: Sha256Hex::genesis(), // computed by write_record_v2_signed Step 6
        signature: Ed25519Signature::new([0u8; 64]), // signed by Step 6.5
        actor: None,
        authority: Some(authority),
        trust: None,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: Some(op_phase),
        verification_level: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::init::audit_init;
    use crate::audit::key_custody::keyring_backend::LocalSigningKey;
    use tempfile::TempDir;

    fn tmp_base() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn svc() -> String {
        format!("csq-audit-signing-test-{}", std::process::id())
    }

    /// R4-TS-5 follow-on: per-test service suffix so parallel tests do not
    /// race on shared keychain mock account names (e.g. `historical/0`).
    fn svc_for(test_name: &str) -> String {
        format!(
            "csq-audit-signing-test-{}-{}",
            std::process::id(),
            test_name
        )
    }

    /// M11 ordering invariant: an authorization failure (enterprise edition with
    /// no roster — threshold 2 but only the outgoing key available) MUST leave
    /// the keychain AND chain.json exactly as they were.
    ///
    /// The pre-fix bug archived the outgoing key (`preserve_outgoing_key`) and
    /// overwrote the head slot (`generate_and_store`) BEFORE the authorization
    /// check, so a fail-closed enterprise rotate left a rotated head slot that
    /// chain.json did not reference — tripping the `SigningKeyIdAnchorMismatch`
    /// guard on the next verify and bricking the chain. After the fix the
    /// authorization runs over an IN-MEMORY incoming key before any keychain
    /// mutation, so a failure has zero side effects.
    #[test]
    fn test_enterprise_rotate_without_roster_leaves_keychain_untouched() {
        super::super::test_helpers::init_mock_keyring();
        // resolve_policy() reads CSQ_AUDIT_EDITION — hold the shared env lock
        // (testing.md Rule 6) for the whole mutate-read-restore window.
        let _env_guard = crate::platform::test_env::lock();
        let tmp = tmp_base();
        let svc = svc_for("enterprise_no_roster");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW";

        // Bootstrap: chain.json + initial signing key.
        ChainState::new(chain_id)
            .save(tmp.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
        audit_init(tmp.path(), &svc).expect("audit_init");

        // Snapshot pre-rotate state.
        let head_kid_before = LocalSigningKey::load_from_keychain(&svc, chain_id)
            .expect("load head before")
            .key_id()
            .as_str()
            .to_string();
        let chain_kid_before = ChainState::load(tmp.path())
            .expect("load chain before")
            .signing_key_id
            .map(|k| k.as_str().to_string());

        // Force enterprise edition (threshold 2) with only the outgoing key.
        let prev = std::env::var("CSQ_AUDIT_EDITION").ok();
        std::env::set_var("CSQ_AUDIT_EDITION", "enterprise");
        let result = rotate_key(tmp.path(), &svc, RotationReason::Operator);
        match prev {
            Some(v) => std::env::set_var("CSQ_AUDIT_EDITION", v),
            None => std::env::remove_var("CSQ_AUDIT_EDITION"),
        }

        // Rotation MUST fail closed.
        assert!(
            result.is_err(),
            "enterprise rotate without a roster must fail closed"
        );

        // Keychain head MUST be unchanged AND still loadable.
        let head_kid_after = LocalSigningKey::load_from_keychain(&svc, chain_id)
            .expect("head key MUST still be present after a failed rotate")
            .key_id()
            .as_str()
            .to_string();
        assert_eq!(
            head_kid_before, head_kid_after,
            "keychain head key_id changed after a fail-closed rotate — the head \
             slot was mutated before authorization (M11 ordering regression)"
        );

        // chain.json signing_key_id MUST be unchanged AND still consistent with
        // the keychain head (so the anchor guard would not trip on next verify).
        let chain_kid_after = ChainState::load(tmp.path())
            .expect("load chain after")
            .signing_key_id
            .map(|k| k.as_str().to_string());
        assert_eq!(
            chain_kid_before, chain_kid_after,
            "chain.json signing_key_id changed after a fail-closed rotate"
        );
        assert_eq!(
            chain_kid_after.as_deref(),
            Some(head_kid_after.as_str()),
            "keychain head and chain.json disagree after a fail-closed rotate \
             (partial rotation — the bug this test guards against)"
        );

        // No historical slot should have been created (nothing was archived).
        assert!(
            !LocalSigningKey::exists_in_keychain(&svc, "historical/0"),
            "a historical slot was created despite the rotate failing closed — \
             preserve_outgoing_key ran before authorization (M11 ordering regression)"
        );

        // Cleanup.
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// Named test — rotate_key produces a record signed by the outgoing key.
    ///
    /// C-1 fix: verification uses `canonical_bytes_for(&record)` as the signing
    /// pre-image (not `serde_json::to_string(&record.payload)`).
    ///
    /// The chain_id MUST be a valid 26-char Crockford Base32 ULID so that
    /// `RecordId::try_new(chain_id)` succeeds inside `rotate_key`.
    #[test]
    fn test_rotate_key_record_signed_by_outgoing_key() {
        super::super::test_helpers::init_mock_keyring();
        // rotate_key → resolve_policy() reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race a sibling that mutates it
        // (testing.md Rule 6 — read-side tests share the risk).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("rotate_record");
        // Valid 26-char Crockford Base32 ULID required by RecordId::try_new.
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

        // Bootstrap chain.json with a chain_id.
        let state = ChainState::new(chain_id);
        state.save(tmp.path()).expect("save chain.json");

        // Clean up.
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, &format!("ed25519:{}", "0".repeat(64)));

        // Init first key.
        audit_init(tmp.path(), &svc).expect("audit_init");
        let state_after_init = ChainState::load(tmp.path()).expect("load");
        let outgoing_kid = state_after_init.signing_key_id.clone().expect("kid");
        let outgoing_pubkey = state_after_init.pubkey.expect("pubkey");

        // Rotate.
        let (new_key, record) =
            rotate_key(tmp.path(), &svc, RotationReason::Operator).expect("rotate");

        // The record's key_id must be the outgoing key.
        assert_eq!(record.key_id.as_str(), outgoing_kid.as_str());

        // R4-TS-2: independently verify the canonical_hash FIELD VALUE
        // (not just the signature over the pre-image). M05's verify_integrity
        // checks the stored canonical_hash matches sha256(canonical_form
        // with canonical_hash = Sha256Hex::genesis()). Reconstruct that
        // pre-hash form and assert byte equality.
        {
            let mut record_with_sentinel = record.clone();
            record_with_sentinel.canonical_hash = crate::audit::types::Sha256Hex::genesis();
            let canonical_with_sentinel =
                crate::audit::persist::canonical_bytes_for(&record_with_sentinel);
            let expected_canonical_hash =
                crate::audit::persist::sha256_hex(&canonical_with_sentinel);
            assert_eq!(
                record.canonical_hash.as_str(),
                expected_canonical_hash,
                "canonical_hash field must equal sha256(canonical_form_with_genesis_sentinel) so M05 verify_integrity accepts the record"
            );
        }

        // C-1 verification (unified contract): the signing pre-image is the 32 raw
        // bytes of canonical_hash (not a second sha256 of the canonical form).
        // canonical_hash = sha256(canonical_bytes_for(record_with_genesis_sentinel));
        // signature was produced over hex::decode(canonical_hash) = those 32 bytes.
        let digest_bytes: [u8; 32] = {
            let hex_str = record.canonical_hash.as_str();
            let bytes = hex::decode(hex_str).expect("canonical_hash is valid hex");
            assert_eq!(bytes.len(), 32, "canonical_hash must decode to 32 bytes");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        };

        let verifying =
            ed25519_dalek::VerifyingKey::from_bytes(&outgoing_pubkey.0).expect("verifying key");
        let sig = ed25519_dalek::Signature::from_bytes(&record.signature.0);
        verifying.verify_strict(&digest_bytes, &sig).expect(
            "signature must verify with outgoing key using canonical_hash raw bytes as pre-image",
        );

        // chain.json now has the new key.
        let state_after_rotate = ChainState::load(tmp.path()).expect("load");
        assert_eq!(
            state_after_rotate
                .signing_key_id
                .as_ref()
                .map(|k| k.as_str()),
            Some(new_key.key_id().as_str())
        );
        assert_ne!(
            state_after_rotate
                .signing_key_id
                .as_ref()
                .map(|k| k.as_str()),
            Some(outgoing_kid.as_str()),
            "chain.json must reflect the new key"
        );

        // R1 M-5 / R2-RS-3: outgoing key is retained under the opaque
        // historical slot `historical/{rotation_count}` (pre-bump value),
        // NOT under the publicly-enumerable KeyId.
        assert!(
            LocalSigningKey::exists_in_keychain(&svc, "historical/0"),
            "outgoing key must be retained under historical/0"
        );
        assert!(
            !LocalSigningKey::exists_in_keychain(&svc, outgoing_kid.as_str()),
            "outgoing key must NOT be enumerable via its public KeyId"
        );

        // R1 M-6: rotation_count was bumped to 1 after the rotation.
        let post_rotate_state = ChainState::load(tmp.path()).expect("load post-rotate");
        assert_eq!(
            post_rotate_state.rotation_count, 1,
            "rotation_count must monotonically increment on rotate-key"
        );

        // Cleanup.
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// R4-TS-1: H-5 rollback path for rotate_key — when chain.json save
    /// fails after both keychain writes (incoming + historical), BOTH
    /// keychain entries MUST be deleted to avoid an orphan duplicate that
    /// leaves the chain in a half-rotated state.
    ///
    /// Uses closure injection per `rules/redteam-discipline.md` Rule 5 —
    /// the test injects a save closure that returns Err, then asserts
    /// BOTH keychain accounts (`<chain_id>` for incoming, `historical/0`
    /// for outgoing) are absent after the failed rotate_key.
    #[test]
    fn test_rotate_key_rollback_on_save_failure() {
        super::super::test_helpers::init_mock_keyring();
        // rotate_key → resolve_policy() reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race a sibling that mutates it
        // (testing.md Rule 6 — read-side tests share the risk).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("rotate_rollback");
        // Valid 26-char Crockford Base32 ULID — distinct from the ULID
        // used by sibling tests so the historical-slot accounts don't
        // alias when tests run in the same process.
        let chain_id = "01JZ00000000000000000000R0";

        // Bootstrap chain.json + initial signing key.
        let state = ChainState::new(chain_id);
        state.save(tmp.path()).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
        audit_init(tmp.path(), &svc).expect("audit_init");

        // Capture the outgoing (pre-rotate) key identity.
        let outgoing_kid = LocalSigningKey::load_from_keychain(&svc, chain_id)
            .expect("load outgoing")
            .key_id()
            .as_str()
            .to_string();

        // Inject a save closure that always fails.
        let result = rotate_key_inner(tmp.path(), &svc, RotationReason::Operator, |_, _| {
            Err(KeyCustodyError::ChainIo(
                "injected rotate save failure".to_string(),
            ))
        });
        assert!(
            result.is_err(),
            "rotate_key must propagate the injected save failure"
        );

        // H-5 rollback (corrected — H-1): the pre-rotate state MUST be RESTORED,
        // not erased. The prior behavior deleted BOTH key slots, losing K_old
        // entirely while chain.json still referenced id(K_old) → chain bricked on
        // the next verify (KeyNotFound). The head slot MUST now still hold the
        // OUTGOING key, in agreement with the unchanged chain.json.
        let head_after = LocalSigningKey::load_from_keychain(&svc, chain_id)
            .expect("H-5 rollback: outgoing key MUST be restored to the head slot")
            .key_id()
            .as_str()
            .to_string();
        assert_eq!(
            head_after, outgoing_kid,
            "H-5 rollback must RESTORE the outgoing key to head (chain.json still \
             references it); found a different key_id"
        );
        let chain_kid = ChainState::load(tmp.path())
            .expect("load chain")
            .signing_key_id
            .map(|k| k.as_str().to_string());
        assert_eq!(
            chain_kid.as_deref(),
            Some(outgoing_kid.as_str()),
            "chain.json must still reference the outgoing key after a failed save \
             — and head must agree with it (no anchor mismatch)"
        );
        // The historical archive MUST be dropped (pre-rotate state had none).
        assert!(
            !LocalSigningKey::exists_in_keychain(&svc, "historical/0"),
            "H-5 rollback must drop the historical archive after restoring head"
        );
    }

    /// DA1 (redteam round 2): the rollback restore-FAILURE branch is the ONE
    /// remaining path that deliberately writes the durable `.chain-broken`
    /// sentinel — every other R1 change exists to AVOID that sentinel. It must
    /// PRESERVE K_old in the historical archive (deleting it would brick the
    /// chain via KeyNotFound) and flag `csq audit repair`. Drive the Err arm by
    /// making the keys dir read-only inside the injected `save_fn` (which runs
    /// AFTER the forward preserve + store_dual land), so the rollback's restore
    /// `preserve_dual(historical → Active)` file write fails.
    #[cfg(unix)]
    #[test]
    fn test_rotate_rollback_restore_failure_preserves_archive_and_flags_repair() {
        use crate::audit::key_custody::file_store::{self, KeySlot};
        use std::os::unix::fs::PermissionsExt;

        super::super::test_helpers::init_mock_keyring();
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("rollback_restore_fail");
        // Valid 26-char Crockford Base32 ULID (alphabet excludes I/L/O/U).
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5RBK";

        ChainState::new(chain_id)
            .save(tmp.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
        audit_init(tmp.path(), &svc).expect("audit_init");
        let outgoing_kid = LocalSigningKey::load_from_keychain(&svc, chain_id)
            .expect("load outgoing")
            .key_id()
            .as_str()
            .to_string();

        // The historical archive file the rollback restore READS. Making it
        // unreadable drives `preserve_dual(historical→Active)` to fail at the
        // load step (the write-side dir perms are reset by `ensure_parent_dir`'s
        // `secure_dir`, so a read-fault on the source is the robust injection).
        let archive_file = tmp
            .path()
            .join("csq-runs")
            .join("keys")
            .join(chain_id)
            .join("historical")
            .join("0.json");
        let archive_for_closure = archive_file.clone();

        // save_fn runs after the forward preserve(Active→historical/0) +
        // store_dual(Active, K_new) have landed. Make the archive unreadable so
        // the rollback restore's read fails, then fail the save.
        let result = rotate_key_inner(tmp.path(), &svc, RotationReason::Operator, move |_, _| {
            let mut perms = std::fs::metadata(&archive_for_closure)
                .unwrap()
                .permissions();
            perms.set_mode(0o000); // no read → rollback restore's load fails
            std::fs::set_permissions(&archive_for_closure, perms).unwrap();
            Err(KeyCustodyError::ChainIo(
                "injected save failure".to_string(),
            ))
        });

        // Restore readability so assertions + cleanup work.
        let mut perms = std::fs::metadata(&archive_file).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&archive_file, perms).unwrap();

        assert!(
            result.is_err(),
            "rotate must propagate the injected save failure"
        );

        // (a) The distinct durable sentinel is set so the operator runs repair.
        assert_eq!(
            crate::audit::health::is_chain_broken(tmp.path()).as_deref(),
            Some("audit_rotate_rollback_incomplete"),
            "restore-failure must set the .chain-broken sentinel with the distinct kind"
        );

        // (b) K_old is PRESERVED in the historical archive — NOT deleted (deleting
        //     it would leave chain.json pointing at a vanished key → KeyNotFound brick).
        assert!(
            file_store::exists(tmp.path(), chain_id, KeySlot::Historical(0)),
            "K_old must survive in the historical archive after a restore failure"
        );
        let archived_raw = file_store::load_payload(tmp.path(), chain_id, KeySlot::Historical(0))
            .expect("load archive")
            .expect("archive present");
        let archived =
            LocalSigningKey::load_from_str(archived_raw.as_str()).expect("parse archive");
        assert_eq!(
            archived.key_id().as_str(),
            outgoing_kid,
            "the historical archive holds K_old (recoverable)"
        );

        // (c) chain.json still references K_old (the save failed), so K_old in the
        //     archive is the recoverable target — the chain is not pointing nowhere.
        let chain_kid = ChainState::load(tmp.path())
            .expect("load chain")
            .signing_key_id
            .map(|k| k.as_str().to_string());
        assert_eq!(chain_kid.as_deref(), Some(outgoing_kid.as_str()));

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// R6-TDD-7 split: independent regression guard for the chain-state
    /// invariants of rotate_key (slot naming, rotation_count increment,
    /// anti-enumeration). Lives separately from
    /// `test_rotate_key_record_signed_by_outgoing_key` (which asserts the
    /// cryptographic invariants) so a regression on either dimension is
    /// independently visible.
    #[test]
    fn test_rotate_key_chain_state_invariants() {
        super::super::test_helpers::init_mock_keyring();
        // rotate_key → resolve_policy() reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race a sibling that mutates it
        // (testing.md Rule 6 — read-side tests share the risk).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("rotate_state_invariants");
        // Valid Crockford Base32 ULID (alphabet excludes I/L/O/U).
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5NVR";

        let state = ChainState::new(chain_id);
        state.save(tmp.path()).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
        audit_init(tmp.path(), &svc).expect("audit_init");
        let pre_state = ChainState::load(tmp.path()).expect("load pre");
        let outgoing_kid = pre_state.signing_key_id.clone().expect("outgoing kid");

        let (_new_key, _record) =
            rotate_key(tmp.path(), &svc, RotationReason::Operator).expect("rotate");

        // Invariant 1: opaque historical slot at `historical/0` holds the
        // outgoing key (R1 M-5 anti-enumeration).
        assert!(
            LocalSigningKey::exists_in_keychain(&svc, "historical/0"),
            "outgoing key must be retained under historical/0"
        );

        // Invariant 2: outgoing KeyId is NOT enumerable as a keychain
        // account (defends against same-UID Keychain Access enumeration).
        assert!(
            !LocalSigningKey::exists_in_keychain(&svc, outgoing_kid.as_str()),
            "outgoing key MUST NOT be enumerable under its public KeyId account name"
        );

        // Invariant 3: rotation_count monotonically incremented to 1.
        let post_state = ChainState::load(tmp.path()).expect("load post");
        assert_eq!(
            post_state.rotation_count, 1,
            "rotation_count MUST monotonically increment on rotate-key (was 0, now 1)"
        );

        // Invariant 4: chain.json now records the new key (not the outgoing).
        assert_ne!(
            post_state.signing_key_id.as_ref().map(|k| k.as_str()),
            Some(outgoing_kid.as_str()),
            "chain.json signing_key_id must point at incoming key after rotation"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// R6-TDD-1: rotate_key MUST return `NoKeyToRotate` when chain.json
    /// has a valid chain_id but no `signing_key_id` (pre-`audit init` state).
    /// Previously untested — the production path
    /// `state.signing_key_id.clone().ok_or(KeyCustodyError::NoKeyToRotate)`
    /// is the most common operator-facing failure mode after a manual
    /// chain.json edit or partial migration.
    #[test]
    fn test_rotate_key_no_key_to_rotate_when_signing_key_absent() {
        super::super::test_helpers::init_mock_keyring();
        // rotate_key → resolve_policy() reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race a sibling that mutates it
        // (testing.md Rule 6 — read-side tests share the risk).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("rotate_no_key");
        // Valid ULID — passes the chain_id-empty guard so we reach the
        // NoKeyToRotate branch below.
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FNK";

        // Bootstrap chain.json with chain_id set but NO signing_key_id.
        let state = ChainState::new(chain_id);
        state.save(tmp.path()).expect("save chain.json");

        let result = rotate_key(tmp.path(), &svc, RotationReason::Operator);
        assert!(
            matches!(result, Err(KeyCustodyError::NoKeyToRotate)),
            "rotate_key with no signing_key_id MUST return NoKeyToRotate, got {result:?}"
        );
    }

    /// R6-TDD-2: rotate_key MUST detect when the key stored in the keychain
    /// has a different `KeyId` than `chain.json` records (the H-7 mismatch
    /// path). This is the most likely corruption mode after a partial
    /// migration or manual keychain edit. Previously untested.
    #[test]
    fn test_rotate_key_keychain_chain_json_keyid_mismatch_returns_error() {
        super::super::test_helpers::init_mock_keyring();
        // rotate_key → resolve_policy() reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race a sibling that mutates it
        // (testing.md Rule 6 — read-side tests share the risk).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("rotate_kid_mismatch");
        // Valid Crockford Base32 ULID (alphabet excludes I/L/O/U).
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5MSM";

        let state = ChainState::new(chain_id);
        state.save(tmp.path()).expect("save chain.json");

        // Step 1: audit_init creates a real key A in the keychain and
        // writes A's key_id to chain.json.
        audit_init(tmp.path(), &svc).expect("audit_init");

        // Step 2: REPLACE the stored key (BOTH file store + keychain) under the
        // active slot with a different key B (simulates a manual edit / partial
        // migration). chain.json still records A's key_id, so rotate's H-7 check
        // (which reads the file store FIRST) must fire.
        let _ = delete_dual(tmp.path(), &svc, chain_id, KeySlot::Active);
        let _replacement = crate::audit::key_custody::generate_and_store_dual(
            tmp.path(),
            &svc,
            chain_id,
            KeySlot::Active,
            0,
            None,
        )
        .expect("generate replacement key B");

        // Step 3: rotate_key MUST detect the mismatch and return ChainParse.
        let result = rotate_key(tmp.path(), &svc, RotationReason::Operator);
        let err = result.expect_err("rotate_key must fail with H-7 mismatch");
        let err_str = format!("{err:?}");
        assert!(
            err_str.contains("keychain account key_id mismatch") || err_str.contains("ChainParse"),
            "expected H-7 mismatch error, got {err_str}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// Named test — rotate_key with empty chain_id returns error.
    #[test]
    fn test_rotate_key_empty_chain_id_returns_error() {
        super::super::test_helpers::init_mock_keyring();
        // rotate_key → resolve_policy() reads CSQ_AUDIT_EDITION; hold the shared
        // env lock so this test doesn't race a sibling that mutates it
        // (testing.md Rule 6 — read-side tests share the risk).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc();

        // Save a ChainState with empty chain_id (simulates missing chain.json
        // where chain_id was never set).
        let state = ChainState::new("");
        state.save(tmp.path()).expect("save");

        let result = rotate_key(tmp.path(), &svc, RotationReason::Operator);
        assert!(
            result.is_err(),
            "rotate_key should fail when chain_id is empty"
        );
        let err = result.unwrap_err();
        let err_str = format!("{err:?}");
        assert!(
            err_str.contains("chain_id is empty") || err_str.contains("ChainParse"),
            "unexpected error: {err_str}"
        );
    }

    // ── M13 — F-LEDGER-02 append-FIRST regression tests ──────────────────────

    /// Reads every record on the committed chain file for `chain_id`.
    fn read_chain_records(base: &Path, chain_id: &str) -> Vec<SignedRecord> {
        let p = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        let content = std::fs::read_to_string(&p).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<SignedRecord>(l).expect("parse chain record"))
            .collect()
    }

    /// an internal ticket review HIGH: rotation MUST carry the keychain-anchored
    /// roster_version_floor into the incoming key's payload — a 3-field
    /// rewrite silently drops the anchor and degrades the detector to
    /// permanent Unconfirmed.
    #[test]
    fn rotate_preserves_roster_floor() {
        super::super::test_helpers::init_mock_keyring();
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("rotate_preserves_floor");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5F0R";

        ChainState::new(chain_id)
            .save(tmp.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(tmp.path(), &svc).expect("audit_init");

        // Anchor a floor (as `csq audit roster install` does).
        crate::audit::key_custody::keyring_backend::write_roster_floor_to_keychain(
            tmp.path(),
            &svc,
            chain_id,
            42,
        );

        let (_new_key, _outcome) =
            rotate_key(tmp.path(), &svc, RotationReason::Operator).expect("rotate");

        // The INCOMING key's payload must still carry the floor...
        let account = KeySlot::Active.keychain_account(chain_id);
        let ec = crate::audit::key_custody::load_embedded_cutoff(&svc, &account)
            .expect("load must not error")
            .expect("active entry must exist post-rotate");
        assert_eq!(
            ec.roster_version_floor,
            Some(42),
            "rotation MUST preserve the keychain-anchored roster floor"
        );
        // ...and remain loadable by the typed key-load path.
        assert!(
            LocalSigningKey::load_from_keychain(&svc, &account).is_ok(),
            "post-rotate floor-bearing entry must load"
        );
    }

    /// AC-1 + AC-2 (success) + the sign-after-assign fix: a community rotate
    /// emits the INTENT record BEFORE the OUTCOME record, both `KeyRotate`,
    /// sharing one correlation id, and the chain (intent at seq N, outcome at
    /// seq N+1) verifies — proving the outcome's signature is valid at seq ≥ 1
    /// (the latent pre-M13 bug signed over a placeholder seq=0 and only verified
    /// at seq 0).
    #[test]
    fn test_m13_rotate_emits_intent_then_outcome() {
        super::super::test_helpers::init_mock_keyring();
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("m13_intent_outcome");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5M13";

        ChainState::new(chain_id)
            .save(tmp.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(tmp.path(), &svc).expect("audit_init");

        let (_new_key, outcome) =
            rotate_key(tmp.path(), &svc, RotationReason::Operator).expect("rotate");

        let records = read_chain_records(tmp.path(), chain_id);
        assert_eq!(
            records.len(),
            2,
            "a rotation emits exactly two records (intent + outcome), got {}",
            records.len()
        );

        // Record 0 — INTENT, drained before the keychain mutation.
        let intent_corr = match &records[0].op_phase {
            Some(OpPhase::Intent { correlation_id }) => correlation_id.clone(),
            other => panic!("record 0 must be an Intent, got {other:?}"),
        };
        assert_eq!(records[0].kind, EventKind::KeyRotate);

        // Record 1 — OUTCOME:ok, appended after the side effect committed.
        let outcome_corr = match &records[1].op_phase {
            Some(OpPhase::Outcome {
                correlation_id,
                result: OpOutcome::Ok,
            }) => correlation_id.clone(),
            other => panic!("record 1 must be an Outcome::Ok, got {other:?}"),
        };
        assert_eq!(records[1].kind, EventKind::KeyRotate);

        assert_eq!(
            intent_corr.as_str(),
            outcome_corr.as_str(),
            "intent and outcome MUST share one correlation id"
        );
        assert!(
            records[0].seq < records[1].seq,
            "intent (seq {}) MUST precede outcome (seq {})",
            records[0].seq,
            records[1].seq
        );

        // The returned record is the finalized OUTCOME with real seq/signature.
        assert!(matches!(outcome.op_phase, Some(OpPhase::Outcome { .. })));
        assert_eq!(outcome.seq, records[1].seq);

        // Full chain verifies — the outcome's signature is valid at seq ≥ 1.
        let config = crate::audit::verify::VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        let summary =
            crate::audit::verify::verify_chain(tmp.path(), &config, None).expect("verify_chain");
        assert_eq!(
            summary.verified_count, 2,
            "both intent and outcome must verify"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
    }

    /// AC-2 (failure path): when the keychain/chain.json mutation fails, the
    /// chain carries the INTENT plus an OUTCOME:failed sharing the correlation
    /// id (not a silent orphan), and the keychain is rolled back so the chain
    /// still verifies.
    #[test]
    fn test_m13_rotate_save_failure_emits_failed_outcome() {
        super::super::test_helpers::init_mock_keyring();
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("m13_failed_outcome");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5M14";

        ChainState::new(chain_id)
            .save(tmp.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
        audit_init(tmp.path(), &svc).expect("audit_init");

        let result = rotate_key_inner(tmp.path(), &svc, RotationReason::Operator, |_, _| {
            Err(KeyCustodyError::ChainIo(
                "injected save failure".to_string(),
            ))
        });
        assert!(result.is_err(), "injected save failure must propagate");

        let records = read_chain_records(tmp.path(), chain_id);
        assert_eq!(
            records.len(),
            2,
            "intent (drained before mutation) + outcome:failed must both be on the chain"
        );
        let intent_corr = match &records[0].op_phase {
            Some(OpPhase::Intent { correlation_id }) => correlation_id.clone(),
            other => panic!("record 0 must be an Intent, got {other:?}"),
        };
        match &records[1].op_phase {
            Some(OpPhase::Outcome {
                correlation_id,
                result: OpOutcome::Failed { .. },
            }) => assert_eq!(correlation_id.as_str(), intent_corr.as_str()),
            other => panic!("record 1 must be an Outcome::Failed, got {other:?}"),
        }

        // The keychain was rolled back (head = outgoing), so the chain — both
        // records signed by the outgoing key — still verifies.
        let config = crate::audit::verify::VerifyConfig {
            record_limit: 10_000,
            keychain_service: svc.clone(),
        };
        crate::audit::verify::verify_chain(tmp.path(), &config, None)
            .expect("chain with intent + failed-outcome must verify after rollback");

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }

    /// AC-3 (fail-closed): if the INTENT record cannot be persisted, the op
    /// aborts BEFORE any keychain mutation — no record lands and the outgoing
    /// key remains the head with no historical archive. Simulated by making the
    /// `csq-runs/` directory read-only so the intent write fails.
    #[cfg(unix)]
    #[test]
    fn test_m13_intent_persist_failure_aborts_op_keychain_untouched() {
        use std::os::unix::fs::PermissionsExt;

        super::super::test_helpers::init_mock_keyring();
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let tmp = tmp_base();
        let svc = svc_for("m13_intent_failclosed");
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5M15";

        ChainState::new(chain_id)
            .save(tmp.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "historical/0");
        audit_init(tmp.path(), &svc).expect("audit_init");

        let outgoing_kid = LocalSigningKey::load_from_keychain(&svc, chain_id)
            .expect("load outgoing")
            .key_id()
            .as_str()
            .to_string();

        // Make csq-runs/ read-only so the intent's tmp write fails (EACCES).
        // Reads (chain.json) still work, so rotate_key gets PAST authorize and
        // fails AT the intent drain — the fail-closed boundary under test.
        let csq_runs = tmp.path().join("csq-runs");
        let mut perms = std::fs::metadata(&csq_runs).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&csq_runs, perms).unwrap();

        let result = rotate_key(tmp.path(), &svc, RotationReason::Operator);

        // Restore write perms so later reads/cleanup work.
        let mut perms = std::fs::metadata(&csq_runs).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&csq_runs, perms).unwrap();

        assert!(
            result.is_err(),
            "intent-persist failure MUST abort the rotation (fail closed)"
        );

        // No KeyRotate record landed (the intent write failed before commit).
        let records = read_chain_records(tmp.path(), chain_id);
        assert!(
            records.iter().all(|r| r.kind != EventKind::KeyRotate),
            "no KeyRotate record may land when the intent could not be persisted"
        );

        // Keychain untouched: head is still the outgoing key, no historical slot.
        let head_after = LocalSigningKey::load_from_keychain(&svc, chain_id)
            .expect("outgoing key must remain in the head slot")
            .key_id()
            .as_str()
            .to_string();
        assert_eq!(
            head_after, outgoing_kid,
            "intent-persist failure must leave the head key untouched"
        );
        assert!(
            !LocalSigningKey::exists_in_keychain(&svc, "historical/0"),
            "no historical archive may exist after a fail-closed intent abort"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
    }
}
