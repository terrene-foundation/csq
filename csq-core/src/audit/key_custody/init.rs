//! Idempotent signing-key initialisation (`csq audit init`).
//!
//! Generates an Ed25519 keypair, stores the private key in the OS keychain
//! via `keyring`, and writes `signing_key_id` + `pubkey` into `chain.json`.
//!
//! If a key already exists in the keychain for the current `chain_id`,
//! returns `Ok(false)` (no-op).  If no key exists, generates one and
//! returns `Ok(true)`.

use std::path::Path;

use crate::audit::key_custody::{
    chain_state::ChainState, delete_dual, exists_any, generate_and_store_dual, KeyCustodyError,
    KeySlot,
};
use crate::audit::traits::SigningKey as _;

// The EATP chain runs_subdir. Mirrors ChainKind::Eatp::runs_subdir() but
// avoids importing persist here (no circular dep risk, and the string is trivial).
const EATP_RUNS_SUBDIR: &str = "eatp-runs";

/// Idempotent key initialisation.
///
/// # Arguments
///
/// - `base_dir` — csq accounts base directory (`~/.claude/accounts`).
/// - `service`  — keychain service name; production callers pass
///   [`crate::audit::key_custody::keyring_backend::SERVICE_NAME`];
///   tests pass a sandboxed name.
///
/// # Returns
///
/// - `Ok(true)` — key was generated and stored.
/// - `Ok(false)` — key already present; no-op.
/// - `Err(...)` — generation, keychain write, or `chain.json` write failed.
pub fn audit_init(base_dir: &Path, service: &str) -> Result<bool, KeyCustodyError> {
    audit_init_inner(base_dir, service, |state, base| state.save(base))
}

/// Closure-injectable inner for failure-branch testing per
/// `rules/redteam-discipline.md` Rule 5. The `save_fn` closure performs the
/// final `chain.json` write; production callers pass `|state, base|
/// state.save(base)`, tests inject failure-returning closures to exercise the
/// H-5 rollback path (delete the keychain entry on save failure).
///
/// R6-TDD-3: visibility narrowed to `pub(super)` so only this module + its
/// parent (`key_custody/mod.rs`) can reach this test-injection seam. Other
/// modules within csq-core cannot accidentally call it with a no-op save
/// closure that would bypass the rollback invariant.
pub(super) fn audit_init_inner<F>(
    base_dir: &Path,
    service: &str,
    save_fn: F,
) -> Result<bool, KeyCustodyError>
where
    F: FnOnce(&ChainState, &Path) -> Result<(), KeyCustodyError>,
{
    let mut state = ChainState::load(base_dir)?;

    // H-1: Derive the keychain account from the chain_id obtained via
    // read_or_init_chain_genesis — never fall back to a "default" sentinel.
    // If chain.json does not yet exist, initialise it; obtain the authoritative
    // chain_id from there.
    let account = if state.chain_id.is_empty() {
        // chain.json missing or has no chain_id — initialise via the canonical
        // persist-layer helper and read back the authoritative chain_id.
        let csq_runs_dir = base_dir.join("csq-runs");

        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&csq_runs_dir)
                .map_err(|e| KeyCustodyError::ChainIo(format!("create csq-runs/: {e}")))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&csq_runs_dir)
                .map_err(|e| KeyCustodyError::ChainIo(format!("create csq-runs/: {e}")))?;
        }

        let ts = crate::audit::persist::current_iso8601_utc_persist();
        let genesis = crate::audit::persist::read_or_init_chain_genesis(&csq_runs_dir, &ts)
            .map_err(|e| KeyCustodyError::ChainIo(format!("read_or_init_chain_genesis: {e}")))?;

        // Reload chain.json so state reflects the newly-written genesis.
        state = ChainState::load(base_dir)?;
        if state.chain_id.is_empty() {
            // Patch chain_id into ChainState from the genesis we just wrote.
            state.chain_id = genesis.chain_id.clone();
        }
        genesis.chain_id
    } else {
        state.chain_id.clone()
    };

    // Idempotency check: if the key is already present in EITHER store (file or
    // keychain), no-op. `exists_any` covers a pre-migration install whose key is
    // keychain-only as well as a file-store install.
    if exists_any(base_dir, service, &account, KeySlot::Active) {
        tracing::info!(
            service = service,
            account = account,
            "audit_init: signing key already present, no-op"
        );
        return Ok(false);
    }

    // Compute the cutoff before generate_and_store so we can embed it in the
    // seed payload atomically (M-hardening: cutoff co-located with seed).
    let cutoff_for_new_key = if let Some(existing) = state.signing_active_since_seq {
        existing
    } else {
        let csq_runs_dir = base_dir.join("csq-runs");
        if !state.chain_id.is_empty() {
            let jsonl_path = csq_runs_dir.join(format!("{}.jsonl", state.chain_id));
            if jsonl_path.exists() {
                std::fs::read_to_string(&jsonl_path)
                    .ok()
                    .and_then(|content| {
                        content
                            .lines()
                            .rev()
                            .find(|l| !l.trim().is_empty())
                            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                            .and_then(|v| v["seq"].as_u64())
                            .map(|s| s + 1)
                    })
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        }
    };

    // Generate and store to BOTH stores — file (daemon-readable primary) +
    // keychain (integrity anchor, best-effort). The cutoff is embedded in the
    // payload so cutoff and key share fate (M-hardening directive).
    let key = generate_and_store_dual(
        base_dir,
        service,
        &account,
        KeySlot::Active,
        cutoff_for_new_key,
        // Fresh init: no roster installed yet — the floor is anchored later by
        // `csq audit roster install`.
        None,
    )?;
    tracing::info!(
        key_id = key.key_id().as_str(),
        "audit_init: generated new signing key"
    );

    // Update chain.json with the new key identity.
    state.signing_key_id = Some(key.key_id());
    state.pubkey = Some(key.public_key());

    // R1-DEEP-2: Set signing_active_since_seq to the cutoff we computed and
    // already embedded in the seed entry above (M-hardening: both must agree).
    // `state.signing_active_since_seq` may already hold a value (if chain.json
    // had it from a previous partial init); overwrite only when absent so the
    // embedded cutoff and chain.json stay consistent.
    if state.signing_active_since_seq.is_none() {
        state.signing_active_since_seq = Some(cutoff_for_new_key);
    }
    // MED-2 consistency: if chain.json already had a cutoff from a prior
    // partial run, the embedded value must agree.  Both paths write the same
    // `cutoff_for_new_key` because the early-return branch above uses the
    // existing value.

    // H-5: Roll back BOTH stores (file + keychain) if chain.json save fails.
    // `save_fn` is the closure-injectable save step; production uses
    // `state.save(base_dir)`, tests inject failures to exercise rollback.
    if let Err(e) = save_fn(&state, base_dir) {
        let _ = delete_dual(base_dir, service, &account, KeySlot::Active);
        return Err(e);
    }

    Ok(true)
}

/// Idempotent EATP chain key initialisation (M3 §10.5 W2b).
///
/// Mirrors [`audit_init`] but targets the `eatp-runs/` chain rather than the
/// op-chain (`csq-runs/`). Uses [`ChainState::load_in`] / [`ChainState::save_in`]
/// with `"eatp-runs"` so the two chains remain fully independent (distinct
/// `chain_id`s, distinct JSONL files, shared `csq-runs/keys/` directory
/// discriminated by chain_id subfolder).
///
/// # Returns
///
/// - `Ok(true)` — key was generated and stored.
/// - `Ok(false)` — key already present; no-op.
/// - `Err(...)` — generation, keychain write, or `eatp-runs/chain.json` write failed.
pub fn eatp_audit_init(base_dir: &std::path::Path, service: &str) -> Result<bool, KeyCustodyError> {
    eatp_audit_init_inner(base_dir, service, |state, base| {
        state.save_in(base, EATP_RUNS_SUBDIR)
    })
}

/// Closure-injectable inner for `eatp_audit_init`. Mirrors `audit_init_inner` but
/// reads/writes via `ChainState::load_in` / `save_in` with `EATP_RUNS_SUBDIR`.
///
/// R6-TDD-3: visibility narrowed to `pub(super)` for the same reason as
/// `audit_init_inner`: only this module + tests in the parent module should
/// call this seam.
pub(super) fn eatp_audit_init_inner<F>(
    base_dir: &std::path::Path,
    service: &str,
    save_fn: F,
) -> Result<bool, KeyCustodyError>
where
    F: FnOnce(&ChainState, &std::path::Path) -> Result<(), KeyCustodyError>,
{
    // M1 (redteam R1): ensure the EATP runs-dir exists, then serialize the ENTIRE
    // key establishment (chain.json init + exists_any check + key mint + save)
    // under the EATP chain-lock. Without this, two concurrent `csq audit init`
    // both pass `exists_any` (key absent) and both `generate_and_store_dual` →
    // last-write-wins on the seed, so the genesis could be signed with a key the
    // file store no longer holds → permanent `verify_chain_in(Eatp)` failure (root
    // key loss). This is the SAME `.chain-lock` sidecar the genesis writer uses,
    // but it is acquired AND released here (before the genesis write in
    // `emit_eatp_genesis`), so there is no nested re-acquire / self-deadlock.
    let eatp_runs_dir = base_dir.join(EATP_RUNS_SUBDIR);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&eatp_runs_dir)
            .map_err(|e| KeyCustodyError::ChainIo(format!("create {EATP_RUNS_SUBDIR}/: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&eatp_runs_dir)
            .map_err(|e| KeyCustodyError::ChainIo(format!("create {EATP_RUNS_SUBDIR}/: {e}")))?;
    }
    let _eatp_lock = crate::audit::persist::acquire_chain_lock(&eatp_runs_dir)
        .map_err(|e| KeyCustodyError::ChainIo(format!("eatp chain-lock acquire: {e}")))?;

    let mut state = ChainState::load_in(base_dir, EATP_RUNS_SUBDIR)?;

    // H-1: derive the keychain account from the EATP chain_id. If `eatp-runs/chain.json`
    // does not yet exist, initialise it via the canonical persist-layer helper
    // (already serialized by the chain-lock above).
    let account = if state.chain_id.is_empty() {
        let ts = crate::audit::persist::current_iso8601_utc_persist();
        let genesis = crate::audit::persist::read_or_init_chain_genesis(&eatp_runs_dir, &ts)
            .map_err(|e| {
                KeyCustodyError::ChainIo(format!("read_or_init_chain_genesis (eatp): {e}"))
            })?;

        // Reload so state reflects the newly-written genesis.
        state = ChainState::load_in(base_dir, EATP_RUNS_SUBDIR)?;
        if state.chain_id.is_empty() {
            state.chain_id = genesis.chain_id.clone();
        }
        genesis.chain_id
    } else {
        state.chain_id.clone()
    };

    // Idempotency: the EATP key uses the same csq-runs/keys/<chain_id>/ path
    // as the op-chain key but a distinct chain_id subfolder.
    if exists_any(base_dir, service, &account, KeySlot::Active) {
        tracing::info!(
            service = service,
            account = account,
            "eatp_audit_init: EATP signing key already present, no-op"
        );
        return Ok(false);
    }

    // For a brand-new EATP chain the genesis record lands at seq 0, so the
    // key is valid from seq 0 (no prior records exist).
    let cutoff_for_new_key: u64 = 0;

    let key = generate_and_store_dual(
        base_dir,
        service,
        &account,
        KeySlot::Active,
        cutoff_for_new_key,
        None,
    )?;
    tracing::info!(
        key_id = key.key_id().as_str(),
        "eatp_audit_init: generated new EATP signing key"
    );

    state.signing_key_id = Some(key.key_id());
    state.pubkey = Some(key.public_key());
    if state.signing_active_since_seq.is_none() {
        state.signing_active_since_seq = Some(cutoff_for_new_key);
    }

    // H-5: roll back BOTH stores if chain.json save fails.
    if let Err(e) = save_fn(&state, base_dir) {
        let _ = delete_dual(base_dir, service, &account, KeySlot::Active);
        return Err(e);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::keyring_backend::LocalSigningKey;
    use tempfile::TempDir;

    fn tmp_base() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn sandboxed_service() -> String {
        format!("csq-audit-signing-test-{}", std::process::id())
    }

    /// Named test — idempotent second call is a no-op.
    #[test]
    fn test_audit_init_idempotent_second_call_is_noop() {
        super::super::test_helpers::init_mock_keyring();
        let tmp = tmp_base();
        let svc = sandboxed_service();
        // Need a stable account name distinct from other tests.
        let account_sentinel = "idempotent_noop_test";
        // Pre-set chain_id so init uses our sentinel as account.
        let state = ChainState::new(account_sentinel);
        state.save(tmp.path()).expect("init chain.json");

        // Clean up any prior residue for this account.
        let _ = LocalSigningKey::delete_from_keychain(&svc, account_sentinel);

        // First call — should generate.
        let first = audit_init(tmp.path(), &svc).expect("first call");
        assert!(first, "first call should return true (generated)");

        // Second call — should be no-op.
        let second = audit_init(tmp.path(), &svc).expect("second call");
        assert!(!second, "second call should return false (no-op)");

        // R6-TDD-4: noop semantics — compare the FULL chain.json bytes
        // before and after the second call. The second call MUST NOT
        // mutate any field (signing_key_id, pubkey, rotation_count,
        // genesis_seq, genesis_ts) — true no-op, not just "returns false".
        let chain_path = tmp.path().join("csq-runs").join("chain.json");
        let bytes_before_second = std::fs::read(&chain_path).expect("read pre-second");
        let _second = audit_init(tmp.path(), &svc).expect("second call (noop)");
        let bytes_after_second = std::fs::read(&chain_path).expect("read post-second");
        assert_eq!(
            bytes_before_second, bytes_after_second,
            "audit_init second call MUST be a true no-op: chain.json bytes \
             unchanged. If this fails, a side field (e.g. rotation_count) \
             was mutated on the idempotent path."
        );

        // chain.json still holds the same key_id (sanity check).
        let s1 = ChainState::load(tmp.path()).expect("load after first");
        let s2 = ChainState::load(tmp.path()).expect("load after second");
        assert_eq!(
            s1.signing_key_id.as_ref().map(|k| k.as_str()),
            s2.signing_key_id.as_ref().map(|k| k.as_str())
        );

        // Cleanup.
        let _ = LocalSigningKey::delete_from_keychain(&svc, account_sentinel);
    }

    /// R4-TS-1: H-5 rollback path — when `chain.json` save fails, the
    /// keychain entry that `generate_and_store` wrote MUST be deleted to
    /// avoid an orphan keychain entry that locks future `csq audit init`
    /// calls into the idempotency no-op branch.
    ///
    /// Uses closure injection per `rules/redteam-discipline.md` Rule 5 —
    /// the test injects a save closure that returns Err, then asserts
    /// the keychain entry is absent after the failed audit_init.
    #[test]
    fn test_audit_init_rollback_on_save_failure() {
        super::super::test_helpers::init_mock_keyring();
        let tmp = tmp_base();
        let svc = sandboxed_service();
        let account_sentinel = "rollback_save_failure_test";
        let state = ChainState::new(account_sentinel);
        state.save(tmp.path()).expect("init chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, account_sentinel);

        // Inject a save closure that always returns Err to drive the
        // H-5 rollback path.
        let result = audit_init_inner(tmp.path(), &svc, |_, _| {
            Err(KeyCustodyError::ChainIo(
                "injected save failure".to_string(),
            ))
        });
        assert!(
            result.is_err(),
            "audit_init must propagate the injected save failure"
        );

        // H-5 rollback: the keychain entry must NOT remain.
        assert!(
            !LocalSigningKey::exists_in_keychain(&svc, account_sentinel),
            "H-5 rollback failed: keychain entry remained after save failure"
        );

        // Cleanup (defensive).
        let _ = LocalSigningKey::delete_from_keychain(&svc, account_sentinel);
    }

    #[test]
    fn test_audit_init_writes_chain_json() {
        super::super::test_helpers::init_mock_keyring();
        let tmp = tmp_base();
        let svc = sandboxed_service();
        let account = "audit_init_writes_chain_json";
        let state = ChainState::new(account);
        state.save(tmp.path()).expect("init chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);

        audit_init(tmp.path(), &svc).expect("init");

        let loaded = ChainState::load(tmp.path()).expect("load");
        assert!(
            loaded.signing_key_id.is_some(),
            "signing_key_id must be set after init"
        );
        assert!(loaded.pubkey.is_some(), "pubkey must be set after init");
        let kid = loaded.signing_key_id.unwrap();
        assert!(kid.as_str().starts_with("ed25519:"));

        let _ = LocalSigningKey::delete_from_keychain(&svc, account);
    }

    // ── M3 §10.5 W2b: eatp_audit_init tests ──────────────────────────────────

    /// C1-pre: `eatp_audit_init` initialises a distinct EATP chain key and
    /// chain.json under `eatp-runs/`, independent of the op-chain under
    /// `csq-runs/`. Tests key generation + idempotency gate for the EATP key.
    #[test]
    fn eatp_audit_init_generates_key_and_writes_eatp_chain_json() {
        super::super::test_helpers::init_mock_keyring();
        let tmp = tmp_base();
        let svc = sandboxed_service();

        // First call — must return true (key generated), create eatp-runs/chain.json.
        let first = eatp_audit_init(tmp.path(), &svc).expect("eatp first call");
        assert!(
            first,
            "eatp_audit_init first call must return true (key generated)"
        );

        let eatp_chain_json = tmp.path().join("eatp-runs").join("chain.json");
        assert!(
            eatp_chain_json.exists(),
            "eatp_audit_init must create eatp-runs/chain.json"
        );

        let eatp_state =
            ChainState::load_in(tmp.path(), "eatp-runs").expect("load eatp chain.json");
        assert!(
            eatp_state.signing_key_id.is_some(),
            "eatp chain.json must have signing_key_id after init"
        );
        assert!(
            eatp_state.pubkey.is_some(),
            "eatp chain.json must have pubkey after init"
        );
        assert!(
            !eatp_state.chain_id.is_empty(),
            "eatp chain.json must have a non-empty chain_id after init"
        );

        // The op-chain must NOT be created by eatp_audit_init.
        // The signing key file-store lives under csq-runs/keys/<chain_id>/ (the shared
        // key directory, discriminated by chain_id). eatp_audit_init IS expected to
        // create csq-runs/keys/ because the file store is shared across chain kinds.
        // The EATP JSONL + chain.json, however, live under eatp-runs/ only (op isolation).
        assert!(
            !tmp.path().join("csq-runs").join("chain.json").exists(),
            "eatp_audit_init must NOT create the op-chain's csq-runs/chain.json"
        );
        // Verify the key file-store entry was created under the EATP chain_id.
        let key_dir = tmp
            .path()
            .join("csq-runs")
            .join("keys")
            .join(&eatp_state.chain_id);
        assert!(
            key_dir.exists(),
            "eatp_audit_init must create csq-runs/keys/<eatp_chain_id>/"
        );

        // Second call — idempotent, must return false (no-op).
        let second = eatp_audit_init(tmp.path(), &svc).expect("eatp second call");
        assert!(
            !second,
            "eatp_audit_init second call must return false (idempotent no-op)"
        );

        // Cleanup.
        let _ = LocalSigningKey::delete_from_keychain(&svc, &eatp_state.chain_id);
    }

    /// C1-pre-2: `eatp_audit_init` and `audit_init` in the same base_dir produce
    /// INDEPENDENT chain_ids and DO NOT cross-populate each other's chain.json.
    #[test]
    fn eatp_and_op_chain_inits_are_independent() {
        super::super::test_helpers::init_mock_keyring();
        let tmp = tmp_base();
        let svc = sandboxed_service();

        // Pre-seed the op-chain with a known chain_id so audit_init uses it.
        let op_account = "op_chain_test_independence";
        let op_state = ChainState::new(op_account);
        op_state.save(tmp.path()).expect("seed op chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, op_account);

        audit_init(tmp.path(), &svc).expect("op-chain audit_init");
        let first_eatp = eatp_audit_init(tmp.path(), &svc).expect("eatp_audit_init");
        assert!(first_eatp, "eatp_audit_init must generate a fresh key");

        let op_loaded = ChainState::load(tmp.path()).expect("op chain.json");
        let eatp_loaded = ChainState::load_in(tmp.path(), "eatp-runs").expect("eatp chain.json");

        // chain_ids must be distinct.
        assert_ne!(
            op_loaded.chain_id, eatp_loaded.chain_id,
            "op-chain and EATP chain must have distinct chain_ids"
        );
        // Signing key ids must be distinct (independent key slots).
        assert_ne!(
            op_loaded.signing_key_id, eatp_loaded.signing_key_id,
            "op-chain and EATP chain must have distinct signing key ids"
        );

        // Cleanup.
        let _ = LocalSigningKey::delete_from_keychain(&svc, op_account);
        let _ = LocalSigningKey::delete_from_keychain(&svc, &eatp_loaded.chain_id);
    }
}
