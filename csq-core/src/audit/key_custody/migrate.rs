//! Explicit audit-key migration + repair (`csq audit migrate-keys`, `csq audit repair`).
//!
//! These are the OPERATOR-INVOKED recovery paths for the keychain → file-store
//! custody change. They are deliberately NOT lazy/automatic on a verify read:
//! `verify_chain` is read-only (spec §12.13.9), and migration must run in an
//! INTERACTIVE context where the user can grant the one-time macOS keychain
//! prompt that a non-interactive daemon cannot answer (the brick root cause,
//! an internal journal entry).
//!
//! - [`migrate_keys_to_file_store`] — copy the active + every historical
//!   keychain seed into the 0o600 file store so the daemon can read them
//!   non-interactively, AND establish the keychain as the integrity anchor for
//!   the file copies. This is the primary recovery for an existing install
//!   whose keys predate the file store.
//! - [`repair_audit_chain`] — clear a stale `.chain-broken` sentinel when the
//!   chain now verifies, or (with `apply`) back up + reset a genuinely-broken
//!   chain so a fresh `csq audit init` can start clean.

use std::path::{Path, PathBuf};

use crate::audit::health::{clear_chain_broken_in, is_chain_broken_in};
use crate::audit::key_custody::chain_state::ChainState;
use crate::audit::key_custody::file_store::{self, KeySlot};
use crate::audit::key_custody::keyring_backend::LocalSigningKey;
use crate::audit::key_custody::KeyCustodyError;
use crate::audit::persist::ChainKind;
use crate::audit::verify::{verify_chain_in, VerifyConfig};

/// Result of a `csq audit migrate-keys` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateOutcome {
    /// The active key was copied keychain → file store this run.
    pub active_migrated: bool,
    /// The active key was already present in the file store (no-op).
    pub active_already_present: bool,
    /// Historical rotation indices copied keychain → file store this run.
    pub historical_migrated: Vec<u64>,
    /// Historical rotation indices that could NOT be migrated because the
    /// keychain entry was present-but-inaccessible (locked / access-denied).
    /// These leave pre-cutoff records signed by that rotated-out key
    /// daemon-unreadable (they verify in DEGRADED mode); retry interactively.
    pub historical_inaccessible: Vec<u64>,
    /// The keychain could not be read for the active key even in this
    /// (interactive) context — the user must unlock the keychain / fix the
    /// item ACL before migration can succeed.
    pub keychain_inaccessible: bool,
    /// No keychain entry existed for the active key (nothing to migrate; e.g.
    /// a fresh install or an already-file-only chain).
    pub keychain_absent: bool,
}

/// Migrate the active + historical signing seeds from the OS keychain into the
/// file store for the chain recorded in `chain.json`.
///
/// Run interactively (`csq audit migrate-keys`) so the one-time keychain prompt
/// can be granted. Idempotent: keys already present in the file store are left
/// untouched. The keychain entries are NOT deleted — they remain the integrity
/// anchor and a back-compat fallback (migration is additive).
pub fn migrate_keys_to_file_store(
    base_dir: &Path,
    service: &str,
) -> Result<MigrateOutcome, KeyCustodyError> {
    let state = ChainState::load(base_dir)?;
    if state.chain_id.is_empty() {
        return Err(KeyCustodyError::ChainParse(
            "chain.json has no chain_id — nothing to migrate (run `csq audit init` first)"
                .to_string(),
        ));
    }
    let chain_id = state.chain_id.clone();

    let mut outcome = MigrateOutcome {
        active_migrated: false,
        active_already_present: false,
        historical_migrated: Vec::new(),
        historical_inaccessible: Vec::new(),
        keychain_inaccessible: false,
        keychain_absent: false,
    };

    // --- Active slot ---
    if file_store::exists(base_dir, &chain_id, KeySlot::Active) {
        outcome.active_already_present = true;
    } else {
        match copy_keychain_seed_to_file(base_dir, service, &chain_id, KeySlot::Active) {
            CopyResult::Copied => outcome.active_migrated = true,
            CopyResult::Inaccessible => outcome.keychain_inaccessible = true,
            CopyResult::Absent => outcome.keychain_absent = true,
            CopyResult::Failed(e) => return Err(e),
        }
    }

    // --- Historical slots 0..=rotation_count ---
    // A historical key absent from the keychain is normal (not every index was
    // archived, or it was legitimately lost long ago) — skip silently.
    for n in 0..=state.rotation_count {
        let slot = KeySlot::Historical(n);
        if file_store::exists(base_dir, &chain_id, slot) {
            continue;
        }
        match copy_keychain_seed_to_file(base_dir, service, &chain_id, slot) {
            CopyResult::Copied => outcome.historical_migrated.push(n),
            // A blocked historical slot is not fatal to migration (the active key
            // is what the daemon needs for the head), but it IS reported so the
            // operator can retry — not silently dropped.
            CopyResult::Inaccessible => outcome.historical_inaccessible.push(n),
            // Absent historical slot = nothing to migrate (normal). Silent skip.
            CopyResult::Absent => {}
            CopyResult::Failed(e) => return Err(e),
        }
    }

    Ok(outcome)
}

enum CopyResult {
    Copied,
    Inaccessible,
    Absent,
    Failed(KeyCustodyError),
}

/// Read the keychain seed for `(chain_id, slot)` and write the SAME payload
/// bytes into the file store. Distinguishes access-error (Inaccessible) from
/// genuine absence (Absent) so the caller can surface the right remediation.
fn copy_keychain_seed_to_file(
    base_dir: &Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
) -> CopyResult {
    use crate::audit::key_custody::is_keychain_access_error;
    use zeroize::Zeroizing;

    let account = slot.keychain_account(chain_id);
    let entry = match crate::audit::key_custody::keyring_entry(service, &account) {
        Ok(e) => e,
        Err(e) => return CopyResult::Failed(KeyCustodyError::Keychain(e)),
    };
    match entry.get_password() {
        Ok(raw) => {
            let payload = Zeroizing::new(raw);
            // Validate the payload parses as a key before persisting (don't
            // copy a corrupt entry into the file store).
            if let Err(e) = LocalSigningKey::load_from_str(payload.as_str()) {
                return CopyResult::Failed(KeyCustodyError::KeyCorrupt(format!(
                    "keychain seed for {account} is unparseable, refusing to migrate: {e}"
                )));
            }
            match file_store::store_payload(base_dir, chain_id, slot, &payload) {
                Ok(()) => CopyResult::Copied,
                Err(e) => CopyResult::Failed(e),
            }
        }
        Err(keyring::Error::NoEntry) => CopyResult::Absent,
        Err(ref ke) if is_keychain_access_error(ke) => CopyResult::Inaccessible,
        Err(e) => CopyResult::Failed(KeyCustodyError::Keychain(e)),
    }
}

/// Result of a `csq audit repair` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairOutcome {
    /// The chain verifies clean (or degraded-historical) — nothing to repair.
    /// Any stale `.chain-broken` sentinel was cleared.
    Healthy { sentinel_cleared: bool },
    /// The chain could not be verified because the signing key is present but
    /// inaccessible (locked / ACL-blocked keychain, no file copy). Repair is
    /// the WRONG tool — the operator must run `csq audit migrate-keys`
    /// interactively (or unlock the keychain) instead of resetting the chain.
    NeedsMigration,
    /// `apply == false`: the chain is genuinely broken and a reset is required.
    /// Reports what `--apply` would back up and reset (dry-run).
    ResetRequired { reason: String },
    /// `apply == true`: the broken chain was backed up to `backup_dir` and the
    /// active chain state was reset so a fresh `csq audit init` starts clean.
    ChainReset { backup_dir: PathBuf, reason: String },
}

/// Diagnose and (optionally) repair the audit chain.
///
/// - Chain verifies (clean or degraded) → clear any stale sentinel, report
///   [`RepairOutcome::Healthy`].
/// - Chain unverifiable because the key is INACCESSIBLE (transient) → report
///   [`RepairOutcome::NeedsMigration`] (do NOT reset — the chain is probably
///   fine, the key just isn't daemon-readable yet).
/// - Chain genuinely broken (`KeyNotFound` / integrity failure) →
///   [`RepairOutcome::ResetRequired`] when `apply == false`, or back up +
///   reset and return [`RepairOutcome::ChainReset`] when `apply == true`.
///
/// `now_compact` is a caller-supplied timestamp fragment (e.g. `20260605T1830`)
/// for the backup directory name — passed in because csq forbids `Date::now()`
/// in library code paths that must remain deterministic for tests.
pub fn repair_audit_chain(
    base_dir: &Path,
    service: &str,
    apply: bool,
    now_compact: &str,
) -> Result<RepairOutcome, KeyCustodyError> {
    repair_audit_chain_in(base_dir, service, apply, now_compact, ChainKind::Op)
}

/// Like [`repair_audit_chain`], but repairs the `chain`'s runs-directory.
///
/// F1 (redteam R3): the born-canonical EATP attestation chain (`ChainKind::Eatp`,
/// `eatp-runs/`) gets the SAME operator recovery path as the op-chain. Without
/// this, an `eatp-runs/.chain-broken` sentinel (set by a `verify_chain_in(Eatp)`
/// reconcile after key loss / tampering) would refuse ALL EATP appends with no
/// command to clear or reset it — `csq audit repair` only knew the op-chain, and
/// `csq audit init` is wedged by the broken-sentinel write-refusal. Mirrors the
/// W2a verify-side `ChainKind` parameterization.
pub fn repair_audit_chain_in(
    base_dir: &Path,
    service: &str,
    apply: bool,
    now_compact: &str,
    chain: ChainKind,
) -> Result<RepairOutcome, KeyCustodyError> {
    let runs_subdir = chain.runs_subdir();
    let cfg = VerifyConfig {
        record_limit: 100_000,
        keychain_service: service.to_string(),
    };
    match verify_chain_in(base_dir, &cfg, None, chain) {
        Ok(_) => {
            let had_sentinel = is_chain_broken_in(base_dir, runs_subdir).is_some();
            if had_sentinel {
                clear_chain_broken_in(base_dir, runs_subdir);
            }
            Ok(RepairOutcome::Healthy {
                sentinel_cleared: had_sentinel,
            })
        }
        Err(crate::audit::LedgerError::KeychainUnavailable { .. }) => {
            Ok(RepairOutcome::NeedsMigration)
        }
        Err(e) => {
            let reason = format!("audit chain verification failed: {e}");
            if !apply {
                return Ok(RepairOutcome::ResetRequired { reason });
            }
            let (backup_dir, failed_moves) =
                backup_and_reset_chain_in(base_dir, runs_subdir, now_compact)?;
            // The new (empty) chain state is clean; clear the broken sentinel.
            clear_chain_broken_in(base_dir, runs_subdir);
            // DA4: a partial backup (some *.jsonl / sentinel could not be moved)
            // is reported in `reason`, not masked as a clean reset.
            let reason = if failed_moves.is_empty() {
                reason
            } else {
                format!(
                    "{reason}; WARNING: backup is INCOMPLETE — {} file(s) could not be moved: {}",
                    failed_moves.len(),
                    failed_moves.join(", ")
                )
            };
            Ok(RepairOutcome::ChainReset { backup_dir, reason })
        }
    }
}

/// Move the broken `csq-runs/` chain artifacts to a timestamped backup
/// directory alongside `base_dir`, leaving a clean slate for `csq audit init`.
///
/// Backs up `chain.json`, the per-chain `<chain_id>.jsonl`, and the `.chain-broken`
/// sentinel. The file-store `keys/` directory is LEFT IN PLACE (the keys are
/// still valid; only the ledger is reset) unless the operator deletes them.
fn backup_and_reset_chain_in(
    base_dir: &Path,
    runs_subdir: &str,
    now_compact: &str,
) -> Result<(PathBuf, Vec<String>), KeyCustodyError> {
    let csq_runs = base_dir.join(runs_subdir);
    let backup_dir = base_dir.join(format!("{runs_subdir}-broken-backup-{now_compact}"));
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| KeyCustodyError::ChainIo(format!("create backup dir: {e}")))?;

    // Move chain.json.
    let chain_json = csq_runs.join("chain.json");
    if chain_json.is_file() {
        let dst = backup_dir.join("chain.json");
        std::fs::rename(&chain_json, &dst)
            .map_err(|e| KeyCustodyError::ChainIo(format!("backup chain.json: {e}")))?;
    }

    // Collect per-file move failures so the caller can report a PARTIAL backup
    // rather than masking it as a clean reset (a stale *.jsonl left behind is
    // inert — a fresh init mints a new chain_id — but the operator must know the
    // backup is incomplete).
    let mut failed: Vec<String> = Vec::new();

    // Move the broken sentinel (so it does not block the fresh chain).
    let sentinel = csq_runs.join(".chain-broken");
    if sentinel.is_file() {
        let dst = backup_dir.join(".chain-broken");
        if std::fs::rename(&sentinel, &dst).is_err() {
            failed.push(".chain-broken".to_string());
        }
    }

    // Move every per-chain ledger file (*.jsonl) so the reset chain is empty.
    if let Ok(entries) = std::fs::read_dir(&csq_runs) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                if let Some(name) = path.file_name() {
                    let dst = backup_dir.join(name);
                    if std::fs::rename(&path, &dst).is_err() {
                        failed.push(name.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }

    Ok((backup_dir, failed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::init::audit_init;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn svc() -> String {
        format!("csq-audit-signing-test-{}", std::process::id())
    }

    /// migrate-keys copies the keychain active seed into the file store.
    #[test]
    fn migrate_copies_active_key_to_file_store() {
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let t = tmp();
        let service = format!("{}-migrate-active", svc());
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5MIG";
        ChainState::new(chain_id)
            .save(t.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&service, chain_id);

        // Seed the keychain only (simulate a pre-file-store install). audit_init
        // writes BOTH stores; to simulate keychain-only we delete the file after.
        audit_init(t.path(), &service).expect("init");
        file_store::delete(t.path(), chain_id, KeySlot::Active).expect("clear file");
        assert!(!file_store::exists(t.path(), chain_id, KeySlot::Active));

        let outcome = migrate_keys_to_file_store(t.path(), &service).expect("migrate");
        assert!(
            outcome.active_migrated,
            "active key must be migrated: {outcome:?}"
        );
        assert!(
            file_store::exists(t.path(), chain_id, KeySlot::Active),
            "file store must hold the active seed after migration"
        );
    }

    /// an internal ticket review C1 recovery path: migrate-keys MUST succeed on a
    /// keychain seed entry that carries the roster_version_floor (the typed
    /// validation parses the 4-field payload).
    #[test]
    fn migrate_copies_floor_bearing_keychain_seed() {
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let t = tmp();
        let service = format!("{}-migrate-floor", svc());
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5F1M";
        ChainState::new(chain_id)
            .save(t.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&service, chain_id);

        audit_init(t.path(), &service).expect("init");
        // Anchor a floor, THEN simulate a pre-file-store install.
        crate::audit::key_custody::keyring_backend::write_roster_floor_to_keychain(
            t.path(),
            &service,
            chain_id,
            9,
        );
        file_store::delete(t.path(), chain_id, KeySlot::Active).expect("clear file");
        assert!(!file_store::exists(t.path(), chain_id, KeySlot::Active));

        let outcome = migrate_keys_to_file_store(t.path(), &service).expect("migrate");
        assert!(
            outcome.active_migrated,
            "floor-bearing active key must migrate: {outcome:?}"
        );
        assert!(
            file_store::exists(t.path(), chain_id, KeySlot::Active),
            "file store must hold the seed after migration"
        );
    }

    /// migrate-keys is idempotent — a second run is a no-op (already present).
    #[test]
    fn migrate_is_idempotent() {
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let t = tmp();
        let service = format!("{}-migrate-idem", svc());
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5IDM";
        ChainState::new(chain_id)
            .save(t.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&service, chain_id);
        audit_init(t.path(), &service).expect("init");

        // audit_init already wrote the file store; migrate should be a no-op.
        let outcome = migrate_keys_to_file_store(t.path(), &service).expect("migrate");
        assert!(
            outcome.active_already_present,
            "active should already be present: {outcome:?}"
        );
        assert!(!outcome.active_migrated);
    }

    /// repair on a healthy chain clears a stale sentinel and reports Healthy.
    #[test]
    fn repair_healthy_chain_clears_sentinel() {
        // repair → verify_chain → resolve_policy() reads CSQ_AUDIT_EDITION; hold
        // the shared env lock so a concurrent edition-mutating test cannot flip
        // verify to fail-closed mid-run (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let t = tmp();
        let service = format!("{}-repair-healthy", svc());
        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5RPH";
        ChainState::new(chain_id)
            .save(t.path())
            .expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&service, chain_id);
        audit_init(t.path(), &service).expect("init");
        // Plant a stale sentinel.
        crate::audit::health::set_chain_broken(t.path(), "audit_verify_timeout");

        let outcome =
            repair_audit_chain(t.path(), &service, false, "20260605T0000").expect("repair");
        match outcome {
            RepairOutcome::Healthy { sentinel_cleared } => {
                assert!(
                    sentinel_cleared,
                    "stale sentinel must be cleared on healthy verify"
                );
            }
            other => panic!("expected Healthy, got {other:?}"),
        }
        assert!(
            is_chain_broken_in(t.path(), "csq-runs").is_none(),
            "sentinel must be gone"
        );
    }

    /// F1 (redteam R3): `repair_audit_chain_in(ChainKind::Eatp)` reconciles the
    /// EATP chain's OWN `eatp-runs/.chain-broken` sentinel — the operator recovery
    /// path that was missing for the born-canonical chain.
    #[test]
    fn repair_eatp_chain_clears_stale_sentinel() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let t = tmp();
        let service = format!("{}-repair-eatp", svc());

        // Establish the EATP chain (mints key + eatp-runs/chain.json; no genesis
        // record — verify_chain_in(Eatp) is Ok for an empty JSONL → Healthy).
        crate::audit::eatp_audit_init(t.path(), &service).expect("eatp init");
        // Plant a stale sentinel on the EATP chain specifically.
        crate::audit::health::set_chain_broken_in(t.path(), "eatp-runs", "audit_verify_timeout");
        // The op-chain has no sentinel — confirm the two chains are independent.
        assert!(
            is_chain_broken_in(t.path(), "csq-runs").is_none(),
            "op-chain sentinel must be untouched"
        );

        let outcome =
            repair_audit_chain_in(t.path(), &service, false, "20260605T0000", ChainKind::Eatp)
                .expect("eatp repair");
        match outcome {
            RepairOutcome::Healthy { sentinel_cleared } => {
                assert!(sentinel_cleared, "stale EATP sentinel must be cleared");
            }
            other => panic!("expected Healthy, got {other:?}"),
        }
        assert!(
            is_chain_broken_in(t.path(), "eatp-runs").is_none(),
            "EATP sentinel must be gone"
        );

        // Cleanup the EATP key.
        if let Ok(state) = ChainState::load_in(t.path(), "eatp-runs") {
            LocalSigningKey::delete_from_keychain(&service, &state.chain_id).ok();
        }
    }

    /// F1 (redteam R3): the reset mechanic backs up + clears the EATP runs-dir
    /// (not the op-chain). Proves `backup_and_reset_chain_in` is correctly
    /// parameterized by `runs_subdir`.
    #[test]
    fn backup_and_reset_chain_in_targets_eatp_runs() {
        let t = tmp();
        let eatp_runs = t.path().join("eatp-runs");
        std::fs::create_dir_all(&eatp_runs).unwrap();
        std::fs::write(eatp_runs.join("chain.json"), b"{}").unwrap();
        std::fs::write(eatp_runs.join("abc.jsonl"), b"{}\n").unwrap();
        std::fs::write(eatp_runs.join(".chain-broken"), b"x").unwrap();

        let (backup_dir, failed) =
            backup_and_reset_chain_in(t.path(), "eatp-runs", "20260605T0000").expect("reset");

        assert!(
            failed.is_empty(),
            "no move failures expected, got {failed:?}"
        );
        assert!(
            backup_dir.ends_with("eatp-runs-broken-backup-20260605T0000"),
            "backup dir must be named for the eatp-runs subdir, got {backup_dir:?}"
        );
        assert!(
            backup_dir.join("chain.json").is_file(),
            "chain.json backed up"
        );
        assert!(backup_dir.join("abc.jsonl").is_file(), "ledger backed up");
        assert!(
            backup_dir.join(".chain-broken").is_file(),
            "sentinel backed up"
        );
        // The live eatp-runs ledger + sentinel are gone (reset to a clean slate).
        assert!(!eatp_runs.join("abc.jsonl").exists(), "ledger moved out");
        assert!(
            !eatp_runs.join(".chain-broken").exists(),
            "sentinel moved out"
        );
    }
}
