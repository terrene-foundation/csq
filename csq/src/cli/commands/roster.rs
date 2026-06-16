//! `csq audit roster install <file>` and `csq audit roster show` — M12 authority
//! roster CLI surface.
//!
//! - `csq audit roster install <file>` — load a signed roster from a JSON file,
//!   verify its Ed25519 signature, pin `roster_activation_seq` (current chain tail
//!   seq + 1 to grandfather all pre-existing records), and bump `roster_version_floor`
//!   in `chain.json`. Verification runs BEFORE any write to the live path (CRIT-2).
//! - `csq audit roster show` — print the active roster's principals, op-class
//!   grants, and the configured root pubkey fingerprint.
//!
//! Both commands are gated behind the production `base_dir` (same as the
//! other audit commands). Tests pass a tmp dir directly into the library
//! functions.

use anyhow::{bail, Result};
use csq_core::audit::authority::{
    resolve_registry, roster_path, save_detached_roster, verify_detached_roster,
    verify_signed_roster, OpClass, SignedRoster, UnsignedRosterFile,
};
use csq_core::audit::multi_sig::edition::resolve_edition;
use csq_core::audit::multi_sig::edition::Edition;
use csq_core::audit::persist::acquire_chain_lock;
use csq_core::audit::verify::{verify_chain, VerifyConfig};
use csq_core::audit::ChainState;
use csq_core::daemon::detect::{detect_daemon, DetectResult};
use csq_core::error::redact_tokens;
use std::path::Path;

/// Handle `csq audit roster install <file>`.
///
/// # TOCTOU quiesce guard
///
/// The chain is single-writer by convention: only the running daemon appends
/// GUARDED records (`KeyRotate`, `IdentityMint`, `ReleaseAuth`). This function
/// computes `activation_seq = head_seq + 1`, then writes the roster + chain.json.
/// If the daemon appends a GUARDED record in the window between the tail-seq read
/// and the chain.json write, that record lands at `head_seq + 1 == activation_seq`,
/// gets membership-enforced, but was signed by the operator key (NOT in the new
/// roster) → `MultiSigInvalid` → daemon refuses to start permanently.
///
/// Fix: refuse install while the daemon's PID is alive. With the daemon stopped,
/// no concurrent guarded write can land, and `activation_seq = head_seq + 1`
/// is race-free. `daemon_alive` is closure-injectable so tests can exercise both
/// paths without a real daemon process.
///
/// # Ordering (CRIT-2 fix)
///
/// 1. Refuse if daemon is alive (TOCTOU quiesce guard).
/// 2. Parse the roster file from disk.
/// 3. Verify the parsed roster IN MEMORY (signature + rollback) — BEFORE
///    writing anything to the live path. If verification fails, the existing
///    on-disk roster is untouched.
/// 4. Only after verification passes: save the roster to `<base>/audit/authority-roster.json`.
/// 5. Compute chain tail seq via `verify_chain` → `summary.head_seq`.
/// 6. Pin `roster_activation_seq = tail_seq + 1` (or the caller-supplied override).
///    This grandfathers all pre-existing records — they fall below the activation
///    seq and continue to verify under M11 self-authorization (no brick) (CRIT-1 fix).
/// 7. Bump `roster_version_floor` to `roster.roster_version`.
/// 8. Save `chain.json`.
///
/// Inputs are validated; paths are not echoed in operator output
/// (per `rules/operator-surface-verification.md`).
pub fn handle_roster_install(
    base_dir: &Path,
    file: &Path,
    override_activation_seq: Option<u64>,
) -> Result<()> {
    handle_roster_install_inner(base_dir, file, override_activation_seq, || {
        matches!(
            detect_daemon(base_dir),
            DetectResult::Healthy { .. } | DetectResult::Unhealthy { .. }
        )
    })
}

/// Inner implementation of roster install with an injectable daemon-liveness
/// check. Production wires `detect_daemon`; tests inject `|| false` (no live
/// daemon) or `|| true` (daemon alive, expect refusal).
///
/// **PRIMARY METHODOLOGICAL DIRECTIVE (redteam-discipline Rule 5):** the
/// `daemon_alive` closure is the ONLY mechanism for testing daemon-liveness
/// behavior. Do NOT use real PID-file tricks or chmod tricks in tests.
fn handle_roster_install_inner(
    base_dir: &Path,
    file: &Path,
    override_activation_seq: Option<u64>,
    daemon_alive: impl Fn() -> bool,
) -> Result<()> {
    // Step 1: Refuse if daemon is alive.
    //
    // The daemon is the sole writer of GUARDED records. If it is running while
    // we install the roster and update chain.json::roster_activation_seq, it
    // could append a GUARDED record at seq == activation_seq between the tail-seq
    // read and the chain.json write. That record would be signed by the operator
    // key (NOT enrolled in the new roster), fail membership enforcement on the
    // next verify_chain call, and permanently brick the daemon (permanent
    // MultiSigInvalid on every startup).
    //
    // With the daemon stopped, the chain is single-writer (only this process),
    // and activation_seq = head_seq + 1 is race-free.
    if daemon_alive() {
        // Best-effort: extract the PID for the operator message. The closure
        // already confirmed the daemon is alive (Healthy or Unhealthy); a
        // second detect call may race but is informational only. Disclosing
        // the PID is intentional (operator-surface Rule 3): any same-user
        // process can `ps` it, and the operator needs it to stop the daemon.
        let pid_hint = if let DetectResult::Healthy { pid, .. } = detect_daemon(base_dir) {
            format!(" (pid {pid})")
        } else {
            String::new()
        };
        bail!(
            "the csq daemon is running{pid_hint} — stop it with \
`csq daemon stop` before installing a roster, then `csq daemon start` afterward. \
Installing a roster while the daemon may append records can permanently brick \
the audit chain (a record written under the old trust model would fail the new \
membership check)."
        );
    }
    // Step 2: Read the roster JSON file as raw bytes (needed for detached-sig verification).
    let raw_bytes = std::fs::read(file).map_err(|e| {
        anyhow::anyhow!(
            "roster file could not be read: {}",
            redact_tokens(&e.to_string())
        )
    })?;
    let raw = std::str::from_utf8(&raw_bytes)
        .map_err(|_| anyhow::anyhow!("roster file is not valid UTF-8"))?;

    // Step 3: Detect form — embedded (SignedRoster) or detached (UnsignedRosterFile + .sig).
    //
    // Resolution order (mirrors RosterFileRegistry::load):
    //   (a) Parses as SignedRoster → embedded form; sidecar ignored.
    //   (b) Parses as UnsignedRosterFile + a sibling .sig file exists → detached form.
    //   (c) Neither → reject.
    enum RosterForm {
        Embedded(SignedRoster),
        Detached {
            unsigned: UnsignedRosterFile,
            raw_bytes: Vec<u8>,
            sidecar_hex: String,
        },
    }

    let form: RosterForm = if let Ok(signed) = serde_json::from_str::<SignedRoster>(raw) {
        RosterForm::Embedded(signed)
    } else if let Ok(unsigned) = serde_json::from_str::<UnsignedRosterFile>(raw) {
        // Look for the sidecar at <file>.sig (adjacent to the supplied roster file).
        // NOTE (PR #703 review LOW-2): this derives the SOURCE sidecar from the
        // operator-supplied path by extension-append; the canonical LIVE sidecar
        // is `roster_sig_path(base)`. The two schemes are intentionally distinct
        // (source convention vs canonical destination) — if the canonical roster
        // filename ever changes, this derivation does not need to follow it.
        let sidecar_path = {
            let mut p = file.to_path_buf();
            let ext = p
                .extension()
                .map(|e| {
                    let mut s = e.to_os_string();
                    s.push(".sig");
                    s
                })
                .unwrap_or_else(|| std::ffi::OsString::from("sig"));
            p.set_extension(ext);
            p
        };
        if !sidecar_path.exists() {
            bail!(
                "roster file is in unsigned (detached-signature) form but no sidecar \
                 file was found at {}. Provide the sidecar or use the embedded form.",
                sidecar_path.display()
            );
        }
        let sidecar_hex = std::fs::read_to_string(&sidecar_path).map_err(|e| {
            anyhow::anyhow!(
                "could not read roster sidecar: {}",
                redact_tokens(&e.to_string())
            )
        })?;
        RosterForm::Detached {
            unsigned,
            raw_bytes: raw_bytes.clone(),
            sidecar_hex,
        }
    } else {
        bail!("roster file is not valid JSON or has unknown fields");
    };

    // Ensure csq-runs/ exists before acquiring the chain lock (the lock sidecar
    // lives at csq-runs/.chain-lock).  The dir is also needed by chain.save()
    // below.  Using 0o700 on Unix mirrors write_record_v2_impl's behaviour.
    let csq_runs = base_dir.join("csq-runs");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&csq_runs)
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to create csq-runs/: {}",
                    redact_tokens(&e.to_string())
                )
            })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&csq_runs).map_err(|e| {
            anyhow::anyhow!(
                "failed to create csq-runs/: {}",
                redact_tokens(&e.to_string())
            )
        })?;
    }

    // Acquire the chain-wide `.chain-lock` BEFORE chain.json is read AND
    // before any write (roster file or chain.json), so the whole
    // read-modify-write (load chain -> compute activation seq -> write roster
    // -> save chain.json) is serialized against every other chain writer.
    // This closes the TOCTOU window identified in issue #694:
    // a daemon GUARDED append at seq == activation_seq interleaved between the
    // roster-file write and chain.json save yields a record signed by a non-
    // roster key → permanent MultiSigInvalid on the next verify_chain.
    //
    // The daemon-quiesce refusal above (Step 1) is defence-in-depth; this lock
    // is the structural fix that closes the remaining window even when two CLI
    // processes race (e.g. two concurrent `csq audit roster-install` invocations).
    //
    // Fail-closed: ChainLockTimeout aborts the install BEFORE any write; both
    // the roster file and chain.json remain in their pre-install state.
    let _chain_lock = acquire_chain_lock(&csq_runs).map_err(|e| {
        anyhow::anyhow!(
            "failed to acquire chain lock: {}",
            redact_tokens(&e.to_string())
        )
    })?;

    // Step 4: Load chain state now (needed for version floor + tail seq).
    let mut chain = ChainState::load(base_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to load chain.json: {}",
            redact_tokens(&e.to_string())
        )
    })?;

    let version_floor = chain.roster_version_floor.unwrap_or(0);

    // Step 5: Verify IN MEMORY — BEFORE writing anything to the live path.
    // (CRIT-2 fix: the old code saved to the live path first, then verified.
    // A bad/corrupt/wrong-sig roster would clobber the existing good roster
    // and leave the daemon unable to start. Invariant: install returns Err ⇒
    // on-disk state unchanged.)
    let roster_version = match &form {
        RosterForm::Embedded(signed) => {
            verify_signed_roster(base_dir, signed, version_floor)
                .map_err(|e| anyhow::anyhow!("roster verification failed: {e}"))?;
            signed.roster.roster_version
        }
        RosterForm::Detached {
            unsigned,
            raw_bytes: rb,
            sidecar_hex,
        } => {
            verify_detached_roster(base_dir, unsigned, rb, sidecar_hex, version_floor)
                .map_err(|e| anyhow::anyhow!("roster verification failed: {e}"))?;
            unsigned.roster.roster_version
        }
    };

    // Step 5b: Rollback defense (double-check the version floor, redundant
    // with the verify_* call above but explicit for clarity).
    let current_floor = chain.roster_version_floor.unwrap_or(0);
    if roster_version < current_floor {
        bail!(
            "roster version {} is below the installed floor {} — rollback rejected",
            roster_version,
            current_floor
        );
    }

    // Step 6: Compute the chain tail seq for activation_seq pinning (CRIT-1 fix).
    //
    // `activation_seq = tail_seq + 1` grandfathers all pre-existing records:
    // they are at seq <= tail_seq, which is strictly < activation_seq, so they
    // continue to verify on M11 self-authorization (no brick).
    //
    // For an empty chain (no records yet, head_seq == 0 with verified_count == 0),
    // use 0 — there are no pre-existing records to grandfather.
    let computed_activation_seq: u64 = if let Some(override_seq) = override_activation_seq {
        override_seq
    } else {
        let cfg = VerifyConfig::default();
        match verify_chain(base_dir, &cfg, None) {
            Ok(summary) if summary.verified_count > 0 => {
                // head_seq is the highest verified seq; activation starts at the NEXT seq.
                summary.head_seq + 1
            }
            Ok(_) => {
                // Empty chain (no v2 records yet): no existing records to grandfather.
                0
            }
            Err(e) => {
                bail!(
                    "failed to read chain tail seq for activation_seq computation: {}",
                    redact_tokens(&e.to_string())
                );
            }
        }
    };

    // Create the audit dir before writing the roster.
    let roster_p = roster_path(base_dir);
    if let Some(parent) = roster_p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create audit directory: {}",
                redact_tokens(&e.to_string())
            )
        })?;
    }

    // Step 7: Save the verified roster to the live path (§5a write path).
    // Both writes happen inside the chain lock (acquired above) — the critical
    // section covers both the roster save and the chain.json update (step 8).
    match &form {
        RosterForm::Embedded(signed) => {
            csq_core::audit::authority::save_roster(base_dir, signed).map_err(|e| {
                anyhow::anyhow!("failed to save roster: {}", redact_tokens(&e.to_string()))
            })?;
        }
        RosterForm::Detached {
            raw_bytes: rb,
            sidecar_hex,
            ..
        } => {
            save_detached_roster(base_dir, rb, sidecar_hex).map_err(|e| {
                anyhow::anyhow!(
                    "failed to save detached roster: {}",
                    redact_tokens(&e.to_string())
                )
            })?;
        }
    }

    // Step 8: Pin activation and floor in chain.json.
    // Only update activation_seq if not already set — preserving an existing
    // activation avoids silently lowering enforcement by a re-install.
    if chain.roster_activation_seq.is_none() {
        chain.roster_activation_seq = Some(computed_activation_seq);
    }
    chain.roster_version_floor = Some(roster_version);

    let activation_in_use = chain
        .roster_activation_seq
        .unwrap_or(computed_activation_seq);
    let existing_record_count = if activation_in_use > 0 {
        activation_in_use // records at seq 0..activation_in_use-1 are grandfathered
    } else {
        0
    };

    // Save chain.json.
    chain.save(base_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to save chain.json: {}",
            redact_tokens(&e.to_string())
        )
    })?;

    // Extract principal count for operator output (independent of form).
    let num_principals = match &form {
        RosterForm::Embedded(signed) => signed.roster.entries.len(),
        RosterForm::Detached { unsigned, .. } => unsigned.roster.entries.len(),
    };

    // Best-effort: anchor the new roster_version_floor in the keychain while
    // the chain lock is held.  Non-fatal — any keychain access error is logged
    // and skipped; chain.json is the durable floor; the keychain entry is the
    // tamper-DETECTION layer cross-checked by `verify_chain`.
    csq_core::audit::write_roster_floor_to_keychain(
        base_dir,
        csq_core::audit::AUDIT_SIGNING_SERVICE_NAME,
        &chain.chain_id,
        roster_version,
    );

    eprintln!(
        "audit roster: roster v{} installed — {} principals",
        roster_version, num_principals,
    );
    eprintln!("audit roster: version floor set to {}", roster_version);
    eprintln!(
        "audit roster: activation_seq = {} — membership enforced from seq {} onward",
        activation_in_use, activation_in_use
    );
    if existing_record_count > 0 {
        eprintln!(
            "audit roster: {} existing record(s) are grandfathered (seq < {}); \
             they continue to verify under M11 self-authorization",
            existing_record_count, activation_in_use
        );
    } else {
        eprintln!("audit roster: no pre-existing records to grandfather (fresh chain or activation_seq=0)");
    }
    Ok(())
}

/// Handle `csq audit roster show`.
///
/// Prints the active roster's principals, op-class grants, root pubkey
/// fingerprint, and the root pubkey resolution source (env var vs file).
/// Validates that the roster is loadable (enterprise edition).
///
/// No paths are echoed in operator output.
pub fn handle_roster_show(base_dir: &Path) -> Result<()> {
    let edition = resolve_edition();
    if edition == Edition::Community {
        eprintln!("audit roster: community edition — no roster configured");
        eprintln!("  activation_seq: none (M11 self-authorization for all records)");
        eprintln!("  Set CSQ_AUDIT_EDITION=enterprise to enable roster membership.");
        return Ok(());
    }

    // Enterprise: try to load the registry.
    let chain = ChainState::load(base_dir)
        .map_err(|e| anyhow::anyhow!("failed to load chain.json: {e}"))?;

    let registry = resolve_registry(base_dir, &chain)
        .map_err(|e| anyhow::anyhow!("roster load failed: {e}"))?;

    match registry {
        None => {
            eprintln!("audit roster: no roster active (community / pre-activation)");
        }
        Some(reg) => {
            // Print activation and op-class grants from the VERIFIED registry.
            let activation = reg.activation_seq();
            eprintln!("audit roster: roster active, activation_seq = {activation:?}");
            eprintln!("  op-class grants:");
            for op_class in [
                OpClass::KeyRotate,
                OpClass::IdentityMint,
                OpClass::ReleaseAuth,
            ] {
                match reg.resolve(op_class) {
                    Some(grant) => {
                        // Dedup key count across all principals for display (LOW).
                        let unique_keys: std::collections::BTreeSet<[u8; 32]> =
                            grant.keys.iter().map(|k| k.pubkey.0).collect();
                        eprintln!("    {:?}: {} enrolled key(s)", op_class, unique_keys.len());
                    }
                    None => {
                        eprintln!("    {:?}: no enrolled keys", op_class);
                    }
                }
            }

            // Print root pubkey fingerprint and source from the VERIFIED registry's
            // underlying roster (read via chain state that was already loaded).
            // Resolution source: env var takes precedence over on-disk file.
            let root_pk_source = if std::env::var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY").is_ok() {
                "CSQ_AUDIT_ROSTER_ROOT_PUBKEY env var"
            } else {
                "roster-root.pub file"
            };

            // Read roster_version from the verified on-disk roster (already loaded
            // by resolve_registry). Re-read is from the same verified path.
            let rp = roster_path(base_dir);
            if rp.exists() {
                if let Ok(raw) = std::fs::read_to_string(&rp) {
                    if let Ok(sr) = serde_json::from_str::<SignedRoster>(&raw) {
                        // Print first 16 hex chars (8 bytes) as fingerprint.
                        let fingerprint: String = sr
                            .roster_pubkey
                            .0
                            .iter()
                            .take(8)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        eprintln!("  root pubkey fingerprint: {fingerprint}... (source: {root_pk_source})");

                        // Warn if env var and on-disk pubkey differ.
                        if let Ok(env_hex) = std::env::var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY") {
                            let env_bytes = hex::decode(env_hex.trim()).unwrap_or_default();
                            if env_bytes.len() == 32
                                && env_bytes.as_slice() != sr.roster_pubkey.0.as_slice()
                            {
                                eprintln!(
                                    "  WARNING: CSQ_AUDIT_ROSTER_ROOT_PUBKEY differs from \
                                     the roster_pubkey field in the on-disk roster — \
                                     the env var takes precedence"
                                );
                            }
                        }

                        eprintln!("  roster_version: {}", sr.roster.roster_version);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::audit::authority::{save_roster, EnrolledKey, Roster, RosterEntry, SignedRoster};
    use csq_core::audit::types::{Ed25519PublicKey, Ed25519Signature};
    use csq_core::audit::ChainState;
    use ed25519_dalek::SigningKey as DalekSigningKey;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn gen_keypair() -> (DalekSigningKey, Ed25519PublicKey) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom");
        let sk = DalekSigningKey::from_bytes(&seed);
        let pk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn sign_roster_for_test(
        sk: &DalekSigningKey,
        roster: &Roster,
        root_pk: Ed25519PublicKey,
    ) -> SignedRoster {
        use ed25519_dalek::Signer;
        let bytes = serde_json::to_vec(roster).expect("serialize");
        let sig = sk.sign(&bytes);
        SignedRoster {
            roster: roster.clone(),
            roster_pubkey: root_pk,
            signature: Ed25519Signature::new(sig.to_bytes()),
        }
    }

    fn minimal_signed_roster(
        sk: &DalekSigningKey,
        pk: Ed25519PublicKey,
        version: u64,
    ) -> SignedRoster {
        let roster = Roster {
            format_version: 1,
            roster_version: version,
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries: BTreeMap::new(),
        };
        sign_roster_for_test(sk, &roster, pk)
    }

    fn setup_env_root_pk(pk: Ed25519PublicKey) {
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", hex::encode(pk.0));
    }

    #[test]
    fn roster_show_community_edition_reports_no_roster() {
        let _g = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");

        let tmp = tmp();
        let result = handle_roster_show(tmp.path());
        assert!(result.is_ok(), "community show must not error: {result:?}");
    }

    #[test]
    fn roster_show_enterprise_missing_roster_fails() {
        let _g = csq_core::platform::test_env::lock();
        std::env::set_var("CSQ_AUDIT_EDITION", "enterprise");
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", "aa".repeat(32));

        let tmp = tmp();
        let result = handle_roster_show(tmp.path());
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            result.is_err(),
            "enterprise show with missing roster must fail"
        );
    }

    /// CRIT-1 (grandfather test): A roster installed on a chain that already has
    /// existing records MUST set `roster_activation_seq = head_seq + 1`, which
    /// grandfathers all pre-existing records. After install, `verify_chain` must
    /// return Ok even though those existing records are placeholder-key signed
    /// (community edition, no signing cutoff set).
    ///
    /// This is the load-bearing regression test for the activation_seq=0 brick.
    #[test]
    fn roster_install_grandfathers_existing_records() {
        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        // Set up community edition for initial chain build.
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Write a placeholder-key record (community, no signing cutoff).
        // write_record_v2 creates chain.json if absent.
        {
            use csq_core::audit::persist::write_record_v2;
            use csq_core::audit::types::{
                CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId,
                Sha256Hex, SignedRecord,
            };
            let r = SignedRecord {
                schema_version: "2".to_string(),
                record_id: RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FGS").unwrap(),
                chain_id: RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FGR").unwrap(),
                seq: 0,
                prev_hash: Sha256Hex::genesis(),
                kind: EventKind::CsqRun,
                payload: EventPayload::CsqRun(CsqRunPayload {
                    run_id: "grandfather-test".to_string(),
                }),
                ts: "2026-06-02T12:00:00+00:00".to_string(),
                key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
                canonical_hash: Sha256Hex::genesis(),
                signature: Ed25519Signature::new([0u8; 64]),
                actor: None,
                authority: None,
                trust: None,
                eatp_start_ts: None,
                eatp_end_ts: None,
                op_phase: None,
            };
            write_record_v2(r, Some(base)).expect("write_record_v2");
        }

        // Verify community chain is clean BEFORE roster install.
        let pre_cfg = csq_core::audit::verify::VerifyConfig::default();
        let pre_verify = csq_core::audit::verify::verify_chain(base, &pre_cfg, None);
        assert!(
            pre_verify.is_ok(),
            "pre-install community verify must pass: {pre_verify:?}"
        );

        // Build a roster that does NOT contain the operator key.
        let (root_sk, root_pk) = gen_keypair();
        let signed = minimal_signed_roster(&root_sk, root_pk, 1);

        // Write the signed roster to a temp file (not the live path).
        let roster_file = dir.path().join("test-roster.json");
        std::fs::write(&roster_file, serde_json::to_string_pretty(&signed).unwrap()).unwrap();

        setup_env_root_pk(root_pk);

        // Install the roster (community edition for install — roster install
        // does not require enterprise edition to be set during install itself).
        let install_result = handle_roster_install(base, &roster_file, None);

        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            install_result.is_ok(),
            "roster install must succeed: {install_result:?}"
        );

        // Load chain.json and assert activation_seq = 1 (head_seq=0, so 0+1=1).
        let chain = ChainState::load(base).expect("load chain");
        let activation = chain.roster_activation_seq.expect("activation must be set");
        assert_eq!(
            activation, 1,
            "activation_seq must be head_seq+1=1 to grandfather the seq=0 record; got {activation}"
        );

        // Verify with community edition — existing record at seq=0 is grandfathered
        // (seq=0 < activation_seq=1). Must pass.
        std::env::remove_var("CSQ_AUDIT_EDITION");
        let verify_result = csq_core::audit::verify::verify_chain(base, &pre_cfg, None);
        assert!(
            verify_result.is_ok(),
            "verify_chain must succeed after roster install (existing records grandfathered): {verify_result:?}"
        );
    }

    /// CRIT-1 (brick-proof / enforcement test): A record at seq >= activation_seq
    /// signed by a NON-enrolled key → `verify_record_multi_sig` returns
    /// VerificationUnderThreshold (proves enforcement fires post-activation).
    #[test]
    fn roster_install_enforcement_fires_post_activation() {
        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        // Build a roster with one member (alice's key).
        let (root_sk, root_pk) = gen_keypair();
        let (_, member_pk) = gen_keypair();
        let mut entries = BTreeMap::new();
        entries.insert(
            "alice@example.com".to_string(),
            RosterEntry {
                keys: vec![EnrolledKey {
                    pubkey: member_pk,
                    active_from_seq: 0,
                    retired_at_seq: None,
                }],
                op_classes: vec![csq_core::audit::authority::OpClass::KeyRotate],
            },
        );
        let roster = Roster {
            format_version: 1,
            roster_version: 1,
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries,
        };
        let signed = sign_roster_for_test(&root_sk, &roster, root_pk);
        save_roster(base, &signed).expect("save roster");

        setup_env_root_pk(root_pk);

        // Build an enterprise registry with activation_seq=5 for direct verification.
        use csq_core::audit::authority::{AuthorityRegistry, RosterFileRegistry};
        let reg = RosterFileRegistry::load(base, 0).expect("load");

        // Build an authorization blob with a NON-enrolled key at seq >= 5.
        let (non_member_sk, non_member_pk) = gen_keypair();
        let payload = csq_core::audit::types::EventPayload::KeyRotate(
            csq_core::audit::types::KeyRotatePayload {
                previous_key_id: csq_core::audit::types::KeyId::try_new(format!(
                    "ed25519:{}",
                    "a".repeat(64)
                ))
                .unwrap(),
                new_key_id: csq_core::audit::types::KeyId::try_new(format!(
                    "ed25519:{}",
                    "b".repeat(64)
                ))
                .unwrap(),
                incoming_pubkey: Ed25519PublicKey([1u8; 32]),
                rotation_reason: csq_core::audit::types::RotationReason::Operator,
            },
        );
        let hash = csq_core::audit::intent_hash(
            "01ARZ3NDEKTSV4RRFFQ69G5FA0",
            &csq_core::audit::types::EventKind::KeyRotate,
            &payload,
        );
        use ed25519_dalek::Signer;
        let sig = non_member_sk.sign(&hash);

        let authority = csq_core::audit::types::EatpAuthority(serde_json::json!({
            "multi_sig": {
                "threshold": 1u64,
                "roster_size": 1u64,
                "authorizations": [{
                    "signer_pubkey": hex::encode(non_member_pk.0),
                    "signature": hex::encode(sig.to_bytes()),
                }]
            }
        }));

        let record = csq_core::audit::types::SignedRecord {
            schema_version: "2".to_string(),
            record_id: csq_core::audit::types::RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FAV")
                .unwrap(),
            chain_id: csq_core::audit::types::RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FA0")
                .unwrap(),
            seq: 10, // >= activation_seq 5
            prev_hash: csq_core::audit::types::Sha256Hex::genesis(),
            kind: csq_core::audit::types::EventKind::KeyRotate,
            payload,
            ts: "2026-06-02T12:00:00+00:00".to_string(),
            key_id: csq_core::audit::types::KeyId::try_new(format!("ed25519:{}", "0".repeat(64)))
                .unwrap(),
            canonical_hash: csq_core::audit::types::Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: Some(authority),
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
        };

        // Wrap with activation_seq=5 to test enforcement.
        struct WithActivation5 {
            inner: RosterFileRegistry,
        }
        impl AuthorityRegistry for WithActivation5 {
            fn resolve(
                &self,
                op_class: csq_core::audit::authority::OpClass,
            ) -> Option<csq_core::audit::authority::AuthorityGrant> {
                self.inner.resolve(op_class)
            }
            fn is_enrolled(
                &self,
                pubkey: &Ed25519PublicKey,
                op_class: csq_core::audit::authority::OpClass,
                seq: u64,
            ) -> bool {
                self.inner.is_enrolled(pubkey, op_class, seq)
            }
            fn activation_seq(&self) -> Option<u64> {
                Some(5)
            }
        }
        let activated = WithActivation5 { inner: reg };

        let result =
            csq_core::audit::multi_sig::verify::verify_record_multi_sig(&record, Some(&activated));

        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            result.is_err(),
            "non-enrolled signer at seq >= activation_seq must be rejected"
        );
        match result.unwrap_err() {
            csq_core::audit::multi_sig::error::MultiSigError::VerificationUnderThreshold {
                valid,
                ..
            } => {
                assert_eq!(valid, 0, "non-member contributes 0 valid votes");
            }
            other => panic!("expected VerificationUnderThreshold, got {other:?}"),
        }
    }

    /// CRIT-2: Installing a bad-signature roster over an existing valid one
    /// MUST return Err AND leave the prior valid roster still on disk and loadable.
    /// Invariant: install returns Err ⇒ on-disk state unchanged.
    #[test]
    fn roster_install_bad_sig_leaves_prior_roster_intact() {
        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        // Install a valid roster first.
        let (root_sk, root_pk) = gen_keypair();
        let valid_signed = minimal_signed_roster(&root_sk, root_pk, 1);
        save_roster(base, &valid_signed).expect("save valid roster");

        setup_env_root_pk(root_pk);

        // Initialize chain.json so install can read it.
        ChainState::new("test-chain-crit2")
            .save(base)
            .expect("save chain");

        // Build a bad-signature roster (different signing key, same root pubkey).
        let (bad_sk, _) = gen_keypair();
        let bad_roster = Roster {
            format_version: 1,
            roster_version: 2, // newer version — would be an upgrade if valid
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries: BTreeMap::new(),
        };
        // Sign with bad_sk but embed root_pk — sig will not verify.
        let bad_signed = sign_roster_for_test(&bad_sk, &bad_roster, root_pk);

        let bad_roster_file = dir.path().join("bad-roster.json");
        std::fs::write(
            &bad_roster_file,
            serde_json::to_string_pretty(&bad_signed).unwrap(),
        )
        .unwrap();

        // Attempt to install the bad roster.
        let result = handle_roster_install(base, &bad_roster_file, None);
        assert!(
            result.is_err(),
            "install of bad-sig roster must fail: {result:?}"
        );

        // The prior valid roster must still be on disk and loadable.
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        setup_env_root_pk(root_pk);
        let load_result = csq_core::audit::authority::RosterFileRegistry::load(base, 0);
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        assert!(
            load_result.is_ok(),
            "prior valid roster must still load after failed install: {load_result:?}"
        );
        let loaded_reg = load_result.unwrap();
        // Verify the roster version is still 1 (not the bad roster's version 2).
        assert_eq!(
            loaded_reg.roster().roster_version,
            1,
            "on-disk roster must still be the original v1 after failed install"
        );
    }

    /// AC-3 (was missing): 2-of-3 enrolled threshold test.
    /// Three enrolled keys, sign with 2 → verify passes; sign with 1 → VerificationUnderThreshold.
    /// Exercises the N>1 threshold × dedup × membership composition.
    #[test]
    fn roster_ac3_two_of_three_enrolled_threshold() {
        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        // Three enrolled member keypairs.
        let (_, pk1) = gen_keypair();
        let (_, pk2) = gen_keypair();
        let (_, pk3) = gen_keypair();
        // The actual signing keys need to be LocalSigningKey-compatible for
        // authorize_op. For this test we build the authority blob manually
        // to test verify_record_multi_sig directly.

        let (root_sk, root_pk) = gen_keypair();
        let mut entries = BTreeMap::new();
        entries.insert(
            "alice@example.com".to_string(),
            RosterEntry {
                keys: vec![EnrolledKey {
                    pubkey: pk1,
                    active_from_seq: 0,
                    retired_at_seq: None,
                }],
                op_classes: vec![csq_core::audit::authority::OpClass::ReleaseAuth],
            },
        );
        entries.insert(
            "bob@example.com".to_string(),
            RosterEntry {
                keys: vec![EnrolledKey {
                    pubkey: pk2,
                    active_from_seq: 0,
                    retired_at_seq: None,
                }],
                op_classes: vec![csq_core::audit::authority::OpClass::ReleaseAuth],
            },
        );
        entries.insert(
            "carol@example.com".to_string(),
            RosterEntry {
                keys: vec![EnrolledKey {
                    pubkey: pk3,
                    active_from_seq: 0,
                    retired_at_seq: None,
                }],
                op_classes: vec![csq_core::audit::authority::OpClass::ReleaseAuth],
            },
        );
        let roster = Roster {
            format_version: 1,
            roster_version: 1,
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries,
        };
        let signed = sign_roster_for_test(&root_sk, &roster, root_pk);
        save_roster(base, &signed).expect("save roster");

        // Drop the first roster (was built with random pk1/pk2/pk3 we can't sign with).
        // We'll build a new roster with deterministic known-seed keys below.
        drop((root_sk, root_pk, pk1, pk2, pk3));

        let chain_id = "01ARZ3NDEKTSV4RRFFQ69G5FA3";

        // We need signing keys for pk1, pk2, pk3. Use fresh known-seed pairs.
        // For testing, use deterministic seeds via getrandom+capture.
        // We can't recover the private keys from pk1/pk2/pk3 above (gen_keypair
        // uses getrandom); use fresh known-seed pairs instead.
        let sk1 = DalekSigningKey::from_bytes(&[0x11u8; 32]);
        let member_pk1 = Ed25519PublicKey(sk1.verifying_key().to_bytes());
        let sk2 = DalekSigningKey::from_bytes(&[0x22u8; 32]);
        let member_pk2 = Ed25519PublicKey(sk2.verifying_key().to_bytes());
        let sk3 = DalekSigningKey::from_bytes(&[0x33u8; 32]);
        let member_pk3 = Ed25519PublicKey(sk3.verifying_key().to_bytes());

        // Build a new roster with these known-pk members.
        let (root_sk2, root_pk2) = gen_keypair();
        let mut entries2 = BTreeMap::new();
        for (name, pk) in [
            ("alice@example.com", member_pk1),
            ("bob@example.com", member_pk2),
            ("carol@example.com", member_pk3),
        ] {
            entries2.insert(
                name.to_string(),
                RosterEntry {
                    keys: vec![EnrolledKey {
                        pubkey: pk,
                        active_from_seq: 0,
                        retired_at_seq: None,
                    }],
                    op_classes: vec![csq_core::audit::authority::OpClass::ReleaseAuth],
                },
            );
        }
        let roster2 = Roster {
            format_version: 1,
            roster_version: 2,
            generated_at: "2026-06-02T00:00:00+00:00".to_string(),
            entries: entries2,
        };
        let signed2 = sign_roster_for_test(&root_sk2, &roster2, root_pk2);
        save_roster(base, &signed2).expect("save roster2");

        setup_env_root_pk(root_pk2);
        let reg2 = csq_core::audit::authority::RosterFileRegistry::load(base, 0).expect("load2");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        struct WithThreshold2 {
            inner: csq_core::audit::authority::RosterFileRegistry,
        }
        impl csq_core::audit::authority::AuthorityRegistry for WithThreshold2 {
            fn resolve(
                &self,
                op_class: csq_core::audit::authority::OpClass,
            ) -> Option<csq_core::audit::authority::AuthorityGrant> {
                self.inner.resolve(op_class)
            }
            fn is_enrolled(
                &self,
                pubkey: &Ed25519PublicKey,
                op_class: csq_core::audit::authority::OpClass,
                seq: u64,
            ) -> bool {
                self.inner.is_enrolled(pubkey, op_class, seq)
            }
            fn activation_seq(&self) -> Option<u64> {
                Some(0)
            }
        }
        let activated = WithThreshold2 { inner: reg2 };

        // Build record with 2-of-3 enrolled signers (threshold=2).
        let payload2 = csq_core::audit::types::EventPayload::ReleaseAuth(
            csq_core::audit::types::ReleaseAuthPayload {
                release_tag: "v3.0.0".to_string(),
                artifact_sha256: csq_core::audit::types::Sha256Hex::try_new("a".repeat(64))
                    .unwrap(),
            },
        );
        let hash2 = csq_core::audit::intent_hash(
            chain_id,
            &csq_core::audit::types::EventKind::ReleaseAuth,
            &payload2,
        );
        use ed25519_dalek::Signer;
        let sig1 = sk1.sign(&hash2);
        let sig2 = sk2.sign(&hash2);

        let authority_2of3 = csq_core::audit::types::EatpAuthority(serde_json::json!({
            "multi_sig": {
                "threshold": 2u64,
                "roster_size": 3u64,
                "authorizations": [
                    {"signer_pubkey": hex::encode(member_pk1.0), "signature": hex::encode(sig1.to_bytes())},
                    {"signer_pubkey": hex::encode(member_pk2.0), "signature": hex::encode(sig2.to_bytes())},
                ]
            }
        }));

        let record_2of3 = csq_core::audit::types::SignedRecord {
            schema_version: "2".to_string(),
            record_id: csq_core::audit::types::RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FA2")
                .unwrap(),
            chain_id: csq_core::audit::types::RecordId::try_new(chain_id).unwrap(),
            seq: 5,
            prev_hash: csq_core::audit::types::Sha256Hex::genesis(),
            kind: csq_core::audit::types::EventKind::ReleaseAuth,
            payload: payload2.clone(),
            ts: "2026-06-02T12:00:00+00:00".to_string(),
            key_id: csq_core::audit::types::KeyId::try_new(format!("ed25519:{}", "0".repeat(64)))
                .unwrap(),
            canonical_hash: csq_core::audit::types::Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: Some(authority_2of3),
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
        };

        // 2 enrolled signers, threshold=2 → PASS.
        let result_pass = csq_core::audit::multi_sig::verify::verify_record_multi_sig(
            &record_2of3,
            Some(&activated),
        );
        assert!(
            result_pass.is_ok(),
            "2-of-3 enrolled must pass: {result_pass:?}"
        );

        // Build record with only 1 enrolled signer (threshold=2) → FAIL.
        let authority_1of3 = csq_core::audit::types::EatpAuthority(serde_json::json!({
            "multi_sig": {
                "threshold": 2u64,
                "roster_size": 3u64,
                "authorizations": [
                    {"signer_pubkey": hex::encode(member_pk1.0), "signature": hex::encode(sig1.to_bytes())},
                ]
            }
        }));
        let record_1of3 = csq_core::audit::types::SignedRecord {
            authority: Some(authority_1of3),
            ..record_2of3.clone()
        };
        let result_fail = csq_core::audit::multi_sig::verify::verify_record_multi_sig(
            &record_1of3,
            Some(&activated),
        );
        assert!(
            result_fail.is_err(),
            "1-of-3 enrolled with threshold=2 must fail: {result_fail:?}"
        );
        match result_fail.unwrap_err() {
            csq_core::audit::multi_sig::error::MultiSigError::VerificationUnderThreshold {
                threshold,
                valid,
            } => {
                assert_eq!(threshold, 2);
                assert_eq!(valid, 1);
            }
            other => panic!("expected VerificationUnderThreshold, got {other:?}"),
        }
    }

    /// TOCTOU guard (a): injected daemon_alive=true → install returns Err
    /// mentioning the daemon, AND the on-disk roster + chain.json are UNCHANGED.
    ///
    /// Verifies that no partial write happens when the daemon is alive.
    #[test]
    fn roster_install_refuses_when_daemon_alive() {
        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        // Build a valid signed roster.
        let (root_sk, root_pk) = gen_keypair();
        let signed = minimal_signed_roster(&root_sk, root_pk, 1);

        let roster_file = dir.path().join("test-roster.json");
        std::fs::write(&roster_file, serde_json::to_string_pretty(&signed).unwrap()).unwrap();

        setup_env_root_pk(root_pk);

        // Confirm no roster or chain.json exists before the attempt.
        let roster_path = csq_core::audit::authority::roster_path(base);
        assert!(!roster_path.exists(), "pre: roster must not exist");

        // Inject daemon_alive=true — daemon is running.
        let result = handle_roster_install_inner(base, &roster_file, None, || true);

        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Must fail with an operator-actionable message.
        assert!(
            result.is_err(),
            "install must fail when daemon is alive: {result:?}"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("daemon stop"),
            "error must mention `csq daemon stop`: {err_msg}"
        );
        assert!(
            err_msg.contains("daemon start"),
            "error must mention `csq daemon start`: {err_msg}"
        );

        // On-disk roster MUST be unchanged (no partial write).
        assert!(
            !roster_path.exists(),
            "roster must NOT be written when daemon is alive: roster file appeared on disk"
        );

        // chain.json MUST be unchanged (absent, since we never initialized it).
        // Authoritative path: chain_state.rs::chain_json_path = base/csq-runs/chain.json.
        let chain_path = base.join("csq-runs").join("chain.json");
        assert!(
            !chain_path.exists(),
            "chain.json must NOT be written when daemon is alive"
        );
    }

    /// TOCTOU guard (b): injected daemon_alive=false → install proceeds normally
    /// (grandfathers existing records, verifies chain). This test routes through
    /// `handle_roster_install_inner` to confirm the not-alive path is exercised.
    #[test]
    fn roster_install_proceeds_when_daemon_not_alive() {
        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Build a valid signed roster.
        let (root_sk, root_pk) = gen_keypair();
        let signed = minimal_signed_roster(&root_sk, root_pk, 1);

        let roster_file = dir.path().join("test-roster.json");
        std::fs::write(&roster_file, serde_json::to_string_pretty(&signed).unwrap()).unwrap();

        setup_env_root_pk(root_pk);

        // Inject daemon_alive=false — no live daemon.
        let result = handle_roster_install_inner(base, &roster_file, None, || false);

        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Must succeed.
        assert!(
            result.is_ok(),
            "install must succeed when daemon is not alive: {result:?}"
        );

        // Roster must be on disk.
        let roster_path = csq_core::audit::authority::roster_path(base);
        assert!(
            roster_path.exists(),
            "roster must be written when daemon is not alive"
        );
    }

    /// Chain-lock contention test (issue #694 regression gate).
    ///
    /// A REAL `.chain-lock` file is held by a background thread past the
    /// 5-second deadline.  `handle_roster_install_inner` MUST:
    ///   1. Return `Err` describing the timeout (not hang indefinitely).
    ///   2. Leave the on-disk roster file UNCHANGED (absent).
    ///   3. Leave `chain.json` UNCHANGED (absent).
    ///
    /// **PRIMARY METHODOLOGICAL DIRECTIVE (TDD spec):** the lock is held using
    /// the same `crate::platform::lock::lock_file` primitive that
    /// `acquire_chain_lock` uses internally — no time mocks, no lock stubs.
    /// The test mirrors the shape of `chain_lock_timeout_fails_closed` in
    /// `persist.rs` but targets the roster-install path.
    ///
    /// Unix-only: the Unix lock is `flock` (per-fd; cross-thread contention in
    /// one process reproduces real contention), while the Windows impl is a
    /// named mutex whose same-process semantics do not reliably contend —
    /// per testing.md's platform-gating rationale. Do NOT remove the gate.
    #[cfg(unix)]
    #[test]
    fn roster_install_chain_lock_timeout_aborts_before_any_write() {
        use csq_core::platform::lock::lock_file;
        use std::time::Duration;

        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        // Arrange — build a valid signed roster (needed so install would succeed
        // under no-contention; if it fails for another reason the test is wrong).
        let (root_sk, root_pk) = gen_keypair();
        let signed = minimal_signed_roster(&root_sk, root_pk, 1);
        let roster_file = dir.path().join("test-roster.json");
        std::fs::write(&roster_file, serde_json::to_string_pretty(&signed).unwrap()).unwrap();
        setup_env_root_pk(root_pk);

        // Arrange — record pre-state bytes so we can assert nothing changed.
        let roster_on_disk = csq_core::audit::authority::roster_path(base);
        // Authoritative path: chain_state.rs::chain_json_path = base/csq-runs/chain.json.
        let chain_json_path = base.join("csq-runs").join("chain.json");

        assert!(!roster_on_disk.exists(), "pre: roster must not exist");
        assert!(!chain_json_path.exists(), "pre: chain.json must not exist");

        // Arrange — ensure csq-runs/ exists so lock_file can open the sidecar.
        let csq_runs = base.join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let lock_path = csq_runs.join(".chain-lock");

        // Arrange — hold the chain lock in a background thread for longer than
        // the 5-second deadline.  Channel synchronisation ensures the holder is
        // confirmed before we attempt the install.
        let lock_path2 = lock_path.clone();
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();
        let _bg = std::thread::spawn(move || {
            let guard = lock_file(&lock_path2).expect("bg: acquire chain lock");
            tx_locked.send(()).unwrap();
            rx_release.recv_timeout(Duration::from_secs(30)).unwrap();
            drop(guard);
        });

        // Wait until the background thread holds the lock.
        rx_locked
            .recv_timeout(Duration::from_secs(5))
            .expect("bg thread must acquire chain lock within 5s");

        // Act — attempt roster install with the lock held.
        let result = handle_roster_install_inner(base, &roster_file, None, || false);

        // Release background lock regardless of outcome.
        let _ = tx_release.send(());

        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Assert — install must fail with a lock-timeout error.
        assert!(
            result.is_err(),
            "install must fail when chain lock is held: {result:?}"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("chain lock")
                || err_msg.contains("chain-lock")
                || err_msg.contains("timed out"),
            "error must describe the lock timeout: {err_msg}"
        );

        // Assert — neither roster file nor chain.json must have been written.
        assert!(
            !roster_on_disk.exists(),
            "roster MUST NOT be written when chain lock acquisition times out"
        );
        assert!(
            !chain_json_path.exists(),
            "chain.json MUST NOT be written when chain lock acquisition times out"
        );
    }

    /// Happy-path regression guard: roster-install under no lock contention
    /// completes successfully and writes both the roster file and chain.json.
    /// This guards that the chain-lock wiring does NOT break the normal path.
    #[test]
    fn roster_install_succeeds_with_no_lock_contention() {
        let _g = csq_core::platform::test_env::lock();

        let dir = tmp();
        let base = dir.path();

        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Arrange.
        let (root_sk, root_pk) = gen_keypair();
        let signed = minimal_signed_roster(&root_sk, root_pk, 1);
        let roster_file = dir.path().join("test-roster.json");
        std::fs::write(&roster_file, serde_json::to_string_pretty(&signed).unwrap()).unwrap();
        setup_env_root_pk(root_pk);

        // Act — daemon not alive, no lock held by any other process.
        let result = handle_roster_install_inner(base, &roster_file, None, || false);

        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        // Assert — install must succeed.
        assert!(
            result.is_ok(),
            "install must succeed with no contention: {result:?}"
        );

        // Assert — both files must exist on disk.
        let roster_on_disk = csq_core::audit::authority::roster_path(base);
        assert!(roster_on_disk.exists(), "roster must be written on success");

        let chain_json = base.join("csq-runs").join("chain.json");
        // ChainState lives at csq-runs/chain.json; chain.json at base/ is a
        // different path.  Verify the chain.json the ChainState writes.
        // ChainState::save writes to base/csq-runs/chain.json per chain_state.rs.
        assert!(chain_json.exists(), "chain.json must be written on success");
    }
}
