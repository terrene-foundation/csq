//! `csq audit` — M04 key-custody + M05 verify + M07 sink-config subcommands.
//!
//! - `csq audit init`           — idempotent signing-key initialisation (M04).
//! - `csq audit rotate-key`     — key rotation (M04).
//! - `csq audit verify`         — chain-integrity verification (M05).
//! - `csq audit config-sink`    — get/set `audit.sink` (M07).
//! - `csq audit config-cadence` — set per-sink cadence (M07).
//!
//! All commands use the production service name
//! [`csq_core::audit::AUDIT_SIGNING_SERVICE_NAME`] and are NOT available
//! when running tests (tests pass sandboxed service names directly into the
//! library functions).

use anyhow::{bail, Result};
use csq_core::audit::{
    audit_init, build_compliance_report, exit_code_for_error, export_bundle, rotate_key,
    verify_chain, AuditSinkConfig, RotationReason, SigningKey, VerifyConfig,
    AUDIT_SIGNING_SERVICE_NAME,
};
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::error::redact_tokens;
use std::path::Path;

/// Handle `csq audit init`.
///
/// Idempotent: generates an Ed25519 signing key + stores it in the OS keychain
/// under the `csq-audit-signing` service. If a key is already present, exits 0
/// with a message indicating no action was needed.
///
/// In enterprise builds (M3 §10.5 W2b) also initialises the EATP attestation chain
/// signing key and emits the born-canonical genesis record. The genesis emission is
/// idempotent — re-running `csq audit init` with an existing EATP chain is a no-op.
pub fn handle_init(base_dir: &Path) -> Result<()> {
    match audit_init(base_dir, AUDIT_SIGNING_SERVICE_NAME)? {
        true => {
            eprintln!("audit: signing key initialised");
        }
        false => {
            eprintln!("audit: signing key already present — no action needed");
        }
    }

    // M3 §10.5 W2b — enterprise-only born-canonical EATP genesis emission.
    #[cfg(feature = "enterprise")]
    {
        emit_eatp_genesis(base_dir, AUDIT_SIGNING_SERVICE_NAME)?;
    }

    Ok(())
}

/// Enterprise-only: initialise the EATP attestation chain and emit the
/// born-canonical genesis record (M3 §10.5 W2b).
///
/// Idempotent: if the genesis record already exists, this is a no-op.
///
/// # Fail-closed shape
/// - Key init failure → propagate `KeyCustodyError` as `anyhow` (fatal — init
///   should not silently succeed without the EATP key).
/// - `attest_born_canonical_genesis` failure → propagate (a non-canonical genesis
///   MUST NOT be written — structural invariant).
/// - `write_record_v2_signed_in` failure → propagate.
///
/// # Sign-after-assign (PRIMARY METHODOLOGICAL DIRECTIVE 3)
/// The genesis is emitted ONLY via `write_record_v2_signed_in`; the writer
/// patches `seq`, `prev_hash`, `ts`, `chain_id`, `canonical_hash`, and `signature`
/// in the correct order so the Ed25519 signature covers the FINAL field values.
#[cfg(feature = "enterprise")]
pub(crate) fn emit_eatp_genesis(base_dir: &Path, service: &str) -> Result<()> {
    use csq_core::audit::key_custody::try_load_signing_key;
    use csq_core::audit::types::{Ed25519Signature, RecordId, Sha256Hex};
    use csq_core::audit::write_genesis_v2_signed_in;
    use csq_core::audit::{
        current_iso8601_utc_persist, eatp_audit_init, gen_chain_id, ChainKind, ChainState,
        EatpAttestationPayload, EventKind, EventPayload, KeyLoadOutcome, KeySlot, SignedRecord,
        VerificationLevel,
    };

    // Enterprise moat op — gate on the license at the seam (covers `audit init`
    // regardless of caller), before any EATP/kailash attestation (W4).
    crate::cli::enforce_enterprise_license(base_dir)?;

    // Step 1: EATP signing-key init (idempotent). Propagate failure — a missing
    // EATP key would leave the chain unverifiable, so this must not succeed silently.
    match eatp_audit_init(base_dir, service).map_err(|e| anyhow::anyhow!("eatp audit init: {e}"))? {
        true => {
            eprintln!("audit: EATP signing key initialised");
        }
        false => {
            eprintln!("audit: EATP signing key already present");
        }
    }

    // Step 2: resolve the EATP chain_id from eatp-runs/chain.json.
    let eatp_state = ChainState::load_in(base_dir, "eatp-runs")
        .map_err(|e| anyhow::anyhow!("eatp chain state load: {e}"))?;
    let eatp_chain_id = eatp_state.chain_id.clone();

    if eatp_chain_id.is_empty() {
        anyhow::bail!("eatp chain_id empty after eatp_audit_init — internal error");
    }

    // Step 3: idempotency gate — if the genesis JSONL already has records, no-op.
    let eatp_jsonl = base_dir
        .join("eatp-runs")
        .join(format!("{eatp_chain_id}.jsonl"));
    if eatp_jsonl.exists() {
        let has_genesis = std::fs::read_to_string(&eatp_jsonl)
            .map(|c| c.lines().any(|l| !l.trim().is_empty()))
            .unwrap_or(false);
        if has_genesis {
            eprintln!("audit: EATP born-canonical genesis already present — no action needed");
            return Ok(());
        }
    }

    // Step 4: load the EATP signing key for emission.
    let key_outcome = try_load_signing_key(base_dir, service, &eatp_chain_id, KeySlot::Active);
    let eatp_key: Box<dyn csq_core::audit::SigningKey> = match key_outcome {
        KeyLoadOutcome::Loaded(k) => k,
        KeyLoadOutcome::Absent => {
            anyhow::bail!("eatp signing key absent immediately after init — internal error")
        }
        KeyLoadOutcome::Inaccessible => {
            anyhow::bail!("eatp signing key inaccessible (keychain locked?)")
        }
        KeyLoadOutcome::Corrupt(reason) => {
            anyhow::bail!("eatp signing key corrupt: {}", redact_tokens(&reason))
        }
    };

    // Step 5: build the CanonicalAnchorInput for attest_born_canonical_genesis.
    // attestation_ts is DISTINCT from SignedRecord::ts (the chain-write time
    // assigned by the writer). It is stored in EatpAttestationPayload.attestation_ts
    // so the daemon guard can re-derive the same hash. (GovernanceTurnPayload
    // analogue: governed_at vs ts.)
    let attestation_ts = current_iso8601_utc_persist();
    let anchor_id = format!("eatp-genesis:{eatp_chain_id}");
    // metadata_json MUST be non-empty (GenesisEmissionError::EmptyOrMissingMetadata
    // if not), and the community engine must REJECT this input for BornCanonical to
    // apply — `SIGNED_ATTESTATION` is enterprise-only (community 4-level rejects).
    // Keys alphabetically sorted as required by the canonical form.
    let metadata_json =
        r#"{"csq_edition":"enterprise","genesis_kind":"eatp_chain_init"}"#.to_string();

    let canonical_input = csq_trust_contract::CanonicalAnchorInput {
        anchor_id: anchor_id.clone(),
        sequence: 0,
        previous_hash: None,
        agent_id: "csq-ee".to_string(),
        action: "eatp_genesis".to_string(),
        verification_level: "SIGNED_ATTESTATION".to_string(),
        envelope_id: None,
        result: "success".to_string(),
        timestamp: attestation_ts.clone(),
        metadata_json: Some(metadata_json.clone()),
    };

    // Step 6: call the kailash seam to produce the canonical hash.
    // PRIMARY METHODOLOGICAL DIRECTIVE 3 (sign-after-assign): the genesis record
    // is emitted ONLY via write_record_v2_signed_in; we do NOT pre-sign.
    let kailash_canonical_hash =
        csq_audit_kailash::enterprise::attest_born_canonical_genesis(&canonical_input)
            .map_err(|e| anyhow::anyhow!("eatp genesis attestation failed: {}", e.tag()))?;

    // Step 7: build the pre-write SignedRecord. The writer (write_record_v2_signed_in)
    // will PATCH: chain_id, seq, prev_hash, ts, schema_version, canonical_hash,
    // signature (sign-after-assign). We set: record_id, kind, payload, key_id.
    // verification_level is set to SignedAttestation; the writer's Step-4b
    // auto-approve guard is `is_none()`, so it will NOT overwrite this.
    let record_id =
        RecordId::try_new(gen_chain_id()).map_err(|e| anyhow::anyhow!("eatp record_id: {e}"))?;
    let placeholder_chain_id = RecordId::try_new(&eatp_chain_id)
        .map_err(|e| anyhow::anyhow!("eatp chain_id record: {e}"))?;

    let record = SignedRecord {
        schema_version: "2".to_string(),
        record_id,
        chain_id: placeholder_chain_id,  // patched by writer
        seq: 0,                          // patched by writer
        prev_hash: Sha256Hex::genesis(), // patched by writer
        kind: EventKind::EatpAttestation,
        payload: EventPayload::EatpAttestation(EatpAttestationPayload {
            anchor_id,
            sequence: 0,
            previous_hash: None,
            agent_id: "csq-ee".to_string(),
            action: "eatp_genesis".to_string(),
            verification_level: "SIGNED_ATTESTATION".to_string(),
            envelope_id: None,
            result: "success".to_string(),
            attestation_ts,
            kailash_canonical_hash: Some(kailash_canonical_hash),
            metadata_json: Some(metadata_json),
        }),
        ts: "".to_string(),        // patched by writer (chain-write time)
        key_id: eatp_key.key_id(), // real key id from the loaded key
        canonical_hash: Sha256Hex::genesis(), // patched by writer
        signature: Ed25519Signature::new([0u8; 64]), // patched by writer (sign-after-assign)
        actor: None,
        authority: None,
        trust: None,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: None,
        // SignedAttestation is set explicitly; the writer's Step-4b AutoApproved stamp
        // is guarded by `is_none()` and will NOT overwrite an already-set level.
        verification_level: Some(VerificationLevel::SignedAttestation),
    };

    // Step 8: sign-after-assign — write_record_v2_signed_in patches seq/prev_hash/ts
    // THEN computes canonical_hash THEN signs. The genesis is born-canonical because:
    // (a) the enterprise edition verified the inputs, and (b) the signature is over the FINAL hash.
    match write_genesis_v2_signed_in(record, Some(base_dir), ChainKind::Eatp, &*eatp_key) {
        Ok(_) => {
            eprintln!("audit: EATP born-canonical genesis written (chain {eatp_chain_id})");
        }
        // M1 (redteam R1): a concurrent `csq audit init` won the genesis-write race
        // (refused IN-LOCK by the writer). Benign — the chain already carries its
        // born-canonical genesis. Idempotent no-op, not an error.
        Err(csq_core::audit::AuditV2Error::GenesisAlreadyExists) => {
            eprintln!("audit: EATP born-canonical genesis already present — no action needed");
        }
        Err(e) => return Err(anyhow::anyhow!("eatp genesis write: {e}")),
    }
    Ok(())
}

/// Handle `csq audit migrate-keys`.
///
/// Copies the active + historical signing seeds from the OS keychain into the
/// 0o600 file store so the NON-INTERACTIVE daemon can read them without a
/// keychain prompt. Run interactively (this command may trigger the one-time
/// macOS keychain prompt, which the operator grants). Idempotent + additive.
pub fn handle_migrate_keys(base_dir: &Path) -> Result<()> {
    use csq_core::audit::migrate_keys_to_file_store;
    eprintln!(
        "audit: migrating signing keys into the file store \
         (macOS may prompt once to read the keychain — this is expected)"
    );
    let outcome =
        migrate_keys_to_file_store(base_dir, AUDIT_SIGNING_SERVICE_NAME).map_err(|e| {
            anyhow::anyhow!(
                "audit migrate-keys failed: {}",
                redact_tokens(&e.to_string())
            )
        })?;

    if outcome.keychain_inaccessible {
        bail!(
            "audit: the active signing key is in the keychain but could not be read \
             (locked / access-denied). Unlock your login keychain (or grant the prompt) \
             and re-run `csq audit migrate-keys`."
        );
    }
    if outcome.active_already_present {
        eprintln!("audit: active signing key already in the file store — no action needed");
    } else if outcome.active_migrated {
        eprintln!("audit: active signing key migrated to the file store");
    } else if outcome.keychain_absent {
        eprintln!(
            "audit: no signing key found in the keychain to migrate \
             (already file-only, or run `csq audit init` first)"
        );
    }
    if !outcome.historical_migrated.is_empty() {
        eprintln!(
            "audit: migrated {} historical key(s)",
            outcome.historical_migrated.len()
        );
    }
    if !outcome.historical_inaccessible.is_empty() {
        eprintln!(
            "audit: WARNING — {} historical key(s) could not be migrated (keychain locked / \
             access-denied). Pre-cutoff records signed by those rotated-out keys remain \
             daemon-unreadable (they verify in degraded mode). Unlock the keychain and re-run \
             `csq audit migrate-keys` to copy them.",
            outcome.historical_inaccessible.len()
        );
    }
    eprintln!(
        "audit: migration complete — the daemon can now read the active signing key without a prompt"
    );
    Ok(())
}

/// Handle `csq audit repair [--apply]`.
///
/// Diagnoses the audit chain. Without `--apply`, read-only. With `--apply`,
/// clears a stale `.chain-broken` sentinel when the chain now verifies, or backs
/// up + resets a genuinely-broken chain. If the signing key is merely
/// inaccessible, recommends `csq audit migrate-keys` rather than a reset.
pub fn handle_repair(base_dir: &Path, apply: bool) -> Result<()> {
    use csq_core::audit::{repair_audit_chain_in, ChainKind, RepairOutcome};

    // Unique, filesystem-safe backup suffix (epoch seconds). `repair_audit_chain_in`
    // takes the timestamp as a parameter — csq forbids `Date::now()` in library
    // paths, so the binary supplies it.
    let now_compact = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Shared reporter for an op-chain or EATP-chain repair outcome. PRINTS only —
    // it never bails (LOW-1, redteam R4): a `NeedsMigration` on ONE chain must not
    // short-circuit the OTHER chain's repair (mixed custody — op key keychain-only
    // and locked, EATP key file-store-readable — leaves the EATP chain
    // independently repairable). The migration nudge is surfaced ONCE at the end,
    // after both chains have been repaired + reported.
    fn report(label: &str, outcome: &RepairOutcome) {
        use csq_core::cli_deps::sanitize::redact_path;
        match outcome {
            RepairOutcome::Healthy { sentinel_cleared } => {
                if *sentinel_cleared {
                    eprintln!("audit: {label} verifies — cleared a stale .chain-broken sentinel");
                } else {
                    eprintln!("audit: {label} verifies — nothing to repair");
                }
            }
            RepairOutcome::NeedsMigration => {
                eprintln!(
                    "audit: the {label} signing key is present but inaccessible (locked / \
                     access-denied keychain) — this is NOT a broken chain. Run \
                     `csq audit migrate-keys` interactively instead of resetting."
                );
            }
            RepairOutcome::ResetRequired { reason } => {
                eprintln!("audit: {label} is broken: {}", redact_tokens(reason));
                eprintln!(
                    "audit: re-run with `--apply` to back up the broken chain and reset it \
                     (a fresh `csq audit init` then starts clean). File-store keys are preserved."
                );
            }
            RepairOutcome::ChainReset { backup_dir, reason } => {
                eprintln!("audit: {label} was broken: {}", redact_tokens(reason));
                eprintln!(
                    "audit: broken chain backed up to {}",
                    redact_path(backup_dir)
                );
                eprintln!("audit: {label} reset — run `csq audit init` to start a fresh chain");
            }
        }
    }

    // Op-chain repair (always).
    let op = repair_audit_chain_in(
        base_dir,
        AUDIT_SIGNING_SERVICE_NAME,
        apply,
        &now_compact,
        ChainKind::Op,
    )
    .map_err(|e| anyhow::anyhow!("audit repair failed: {}", redact_tokens(&e.to_string())))?;
    report("audit chain", &op);
    #[allow(unused_mut)]
    let mut needs_migration = matches!(op, RepairOutcome::NeedsMigration);

    // F1 (redteam R3): EATP attestation chain repair (enterprise only). Gives the
    // born-canonical EATP chain the SAME operator recovery path as the op-chain —
    // without it an `eatp-runs/.chain-broken` sentinel would wedge all EATP appends
    // with no command to clear it. `verify_chain_in(Eatp)` returns Ok for an absent
    // `eatp-runs/`, so this is a clean no-op on hosts that never ran the EATP init.
    #[cfg(feature = "enterprise")]
    {
        let eatp = repair_audit_chain_in(
            base_dir,
            AUDIT_SIGNING_SERVICE_NAME,
            apply,
            &now_compact,
            ChainKind::Eatp,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "EATP attestation chain repair failed: {}",
                redact_tokens(&e.to_string())
            )
        })?;
        report("EATP attestation chain", &eatp);
        needs_migration |= matches!(eatp, RepairOutcome::NeedsMigration);
    }

    // LOW-1 (redteam R4): surface a key-inaccessible verdict ONCE, after BOTH
    // chains have been repaired — never as an early bail that skips a chain.
    if needs_migration {
        bail!(
            "audit: a signing key is present but inaccessible (locked / access-denied \
             keychain) — this is NOT a broken chain. Run `csq audit migrate-keys` \
             interactively, then re-run `csq audit repair`."
        );
    }

    Ok(())
}

/// Handle `csq audit rotate-key`.
///
/// Generates a fresh Ed25519 keypair, archives the outgoing key in the keychain
/// under its `KeyId` account (retained for historical-record verification), and
/// appends the rotation to the audit ledger using the M13 F-LEDGER-02
/// append-FIRST pattern: a pre-op `KeyRotate` INTENT record is drained BEFORE
/// the keychain mutation, and a post-op `KeyRotate` OUTCOME record is appended
/// after it commits. `rotate_key` performs both appends internally (the signing
/// key lives inside that call); this handler MUST NOT append again. The OUTCOME
/// record is echoed as JSON to stdout for M05 consumers.
///
/// `rotation_reason` defaults to `Operator` when not supplied.
pub fn handle_rotate_key(base_dir: &Path, rotation_reason: Option<&str>) -> Result<()> {
    let reason = match rotation_reason {
        None | Some("operator") => RotationReason::Operator,
        Some("policy") => RotationReason::Policy,
        Some("compromised") => RotationReason::Compromised,
        // M-14: "scheduled" → RotationReason::Scheduled.
        Some("scheduled") => RotationReason::Scheduled,
        Some(other) => {
            // L-4: Route error string through redact_tokens per rules/security.md §2.
            let safe = redact_tokens(other);
            bail!(
                "unknown rotation-reason '{}'; valid values: operator, policy, compromised, scheduled",
                safe
            )
        }
    };

    // L-3: new_key (not _new_key) — the variable IS used below.
    // M13: `rotate_key` drains the KeyRotate INTENT record before the keychain
    // mutation and appends the OUTCOME record after it commits — both via
    // `write_record_v2_signed` internally. `record` is the (already-persisted)
    // OUTCOME record; this handler MUST NOT append it again.
    let (new_key, record) = rotate_key(base_dir, AUDIT_SIGNING_SERVICE_NAME, reason)?;

    // Emit the KeyRotate OUTCOME audit record as JSON to stdout for M05 consumers.
    let json = serde_json::to_string(&record).map_err(|e| {
        anyhow::anyhow!(
            "failed to serialise audit record: {}",
            redact_tokens(&e.to_string())
        )
    })?;
    println!("{json}");

    eprintln!(
        "audit: key rotated — new key_id: {}",
        new_key.key_id().as_str()
    );
    Ok(())
}

/// Handle `csq audit config-sink [NAME]` (M07).
///
/// With no argument: print current `audit.sink` value.
/// With argument: set `audit.sink = <name>`.
///
/// Fails loud when `<name>` is a known sink that was not compiled into
/// this binary (PRIMARY DIRECTIVE 1: sinks are feature-gated).
pub fn handle_config_sink(base_dir: &Path, name: Option<&str>) -> Result<()> {
    let mut cfg = AuditSinkConfig::load(base_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    match name {
        None => {
            // Read mode.
            println!("{}", cfg.sink);
        }
        Some(name) => {
            // Write mode — validates + fail-loud on not-compiled-in.
            cfg.set_sink(name).map_err(|e| anyhow::anyhow!("{e}"))?;
            cfg.save(base_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
            eprintln!("audit: sink set to '{name}'");
        }
    }
    Ok(())
}

/// Handle `csq audit verify [--full] [--since <ts>] [--json]`.
///
/// Verifies the on-disk JSONL chain under `base_dir`. Exit codes per spec 12
/// §12.13:
///   0 — clean
///   1 — integrity failure (ChainBroken, InvalidSignature, IntegrityBroken, Io)
///   2 — partial (KeyNotFound — signing key for historical records not in keychain)
///
/// When `--full` is NOT passed, only the last 1,000 records are verified (tail).
/// `--since <ts>` is accepted for forward-compat but seq-level timestamp filtering
/// is deferred; pass `None` for the seq parameter.
/// `--json` emits the shared SDK envelope `csq.verify.v1` (S2): the verdict payload
/// (`status`, `verified_count`, `skipped_v1_count`, `failure_detail?`, …) wrapped in
/// `{schema, ok, …, edition}`. `ok = result.is_ok()` (a clean or historically-degraded
/// chain is `ok:true`; a `KeyNotFound`/integrity failure is `ok:false`); the 3-valued
/// process exit code (0/1/2) is still derived separately. See
/// [`csq_core::sdk::build_verify_envelope`].
/// M2 T2.5 — print the trust-plane conformance grade after a successful
/// `csq audit verify` (human-readable path).
///
/// **Enterprise edition only.** The community build compiles this to a no-op
/// (no trust plane — `rules/independence.md` dog/tail model), so the community
/// CLI output is byte-identical. Mirrors the `--json` `trust_plane_grade` field.
#[cfg(feature = "enterprise")]
fn print_trust_plane_grade(
    result: &Result<csq_core::audit::VerifySummary, csq_core::audit::LedgerError>,
) {
    if let Some(grade) = csq_core::audit::grade_for_verify_result(result) {
        eprintln!("audit verify: trust-plane grade — {}", grade.as_str());
    }
}

#[cfg(not(feature = "enterprise"))]
fn print_trust_plane_grade(
    _result: &Result<csq_core::audit::VerifySummary, csq_core::audit::LedgerError>,
) {
}

/// Handle `csq audit report` (M5) — the model-residency compliance report.
///
/// Reads the signed audit chain and summarizes residency enforcement per session
/// (providers used + region + verdict) plus whole-store counts. Residency
/// enforcement is enterprise-only; the community build reports that the feature is
/// unavailable (and emits an empty `{}` for `--json`).
pub fn handle_report(base_dir: &Path, output_json: bool) -> Result<()> {
    report_residency(base_dir, output_json)
}

/// Enterprise: the `--json` report body — `{"residency": <summary>}`. Pure
/// (reads the chain, returns a String) so it is unit-testable without capturing
/// stdout. Mirrors `VerifyJsonOutput`'s enterprise-only-field idiom.
#[cfg(feature = "enterprise")]
fn residency_report_json(base_dir: &Path) -> String {
    let summary = csq_core::phase2b::residency::summarize_residency(base_dir);
    serde_json::to_string_pretty(&serde_json::json!({ "residency": summary }))
        .unwrap_or_else(|_| "{}".to_string())
}

/// Community: residency is enterprise-only → the `--json` report is empty `{}`.
#[cfg(not(feature = "enterprise"))]
fn residency_report_json(_base_dir: &Path) -> String {
    "{}".to_string()
}

/// Enterprise: build + print the residency summary from the audit chain.
#[cfg(feature = "enterprise")]
fn report_residency(base_dir: &Path, output_json: bool) -> Result<()> {
    // Enterprise moat op — gate on the license before any phase2b residency read (W4).
    crate::cli::enforce_enterprise_license(base_dir)?;
    if output_json {
        // The whole report object — the residency summary lives under a top-level
        // `residency` key (the testable shape is `residency_report_json`).
        println!("{}", residency_report_json(base_dir));
        return Ok(());
    }
    let summary = csq_core::phase2b::residency::summarize_residency(base_dir);
    eprintln!("audit report: model-residency enforcement");
    eprintln!(
        "  totals — pass: {}  block: {}  overridden: {}",
        summary.total_pass, summary.total_block, summary.total_overridden
    );
    if summary.sessions.is_empty() {
        eprintln!("  (no residency-enforced sessions on the chain)");
        return Ok(());
    }
    for s in &summary.sessions {
        eprintln!(
            "  session {} (policy: {}){}",
            s.session_id,
            s.policy_name.as_deref().unwrap_or("—"),
            if s.overridden {
                "  [a blocked request was overridden]"
            } else {
                ""
            }
        );
        for c in &s.checks {
            eprintln!("    {} [{}] → {}", c.provider_id, c.region, c.verdict);
        }
    }
    Ok(())
}

/// Community: residency enforcement does not exist in this edition.
#[cfg(not(feature = "enterprise"))]
fn report_residency(base_dir: &Path, output_json: bool) -> Result<()> {
    if output_json {
        // Empty report object — no `residency` key (residency is enterprise-only).
        println!("{}", residency_report_json(base_dir));
    } else {
        eprintln!("audit report: model-residency enforcement is an enterprise feature.");
    }
    Ok(())
}

/// Handle `csq audit compliance-report [--format md|html] [--out <path>]` (FR-GOV).
///
/// Runs a read-only `verify_chain` (same integrity check `csq audit verify` and
/// `csq audit export` run) and renders the signed chain into an auditor-readable
/// document whose header states the verification verdict. The report presents
/// only verified facts — it never re-derives them, never reads a raw payload,
/// and never touches the keychain beyond the verification read. When `--out` is
/// given the document is written there (stdout stays clean for scripting) and a
/// redacted confirmation prints to stderr; otherwise the document prints to
/// stdout.
pub fn handle_compliance_report(base_dir: &Path, html: bool, out: Option<&Path>) -> Result<()> {
    // Read-only integrity verification; grounds the report's header verdict.
    let verify = verify_chain(base_dir, &VerifyConfig::default(), None);
    let report = build_compliance_report(base_dir, &verify);
    let document = if html {
        report.render_html()
    } else {
        report.render_markdown()
    };
    match out {
        Some(path) => {
            std::fs::write(path, document.as_bytes())
                .map_err(|e| anyhow::anyhow!("write report to {}: {e}", redact_path(path)))?;
            eprintln!("audit compliance-report: wrote {}", redact_path(path));
            Ok(())
        }
        None => {
            print!("{document}");
            Ok(())
        }
    }
}

/// Handle `csq audit intent [on|off]` (M6 #909 shard C).
///
/// Declares or clears the durable **attestation-intent** marker, or (no arg)
/// prints the current state plus any pre-init queued-decision count. When intent
/// is ON, gated MCP decisions made before `csq audit init` QUEUE to the durable
/// outbox (and shard B's continuous drain flushes them once the chain exists)
/// instead of dropping; default OFF drops them so a non-audit host never
/// accumulates. See `csq_core::audit::outbox_paths::ATTESTATION_INTENT_FILE`.
pub fn handle_intent(base_dir: &Path, state: Option<&str>) -> Result<()> {
    use csq_core::audit::outbox_paths::{
        attestation_intent_is_set, clear_attestation_intent, mcp_gate_outbox_dir,
        set_attestation_intent,
    };

    match state {
        None => {
            let queued = count_outbox_json(&mcp_gate_outbox_dir(base_dir));
            if attestation_intent_is_set(base_dir) {
                eprintln!(
                    "attestation intent: ON — pre-init gated MCP decisions queue until \
                     `csq audit init` ({queued} queued)"
                );
            } else {
                eprintln!(
                    "attestation intent: OFF — pre-init gated MCP decisions drop \
                     (run `csq audit intent on` to preserve them)"
                );
            }
            Ok(())
        }
        Some("on") => {
            set_attestation_intent(base_dir)
                .map_err(|e| anyhow::anyhow!("set attestation intent: {e}"))?;
            eprintln!(
                "attestation intent SET — pre-init gated MCP decisions will queue to the \
                 durable outbox until you run `csq audit init`."
            );
            Ok(())
        }
        Some("off") => {
            clear_attestation_intent(base_dir)
                .map_err(|e| anyhow::anyhow!("clear attestation intent: {e}"))?;
            eprintln!(
                "attestation intent CLEARED — pre-init gated MCP decisions will drop \
                 (a non-audit host does not accumulate a queue)."
            );
            Ok(())
        }
        Some(other) => bail!(
            "unknown intent state '{other}' — expected 'on' or 'off' \
             (or omit the argument to print the current state)"
        ),
    }
}

/// Count drainable `.json` files in an outbox dir (a regular file, `.json`
/// extension, no `.tmp.` in-flight marker), or 0 when the dir is absent. Mirrors
/// the drain's file filter so the operator-reported count matches what will
/// actually drain. Non-gated (both editions read the same on-disk outbox).
fn count_outbox_json(dir: &Path) -> usize {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    entries
        .flatten()
        .filter(|entry| {
            let path = entry.path();
            !path.is_dir()
                && path.extension().and_then(|e| e.to_str()) == Some("json")
                && !path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .contains(".tmp.")
        })
        .count()
}

#[cfg(test)]
mod report_tests {
    use super::*;

    /// Stage a minimal chain (`csq-runs/chain.json` + `<chain>.jsonl`) carrying
    /// the given residency JSONL lines, returning the temp base dir.
    #[cfg(feature = "enterprise")]
    fn stage_chain(jsonl: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let csq_runs = dir.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let chain_id = "01JZ00000000000000000000XY";
        std::fs::write(
            csq_runs.join("chain.json"),
            format!(r#"{{"chain_id":"{chain_id}"}}"#),
        )
        .unwrap();
        std::fs::write(csq_runs.join(format!("{chain_id}.jsonl")), jsonl).unwrap();
        dir
    }

    /// A `residency_enforcement` GovernanceTurn record line for the chain.
    #[cfg(feature = "enterprise")]
    fn residency_line(session: &str, provider: &str, verdict: &str) -> String {
        use csq_core::audit::types::{
            Ed25519Signature, EventKind, EventPayload, GovernanceTurnPayload, KeyId, RecordId,
            Sha256Hex, SignedRecord,
        };
        let rec = SignedRecord {
            schema_version: "2".to_owned(),
            record_id: RecordId::try_new("01JZ00000000000000000001AB").unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::GovernanceTurn,
            payload: EventPayload::GovernanceTurn(GovernanceTurnPayload {
                session_id: session.to_owned(),
                record_seq: 0,
                event_class: "residency_enforcement".to_owned(),
                turn: 1,
                provider_id: Some(provider.to_owned()),
                failover_from: None,
                failover_reason: None,
                usage: None,
                justification_hash: None,
                justification_redacted: None,
                governance_reason: None,
                governed_at: None,
                kailash_canonical_hash: None,
                auth_mode: None,
                residency_verdict: Some(verdict.to_owned()),
                residency_policy_name: Some("eu-only".to_owned()),
                residency_policy_hash: Some("abc123".to_owned()),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_owned(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        serde_json::to_string(&rec).unwrap()
    }

    /// TEST-1 (T5.4 enterprise): `csq audit report --json` emits
    /// `{"residency": {...}}` with the correct 2-pass / 1-block totals read from
    /// the on-disk chain.
    #[cfg(feature = "enterprise")]
    #[test]
    fn report_json_enterprise_has_residency_summary() {
        let jsonl = [
            residency_line("sess-A", "ollama", "pass"),
            residency_line("sess-A", "gemini", "pass"),
            residency_line("sess-A", "claude", "block"),
        ]
        .join("\n");
        let dir = stage_chain(&jsonl);
        let out = residency_report_json(dir.path());
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        let r = &v["residency"];
        assert_eq!(r["total_pass"], 2);
        assert_eq!(r["total_block"], 1);
        assert_eq!(r["sessions"].as_array().unwrap().len(), 1);
        assert_eq!(r["sessions"][0]["session_id"], "sess-A");
    }

    /// TEST-1 (T5.4 community): `csq audit report --json` emits exactly `{}` (no
    /// residency surface in the community edition; spec 27 §27.6 byte-shape).
    #[cfg(not(feature = "enterprise"))]
    #[test]
    fn report_json_community_is_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(residency_report_json(dir.path()), "{}");
    }
}

pub fn handle_verify(
    base_dir: &Path,
    full: bool,
    since: Option<&str>,
    output_json: bool,
) -> Result<()> {
    let record_limit = if full { usize::MAX } else { 1_000 };

    let cfg = VerifyConfig {
        record_limit,
        keychain_service: AUDIT_SIGNING_SERVICE_NAME.to_string(),
    };

    // `since` is accepted for forward-compat; seq-level ts filtering deferred.
    let _ = since;

    let result = verify_chain(base_dir, &cfg, None);

    // FIX-1/FIX-2: update the cross-process .chain-broken sentinel so CLI-side
    // writes (op_emit, rotate, anchor) are gated by the result of this run.
    // `from_verify_result` yields Unknown when the chain returns
    // `LedgerError::KeychainUnavailable` (a transient keychain access error) —
    // the Unknown arm deliberately leaves the sentinel UNCHANGED (a transient
    // condition must NOT produce a durable write-lockout). Keep this arm; do NOT
    // collapse it to `unreachable!()`.
    {
        let health = csq_core::audit::AuditHealth::from_verify_result(&result);
        match &health {
            csq_core::audit::AuditHealth::Verified
            | csq_core::audit::AuditHealth::Degraded { .. } => {
                csq_core::audit::clear_chain_broken(base_dir);
            }
            csq_core::audit::AuditHealth::Broken { error_kind, .. } => {
                csq_core::audit::set_chain_broken(base_dir, error_kind);
            }
            csq_core::audit::AuditHealth::Unknown { .. } => {
                // Transient (KeychainUnavailable): leave the sentinel unchanged.
            }
        }
    }

    // M3 §10.5 (W2a): reconcile the born-canonical EATP attestation chain's own
    // `.chain-broken` sentinel. Independent fault domain — does not affect the
    // op-chain result reported below. Inert until the EATP chain exists
    // (`verify_chain_in` returns Ok(default) for an absent `eatp-runs/`).
    {
        use csq_core::audit::ChainKind;
        let eatp = csq_core::audit::verify_chain_in(base_dir, &cfg, None, ChainKind::Eatp);
        csq_core::audit::reconcile_chain_sentinel(base_dir, ChainKind::Eatp.runs_subdir(), &eatp);
    }

    if output_json {
        // S2 (`csq.verify.v1`): emit the verdict through the shared SDK envelope
        // (`schema` + `ok` + the verdict payload + `edition`). `sdk::emit` is the
        // ONLY stdout writer (R3); its binary 0/1 return is DISCARDED because the
        // 3-valued process exit code (0 clean / 1 integrity / 2 partial) is derived
        // from `result` via `exit_code_for_error`, preserving spec 12 §12.13.5's exit
        // contract.
        let env = csq_core::sdk::build_verify_envelope(&result);
        let emit_result = csq_core::sdk::emit(&env);
        // Redteam R1 (deep-analyst LOW): a `?`-propagated emit failure on an `Err`
        // result would short-circuit BEFORE the exit-code derivation, silently
        // degrading a `partial` (exit 2) to the generic error exit. So on the failure
        // arm the exit code is honored REGARDLESS of whether the envelope reached
        // stdout — an emit failure there is diagnosed to stderr, never allowed to
        // mask the verification exit code.
        if let Err(ref e) = result {
            if let Err(emit_err) = emit_result {
                eprintln!(
                    "audit verify: failed to emit envelope: {}",
                    redact_tokens(&emit_err.to_string())
                );
            }
            std::process::exit(exit_code_for_error(e));
        }
        // Clean / degraded chain: an emit failure IS the command's failure (no output
        // was produced) — propagate it rather than exit 0 silently (`zero-tolerance`
        // Rule 3, no silent fallback).
        emit_result.map_err(|e| {
            anyhow::anyhow!(
                "failed to emit verify envelope: {}",
                redact_tokens(&e.to_string())
            )
        })?;
        return Ok(());
    }

    // Human-readable output.
    match &result {
        Ok(summary) if summary.historical_key_gaps.is_empty() => {
            eprintln!(
                "audit verify: clean — {} v2 records verified, {} v1 skipped",
                summary.verified_count, summary.skipped_v1_count
            );
            print_trust_plane_grade(&result);
        }
        Ok(summary) => {
            // Degraded: chain-linked end-to-end but signature-verification was
            // skipped for records signed by a rotated-out (historical) key whose
            // seed is no longer in the keychain.
            eprintln!(
                "audit verify: DEGRADED-AUDIT(historical) — {} v2 records chain-linked, {} v1 skipped",
                summary.verified_count, summary.skipped_v1_count
            );
            for gap in &summary.historical_key_gaps {
                eprintln!(
                    "  historical key gap: key_id={} seq {}..={} ({} records, signatures skipped)",
                    gap.key_id, gap.first_seq, gap.last_seq, gap.count
                );
            }
            eprintln!(
                "  chain-linking verified end-to-end. Run `csq audit verify --full` for details."
            );
            print_trust_plane_grade(&result);
        }
        Err(ref e @ csq_core::audit::LedgerError::ChainBroken { seq, .. }) => {
            eprintln!(
                "audit verify: INTEGRITY FAILURE — chain broken at seq {seq}. \
Run `csq audit verify --full` for full diagnosis. Repair tooling is forthcoming."
            );
            std::process::exit(exit_code_for_error(e));
        }
        Err(
            ref e @ csq_core::audit::LedgerError::InvalidSignature {
                ref record_id,
                ref key_id,
            },
        ) => {
            eprintln!(
                "audit verify: INTEGRITY FAILURE — invalid signature for record \
{record_id} (key {key_id}). Run `csq audit verify --full` for diagnosis. \
Repair tooling is forthcoming."
            );
            std::process::exit(exit_code_for_error(e));
        }
        Err(ref e @ csq_core::audit::LedgerError::KeyNotFound { ref key_id }) => {
            eprintln!(
                "audit verify: PARTIAL — signing key `{key_id}` not found in \
keychain. If you rotated keys, the outgoing key must be retained — see \
`csq audit key-history`."
            );
            std::process::exit(exit_code_for_error(e));
        }
        Err(ref e @ csq_core::audit::LedgerError::KeychainUnavailable { ref key_id }) => {
            // Transient (NOT an integrity failure): the key is present but the
            // credential store could not be read this run. Exit 2 (partial) to
            // match the --json path; the human label is DEFERRED, not FAILURE.
            eprintln!(
                "audit verify: DEFERRED — signing key `{key_id}` is present but the \
credential store could not be read this run (keychain locked / access-denied). The \
chain is NOT broken — verification is deferred. Run `csq audit migrate-keys` to make \
the key daemon-readable, or retry with the keychain unlocked."
            );
            std::process::exit(exit_code_for_error(e));
        }
        Err(ref e @ csq_core::audit::LedgerError::HistoricalKeyAtHead { head_seq, .. }) => {
            eprintln!(
                "audit verify: INTEGRITY FAILURE — chain head (seq {head_seq}) is signed \
by a historical key that is no longer in the keychain. The chain cannot be verified \
to the present. Run `csq audit verify --full` for diagnosis."
            );
            std::process::exit(exit_code_for_error(e));
        }
        Err(ref e @ csq_core::audit::LedgerError::GapAfterVerifiedSegment { gap_seq, .. }) => {
            eprintln!(
                "audit verify: INTEGRITY FAILURE — historical-key gap record at seq \
{gap_seq} appeared after a signature-verified record. This indicates chain \
tampering or an invalid rotation order. Run `csq audit verify --full` for diagnosis."
            );
            std::process::exit(exit_code_for_error(e));
        }
        Err(e) => {
            // Defense-in-depth (security.md §2): route the error Display through
            // redact_tokens for parity with the --json path, even though every
            // LedgerError Display is currently token-free (key_id/seq/hashes only).
            eprintln!(
                "audit verify: FAILURE — {}. \
Run `csq audit verify --full` for diagnosis.",
                redact_tokens(&e.to_string())
            );
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Handle `csq audit config-cadence <sink> <key> <value>` (M07).
///
/// Sets a per-sink cadence config key. Valid keys: `cadence`,
/// `cadence-high-impact`, `fail-loud`.
pub fn handle_config_cadence(base_dir: &Path, sink: &str, key: &str, value: &str) -> Result<()> {
    let mut cfg = AuditSinkConfig::load(base_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    cfg.set_sink_cadence(sink, key, value)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    cfg.save(base_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("audit: {sink}.{key} set to '{value}'");
    Ok(())
}

/// Handle `csq audit export [--since <ts>] [--until <ts>] [--out <path>]` (M09).
///
/// Produces a self-contained, cross-org-verifiable `.tar` bundle of the local
/// audit chain. Runs a pre-flight `verify_chain` before packaging and refuses
/// to export a chain that does not verify locally. The produced path is printed
/// to stderr (discoverability); stdout stays clean for scripting.
pub fn handle_export(
    base_dir: &Path,
    since: Option<&str>,
    until: Option<&str>,
    out: Option<&Path>,
) -> Result<()> {
    match export_bundle(base_dir, AUDIT_SIGNING_SERVICE_NAME, out, since, until) {
        Ok(summary) => {
            eprintln!(
                "audit export: wrote bundle — {} records, {} signing keys",
                summary.record_count, summary.key_count
            );
            // M21: surface the governance provenance lane so an UNBACKED claim
            // is visible at export time, not only on `./verify` (AC5). Printed
            // only when the chain carries provenance records.
            if summary.provenance_record_count > 0 {
                eprintln!(
                    "audit export: provenance lane — {} decision(s), {} unbacked",
                    summary.provenance_record_count, summary.provenance_unbacked_count
                );
            }
            // Print the bundle path on stdout so scripts can capture it.
            println!("{}", summary.bundle_path.display());
            eprintln!(
                "audit export: verify with `tar xf <bundle> && ./verify` \
(requires only python3; no csq install needed)"
            );
            Ok(())
        }
        Err(e) => {
            // redact_tokens defends against any echoed path/secret in the
            // (already fixed-vocabulary) error message.
            bail!("audit export failed: {}", redact_tokens(&e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn audit_config_sink_handler_round_trip() {
        let dir = temp_dir();
        let base = dir.path();
        // Get — default is "none".
        handle_config_sink(base, None).expect("get default");
        // Set "none" (always valid regardless of features).
        handle_config_sink(base, Some("none")).expect("set none");
        let cfg = AuditSinkConfig::load(base).expect("load after set");
        assert_eq!(cfg.sink, "none");
    }
}

#[cfg(test)]
mod intent_tests {
    use super::*;
    use csq_core::audit::outbox_paths::attestation_intent_is_set;
    use tempfile::TempDir;

    #[test]
    fn intent_on_sets_off_clears_marker() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        assert!(!attestation_intent_is_set(base), "default OFF");

        handle_intent(base, Some("on")).expect("on");
        assert!(attestation_intent_is_set(base), "on sets the marker");

        // Status read is a no-op that does not change state.
        handle_intent(base, None).expect("status");
        assert!(attestation_intent_is_set(base), "status leaves it ON");

        handle_intent(base, Some("off")).expect("off");
        assert!(!attestation_intent_is_set(base), "off clears the marker");
    }

    #[test]
    fn intent_on_and_off_are_idempotent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        handle_intent(base, Some("on")).unwrap();
        handle_intent(base, Some("on")).expect("re-on is idempotent");
        assert!(attestation_intent_is_set(base));
        handle_intent(base, Some("off")).unwrap();
        handle_intent(base, Some("off")).expect("re-off is idempotent");
        assert!(!attestation_intent_is_set(base));
    }

    #[test]
    fn intent_status_on_empty_host_is_off_and_succeeds() {
        let dir = TempDir::new().unwrap();
        // No csq-runs, no marker → status prints OFF, never errors, creates nothing.
        handle_intent(dir.path(), None).expect("status on a bare host");
        assert!(
            !dir.path().join("csq-runs").exists(),
            "status must not create csq-runs/"
        );
    }

    #[test]
    fn intent_rejects_unknown_state() {
        let dir = TempDir::new().unwrap();
        let err = handle_intent(dir.path(), Some("enable")).expect_err("unknown state rejected");
        assert!(
            err.to_string().contains("unknown intent state"),
            "actionable error naming the bad value: {err}"
        );
    }

    #[test]
    fn count_outbox_json_ignores_tmp_and_missing() {
        let dir = TempDir::new().unwrap();
        // Absent dir → 0.
        assert_eq!(count_outbox_json(&dir.path().join("nope")), 0);
        // Two json + one tmp + one subdir → counts only the 2 json.
        let outbox = dir.path().join("outbox");
        std::fs::create_dir_all(&outbox).unwrap();
        std::fs::write(outbox.join("a.0.json"), b"{}").unwrap();
        std::fs::write(outbox.join("b.1.json"), b"{}").unwrap();
        std::fs::write(outbox.join("c.tmp.2.json"), b"{}").unwrap();
        std::fs::create_dir_all(outbox.join("sub.json")).unwrap();
        assert_eq!(count_outbox_json(&outbox), 2);
    }
}
