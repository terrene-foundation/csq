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
    audit_init, exit_code_for_error, export_bundle, rotate_key, to_json_output, verify_chain,
    AuditSinkConfig, RotationReason, SigningKey, VerifyConfig, AUDIT_SIGNING_SERVICE_NAME,
};
use csq_core::error::redact_tokens;
use std::path::Path;

/// Handle `csq audit init`.
///
/// Idempotent: generates an Ed25519 signing key + stores it in the OS keychain
/// under the `csq-audit-signing` service. If a key is already present, exits 0
/// with a message indicating no action was needed.
pub fn handle_init(base_dir: &Path) -> Result<()> {
    match audit_init(base_dir, AUDIT_SIGNING_SERVICE_NAME)? {
        true => {
            eprintln!("audit: signing key initialised");
            Ok(())
        }
        false => {
            eprintln!("audit: signing key already present — no action needed");
            Ok(())
        }
    }
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
    use csq_core::audit::{repair_audit_chain, RepairOutcome};
    use csq_core::cli_deps::sanitize::redact_path;

    // Unique, filesystem-safe backup suffix (epoch seconds). `repair_audit_chain`
    // takes the timestamp as a parameter — csq forbids `Date::now()` in library
    // paths, so the binary supplies it.
    let now_compact = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let outcome = repair_audit_chain(base_dir, AUDIT_SIGNING_SERVICE_NAME, apply, &now_compact)
        .map_err(|e| anyhow::anyhow!("audit repair failed: {}", redact_tokens(&e.to_string())))?;

    match outcome {
        RepairOutcome::Healthy { sentinel_cleared } => {
            if sentinel_cleared {
                eprintln!("audit: chain verifies — cleared a stale .chain-broken sentinel");
            } else {
                eprintln!("audit: chain verifies — nothing to repair");
            }
        }
        RepairOutcome::NeedsMigration => {
            bail!(
                "audit: the signing key is present but inaccessible (locked / access-denied \
                 keychain) — this is NOT a broken chain. Run `csq audit migrate-keys` \
                 interactively instead of resetting."
            );
        }
        RepairOutcome::ResetRequired { reason } => {
            eprintln!("audit: chain is broken: {}", redact_tokens(&reason));
            eprintln!(
                "audit: re-run with `--apply` to back up the broken chain and reset it \
                 (a fresh `csq audit init` then starts clean). File-store keys are preserved."
            );
        }
        RepairOutcome::ChainReset { backup_dir, reason } => {
            eprintln!("audit: chain was broken: {}", redact_tokens(&reason));
            eprintln!(
                "audit: broken chain backed up to {}",
                redact_path(&backup_dir)
            );
            eprintln!("audit: chain reset — run `csq audit init` to start a fresh chain");
        }
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
/// `--json` outputs `{status, verified_count, skipped_v1_count, failure_detail?}`.
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

    if output_json {
        let json_out = to_json_output(&result);
        match serde_json::to_string(&json_out) {
            Ok(s) => println!("{s}"),
            Err(e) => bail!(
                "failed to serialise JSON output: {}",
                redact_tokens(&e.to_string())
            ),
        }
        if let Err(ref e) = result {
            std::process::exit(exit_code_for_error(e));
        }
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
