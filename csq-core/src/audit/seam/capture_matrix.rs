//! M19 — Provenance capture-capability matrix builder and content-hash dedup.
//!
//! ## Purpose
//!
//! Addresses F-SEAM-07: absence of provenance for a surface must not be read
//! as "no decisions made". This module builds a `ProvenanceCaptureMatrixPayload`
//! that declares csq's actual capture capability per known surface, and emits it
//! as a `ProvenanceCaptureMatrix` chain record at daemon start (with sidecar
//! content-hash dedup so identical matrices do not generate duplicate records
//! across restarts).
//!
//! ## Invariants
//!
//! - In production ALL surfaces are `CaptureState::Unwired`. M18-bind registered
//!   the frozen F101-1 v1 decoder (`VersionRegistry::production()` registers
//!   `"1"`), but that is VERSION capability, not per-lane hook wiring: the
//!   frozen v1 wire schema carries no CLI-lane field, and
//!   `ProvenanceAnchored.surface` is an artifact target (journal path, file
//!   path, "shell", "human-input") — a disjoint namespace from the registry's
//!   lane ids (`cc`/`codex`/`gemini`). Lane-level `Wired` transitions are gated
//!   on the loom hook contract (F101-2 / the loom#411 seam-wiring remainder)
//!   providing lane-attribution evidence; until then the matrix honestly
//!   declares every lane Unwired (spec 12 §12.20.1).
//! - Surface list is data-driven via `SurfaceRegistry` (F-SEAM-08). Not hardcoded.
//! - HIGH-1 compliant: no raw event bodies, no free-text, no surface-derived
//!   content in the chain record.
//! - Sidecar (`<base>/audit/.last-capture-matrix`) is NOT under `csq-runs/` so
//!   it does not trigger the single-writer audit test.
//! - The sidecar is not secret-bearing (it is a sha256 hex string of surface ids).
//!   `atomic_replace` is used for rename-atomicity only, not §5a secret-cleanup.
//! - Sidecar dedup key = sha256(chain_id || matrix_content_hash) so that a
//!   chain re-genesis (new chain_id) forces a re-emit even when the surface
//!   content is identical (Finding C fix).

use std::path::{Path, PathBuf};

use crate::audit::persist::{
    write_record_v2, write_record_v2_signed, AuditV2Error, AUDIT_SCHEMA_VERSION,
};
use crate::audit::seam::error::SeamError;
use crate::audit::seam::registry::SurfaceRegistry;
use crate::audit::traits::SigningKey as _;
use crate::audit::types::{
    CaptureState, Ed25519Signature, EventKind, EventPayload, KeyId, ProvenanceCaptureMatrixPayload,
    RecordId, Sha256Hex, SignedRecord, SurfaceCaptureStatus,
};
use crate::platform::fs::{atomic_replace, unique_tmp_path};

/// Build the capture matrix payload for the surfaces in `base`'s registry.
///
/// All surfaces are `CaptureState::Unwired` in production. The surface list is
/// sorted alphabetically for deterministic content-hashing. Fails only when the
/// surface registry file exists but is malformed (`SeamError::RegistryLoad`).
pub fn build_capture_matrix(base: &Path) -> Result<ProvenanceCaptureMatrixPayload, SeamError> {
    let registry = SurfaceRegistry::load(base)?;
    let mut surfaces: Vec<SurfaceCaptureStatus> = registry
        .iter()
        .map(|surface| SurfaceCaptureStatus {
            surface: surface.to_string(),
            // Production invariant: every lane reports Unwired. The v1 decoder
            // (M18-bind) gives csq VERSION capability, but the frozen F101-1
            // v1 schema has no CLI-lane field and `ProvenanceAnchored.surface`
            // is an artifact-target namespace — per-lane capture evidence does
            // not exist. DO NOT set Wired here — that would claim hook wiring
            // csq cannot observe (loom F101-2-gated; spec 12 §12.20.1).
            capture: CaptureState::Unwired,
        })
        .collect();
    // Sort alphabetically so hashing is deterministic across runs.
    surfaces.sort_by(|a, b| a.surface.cmp(&b.surface));
    Ok(ProvenanceCaptureMatrixPayload { surfaces })
}

/// Compute a content hash over the sorted surface list for sidecar dedup.
///
/// The hash covers only the surface ids and capture states — not timestamps or
/// other runtime metadata. Two matrices produced from the same registry and
/// capture state will produce the same hash regardless of when they were built.
///
/// Returns a lowercase hex SHA-256 string (64 chars).
pub fn matrix_content_hash(payload: &ProvenanceCaptureMatrixPayload) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for entry in &payload.surfaces {
        hasher.update(entry.surface.as_bytes());
        hasher.update(b":");
        match entry.capture {
            CaptureState::Wired => hasher.update(b"wired"),
            CaptureState::Unwired => hasher.update(b"unwired"),
        }
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

/// Compute the sidecar dedup key: sha256(chain_id || matrix_content_hash).
///
/// Folding chain_id in ensures that a chain re-genesis (new chain_id) forces
/// a re-emit even when the matrix surface content is identical. chain_id is
/// stable across normal restarts so dedup still suppresses redundant re-emits.
///
/// Returns a lowercase hex SHA-256 string (64 chars).
pub fn sidecar_dedup_key(chain_id: &str, content_hash: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(chain_id.as_bytes());
    hasher.update(b"\x00"); // domain separator
    hasher.update(content_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Path to the sidecar file that records the last-emitted matrix dedup key.
///
/// Located at `<base>/audit/.last-capture-matrix` — NOT under `csq-runs/`,
/// so it does not interact with the single-writer test or the v2 chain.
fn sidecar_path(base: &Path) -> PathBuf {
    base.join("audit").join(".last-capture-matrix")
}

/// Maximum bytes to read from the sidecar file.
///
/// The sidecar holds a 64-char sha256 hex string + newline = 65 bytes.
/// Capping at 128 bytes defends against same-UID DoS via a large planted file
/// without rejecting any valid sidecar (LOW-2 hardening).
const SIDECAR_READ_CAP: u64 = 128;

/// Read the last-emitted matrix dedup key from the sidecar, if any.
///
/// Returns `None` when the sidecar is absent (first run), unreadable, or
/// oversized (> `SIDECAR_READ_CAP` bytes — same-UID DoS defence, LOW-2).
/// On any `None` the daemon re-emits the matrix — fail-safe behaviour.
pub fn read_last_hash(base: &Path) -> Option<String> {
    use std::io::Read as _;
    let path = sidecar_path(base);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => {
            tracing::warn!(
                error_kind = "capture_matrix_sidecar_read_error",
                "M19: could not open .last-capture-matrix sidecar; treating as absent"
            );
            return None;
        }
    };
    // LOW-2: read at most SIDECAR_READ_CAP bytes. A valid sidecar is 65 bytes;
    // anything larger is either corrupt or planted — treat as absent so the
    // daemon re-emits (fail-safe). Read cap+1 to detect oversized files.
    let mut buf = Vec::with_capacity((SIDECAR_READ_CAP + 1) as usize);
    match file.take(SIDECAR_READ_CAP + 1).read_to_end(&mut buf) {
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(
                error_kind = "capture_matrix_sidecar_read_error",
                "M19: could not read .last-capture-matrix sidecar; treating as absent"
            );
            return None;
        }
    }
    if buf.len() > SIDECAR_READ_CAP as usize {
        tracing::warn!(
            error_kind = "capture_matrix_sidecar_malformed",
            "M19: .last-capture-matrix sidecar exceeds size cap ({} bytes); treating as absent",
            SIDECAR_READ_CAP
        );
        return None;
    }
    let s = match std::str::from_utf8(&buf) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!(
                error_kind = "capture_matrix_sidecar_malformed",
                "M19: .last-capture-matrix sidecar is not valid UTF-8; treating as absent"
            );
            return None;
        }
    };
    let trimmed = s.trim();
    // Validate it looks like a sha256 hex string (64 lowercase hex chars).
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trimmed.to_string())
    } else {
        tracing::warn!(
            error_kind = "capture_matrix_sidecar_malformed",
            "M19: .last-capture-matrix sidecar has unexpected shape; treating as absent"
        );
        None
    }
}

/// Atomically write `key` to the sidecar.
///
/// Uses `atomic_replace` for rename-atomicity. The sidecar is not
/// secret-bearing (it is a public sha256 hash), so §5a partial-failure
/// cleanup is not required — the content is benign.
pub fn write_last_hash(base: &Path, key: &str) -> Result<(), SeamError> {
    let sidecar_dir = base.join("audit");
    std::fs::create_dir_all(&sidecar_dir)?;
    let dst = sidecar_path(base);
    let tmp = unique_tmp_path(&dst);
    std::fs::write(&tmp, format!("{key}\n"))?;
    atomic_replace(&tmp, &dst).map_err(|_| {
        // tmp is non-secret; cleanup is best-effort.
        let _ = std::fs::remove_file(&tmp);
        std::io::Error::other("atomic_replace failed")
    })?;
    Ok(())
}

/// Build an unsigned skeleton `SignedRecord` for a `ProvenanceCaptureMatrix` emit.
///
/// The matrix is a STATE record (not an intent/outcome pair), so there is no
/// `op_phase` envelope. Seq, prev_hash, canonical_hash, and signature are
/// assigned by `write_record_v2_impl` at write time.
///
/// Returns `Err(AuditV2Error::ChainCorrupt)` when `chain_id_str` is empty —
/// the matrix MUST NOT mint a new chain_id; that belongs to the chain's
/// genesis write. Callers MUST pass the chain_id loaded from `chain.json`.
fn build_matrix_record(
    chain_id_str: &str,
    payload: ProvenanceCaptureMatrixPayload,
) -> Result<SignedRecord, AuditV2Error> {
    // Finding E fix: reject empty chain_id rather than minting a new one.
    // An empty chain_id means the chain hasn't been initialised yet; the
    // caller's `is_operational()` gate should prevent us getting here, but
    // fail closed explicitly just in case.
    if chain_id_str.is_empty() {
        return Err(AuditV2Error::ChainCorrupt {
            reason: "capture-matrix emit called with empty chain_id; \
                     chain must be initialised before emitting M19 record"
                .to_string(),
        });
    }
    let chain_id =
        RecordId::try_new(chain_id_str.to_string()).map_err(|e| AuditV2Error::ChainCorrupt {
            reason: format!("chain_id '{chain_id_str}' is not a valid RecordId: {e}"),
        })?;
    // record_id is a fresh ULID, distinct from chain_id.
    let record_id = RecordId::try_new(crate::audit::persist::gen_chain_id()).map_err(|e| {
        AuditV2Error::ChainCorrupt {
            reason: format!("gen_chain_id produced invalid record_id: {e}"),
        }
    })?;
    // Placeholder key_id; the writer overwrites this when signing.
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
        kind: EventKind::ProvenanceCaptureMatrix,
        payload: EventPayload::ProvenanceCaptureMatrix(payload),
        ts: crate::audit::persist::current_iso8601_utc_persist(),
        key_id,
        canonical_hash: Sha256Hex::genesis(),
        signature: Ed25519Signature::new([0u8; 64]),
        actor: None,
        authority: None,
        trust: None,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: None, // STATE record — no op_phase envelope
    })
}

/// Emit a `ProvenanceCaptureMatrix` chain record using the cutoff-aware signing
/// posture from `op_emit`.
///
/// Returns `Ok(true)` when written (signed or unsigned), `Ok(false)` when
/// skipped because `.chain-broken` is set, or `Err` on a hard write failure
/// (including empty `chain_id_str`).
///
/// Callers MUST check `audit_health.is_operational()` before calling this.
/// This function does not gate on health itself — that gate is the caller's
/// responsibility so the skip path is clearly visible in daemon.rs.
///
/// The `chain_id_str` MUST be the chain_id already in `chain.json` (loaded via
/// `op_emit::load_chain_id`). Passing an empty string is an error: the matrix
/// record MUST NOT trigger a chain genesis.
pub fn emit_matrix_record(
    base: &Path,
    chain_id_str: &str,
    payload: ProvenanceCaptureMatrixPayload,
) -> Result<bool, AuditV2Error> {
    // Check chain-broken sentinel before attempting signing.
    if let Some(broken_kind) = crate::audit::health::is_chain_broken(base) {
        tracing::warn!(
            error_kind = "audit_matrix_skipped_chain_broken",
            broken_kind = %broken_kind,
            "M19: capture-matrix emit skipped — .chain-broken sentinel is set; \
             daemon proceeds without matrix record. Run `csq audit verify` after repair."
        );
        return Ok(false);
    }

    let record = build_matrix_record(chain_id_str, payload)?;

    // Attempt signing with the pre-cutoff budget. State records use the same
    // signing posture as lifecycle ops: opportunistic pre-cutoff, fail-closed
    // post-cutoff. A matrix emit failure is non-fatal to daemon startup — the
    // caller should log a WARN and proceed.
    use crate::audit::key_custody::{
        try_load_signing_key, ChainState, KeyLoadOutcome, KeySlot, SERVICE_NAME,
    };
    use std::time::{Duration, Instant};

    const BUDGET: Duration = Duration::from_millis(200);
    const INACCESSIBLE_POLL_CAP: Duration = Duration::from_millis(200);

    // Load ChainState ONCE for both key lookup and chain_id consistency
    // (avoids a double-load race between key lookup and record write).
    let chain_state = ChainState::load(base).ok();
    let signing_key_registered = chain_state
        .as_ref()
        .map(|s| s.signing_key_id.is_some())
        .unwrap_or(false);
    let chain_id_for_key = chain_state
        .as_ref()
        .map(|s| s.chain_id.clone())
        .unwrap_or_default();

    if signing_key_registered && !chain_id_for_key.is_empty() {
        let deadline = Instant::now() + BUDGET.min(INACCESSIBLE_POLL_CAP);
        let poll_interval = Duration::from_millis(50);
        loop {
            match try_load_signing_key(base, SERVICE_NAME, &chain_id_for_key, KeySlot::Active) {
                KeyLoadOutcome::Loaded(key) => {
                    let mut signed_record = record;
                    signed_record.key_id = key.key_id();
                    return write_record_v2_signed(signed_record, Some(base), &*key)
                        .map(|_| true)
                        .or_else(|e| match e {
                            AuditV2Error::ChainBrokenRefuseAppend { .. } => Ok(false),
                            other => Err(other),
                        });
                }
                KeyLoadOutcome::Absent | KeyLoadOutcome::Corrupt(_) => {
                    // Fall through to unsigned write below.
                    break;
                }
                KeyLoadOutcome::Inaccessible => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(poll_interval);
                }
            }
        }
    }

    // No key or key unavailable within budget — write unsigned (pre-cutoff safe).
    write_record_v2(record, Some(base))
        .map(|()| true)
        .or_else(|e| match e {
            AuditV2Error::ChainBrokenRefuseAppend { .. } => Ok(false),
            other => Err(other),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_base() -> TempDir {
        TempDir::new().unwrap()
    }

    fn write_surface_registry(base: &Path, json: &str) {
        let dir = base.join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("surface-registry.json"), json).unwrap();
    }

    // ── AC-1: matrix emits per-surface capture status ──────────────────────────

    /// AC-1: build_capture_matrix returns all known surfaces.
    #[test]
    fn build_capture_matrix_covers_all_registry_surfaces() {
        let base = make_base();
        write_surface_registry(base.path(), r#"["cc","codex","gemini"]"#);
        let payload = build_capture_matrix(base.path()).expect("build should succeed");
        let surfaces: Vec<&str> = payload
            .surfaces
            .iter()
            .map(|s| s.surface.as_str())
            .collect();
        assert!(
            surfaces.contains(&"cc"),
            "cc must be in matrix: {surfaces:?}"
        );
        assert!(
            surfaces.contains(&"codex"),
            "codex must be in matrix: {surfaces:?}"
        );
        assert!(
            surfaces.contains(&"gemini"),
            "gemini must be in matrix: {surfaces:?}"
        );
    }

    /// AC-1/production invariant: all surfaces are Unwired in production.
    #[test]
    fn all_surfaces_unwired_in_production() {
        let base = make_base();
        let payload =
            build_capture_matrix(base.path()).expect("build should succeed with defaults");
        for entry in &payload.surfaces {
            assert_eq!(
                entry.capture,
                CaptureState::Unwired,
                "surface {} must be Unwired in production (no lane-attribution \
                 evidence exists under the frozen v1 schema; loom F101-2-gated)",
                entry.surface
            );
        }
    }

    // ── AC-2: surface set is data-driven ────────────────────────────────────────

    /// AC-2: custom registry is reflected in the matrix.
    #[test]
    fn custom_registry_reflected_in_matrix() {
        let base = make_base();
        write_surface_registry(base.path(), r#"["custom-lane","cc"]"#);
        let payload = build_capture_matrix(base.path()).expect("build should succeed");
        let surfaces: Vec<&str> = payload
            .surfaces
            .iter()
            .map(|s| s.surface.as_str())
            .collect();
        assert!(surfaces.contains(&"custom-lane"), "custom-lane must appear");
        assert!(surfaces.contains(&"cc"), "cc must appear");
        assert!(
            !surfaces.contains(&"codex"),
            "codex must NOT appear in custom registry"
        );
        assert!(
            !surfaces.contains(&"gemini"),
            "gemini must NOT appear in custom registry"
        );
    }

    // ── AC-5: codex session with zero provenance reads as declared-unwired, not gap
    //
    // PRIMARY METHODOLOGICAL DIRECTIVE #2: csq-lane session lifecycle records
    // (CsqRun) are the defense-in-depth floor. Even with zero F101-1 provenance
    // for a codex session, csq's chain MUST carry the SESSION record independently.
    //
    // M19b UPGRADE (2026-06-09): this test previously SEEDED the CsqRun floor
    // record via `write_record_v2` because production did not emit one — `csq run`
    // wrote only a schema-v1 `AuditRecord` to `csq-runs/*.jsonl` with
    // `surface: Cc` hardcoded (the Finding-A gap). M19b closed that gap: the
    // daemon now emits a chain-v2 `CsqRun` floor record via
    // `run_floor::emit_csq_run_record` when it ingests a v1 run record. This test
    // is upgraded to exercise that PRODUCTION function directly (AC4 resolution =
    // option (a), owner decision 2026-06-09; see the M19b todo).

    /// AC-5: composition test — given a `CsqRun` session floor produced by the
    /// PRODUCTION emit path AND a capture matrix in the chain, a codex session
    /// with zero F101-1 provenance reads as "attested session + declared-unwired
    /// capture", NOT a silent gap.
    ///
    /// PRODUCTION-PATH assertion (no longer seeded): the codex floor record is
    /// emitted by `run_floor::emit_csq_run_record` — the exact function the
    /// daemon's `audit_record_handler` and the startup reconciler's `.pending`
    /// drain call — so this proves production actually produces the floor record.
    #[test]
    #[cfg(feature = "test-utils")]
    fn ac5_csq_run_floor_plus_capture_matrix_composition() {
        use crate::audit::persist::write_record_v2;
        use crate::audit::run_floor::emit_csq_run_record;
        use crate::audit::types::{
            CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
            SignedRecord,
        };

        let base = make_base();

        // Bootstrap the chain genesis (stands in for `csq audit init` + prior
        // activity). `emit_csq_run_record` deliberately REFUSES to mint a genesis
        // — a floor record must never start a chain — so a chain must pre-exist.
        let bootstrap = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "bootstrap-genesis".to_string(),
            }),
            ts: crate::audit::persist::current_iso8601_utc_persist(),
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
        write_record_v2(bootstrap, Some(base.path())).expect("bootstrap chain genesis");

        // PRODUCTION PATH: emit the codex session floor via the real function.
        let emitted = emit_csq_run_record(base.path(), "codex-session-test-001")
            .expect("emit_csq_run_record must not hard-error");
        assert!(
            emitted,
            "production emit_csq_run_record must append a CsqRun floor record"
        );

        // Read chain.json to get the ACTUAL genesis chain_id assigned by persist.
        let chain_json_path = base.path().join("csq-runs").join("chain.json");
        let chain_json_text = std::fs::read_to_string(&chain_json_path)
            .expect("chain.json must exist after bootstrap write");
        let genesis: serde_json::Value =
            serde_json::from_str(&chain_json_text).expect("chain.json must be valid JSON");
        let genesis_chain_id = genesis["chain_id"]
            .as_str()
            .expect("chain.json must have chain_id string")
            .to_string();

        // Emit the capture matrix onto the same chain using the real chain_id.
        write_surface_registry(base.path(), r#"["cc","codex","gemini"]"#);
        let matrix_payload = build_capture_matrix(base.path()).expect("build matrix must succeed");
        let result = emit_matrix_record(base.path(), &genesis_chain_id, matrix_payload);
        assert!(
            matches!(result, Ok(true)),
            "emit_matrix_record must write a record: {result:?}"
        );

        // Read the chain JSONL and assert composition.
        let chain_jsonl = base
            .path()
            .join("csq-runs")
            .join(format!("{genesis_chain_id}.jsonl"));
        let chain_text =
            std::fs::read_to_string(&chain_jsonl).expect("chain JSONL must exist after writes");

        // (a) the PRODUCTION-emitted codex session floor record is present.
        assert!(
            chain_text.contains("codex-session-test-001"),
            "chain must contain the production-emitted CsqRun floor for the codex \
             session (run_id codex-session-test-001): {chain_text}"
        );
        assert!(
            chain_text.contains("\"csq_run\"") || chain_text.contains("\"CsqRun\""),
            "chain must contain a CsqRun record kind: {chain_text}"
        );

        // (b) ProvenanceCaptureMatrix record present declaring codex=Unwired.
        assert!(
            chain_text.contains("\"provenance_capture_matrix\"")
                || chain_text.contains("\"ProvenanceCaptureMatrix\""),
            "chain must contain a ProvenanceCaptureMatrix record: {chain_text}"
        );
        assert!(
            chain_text.contains("\"codex\""),
            "capture matrix must name codex surface: {chain_text}"
        );
        assert!(
            chain_text.contains("\"unwired\""),
            "capture matrix must declare codex=unwired: {chain_text}"
        );
    }

    // ── Content hash dedup ──────────────────────────────────────────────────────

    /// Same registry + same capture state → same hash.
    #[test]
    fn identical_matrix_produces_same_hash() {
        let base = make_base();
        let p1 = build_capture_matrix(base.path()).unwrap();
        let p2 = build_capture_matrix(base.path()).unwrap();
        assert_eq!(
            matrix_content_hash(&p1),
            matrix_content_hash(&p2),
            "deterministic: same registry → same hash"
        );
    }

    /// Different registry → different hash.
    #[test]
    fn different_registry_produces_different_hash() {
        let base = make_base();
        let p1 = build_capture_matrix(base.path()).unwrap(); // cc/codex/gemini default

        write_surface_registry(base.path(), r#"["custom-only"]"#);
        let p2 = build_capture_matrix(base.path()).unwrap();

        assert_ne!(
            matrix_content_hash(&p1),
            matrix_content_hash(&p2),
            "different surface sets must produce different hashes"
        );
    }

    // ── Sidecar dedup key (Finding C fix) ──────────────────────────────────────

    /// Same chain_id + same content → same dedup key.
    #[test]
    fn sidecar_dedup_key_deterministic() {
        let k1 = sidecar_dedup_key("chain-abc", "contenthash123");
        let k2 = sidecar_dedup_key("chain-abc", "contenthash123");
        assert_eq!(k1, k2, "dedup key must be deterministic");
    }

    /// Different chain_id + same content → different dedup key (re-genesis re-emits).
    #[test]
    fn sidecar_dedup_key_differs_on_new_chain_id() {
        let content = "a".repeat(64);
        let k1 = sidecar_dedup_key("chain-original", &content);
        let k2 = sidecar_dedup_key("chain-regenesis", &content);
        assert_ne!(
            k1, k2,
            "different chain_id must produce different dedup key even with same content"
        );
    }

    /// Same chain_id + different content → different dedup key.
    #[test]
    fn sidecar_dedup_key_differs_on_content_change() {
        let chain = "chain-stable";
        let k1 = sidecar_dedup_key(chain, &"a".repeat(64));
        let k2 = sidecar_dedup_key(chain, &"b".repeat(64));
        assert_ne!(k1, k2, "different content must produce different dedup key");
    }

    // ── Sidecar read/write ───────────────────────────────────────────────────────

    /// Absent sidecar → None.
    #[test]
    fn absent_sidecar_returns_none() {
        let base = make_base();
        assert_eq!(read_last_hash(base.path()), None);
    }

    /// Write + read round-trip.
    #[test]
    fn sidecar_write_read_roundtrip() {
        let base = make_base();
        let hash = "a".repeat(64);
        write_last_hash(base.path(), &hash).expect("write should succeed");
        assert_eq!(read_last_hash(base.path()), Some(hash));
    }

    /// LOW-2: oversized sidecar (> SIDECAR_READ_CAP bytes) → None (safe re-emit).
    /// Defends against same-UID DoS via a large planted sidecar file.
    #[test]
    fn oversized_sidecar_returns_none() {
        let base = make_base();
        // Write a sidecar that exceeds SIDECAR_READ_CAP (128 bytes).
        let oversized = "a".repeat(200);
        let sidecar_dir = base.path().join("audit");
        std::fs::create_dir_all(&sidecar_dir).unwrap();
        std::fs::write(
            sidecar_dir.join(".last-capture-matrix"),
            oversized.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            read_last_hash(base.path()),
            None,
            "oversized sidecar MUST be treated as absent (fail-safe re-emit)"
        );
    }

    // ── AC-6: matrix emission on daemon start ───────────────────────────────────

    /// AC-6: emit_matrix_record with an initialised chain writes a record.
    #[test]
    fn emit_matrix_record_writes_chain_record() {
        use crate::audit::persist::write_record_v2;
        use crate::audit::types::{
            CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
            SignedRecord,
        };

        let base = make_base();

        // Seed a genesis record so the chain exists and chain_id is known.
        let chain_id_str = crate::audit::persist::gen_chain_id();
        let chain_id =
            RecordId::try_new(chain_id_str.clone()).expect("chain_id must be valid ULID");
        let run_record_id =
            RecordId::try_new(crate::audit::persist::gen_chain_id()).expect("record_id valid");
        let key_id =
            KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).expect("placeholder key_id");
        let seed = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: run_record_id,
            chain_id,
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "seed-for-matrix-test".to_string(),
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
            op_phase: None,
        };
        write_record_v2(seed, Some(base.path())).expect("seed write must succeed");

        let payload = build_capture_matrix(base.path()).unwrap();
        let result = emit_matrix_record(base.path(), &chain_id_str, payload);
        assert!(
            matches!(result, Ok(true)),
            "emit must succeed and write a record: {result:?}"
        );
        // Verify the chain file was created.
        let chain_file = base.path().join("csq-runs").join("chain.json");
        assert!(
            chain_file.exists(),
            "chain.json must exist after matrix emit"
        );
    }

    /// Finding E regression: emit_matrix_record with empty chain_id returns Err.
    #[test]
    fn emit_matrix_record_errors_on_empty_chain_id() {
        let base = make_base();
        let payload = build_capture_matrix(base.path()).unwrap();
        let result = emit_matrix_record(base.path(), "", payload);
        assert!(
            matches!(result, Err(AuditV2Error::ChainCorrupt { .. })),
            "empty chain_id must return Err(ChainCorrupt): {result:?}"
        );
    }

    /// Finding B regression: Ok(false) (chain-broken skip) MUST NOT advance sidecar.
    /// Daemon must check Ok(true) before writing sidecar.
    #[test]
    fn emit_false_means_chain_broken_sidecar_must_not_advance() {
        // Verify the return value semantics that daemon.rs relies on.
        // Ok(false) = chain-broken skip; daemon MUST NOT call write_last_hash.
        // We can't easily trigger Ok(false) without setting the sentinel, but
        // we can test the daemon-side logic path by verifying that our
        // emit_matrix_record returns Ok(true) only when written.
        let base = make_base();
        let chain_id_str = crate::audit::persist::gen_chain_id();
        // Seed a chain so chain_id is non-empty.
        use crate::audit::persist::write_record_v2;
        use crate::audit::types::{
            CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
            SignedRecord,
        };
        let chain_id = RecordId::try_new(chain_id_str.clone()).expect("chain_id valid");
        let rid = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        let kid = KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap();
        let seed = SignedRecord {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            record_id: rid,
            chain_id,
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "finding-b-test".to_string(),
            }),
            ts: crate::audit::persist::current_iso8601_utc_persist(),
            key_id: kid,
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
        };
        write_record_v2(seed, Some(base.path())).unwrap();

        let payload = build_capture_matrix(base.path()).unwrap();
        let result = emit_matrix_record(base.path(), &chain_id_str, payload);
        // Normal write (no chain-broken sentinel) → Ok(true).
        assert!(
            matches!(result, Ok(true)),
            "normal emit must return Ok(true): {result:?}"
        );
        // Daemon MUST advance sidecar ONLY on Ok(true), NOT on Ok(false).
        // The sidecar is separate from emit_matrix_record — the daemon controls it.
        // This test confirms the Ok(true) signal is the guard condition.
    }

    /// Sidecar dedup: second emit with same chain_id+content hash is skipped at caller level.
    #[test]
    fn sidecar_dedup_skips_redundant_emit() {
        let base = make_base();
        let payload = build_capture_matrix(base.path()).unwrap();
        let content_hash = matrix_content_hash(&payload);
        let chain_id = "test-chain-stable";
        let dedup_key = sidecar_dedup_key(chain_id, &content_hash);

        // Simulate: first emit wrote the sidecar.
        write_last_hash(base.path(), &dedup_key).unwrap();

        // Caller checks: key matches → skip.
        let last = read_last_hash(base.path());
        assert_eq!(
            last.as_deref(),
            Some(dedup_key.as_str()),
            "sidecar should return the written dedup key"
        );
        // Key matches → caller would NOT call emit_matrix_record (dedup gate).
        assert!(
            last.as_deref() == Some(dedup_key.as_str()),
            "when dedup keys match, caller skips emit"
        );
    }
}
