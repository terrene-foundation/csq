//! M09 — `csq audit export` verifiable-bundle producer (spec 16).
//!
//! Packages the local audit chain into a self-contained, cross-org-verifiable
//! `.tar` bundle. An external auditor (or an operator on a different install,
//! with NO csq installed) extracts the bundle and runs the embedded `verify`
//! script to get a PASS/FAIL verdict.
//!
//! # Bundle shape (spec 16 §16.2)
//!
//! ```text
//! csq-audit-bundle-<chain_id>-<exp_id>.tar
//! ├── README.md                auditor trust notice (HONEST-HOST GRADE caveat)
//! ├── chain.jsonl              canonical-form records in sequence
//! ├── public_keys.json         every key referenced by signatures + genesis
//! ├── rotation_chain.json      key-rotation history from genesis
//! ├── canonical_form_vectors/  embedded golden (record→hash) vectors + VERSION
//! ├── CUTOFF.json              M16 signed export cutoff (head snapshot + anchor ref)
//! ├── BUNDLE.lock              sorted-by-path SHA-256 of every other file
//! ├── BUNDLE.sig               Ed25519 over BUNDLE.lock by the genesis key
//! └── verify                   self-contained python3 + openssl verifier
//! ```
//!
//! # Honest-host grade caveat (T3.6)
//!
//! The bundle carries a `README.md` stating that these attestations are
//! **honest-host grade** — tamper-evident in transit (covered by `BUNDLE.lock`
//! → `BUNDLE.sig`) but NOT proof the producing host was uncompromised, until an
//! external witness (Rekor / Foundation notary) corroborates the chain head.
//! Because `README.md` is an `entries` member hashed into `BUNDLE.lock` before
//! the genesis key signs it, an auditor cannot silently strip or weaken the
//! caveat: a tampered README fails the Step-2 hash check and a stripped README
//! fails as a missing lock-referenced file. See spec 15 §15.4
//! (honest-host-caveat subsection: §15.4.4 enterprise / §15.4.3 community).
//!
//! # PRIMARY METHODOLOGICAL DIRECTIVES (M09)
//!
//! 1. **verify script is stdlib-only.** The bundled `verify` script is
//!    `#!/usr/bin/env python3` using ONLY the Python 3 standard library
//!    (`hashlib`/`json`/`base64`/`tarfile`/`urllib`). Ed25519 verification is a
//!    pure-Python RFC 8032 implementation — neither the `cryptography` PyPI
//!    package NOR the `openssl` CLI is required. (macOS ships LibreSSL, whose
//!    `openssl` CLI does not support Ed25519, so a pure-Python verifier is the
//!    only construction that runs identically on Linux, macOS, and Windows.)
//! 2. **BUNDLE.sig is self-verifying.** It is verifiable using ONLY the
//!    bundle's own `public_keys.json[genesis]` entry — no external key server.
//! 3. **canonical_form_vectors/ is embedded, not referenced.** Golden vectors
//!    (record → canonical_hash) for the active canonical-form version are
//!    embedded so the verifier self-checks its reproduction of csq's canonical
//!    form before trusting it on real records.
//!
//! # Dependency footprint (independence.md)
//!
//! This module adds ZERO new Rust crates. The archive is a plain (uncompressed)
//! USTAR `.tar` produced by a hand-rolled writer (`tar`) using only `std`.
//! `zstd`/`tar`/`flate2` are NOT in the dependency tree and were NOT added;
//! a `.tar` is universally extractable (`tar xf`, Python `tarfile`) without any
//! third-party tooling. See spec 16 §16.8.
//!
//! # §5a compliance
//!
//! The final bundle write uses `unique_tmp_path → write → secure_file →
//! atomic_replace` with `remove_file(&tmp)` on every failure branch. The tar
//! bytes contain audit records (no OAuth tokens), but the bundle is treated as
//! secret-bearing for cleanup discipline since chain records may carry
//! operator-identifying payloads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::audit::key_custody::chain_state::ChainState;
use crate::audit::key_custody::KeyCustodyError;
// LocalSigningKey is now only referenced by the in-file test module (production
// reads go through `try_load_signing_key`); gate the import to test builds.
#[cfg(test)]
use crate::audit::key_custody::LocalSigningKey;
use crate::audit::persist::{canonical_bytes_for, sha256_hex};
use crate::audit::traits::SigningKey as _;
use crate::audit::types::{KeyId, SignedRecord};
use crate::audit::verify::{verify_chain, VerifyConfig};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

/// The embedded verify-script template (PRIMARY DIRECTIVE 1).
///
/// Shipped verbatim as the bundle's `verify` entry (mode 0o755).
const VERIFY_SCRIPT: &str = include_str!("export/verify.py.template");

/// The embedded auditor trust notice (T3.6).
///
/// Shipped verbatim as the bundle's `README.md` entry (mode 0o644). Added to
/// `entries` BEFORE `BUNDLE.lock` is computed, so its SHA-256 is in the lock and
/// the genesis `BUNDLE.sig` covers it — the caveat is tamper-evident (a tampered
/// README fails the verify-script Step-2 hash check; a stripped README fails as a
/// missing lock-referenced file). Edition-neutral prose ("csq", not "csq-ee") —
/// this module ships in BOTH editions (`terrene-naming.md`). See spec 15 §15.4
/// (honest-host-caveat subsection: §15.4.4 enterprise / §15.4.3 community).
const README_NOTICE: &str = include_str!("export/README.md.template");

/// Errors returned by [`export_bundle`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// No chain exists to export (no `chain.json` / no records).
    #[error("no audit chain to export — run some audited operations first")]
    EmptyChain,
    /// The local pre-flight `verify_chain` failed; refusing to produce a bundle
    /// that would not verify externally.
    #[error(
        "pre-flight chain verification failed: {reason} — refusing to export an unverifiable chain"
    )]
    PreflightFailed {
        /// Operator-facing, redacted reason.
        reason: String,
    },
    /// The genesis signing key required to sign `BUNDLE.lock` is not in the
    /// keychain (run `csq audit init`).
    #[error("genesis signing key not available — run `csq audit init` before exporting")]
    GenesisKeyMissing,
    /// A key-custody (keychain / chain.json) error.
    #[error("key custody error: {0}")]
    KeyCustody(#[from] KeyCustodyError),
    /// An I/O error.
    #[error("export i/o error: {message}")]
    Io {
        /// Operator-facing reason.
        message: String,
    },
    /// A serialization error.
    #[error("export serialization error: {message}")]
    Serialize {
        /// Operator-facing reason.
        message: String,
    },
    /// The M16 signed cutoff manifest (`CUTOFF.json`) could not be built/signed.
    #[error("export cutoff error: {0}")]
    Cutoff(String),
}

/// Result of a successful export.
#[derive(Debug, Clone)]
pub struct ExportSummary {
    /// Absolute path to the produced `.tar` bundle.
    pub bundle_path: PathBuf,
    /// Number of chain records included.
    pub record_count: u64,
    /// Number of distinct signing keys referenced.
    pub key_count: usize,
    /// M21 — number of `ProvenanceAnchored` records projected into the
    /// `PROVENANCE.json` governance lane (§16.15). Zero on a chain with no
    /// seam-ingested provenance (the common case pre-M18-bind).
    pub provenance_record_count: u64,
    /// M21 — number of provenance-lane records whose authorship attestation is
    /// NOT `backing: verified` (i.e. `unbacked`). Surfaced so an UNBACKED claim
    /// is visible at export time, not only on `./verify` (AC5).
    pub provenance_unbacked_count: u64,
}

/// Produce a verifiable audit bundle.
///
/// # Arguments
///
/// - `base_dir`   — csq accounts base directory (`~/.claude/accounts`).
/// - `service`    — keychain service name (production: `csq-audit-signing`).
/// - `out`        — optional output path. When `None`, writes
///   `csq-audit-bundle-<chain_id>-<exp_id>.tar` to the current working
///   directory.
/// - `_since`/`_until` — accepted for CLI-surface stability; the bundle always
///   exports the whole local chain (partial-range export is Phase B per spec 16
///   §16.10, mirroring `csq audit verify --since` being a no-op today).
///
/// # Pre-flight
///
/// Runs [`verify_chain`] before packaging. If the local chain does not verify,
/// returns [`ExportError::PreflightFailed`] and writes nothing — a bundle that
/// fails locally cannot verify for an external auditor.
pub fn export_bundle(
    base_dir: &Path,
    service: &str,
    out: Option<&Path>,
    since: Option<&str>,
    until: Option<&str>,
) -> Result<ExportSummary, ExportError> {
    // ── Forward-compat flag honesty (spec 16 §16.10) ───────────────────────
    // `--since`/`--until` are accepted for CLI-surface stability but NOT yet
    // applied; the WHOLE local chain is exported. Warn the operator so the
    // flags never silently no-op. Partial-range export is Phase B.
    if since.is_some() || until.is_some() {
        eprintln!(
            "WARN: --since/--until are accepted for forward-compatibility but \
NOT yet applied — exporting the WHOLE chain (partial-range export is Phase B)"
        );
    }

    // ── Load chain identity ────────────────────────────────────────────────
    let chain_state = ChainState::load(base_dir)?;
    if chain_state.chain_id.is_empty() {
        return Err(ExportError::EmptyChain);
    }
    let chain_id = chain_state.chain_id.clone();
    let csq_runs = base_dir.join("csq-runs");
    let jsonl_path = csq_runs.join(format!("{chain_id}.jsonl"));
    if !jsonl_path.exists() {
        return Err(ExportError::EmptyChain);
    }

    // ── Pre-flight: local verify MUST pass (M05 reuse) ──────────────────────
    let verify_cfg = VerifyConfig {
        record_limit: usize::MAX,
        keychain_service: service.to_string(),
    };
    let summary = verify_chain(base_dir, &verify_cfg, None).map_err(|e| {
        // Use the M05 fixed-vocabulary JSON detail so we never echo tokens.
        let detail = crate::audit::verify::to_json_output(&Err(e));
        let reason = detail
            .failure_detail
            .map(|d| format!("{}: {}", d.kind, d.message))
            .unwrap_or_else(|| "unknown".to_string());
        ExportError::PreflightFailed { reason }
    })?;
    if summary.verified_count == 0 {
        return Err(ExportError::EmptyChain);
    }

    // ── Read the raw chain.jsonl bytes (verbatim, sequence-preserving) ──────
    let chain_jsonl = std::fs::read(&jsonl_path).map_err(|e| ExportError::Io {
        message: format!("read chain.jsonl: {e}"),
    })?;

    // ── Parse records to collect referenced signing keys ────────────────────
    let records: Vec<SignedRecord> = String::from_utf8_lossy(&chain_jsonl)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<SignedRecord>(l).ok())
        .collect();

    // GH #910: a forward-compat record whose EventKind this build does not know
    // does NOT parse as `SignedRecord`, but its Ed25519 signature is still real
    // and verifiable. Its signing key MUST be bundled too, or the exported
    // bundle cannot self-verify that record on a newer reader. Collect the
    // key_ids of any such opaque records so the key-resolution loop below picks
    // them up alongside the typed records' keys.
    let opaque_key_ids: Vec<String> = String::from_utf8_lossy(&chain_jsonl)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| serde_json::from_str::<SignedRecord>(l).is_err())
        .filter_map(|l| serde_json::from_str::<crate::audit::opaque::OpaqueRecord>(l).ok())
        .map(|o| o.key_id.as_str().to_string())
        .collect();

    // ── Resolve the genesis-anchored signing key (signs BUNDLE.lock) ────────
    // The genesis-anchored key is the chain's CURRENT active signing key in the
    // head slot (account = chain_id). It is the key whose public half is the
    // bundle's self-verification anchor (PRIMARY DIRECTIVE 2).
    // File store FIRST, keychain FALLBACK (export is interactive — the keychain
    // prompt, if reached, can be granted by the operator).
    let genesis_key = match crate::audit::key_custody::try_load_signing_key(
        base_dir,
        service,
        &chain_id,
        crate::audit::key_custody::KeySlot::Active,
    ) {
        crate::audit::key_custody::KeyLoadOutcome::Loaded(k) => *k,
        _ => return Err(ExportError::GenesisKeyMissing),
    };
    let genesis_key_id = genesis_key.key_id();
    let genesis_pubkey_hex = hex::encode(genesis_key.public_key().0);

    // ── Build public_keys.json: { genesis, keys: { key_id -> raw_pubkey_hex } }
    // Collect every key_id referenced by a record signature, plus the genesis
    // key, plus every rotation-chain key. Map each to its raw 32-byte pubkey.
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    keys.insert(
        genesis_key_id.as_str().to_string(),
        genesis_pubkey_hex.clone(),
    );

    // Active key's pubkey is also recorded in chain.json; cross-fill from there.
    if let (Some(kid), Some(pk)) = (&chain_state.signing_key_id, &chain_state.pubkey) {
        keys.insert(kid.as_str().to_string(), hex::encode(pk.0));
    }

    // ── Build rotation_chain.json by walking KeyRotate records + historical keys
    // Each KeyRotate payload carries previous_key_id, new_key_id, and the
    // incoming_pubkey — enough for an offline verifier to anchor each key.
    let rotation_chain = build_rotation_chain(&records, &genesis_key_id, &mut keys);

    // Any non-placeholder key_id referenced by a record but still missing a
    // pubkey: try the head slot + historical slots. A key we cannot resolve is
    // a hard error — the bundle must be self-contained.
    let placeholder = format!("ed25519:{}", "0".repeat(64));
    // Typed records' keys + GH #910 opaque (unknown-kind) records' keys — both
    // must be self-contained in the bundle for offline verification.
    let referenced_key_ids = records
        .iter()
        .map(|rec| rec.key_id.as_str())
        .chain(opaque_key_ids.iter().map(String::as_str));
    for kid in referenced_key_ids {
        if kid == placeholder || keys.contains_key(kid) {
            continue;
        }
        if let Some(hexpk) = resolve_pubkey_for_key_id(base_dir, service, &chain_state, kid) {
            keys.insert(kid.to_string(), hexpk);
        } else {
            return Err(ExportError::KeyCustody(KeyCustodyError::Signing(format!(
                "cannot resolve public key for {kid} — outgoing keys must be retained \
                 (see `csq audit rotate-key`); chain is not self-contained for export"
            ))));
        }
    }

    let public_keys_json = serde_json::to_vec_pretty(&serde_json::json!({
        "genesis": genesis_key_id.as_str(),
        "keys": keys,
    }))
    .map_err(|e| ExportError::Serialize {
        message: format!("public_keys.json: {e}"),
    })?;

    let rotation_chain_json =
        serde_json::to_vec_pretty(&rotation_chain).map_err(|e| ExportError::Serialize {
            message: format!("rotation_chain.json: {e}"),
        })?;

    // ── canonical_form_vectors/ — embedded golden vectors (PRIMARY DIR 3) ──
    // Pass the RAW JSONL lines so vectors preserve serde's declaration-order
    // field layout (a round-trip through serde_json::Value would sort object
    // keys and diverge from on-disk bytes).
    let raw_lines: Vec<String> = String::from_utf8_lossy(&chain_jsonl)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|s| s.to_string())
        .collect();
    let (vectors_json, vectors_version) = build_canonical_form_vectors(&raw_lines)?;

    // ── CUTOFF.json — M16 signed export cutoff (spec 16 §16.14) ─────────────
    // Snapshots the chain HEAD (latest_hash, latest_seq) + the most recent
    // external-anchor reference (M14 link) + export_ts, signed by the
    // genesis-anchored key over the §12.13.8 canonical-hash → sign-32-raw-bytes
    // contract. Added to `entries` BELOW so BUNDLE.lock covers it (BUNDLE.sig
    // then protects it from a post-export swap), and it carries its own
    // canonical-form signature so the cutoff tuple is reproducibly verifiable.
    //
    // H-1: the HEAD (latest_hash, latest_seq) is sourced from the LAST RAW
    // `chain.jsonl` line — the exact line the embedded verify script computes
    // its head from — NOT from `records.last()`. `records` is the
    // `SignedRecord`-parsed set, which (like `verify_chain`) SKIPS legacy v1
    // lines; deriving the head from it could diverge from the bundled raw head
    // and false-FAIL the verifier. `records` is still used for the anchor scan
    // (v1 records carry no ReplicationAck, so the skip is correct there).
    let export_ts = crate::audit::persist::current_iso8601_utc_persist();
    let head_line = raw_lines.last().ok_or(ExportError::EmptyChain)?;
    let head_value: serde_json::Value =
        serde_json::from_str(head_line).map_err(|e| ExportError::Serialize {
            message: format!("chain head line is not valid JSON: {e}"),
        })?;
    let latest_seq = head_value
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ExportError::Serialize {
            message: "chain head line missing a numeric `seq` field".to_string(),
        })?;
    let latest_hash = head_value
        .get("canonical_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ExportError::Serialize {
            message: "chain head line missing a string `canonical_hash` field".to_string(),
        })?
        .to_string();
    let cutoff_json = crate::audit::cutoff::build_cutoff_json(
        &chain_id,
        &latest_hash,
        latest_seq,
        &records,
        &export_ts,
        &genesis_key_id,
        &genesis_key,
    )
    .map_err(|e| ExportError::Cutoff(e.to_string()))?;

    // ── PROVENANCE.json — M21 governance provenance lane (spec 16 §16.15) ───
    // A seq-ordered, auditor-consumable projection of every `ProvenanceAnchored`
    // chain record (actor/backing/trust/authority/words_hash). Built from the
    // SAME parsed `records` the chain walk verifies, added to `entries` BELOW so
    // BUNDLE.lock covers it (BUNDLE.sig then protects it from a post-export
    // swap). The embedded verify script cross-checks the lane is a FAITHFUL +
    // COMPLETE projection of the chain's provenance records (§16.15), turning it
    // from an unverified hint into a trustworthy derived view. The verbatim
    // `human_words` are NEVER present — the lane carries only `words_hash`
    // (HIGH-1; the chain itself never stores the words, types.rs:1427).
    let (provenance_json, prov_count, prov_unbacked) = build_provenance_lane(&records, &chain_id)?;

    // ── Assemble bundle entries (path → bytes) ──────────────────────────────
    // BUNDLE.lock and BUNDLE.sig are computed AFTER the other entries.
    let mut entries: Vec<(String, Vec<u8>, u32)> = vec![
        // T3.6 — auditor honest-host-grade trust notice. Placed in `entries`
        // BEFORE BUNDLE.lock/BUNDLE.sig are computed below, so the caveat is
        // hashed into the lock and covered by the genesis signature (a tampered
        // or stripped README fails the embedded verifier). Spec 15 §15.4
        // (honest-host-caveat subsection: §15.4.4 enterprise / §15.4.3 community).
        (
            "README.md".to_string(),
            README_NOTICE.as_bytes().to_vec(),
            0o644,
        ),
        ("chain.jsonl".to_string(), chain_jsonl.clone(), 0o644),
        ("public_keys.json".to_string(), public_keys_json, 0o644),
        (
            "rotation_chain.json".to_string(),
            rotation_chain_json,
            0o644,
        ),
        (
            "canonical_form_vectors/VERSION".to_string(),
            vectors_version.into_bytes(),
            0o644,
        ),
        (
            "canonical_form_vectors/vectors.json".to_string(),
            vectors_json,
            0o644,
        ),
        ("CUTOFF.json".to_string(), cutoff_json, 0o644),
        ("PROVENANCE.json".to_string(), provenance_json, 0o644),
        (
            "verify".to_string(),
            VERIFY_SCRIPT.as_bytes().to_vec(),
            0o755,
        ),
    ];

    // ── BUNDLE.lock: "<sha256>  <relpath>\n" sorted by path ────────────────
    let mut lock_rows: Vec<(String, String)> = entries
        .iter()
        .map(|(path, bytes, _)| (path.clone(), sha256_hex(bytes)))
        .collect();
    lock_rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut lock = String::new();
    for (path, hash) in &lock_rows {
        lock.push_str(hash);
        lock.push_str("  ");
        lock.push_str(path);
        lock.push('\n');
    }
    let lock_bytes = lock.into_bytes();

    // ── BUNDLE.sig: Ed25519 over BUNDLE.lock by the genesis key ────────────
    let sig = genesis_key.sign(&lock_bytes).map_err(|e| {
        ExportError::KeyCustody(KeyCustodyError::Signing(format!("sign lock: {e}")))
    })?;
    let sig_bytes = sig.0.to_vec();

    entries.push(("BUNDLE.lock".to_string(), lock_bytes, 0o644));
    entries.push(("BUNDLE.sig".to_string(), sig_bytes, 0o644));

    // ── Serialize the tar archive (stdlib USTAR, no new crate) ─────────────
    // Sort entries by path for a deterministic archive layout.
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let tar_bytes = tar::build_tar(&entries);

    // ── Resolve output path ─────────────────────────────────────────────────
    let exp_id = crate::audit::persist::gen_run_id();
    let bundle_name = format!("csq-audit-bundle-{chain_id}-{exp_id}.tar");
    let bundle_path = match out {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()
            .map_err(|e| ExportError::Io {
                message: format!("cwd: {e}"),
            })?
            .join(&bundle_name),
    };

    // ── §5a write: unique_tmp → write → secure_file → atomic_replace ───────
    write_bundle_atomic(&bundle_path, &tar_bytes)?;

    Ok(ExportSummary {
        bundle_path,
        record_count: summary.verified_count,
        key_count: keys.len(),
        provenance_record_count: prov_count,
        provenance_unbacked_count: prov_unbacked,
    })
}

/// §5a-compliant bundle write with tmp cleanup on every failure branch.
fn write_bundle_atomic(bundle_path: &Path, tar_bytes: &[u8]) -> Result<(), ExportError> {
    if let Some(parent) = bundle_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| ExportError::Io {
                message: format!("create out dir: {e}"),
            })?;
        }
    }
    let tmp = unique_tmp_path(bundle_path);
    if let Err(e) = std::fs::write(&tmp, tar_bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ExportError::Io {
            message: format!("write bundle tmp: {e}"),
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ExportError::Io {
            message: format!("secure bundle tmp: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, bundle_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ExportError::Io {
            message: format!("atomic replace bundle: {e}"),
        });
    }
    Ok(())
}

/// Walk KeyRotate records to build the rotation chain and harvest pubkeys.
///
/// The emitted `anchor_key_id` is the chain's genesis-ANCHORED signing key —
/// the current active head key whose public half is the bundle's
/// self-verification anchor (it signs `BUNDLE.sig`). It is named `anchor_key_id`
/// (not `genesis_key_id`) because for a chain that has rotated keys it is the
/// HEAD key, not the original genesis key; the `entries` list carries the
/// rotation history back through prior keys. Producer + verify-script consumer
/// MUST agree on this field name.
fn build_rotation_chain(
    records: &[SignedRecord],
    anchor_key_id: &KeyId,
    keys: &mut BTreeMap<String, String>,
) -> serde_json::Value {
    use crate::audit::types::EventPayload;
    let mut entries = Vec::new();
    for rec in records {
        if let EventPayload::KeyRotate(p) = &rec.payload {
            // Record the incoming pubkey (carried in the payload for offline use).
            let incoming_hex = hex::encode(p.incoming_pubkey.0);
            // Only record if it is a real (non-zero) pubkey.
            if incoming_hex != "0".repeat(64) {
                keys.insert(p.new_key_id.as_str().to_string(), incoming_hex);
            }
            entries.push(serde_json::json!({
                "previous_key_id": p.previous_key_id.as_str(),
                "new_key_id": p.new_key_id.as_str(),
                "rotation_reason": p.rotation_reason.to_string(),
            }));
        }
    }
    serde_json::json!({
        "anchor_key_id": anchor_key_id.as_str(),
        "entries": entries,
    })
}

/// Resolve a raw-pubkey hex for `key_id` from the head slot or historical slots.
/// File store FIRST, keychain FALLBACK, per slot.
fn resolve_pubkey_for_key_id(
    base_dir: &Path,
    service: &str,
    chain_state: &ChainState,
    key_id: &str,
) -> Option<String> {
    use crate::audit::key_custody::{try_load_signing_key, KeyLoadOutcome, KeySlot};
    let chain_id = &chain_state.chain_id;
    let mut slots: Vec<KeySlot> = vec![KeySlot::Active];
    for i in 0..=chain_state.rotation_count {
        slots.push(KeySlot::Historical(i));
    }
    for slot in slots {
        if let KeyLoadOutcome::Loaded(k) = try_load_signing_key(base_dir, service, chain_id, slot) {
            if k.key_id().as_str() == key_id {
                return Some(hex::encode(k.public_key().0));
            }
        }
    }
    None
}

/// Maximum number of golden vectors embedded. The self-check covers one vector
/// per distinct record SHAPE (payload kind × EATP-field presence); this cap
/// bounds the embed even if a future schema grows the shape space beyond the
/// 14 event kinds × EATP-present/absent combinations.
const MAX_CANONICAL_FORM_VECTORS: usize = 64;

/// Compute a stable SHAPE key for a record: its `payload.kind` plus which EATP
/// optional fields are present. Two records with the same shape key exercise
/// the SAME canonical-form reproduction path in the verifier, so one golden
/// vector per shape suffices to gate every distinct shape in the chain.
fn record_shape_key(rec: &SignedRecord) -> String {
    let kind = rec.payload.kind();
    // serde snake_case discriminant via Debug is stable enough for a dedup key;
    // append EATP-field presence flags so an EATP-bearing record of the same
    // payload kind is treated as a DISTINCT shape (its optional fields change
    // the canonical pre-image).
    format!(
        "{kind:?}|actor={}|authority={}|trust={}|estart={}|eend={}",
        rec.actor.is_some(),
        rec.authority.is_some(),
        rec.trust.is_some(),
        rec.eatp_start_ts.is_some(),
        rec.eatp_end_ts.is_some(),
    )
}

/// Build the embedded canonical-form golden vectors.
///
/// Returns `(vectors.json bytes, VERSION string)`. Vectors are (record →
/// canonical_hash) pairs the verify script self-checks against before trusting
/// its canonical-form reproduction. We embed ONE golden vector per distinct
/// record SHAPE (payload kind × EATP-field presence) present in the exported
/// chain — capped at [`MAX_CANONICAL_FORM_VECTORS`] — so EVERY shape the
/// verifier will encounter on real records is self-checked first. (The earlier
/// `.take(3)` form only gated the first three records, leaving an EATP-payload
/// record beyond record 3 with its shape never self-checked.)
///
/// The `record_json` field embeds the VERBATIM on-disk record line as a JSON
/// string, NOT a parsed object: a round-trip through `serde_json::Value` backs
/// objects with a sorted `BTreeMap`, which would reorder the `payload` enum's
/// `{"kind","data"}` fields away from serde's declaration order and diverge
/// from what the verifier parses from chain.jsonl. The verify script does
/// `json.loads(record_json)` (Python preserves insertion order) to recover the
/// exact on-disk field layout.
fn build_canonical_form_vectors(raw_lines: &[String]) -> Result<(Vec<u8>, String), ExportError> {
    use std::collections::BTreeSet;
    let version = crate::audit::persist::AUDIT_SCHEMA_VERSION.to_string();
    let mut vectors = Vec::new();
    let mut seen_shapes: BTreeSet<String> = BTreeSet::new();
    for line in raw_lines {
        if vectors.len() >= MAX_CANONICAL_FORM_VECTORS {
            // Cap reached: keep scanning to count how many DISTINCT shapes the
            // chain actually contains so the truncation warn can name the true
            // shape-space size, then surface a single WARN and stop emitting.
            // (Dedup + emission logic below is unchanged; this branch only
            // measures and reports — no silent cap.)
            for tail in raw_lines {
                if let Ok(r) = serde_json::from_str::<SignedRecord>(tail) {
                    seen_shapes.insert(record_shape_key(&r));
                }
            }
            eprintln!(
                "WARN: audit export canonical-form self-check truncated — \
                 {} distinct record shapes found, cap is {}; coverage limited \
                 to the first {} shapes (shapes beyond the cap are not \
                 self-checked before chain verification)",
                seen_shapes.len(),
                MAX_CANONICAL_FORM_VECTORS,
                MAX_CANONICAL_FORM_VECTORS,
            );
            break;
        }
        let rec: SignedRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let shape = record_shape_key(&rec);
        if !seen_shapes.insert(shape.clone()) {
            // Shape already covered by an earlier vector — dedup.
            continue;
        }
        // Recompute the canonical_hash from content (genesis-sentinel form),
        // exactly as the verifier will.
        let mut for_hash = rec.clone();
        for_hash.canonical_hash = crate::audit::types::Sha256Hex::genesis();
        let canonical = canonical_bytes_for(&for_hash);
        let canonical_hash = sha256_hex(&canonical);
        vectors.push(serde_json::json!({
            "name": format!("shape_{}", vectors.len()),
            "shape_key": shape,
            "record_json": line,
            "canonical_hash": canonical_hash,
        }));
    }
    let doc = serde_json::json!({
        "canonical_form_version": version,
        "description": "Golden (record -> canonical_hash) vectors, one per \
    distinct record shape (payload kind x EATP-field presence). The verify \
    script recomputes sha256(canonical_bytes(record)) and asserts equality before \
    verifying any chain record.",
        "vectors": vectors,
    });
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| ExportError::Serialize {
        message: format!("canonical_form_vectors: {e}"),
    })?;
    Ok((bytes, version))
}

/// Build the `PROVENANCE.json` governance lane (M21, spec 16 §16.15).
///
/// Returns `(bytes, record_count, unbacked_count)`. The lane is a seq-ordered,
/// auditor-consumable projection of every `ProvenanceAnchored` chain record —
/// the deliverable that makes "every co-authored decision in window W, with the
/// authorizing principal and whether it was backed" reconstructable from the
/// bundle ALONE (AC4), without the auditor needing csq's internal record schema.
///
/// # HIGH-1 — redact-then-hash (load-bearing)
///
/// The verbatim `human_words` are NEVER projected. The chain record itself only
/// carries `words_hash = sha256(canonical(words))` (the verbatim words are
/// discarded at ingest, `seam/ingest.rs:324`), so the lane structurally CANNOT
/// leak them: this builder copies only the explicitly-named scalar fields
/// (`words_hash`, `decision_id`, `surface`, `principal`, `backing`, …) — never a
/// free-text body. The verify script asserts no `human_words` key is present
/// (§16.15) so a tampered lane that injected verbatim text FAILs.
///
/// # Backing (AC5)
///
/// Each record's `backing` comes from its `actor` attestation
/// (`{"principal": …, "backing": "verified"|"unbacked"}`). A record whose
/// backing is anything other than `"verified"` (including a missing/absent
/// actor) counts as unbacked and is flagged in `unbacked_count`.
///
/// # Authority
///
/// `authority` projects the record's PACT-D authority slot verbatim, or `null`.
/// Seam-ingested provenance records carry `null` here — the seam attests
/// authorship via `actor`/`trust` (`build_seam_record` sets `authority: None`),
/// not a PACT-D delegation grant. The slot is projected as-is so a record that
/// DOES carry authority is surfaced faithfully.
fn build_provenance_lane(
    records: &[SignedRecord],
    chain_id: &str,
) -> Result<(Vec<u8>, u64, u64), ExportError> {
    use crate::audit::types::{EventKind, EventPayload};
    let mut lane: Vec<serde_json::Value> = Vec::new();
    let mut unbacked: u64 = 0;
    for rec in records {
        if rec.kind != EventKind::ProvenanceAnchored {
            continue;
        }
        let EventPayload::ProvenanceAnchored(p) = &rec.payload else {
            // kind/payload disagreement — skip; the chain walk (Step 5) would
            // already have rejected such a record, so this is defensive only.
            continue;
        };
        // actor slot: { "principal": <redacted str>, "backing": "verified"|"unbacked", ... }
        let (principal, backing) = match &rec.actor {
            Some(a) => (
                a.0.get("principal")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                a.0.get("backing")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
            ),
            None => (None, None),
        };
        // Fail-closed accounting: anything that is not explicitly "verified" is
        // unbacked (a missing actor / missing backing field counts as unbacked).
        let backing = backing.unwrap_or_else(|| "unbacked".to_string());
        if backing != "verified" {
            unbacked += 1;
        }
        let trust_level = rec.trust.as_ref().and_then(|t| {
            t.0.get("level")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
        let authority = rec
            .authority
            .as_ref()
            .map(|a| a.0.clone())
            .unwrap_or(serde_json::Value::Null);
        // HIGH-2: mirror the chain's OperatorRefRecord serialization —
        // `display_id` is `skip_serializing_if = Option::is_none` on the chain
        // record, so the lane MUST also omit the key when `None`. A `null` in
        // the lane vs an absent key in the chain causes the verifier's
        // whole-object comparison to FAIL honest bundles (null != absent).
        let operator_ref_json = p.operator_ref.as_ref().map(|o| {
            let mut map = serde_json::Map::new();
            map.insert(
                "verified_id".to_string(),
                serde_json::Value::String(o.verified_id.clone()),
            );
            map.insert(
                "person_id".to_string(),
                serde_json::Value::String(o.person_id.clone()),
            );
            if let Some(ref did) = o.display_id {
                map.insert(
                    "display_id".to_string(),
                    serde_json::Value::String(did.clone()),
                );
            }
            serde_json::Value::Object(map)
        });
        lane.push(serde_json::json!({
            "seq": rec.seq,
            "record_id": rec.record_id.as_str(),
            "decision_id": p.decision_id,
            "surface": p.surface,
            "claimed_decision_ts": p.claimed_decision_ts,
            "principal": principal,
            "backing": backing,
            "trust_level": trust_level,
            "authority": authority,
            "f101_schema_version": p.f101_schema_version,
            "words_hash": p.words_hash.as_ref().map(|h| h.as_str()),
            "received_bytes_hash": p.received_bytes_hash.as_str(),
            "ordering_basis": p.ordering_basis,
            "predecessor_missing": p.predecessor_missing,
            "prev_link": p.prev_link,
            "kind": p.kind,
            "session": p.session,
            "operator_ref": operator_ref_json,
        }));
    }
    // chain.jsonl is already seq-ordered; sort defensively so the lane order is
    // deterministic (the chain-authoritative order, F-SEAM-04) regardless of
    // input ordering.
    lane.sort_by_key(|v| {
        v.get("seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    });
    let record_count = lane.len() as u64;
    let doc = serde_json::json!({
        "provenance_version": "1",
        "chain_id": chain_id,
        "description": "Governance provenance lane: one entry per ProvenanceAnchored \
    chain record, in chain-authoritative seq order. `claimed_decision_ts` is loom's \
    EVIDENCE-ONLY timestamp; `seq` is the authoritative order. `words_hash` commits to \
    the human words WITHOUT exposing them (HIGH-1 redact-then-hash). `backing` is the \
    per-developer authorship attestation status; `unbacked_count` flags claims that \
    lacked a verified per-dev key.",
        "record_count": record_count,
        "unbacked_count": unbacked,
        "records": lane,
    });
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| ExportError::Serialize {
        message: format!("PROVENANCE.json: {e}"),
    })?;
    Ok((bytes, record_count, unbacked))
}

// ─────────────────────────────────────────────────────────────────────────────
// Stdlib USTAR tar writer — no third-party crate (independence.md).
// ─────────────────────────────────────────────────────────────────────────────

mod tar {
    //! Minimal POSIX USTAR archive writer using only `std`.
    //!
    //! Produces a plain (uncompressed) `.tar` readable by GNU/BSD `tar` and by
    //! Python's stdlib `tarfile`. Each file is one 512-byte header block + the
    //! content padded to a 512-byte boundary; the archive ends with two zeroed
    //! 512-byte blocks. Directory entries are emitted implicitly by the path
    //! prefix (`canonical_form_vectors/...`); a leading directory member is also
    //! written so `tar tf` lists the directory.

    /// Build a USTAR archive from `(path, bytes, mode)` entries (already sorted).
    pub fn build_tar(entries: &[(String, Vec<u8>, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        // Emit a directory member for canonical_form_vectors/ so extractors that
        // require explicit dir entries (older tar) create it. Idempotent for
        // Python tarfile, which creates parents anyway.
        if entries
            .iter()
            .any(|(p, _, _)| p.starts_with("canonical_form_vectors/"))
        {
            write_header(&mut out, "canonical_form_vectors/", 0, 0o755, b'5');
            // No content blocks for a directory.
        }
        for (path, bytes, mode) in entries {
            write_header(&mut out, path, bytes.len(), *mode, b'0');
            out.extend_from_slice(bytes);
            let pad = (512 - (bytes.len() % 512)) % 512;
            out.extend(std::iter::repeat_n(0u8, pad));
        }
        // Two zeroed blocks terminate the archive.
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    /// Write a single 512-byte USTAR header block.
    fn write_header(out: &mut Vec<u8>, name: &str, size: usize, mode: u32, typeflag: u8) {
        let mut h = [0u8; 512];
        // name[0..100]
        let name_bytes = name.as_bytes();
        let n = name_bytes.len().min(100);
        h[0..n].copy_from_slice(&name_bytes[..n]);
        // mode[100..108] — octal, NUL-terminated.
        write_octal(&mut h[100..108], mode as u64);
        // uid[108..116], gid[116..124] — zero.
        write_octal(&mut h[108..116], 0);
        write_octal(&mut h[116..124], 0);
        // size[124..136] — octal.
        write_octal(&mut h[124..136], size as u64);
        // mtime[136..148] — fixed (2100-01-01 = 4102444800) for determinism /
        // no test time-bombs.
        write_octal(&mut h[136..148], 4_102_444_800);
        // typeflag[156].
        h[156] = typeflag;
        // magic[257..263] = "ustar\0", version[263..265] = "00".
        h[257..263].copy_from_slice(b"ustar\0");
        h[263] = b'0';
        h[264] = b'0';
        // Checksum: compute over the header with chksum field (148..156) as
        // spaces, then write the octal value.
        for b in h.iter_mut().skip(148).take(8) {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        // chksum field: 6 octal digits, NUL, space.
        let chk = format!("{sum:06o}\0 ");
        h[148..148 + chk.len()].copy_from_slice(chk.as_bytes());
        out.extend_from_slice(&h);
    }

    /// Write an octal value into a fixed-width field as `0`-padded digits
    /// followed by a NUL terminator (USTAR numeric field convention).
    fn write_octal(field: &mut [u8], value: u64) {
        let width = field.len();
        // width-1 digits + trailing NUL.
        let digits = width - 1;
        let s = format!("{value:0width$o}", width = digits);
        let sb = s.as_bytes();
        let take = sb.len().min(digits);
        field[..take].copy_from_slice(&sb[sb.len() - take..]);
        field[digits] = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::audit_init;
    use crate::audit::persist::{canonical_bytes_for, sha256_hex};
    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
        SignedRecord,
    };
    use tempfile::TempDir;

    fn svc_name(tag: &str) -> String {
        format!("csq-audit-export-test-{}-{}", std::process::id(), tag)
    }

    /// Build + sign a single genesis record into a fresh chain, returning the
    /// (base_dir tempdir, chain_id, service) so tests can export it.
    fn make_signed_chain(tag: &str) -> (TempDir, String, String) {
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name(tag);
        let chain_id = "01JZ00000000000000000000AA";

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init"); // cutoff = 0

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        let mut record = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000BB").unwrap(),
            chain_id: RecordId::try_new(chain_id).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "export-genesis".to_string(),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: key_id.clone(),
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
        let canonical = canonical_bytes_for(&record);
        record.canonical_hash = Sha256Hex::try_new(sha256_hex(&canonical)).unwrap();
        let digest = {
            let b = hex::decode(record.canonical_hash.as_str()).unwrap();
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };
        use crate::audit::traits::SigningKey as _;
        record.signature = signing_key.sign(&digest).unwrap();

        let jsonl = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        std::fs::write(&jsonl, serde_json::to_string(&record).unwrap() + "\n").unwrap();

        (tmp, chain_id.to_string(), svc)
    }

    /// `test python_json_dumps_matches_serde_canonical_form`
    ///
    /// PRIMARY DIRECTIVE 3 keystone: prove that Python's
    /// `json.dumps(separators=(',',':'))` over the verify-script's field order
    /// reproduces `canonical_bytes_for` BYTE-FOR-BYTE for a real signed record.
    /// If this drifts, the verify script cannot reproduce csq's canonical form
    /// and the bundle is unverifiable.
    #[test]
    fn python_json_dumps_matches_serde_canonical_form() {
        // Build a record with the genesis sentinel canonical_hash (the form
        // canonical_bytes_for serializes).
        let mut record = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01JZ00000000000000000000CD").unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000AA").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "parity".to_string(),
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
            op_phase: None,
            verification_level: None,
        };
        record.canonical_hash = Sha256Hex::genesis();
        let rust_canonical = canonical_bytes_for(&record);
        let rust_hash = sha256_hex(&rust_canonical);

        // On-disk JSON of the record (what the verify script parses).
        let rec_json = serde_json::to_string(&record).unwrap();

        // Run a tiny python that reproduces canonical_bytes via the script's logic.
        let py = format!(
            r#"
import json, hashlib
rec = json.loads({rec_json:?})
GENESIS = "0"*64
TOP = ["schema_version","record_id","chain_id","seq","prev_hash","kind","payload","ts","key_id","canonical_hash"]
OPT = ["actor","authority","trust","eatp_start_ts","eatp_end_ts"]
def sortv(v):
    if isinstance(v, dict): return {{k:sortv(v[k]) for k in sorted(v)}}
    if isinstance(v, list): return [sortv(x) for x in v]
    return v
view = {{}}
for f in TOP:
    view[f] = GENESIS if f=="canonical_hash" else rec[f]
for f in OPT:
    if rec.get(f) is not None: view[f]=sortv(rec[f])
b = json.dumps(view, separators=(",",":"), ensure_ascii=False).encode()
print(hashlib.sha256(b).hexdigest())
"#
        );
        let out = std::process::Command::new("python3")
            .arg("-c")
            .arg(&py)
            .output()
            .expect("run python3");
        let py_hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_eq!(
            py_hash, rust_hash,
            "python json.dumps canonical hash must match serde canonical hash byte-for-byte\nrust canonical bytes: {}",
            String::from_utf8_lossy(&rust_canonical)
        );
    }

    /// Build a verbatim on-disk JSONL line for a synthetic record of a given
    /// payload + optional EATP fields. Used by the F3 shape-coverage test; the
    /// signature/canonical_hash need not be valid because
    /// `build_canonical_form_vectors` only reads payload-kind + EATP-presence
    /// and recomputes the canonical_hash from content itself.
    fn synthetic_line(seq: u64, payload: EventPayload, with_eatp: bool) -> String {
        let kind = payload.kind();
        let rec = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(format!("01JZ000000000000000000{seq:04}")).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000AA").unwrap(),
            seq,
            prev_hash: Sha256Hex::genesis(),
            kind,
            payload,
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: with_eatp
                .then(|| crate::audit::types::EatpActor(serde_json::json!({"role": "agent"}))),
            authority: None,
            trust: with_eatp
                .then(|| crate::audit::types::EatpTrust(serde_json::json!({"tier": "T2"}))),
            eatp_start_ts: with_eatp.then(|| "2100-01-01T00:00:00+00:00".to_string()),
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        serde_json::to_string(&rec).unwrap()
    }

    /// `test canonical_form_vectors_cover_eatp_shape_beyond_first_three`
    ///
    /// F3 regression: a chain whose 5th record (index 4, BEYOND the old
    /// `.take(3)` window) carries an EATP payload shape must still have that
    /// shape self-checked. Build 5 records — 4 plain CsqRun + 1 EATP-bearing
    /// AccountSwap at index 4 — and assert the EATP shape's golden vector is
    /// emitted AND self-checks under the verify script's exact logic.
    #[test]
    fn canonical_form_vectors_cover_eatp_shape_beyond_first_three() {
        use crate::audit::types::{AccountSwapPayload, CsqRunPayload};
        // Indices 0..=3: same plain shape (dedups to ONE vector).
        let mut lines: Vec<String> = (0u64..4)
            .map(|i| {
                synthetic_line(
                    i,
                    EventPayload::CsqRun(CsqRunPayload {
                        run_id: format!("run-{i}"),
                    }),
                    false,
                )
            })
            .collect();
        // Index 4: a DISTINCT EATP-bearing shape, beyond the first 3 records.
        lines.push(synthetic_line(
            4,
            EventPayload::AccountSwap(AccountSwapPayload {
                from_slot: crate::types::AccountNum::try_from(1u16).unwrap(),
                to_slot: crate::types::AccountNum::try_from(2u16).unwrap(),
            }),
            true,
        ));

        let (bytes, _ver) = build_canonical_form_vectors(&lines).expect("vectors");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();

        // The EATP-bearing AccountSwap shape MUST be present despite being the
        // 5th record. Find it by shape_key.
        let eatp_vec = vectors.iter().find(|v| {
            let k = v["shape_key"].as_str().unwrap_or("");
            k.contains("AccountSwap") && k.contains("actor=true")
        });
        assert!(
            eatp_vec.is_some(),
            "EATP-bearing shape (record 4) must be self-checked; vectors: {vectors:?}"
        );

        // And self-check it: sha256(canonical_bytes(record_json)) == canonical_hash.
        let v = eatp_vec.unwrap();
        let line = v["record_json"].as_str().unwrap();
        let rec: SignedRecord = serde_json::from_str(line).unwrap();
        let mut for_hash = rec.clone();
        for_hash.canonical_hash = Sha256Hex::genesis();
        let recomputed = sha256_hex(&canonical_bytes_for(&for_hash));
        assert_eq!(
            v["canonical_hash"].as_str().unwrap(),
            recomputed,
            "embedded EATP vector canonical_hash must match recompute"
        );

        // The plain CsqRun shape (indices 0-3) dedups to exactly one vector;
        // total distinct shapes here = 2.
        assert_eq!(
            vectors.len(),
            2,
            "expected 2 distinct shapes (plain CsqRun + EATP AccountSwap), got: {vectors:?}"
        );
    }

    /// `test audit_export_produces_canonical_bundle_shape`
    #[test]
    fn audit_export_produces_canonical_bundle_shape() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("shape");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        let summary = export_bundle(base, &svc, Some(&out), None, None).expect("export");
        assert!(out.exists(), "bundle .tar must exist");
        assert_eq!(summary.record_count, 1);

        // Extract via python tarfile and assert the required entries are present.
        let py = format!(
            r#"
import tarfile, sys
names = set(tarfile.open({:?}).getnames())
required = {{"README.md","chain.jsonl","public_keys.json","rotation_chain.json","CUTOFF.json","PROVENANCE.json","BUNDLE.lock","BUNDLE.sig","verify"}}
missing = required - names
has_vectors = any(n.startswith("canonical_form_vectors/") for n in names)
print("MISSING" if missing else ("NOVEC" if not has_vectors else "OK"))
"#,
            out.to_string_lossy()
        );
        let r = std::process::Command::new("python3")
            .arg("-c")
            .arg(&py)
            .output()
            .expect("python3");
        let verdict = String::from_utf8_lossy(&r.stdout).trim().to_string();
        assert_eq!(verdict, "OK", "bundle shape wrong: {verdict}");

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test bundle_lock_matches_recomputed_sha256_per_file`
    #[test]
    fn bundle_lock_matches_recomputed_sha256_per_file() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("lock");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");

        // Extract and recompute every file's sha256, compare to BUNDLE.lock.
        let extract = base.join("extract");
        extract_tar(&out, &extract);
        let lock = std::fs::read_to_string(extract.join("BUNDLE.lock")).unwrap();
        for line in lock.lines().filter(|l| !l.trim().is_empty()) {
            let (hash, path) = line.split_once("  ").expect("lock line shape");
            let bytes = std::fs::read(extract.join(path)).expect("lock-referenced file exists");
            assert_eq!(
                sha256_hex(&bytes),
                hash,
                "BUNDLE.lock sha256 mismatch for {path}"
            );
        }
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test bundle_readme_present_and_carries_honest_host_caveat`
    ///
    /// T3.6: the exported bundle carries a `README.md` whose content states the
    /// honest-host-grade caveat (the load-bearing auditor-facing invariant — an
    /// auditor must not over-trust a signature-valid bundle as tamper-evident at
    /// the source). Assert presence + the key phrases.
    #[test]
    fn bundle_readme_present_and_carries_honest_host_caveat() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("readme");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let readme = std::fs::read_to_string(extract.join("README.md"))
            .expect("bundle must contain README.md");
        assert!(
            readme.contains("honest-host grade"),
            "README.md must state the honest-host-grade caveat; got: {readme}"
        );
        assert!(
            readme.contains("external witness"),
            "README.md must name the external-witness corroboration; got: {readme}"
        );
        assert!(
            readme.contains("verification_level"),
            "README.md must warn against over-trusting any verification_level; got: {readme}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test bundle_readme_covered_by_bundle_lock`
    ///
    /// T3.6: the caveat is tamper-evident because `README.md` is hashed into
    /// `BUNDLE.lock` (which `BUNDLE.sig` then signs). Assert the lock carries a
    /// row for `README.md` whose SHA-256 matches the extracted bytes — the
    /// integrity anchor the adversarial tests below rely on.
    #[test]
    fn bundle_readme_covered_by_bundle_lock() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("readme_lock");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let lock = std::fs::read_to_string(extract.join("BUNDLE.lock")).unwrap();
        let readme_bytes = std::fs::read(extract.join("README.md")).unwrap();
        let expected = sha256_hex(&readme_bytes);
        let row = lock
            .lines()
            .find(|l| l.ends_with("  README.md"))
            .expect("BUNDLE.lock must carry a README.md row");
        let (hash, _path) = row.split_once("  ").expect("lock line shape");
        assert_eq!(
            hash, expected,
            "BUNDLE.lock README.md hash must match the extracted README.md bytes"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test bundle_sig_verifies_via_embedded_public_keys`
    #[test]
    fn bundle_sig_verifies_via_embedded_public_keys() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("sig");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");

        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Load BUNDLE.lock + BUNDLE.sig + public_keys.json[genesis] and verify
        // the Ed25519 signature with ed25519-dalek directly (the same check the
        // python verifier does via openssl).
        let lock = std::fs::read(extract.join("BUNDLE.lock")).unwrap();
        let sig = std::fs::read(extract.join("BUNDLE.sig")).unwrap();
        assert_eq!(sig.len(), 64);
        let pk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(extract.join("public_keys.json")).unwrap())
                .unwrap();
        let genesis_kid = pk["genesis"].as_str().unwrap();
        let pubhex = pk["keys"][genesis_kid].as_str().unwrap();
        let pubbytes: [u8; 32] = hex::decode(pubhex).unwrap().try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubbytes).unwrap();
        let sig_arr: [u8; 64] = sig.try_into().unwrap();
        let dsig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify_strict(&lock, &dsig)
            .expect("BUNDLE.sig must verify against embedded genesis pubkey");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test export_refuses_unverifiable_chain`
    ///
    /// Tamper a record before export; pre-flight verify must fail and NO bundle
    /// is written (PreflightFailed).
    #[test]
    fn export_refuses_unverifiable_chain() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, chain_id, svc) = make_signed_chain("preflight");
        let base = tmp.path();
        // Tamper the on-disk record's signature.
        let jsonl = base.join("csq-runs").join(format!("{chain_id}.jsonl"));
        let content = std::fs::read_to_string(&jsonl).unwrap();
        let tampered = content.replace("export-genesis", "attacker-injected");
        std::fs::write(&jsonl, tampered).unwrap();

        let out = base.join("bundle.tar");
        let result = export_bundle(base, &svc, Some(&out), None, None);
        assert!(
            matches!(result, Err(ExportError::PreflightFailed { .. })),
            "export must refuse a chain that does not verify locally, got {result:?}"
        );
        assert!(
            !out.exists(),
            "no bundle must be written on pre-flight failure"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, &chain_id);
    }

    /// `test export_empty_chain_errors`
    #[test]
    fn export_empty_chain_errors() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let result = export_bundle(tmp.path(), "csq-audit-export-empty", None, None, None);
        assert!(
            matches!(result, Err(ExportError::EmptyChain)),
            "empty chain must error, got {result:?}"
        );
    }

    /// `test canonical_form_vectors_self_check_matches`
    ///
    /// The embedded vectors must each satisfy
    /// sha256(canonical_bytes(record)) == stored canonical_hash, computed by
    /// the SAME python logic the verify script uses.
    #[test]
    fn canonical_form_vectors_self_check_matches() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("vectors");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let py = format!(
            r#"
import json, hashlib, sys
doc = json.load(open({:?}))
GENESIS="0"*64
TOP=["schema_version","record_id","chain_id","seq","prev_hash","kind","payload","ts","key_id","canonical_hash"]
OPT=["actor","authority","trust","eatp_start_ts","eatp_end_ts"]
def sortv(v):
    if isinstance(v,dict): return {{k:sortv(v[k]) for k in sorted(v)}}
    if isinstance(v,list): return [sortv(x) for x in v]
    return v
for vec in doc["vectors"]:
    rec=json.loads(vec["record_json"]); view={{}}
    for f in TOP: view[f]=GENESIS if f=="canonical_hash" else rec[f]
    for f in OPT:
        if rec.get(f) is not None: view[f]=sortv(rec[f])
    b=json.dumps(view,separators=(",",":"),ensure_ascii=False).encode()
    got=hashlib.sha256(b).hexdigest()
    if got!=vec["canonical_hash"]:
        print("MISMATCH got="+got+" want="+vec["canonical_hash"]+" canon="+b.decode()); sys.exit(0)
print("OK")
"#,
            extract
                .join("canonical_form_vectors/vectors.json")
                .to_string_lossy()
        );
        let r = std::process::Command::new("python3")
            .arg("-c")
            .arg(&py)
            .output()
            .expect("python3");
        assert_eq!(
            String::from_utf8_lossy(&r.stdout).trim(),
            "OK",
            "canonical_form_vectors self-check failed under verify-script logic"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    // ── verify-script harness tests (Unix-gated) ──────────────────────────
    //
    // The exported bundle AND its `verify` script are fully cross-platform:
    // the script is pure Python-3 stdlib (`hashlib`, `json`, `base64`,
    // `urllib`, hand-rolled Ed25519) and a Windows auditor verifies a bundle
    // by running `python3 verify` directly. The `#[cfg(unix)]` gate below is
    // ONLY on the TEST's shell-isolation harness — `run_verify` hardens the
    // child PATH to `/usr/bin:/bin` (proving no csq on PATH) and relies on
    // shebang (`#!/usr/bin/env python3`) execution of `./verify`. Neither
    // construct exists on Windows (no `/usr/bin/python3`, shebangs don't
    // execute), so the harness — not the artifact — is what's Unix-specific.
    // The producer-side export tests (bundle shape, lock, sig, canonical
    // vectors) do NOT spawn the script and run on every platform.

    /// Run the bundle's extracted `./verify` script with a hardened PATH
    /// (`/usr/bin:/bin`) so the test proves the script works with NO csq on
    /// PATH. Returns `(exit_code, stdout)`.
    #[cfg(unix)]
    fn run_verify(extract_dir: &Path, extra_args: &[&str]) -> (i32, String) {
        let verify = extract_dir.join("verify");
        // Ensure the script is executable (tar preserves 0o755, but be defensive).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&verify, std::fs::Permissions::from_mode(0o755));
        }
        let mut cmd = std::process::Command::new(&verify);
        cmd.args(extra_args)
            .current_dir(extract_dir)
            .env("PATH", "/usr/bin:/bin");
        let out = cmd.output().expect("run ./verify");
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        (code, stdout)
    }

    /// `test verify_script_passes_clean_bundle_without_csq`
    ///
    /// Produce a bundle, extract it, run `./verify` with `PATH=/usr/bin:/bin`
    /// (no csq binary reachable), assert exit 0 + a PASS line. This is the
    /// load-bearing cross-org acceptance criterion.
    #[test]
    #[cfg(unix)]
    fn verify_script_passes_clean_bundle_without_csq() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("verify_clean");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(
            code, 0,
            "verify must exit 0 on a clean bundle; stdout: {stdout}"
        );
        assert!(
            stdout.contains("PASS: chain verified end-to-end"),
            "expected PASS line, got: {stdout}"
        );
        // --rekor absent → WARN line, still PASS.
        assert!(
            stdout.contains("WARN: --rekor not passed"),
            "expected --rekor-absent WARN, got: {stdout}"
        );
        // F4: PASS output MUST carry the out-of-band genesis-key trust NOTE.
        assert!(
            stdout.contains("NOTE: trust requires the genesis public key")
                && stdout.contains("confirmed out-of-band"),
            "expected out-of-band genesis-key NOTE on PASS, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_tampered_readme`
    ///
    /// T3.6 adversarial (in-transit tamper): an attacker WITHOUT the genesis key
    /// who weakens the honest-host caveat in `README.md` — but cannot re-sign
    /// `BUNDLE.sig` — is caught. The README's SHA-256 in `BUNDLE.lock` no longer
    /// matches, so the verify script FAILs at Step 2 naming the tampered file.
    /// Proves the caveat is tamper-evident, not advisory decoration.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_tampered_readme() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("readme_tamper");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Weaken the caveat WITHOUT re-locking/re-signing (attacker has no key).
        std::fs::write(
            extract.join("README.md"),
            "These attestations are fully tamper-evident. Trust them.\n",
        )
        .unwrap();

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must FAIL on a tampered README.md; stdout: {stdout}"
        );
        assert!(
            stdout.contains("README.md") && stdout.contains("tampered"),
            "FAIL must name the tampered README.md; got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_stripped_readme`
    ///
    /// T3.6 adversarial (strip the caveat): removing `README.md` entirely leaves
    /// its row in the signed `BUNDLE.lock`, so the verify script FAILs — either
    /// on the `required`-file presence check or on the "BUNDLE.lock references
    /// missing file" Step-2 check. An honest exporter cannot silently drop the
    /// caveat and still produce a passing bundle.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_stripped_readme() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("readme_strip");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Strip the caveat WITHOUT re-locking/re-signing.
        std::fs::remove_file(extract.join("README.md")).unwrap();

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must FAIL on a stripped README.md; stdout: {stdout}"
        );
        assert!(
            stdout.contains("README.md"),
            "FAIL must name the missing README.md; got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_decoy_unlocked_file`
    ///
    /// T3.6 adversarial (decoy shadow): the honest, lock-covered `README.md` is
    /// left byte-intact (so Step 1 + Step 2 pass), but an attacker WITHOUT the
    /// genesis key drops a sibling `README` (no `.md`) — the file an auditor's
    /// `less README*` reflex reads first — claiming the attestations are fully
    /// tamper-evident. The Step-2b extra-file guard rejects any file not in the
    /// signed `BUNDLE.lock`, so `verify` FAILs naming the decoy. Proves the
    /// caveat cannot be socially defeated by an unlocked shadow file.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_decoy_unlocked_file() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("readme_decoy");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Honest README.md is untouched; drop an unlocked decoy beside it.
        std::fs::write(
            extract.join("README"),
            "These attestations are fully tamper-evident. Trust them unconditionally.\n",
        )
        .unwrap();

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must FAIL on an unlocked decoy file; stdout: {stdout}"
        );
        assert!(
            stdout.contains("not covered by BUNDLE.lock") && stdout.contains("README"),
            "FAIL must name the decoy as uncovered by BUNDLE.lock; got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_symlinked_decoy`
    ///
    /// T3.6 adversarial (symlink evasion): an attacker plants a symlink into the
    /// extracted bundle. The Step-2b walk rejects any symlink fail-closed —
    /// otherwise a decoy hidden behind a symlinked directory would escape the
    /// files-only enumeration. Honest bundles (stdlib USTAR writer) carry no
    /// symlinks, so any symlink is a post-export plant.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_symlinked_decoy() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("readme_symlink");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Plant a symlink beside the honest, lock-covered files.
        std::os::unix::fs::symlink(extract.join("README.md"), extract.join("READ-ME-FIRST"))
            .unwrap();

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must FAIL on a planted symlink; stdout: {stdout}"
        );
        assert!(
            stdout.contains("symlink"),
            "FAIL must name the symlink rejection; got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_validates_provenance_lane`
    ///
    /// AC4/AC5: the embedded verifier cross-checks PROVENANCE.json against the
    /// signed chain and surfaces the decision + unbacked counts on the PASS
    /// line, so an auditor running ONLY `./verify` (no csq) reconstructs the
    /// provenance lane and sees the UNBACKED flag.
    #[test]
    #[cfg(unix)]
    fn verify_script_validates_provenance_lane() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![
            provenance_fixture("dec-backed", "codex", 1, "alice@example.test", true, None),
            provenance_fixture("dec-unbacked", "cc", 2, "bob@example.test", false, None),
        ];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("verify_prov_lane", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(
            code, 0,
            "verify must PASS on a clean lane; stdout: {stdout}"
        );
        assert!(
            stdout.contains("provenance lane: 2 decision(s), 1 unbacked"),
            "PASS line must surface the provenance lane counts, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_dropped_provenance_lane_record`
    ///
    /// FAITHFULNESS (independent of BUNDLE.lock): an exporter who drops a
    /// provenance record from PROVENANCE.json — then honestly re-locks +
    /// re-signs (still holding the genesis key) — produces a bundle that passes
    /// Step 1+2 but FAILs the lane-faithfulness cross-check (a chain provenance
    /// record has no lane entry). This proves the check is load-bearing on top
    /// of the lock, not subsumed by it.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_dropped_provenance_lane_record() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![
            provenance_fixture("dec-1", "codex", 1, "alice@example.test", true, None),
            provenance_fixture("dec-2", "cc", 2, "bob@example.test", false, None),
        ];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("verify_prov_drop", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Drop the second lane record (but it remains in the signed chain).
        let mut prov = read_provenance(&extract);
        let recs = prov["records"].as_array().unwrap().clone();
        prov["records"] = serde_json::Value::Array(vec![recs[0].clone()]);
        prov["record_count"] = serde_json::json!(1);
        prov["unbacked_count"] = serde_json::json!(0);
        std::fs::write(
            extract.join("PROVENANCE.json"),
            serde_json::to_vec_pretty(&prov).unwrap(),
        )
        .unwrap();
        // Honest re-lock + re-sign so Step 1+2 pass and the faithfulness check fires.
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must FAIL on a dropped lane record; stdout: {stdout}"
        );
        assert!(
            stdout.contains("not a faithful projection"),
            "FAIL must name the faithfulness mismatch, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_tampered_ordering_basis`
    ///
    /// MEDIUM-2 load-bearing: the lane's `ordering_basis` is cross-checked
    /// against the signed chain, so a tampered lane that relabels a
    /// wall-clock-ordered span (flips `ordering_basis` to null) FAILs the
    /// verifier even when honestly re-locked + re-signed.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_tampered_ordering_basis() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![provenance_fixture_ordered(
            "dec-ordered",
            1,
            Some("wallclock_skew_bounded"),
            Some(true),
        )];
        let (tmp, _chain_id, svc) =
            make_chain_with_attested_records("verify_prov_ordering", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Relabel the wall-clock-ordered span as if causally ordered.
        let mut prov = read_provenance(&extract);
        prov["records"][0]["ordering_basis"] = serde_json::Value::Null;
        std::fs::write(
            extract.join("PROVENANCE.json"),
            serde_json::to_vec_pretty(&prov).unwrap(),
        )
        .unwrap();
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must FAIL on tampered ordering_basis; stdout: {stdout}"
        );
        assert!(
            stdout.contains("field 'ordering_basis'"),
            "FAIL must name the ordering_basis mismatch, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_verbatim_words_in_lane`
    ///
    /// HIGH-1 structural: a tampered lane that injects a verbatim `human_words`
    /// key FAILs at the verifier even when honestly re-locked + re-signed.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_verbatim_words_in_lane() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![provenance_fixture(
            "dec-1",
            "codex",
            1,
            "alice@example.test",
            true,
            Some(&sha256_hex(b"some words")),
        )];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("verify_prov_words", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Inject a verbatim human_words key into the lane record.
        let mut prov = read_provenance(&extract);
        prov["records"][0]["human_words"] =
            serde_json::json!("the verbatim text that must never appear");
        std::fs::write(
            extract.join("PROVENANCE.json"),
            serde_json::to_vec_pretty(&prov).unwrap(),
        )
        .unwrap();
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must FAIL on verbatim words in lane; stdout: {stdout}"
        );
        assert!(
            stdout.contains("HIGH-1 redact-then-hash violated"),
            "FAIL must name the HIGH-1 violation, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_tampered_chain_record`
    ///
    /// Flip a byte of the chain record's signature inside the extracted bundle,
    /// re-tar, run `./verify`; assert FAIL naming the record_id.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_tampered_chain_record() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("verify_tamper_rec");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Tamper the chain record's signature (flip first hex pair), then
        // recompute BUNDLE.lock + re-sign is NOT done — but we must keep
        // BUNDLE.lock matching so the chain check (not the lock check) fires.
        // To isolate the chain-record failure, we update BUNDLE.lock's hash for
        // chain.jsonl to the tampered value so Step 2 passes, but we CANNOT
        // re-sign BUNDLE.lock (no genesis key in the auditor's hands). The
        // verifier checks BUNDLE.sig over the ORIGINAL lock first, so to reach
        // the chain check we instead tamper the record's SIGNATURE only and
        // leave canonical_hash intact — the signature check fails with the
        // record_id BEFORE any lock mismatch matters... but Step 2 (lock)
        // fires first. So: tamper the record AND update the lock hash AND
        // re-sign with the genesis key (which the EXPORTER still holds in this
        // test's keychain). That models an attacker who controls the bundle but
        // NOT the signing key — except here we DO hold the key, so this models
        // "honest re-pack of a tampered chain", which still must FAIL at the
        // per-record signature check.
        let chain_path = extract.join("chain.jsonl");
        let content = std::fs::read_to_string(&chain_path).unwrap();
        // Flip a byte in the signature hex (last field). Keep it valid hex.
        let mut rec: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        let record_id = rec["record_id"].as_str().unwrap().to_string();
        let sig = rec["signature"].as_str().unwrap().to_string();
        let flipped = if let Some(rest) = sig.strip_prefix("00") {
            format!("ff{rest}")
        } else {
            format!("00{}", &sig[2..])
        };
        rec["signature"] = serde_json::Value::String(flipped);
        let tampered_line = serde_json::to_string(&rec).unwrap() + "\n";
        std::fs::write(&chain_path, &tampered_line).unwrap();

        // Recompute BUNDLE.lock for the tampered chain.jsonl and re-sign it with
        // the genesis key (exporter still holds it) so Step 1+2 pass and the
        // per-record signature check is what fires.
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must fail on tampered record; stdout: {stdout}"
        );
        assert!(
            stdout.starts_with("FAIL:"),
            "expected FAIL line, got: {stdout}"
        );
        assert!(
            stdout.contains(&record_id),
            "FAIL message must name the tampered record_id {record_id}, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_tampered_bundle_lock`
    ///
    /// Mutate BUNDLE.lock WITHOUT re-signing; assert FAIL surfaces
    /// "BUNDLE.sig verification failed" BEFORE any chain-level check fires.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_tampered_bundle_lock() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("verify_tamper_lock");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Corrupt BUNDLE.lock (flip a hex digit) without re-signing BUNDLE.sig.
        let lock_path = extract.join("BUNDLE.lock");
        let mut lock = std::fs::read_to_string(&lock_path).unwrap();
        // Change the first character of the first hash.
        let first = lock.chars().next().unwrap();
        let repl = if first == 'a' { 'b' } else { 'a' };
        lock.replace_range(0..1, &repl.to_string());
        std::fs::write(&lock_path, &lock).unwrap();

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must fail on tampered lock; stdout: {stdout}"
        );
        assert!(
            stdout.contains("BUNDLE.sig verification failed"),
            "tampered-lock FAIL must surface 'BUNDLE.sig verification failed' \
before chain checks, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_warns_when_rekor_absent_and_still_passes`
    ///
    /// Explicitly assert the `--rekor`-absent graceful-degrade path: WARN line
    /// emitted, PASS verdict, exit 0. (Covered partly by the clean test; this
    /// names the AC directly.)
    #[test]
    #[cfg(unix)]
    fn verify_script_warns_when_rekor_absent_and_still_passes() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("verify_rekor_absent");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(
            code, 0,
            "clean bundle without --rekor must PASS; stdout: {stdout}"
        );
        assert!(stdout.contains("WARN: --rekor not passed"), "got: {stdout}");
        assert!(stdout.contains("PASS:"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_nongenesis_key_id_derivation_mismatch`
    ///
    /// F6 regression: add a SECOND (non-genesis) key to public_keys.json whose
    /// key_id does NOT derive from its pubkey (`ed25519:<sha256(pubkey)>`),
    /// repack lock+sig, run `./verify`; assert FAIL naming the bad key_id. The
    /// pre-fix verifier only derived+checked the genesis key, so a tampered
    /// non-genesis pubkey slipped through.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_nongenesis_key_id_derivation_mismatch() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("nongenesis_derive");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Add a non-genesis key whose pubkey does NOT hash to its key_id.
        let pk_path = extract.join("public_keys.json");
        let mut pk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&pk_path).unwrap()).unwrap();
        // A key_id that is well-formed but whose pubkey (all-ones) does not
        // derive it.
        let bad_kid = format!("ed25519:{}", "a".repeat(64));
        let bad_pubkey = "1".repeat(64);
        pk["keys"][&bad_kid] = serde_json::Value::String(bad_pubkey);
        std::fs::write(&pk_path, serde_json::to_vec_pretty(&pk).unwrap()).unwrap();
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "verify must fail when a non-genesis key_id does not derive from \
its pubkey; stdout: {stdout}"
        );
        assert!(
            stdout.starts_with("FAIL:"),
            "expected FAIL line, got: {stdout}"
        );
        assert!(
            stdout.contains(&bad_kid),
            "FAIL message must name the bad non-genesis key_id {bad_kid}, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// Inject a `rekor_log_index` field into the single chain.jsonl record in
    /// the extracted bundle, then repack BUNDLE.lock + BUNDLE.sig. The extra
    /// field is ignored by the verifier's canonical-form reproduction (it is
    /// not in `_TOP_ORDER`/`_OPT_ORDER`) so the chain check still passes; it
    /// only opts the record into the `--rekor` entry-existence path.
    ///
    /// The field is inserted by VERBATIM string splice right after the opening
    /// `{` — NOT by round-tripping through `serde_json::Value`, which would
    /// re-sort nested object keys (the `payload` enum's `{"kind","data"}`) and
    /// break the canonical_hash recompute. We read `canonical_hash` for the
    /// caller's stub-Rekor body via a non-destructive parse of a clone.
    #[cfg(unix)]
    fn inject_rekor_log_index(extract: &Path, svc: &str, chain_id: &str, log_index: u64) -> String {
        let chain_path = extract.join("chain.jsonl");
        let content = std::fs::read_to_string(&chain_path).unwrap();
        let trimmed = content.trim();
        // Read canonical_hash without mutating the original byte layout.
        let parsed: serde_json::Value = serde_json::from_str(trimmed).unwrap();
        let canonical_hash = parsed["canonical_hash"].as_str().unwrap().to_string();
        // Verbatim splice: keep every original byte, only add a leading field.
        assert!(trimmed.starts_with('{'), "record must be a JSON object");
        let spliced = format!("{{\"rekor_log_index\":{log_index},{}\n", &trimmed[1..]);
        std::fs::write(&chain_path, &spliced).unwrap();
        repack_lock_and_sig(extract, svc, chain_id);
        canonical_hash
    }

    /// Start a stdlib-only stub Rekor responder on 127.0.0.1:<ephemeral> that
    /// returns a Rekor-shaped `hashedrekord` body whose `spec.data.hash.value`
    /// is `hash_value`. Returns `(child, base_url)`. The child is killed on
    /// drop by the caller. The server prints `READY <port>` on stdout once
    /// bound so we can discover the ephemeral port deterministically.
    #[cfg(unix)]
    fn start_stub_rekor(hash_value: &str) -> (std::process::Child, String) {
        // The stub serves the same body for any logIndex query — sufficient to
        // exercise the verifier's structured existence check (PASS on match,
        // FAIL on mismatch).
        let py = format!(
            r#"
import json, base64, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
HASH = {hash_value:?}
body_inner = json.dumps({{
    "apiVersion": "0.0.1",
    "kind": "hashedrekord",
    "spec": {{"data": {{"hash": {{"algorithm": "sha256", "value": HASH}}}}}},
}}).encode()
entry = {{"<uuid>": {{"logIndex": 1, "body": base64.b64encode(body_inner).decode()}}}}
payload = json.dumps(entry).encode()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a):
        pass
srv = HTTPServer(("127.0.0.1", 0), H)
print("READY " + str(srv.server_address[1]), flush=True)
srv.serve_forever()
"#
        );
        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(&py)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn stub rekor");
        // Read the READY <port> line from the child's stdout.
        use std::io::{BufRead, BufReader};
        let stdout = child.stdout.take().expect("child stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read READY line");
        let port: u16 = line
            .trim()
            .strip_prefix("READY ")
            .expect("READY prefix")
            .parse()
            .expect("port");
        (child, format!("http://127.0.0.1:{port}"))
    }

    /// `test verify_script_rekor_existence_check_passes_on_match`
    ///
    /// F2 regression: stage a chain record carrying `rekor_log_index`, stand up
    /// a stub Rekor responder returning a body whose hash value MATCHES the
    /// record's canonical_hash, run `./verify --rekor <url>`; assert a real
    /// PASS verdict (exit 0) — NOT a NameError/traceback (the pre-fix
    /// `base64`-unimported crash) and NOT a false WARN-skip.
    #[test]
    #[cfg(unix)]
    fn verify_script_rekor_existence_check_passes_on_match() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("rekor_match");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let canonical_hash =
            inject_rekor_log_index(&extract, &svc, "01JZ00000000000000000000AA", 42);
        let (mut child, url) = start_stub_rekor(&canonical_hash);

        let (code, stdout) = run_verify(&extract, &["--rekor", &url]);
        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(
            code, 0,
            "verify --rekor must PASS when the Rekor entry references the \
canonical_hash; stdout: {stdout}"
        );
        assert!(
            stdout.contains("PASS: chain verified end-to-end"),
            "expected PASS line, got: {stdout}"
        );
        // Honest labeling: no "inclusion-proof" claim anywhere.
        assert!(
            !stdout
                .to_lowercase()
                .contains("inclusion-proof verification")
                && !stdout
                    .to_lowercase()
                    .contains("inclusion proof verification"),
            "verify output must NOT claim inclusion-proof verification, got: {stdout}"
        );
        // Crash defense: no Python traceback / NameError reached the user.
        assert!(
            !stdout.contains("Traceback") && !stdout.contains("NameError"),
            "verify must reach a real verdict, not a traceback; got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_rekor_existence_check_fails_on_mismatch`
    ///
    /// F2 regression: same staging, but the stub Rekor body's hash value does
    /// NOT match the record's canonical_hash; assert FAIL (exit 1) with the
    /// entry-existence failure message — a real verdict, not a traceback.
    #[test]
    #[cfg(unix)]
    fn verify_script_rekor_existence_check_fails_on_mismatch() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("rekor_mismatch");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let _canonical_hash =
            inject_rekor_log_index(&extract, &svc, "01JZ00000000000000000000AA", 42);
        // Stub returns a DIFFERENT hash than the record's canonical_hash.
        let (mut child, url) = start_stub_rekor(&"f".repeat(64));

        let (code, stdout) = run_verify(&extract, &["--rekor", &url]);
        let _ = child.kill();
        let _ = child.wait();

        assert_ne!(
            code, 0,
            "verify --rekor must FAIL when the Rekor entry does not reference \
the canonical_hash; stdout: {stdout}"
        );
        assert!(
            stdout.contains("Rekor entry-existence check failed"),
            "expected entry-existence FAIL message, got: {stdout}"
        );
        assert!(
            !stdout.contains("Traceback") && !stdout.contains("NameError"),
            "verify must reach a real verdict, not a traceback; got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// Recompute BUNDLE.lock over the (mutated) extracted files and re-sign it
    /// with the genesis key from the test keychain, then re-tar in place is NOT
    /// needed — `run_verify` reads from the extracted dir directly. This models
    /// an exporter honestly re-packing a chain that happens to be tampered.
    #[cfg(unix)]
    fn repack_lock_and_sig(extract: &Path, svc: &str, chain_id: &str) {
        use crate::audit::traits::SigningKey as _;
        // Mirror the producer's full `entries` set (export_bundle) so an honest
        // repack reproduces every lock row — including README.md. Omitting a
        // producer entry here would leave that file present-but-unlocked, which
        // the verify script's extra-file guard (Step 2b) now rejects.
        let files = [
            "README.md",
            "chain.jsonl",
            "public_keys.json",
            "rotation_chain.json",
            "canonical_form_vectors/VERSION",
            "canonical_form_vectors/vectors.json",
            "CUTOFF.json",
            "PROVENANCE.json",
            "verify",
        ];
        let mut rows: Vec<(String, String)> = Vec::new();
        for f in files {
            let bytes = std::fs::read(extract.join(f)).unwrap();
            rows.push((f.to_string(), sha256_hex(&bytes)));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let mut lock = String::new();
        for (p, h) in &rows {
            lock.push_str(h);
            lock.push_str("  ");
            lock.push_str(p);
            lock.push('\n');
        }
        std::fs::write(extract.join("BUNDLE.lock"), lock.as_bytes()).unwrap();
        let key = LocalSigningKey::load_from_keychain(svc, chain_id).unwrap();
        let sig = key.sign(lock.as_bytes()).unwrap();
        std::fs::write(extract.join("BUNDLE.sig"), sig.0).unwrap();
    }

    // ── Multi-record chain builder ────────────────────────────────────────
    //
    // Builds `n` properly-linked signed records into a fresh chain. Returns
    // `(TempDir, chain_id, svc)` exactly like `make_signed_chain`.
    //
    // Chain-link prev_hash computation: the Rust production path
    // (`read_last_canonical_bytes`) calls `canonical_bytes_for` on the
    // DESERIALIZED prior record, which at that point carries its REAL stored
    // `canonical_hash` (not the genesis sentinel). The verify script's
    // `canonical_bytes_with_real_hash` mirrors this. We therefore call
    // `canonical_bytes_for(&record)` AFTER computing the real canonical_hash —
    // that gives the correct prev_hash for the next record.
    fn make_multi_record_chain(n: u64, tag: &str) -> (TempDir, String, String) {
        use crate::audit::traits::SigningKey as _;
        assert!(n >= 2, "multi-record chain must have at least 2 records");

        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name(tag);
        let chain_id = "01JZ00000000000000000000AA";

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        let jsonl_dir = base.join("csq-runs");
        std::fs::create_dir_all(&jsonl_dir).unwrap();
        let jsonl_path = jsonl_dir.join(format!("{chain_id}.jsonl"));
        let mut jsonl_content = String::new();

        // First record's prev_hash is the genesis sentinel.
        let mut prev_hash_for_next = Sha256Hex::genesis();

        for seq in 0..n {
            // Use distinct record IDs (ULID-shaped, unique per seq).
            let rid = format!("01JZ0000000000000000MR{seq:04}");
            let mut record = SignedRecord {
                schema_version: "2".to_string(),
                record_id: RecordId::try_new(&rid).unwrap(),
                chain_id: RecordId::try_new(chain_id).unwrap(),
                seq,
                prev_hash: prev_hash_for_next.clone(),
                kind: EventKind::CsqRun,
                payload: EventPayload::CsqRun(CsqRunPayload {
                    run_id: format!("multi-record-seq-{seq}"),
                }),
                ts: "2100-01-01T00:00:00+00:00".to_string(),
                key_id: key_id.clone(),
                // Set to genesis sentinel so canonical_bytes_for produces the
                // canonical pre-image (same as the production write path).
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

            // Compute canonical_hash: sha256(canonical_bytes_for(record with genesis sentinel)).
            let canonical = canonical_bytes_for(&record);
            record.canonical_hash = Sha256Hex::try_new(sha256_hex(&canonical)).unwrap();

            // Sign over the raw 32-byte canonical_hash digest (32 bytes).
            let digest: [u8; 32] = hex::decode(record.canonical_hash.as_str())
                .unwrap()
                .try_into()
                .unwrap();
            record.signature = signing_key.sign(&digest).unwrap();

            // Compute prev_hash for the NEXT record. Production path:
            // `read_last_canonical_bytes` deserializes the record from JSONL
            // (real canonical_hash already in place) then calls
            // `canonical_bytes_for` — this now serializes with the REAL
            // canonical_hash. Calling `canonical_bytes_for(&record)` here
            // after setting the real canonical_hash mirrors that exactly.
            prev_hash_for_next =
                Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&record))).unwrap();

            jsonl_content.push_str(&serde_json::to_string(&record).unwrap());
            jsonl_content.push('\n');
        }

        std::fs::write(&jsonl_path, &jsonl_content).unwrap();
        (tmp, chain_id.to_string(), svc)
    }

    // ── M09 multi-record tamper tests (defense-in-depth NIT) ─────────────────
    //
    // These three tests fill the gap left by M09 R3: the single-record tamper
    // tests proved the verifier catches tampering in a one-record bundle, but
    // not that it catches tampering anywhere in a multi-record bundle. The
    // attack model here is "attacker tampers record N > 1 in a long chain;
    // does the verifier catch it even though earlier records are intact?"

    /// `test verify_script_passes_clean_multi_record_bundle`
    ///
    /// CONTROL: produce a 7-record bundle, run `./verify`, assert PASS + 7
    /// verified records. This confirms the multi-record chain builder is
    /// correct BEFORE the tamper variants exercise it.
    #[test]
    #[cfg(unix)]
    fn verify_script_passes_clean_multi_record_bundle() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(7, "multi_clean");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export multi-record bundle");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(
            code, 0,
            "verify must exit 0 on a clean 7-record bundle; stdout: {stdout}"
        );
        // Structural probe: verify output must name the verified record count.
        assert!(
            stdout.contains("PASS: chain verified end-to-end"),
            "expected PASS line for clean multi-record bundle, got: {stdout}"
        );
        assert!(
            stdout.contains("7 records"),
            "PASS line must report 7 verified records, got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_multi_record_payload_tamper_at_record_2`
    ///
    /// Tamper the payload of record 2 (seq=1) in a 7-record bundle by mutating
    /// its `run_id` string. Repack BUNDLE.lock + BUNDLE.sig so Step 1 and
    /// Step 2 pass, exposing the per-record canonical_hash mismatch check in
    /// Step 5. Assert: (a) non-zero exit, (b) FAIL line naming record 2's
    /// record_id, (c) the tamper was caught by canonical_hash mismatch (not a
    /// lock mismatch — the repacking makes BUNDLE.lock honest about the
    /// tampered chain.jsonl content).
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_multi_record_payload_tamper_at_record_2() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(7, "multi_tamper_payload");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Read chain.jsonl and identify record 2 (seq=1, index 1 in the file).
        let chain_path = extract.join("chain.jsonl");
        let content = std::fs::read_to_string(&chain_path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(lines.len() >= 7, "expected 7 records, got {}", lines.len());

        // Parse record at index 1 (seq=1, the second record) and capture its id.
        let mut rec2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let record_id_2 = rec2["record_id"].as_str().unwrap().to_string();

        // Tamper: mutate run_id inside the CsqRun payload (this changes the
        // canonical form → canonical_hash mismatch, but NOT the signature field
        // directly, so the tamper hits the canonical_hash check, not the sig check).
        rec2["payload"]["data"]["run_id"] =
            serde_json::Value::String("ATTACKER-INJECTED-PAYLOAD".to_string());

        // Reconstruct chain.jsonl with the tampered record 2, rest unchanged.
        let mut tampered = String::new();
        tampered.push_str(lines[0]);
        tampered.push('\n');
        tampered.push_str(&serde_json::to_string(&rec2).unwrap());
        tampered.push('\n');
        for line in &lines[2..] {
            tampered.push_str(line);
            tampered.push('\n');
        }
        std::fs::write(&chain_path, &tampered).unwrap();

        // Repack BUNDLE.lock + BUNDLE.sig so the lock check (Step 2) passes
        // and the chain check (Step 5) is what fires.
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);

        // Structural probe: non-zero exit + FAIL line naming the tampered record.
        assert_ne!(
            code, 0,
            "verify must fail on payload tamper at record 2; stdout: {stdout}"
        );
        assert!(
            stdout.starts_with("FAIL:"),
            "expected FAIL line, got: {stdout}"
        );
        // The FAIL must name the specific tampered record_id (structured verdict,
        // not a catch-all "chain tampered" without attribution).
        assert!(
            stdout.contains(&record_id_2),
            "FAIL message must name the tampered record_id {record_id_2} \
             (record 2 / seq=1), got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_multi_record_signature_tamper_at_record_5`
    ///
    /// Tamper the Ed25519 signature of record 5 (seq=4, index 4) in a 7-record
    /// bundle by flipping the first two bytes of the signature hex string.
    /// Records 1-4 are left intact. Repack BUNDLE.lock + BUNDLE.sig so
    /// Step 1 and Step 2 pass. Assert: (a) non-zero exit, (b) FAIL line naming
    /// record 5's record_id. This proves tamper detection works for records
    /// BEYOND the first in a long chain — the verifier does not short-circuit
    /// after the first clean record.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_multi_record_signature_tamper_at_record_5() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(7, "multi_tamper_sig5");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Read chain.jsonl, identify record 5 (seq=4, index 4).
        let chain_path = extract.join("chain.jsonl");
        let content = std::fs::read_to_string(&chain_path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(lines.len() >= 7, "expected 7 records, got {}", lines.len());

        // Parse record at index 4 (seq=4, the fifth record, "record 5").
        let mut rec5: serde_json::Value = serde_json::from_str(lines[4]).unwrap();
        let record_id_5 = rec5["record_id"].as_str().unwrap().to_string();

        // Flip the first 2 bytes of the 128-hex-char signature string.
        // The canonical_hash is LEFT INTACT — the tamper is on the signature
        // field only, so the verify script's canonical_hash check passes for
        // this record but the Ed25519 signature check fires.
        let sig_hex = rec5["signature"].as_str().unwrap().to_string();
        let flipped = if let Some(rest) = sig_hex.strip_prefix("00") {
            format!("ff{rest}")
        } else {
            format!("00{}", sig_hex.strip_prefix("ff").unwrap_or(&sig_hex[2..]))
        };
        rec5["signature"] = serde_json::Value::String(flipped);

        // Reconstruct chain.jsonl: records 0-3 intact, record 4 (seq=4) tampered,
        // records 5-6 intact. The chain link is NOT broken because prev_hash
        // and canonical_hash are unchanged — only the signature field is wrong.
        let mut tampered = String::new();
        for line in &lines[..4] {
            tampered.push_str(line);
            tampered.push('\n');
        }
        tampered.push_str(&serde_json::to_string(&rec5).unwrap());
        tampered.push('\n');
        for line in &lines[5..] {
            tampered.push_str(line);
            tampered.push('\n');
        }
        std::fs::write(&chain_path, &tampered).unwrap();

        // Repack BUNDLE.lock + BUNDLE.sig so Step 2 passes and the per-record
        // signature check (Step 5) is what fires.
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);

        // Structural probe: non-zero exit + FAIL line naming the tampered record.
        assert_ne!(
            code, 0,
            "verify must fail on signature tamper at record 5 (seq=4); stdout: {stdout}"
        );
        assert!(
            stdout.starts_with("FAIL:"),
            "expected FAIL line, got: {stdout}"
        );
        // The FAIL must name the specific tampered record_id (structured verdict).
        assert!(
            stdout.contains(&record_id_5),
            "FAIL message must name the tampered record_id {record_id_5} \
             (record 5 / seq=4), got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    // ── Test helper: extract a tar via python (no tar crate in tree) ───────
    fn extract_tar(tar_path: &Path, dest: &Path) {
        std::fs::create_dir_all(dest).unwrap();
        let py = format!(
            "import tarfile; tarfile.open({:?}).extractall({:?})",
            tar_path.to_string_lossy(),
            dest.to_string_lossy()
        );
        let r = std::process::Command::new("python3")
            .arg("-c")
            .arg(&py)
            .output()
            .expect("python3 extract");
        assert!(
            r.status.success(),
            "tar extract failed: {}",
            String::from_utf8_lossy(&r.stderr)
        );
    }

    // ── M16 signed-cutoff tests ──────────────────────────────────────────────

    /// Builds + signs a chain from `payloads` (one record per payload, seq 0..n)
    /// into a fresh chain. Mirrors `make_multi_record_chain` but lets a test mix
    /// event kinds — used to place a `ReplicationAck` mid-chain so the cutoff's
    /// `latest_anchor_ref` rev-scan is exercised. Returns `(tempdir, chain_id, svc)`.
    fn make_chain_with_payloads(
        tag: &str,
        payloads: Vec<EventPayload>,
    ) -> (TempDir, String, String) {
        use crate::audit::traits::SigningKey as _;
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name(tag);
        let chain_id = "01JZ00000000000000000000AA";

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        let jsonl_dir = base.join("csq-runs");
        std::fs::create_dir_all(&jsonl_dir).unwrap();
        let jsonl_path = jsonl_dir.join(format!("{chain_id}.jsonl"));
        let mut jsonl_content = String::new();
        let mut prev_hash_for_next = Sha256Hex::genesis();

        for (seq, payload) in payloads.into_iter().enumerate() {
            let seq = seq as u64;
            let rid = format!("01JZ0000000000000000MR{seq:04}");
            let mut record = SignedRecord {
                schema_version: "2".to_string(),
                record_id: RecordId::try_new(&rid).unwrap(),
                chain_id: RecordId::try_new(chain_id).unwrap(),
                seq,
                prev_hash: prev_hash_for_next.clone(),
                kind: payload.kind(),
                payload,
                ts: "2100-01-01T00:00:00+00:00".to_string(),
                key_id: key_id.clone(),
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
            let canonical = canonical_bytes_for(&record);
            record.canonical_hash = Sha256Hex::try_new(sha256_hex(&canonical)).unwrap();
            let digest: [u8; 32] = hex::decode(record.canonical_hash.as_str())
                .unwrap()
                .try_into()
                .unwrap();
            record.signature = signing_key.sign(&digest).unwrap();
            prev_hash_for_next =
                Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&record))).unwrap();
            jsonl_content.push_str(&serde_json::to_string(&record).unwrap());
            jsonl_content.push('\n');
        }
        std::fs::write(&jsonl_path, &jsonl_content).unwrap();
        (tmp, chain_id.to_string(), svc)
    }

    fn read_cutoff(extract: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(extract.join("CUTOFF.json")).unwrap()).unwrap()
    }

    fn read_provenance(extract: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(extract.join("PROVENANCE.json")).unwrap()).unwrap()
    }

    /// Build a signed chain whose records carry per-record `actor`/`trust`
    /// attestation slots (M21 provenance-lane fixtures). Each tuple is
    /// `(payload, actor, trust)`; the helper hash-chains + signs every record
    /// with the genesis key so the export pre-flight `verify_chain` passes.
    fn make_chain_with_attested_records(
        tag: &str,
        records: Vec<(
            EventPayload,
            Option<crate::audit::types::EatpActor>,
            Option<crate::audit::types::EatpTrust>,
        )>,
    ) -> (TempDir, String, String) {
        use crate::audit::traits::SigningKey as _;
        crate::audit::key_custody::test_helpers::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let svc = svc_name(tag);
        let chain_id = "01JZ00000000000000000000AA";

        let state = ChainState::new(chain_id);
        state.save(base).expect("save chain.json");
        let _ = LocalSigningKey::delete_from_keychain(&svc, chain_id);
        audit_init(base, &svc).expect("audit_init");

        let signing_key =
            LocalSigningKey::load_from_keychain(&svc, chain_id).expect("load signing key");
        let key_id = signing_key.key_id();

        let jsonl_dir = base.join("csq-runs");
        std::fs::create_dir_all(&jsonl_dir).unwrap();
        let jsonl_path = jsonl_dir.join(format!("{chain_id}.jsonl"));
        let mut jsonl_content = String::new();
        let mut prev_hash_for_next = Sha256Hex::genesis();

        for (seq, (payload, actor, trust)) in records.into_iter().enumerate() {
            let seq = seq as u64;
            let rid = format!("01JZ0000000000000000PR{seq:04}");
            let mut record = SignedRecord {
                schema_version: "2".to_string(),
                record_id: RecordId::try_new(&rid).unwrap(),
                chain_id: RecordId::try_new(chain_id).unwrap(),
                seq,
                prev_hash: prev_hash_for_next.clone(),
                kind: payload.kind(),
                payload,
                ts: "2100-01-01T00:00:00+00:00".to_string(),
                key_id: key_id.clone(),
                canonical_hash: Sha256Hex::genesis(),
                signature: Ed25519Signature::new([0u8; 64]),
                actor,
                authority: None,
                trust,
                eatp_start_ts: None,
                eatp_end_ts: None,
                op_phase: None,
                verification_level: None,
            };
            let canonical = canonical_bytes_for(&record);
            record.canonical_hash = Sha256Hex::try_new(sha256_hex(&canonical)).unwrap();
            let digest: [u8; 32] = hex::decode(record.canonical_hash.as_str())
                .unwrap()
                .try_into()
                .unwrap();
            record.signature = signing_key.sign(&digest).unwrap();
            prev_hash_for_next =
                Sha256Hex::try_new(sha256_hex(&canonical_bytes_for(&record))).unwrap();
            jsonl_content.push_str(&serde_json::to_string(&record).unwrap());
            jsonl_content.push('\n');
        }
        std::fs::write(&jsonl_path, &jsonl_content).unwrap();
        (tmp, chain_id.to_string(), svc)
    }

    /// A backed `ProvenanceAnchored` payload + its attestation slots, carrying a
    /// `words_hash` whose pre-image (`verbatim`) MUST NOT appear in the bundle.
    fn provenance_fixture(
        decision_id: &str,
        surface: &str,
        _counter: u64,
        principal: &str,
        backed: bool,
        words_hash: Option<&str>,
    ) -> (
        EventPayload,
        Option<crate::audit::types::EatpActor>,
        Option<crate::audit::types::EatpTrust>,
    ) {
        use crate::audit::types::{
            EatpActor, EatpTrust, EventPayload, ProvenanceAnchoredPayload, Sha256Hex,
        };
        let payload = EventPayload::ProvenanceAnchored(ProvenanceAnchoredPayload {
            decision_id: decision_id.to_string(),
            surface: surface.to_string(),
            claimed_decision_ts: "2100-01-01T00:00:00+00:00".to_string(),
            words_hash: words_hash.map(|h| Sha256Hex::try_new(h).unwrap()),
            f101_schema_version: "f101-1@1".to_string(),
            received_bytes_hash: Sha256Hex::try_new(sha256_hex(decision_id.as_bytes())).unwrap(),
            ordering_basis: None,
            predecessor_missing: None,
            prev_link: None,
            kind: None,
            session: None,
            operator_ref: None,
        });
        let (actor, trust) = if backed {
            (
                EatpActor(serde_json::json!({
                    "principal": principal,
                    "backing": "verified",
                    "proof": "deadbeefdeadbeef",
                })),
                EatpTrust(serde_json::json!({ "level": "verified" })),
            )
        } else {
            (
                EatpActor(serde_json::json!({
                    "principal": principal,
                    "backing": "unbacked",
                })),
                EatpTrust(serde_json::json!({ "level": "unbacked" })),
            )
        };
        (payload, Some(actor), Some(trust))
    }

    /// A backed `ProvenanceAnchored` fixture carrying POPULATED M20 epistemic
    /// annotations (`ordering_basis` + `predecessor_missing`) so the lane's
    /// cross-check of those fields is exercised in their `Some` form (not only
    /// the `None`/null-vs-absent form the other fixtures cover).
    fn provenance_fixture_ordered(
        decision_id: &str,
        _counter: u64,
        ordering_basis: Option<&str>,
        predecessor_missing: Option<bool>,
    ) -> (
        EventPayload,
        Option<crate::audit::types::EatpActor>,
        Option<crate::audit::types::EatpTrust>,
    ) {
        use crate::audit::types::{
            EatpActor, EatpTrust, EventPayload, ProvenanceAnchoredPayload, Sha256Hex,
        };
        let payload = EventPayload::ProvenanceAnchored(ProvenanceAnchoredPayload {
            decision_id: decision_id.to_string(),
            surface: "codex".to_string(),
            claimed_decision_ts: "2100-01-01T00:00:00+00:00".to_string(),
            words_hash: None,
            f101_schema_version: "f101-1@1".to_string(),
            received_bytes_hash: Sha256Hex::try_new(sha256_hex(decision_id.as_bytes())).unwrap(),
            ordering_basis: ordering_basis.map(str::to_string),
            predecessor_missing,
            prev_link: None,
            kind: None,
            session: None,
            operator_ref: None,
        });
        (
            payload,
            Some(EatpActor(serde_json::json!({
                "principal": "alice@example.test",
                "backing": "verified",
                "proof": "deadbeefdeadbeef",
            }))),
            Some(EatpTrust(serde_json::json!({ "level": "verified" }))),
        )
    }

    /// `test provenance_lane_projects_ordering_annotations`
    ///
    /// MEDIUM-2 regression (Some-case): a record carrying populated M20
    /// epistemic annotations projects them faithfully into the lane. The
    /// verifier's acceptance of this round-trip is covered by
    /// `verify_script_validates_provenance_lane` (clean PASS) and its
    /// load-bearing-on-tamper property by
    /// `verify_script_fails_on_tampered_ordering_basis`.
    #[test]
    fn provenance_lane_projects_ordering_annotations() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![provenance_fixture_ordered(
            "dec-ordered",
            1,
            Some("wallclock_skew_bounded"),
            Some(true),
        )];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("prov_ordered", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);
        let prov = read_provenance(&extract);
        let r = &prov["records"][0];
        assert_eq!(r["ordering_basis"], "wallclock_skew_bounded");
        assert_eq!(r["predecessor_missing"], true);
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test provenance_lane_present_with_backing_per_record`
    ///
    /// AC1/AC5: the bundle's PROVENANCE.json projects every ProvenanceAnchored
    /// record with decision_id/surface/principal/backing/trust_level, in
    /// chain-authoritative seq order; backed + unbacked records are both present
    /// with their correct backing, and unbacked_count is accurate.
    #[test]
    fn provenance_lane_present_with_backing_per_record() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![
            (
                EventPayload::CsqRun(CsqRunPayload {
                    run_id: "r0".to_string(),
                }),
                None,
                None,
            ),
            provenance_fixture("dec-backed", "codex", 1, "alice@example.test", true, None),
            provenance_fixture("dec-unbacked", "cc", 2, "bob@example.test", false, None),
        ];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("prov_present", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        let summary = export_bundle(base, &svc, Some(&out), None, None).expect("export");
        assert_eq!(summary.provenance_record_count, 2);
        assert_eq!(summary.provenance_unbacked_count, 1);

        let extract = base.join("extract");
        extract_tar(&out, &extract);
        let prov = read_provenance(&extract);
        assert_eq!(prov["provenance_version"], "1");
        assert_eq!(prov["record_count"], 2);
        assert_eq!(prov["unbacked_count"], 1);
        let recs = prov["records"].as_array().unwrap();
        assert_eq!(
            recs.len(),
            2,
            "CsqRun must NOT appear in the provenance lane"
        );

        // seq-ordered: backed (seq 1) then unbacked (seq 2).
        assert_eq!(recs[0]["decision_id"], "dec-backed");
        assert_eq!(recs[0]["surface"], "codex");
        assert_eq!(recs[0]["principal"], "alice@example.test");
        assert_eq!(recs[0]["backing"], "verified");
        assert_eq!(recs[0]["trust_level"], "verified");
        assert_eq!(recs[0]["f101_schema_version"], "f101-1@1");
        assert!(
            recs[0]["authority"].is_null(),
            "seam records carry null authority"
        );

        assert_eq!(recs[1]["decision_id"], "dec-unbacked");
        assert_eq!(recs[1]["surface"], "cc");
        assert_eq!(recs[1]["principal"], "bob@example.test");
        assert_eq!(recs[1]["backing"], "unbacked");
        assert_eq!(recs[1]["trust_level"], "unbacked");

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test provenance_lane_omits_verbatim_human_words`
    ///
    /// AC2 LOAD-BEARING (HIGH-1): a ProvenanceAnchored record commits to human
    /// words via `words_hash` only. The verbatim words MUST NOT appear ANYWHERE
    /// in the produced bundle bytes; the `words_hash` MUST appear in the lane.
    #[test]
    fn provenance_lane_omits_verbatim_human_words() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        // The pre-image of the words_hash — the phrase that MUST NOT leak.
        const VERBATIM: &str = "the confidential Q3 layoff decision rationale";
        let words_hash = sha256_hex(VERBATIM.as_bytes());
        let records = vec![
            (
                EventPayload::CsqRun(CsqRunPayload {
                    run_id: "r0".to_string(),
                }),
                None,
                None,
            ),
            provenance_fixture(
                "dec-words",
                "codex",
                1,
                "carol@example.test",
                true,
                Some(&words_hash),
            ),
        ];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("prov_words", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");

        // Grep the ENTIRE bundle bytes for the verbatim phrase — expect ABSENT.
        let bundle_bytes = std::fs::read(&out).expect("read bundle");
        let needle = VERBATIM.as_bytes();
        let leaked = bundle_bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            !leaked,
            "HIGH-1 violation: verbatim human words leaked into the export bundle"
        );

        // The words_hash MUST be present in the lane (the commitment is kept).
        let extract = base.join("extract");
        extract_tar(&out, &extract);
        let prov = read_provenance(&extract);
        assert_eq!(
            prov["records"][0]["words_hash"].as_str().unwrap(),
            words_hash,
            "the words_hash commitment must be present in the lane"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test provenance_lane_covered_by_bundle_lock`
    ///
    /// PROVENANCE.json is signed-covered: it appears in BUNDLE.lock with its
    /// correct SHA-256 (so BUNDLE.sig protects it from a post-export swap).
    #[test]
    fn provenance_lane_covered_by_bundle_lock() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![provenance_fixture(
            "dec-1",
            "codex",
            1,
            "alice@example.test",
            true,
            None,
        )];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("prov_lock", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let lock = std::fs::read_to_string(extract.join("BUNDLE.lock")).unwrap();
        let prov_bytes = std::fs::read(extract.join("PROVENANCE.json")).unwrap();
        let want = sha256_hex(&prov_bytes);
        let found = lock.lines().any(|l| {
            l.split_once("  ")
                .map(|(h, p)| p == "PROVENANCE.json" && h == want)
                .unwrap_or(false)
        });
        assert!(
            found,
            "BUNDLE.lock must carry PROVENANCE.json's correct sha256; lock:\n{lock}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test provenance_lane_empty_when_no_provenance_records`
    ///
    /// A chain with no seam-ingested provenance (the common case pre-M18-bind)
    /// still produces a well-formed, empty lane — the bundle shape is stable.
    #[test]
    fn provenance_lane_empty_when_no_provenance_records() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("prov_empty");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        let summary = export_bundle(base, &svc, Some(&out), None, None).expect("export");
        assert_eq!(summary.provenance_record_count, 0);
        assert_eq!(summary.provenance_unbacked_count, 0);
        let extract = base.join("extract");
        extract_tar(&out, &extract);
        let prov = read_provenance(&extract);
        assert_eq!(prov["record_count"], 0);
        assert_eq!(prov["unbacked_count"], 0);
        assert!(prov["records"].as_array().unwrap().is_empty());
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test cutoff_json_snapshots_chain_head`
    ///
    /// AC1: `csq audit export` writes CUTOFF.json carrying (latest_hash,
    /// latest_seq, latest_anchor_ref, export_ts). For a never-anchored chain
    /// latest_anchor_ref is null and the head fields match the sole record.
    #[test]
    fn cutoff_json_snapshots_chain_head() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, chain_id, svc) = make_signed_chain("cutoff_head");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Read the sole chain record to learn the true head hash/seq.
        let chain = std::fs::read_to_string(extract.join("chain.jsonl")).unwrap();
        let head: serde_json::Value = serde_json::from_str(chain.lines().last().unwrap()).unwrap();

        let cutoff = read_cutoff(&extract);
        assert_eq!(cutoff["cutoff_version"], "1");
        assert_eq!(cutoff["chain_id"], chain_id);
        assert_eq!(cutoff["latest_seq"], head["seq"]);
        assert_eq!(cutoff["latest_hash"], head["canonical_hash"]);
        assert!(
            cutoff["latest_anchor_ref"].is_null(),
            "never-anchored chain must have null latest_anchor_ref, got {}",
            cutoff["latest_anchor_ref"]
        );
        assert_ne!(
            cutoff["cutoff_hash"].as_str().unwrap(),
            Sha256Hex::GENESIS,
            "cutoff_hash must be computed, not the genesis sentinel"
        );
        assert!(!cutoff["export_ts"].as_str().unwrap().is_empty());

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test cutoff_signature_verifies_via_genesis_key`
    ///
    /// AC2: the cutoff is signed by the genesis-anchored export key over the 32
    /// raw bytes of cutoff_hash; the signature verifies against the bundled
    /// public_keys.json[genesis]. Verified here with ed25519-dalek directly (the
    /// same check the embedded verify.py performs in pure Python).
    #[test]
    fn cutoff_signature_verifies_via_genesis_key() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_signed_chain("cutoff_sig");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let cutoff = read_cutoff(&extract);
        let pk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(extract.join("public_keys.json")).unwrap())
                .unwrap();
        let genesis_kid = pk["genesis"].as_str().unwrap();
        assert_eq!(
            cutoff["key_id"].as_str().unwrap(),
            genesis_kid,
            "cutoff must be signed by the genesis-anchored export key"
        );
        let pubhex = pk["keys"][genesis_kid].as_str().unwrap();
        let pubbytes: [u8; 32] = hex::decode(pubhex).unwrap().try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubbytes).unwrap();

        let digest: [u8; 32] = hex::decode(cutoff["cutoff_hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig_arr: [u8; 64] = hex::decode(cutoff["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let dsig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify_strict(&digest, &dsig)
            .expect("CUTOFF.json signature must verify against embedded genesis pubkey");

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test cutoff_latest_anchor_ref_from_replication_ack`
    ///
    /// AC: latest_anchor_ref is the most recent ReplicationAck in the chain
    /// (rev-scan: a ReplicationAck mid-chain is picked even when the head is a
    /// later CsqRun), and ack_seq is the ReplicationAck record's own seq.
    #[test]
    fn cutoff_latest_anchor_ref_from_replication_ack() {
        use crate::audit::types::{ReplicationAckPayload, SinkId, SinkName};
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let payloads = vec![
            EventPayload::CsqRun(CsqRunPayload {
                run_id: "r0".to_string(),
            }),
            EventPayload::ReplicationAck(ReplicationAckPayload {
                sink: SinkName::try_new("rekor").unwrap(),
                sink_id: SinkId::try_new("treeA:42").unwrap(),
            }),
            EventPayload::CsqRun(CsqRunPayload {
                run_id: "r2".to_string(),
            }),
        ];
        let (tmp, _chain_id, svc) = make_chain_with_payloads("cutoff_anchor", payloads);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let cutoff = read_cutoff(&extract);
        assert_eq!(cutoff["latest_seq"], 2, "head is the seq-2 CsqRun");
        let ar = &cutoff["latest_anchor_ref"];
        assert!(!ar.is_null(), "anchored chain must carry latest_anchor_ref");
        assert_eq!(ar["sink"], "rekor");
        assert_eq!(ar["sink_id"], "treeA:42");
        assert_eq!(
            ar["ack_seq"], 1,
            "ack_seq is the ReplicationAck record's seq"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_tampered_cutoff`
    ///
    /// AC4: a tampered cutoff (latest_seq altered) fails verification even when
    /// the attacker honestly repacks BUNDLE.lock + BUNDLE.sig over the mutated
    /// CUTOFF.json — the cutoff's own canonical-hash self-check (Step 2.5)
    /// catches the inconsistency.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_tampered_cutoff() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(3, "cutoff_tamper");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Mutate latest_seq inside CUTOFF.json WITHOUT recomputing cutoff_hash.
        let mut cutoff = read_cutoff(&extract);
        cutoff["latest_seq"] = serde_json::json!(999);
        std::fs::write(
            extract.join("CUTOFF.json"),
            serde_json::to_vec_pretty(&cutoff).unwrap(),
        )
        .unwrap();
        // Honest exporter repacks lock+sig over the mutated bundle.
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(code, 0, "tampered cutoff must FAIL; stdout: {stdout}");
        assert!(
            stdout.contains("CUTOFF.json cutoff_hash does not match"),
            "expected cutoff self-check failure, got: {stdout}"
        );
        assert!(
            !stdout.contains("Traceback") && !stdout.contains("NameError"),
            "verify must reach a real verdict, not a traceback; got: {stdout}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_tail_truncation_via_cutoff`
    ///
    /// AC3 (headline): dropping the chain TAIL after export leaves a chain whose
    /// head no longer matches the signed cutoff. The prefix is internally valid
    /// (the per-record walk PASSes), so ONLY the cutoff cross-check detects the
    /// truncation — the M16 capability M09 lacked explicitly.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_tail_truncation_via_cutoff() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(3, "cutoff_trunc");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Drop the last chain record (seq 2). The remaining 0..1 prefix is a
        // perfectly valid chain on its own.
        let chain = std::fs::read_to_string(extract.join("chain.jsonl")).unwrap();
        let mut lines: Vec<&str> = chain.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 3);
        lines.pop();
        std::fs::write(extract.join("chain.jsonl"), lines.join("\n") + "\n").unwrap();
        // Attacker repacks lock+sig so Steps 1–2 PASS over the truncated chain.
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(code, 0, "tail truncation must FAIL; stdout: {stdout}");
        assert!(
            stdout.contains("does not match the chain head seq")
                || stdout.contains("tail truncation"),
            "expected cutoff head-mismatch failure, got: {stdout}"
        );
        assert!(
            !stdout.contains("Traceback") && !stdout.contains("NameError"),
            "verify must reach a real verdict, not a traceback; got: {stdout}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    // ── M16 redteam round-1 follow-ups (negative-path + Some-branch coverage) ─

    #[cfg(unix)]
    fn chain_head_fields(extract: &Path) -> (String, u64) {
        let chain = std::fs::read_to_string(extract.join("chain.jsonl")).unwrap();
        let head: serde_json::Value =
            serde_json::from_str(chain.lines().rfind(|l| !l.trim().is_empty()).unwrap()).unwrap();
        (
            head["canonical_hash"].as_str().unwrap().to_string(),
            head["seq"].as_u64().unwrap(),
        )
    }

    /// Models an attacker who HOLDS the genesis key and forges a
    /// self-consistent (correct cutoff_hash + valid genesis signature) cutoff
    /// with arbitrary head/anchor fields, then honestly repacks lock+sig. Only
    /// the Step-5.5 chain cross-check can catch a wrong anchor ref this way.
    #[cfg(unix)]
    fn rewrite_signed_cutoff(
        extract: &Path,
        svc: &str,
        chain_id: &str,
        latest_hash: &str,
        latest_seq: u64,
        anchor: Option<crate::audit::cutoff::AnchorRef>,
    ) {
        use crate::audit::traits::SigningKey as _;
        let key = LocalSigningKey::load_from_keychain(svc, chain_id).unwrap();
        let bytes = crate::audit::cutoff::build_cutoff_json_from_parts(
            chain_id,
            latest_hash,
            latest_seq,
            anchor,
            "2100-01-01T00:00:00+00:00",
            &key.key_id(),
            &key,
        )
        .unwrap();
        std::fs::write(extract.join("CUTOFF.json"), bytes).unwrap();
        repack_lock_and_sig(extract, svc, chain_id);
    }

    #[cfg(unix)]
    fn ack_payloads() -> Vec<EventPayload> {
        use crate::audit::types::{ReplicationAckPayload, SinkId, SinkName};
        vec![
            EventPayload::CsqRun(CsqRunPayload {
                run_id: "r0".to_string(),
            }),
            EventPayload::ReplicationAck(ReplicationAckPayload {
                sink: SinkName::try_new("rekor").unwrap(),
                sink_id: SinkId::try_new("treeA:42").unwrap(),
            }),
            EventPayload::CsqRun(CsqRunPayload {
                run_id: "r2".to_string(),
            }),
        ]
    }

    /// `test verify_script_passes_clean_anchored_bundle`
    ///
    /// M-1: exercises the NON-NULL latest_anchor_ref branch end-to-end through
    /// the Python verifier (Step 2.5 `Some`-branch canonical bytes + Step 5.5
    /// anchor cross-check). The clean-bundle tests use null-anchor chains only.
    #[test]
    #[cfg(unix)]
    fn verify_script_passes_clean_anchored_bundle() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_chain_with_payloads("anchored_pass", ack_payloads());
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(code, 0, "anchored bundle must PASS; stdout: {stdout}");
        assert!(
            stdout.contains("PASS: chain verified end-to-end"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_passes_clean_bundle_with_ack_head`
    ///
    /// L-2 edge: the chain HEAD is itself a ReplicationAck, so ack_seq ==
    /// latest_seq. Confirms the rev-scan + cross-check handle the head-is-ack
    /// case (including the seq-0-adjacent `by_seq.get` key path).
    #[test]
    #[cfg(unix)]
    fn verify_script_passes_clean_bundle_with_ack_head() {
        use crate::audit::types::{ReplicationAckPayload, SinkId, SinkName};
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let payloads = vec![
            EventPayload::CsqRun(CsqRunPayload {
                run_id: "r0".to_string(),
            }),
            EventPayload::ReplicationAck(ReplicationAckPayload {
                sink: SinkName::try_new("rekor").unwrap(),
                sink_id: SinkId::try_new("treeB:7").unwrap(),
            }),
        ];
        let (tmp, _chain_id, svc) = make_chain_with_payloads("ack_head", payloads);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let cutoff = read_cutoff(&extract);
        assert_eq!(cutoff["latest_seq"], 1);
        assert_eq!(cutoff["latest_anchor_ref"]["ack_seq"], 1, "head IS the ack");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(code, 0, "head-is-ack bundle must PASS; stdout: {stdout}");
        assert!(stdout.contains("PASS:"), "got: {stdout}");
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_nongenesis_cutoff_key_id`
    ///
    /// Isolates the Step-2.5 `key_id == genesis` guard: a cutoff that is
    /// internally self-consistent (correct cutoff_hash + valid signature) but
    /// signed by a NON-genesis key MUST be rejected.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_nongenesis_cutoff_key_id() {
        use crate::audit::traits::SigningKey as _;
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(2, "nongenesis_key");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (h, s) = chain_head_fields(&extract);
        // A different, self-consistent key signs the cutoff (different key_id).
        let other =
            LocalSigningKey::generate_and_store(&svc, "01JZ00000000000000000000ZZ", 0).unwrap();
        let bytes = crate::audit::cutoff::build_cutoff_json_from_parts(
            "01JZ00000000000000000000AA",
            &h,
            s,
            None,
            "2100-01-01T00:00:00+00:00",
            &other.key_id(),
            &other,
        )
        .unwrap();
        std::fs::write(extract.join("CUTOFF.json"), bytes).unwrap();
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "non-genesis cutoff key must FAIL; stdout: {stdout}"
        );
        assert!(
            stdout.contains("is not the genesis-anchored export key"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000ZZ");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_anchor_ref_sink_mismatch`
    ///
    /// Isolates the Step-5.5 sink/sink_id equality check: a genesis-signed,
    /// self-consistent cutoff whose anchor_ref names a wrong sink_id at the real
    /// ack seq MUST FAIL.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_anchor_ref_sink_mismatch() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) =
            make_chain_with_payloads("anchor_sink_mismatch", ack_payloads());
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (h, s) = chain_head_fields(&extract);
        rewrite_signed_cutoff(
            &extract,
            &svc,
            "01JZ00000000000000000000AA",
            &h,
            s,
            Some(crate::audit::cutoff::AnchorRef {
                sink: "rekor".to_string(),
                sink_id: "WRONG:99".to_string(),
                ack_seq: 1,
            }),
        );

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(code, 0, "anchor sink mismatch must FAIL; stdout: {stdout}");
        assert!(
            stdout.contains("latest_anchor_ref does not match the chain"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_anchor_ref_pointing_at_nonack_record`
    ///
    /// Isolates the Step-5.5 `kind == replication_ack` check: anchor_ref.ack_seq
    /// pointing at a CsqRun record (seq 0) MUST FAIL.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_anchor_ref_pointing_at_nonack_record() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_chain_with_payloads("anchor_nonack", ack_payloads());
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (h, s) = chain_head_fields(&extract);
        rewrite_signed_cutoff(
            &extract,
            &svc,
            "01JZ00000000000000000000AA",
            &h,
            s,
            Some(crate::audit::cutoff::AnchorRef {
                sink: "rekor".to_string(),
                sink_id: "treeA:42".to_string(),
                ack_seq: 0, // seq 0 is a CsqRun, not a ReplicationAck
            }),
        );

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "anchor at non-ack record must FAIL; stdout: {stdout}"
        );
        assert!(
            stdout.contains("latest_anchor_ref does not match the chain"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_anchor_ref_ack_seq_absent`
    ///
    /// Isolates the Step-5.5 `by_seq.get` miss path: anchor_ref.ack_seq pointing
    /// at a seq not present in the chain MUST FAIL.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_anchor_ref_ack_seq_absent() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_chain_with_payloads("anchor_absent", ack_payloads());
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (h, s) = chain_head_fields(&extract);
        rewrite_signed_cutoff(
            &extract,
            &svc,
            "01JZ00000000000000000000AA",
            &h,
            s,
            Some(crate::audit::cutoff::AnchorRef {
                sink: "rekor".to_string(),
                sink_id: "treeA:42".to_string(),
                ack_seq: 999,
            }),
        );

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(code, 0, "absent ack_seq must FAIL; stdout: {stdout}");
        assert!(
            stdout.contains("is not present in chain.jsonl"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_cutoff_missing_field`
    ///
    /// The verifier MUST fail CLOSED with a clean verdict (NOT a Python
    /// traceback) when a tampered CUTOFF.json deletes a required canonical field.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_cutoff_missing_field() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(2, "cutoff_missing_field");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let mut cutoff = read_cutoff(&extract);
        cutoff.as_object_mut().unwrap().remove("latest_hash");
        std::fs::write(
            extract.join("CUTOFF.json"),
            serde_json::to_vec_pretty(&cutoff).unwrap(),
        )
        .unwrap();
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(code, 0, "missing cutoff field must FAIL; stdout: {stdout}");
        assert!(
            stdout.contains("missing required field 'latest_hash'"),
            "got: {stdout}"
        );
        assert!(
            !stdout.contains("Traceback") && !stdout.contains("KeyError"),
            "must be a clean FAIL, not a traceback; got: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_cutoff_head_hash_mismatch_same_seq`
    ///
    /// Isolates the Step-5.5 head-HASH branch (distinct from the seq branch the
    /// truncation test trips): a genesis-signed, self-consistent cutoff whose
    /// `latest_seq` matches the head but whose `latest_hash` is wrong MUST FAIL.
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_cutoff_head_hash_mismatch_same_seq() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(3, "cutoff_hash_mismatch");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let (_h, s) = chain_head_fields(&extract);
        // Correct seq, WRONG hash — only the head-hash cross-check can catch it.
        rewrite_signed_cutoff(
            &extract,
            &svc,
            "01JZ00000000000000000000AA",
            &"f".repeat(64),
            s,
            None,
        );

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(code, 0, "head-hash mismatch must FAIL; stdout: {stdout}");
        assert!(
            stdout.contains("does not match the chain head canonical_hash"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_cutoff_signature_corruption`
    ///
    /// Isolates the Step-2.5 signature-verify branch: a cutoff with a valid
    /// (self-consistent) `cutoff_hash` but a corrupted `signature` MUST FAIL the
    /// Ed25519 check (not the hash check).
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_cutoff_signature_corruption() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(2, "cutoff_sig_corrupt");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let mut cutoff = read_cutoff(&extract);
        // Flip the first hex nibble of the signature — still 128 valid hex chars
        // (64 bytes), so the hex-decode + length checks pass; only the Ed25519
        // verification fails. cutoff_hash is untouched, so the hash check passes.
        let sig = cutoff["signature"].as_str().unwrap().to_string();
        let first = if sig.starts_with('0') { '1' } else { '0' };
        let flipped = format!("{first}{}", &sig[1..]);
        cutoff["signature"] = serde_json::json!(flipped);
        std::fs::write(
            extract.join("CUTOFF.json"),
            serde_json::to_vec_pretty(&cutoff).unwrap(),
        )
        .unwrap();
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "corrupted cutoff signature must FAIL; stdout: {stdout}"
        );
        assert!(
            stdout.contains("CUTOFF.json signature did not verify"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// `test verify_script_fails_on_cutoff_version_mismatch`
    ///
    /// Isolates the Step-2.5 version pin: a cutoff whose `cutoff_version` is not
    /// `"1"` MUST FAIL with the version message (the version check runs before
    /// the cutoff_hash recompute, so no re-sign is needed to reach it).
    #[test]
    #[cfg(unix)]
    fn verify_script_fails_on_cutoff_version_mismatch() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let (tmp, _chain_id, svc) = make_multi_record_chain(2, "cutoff_version");
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let mut cutoff = read_cutoff(&extract);
        cutoff["cutoff_version"] = serde_json::json!("2");
        std::fs::write(
            extract.join("CUTOFF.json"),
            serde_json::to_vec_pretty(&cutoff).unwrap(),
        )
        .unwrap();
        repack_lock_and_sig(&extract, &svc, "01JZ00000000000000000000AA");

        let (code, stdout) = run_verify(&extract, &[]);
        assert_ne!(
            code, 0,
            "unknown cutoff_version must FAIL; stdout: {stdout}"
        );
        assert!(
            stdout.contains("this verifier only understands version 1"),
            "got: {stdout}"
        );
        assert!(!stdout.contains("Traceback"), "got: {stdout}");
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    // ── HIGH-2 regression: operator_ref without display_id must NOT emit null
    //    in the lane (null vs absent breaks the verifier's whole-object comparison) ──

    /// Build a `ProvenanceAnchored` fixture with a populated `operator_ref` that
    /// LACKS `display_id` (the production `mk_event_v1` shape).
    fn provenance_fixture_with_operator_ref(
        decision_id: &str,
        with_display_id: bool,
    ) -> (
        EventPayload,
        Option<crate::audit::types::EatpActor>,
        Option<crate::audit::types::EatpTrust>,
    ) {
        use crate::audit::types::{
            EatpActor, EatpTrust, EventPayload, OperatorRefRecord, ProvenanceAnchoredPayload,
            Sha256Hex,
        };
        let operator_ref = OperatorRefRecord {
            verified_id: "548F2C562EB4246D025FA80A70552B124755B685".to_string(),
            person_id: "pid-esperie-10e7dd16".to_string(),
            display_id: if with_display_id {
                Some("esperie".to_string())
            } else {
                None
            },
        };
        let payload = EventPayload::ProvenanceAnchored(ProvenanceAnchoredPayload {
            decision_id: decision_id.to_string(),
            surface: "journal/test.md".to_string(),
            claimed_decision_ts: "2100-01-01T00:00:00+00:00".to_string(),
            words_hash: None,
            f101_schema_version: "1".to_string(),
            received_bytes_hash: Sha256Hex::try_new(sha256_hex(decision_id.as_bytes())).unwrap(),
            ordering_basis: None,
            predecessor_missing: None,
            prev_link: None,
            kind: Some("Decision".to_string()),
            session: Some("sess-CONFORMANCE-V1-0001".to_string()),
            operator_ref: Some(operator_ref),
        });
        (
            payload,
            Some(EatpActor(serde_json::json!({
                "principal": "pid-esperie-10e7dd16",
                "backing": "verified",
            }))),
            Some(EatpTrust(serde_json::json!({ "level": "verified" }))),
        )
    }

    /// HIGH-2 regression: a record with `operator_ref` lacking `display_id`
    /// must pass the verifier (lane omits `display_id` key, matching the chain).
    /// This test exists because the lane previously used `serde_json::json!`
    /// which serialized `None` as `null`, while the chain omits the key — causing
    /// the verifier's whole-object `operator_ref` comparison to FAIL.
    #[test]
    #[cfg(unix)]
    fn verify_script_passes_with_operator_ref_no_display_id() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![provenance_fixture_with_operator_ref(
            "dec-no-display-id",
            false,
        )];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("prov_no_display_id", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        // Verify the PROVENANCE.json lane doesn't have "display_id": null.
        let prov = read_provenance(&extract);
        let rec = &prov["records"][0];
        let operator_ref = rec["operator_ref"]
            .as_object()
            .expect("operator_ref must be a JSON object");
        assert!(
            !operator_ref.contains_key("display_id"),
            "HIGH-2: operator_ref without display_id must NOT emit 'display_id' key in lane (got: {:?})",
            operator_ref
        );
        assert_eq!(operator_ref["person_id"], "pid-esperie-10e7dd16");
        assert_eq!(
            operator_ref["verified_id"],
            "548F2C562EB4246D025FA80A70552B124755B685"
        );

        // Run the verify script — must PASS.
        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(
            code, 0,
            "HIGH-2: verify must PASS for honest bundle with operator_ref lacking display_id; stdout: {stdout}"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// HIGH-2 regression: a record WITH display_id must also pass the verifier
    /// (both None and Some(display_id) cases must work).
    #[test]
    #[cfg(unix)]
    fn verify_script_passes_with_operator_ref_with_display_id() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![provenance_fixture_with_operator_ref(
            "dec-with-display-id",
            true,
        )];
        let (tmp, _chain_id, svc) =
            make_chain_with_attested_records("prov_with_display_id", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let prov = read_provenance(&extract);
        let rec = &prov["records"][0];
        let operator_ref = rec["operator_ref"]
            .as_object()
            .expect("operator_ref must be a JSON object");
        assert_eq!(
            operator_ref.get("display_id").and_then(|v| v.as_str()),
            Some("esperie"),
            "operator_ref WITH display_id must emit it in the lane"
        );

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(
            code, 0,
            "verify must PASS for honest bundle with operator_ref carrying display_id; stdout: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }

    /// MEDIUM-2 regression: session field is threaded from ingest to lane.
    /// A record with a populated `session` field must project it into the lane
    /// and the verifier must PASS (lane and chain session values match).
    #[test]
    #[cfg(unix)]
    fn provenance_lane_projects_session_field() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let records = vec![provenance_fixture_with_operator_ref("dec-session", false)];
        let (tmp, _chain_id, svc) = make_chain_with_attested_records("prov_session", records);
        let base = tmp.path();
        let out = base.join("bundle.tar");
        export_bundle(base, &svc, Some(&out), None, None).expect("export");
        let extract = base.join("extract");
        extract_tar(&out, &extract);

        let prov = read_provenance(&extract);
        let rec = &prov["records"][0];
        assert_eq!(
            rec["session"].as_str(),
            Some("sess-CONFORMANCE-V1-0001"),
            "MEDIUM-2: session must be projected non-null into the provenance lane"
        );

        let (code, stdout) = run_verify(&extract, &[]);
        assert_eq!(
            code, 0,
            "MEDIUM-2: verify must PASS for honest bundle with session field; stdout: {stdout}"
        );
        let _ = LocalSigningKey::delete_from_keychain(&svc, "01JZ00000000000000000000AA");
    }
}
