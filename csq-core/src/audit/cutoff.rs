//! M16 — Signed export cutoff manifest (`CUTOFF.json`, spec 16 §16.14).
//!
//! At `csq audit export` time this builds a `CUTOFF.json` carrying a signed
//! snapshot of the chain HEAD `(latest_hash, latest_seq)`, the most recent
//! external-anchor reference (`latest_anchor_ref`, the M14 link), and the
//! `export_ts`. The cutoff is signed by the genesis-anchored export key over the
//! SAME canonical-hash → sign-32-raw-bytes contract used by every chain record
//! (spec 12 §12.13.8), so a third-party auditor reproduces the cutoff hash with
//! the SAME routine the embedded `verify` script already runs on chain records.
//!
//! # Why a dedicated `CUTOFF.json` (not `BUNDLE.lock`)
//!
//! M09 already defines `BUNDLE.lock` as the bundle's file-checksum manifest and
//! `BUNDLE.sig` as the Ed25519 signature over it (spec 16 §16.2–16.3); the
//! embedded `verify` script parses `BUNDLE.lock` line-by-line. The M16 cutoff is
//! a distinct artifact and lands in its own file so the file-manifest contract
//! is untouched. `CUTOFF.json` is itself covered by `BUNDLE.lock` (so
//! `BUNDLE.sig` protects it from a post-export swap) AND carries its own
//! canonical-form signature (so the cutoff tuple is reproducibly verifiable on
//! its own, independent of the file manifest).
//!
//! This is an explicit, acknowledged deviation from the M16 milestone's literal
//! "emit a `BUNDLE.lock` carrying the signed cutoff" wording — that wording
//! predates M09's `BUNDLE.lock` = file-manifest semantics. Per
//! `rules/specs-authority.md` Rule 5 the deviation is recorded in spec 16 §16.14.
//!
//! # Tamper-evidence (threat model)
//!
//! `latest_hash` + `latest_seq` are signed at export time. Against an attacker
//! who does NOT hold the genesis key (the post-export interception case: the
//! bundle is handed to an auditor and tampered in transit), a tail truncation
//! (dropping records `k+1..n`) leaves a chain whose HEAD seq/hash no longer
//! match the signed cutoff — the verify script's cutoff cross-check FAILs, and
//! the attacker cannot re-sign the cutoff to match. This is belt-and-suspenders
//! with `BUNDLE.lock` (which already SHA-256s the full `chain.jsonl`, signed by
//! `BUNDLE.sig` — spec 16 §16.3.2); the cutoff additionally makes the head
//! snapshot EXPLICIT and signed, and carries the M14 `latest_anchor_ref` that
//! `BUNDLE.lock` does not.
//!
//! It does NOT — and cannot — defend against an attacker who HOLDS the
//! genesis-anchored key: such an attacker re-signs the chain, the cutoff, and
//! `BUNDLE.sig` together and produces a bundle that PASSes identically. That is
//! the irreducible self-attestation boundary documented at spec 16 §16.3.1
//! (the auditor MUST confirm the genesis key out-of-band). The cutoff narrows
//! nothing here and widens nothing — it adds the `key_id == genesis` check, so
//! the attacker must swap the same key everywhere they already had to.

use serde::Serialize;

use crate::audit::persist::sha256_hex;
use crate::audit::traits::SigningKey;
use crate::audit::types::{EventPayload, KeyId, Sha256Hex, SignedRecord};

/// The cutoff-manifest format version. Bumped only on a breaking change to the
/// canonical pre-image field set or order (the verify script pins this).
pub const CUTOFF_VERSION: &str = "1";

/// Errors returned by [`build_cutoff_json`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CutoffError {
    /// Signing the cutoff hash failed.
    #[error("cutoff signing failed: {0}")]
    Signing(String),
    /// Serializing the cutoff manifest or canonical view failed.
    #[error("cutoff serialization failed: {0}")]
    Serialize(String),
    /// The recomputed cutoff hash did not hex-decode to 32 bytes.
    #[error("cutoff hash decode failed: {0}")]
    HashDecode(String),
}

/// Reference to the most recent external-anchor acknowledgement in the chain.
///
/// `ack_seq` is the seq of the `ReplicationAck` chain record itself — the
/// chain-authoritative anchor evidence (the per-sink state file is NOT in the
/// bundle and is attacker-writable per spec 12 §12.18.3 H2). An auditor locates
/// `chain.jsonl[ack_seq]` and confirms it is a `replication_ack` carrying this
/// `sink` + `sink_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorRef {
    /// Name of the sink that acknowledged the anchor.
    pub sink: String,
    /// Sink-assigned identifier from the acknowledgement.
    pub sink_id: String,
    /// Seq of the `ReplicationAck` chain record carrying this acknowledgement.
    pub ack_seq: u64,
}

/// On-disk `CUTOFF.json` shape.
///
/// Field order is significant: it is the declaration order the canonical
/// pre-image ([`CanonicalCutoffView`]) and the embedded `verify` script both
/// reproduce. `signature` is excluded from the pre-image; `cutoff_hash` is
/// forced to the 64-zero genesis sentinel while hashing.
#[derive(Debug, Clone, Serialize)]
pub struct CutoffManifest {
    /// Format version ([`CUTOFF_VERSION`]).
    pub cutoff_version: String,
    /// Chain this cutoff snapshots — binds the cutoff to its chain (anti
    /// cross-chain replay, mirroring the §12.15 intent-hash `chain_id` bind).
    pub chain_id: String,
    /// `canonical_hash` of the chain HEAD record at export time.
    pub latest_hash: String,
    /// `seq` of the chain HEAD record at export time.
    pub latest_seq: u64,
    /// Most recent external-anchor reference, or `null` if never anchored.
    pub latest_anchor_ref: Option<AnchorRef>,
    /// ISO-8601 UTC export timestamp.
    pub export_ts: String,
    /// SHA-256 of the canonical pre-image (this struct with `cutoff_hash` =
    /// genesis sentinel and `signature` excluded).
    pub cutoff_hash: String,
    /// Key id of the genesis-anchored export key that signed `cutoff_hash`.
    pub key_id: String,
    /// Ed25519 signature (hex) over the 32 raw bytes of `cutoff_hash`.
    pub signature: String,
}

/// Borrowing canonical-pre-image view: `signature` excluded, `cutoff_hash`
/// forced to the genesis sentinel. Field order MUST match [`CutoffManifest`]
/// and `export/verify.py.template::cutoff_canonical_bytes`.
#[derive(Serialize)]
struct CanonicalCutoffView<'a> {
    cutoff_version: &'a str,
    chain_id: &'a str,
    latest_hash: &'a str,
    latest_seq: u64,
    latest_anchor_ref: Option<&'a AnchorRef>,
    export_ts: &'a str,
    cutoff_hash: &'a str,
    key_id: &'a str,
}

/// Finds the most recent `ReplicationAck` in `records` (scanning from the tail)
/// and projects it to an [`AnchorRef`]. Returns `None` when the chain has never
/// been anchored.
fn find_latest_anchor_ref(records: &[SignedRecord]) -> Option<AnchorRef> {
    records.iter().rev().find_map(|r| match &r.payload {
        EventPayload::ReplicationAck(p) => Some(AnchorRef {
            sink: p.sink.as_str().to_string(),
            sink_id: p.sink_id.as_str().to_string(),
            ack_seq: r.seq,
        }),
        _ => None,
    })
}

/// Builds and signs the `CUTOFF.json` bytes for an export bundle.
///
/// - `chain_id` — the chain being exported.
/// - `latest_hash` / `latest_seq` — the chain HEAD snapshot. **The caller MUST
///   source these from the SAME raw `chain.jsonl` last line the embedded verify
///   script computes its head from** (export.rs reads the last raw line as JSON
///   and extracts `seq` + `canonical_hash`), NOT from a `SignedRecord`-parsed
///   view — `verify_chain` and the export key/anchor scan both SKIP legacy v1
///   records (`schema_version:"1"` lines that fail `SignedRecord` parse), so a
///   head derived from the parsed set could diverge from the bundled raw head
///   and produce a cutoff that false-FAILs the verifier (H-1).
/// - `records` — the parsed (v2) chain records; the latest `ReplicationAck`
///   supplies `latest_anchor_ref`. v1 records are correctly absent here (they
///   carry no `ReplicationAck`), mirroring `verify_chain`'s v1-skip.
/// - `export_ts` — ISO-8601 UTC export timestamp.
/// - `key_id` / `signing_key` — the genesis-anchored export key (same key that
///   signs `BUNDLE.sig`).
///
/// The signature is over the 32 raw bytes of the recomputed `cutoff_hash`, the
/// §12.13.8 unified signing contract the verify script reproduces for every
/// chain record.
#[allow(clippy::too_many_arguments)]
pub fn build_cutoff_json(
    chain_id: &str,
    latest_hash: &str,
    latest_seq: u64,
    records: &[SignedRecord],
    export_ts: &str,
    key_id: &KeyId,
    signing_key: &dyn SigningKey,
) -> Result<Vec<u8>, CutoffError> {
    let latest_anchor_ref = find_latest_anchor_ref(records);
    build_cutoff_json_from_parts(
        chain_id,
        latest_hash,
        latest_seq,
        latest_anchor_ref,
        export_ts,
        key_id,
        signing_key,
    )
}

/// Core canonical-form + sign routine. Takes every cutoff field explicitly so
/// callers (and tests) can construct a fully-specified, self-consistent cutoff.
/// `build_cutoff_json` is the production wrapper that derives `latest_anchor_ref`
/// from the chain records.
///
/// # Caller contract
///
/// This routine signs WHATEVER fields it is given — it does not validate them
/// against any chain. The caller MUST ensure `latest_hash` / `latest_seq` are
/// the real chain HEAD (sourced from the bundled `chain.jsonl`'s last raw line,
/// per `build_cutoff_json`'s wrapper) and that `latest_anchor_ref`, if present,
/// names an actual `ReplicationAck` in that chain. A cutoff built from
/// inconsistent parts is internally well-formed (its signature verifies) but
/// will FAIL the verify script's HEAD/anchor cross-check (Step 7). The verify
/// script is the backstop; this builder is not.
#[allow(clippy::too_many_arguments)]
pub fn build_cutoff_json_from_parts(
    chain_id: &str,
    latest_hash: &str,
    latest_seq: u64,
    latest_anchor_ref: Option<AnchorRef>,
    export_ts: &str,
    key_id: &KeyId,
    signing_key: &dyn SigningKey,
) -> Result<Vec<u8>, CutoffError> {
    // 1) Canonical pre-image: cutoff_hash = genesis sentinel, signature absent.
    let view = CanonicalCutoffView {
        cutoff_version: CUTOFF_VERSION,
        chain_id,
        latest_hash,
        latest_seq,
        latest_anchor_ref: latest_anchor_ref.as_ref(),
        export_ts,
        cutoff_hash: Sha256Hex::GENESIS,
        key_id: key_id.as_str(),
    };
    let canonical = serde_json::to_vec(&view).map_err(|e| CutoffError::Serialize(e.to_string()))?;
    let cutoff_hash = sha256_hex(&canonical);

    // 2) Sign the 32 raw bytes of cutoff_hash (§12.13.8 unified contract).
    let digest: [u8; 32] = {
        let bytes =
            hex::decode(&cutoff_hash).map_err(|e| CutoffError::HashDecode(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(CutoffError::HashDecode(
                "cutoff_hash decoded to wrong length (expected 32 bytes)".to_string(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };
    let sig = signing_key
        .sign(&digest)
        .map_err(|e| CutoffError::Signing(e.to_string()))?;
    let signature = hex::encode(sig.0);

    // 3) Final on-disk manifest (with real cutoff_hash + signature).
    let manifest = CutoffManifest {
        cutoff_version: CUTOFF_VERSION.to_string(),
        chain_id: chain_id.to_string(),
        latest_hash: latest_hash.to_string(),
        latest_seq,
        latest_anchor_ref,
        export_ts: export_ts.to_string(),
        cutoff_hash,
        key_id: key_id.as_str().to_string(),
        signature,
    };
    serde_json::to_vec_pretty(&manifest).map_err(|e| CutoffError::Serialize(e.to_string()))
}
