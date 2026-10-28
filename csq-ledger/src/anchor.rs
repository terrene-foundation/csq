//! Anchor-to-sink strengthening (M10 Strengthening 1, PRIMARY DIRECTIVE 3).
//!
//! When `--anchor-to-sink <name>` is configured, csq-ledger periodically
//! submits its signed checkpoint to an external sink at the configured cadence
//! (default 1/day). The anchor receipt is stored back in csq-ledger's storage
//! and surfaced via `GET /v1/checkpoint`'s `anchored_to` field.
//!
//! # Re-uses csq-core's M07 `LedgerSink` trait (PRIMARY DIRECTIVE 3)
//!
//! csq-ledger defines NO new sink abstraction. It consumes
//! `csq_core::audit::traits::LedgerSink` and the M07 reference-impl catalog
//! (`RekorSink`, `S3ObjectLockSink`, ...). The audit primitive:
//!
//! ```bash
//! grep -rEn 'trait\s+\w*Sink\b' csq-ledger/src/ --include='*.rs'
//! # Expected: 0 matches (no new sink trait defined here)
//! ```
//!
//! is the structural enforcement.
//!
//! # The checkpoint-as-record encoding
//!
//! `LedgerSink::append` takes a `&SignedRecord`. A checkpoint is not itself a
//! `SignedRecord`, so the anchor wraps the checkpoint's `(tree_size, root_hash)`
//! commitment into a `SignedRecord` of kind [`EventKind::ReleaseAuth`]:
//!
//! - `release_tag` = `"csq-ledger-checkpoint-<tree_size>"`
//! - `artifact_sha256` = the checkpoint root hash
//! - `record_id` = a deterministic ULID-shaped id derived from the root hash
//!
//! `ReleaseAuth` is the closest existing event kind for "an authorized
//! commitment to a content hash" — it carries exactly the two fields a
//! checkpoint commitment needs (a tag and a content digest). The external sink
//! stores this record; its receipt is the proof the checkpoint was witnessed.

use std::sync::Arc;

use csq_core::audit::traits::LedgerSink;
use csq_core::audit::types::{
    Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, ReleaseAuthPayload, Sha256Hex,
    SignedRecord,
};

use crate::checkpoint::Checkpoint;
use crate::storage::AnchorReceipt;

/// An anchor target: a named M07 `LedgerSink` plus the cadence between
/// routine anchors.
pub struct AnchorTarget {
    /// The sink to anchor to (an M07 reference impl behind `dyn LedgerSink`).
    pub sink: Arc<dyn LedgerSink>,
    /// Seconds between routine anchors (default 86400 = 1 day).
    pub cadence_secs: u64,
}

/// Builds the `SignedRecord` that commits a checkpoint to an external sink.
///
/// The record carries the checkpoint's root hash as `artifact_sha256` and the
/// tree size in the `release_tag`. The `record_id` is a ULID-shaped 26-char
/// Crockford-Base32 id derived from the root hash so the same checkpoint maps
/// to a stable sink id (idempotent re-anchor).
pub fn checkpoint_as_record(checkpoint: &Checkpoint) -> Result<SignedRecord, AnchorError> {
    let root_hash = Sha256Hex::try_new(checkpoint.root_hash.clone())
        .map_err(|_| AnchorError::Encode("checkpoint root_hash is not 64-char lowercase hex"))?;

    let record_id = derive_checkpoint_record_id(&checkpoint.root_hash, checkpoint.tree_size);
    let record_id = RecordId::try_new(record_id)
        .map_err(|_| AnchorError::Encode("derived checkpoint record_id is malformed"))?;

    // The chain_id namespaces all checkpoint anchors from this ledger. A fixed
    // ULID-shaped sentinel (26 Crockford Base32 chars, no I/L/O/U) is
    // sufficient — the sink dedups on record_id.
    let chain_id = RecordId::try_new("01JCSQ0000000000000CKPT000")
        .map_err(|_| AnchorError::Encode("checkpoint chain_id sentinel is malformed"))?;

    let key_id = KeyId::try_new(checkpoint.signed_by_key_id.clone())
        .map_err(|_| AnchorError::Encode("checkpoint signed_by_key_id is malformed"))?;

    let signature_bytes = decode_sig(&checkpoint.signature)?;

    Ok(SignedRecord {
        schema_version: "2".to_string(),
        record_id,
        chain_id,
        seq: checkpoint.tree_size,
        prev_hash: Sha256Hex::genesis(),
        kind: EventKind::ReleaseAuth,
        payload: EventPayload::ReleaseAuth(ReleaseAuthPayload {
            release_tag: format!("csq-ledger-checkpoint-{}", checkpoint.tree_size),
            artifact_sha256: root_hash.clone(),
        }),
        ts: chrono::Utc::now().to_rfc3339(),
        key_id,
        canonical_hash: root_hash,
        signature: Ed25519Signature::new(signature_bytes),
        actor: None,
        authority: None,
        trust: None,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: None,
        verification_level: None,
    })
}

/// Submits `checkpoint` to `target.sink` and returns the resulting
/// [`AnchorReceipt`] for storage + the `anchored_to` field.
pub async fn anchor_checkpoint(
    checkpoint: &Checkpoint,
    target: &AnchorTarget,
) -> Result<AnchorReceipt, AnchorError> {
    let record = checkpoint_as_record(checkpoint)?;
    let receipt = target
        .sink
        .append(&record)
        .await
        .map_err(|e| AnchorError::Sink(format!("{e:?}")))?;
    // Integrity labeling (security-L1): a sink that returns an inclusion proof
    // (e.g. Rekor) is recorded as witnessed-WITH-proof (`unverified = false`); a
    // sink that returns NO proof (e.g. a WORM object store that only acks
    // storage) is witnessed-ON-TRUST (`unverified = true`). This distinction is
    // surfaced through `GET /v1/checkpoint`'s `anchored_to.unverified` so an
    // operator can tell "the sink proved inclusion" from "the sink merely
    // acked". NOTE: full cryptographic verification that the returned proof
    // commits to this checkpoint's record_id/root is sink-dependent and deferred
    // to Phase B — M10 labels on proof PRESENCE, not proof validity.
    let unverified = receipt.inclusion_proof.is_none();
    Ok(AnchorReceipt {
        sink: receipt.sink.as_str().to_string(),
        anchor_id: receipt.sink_id.as_str().to_string(),
        tree_size: checkpoint.tree_size,
        root_hash: checkpoint.root_hash.clone(),
        anchored_at: receipt.anchored_at,
        unverified,
    })
}

/// Derives a stable 26-char Crockford-Base32 ULID-shaped record id from the
/// checkpoint root hash + tree size. Deterministic so re-anchoring the same
/// checkpoint maps to the same id.
fn derive_checkpoint_record_id(root_hash_hex: &str, tree_size: u64) -> String {
    use sha2::{Digest, Sha256};
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut hasher = Sha256::new();
    hasher.update(root_hash_hex.as_bytes());
    hasher.update(tree_size.to_be_bytes());
    let digest = hasher.finalize();
    // Map the first 26 bytes of the digest into Crockford Base32 chars.
    //
    // INVARIANT (security-L2): the `% CROCKFORD.len()` reduction is bias-free
    // ONLY because the alphabet is exactly 32 chars and the input byte range is
    // 256 — 256 % 32 == 0, so every Crockford char is hit by exactly 8 byte
    // values (uniform). If the alphabet length is ever changed to a value that
    // does NOT divide 256, this modulo silently becomes biased (some chars more
    // likely than others), weakening the id's collision resistance. Any change
    // to `CROCKFORD` MUST preserve len() ∈ {1,2,4,8,16,32,64,128,256} or replace
    // the modulo with rejection sampling.
    debug_assert_eq!(
        CROCKFORD.len(),
        32,
        "Crockford Base32 alphabet must be 32 chars"
    );
    digest
        .iter()
        .take(26)
        .map(|b| CROCKFORD[(*b as usize) % CROCKFORD.len()] as char)
        .collect()
}

/// Decodes a 64-byte signature from hex.
fn decode_sig(hex_sig: &str) -> Result<[u8; 64], AnchorError> {
    let bytes = hex::decode(hex_sig)
        .map_err(|_| AnchorError::Encode("checkpoint signature is not valid hex"))?;
    if bytes.len() != 64 {
        return Err(AnchorError::Encode("checkpoint signature is not 64 bytes"));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// An error from the anchor flow.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// The checkpoint could not be encoded as a `SignedRecord`.
    #[error("anchor encode error: {0}")]
    Encode(&'static str),
    /// The sink rejected or could not process the anchor (message pre-redacted
    /// by the sink's own `RedactedString` discipline).
    #[error("anchor sink error: {0}")]
    Sink(String),
    /// `--anchor-to-sink <name>` named a sink whose `csq-core/<name>-sink`
    /// feature was not compiled into this binary.
    #[error("anchor sink '{0}' not compiled in — rebuild with the matching csq-core/<name>-sink feature")]
    SinkNotCompiledIn(String),
}

/// Resolves a sink name (from `--anchor-to-sink`) to an M07 reference-impl
/// behind `dyn LedgerSink`. The impl is only available when the binary was
/// built with the matching `csq-core/<name>-sink` feature; otherwise this
/// returns [`AnchorError::SinkNotCompiledIn`] (fail-loud, never a silent
/// no-op — matching the M07 fail-loud-on-not-compiled-in posture).
///
/// PRIMARY DIRECTIVE 3: the returned sink IS an M07 `LedgerSink`. csq-ledger
/// defines no sink trait of its own.
pub fn resolve_sink(name: &str) -> Result<Arc<dyn LedgerSink>, AnchorError> {
    match name {
        #[cfg(feature = "anchor-rekor")]
        "rekor" => Ok(Arc::new(
            csq_core::audit::impls::sinks::RekorSink::with_defaults()
                .map_err(|_| AnchorError::Encode("rekor sink config invalid"))?,
        )),
        #[cfg(feature = "anchor-s3")]
        "s3" => Ok(Arc::new(
            csq_core::audit::impls::sinks::S3ObjectLockSink::with_defaults()
                .map_err(|_| AnchorError::Encode("s3 sink config invalid"))?,
        )),
        #[cfg(feature = "anchor-azure")]
        "azure" => Ok(Arc::new(
            csq_core::audit::impls::sinks::AzureImmutableBlobSink::with_defaults()
                .map_err(|_| AnchorError::Encode("azure sink config invalid"))?,
        )),
        #[cfg(feature = "anchor-gcp")]
        "gcp" => Ok(Arc::new(
            csq_core::audit::impls::sinks::GcpBucketLockSink::with_defaults()
                .map_err(|_| AnchorError::Encode("gcp sink config invalid"))?,
        )),
        other => Err(AnchorError::SinkNotCompiledIn(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::signing::ServerSigningKey;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// In-test mock sink. NOT a new sink TRAIT — it IMPLEMENTS csq-core's M07
    /// `LedgerSink` (PRIMARY DIRECTIVE 3 satisfied: we consume the trait).
    struct MockSink {
        name: csq_core::audit::types::SinkName,
        store: Mutex<HashMap<RecordId, SignedRecord>>,
        counter: Mutex<u64>,
        /// When `true`, the mock returns an inclusion proof on `append` (models
        /// a Rekor-style sink); when `false`, no proof (models a WORM ack-only
        /// sink). Drives the `AnchorReceipt::unverified` labeling (security-L1).
        returns_proof: bool,
    }

    impl MockSink {
        fn new() -> Self {
            Self {
                name: csq_core::audit::types::SinkName::try_new("mock-anchor").unwrap(),
                store: Mutex::new(HashMap::new()),
                counter: Mutex::new(0),
                returns_proof: false,
            }
        }

        fn with_proof() -> Self {
            Self {
                returns_proof: true,
                ..Self::new()
            }
        }
    }

    #[async_trait::async_trait]
    impl LedgerSink for MockSink {
        fn name(&self) -> &str {
            self.name.as_str()
        }
        async fn append(
            &self,
            record: &SignedRecord,
        ) -> Result<csq_core::audit::types::SinkReceipt, csq_core::audit::types::SinkError>
        {
            let mut ctr = self.counter.lock().unwrap();
            let idx = *ctr;
            *ctr += 1;
            drop(ctr);
            let sink_id =
                csq_core::audit::types::SinkId::try_new(format!("mock-anchor-{idx}")).unwrap();
            self.store
                .lock()
                .unwrap()
                .insert(record.record_id.clone(), record.clone());
            Ok(csq_core::audit::types::SinkReceipt {
                sink: self.name.clone(),
                sink_id,
                anchored_at: record.ts.clone(),
                inclusion_proof: if self.returns_proof {
                    Some("deadbeef".to_string())
                } else {
                    None
                },
            })
        }
        async fn verify_at(
            &self,
            id: &RecordId,
        ) -> Result<SignedRecord, csq_core::audit::types::SinkError> {
            self.store.lock().unwrap().get(id).cloned().ok_or_else(|| {
                csq_core::audit::types::SinkError::NotFound {
                    record_id: id.clone(),
                }
            })
        }
    }

    /// `test anchor_checkpoint_produces_receipt_via_m07_sink`
    #[tokio::test]
    async fn anchor_checkpoint_produces_receipt_via_m07_sink() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let leaves: Vec<merkle::Hash> = (0..3u8).map(|i| merkle::hash_leaf(&[i])).collect();
        let root = merkle::merkle_root(&leaves);
        let cp = Checkpoint::sign(3, &root, &key, None);

        let target = AnchorTarget {
            sink: Arc::new(MockSink::new()),
            cadence_secs: 86400,
        };
        let receipt = anchor_checkpoint(&cp, &target).await.unwrap();
        assert_eq!(receipt.sink, "mock-anchor");
        assert!(receipt.anchor_id.starts_with("mock-anchor-"));
        assert_eq!(receipt.tree_size, 3);
        assert_eq!(receipt.root_hash, cp.root_hash);
        // The mock returns NO inclusion proof → witnessed-on-trust (security-L1).
        assert!(
            receipt.unverified,
            "ack-only sink (no proof) → unverified == true"
        );
    }

    /// `test anchor_receipt_unverified_reflects_proof_presence`
    ///
    /// security-L1: a sink returning an inclusion proof yields `unverified ==
    /// false` (witnessed-with-proof); a sink with no proof yields `true`
    /// (witnessed-on-trust). The label distinguishes the two on
    /// `GET /v1/checkpoint`.
    #[tokio::test]
    async fn anchor_receipt_unverified_reflects_proof_presence() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let root = merkle::merkle_root(&[merkle::hash_leaf(b"p")]);
        let cp = Checkpoint::sign(1, &root, &key, None);

        // Sink WITH proof → unverified == false.
        let with_proof = AnchorTarget {
            sink: Arc::new(MockSink::with_proof()),
            cadence_secs: 86400,
        };
        let r_proof = anchor_checkpoint(&cp, &with_proof).await.unwrap();
        assert!(
            !r_proof.unverified,
            "sink returning a proof → unverified == false"
        );

        // Sink WITHOUT proof → unverified == true.
        let no_proof = AnchorTarget {
            sink: Arc::new(MockSink::new()),
            cadence_secs: 86400,
        };
        let r_trust = anchor_checkpoint(&cp, &no_proof).await.unwrap();
        assert!(
            r_trust.unverified,
            "sink with no proof → unverified == true"
        );
    }

    /// `test anchor_checkpoint_record_id_is_deterministic`
    #[tokio::test]
    async fn anchor_checkpoint_record_id_is_deterministic() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let root = merkle::merkle_root(&[merkle::hash_leaf(b"x")]);
        let cp = Checkpoint::sign(1, &root, &key, None);
        let r1 = checkpoint_as_record(&cp).unwrap();
        let r2 = checkpoint_as_record(&cp).unwrap();
        assert_eq!(
            r1.record_id, r2.record_id,
            "same checkpoint → same record_id (idempotent anchor)"
        );
    }

    /// `test anchor_checkpoint_record_is_release_auth_with_root`
    #[test]
    fn anchor_checkpoint_record_is_release_auth_with_root() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let root = merkle::merkle_root(&[merkle::hash_leaf(b"y")]);
        let cp = Checkpoint::sign(1, &root, &key, None);
        let rec = checkpoint_as_record(&cp).unwrap();
        assert_eq!(rec.kind, EventKind::ReleaseAuth);
        match rec.payload {
            EventPayload::ReleaseAuth(p) => {
                assert_eq!(p.artifact_sha256.as_str(), cp.root_hash);
                assert_eq!(p.release_tag, "csq-ledger-checkpoint-1");
            }
            _ => panic!("expected ReleaseAuth payload"),
        }
    }
}
