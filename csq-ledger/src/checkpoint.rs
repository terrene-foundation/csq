//! Signed tree head (checkpoint) for csq-ledger (M10).
//!
//! A checkpoint is the server's signed commitment to the current Merkle root
//! at a given tree size. It is what `GET /v1/checkpoint` returns and what the
//! `--anchor-to-sink` strengthening submits to an external sink.
//!
//! # Signature pre-image (deterministic)
//!
//! The signature covers a deterministic pre-image so any client can recompute
//! and verify it:
//!
//! ```text
//! preimage := "csq-ledger-checkpoint/v1\n"
//!           || "tree_size=" || decimal(tree_size) || "\n"
//!           || "root_hash="  || hex(root_hash)    || "\n"
//! signature := Ed25519_sign(server_key, preimage_bytes)
//! ```
//!
//! The domain-separation prefix (`csq-ledger-checkpoint/v1`) prevents a
//! checkpoint signature from being replayed as a record signature or vice
//! versa. The `anchored_to` field is NOT part of the pre-image: it is metadata
//! about where the checkpoint was externally witnessed, added AFTER signing,
//! and a verifier checks the anchor against the external sink independently.

use serde::{Deserialize, Serialize};

use crate::merkle::Hash;
use crate::signing::ServerSigningKey;
use crate::storage::AnchorReceipt;

/// The checkpoint signature pre-image domain-separation prefix.
const CHECKPOINT_DOMAIN: &str = "csq-ledger-checkpoint/v1";

/// Where a checkpoint was externally anchored (the M07-sink receipt surface).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchoredTo {
    /// The sink name (e.g. `"rekor"`, `"s3"`).
    pub sink: String,
    /// The sink-assigned anchor id.
    pub anchor_id: String,
    /// RFC 3339 timestamp the anchor was acknowledged.
    pub anchored_at: String,
    /// `true` when the anchor was witnessed ON TRUST (the sink returned no
    /// inclusion proof — only its word that the checkpoint was logged); `false`
    /// when the sink returned an inclusion proof (security-L1). Lets a verifier
    /// distinguish witnessed-with-proof from witnessed-on-trust. M10 labels on
    /// proof PRESENCE; cryptographic proof verification is Phase B.
    pub unverified: bool,
}

impl From<AnchorReceipt> for AnchoredTo {
    fn from(r: AnchorReceipt) -> Self {
        Self {
            sink: r.sink,
            anchor_id: r.anchor_id,
            anchored_at: r.anchored_at,
            unverified: r.unverified,
        }
    }
}

/// A signed tree head. Serializes as the `GET /v1/checkpoint` JSON body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    /// Number of records committed to by `root_hash`.
    pub tree_size: u64,
    /// Lowercase-hex SHA-256 Merkle root over all `tree_size` leaves.
    pub root_hash: String,
    /// The server key id that signed this checkpoint
    /// (`ed25519:<sha256(pubkey)>`).
    pub signed_by_key_id: String,
    /// Lowercase-hex 32-byte server public key (lets an offline verifier check
    /// the signature without a separate key-distribution channel).
    pub public_key: String,
    /// Lowercase-hex 64-byte Ed25519 signature over the deterministic
    /// pre-image (see module docs).
    pub signature: String,
    /// Present when `--anchor-to-sink` is configured AND at least one anchor
    /// has been acknowledged. Absent (skipped in JSON) otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_to: Option<AnchoredTo>,
}

/// Builds the deterministic signature pre-image bytes for a checkpoint.
#[must_use]
pub fn checkpoint_preimage(tree_size: u64, root_hash: &Hash) -> Vec<u8> {
    let mut p = String::new();
    p.push_str(CHECKPOINT_DOMAIN);
    p.push('\n');
    p.push_str("tree_size=");
    p.push_str(&tree_size.to_string());
    p.push('\n');
    p.push_str("root_hash=");
    p.push_str(&hex::encode(root_hash));
    p.push('\n');
    p.into_bytes()
}

impl Checkpoint {
    /// Constructs and signs a checkpoint for `(tree_size, root_hash)` using the
    /// server signing key, attaching the optional `anchored_to` metadata.
    #[must_use]
    pub fn sign(
        tree_size: u64,
        root_hash: &Hash,
        key: &ServerSigningKey,
        anchored_to: Option<AnchoredTo>,
    ) -> Self {
        let preimage = checkpoint_preimage(tree_size, root_hash);
        let sig = key.sign(&preimage);
        Self {
            tree_size,
            root_hash: hex::encode(root_hash),
            signed_by_key_id: key.key_id().to_string(),
            public_key: hex::encode(key.public_key_bytes()),
            signature: hex::encode(sig),
            anchored_to,
        }
    }

    /// Verifies this checkpoint's signature against its embedded public key.
    ///
    /// Returns `false` on any decode error or signature mismatch. A verifier
    /// that pins a key id MUST additionally check `self.signed_by_key_id`
    /// against the pinned id — this method only proves the signature is
    /// internally consistent with the embedded `public_key`.
    #[must_use]
    pub fn verify(&self) -> bool {
        let Ok(root_bytes) = hex::decode(&self.root_hash) else {
            return false;
        };
        if root_bytes.len() != 32 {
            return false;
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_bytes);

        let Ok(pk_bytes) = hex::decode(&self.public_key) else {
            return false;
        };
        if pk_bytes.len() != 32 {
            return false;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);

        let Ok(sig_bytes) = hex::decode(&self.signature) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        // The embedded public_key must derive the claimed key id.
        if crate::signing::derive_key_id(&pk) != self.signed_by_key_id {
            return false;
        }

        let preimage = checkpoint_preimage(self.tree_size, &root);
        crate::signing::verify(&pk, &preimage, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use tempfile::TempDir;

    fn test_key(dir: &std::path::Path) -> ServerSigningKey {
        ServerSigningKey::load_or_generate(dir, None).unwrap()
    }

    /// `test checkpoint_sign_then_verify_round_trips`
    #[test]
    fn checkpoint_sign_then_verify_round_trips() {
        let dir = TempDir::new().unwrap();
        let key = test_key(dir.path());
        let leaves: Vec<Hash> = (0..5u8).map(|i| merkle::hash_leaf(&[i])).collect();
        let root = merkle::merkle_root(&leaves);
        let cp = Checkpoint::sign(5, &root, &key, None);
        assert!(cp.verify(), "freshly-signed checkpoint verifies");
        assert_eq!(cp.tree_size, 5);
        assert_eq!(cp.signed_by_key_id, key.key_id());
    }

    /// `test checkpoint_rejects_tampered_root`
    #[test]
    fn checkpoint_rejects_tampered_root() {
        let dir = TempDir::new().unwrap();
        let key = test_key(dir.path());
        let root = merkle::merkle_root(&[merkle::hash_leaf(b"a")]);
        let mut cp = Checkpoint::sign(1, &root, &key, None);
        // Flip the root hex without re-signing.
        cp.root_hash = "f".repeat(64);
        assert!(!cp.verify(), "tampered root must fail verification");
    }

    /// `test checkpoint_rejects_tampered_tree_size`
    #[test]
    fn checkpoint_rejects_tampered_tree_size() {
        let dir = TempDir::new().unwrap();
        let key = test_key(dir.path());
        let root = merkle::merkle_root(&[merkle::hash_leaf(b"a")]);
        let mut cp = Checkpoint::sign(1, &root, &key, None);
        cp.tree_size = 99;
        assert!(!cp.verify(), "tampered tree_size must fail verification");
    }

    /// `test checkpoint_anchored_to_serializes_when_present`
    #[test]
    fn checkpoint_anchored_to_serializes_when_present() {
        let dir = TempDir::new().unwrap();
        let key = test_key(dir.path());
        let root = merkle::empty_root();
        let anchor = AnchoredTo {
            sink: "rekor".to_string(),
            anchor_id: "rekor-log-3".to_string(),
            anchored_at: "2026-05-29T00:00:00+00:00".to_string(),
            unverified: false,
        };
        let cp = Checkpoint::sign(0, &root, &key, Some(anchor));
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"anchored_to\""));
        assert!(json.contains("rekor-log-3"));
        assert!(json.contains("\"unverified\":false"));
        // The anchor metadata does NOT affect signature validity.
        assert!(cp.verify());
    }

    /// `test checkpoint_anchored_to_absent_when_none`
    #[test]
    fn checkpoint_anchored_to_absent_when_none() {
        let dir = TempDir::new().unwrap();
        let key = test_key(dir.path());
        let cp = Checkpoint::sign(0, &merkle::empty_root(), &key, None);
        let json = serde_json::to_string(&cp).unwrap();
        assert!(
            !json.contains("anchored_to"),
            "anchored_to must be skipped when None"
        );
    }

    /// `test checkpoint_preimage_is_domain_separated`
    #[test]
    fn checkpoint_preimage_is_domain_separated() {
        let root = merkle::empty_root();
        let pre = checkpoint_preimage(0, &root);
        let s = String::from_utf8(pre).unwrap();
        assert!(s.starts_with("csq-ledger-checkpoint/v1\n"));
    }
}
