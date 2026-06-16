//! M12 — Enrolled-key grant types.
//!
//! An `EnrolledKey` is one Ed25519 pubkey with a validity window:
//! `[active_from_seq, retired_at_seq)`. A record at `seq S` counts the key
//! as enrolled iff `active_from_seq <= S < retired_at_seq.unwrap_or(u64::MAX)`.
//!
//! `PactDefinition` carries the PACT-D envelope string for the grant.
//! `AuthorityGrant` combines a `Vec<EnrolledKey>` with a `PactDefinition`.

use serde::{Deserialize, Serialize};

use crate::audit::types::Ed25519PublicKey;

use super::op_class::OpClass;

/// A single enrolled signing key with a per-key validity window.
///
/// Handles member key rotation: when a member's key is rotated, their old
/// key's `retired_at_seq` is set to the first seq where the new key is
/// active. Records signed by the old key at seq < `retired_at_seq` remain
/// valid; records at seq >= `retired_at_seq` must use the new key.
///
/// A key with `retired_at_seq: None` is currently active with no scheduled
/// retirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledKey {
    /// The Ed25519 public key (32 bytes, hex-serialized).
    #[serde(serialize_with = "ser_pubkey", deserialize_with = "de_pubkey")]
    pub pubkey: Ed25519PublicKey,
    /// The first seq at which this key is active (inclusive).
    pub active_from_seq: u64,
    /// The first seq at which this key is retired (exclusive).
    /// `None` = currently active, no scheduled retirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at_seq: Option<u64>,
}

impl EnrolledKey {
    /// Returns `true` if this key is active for a record at `seq`.
    ///
    /// Active iff `active_from_seq <= seq < retired_at_seq.unwrap_or(u64::MAX)`.
    pub fn is_active_at(&self, seq: u64) -> bool {
        seq >= self.active_from_seq && seq < self.retired_at_seq.unwrap_or(u64::MAX)
    }
}

/// The PACT-D envelope for an authority grant.
///
/// `op_classes` names the set of `OpClass` values this grant covers.
/// `definition` is the PACT-D policy text (prose or structured).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PactDefinition {
    /// The op classes this grant covers.
    pub op_classes: Vec<OpClass>,
    /// The PACT-D policy definition text.
    pub definition: String,
}

/// The combined authority grant: enrolled keys + PACT-D envelope.
///
/// Returned by `AuthorityRegistry::resolve(op_class)`.
#[derive(Debug, Clone)]
pub struct AuthorityGrant {
    /// Enrolled keys with validity windows.
    pub keys: Vec<EnrolledKey>,
    /// The PACT-D envelope for this grant.
    pub envelope: PactDefinition,
}

// ---------------------------------------------------------------------------
// Custom (de)serialisers for Ed25519PublicKey ↔ hex string
// ---------------------------------------------------------------------------

fn ser_pubkey<S>(val: &Ed25519PublicKey, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(val.0))
}

fn de_pubkey<'de, D>(d: D) -> Result<Ed25519PublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str = String::deserialize(d)?;
    let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom(format!(
            "pubkey hex must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Ed25519PublicKey(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolled_key_active_at_window() {
        let k = EnrolledKey {
            pubkey: Ed25519PublicKey([1u8; 32]),
            active_from_seq: 10,
            retired_at_seq: Some(20),
        };
        assert!(!k.is_active_at(9), "seq 9 is before activation");
        assert!(k.is_active_at(10), "seq 10 is the first active seq");
        assert!(k.is_active_at(19), "seq 19 is the last active seq");
        assert!(
            !k.is_active_at(20),
            "seq 20 is the retirement seq (exclusive)"
        );
        assert!(!k.is_active_at(100), "retired key not active after window");
    }

    #[test]
    fn enrolled_key_no_retirement() {
        let k = EnrolledKey {
            pubkey: Ed25519PublicKey([2u8; 32]),
            active_from_seq: 5,
            retired_at_seq: None,
        };
        assert!(k.is_active_at(5));
        assert!(
            k.is_active_at(u64::MAX - 1),
            "no retirement — active forever"
        );
    }

    #[test]
    fn enrolled_key_serde_roundtrip() {
        let k = EnrolledKey {
            pubkey: Ed25519PublicKey([0xab; 32]),
            active_from_seq: 0,
            retired_at_seq: Some(100),
        };
        let json = serde_json::to_string(&k).expect("serialize");
        let k2: EnrolledKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(k2.pubkey.0, k.pubkey.0);
        assert_eq!(k2.active_from_seq, k.active_from_seq);
        assert_eq!(k2.retired_at_seq, k.retired_at_seq);
    }
}
