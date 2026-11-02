//! Owner-origin attestation — the proof that a delivery came from the owner's
//! Telegram account and not from another process on the same machine.
//!
//! # Construction
//!
//! `MAC = HMAC-SHA256(origin_key, ATTESTATION_ID || to_pid || to_started_at ||
//! update_id || SHA256(body))`, hex encoded. The domain tag `ATTESTATION_ID`
//! separates this MAC from any other use of the same origin key; the process
//! binding (`to_pid`, `to_started_at`) makes a MAC minted for one session
//! useless for another; `update_id` and the body hash bind the exact message.
//!
//! # Why `mint` is private
//!
//! The origin key lives in the vault and is loaded by csq-core only. If minting
//! were reachable from the separate `csq` CLI crate (or an MCP server built on
//! it), that crate could manufacture an "owner" delivery out of thin air. So
//! [`OwnerAttestation`] has private fields and the sole constructor is
//! `pub(crate)`. Verification is public because verifying cannot forge.
//!
//! # Logging
//!
//! The MAC is not secret-key material, but it is not logged either: a MAC in a
//! log is a replayable value. Failures are reported by a fixed tag.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::validator::ValidatedUpdate;

/// Domain/version tag mixed into every MAC (`id` in the design's MAC layout).
const ATTESTATION_ID: &[u8] = b"csq.bridge.owner-attestation.v1";

type HmacSha256 = Hmac<Sha256>;

/// A MAC binding one validated update to one target session.
///
/// Private fields: constructible only through `mint` inside csq-core.
#[derive(Clone)]
pub struct OwnerAttestation {
    mac_hex: String,
}

impl OwnerAttestation {
    /// Mints the owner-origin proof for `update` targeting `(to_pid,
    /// to_started_at)`. The daemon ingest (`daemon::telegram_bridge`) is the
    /// only caller.
    ///
    /// `#[allow(dead_code)]`: kept while the ingest caller and its tests land
    /// together in the same lane; a plain `cargo clippy` of this module alone
    /// would otherwise see no non-test caller. The attribute does NOT widen
    /// visibility — `mint` stays `pub(crate)` because making it public would
    /// hand the `csq` CLI a forging path (that crate can load the origin key).
    #[allow(dead_code)]
    pub(crate) fn mint(
        update: &ValidatedUpdate,
        to_pid: u32,
        to_started_at: u64,
        key: &[u8; 32],
    ) -> Self {
        let mac = compute(key, update, to_pid, to_started_at);
        Self {
            mac_hex: hex::encode(mac),
        }
    }

    /// Verifies this attestation against the update and target it claims.
    ///
    /// False for a body that changed by even one byte, a different target, a
    /// different update id, or a malformed stored MAC.
    pub fn verify(
        &self,
        update: &ValidatedUpdate,
        to_pid: u32,
        to_started_at: u64,
        key: &[u8; 32],
    ) -> bool {
        let Ok(stored) = hex::decode(&self.mac_hex) else {
            return false;
        };
        if stored.len() != 32 {
            return false;
        }
        let expected = compute(key, update, to_pid, to_started_at);
        bool::from(stored.ct_eq(expected.as_slice()))
    }

    /// Hex MAC, for propagation over the daemon IPC and for audit display.
    /// Reading it grants no ability to mint another.
    pub fn mac_hex(&self) -> &str {
        &self.mac_hex
    }

    /// Rebuilds an attestation from a MAC that was stored on a message record,
    /// so a render/verify path does not have to re-mint.
    ///
    /// Returns `None` unless the string is exactly 64 lowercase hex digits
    /// (the canonical form [`hex::encode`] produces for a 32-byte MAC). An
    /// uppercase or malformed value is refused rather than normalised, so a
    /// stored record cannot smuggle an alternate encoding past [`Self::verify`].
    ///
    /// `pub(crate)`: the constructor is not exposed to the `csq` CLI crate —
    /// constructing is harmless without the key, but keeping one doorway keeps
    /// the forging surface auditable.
    #[allow(dead_code)]
    pub(crate) fn from_stored_mac(mac_hex: &str) -> Option<Self> {
        if mac_hex.len() != 64
            || !mac_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        Some(Self {
            mac_hex: mac_hex.to_owned(),
        })
    }
}

fn compute(key: &[u8; 32], update: &ValidatedUpdate, to_pid: u32, to_started_at: u64) -> [u8; 32] {
    // RFC 2104 HMAC accepts keys of ANY length: `get_der_key` pads a short key
    // and hashes an over-long one, so `new_from_slice` cannot fail for
    // `Hmac<Sha256>`. The expect names that invariant rather than hiding a
    // reachable failure (same posture as `oauth::pkce`'s CSPRNG expect).
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length (RFC 2104)");
    let body = Sha256::digest(update.text.as_bytes());
    mac.update(ATTESTATION_ID);
    mac.update(&to_pid.to_be_bytes());
    mac.update(&to_started_at.to_be_bytes());
    mac.update(&update.update_id.to_be_bytes());
    mac.update(&body);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5au8; 32];

    fn update(text: &str) -> ValidatedUpdate {
        ValidatedUpdate {
            update_id: 77,
            text: text.to_owned(),
            date: 1_000_000,
        }
    }

    #[test]
    fn mint_then_verify_succeeds() {
        let att = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY);
        assert!(att.verify(&update("/clear"), 12, 34, &KEY));
        assert_eq!(att.mac_hex().len(), 64, "hex-encoded 32-byte MAC");
    }

    #[test]
    fn one_byte_body_change_fails() {
        let att = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY);
        assert!(!att.verify(&update("/cleaR"), 12, 34, &KEY));
        assert!(!att.verify(&update("/clear "), 12, 34, &KEY));
    }

    #[test]
    fn wrong_target_fails() {
        let att = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY);
        assert!(!att.verify(&update("/clear"), 13, 34, &KEY));
        assert!(!att.verify(&update("/clear"), 12, 35, &KEY));
        // A PID reused by a different process start is a different target.
        assert!(!att.verify(&update("/clear"), 12, 0, &KEY));
    }

    #[test]
    fn wrong_update_id_fails() {
        let att = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY);
        let mut other = update("/clear");
        other.update_id = 78;
        assert!(!att.verify(&other, 12, 34, &KEY));
    }

    #[test]
    fn wrong_key_fails() {
        let att = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY);
        assert!(!att.verify(&update("/clear"), 12, 34, &[0x5bu8; 32]));
    }

    #[test]
    fn malformed_stored_mac_fails_closed() {
        let mut att = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY);
        att.mac_hex = "not-hex".into();
        assert!(!att.verify(&update("/clear"), 12, 34, &KEY));
        att.mac_hex = "00".repeat(31);
        assert!(!att.verify(&update("/clear"), 12, 34, &KEY));
    }

    #[test]
    fn stored_mac_round_trips_through_verification() {
        let att = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY);
        let rebuilt =
            OwnerAttestation::from_stored_mac(att.mac_hex()).expect("canonical mac accepted");
        assert!(rebuilt.verify(&update("/clear"), 12, 34, &KEY));
        assert!(!rebuilt.verify(&update("/cleaR"), 12, 34, &KEY));
    }

    #[test]
    fn stored_mac_rejects_non_canonical_forms() {
        let canonical = OwnerAttestation::mint(&update("/clear"), 12, 34, &KEY)
            .mac_hex()
            .to_owned();
        assert!(OwnerAttestation::from_stored_mac(&canonical.to_uppercase()).is_none());
        assert!(OwnerAttestation::from_stored_mac(&canonical[..63]).is_none());
        assert!(OwnerAttestation::from_stored_mac(&format!("{canonical}0")).is_none());
        assert!(OwnerAttestation::from_stored_mac(&"g".repeat(64)).is_none());
        assert!(OwnerAttestation::from_stored_mac("").is_none());
    }
}
