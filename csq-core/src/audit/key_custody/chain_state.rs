//! `chain.json` reader/writer — M04 extension.
//!
//! `chain.json` lives at `<base_dir>/csq-runs/chain.json` (per spec 12 §12.10.4;
//! the same location M02's `write_record_v2` reads + writes). M04 extends its
//! schema with two new optional fields: `signing_key_id` (a `KeyId` string)
//! and `pubkey` (the 32-byte public key as a lowercase hex string). M02's
//! `genesis_seq` and `genesis_ts` fields are preserved on round-trip via the
//! explicit optional fields `genesis_seq` and `genesis_ts` on [`ChainState`].
//!
//! # §5a compliance (PRIMARY METHODOLOGICAL DIRECTIVE)
//!
//! Every write path uses `unique_tmp_path → write → secure_file →
//! atomic_replace` with `remove_file(&tmp)` on every failure branch, per
//! `rules/security.md §5a`. The audit primitive:
//!
//! ```bash
//! grep -rn 'unique_tmp_path' csq-core/src/audit/key_custody/ --include='*.rs' | grep -v '#\[cfg(test)\]'
//! # For each match: confirm cleanup on all 3 failure branches.
//! ```

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit::key_custody::KeyCustodyError;
use crate::audit::types::{Ed25519PublicKey, KeyId};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

/// M04-extended view of `chain.json`.
///
/// Fields present before M04 (`chain_id`, `genesis_seq`, `genesis_ts`) are
/// preserved verbatim as explicit optional fields with `#[serde(default)]`.
/// This avoids the compile-time ambiguity of `#[serde(flatten)]` (M-1: the
/// flatten catch-all prevented `deny(unknown_fields)` and caused serde to
/// reject unrelated extra fields) while still letting M04 read and write
/// `signing_key_id` and `pubkey` atomically with the rest of the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Chain identifier — `<username>/<machine>/<chain_uuid>` or similar.
    /// Present in all chain.json files regardless of M04.
    #[serde(default)]
    pub chain_id: String,

    /// Chain genesis sequence number (from M02). Optional — absent on
    /// pre-M02 chain.json files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_seq: Option<u64>,

    /// Chain genesis timestamp (from M02). Optional — absent on pre-M02
    /// chain.json files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_ts: Option<String>,

    /// Monotonic rotation counter (R1 M-6 anti-replay defence). Starts at 0
    /// for a freshly-initialised chain; `rotate_key` increments by 1 and
    /// chain.json save persists the new value. Replay of an old KeyRotate
    /// record can be detected by comparing the record's expected count to
    /// `rotation_count`.
    ///
    /// Also used by `rotate.rs` (R1 M-5) to name the historical keychain
    /// slot opaquely as `format!("historical/{rotation_count}")` instead
    /// of the publicly-enumerable `KeyId` string.
    #[serde(default)]
    pub rotation_count: u64,

    /// The first sequence number at which signature verification is mandatory
    /// (R1-DEEP-2 signing cutoff). Written by `csq audit init` at the time
    /// signing is activated — set to the next seq to be written (0 for a
    /// freshly-initialised chain, or `last_seq + 1` for an existing chain).
    ///
    /// Records with `seq >= signing_active_since_seq` MUST carry a real
    /// (non-placeholder) signature that verifies against the stored public key;
    /// records before the cutoff are allowed to carry the placeholder key
    /// (pre-`csq audit init` migration window).
    ///
    /// When `None` (absent from chain.json — an install that never ran
    /// `csq audit init`), all placeholder-key records are tolerated regardless
    /// of seq (pre-init migration concession).
    ///
    /// `#[serde(default)]` ensures old chain.json files without this field
    /// deserialise cleanly (field defaults to `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_active_since_seq: Option<u64>,

    /// Current active signing key identifier.
    /// `None` before `csq audit init` has run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<KeyId>,

    /// Raw 32-byte public key serialised as lowercase hex (64 chars).
    /// `None` before `csq audit init` has run.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_pubkey_opt",
        deserialize_with = "de_pubkey_opt",
        default
    )]
    pub pubkey: Option<Ed25519PublicKey>,

    /// M12 — The first `seq` at which roster membership is enforced.
    ///
    /// Written by `csq audit roster install` at install time; set to the
    /// chain's current tail seq + 1 so pre-existing records continue to
    /// verify with M11 self-authorization behavior (no brick).
    ///
    /// `None` means no roster has been installed yet (community / pre-M12).
    /// When `None`, `verify_record_multi_sig` uses pure M11 behavior for ALL
    /// records regardless of edition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_activation_seq: Option<u64>,

    /// M12 — Rollback-defense floor for `roster_version`.
    ///
    /// When a new roster is installed, `roster_version_floor` is bumped to
    /// the incoming `roster.roster_version`. A roster with
    /// `roster_version < roster_version_floor` is rejected with
    /// `AuthorityError::RosterRollback` (fail closed).
    ///
    /// `None` means no roster has ever been installed; floor is treated as 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_version_floor: Option<u64>,
}

/// Path to `chain.json` for a given `base_dir`.
///
/// Unified with M02's location per spec 12 §12.10.4 — `csq-runs/chain.json`.
pub fn chain_json_path(base_dir: &Path) -> PathBuf {
    base_dir.join("csq-runs").join("chain.json")
}

impl ChainState {
    /// Creates a minimal fresh `ChainState` with the given `chain_id`.
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis_seq: None,
            genesis_ts: None,
            rotation_count: 0,
            signing_active_since_seq: None,
            signing_key_id: None,
            pubkey: None,
            roster_activation_seq: None,
            roster_version_floor: None,
        }
    }

    /// Read `chain.json` from disk.
    ///
    /// Returns a fresh default state (with empty `chain_id`) when the file
    /// does not exist yet — callers must set `chain_id` before writing back.
    pub fn load(base_dir: &Path) -> Result<Self, KeyCustodyError> {
        let path = chain_json_path(base_dir);
        if !path.exists() {
            return Ok(Self::new(""));
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| KeyCustodyError::ChainIo(format!("read {}: {e}", path.display())))?;
        serde_json::from_str(&raw).map_err(|_| {
            KeyCustodyError::ChainParse(
                "chain.json could not be parsed — file may be corrupt or from a newer version"
                    .to_string(),
            )
        })
    }

    /// Write `chain.json` atomically, with §5a tmp cleanup on every failure
    /// branch (PRIMARY METHODOLOGICAL DIRECTIVE, M04).
    ///
    /// Creates `<base_dir>/audit/` if it does not exist.
    pub fn save(&self, base_dir: &Path) -> Result<(), KeyCustodyError> {
        let path = chain_json_path(base_dir);

        // Ensure parent directory exists.
        // M-19: use mode 0o700 on Unix so the csq-runs/ directory is
        // not world-readable (the chain.json contains key identifiers).
        if let Some(parent) = path.parent() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| {
                        KeyCustodyError::ChainIo(format!(
                            "create csq-runs/ {}: {e}",
                            parent.display()
                        ))
                    })?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KeyCustodyError::ChainIo(format!("create_dir_all {}: {e}", parent.display()))
                })?;
            }
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| KeyCustodyError::ChainParse(format!("serialize: {e}")))?;

        // §5a: unique_tmp_path → write → secure_file → atomic_replace,
        // with remove_file(&tmp) on every failure branch.
        let tmp = unique_tmp_path(&path);

        if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(KeyCustodyError::ChainIo(format!(
                "write tmp {}: {e}",
                tmp.display()
            )));
        }

        if let Err(e) = secure_file(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(KeyCustodyError::ChainIo(format!(
                "secure_file {}: {e}",
                tmp.display()
            )));
        }

        if let Err(e) = atomic_replace(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(KeyCustodyError::ChainIo(format!(
                "atomic_replace {} → {}: {e}",
                tmp.display(),
                path.display()
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Custom (de)serialisers for `Option<Ed25519PublicKey>` ↔ hex string
// ---------------------------------------------------------------------------

fn ser_pubkey_opt<S>(val: &Option<Ed25519PublicKey>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match val {
        None => s.serialize_none(),
        Some(pk) => s.serialize_str(&hex::encode(pk.0)),
    }
}

fn de_pubkey_opt<'de, D>(d: D) -> Result<Option<Ed25519PublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom(format!(
                    "pubkey hex must be 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(Ed25519PublicKey(arr)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_base() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn test_chain_state_roundtrip_no_key() {
        let tmp = tmp_base();
        let state = ChainState::new("test-chain");
        state.save(tmp.path()).expect("save");

        let loaded = ChainState::load(tmp.path()).expect("load");
        assert_eq!(loaded.chain_id, "test-chain");
        assert!(loaded.signing_key_id.is_none());
        assert!(loaded.pubkey.is_none());
    }

    #[test]
    fn test_chain_state_roundtrip_with_key() {
        let tmp = tmp_base();
        let mut state = ChainState::new("my-chain");
        let kid = KeyId::try_new(format!("ed25519:{}", "a".repeat(64))).expect("kid");
        let pk = Ed25519PublicKey([0xab; 32]);
        state.signing_key_id = Some(kid.clone());
        state.pubkey = Some(pk);
        state.save(tmp.path()).expect("save");

        let loaded = ChainState::load(tmp.path()).expect("load");
        assert_eq!(loaded.signing_key_id.unwrap().as_str(), kid.as_str());
        assert_eq!(loaded.pubkey.unwrap().0, [0xab; 32]);
    }

    #[test]
    fn test_chain_state_load_missing_returns_default() {
        let tmp = tmp_base();
        let state = ChainState::load(tmp.path()).expect("load");
        assert_eq!(state.chain_id, "");
        assert!(state.signing_key_id.is_none());
    }

    /// R6-TDD-5: `ChainState::load` MUST return `KeyCustodyError::ChainParse`
    /// when `chain.json` exists but holds malformed JSON (corruption, manual
    /// edit, partial write). The error message MUST NOT echo the input bytes
    /// per `rules/security.md §2`.
    #[test]
    fn test_chain_state_load_returns_chain_parse_on_malformed_json() {
        let tmp = tmp_base();
        let csq_runs = tmp.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).expect("mkdir csq-runs");
        // Write valid UTF-8 that is NOT valid JSON. (Non-UTF-8 bytes hit
        // the ChainIo I/O-error branch in std::fs::read_to_string, not
        // the ChainParse branch we want to exercise.)
        std::fs::write(
            csq_runs.join("chain.json"),
            b"{ not valid json - dangling brace {{{ ",
        )
        .expect("write malformed");

        let result = ChainState::load(tmp.path());
        let err = result.expect_err("malformed chain.json must produce Err");
        let err_str = format!("{err:?}");
        assert!(
            err_str.contains("ChainParse"),
            "expected ChainParse variant, got {err_str}"
        );
        // Security.md §2: error message must be fixed-vocabulary, not echo bytes.
        assert!(
            !err_str.contains("\\xff") && !err_str.contains("not-json"),
            "ChainParse error MUST NOT echo input bytes (got {err_str})"
        );
    }
}
