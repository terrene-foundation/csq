//! File-based custody for audit signing seeds — the PRIMARY store.
//!
//! # Why a file store exists (the daemon-brick root cause)
//!
//! Audit signing seeds were originally stored ONLY in the OS keychain
//! (`keyring` crate, per-app ACL). The daemon — which is NON-INTERACTIVE
//! (`csq daemon`, the desktop in-process supervisor, the anchor task) — must
//! read the seed to BOTH verify the chain AND sign new records. Every csq
//! rebuild changes the binary's code signature, so the daemon stops matching
//! the per-app ACL of the keychain item the previous binary created; macOS then
//! wants to PROMPT for keychain access, which a non-interactive process cannot
//! answer → `errSecInteractionNotAllowed` → `keyring::Error::PlatformFailure`.
//! A present-but-blocked key was then misclassified as absent and bricked the
//! daemon (journal 0033/0034).
//!
//! A 0o600 file store is read by ANY same-user csq binary identically — no
//! ACL, no prompt, no signature dependency — so the daemon can always read the
//! seed non-interactively. The file store is also strictly MORE portable than
//! the keychain: `keyring` ships no persistent Linux backend in this workspace
//! (Cargo.toml compiles only `apple-native` + `windows-native`), so keychain
//! custody was silently non-durable on Linux; the file store restores it.
//!
//! # Roles — file = availability, keychain = tamper DETECTOR (not a gate)
//!
//! This module is the AVAILABILITY mirror, and it is what the daemon reads. Be
//! precise about what this does and does NOT provide:
//!
//! - It does NOT make the signing key CONFIDENTIAL against a same-UID attacker.
//!   The 0o600 file is readable by ANY same-UID process (that is the point — the
//!   daemon is one). Per the chain's pre-existing SEC-1 boundary, an attacker
//!   who holds the live key forges regardless, and here the key is in the file.
//!   Moving custody off the keychain trades the keychain's same-UID read-prompt
//!   (a modest covert-theft tripwire) for non-interactive daemon access — a
//!   deliberate, owner-chosen trade (availability over realtime integrity).
//!
//! - The OS keychain is retained as a TAMPER DETECTOR: a same-UID attacker can
//!   DELETE the keychain item but cannot silently REWRITE it (a planted/replaced
//!   entry prompts or surfaces `Ambiguous`/`BadEncoding`). So when the keychain
//!   is readable, `verify_chain` Step-0 cross-checks the file's `(cutoff,
//!   key_id)` against it and prefers the trustworthy keychain cutoff — DEFEATING
//!   a file/chain.json cutoff-raise. A disagreement is SURFACED as
//!   `KeychainAnchorStatus::Mismatch` (loud ERROR + `csq doctor` alarm) but is
//!   NEVER fatal — the keychain anchor is a DETECTOR, not a brick-gate (the brick
//!   is exactly what this change eliminates). Keychain access-blocked / absent →
//!   `Unconfirmed` (forge-resistance was file-only this run). See
//!   [`crate::audit::verify::KeychainAnchorStatus`].
//!
//! The cutoff is co-located inside the same file as the seed: deleting the file
//! destroys both the key AND its cutoff together (shared-fate, spec §12.11.3a).
//!
//! # On-disk layout
//!
//! ```text
//! <base>/csq-runs/keys/<chain_id>/active.json          # active signing key
//! <base>/csq-runs/keys/<chain_id>/historical/<n>.json  # rotated-out key n
//! ```
//!
//! Each file holds the EXACT same `SeedEntryPayload` JSON bytes the keychain
//! entry holds (`{"seed_hex":..,"signing_active_since_seq":..,"signing_key_id":..}`,
//! or a legacy bare-hex string), so the dual-format parser
//! (`LocalSigningKey::load_from_str`) and the cutoff reader work unchanged. The
//! cutoff is co-located inside the same file as the seed: deleting the file
//! destroys both the key AND its cutoff together, preserving the M-hardening
//! shared-fate property (spec §12.11.3a) without a separable anchor to target.
//!
//! `chain_id`-scoping the historical slots also fixes a latent multi-chain
//! collision present in the keychain naming (`historical/{rotation_count}` had
//! no chain_id, so two chains under one base_dir collided — spec §12.11.1).
//!
//! # Permissions — 0o600 files, 0o700 dirs
//!
//! Files are written via the canonical `unique_tmp_path → write → secure_file →
//! atomic_replace` §5a pipeline with tmp cleanup on every failure branch (the
//! payload contains the private seed). The `keys/` and `keys/<chain_id>/`
//! directories are created at 0o700 via `secure_dir` so credential filenames
//! are not enumerable by other users.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::audit::key_custody::KeyCustodyError;
use crate::platform::fs::{atomic_replace, secure_dir, secure_file, unique_tmp_path};

/// Which key slot within a chain's keystore.
///
/// Maps to BOTH a file path (`active.json` / `historical/<n>.json`) and a
/// keychain account name (`<chain_id>` / `historical/<n>`) so the file store
/// and the keychain fallback address the same logical key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// The active (head) signing key for the chain.
    Active,
    /// A rotated-out historical key, archived at the given `rotation_count`.
    Historical(u64),
}

impl KeySlot {
    /// The keychain account name for this slot.
    ///
    /// Back-compat with the pre-file-store keychain naming: the active slot is
    /// keyed by `chain_id` and historical slots by `historical/<n>` (NO
    /// chain_id prefix — this matches the existing keychain items so migration
    /// and fallback read the same entries the current code wrote).
    pub fn keychain_account(&self, chain_id: &str) -> String {
        match self {
            KeySlot::Active => chain_id.to_string(),
            KeySlot::Historical(n) => format!("historical/{n}"),
        }
    }
}

/// The `keys/<chain_id>/` root directory for a chain's file-based keystore.
fn keys_dir(base_dir: &Path, chain_id: &str) -> PathBuf {
    base_dir.join("csq-runs").join("keys").join(chain_id)
}

/// The seed file path for `(chain_id, slot)`.
pub fn seed_file_path(base_dir: &Path, chain_id: &str, slot: KeySlot) -> PathBuf {
    let root = keys_dir(base_dir, chain_id);
    match slot {
        KeySlot::Active => root.join("active.json"),
        KeySlot::Historical(n) => root.join("historical").join(format!("{n}.json")),
    }
}

/// Create the keystore directory tree for `(chain_id, slot)` at 0o700.
fn ensure_parent_dir(
    base_dir: &Path,
    chain_id: &str,
    slot: KeySlot,
) -> Result<(), KeyCustodyError> {
    let path = seed_file_path(base_dir, chain_id, slot);
    let parent = path
        .parent()
        .ok_or_else(|| KeyCustodyError::ChainIo("seed file has no parent dir".to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| KeyCustodyError::ChainIo(format!("create keys dir: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| KeyCustodyError::ChainIo(format!("create keys dir: {e}")))?;
    }
    // Belt-and-suspenders: tighten perms in case the dir already existed at a
    // looser mode (secure_dir is a no-op on Windows).
    let _ = secure_dir(parent);
    // Also tighten the keys/<chain_id> root (parent of historical/).
    let _ = secure_dir(&keys_dir(base_dir, chain_id));
    Ok(())
}

/// Persist a seed payload (the exact `SeedEntryPayload` JSON bytes, or a legacy
/// bare-hex string) to the file store at `(chain_id, slot)`.
///
/// The payload is private-key material; the write follows the §5a pipeline
/// (`unique_tmp_path → write → secure_file(0o600) → atomic_replace`) with
/// `remove_file(&tmp)` on EVERY failure branch so a crash mid-write cannot
/// leave the seed readable at a umask-default mode.
///
/// `payload` is taken as `&Zeroizing<String>` so the caller's copy is zeroed on
/// drop; this function does not retain it past the write.
pub fn store_payload(
    base_dir: &Path,
    chain_id: &str,
    slot: KeySlot,
    payload: &Zeroizing<String>,
) -> Result<(), KeyCustodyError> {
    if chain_id.is_empty() {
        return Err(KeyCustodyError::ChainParse(
            "cannot store a seed for an empty chain_id".to_string(),
        ));
    }
    ensure_parent_dir(base_dir, chain_id, slot)?;
    let path = seed_file_path(base_dir, chain_id, slot);
    let tmp = unique_tmp_path(&path);

    // §5a: write → secure → replace, clean up tmp on every failure branch.
    if let Err(e) = std::fs::write(&tmp, payload.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(KeyCustodyError::ChainIo(format!("seed file write: {e}")));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(KeyCustodyError::ChainIo(format!("seed file secure: {e}")));
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(KeyCustodyError::ChainIo(format!(
            "seed file atomic replace: {e}"
        )));
    }
    Ok(())
}

/// Read the raw seed payload string from the file store at `(chain_id, slot)`.
///
/// Returns:
/// - `Ok(Some(payload))` — file present; `payload` is the raw bytes wrapped in
///   `Zeroizing<String>` (zeroed on drop). The caller parses it via
///   `LocalSigningKey::load_from_str` (dual JSON / legacy-bare-hex format).
/// - `Ok(None)` — file genuinely absent (the `NoEntry` analog for the file
///   store).
/// - `Err(_)` — a real I/O error (permission denied, not-a-file, etc.) distinct
///   from absence. The caller treats this as fail-closed, NOT as absence.
pub fn load_payload(
    base_dir: &Path,
    chain_id: &str,
    slot: KeySlot,
) -> Result<Option<Zeroizing<String>>, KeyCustodyError> {
    let path = seed_file_path(base_dir, chain_id, slot);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(Zeroizing::new(s))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(KeyCustodyError::ChainIo(format!("seed file read: {e}"))),
    }
}

/// Returns `true` when a seed file exists for `(chain_id, slot)`.
///
/// Does NOT read or validate the contents (mirrors
/// `LocalSigningKey::exists_in_keychain`).
pub fn exists(base_dir: &Path, chain_id: &str, slot: KeySlot) -> bool {
    seed_file_path(base_dir, chain_id, slot).is_file()
}

/// Delete the seed file for `(chain_id, slot)`. Idempotent (ignores ENOENT).
///
/// Used by the H-5 rollback paths in `audit_init` / `rotate_key` to clean up a
/// freshly-written file when a later step fails.
pub fn delete(base_dir: &Path, chain_id: &str, slot: KeySlot) -> Result<(), KeyCustodyError> {
    let path = seed_file_path(base_dir, chain_id, slot);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(KeyCustodyError::ChainIo(format!("seed file delete: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn payload(seed_hex: &str) -> Zeroizing<String> {
        Zeroizing::new(format!(
            r#"{{"seed_hex":"{seed_hex}","signing_active_since_seq":7,"signing_key_id":"ed25519:{}"}}"#,
            "a".repeat(64)
        ))
    }

    #[test]
    fn active_slot_maps_to_active_json() {
        let t = tmp();
        let p = seed_file_path(t.path(), "CHAIN1", KeySlot::Active);
        assert!(p.ends_with("csq-runs/keys/CHAIN1/active.json"), "got {p:?}");
    }

    #[test]
    fn historical_slot_is_chain_scoped() {
        let t = tmp();
        let p = seed_file_path(t.path(), "CHAIN1", KeySlot::Historical(3));
        assert!(
            p.ends_with("csq-runs/keys/CHAIN1/historical/3.json"),
            "got {p:?}"
        );
        // The latent collision fix: a DIFFERENT chain with the same historical
        // index resolves to a DIFFERENT path (the keychain naming did not).
        let p2 = seed_file_path(t.path(), "CHAIN2", KeySlot::Historical(3));
        assert_ne!(p, p2, "historical slots must be chain_id-scoped");
    }

    #[test]
    fn keychain_account_back_compat() {
        assert_eq!(KeySlot::Active.keychain_account("CHAIN1"), "CHAIN1");
        assert_eq!(
            KeySlot::Historical(5).keychain_account("CHAIN1"),
            "historical/5"
        );
    }

    #[test]
    fn store_then_load_roundtrip() {
        let t = tmp();
        let pl = payload(&"b".repeat(64));
        store_payload(t.path(), "CHAIN1", KeySlot::Active, &pl).expect("store");
        let got = load_payload(t.path(), "CHAIN1", KeySlot::Active)
            .expect("load ok")
            .expect("present");
        assert_eq!(got.as_str(), pl.as_str());
    }

    #[test]
    fn load_absent_returns_none_not_err() {
        let t = tmp();
        let got = load_payload(t.path(), "CHAIN1", KeySlot::Active).expect("no err on absent");
        assert!(got.is_none(), "absent seed must be Ok(None), not Err");
    }

    #[cfg(unix)]
    #[test]
    fn stored_file_is_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let t = tmp();
        store_payload(
            t.path(),
            "CHAIN1",
            KeySlot::Active,
            &payload(&"c".repeat(64)),
        )
        .expect("store");
        let p = seed_file_path(t.path(), "CHAIN1", KeySlot::Active);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "seed file must be 0o600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn keys_dir_is_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let t = tmp();
        store_payload(
            t.path(),
            "CHAIN1",
            KeySlot::Active,
            &payload(&"d".repeat(64)),
        )
        .expect("store");
        let dir = keys_dir(t.path(), "CHAIN1");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "keys/<chain_id> dir must be 0o700, got {mode:o}"
        );
    }

    #[test]
    fn exists_reflects_store_and_delete() {
        let t = tmp();
        assert!(!exists(t.path(), "CHAIN1", KeySlot::Active));
        store_payload(
            t.path(),
            "CHAIN1",
            KeySlot::Active,
            &payload(&"e".repeat(64)),
        )
        .expect("store");
        assert!(exists(t.path(), "CHAIN1", KeySlot::Active));
        delete(t.path(), "CHAIN1", KeySlot::Active).expect("delete");
        assert!(!exists(t.path(), "CHAIN1", KeySlot::Active));
    }

    #[test]
    fn delete_absent_is_ok() {
        let t = tmp();
        delete(t.path(), "CHAIN1", KeySlot::Active).expect("delete of absent must be Ok");
    }

    #[test]
    fn store_empty_chain_id_rejected() {
        let t = tmp();
        let err = store_payload(t.path(), "", KeySlot::Active, &payload(&"a".repeat(64)))
            .expect_err("empty chain_id must be rejected");
        assert!(matches!(err, KeyCustodyError::ChainParse(_)), "got {err:?}");
    }
}
