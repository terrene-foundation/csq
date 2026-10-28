//! Server-side checkpoint signing key (M10).
//!
//! csq-ledger signs every checkpoint (signed tree head) with its OWN Ed25519
//! key — distinct from the csq CLIENT keys that sign individual audit records.
//! This is the key whose `KeyId` clients pin when they anchor to this ledger;
//! losing it makes existing checkpoints unverifiable (hence the first-boot
//! backup WARN).
//!
//! # First-boot UX (milestone decision 2)
//!
//! When `CSQ_LEDGER_SIGNING_KEY_PATH` is NOT set, the server:
//! 1. Generates a random Ed25519 keypair.
//! 2. Writes the private key to `<data_dir>/signing-key.pem` at mode 0o600.
//! 3. Logs a prominent WARN to stderr AND surfaces it via `GET /v1/health`,
//!    persisting on EVERY boot until `CSQ_LEDGER_SIGNING_KEY_PATH` is set.
//!
//! Explicitly setting `CSQ_LEDGER_SIGNING_KEY_PATH` (even to the auto-generated
//! file) is the operator's acknowledgement that they have reviewed the key and
//! committed to it — that clears the WARN.
//!
//! # Key file format
//!
//! A self-contained PEM-style envelope wrapping the hex-encoded 32-byte seed:
//!
//! ```text
//! -----BEGIN CSQ-LEDGER ED25519 PRIVATE KEY-----
//! <64 lowercase hex chars of the 32-byte seed>
//! -----END CSQ-LEDGER ED25519 PRIVATE KEY-----
//! ```
//!
//! We do NOT use the ed25519-dalek `pem`/`pkcs8` feature (it pulls the
//! pkcs8/der/spki dep chain into the workspace). The envelope is read/written
//! here with no extra dependency. The `KeyId` is the SAME derivation csq-core
//! uses: `ed25519:<sha256(raw_32_byte_pubkey)_hex>`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey as DalekSigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Environment variable an operator sets to point at a provisioned signing key
/// (HSM export, KMS-managed file, or the reviewed auto-generated file).
pub const SIGNING_KEY_PATH_ENV: &str = "CSQ_LEDGER_SIGNING_KEY_PATH";

/// PEM envelope label.
const PEM_BEGIN: &str = "-----BEGIN CSQ-LEDGER ED25519 PRIVATE KEY-----";
const PEM_END: &str = "-----END CSQ-LEDGER ED25519 PRIVATE KEY-----";

/// The persistent first-boot backup warning, surfaced on stderr and
/// `GET /v1/health` until `CSQ_LEDGER_SIGNING_KEY_PATH` is explicitly set.
pub const AUTO_KEY_WARNING: &str = concat!(
    "auto-generated signing key in use — BACK UP <data_dir>/signing-key.pem. ",
    "If lost, checkpoints become unverifiable on restart and operator csq ",
    "installs anchored to this ledger fail with KeyId mismatch. To use an ",
    "operator-provisioned key (HSM, KMS, etc.), set CSQ_LEDGER_SIGNING_KEY_PATH ",
    "and restart."
);

/// An error from the signing-key layer.
#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    /// Filesystem I/O failure (fixed-vocabulary context, no key-byte leakage).
    #[error("signing-key io error: {0}")]
    Io(&'static str),
    /// The key file did not contain a valid PEM envelope / 32-byte hex seed.
    #[error("signing-key file is malformed (expected csq-ledger PEM envelope)")]
    Malformed,
    /// Random seed generation failed.
    #[error("failed to generate random signing-key seed")]
    Rng,
}

/// The server's checkpoint signing key, plus whether it was auto-generated
/// this boot (drives the persistent WARN).
pub struct ServerSigningKey {
    inner: DalekSigningKey,
    key_id: String,
    pubkey: [u8; 32],
    /// True when the key was loaded from the auto-generated default path AND
    /// `CSQ_LEDGER_SIGNING_KEY_PATH` was not explicitly set — i.e. the operator
    /// has not yet acknowledged the key. Drives [`AUTO_KEY_WARNING`].
    auto_generated_unacknowledged: bool,
}

impl std::fmt::Debug for ServerSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private key material.
        f.debug_struct("ServerSigningKey")
            .field("key_id", &self.key_id)
            .field(
                "auto_generated_unacknowledged",
                &self.auto_generated_unacknowledged,
            )
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

impl ServerSigningKey {
    /// Loads the signing key according to the milestone-decision-2 first-boot
    /// UX:
    ///
    /// - If `CSQ_LEDGER_SIGNING_KEY_PATH` is set → load from that path
    ///   (operator-acknowledged; no WARN). Missing file at an explicit path is
    ///   a hard error (operator pointed at something that doesn't exist).
    /// - Else, load `<data_dir>/signing-key.pem` if present, generating it if
    ///   not. Either way the WARN is active (unacknowledged).
    ///
    /// `env_override` is the resolved value of `CSQ_LEDGER_SIGNING_KEY_PATH`
    /// (passed in rather than read here so callers can test deterministically).
    pub fn load_or_generate(
        data_dir: &Path,
        env_override: Option<&str>,
    ) -> Result<Self, SigningKeyError> {
        match env_override {
            Some(path) => {
                // Operator-provisioned path — must exist; acknowledged.
                let pem = std::fs::read_to_string(path)
                    .map_err(|_| SigningKeyError::Io("read operator-provisioned key"))?;
                let seed = parse_pem_seed(&pem)?;
                Ok(Self::from_seed(&seed, false))
            }
            None => {
                let default_path = default_key_path(data_dir);
                if default_path.exists() {
                    let pem = std::fs::read_to_string(&default_path)
                        .map_err(|_| SigningKeyError::Io("read auto-generated key"))?;
                    let seed = parse_pem_seed(&pem)?;
                    Ok(Self::from_seed(&seed, true))
                } else {
                    // Generate + persist at 0o600.
                    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
                    getrandom::getrandom(&mut *seed).map_err(|_| SigningKeyError::Rng)?;
                    write_key_file(&default_path, &seed)?;
                    Ok(Self::from_seed(&seed, true))
                }
            }
        }
    }

    /// Constructs the key handle from a 32-byte seed.
    fn from_seed(seed: &[u8; 32], auto_unacked: bool) -> Self {
        let inner = DalekSigningKey::from_bytes(seed);
        let pubkey = inner.verifying_key().to_bytes();
        let key_id = derive_key_id(&pubkey);
        Self {
            inner,
            key_id,
            pubkey,
            auto_generated_unacknowledged: auto_unacked,
        }
    }

    /// The stable key id (`ed25519:<sha256(pubkey)_hex>`) clients pin.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The raw 32-byte public key (hex-encoded by callers for the checkpoint).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.pubkey
    }

    /// True when the persistent backup WARN should be surfaced (auto-generated
    /// key, not yet acknowledged via `CSQ_LEDGER_SIGNING_KEY_PATH`).
    #[must_use]
    pub fn warn_active(&self) -> bool {
        self.auto_generated_unacknowledged
    }

    /// Signs `message` (typically the 32-byte checkpoint pre-image) and returns
    /// the 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }
}

/// The default auto-generated key file path under `data_dir`.
#[must_use]
pub fn default_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("signing-key.pem")
}

/// Derives the `KeyId` exactly as csq-core does:
/// `ed25519:<lowercase-hex-sha256(raw_32_byte_pubkey)>`.
#[must_use]
pub fn derive_key_id(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let digest = hasher.finalize();
    format!("ed25519:{}", hex::encode(digest))
}

/// Verifies a signature over `message` against `pubkey` (helper for tests +
/// the checkpoint verifier).
#[must_use]
pub fn verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify_strict(message, &sig).is_ok()
}

/// Parses the hex seed out of a csq-ledger PEM envelope.
fn parse_pem_seed(pem: &str) -> Result<[u8; 32], SigningKeyError> {
    let mut body = String::new();
    let mut in_body = false;
    for line in pem.lines() {
        let t = line.trim();
        if t == PEM_BEGIN {
            in_body = true;
            continue;
        }
        if t == PEM_END {
            in_body = false;
            continue;
        }
        if in_body {
            body.push_str(t);
        }
    }
    if body.len() != 64 {
        return Err(SigningKeyError::Malformed);
    }
    let bytes = hex::decode(&body).map_err(|_| SigningKeyError::Malformed)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Writes the key file as a PEM envelope at mode 0o600, fsyncing before return.
///
/// Per `rules/security.md §5a`: clean up the partially-written file on any
/// failure branch so a 0o644 seed artifact is never left on disk.
fn write_key_file(path: &Path, seed: &[u8; 32]) -> Result<(), SigningKeyError> {
    let hex_seed: Zeroizing<String> = Zeroizing::new(hex::encode(seed));
    let pem = format!("{PEM_BEGIN}\n{}\n{PEM_END}\n", hex_seed.as_str());

    // Create with 0o600 from the start on Unix so the seed is never world-
    // readable, even momentarily.
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = match opts.open(path) {
        Ok(f) => f,
        Err(_) => return Err(SigningKeyError::Io("create signing-key file")),
    };
    if file.write_all(pem.as_bytes()).is_err() {
        let _ = std::fs::remove_file(path);
        return Err(SigningKeyError::Io("write signing-key file"));
    }
    // Belt-and-suspenders chmod (no-op on Windows).
    secure_file_best_effort(path);
    if file.sync_all().is_err() {
        let _ = std::fs::remove_file(path);
        return Err(SigningKeyError::Io("fsync signing-key file"));
    }
    Ok(())
}

/// Best-effort 0o600 on a file (Unix).
fn secure_file_best_effort(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// `test signing_first_boot_generates_key_and_warns`
    #[test]
    fn signing_first_boot_generates_key_and_warns() {
        let dir = TempDir::new().unwrap();
        assert!(!default_key_path(dir.path()).exists());
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        assert!(default_key_path(dir.path()).exists(), "key file created");
        assert!(key.warn_active(), "auto-generated key surfaces the WARN");
        assert!(key.key_id().starts_with("ed25519:"));
    }

    /// `test signing_key_file_is_mode_0600`
    #[cfg(unix)]
    #[test]
    fn signing_key_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let meta = std::fs::metadata(default_key_path(dir.path())).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// `test signing_env_override_clears_warn`
    #[test]
    fn signing_env_override_clears_warn() {
        let dir = TempDir::new().unwrap();
        // First boot generates the file.
        ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let path = default_key_path(dir.path());
        let path_str = path.to_str().unwrap();
        // Now boot WITH the env override pointing at the same file → acknowledged.
        let key = ServerSigningKey::load_or_generate(dir.path(), Some(path_str)).unwrap();
        assert!(!key.warn_active(), "explicit env path clears the WARN");
    }

    /// `test signing_persists_key_id_across_reload`
    #[test]
    fn signing_persists_key_id_across_reload() {
        let dir = TempDir::new().unwrap();
        let k1 = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let id1 = k1.key_id().to_string();
        let k2 = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        assert_eq!(id1, k2.key_id(), "same key id after reload");
    }

    /// `test signing_sign_then_verify_round_trips`
    #[test]
    fn signing_sign_then_verify_round_trips() {
        let dir = TempDir::new().unwrap();
        let key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
        let msg = b"checkpoint-preimage";
        let sig = key.sign(msg);
        assert!(verify(key.public_key_bytes(), msg, &sig));
        // Tamper detection.
        let mut bad = sig;
        bad[0] ^= 0xff;
        assert!(!verify(key.public_key_bytes(), msg, &bad));
    }

    /// `test signing_rejects_malformed_key_file`
    #[test]
    fn signing_rejects_malformed_key_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.pem");
        std::fs::write(&path, "not a pem envelope").unwrap();
        let result = ServerSigningKey::load_or_generate(dir.path(), Some(path.to_str().unwrap()));
        assert!(matches!(result, Err(SigningKeyError::Malformed)));
    }

    /// `test signing_key_id_matches_csq_core_derivation`
    ///
    /// The KeyId derivation MUST match csq-core's `ed25519:<sha256(pubkey)>` so
    /// a checkpoint's `signed_by_key_id` is the same shape csq's verifier
    /// expects.
    #[test]
    fn signing_key_id_matches_csq_core_derivation() {
        let pubkey = [7u8; 32];
        let id = derive_key_id(&pubkey);
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        let expected = format!("ed25519:{}", hex::encode(hasher.finalize()));
        assert_eq!(id, expected);
        // KeyId shape: prefix + 64 hex chars.
        assert_eq!(id.len(), "ed25519:".len() + 64);
    }
}
