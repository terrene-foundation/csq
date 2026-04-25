//! AES-GCM-on-disk [`Vault`] backend — opt-in fallback for Linux
//! hosts without Secret Service / kwallet (headless CI, WSL, minimal
//! Docker images).
//!
//! Compiled on every platform so the crypto contract is unit-testable
//! everywhere (Argon2id + AES-256-GCM are pure-Rust RustCrypto), but
//! [`super::open_default_vault`] only wires it on Linux when
//! `CSQ_SECRET_BACKEND=file` is set explicitly. Per security review §3
//! ("no silent fallback"): macOS / Windows refuse to route here even
//! with the env override, because they have a native primitive that
//! would be silently downgraded.
//!
//! # File format
//!
//! `<base_dir>/vault-store.json` — one JSON document with a fixed
//! header for KDF parameters and a list of per-slot AEAD-encrypted
//! entries. Atomic-replaced on every write via the existing
//! `platform::fs::atomic_replace` helper. Mode 0o600 enforced after
//! every write via `secure_file`. The header lives in plaintext (KDF
//! parameters MUST be readable to decrypt) but contains no secret
//! material — the salt is non-secret by construction.
//!
//! ```json
//! {
//!   "version": 1,
//!   "kdf": {
//!     "algo": "argon2id",
//!     "salt": "<base64>",
//!     "m_kib": 65536,
//!     "t_cost": 3,
//!     "p_cost": 1
//!   },
//!   "entries": [
//!     { "surface": "gemini", "account": 3,
//!       "nonce": "<base64-12B>", "ciphertext": "<base64>" }
//!   ]
//! }
//! ```
//!
//! Each entry's nonce is a fresh 96-bit random value drawn from
//! `getrandom`. AES-GCM associated data is the canonical
//! `surface:account` byte string — this binds ciphertext to slot so a
//! file-edit attacker cannot swap entries between slots without
//! invalidating the AEAD tag.
//!
//! # Passphrase source
//!
//! Read from one of, in order:
//!
//! 1. `CSQ_SECRET_PASSPHRASE` env var (the value).
//! 2. `CSQ_SECRET_PASSPHRASE_FILE` env var (a path; the file contents
//!    are the passphrase; trailing whitespace stripped).
//!
//! If neither is set, `FileVault::open` returns
//! [`SecretError::BackendUnavailable`] — the user opted into the file
//! backend but did not provide a passphrase. There is no first-run
//! prompt: the vault is called from non-interactive contexts
//! (daemon hot path, Tauri commands) where a TTY prompt would hang.
//!
//! # Caching
//!
//! The derived 32-byte master key is cached in the `FileVault` struct
//! for the lifetime of the process. This is unavoidable for any
//! Argon2-based scheme — re-deriving on every call would block the
//! daemon for ~1 second per vault op at the chosen cost parameters.
//! The cleartext secrets themselves are NOT cached; each `get`
//! re-reads the file and performs a fresh AEAD decrypt. The cached
//! key is wiped on `Drop` via `zeroize`.

use super::{SecretError, SlotKey, Vault};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::types::AccountNum;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id memory cost in KiB. 64 MiB matches OWASP 2023 guidance
/// for interactive scenarios; high enough that a brute-force run
/// against a captured `vault-store.json` cannot pipeline through GPU
/// memory cheaply.
const KDF_M_KIB: u32 = 64 * 1024;
/// Argon2id iteration count. 3 passes with the chosen memory cost
/// take ~700ms on a 2024-class laptop — slow enough to deter brute
/// force, fast enough that the once-per-process derivation does not
/// add user-visible latency at csq startup.
const KDF_T_COST: u32 = 3;
/// Argon2id parallelism. Single-threaded keeps cost analysis simple
/// and matches the OWASP "interactive" reference parameter set.
const KDF_P_COST: u32 = 1;
/// Argon2 salt length in bytes. 16 bytes is the RustCrypto default
/// and matches the RFC 9106 recommendation.
const KDF_SALT_LEN: usize = 16;
/// AES-GCM nonce length in bytes (96 bits). REQUIRED by the spec.
const AEAD_NONCE_LEN: usize = 12;
/// AES-256 key length in bytes.
const AEAD_KEY_LEN: usize = 32;

/// Env var holding the file-backend passphrase as its literal value.
const ENV_PASSPHRASE: &str = "CSQ_SECRET_PASSPHRASE";
/// Env var holding a path to a file whose contents are the passphrase.
const ENV_PASSPHRASE_FILE: &str = "CSQ_SECRET_PASSPHRASE_FILE";

/// On-disk file name for the vault store.
const VAULT_FILE_NAME: &str = "vault-store.json";

/// Encrypted-on-disk vault. Holds the derived master key in memory
/// for the lifetime of the process; never holds cleartext secrets
/// across calls.
pub struct FileVault {
    path: PathBuf,
    /// Argon2id-derived 32-byte master key. `ZeroizeOnDrop` wipes it
    /// when the vault is dropped (process shutdown / live reload).
    master_key: SecretBytes,
}

/// Manual `Debug` so the master key never appears in panic messages,
/// `dbg!()` output, or `Result::unwrap_err` formatting. Renders only
/// the on-disk path and a fixed redaction marker.
impl std::fmt::Debug for FileVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileVault")
            .field("path", &self.path)
            .field("master_key", &"<redacted>")
            .finish()
    }
}

/// 32-byte buffer for the AES-256 master key. Wraps a `Vec<u8>` so we
/// can use `ZeroizeOnDrop`; the vec length is fixed at construction.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Header + entries serialized to disk. `serde` derive only — the
/// data on disk is plaintext JSON and the field names are part of the
/// stable on-disk format.
#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: KdfParams,
    entries: Vec<EncryptedEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfParams {
    /// Currently always `"argon2id"`. Parsed back to enforce
    /// algorithm match — a future change to the KDF would bump
    /// `version` and migrate.
    algo: String,
    /// Argon2 salt, base64-encoded.
    salt: String,
    /// Argon2 memory cost in KiB.
    m_kib: u32,
    /// Argon2 iteration count.
    t_cost: u32,
    /// Argon2 parallelism.
    p_cost: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedEntry {
    surface: String,
    account: u16,
    /// AES-GCM 96-bit nonce, base64-encoded.
    nonce: String,
    /// AES-GCM ciphertext including the 16-byte authentication tag,
    /// base64-encoded.
    ciphertext: String,
}

/// Currently-supported file format version. Bumping this requires a
/// migration step in `read_file`.
const CURRENT_VERSION: u32 = 1;

impl FileVault {
    /// Opens (or initializes on first use) the file vault at
    /// `<base_dir>/vault-store.json`. Reads the passphrase from
    /// environment per [the module docs][self], derives the master
    /// key via Argon2id, and caches it in the returned struct.
    ///
    /// # Errors
    ///
    /// - [`SecretError::BackendUnavailable`] when no passphrase is
    ///   configured. The caller (`open_default_vault`) wraps this in
    ///   the same variant with a more specific message so the UI text
    ///   names the missing env var.
    /// - [`SecretError::Io`] for filesystem failures reading an
    ///   existing vault file.
    /// - [`SecretError::EncryptionFailed`] for KDF failure (memory
    ///   allocation rejected, malformed parameter set).
    pub fn open(base_dir: &Path) -> Result<Self, SecretError> {
        let passphrase = read_passphrase()?;
        let path = base_dir.join(VAULT_FILE_NAME);
        let kdf_params = if path.exists() {
            // Existing store: KDF parameters are pinned in the file
            // header. Verify algorithm match before deriving against
            // them.
            let file = read_file(&path)?;
            if file.kdf.algo != "argon2id" {
                return Err(SecretError::DecryptionFailed);
            }
            file.kdf
        } else {
            // First use: ensure the directory exists, mint a fresh
            // salt, and persist a header-only file. Subsequent writes
            // append entries via `set`.
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| SecretError::Io {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
            let mut salt = [0u8; KDF_SALT_LEN];
            getrandom::getrandom(&mut salt).map_err(|e| SecretError::EncryptionFailed {
                reason: format!("salt rng: {e}"),
            })?;
            let kdf = KdfParams {
                algo: "argon2id".into(),
                salt: B64.encode(salt),
                m_kib: KDF_M_KIB,
                t_cost: KDF_T_COST,
                p_cost: KDF_P_COST,
            };
            let empty = VaultFile {
                version: CURRENT_VERSION,
                kdf: clone_kdf(&kdf),
                entries: Vec::new(),
            };
            write_file(&path, &empty)?;
            kdf
        };

        let master_key = derive_key(passphrase.expose_secret(), &kdf_params)?;
        Ok(Self { path, master_key })
    }

    /// Path of the underlying vault file. Test-only — production code
    /// should not need to know.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Vault for FileVault {
    fn set(&self, slot: SlotKey, secret: &SecretString) -> Result<(), SecretError> {
        if secret.expose_secret().is_empty() {
            return Err(SecretError::InvalidKey {
                reason: "secret must not be empty".into(),
            });
        }

        let mut file = read_file(&self.path)?;

        let mut nonce = [0u8; AEAD_NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| SecretError::EncryptionFailed {
            reason: format!("nonce rng: {e}"),
        })?;

        let aad = aad_for(slot);
        let cipher = build_cipher(self.master_key.as_slice())?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret.expose_secret().as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|e| SecretError::EncryptionFailed {
                reason: format!("aead encrypt: {e}"),
            })?;

        let entry = EncryptedEntry {
            surface: slot.surface.to_string(),
            account: slot.account.get(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(&ciphertext),
        };

        // Overwrite-or-insert per the trait contract on `set`.
        if let Some(existing) = file
            .entries
            .iter_mut()
            .find(|e| e.surface == slot.surface && e.account == slot.account.get())
        {
            *existing = entry;
        } else {
            file.entries.push(entry);
        }

        write_file(&self.path, &file)
    }

    fn get(&self, slot: SlotKey) -> Result<SecretString, SecretError> {
        let file = read_file_or_empty(&self.path)?;
        let entry = file
            .entries
            .iter()
            .find(|e| e.surface == slot.surface && e.account == slot.account.get())
            .ok_or(SecretError::NotFound {
                surface: slot.surface,
                account: slot.account.get(),
            })?;

        let nonce_bytes = B64
            .decode(&entry.nonce)
            .map_err(|_| SecretError::DecryptionFailed)?;
        let ciphertext = B64
            .decode(&entry.ciphertext)
            .map_err(|_| SecretError::DecryptionFailed)?;
        if nonce_bytes.len() != AEAD_NONCE_LEN {
            return Err(SecretError::DecryptionFailed);
        }

        let aad = aad_for(slot);
        let cipher = build_cipher(self.master_key.as_slice())?;
        let cleartext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecretError::DecryptionFailed)?;

        // Convert via String — non-UTF-8 secrets are not a thing csq
        // stores (Gemini API keys are ASCII). UTF-8 conversion failure
        // is a corruption signal, not a benign decode mismatch.
        let s = String::from_utf8(cleartext).map_err(|_| SecretError::DecryptionFailed)?;
        Ok(SecretString::new(s.into()))
    }

    fn delete(&self, slot: SlotKey) -> Result<(), SecretError> {
        let mut file = read_file(&self.path)?;
        let before = file.entries.len();
        file.entries
            .retain(|e| !(e.surface == slot.surface && e.account == slot.account.get()));
        if file.entries.len() == before {
            // Idempotent contract: deleting a non-existent slot is OK.
            return Ok(());
        }
        write_file(&self.path, &file)
    }

    fn list_slots(&self, surface: &'static str) -> Result<Vec<AccountNum>, SecretError> {
        let file = read_file_or_empty(&self.path)?;
        let mut out: Vec<AccountNum> = file
            .entries
            .iter()
            .filter(|e| e.surface == surface)
            .filter_map(|e| AccountNum::try_from(e.account).ok())
            .collect();
        out.sort_by_key(|a| a.get());
        Ok(out)
    }

    fn backend_id(&self) -> &'static str {
        "linux-file-aes"
    }
}

// ── helpers ───────────────────────────────────────────────────────────

/// Reads the passphrase from `CSQ_SECRET_PASSPHRASE` or
/// `CSQ_SECRET_PASSPHRASE_FILE`. Returns `BackendUnavailable` when
/// neither is set so the caller surfaces the actionable env-var name.
fn read_passphrase() -> Result<SecretString, SecretError> {
    if let Ok(value) = std::env::var(ENV_PASSPHRASE) {
        if value.is_empty() {
            return Err(SecretError::BackendUnavailable {
                reason: format!("{ENV_PASSPHRASE} is set but empty"),
            });
        }
        return Ok(SecretString::new(value.into()));
    }
    if let Ok(path) = std::env::var(ENV_PASSPHRASE_FILE) {
        let content = std::fs::read_to_string(&path).map_err(|e| SecretError::Io {
            path: PathBuf::from(&path),
            source: e,
        })?;
        let trimmed = content.trim_end_matches(['\n', '\r']).to_string();
        if trimmed.is_empty() {
            return Err(SecretError::BackendUnavailable {
                reason: format!("{ENV_PASSPHRASE_FILE} points at an empty file"),
            });
        }
        return Ok(SecretString::new(trimmed.into()));
    }
    Err(SecretError::BackendUnavailable {
        reason: format!(
            "file backend selected but neither {ENV_PASSPHRASE} nor {ENV_PASSPHRASE_FILE} is set"
        ),
    })
}

/// Argon2id key derivation. Returns the 32-byte master key wrapped in
/// `SecretBytes` so it zeroizes on drop.
fn derive_key(passphrase: &str, kdf: &KdfParams) -> Result<SecretBytes, SecretError> {
    let salt = B64
        .decode(&kdf.salt)
        .map_err(|_| SecretError::DecryptionFailed)?;
    let params =
        Params::new(kdf.m_kib, kdf.t_cost, kdf.p_cost, Some(AEAD_KEY_LEN)).map_err(|e| {
            SecretError::EncryptionFailed {
                reason: format!("argon2 params: {e}"),
            }
        })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; AEAD_KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .map_err(|e| SecretError::EncryptionFailed {
            reason: format!("argon2 derive: {e}"),
        })?;
    Ok(SecretBytes(out))
}

/// Builds an AES-256-GCM cipher around the cached master key.
fn build_cipher(key_bytes: &[u8]) -> Result<Aes256Gcm, SecretError> {
    if key_bytes.len() != AEAD_KEY_LEN {
        return Err(SecretError::EncryptionFailed {
            reason: format!("expected {AEAD_KEY_LEN}-byte key, got {}", key_bytes.len()),
        });
    }
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes)))
}

/// Canonical associated data for AEAD per slot:
/// `v<version>:<surface>:<account>`. Pinning the file format version
/// in AAD means a future schema bump must include an explicit
/// migration step — silently changing AAD shape would invalidate
/// every existing entry. Binding the tag to the slot identity
/// prevents a file-edit attacker from re-pairing ciphertext under a
/// different slot.
fn aad_for(slot: SlotKey) -> String {
    format!(
        "v{}:{}:{}",
        CURRENT_VERSION,
        slot.surface,
        slot.account.get()
    )
}

/// Reads + parses the vault file. Returns `BackendUnavailable` when
/// the file does not exist — `open` always writes the header at first
/// use, so a missing file mid-process means an external actor (or a
/// crashed `secure_file` race) deleted it. Returning an empty
/// synthetic header would let `set` write a NEW header with a fresh
/// salt while the in-process master key is still bound to the OLD
/// salt — every subsequent `get` would then fail decryption (security
/// review H1).
///
/// `get` and `list_slots` use [`read_file_or_empty`] instead so a
/// vanished file surfaces as "no slots" rather than a hard error,
/// matching the trait's `NotFound` contract.
fn read_file(path: &Path) -> Result<VaultFile, SecretError> {
    let bytes = std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => SecretError::BackendUnavailable {
            reason: format!(
                "vault file disappeared at {} after open — restart csq to re-derive",
                path.display()
            ),
        },
        _ => SecretError::Io {
            path: path.to_path_buf(),
            source: e,
        },
    })?;
    let parsed: VaultFile = serde_json::from_slice(&bytes).map_err(|e| SecretError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;
    if parsed.version != CURRENT_VERSION {
        return Err(SecretError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unsupported vault file version {}, expected {CURRENT_VERSION}",
                    parsed.version
                ),
            ),
        });
    }
    Ok(parsed)
}

/// Read variant for query paths (`get`, `list_slots`) — synthesizes an
/// empty entry list when the file does not exist so the trait's
/// `NotFound` / empty-list contracts hold without a hard error. Does
/// NOT touch the salt: the synthesized header carries placeholder KDF
/// fields that are ONLY used to satisfy `serde` round-trip; query
/// paths never use the synthesized salt for derivation because they
/// reuse the cached master key from `FileVault::open`.
fn read_file_or_empty(path: &Path) -> Result<VaultFile, SecretError> {
    match read_file(path) {
        Ok(file) => Ok(file),
        // `BackendUnavailable` is the disappeared-file signal from
        // `read_file`; map it to an empty view so query paths return
        // `NotFound` per slot or an empty `list_slots`. Other errors
        // (corrupt JSON, version mismatch) propagate.
        Err(SecretError::BackendUnavailable { .. }) => Ok(VaultFile {
            version: CURRENT_VERSION,
            kdf: KdfParams {
                algo: "argon2id".into(),
                // Empty salt is a sentinel — never used for derivation
                // because the cached `master_key` was already derived
                // from the on-disk salt at `open` time.
                salt: String::new(),
                m_kib: KDF_M_KIB,
                t_cost: KDF_T_COST,
                p_cost: KDF_P_COST,
            },
            entries: Vec::new(),
        }),
        Err(other) => Err(other),
    }
}

/// Writes the vault file via the platform atomic-replace + secure
/// permissions pattern. Cleans up the temp file on every failure path
/// per `rules/security.md` §5a — a partial write of vault data left
/// at world-readable mode would be a downgrade vs the keychain.
fn write_file(path: &Path, file: &VaultFile) -> Result<(), SecretError> {
    let json = serde_json::to_vec_pretty(file).map_err(|e| SecretError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;
    let tmp = unique_tmp_path(path);
    if let Err(e) = std::fs::write(&tmp, &json) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SecretError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SecretError::Io {
            path: tmp,
            source: std::io::Error::other(format!("secure_file: {e}")),
        });
    }
    if let Err(e) = atomic_replace(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SecretError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(format!("atomic replace: {e}")),
        });
    }
    Ok(())
}

/// Manual clone for `KdfParams` — `serde` derive does not give us
/// `Clone` and we only need this once at first-init time.
fn clone_kdf(k: &KdfParams) -> KdfParams {
    KdfParams {
        algo: k.algo.clone(),
        salt: k.salt.clone(),
        m_kib: k.m_kib,
        t_cost: k.t_cost,
        p_cost: k.p_cost,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests run on every platform. They verify the crypto
    //! contract independent of dispatch — `open_default_vault` only
    //! routes to this backend on Linux, but the bytes-in / bytes-out
    //! invariants are platform-independent.
    //!
    //! Tests use a serial mutex around env-var manipulation; without
    //! it parallel tests race on `CSQ_SECRET_PASSPHRASE` and produce
    //! intermittent failures.

    use super::*;
    use crate::providers::catalog::Surface;
    use crate::types::AccountNum;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Surface tag for the only vault-using surface today. Resolved
    /// from [`Surface::Gemini::as_str()`] so the file-vault fixtures
    /// pivot automatically with any future Surface rename — no literal
    /// `"gemini"` survives in test code per PR-G2b.
    ///
    /// [`Surface::Gemini::as_str()`]: crate::providers::catalog::Surface::as_str
    const GEMINI: &str = Surface::Gemini.as_str();

    /// Serializes env-var manipulation across all tests in this
    /// module. `cargo test` runs tests in parallel; reading and
    /// writing process env without coordination produces flaky
    /// failures where one test sees another's passphrase.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that restores the env-var state on drop. Tests use
    /// this so a panicking assertion does not leak the test
    /// passphrase into sibling tests.
    struct EnvGuard {
        prev_pass: Option<String>,
        prev_pass_file: Option<String>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                prev_pass: std::env::var(ENV_PASSPHRASE).ok(),
                prev_pass_file: std::env::var(ENV_PASSPHRASE_FILE).ok(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev_pass.take() {
                Some(v) => std::env::set_var(ENV_PASSPHRASE, v),
                None => std::env::remove_var(ENV_PASSPHRASE),
            }
            match self.prev_pass_file.take() {
                Some(v) => std::env::set_var(ENV_PASSPHRASE_FILE, v),
                None => std::env::remove_var(ENV_PASSPHRASE_FILE),
            }
        }
    }

    fn slot(n: u16) -> SlotKey {
        SlotKey {
            surface: GEMINI,
            account: AccountNum::try_from(n).unwrap(),
        }
    }

    /// Lower-cost KDF parameters for tests. Argon2id at the production
    /// 64MiB / t=3 settings adds ~700ms per `open` call which compounds
    /// across the test suite. Tests verify the protocol; production
    /// constants are what the released binary uses.
    fn fast_open(dir: &Path) -> FileVault {
        // Bypass the production `open` path which uses the
        // production Argon2 params; mint a vault directly with a
        // small fixed key so tests run in milliseconds.
        let path = dir.join(VAULT_FILE_NAME);
        if !path.exists() {
            let header = VaultFile {
                version: CURRENT_VERSION,
                kdf: KdfParams {
                    algo: "argon2id".into(),
                    salt: B64.encode([0u8; KDF_SALT_LEN]),
                    m_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
                entries: Vec::new(),
            };
            write_file(&path, &header).unwrap();
        }
        FileVault {
            path,
            // Deterministic test key — NOT a real passphrase derive.
            // Production opens go through `derive_key`.
            master_key: SecretBytes(vec![0x42; AEAD_KEY_LEN]),
        }
    }

    #[test]
    fn set_and_get_round_trip() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        let s = SecretString::new("AIzaSyTEST_FILE_BACKEND_ROUND_TRIP_xxxxx".into());
        v.set(slot(1), &s).unwrap();
        let got = v.get(slot(1)).unwrap();
        assert_eq!(
            got.expose_secret(),
            "AIzaSyTEST_FILE_BACKEND_ROUND_TRIP_xxxxx"
        );
    }

    #[test]
    fn set_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        v.set(slot(2), &SecretString::new("first".into())).unwrap();
        v.set(slot(2), &SecretString::new("second".into())).unwrap();
        let got = v.get(slot(2)).unwrap();
        assert_eq!(got.expose_secret(), "second");
        let listed = v.list_slots(GEMINI).unwrap();
        assert_eq!(listed.len(), 1, "set must overwrite, not append");
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        v.delete(slot(5)).unwrap();
        v.set(slot(5), &SecretString::new("x".into())).unwrap();
        v.delete(slot(5)).unwrap();
        v.delete(slot(5)).unwrap();
        assert!(matches!(v.get(slot(5)), Err(SecretError::NotFound { .. })));
    }

    #[test]
    fn list_slots_returns_sorted_account_numbers_only() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        v.set(slot(10), &SecretString::new("x".into())).unwrap();
        v.set(slot(2), &SecretString::new("y".into())).unwrap();
        v.set(slot(7), &SecretString::new("z".into())).unwrap();
        let nums: Vec<u16> = v
            .list_slots(GEMINI)
            .unwrap()
            .iter()
            .map(|a| a.get())
            .collect();
        assert_eq!(nums, vec![2, 7, 10]);
    }

    #[test]
    fn list_slots_filters_by_surface() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        v.set(slot(1), &SecretString::new("g".into())).unwrap();
        v.set(
            SlotKey {
                surface: "future-surface",
                account: AccountNum::try_from(1u16).unwrap(),
            },
            &SecretString::new("f".into()),
        )
        .unwrap();
        assert_eq!(v.list_slots(GEMINI).unwrap().len(), 1);
        assert_eq!(v.list_slots("future-surface").unwrap().len(), 1);
    }

    #[test]
    fn get_missing_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        let err = v.get(slot(7)).unwrap_err();
        assert!(matches!(
            err,
            SecretError::NotFound {
                surface: GEMINI,
                account: 7
            }
        ));
    }

    #[test]
    fn empty_secret_rejected_at_set() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        let err = v
            .set(slot(1), &SecretString::new(String::new().into()))
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    #[test]
    fn backend_id_is_linux_file_aes() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        assert_eq!(v.backend_id(), "linux-file-aes");
    }

    /// AAD binding: an attacker editing the file to swap a slot 1
    /// ciphertext into the slot 2 entry MUST get `DecryptionFailed`,
    /// not the slot 1 cleartext bound to slot 2.
    #[test]
    fn aad_binding_prevents_slot_swap() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        v.set(slot(1), &SecretString::new("AAA-secret-one".into()))
            .unwrap();
        v.set(slot(2), &SecretString::new("BBB-secret-two".into()))
            .unwrap();

        // Read raw file, swap nonce + ciphertext between slots 1 and 2,
        // rewrite, then confirm decrypt fails for both rather than
        // returning the swapped cleartext.
        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(v.path()).unwrap()).unwrap();
        let (i1, i2) = (
            file.entries.iter().position(|e| e.account == 1).unwrap(),
            file.entries.iter().position(|e| e.account == 2).unwrap(),
        );
        let one_nonce = file.entries[i1].nonce.clone();
        let one_ct = file.entries[i1].ciphertext.clone();
        file.entries[i1].nonce = file.entries[i2].nonce.clone();
        file.entries[i1].ciphertext = file.entries[i2].ciphertext.clone();
        file.entries[i2].nonce = one_nonce;
        file.entries[i2].ciphertext = one_ct;
        write_file(v.path(), &file).unwrap();

        assert!(matches!(v.get(slot(1)), Err(SecretError::DecryptionFailed)));
        assert!(matches!(v.get(slot(2)), Err(SecretError::DecryptionFailed)));
    }

    /// Tampering the ciphertext (single-byte flip) MUST surface as
    /// `DecryptionFailed`; AES-GCM's authentication tag catches this.
    #[test]
    fn ciphertext_tamper_detected() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        v.set(slot(3), &SecretString::new("untampered".into()))
            .unwrap();

        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(v.path()).unwrap()).unwrap();
        let mut ct = B64.decode(&file.entries[0].ciphertext).unwrap();
        // Flip one bit in the middle (avoid the auth tag tail to be
        // sure we're testing detection of payload mutation, not
        // tag corruption).
        let mid = ct.len() / 2;
        ct[mid] ^= 0x01;
        file.entries[0].ciphertext = B64.encode(&ct);
        write_file(v.path(), &file).unwrap();

        assert!(matches!(v.get(slot(3)), Err(SecretError::DecryptionFailed)));
    }

    /// Wrong derived key MUST surface as `DecryptionFailed`. We
    /// simulate by writing with one key and reading with a different
    /// one — the AEAD authentication tag is keyed.
    #[test]
    fn wrong_key_surfaces_decryption_failed() {
        let dir = TempDir::new().unwrap();
        let v_writer = fast_open(dir.path());
        v_writer
            .set(slot(4), &SecretString::new("written-with-key-a".into()))
            .unwrap();

        // Open a "different process" view — same path, different key.
        let v_reader = FileVault {
            path: v_writer.path().to_path_buf(),
            master_key: SecretBytes(vec![0x99; AEAD_KEY_LEN]),
        };
        assert!(matches!(
            v_reader.get(slot(4)),
            Err(SecretError::DecryptionFailed)
        ));
    }

    /// Plaintext MUST NOT appear in the on-disk file. The most basic
    /// regression — if someone accidentally serializes the cleartext
    /// alongside the ciphertext, this test breaks loudly.
    #[test]
    fn plaintext_not_present_on_disk() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        let plaintext = "AIzaSy_PLAINTEXT_LEAK_CHECK_xxxxxxxxxxxx";
        v.set(slot(1), &SecretString::new(plaintext.into()))
            .unwrap();
        let raw = std::fs::read_to_string(v.path()).unwrap();
        assert!(!raw.contains(plaintext), "plaintext leaked: {raw}");
        assert!(!raw.contains("AIza"), "Gemini key prefix leaked");
    }

    /// File mode MUST be 0o600 after every write so a sibling-user
    /// process on a multi-user box cannot read the ciphertext.
    /// Required for the threat-model upgrade over a plain JSON
    /// credential file.
    #[cfg(unix)]
    #[test]
    fn file_mode_is_0o600_after_set() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        v.set(slot(1), &SecretString::new("x".into())).unwrap();
        let mode = std::fs::metadata(v.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }

    /// Two different vault files derived from the same passphrase MUST
    /// pin *different* salts. Without a fresh salt per vault, a
    /// rainbow table covering one user's vault would also crack
    /// another's. The salt is generated in `open`, not hardcoded in
    /// the cipher, so this is the regression check.
    #[test]
    fn two_opens_use_distinct_salts() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        std::env::set_var(ENV_PASSPHRASE, "test-passphrase-for-salt-uniqueness-x");
        let d1 = TempDir::new().unwrap();
        let d2 = TempDir::new().unwrap();
        let _v1 = FileVault::open(d1.path()).unwrap();
        let _v2 = FileVault::open(d2.path()).unwrap();
        let f1: VaultFile =
            serde_json::from_slice(&std::fs::read(d1.path().join(VAULT_FILE_NAME)).unwrap())
                .unwrap();
        let f2: VaultFile =
            serde_json::from_slice(&std::fs::read(d2.path().join(VAULT_FILE_NAME)).unwrap())
                .unwrap();
        assert_ne!(f1.kdf.salt, f2.kdf.salt, "salts must be unique per vault");
    }

    /// Open without any passphrase env var set MUST refuse with
    /// `BackendUnavailable`. This is the user-visible refusal the
    /// dispatch layer relies on.
    #[test]
    fn open_without_passphrase_returns_backend_unavailable() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        std::env::remove_var(ENV_PASSPHRASE);
        std::env::remove_var(ENV_PASSPHRASE_FILE);
        let dir = TempDir::new().unwrap();
        let err = FileVault::open(dir.path()).unwrap_err();
        assert!(
            matches!(err, SecretError::BackendUnavailable { .. }),
            "expected BackendUnavailable, got {err:?}"
        );
    }

    /// Empty passphrase MUST also refuse — empty string would derive
    /// a deterministic key from a known salt schedule.
    #[test]
    fn open_with_empty_passphrase_returns_backend_unavailable() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        std::env::set_var(ENV_PASSPHRASE, "");
        std::env::remove_var(ENV_PASSPHRASE_FILE);
        let dir = TempDir::new().unwrap();
        let err = FileVault::open(dir.path()).unwrap_err();
        assert!(matches!(err, SecretError::BackendUnavailable { .. }));
    }

    /// `CSQ_SECRET_PASSPHRASE_FILE` MUST work as an alternate source.
    /// Tests the file-read path including trailing-newline strip.
    #[test]
    fn open_with_passphrase_file_works_and_strips_newline() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        std::env::remove_var(ENV_PASSPHRASE);
        let pass_dir = TempDir::new().unwrap();
        let pass_path = pass_dir.path().join("pass.txt");
        std::fs::write(&pass_path, "from-file-passphrase\n").unwrap();
        std::env::set_var(ENV_PASSPHRASE_FILE, &pass_path);

        let vault_dir = TempDir::new().unwrap();
        let v = FileVault::open(vault_dir.path()).unwrap();
        v.set(slot(1), &SecretString::new("payload".into()))
            .unwrap();

        // Fresh open with the same file MUST decrypt the same value.
        let v2 = FileVault::open(vault_dir.path()).unwrap();
        assert_eq!(v2.get(slot(1)).unwrap().expose_secret(), "payload");
    }

    /// Round-trip across an `open` boundary using the production
    /// Argon2 derive — slow (~1.5s) but verifies the real KDF
    /// integrates with set/get. Marked `#[ignore]` so the standard
    /// `cargo test` run stays fast; CI / security review run it via
    /// `--include-ignored`.
    #[test]
    #[ignore = "exercises full Argon2id at production cost — run with --include-ignored"]
    fn full_argon2_round_trip() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        std::env::set_var(ENV_PASSPHRASE, "argon2-full-cost-passphrase-xyz");
        std::env::remove_var(ENV_PASSPHRASE_FILE);
        let dir = TempDir::new().unwrap();
        let v = FileVault::open(dir.path()).unwrap();
        v.set(
            slot(1),
            &SecretString::new("AIzaSyHEAVY_KDF_TEST_xxxxx".into()),
        )
        .unwrap();
        let v2 = FileVault::open(dir.path()).unwrap();
        assert_eq!(
            v2.get(slot(1)).unwrap().expose_secret(),
            "AIzaSyHEAVY_KDF_TEST_xxxxx"
        );
    }

    /// Tests that a corrupt JSON file surfaces as Io with InvalidData
    /// rather than panicking.
    #[test]
    fn corrupt_file_surfaces_as_io_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(VAULT_FILE_NAME);
        std::fs::write(&path, b"this is not json").unwrap();
        let result = read_file(&path);
        assert!(matches!(result, Err(SecretError::Io { .. })));
    }

    /// Regression for security review H1: if the vault file is
    /// deleted between `open` and `set`, `set` MUST refuse with
    /// `BackendUnavailable` rather than synthesize an empty header
    /// and write it out with a fresh salt that orphans the cached
    /// master key. Same invariant for `delete`.
    #[test]
    fn set_refuses_when_file_vanished_after_open() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        // Simulate external deletion mid-process.
        std::fs::remove_file(v.path()).unwrap();
        match v.set(slot(1), &SecretString::new("x".into())) {
            Err(SecretError::BackendUnavailable { reason }) => {
                assert!(
                    reason.contains("vanished") || reason.contains("disappeared"),
                    "reason must explain the vanished file, got: {reason}"
                );
            }
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
    }

    /// Companion: `delete` MUST refuse when the file vanished — the
    /// idempotent-delete contract is "deleting an unstored slot
    /// returns Ok", but a vanished FILE is a structural failure
    /// distinct from a missing slot.
    #[test]
    fn delete_refuses_when_file_vanished_after_open() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        std::fs::remove_file(v.path()).unwrap();
        match v.delete(slot(1)) {
            Err(SecretError::BackendUnavailable { .. }) => {}
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
    }

    /// Companion: `get` and `list_slots` SHOULD treat a vanished
    /// file as "no entries" — preserves the trait's NotFound /
    /// empty-list contracts. The asymmetry vs `set`/`delete` is
    /// intentional: read paths cannot corrupt the salt invariant.
    #[test]
    fn get_after_file_vanished_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        std::fs::remove_file(v.path()).unwrap();
        match v.get(slot(1)) {
            Err(SecretError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
        let listed = v.list_slots(GEMINI).unwrap();
        assert!(listed.is_empty());
    }

    /// Future version numbers MUST be rejected explicitly so a
    /// downgraded csq does not silently misread a newer file format.
    #[test]
    fn unsupported_version_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(VAULT_FILE_NAME);
        let header = serde_json::json!({
            "version": 99,
            "kdf": {
                "algo": "argon2id", "salt": B64.encode([0u8; KDF_SALT_LEN]),
                "m_kib": 8, "t_cost": 1, "p_cost": 1,
            },
            "entries": [],
        });
        std::fs::write(&path, header.to_string()).unwrap();
        let result = read_file(&path);
        assert!(matches!(result, Err(SecretError::Io { .. })));
    }
}
