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

use super::{NamedKey, SecretError, SlotKey, Vault};
#[cfg(test)]
use crate::platform::fs::write_new_private_retained;
use crate::platform::fs::write_private_tmp_synced_retained;
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
    pool_path: std::path::PathBuf,
    pool_kdf: KdfParams,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    named_entries: Vec<NamedEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NamedEntry {
    name: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        // R2 N3: the first-use decision is FAIL-CLOSED. `path.exists()` reports
        // false on any stat error (and on a dangling symlink), which would mint a
        // fresh salt and rewrite the header — permanent credential loss for an
        // existing store. `vault_first_use` returns `true` only for a
        // determinate absence and ERRORS on a stat failure, a symlink, or a
        // non-file entry.
        let kdf_params = if vault_first_use(&path)? {
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
                named_entries: Vec::new(),
            };
            write_file(&path, &empty)?;
            kdf
        } else {
            // Existing store: KDF parameters are pinned in the file
            // header. Verify algorithm match before deriving against
            // them.
            let file = read_file(&path)?;
            if file.kdf.algo != "argon2id" {
                return Err(SecretError::DecryptionFailed);
            }
            file.kdf
        };

        let master_key = derive_key(passphrase.expose_secret(), &kdf_params)?;
        let pool_path = base_dir.join("pool-vault-store.json");
        // Separate file prevents ordinary slot writers from losing pool updates.
        // The pool caller holds its custody lock across these read/modify/writes.
        // Named storage has its own file and domain-separated AAD, but shares
        // this vault's derived key. Opening a legacy slot vault never reads or
        // creates pool data. Named operations verify the pinned KDF header.
        let pool_kdf = clone_kdf(&kdf_params);
        Ok(Self {
            path,
            master_key,
            pool_path,
            pool_kdf,
        })
    }

    /// Fixture-only constructor. Never selects a host credential backend.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_test(base_dir: &Path) -> Result<Self, SecretError> {
        std::fs::create_dir_all(base_dir).map_err(|source| SecretError::Io {
            path: base_dir.into(),
            source,
        })?;
        let path = base_dir.join(VAULT_FILE_NAME);
        let pool_path = base_dir.join("pool-vault-store.json");
        for p in [&path, &pool_path] {
            if !p.exists() {
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
                    named_entries: Vec::new(),
                };
                write_file(p, &header)?;
            }
        }
        let pool_kdf = read_file(&path)?.kdf;
        Ok(Self {
            path,
            pool_path,
            master_key: SecretBytes(vec![0x42; AEAD_KEY_LEN]),
            pool_kdf,
        })
    }

    /// Path of the underlying vault file. Test-only — production code
    /// should not need to know.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl FileVault {
    fn write_named(
        &self,
        key: &NamedKey,
        secret: &SecretString,
        create_allowed: bool,
    ) -> Result<(), SecretError> {
        if secret.expose_secret().is_empty() {
            return Err(SecretError::InvalidKey {
                reason: "secret must not be empty".into(),
            });
        }
        let initially_exists = !vault_file_absent(&self.pool_path)?;
        let mut file = if initially_exists {
            read_file(&self.pool_path)?
        } else if create_allowed {
            VaultFile {
                version: CURRENT_VERSION,
                kdf: clone_kdf(&self.pool_kdf),
                entries: Vec::new(),
                named_entries: Vec::new(),
            }
        } else {
            return Err(SecretError::BackendUnavailable {
                reason: "named vault file is unavailable".into(),
            });
        };
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| SecretError::EncryptionFailed {
            reason: "nonce rng failed".into(),
        })?;
        if file.kdf != self.pool_kdf {
            return Err(SecretError::DecryptionFailed);
        }
        let aad = format!("v1:{}", key.native_name());
        let ciphertext = build_cipher(self.master_key.as_slice())?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret.expose_secret().as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecretError::EncryptionFailed {
                reason: "aead encrypt failed".into(),
            })?;
        let entry = NamedEntry {
            name: key.name().to_owned(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        };
        if let Some(old) = file.named_entries.iter_mut().find(|e| e.name == key.name()) {
            *old = entry;
        } else {
            file.named_entries.push(entry);
        }
        write_file_with_policy(&self.pool_path, &file, initially_exists)
    }
}

impl Vault for FileVault {
    fn set_named(&self, key: &NamedKey, secret: &SecretString) -> Result<(), SecretError> {
        self.write_named(key, secret, true)
    }
    fn set_named_existing(&self, key: &NamedKey, secret: &SecretString) -> Result<(), SecretError> {
        self.write_named(key, secret, false)
    }
    fn get_named(&self, key: &NamedKey) -> Result<SecretString, SecretError> {
        if vault_file_absent(&self.pool_path)? {
            // The store disappeared, rather than one item inside a readable
            // store. Callers with published native rows must stop execution.
            return Err(SecretError::BackendUnavailable {
                reason: "named vault file is unavailable".into(),
            });
        }
        let file = read_file(&self.pool_path)?;
        if file.kdf != self.pool_kdf {
            return Err(SecretError::DecryptionFailed);
        }
        let e = file
            .named_entries
            .iter()
            .find(|e| e.name == key.name())
            .ok_or(SecretError::NamedNotFound)?;
        let nonce = B64
            .decode(&e.nonce)
            .map_err(|_| SecretError::NamedItemUnreadable)?;
        if nonce.len() != AEAD_NONCE_LEN {
            return Err(SecretError::NamedItemUnreadable);
        }
        let ciphertext = B64
            .decode(&e.ciphertext)
            .map_err(|_| SecretError::NamedItemUnreadable)?;
        // Aes256Gcm stores its 128-bit authentication tag with the ciphertext.
        // Fewer bytes cannot be a complete item under any passphrase.
        if ciphertext.len() < 16 {
            return Err(SecretError::NamedItemUnreadable);
        }
        let aad = format!("v1:{}", key.native_name());
        let clear = zeroize::Zeroizing::new(
            build_cipher(self.master_key.as_slice())?
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| SecretError::DecryptionFailed)?,
        );
        let value = std::str::from_utf8(&clear).map_err(|_| SecretError::NamedItemUnreadable)?;
        Ok(SecretString::new(value.to_owned().into()))
    }
    fn delete_named(&self, key: &NamedKey) -> Result<(), SecretError> {
        if vault_file_absent(&self.pool_path)? {
            return Ok(());
        }
        let mut file = read_file(&self.pool_path)?;
        if file.kdf != self.pool_kdf {
            return Err(SecretError::DecryptionFailed);
        }
        file.named_entries.retain(|e| e.name != key.name());
        write_file_with_policy(&self.pool_path, &file, true)
    }
    fn contains_named(&self, key: &NamedKey) -> Result<bool, SecretError> {
        if vault_file_absent(&self.pool_path)? {
            return Ok(false);
        }
        Ok(read_file(&self.pool_path)?
            .named_entries
            .iter()
            .any(|e| e.name == key.name()))
    }
    fn named_store_present(&self) -> Result<bool, SecretError> {
        if vault_file_absent(&self.pool_path)? {
            return Ok(false);
        }
        let file = read_file(&self.pool_path)?;
        if file.kdf != self.pool_kdf {
            return Err(SecretError::DecryptionFailed);
        }
        Ok(true)
    }

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

/// The FIRST-USE decision for `FileVault::open`: `Ok(true)` only when `path` is
/// determinately absent — the parent resolves to a real directory (or is itself
/// absent, in which case the child cannot exist) and the entry does not exist.
/// A stat error, a symlink (dangling or not), or a non-file entry is an ERROR,
/// never "first use": minting a new salt and rewriting the header over an
/// existing or unreadable store is permanent credential loss (R2 N3).
fn vault_first_use(path: &Path) -> Result<bool, SecretError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() && !meta.file_type().is_symlink() => Ok(false),
        Ok(_) => Err(SecretError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other("the vault path exists but is not a regular file"),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match path.parent() {
            Some(parent) => match std::fs::metadata(parent) {
                Ok(meta) if meta.is_dir() => Ok(true),
                // The parent is absent: the child cannot exist either.
                Err(parent_error) if parent_error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(true)
                }
                Ok(_) => Err(SecretError::Io {
                    path: parent.to_path_buf(),
                    source: std::io::Error::other("the vault parent is not a directory"),
                }),
                Err(source) => Err(SecretError::Io {
                    path: parent.to_path_buf(),
                    source,
                }),
            },
            None => Ok(true),
        },
        Err(source) => Err(SecretError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// `true` only when `path` is GENUINELY absent. A non-directory component on the
/// way to `path` makes every child open fail with `ERROR_DIRECTORY` /
/// `ERROR_PATH_NOT_FOUND`, which `std` reports as `ErrorKind::NotFound`; reading
/// that as "the vault is absent" lets a removal confirm a store it never opened
/// (native run 41157525966; guard-reader-writer parity MUST-2 — a destructive
/// path fails CLOSED). The parent must therefore resolve to a real directory;
/// a symlinked/reparse parent that does resolve is allowed, matching the rest of
/// this backend, but a file standing where the directory belongs is not.
fn vault_file_absent(path: &Path) -> Result<bool, SecretError> {
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    let parent_meta = std::fs::metadata(parent).map_err(|source| SecretError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    if !parent_meta.is_dir() {
        return Err(SecretError::BackendUnavailable {
            reason: "the vault parent is not a directory; a child open failure there is not \
                     evidence the vault is absent"
                .into(),
        });
    }
    // The identity of the directory the parent path reaches, captured BEFORE
    // the child lookup. A Windows `Metadata` cannot supply it (std's
    // `volume_serial_number`/`file_index` are still unstable, rust-lang#63010),
    // so every platform captures through [`directory_identity`].
    let before = directory_identity(parent).ok_or_else(|| SecretError::BackendUnavailable {
        reason: "the vault parent's identity could not be read; absence cannot be confirmed".into(),
    })?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Re-verify the parent AFTER the child lookup: a parent swapped for
            // another directory (or for a file) between the two lookups makes
            // this child lookup report NotFound for a store that is really
            // there. Only the SAME directory that was checked may confirm
            // absence (R2 NEW-6).
            #[cfg(test)]
            BEFORE_ABSENCE_RECHECK.with(|slot| {
                let hook = slot.borrow_mut().take();
                if let Some(hook) = hook {
                    hook(parent);
                }
            });
            let after_meta = std::fs::metadata(parent).map_err(|source| SecretError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
            if !after_meta.is_dir() || directory_identity(parent) != Some(before) {
                return Err(SecretError::BackendUnavailable {
                    reason: "the vault parent changed while its absence was checked".into(),
                });
            }
            Ok(true)
        }
        Err(source) => Err(SecretError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The identity of the directory `path` resolves to: device+inode on unix.
#[cfg(unix)]
fn directory_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}
/// Windows: open a no-follow directory handle and read
/// `BY_HANDLE_FILE_INFORMATION`'s volume serial + file index. std's `Metadata`
/// accessors for both are still unstable (rust-lang/rust#63010), so a handle is
/// the only stable source.
#[cfg(windows)]
fn directory_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .ok()?;
    // SAFETY: `BY_HANDLE_FILE_INFORMATION` is plain old data; a zeroed value is
    // fully initialised and the API fills it for a live handle.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: live handle owned by `file` and a valid output slot.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return None;
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Some((u64::from(info.dwVolumeSerialNumber), index))
}
#[cfg(not(any(unix, windows)))]
fn directory_identity(_path: &Path) -> Option<(u64, u64)> {
    None
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
/// empty entry list when the file is GENUINELY absent so the trait's
/// `NotFound` / empty-list contracts hold without a hard error. Does
/// NOT touch the salt: the synthesized header carries placeholder KDF
/// fields that are ONLY used to satisfy `serde` round-trip; query
/// paths never use the synthesized salt for derivation because they
/// reuse the cached master key from `FileVault::open`.
///
/// Absence is decided by [`vault_file_absent`], never by a child open
/// failure: a parent replaced by a file makes every child open fail with
/// `ERROR_PATH_NOT_FOUND`, which `std` reports as `NotFound` — reading that as
/// "no entries" would report an empty store for one that was never opened
/// (native run 41157525966). A broken parent therefore propagates
/// `BackendUnavailable`; only a missing file under a real directory is empty.
fn read_file_or_empty(path: &Path) -> Result<VaultFile, SecretError> {
    if !vault_file_absent(path)? {
        return read_file(path);
    }
    Ok(VaultFile {
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
        named_entries: Vec::new(),
    })
}

/// Writes the vault file via the platform atomic-replace + secure
/// permissions pattern. The retained writer cleans up its temp on failure
/// per `rules/security.md` §5a — a partial write of vault data left
/// at world-readable mode would be a downgrade vs the keychain.
fn write_file(path: &Path, file: &VaultFile) -> Result<(), SecretError> {
    write_file_with_policy(path, file, false)
}

#[cfg(test)]
type NamedPublishHook = Box<dyn FnOnce(&Path)>;
#[cfg(test)]
thread_local! {
    static BEFORE_NAMED_PUBLISH: std::cell::RefCell<Option<NamedPublishHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn with_named_publish_hook<T>(
    hook: impl FnOnce(&Path) + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<NamedPublishHook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            BEFORE_NAMED_PUBLISH.with(|slot| {
                *slot.borrow_mut() = self.0.take();
            });
        }
    }
    let _restore =
        Restore(BEFORE_NAMED_PUBLISH.with(|slot| slot.borrow_mut().replace(Box::new(hook))));
    operation()
}

// Seam between the child lookup and the parent re-check inside
// `vault_file_absent`: a test swaps the parent here to prove the absence
// re-check refuses a different directory (R2 NEW-6).
#[cfg(test)]
thread_local! {
    static BEFORE_ABSENCE_RECHECK: std::cell::RefCell<Option<NamedPublishHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn with_absence_recheck_hook<T>(
    hook: impl FnOnce(&Path) + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<NamedPublishHook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            BEFORE_ABSENCE_RECHECK.with(|slot| {
                *slot.borrow_mut() = self.0.take();
            });
        }
    }
    let _restore =
        Restore(BEFORE_ABSENCE_RECHECK.with(|slot| slot.borrow_mut().replace(Box::new(hook))));
    operation()
}

fn write_file_with_policy(
    path: &Path,
    file: &VaultFile,
    require_existing: bool,
) -> Result<(), SecretError> {
    let json = serde_json::to_vec_pretty(file).map_err(|e| SecretError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;
    // The target factory retains private staging custody and syncs before publication.
    let writer = write_private_tmp_synced_retained(path, &json).map_err(|e| SecretError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(format!("write: {e}")),
    })?;
    publish_file_with_policy(path, writer, require_existing)
}

// Explicit-path collision fixture: production writes use the target factory above.
#[cfg(test)]
fn write_file_bytes_with_tmp(path: &Path, json: &[u8], tmp: PathBuf) -> Result<(), SecretError> {
    let writer = write_new_private_retained(&tmp, json).map_err(|e| SecretError::Io {
        path: tmp,
        source: std::io::Error::other(format!("write: {e}")),
    })?;
    publish_file_with_policy(path, writer, false)
}

fn publish_file_with_policy(
    path: &Path,
    writer: crate::platform::fs::WrittenPrivateFile,
    require_existing: bool,
) -> Result<(), SecretError> {
    // Retained custody replaces the former path-only UnpublishedFile guard:
    // early returns and hook unwind drop only the file this writer created.
    #[cfg(test)]
    BEFORE_NAMED_PUBLISH.with(|slot| {
        let hook = slot.borrow_mut().take();
        if let Some(hook) = hook {
            hook(path);
        }
    });
    // This checks loss after reading and staging, immediately before publish.
    // Pool custody remains held by callers. POSIX rename has a residual
    // final-check-to-rename window; this is not a compare-and-replace primitive.
    //
    // NB: this presence check is fail-CLOSED — a false, including a broken
    // parent's ERROR_PATH_NOT_FOUND (which `try_exists` reports as false),
    // REFUSES the write, so no absence is assumed here and `vault_file_absent`
    // is intentionally not applied: an internal ticket reworks this exact check-to-rename
    // window as a compare-and-replace, and duplicating the parent check here
    // would collide with that change.
    if require_existing
        && !path.try_exists().map_err(|source| SecretError::Io {
            path: path.to_path_buf(),
            source,
        })?
    {
        return Err(SecretError::BackendUnavailable {
            reason: "named vault file is unavailable".into(),
        });
    }
    writer.replace(path).map_err(|e| SecretError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(format!("atomic replace: {e}")),
    })
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

    #[test]
    fn f_a_vault_save_retries_first_sibling_collision() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("vault-store.json");
        let vault = read_file_or_empty(&target).unwrap();
        let expected = serde_json::to_value(&vault).unwrap();
        let parent = dir.path().to_path_buf();
        let collision = std::rc::Rc::new(std::cell::RefCell::new(None));
        let planted = collision.clone();
        let result = crate::platform::fs::with_private_create_observer_for_test(
            move |candidate| {
                assert_eq!(candidate.parent(), Some(parent.as_path()));
                if planted.borrow().is_none() {
                    std::fs::write(candidate, b"foreign-vault-stage").unwrap();
                    *planted.borrow_mut() = Some(candidate.to_path_buf());
                }
            },
            || write_file(&target, &vault),
        );
        let foreign = collision
            .borrow()
            .clone()
            .expect("production create observed");
        assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign-vault-stage");
        result.expect("vault save must retry the first sibling collision");
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(saved, expected);
    }

    #[test]
    fn atomic_write_collision_preserves_foreign_vault_temporary_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault-store.json");
        let tmp = dir.path().join("occupied.tmp");
        std::fs::write(&path, b"canonical-before").unwrap();
        std::fs::write(&tmp, b"foreign-before").unwrap();

        let result = write_file_bytes_with_tmp(&path, b"{}", tmp.clone());

        assert!(matches!(result, Err(SecretError::Io { path, .. }) if path == tmp));
        assert_eq!(std::fs::read(&path).unwrap(), b"canonical-before");
        assert_eq!(
            std::fs::read(&tmp).ok().as_deref(),
            Some(&b"foreign-before"[..])
        );
    }

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
    /// failures where one test sees another's passphrase. Tests
    /// acquire `crate::platform::test_env::lock()` BEFORE this lock so
    /// every env-mutating test in the workspace serializes against
    /// every other (cross-module flakes manifest as one test seeing
    /// another's PATH / HOME / XDG_RUNTIME_DIR mid-flight; the
    /// per-module lock alone does not catch that).
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
                named_entries: Vec::new(),
            };
            write_file(&path, &header).unwrap();
        }
        let pool_path = dir.join("pool-vault-store.json");
        if !pool_path.exists() {
            let mut header = read_file(&path).unwrap();
            header.entries.clear();
            write_file(&pool_path, &header).unwrap();
        }
        let pool_kdf = read_file(&path).unwrap().kdf;
        FileVault {
            pool_kdf,
            pool_path,
            path,
            // Deterministic test key — NOT a real passphrase derive.
            // Production opens go through `derive_key`.
            master_key: SecretBytes(vec![0x42; AEAD_KEY_LEN]),
        }
    }

    #[test]
    fn legacy_open_does_not_read_corrupt_pool_store() {
        let _shared = crate::platform::test_env::lock();
        let _local = ENV_LOCK.lock().unwrap();
        let _restore = EnvGuard::capture();
        std::env::set_var(ENV_PASSPHRASE, "fixture-passphrase");
        std::env::remove_var(ENV_PASSPHRASE_FILE);
        let dir = TempDir::new().unwrap();
        let vault = fast_open(dir.path());
        vault
            .set(slot(3), &SecretString::new("fixture-slot-value".into()))
            .unwrap();
        std::fs::write(&vault.pool_path, b"invalid-json").unwrap();
        let slot_before = std::fs::read(&vault.path).unwrap();
        let reopened = FileVault::open(dir.path()).unwrap();
        assert_eq!(reopened.list_slots(GEMINI).unwrap(), vec![slot(3).account]);
        assert_eq!(std::fs::read(&vault.path).unwrap(), slot_before);
        assert!(reopened
            .contains_named(&NamedKey::pool("fixture").unwrap())
            .is_err());
    }

    #[test]
    fn named_file_roundtrip_isolated_from_slot_writers() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("generation.01").unwrap();
        vault
            .set_named(&key, &SecretString::new("fixture-pool-value".into()))
            .unwrap();
        let pool_before = std::fs::read(&vault.pool_path).unwrap();
        vault
            .set(slot(1), &SecretString::new("fixture-slot-value".into()))
            .unwrap();
        assert_eq!(std::fs::read(&vault.pool_path).unwrap(), pool_before);
        assert_eq!(
            vault.get_named(&key).unwrap().expose_secret(),
            "fixture-pool-value"
        );
        assert!(vault.contains_named(&key).unwrap());
        vault.delete_named(&key).unwrap();
        vault.delete_named(&key).unwrap();
        assert!(!vault.contains_named(&key).unwrap());
        assert!(matches!(
            vault.get_named(&key),
            Err(SecretError::NamedNotFound)
        ));
        assert_eq!(
            vault.get(slot(1)).unwrap().expose_secret(),
            "fixture-slot-value"
        );
    }

    #[test]
    fn named_existing_write_refuses_absence_but_first_write_can_initialize() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("fixture").unwrap();
        std::fs::remove_file(&vault.pool_path).unwrap();
        assert!(
            matches!(
                vault.set_named_existing(&key, &SecretString::from("synthetic-value")),
                Err(SecretError::BackendUnavailable { .. })
            ),
            "must-exist named writes must refuse an absent file"
        );
        assert!(!vault.pool_path.try_exists().unwrap());
        vault
            .set_named(&key, &SecretString::from("synthetic-value"))
            .unwrap();
        assert!(vault.named_store_present().unwrap());
    }

    fn assert_loss_after_staging_refuses_publish(
        operation: impl FnOnce(&FileVault, &NamedKey) -> Result<(), SecretError>,
        message: &str,
    ) {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("fixture").unwrap();
        vault
            .set_named(&key, &SecretString::from("synthetic-before-loss"))
            .unwrap();
        let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = hit.clone();
        let result = with_named_publish_hook(
            move |path| {
                // Slot file, named file, then the encrypted staged replacement.
                assert_eq!(
                    std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
                    3
                );
                std::fs::remove_file(path).unwrap();
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            },
            || operation(&vault, &key),
        );
        assert!(hit.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            matches!(result, Err(SecretError::BackendUnavailable { .. })),
            "{message}"
        );
        assert!(!vault.pool_path.try_exists().unwrap());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn named_existing_write_refuses_loss_after_staging_before_publish() {
        assert_loss_after_staging_refuses_publish(
            |vault, key| vault.set_named_existing(key, &SecretString::from("synthetic-after-loss")),
            "existing named write must refuse loss after staging before publish",
        );
    }

    #[test]
    fn named_delete_refuses_loss_after_staging_before_publish() {
        assert_loss_after_staging_refuses_publish(
            |vault, key| vault.delete_named(key),
            "named delete must refuse loss after staging before publish",
        );
    }

    #[test]
    fn named_creation_allowed_write_preserves_initial_existence_requirement() {
        assert_loss_after_staging_refuses_publish(
            |vault, key| vault.set_named(key, &SecretString::from("synthetic-after-loss")),
            "creation-allowed named write must not recreate an initially existing file",
        );
    }

    #[cfg(unix)]
    #[test]
    fn named_publish_refuses_undeterminable_presence_after_staging() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("fixture").unwrap();
        let result = with_named_publish_hook(
            |path| {
                assert_eq!(
                    std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
                    3
                );
                std::fs::remove_file(path).unwrap();
                std::os::unix::fs::symlink("pool-vault-store.json", path).unwrap();
            },
            || vault.set_named_existing(&key, &SecretString::from("synthetic-value")),
        );
        assert!(
            matches!(result, Err(SecretError::Io { .. })),
            "undeterminable final presence must refuse named publication"
        );
        assert!(std::fs::symlink_metadata(&vault.pool_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn named_publish_hook_unwind_restores_scope_and_cleans_staging() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("fixture").unwrap();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_named_publish_hook(
                |_| panic!("synthetic before-publish unwind"),
                || vault.set_named_existing(&key, &SecretString::from("synthetic-value")),
            )
        }));
        assert!(panicked.is_err());
        assert!(BEFORE_NAMED_PUBLISH.with(|slot| slot.borrow().is_none()));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        vault
            .set_named_existing(&key, &SecretString::from("synthetic-after-unwind"))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn named_set_refuses_an_undeterminable_store_instead_of_recreating_it() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("fixture").unwrap();
        std::fs::remove_file(&vault.pool_path).unwrap();
        std::os::unix::fs::symlink("pool-vault-store.json", &vault.pool_path).unwrap();
        assert!(
            matches!(
                vault.set_named(&key, &SecretString::from("synthetic-value")),
                Err(SecretError::Io { .. })
            ),
            "an undeterminable store must not be recreated by set_named"
        );
    }

    #[cfg(unix)]
    #[test]
    fn named_delete_refuses_an_undeterminable_store_instead_of_claiming_success() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("fixture").unwrap();
        std::fs::remove_file(&vault.pool_path).unwrap();
        std::os::unix::fs::symlink("pool-vault-store.json", &vault.pool_path).unwrap();
        assert!(
            matches!(vault.delete_named(&key), Err(SecretError::Io { .. })),
            "an undeterminable store must not count as a successful delete"
        );
    }

    #[test]
    fn named_presence_does_not_decode_or_decrypt_payload() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("fixture").unwrap();
        vault
            .set_named(&key, &SecretString::new("fixture-value".into()))
            .unwrap();
        let mut file = read_file(&vault.pool_path).unwrap();
        file.named_entries[0].nonce = "invalid-base64".into();
        file.named_entries[0].ciphertext = "invalid-base64".into();
        write_file(&vault.pool_path, &file).unwrap();
        // F7: malformed named-item bytes are item-local; presence stays metadata-only.
        assert!(vault.contains_named(&key).unwrap());
        assert!(matches!(
            vault.get_named(&key),
            Err(SecretError::NamedItemUnreadable)
        ));

        // A corrupt pool file remains a vault-wide I/O error under F7.
        std::fs::write(&vault.pool_path, b"{broken-json").unwrap();
        assert!(matches!(
            vault.get_named(&key),
            Err(SecretError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn legacy_slot_name_aad_and_layout_are_pinned() {
        assert_eq!(slot(3).native_name(), "csq.gemini.3");
        assert_eq!(aad_for(slot(3)), "v1:gemini:3");
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        vault
            .set(slot(3), &SecretString::new("fixture-slot-value".into()))
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vault.path()).unwrap()).unwrap();
        assert!(json.get("named_entries").is_none());
        assert_eq!(json["version"], 1);
        assert_eq!(json["entries"][0]["account"], 3);
        assert_eq!(json["entries"][0]["surface"], "gemini");
    }

    #[test]
    fn named_aad_refuses_ciphertext_readdressing() {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::open_test(dir.path()).unwrap();
        let key = NamedKey::pool("original").unwrap();
        vault
            .set_named(&key, &SecretString::new("fixture-value".into()))
            .unwrap();
        let mut file = read_file(&vault.pool_path).unwrap();
        file.named_entries[0].name = "replacement".into();
        write_file(&vault.pool_path, &file).unwrap();
        assert!(matches!(
            vault.get_named(&NamedKey::pool("replacement").unwrap()),
            Err(SecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn set_and_get_round_trip() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        let s = SecretString::new("AIzaFAKETESTKEYDONOTUSE0000000000000000".into());
        v.set(slot(1), &s).unwrap();
        let got = v.get(slot(1)).unwrap();
        assert_eq!(
            got.expose_secret(),
            "AIzaFAKETESTKEYDONOTUSE0000000000000000"
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
            pool_path: v_writer.pool_path.clone(),
            pool_kdf: clone_kdf(&v_writer.pool_kdf),
            path: v_writer.path().to_path_buf(),
            master_key: SecretBytes(vec![0x99; AEAD_KEY_LEN]),
        };
        assert!(matches!(
            v_reader.get(slot(4)),
            Err(SecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn named_wrong_key_remains_a_vault_wide_decryption_failure() {
        let dir = TempDir::new().unwrap();
        let writer = fast_open(dir.path());
        let name = NamedKey::pool(&"11".repeat(16)).unwrap();
        writer
            .set_named(&name, &SecretString::from("synthetic-written-with-key-a"))
            .unwrap();
        let reader = FileVault {
            pool_path: writer.pool_path.clone(),
            pool_kdf: clone_kdf(&writer.pool_kdf),
            path: writer.path().to_path_buf(),
            master_key: SecretBytes(vec![0x99; AEAD_KEY_LEN]),
        };
        assert!(matches!(
            reader.get_named(&name),
            Err(SecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn named_authenticated_invalid_utf8_is_an_item_read_failure() {
        let dir = TempDir::new().unwrap();
        let vault = fast_open(dir.path());
        let name = NamedKey::pool(&"22".repeat(16)).unwrap();
        vault
            .set_named(&name, &SecretString::from("synthetic-original-item"))
            .unwrap();
        let mut stored = read_file(&vault.pool_path).unwrap();
        let nonce = [1_u8; AEAD_NONCE_LEN];
        let aad = format!("v1:{}", name.native_name());
        let ciphertext = build_cipher(vault.master_key.as_slice())
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &[0xff],
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        stored.named_entries[0].nonce = B64.encode(nonce);
        stored.named_entries[0].ciphertext = B64.encode(ciphertext);
        write_file(&vault.pool_path, &stored).unwrap();
        assert!(matches!(
            vault.get_named(&name),
            Err(SecretError::NamedItemUnreadable)
        ));
    }

    /// Plaintext MUST NOT appear in the on-disk file. The most basic
    /// regression — if someone accidentally serializes the cleartext
    /// alongside the ciphertext, this test breaks loudly.
    #[test]
    fn plaintext_not_present_on_disk() {
        let dir = TempDir::new().unwrap();
        let v = fast_open(dir.path());
        let plaintext = "AIzaFAKETESTKEYDONOTUSE0000000000000000";
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
        let _shared_env_guard = crate::platform::test_env::lock();
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
        let _shared_env_guard = crate::platform::test_env::lock();
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
        let _shared_env_guard = crate::platform::test_env::lock();
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
        let _shared_env_guard = crate::platform::test_env::lock();
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
        let _shared_env_guard = crate::platform::test_env::lock();
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

    /// Same query paths, but through a BROKEN parent: the base directory is
    /// replaced by a regular file, so every child open fails with
    /// `ERROR_PATH_NOT_FOUND` — `std` reports `NotFound`. Absence must NOT be
    /// inferred from that: `get` and `list_slots` must Err, never return the
    /// empty view (the slot-vault sibling of native run 41157525966). On unix
    /// the same replacement fails with ENOTDIR, which `read_file` already maps
    /// to an error, so only the Windows target can RED; the native run is the
    /// instrument.
    #[cfg(windows)]
    #[test]
    fn a_parent_replaced_by_a_file_is_not_an_absent_vault() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base");
        // `fast_open` writes the header but does not create the directory
        // (production `open` does); the fixture owns that step.
        std::fs::create_dir_all(&base).unwrap();
        let vault = fast_open(&base);
        vault
            .set(slot(1), &SecretString::from("synthetic-value"))
            .unwrap();
        drop(vault);
        let aside = dir.path().join("base.moved");
        std::fs::rename(&base, &aside).unwrap();
        std::fs::write(&base, b"not a directory").unwrap();
        let vault = FileVault {
            path: base.join(VAULT_FILE_NAME),
            pool_path: base.join("pool-vault-store.json"),
            ..fast_open(&aside)
        };
        assert!(
            matches!(
                vault.get(slot(1)),
                Err(SecretError::BackendUnavailable { .. })
            ),
            "get through a broken parent must refuse, not report NotFound"
        );
        assert!(
            matches!(
                vault.list_slots(GEMINI),
                Err(SecretError::BackendUnavailable { .. })
            ),
            "list_slots through a broken parent must refuse, not report an empty store"
        );
    }

    /// R2 NEW-6: the parent is swapped for a DIFFERENT directory between the
    /// child lookup and the re-check, so the child `NotFound` was produced by a
    /// path that no longer leads to the checked store. Absence must refuse.
    #[test]
    fn absence_recheck_refuses_a_parent_swapped_between_lookups() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base");
        std::fs::create_dir(&base).unwrap();
        let replacement = dir.path().join("replacement");
        std::fs::create_dir(&replacement).unwrap();
        let aside = dir.path().join("base.moved");
        let target = base.join("pool-vault-store.json");
        let result = with_absence_recheck_hook(
            move |parent| {
                std::fs::rename(parent, &aside).unwrap();
                std::fs::rename(&replacement, parent).unwrap();
            },
            || vault_file_absent(&target),
        );
        assert!(
            matches!(result, Err(SecretError::BackendUnavailable { .. })),
            "a parent swapped between the lookups must refuse absence: {result:?}"
        );
    }

    /// Control: with the parent unchanged, a missing child under a real
    /// directory is determinately absent.
    #[test]
    fn absence_recheck_confirms_absence_under_an_unchanged_parent() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base");
        std::fs::create_dir(&base).unwrap();
        assert!(vault_file_absent(&base.join("pool-vault-store.json")).unwrap());
    }

    /// R2 N3: a dangling symlink at `vault.json` must never be read as "first
    /// use". Minting a new salt there would create the link target and rewrite
    /// the header — permanent credential loss.
    #[cfg(unix)]
    #[test]
    fn open_refuses_a_dangling_vault_symlink() {
        let _shared_env_guard = crate::platform::test_env::lock();
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::capture();
        std::env::remove_var(ENV_PASSPHRASE);
        let pass_dir = TempDir::new().unwrap();
        let pass_path = pass_dir.path().join("pass.txt");
        std::fs::write(&pass_path, "synthetic-passphrase\n").unwrap();
        std::env::set_var(ENV_PASSPHRASE_FILE, &pass_path);

        let vault_dir = TempDir::new().unwrap();
        let link = vault_dir.path().join(VAULT_FILE_NAME);
        let missing = vault_dir.path().join("missing-target.json");
        std::os::unix::fs::symlink(&missing, &link).unwrap();
        let result = FileVault::open(vault_dir.path());
        assert!(
            matches!(result, Err(SecretError::Io { .. })),
            "a dangling vault symlink must refuse first use: {result:?}"
        );
        assert!(
            std::fs::symlink_metadata(&missing).is_err(),
            "the refused open must not create the symlink target"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink must be untouched"
        );
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
