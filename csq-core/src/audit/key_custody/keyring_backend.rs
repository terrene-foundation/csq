//! `LocalSigningKey` — Ed25519 signing key backed by the OS keychain via
//! the `keyring` crate (M04 PRIMARY METHODOLOGICAL DIRECTIVE).
//!
//! # Storage layout — M-hardening co-located payload
//!
//! - Service name: `csq-audit-signing` (production) or
//!   `csq-audit-signing-test-<pid>` (test isolation, set by caller).
//! - Account: the `chain_id` string from `chain.json`.
//! - Payload: JSON `{"seed_hex":"<64hex>","signing_active_since_seq":<u64>,
//!   "signing_key_id":"<KeyId string>"}` (new format after M-hardening), OR
//!   bare 64-hex string (legacy format from before M-hardening).
//!
//! ## Why co-location closes the attack
//!
//! Storing the signing cutoff INSIDE the same keychain entry as the private
//! seed means cutoff and key SHARE FATE: a same-UID attacker who deletes the
//! entry destroys the key, causing `verify_chain` to fail closed with
//! `LedgerError::KeyNotFound` for any record that references that key.
//! There is no separate anchor item to target — the only deletion that can
//! silence the cutoff is the deletion that also silences the key.
//!
//! A separate `{chain_id}#anchor` item (the Round-1 design) could be deleted
//! without touching the key; the verifier would then TOFU-backfill the anchor
//! from attacker-writable `chain.json`, laundering the forged cutoff into the
//! authoritative keychain.  Co-location eliminates that path entirely.
//!
//! # Zeroize
//!
//! The seed bytes are held in `Zeroizing<[u8; 32]>` — the 32-byte scalar is
//! explicitly zeroed on drop via `Zeroizing<T>`.  The live `DalekSigningKey`
//! additionally carries `ZeroizeOnDrop` (ed25519-dalek v2), so both the
//! expanded key material and the raw seed are zeroed before the allocation is
//! released.
//!
//! This satisfies the M04 PRIMARY METHODOLOGICAL DIRECTIVE:
//!   "The private key MUST be wrapped in `Zeroizing<T>`."
//!
//! # Seed-hex zeroize discipline (F3, M-hardening R2)
//!
//! The 64-char hex representation of the Ed25519 seed is private-key material.
//! Three sites handle it:
//!
//! 1. **`generate_and_store`** (write): the JSON string passed to `set_password`
//!    is wrapped in `Zeroizing<String>` and zeroed before the function returns.
//!    `SeedEntryPayload` is not `Debug`, preventing accidental hex exposure in
//!    log output.
//!
//! 2. **`load_from_str`** (key load): the payload is deserialized only when the
//!    full seed is needed.  `payload.seed_hex` is explicitly zeroized immediately
//!    after `hex::decode` copies it into a `Zeroizing<Vec<u8>>`.
//!
//! 3. **`load_embedded_cutoff`** (cutoff-only load): deliberately does NOT
//!    deserialize into `SeedEntryPayload` to avoid allocating `seed_hex` at all.
//!    It parses via `serde_json::Value` and extracts only the two non-secret
//!    fields, keeping the `Zeroizing<String>` raw payload as the sole
//!    seed-bearing allocation (zeroed on drop by `Zeroizing`).
//!
//! # `keyring` crate only
//!
//! `security-framework`, `secret-service`, and `windows-rs` are BLOCKED
//! in this file. All keychain I/O goes through `keyring::Entry`.

use ed25519_dalek::{Signer, SigningKey as DalekSigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::audit::key_custody::KeyCustodyError;
use crate::audit::traits::SigningKey;
use crate::audit::types::{Ed25519PublicKey, Ed25519Signature, KeyId, SigningError};

/// Production keychain service name.
pub const SERVICE_NAME: &str = "csq-audit-signing";

// ---------------------------------------------------------------------------
// Wire format for the seed entry (M-hardening)
// ---------------------------------------------------------------------------

/// The JSON payload stored in the seed keychain entry (new format).
///
/// `#[serde(deny_unknown_fields)]` is enforced (not just documented): future
/// fields MUST bump to a versioned shape rather than silently accumulate.
/// This makes the "no unknown fields" invariant machine-checked, not a
/// docstring promise.
///
/// `SeedEntryPayload` intentionally has NO `#[derive(Debug)]` — the
/// `seed_hex` field is private-key material and must never appear in log
/// output.  Manual `Debug` is not provided; code that needs to log the
/// entry should log only `signing_key_id`.
///
/// # Seed-hex zeroize on drop
///
/// `seed_hex` is a plain `String` field. Callers MUST call
/// `payload.seed_hex.zeroize()` immediately after extracting the bytes
/// (see `load_from_str`).  The `Zeroizing<String>` wrapper is not used
/// here because serde does not derive `Deserialize` for `Zeroizing<String>`;
/// the explicit `.zeroize()` call is the documented contract instead.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SeedEntryPayload {
    /// Raw 32-byte Ed25519 seed as lowercase hex (64 chars).
    /// SECRET — callers must `.zeroize()` this field after use.
    seed_hex: String,
    /// The first chain `seq` at which signature verification is mandatory.
    /// Matches `chain.json::signing_active_since_seq` at write time.
    /// Authoritative for the verifier; `chain.json`'s field is advisory.
    signing_active_since_seq: u64,
    /// The `KeyId` of the signing key bound to this cutoff.
    /// Used by `verify_chain` to detect `chain.json` tampering.
    signing_key_id: String,
    /// Keychain-anchored copy of `chain.json::roster_version_floor` (an internal ticket
    /// item 2). Additive-optional: entries written before this field exist
    /// parse as `None` (`serde(default)`), and the field is omitted when
    /// `None` so pre-an internal ticket binaries' `deny_unknown_fields` readers are only
    /// affected AFTER a roster install writes the floor (documented rollback
    /// caveat in spec 12 §12.16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    roster_version_floor: Option<u64>,
}

/// Embedded cutoff returned by `load_embedded_cutoff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedCutoff {
    /// The authoritative signing cutoff stored inside the seed entry.
    pub signing_active_since_seq: u64,
    /// The `KeyId` the entry records as the bound key.
    pub signing_key_id: String,
    /// The `roster_version_floor` baked into the keychain entry, if any.
    /// Pre-existing keychain entries (written before this field was added)
    /// return `None` here — the detector treats `None` as `Unconfirmed`.
    /// Written by the roster-install WRITE path (best-effort, non-fatal).
    pub roster_version_floor: Option<u64>,
}

// ---------------------------------------------------------------------------
// LocalSigningKey
// ---------------------------------------------------------------------------

/// A signing key whose private bytes live in the OS keychain.
///
/// The raw 32-byte seed is held in `Zeroizing<[u8; 32]>` — the
/// `Zeroizing<T>` wrapper explicitly zeroes the bytes on drop.
/// The `DalekSigningKey` additionally implements `ZeroizeOnDrop`
/// (ed25519-dalek v2), providing a second zeroing layer for the
/// expanded scalar.
///
/// No private-key bytes are returned or logged per `rules/security.md §2`.
///
/// `Debug` is implemented manually to redact all private-key material — only
/// the public `key_id` is shown.
pub struct LocalSigningKey {
    /// Stable fingerprint: `ed25519:<sha256_of_raw_32_byte_pubkey_hex>`.
    key_id: KeyId,
    /// The corresponding public key (32 bytes).
    pubkey: Ed25519PublicKey,
    /// Live dalek signing key — zeroed on drop via `ZeroizeOnDrop`
    /// (ed25519-dalek v2). The expanded 32-byte secret scalar is held
    /// inside `inner` and is the single source of truth for private-key
    /// material.
    inner: DalekSigningKey,
}

/// Manual `Debug` impl — shows only the public `key_id`; all private-key
/// bytes (`inner`) are redacted to avoid leaking key material into
/// debug output per `rules/security.md §2`.
impl std::fmt::Debug for LocalSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSigningKey")
            .field("key_id", &self.key_id)
            .field("pubkey", &self.pubkey)
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

impl LocalSigningKey {
    /// Generate a fresh Ed25519 keypair, store the private key in the keychain
    /// under `service` / `account` in the NEW JSON payload format (with
    /// embedded cutoff), and return the key handle.
    ///
    /// `signing_active_since_seq` is the cutoff written into the payload —
    /// it MUST match `chain.json::signing_active_since_seq` at the call site
    /// so the two sources remain consistent (cross-check in `verify_chain`).
    ///
    /// # Zeroize discipline (F3)
    ///
    /// - `seed` and `hex_seed` are `Zeroizing<T>` and zeroed on drop.
    /// - The JSON string passed to `set_password` contains `seed_hex`; it is
    ///   wrapped in `Zeroizing<String>` and zeroed before the function returns.
    pub fn generate_and_store(
        service: &str,
        account: &str,
        signing_active_since_seq: u64,
    ) -> Result<Self, KeyCustodyError> {
        // Compose the two halves: generate the keypair in memory, then persist
        // it. Splitting these lets key-rotation collect a multi-sig authorization
        // over the rotation intent (which names the incoming key's identity)
        // BEFORE any destructive keychain mutation — see `generate_keypair`.
        let (seed, _key_id, _pubkey) = Self::generate_keypair()?;
        // Fresh keys never carry a roster floor — `csq audit roster install`
        // anchors it later (and rotation threads it via `store_dual`).
        Self::store_generated(service, account, &seed, signing_active_since_seq, None)
    }

    /// Generate a fresh Ed25519 keypair IN MEMORY, returning the zeroizing seed
    /// plus the derived identity (`KeyId` + public key). Does NOT touch the
    /// keychain.
    ///
    /// # Why the split exists (M11)
    ///
    /// Key-rotation must collect a multi-sig authorization over the rotation
    /// intent — and that intent names the INCOMING key's `key_id` + pubkey, so
    /// the incoming identity has to exist before authorization. Generating it in
    /// memory lets `rotate.rs` build the intent and authorize it BEFORE calling
    /// [`Self::store_generated`] (and before `preserve_outgoing_key` archives the
    /// outgoing key). An authorization failure therefore leaves the keychain
    /// completely untouched — there is no partially-rotated head slot to repair.
    ///
    /// # Zeroize discipline
    ///
    /// The returned seed is `Zeroizing<[u8; 32]>` and is zeroed on drop. The
    /// caller MUST hand it to `store_generated` (which re-derives the identity)
    /// rather than serialising it itself.
    pub(crate) fn generate_keypair(
    ) -> Result<(Zeroizing<[u8; 32]>, KeyId, Ed25519PublicKey), KeyCustodyError> {
        // H-9: Initialise the seed directly as Zeroizing<[u8; 32]> so no
        // intermediate [u8; 32] stack slot exists outside the Zeroizing wrapper.
        let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *seed)
            .map_err(|e| KeyCustodyError::KeyCorrupt(format!("getrandom: {e}")))?;

        let inner = DalekSigningKey::from_bytes(&seed);
        let pubkey_bytes = inner.verifying_key().to_bytes();
        let key_id = derive_key_id(&pubkey_bytes)?;
        Ok((seed, key_id, Ed25519PublicKey(pubkey_bytes)))
    }

    /// Persist a [`Self::generate_keypair`]-produced `seed` under `service` /
    /// `account` in the NEW JSON payload format (with embedded cutoff), and
    /// return the key handle. The identity is re-derived from the seed so the
    /// returned [`LocalSigningKey`] is self-consistent.
    ///
    /// `signing_active_since_seq` is the cutoff written into the payload — it
    /// MUST match `chain.json::signing_active_since_seq` at the call site so the
    /// two sources remain consistent (cross-check in `verify_chain`).
    ///
    /// # Zeroize discipline (F3)
    ///
    /// - `hex_seed` is `Zeroizing<String>` and zeroed on drop.
    /// - The JSON string passed to `set_password` contains `seed_hex`; it is
    ///   wrapped in `Zeroizing<String>` and zeroed before the function returns.
    pub(crate) fn store_generated(
        service: &str,
        account: &str,
        seed: &Zeroizing<[u8; 32]>,
        signing_active_since_seq: u64,
        roster_version_floor: Option<u64>,
    ) -> Result<Self, KeyCustodyError> {
        let (key, json) =
            Self::derive_and_serialize(seed, signing_active_since_seq, roster_version_floor)?;

        // Persist to keychain — service must not be the blocked native crates.
        // H-13: `?` leverages `#[from] keyring::Error` on `KeyCustodyError::Keychain`.
        let entry = crate::audit::key_custody::keyring_entry(service, account)?;
        entry.set_password(&json)?;
        // json (Zeroizing<String>) zeroed on drop here.

        Ok(key)
    }

    /// Derive the key identity from `seed` and serialize the co-located seed
    /// payload (`{seed_hex, signing_active_since_seq, signing_key_id}`) WITHOUT
    /// any I/O. Returns the live key handle plus the JSON payload string wrapped
    /// in `Zeroizing<String>` (zeroed on drop) so the caller can persist the
    /// SAME bytes to BOTH the file store and the OS keychain (`store_dual`).
    ///
    /// # Zeroize discipline (F3)
    /// - `hex_seed` is `Zeroizing<String>` and zeroed on drop.
    /// - The returned `json` is `Zeroizing<String>`; the caller MUST not clone
    ///   it into a non-zeroizing allocation.
    pub(crate) fn derive_and_serialize(
        seed: &Zeroizing<[u8; 32]>,
        signing_active_since_seq: u64,
        roster_version_floor: Option<u64>,
    ) -> Result<(Self, Zeroizing<String>), KeyCustodyError> {
        let inner = DalekSigningKey::from_bytes(seed);
        let verifying = inner.verifying_key();
        let pubkey_bytes = verifying.to_bytes();
        let key_id = derive_key_id(&pubkey_bytes)?;

        // H-8: hex_seed wrapped in Zeroizing<String> so the hex representation
        // of the seed is zeroed on drop.
        let hex_seed: Zeroizing<String> = Zeroizing::new(hex::encode(**seed));

        let payload = SeedEntryPayload {
            seed_hex: hex_seed.as_str().to_string(),
            signing_active_since_seq,
            signing_key_id: key_id.as_str().to_string(),
            roster_version_floor,
        };
        // hex_seed (Zeroizing<String>) is zeroed on drop here.

        // F3: wrap the serialized JSON in Zeroizing<String> so seed_hex bytes
        // in the serialized form are zeroed before the value is dropped.
        let json: Zeroizing<String> =
            Zeroizing::new(serde_json::to_string(&payload).map_err(|e| {
                KeyCustodyError::KeyCorrupt(format!("serialize seed payload: {e}"))
            })?);

        Ok((
            Self {
                key_id,
                pubkey: Ed25519PublicKey(pubkey_bytes),
                inner,
            },
            json,
        ))
    }

    /// Load an existing private key from the keychain.
    ///
    /// Accepts BOTH payload formats:
    /// - **New (JSON)**: `{"seed_hex":"...","signing_active_since_seq":N,"signing_key_id":"..."}`
    /// - **Legacy (bare hex)**: a 64-char lowercase hex string (the M04 format before
    ///   M-hardening added the embedded cutoff).
    ///
    /// Returns `Err(KeyCustodyError::Keychain(NoEntry))` when the entry is absent.
    pub fn load_from_keychain(service: &str, account: &str) -> Result<Self, KeyCustodyError> {
        // H-13: `?` leverages `#[from] keyring::Error` on `KeyCustodyError::Keychain`.
        let entry = crate::audit::key_custody::keyring_entry(service, account)?;
        // H-6: Wrap the retrieved string in Zeroizing<String> so the bytes
        // are zeroed on drop.
        let raw: Zeroizing<String> = Zeroizing::new(entry.get_password()?);

        Self::load_from_str(raw.as_str())
    }

    /// Parse a key from a raw payload string (new JSON or legacy bare-hex).
    ///
    /// Used internally by `load_from_keychain` and in tests for the
    /// locked-keychain injection path.
    ///
    /// # Zeroize discipline (F3)
    ///
    /// When parsing new JSON format, `payload.seed_hex` (a plain `String`) is
    /// explicitly zeroized immediately after the bytes are copied into a
    /// `Zeroizing<Vec<u8>>`.  This closes the window where the 64-char hex
    /// lives on the heap as a non-zeroed allocation after `hex::decode`.
    pub(crate) fn load_from_str(raw: &str) -> Result<Self, KeyCustodyError> {
        let seed_bytes: Zeroizing<Vec<u8>> = if raw.starts_with('{') {
            // New JSON format — deserialize into SeedEntryPayload to get seed_hex.
            let mut payload: SeedEntryPayload = serde_json::from_str(raw).map_err(|_| {
                KeyCustodyError::KeyCorrupt("seed entry JSON could not be parsed".to_string())
            })?;
            // F3: decode seed_hex into a Zeroizing allocation, then immediately
            // zeroize the plain-String heap copy before it falls off the stack.
            let decoded = Zeroizing::new(
                hex::decode(&payload.seed_hex)
                    .map_err(|e| KeyCustodyError::KeyCorrupt(format!("seed hex decode: {e}")))?,
            );
            // Zeroize the plain-String field before the struct is dropped.
            payload.seed_hex.zeroize();
            decoded
        } else {
            // Legacy bare-hex format.
            Zeroizing::new(
                hex::decode(raw)
                    .map_err(|e| KeyCustodyError::KeyCorrupt(format!("hex decode: {e}")))?,
            )
        };

        if seed_bytes.len() != 32 {
            return Err(KeyCustodyError::KeyCorrupt(format!(
                "expected 32 bytes, got {}",
                seed_bytes.len()
            )));
        }
        let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&seed_bytes);
        let inner = DalekSigningKey::from_bytes(&seed);
        let verifying = inner.verifying_key();
        let pubkey_bytes = verifying.to_bytes();
        let key_id = derive_key_id(&pubkey_bytes)?;

        Ok(Self {
            key_id,
            pubkey: Ed25519PublicKey(pubkey_bytes),
            inner,
        })
    }

    /// Returns `true` when the keychain already holds an entry under
    /// `service` / `account`. Does not load or verify the key bytes.
    pub fn exists_in_keychain(service: &str, account: &str) -> bool {
        let Ok(entry) = crate::audit::key_custody::keyring_entry(service, account) else {
            return false;
        };
        entry.get_password().is_ok()
    }

    /// Delete the keychain entry for `service` / `account`.
    ///
    /// Called in production for atomicity rollback (H-5): when key rotation
    /// or init fails after a keychain write, this cleans up the orphaned entry.
    /// Also used in tests to clean up sandboxed entries.
    pub fn delete_from_keychain(service: &str, account: &str) -> Result<(), KeyCustodyError> {
        // H-13: `?` leverages `#[from] keyring::Error` on `KeyCustodyError::Keychain`.
        let entry = crate::audit::key_custody::keyring_entry(service, account)?;
        entry.delete_credential()?;
        Ok(())
    }
}

/// Try to extract the embedded cutoff from the keychain seed entry.
///
/// Returns:
/// - `Ok(Some(cutoff))` — new JSON format, cutoff present.
/// - `Ok(None)` — legacy bare-hex format, no embedded cutoff.
/// - `Err(KeyCustodyError::Keychain(NoEntry))` — entry absent.
/// - `Err(other)` — keychain access error or corrupt payload.
///
/// # Zeroize discipline (F3)
///
/// This function deliberately does NOT deserialize into `SeedEntryPayload`.
/// Doing so would copy `seed_hex` (64 chars of private-key hex) into a plain
/// heap `String` field for the sole purpose of discarding it.  Instead, the
/// raw `Zeroizing<String>` from the keychain is parsed via
/// `serde_json::Value`, which never allocates a named `seed_hex` field — the
/// bytes for that key still exist transiently inside serde's parse buffer but
/// are not promoted to a typed, long-lived allocation the caller can observe.
/// The `Zeroizing<String>` `raw` binding is the only seed-bearing heap
/// allocation, and it is zeroed on drop at the end of this function.
pub fn load_embedded_cutoff(
    service: &str,
    account: &str,
) -> Result<Option<EmbeddedCutoff>, KeyCustodyError> {
    let entry = crate::audit::key_custody::keyring_entry(service, account)?;
    // H-6: zero the raw payload string on drop.
    let raw: Zeroizing<String> = Zeroizing::new(entry.get_password()?);
    // F3: parse via serde_json::Value (inside parse_embedded_cutoff) instead of
    // SeedEntryPayload to avoid materialising seed_hex into a named struct field.
    // raw (Zeroizing<String>) is zeroed on drop here once parsing completes.
    parse_embedded_cutoff(raw.as_str())
}

/// Returns `true` when the `keyring::Error` represents a transiently
/// inaccessible keychain (locked at boot or permission denied) where the
/// entry EXISTS but cannot be read right now.
///
/// # ALLOWLIST — deliberately `#[non_exhaustive]`-safe
///
/// This function uses an ALLOWLIST (`NoStorageAccess | PlatformFailure`)
/// rather than a denylist.  The rationale:
///
/// - `NoStorageAccess`: keychain storage not available (macOS
///   `errSecNotAvailable`, Linux secret-service not running).
/// - `PlatformFailure`: OS-level error that may be transient, including
///   macOS `errSecInteractionNotAllowed` (keychain locked at boot before
///   first user unlock).
///
/// All other variants — including `BadEncoding`, `TooLong`, `Invalid`,
/// `Ambiguous`, `NoEntry`, and any FUTURE variants added by `keyring`
/// (`#[non_exhaustive]`) — are treated as FAIL-CLOSED.  `BadEncoding` or
/// `Ambiguous` entries indicate a corrupt or planted replacement entry,
/// not a transient lock; routing them to chain.json-trust would re-enable
/// the downgrade attack on platforms where the attacker can plant a
/// duplicate/non-UTF-8 keychain item.  Unknown future variants default to
/// fail-closed for the same reason: an allowlist makes unknown variants safe
/// by default.
pub fn is_keychain_access_error(e: &keyring::Error) -> bool {
    matches!(
        e,
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_)
    )
}

/// File-store leg of the roster-floor write: typed read-modify-write of the
/// active seed file (same SeedEntryPayload shape as the keychain entry).
/// Best-effort — absence, legacy bare-hex, or I/O failure logs a fixed-tag
/// warning and returns; the chain.json floor remains authoritative.
fn write_roster_floor_to_file_store(base_dir: &std::path::Path, chain_id: &str, floor: u64) {
    use zeroize::Zeroize;
    let raw = match crate::audit::key_custody::file_store::load_payload(
        base_dir,
        chain_id,
        KeySlot::Active,
    ) {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_skipped",
                chain_id = %chain_id,
                "write_roster_floor_to_file_store: no seed file (keychain-only install) \
                 — file-store floor write skipped"
            );
            return;
        }
        Err(_) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_failed",
                chain_id = %chain_id,
                "write_roster_floor_to_file_store: seed file unreadable — floor write skipped"
            );
            return;
        }
    };
    let mut payload: SeedEntryPayload = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_skipped",
                chain_id = %chain_id,
                "write_roster_floor_to_file_store: seed file is not a JSON seed payload \
                 (legacy bare-hex) — floor write skipped"
            );
            return;
        }
    };
    payload.roster_version_floor = Some(floor);
    let new_json: Zeroizing<String> = match serde_json::to_string(&payload) {
        Ok(j) => Zeroizing::new(j),
        Err(_) => {
            payload.seed_hex.zeroize();
            return;
        }
    };
    payload.seed_hex.zeroize();
    if let Err(e) = crate::audit::key_custody::file_store::store_payload(
        base_dir,
        chain_id,
        KeySlot::Active,
        &new_json,
    ) {
        tracing::warn!(
            error_kind = "audit_roster_floor_anchor_write_failed",
            chain_id = %chain_id,
            "write_roster_floor_to_file_store: seed file write failed ({e})"
        );
    }
}

/// Patch the `roster_version_floor` field in the keychain entry for the active
/// signing key slot. This is a BEST-EFFORT, NON-FATAL write: every failure mode
/// logs a `tracing::warn!` with a fixed-vocabulary `error_kind` tag and returns
/// without propagating the error.
///
/// Design constraints:
/// - MUST NOT use `SeedEntryPayload` (it has `#[serde(deny_unknown_fields)]`).
///   Reads and writes via `serde_json::Value` so the new field is additive and
///   older binaries reading the same entry silently ignore it.
/// - MUST stay inside the chain lock at the call site (roster install holds
///   `_chain_lock` across this call).
/// - Called after `chain.json` is successfully saved — if the keychain is
///   unavailable the floor is still durable in `chain.json`; the keychain
///   anchor is additional tamper-DETECTION, never the sole anchor.
pub fn write_roster_floor_to_keychain(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    floor: u64,
) {
    // FILE-store copy first (the daemon-readable primary; rotation's
    // load_raw_payload reads file-FIRST, so a keychain-only patch would be
    // dropped at the next rotation). Best-effort, same posture as the
    // keychain leg below.
    write_roster_floor_to_file_store(base_dir, chain_id, floor);

    let account = KeySlot::Active.keychain_account(chain_id);
    // Obtain the keyring entry handle. KeyCustodyError (not keyring::Error) at
    // this stage because `keyring_entry` wraps creation errors.
    let entry = match crate::audit::key_custody::keyring_entry(service, &account) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_deferred",
                chain_id = %chain_id,
                "write_roster_floor_to_keychain: keyring entry unavailable ({e}) \
                 — floor write deferred"
            );
            return;
        }
    };
    // Read the existing payload.
    let raw = match entry.get_password() {
        Ok(s) => s,
        Err(ref e) if is_keychain_access_error(e) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_deferred",
                chain_id = %chain_id,
                "write_roster_floor_to_keychain: keychain locked/inaccessible \
                 — floor write deferred"
            );
            return;
        }
        Err(keyring::Error::NoEntry) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_deferred",
                chain_id = %chain_id,
                "write_roster_floor_to_keychain: no keychain entry (file-only install) \
                 — floor write skipped"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_failed",
                chain_id = %chain_id,
                "write_roster_floor_to_keychain: keychain read failed ({e}) \
                 — floor write skipped"
            );
            return;
        }
    };
    // Typed read-modify-write: parse the entry as the seed payload, set the
    // field, re-serialise. Refusing to patch anything that is not a seed
    // payload (legacy bare-hex, foreign JSON) keeps this writer from
    // corrupting unknown entries AND keeps the entry parseable by the typed
    // `load_from_str` key-load path (`deny_unknown_fields`).
    use zeroize::Zeroize;
    let mut raw = raw;
    let mut payload: SeedEntryPayload = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(_) => {
            raw.zeroize();
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_skipped",
                chain_id = %chain_id,
                "write_roster_floor_to_keychain: keychain entry is not a JSON \
                 seed payload (legacy bare-hex or foreign) — floor write skipped; \
                 detector reports unconfirmed until `csq audit init` upgrades the entry"
            );
            return;
        }
    };
    raw.zeroize();
    payload.roster_version_floor = Some(floor);
    let new_json: Zeroizing<String> = match serde_json::to_string(&payload) {
        Ok(s) => Zeroizing::new(s),
        Err(_) => {
            payload.seed_hex.zeroize();
            return;
        }
    };
    payload.seed_hex.zeroize();
    match entry.set_password(&new_json) {
        Ok(()) => {}
        Err(ref e) if is_keychain_access_error(e) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_deferred",
                chain_id = %chain_id,
                "write_roster_floor_to_keychain: keychain locked on write \
                 — floor write deferred"
            );
        }
        Err(e) => {
            tracing::warn!(
                error_kind = "audit_roster_floor_anchor_write_failed",
                chain_id = %chain_id,
                "write_roster_floor_to_keychain: keychain write failed ({e})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// File-first custody facade (TIER B)
// ---------------------------------------------------------------------------

use crate::audit::key_custody::file_store::{self, KeySlot};

/// Outcome of attempting to load a signing key, distinguishing genuine
/// ABSENCE from transient INACCESSIBILITY — the load-bearing distinction that
/// the pre-fix `Err(_) => continue` swallow collapsed (the daemon brick).
#[derive(Debug)]
pub enum KeyLoadOutcome {
    /// The key was loaded (from the file store, or the keychain fallback).
    /// Boxed because `LocalSigningKey` is far larger than the other (unit /
    /// small-string) variants (`clippy::large_enum_variant`).
    Loaded(Box<LocalSigningKey>),
    /// The key is genuinely absent from BOTH the file store AND the keychain
    /// (`NoEntry` / file not found). Fatal for a CURRENT active key
    /// (`KeyNotFound`); a degrade candidate for a HISTORICAL key.
    Absent,
    /// The key may exist but could not be read right now: the file store had no
    /// copy AND the keychain returned an access error
    /// (`is_keychain_access_error` — locked / per-app-ACL prompt a
    /// non-interactive process cannot answer). TRANSIENT — route to
    /// `AuditHealth::Unknown` / `LedgerError::KeychainUnavailable`, NEVER to a
    /// durable Broken/sentinel state.
    Inaccessible,
    /// A copy was present (file or keychain) but could not be parsed, or the
    /// keychain entry is corrupt/planted (`BadEncoding`/`Ambiguous`/...).
    /// Fail-closed: a present-but-unreadable seed is a tamper signal, not a
    /// transient lock.
    Corrupt(String),
}

/// Load a signing key for `(chain_id, slot)`: **file store FIRST** (always
/// daemon-readable), **OS keychain FALLBACK** (migration source for installs
/// whose keys predate the file store).
///
/// This is the single primitive every read site (verify, sign, doctor, export)
/// MUST use instead of a bare `load_from_keychain`, because it classifies
/// access-vs-absence. It performs NO writes (the verifier's read-only invariant
/// — migration is an explicit operation, see [`super::migrate`]).
pub fn try_load_signing_key(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
) -> KeyLoadOutcome {
    // 1. File store (primary).
    match file_store::load_payload(base_dir, chain_id, slot) {
        Ok(Some(raw)) => {
            return match LocalSigningKey::load_from_str(raw.as_str()) {
                Ok(k) => KeyLoadOutcome::Loaded(Box::new(k)),
                Err(e) => KeyLoadOutcome::Corrupt(format!("file seed unparseable: {e}")),
            };
        }
        Ok(None) => { /* file absent — fall through to keychain fallback */ }
        Err(e) => {
            // A real file I/O error (permission denied, not-a-file) — distinct
            // from absence. Fail-closed: do not silently treat as absent.
            return KeyLoadOutcome::Corrupt(format!("file seed read error: {e}"));
        }
    }

    // 2. Keychain fallback (pre-migration installs).
    let account = slot.keychain_account(chain_id);
    match LocalSigningKey::load_from_keychain(service, &account) {
        Ok(k) => KeyLoadOutcome::Loaded(Box::new(k)),
        Err(KeyCustodyError::Keychain(keyring::Error::NoEntry)) => KeyLoadOutcome::Absent,
        Err(KeyCustodyError::Keychain(ref ke)) if is_keychain_access_error(ke) => {
            KeyLoadOutcome::Inaccessible
        }
        Err(e) => KeyLoadOutcome::Corrupt(format!("keychain seed unreadable: {e}")),
    }
}

/// Returns `true` when a seed exists for `(chain_id, slot)` in EITHER the file
/// store or the keychain. Does not load or validate the bytes.
pub fn exists_any(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
) -> bool {
    file_store::exists(base_dir, chain_id, slot)
        || LocalSigningKey::exists_in_keychain(service, &slot.keychain_account(chain_id))
}

/// Persist `(key, json)` to BOTH stores: the **file store (PRIMARY, must
/// succeed)** and the **OS keychain (anchor mirror, best-effort)**.
///
/// The file write is the availability guarantee — if it fails, the whole
/// operation fails (a key the daemon cannot read is useless). The keychain
/// write is the integrity anchor: it is attempted but a failure is NON-fatal
/// and logged, because (a) a non-interactive daemon-triggered write hits the
/// very ACL prompt this whole change exists to route around, and (b) the file
/// is sufficient for availability. A missing anchor degrades forge-resistance
/// to file-only for THIS key until an interactive `csq audit init` / `migrate-
/// keys` establishes it — `csq doctor` surfaces that degraded state. This is
/// the deliberate availability-over-realtime-integrity trade (the chain owner
/// chose "optimistic-sign").
fn persist_dual(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
    key: LocalSigningKey,
    json: &Zeroizing<String>,
) -> Result<LocalSigningKey, KeyCustodyError> {
    // 1. File store — PRIMARY. Failure aborts.
    file_store::store_payload(base_dir, chain_id, slot, json)?;

    // 2. Keychain anchor — best-effort. On a FAILED write the keychain may
    //    still hold a DIFFERENT (stale) key for this slot — e.g. a rotate whose
    //    keychain leg is blocked leaves the OLD key there. A stale entry that
    //    DISAGREES with the file would surface as a (false) anchor `Mismatch` on
    //    the next readable verify. To avoid that false alarm, DELETE the keychain
    //    entry when the write fails, leaving `NoEntry` (anchor `Unconfirmed`,
    //    non-fatal). A same-UID process can delete its own keychain item; if even
    //    the delete is blocked it is harmless (the verify is a non-fatal detector).
    let account = slot.keychain_account(chain_id);
    match crate::audit::key_custody::keyring_entry(service, &account)
        .and_then(|e| e.set_password(json))
    {
        Ok(()) => {}
        Err(ref ke) if is_keychain_access_error(ke) => {
            let _ = LocalSigningKey::delete_from_keychain(service, &account);
            tracing::warn!(
                error_kind = "audit_anchor_write_deferred",
                chain_id = %chain_id,
                "store_dual: keychain anchor write deferred (keychain locked / \
                 access-denied) — file seed written and usable; any stale keychain \
                 entry dropped. Forge-resistance is file-only until `csq audit \
                 migrate-keys` runs interactively to (re)establish the anchor"
            );
        }
        Err(e) => {
            let _ = LocalSigningKey::delete_from_keychain(service, &account);
            tracing::warn!(
                error_kind = "audit_anchor_write_failed",
                chain_id = %chain_id,
                "store_dual: keychain anchor write failed ({e}) — file seed written \
                 and usable; any stale keychain entry dropped"
            );
        }
    }
    Ok(key)
}

/// Generate a fresh keypair and persist it to BOTH stores (file primary +
/// keychain anchor). File-first analog of [`LocalSigningKey::generate_and_store`].
pub fn generate_and_store_dual(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
    signing_active_since_seq: u64,
    roster_version_floor: Option<u64>,
) -> Result<LocalSigningKey, KeyCustodyError> {
    let (seed, _kid, _pk) = LocalSigningKey::generate_keypair()?;
    store_dual(
        base_dir,
        service,
        chain_id,
        slot,
        &seed,
        signing_active_since_seq,
        roster_version_floor,
    )
}

/// Persist a caller-provided `seed` (e.g. rotation's in-memory incoming key) to
/// BOTH stores (file primary + keychain anchor). File-first analog of
/// [`LocalSigningKey::store_generated`].
pub fn store_dual(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
    seed: &Zeroizing<[u8; 32]>,
    signing_active_since_seq: u64,
    roster_version_floor: Option<u64>,
) -> Result<LocalSigningKey, KeyCustodyError> {
    let (key, json) = LocalSigningKey::derive_and_serialize(
        seed,
        signing_active_since_seq,
        roster_version_floor,
    )?;
    persist_dual(base_dir, service, chain_id, slot, key, &json)
}

/// Delete a key from BOTH stores (file + keychain) for `(chain_id, slot)`.
///
/// Used by the H-5 rollback paths in `audit_init` / `rotate_key`, which must
/// undo a freshly-written key on both channels. Both deletes are best-effort
/// (idempotent on absence); the file delete returns its error only if it is a
/// real I/O failure, while the keychain delete is swallowed (a rolled-back
/// keychain anchor that lingers is harmless — the next verify reconciles it).
pub fn delete_dual(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
) -> Result<(), KeyCustodyError> {
    let _ = LocalSigningKey::delete_from_keychain(service, &slot.keychain_account(chain_id));
    file_store::delete(base_dir, chain_id, slot)
}

/// Read the RAW seed payload string for `(chain_id, slot)`: file store FIRST,
/// keychain FALLBACK. Returns the opaque payload bytes (new JSON or legacy
/// bare-hex) wrapped in `Zeroizing<String>` so a rotation/migration can copy
/// the EXACT bytes (cutoff included) to another slot without re-deriving.
///
/// `Ok(None)` only when the seed is absent in BOTH stores. A keychain access
/// error with no file copy surfaces as `Err(Keychain(..))` so the caller can
/// distinguish "blocked" from "absent" (preserve/rotate must not silently treat
/// an inaccessible outgoing key as gone).
pub fn load_raw_payload(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    slot: KeySlot,
) -> Result<Option<Zeroizing<String>>, KeyCustodyError> {
    if let Some(raw) = file_store::load_payload(base_dir, chain_id, slot)? {
        return Ok(Some(raw));
    }
    let account = slot.keychain_account(chain_id);
    let entry = crate::audit::key_custody::keyring_entry(service, &account)?;
    match entry.get_password() {
        Ok(s) => Ok(Some(Zeroizing::new(s))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeyCustodyError::Keychain(e)),
    }
}

/// Copy a seed from `src_slot` to `dst_slot` in BOTH stores, preserving the
/// payload bytes verbatim (cutoff shares fate with the key). File-first analog
/// of `rotate::preserve_outgoing_key`: archives the outgoing key (active →
/// historical) and restores it on rollback (historical → active).
///
/// The file copy is authoritative (must succeed). The keychain copy is
/// best-effort (warn on access error) — a missing keychain archive degrades the
/// historical key's anchor to file-only, surfaced by `csq doctor`, never fatal.
pub fn preserve_dual(
    base_dir: &std::path::Path,
    service: &str,
    chain_id: &str,
    src_slot: KeySlot,
    dst_slot: KeySlot,
) -> Result<(), KeyCustodyError> {
    let raw = load_raw_payload(base_dir, service, chain_id, src_slot)?
        .ok_or(KeyCustodyError::NoKeyToRotate)?;
    // File store — authoritative.
    file_store::store_payload(base_dir, chain_id, dst_slot, &raw)?;
    // Keychain anchor — best-effort. Delete a stale dst entry on a failed write
    // so the keychain never holds a key that DISAGREES with the file archive
    // (which would surface as a false anchor Mismatch). See `persist_dual`.
    let dst_account = dst_slot.keychain_account(chain_id);
    match crate::audit::key_custody::keyring_entry(service, &dst_account)
        .and_then(|e| e.set_password(&raw))
    {
        Ok(()) => {}
        Err(ref ke) if is_keychain_access_error(ke) => {
            let _ = LocalSigningKey::delete_from_keychain(service, &dst_account);
            tracing::warn!(
                error_kind = "audit_anchor_preserve_deferred",
                chain_id = %chain_id,
                "preserve_dual: keychain archive write deferred (locked/access-denied) — \
                 file archive written; stale dst entry dropped; anchor file-only until migrate"
            );
        }
        Err(e) => {
            let _ = LocalSigningKey::delete_from_keychain(service, &dst_account);
            tracing::warn!(
                error_kind = "audit_anchor_preserve_failed",
                chain_id = %chain_id,
                "preserve_dual: keychain archive write failed ({e}) — file archive written; \
                 stale dst entry dropped"
            );
        }
    }
    Ok(())
}

/// Read the co-located signing cutoff from the **file store** active slot
/// (primary). Returns `Ok(None)` when the file is a legacy bare-hex seed (no
/// embedded cutoff) OR when the file is absent — the caller distinguishes via
/// [`file_store::exists`] if needed. The keychain cutoff is read separately
/// (`load_embedded_cutoff`) by `verify_chain` Step-0 for the integrity-anchor
/// cross-check.
pub fn load_embedded_cutoff_file_first(
    base_dir: &std::path::Path,
    chain_id: &str,
) -> Result<Option<EmbeddedCutoff>, KeyCustodyError> {
    let raw = match file_store::load_payload(base_dir, chain_id, KeySlot::Active)? {
        Some(r) => r,
        None => return Ok(None),
    };
    parse_embedded_cutoff(raw.as_str())
}

/// Parse the embedded cutoff out of a raw seed payload string (new JSON format)
/// without materialising `seed_hex` into a typed field. Shared by the keychain
/// and file-store cutoff readers. Returns `Ok(None)` for a legacy bare-hex seed.
pub(crate) fn parse_embedded_cutoff(raw: &str) -> Result<Option<EmbeddedCutoff>, KeyCustodyError> {
    if !raw.starts_with('{') {
        return Ok(None);
    }
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|_| {
        KeyCustodyError::KeyCorrupt("seed entry JSON could not be parsed".to_string())
    })?;
    let seq = v
        .get("signing_active_since_seq")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| {
            KeyCustodyError::KeyCorrupt("seed entry missing signing_active_since_seq".to_string())
        })?;
    let kid = v
        .get("signing_key_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            KeyCustodyError::KeyCorrupt("seed entry missing signing_key_id".to_string())
        })?
        .to_string();
    // Additively read the new optional field. Pre-existing keychain entries that
    // predate this field's introduction will not have the key → returns None.
    // Older binaries reading a new entry via `serde_json::Value` simply ignore it.
    let roster_version_floor = v.get("roster_version_floor").and_then(|x| x.as_u64());
    Ok(Some(EmbeddedCutoff {
        signing_active_since_seq: seq,
        signing_key_id: kid,
        roster_version_floor,
    }))
}

/// Derives a `KeyId` from the raw 32-byte Ed25519 public key.
///
/// Format: `ed25519:<sha256_of_raw_pubkey_lowercase_hex>`.
/// The 64-char hex body is the SHA-256 of the raw 32-byte public key.
pub(crate) fn derive_key_id(pubkey_bytes: &[u8; 32]) -> Result<KeyId, KeyCustodyError> {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    let digest = hasher.finalize();
    let hex_body = hex::encode(digest);
    let full = format!("ed25519:{hex_body}");
    KeyId::try_new(full).map_err(|e| KeyCustodyError::KeyCorrupt(format!("KeyId: {e}")))
}

impl SigningKey for LocalSigningKey {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn public_key(&self) -> Ed25519PublicKey {
        self.pubkey
    }

    fn sign(&self, message: &[u8]) -> Result<Ed25519Signature, SigningError> {
        let sig = self.inner.sign(message);
        Ok(Ed25519Signature(sig.to_bytes()))
    }
}

// Compile-time assertion: LocalSigningKey must be Send + Sync as required by
// SigningKey: Send + Sync. DalekSigningKey is Send + Sync; Zeroizing<T> inherits
// those bounds. The assertion is a dead-code function that the type-checker
// evaluates without runtime cost.
const _: fn() = || {
    fn _is_send_sync<T: Send + Sync>() {}
    _is_send_sync::<LocalSigningKey>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    fn test_service() -> String {
        format!("csq-audit-signing-test-{}", std::process::id())
    }

    /// Named test per M04 acceptance criteria — new JSON format.
    #[test]
    fn test_local_key_init_stores_in_keyring() {
        super::super::test_helpers::init_mock_keyring();
        let svc = test_service();
        let account = "test_local_key_init_stores_in_keyring";

        // Clean up any prior residue.
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);

        let key = LocalSigningKey::generate_and_store(&svc, account, 42)
            .expect("generate_and_store failed");
        assert!(LocalSigningKey::exists_in_keychain(&svc, account));

        // Verify key_id has the correct prefix.
        let kid = key.key_id();
        let kid_str = kid.as_str();
        assert!(
            kid_str.starts_with("ed25519:"),
            "key_id prefix wrong: {kid_str}"
        );
        assert_eq!(kid_str.len(), "ed25519:".len() + 64);

        // The embedded cutoff must match what was passed to generate_and_store.
        let ec = load_embedded_cutoff(&svc, account)
            .expect("load_embedded_cutoff must not error")
            .expect("embedded cutoff must be present");
        assert_eq!(ec.signing_active_since_seq, 42);
        assert_eq!(ec.signing_key_id, kid_str);

        // Cleanup.
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);
    }

    /// M2 T2.4 custody-contract anchor — `generate_and_store_dual` (the
    /// production custody entry point) lands the Ed25519 seed in BOTH stores:
    /// the 0o600 file (PRIMARY, daemon-readable) AND the keychain (best-effort
    /// anchor). Pins the resolved custody model and the rejection of T2.4's
    /// literal "keychain-primary" premise:
    ///
    /// - The seed file is `0o600` — never world/group readable (`never 0o644`),
    ///   satisfying the T2.4 security contract.
    /// - The seed is ALSO anchored in the keychain (dual-store) — but the
    ///   keychain is the ANCHOR, not the primary store. Keychain-primary bricks
    ///   the non-interactive daemon (journals 0033/0034); see an internal journal entry for
    ///   why T2.4 was re-scoped to verify+document rather than make the keychain
    ///   authoritative.
    #[cfg(unix)]
    #[test]
    fn t2_4_generate_and_store_dual_writes_both_stores_file_is_0o600() {
        use std::os::unix::fs::PermissionsExt;
        super::super::test_helpers::init_mock_keyring();
        let base = tempfile::TempDir::new().expect("tempdir");
        let svc = test_service();
        let chain_id = "T2_4_CUSTODY_CONTRACT_CHAIN";
        let slot = super::super::file_store::KeySlot::Active;
        let account = slot.keychain_account(chain_id);
        let _ = LocalSigningKey::delete_from_keychain(&svc, &account);

        let key = generate_and_store_dual(base.path(), &svc, chain_id, slot, 0, None)
            .expect("generate_and_store_dual must succeed");

        // (1) File store — PRIMARY: seed present and daemon-readable.
        assert!(
            super::super::file_store::exists(base.path(), chain_id, slot),
            "seed must be in the file store (primary, daemon-readable channel)"
        );

        // (2) File is 0o600 — never world/group readable. THE T2.4 security contract.
        let path = super::super::file_store::seed_file_path(base.path(), chain_id, slot);
        let mode = std::fs::metadata(&path)
            .expect("seed file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "seed file must be 0o600 (never 0o644), got {mode:o}"
        );

        // (3) Keychain — best-effort ANCHOR (not primary): also holds the seed,
        //     and both stores agree on the key identity.
        assert!(
            LocalSigningKey::exists_in_keychain(&svc, &account),
            "seed must ALSO be anchored in the keychain (dual-store)"
        );
        let from_keychain =
            LocalSigningKey::load_from_keychain(&svc, &account).expect("keychain load");
        assert_eq!(
            key.key_id().as_str(),
            from_keychain.key_id().as_str(),
            "both stores must hold the same key identity"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, &account);
    }

    /// Named test — sign/verify round-trip.
    #[test]
    fn test_signing_key_sign_verify_roundtrip() {
        super::super::test_helpers::init_mock_keyring();
        let svc = test_service();
        let account = "test_signing_key_sign_verify_roundtrip";
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);

        let key = LocalSigningKey::generate_and_store(&svc, account, 0)
            .expect("generate_and_store failed");

        let msg = b"hello world";
        let sig = key.sign(msg).expect("sign failed");
        let pubkey = key.public_key();

        // Verify using dalek directly.
        let verifying = VerifyingKey::from_bytes(&pubkey.0).expect("bad pubkey bytes");
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        verifying
            .verify_strict(msg, &dalek_sig)
            .expect("signature verification failed");

        let _ = LocalSigningKey::delete_from_keychain(&svc, account);
    }

    #[test]
    fn test_exists_false_when_absent() {
        super::super::test_helpers::init_mock_keyring();
        let svc = test_service();
        let account = "test_exists_false_when_absent_sentinel";
        // Ensure clean.
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);
        assert!(!LocalSigningKey::exists_in_keychain(&svc, account));
    }

    #[test]
    fn test_load_from_keychain_roundtrip() {
        super::super::test_helpers::init_mock_keyring();
        let svc = test_service();
        let account = "test_load_from_keychain_roundtrip";
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);

        let k1 = LocalSigningKey::generate_and_store(&svc, account, 7).expect("generate failed");
        let k2 = LocalSigningKey::load_from_keychain(&svc, account).expect("load failed");

        assert_eq!(k1.key_id().as_str(), k2.key_id().as_str());
        assert_eq!(k1.public_key().0, k2.public_key().0);

        let _ = LocalSigningKey::delete_from_keychain(&svc, account);
    }

    /// Legacy bare-hex format must still load correctly.
    #[test]
    fn test_load_from_keychain_legacy_bare_hex() {
        super::super::test_helpers::init_mock_keyring();
        let svc = test_service();
        let account = "test_load_legacy_bare_hex";
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);

        // Write a legacy bare-hex seed entry directly.
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).expect("getrandom");
        let bare_hex = hex::encode(seed_bytes);
        let entry = crate::audit::key_custody::keyring_entry(&svc, account).expect("entry");
        entry.set_password(&bare_hex).expect("set_password");

        // Must load correctly.
        let key = LocalSigningKey::load_from_keychain(&svc, account)
            .expect("load legacy bare-hex must succeed");
        assert!(key.key_id().as_str().starts_with("ed25519:"));

        // load_embedded_cutoff must return None for legacy format.
        let ec = load_embedded_cutoff(&svc, account).expect("no error");
        assert!(
            ec.is_none(),
            "legacy bare-hex must return None for embedded cutoff"
        );

        let _ = LocalSigningKey::delete_from_keychain(&svc, account);
    }

    /// `load_embedded_cutoff` on absent entry returns `Err(Keychain(NoEntry))`.
    #[test]
    fn test_load_embedded_cutoff_absent_returns_err() {
        super::super::test_helpers::init_mock_keyring();
        let svc = test_service();
        let account = "test_embedded_cutoff_absent";
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);

        let result = load_embedded_cutoff(&svc, account);
        // Must be Err (NoEntry) not Ok(None).
        assert!(
            result.is_err(),
            "absent entry must return Err, not Ok(None)"
        );
    }

    /// F2: `serde(deny_unknown_fields)` is applied — an extra field in the
    /// JSON payload MUST cause a parse error, not silent success.
    #[test]
    fn test_seed_entry_payload_rejects_unknown_field() {
        super::super::test_helpers::init_mock_keyring();
        let svc = test_service();
        let account = "test_deny_unknown_fields";
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);

        // Write a JSON payload with a valid shape PLUS an extra unknown field.
        let tampered = r#"{"seed_hex":"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd","signing_active_since_seq":0,"signing_key_id":"ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unknown_future_field":"evil"}"#;
        let entry = crate::audit::key_custody::keyring_entry(&svc, account).expect("entry");
        entry.set_password(tampered).expect("set");

        // load_from_keychain MUST fail because of the unknown field.
        let result = LocalSigningKey::load_from_keychain(&svc, account);
        assert!(
            result.is_err(),
            "unknown field in seed entry MUST be rejected (deny_unknown_fields). \
             Got: {result:?}"
        );

        // load_embedded_cutoff uses serde_json::Value (not SeedEntryPayload) so
        // it is permissive — but load_from_keychain must fail.
        let _ = LocalSigningKey::delete_from_keychain(&svc, account);
    }

    /// F1: `is_keychain_access_error` allowlist — correct classification.
    #[test]
    fn test_is_keychain_access_error_allowlist() {
        // TRUE — transient lock variants (allowlisted).
        assert!(
            is_keychain_access_error(&keyring::Error::NoStorageAccess(
                "no storage".to_string().into()
            )),
            "NoStorageAccess must be treated as transient lock"
        );
        assert!(
            is_keychain_access_error(&keyring::Error::PlatformFailure(
                "platform err".to_string().into()
            )),
            "PlatformFailure must be treated as transient lock"
        );

        // FALSE — all other variants treated as fail-closed.
        assert!(
            !is_keychain_access_error(&keyring::Error::NoEntry),
            "NoEntry must NOT be access error (entry is genuinely absent)"
        );
        assert!(
            !is_keychain_access_error(&keyring::Error::BadEncoding(vec![0xff, 0xfe])),
            "BadEncoding must NOT be access error (present-but-corrupt = fail-closed)"
        );
        assert!(
            !is_keychain_access_error(&keyring::Error::TooLong("field".to_string(), 128)),
            "TooLong must NOT be access error"
        );
        assert!(
            !is_keychain_access_error(&keyring::Error::Invalid(
                "field".to_string(),
                "reason".to_string()
            )),
            "Invalid must NOT be access error"
        );
        assert!(
            !is_keychain_access_error(&keyring::Error::Ambiguous(vec![])),
            "Ambiguous must NOT be access error (duplicate entry = fail-closed)"
        );
    }

    /// F1: a present-but-corrupt seed entry (bad encoding) must fail CLOSED
    /// through `load_from_keychain`, not fall back to chain.json-trust.
    ///
    /// The verify_chain path branches on `is_keychain_access_error(ke)` to
    /// distinguish "transient lock → defer" from "corrupt/present → fail
    /// closed".  Here we test directly that `is_keychain_access_error` on
    /// BadEncoding and Ambiguous is `false`, so the caller routes to the
    /// fail-closed arm.
    ///
    /// The mock keyring only stores valid UTF-8 strings; to drive the
    /// corrupt-but-present path we inject keyring errors directly and
    /// verify the classification.
    #[test]
    fn test_corrupt_present_entry_classified_fail_closed() {
        // Simulate a corrupt-but-present error (BadEncoding) returned by keyring.
        let bad_enc = keyring::Error::BadEncoding(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(
            !is_keychain_access_error(&bad_enc),
            "BadEncoding MUST classify as fail-closed (not transient lock)"
        );

        // Verify that Ambiguous (duplicate entry planted by attacker) is also
        // fail-closed.
        let ambiguous = keyring::Error::Ambiguous(vec![]);
        assert!(
            !is_keychain_access_error(&ambiguous),
            "Ambiguous MUST classify as fail-closed"
        );
    }

    // ── EmbeddedCutoff roster_version_floor field ─────────────────────────

    /// Legacy JSON without `roster_version_floor` parses successfully with
    /// `roster_version_floor: None` — backward compatibility.
    #[test]
    fn embedded_cutoff_legacy_json_no_floor_returns_none() {
        // Arrange — JSON as written by pre-an internal ticket code (no roster_version_floor key).
        let legacy = r#"{
            "signing_active_since_seq": 0,
            "signing_key_id": "key-abc123",
            "type": "EmbeddedCutoff",
            "pubkey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"#;

        // Act
        let result = parse_embedded_cutoff(legacy);

        // Assert — parses OK and the floor field is None.
        let ec = result.expect("must parse").expect("must be Some");
        assert_eq!(
            ec.roster_version_floor, None,
            "pre-an internal ticket JSON must yield None floor"
        );
        assert_eq!(ec.signing_key_id, "key-abc123");
        assert_eq!(ec.signing_active_since_seq, 0);
    }

    /// JSON with `roster_version_floor` set parses the value correctly.
    #[test]
    fn embedded_cutoff_with_floor_parses_correctly() {
        // Arrange — JSON as written by post-an internal ticket roster-install.
        let with_floor = r#"{
            "signing_active_since_seq": 5,
            "signing_key_id": "key-def456",
            "roster_version_floor": 42,
            "type": "EmbeddedCutoff",
            "pubkey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }"#;

        // Act
        let result = parse_embedded_cutoff(with_floor);

        // Assert
        let ec = result.expect("must parse").expect("must be Some");
        assert_eq!(ec.roster_version_floor, Some(42), "floor must be 42");
        assert_eq!(ec.signing_active_since_seq, 5);
        assert_eq!(ec.signing_key_id, "key-def456");
    }

    /// `write_roster_floor_to_keychain` writes the floor into an existing
    /// keychain entry and a subsequent `load_embedded_cutoff` reads it back.
    #[test]
    fn write_roster_floor_roundtrip_via_keychain() {
        // Arrange — a REAL seed entry, exactly as `audit_init`/`csq login`
        // writes it (fixtures MUST mirror the real mint path; the original
        // fixture used a synthetic non-seed JSON and masked the
        // deny_unknown_fields brick — an internal ticket review C1/H1).
        super::super::test_helpers::init_mock_keyring();
        let service = "csq-test-roster-floor-svc";
        let chain_id = "test-chain-floor-roundtrip";
        let account = KeySlot::Active.keychain_account(chain_id);
        let _ = LocalSigningKey::delete_from_keychain(service, &account);
        let _key =
            LocalSigningKey::generate_and_store(service, &account, 0).expect("generate seed");

        // Act — write the floor (tempdir base: no file-store seed exists, the
        // file leg warns + skips; the keychain leg is what this test pins).
        let base = tempfile::tempdir().expect("tempdir");
        write_roster_floor_to_keychain(base.path(), service, chain_id, 7);

        // Assert — the permissive cutoff reader sees the floor...
        let ec = load_embedded_cutoff(service, &account)
            .expect("load must not error")
            .expect("entry must exist");
        assert_eq!(
            ec.roster_version_floor,
            Some(7),
            "keychain-anchored floor must be 7 after write"
        );
        // ...AND the typed key-load path still parses the patched entry
        // (C1 regression: deny_unknown_fields must tolerate the 4th field —
        // a failure here is the keychain-only-install chain brick).
        let loaded = LocalSigningKey::load_from_keychain(service, &account);
        assert!(
            loaded.is_ok(),
            "load_from_keychain MUST succeed on a floor-bearing seed entry: {:?}",
            loaded.err()
        );
    }

    /// The floor writer refuses to patch an entry that is not a JSON seed
    /// payload (foreign JSON / legacy bare-hex) — it must not corrupt unknown
    /// entries (an internal ticket review M1).
    #[test]
    fn write_roster_floor_skips_non_seed_entry() {
        super::super::test_helpers::init_mock_keyring();
        let service = "csq-test-roster-floor-foreign-svc";
        let chain_id = "test-chain-floor-foreign";
        let account = KeySlot::Active.keychain_account(chain_id);
        let entry = crate::audit::key_custody::keyring_entry(service, &account).unwrap();
        let foreign = r#"{"hello":"world"}"#;
        entry.set_password(foreign).unwrap();

        let base = tempfile::tempdir().expect("tempdir");
        write_roster_floor_to_keychain(base.path(), service, chain_id, 7);

        let after = entry.get_password().unwrap();
        assert_eq!(
            after, foreign,
            "non-seed keychain entry MUST be left byte-identical"
        );
    }

    /// `write_roster_floor_to_keychain` is non-fatal when the keychain entry
    /// is absent (NoEntry) — returns without error and without panicking.
    #[test]
    fn write_roster_floor_to_absent_entry_is_nonfatal() {
        // Arrange — fresh mock keychain with no entry for this chain.
        super::super::test_helpers::init_mock_keyring();
        let service = "csq-test-roster-floor-absent-svc";
        let chain_id = "test-chain-no-entry";

        // Act — calling write on an absent entry MUST NOT panic or return an error
        // (the function is `()` — if it would panic, the test would fail).
        let base = tempfile::tempdir().expect("tempdir");
        write_roster_floor_to_keychain(base.path(), service, chain_id, 99);
        // If we reach here, the non-fatal contract is satisfied.
    }
}
