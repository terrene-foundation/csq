//! csq-owned data types for the audit ledger (M01 + M02 schema v1→v2).
//!
//! See [`crate::audit::traits`] for the trait surface that consumes
//! these types. Per the M01 structural invariant: no vendor module
//! paths (`use kailash::*` / `eatp::*` / qualified `kailash_x::y`)
//! may appear in this file.
//!
//! # M02 additions
//!
//! - [`EatpActor`], [`EatpAuthority`], [`EatpTrust`] — typed wrapper structs
//!   for EATP attestation fields. These are opaque `serde_json::Value`
//!   wrappers that allow the on-disk schema to carry forward-compatible
//!   EATP blobs without importing vendored EATP crate types.
//! - [`SignedRecord`] gains five optional EATP attestation fields:
//!   `actor`, `authority`, `trust`, `eatp_start_ts`, `eatp_end_ts`.
//! - [`RecordId::try_new`] tightened from `[A-Za-z0-9_-]{8,64}` to
//!   ULID (26-char Crockford Base32) or UUIDv7 (36-char hyphenated) only.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::AccountNum;

// ---------------------------------------------------------------------------
// Errors used by the type-construction validators
// ---------------------------------------------------------------------------

/// Errors from constructing or deserializing audit-trail identifiers
/// and tagged strings. Every variant names the field that failed and
/// the reason; messages are safe to surface to operators (no echoing
/// of the offending input, which may carry attacker-controlled bytes).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// Input was empty or all-whitespace.
    #[error("{field} must not be empty")]
    Empty {
        /// Field name (e.g. `"record_id"`, `"sink_name"`).
        field: &'static str,
    },
    /// Input length is outside the allowed range.
    #[error("{field} length {got} outside allowed range {min}..={max}")]
    Length {
        /// Field name.
        field: &'static str,
        /// Observed length.
        got: usize,
        /// Minimum allowed length.
        min: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Input contains a disallowed character or substring.
    /// The offending sequence is described by NAME, never echoed.
    #[error("{field} contains disallowed sequence: {what}")]
    Charset {
        /// Field name.
        field: &'static str,
        /// What was disallowed (e.g. `"CRLF"`, `"path traversal '..'"`,
        /// `"non-ASCII"`, `"uppercase hex"`).
        what: &'static str,
    },
    /// Input did not match the required shape (regex / structural).
    #[error("{field} does not match required shape: {shape}")]
    Shape {
        /// Field name.
        field: &'static str,
        /// Human description of the required shape.
        shape: &'static str,
    },
}

/// Errors from a [`crate::audit::traits::SigningKey`] operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigningError {
    /// The OS keychain is locked; user must unlock to proceed.
    #[error("keychain locked")]
    KeychainLocked,
    /// The key has been revoked or rotated; lookup against the
    /// rotation chain (M04) is required to find the active key.
    #[error("signing key {key_id} revoked or rotated")]
    KeyRevoked {
        /// The key id that was revoked.
        key_id: KeyId,
    },
    /// The signing backend is unavailable (hardware missing, network
    /// down for remote HSM, etc.).
    #[error("signing backend unavailable: {message}")]
    Unavailable {
        /// Operator-facing reason (already redacted).
        message: RedactedString,
    },
    /// Catch-all for unexpected signing-backend errors.
    #[error("signing internal error: {message}")]
    Internal {
        /// Operator-facing reason (already redacted).
        message: RedactedString,
    },
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Reject characters that produce log forgery, path traversal, or
/// header injection if echoed to an operator surface or persisted to
/// disk: CR, LF, NUL, `/`, `\`, and the `..` substring.
fn reject_dangerous_chars(s: &str, field: &'static str) -> Result<(), IdError> {
    for c in s.chars() {
        match c {
            '\r' | '\n' => {
                return Err(IdError::Charset {
                    field,
                    what: "CRLF",
                })
            }
            '\0' => {
                return Err(IdError::Charset {
                    field,
                    what: "NUL byte",
                })
            }
            '/' | '\\' => {
                return Err(IdError::Charset {
                    field,
                    what: "path separator",
                });
            }
            c if c.is_control() => {
                return Err(IdError::Charset {
                    field,
                    what: "control character",
                });
            }
            _ => {}
        }
    }
    if s.contains("..") {
        return Err(IdError::Charset {
            field,
            what: "path traversal '..'",
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Stable per-record identifier.
///
/// Accepts exactly two shapes (Amendment 4, M02):
///
/// - **ULID**: 26 uppercase Crockford Base32 characters
///   (`0-9`, `A-Z` excluding `I`, `L`, `O`, `U`).
/// - **UUIDv7**: 36 characters in the canonical hyphenated form
///   `xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx` where all hex digits are
///   lowercase.
///
/// The inner field is private; construct via [`RecordId::try_new`] or
/// `serde` deserialization (which routes through the validator).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordId(String);

/// Crockford Base32 alphabet (26 uppercase chars, excludes I, L, O, U).
const CROCKFORD_BASE32: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Returns true if `c` is in the Crockford Base32 alphabet.
fn is_crockford(c: char) -> bool {
    CROCKFORD_BASE32.contains(&(c as u8))
}

/// Returns true if `s` is a valid ULID: exactly 26 Crockford Base32 chars.
fn is_ulid(s: &str) -> bool {
    s.len() == 26 && s.chars().all(is_crockford)
}

/// Returns true if `s` is a valid UUIDv7: 36 chars,
/// `xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx`, lowercase hex.
fn is_uuidv7(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    // Positions of hyphens: 8, 13, 18, 23.
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    // Version nibble at position 14 must be '7'.
    if b[14] != b'7' {
        return false;
    }
    // Variant nibble at position 19 must be 8, 9, a, or b.
    if !matches!(b[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    // All other chars must be lowercase hex.
    for &byte in b.iter() {
        match byte {
            b'-' => {} // hyphens are already checked above
            b'0'..=b'9' | b'a'..=b'f' => {}
            _ => return false,
        }
    }
    true
}

impl RecordId {
    /// Constructs a [`RecordId`] from `s`, validating the shape.
    ///
    /// Accepts exactly:
    /// - A 26-character Crockford Base32 ULID (uppercase, excludes I/L/O/U).
    /// - A 36-character hyphenated UUIDv7 (`xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx`,
    ///   lowercase hex only).
    ///
    /// All other inputs are rejected.
    pub fn try_new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(IdError::Empty { field: "record_id" });
        }
        // Reject CRLF, NUL, control chars, `/`, `\`, `..` first.
        reject_dangerous_chars(&s, "record_id")?;
        if is_ulid(&s) || is_uuidv7(&s) {
            return Ok(Self(s));
        }
        Err(IdError::Shape {
            field: "record_id",
            shape: "26-char Crockford Base32 ULID or 36-char UUIDv7",
        })
    }

    /// Returns the raw string identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RecordId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RecordId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(D::Error::custom)
    }
}

/// Stable identifier for a signing key.
///
/// Encoded as `"ed25519:<32-byte-public-key-hex>"`. The structural
/// shape is enforced at construction: literal `"ed25519:"` prefix plus
/// 64 lowercase hex characters. M04 ships the rotation chain that
/// links one [`KeyId`] to the next.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl KeyId {
    /// Constructs a [`KeyId`] from `s`, validating shape
    /// `^ed25519:[0-9a-f]{64}$`.
    pub fn try_new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if !s.starts_with("ed25519:") {
            return Err(IdError::Shape {
                field: "key_id",
                shape: "ed25519:<64-hex>",
            });
        }
        let body = &s["ed25519:".len()..];
        if body.len() != 64 {
            return Err(IdError::Length {
                field: "key_id",
                got: body.len(),
                min: 64,
                max: 64,
            });
        }
        if !body
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        {
            return Err(IdError::Charset {
                field: "key_id",
                what: "non-lowercase-hex in body",
            });
        }
        Ok(Self(s))
    }

    /// Returns the raw string identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(D::Error::custom)
    }
}

/// Lowercase-hex SHA-256 digest, exactly 64 characters.
///
/// Enforced at construction: `^[0-9a-f]{64}$`. Uppercase hex is
/// rejected — the cross-SDK canonical-form contract requires
/// deterministic byte-for-byte agreement, and an uppercase-tolerant
/// deserializer that re-serializes lowercase breaks signature
/// verification on round-trips through any sink that preserves bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// Constructs a [`Sha256Hex`] from `s`, enforcing lowercase 64-char
    /// hex.
    pub fn try_new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.len() != 64 {
            return Err(IdError::Length {
                field: "sha256_hex",
                got: s.len(),
                min: 64,
                max: 64,
            });
        }
        for c in s.chars() {
            if c.is_ascii_uppercase() {
                return Err(IdError::Charset {
                    field: "sha256_hex",
                    what: "uppercase hex",
                });
            }
            if !(c.is_ascii_digit() || ('a'..='f').contains(&c)) {
                return Err(IdError::Charset {
                    field: "sha256_hex",
                    what: "non-hex character",
                });
            }
        }
        Ok(Self(s))
    }

    /// Returns the raw hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The genesis-prev-hash sentinel — 64 lowercase zeros.
    pub const GENESIS: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// Returns a [`Sha256Hex`] containing the genesis sentinel.
    #[must_use]
    pub fn genesis() -> Self {
        // Const-validated above; cannot fail.
        Self(Self::GENESIS.to_string())
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Sha256Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(D::Error::custom)
    }
}

/// Operator-friendly identifier for a [`crate::audit::traits::LedgerSink`].
///
/// Shape: `^[a-z0-9-]{1,64}$`. Used in [`SinkReceipt::sink`] and in
/// structured log lines; the charset prevents CRLF / header injection
/// and the length bound prevents log-flood DoS.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SinkName(String);

impl SinkName {
    /// Constructs a [`SinkName`] from `s`, enforcing `^[a-z0-9-]{1,64}$`.
    pub fn try_new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(IdError::Empty { field: "sink_name" });
        }
        if !(1..=64).contains(&s.len()) {
            return Err(IdError::Length {
                field: "sink_name",
                got: s.len(),
                min: 1,
                max: 64,
            });
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(IdError::Charset {
                field: "sink_name",
                what: "non-[a-z0-9-] character",
            });
        }
        Ok(Self(s))
    }

    /// Returns the raw name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SinkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SinkName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SinkName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(D::Error::custom)
    }
}

/// Sink-assigned record identifier (Rekor log index, S3 ETag, ...).
///
/// Shape: `^[A-Za-z0-9._:-]{1,256}$`. The `:` is allowed so sinks that
/// namespace by `<tree>:<index>` (Rekor v2) or `<bucket>:<key>` (S3
/// Object Lock) fit without escaping. Rejects CRLF and control chars
/// even within the broader charset; sinks that return non-conforming
/// ids are treated as protocol violations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SinkId(String);

impl SinkId {
    /// Constructs a [`SinkId`] from `s`, enforcing
    /// `^[A-Za-z0-9._:-]{1,256}$`.
    pub fn try_new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(IdError::Empty { field: "sink_id" });
        }
        if !(1..=256).contains(&s.len()) {
            return Err(IdError::Length {
                field: "sink_id",
                got: s.len(),
                min: 1,
                max: 256,
            });
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
        {
            return Err(IdError::Charset {
                field: "sink_id",
                what: "non-[A-Za-z0-9._:-] character",
            });
        }
        Ok(Self(s))
    }

    /// Returns the raw sink-id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SinkId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SinkId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::try_new(s).map_err(D::Error::custom)
    }
}

/// Operator-facing error message guaranteed to have passed through
/// [`redact_tokens`](csq_redact::redact_tokens) — relocated to the `csq-redact`
/// leaf crate (W1) and re-exported here at its historical path
/// (`crate::audit::types::RedactedString`; also re-exported from `crate::audit`)
/// so every callsite compiles unchanged. See sdk-surface/an internal journal entry
pub use csq_redact::RedactedString;

// ---------------------------------------------------------------------------
// Cryptographic primitives
// ---------------------------------------------------------------------------

/// Ed25519 public key (32 bytes).
///
/// We wrap the raw bytes rather than `ed25519_dalek::VerifyingKey` so
/// the trait surface stays dependency-light and so callers can
/// serialize the key without importing the upstream crate. The
/// 32-byte invariant is enforced at construction and at deserialize.
///
/// `PartialEq` is provided; do NOT use `==` to compare a signature
/// when the result is security-sensitive — use the upstream
/// `ed25519-dalek` verifier (which is constant-time).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(transparent)]
pub struct Ed25519PublicKey(#[serde(with = "hex_array_32")] pub [u8; 32]);

impl Ed25519PublicKey {
    /// Wraps `bytes` as an [`Ed25519PublicKey`].
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32-byte key material.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 signature (64 bytes).
///
/// See [`Ed25519PublicKey`] for the wrapping rationale. Constant-time
/// comparison is the caller's responsibility; this wrapper deliberately
/// does NOT expose a `==` impl in any security-sensitive helper.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct Ed25519Signature(#[serde(with = "hex_array_64")] pub [u8; 64]);

impl Ed25519Signature {
    /// Wraps `bytes` as an [`Ed25519Signature`].
    #[must_use]
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 64-byte signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Sink receipts and errors
// ---------------------------------------------------------------------------

/// Receipt returned by [`crate::audit::traits::LedgerSink::append`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SinkReceipt {
    /// Sink name (matches [`crate::audit::traits::LedgerSink::name`]).
    pub sink: SinkName,
    /// Sink-assigned identifier.
    pub sink_id: SinkId,
    /// ISO-8601 UTC `+00:00` timestamp the sink acknowledged the
    /// append. Validated at the [`SignedRecord`] consistency layer
    /// (M02 deserializer); the receipt accepts the string as-given by
    /// the sink and the engine cross-checks against its own clock.
    pub anchored_at: String,
    /// Optional inclusion proof (hex-encoded Merkle path, sink-specific).
    /// `None` for sinks that do not produce per-entry proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<String>,
}

/// Error from a [`crate::audit::traits::LedgerSink`] operation.
///
/// `#[non_exhaustive]` so M07/M10 can add variants (`AuthExpired`,
/// `RateLimited`, ...) without breaking the public match surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SinkError {
    /// The sink rejected the submission. Message is pre-redacted.
    #[error("sink rejected submission: {message}")]
    Rejected {
        /// Operator-facing reason — already through `redact_tokens`.
        message: RedactedString,
    },
    /// The sink is unreachable (network, DNS, timeout).
    #[error("sink unreachable: {message}")]
    Unreachable {
        /// Operator-facing reason — already through `redact_tokens`.
        message: RedactedString,
    },
    /// The fetched record does not match the locally-stored canonical
    /// hash. This is a tamper signal; M05's chain verifier escalates.
    #[error("sink drift detected for record {record_id}")]
    Drift {
        /// The record whose sink-stored bytes differ from local.
        record_id: RecordId,
    },
    /// The record id was not found at the sink. Distinct from
    /// `Rejected` so callers can retry against a different sink or
    /// fall back to local verification.
    #[error("record {record_id} not found at sink")]
    NotFound {
        /// The record id that did not resolve.
        record_id: RecordId,
    },
    /// Catch-all for sink-internal errors. Prefer typed variants.
    #[error("sink internal error: {message}")]
    Internal {
        /// Operator-facing reason — already through `redact_tokens`.
        message: RedactedString,
    },
}

/// Error from a [`crate::audit::traits::LedgerEngine`] operation.
///
/// `#[non_exhaustive]` — new variants may be added in future milestones
/// without breaking existing match surfaces.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// Append rejected because `prev_hash` does not match chain head.
    /// The M05-canonical field shape: includes `seq` of the rejected
    /// record so verifier diagnostics point at the exact break.
    #[error("chain break at seq {seq}: expected prev {expected_prev}, got {actual_prev}")]
    ChainBroken {
        /// Sequence number of the record whose `prev_hash` did not
        /// match the chain head.
        seq: u64,
        /// The hash the engine expected (current chain head's
        /// canonical hash).
        expected_prev: Sha256Hex,
        /// The hash the submitted record carried in its `prev_hash`.
        actual_prev: Sha256Hex,
    },
    /// Ed25519 signature verification failed for a record during
    /// `verify_integrity` (M05). The record's claimed `canonical_hash`
    /// does not match the signature produced by the key identified by
    /// `key_id`. This indicates tamper (record mutation after signing)
    /// or key/record mismatch.
    ///
    /// Added by M05 per `specs/12-audit-trail.md §12.13`.
    #[error("invalid signature for record {record_id} (key {key_id})")]
    InvalidSignature {
        /// The `record_id` of the record whose signature failed
        /// verification.
        record_id: RecordId,
        /// The `signing_key_id` the record claims to have been signed
        /// with.
        key_id: KeyId,
    },
    /// The signing key required to verify a record is not available
    /// in the keychain (M05). This occurs when a key was rotated and
    /// the outgoing key was not retained in the historical slot, or
    /// when the keychain was manually cleared. Operators must retain
    /// outgoing keys via `csq audit rotate-key` to enable historical
    /// verification.
    ///
    /// Added by M05 per `specs/12-audit-trail.md §12.13`.
    #[error("signing key {key_id} not found in keychain — retain outgoing keys via `csq audit rotate-key`")]
    KeyNotFound {
        /// The `key_id` that was required but could not be loaded.
        key_id: KeyId,
    },
    /// The signing key required to verify a record is PRESENT but currently
    /// INACCESSIBLE — the credential store could not be read right now
    /// (OS keychain locked at boot, or a per-app-ACL prompt that a
    /// non-interactive process such as the daemon cannot answer →
    /// `errSecInteractionNotAllowed` / `keyring::Error::PlatformFailure`).
    ///
    /// This is structurally distinct from `KeyNotFound` (the key is
    /// genuinely absent): a present-but-blocked key is a TRANSIENT condition
    /// that must NOT durably fail the chain. The verifier maps this to
    /// [`crate::audit::AuditHealth::Unknown`] (no `.chain-broken` sentinel) so
    /// the chain is neither bricked nor durably locked out — it recovers on the
    /// next run that can read the store (e.g. an interactive `csq audit verify`,
    /// or the file-based seed store once present).
    ///
    /// The access-vs-absence distinction is the load-bearing invariant: only
    /// `keyring::Error::{NoStorageAccess, PlatformFailure}` (allowlisted by
    /// `key_custody::is_keychain_access_error`) routes here; genuine `NoEntry`
    /// stays `KeyNotFound`, and a present-but-corrupt/planted entry stays
    /// fail-closed. See `specs/12-audit-trail.md` §12.13.2.
    #[error("signing key {key_id} is present but temporarily inaccessible (credential store locked / access-denied) — chain verification deferred, not failed")]
    KeychainUnavailable {
        /// The `key_id` whose credential could not be read right now.
        key_id: KeyId,
    },
    /// A record at or after the signing cutoff carries the placeholder key
    /// (all-zero key_id) — indicating the record was never signed by a real
    /// key despite signing being mandatory from that seq onward (R1-DEEP-2 fix).
    ///
    /// `signing_active_since_seq` in chain.json records the cutoff written by
    /// `csq audit init`. Any record at `seq >= cutoff` MUST carry a non-placeholder
    /// signature; a placeholder at or after the cutoff is treated as tamper.
    #[error("unsigned record at seq {seq}: signing became mandatory at seq {cutoff}")]
    UnsignedRecordAfterCutoff {
        /// Sequence number of the unsigned record.
        seq: u64,
        /// The cutoff seq from chain.json (`signing_active_since_seq`).
        cutoff: u64,
    },
    /// The signing cutoff embedded inside the keychain seed entry disagrees
    /// with the value in `chain.json` (or with `chain.json`'s `signing_key_id`).
    ///
    /// This is the primary tamper signal for the M-hardening attack: an
    /// attacker who can write `chain.json` but not the OS keychain can raise
    /// `signing_active_since_seq` in `chain.json` to re-open placeholder-key
    /// acceptance.  When the verifier reads the embedded cutoff from the
    /// keychain seed entry and compares it with `chain.json`'s value, any
    /// disagreement is detected here.
    ///
    /// Note: the two values shown in the error message MUST differ (enforced
    /// at the call site — callers only construct this variant when they have
    /// confirmed a difference).
    ///
    /// **Operator UI message**: "audit chain integrity failure: the signing
    /// cutoff in chain.json disagrees with the authoritative value embedded
    /// in the keychain seed entry — this indicates tampering with chain.json.
    /// Run `csq audit verify --full` for diagnosis."
    #[error(
        "cutoff anchor mismatch: chain.json cutoff {chain_json_cutoff:?} \
         disagrees with keychain embedded cutoff {keychain_cutoff} — possible tamper"
    )]
    CutoffAnchorMismatch {
        /// The cutoff value recorded in `chain.json`
        /// (`signing_active_since_seq`), or `None` when the field is absent.
        chain_json_cutoff: Option<u64>,
        /// The authoritative cutoff from the keychain seed entry.
        keychain_cutoff: u64,
    },

    /// The signing key identifier recorded in `chain.json` disagrees with the
    /// `signing_key_id` embedded inside the keychain seed entry.
    ///
    /// This is a tamper signal distinct from `CutoffAnchorMismatch`: the
    /// attacker altered `chain.json`'s `signing_key_id` field (e.g. to point
    /// at a different key they control) while the keychain entry still records
    /// the original key.
    ///
    /// A separate variant is required because if `CutoffAnchorMismatch` were
    /// used here the two cutoff values in its message would be EQUAL (the
    /// cutoff was not tampered), producing the confusing output
    /// "cutoff X disagrees with cutoff X".
    ///
    /// **Operator UI message**: "audit chain integrity failure: the signing key
    /// identifier in chain.json does not match the authoritative value embedded
    /// in the keychain seed entry — this indicates tampering with chain.json.
    /// Run `csq audit verify --full` for diagnosis."
    #[error(
        "signing key id anchor mismatch: chain.json signing_key_id {chain_json_key_id:?} \
         disagrees with keychain embedded signing_key_id {keychain_key_id:?} — possible tamper"
    )]
    SigningKeyIdAnchorMismatch {
        /// The `signing_key_id` recorded in `chain.json`, or `None` when absent.
        chain_json_key_id: Option<String>,
        /// The authoritative `signing_key_id` from the keychain seed entry.
        keychain_key_id: String,
    },

    /// The requested sequence is out of bounds.
    #[error("sequence {seq} not found")]
    NotFound {
        /// The sequence number that was requested.
        seq: u64,
    },
    /// `verify_integrity` detected a broken link.
    #[error("integrity check failed at seq {seq}: {reason}")]
    IntegrityBroken {
        /// The sequence at which the break was detected.
        seq: u64,
        /// Operator-facing reason — already redacted.
        reason: RedactedString,
    },
    /// Underlying storage I/O failure. Carries the original
    /// `std::io::Error` as `#[source]` so operator tools can walk the
    /// chain; `context` is the redacted, operator-facing description.
    #[error("storage io error: {context}")]
    Io {
        /// Operator-facing redacted reason.
        context: RedactedString,
        /// The underlying io error.
        #[source]
        source: std::io::Error,
    },
    /// Catch-all for unexpected engine internal errors. Prefer typed
    /// variants whenever the failure mode is enumerable.
    #[error("engine internal error: {message}")]
    Internal {
        /// Operator-facing redacted reason.
        message: RedactedString,
    },

    /// A record carries a `multi_sig` authority blob that fails verification:
    /// either under-threshold (fewer valid inner authorizations than the blob's
    /// own threshold field), or structurally malformed (missing fields, bad hex).
    ///
    /// M11 — inserted by `verify_record_multi_sig` immediately after the outer
    /// Ed25519 signature check in `verify_chain`.
    ///
    /// **Operator UI message**: "multi-sig verification failed for record
    /// `<record_id>` — the authority blob is malformed or under-threshold.
    /// This record cannot be accepted. See `csq audit verify` for details."
    #[error("multi-sig verification failed for record {record_id}: {reason}")]
    MultiSigInvalid {
        /// The `record_id` of the record that failed multi-sig verification.
        record_id: RecordId,
        /// Operator-facing redacted reason (fixed vocabulary).
        reason: RedactedString,
    },

    /// The head (newest / highest-seq) record of the chain is a historical-key
    /// gap — its signing key is absent from the keychain and is classified as a
    /// historical (rotated-out) key. A chain that ends in an unverifiable signature
    /// provides no tamper-evidence for new records and MUST NOT be accepted.
    ///
    /// The degrade path (§12.13.10) is only sound when the historical-key segment
    /// is a prefix, with a current-key-signed suffix up to and including the head.
    /// When the head itself is a gap, the chain is in an invalid state: either
    /// the current active key is also missing, or the most-recent records were
    /// written by an unknown key. Both are integrity failures.
    ///
    /// **Operator UI message**: "audit chain head record is signed by a historical
    /// key that is no longer in the keychain. The chain cannot be verified to the
    /// present. Run `csq audit init` to re-establish a current signing key, or
    /// restore the outgoing key from backup."
    #[error(
        "historical-key gap at head (seq {head_seq}): \
         the most-recent record's signing key {key_id} is absent from the keychain \
         — the chain cannot be verified to the present"
    )]
    HistoricalKeyAtHead {
        /// Sequence number of the head (newest) record in the gap.
        head_seq: u64,
        /// The key_id of the absent signing key.
        key_id: KeyId,
    },

    /// A record classified as a historical-key gap appeared AFTER a record whose
    /// signature was successfully verified with a present key. Under the legitimate
    /// rotation topology, historical-key records form a prefix (older segment); a
    /// gap record appearing after a verified record indicates either chain tampering
    /// (a forged record inserted after the key-rotation boundary) or an invalid
    /// chain layout that cannot be safely degraded.
    ///
    /// **Operator UI message**: "historical-key gap record at seq {gap_seq} appears
    /// after a verified record — this indicates chain tampering or an invalid rotation
    /// order. Run `csq audit verify --full` for diagnosis."
    #[error(
        "historical-key gap record at seq {gap_seq} appears after a signature-verified record \
         (key {key_id}) — invalid rotation order or chain tampering"
    )]
    GapAfterVerifiedSegment {
        /// Sequence number of the unexpected gap record.
        gap_seq: u64,
        /// The key_id of the absent signing key on the gap record.
        key_id: KeyId,
    },
}

// ---------------------------------------------------------------------------
// Event taxonomy
// ---------------------------------------------------------------------------

/// Discriminant for the audit-event kinds (see [`EventKind::ALL`] for the
/// canonical list; the count is asserted at compile time).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A `csq run` invocation completed (success or failure).
    CsqRun,
    /// An OAuth refresh-token exchange ran.
    OAuthRefresh,
    /// A COC artifact was loaded into a session.
    ArtifactLoad,
    /// A model invocation ran (request / response pair).
    ModelInvoke,
    /// Output was captured (transcript, artifact write).
    OutputCapture,
    /// A `csq swap` repointed handle-dir symlinks.
    AccountSwap,
    /// An identity record was minted in the identity store.
    IdentityMint,
    /// A signing key was rotated.
    KeyRotate,
    /// A release artifact was authorized.
    ReleaseAuth,
    /// A sink acknowledged an anchor (replication success).
    ReplicationAck,
    /// A sink rejected or failed an anchor attempt.
    ReplicationFailed,
    /// The chain continued in-place across a process restart.
    ChainContinuation,
    /// The chain was re-genesised (key rotation, schema migration).
    ChainReGenesis,
    /// A sink-vs-local drift was detected during verify.
    SinkDriftDetected,
    /// An account was logged out and its credential files removed.
    ///
    /// M13b — append-FIRST lifecycle op. Records slot + optional orphaned
    /// identity UUID. Trust boundary: orphan-detection + external-anchor
    /// evidence only; NOT same-user forge-resistance (see spec 12 §12.17).
    AccountLogout,
    /// An account slot was moved to a different slot number.
    ///
    /// M13b — append-FIRST lifecycle op. Records from_slot + to_slot.
    /// Trust boundary: same as [`EventKind::AccountLogout`].
    AccountMove,
    /// An inbound seam (loom F101-1) provenance event was REJECTED at the
    /// validating ingestion frontier and NOT linked into the chain spine.
    ///
    /// M18 (BE seam) — the auditable rejection record (F-SEAM-02). The
    /// malformed/unvalidatable payload goes to `.quarantine/`; only this
    /// metadata-only rejection record links into the chain. Carries NO raw
    /// event body (HIGH-1: never persist untrusted free-text into the chain).
    SeamEventRejected,
    /// A loom F101-1 provenance event was signed/anchored into the chain.
    ///
    /// M18 (BE seam) — the seam's product record. `actor`/`authority`/`trust`
    /// SignedRecord slots are populated from the event via M17
    /// `attest_authorship` (fail-closed UNBACKED). Production never writes this
    /// kind until M18-bind registers a frozen F101-1 decode arm; the M18
    /// scaffolding builds + unit-tests the projection via a test-only arm.
    ProvenanceAnchored,
    /// Per-surface provenance capture capability matrix declaration.
    ///
    /// M19 (hook-conformance + capture-capability matrix) — emitted at daemon
    /// start and on capability change (content-hash dedup). Records whether each
    /// known surface has an ingestion hook wired (`Wired`) or not (`Unwired`).
    ///
    /// Addresses F-SEAM-07: absence of provenance for a surface must not be
    /// read as "no decisions made". This record declares csq's actual capture
    /// state structurally, so an attested session on an `Unwired` surface is
    /// correctly interpreted as "session happened + provenance capture not active"
    /// rather than "session happened + decisions unknown". No raw body, no
    /// surface-derived content (HIGH-1 compliant).
    ProvenanceCaptureMatrix,
    /// A replayed/duplicate inbound seam (loom F101-1) provenance event was
    /// suppressed at ingest — its `decision_id` already anchored into the chain.
    ///
    /// M20 (degraded-reconcile) — the auditable suppression record for the
    /// daemon-down/hook-down reconnect path (F-SEAM-03(a)). The hook's outbox
    /// replays buffered events on reconnect; a replayed `decision_id` is a no-op.
    /// Emitted at most ONCE per `decision_id` (F-SEAM-05 amplification defense:
    /// a flood of one id → 1 anchor + 1 suppression record + silent no-ops).
    /// Metadata-only (HIGH-1: no raw body).
    SeamDuplicateSuppressed,
    /// A per-turn governance decision from the live Phase-2b interactive
    /// enforcement session (#784, M3 per-decision EATP attestation).
    ///
    /// One record per `GovernanceEvent` emitted by `InteractiveSession`
    /// (turn-started / turn-completed / governance-failure / failover /
    /// operator-override), distinguished by the fixed-vocabulary
    /// [`GovernanceTurnPayload::event_class`] tag. The decision VERDICT rides on
    /// [`SignedRecord::verification_level`] (a separate axis); an operator
    /// override is the reserved `SignedAttestation` level (enterprise 6-level
    /// gradient). The producer (the Phase-2b interactive substrate) is
    /// enterprise-only and moat-stripped from the community edition; the kind
    /// lives in the shared taxonomy so both editions compile it (community never
    /// constructs one). HIGH-1: no raw untrusted free-text — the operator
    /// override justification is stored redacted + as a content hash, and the
    /// failover transport detail is dropped (only the discriminant is kept).
    GovernanceTurn,
    /// M3 §10.5 W2b/W3 — born-canonical EATP genesis record (seq == 0, signed)
    /// and per-session-close EATP attestations. Record #0 is a
    /// `SIGNED_ATTESTATION` genesis in the enterprise edition canonical form (W2b, emitted
    /// at `csq audit init`); subsequent records are session-close attestations
    /// from W3. The enterprise producer uses `attest_born_canonical_genesis` +
    /// `write_record_v2_signed_in`; the community edition never constructs one;
    /// the kind lives in the shared taxonomy so both editions compile it.
    EatpAttestation,
    /// An MCP tool-call gate decision from the spawn-boundary `csq mcp-proxy`
    /// (#M6 T6.2 Shard 4). One record per gated `tools/call` a coding CLI
    /// (codex/gemini) routes through the proxy: the tool id, the verdict
    /// (`pass` / `block` / `escalate`), the spawned CLI, and the honest
    /// `enforcement_fidelity = "spawn_boundary_only"` label.
    ///
    /// The proxy is a spawn-boundary interposer, NOT an in-loop enforcer, so
    /// the verdict is on the tool-call REQUEST (not the model's decision to make
    /// it) — hence the honest fidelity label distinguishing it from the cc/3P
    /// in-loop `GovernanceTurn` stream. The producer (the proxy → the daemon
    /// `POST /api/audit/mcp-gate` route, which builds + signs + appends this
    /// record server-side) is enterprise-only and moat-stripped from the
    /// community edition; the kind lives in the shared taxonomy so both editions
    /// compile it (community never constructs one). HIGH-1: the `tool` is a
    /// bounded MCP-declared identifier, never free-text prose; every other field
    /// is a fixed-vocabulary tag.
    McpGateDecision,
    /// #787 b2b — a signed policy bundle was installed via `csq audit
    /// bundle-install`. One record per successful install: the installed
    /// `bundle_version` (== the new rollback floor), the out-of-band Ed25519
    /// verifying key the detached signature was checked against, and the
    /// installer's timestamp.
    ///
    /// A passive OWN-OP OBSERVATION, not a multi-sig-guarded decision: the
    /// bundle's own detached signature (verified against the operator's
    /// out-of-band `--pubkey`) IS its authority, so this record is single-sig
    /// chain-signed and unguarded for op-class purposes (same rationale as
    /// [`EventKind::GovernanceTurn`]). The producer (the `bundle-install`
    /// handler) is enterprise-only and moat-stripped from the community edition;
    /// the kind lives in the shared taxonomy so both editions compile it
    /// (community never constructs one). HIGH-1: every field is a `u64`, a hex
    /// key, or a structured timestamp — never free-text prose.
    PolicyBundleInstall,
}

impl EventKind {
    /// All 24 variants in declaration order. The wildcard-free match
    /// in `event_payload_kind_matches_variant` is the compile-time
    /// drift catch; this array is for runtime iteration.
    pub const ALL: [Self; 24] = [
        Self::CsqRun,
        Self::OAuthRefresh,
        Self::ArtifactLoad,
        Self::ModelInvoke,
        Self::OutputCapture,
        Self::AccountSwap,
        Self::IdentityMint,
        Self::KeyRotate,
        Self::ReleaseAuth,
        Self::ReplicationAck,
        Self::ReplicationFailed,
        Self::ChainContinuation,
        Self::ChainReGenesis,
        Self::SinkDriftDetected,
        Self::AccountLogout,
        Self::AccountMove,
        Self::SeamEventRejected,
        Self::ProvenanceAnchored,
        Self::ProvenanceCaptureMatrix,
        Self::SeamDuplicateSuppressed,
        Self::GovernanceTurn,
        Self::EatpAttestation,
        Self::McpGateDecision,
        Self::PolicyBundleInstall,
    ];
}

/// Per-event-kind typed payload. Each variant has the minimum field
/// set needed at M01; M02 enriches per-variant fields alongside the
/// schema v1→v2 migration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // ProvenanceAnchoredPayload is a chain record; Boxing adds
                                     // indirection without meaningful performance gain here.
pub enum EventPayload {
    /// See [`EventKind::CsqRun`].
    CsqRun(CsqRunPayload),
    /// See [`EventKind::OAuthRefresh`].
    OAuthRefresh(OAuthRefreshPayload),
    /// See [`EventKind::ArtifactLoad`].
    ArtifactLoad(ArtifactLoadPayload),
    /// See [`EventKind::ModelInvoke`].
    ModelInvoke(ModelInvokePayload),
    /// See [`EventKind::OutputCapture`].
    OutputCapture(OutputCapturePayload),
    /// See [`EventKind::AccountSwap`].
    AccountSwap(AccountSwapPayload),
    /// See [`EventKind::IdentityMint`].
    IdentityMint(IdentityMintPayload),
    /// See [`EventKind::KeyRotate`].
    KeyRotate(KeyRotatePayload),
    /// See [`EventKind::ReleaseAuth`].
    ReleaseAuth(ReleaseAuthPayload),
    /// See [`EventKind::ReplicationAck`].
    ReplicationAck(ReplicationAckPayload),
    /// See [`EventKind::ReplicationFailed`].
    ReplicationFailed(ReplicationFailedPayload),
    /// See [`EventKind::ChainContinuation`].
    ChainContinuation(ChainContinuationPayload),
    /// See [`EventKind::ChainReGenesis`].
    ChainReGenesis(ChainReGenesisPayload),
    /// See [`EventKind::SinkDriftDetected`].
    SinkDriftDetected(SinkDriftDetectedPayload),
    /// See [`EventKind::AccountLogout`].
    AccountLogout(AccountLogoutPayload),
    /// See [`EventKind::AccountMove`].
    AccountMove(AccountMovePayload),
    /// See [`EventKind::SeamEventRejected`].
    SeamEventRejected(SeamEventRejectedPayload),
    /// See [`EventKind::ProvenanceAnchored`].
    ProvenanceAnchored(ProvenanceAnchoredPayload),
    /// See [`EventKind::ProvenanceCaptureMatrix`].
    ProvenanceCaptureMatrix(ProvenanceCaptureMatrixPayload),
    /// See [`EventKind::SeamDuplicateSuppressed`].
    SeamDuplicateSuppressed(SeamDuplicateSuppressedPayload),
    /// See [`EventKind::GovernanceTurn`].
    GovernanceTurn(GovernanceTurnPayload),
    /// See [`EventKind::EatpAttestation`].
    EatpAttestation(EatpAttestationPayload),
    /// See [`EventKind::McpGateDecision`].
    McpGateDecision(McpGateDecisionPayload),
    /// See [`EventKind::PolicyBundleInstall`].
    PolicyBundleInstall(PolicyBundleInstallPayload),
}

impl EventPayload {
    /// Returns the [`EventKind`] discriminant for this payload.
    /// The [`SignedRecord`] custom deserializer enforces
    /// `record.kind == record.payload.kind()`.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        match self {
            Self::CsqRun(_) => EventKind::CsqRun,
            Self::OAuthRefresh(_) => EventKind::OAuthRefresh,
            Self::ArtifactLoad(_) => EventKind::ArtifactLoad,
            Self::ModelInvoke(_) => EventKind::ModelInvoke,
            Self::OutputCapture(_) => EventKind::OutputCapture,
            Self::AccountSwap(_) => EventKind::AccountSwap,
            Self::IdentityMint(_) => EventKind::IdentityMint,
            Self::KeyRotate(_) => EventKind::KeyRotate,
            Self::ReleaseAuth(_) => EventKind::ReleaseAuth,
            Self::ReplicationAck(_) => EventKind::ReplicationAck,
            Self::ReplicationFailed(_) => EventKind::ReplicationFailed,
            Self::ChainContinuation(_) => EventKind::ChainContinuation,
            Self::ChainReGenesis(_) => EventKind::ChainReGenesis,
            Self::SinkDriftDetected(_) => EventKind::SinkDriftDetected,
            Self::AccountLogout(_) => EventKind::AccountLogout,
            Self::AccountMove(_) => EventKind::AccountMove,
            Self::SeamEventRejected(_) => EventKind::SeamEventRejected,
            Self::ProvenanceAnchored(_) => EventKind::ProvenanceAnchored,
            Self::ProvenanceCaptureMatrix(_) => EventKind::ProvenanceCaptureMatrix,
            Self::SeamDuplicateSuppressed(_) => EventKind::SeamDuplicateSuppressed,
            Self::GovernanceTurn(_) => EventKind::GovernanceTurn,
            Self::EatpAttestation(_) => EventKind::EatpAttestation,
            Self::McpGateDecision(_) => EventKind::McpGateDecision,
            Self::PolicyBundleInstall(_) => EventKind::PolicyBundleInstall,
        }
    }
}

// Per-variant payload structs. M01 stores the minimum identifying
// field per kind; M02 enriches each struct alongside the on-disk
// schema migration (see `M02-spec12-schema-v1-to-v2.md`).

/// Payload for [`EventKind::CsqRun`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CsqRunPayload {
    /// The `csq run` invocation id (matches existing
    /// `audit::persist::AuditRecord::run_id`).
    pub run_id: String,
}

/// Payload for [`EventKind::OAuthRefresh`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuthRefreshPayload {
    /// Slot whose token was refreshed.
    pub slot: AccountNum,
    /// Identity UUID (stable across re-login).
    pub identity_uuid: String,
}

/// Payload for [`EventKind::ArtifactLoad`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLoadPayload {
    /// SHA-256 hex of the artifact bundle that was loaded.
    pub artifact_sha256: Sha256Hex,
}

/// Payload for [`EventKind::ModelInvoke`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelInvokePayload {
    /// Model identifier (e.g. `claude-opus-4-7`).
    pub model: String,
    /// Surface that invoked the model (e.g. `cc`, `codex`, `gemini`).
    pub surface: String,
}

/// Payload for [`EventKind::OutputCapture`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputCapturePayload {
    /// SHA-256 hex of the captured output bytes.
    pub output_sha256: Sha256Hex,
}

/// Payload for [`EventKind::AccountSwap`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountSwapPayload {
    /// Slot swapped FROM.
    pub from_slot: AccountNum,
    /// Slot swapped TO.
    pub to_slot: AccountNum,
}

/// Payload for [`EventKind::AccountLogout`].
///
/// SEC-4: validated newtypes only — no email or filesystem path fields.
/// `orphaned_uuid` is the identity UUID string (not a path) from
/// `remove_profiles_entry`; `None` when the UUID is shared by another slot
/// (M13b OD-1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountLogoutPayload {
    /// Slot that was logged out.
    pub slot: AccountNum,
    /// Identity UUID whose `identities/<UUID>/` dir was removed, if this
    /// logout dropped the last reference to that UUID. `None` when the UUID
    /// is still referenced by another slot or no UUID resolved.
    pub orphaned_uuid: Option<String>,
}

/// Payload for [`EventKind::AccountMove`].
///
/// SEC-4: validated newtypes only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountMovePayload {
    /// Source slot.
    pub from_slot: AccountNum,
    /// Destination slot.
    pub to_slot: AccountNum,
}

/// Payload for [`EventKind::IdentityMint`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityMintPayload {
    /// The minted identity UUID.
    pub identity_uuid: String,
    /// The slot the identity is initially bound to.
    pub slot: AccountNum,
}

/// Reason for a signing-key rotation (M04).
///
/// Carried in [`KeyRotatePayload::rotation_reason`] to record the operator's
/// stated reason for rotating the signing key.  Future verifiers and audit
/// consumers can filter on this value.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    /// Routine scheduled rotation (time-based policy).
    Scheduled,
    /// Emergency rotation after key compromise or suspected compromise.
    Compromised,
    /// Operator-initiated rotation without a specific policy trigger.
    Operator,
    /// Rotation mandated by a written policy (e.g. annual, post-incident).
    Policy,
}

impl std::fmt::Display for RotationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationReason::Scheduled => write!(f, "scheduled"),
            RotationReason::Compromised => write!(f, "compromised"),
            RotationReason::Operator => write!(f, "operator"),
            RotationReason::Policy => write!(f, "policy"),
        }
    }
}

impl std::str::FromStr for RotationReason {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "scheduled" => Ok(RotationReason::Scheduled),
            "compromised" => Ok(RotationReason::Compromised),
            "operator" => Ok(RotationReason::Operator),
            "policy" => Ok(RotationReason::Policy),
            other => Err(format!(
                "unknown rotation reason '{}'; expected one of: scheduled, compromised, operator, policy",
                other
            )),
        }
    }
}

/// Payload for [`EventKind::KeyRotate`].
///
/// Extended in M04 to carry the incoming public key and the operator-stated
/// reason for the rotation.  Both new fields use `#[serde(default)]` so that
/// older `chain.json` records (written before M04 shipped) still deserialize
/// without error — `incoming_pubkey` defaults to the all-zeros sentinel and
/// `rotation_reason` defaults to `Operator`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRotatePayload {
    /// The previous key id (now superseded).
    pub previous_key_id: KeyId,
    /// The new key id taking over.
    pub new_key_id: KeyId,
    /// Raw 32-byte public key of the incoming key, hex-encoded.
    ///
    /// Carried here so an offline verifier that only has the chain.json can
    /// reconstruct `new_key_id = "ed25519:<sha256(incoming_pubkey)>"` and
    /// verify the derivation without querying the keychain.
    ///
    /// Defaults to the all-zeros `Ed25519PublicKey` for backward-compat
    /// deserialization of pre-M04 records; verifiers MUST treat the zero
    /// pubkey as "pubkey not recorded" and skip derivation checks.
    #[serde(default)]
    pub incoming_pubkey: Ed25519PublicKey,
    /// Operator-stated reason for the rotation.
    ///
    /// Defaults to [`RotationReason::Operator`] for backward-compat
    /// deserialization of pre-M04 records.
    #[serde(default = "default_rotation_reason")]
    pub rotation_reason: RotationReason,
}

fn default_rotation_reason() -> RotationReason {
    RotationReason::Operator
}

/// Payload for [`EventKind::ReleaseAuth`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAuthPayload {
    /// Release tag (e.g. `v2.14.0`).
    pub release_tag: String,
    /// SHA-256 hex of the authorised artifact.
    pub artifact_sha256: Sha256Hex,
}

/// Payload for [`EventKind::ReplicationAck`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplicationAckPayload {
    /// Sink that acknowledged the anchor.
    pub sink: SinkName,
    /// Sink-assigned id.
    pub sink_id: SinkId,
}

/// Payload for [`EventKind::ReplicationFailed`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplicationFailedPayload {
    /// Sink that rejected or failed the anchor.
    pub sink: SinkName,
    /// Operator-facing reason — already redacted.
    pub reason: RedactedString,
}

/// Payload for [`EventKind::ChainContinuation`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainContinuationPayload {
    /// Sequence number resumed at.
    pub resumed_at_seq: u64,
}

/// Payload for [`EventKind::ChainReGenesis`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainReGenesisPayload {
    /// Reason for re-genesis (e.g. `"key_rotation"`, `"schema_v2"`).
    pub reason: RedactedString,
    /// Optional pointer to the prior chain's terminal canonical hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_chain_terminal_hash: Option<Sha256Hex>,
}

/// Payload for [`EventKind::SinkDriftDetected`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SinkDriftDetectedPayload {
    /// Sink where drift was detected.
    pub sink: SinkName,
    /// The record id whose sink-stored bytes did not match local.
    pub record_id: RecordId,
}

/// Payload for [`EventKind::SeamEventRejected`] (M18 BE seam, F-SEAM-02).
///
/// Metadata-ONLY rejection record. The malformed/unvalidatable inbound event
/// body is written to `.quarantine/` and NEVER into the chain; this record
/// carries only the rejection reason and whatever header fields parsed cleanly.
///
/// HIGH-1 invariant: no raw event body, no free-text human words, no untrusted
/// payload appears here. `reason` is a FIXED-VOCABULARY tag (see
/// [`crate::audit::seam`] `RejectReason::as_tag`), not an echoed error string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeamEventRejectedPayload {
    /// Fixed-vocabulary rejection tag (e.g. `malformed_json`,
    /// `missing_required_field`, `decision_id_not_uuid`, `timestamp_out_of_skew`,
    /// `unregistered_surface`). NEVER an echoed upstream error body.
    pub reason: String,
    /// The `f101_schema_version` from the event, if it parsed; `None` when the
    /// event was too malformed to extract a version.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub f101_schema_version: Option<String>,
    /// The `surface` id from the event, if it parsed; `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub surface: Option<String>,
}

/// Payload for [`EventKind::ProvenanceAnchored`] (M18 BE seam).
///
/// The seam's product record: a loom F101-1 provenance event accepted at the
/// frontier, version-dispatched, and signed/anchored into the chain. The
/// per-developer authorship attestation lands in the SignedRecord `actor` /
/// `trust` slots (via M17 `attest_authorship`), NOT in this payload.
///
/// Key invariants:
/// - `received_bytes_hash` binds `sha256(exact bytes loom emitted)` — csq signs
///   over the EXACT bytes, never a re-canonicalization (F-SEAM-01 sub-case (c)).
/// - `claimed_decision_ts` is EVIDENCE ONLY; chain order is the csq-assigned
///   `SignedRecord.seq` (F-SEAM-04).
/// - `words_hash` is `sha256(canonical(human_words))` — the verbatim words are
///   NEVER persisted into the chain (HIGH-1 redact-then-hash; full depth M21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceAnchoredPayload {
    /// loom-supplied stable event UUID — the idempotent-dedup key (F-SEAM-03).
    ///
    /// For v1+ events this is `sha256(exact received bytes)`, not a UUID.
    /// For the legacy test-version scaffolding it is the loom-supplied UUID.
    pub decision_id: String,
    /// Derived surface identifier (artifact target) — for v1 events this is
    /// derived from `kind`+`payload` (e.g. a journal path, file path, or
    /// `"shell"`/`"human-input"`).
    pub surface: String,
    /// loom's claimed decision timestamp — EVIDENCE ONLY, never chain order.
    pub claimed_decision_ts: String,
    /// `sha256(canonical(human_words))` when the event carried words; `None`
    /// otherwise. The verbatim words are never stored (HIGH-1).
    /// `None` for v1 (v1 has no `words_hash` field; `received_bytes_hash` is
    /// the whole-event commitment).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub words_hash: Option<Sha256Hex>,
    /// The frozen F101-1 schema version this event was decoded against.
    pub f101_schema_version: String,
    /// `sha256(exact received bytes)` — the signed-over artifact (F-SEAM-01).
    pub received_bytes_hash: Sha256Hex,
    /// Epistemic ordering annotation for spans linked across a daemon-down gap
    /// (M20, F-SEAM-03(b)/F-SEAM-06). `Some("wallclock_skew_bounded")` marks a
    /// record whose cross-source ordering relative to its neighbors was derived
    /// from skew-bounded wall-clock, NOT a proven causal `seq` order — the chain
    /// is HONEST that this span's ordering is wall-clock-derived. `None` for the
    /// normal live-ingest path where the csq-assigned `seq` is authoritative.
    ///
    /// Additive + `skip_serializing_if = None`: a record without a gap annotation
    /// serializes byte-identically to the pre-M20 shape (no canonical-hash drift).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ordering_basis: Option<String>,
    /// Intra-source predecessor-gap annotation (M20, F-SEAM-09). `Some(true)`
    /// when this event linked past an unfilled prev_link gap on bounded timeout
    /// (its predecessor never arrived within `PREDECESSOR_WAIT_SECS`) —
    /// the auditor sees the gap was real and the link was timeout-forced.
    /// `None` on the normal in-order path.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub predecessor_missing: Option<bool>,
    // ── v1 fields (additive, skip_serializing_if = None) ──────────────────
    /// prev_link hash-chain predecessor: `None` = genesis, `Some(sha256hex)`.
    /// M18-bind: replaces `source_counter` for per-operator ordering.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prev_link: Option<String>,
    /// Event kind as projected from the v1 wire (`"Decision"`, `"Action"`, etc.).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kind: Option<String>,
    /// Full `operator_ref` from the v1 wire — carries `verified_id`,
    /// `person_id`, and optionally `display_id`. Stored for crypto verification.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operator_ref: Option<OperatorRefRecord>,
    /// v1 wire `session` field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session: Option<String>,
}

/// Serializable projection of the v1 `operator_ref` sub-object stored in the
/// chain record for later cryptographic verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorRefRecord {
    pub verified_id: String,
    pub person_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display_id: Option<String>,
}

/// Payload for [`EventKind::SeamDuplicateSuppressed`] (M20 degraded-reconcile).
///
/// Written when an inbound seam event's `decision_id` is already anchored into
/// the chain — the duplicate is a no-op and this metadata-only record documents
/// the suppression (F-SEAM-03(a)). Emitted at most ONCE per `decision_id`
/// (F-SEAM-05 amplification defense via the `.seam-dedup-index` sidecar).
///
/// HIGH-1: carries only the header projection (id / surface), never a
/// raw event body or free-text.
///
/// M18-bind: `source_counter` removed — the v1 ordering model uses `prev_link`
/// hash-chains, not monotonic counters. `surface` is retained as a human-readable
/// annotation (the derived artifact target).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeamDuplicateSuppressedPayload {
    /// The already-anchored loom-supplied event decision_id that was replayed.
    pub decision_id: String,
    /// Derived surface the duplicate claimed.
    pub surface: String,
}

// ---------------------------------------------------------------------------
// M19 — Provenance capture-capability matrix (§12.20)
// ---------------------------------------------------------------------------

/// Capture capability state for one surface.
///
/// `Wired` means csq has an active ingestion hook for this surface and will
/// receive F101-1 provenance events from it. `Unwired` means no hook is
/// active — sessions on this surface are attested via csq-lane `CsqRun`
/// records only.
///
/// Per F-SEAM-07: absence of provenance events MUST NOT be interpreted as
/// "no decisions made". This enum makes the distinction explicit on the chain:
/// `Wired` + no events = genuine "no decisions"; `Unwired` + no events =
/// "capture not active, decisions unknown".
///
/// In production (M19) ALL surfaces are `Unwired` because
/// `VersionRegistry::production()` has zero registered decoder arms.
/// M18-bind will flip the first surface to `Wired`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    /// An active ingestion hook is wired for this surface.
    Wired,
    /// No ingestion hook is active for this surface.
    Unwired,
}

/// Per-surface capture status entry within a [`ProvenanceCaptureMatrixPayload`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SurfaceCaptureStatus {
    /// Data-driven surface registry key (e.g. `cc`, `codex`, `gemini`).
    pub surface: String,
    /// Whether csq has an active ingestion hook for this surface.
    pub capture: CaptureState,
}

/// Payload for [`EventKind::ProvenanceCaptureMatrix`] (M19).
///
/// Declares csq's current provenance capture capability per known surface.
/// Emitted at daemon start and whenever the content-hash changes (sidecar
/// dedup). Carries NO raw event bodies, NO free-text, NO surface-derived
/// content (HIGH-1 compliant). The surface list comes from `SurfaceRegistry`
/// (data-driven, F-SEAM-08); it is NOT hardcoded.
///
/// Addresses F-SEAM-07 (absence-of-provenance is not "no decisions made"):
/// an operator reading this record can distinguish "session happened +
/// capture unwired" from "session happened + decisions genuinely absent".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceCaptureMatrixPayload {
    /// Per-surface capture status, sorted alphabetically by surface id for
    /// deterministic content-hashing and chain diffing.
    pub surfaces: Vec<SurfaceCaptureStatus>,
}

// ---------------------------------------------------------------------------
// #784 — per-decision EATP attestation (M3): per-turn governance record
// ---------------------------------------------------------------------------

/// Token usage projection for a completed governed turn.
///
/// A shared (community-compiled) numeric projection of the Phase-2b
/// `TokenUsage` (which lives in the enterprise-only `phase2b` tree and cannot
/// be referenced from this shared module). All fields are optional because
/// some Anthropic-compatible 3P endpoints omit sub-counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceTokenUsage {
    /// Prompt/input tokens reported by the provider.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub input_tokens: Option<u32>,
    /// Completion/output tokens reported by the provider.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub output_tokens: Option<u32>,
    /// Cache-creation input tokens (Anthropic prompt caching), when reported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cache_creation_input_tokens: Option<u32>,
    /// Cache-read input tokens (Anthropic prompt caching), when reported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cache_read_input_tokens: Option<u32>,
}

/// Payload for [`EventKind::GovernanceTurn`] (#784, M3 per-decision EATP
/// attestation).
///
/// One record per per-turn governance event emitted by the live Phase-2b
/// interactive enforcement session. The six `GovernanceEvent` variants
/// (`csq-core/src/phase2b/provider_client.rs`) project onto this single payload,
/// distinguished by the fixed-vocabulary [`Self::event_class`] tag. The decision
/// VERDICT is carried on [`SignedRecord::verification_level`] (a separate axis),
/// NOT in this payload.
///
/// HIGH-1 invariant: no raw untrusted free-text. The operator override
/// justification is stored redacted ([`RedactedString`]) AND as
/// `justification_hash = sha256(redacted)` (the tamper-evidence binding,
/// mirroring [`ProvenanceAnchoredPayload::words_hash`]); the failover
/// `Transport { detail }` free-text is dropped entirely (only the discriminant
/// is kept).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceTurnPayload {
    /// The live session id (`interactive-live-<pid>-<nonce>`) — the dedup-key
    /// namespace component AND the session this governance event belongs to.
    /// Persisted in the payload (not only the `authority` blob) so the M20 dedup
    /// index rebuild can re-derive the `gov:<session_id>:<record_seq>` key from
    /// the on-chain record alone (mirrors `CsqRunPayload::run_id`).
    pub session_id: String,
    /// Session-monotonic record ordinal (the second dedup-key component). Counts
    /// flushed governance records within the session; with `session_id` it forms
    /// the globally-unique `gov:<session_id>:<record_seq>` idempotency key.
    pub record_seq: u64,
    /// Fixed-vocabulary event class: `turn_started`, `turn_completed`,
    /// `governance_failure`, `failover`, `governance_override`,
    /// `residency_enforcement` (M5). NEVER free-text.
    pub event_class: String,
    /// Session-level turn number the event pertains to (`0` for `failover`,
    /// which carries no turn index).
    pub turn: u32,
    /// Provider catalog id involved (`event.provider_id` / `Failover.to`) —
    /// catalog id only, never a secret. `None` where the event carries none.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_id: Option<String>,
    /// `Failover.from` provider catalog id (failover records only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub failover_from: Option<String>,
    /// Fixed-vocabulary failover reason discriminant (`rate_limited`,
    /// `service_unavailable`, `transport`). The `Transport { detail }` free-text
    /// is DROPPED (HIGH-1) — only the discriminant is recorded.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub failover_reason: Option<String>,
    /// Token usage reported for a completed turn (numeric counts only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub usage: Option<GovernanceTokenUsage>,
    /// `sha256(redacted-justification)` for an operator override — the
    /// tamper-evidence binding (the verbatim words are never stored raw).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub justification_hash: Option<Sha256Hex>,
    /// The operator override justification, redacted ([`RedactedString`]) — the
    /// human-readable reason-of-record an auditor reads. Present on
    /// `governance_override` records.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub justification_redacted: Option<RedactedString>,
    /// Governance failure reason (already redacted at source), re-wrapped for
    /// structural type-safety. Present on `governance_failure` records.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub governance_reason: Option<RedactedString>,
    /// #784 follow-up: the ISO-8601 UTC time the turn was GOVERNED (captured at
    /// projection-build time). Distinct from `SignedRecord.ts` (the chain-WRITE
    /// time, reassigned by the writer). This is the `timestamp` input to the
    /// frozen cross-SDK kailash projection, so a witness recomputes against the
    /// SAME value the producer used. `None` when no kailash projector is wired
    /// (community / test paths). See an internal journal entry
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub governed_at: Option<String>,
    /// #784 follow-up: the cross-SDK kailash-canonical projection hash for this
    /// governance decision (`compute_hash_kailash_rs` over the frozen
    /// GovernanceTurn → EATP anchor mapping, produced BY the `the enterprise seam crate`
    /// seam via an injected projector — spec 18 §18.1). Stored INSIDE the signed
    /// `CanonicalView`, so the existing Ed25519 signature makes it tamper-evident.
    /// `None` when no projector is wired (community / pre-witness / test paths).
    /// Honest-host grade: an external witness recomputes + corroborates this once
    /// one exists; until then it is a same-key self-consistency checkpoint.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kailash_canonical_hash: Option<String>,
    /// #793: the session-constant auth mode that produced this governed turn —
    /// `"subscription"` (reference-CLI capture, degraded tier) or `"direct-api"`
    /// (paid-key native client, the moat). The maintainer's "segregate + tag"
    /// requirement: every governed turn records which auth path drove it. Stored
    /// inside the signed `CanonicalView` (the Ed25519 signature covers it).
    /// `skip_serializing_if`/`default` keep records written before this field
    /// (and untagged mock/test sessions) byte-identical + chain-verifiable.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub auth_mode: Option<String>,
    /// M5: the residency verdict for a `residency_enforcement` record —
    /// fixed-vocabulary `"pass"` / `"block"` (the `EnvelopeVerdict` projected to a
    /// binary admit/deny). Records BOTH allowed (`pass`) and denied (`block`)
    /// provider requests so an auditor can verify every provider request was
    /// checked. `None` on all non-residency event classes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub residency_verdict: Option<String>,
    /// M5: the operator-authored `policy_name` of the residency policy that
    /// produced the verdict (`residency_enforcement` records only). Not a secret.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub residency_policy_name: Option<String>,
    /// M5: `sha256` of the canonical serialization of the residency policy that
    /// applied — binds the attestation to the EXACT policy in force, so an auditor
    /// can prove which policy a verdict was decided under. `residency_enforcement`
    /// records only. `skip_serializing_if`/`default` (like every field above) keep
    /// pre-M5 records byte-identical + chain-verifiable.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub residency_policy_hash: Option<String>,
}

/// Payload for [`EventKind::McpGateDecision`] (M6 T6.2 Shard 4 — the
/// spawn-boundary MCP-proxy gate decision attestation).
///
/// One record per gated `tools/call` the `csq mcp-proxy` interposes on. The
/// verdict is on the tool-call REQUEST at the spawn boundary — NOT the model's
/// in-loop decision to make the call — so [`Self::enforcement_fidelity`] is the
/// honest constant `"spawn_boundary_only"`, distinguishing it from the cc/3P
/// in-loop [`GovernanceTurnPayload`] stream (spec 25 §25.12).
///
/// HIGH-1 invariant: no raw untrusted free-text. [`Self::tool`] is a bounded
/// MCP-declared tool identifier (the same value the proxy echoes in its denial
/// message — `serde` escapes any metacharacter, and the daemon route caps its
/// length); [`Self::verdict`], [`Self::cli`], and [`Self::enforcement_fidelity`]
/// are fixed-vocabulary tags.
///
/// Idempotency: `session_nonce` + `record_seq` form the globally-unique
/// `mcp:<session_nonce>:<record_seq>` dedup key (mirrors
/// [`GovernanceTurnPayload`]'s `session_id`/`record_seq`), re-derivable from the
/// on-chain record alone so the M20 in-lock dedup-index rebuild survives a
/// sidecar drop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpGateDecisionPayload {
    /// Per-proxy-process nonce (`mcp-proxy-<pid>-<nonce>`) — the dedup-key
    /// namespace component AND the proxy session this decision belongs to.
    pub session_nonce: String,
    /// Proxy-session-monotonic decision ordinal (the second dedup-key
    /// component); with `session_nonce` it forms the globally-unique
    /// `mcp:<session_nonce>:<record_seq>` idempotency key.
    pub record_seq: u64,
    /// The spawned CLI whose MCP traffic was gated: `"codex"` | `"gemini"`.
    pub cli: String,
    /// The MCP-declared tool identifier that was gated (bounded; not a secret;
    /// not free-text prose). E.g. `"mcp__fs__read"`.
    pub tool: String,
    /// Fixed-vocabulary gate verdict: `"pass"` (forwarded) | `"block"`
    /// (allow-list miss, denied) | `"escalate"` (never-delegated, denied).
    pub verdict: String,
    /// Honest enforcement-fidelity label — always `"spawn_boundary_only"` for
    /// this record kind (the proxy gates the tool-call request at the spawn
    /// boundary, not the model's in-loop decision). Reserved as a field (rather
    /// than implied by the kind) so the T6.5 fidelity matrix + the compliance
    /// report can read it uniformly across event kinds.
    pub enforcement_fidelity: String,
}

/// Payload for [`EventKind::PolicyBundleInstall`] (#787 b2b — the audited
/// own-op record appended when `csq audit bundle-install` succeeds).
///
/// HIGH-1 invariant: no raw untrusted free-text. Every field is a `u64`, a hex
/// public key, or a structured ISO-8601 timestamp — an auditor can tie the
/// install to the exact bundle version and verifying key without any operator
/// prose entering the signed chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleInstallPayload {
    /// The installed bundle's monotonic version. Equals the new rollback floor
    /// after this install completes (see `phase2b::bundle_floor::write_bundle_floor`
    /// — a plain code span, not an intra-doc link: this SHARED payload documents
    /// under the community feature set where the enterprise-only `phase2b` module
    /// is absent, so a `[...]` link would fail the broken-link doc gate).
    pub bundle_version: u64,
    /// The out-of-band Ed25519 verifying key the bundle's detached signature was
    /// checked against (the operator's `--pubkey`). This is PUBLIC key material —
    /// never a secret — stored verbatim so a governance auditor can tie the
    /// install to the exact org-admin key with no indirection.
    ///
    /// A validated [`Ed25519PublicKey`] (NOT a raw `String`): it serializes as a
    /// 64-char lowercase hex string but deserialize-VALIDATES to exactly 32 bytes
    /// of hex (via `hex_array_32`), so the HIGH-1 "no free-text" invariant is
    /// structurally enforced at the chain boundary — a tampered record with a
    /// malformed key is rejected at parse time, never reaching a consumer.
    pub bundle_pubkey: Ed25519PublicKey,
    /// ISO-8601 UTC timestamp the installer captured at record-append time
    /// (after the bundle + floor were persisted, before the chain append).
    /// DISTINCT from [`SignedRecord::ts`] (the chain-write time the writer stamps
    /// inside the lock, a slightly later instant) — this is the producer's own
    /// clock, the [`GovernanceTurnPayload::governed_at`] analogue for bundle
    /// installs.
    pub installed_at: String,
}

/// Payload for [`EventKind::EatpAttestation`] (M3 §10.5 W2b/W3 — born-canonical
/// EATP genesis record and per-session-close attestations).
///
/// Carries all `csq_trust_contract::CanonicalAnchorInput` fields verbatim plus
/// the the enterprise edition canonical hash, so a daemon-side guard can re-derive and
/// verify the genesis via the injected `EatpGenesisGuard` without re-encoding.
///
/// HIGH-1 invariant: no raw untrusted free-text. Every field is either a
/// fixed-vocabulary tag, a hash, a structured timestamp, or operator-controlled
/// metadata whose non-emptiness is validated by `attest_born_canonical_genesis`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EatpAttestationPayload {
    /// kailash `anchor_id` — stable within a chain genesis:
    /// `"eatp-genesis:<eatp_chain_id>"`.
    pub anchor_id: String,
    /// Monotonic EATP sequence within the kailash attestation anchor; always 0
    /// for genesis records.
    pub sequence: u64,
    /// Previous anchor hash; `None` for genesis records (the kailash canonical
    /// encoder uses the zero-hex sentinel; we do NOT store it here).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub previous_hash: Option<String>,
    /// Agent or principal producing this attestation; `"csq-ee"` for W2b genesis.
    pub agent_id: String,
    /// Fixed-vocabulary action tag: `"eatp_genesis"` for W2b genesis;
    /// `"session_close_attestation"` for W3 session-close records.
    pub action: String,
    /// kailash verification-level string. `"SIGNED_ATTESTATION"` for enterprise
    /// EATP genesis and session-close attestations (the enterprise 6-level grade).
    pub verification_level: String,
    /// Optional kailash envelope id. `None` for genesis records.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub envelope_id: Option<String>,
    /// Outcome tag: `"success"` for genesis records; fixed-vocabulary for W3.
    pub result: String,
    /// ISO-8601 UTC timestamp passed to `attest_born_canonical_genesis` (W2b) or
    /// the W3 attestation function. DISTINCT from [`SignedRecord::ts`] (the
    /// chain-write time, set by the writer). Stored here so the daemon guard
    /// re-uses the EXACT same value the producer used — the
    /// [`GovernanceTurnPayload::governed_at`] analogue for EATP attestations.
    pub attestation_ts: String,
    /// The the enterprise edition canonical projection hash produced by
    /// `attest_born_canonical_genesis` (W2b) or the W3 equivalent. Stored INSIDE
    /// the signed `CanonicalView`, so the Ed25519 signature makes it
    /// tamper-evident. `None` is structurally BLOCKED for production genesis
    /// records but kept `Option` for forward compatibility with record shapes not
    /// yet assigned a canonical hash.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kailash_canonical_hash: Option<String>,
    /// Non-empty JSON object metadata distinguishing this genesis as born-canonical
    /// (`GenesisCanonicalStatus::BornCanonical`) from the legacy kailash-py
    /// empty-metadata shape (`AmbiguousLegacyTwin`). REQUIRED non-empty for W2b
    /// genesis records; validated by `attest_born_canonical_genesis` before
    /// emission.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata_json: Option<String>,
}

// ---------------------------------------------------------------------------
// EATP attestation typed placeholder wrappers (M02, Amendment 3)
// ---------------------------------------------------------------------------

/// Opaque wrapper for an EATP Actor attestation blob.
///
/// Carries a forward-compatible `serde_json::Value` so the on-disk schema
/// can store EATP actor claims without importing the vendored EATP crate.
/// Per the M01 structural invariant no `kailash::*` / `eatp::*` paths appear
/// here; the concrete EATP engine (M07+) will deserialize from this value.
///
/// # Wire format
///
/// Serializes / deserializes as the underlying JSON value verbatim.
/// An empty object `{}` is a valid placeholder for "actor present but
/// minimally populated."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EatpActor(pub serde_json::Value);

/// Opaque wrapper for an EATP Authority attestation blob.
///
/// Same rationale and shape as [`EatpActor`]. The authority blob identifies
/// the issuing authority (M07 key-custody milestone will populate this
/// with a real authority descriptor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EatpAuthority(pub serde_json::Value);

impl EatpAuthority {
    /// M3 §10.5 W3 (H3) — build a session-close authority blob from ONLY the
    /// three opaque, install/session-scoped identifiers. The tuple constructor
    /// (`EatpAuthority(serde_json::Value)`) is an untyped redaction-bypass channel:
    /// any caller can stuff a host fingerprint, a username, or any PII into the
    /// blob and it serializes verbatim. This constructor is the typed gate — it
    /// accepts EXACTLY `instance_id` (random, install-scoped), `session_id` (the
    /// daemon-minted session id), and `signing_key_id` (the PUBLIC key fingerprint,
    /// never the private seed). No field can carry host fingerprint / PII by
    /// construction, so a record built through it is H3-safe.
    ///
    /// The keys are emitted in a fixed alphabetical order so the resulting JSON is
    /// deterministic regardless of the serde map backend.
    #[must_use]
    pub fn new_typed(instance_id: &str, session_id: &str, signing_key_id: &str) -> Self {
        // `Map` preserves insertion order under `serde_json`'s default
        // (`preserve_order` off → `BTreeMap`, alphabetical); inserting in
        // alphabetical order keeps the wire form stable under either backend.
        let mut map = serde_json::Map::new();
        map.insert(
            "instance_id".to_string(),
            serde_json::Value::String(instance_id.to_string()),
        );
        map.insert(
            "session_id".to_string(),
            serde_json::Value::String(session_id.to_string()),
        );
        map.insert(
            "signing_key_id".to_string(),
            serde_json::Value::String(signing_key_id.to_string()),
        );
        EatpAuthority(serde_json::Value::Object(map))
    }
}

/// Opaque wrapper for an EATP Trust attestation blob.
///
/// Same rationale and shape as [`EatpActor`]. The trust blob carries the
/// Verification Gradient tier and operating-envelope constraints (M07+).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EatpTrust(pub serde_json::Value);

// ---------------------------------------------------------------------------
// F-LEDGER-02 append-FIRST op-phase envelope (M13)
// ---------------------------------------------------------------------------

/// Terminal result carried by an [`OpPhase::Outcome`] record.
///
/// `Ok` records a side effect that completed successfully; `Failed` records
/// a side effect that terminated with an error. The failure reason is a
/// [`RedactedString`] — it is routed through `redact_tokens` at construction
/// per `rules/security.md` §2 (the reason may quote an OS / keychain error
/// body that echoes secret-derivable bytes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum OpOutcome {
    /// The side effect completed successfully.
    Ok,
    /// The side effect terminated with an error.
    Failed {
        /// Redacted, operator-facing failure reason.
        reason: RedactedString,
    },
}

/// F-LEDGER-02 append-FIRST phase marker for a side-effecting operation.
///
/// A side-effecting op emits TWO chain records that share one
/// `correlation_id`: an [`OpPhase::Intent`] appended AND drained (durably
/// persisted) BEFORE the side effect runs, and an [`OpPhase::Outcome`]
/// appended AFTER the side effect terminates. A crash or kill between the
/// two leaves a visible "intent without outcome" on the chain — the
/// F-LEDGER-02 detectable state. `csq doctor` surfaces such orphans.
///
/// The intent and outcome records carry the SAME `kind` + `payload` (they
/// describe the same logical op); only the `op_phase` envelope differs. The
/// `correlation_id` is a per-op [`RecordId`] (ULID / UUIDv7 shape) generated
/// once and embedded in both records, so orphan detection is a single
/// linear scan keyed on `correlation_id`.
///
/// # Why a correlation id rather than the intent's `record_id`
///
/// `record_id` is also a [`RecordId`], but binding the outcome to the
/// intent via an explicit `correlation_id` keeps the linkage independent of
/// the writer's record-id assignment and survives any future change to how
/// `record_id` is minted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum OpPhase {
    /// Pre-operation intent: "csq is about to do X, authorized by Y."
    /// Appended and drained before the side effect runs.
    Intent {
        /// Correlates this intent with its outcome record.
        correlation_id: RecordId,
    },
    /// Post-operation outcome: "X succeeded / failed."
    /// Appended after the side effect terminates.
    Outcome {
        /// The `correlation_id` of the intent this outcome closes.
        correlation_id: RecordId,
        /// Terminal result of the side effect.
        result: OpOutcome,
    },
}

impl OpPhase {
    /// Returns the `correlation_id` shared by an intent / outcome pair.
    #[must_use]
    pub fn correlation_id(&self) -> &RecordId {
        match self {
            OpPhase::Intent { correlation_id } => correlation_id,
            OpPhase::Outcome { correlation_id, .. } => correlation_id,
        }
    }
}

// ---------------------------------------------------------------------------
// The signed record
// ---------------------------------------------------------------------------

/// The on-disk schema-v2 record. M01 defines the struct; M02 lands
/// the writer that serialises it to `<base_dir>/audit/chain.jsonl`.
///
/// # `schema_version` is `String`
///
/// Per spec 12 §12.7 the schema version is a const string (`"2"` for
/// v2 records). v1 records carried `"1"`. Holding the type as `String`
/// preserves wire compatibility with the v1 [`crate::audit::persist::AuditRecord`]
/// writer; the M02 drain dispatcher dispatches on this string before
/// strict-decoding into a typed shape.
///
/// # `deny_unknown_fields` + `#[non_exhaustive]` parent enums
///
/// The struct is strict; future field additions bump the version
/// AND ship a parallel typed shape rather than extending this one.
///
/// # `kind` / `payload.kind()` consistency
///
/// `Deserialize` enforces `record.kind == record.payload.kind()`.
/// An attacker-crafted record with skewed kind/payload is rejected
/// at deserialize time, so the verifier and the consumer always
/// agree on what the record is.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedRecord {
    /// Schema version (string). `"2"` for the M01/M02 schema.
    pub schema_version: String,
    /// Unique per-record id.
    pub record_id: RecordId,
    /// Chain identifier — install-scoped, set at first genesis,
    /// re-issued on `ChainReGenesis`. M05's `verify_integrity`
    /// asserts every record in a chain file shares the same
    /// `chain_id`. Stored as a [`RecordId`] because the same shape
    /// constraints apply.
    pub chain_id: RecordId,
    /// Monotonic sequence within this chain, starting at 0.
    pub seq: u64,
    /// SHA-256 of the previous record's canonical form. Genesis
    /// records carry [`Sha256Hex::GENESIS`].
    pub prev_hash: Sha256Hex,
    /// Event taxonomy discriminant. MUST equal `payload.kind()`.
    pub kind: EventKind,
    /// Typed per-kind payload.
    pub payload: EventPayload,
    /// ISO-8601 UTC `+00:00` timestamp (matches the cross-SDK
    /// canonical-form contract).
    pub ts: String,
    /// Identifier of the key that signed this record.
    pub key_id: KeyId,
    /// SHA-256 of THIS record's canonical form (excluding `signature`).
    pub canonical_hash: Sha256Hex,
    /// Ed25519 signature over `canonical_hash`.
    pub signature: Ed25519Signature,

    // ── EATP attestation fields (M02, Amendment 3) ──────────────────────────
    // All optional with serde(default) so v1-era records and records
    // produced before M07 key-custody deserialize cleanly. The M07
    // engine will populate these on new records; older records carry None.
    /// EATP Actor attestation blob. Identifies the agent or human
    /// principal that triggered the audited event. `None` until M07.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<EatpActor>,

    /// EATP Authority attestation blob. Identifies the issuing
    /// authority for this record's trust claim. `None` until M07.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<EatpAuthority>,

    /// EATP Trust attestation blob. Carries Verification Gradient tier
    /// and operating-envelope constraints. `None` until M07.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<EatpTrust>,

    /// ISO-8601 UTC timestamp when the EATP attestation window opened.
    /// `None` until M07.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eatp_start_ts: Option<String>,

    /// ISO-8601 UTC timestamp when the EATP attestation window closed.
    /// `None` until M07.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eatp_end_ts: Option<String>,

    /// F-LEDGER-02 append-FIRST op-phase envelope (M13). `None` for every
    /// record that is not part of an intent / outcome pair — which is every
    /// record written before M13 and every op-FIRST (replay-safe) op. When
    /// `Some`, this record is either the pre-op intent or the post-op
    /// outcome of a side-effecting operation. Skipped on serialize when
    /// `None` so pre-M13 records remain byte-identical in canonical form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_phase: Option<OpPhase>,

    /// M3a — explicit PACT verification level for this record. `None` for
    /// every record written before M3a (legacy); skipped on serialize when
    /// `None` so pre-M3a records remain byte-identical in canonical form.
    /// When `Some`, the value is signed as part of the canonical hash.
    ///
    /// The ONLY level stamped by the op-emit path is `AutoApproved` —
    /// see `PRIMARY METHODOLOGICAL DIRECTIVE 3` in the M3a contract.
    /// `SIGNED_ATTESTATION` / `PEER_REVIEWED` are reserved for Phase-2b
    /// turn-events (M3 T3.2) and MUST NOT be emitted here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_level: Option<crate::audit::eatp_canonical::VerificationLevel>,
}

impl SignedRecord {
    /// Returns the genesis-record sentinel as the canonical
    /// [`Sha256Hex`] type.
    #[must_use]
    pub fn genesis_prev_hash() -> Sha256Hex {
        Sha256Hex::genesis()
    }
}

// Custom Deserialize: strict shape + kind/payload consistency check.
// `deny_unknown_fields` is enforced by the derive on the helper, and
// the post-deserialize predicate catches the kind/payload skew that a
// derive-only Deserialize would silently accept.
impl<'de> Deserialize<'de> for SignedRecord {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // `deny_unknown_fields` is enforced by the derive on the helper.
        // The EATP fields use `#[serde(default)]` so records written
        // before M07 (which omit these fields) deserialize without error.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: String,
            record_id: RecordId,
            chain_id: RecordId,
            seq: u64,
            prev_hash: Sha256Hex,
            kind: EventKind,
            payload: EventPayload,
            ts: String,
            key_id: KeyId,
            canonical_hash: Sha256Hex,
            signature: Ed25519Signature,
            #[serde(default)]
            actor: Option<EatpActor>,
            #[serde(default)]
            authority: Option<EatpAuthority>,
            #[serde(default)]
            trust: Option<EatpTrust>,
            #[serde(default)]
            eatp_start_ts: Option<String>,
            #[serde(default)]
            eatp_end_ts: Option<String>,
            #[serde(default)]
            op_phase: Option<OpPhase>,
            #[serde(default)]
            verification_level: Option<crate::audit::eatp_canonical::VerificationLevel>,
        }
        let raw = Raw::deserialize(d)?;
        if raw.kind != raw.payload.kind() {
            return Err(D::Error::custom(format!(
                "SignedRecord.kind ({:?}) does not match payload.kind() ({:?})",
                raw.kind,
                raw.payload.kind()
            )));
        }
        Ok(Self {
            schema_version: raw.schema_version,
            record_id: raw.record_id,
            chain_id: raw.chain_id,
            seq: raw.seq,
            prev_hash: raw.prev_hash,
            kind: raw.kind,
            payload: raw.payload,
            ts: raw.ts,
            key_id: raw.key_id,
            canonical_hash: raw.canonical_hash,
            signature: raw.signature,
            actor: raw.actor,
            authority: raw.authority,
            trust: raw.trust,
            eatp_start_ts: raw.eatp_start_ts,
            eatp_end_ts: raw.eatp_end_ts,
            op_phase: raw.op_phase,
            verification_level: raw.verification_level,
        })
    }
}

// ---------------------------------------------------------------------------
// Serde helpers — hex-encoded fixed-length byte arrays
// ---------------------------------------------------------------------------

mod hex_array_32 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        // Reject uppercase hex up-front so the cross-SDK canonical form
        // is preserved on round-trip.
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("uppercase hex not allowed"));
        }
        if s.len() != 64 {
            return Err(D::Error::custom(format!(
                "expected 32-byte hex (64 chars), got {}",
                s.len()
            )));
        }
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod hex_array_64 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("uppercase hex not allowed"));
        }
        if s.len() != 128 {
            return Err(D::Error::custom(format!(
                "expected 64-byte hex (128 chars), got {}",
                s.len()
            )));
        }
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// M3 §10.5 W3 (H3): `EatpAuthority::new_typed` admits ONLY the three opaque
    /// identifiers and emits them as a 3-key string object — no field can carry a
    /// host fingerprint / PII through the typed gate, and the key set is exact.
    #[test]
    fn eatp_authority_new_typed_carries_only_opaque_ids() {
        let authority = EatpAuthority::new_typed("instance-xyz", "session-abc", "ed25519:deadbeef");
        let obj = authority
            .0
            .as_object()
            .expect("authority must serialize as a JSON object");
        // Exactly the three opaque fields — no extra channel.
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["instance_id", "session_id", "signing_key_id"]);
        // Every value is a string (no nested object / number that could smuggle data).
        assert!(
            obj.values().all(|v| v.is_string()),
            "all values are strings"
        );
        assert_eq!(obj["instance_id"], serde_json::json!("instance-xyz"));
        assert_eq!(obj["session_id"], serde_json::json!("session-abc"));
        assert_eq!(obj["signing_key_id"], serde_json::json!("ed25519:deadbeef"));
    }

    /// The wire form is key-stable (deterministic) regardless of construction.
    #[test]
    fn eatp_authority_new_typed_wire_form_is_deterministic() {
        let a = EatpAuthority::new_typed("i", "s", "k");
        let b = EatpAuthority::new_typed("i", "s", "k");
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    fn sample_record() -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01HZ7Y2N3M4P5Q6R7S8T9V0WXY").unwrap(),
            // chain_id is a ULID: 26 Crockford Base32 chars (no I/L/O/U).
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "run-001".to_string(),
            }),
            ts: "2026-05-28T12:34:56+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        }
    }

    // -- Identifier validators -----------------------------------------------

    #[test]
    fn record_id_rejects_path_traversal() {
        assert!(matches!(
            RecordId::try_new("foo/../bar"),
            Err(IdError::Charset {
                what: "path separator",
                ..
            }) | Err(IdError::Charset {
                what: "path traversal '..'",
                ..
            })
        ));
    }

    #[test]
    fn record_id_rejects_crlf() {
        assert!(matches!(
            RecordId::try_new("foo\r\nbar"),
            Err(IdError::Charset { what: "CRLF", .. })
        ));
    }

    #[test]
    fn record_id_rejects_non_ulid_non_uuidv7() {
        // Old-style alphanumeric-with-dashes tokens are now rejected.
        assert!(matches!(
            RecordId::try_new("short"),
            Err(IdError::Shape { .. })
        ));
        assert!(matches!(
            RecordId::try_new("chain-test-001"),
            Err(IdError::Shape { .. })
        ));
    }

    #[test]
    fn record_id_accepts_ulid_shape() {
        // Valid 26-char Crockford Base32 ULID — no I/L/O/U.
        assert!(RecordId::try_new("01HZ7Y2N3M4P5Q6R7S8T9V0WXY").is_ok());
    }

    #[test]
    fn record_id_rejects_ulid_with_forbidden_chars() {
        // 'I' is excluded from Crockford Base32.
        let bad = "01IZ7Y2N3M4P5Q6R7S8T9V0WXY";
        assert_eq!(bad.len(), 26);
        assert!(
            RecordId::try_new(bad).is_err(),
            "ULID with 'I' must be rejected"
        );
    }

    #[test]
    fn record_id_accepts_uuidv7_shape() {
        // Canonical UUIDv7: version nibble 7, variant nibble 8-b, lowercase hex.
        assert!(RecordId::try_new("01931234-5678-7abc-8def-0123456789ab").is_ok());
    }

    #[test]
    fn record_id_rejects_uuidv4_version_nibble() {
        // UUIDv4 has version nibble 4, not 7.
        assert!(
            RecordId::try_new("00000000-0000-4000-8000-000000000001").is_err(),
            "UUIDv4 must be rejected (version nibble 4)"
        );
    }

    #[test]
    fn key_id_rejects_missing_prefix() {
        assert!(matches!(
            KeyId::try_new(format!("rsa:{}", "0".repeat(64))),
            Err(IdError::Shape { .. })
        ));
    }

    #[test]
    fn key_id_rejects_uppercase_hex() {
        assert!(matches!(
            KeyId::try_new(format!("ed25519:{}", "F".repeat(64))),
            Err(IdError::Charset {
                what: "non-lowercase-hex in body",
                ..
            })
        ));
    }

    #[test]
    fn key_id_accepts_canonical_shape() {
        assert!(KeyId::try_new(format!("ed25519:{}", "a".repeat(64))).is_ok());
    }

    #[test]
    fn sha256_hex_rejects_uppercase() {
        assert!(matches!(
            Sha256Hex::try_new("A".repeat(64)),
            Err(IdError::Charset {
                what: "uppercase hex",
                ..
            })
        ));
    }

    #[test]
    fn sha256_hex_rejects_wrong_length() {
        assert!(matches!(
            Sha256Hex::try_new("0".repeat(63)),
            Err(IdError::Length { .. })
        ));
    }

    #[test]
    fn sink_name_rejects_crlf() {
        assert!(matches!(
            SinkName::try_new("evil\r\nx"),
            Err(IdError::Charset { .. })
        ));
    }

    #[test]
    fn sink_name_rejects_uppercase() {
        assert!(matches!(
            SinkName::try_new("Rekor"),
            Err(IdError::Charset {
                what: "non-[a-z0-9-] character",
                ..
            })
        ));
    }

    #[test]
    fn sink_name_accepts_lowercase_alnum_dash() {
        assert!(SinkName::try_new("csq-ledger-v2").is_ok());
    }

    #[test]
    fn sink_id_rejects_control_chars() {
        assert!(matches!(
            SinkId::try_new("rekor\x01id"),
            Err(IdError::Charset { .. })
        ));
    }

    #[test]
    fn sink_id_accepts_typical_shapes() {
        assert!(SinkId::try_new("rekor:12345").is_ok());
        assert!(SinkId::try_new("etag.abc-123_x").is_ok());
    }

    // -- Hex shim length + case enforcement ----------------------------------

    #[test]
    fn ed25519_public_key_rejects_wrong_length_hex() {
        // 66 hex chars = 33 bytes — wrong length for pubkey.
        let json = serde_json::Value::String("0".repeat(66));
        let result: Result<Ed25519PublicKey, _> = serde_json::from_value(json);
        assert!(result.is_err(), "wrong-length pubkey hex must be rejected");
    }

    #[test]
    fn ed25519_public_key_rejects_uppercase_hex() {
        let json = serde_json::Value::String("A".repeat(64));
        let result: Result<Ed25519PublicKey, _> = serde_json::from_value(json);
        assert!(result.is_err(), "uppercase pubkey hex must be rejected");
    }

    #[test]
    fn ed25519_public_key_rejects_non_hex_charset() {
        // 64 lowercase chars but 'g' is outside [0-9a-f] — must fail `hex::decode`.
        // Guards the #787 b2b `bundle_pubkey` chain-parse boundary: a tampered
        // record with a non-hex key is rejected before reaching any consumer.
        let json = serde_json::Value::String("g".repeat(64));
        let result: Result<Ed25519PublicKey, _> = serde_json::from_value(json);
        assert!(result.is_err(), "non-hex pubkey charset must be rejected");
    }

    #[test]
    fn ed25519_signature_rejects_wrong_length_hex() {
        // 126 hex chars = 63 bytes — wrong length for signature.
        let json = serde_json::Value::String("0".repeat(126));
        let result: Result<Ed25519Signature, _> = serde_json::from_value(json);
        assert!(result.is_err(), "wrong-length sig hex must be rejected");
    }

    // -- SignedRecord round-trip + consistency check -------------------------

    #[test]
    fn types_definitions_compile() {
        let r = sample_record();
        let json = serde_json::to_string(&r).expect("serialise");
        let back: SignedRecord = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(r, back);
    }

    #[test]
    fn signed_record_rejects_unknown_fields() {
        let r = sample_record();
        let mut json: serde_json::Value = serde_json::to_value(&r).expect("serialise");
        json.as_object_mut()
            .unwrap()
            .insert("attacker_injected".to_string(), serde_json::json!("evil"));
        let result: Result<SignedRecord, _> = serde_json::from_value(json);
        assert!(result.is_err(), "deny_unknown_fields must reject");
    }

    #[test]
    fn signed_record_rejects_kind_payload_mismatch() {
        // Build a record whose top-level `kind` says CsqRun but
        // whose payload is KeyRotate. The custom Deserialize must
        // reject — this is the confused-deputy defense.
        let r = sample_record();
        let mut json: serde_json::Value = serde_json::to_value(&r).expect("serialise");
        let obj = json.as_object_mut().unwrap();
        // Swap payload to KeyRotate while leaving top-level kind as csq_run.
        obj.insert(
            "payload".to_string(),
            serde_json::json!({
                "kind": "key_rotate",
                "data": {
                    "previous_key_id": format!("ed25519:{}", "1".repeat(64)),
                    "new_key_id": format!("ed25519:{}", "2".repeat(64)),
                    "incoming_pubkey": "00".repeat(32),
                    "rotation_reason": "operator"
                }
            }),
        );
        let result: Result<SignedRecord, _> = serde_json::from_value(json);
        let err = result.expect_err("kind/payload mismatch must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("does not match payload.kind"),
            "error must name the mismatch; got: {msg}"
        );
    }

    #[test]
    fn event_kind_variant_exhaustiveness() {
        for k in EventKind::ALL {
            #[allow(clippy::match_same_arms)]
            let _stable: &'static str = match k {
                EventKind::CsqRun => "csq_run",
                EventKind::OAuthRefresh => "oauth_refresh",
                EventKind::ArtifactLoad => "artifact_load",
                EventKind::ModelInvoke => "model_invoke",
                EventKind::OutputCapture => "output_capture",
                EventKind::AccountSwap => "account_swap",
                EventKind::IdentityMint => "identity_mint",
                EventKind::KeyRotate => "key_rotate",
                EventKind::ReleaseAuth => "release_auth",
                EventKind::ReplicationAck => "replication_ack",
                EventKind::ReplicationFailed => "replication_failed",
                EventKind::ChainContinuation => "chain_continuation",
                EventKind::ChainReGenesis => "chain_re_genesis",
                EventKind::SinkDriftDetected => "sink_drift_detected",
                EventKind::AccountLogout => "account_logout",
                EventKind::AccountMove => "account_move",
                EventKind::SeamEventRejected => "seam_event_rejected",
                EventKind::ProvenanceAnchored => "provenance_anchored",
                EventKind::ProvenanceCaptureMatrix => "provenance_capture_matrix",
                EventKind::SeamDuplicateSuppressed => "seam_duplicate_suppressed",
                EventKind::GovernanceTurn => "governance_turn",
                EventKind::EatpAttestation => "eatp_attestation",
                EventKind::McpGateDecision => "mcp_gate_decision",
                EventKind::PolicyBundleInstall => "policy_bundle_install",
            };
        }
    }

    // Compile-time variant-count check; if a 25th variant lands, this
    // const-assert fails to compile.
    const _EVENT_KIND_VARIANT_COUNT_CHECK: () = assert!(EventKind::ALL.len() == 24);

    #[test]
    fn event_payload_kind_matches_variant() {
        for k in EventKind::ALL {
            let payload: EventPayload = match k {
                EventKind::CsqRun => EventPayload::CsqRun(CsqRunPayload {
                    run_id: "r".to_string(),
                }),
                EventKind::OAuthRefresh => EventPayload::OAuthRefresh(OAuthRefreshPayload {
                    slot: AccountNum::try_from(1u16).unwrap(),
                    identity_uuid: "u".to_string(),
                }),
                EventKind::ArtifactLoad => EventPayload::ArtifactLoad(ArtifactLoadPayload {
                    artifact_sha256: Sha256Hex::genesis(),
                }),
                EventKind::ModelInvoke => EventPayload::ModelInvoke(ModelInvokePayload {
                    model: "m".to_string(),
                    surface: "s".to_string(),
                }),
                EventKind::OutputCapture => EventPayload::OutputCapture(OutputCapturePayload {
                    output_sha256: Sha256Hex::genesis(),
                }),
                EventKind::AccountSwap => EventPayload::AccountSwap(AccountSwapPayload {
                    from_slot: AccountNum::try_from(1u16).unwrap(),
                    to_slot: AccountNum::try_from(2u16).unwrap(),
                }),
                EventKind::IdentityMint => EventPayload::IdentityMint(IdentityMintPayload {
                    identity_uuid: "u".to_string(),
                    slot: AccountNum::try_from(1u16).unwrap(),
                }),
                EventKind::KeyRotate => EventPayload::KeyRotate(KeyRotatePayload {
                    previous_key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
                    new_key_id: KeyId::try_new(format!("ed25519:{}", "1".repeat(64))).unwrap(),
                    incoming_pubkey: Ed25519PublicKey([0u8; 32]),
                    rotation_reason: RotationReason::Operator,
                }),
                EventKind::ReleaseAuth => EventPayload::ReleaseAuth(ReleaseAuthPayload {
                    release_tag: "v0".to_string(),
                    artifact_sha256: Sha256Hex::genesis(),
                }),
                EventKind::ReplicationAck => EventPayload::ReplicationAck(ReplicationAckPayload {
                    sink: SinkName::try_new("rekor").unwrap(),
                    sink_id: SinkId::try_new("1").unwrap(),
                }),
                EventKind::ReplicationFailed => {
                    EventPayload::ReplicationFailed(ReplicationFailedPayload {
                        sink: SinkName::try_new("rekor").unwrap(),
                        reason: RedactedString::from_trusted("timeout"),
                    })
                }
                EventKind::ChainContinuation => {
                    EventPayload::ChainContinuation(ChainContinuationPayload { resumed_at_seq: 0 })
                }
                EventKind::ChainReGenesis => EventPayload::ChainReGenesis(ChainReGenesisPayload {
                    reason: RedactedString::from_trusted("key_rotation"),
                    previous_chain_terminal_hash: None,
                }),
                EventKind::SinkDriftDetected => {
                    EventPayload::SinkDriftDetected(SinkDriftDetectedPayload {
                        sink: SinkName::try_new("rekor").unwrap(),
                        // Valid 26-char Crockford Base32 ULID (tightened M02 validator).
                        record_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
                    })
                }
                EventKind::AccountLogout => EventPayload::AccountLogout(AccountLogoutPayload {
                    slot: AccountNum::try_from(1u16).unwrap(),
                    orphaned_uuid: None,
                }),
                EventKind::AccountMove => EventPayload::AccountMove(AccountMovePayload {
                    from_slot: AccountNum::try_from(1u16).unwrap(),
                    to_slot: AccountNum::try_from(2u16).unwrap(),
                }),
                EventKind::SeamEventRejected => {
                    EventPayload::SeamEventRejected(SeamEventRejectedPayload {
                        reason: "malformed_json".to_string(),
                        f101_schema_version: None,
                        surface: None,
                    })
                }
                EventKind::ProvenanceAnchored => {
                    EventPayload::ProvenanceAnchored(ProvenanceAnchoredPayload {
                        decision_id:
                            "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a"
                                .to_string(),
                        surface: "journal/test.md".to_string(),
                        claimed_decision_ts: "2026-06-09T15:44:57+00:00".to_string(),
                        words_hash: None,
                        f101_schema_version: "1".to_string(),
                        received_bytes_hash: Sha256Hex::genesis(),
                        ordering_basis: None,
                        predecessor_missing: None,
                        prev_link: None,
                        kind: Some("Decision".to_string()),
                        operator_ref: None,
                        session: None,
                    })
                }
                EventKind::ProvenanceCaptureMatrix => {
                    EventPayload::ProvenanceCaptureMatrix(ProvenanceCaptureMatrixPayload {
                        surfaces: vec![],
                    })
                }
                EventKind::SeamDuplicateSuppressed => {
                    EventPayload::SeamDuplicateSuppressed(SeamDuplicateSuppressedPayload {
                        decision_id:
                            "3ae2926203bff32a2349e7584fd4df0c5bd01c4745bab723d666d8a7167cc00a"
                                .to_string(),
                        surface: "journal/test.md".to_string(),
                    })
                }
                EventKind::GovernanceTurn => EventPayload::GovernanceTurn(GovernanceTurnPayload {
                    session_id: "sess-test".to_string(),
                    record_seq: 0,
                    event_class: "turn_completed".to_string(),
                    turn: 1,
                    provider_id: Some("claude".to_string()),
                    failover_from: None,
                    failover_reason: None,
                    usage: None,
                    justification_hash: None,
                    justification_redacted: None,
                    governance_reason: None,
                    governed_at: None,
                    kailash_canonical_hash: None,
                    auth_mode: None,
                    residency_verdict: None,
                    residency_policy_name: None,
                    residency_policy_hash: None,
                }),
                EventKind::EatpAttestation => {
                    EventPayload::EatpAttestation(EatpAttestationPayload {
                        anchor_id: "eatp-genesis:01JZ00000000000000000000XY".to_string(),
                        sequence: 0,
                        previous_hash: None,
                        agent_id: "csq-ee".to_string(),
                        action: "eatp_genesis".to_string(),
                        verification_level: "SIGNED_ATTESTATION".to_string(),
                        envelope_id: None,
                        result: "success".to_string(),
                        attestation_ts: "2026-01-01T00:00:00+00:00".to_string(),
                        kailash_canonical_hash: None,
                        metadata_json: Some(
                            "{\"csq_edition\":\"enterprise\",\"genesis_kind\":\"eatp_chain_init\"}"
                                .to_string(),
                        ),
                    })
                }
                EventKind::McpGateDecision => {
                    EventPayload::McpGateDecision(McpGateDecisionPayload {
                        session_nonce: "mcp-proxy-1234-abcd".to_string(),
                        record_seq: 0,
                        cli: "codex".to_string(),
                        tool: "mcp__fs__read".to_string(),
                        verdict: "block".to_string(),
                        enforcement_fidelity: "spawn_boundary_only".to_string(),
                    })
                }
                EventKind::PolicyBundleInstall => {
                    EventPayload::PolicyBundleInstall(PolicyBundleInstallPayload {
                        bundle_version: 7,
                        bundle_pubkey: Ed25519PublicKey::new([0xaa; 32]),
                        installed_at: "2026-07-04T00:00:00+00:00".to_string(),
                    })
                }
            };
            assert_eq!(payload.kind(), k);
        }
    }
}
