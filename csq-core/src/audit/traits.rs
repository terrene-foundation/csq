//! csq-owned trait surface for the audit ledger (M01 + R1 fix-wave,
//! workspace `csq-pact-eatp-adoption`, Phase A.1).
//!
//! Four traits define the abstraction boundary between csq's daemon /
//! CLI surfaces and the underlying canonical-form + signing + storage
//! providers. Per `00-index.md` §Framing and the architecture
//! recommendation §D3: the trait surface is csq-owned (Apache 2.0,
//! Foundation-owned). Concrete providers — the enterprise edition (proprietary)
//! today, a future kailash-py bridge, the future `csq-ledger` substrate
//! — implement the traits without leaking their type names into this
//! file.
//!
//! # Structural invariant
//!
//! No vendor module paths may appear in compilable code in this file
//! or `csq-core/src/audit/types.rs`. The audit primitive (canonical
//! source: `M01-trait-skeleton-csq-core-audit.md` § "Audit primitive"
//! and spec 12 §12.9.3) enforces it mechanically:
//!
//! ```text
//! # Vendor coupling — `use` imports
//! grep -rEn '^use\s+(kailash|eatp)\b' \
//!   csq-core/src/audit/traits.rs csq-core/src/audit/types.rs
//! # Expected: 0 matches
//!
//! # Vendor coupling — qualified module paths in code positions
//! grep -rEn '\b(kailash[a-z_-]*::|eatp::)' \
//!   csq-core/src/audit/traits.rs csq-core/src/audit/types.rs \
//!   | grep -vE ':\s*(///?!?|//)'
//! # Expected: 0 matches
//! ```
//!
//! Prose references in `//!` / `///` comments naming the vendor are
//! allowed — they are documentation, not coupling.

use async_trait::async_trait;

use crate::audit::types::{
    Ed25519PublicKey, Ed25519Signature, KeyId, LedgerError, RecordId, SignedRecord, SigningError,
    SinkError, SinkReceipt,
};

/// Canonical-form helper for a record.
///
/// A canonical form is a deterministic, byte-portable serialization of
/// the load-bearing fields of a record. The hash of the canonical form
/// is what every signature and every hash-chain link is computed over.
/// Two implementations that agree on canonical form MUST produce
/// byte-identical canonical strings and identical SHA-256 digests for
/// the same input — that is the cross-impl CI gate of M08.
pub trait CanonicalForm {
    /// Returns the canonical-form byte sequence for `record`.
    /// MUST be deterministic.
    fn canonical_bytes(&self, record: &SignedRecord) -> Vec<u8>;

    /// Returns the lowercase-hex SHA-256 digest of `canonical_bytes(record)`.
    fn canonical_hash(&self, record: &SignedRecord) -> String;
}

/// Local signing-key handle.
///
/// `sign` is FALLIBLE — an OS-keychain-backed impl (M04) must be able
/// to surface `KeychainLocked`, `KeyRevoked`, or `Unavailable` without
/// panicking. Per `rules/security.md` MUST Rule 6 (Fail-Closed on
/// Keychain/Lock Contention) and `rules/tauri-commands.md` MUST Rule 1
/// (every command returns Result, never panics).
pub trait SigningKey: Send + Sync {
    /// The stable identifier for this key.
    fn key_id(&self) -> KeyId;

    /// The Ed25519 public-key bytes (32 bytes) paired with this key.
    fn public_key(&self) -> Ed25519PublicKey;

    /// Produces an Ed25519 signature over `message`.
    ///
    /// `message` is typically the SHA-256 digest of a canonical form;
    /// callers MUST NOT pass raw payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::KeychainLocked`] when the OS keychain
    /// requires user unlock; [`SigningError::KeyRevoked`] when the
    /// key id is no longer the active head of the rotation chain;
    /// [`SigningError::Unavailable`] when the backend (hardware HSM,
    /// remote signer) is unreachable; [`SigningError::Internal`] for
    /// unexpected backend errors.
    fn sign(&self, message: &[u8]) -> Result<Ed25519Signature, SigningError>;
}

/// Local hash-chained append-only audit log.
///
/// Implementations are the substrate for Tier-1 storage per the
/// architecture recommendation §B: a JSONL file backed by the daemon,
/// where every record carries `prev_hash` linking to its predecessor.
/// `verify_integrity` walks the chain from genesis and recomputes
/// every link; it MUST detect any mutation, deletion, or reordering.
///
/// # `&self` everywhere
///
/// Methods take `&self` so the daemon can share a single engine
/// instance via `Arc<dyn LedgerEngine>` without external locking.
/// The single-writer invariant (spec 12 §12.3) is enforced INSIDE the
/// impl via interior mutability — never by forcing every caller to
/// hold an external `Mutex` across `.await` (the pattern
/// `rules/tauri-patterns.md` § "Never hold a lock across an `await`"
/// blocks).
pub trait LedgerEngine: Send + Sync {
    /// Appends `record` to the chain. Returns the assigned sequence
    /// number. Implementations MUST reject a record whose `prev_hash`
    /// does not match the chain head ([`LedgerError::ChainBroken`])
    /// — that is the structural defense against silent corruption.
    fn append(&self, record: SignedRecord) -> Result<u64, LedgerError>;

    /// Returns the record at `seq`, or `Err(LedgerError::NotFound)`.
    fn seq_at(&self, seq: u64) -> Result<SignedRecord, LedgerError>;

    /// Walks the chain from genesis and recomputes every hash link.
    /// Returns `Ok(head_seq)` on success.
    ///
    /// MUST be called at daemon start (M05) and BEFORE any append in
    /// a fresh process.
    fn verify_integrity(&self) -> Result<u64, LedgerError>;
}

/// External anchor surface — Rekor, S3 Object Lock, Azure Immutable
/// Blob, GCP Bucket Lock, the future Foundation-owned `csq-ledger`,
/// or any operator-run sink. Per workspace-owner decision §5
/// (00-index.md): csq ships local-only by default; sinks are opt-in
/// plugins behind this trait.
///
/// # Method count is load-bearing
///
/// `LedgerSink` defines EXACTLY three methods: [`Self::append`],
/// [`Self::verify_at`], [`Self::name`]. Per the M01 PRIMARY
/// METHODOLOGICAL DIRECTIVE and the architecture recommendation D1
/// ("narrow" sink rationale): every additional method is a place a
/// sink impl can violate contract. Future capabilities land as
/// sibling traits (`trait BatchSink: LedgerSink`,
/// `trait HealthCheckableSink: LedgerSink`) — never by widening this
/// trait.
///
/// # Send + Sync + 'static
///
/// All sinks are daemon-thread-shared; the bound makes that structural.
#[async_trait]
pub trait LedgerSink: Send + Sync + 'static {
    /// Stable identifier for this sink (e.g. `"rekor"`, `"csq-ledger"`).
    /// Used by config lookup and operator-facing diagnostics. The
    /// return type's contract is enforced by
    /// [`crate::audit::types::SinkName`] in impls that route through
    /// the typed newtype (recommended).
    fn name(&self) -> &str;

    /// Submits `record` to the external sink. Returns a [`SinkReceipt`]
    /// the local engine persists alongside the chain entry.
    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError>;

    /// Fetches the record previously anchored under the sink id
    /// corresponding to `id`. Returns `Err(SinkError::NotFound)` when
    /// the sink does not have a record for this id; returns
    /// `Err(SinkError::Drift)` when the fetched bytes do not match
    /// local canonical hash.
    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError>;
}

// ---------------------------------------------------------------------------
// Compile-time structural assertions
// ---------------------------------------------------------------------------

/// Compile-time assertion: `LedgerSink` is object-safe with the bounds
/// required for `dyn LedgerSink` to be `Send + Sync + 'static`.
#[allow(dead_code)]
fn _assert_ledger_sink_dyn_send_sync_static() {
    fn _is_send_sync_static<T: Send + Sync + 'static + ?Sized>() {}
    _is_send_sync_static::<dyn LedgerSink>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_definitions_compile() {
        _assert_ledger_sink_dyn_send_sync_static();
    }

    #[test]
    fn ledger_sink_method_count_is_three() {
        // The structural defense for "exactly three methods" is the
        // audit primitive at the milestone level (greps `fn name|async
        // fn append|async fn verify_at` against this file). This test
        // is a marker that exercises the three-method shape — it
        // cannot detect a 4th method added with a default body, so
        // the audit-primitive grep is the load-bearing check.
        struct CountSink;
        #[async_trait]
        impl LedgerSink for CountSink {
            fn name(&self) -> &str {
                "count"
            }
            async fn append(&self, _r: &SignedRecord) -> Result<SinkReceipt, SinkError> {
                unreachable!("compile-time shape only")
            }
            async fn verify_at(&self, _id: &RecordId) -> Result<SignedRecord, SinkError> {
                unreachable!("compile-time shape only")
            }
        }
        let _sink: Box<dyn LedgerSink> = Box::new(CountSink);
    }
}
