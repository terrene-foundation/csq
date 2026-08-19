//! M11 — Multi-sig authorization gate for high-impact own-ops.
//!
//! Implements N-of-M Ed25519 signature collection over the canonical intent
//! of high-impact operations (KeyRotate, ReleaseAuth, IdentityMint) BEFORE the
//! record is written to the audit chain. The multi-sig proof is stored in
//! `SignedRecord.authority` as an `EatpAuthority` blob and is verified by
//! `verify_chain` for every record that carries it.
//!
//! # Architecture
//!
//! - `edition`: `Edition` (Community / Enterprise), `MultiSigPolicy`,
//!   `resolve_edition()`, `resolve_policy()`. Config-driven via environment
//!   variables; no new runtime dependency.
//! - `intent`: `intent_hash(chain_id, kind, payload)` — SHA-256 of the
//!   canonical `(chain_id, EventKind, EventPayload)` JSON. Each authorizing
//!   signer signs this hash. The verifier re-derives it from the stored record.
//!   `chain_id` binds the intent to the specific chain (SEC-3: closes
//!   cross-chain replay).
//! - `gate`: `authorize_op(chain_id, kind, payload, signers, policy)` — the
//!   single collection call-site. Fail-closed: returns
//!   `Err(MultiSigError::InsufficientSignatures)` if fewer than
//!   `policy.threshold` valid signatures are collected. Rejects duplicate signer
//!   pubkeys (SEC-1 defense-in-depth).
//! - [`verify`]: `verify_record_multi_sig(record)` — the verify_chain hook.
//!   Records with `authority: None` are unaffected (fast `Ok(())`). Records
//!   claiming multi-sig with a broken or under-threshold blob are rejected.
//!   Duplicate signer pubkeys in a blob cause immediate rejection (SEC-1).
//! - `error`: `MultiSigError` — all variants use fixed-vocabulary messages.
//!
//! # The authority blob shape
//!
//! ```json
//! {
//!   "multi_sig": {
//!     "threshold": N,
//!     "roster_size": M,
//!     "authorizations": [
//!       { "signer_pubkey": "<hex 32B>", "signature": "<hex 64B>" },
//!       ...
//!     ]
//!   }
//! }
//! ```
//!
//! Signer pubkeys are INLINE (hex of the 32 raw bytes) so the verifier is
//! SELF-CONTAINED — no M12 roster lookup needed. An offline auditor with only
//! the chain bytes can verify.
//!
//! # Trust boundary (M11 vs M12)
//!
//! M11 verifies each authorization's signature over the intent hash against the
//! pubkey inlined in the blob, but performs NO roster-membership check. An actor
//! able to write records can therefore satisfy ANY threshold with self-minted
//! keypairs (even with pubkey dedup enforced per SEC-1, by minting N DISTINCT
//! keys). The threshold confers real N-of-M authority ONLY once M12's
//! `AuthorityRegistry` restricts accepted pubkeys to enrolled roster members.
//!
//! The inline-pubkey design is a self-containment convenience for offline
//! verification — it is NOT a Sybil-resistance mechanism. Sybil resistance
//! requires M12's registry.
//!
//! # Edition / threshold policy
//!
//! | Edition    | Default threshold | Env override                     |
//! |------------|-------------------|----------------------------------|
//! | Community  | 1 (1-of-1)        | `CSQ_AUDIT_MULTISIG_THRESHOLD`   |
//! | Enterprise | 2 (N≥2-of-M)      | `CSQ_AUDIT_MULTISIG_THRESHOLD`   |
//!
//! Select edition via `CSQ_AUDIT_EDITION` (`"community"` default | `"enterprise"`).
//!
//! This is the **placeholder** edition mechanism for M11. M12's
//! `AuthorityRegistry` will supersede it with a registry-backed roster lookup.
//!
//! # Roster trait seam for M12
//!
//! `gate::SignerSet` is the minimal trait the gate consumes. M12 will add an
//! `AuthorityRegistry`-backed impl. `gate::InMemorySignerSet` is the M11
//! in-memory impl used by tests and the community/enterprise default path.
//!
//! # Backward compatibility
//!
//! All existing records carry `authority: None` and are unaffected by the
//! `verify_record_multi_sig` hook (immediate `Ok(())`).

pub mod edition;
pub mod error;
pub mod gate;
pub mod intent;
pub mod verify;

// Public surface for M11.
pub use edition::{resolve_edition, resolve_policy, Edition, MultiSigPolicy};
pub use error::MultiSigError;
pub use gate::{authorize_op, InMemorySignerSet, SignerSet};
/// GH an internal ticket — forward-compat opaque multi-sig verification (pure-M11 inner
/// threshold for a record whose `EventKind` this binary does not know).
pub(crate) use verify::verify_opaque_multi_sig;
pub use verify::verify_record_multi_sig;

// Test-utils re-exports.
#[cfg(any(test, feature = "test-utils"))]
pub use error::error_leaks_secret;
#[cfg(any(test, feature = "test-utils"))]
pub use intent::intent_bytes_test;
#[cfg(any(test, feature = "test-utils"))]
pub use intent::intent_hash;
