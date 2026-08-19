//! M12 — Authority Registry for multi-sig own-ops.
//!
//! # Problem (M11 trust boundary)
//!
//! M11 verifies each inner authorization's signature against the pubkey **inlined
//! in the blob** — it does NOT check whether that pubkey belongs to an enrolled
//! member. An actor who writes records can therefore satisfy any threshold by
//! minting N distinct self-signed keypairs. M11's threshold is only meaningful
//! once M12's registry restricts accepted pubkeys to enrolled roster members.
//!
//! # M12 deliverable
//!
//! The VERIFY-SIDE enforcement: a sig-valid-but-unenrolled pubkey contributes 0
//! to the threshold count for guarded op-classes post-activation. The on-disk
//! multi-sig blob is BYTE-IDENTICAL to M11 (no `principal` field added; no
//! schema change). Sybil resistance is structural, not cosmetic.
//!
//! # Architecture (Design A)
//!
//! The verifier checks each inline pubkey against a pubkey-indexed roster.
//! No change to the M11 on-disk blob — the `principal` for a pubkey is
//! recoverable via roster reverse-lookup for logging, but NOT embedded in
//! authorization entries.
//!
//! # Modules
//!
//! - `op_class`: `OpClass` enum (KeyRotate, IdentityMint, ReleaseAuth) and
//!   `from_event_kind` mapper.
//! - `grant`: `EnrolledKey` (pubkey + validity window), `PactDefinition`
//!   (PACT-D envelope), `AuthorityGrant` (keys + envelope).
//! - `registry`: `AuthorityRegistry` trait, `LocalOperatorRegistry`
//!   (community), `EnterpriseRegistry` (wrapper), `resolve_registry` factory.
//! - `roster`: `Roster`, `RosterEntry`, `SignedRoster`, `RosterFileRegistry`,
//!   `save_roster`, path helpers.
//! - `error`: `AuthorityError` (`#[non_exhaustive]`).
//!
//! # Op-class scoping (PRIMARY METHODOLOGICAL DIRECTIVE)
//!
//! A signer enrolled for `KeyRotate` MUST NOT count toward a `ReleaseAuth`
//! threshold. `is_enrolled` checks the pubkey's grant includes the record's
//! op-class.
//!
//! # Fail-closed matrix
//!
//! | Condition                          | Result              |
//! |------------------------------------|---------------------|
//! | Community edition                  | No membership check |
//! | Enterprise, no activation_seq yet  | No membership check |
//! | Enterprise, seq < activation_seq   | No membership check |
//! | Enterprise, seq >= activation_seq  | Membership enforced |
//! | Enterprise, missing roster         | Err (fail closed)   |
//! | Enterprise, corrupt roster         | Err (fail closed)   |
//! | Enterprise, bad sig roster         | Err (fail closed)   |
//! | Enterprise, rolled-back roster     | Err (fail closed)   |
//! | Enterprise, missing root pubkey    | Err (fail closed)   |
//!
//! # Migration cutoff
//!
//! Pre-activation community records continue to verify on M11 self-authorization
//! after a roster is installed (the `activation_seq` is the cutoff). This
//! prevents bricking an existing chain when enterprise is enabled on a live
//! installation.
//!
//! # Rollback-defense scope (M12)
//!
//! M12 ships the rollback defense as:
//! 1. Org-root signature (primary — forgery impossible without the org root key).
//! 2. Monotonic `roster_version` in the signed roster.
//! 3. `roster_version_floor` in `chain.json` (rejects below-floor rosters).
//!
//! **Trust boundary**: the floor is FS-anchored (`chain.json`), not
//! keychain-anchored. Same-user-FS-write tamper of the floor sits outside the
//! defended boundary because (a) the roster is org-root-signed, so an FS-write
//! attacker cannot forge a valid replacement; (b) rollback additionally
//! requires a compromised revoked member key; (c) the FS-based floor catches
//! naive rollback. Keychain-anchoring the floor is tracked in an internal ticket
//! (was an internal ticket, a 3-item hardening backlog closed with no successor for this
//! item — re-pointed 2026-08-12; see `scripts/verify/todo-closed-issue.sh`).
//!
//! # LDAP/AD source
//!
//! OUT OF SCOPE for M12. The `AuthorityRegistry` trait is structured so an
//! LDAP-backed implementation could be added as a future feature (a new
//! `resolve_registry` branch behind `CSQ_AUDIT_EDITION=ldap` or similar).
//! Do NOT implement or stub it in M12.
//!
//! # Embedding roster verification in offline export
//!
//! OUT OF SCOPE for M12. `verify.py.template` (the offline export verifier,
//! spec 16) does not embed roster verification. The boundary decision:
//! offline verifiers need only check the hash-chain + Ed25519 signatures on
//! individual records (M11 inline-pubkey self-contained verification). Roster
//! membership is an online/enterprise governance check. Future work would add
//! a `--roster` flag to the export bundle verifier.

pub mod error;
pub mod grant;
pub mod op_class;
pub mod registry;
pub mod roster;
pub mod sign;

#[cfg(test)]
mod tests_m12;

// Public surface.
pub use error::AuthorityError;
pub use grant::{AuthorityGrant, EnrolledKey, PactDefinition};
pub use op_class::OpClass;
pub use registry::{resolve_registry, AuthorityRegistry, LocalOperatorRegistry};
pub use roster::{
    roster_path, roster_sig_path, save_detached_roster, save_roster, verify_detached_roster,
    verify_signed_roster, Roster, RosterEntry, RosterFileRegistry, SignedRoster,
    UnsignedRosterFile, SUPPORTED_ROSTER_FORMAT_VERSION,
};
pub use sign::{
    generate_keypair, public_key_of, public_key_of_seed, sign_raw_bytes, sign_raw_bytes_with_seed,
    signing_key_from_seed, verify_hex_signature,
};
