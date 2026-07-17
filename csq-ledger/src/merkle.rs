//! RFC 6962 Merkle Tree — re-export of the `csq-merkle` leaf crate.
//!
//! The RFC 6962 verifier (`hash_leaf` / `hash_children` / `merkle_root` /
//! `inclusion_proof` / `verify_inclusion` / `consistency_proof` /
//! `verify_consistency` + the full CT vector-test suite) was EXTRACTED from
//! csq-ledger into the standalone `csq-merkle` leaf crate (an internal ticket) so that
//! BOTH csq-ledger AND csq-core can depend on the SAME verification code without
//! a dependency cycle (csq-ledger already depends on csq-core; a
//! `csq-core → csq-ledger` edge would be circular). csq-core needs the verifier
//! to check inclusion proofs the ledger returns from `CsqLedgerSink::append`.
//!
//! This module re-exports every public symbol so every existing
//! `crate::merkle::…` callsite and test in csq-ledger is unchanged.
//!
//! See `csq-merkle/src/lib.rs` for the implementation, domain-separation notes,
//! and the RFC 6962 canonical test vectors (now owned by the leaf crate).

pub use csq_merkle::{
    consistency_proof, empty_root, hash_children, hash_leaf, inclusion_proof, merkle_root,
    verify_consistency, verify_inclusion, Hash,
};
