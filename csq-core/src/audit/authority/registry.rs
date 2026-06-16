//! M12 — `AuthorityRegistry` trait and `LocalOperatorRegistry` (community impl).
//!
//! # Trait contract
//!
//! `AuthorityRegistry` is the single abstraction consumed by
//! `verify_record_multi_sig`. Two implementations ship in M12:
//!
//! - `LocalOperatorRegistry` (community): wraps the chain operator's pubkey
//!   from `chain.json`. Returns a grant for ALL op-classes (the operator
//!   self-authorizes). `activation_seq()` returns `None` — community
//!   installs never enforce roster membership; the outer chain-key signature
//!   IS the authority.
//!
//! - `RosterFileRegistry` (enterprise): backed by a signed roster on disk.
//!   See `roster.rs`. `activation_seq()` returns `None` on the registry itself;
//!   `resolve_registry` wraps it in `EnterpriseRegistry` which carries the
//!   `roster_activation_seq` from `chain.json`.
//!
//! # Edition dispatch
//!
//! `resolve_registry(base, chain_state)` is the single factory entry point.
//! It reads `CSQ_AUDIT_EDITION` and dispatches:
//!
//! - Community → `Some(Box<LocalOperatorRegistry>)` (or `None` — same
//!   semantics; community is always M11 behavior, no membership check).
//! - Enterprise → `Some(Box<EnterpriseRegistry>)` wrapping `RosterFileRegistry`.
//!   Missing/corrupt/bad-sig/rolled-back roster → `Err` (fail closed).
//!   The caller propagates this as a `LedgerError` BEFORE the per-record loop.
//!
//! # `activation_seq` semantics
//!
//! Membership enforcement is gated on `activation_seq`:
//!
//! - `None` → no membership check for ANY record (M11 behavior, community path).
//! - `Some(a)` → records with `seq >= a` and a guarded `op_class` have their
//!   signer pubkeys membership-checked against the roster.
//!
//! The `activation_seq` is written by `csq audit roster install` when the roster
//! is first installed, pinned to the chain's tail seq at install time. This
//! ensures pre-activation records (including any records written before M12 was
//! deployed) continue to verify on the M11 self-authorization rule.

use std::path::Path;

use crate::audit::key_custody::chain_state::ChainState;
use crate::audit::multi_sig::edition::resolve_edition;
use crate::audit::multi_sig::edition::Edition;
use crate::audit::types::Ed25519PublicKey;

use super::error::AuthorityError;
use super::grant::{AuthorityGrant, EnrolledKey, PactDefinition};
use super::op_class::OpClass;
use super::roster::RosterFileRegistry;

// ---------------------------------------------------------------------------
// AuthorityRegistry trait
// ---------------------------------------------------------------------------

/// Trait consumed by `verify_record_multi_sig` to check roster membership.
///
/// Implementations are `Send + Sync` so they can be constructed once before
/// `verify_chain`'s per-record loop and shared across record iterations.
pub trait AuthorityRegistry: Send + Sync {
    /// Return the `AuthorityGrant` for the given op class, or `None` if this
    /// op class has no enrolled keys.
    fn resolve(&self, op_class: OpClass) -> Option<AuthorityGrant>;

    /// Return `true` if the given pubkey is enrolled for `op_class` at `seq`.
    ///
    /// Active membership: `enrolled_key.active_from_seq <= seq < retired_at_seq`.
    fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool;

    /// The first `seq` at which roster membership is enforced.
    ///
    /// - `None` → no membership enforcement (community / pre-activation).
    /// - `Some(a)` → records with `seq >= a` on guarded op-classes are
    ///   membership-checked.
    fn activation_seq(&self) -> Option<u64>;
}

// ---------------------------------------------------------------------------
// LocalOperatorRegistry (community)
// ---------------------------------------------------------------------------

/// Community registry: the chain operator self-authorizes with their own key.
///
/// `activation_seq()` always returns `None` — community installs never enforce
/// roster membership. The outer chain-key Ed25519 signature is the authority.
///
/// In a single-operator install, Sybil resistance is meaningless: the operator
/// can already write any record to the chain, and the multi-sig gate is a
/// ceremony for multi-party operations. Community 1-of-1 therefore uses the
/// same M11 behavior (inner-sig valid over intent hash) without membership check.
pub struct LocalOperatorRegistry {
    /// The chain operator's current public key (from `chain.json::pubkey`).
    operator_pubkey: Ed25519PublicKey,
}

impl LocalOperatorRegistry {
    /// Create a registry wrapping the chain operator's pubkey.
    pub fn new(operator_pubkey: Ed25519PublicKey) -> Self {
        Self { operator_pubkey }
    }
}

impl AuthorityRegistry for LocalOperatorRegistry {
    fn resolve(&self, op_class: OpClass) -> Option<AuthorityGrant> {
        Some(AuthorityGrant {
            keys: vec![EnrolledKey {
                pubkey: self.operator_pubkey,
                active_from_seq: 0,
                retired_at_seq: None,
            }],
            envelope: PactDefinition {
                op_classes: vec![op_class],
                definition: "community — single operator self-authorizes".to_string(),
            },
        })
    }

    fn is_enrolled(&self, pubkey: &Ed25519PublicKey, _op_class: OpClass, _seq: u64) -> bool {
        // Community: only the operator's own key is "enrolled" (no membership enforcement).
        pubkey.0 == self.operator_pubkey.0
    }

    fn activation_seq(&self) -> Option<u64> {
        // Community installs never enforce membership.
        None
    }
}

// ---------------------------------------------------------------------------
// EnterpriseRegistry — wraps RosterFileRegistry with activation_seq
// ---------------------------------------------------------------------------

/// Enterprise registry: wraps `RosterFileRegistry` and carries the
/// `roster_activation_seq` from `chain.json`.
pub struct EnterpriseRegistry {
    inner: RosterFileRegistry,
    /// Seq from `chain.json::roster_activation_seq`.
    activation: Option<u64>,
}

impl AuthorityRegistry for EnterpriseRegistry {
    fn resolve(&self, op_class: OpClass) -> Option<AuthorityGrant> {
        self.inner.resolve(op_class)
    }

    fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
        self.inner.is_enrolled(pubkey, op_class, seq)
    }

    fn activation_seq(&self) -> Option<u64> {
        self.activation
    }
}

// ---------------------------------------------------------------------------
// resolve_registry — edition-driven factory
// ---------------------------------------------------------------------------

/// Construct the active `AuthorityRegistry` from edition + chain state.
///
/// Called once before `verify_chain`'s per-record loop.
///
/// # Returns
///
/// - `Ok(None)` — community edition: M11 behavior for all records (no
///   membership check). Callers MUST treat `None` registry as "pass-through"
///   (same as `activation_seq() == None`).
///
/// - `Ok(Some(registry))` — enterprise edition: membership enforced for
///   guarded op-classes after `activation_seq`. The caller threads this into
///   each `verify_record_multi_sig` call.
///
/// - `Err(AuthorityError)` — enterprise edition misconfiguration (missing
///   roster, bad signature, corrupt, rolled-back, or missing root pubkey).
///   FAIL CLOSED: the caller MUST propagate this as a fatal error BEFORE the
///   per-record loop (daemon startup refuses to continue).
///
/// # Fail-closed guarantee
///
/// Enterprise edition with ANY roster misconfiguration → `Err`. NEVER falls
/// back to community 1-of-1 under enterprise edition.
pub fn resolve_registry(
    base: &Path,
    chain_state: &ChainState,
) -> Result<Option<Box<dyn AuthorityRegistry>>, AuthorityError> {
    let edition = resolve_edition();

    match edition {
        Edition::Community => {
            // Community: no membership enforcement. Return None for pure M11.
            // We could return Some(LocalOperatorRegistry), but None is cleaner
            // and avoids any chance of membership checks being accidentally
            // triggered for community installs.
            Ok(None)
        }
        Edition::Enterprise => {
            // Enterprise: load and verify the signed roster. Fail closed on any error.
            let version_floor = chain_state.roster_version_floor.unwrap_or(0);

            let roster_registry = RosterFileRegistry::load(base, version_floor)?;
            let activation = chain_state.roster_activation_seq;

            let registry: Box<dyn AuthorityRegistry> = Box::new(EnterpriseRegistry {
                inner: roster_registry,
                activation,
            });
            Ok(Some(registry))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::chain_state::ChainState;
    use crate::audit::types::Ed25519PublicKey;

    fn arbitrary_pubkey(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey([seed; 32])
    }

    // Tests for LocalOperatorRegistry.

    #[test]
    fn local_operator_registry_resolves_all_op_classes() {
        let pk = arbitrary_pubkey(1);
        let reg = LocalOperatorRegistry::new(pk);
        for op in [
            OpClass::KeyRotate,
            OpClass::IdentityMint,
            OpClass::ReleaseAuth,
        ] {
            let grant = reg.resolve(op);
            assert!(grant.is_some(), "community must resolve {op:?}");
        }
    }

    #[test]
    fn local_operator_registry_activation_seq_is_none() {
        let pk = arbitrary_pubkey(2);
        let reg = LocalOperatorRegistry::new(pk);
        assert!(
            reg.activation_seq().is_none(),
            "community activation_seq must be None"
        );
    }

    #[test]
    fn local_operator_registry_is_enrolled_operator_key() {
        let pk = arbitrary_pubkey(3);
        let reg = LocalOperatorRegistry::new(pk);
        assert!(
            reg.is_enrolled(&pk, OpClass::KeyRotate, 0),
            "operator's own key must be enrolled in community"
        );
    }

    #[test]
    fn local_operator_registry_not_enrolled_other_key() {
        // M12: transitively reads CSQ_AUDIT_EDITION (via verify_chain/export_bundle/resolve_*);
        // hold the shared env lock so it doesn't race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        let pk = arbitrary_pubkey(4);
        let other = arbitrary_pubkey(5);
        let reg = LocalOperatorRegistry::new(pk);
        assert!(
            !reg.is_enrolled(&other, OpClass::KeyRotate, 0),
            "non-operator key must not be enrolled in community"
        );
    }

    // Tests for resolve_registry (community path — enterprise path needs env + disk).

    #[test]
    fn resolve_registry_community_returns_none() {
        use crate::platform::test_env;
        let _g = test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let chain = ChainState::new("test-chain-community");
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_registry(dir.path(), &chain);
        assert!(result.is_ok(), "community resolve_registry must not error");
        assert!(
            result.unwrap().is_none(),
            "community must return None registry"
        );
    }

    #[test]
    fn resolve_registry_enterprise_missing_roster_fails_closed() {
        use crate::platform::test_env;
        let _g = test_env::lock();
        std::env::set_var("CSQ_AUDIT_EDITION", "enterprise");
        std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", "aa".repeat(32));

        let chain = ChainState::new("test-chain-enterprise");
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_registry(dir.path(), &chain);
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let is_roster_missing = matches!(result, Err(AuthorityError::RosterMissing));
        assert!(
            is_roster_missing,
            "enterprise with missing roster must fail closed"
        );
    }
}
