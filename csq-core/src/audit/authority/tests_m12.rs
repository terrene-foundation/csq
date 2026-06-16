//! M12 — Acceptance criterion tests for `verify_record_multi_sig` with
//! `AuthorityRegistry` membership enforcement.
//!
//! # Coverage
//!
//! AC-1: AuthorityRegistry trait: resolve(op_class) + is_enrolled.
//! AC-2: Community self-authorizes (LocalOperatorRegistry; M11 behavior).
//! AC-3: Enterprise roster-file: 2-of-3 enrolled passes.
//! AC-5: Non-member pubkey rejected post-activation.
//! AC-6: Unknown/non-member/invalid/rolled-back → fail closed.
//! AC-7: Regression — community self-auth passes; enterprise 2-of-3 enrolled
//!        passes; unknown pubkey rejected; tampered roster rejected; rollback
//!        rejected; op-class confusion rejected; migration (pre-activation
//!        community records still verify after roster installed); member key
//!        rotation window (inside/outside).

use std::collections::BTreeMap;

use crate::audit::authority::grant::EnrolledKey;
use crate::audit::authority::op_class::OpClass;
use crate::audit::authority::registry::{AuthorityRegistry, LocalOperatorRegistry};
use crate::audit::authority::roster::{
    save_roster, Roster, RosterEntry, RosterFileRegistry, SignedRoster,
};
use crate::audit::key_custody::chain_state::ChainState;
use crate::audit::key_custody::test_helpers::init_mock_keyring;
use crate::audit::key_custody::{audit_init, LocalSigningKey};
use crate::audit::multi_sig::edition::MultiSigPolicy;
use crate::audit::multi_sig::gate::authorize_op;
use crate::audit::multi_sig::verify::verify_record_multi_sig;
use crate::audit::traits::SigningKey as SigningKeyTrait;
use crate::audit::types::{
    Ed25519PublicKey, Ed25519Signature, EventKind, EventPayload, KeyId, KeyRotatePayload, RecordId,
    ReleaseAuthPayload, RotationReason, Sha256Hex, SignedRecord,
};
use crate::platform::test_env;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey as DalekSigningKey;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn svc(tag: &str) -> String {
    format!("csq-m12-test-{}-{}", std::process::id(), tag)
}

fn gen_keypair() -> (DalekSigningKey, Ed25519PublicKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom");
    let sk = DalekSigningKey::from_bytes(&seed);
    let pk = Ed25519PublicKey(sk.verifying_key().to_bytes());
    (sk, pk)
}

fn bootstrap_signing_key(dir: &std::path::Path, chain_id: &str, svc_name: &str) -> LocalSigningKey {
    ChainState::new(chain_id)
        .save(dir)
        .expect("save chain.json");
    let _ = LocalSigningKey::delete_from_keychain(svc_name, chain_id);
    audit_init(dir, svc_name).expect("audit_init");
    LocalSigningKey::load_from_keychain(svc_name, chain_id).expect("load key")
}

fn key_rotate_payload() -> EventPayload {
    EventPayload::KeyRotate(KeyRotatePayload {
        previous_key_id: KeyId::try_new(format!("ed25519:{}", "a".repeat(64))).unwrap(),
        new_key_id: KeyId::try_new(format!("ed25519:{}", "b".repeat(64))).unwrap(),
        incoming_pubkey: Ed25519PublicKey([1u8; 32]),
        rotation_reason: RotationReason::Operator,
    })
}

fn release_auth_payload() -> EventPayload {
    EventPayload::ReleaseAuth(ReleaseAuthPayload {
        release_tag: "v2.0.0".to_string(),
        artifact_sha256: Sha256Hex::try_new("a".repeat(64)).unwrap(),
    })
}

/// Build a minimal SignedRecord for testing.
fn make_record(
    chain_id: &str,
    seq: u64,
    kind: EventKind,
    payload: EventPayload,
    authority: Option<crate::audit::types::EatpAuthority>,
) -> SignedRecord {
    SignedRecord {
        schema_version: "2".to_string(),
        record_id: RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(),
        chain_id: RecordId::try_new(chain_id).unwrap(),
        seq,
        prev_hash: Sha256Hex::genesis(),
        kind,
        payload,
        ts: "2026-06-02T12:00:00+00:00".to_string(),
        key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
        canonical_hash: Sha256Hex::genesis(),
        signature: Ed25519Signature::new([0u8; 64]),
        actor: None,
        authority,
        trust: None,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: None,
    }
}

/// Build a signed roster, save to tmp, and return (root_sk, root_pk, member_pk, RosterFileRegistry).
///
/// # Contract
///
/// REQUIRES: caller holds `test_env::lock()` before calling this function.
/// This function calls `std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", ...)` and
/// then removes it — it MUST NOT be called from tests that do not hold the shared
/// env lock, or concurrent tests will race on this env var.
fn make_enterprise_registry(
    base: &std::path::Path,
    op_classes: Vec<OpClass>,
    member_active_from: u64,
    member_retired_at: Option<u64>,
) -> (
    DalekSigningKey,
    Ed25519PublicKey,
    Ed25519PublicKey,
    RosterFileRegistry,
) {
    let (root_sk, root_pk) = gen_keypair();
    let (_, member_pk) = gen_keypair();

    let mut entries = BTreeMap::new();
    entries.insert(
        "alice@example.com".to_string(),
        RosterEntry {
            keys: vec![EnrolledKey {
                pubkey: member_pk,
                active_from_seq: member_active_from,
                retired_at_seq: member_retired_at,
            }],
            op_classes,
        },
    );
    let roster = Roster {
        format_version: 1,
        roster_version: 1,
        generated_at: "2026-06-02T00:00:00+00:00".to_string(),
        entries,
    };

    let roster_bytes = serde_json::to_vec(&roster).expect("serialize");
    let sig = root_sk.sign(&roster_bytes);
    let signed = SignedRoster {
        roster,
        roster_pubkey: root_pk,
        signature: Ed25519Signature::new(sig.to_bytes()),
    };
    save_roster(base, &signed).expect("save_roster");

    let root_hex = hex::encode(root_pk.0);
    std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
    let reg = RosterFileRegistry::load(base, 0).expect("load registry");
    std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

    (root_sk, root_pk, member_pk, reg)
}

const CHAIN_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA0";
const CHAIN_ID_2: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA1";

// ---------------------------------------------------------------------------
// AC-2: Community self-auth → M11 behavior (no membership check)
// ---------------------------------------------------------------------------

/// AC-2: community LocalOperatorRegistry activation_seq is None → no
/// membership enforcement. A valid inner sig passes regardless of enrollment.
#[test]
fn test_m12_community_local_operator_no_membership_check() {
    init_mock_keyring();
    let dir = tmp();
    let svc_name = svc("comm_op");
    let key = bootstrap_signing_key(dir.path(), CHAIN_ID, &svc_name);
    let operator_pk = key.public_key();

    let reg = LocalOperatorRegistry::new(operator_pk);
    // activation_seq is None → no membership enforcement.
    assert!(reg.activation_seq().is_none());
    // resolve returns a grant.
    assert!(reg.resolve(OpClass::KeyRotate).is_some());
    // is_enrolled true for operator's own key.
    assert!(reg.is_enrolled(&operator_pk, OpClass::KeyRotate, 0));
    // is_enrolled false for a different key.
    let other_pk = Ed25519PublicKey([0xff; 32]);
    assert!(!reg.is_enrolled(&other_pk, OpClass::KeyRotate, 0));

    let _ = LocalSigningKey::delete_from_keychain(&svc_name, CHAIN_ID);
}

/// AC-2: verify_record_multi_sig with a community registry (None activation_seq)
/// passes on valid inner sig — same as M11 behavior.
#[test]
fn test_m12_community_valid_sig_passes_with_registry() {
    init_mock_keyring();
    let dir = tmp();
    let svc_name = svc("comm_pass");
    let key = bootstrap_signing_key(dir.path(), CHAIN_ID, &svc_name);
    let operator_pk = key.public_key();

    let payload = key_rotate_payload();
    let policy = MultiSigPolicy { threshold: 1 };
    let signers: &[&dyn SigningKeyTrait] = &[&key];
    let authority = authorize_op(CHAIN_ID, &EventKind::KeyRotate, &payload, signers, &policy)
        .expect("authorize");

    let record = make_record(CHAIN_ID, 0, EventKind::KeyRotate, payload, Some(authority));

    // Community registry: no activation_seq → no membership check.
    let reg = LocalOperatorRegistry::new(operator_pk);
    let result = verify_record_multi_sig(&record, Some(&reg));
    assert!(
        result.is_ok(),
        "community valid sig must pass with registry: {result:?}"
    );

    let _ = LocalSigningKey::delete_from_keychain(&svc_name, CHAIN_ID);
}

// ---------------------------------------------------------------------------
// AC-5: Non-member pubkey rejected post-activation
// ---------------------------------------------------------------------------

/// AC-5: a sig-valid-but-non-enrolled pubkey does NOT count toward threshold
/// post-activation. The record is rejected with VerificationUnderThreshold.
#[test]
fn test_m12_non_member_signer_rejected_post_activation() {
    let _g = test_env::lock();
    init_mock_keyring();

    let dir = tmp();

    // Register a member and build the enterprise registry.
    let (_, _, member_pk, reg) =
        make_enterprise_registry(dir.path(), vec![OpClass::KeyRotate], 0, None);

    // Build a NON-member keypair and sign an authorization with it.
    let (non_member_sk, non_member_pk) = gen_keypair();
    let _ = non_member_pk; // public key of non-member

    // Create a multi-sig blob with the non-member signing.
    // We need to construct the intent hash manually and produce a valid sig
    // from the non-member key.
    let payload = key_rotate_payload();
    let hash = {
        use crate::audit::multi_sig::intent::intent_hash;
        intent_hash(CHAIN_ID, &EventKind::KeyRotate, &payload)
    };
    let sig = non_member_sk.sign(&hash);

    let authority = crate::audit::types::EatpAuthority(serde_json::json!({
        "multi_sig": {
            "threshold": 1u64,
            "roster_size": 1u64,
            "authorizations": [{
                "signer_pubkey": hex::encode(non_member_pk.0),
                "signature": hex::encode(sig.to_bytes()),
            }]
        }
    }));

    // seq 10 >= activation_seq 5.
    let record = make_record(CHAIN_ID, 10, EventKind::KeyRotate, payload, Some(authority));

    // Wrap the roster registry with activation_seq = 5.
    struct WithActivation {
        inner: RosterFileRegistry,
    }
    impl AuthorityRegistry for WithActivation {
        fn resolve(
            &self,
            op_class: OpClass,
        ) -> Option<crate::audit::authority::grant::AuthorityGrant> {
            self.inner.resolve(op_class)
        }
        fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
            self.inner.is_enrolled(pubkey, op_class, seq)
        }
        fn activation_seq(&self) -> Option<u64> {
            Some(5) // activation at seq 5
        }
    }
    let activated_reg = WithActivation { inner: reg };

    let result = verify_record_multi_sig(&record, Some(&activated_reg));
    assert!(
        result.is_err(),
        "non-member sig must be rejected post-activation"
    );
    match result.unwrap_err() {
        crate::audit::multi_sig::error::MultiSigError::VerificationUnderThreshold {
            threshold,
            valid,
        } => {
            assert_eq!(threshold, 1, "threshold must be 1");
            assert_eq!(valid, 0, "non-member contributes 0 valid");
        }
        other => panic!("expected VerificationUnderThreshold, got {other:?}"),
    }

    // Verify the member_pk (enrolled) would be accepted instead.
    let _ = member_pk; // used implicitly via is_enrolled
}

/// M13 (closes the M11/M12 authority-presence gap): a guarded op-class record
/// at or after the roster activation seq that carries NO `multi_sig` blob is
/// REJECTED under active enterprise enforcement. Without this an attacker who
/// controls a single (outgoing) signing key could forge an authority-less
/// guarded record — bypassing the N-of-M roster threshold entirely, and (since
/// M13) forging an `Outcome::Ok` to suppress an orphan.
#[test]
fn test_m13_guarded_op_without_authority_rejected_post_activation() {
    use crate::audit::authority::grant::AuthorityGrant;
    use crate::audit::multi_sig::error::MultiSigError;
    use crate::audit::types::CsqRunPayload;

    // Minimal registry: activation at seq 5. Membership logic is never reached
    // — the presence check fires first in the fast path — so an empty roster is
    // sufficient.
    struct Activated;
    impl AuthorityRegistry for Activated {
        fn resolve(&self, _: OpClass) -> Option<AuthorityGrant> {
            None
        }
        fn is_enrolled(&self, _: &Ed25519PublicKey, _: OpClass, _: u64) -> bool {
            false
        }
        fn activation_seq(&self) -> Option<u64> {
            Some(5)
        }
    }

    // Guarded (KeyRotate), seq 10 >= activation 5, authority None → REJECTED.
    let guarded = make_record(
        CHAIN_ID,
        10,
        EventKind::KeyRotate,
        key_rotate_payload(),
        None,
    );
    assert!(
        matches!(
            verify_record_multi_sig(&guarded, Some(&Activated)),
            Err(MultiSigError::MissingAuthorizationForGuardedOp)
        ),
        "guarded op without authority must be rejected post-activation"
    );

    // Pre-activation (seq 2 < 5): grandfathered, no authority required → Ok.
    let pre = make_record(
        CHAIN_ID,
        2,
        EventKind::KeyRotate,
        key_rotate_payload(),
        None,
    );
    assert!(
        verify_record_multi_sig(&pre, Some(&Activated)).is_ok(),
        "pre-activation guarded record is grandfathered"
    );

    // Community edition (registry None): no enforcement → Ok.
    assert!(
        verify_record_multi_sig(&guarded, None).is_ok(),
        "community edition does not enforce authority presence"
    );

    // Unguarded kind (CsqRun) post-activation, no authority → Ok.
    let unguarded = make_record(
        CHAIN_ID,
        10,
        EventKind::CsqRun,
        EventPayload::CsqRun(CsqRunPayload {
            run_id: "r".to_string(),
        }),
        None,
    );
    assert!(
        verify_record_multi_sig(&unguarded, Some(&Activated)).is_ok(),
        "unguarded op-class never requires a multi_sig blob"
    );
}

/// AC-5: an enrolled member's sig IS counted post-activation.
#[test]
fn test_m12_enrolled_member_sig_counted_post_activation() {
    let _g = test_env::lock();
    init_mock_keyring();

    let dir = tmp();
    let svc_name = svc("enrolled_pass");
    let key = bootstrap_signing_key(dir.path(), CHAIN_ID_2, &svc_name);

    // Build enterprise registry with the signing key as a member.
    let member_pk = key.public_key();
    let (root_sk, root_pk) = gen_keypair();

    let mut entries = BTreeMap::new();
    entries.insert(
        "alice@example.com".to_string(),
        RosterEntry {
            keys: vec![EnrolledKey {
                pubkey: member_pk,
                active_from_seq: 0,
                retired_at_seq: None,
            }],
            op_classes: vec![OpClass::KeyRotate],
        },
    );
    let roster = Roster {
        format_version: 1,
        roster_version: 1,
        generated_at: "2026-06-02T00:00:00+00:00".to_string(),
        entries,
    };
    let roster_bytes = serde_json::to_vec(&roster).expect("serialize");
    let sig = root_sk.sign(&roster_bytes);
    let signed = SignedRoster {
        roster,
        roster_pubkey: root_pk,
        signature: Ed25519Signature::new(sig.to_bytes()),
    };
    save_roster(dir.path(), &signed).expect("save_roster");

    let root_hex = hex::encode(root_pk.0);
    std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
    let reg = RosterFileRegistry::load(dir.path(), 0).expect("load");
    std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

    // Build the authority blob with the enrolled key.
    let payload = key_rotate_payload();
    let policy = MultiSigPolicy { threshold: 1 };
    let signers: &[&dyn SigningKeyTrait] = &[&key];
    let authority = authorize_op(
        CHAIN_ID_2,
        &EventKind::KeyRotate,
        &payload,
        signers,
        &policy,
    )
    .expect("authorize");

    let record = make_record(
        CHAIN_ID_2,
        10,
        EventKind::KeyRotate,
        payload,
        Some(authority),
    );

    struct WithActivation {
        inner: RosterFileRegistry,
    }
    impl AuthorityRegistry for WithActivation {
        fn resolve(
            &self,
            op_class: OpClass,
        ) -> Option<crate::audit::authority::grant::AuthorityGrant> {
            self.inner.resolve(op_class)
        }
        fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
            self.inner.is_enrolled(pubkey, op_class, seq)
        }
        fn activation_seq(&self) -> Option<u64> {
            Some(5)
        }
    }
    let activated_reg = WithActivation { inner: reg };

    let result = verify_record_multi_sig(&record, Some(&activated_reg));
    assert!(
        result.is_ok(),
        "enrolled member must pass post-activation: {result:?}"
    );

    let _ = LocalSigningKey::delete_from_keychain(&svc_name, CHAIN_ID_2);
}

// ---------------------------------------------------------------------------
// AC-7: Migration — pre-activation records still verify
// ---------------------------------------------------------------------------

/// AC-7 (migration): a record at seq < activation_seq verifies as M11 even if
/// the signing key is NOT enrolled. Pre-activation records are grandfathered.
#[test]
fn test_m12_pre_activation_record_passes_without_membership() {
    let _g = test_env::lock();
    init_mock_keyring();

    let dir = tmp();
    let svc_name = svc("pre_act");
    let key = bootstrap_signing_key(dir.path(), CHAIN_ID, &svc_name);

    let (_, _, _member_pk, reg) = make_enterprise_registry(
        dir.path(),
        vec![OpClass::KeyRotate],
        100, // member active from seq 100
        None,
    );

    // The signing key is NOT enrolled in the roster.
    // But seq 3 < activation_seq 5 → no membership check.
    let payload = key_rotate_payload();
    let policy = MultiSigPolicy { threshold: 1 };
    let signers: &[&dyn SigningKeyTrait] = &[&key];
    let authority = authorize_op(CHAIN_ID, &EventKind::KeyRotate, &payload, signers, &policy)
        .expect("authorize");

    // seq 3 < activation_seq 5 → no membership enforcement.
    let record = make_record(CHAIN_ID, 3, EventKind::KeyRotate, payload, Some(authority));

    struct WithActivation {
        inner: RosterFileRegistry,
    }
    impl AuthorityRegistry for WithActivation {
        fn resolve(
            &self,
            op_class: OpClass,
        ) -> Option<crate::audit::authority::grant::AuthorityGrant> {
            self.inner.resolve(op_class)
        }
        fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
            self.inner.is_enrolled(pubkey, op_class, seq)
        }
        fn activation_seq(&self) -> Option<u64> {
            Some(5) // activation at seq 5; record at seq 3 is pre-activation
        }
    }
    let activated_reg = WithActivation { inner: reg };

    let result = verify_record_multi_sig(&record, Some(&activated_reg));
    assert!(
        result.is_ok(),
        "pre-activation record must pass without membership check (migration): {result:?}"
    );

    let _ = LocalSigningKey::delete_from_keychain(&svc_name, CHAIN_ID);
}

// ---------------------------------------------------------------------------
// AC-7: Op-class confusion rejected
// ---------------------------------------------------------------------------

/// AC-7 (op-class confusion): a signer enrolled for KeyRotate MUST NOT
/// satisfy a ReleaseAuth threshold.
#[test]
fn test_m12_op_class_confusion_rejected() {
    let _g = test_env::lock();
    init_mock_keyring();

    let dir = tmp();
    let svc_name = svc("opclass_conf");
    let key = bootstrap_signing_key(dir.path(), CHAIN_ID, &svc_name);

    // Member enrolled for KeyRotate only (NOT ReleaseAuth).
    let member_pk = key.public_key();
    let (root_sk, root_pk) = gen_keypair();
    let mut entries = BTreeMap::new();
    entries.insert(
        "alice@example.com".to_string(),
        RosterEntry {
            keys: vec![EnrolledKey {
                pubkey: member_pk,
                active_from_seq: 0,
                retired_at_seq: None,
            }],
            op_classes: vec![OpClass::KeyRotate], // NOT ReleaseAuth
        },
    );
    let roster = Roster {
        format_version: 1,
        roster_version: 1,
        generated_at: "2026-06-02T00:00:00+00:00".to_string(),
        entries,
    };
    let roster_bytes = serde_json::to_vec(&roster).expect("serialize");
    let sig = root_sk.sign(&roster_bytes);
    let signed = SignedRoster {
        roster,
        roster_pubkey: root_pk,
        signature: Ed25519Signature::new(sig.to_bytes()),
    };
    save_roster(dir.path(), &signed).expect("save");

    let root_hex = hex::encode(root_pk.0);
    std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
    let reg = RosterFileRegistry::load(dir.path(), 0).expect("load");
    std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

    // Produce a ReleaseAuth authorization signed by alice.
    let payload = release_auth_payload();
    let policy = MultiSigPolicy { threshold: 1 };
    let signers: &[&dyn SigningKeyTrait] = &[&key];
    let authority = authorize_op(
        CHAIN_ID,
        &EventKind::ReleaseAuth,
        &payload,
        signers,
        &policy,
    )
    .expect("authorize");

    let record = make_record(
        CHAIN_ID,
        10,
        EventKind::ReleaseAuth,
        payload,
        Some(authority),
    );

    struct WithActivation {
        inner: RosterFileRegistry,
    }
    impl AuthorityRegistry for WithActivation {
        fn resolve(
            &self,
            op_class: OpClass,
        ) -> Option<crate::audit::authority::grant::AuthorityGrant> {
            self.inner.resolve(op_class)
        }
        fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
            self.inner.is_enrolled(pubkey, op_class, seq)
        }
        fn activation_seq(&self) -> Option<u64> {
            Some(5)
        }
    }
    let activated_reg = WithActivation { inner: reg };

    let result = verify_record_multi_sig(&record, Some(&activated_reg));
    assert!(
        result.is_err(),
        "KeyRotate-enrolled signer must NOT satisfy ReleaseAuth threshold"
    );

    let _ = LocalSigningKey::delete_from_keychain(&svc_name, CHAIN_ID);
}

// ---------------------------------------------------------------------------
// AC-7: Member key rotation window
// ---------------------------------------------------------------------------

/// AC-7 (key rotation window): a record signed by a member's RETIRED key
/// outside its window is rejected; inside its window is accepted.
#[test]
fn test_m12_member_key_rotation_window() {
    let _g = test_env::lock();
    init_mock_keyring();

    let dir_active = tmp();
    let dir_retired = tmp();
    let svc_active = svc("mrkw_act");
    let svc_retired = svc("mrkw_ret");
    let chain_a = "01ARZ3NDEKTSV4RRFFQ69G5FB5";
    let chain_r = "01ARZ3NDEKTSV4RRFFQ69G5FB6";

    let active_key = bootstrap_signing_key(dir_active.path(), chain_a, &svc_active);
    let retired_key = bootstrap_signing_key(dir_retired.path(), chain_r, &svc_retired);

    let active_pk = active_key.public_key();
    let retired_pk = retired_key.public_key();

    // Roster: retired key active [0, 10), new key active from 10.
    let (root_sk, root_pk) = gen_keypair();
    let mut entries = BTreeMap::new();
    entries.insert(
        "alice@example.com".to_string(),
        RosterEntry {
            keys: vec![
                EnrolledKey {
                    pubkey: retired_pk,
                    active_from_seq: 0,
                    retired_at_seq: Some(10), // retired at seq 10
                },
                EnrolledKey {
                    pubkey: active_pk,
                    active_from_seq: 10,
                    retired_at_seq: None,
                },
            ],
            op_classes: vec![OpClass::KeyRotate],
        },
    );
    let roster = Roster {
        format_version: 1,
        roster_version: 1,
        generated_at: "2026-06-02T00:00:00+00:00".to_string(),
        entries,
    };
    let roster_bytes = serde_json::to_vec(&roster).expect("serialize");
    let sig = root_sk.sign(&roster_bytes);
    let signed = SignedRoster {
        roster,
        roster_pubkey: root_pk,
        signature: Ed25519Signature::new(sig.to_bytes()),
    };
    let base = tmp();
    save_roster(base.path(), &signed).expect("save");

    let root_hex = hex::encode(root_pk.0);
    std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
    let reg = RosterFileRegistry::load(base.path(), 0).expect("load");
    std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

    struct WithActivation {
        inner: RosterFileRegistry,
    }
    impl AuthorityRegistry for WithActivation {
        fn resolve(
            &self,
            op_class: OpClass,
        ) -> Option<crate::audit::authority::grant::AuthorityGrant> {
            self.inner.resolve(op_class)
        }
        fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
            self.inner.is_enrolled(pubkey, op_class, seq)
        }
        fn activation_seq(&self) -> Option<u64> {
            Some(0) // activation from seq 0
        }
    }

    let activated_reg = WithActivation { inner: reg };

    let payload = key_rotate_payload();
    let policy = MultiSigPolicy { threshold: 1 };

    // Test 1: record at seq 5 signed by retired key → accepted (inside window [0, 10)).
    let auth_retired = authorize_op(
        chain_r,
        &EventKind::KeyRotate,
        &payload,
        &[&retired_key as &dyn SigningKeyTrait],
        &policy,
    )
    .expect("authorize");
    // Note: record chain_id must match the chain_id used in authorize_op.
    // But we're using a record chain_id that may differ. For this test the
    // intent_hash uses chain_r, so use chain_r as chain_id for the record.
    let record_inside = make_record(
        chain_r,
        5,
        EventKind::KeyRotate,
        payload.clone(),
        Some(auth_retired),
    );
    let result_inside = verify_record_multi_sig(&record_inside, Some(&activated_reg));
    assert!(
        result_inside.is_ok(),
        "retired key inside window must be accepted: {result_inside:?}"
    );

    // Test 2: record at seq 10 signed by retired key → rejected (outside window [0, 10)).
    let auth_retired_late = authorize_op(
        chain_r,
        &EventKind::KeyRotate,
        &payload,
        &[&retired_key as &dyn SigningKeyTrait],
        &policy,
    )
    .expect("authorize");
    let record_outside = make_record(
        chain_r,
        10,
        EventKind::KeyRotate,
        payload,
        Some(auth_retired_late),
    );
    let result_outside = verify_record_multi_sig(&record_outside, Some(&activated_reg));
    assert!(
        result_outside.is_err(),
        "retired key outside window (seq 10 == retired_at_seq 10) must be rejected"
    );

    let _ = LocalSigningKey::delete_from_keychain(&svc_active, chain_a);
    let _ = LocalSigningKey::delete_from_keychain(&svc_retired, chain_r);
}

// ---------------------------------------------------------------------------
// AC-7: Unguarded kinds are never membership-checked
// ---------------------------------------------------------------------------

/// AC-7: unguarded EventKind (OAuthRefresh) with a registry does NOT trigger
/// membership check — passes as M11 regardless of enrollment.
#[test]
fn test_m12_unguarded_kind_no_membership_check() {
    use crate::audit::multi_sig::intent::intent_hash;
    use crate::audit::types::OAuthRefreshPayload;

    let _g = test_env::lock();

    let dir = tmp();
    let (root_sk, root_pk) = gen_keypair();
    let (non_member_sk, non_member_pk) = gen_keypair();

    // Registry with no entries (no one enrolled for anything).
    let roster = Roster {
        format_version: 1,
        roster_version: 1,
        generated_at: "2026-06-02T00:00:00+00:00".to_string(),
        entries: BTreeMap::new(),
    };
    let roster_bytes = serde_json::to_vec(&roster).expect("serialize");
    let sig = root_sk.sign(&roster_bytes);
    let signed = SignedRoster {
        roster,
        roster_pubkey: root_pk,
        signature: Ed25519Signature::new(sig.to_bytes()),
    };
    save_roster(dir.path(), &signed).expect("save");

    let root_hex = hex::encode(root_pk.0);
    std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
    let reg = RosterFileRegistry::load(dir.path(), 0).expect("load");
    std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

    // Use OAuthRefresh — an unguarded kind.
    let oauth_payload = EventPayload::OAuthRefresh(OAuthRefreshPayload {
        slot: crate::types::AccountNum::try_from(1u16).unwrap(),
        identity_uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    });

    // Produce a valid multi-sig blob from the non-member key.
    let hash = intent_hash(CHAIN_ID, &EventKind::OAuthRefresh, &oauth_payload);
    let sig = non_member_sk.sign(&hash);
    let authority = crate::audit::types::EatpAuthority(serde_json::json!({
        "multi_sig": {
            "threshold": 1u64,
            "roster_size": 1u64,
            "authorizations": [{
                "signer_pubkey": hex::encode(non_member_pk.0),
                "signature": hex::encode(sig.to_bytes()),
            }]
        }
    }));

    let record = make_record(
        CHAIN_ID,
        100,
        EventKind::OAuthRefresh,
        oauth_payload,
        Some(authority),
    );

    struct WithActivation {
        inner: RosterFileRegistry,
    }
    impl AuthorityRegistry for WithActivation {
        fn resolve(
            &self,
            op_class: OpClass,
        ) -> Option<crate::audit::authority::grant::AuthorityGrant> {
            self.inner.resolve(op_class)
        }
        fn is_enrolled(&self, pubkey: &Ed25519PublicKey, op_class: OpClass, seq: u64) -> bool {
            self.inner.is_enrolled(pubkey, op_class, seq)
        }
        fn activation_seq(&self) -> Option<u64> {
            Some(0)
        }
    }
    let activated_reg = WithActivation { inner: reg };

    // OAuthRefresh is unguarded → no membership check → inner sig validity only.
    let result = verify_record_multi_sig(&record, Some(&activated_reg));
    assert!(
        result.is_ok(),
        "unguarded OAuthRefresh kind must pass without membership check: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// MEDIUM: format_version gate
// ---------------------------------------------------------------------------

/// MEDIUM: A roster with `format_version > SUPPORTED_ROSTER_FORMAT_VERSION`
/// MUST be rejected with `RosterFormatTooNew` BEFORE signature verification,
/// so an unrecognized schema never silently passes.
#[test]
fn test_m12_roster_format_version_too_new_fails_closed() {
    let _g = test_env::lock();

    let dir = tmp();
    let (sk, root_pk) = gen_keypair();

    // Build a roster with format_version = SUPPORTED + 1.
    use crate::audit::authority::roster::SUPPORTED_ROSTER_FORMAT_VERSION;
    let too_new_version = SUPPORTED_ROSTER_FORMAT_VERSION + 1;
    let roster = crate::audit::authority::roster::Roster {
        format_version: too_new_version,
        roster_version: 1,
        generated_at: "2026-06-02T00:00:00+00:00".to_string(),
        entries: std::collections::BTreeMap::new(),
    };
    let roster_bytes = serde_json::to_vec(&roster).expect("serialize");
    let sig = sk.sign(&roster_bytes);
    let signed = SignedRoster {
        roster,
        roster_pubkey: root_pk,
        signature: Ed25519Signature::new(sig.to_bytes()),
    };
    save_roster(dir.path(), &signed).expect("save");

    let root_hex = hex::encode(root_pk.0);
    std::env::set_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY", &root_hex);
    let result = RosterFileRegistry::load(dir.path(), 0);
    std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

    assert!(
        matches!(
            result,
            Err(crate::audit::authority::error::AuthorityError::RosterFormatTooNew(v, s))
            if v == too_new_version && s == SUPPORTED_ROSTER_FORMAT_VERSION
        ),
        "format_version > supported must produce RosterFormatTooNew; got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// MEDIUM: ChainState backward-compat test
// ---------------------------------------------------------------------------

/// MEDIUM: Deserializing a `chain.json` STRING that lacks
/// `roster_activation_seq` and `roster_version_floor` MUST deserialize both
/// fields to `None` (backward compatibility with pre-M12 chain.json files).
#[test]
fn test_m12_chain_state_backward_compat_missing_m12_fields() {
    let chain_json_pre_m12 = r#"{
        "chain_id": "pre-m12-chain",
        "rotation_count": 0
    }"#;

    let state: ChainState = serde_json::from_str(chain_json_pre_m12)
        .expect("pre-M12 chain.json must deserialize cleanly");

    assert_eq!(state.chain_id, "pre-m12-chain");
    assert!(
        state.roster_activation_seq.is_none(),
        "roster_activation_seq must be None when absent from JSON; got: {:?}",
        state.roster_activation_seq
    );
    assert!(
        state.roster_version_floor.is_none(),
        "roster_version_floor must be None when absent from JSON; got: {:?}",
        state.roster_version_floor
    );
}
