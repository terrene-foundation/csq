//! Private writer/detector receipts for the adopted roster-floor policy (an internal ticket).

use std::ffi::OsString;
use std::path::Path;

use crate::audit::key_custody::{
    audit_init, init_mock_keyring, load_embedded_cutoff, load_embedded_cutoff_file_first,
    write_roster_floor_to_keychain, ChainState,
};
use crate::audit::{verify_chain, RosterFloorAnchorStatus, VerifyConfig};

struct RestoreEnv(Vec<(&'static str, Option<OsString>)>);
impl Drop for RestoreEnv {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// Explicit in-memory keyring; private base/service; env restored before unlocking,
/// including unwinds. No ambient host paths, keychain entries or daemon probes.
fn with_fixture(test: impl FnOnce(&Path, &str, ChainState)) {
    let _guard = crate::platform::test_env::lock();
    let _restore = RestoreEnv(
        ["CSQ_AUDIT_EDITION", "CSQ_AUDIT_ROSTER_ROOT_PUBKEY"]
            .into_iter()
            .map(|name| (name, std::env::var_os(name)))
            .collect(),
    );
    std::env::set_var("CSQ_AUDIT_EDITION", "community");
    std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
    init_mock_keyring();
    let dir = tempfile::tempdir().expect("private fixture directory");
    let service = format!("csq-test-roster-disposition-{}", uuid::Uuid::new_v4());
    assert!(audit_init(dir.path(), &service).expect("private audit init"));
    let state = ChainState::load(dir.path()).expect("load private chain");
    test(dir.path(), &service, state);
}

fn verify(base: &Path, service: &str) -> crate::audit::VerifySummary {
    verify_chain(
        base,
        &VerifyConfig {
            record_limit: 10_000,
            keychain_service: service.into(),
        },
        None,
    )
    .expect("roster-floor detector must remain nonfatal")
}

#[test]
fn roster_disposition_writer_updates_both_seed_stores_without_changing_key_identity() {
    with_fixture(|base, service, state| {
        let before = load_embedded_cutoff(service, &state.chain_id)
            .unwrap()
            .unwrap();
        write_roster_floor_to_keychain(base, service, &state.chain_id, 17);
        let keychain = load_embedded_cutoff(service, &state.chain_id)
            .unwrap()
            .unwrap();
        let file = load_embedded_cutoff_file_first(base, &state.chain_id)
            .unwrap()
            .unwrap();
        for after in [keychain, file] {
            assert_eq!(after.roster_version_floor, Some(17));
            assert_eq!(after.signing_key_id, before.signing_key_id);
            assert_eq!(
                after.signing_active_since_seq,
                before.signing_active_since_seq
            );
        }
    });
}

#[test]
fn roster_disposition_lowered_file_floor_is_mismatch_but_nonfatal() {
    with_fixture(|base, service, mut state| {
        state.roster_version_floor = Some(17);
        state.save(base).unwrap();
        write_roster_floor_to_keychain(base, service, &state.chain_id, 17);
        assert_eq!(
            verify(base, service).roster_floor_anchor,
            RosterFloorAnchorStatus::Confirmed
        );
        // Actual file-only tamper: the existing seed stores stay at 17.
        state.roster_version_floor = Some(3);
        state.save(base).unwrap();
        let result = verify(base, service);
        assert_eq!(
            result.roster_floor_anchor,
            RosterFloorAnchorStatus::Mismatch
        );
        assert!(result.roster_floor_present);
        assert!(!base.join("csq-runs/.chain-broken").exists());
        assert_eq!(
            ChainState::load(base).unwrap().roster_version_floor,
            Some(3)
        );
    });
}

#[test]
fn roster_disposition_deleted_file_floor_stays_visible_as_unconfirmed() {
    with_fixture(|base, service, mut state| {
        state.roster_version_floor = Some(17);
        state.save(base).unwrap();
        write_roster_floor_to_keychain(base, service, &state.chain_id, 17);
        state.roster_version_floor = None;
        state.save(base).unwrap();
        let result = verify(base, service);
        assert_eq!(
            result.roster_floor_anchor,
            RosterFloorAnchorStatus::Unconfirmed
        );
        assert!(
            result.roster_floor_present,
            "anchor-only floor must remain visible to doctor"
        );
        assert!(!base.join("csq-runs/.chain-broken").exists());
    });
}

#[test]
fn roster_disposition_both_floors_absent_remains_omittable() {
    with_fixture(|base, service, _| {
        let result = verify(base, service);
        assert_eq!(
            result.roster_floor_anchor,
            RosterFloorAnchorStatus::Confirmed
        );
        assert!(!result.roster_floor_present);
    });
}

#[test]
fn roster_disposition_file_only_floor_is_unconfirmed_but_nonfatal() {
    with_fixture(|base, service, mut state| {
        state.roster_version_floor = Some(17);
        state.save(base).unwrap();
        let result = verify(base, service);
        assert_eq!(
            result.roster_floor_anchor,
            RosterFloorAnchorStatus::Unconfirmed
        );
        assert!(result.roster_floor_present);
    });
}
