//! Actual keyed publication followed by an explicit admission-provider error.
//! PRIVATE fixture companion; no host state, sleeps, clock override, or fabricated store result.
use super::*;
use crate::messaging::model::Surface;
use crate::sessions::directives::real_fs;
use std::cell::Cell;
use tempfile::TempDir;

const HONEST: u64 = 1_000_000;
const PROVIDER_RAW: &str = "CALLBACK-RAW-SECRET-MUST-NOT-LEAK";

#[cfg(test)]
fn session(pid: u32) -> VerifiedSession {
    VerifiedSession::from_resolved(Sender {
        pid,
        started_at: 100,
        started_exact: Some(100_000 + u64::from(pid)),
        surface: Surface::Codex,
        handle_dir_hash: format!("fixture{pid}"),
        handle_dir: "/fixture".into(),
        name: None,
    })
}

#[test]
fn late_publication_provider_error_is_uncertain_and_recovers_original_record() {
    let owned = TempDir::new().unwrap();
    let fs = real_fs();
    initialize(owned.path(), HONEST, &fs).unwrap();
    let sender = session(1);
    let recipient = session(2).as_recipient();
    let key = mint(HONEST);
    let calls = Cell::new(0);
    let wall = || {
        calls.set(calls.get() + 1);
        if calls.get() == 3 {
            // begin and prepare observe honestly; commit observes AFTER the actual save.
            Err(DirectiveError {
                code: csq_sdk::SdkErrorCode::InvalidInput,
                message: PROVIDER_RAW.to_string(),
                cause: Some(Cause::RegistryRead),
                attempts: None,
                next_allowed_at: Some(HONEST + 50),
            })
        } else {
            Ok(HONEST)
        }
    };
    let error = send_with_admission_clock(
        owned.path(),
        AdmissionClock::new(Clock::from(HONEST), &wall),
        &fs,
        &Limits::DEFAULT,
        &|_: &Recipient| Liveness::Live,
        &sender,
        recipient,
        "peer",
        "original immutable intent",
        None,
        &key,
        true,
    )
    .unwrap_err();
    assert_eq!(
        calls.get(),
        3,
        "fixture must reach commit observation after publication"
    );
    let dir = store::store_dir(owned.path());
    let id = request_id(sender.sender(), &key).unwrap();
    let record_path = dir.join(format!("{id}.json"));
    let record_before =
        std::fs::read(&record_path).expect("actual public record must already exist");
    let ledger_path = dir.join("requests/ledger.json");
    let ledger_before = std::fs::read(&ledger_path).unwrap();
    let marker_path = owned.path().join(".message-requests-initialized");
    let marker_before = std::fs::read(&marker_path).unwrap();
    let ledger: Ledger = serde_json::from_slice(&ledger_before).unwrap();
    assert_eq!(ledger.entries.len(), 1);
    let prepared = ledger.entries.get(&id).unwrap();
    assert!(
        !prepared.committed,
        "commit must not have repaired the prepared request"
    );
    assert_eq!(prepared.issued, HONEST);
    assert_eq!(prepared.receipt.id, id);
    assert_eq!(prepared.to, recipient);
    assert_eq!(
        error.code,
        csq_sdk::SdkErrorCode::Undetermined,
        "late publication provider error must remain uncertain"
    );
    assert_eq!(error.cause, Some(Cause::Clock));
    assert_eq!(error.message, "message store: request outcome undetermined");
    assert_eq!(error.next_allowed_at, None);
    assert!(
        !error.to_string().contains(PROVIDER_RAW),
        "provider text must not leak"
    );
    let expected = (prepared.receipt.clone(), prepared.to);
    let recovered = recover_existing(
        owned.path(),
        HONEST - 301,
        &fs,
        &sender,
        &key,
        Some(Intent::Send {
            target: "peer",
            parent: None,
            body: "original immutable intent",
            wake: true,
        }),
    )
    .unwrap()
    .expect("actual prepared public record must recover under rollback");
    assert_eq!(
        recovered, expected,
        "positive recovery must return the original record and recipient"
    );
    let should_not_read = || -> Result<u64, DirectiveError> {
        panic!("retained positive lookup must not consult a mutating admission provider");
    };
    let lookup = lookup_with_admission_clock(
        owned.path(),
        AdmissionClock::new(Clock::from(HONEST - 301), &should_not_read),
        &fs,
        &sender,
        &key,
    )
    .unwrap();
    assert_eq!(lookup, Lookup::Stored(expected.0, expected.1));
    assert_eq!(calls.get(), 3);
    assert_eq!(std::fs::read(&record_path).unwrap(), record_before);
    assert_eq!(
        std::fs::read(&ledger_path).unwrap(),
        ledger_before,
        "positive recovery must not repair commitment or advance clock/floor"
    );
    assert_eq!(std::fs::read(&marker_path).unwrap(), marker_before);
}
