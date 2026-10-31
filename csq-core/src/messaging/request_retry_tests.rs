//! Proposed in-crate tests for the shared retry helper. Callback faults model retry
//! admission; filesystem replacement faults model publication ambiguity. Neither
//! reproduces the unobserved host incident. Include under cfg(all(test, unix)).
use super::run_with_wait;
use crate::platform::fs::WrittenPrivateFile;
use crate::{
    error::PlatformError,
    messaging::{
        limits::{Limits, Liveness},
        model::{Message, Receipt, Recipient, Sender, Surface, VerifiedSession},
        request::{self, Intent, Lookup},
        store,
    },
    sessions::directives::{
        canonical_uuid, real_fs, DirectiveError, FsOps, UndeterminedCause as Cause,
    },
};
use csq_sdk::SdkErrorCode;
use std::{
    cell::{Cell, RefCell},
    io,
    path::Path,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const NOW: u64 = 100_000;
type Outcome = (Receipt, Recipient);
type RequestAuthoritySnapshot = (Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>);
#[cfg(test)]
fn who(pid: u32) -> VerifiedSession {
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
fn intent(body: &str) -> Intent<'_> {
    Intent::Send {
        target: "peer",
        parent: None,
        body,
        wake: true,
    }
}
fn put(base: &Path, fs: &FsOps<'_>, key: &str, body: &str) -> Result<Outcome, DirectiveError> {
    request::send(
        base,
        NOW,
        fs,
        &Limits::DEFAULT,
        &|_| Liveness::Live,
        &who(1),
        who(2).as_recipient(),
        "peer",
        body,
        None,
        key,
    )
}
fn recover(base: &Path, key: &str) -> Result<Option<Outcome>, DirectiveError> {
    request::recover_existing_for_retry(base, NOW, &real_fs(), &who(1), key, Some(intent("one")))
}
fn records(base: &Path) -> Vec<Message> {
    let dir = store::store_dir(base);
    if !dir.exists() {
        return Vec::new();
    }
    std::fs::read_dir(dir)
        .unwrap()
        .map(Result::unwrap)
        .filter_map(|entry| {
            let name = entry.file_name();
            let id = name.to_str()?.strip_suffix(".json")?;
            canonical_uuid(id)
                .then(|| serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap())
        })
        .collect()
}
fn snapshot(base: &Path) -> RequestAuthoritySnapshot {
    let dir = store::store_dir(base);
    let mut messages: Vec<_> = records(base)
        .into_iter()
        .map(|m| {
            let bytes = std::fs::read(dir.join(format!("{}.json", m.id))).unwrap();
            (m.id, bytes)
        })
        .collect();
    messages.sort_by(|a, b| a.0.cmp(&b.0));
    (
        std::fs::read(base.join(".message-requests-initialized")).unwrap(),
        std::fs::read(dir.join("requests/ledger.json")).unwrap(),
        messages,
    )
}
fn injected() -> DirectiveError {
    DirectiveError::undetermined("message store: retry fixture", io::ErrorKind::WouldBlock)
        .with_cause(Cause::LedgerWrite)
}

#[test]
fn und_retry_transient_twice_commits_one_record_with_original_key_and_intent() {
    let base = TempDir::new().unwrap();
    request::initialize(base.path(), NOW, &real_fs()).unwrap();
    let attempts = Cell::new(0);
    let lookups = Cell::new(0);
    let keys = RefCell::new(Vec::new());
    let waits = RefCell::new(Vec::new());
    let original_key = RefCell::new(String::new());
    let receipt = request::with_key_recovery(
        Ok(NOW),
        None,
        |_, _| panic!("new automatic key does not use supplied-key recovery"),
        |_, key| {
            *original_key.borrow_mut() = key.to_owned();
            run_with_wait(
                true,
                key,
                |same| {
                    lookups.set(lookups.get() + 1);
                    keys.borrow_mut().push(same.to_owned());
                    recover(base.path(), same)
                },
                |same| {
                    attempts.set(attempts.get() + 1);
                    keys.borrow_mut().push(same.to_owned());
                    if attempts.get() < 3 {
                        Err(injected())
                    } else {
                        put(base.path(), &real_fs(), same, "one")
                    }
                },
                |delay| waits.borrow_mut().push(delay),
            )
        },
    )
    .unwrap();
    let key = original_key.into_inner();
    request::validate(&key, NOW).unwrap();
    assert!(keys.borrow().iter().all(|captured| captured == &key));
    assert_eq!((attempts.get(), lookups.get()), (3, 2));
    assert_eq!(
        *waits.borrow(),
        vec![Duration::from_millis(150), Duration::from_millis(300)]
    );
    let stored = records(base.path());
    assert_eq!(stored.len(), 1);
    assert_eq!(
        (stored[0].body.as_str(), &stored[0].from, stored[0].to),
        ("one", who(1).sender(), who(2).as_recipient())
    );
    assert_eq!(
        request::lookup(base.path(), NOW, &real_fs(), &who(1), &key).unwrap(),
        Lookup::Stored(receipt.0, receipt.1)
    );
}

#[test]
fn und_retry_published_prepared_receipt_recovers_before_second_write() {
    let base = TempDir::new().unwrap();
    let key = request::mint(NOW);
    let public_writes = Cell::new(0);
    let attempts = Cell::new(0);
    let waits = RefCell::new(Vec::new());
    let before = RefCell::new(None);
    let real = real_fs();
    let replace = |a: &Path, b: &Path, identity: WrittenPrivateFile| {
        (real.replace)(a, b, identity)?;
        if b.parent() == Some(store::store_dir(base.path()).as_path())
            && b.file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(canonical_uuid)
        {
            public_writes.set(public_writes.get() + 1);
            return Err(PlatformError::Io(io::Error::new(
                io::ErrorKind::WouldBlock,
                "publication fixture",
            )));
        }
        Ok(())
    };
    let fs = FsOps {
        replace: &replace,
        ..real_fs()
    };
    let receipt = run_with_wait(
        true,
        &key,
        |same| {
            assert_eq!(same, key);
            recover(base.path(), same)
        },
        |same| {
            attempts.set(attempts.get() + 1);
            assert_eq!(
                attempts.get(),
                1,
                "positive-first recovery omitted: second write attempted"
            );
            let result = put(base.path(), &fs, same, "one");
            assert_eq!(
                result.as_ref().unwrap_err().code,
                SdkErrorCode::Undetermined
            );
            *before.borrow_mut() = Some(snapshot(base.path()));
            result
        },
        |delay| waits.borrow_mut().push(delay),
    )
    .unwrap();
    assert_eq!((attempts.get(), public_writes.get()), (1, 1));
    assert!(
        waits.borrow().is_empty(),
        "positive recovery must precede backoff"
    );
    assert_eq!(snapshot(base.path()), before.into_inner().unwrap());
    assert_eq!(records(base.path())[0].id, receipt.0.id);
    assert_eq!(recover(base.path(), &key).unwrap(), Some(receipt));
}

#[test]
fn und_retry_definite_refusals_never_recover_or_wait() {
    for rate_limited in [false, true] {
        let base = TempDir::new().unwrap();
        let key = request::mint(NOW);
        let attempts = Cell::new(0);
        let limits = if rate_limited {
            Limits {
                max_send_per_pair: 0,
                ..Limits::DEFAULT
            }
        } else {
            Limits::DEFAULT
        };
        let body = if rate_limited { "one" } else { "" };
        let error = run_with_wait(
            true,
            &key,
            |_| -> Result<Option<Outcome>, DirectiveError> {
                panic!("definite refusal must not look up")
            },
            |same| {
                attempts.set(attempts.get() + 1);
                request::send(
                    base.path(),
                    NOW,
                    &real_fs(),
                    &limits,
                    &|_| Liveness::Live,
                    &who(1),
                    who(2).as_recipient(),
                    "peer",
                    body,
                    None,
                    same,
                )
            },
            |_| panic!("definite refusal must not wait"),
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            if rate_limited {
                SdkErrorCode::RateLimited
            } else {
                SdkErrorCode::InvalidInput
            }
        );
        assert_eq!(attempts.get(), 1);
        assert!(records(base.path()).is_empty());
    }
}

#[test]
fn und_retry_exhaustion_is_four_attempts_and_three_scheduled_waits() {
    for outer_wrapper in [false, true] {
        let base = TempDir::new().unwrap();
        request::initialize(base.path(), NOW, &real_fs()).unwrap();
        let key = request::mint(NOW);
        let before = snapshot(base.path());
        let attempts = Cell::new(0);
        let lookups = Cell::new(0);
        let waits = RefCell::new(Vec::new());
        let operation = |admitted: &str| {
            run_with_wait(
                true,
                admitted,
                |same| {
                    assert_eq!(same, key);
                    lookups.set(lookups.get() + 1);
                    recover(base.path(), same)
                },
                |same| {
                    assert_eq!(same, key);
                    attempts.set(attempts.get() + 1);
                    let cause = match attempts.get() {
                        1 => Cause::LockTimeout,
                        2 => Cause::LedgerRead,
                        3 => Cause::Clock,
                        _ => Cause::RecordUncertain,
                    };
                    Err::<Outcome, _>(
                        DirectiveError::undet("private fixture body must not survive sanitation")
                            .with_cause(cause),
                    )
                },
                |delay| waits.borrow_mut().push(delay),
            )
        };
        let result = if outer_wrapper {
            request::with_key_recovery(
                Ok(NOW),
                Some(&key),
                |_, same| recover(base.path(), same),
                |_, admitted| operation(admitted),
            )
        } else {
            operation(&key)
        };
        let error = result.unwrap_err();
        assert_eq!(error.code, SdkErrorCode::Undetermined);
        assert_eq!((attempts.get(), lookups.get()), (4, 3));
        assert_eq!(
            *waits.borrow(),
            vec![
                Duration::from_millis(150),
                Duration::from_millis(300),
                Duration::from_millis(600)
            ]
        );
        assert_eq!(error.cause, Some(Cause::RecordUncertain));
        assert_eq!(error.attempts, Some(4));
        if outer_wrapper {
            assert!(error.message.contains(&format!("idempotency_key={key}")));
            assert!(error.message.contains("cause=record_uncertain"));
            assert!(error.message.contains("attempts=4"));
            assert!(!error.message.contains("private fixture body"));
        }
        assert_eq!(snapshot(base.path()), before);
    }
}

#[test]
fn und_retry_unpinned_legacy_send_never_retries_or_looks_up() {
    let base = TempDir::new().unwrap();
    let mut sender = who(1).sender().clone();
    sender.started_exact = None;
    let from = VerifiedSession::from_resolved(sender);
    assert!(!request::protection(false, &from).unwrap());
    assert_eq!(
        request::protection(true, &from).unwrap_err().code,
        SdkErrorCode::Undetermined
    );
    let attempts = Cell::new(0);
    let real = real_fs();
    let replace = |_: &Path, _: &Path, _: WrittenPrivateFile| {
        Err(PlatformError::Io(io::Error::new(
            io::ErrorKind::WouldBlock,
            "legacy fixture",
        )))
    };
    let fs = FsOps {
        replace: &replace,
        ..real
    };
    let error = run_with_wait(
        request::protection(false, &from).unwrap(),
        &request::mint(NOW),
        |_| -> Result<Option<Receipt>, DirectiveError> { panic!("legacy send must not recover") },
        |_| {
            attempts.set(attempts.get() + 1);
            store::send(
                base.path(),
                NOW,
                &fs,
                &Limits::DEFAULT,
                &|_| Liveness::Live,
                &from,
                who(2).as_recipient(),
                "one",
                None,
            )
        },
        |_| panic!("legacy send must not wait"),
    )
    .unwrap_err();
    assert_eq!(error.code, SdkErrorCode::Undetermined);
    assert_eq!(attempts.get(), 1);
    assert!(records(base.path()).is_empty());
    assert!(!base.path().join(".message-requests-initialized").exists());
}

#[test]
fn und_retry_missing_or_corrupt_prepared_record_refuses_republication() {
    for corrupt in [false, true] {
        let base = TempDir::new().unwrap();
        let key = request::mint(NOW);
        let attempts = Cell::new(0);
        let public_writes = Cell::new(0);
        let before = RefCell::new(None);
        let real = real_fs();
        let replace = |a: &Path, b: &Path, identity: WrittenPrivateFile| {
            let public = b.parent() == Some(store::store_dir(base.path()).as_path())
                && b.file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(canonical_uuid);
            if public {
                public_writes.set(public_writes.get() + 1);
                if corrupt {
                    (real.replace)(a, b, identity)?;
                    std::fs::write(b, "{").unwrap();
                }
                return Err(PlatformError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "prepared fixture",
                )));
            }
            (real.replace)(a, b, identity)
        };
        let fs = FsOps {
            replace: &replace,
            ..real_fs()
        };
        let authority = store::store_dir(base.path()).join("requests/ledger.json");
        let error = run_with_wait(
            true,
            &key,
            |same| recover(base.path(), same),
            |same| {
                attempts.set(attempts.get() + 1);
                assert_eq!(
                    attempts.get(),
                    1,
                    "ambiguous Prepared request must not be re-admitted"
                );
                let result = put(base.path(), &fs, same, "one");
                *before.borrow_mut() = Some(std::fs::read(&authority).unwrap());
                result
            },
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::Undetermined);
        assert_eq!((attempts.get(), public_writes.get()), (1, 1));
        assert_eq!(
            std::fs::read(&authority).unwrap(),
            before.into_inner().unwrap()
        );
        assert_eq!(
            request::lookup(base.path(), NOW, &real_fs(), &who(1), &key)
                .unwrap_err()
                .code,
            SdkErrorCode::Undetermined
        );
    }
}

#[test]
fn und_retry_original_clock_deadline_is_carried_through_backoff() {
    let base = TempDir::new().unwrap();
    request::initialize(base.path(), NOW, &real_fs()).unwrap();
    let key = request::mint(NOW);
    let attempts = Cell::new(0);
    let waits = RefCell::new(Vec::new());
    let original_clock = request::clock(
        NOW,
        Instant::now()
            .checked_sub(Duration::from_secs(request::WINDOW_SECS))
            .unwrap(),
        Ok(NOW),
    )
    .unwrap();
    let error = run_with_wait(
        true,
        &key,
        |same| recover(base.path(), same),
        |same| {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 {
                return Err(injected());
            }
            request::send(
                base.path(),
                original_clock,
                &real_fs(),
                &Limits::DEFAULT,
                &|_| Liveness::Live,
                &who(1),
                who(2).as_recipient(),
                "peer",
                "one",
                None,
                same,
            )
        },
        |delay| waits.borrow_mut().push(delay),
    )
    .unwrap_err();
    assert_eq!(error.code, SdkErrorCode::Undetermined);
    assert_eq!(attempts.get(), 4);
    assert_eq!(
        *waits.borrow(),
        vec![
            Duration::from_millis(150),
            Duration::from_millis(300),
            Duration::from_millis(600)
        ]
    );
    assert!(
        records(base.path()).is_empty(),
        "refreshing Clock after a retry would incorrectly publish"
    );
}

#[test]
fn und_retry_lost_or_corrupt_authority_never_reinitializes_or_retries() {
    for case in ["both", "marker", "ledger", "corrupt"] {
        let base = TempDir::new().unwrap();
        request::initialize(base.path(), NOW, &real_fs()).unwrap();
        let key = request::mint(NOW);
        let marker = base.path().join(".message-requests-initialized");
        let requests = store::store_dir(base.path()).join("requests");
        let ledger = requests.join("ledger.json");
        let attempts = Cell::new(0);
        let lookups = Cell::new(0);
        let error = run_with_wait(
            true,
            &key,
            |same| {
                lookups.set(lookups.get() + 1);
                recover(base.path(), same)
            },
            |_| {
                attempts.set(attempts.get() + 1);
                assert_eq!(
                    attempts.get(),
                    1,
                    "lost authority must not authorize reinitialization"
                );
                match case {
                    "both" => {
                        std::fs::remove_file(&marker).unwrap();
                        std::fs::remove_dir_all(&requests).unwrap();
                    }
                    "marker" => std::fs::remove_file(&marker).unwrap(),
                    "ledger" => std::fs::remove_file(&ledger).unwrap(),
                    "corrupt" => std::fs::write(&ledger, "{").unwrap(),
                    _ => unreachable!(),
                }
                Err::<Outcome, _>(injected())
            },
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error.code, SdkErrorCode::Undetermined);
        assert_eq!((attempts.get(), lookups.get()), (1, 1));
        assert_eq!(marker.exists(), !matches!(case, "both" | "marker"));
        assert_eq!(requests.exists(), case != "both");
        assert_eq!(ledger.exists(), !matches!(case, "both" | "ledger"));
        if case == "corrupt" {
            assert_eq!(std::fs::read(&ledger).unwrap(), b"{");
        }
        assert!(records(base.path()).is_empty());
    }
}
