#[cfg(test)]
use super::*;
use crate::platform::fs::WrittenPrivateFile;
use crate::{
    error::PlatformError,
    messaging::{model::Surface, store::Mark},
    sessions::directives::real_fs,
};
use std::{
    io,
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};
use tempfile::TempDir;
const NOW: u64 = 100_000;
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
fn live(_: &Recipient) -> Liveness {
    Liveness::Live
}
fn intent(body: &str) -> Intent<'_> {
    Intent::Send {
        target: "peer",
        parent: None,
        body,
        wake: true,
    }
}
fn put(
    base: &Path,
    now: u64,
    fs: &FsOps<'_>,
    token: &str,
    body: &str,
) -> Result<(Receipt, Recipient), DirectiveError> {
    send(
        base,
        now,
        fs,
        &Limits::DEFAULT,
        &live,
        &who(1),
        who(2).as_recipient(),
        "peer",
        body,
        None,
        token,
    )
}
fn message_path(base: &Path, id: &str) -> std::path::PathBuf {
    store::store_dir(base).join(format!("{id}.json"))
}
fn messages(base: &Path) -> usize {
    std::fs::read_dir(store::store_dir(base))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                .is_some_and(canonical_uuid)
        })
        .count()
}
fn und<T: std::fmt::Debug>(result: Result<T, DirectiveError>) {
    assert_eq!(
        result.unwrap_err().code,
        csq_sdk::SdkErrorCode::Undetermined
    );
}
#[test]
fn concurrent_same_key_commits_one_actual_record_and_one_rate_slot() {
    let temp = TempDir::new().unwrap();
    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));
    let key = mint(NOW);
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let (base, key, barrier) = (temp.path().to_owned(), key.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                // Contract-following caller: a typed `lock_timeout` wrote nothing, so the
                // same-key re-issue is the product's recovery. The lock admits one holder
                // at a time and each holder finishes, so a contender loses at most once
                // per OTHER contender (THREADS - 1), however slow the host's fsync is.
                let mut losses = 0;
                loop {
                    match put(&base, NOW, &real_fs(), &key, "one") {
                        Err(e)
                            if e.cause
                                == Some(
                                    crate::sessions::directives::UndeterminedCause::LockTimeout,
                                )
                                && losses < THREADS - 1 =>
                        {
                            losses += 1;
                        }
                        other => break other.unwrap(),
                    }
                }
            })
        })
        .collect();
    let receipts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(receipts.iter().all(|r| r == &receipts[0]));
    assert_eq!(messages(temp.path()), 1);
    let records =
        vec![
            store::request_record(&store::store_dir(temp.path()), &receipts[0].0.id, NOW)
                .unwrap()
                .unwrap(),
        ];
    let limits = Limits {
        max_send_per_pair: 2,
        ..Limits::DEFAULT
    };
    super::super::limits::check_rate(
        &records,
        who(1).sender(),
        &who(2).as_recipient(),
        NOW,
        &limits,
    )
    .unwrap();
}
#[test]
fn intent_conflicts_sender_namespaces_and_mutable_names_are_bound_correctly() {
    let temp = TempDir::new().unwrap();
    let key = mint(NOW);
    let first = put(temp.path(), NOW, &real_fs(), &key, "original").unwrap();
    let before = std::fs::read(message_path(temp.path(), &first.0.id)).unwrap();
    let e = put(temp.path(), NOW, &real_fs(), &key, "changed").unwrap_err();
    assert_eq!(e.code, csq_sdk::SdkErrorCode::InvalidInput);
    assert_eq!(
        std::fs::read(message_path(temp.path(), &first.0.id)).unwrap(),
        before
    );
    let mut renamed = who(1).sender().clone();
    renamed.name = Some("renamed".into());
    renamed.handle_dir = "/other".into();
    let renamed = VerifiedSession::from_resolved(renamed);
    assert_eq!(
        replay(
            temp.path(),
            NOW,
            &real_fs(),
            &renamed,
            &key,
            intent("original")
        )
        .unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        lookup(temp.path(), NOW, &real_fs(), &who(3), &key).unwrap(),
        Lookup::NotStored
    );
    let other = send(
        temp.path(),
        NOW,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &who(3),
        who(2).as_recipient(),
        "peer",
        "original",
        None,
        &key,
    )
    .unwrap();
    assert_ne!(other.0.id, first.0.id);
    let different_key = put(temp.path(), NOW, &real_fs(), &mint(NOW), "original").unwrap();
    assert_ne!(different_key.0.id, first.0.id);
}
#[test]
fn committed_replay_precedes_liveness_rate_caps_and_parent_resolution() {
    let temp = TempDir::new().unwrap();
    let key = mint(NOW);
    let first = put(temp.path(), NOW, &real_fs(), &key, "one").unwrap();
    let limits = Limits {
        max_send_per_pair: 0,
        max_pending: 0,
        max_pending_per_sender: 0,
        max_records: 0,
    };
    assert_eq!(
        send(
            temp.path(),
            NOW + 1,
            &real_fs(),
            &limits,
            &|_| Liveness::Ended,
            &who(1),
            who(9).as_recipient(),
            "peer",
            "one",
            None,
            &key
        )
        .unwrap(),
        first
    );
    let parent = store::send(
        temp.path(),
        NOW + 1,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &who(2),
        who(1).as_recipient(),
        "parent",
        None,
    )
    .unwrap();
    let reply_key = mint(NOW + 2);
    let answer = reply(
        temp.path(),
        NOW + 2,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &who(1),
        &parent.id,
        "answer",
        &reply_key,
    )
    .unwrap();
    std::fs::remove_file(message_path(temp.path(), &parent.id)).unwrap();
    assert_eq!(
        reply(
            temp.path(),
            NOW + 3,
            &real_fs(),
            &limits,
            &|_| Liveness::Ended,
            &who(1),
            &parent.id,
            "answer",
            &reply_key
        )
        .unwrap(),
        answer
    );
}
fn fail() -> PlatformError {
    PlatformError::Io(io::Error::other("qualification injected failure"))
}
#[test]
fn actual_atomic_write_failures_never_republish_ambiguous_prepared_requests() {
    for phase in ["before_prepared", "before_public", "after_public", "commit"] {
        let temp = TempDir::new().unwrap();
        let key = mint(NOW);
        let count = std::cell::Cell::new(0);
        let real = real_fs();
        let replace = |a: &Path, b: &Path, identity: WrittenPrivateFile| {
            let ledger = b.file_name().is_some_and(|n| n == "ledger.json");
            if ledger {
                count.set(count.get() + 1);
            }
            let public = b.parent() == Some(store::store_dir(temp.path()).as_path())
                && b.file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(canonical_uuid);
            if (phase == "before_prepared" && ledger && count.get() == 3)
                || (phase == "before_public" && public)
                || (phase == "commit" && ledger && count.get() == 5)
            {
                return Err(fail());
            }
            (real.replace)(a, b, identity)?;
            if phase == "after_public" && public {
                return Err(fail());
            }
            Ok(())
        };
        let fs = FsOps {
            replace: &replace,
            ..real_fs()
        };
        und(put(temp.path(), NOW, &fs, &key, "one"));
        match phase {
            "before_prepared" => assert_eq!(
                lookup(temp.path(), NOW, &real_fs(), &who(1), &key).unwrap(),
                Lookup::NotStored
            ),
            "before_public" => {
                und(lookup(temp.path(), NOW, &real_fs(), &who(1), &key));
                und(put(temp.path(), NOW, &real_fs(), &key, "one"));
                assert_eq!(messages(temp.path()), 0);
            }
            _ => {
                let Lookup::Stored(r, _) =
                    lookup(temp.path(), NOW, &real_fs(), &who(1), &key).unwrap()
                else {
                    panic!("actual public record must prove Stored")
                };
                assert_eq!(
                    put(temp.path(), NOW, &real_fs(), &key, "one").unwrap().0.id,
                    r.id
                );
                assert_eq!(messages(temp.path()), 1);
            }
        }
    }
}
#[test]
fn ledger_outcome_survives_actual_quarantine_and_rejected_pruning() {
    let temp = TempDir::new().unwrap();
    let key = mint(NOW);
    let first = put(temp.path(), NOW, &real_fs(), &key, "one").unwrap();
    std::fs::write(message_path(temp.path(), &first.0.id), b"corrupted record").unwrap();
    store::inbox(
        temp.path(),
        NOW + 1,
        &real_fs(),
        &live,
        &who(2),
        false,
        Some(Mark::Read),
    )
    .unwrap();
    assert!(!message_path(temp.path(), &first.0.id).exists());
    for i in 0..30 {
        std::fs::write(
            store::store_dir(temp.path())
                .join("rejected")
                .join(format!("{:020}-1-{i}-{}.json", NOW, first.0.id)),
            b"bad",
        )
        .unwrap();
    }
    crate::sessions::directives::prune_rejected_as(LABEL, &store::store_dir(temp.path())).unwrap();
    assert_eq!(
        lookup(temp.path(), NOW + 2, &real_fs(), &who(1), &key).unwrap(),
        Lookup::Stored(first.0.clone(), first.1)
    );
    assert_eq!(
        put(temp.path(), NOW + 2, &real_fs(), &key, "one").unwrap(),
        first
    );
    assert_eq!(
        messages(temp.path()),
        0,
        "committed retry must not recreate a removed message"
    );
}
#[test]
fn expiry_floor_and_observed_clock_rollback_fail_closed() {
    let temp = TempDir::new().unwrap();
    let key = mint(NOW);
    put(temp.path(), NOW, &real_fs(), &key, "one").unwrap();
    let fresh = mint(NOW + WINDOW_SECS);
    assert_eq!(
        replay(
            temp.path(),
            NOW + WINDOW_SECS,
            &real_fs(),
            &who(1),
            &fresh,
            intent("fresh")
        )
        .unwrap(),
        None
    );
    expired_lookup(lookup(
        temp.path(),
        NOW + WINDOW_SECS,
        &real_fs(),
        &who(1),
        &key,
    ));
    // Probe beyond the explicit two-second stored-authority allowance with a nonfuture key.
    // A future key is rejected by strict admission before the rollback check.
    und(lookup(
        temp.path(),
        NOW + WINDOW_SECS - 3,
        &real_fs(),
        &who(1),
        &mint(NOW + WINDOW_SECS - 3),
    ));
    und(put(temp.path(), NOW + WINDOW_SECS, &real_fs(), &key, "one"));
    assert_eq!(messages(temp.path()), 1);
    assert_eq!(
        lookup(
            temp.path(),
            NOW + WINDOW_SECS,
            &real_fs(),
            &who(1),
            &mint(NOW + WINDOW_SECS + 1),
        )
        .unwrap_err()
        .code,
        csq_sdk::SdkErrorCode::InvalidIdempotencyKey
    );
}
#[test]
fn lost_or_corrupt_authority_is_never_reset_or_reported_not_stored() {
    for missing in ["ledger", "directory", "marker", "corrupt"] {
        let temp = TempDir::new().unwrap();
        let key = mint(NOW);
        let first = put(temp.path(), NOW, &real_fs(), &key, "one").unwrap();
        let before = std::fs::read(message_path(temp.path(), &first.0.id)).unwrap();
        let dir = store::store_dir(temp.path());
        match missing {
            "ledger" => std::fs::remove_file(dir.join("requests/ledger.json")).unwrap(),
            "directory" => std::fs::remove_dir_all(dir.join("requests")).unwrap(),
            "marker" => {
                std::fs::remove_file(temp.path().join(".message-requests-initialized")).unwrap()
            }
            _ => std::fs::write(dir.join("requests/ledger.json"), b"{}").unwrap(),
        }
        und(lookup(temp.path(), NOW + 1, &real_fs(), &who(1), &key));
        und(put(temp.path(), NOW + 1, &real_fs(), &key, "changed"));
        assert_eq!(
            std::fs::read(message_path(temp.path(), &first.0.id)).unwrap(),
            before
        );
    }
}
#[cfg(unix)]
#[test]
fn ledger_and_parent_symlinks_are_refused_without_touching_external_bytes() {
    use std::os::unix::fs::symlink;
    for part in ["requests", "ledger", "marker", "messages"] {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let key = mint(NOW);
        put(temp.path(), NOW, &real_fs(), &key, "one").unwrap();
        let dir = store::store_dir(temp.path());
        let target = outside.path().join("sentinel");
        std::fs::write(&target, b"external").unwrap();
        let path = match part {
            "requests" => dir.join("requests"),
            "ledger" => dir.join("requests/ledger.json"),
            "marker" => temp.path().join(".message-requests-initialized"),
            _ => dir.clone(),
        };
        if path.is_dir() {
            std::fs::remove_dir_all(&path).unwrap();
            symlink(outside.path(), &path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
            symlink(&target, &path).unwrap();
        }
        und(lookup(temp.path(), NOW, &real_fs(), &who(1), &key));
        assert_eq!(std::fs::read(&target).unwrap(), b"external");
    }
}
#[test]
fn contended_actual_message_lock_reports_only_acquisition_wait() {
    let temp = TempDir::new().unwrap();
    let dir = store::store_dir(temp.path());
    ensure_dir_as(LABEL, &dir).unwrap();
    let held = acquire_message_store_lock_as(LABEL, &dir.join(".lock")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let child_barrier = barrier.clone();
    let path = dir.join(".lock");
    let child = std::thread::spawn(move || {
        child_barrier.wait();
        let start = Instant::now();
        let _guard = acquire_message_store_lock_as(LABEL, &path).unwrap();
        start.elapsed()
    });
    barrier.wait();
    let hold = Instant::now();
    std::thread::sleep(Duration::from_millis(250));
    drop(held);
    let wait = child.join().unwrap();
    println!(
        "request_lock_probe acquisition_wait_ms={} controlled_hold_ms={} window_seconds={}",
        wait.as_millis(),
        hold.elapsed().as_millis(),
        WINDOW_SECS
    );
    assert!(wait >= Duration::from_millis(150));
    assert!(wait < Duration::from_secs(WINDOW_SECS));
}
#[test]
fn recovery_errors_carry_only_canonical_valid_tokens() {
    let token = mint(NOW);
    let e = with_key::<()>(Ok(NOW), Some(&token), |_, _| Err(uncertain())).unwrap_err();
    assert!(e.message.contains(&token));
    assert!(e.message.contains("lookup-message --idempotency-key"));
    assert!(e
        .message
        .contains(&format!("retry the same call with key={token}")));
    assert!(!e.message.contains("lookup_send"));
    let expired = with_key::<()>(Ok(NOW + WINDOW_SECS), Some(&token), |_, _| {
        panic!("expired key must not execute")
    })
    .unwrap_err();
    assert_eq!(expired.code, csq_sdk::SdkErrorCode::InvalidIdempotencyKey);
    assert!(!expired.message.contains(&token));
    assert!(!expired.message.contains("retry the same call"));
    let clock = with_key::<()>(Err(uncertain()), Some(&token), |_, _| {
        panic!("unavailable clock must not execute")
    })
    .unwrap_err();
    assert!(clock.message.contains(&token));
    let auto = with_key::<()>(Err(uncertain()), None, |_, _| {
        panic!("unavailable clock must not execute")
    })
    .unwrap_err();
    assert!(!auto.message.contains("idempotency_key="));
    let raw = "untrusted\nbody";
    let e = with_key::<()>(Ok(NOW), Some(raw), |_, _| {
        panic!("invalid tokens must not invoke an operation")
    })
    .unwrap_err();
    assert_eq!(e.code, csq_sdk::SdkErrorCode::InvalidIdempotencyKey);
    assert!(!e.message.contains(raw));
}

thread_local! { static LAST_LOCK_WAIT: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) }; }
pub(super) fn note_lock_wait(wait: Duration) {
    LAST_LOCK_WAIT.with(|value| value.set(wait));
}
thread_local! { static POSITIVE_LOCK_WAIT: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) }; }
pub(super) fn note_positive_lock_wait(wait: Duration) {
    POSITIVE_LOCK_WAIT.with(|value| value.set(wait));
}
#[test]
fn actual_lock_wait_expires_a_key_before_admission() {
    let temp = TempDir::new().unwrap();
    initialize(temp.path(), NOW - 10, &real_fs()).unwrap();
    let held =
        acquire_message_store_lock_as(LABEL, &store::store_dir(temp.path()).join(".lock")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let child_barrier = barrier.clone();
    let base = temp.path().to_owned();
    let key = mint(NOW - WINDOW_SECS + 2);
    let child = std::thread::spawn(move || {
        child_barrier.wait();
        let result = lookup(&base, NOW, &real_fs(), &who(1), &key);
        (result, POSITIVE_LOCK_WAIT.with(std::cell::Cell::get))
    });
    barrier.wait();
    let hold = Instant::now();
    std::thread::sleep(Duration::from_millis(1250));
    let hold_duration = hold.elapsed();
    drop(held);
    let (result, wait) = child.join().unwrap();
    println!("request_expiry_probe acquisition_wait_ms={} controlled_hold_ms={} key_age_at_capture_seconds=598 window_seconds={}", wait.as_millis(), hold_duration.as_millis(), WINDOW_SECS);
    assert!(wait >= Duration::from_secs(1));
    assert!(wait < Duration::from_secs(10));
    assert!(
        result.is_err(),
        "positive probe lock wait must count before an absence answer"
    );
    und(result);
    let ledger: Ledger = serde_json::from_slice(
        &std::fs::read(store::store_dir(temp.path()).join("requests/ledger.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ledger.clock, NOW,
        "elapsed expiry must not manufacture observed UTC"
    );
    assert!(ledger.floor >= NOW - WINDOW_SECS + 2);

    assert_eq!(messages(temp.path()), 0);
}
#[test]
fn full_store_loss_preserves_external_initialization_authority() {
    let temp = TempDir::new().unwrap();
    let key = mint(NOW);
    let first = put(temp.path(), NOW, &real_fs(), &key, "one").unwrap();
    std::fs::remove_dir_all(store::store_dir(temp.path())).unwrap();
    und(put(temp.path(), NOW + 1, &real_fs(), &key, "one"));
    assert!(!message_path(temp.path(), &first.0.id).exists());
    assert!(temp.path().join(".message-requests-initialized").exists());
}
#[test]
fn untracked_deterministic_id_collision_never_overwrites_existing_record() {
    let temp = TempDir::new().unwrap();
    let key = mint(NOW);
    initialize(temp.path(), NOW, &real_fs()).unwrap();
    let ordinary = store::send(
        temp.path(),
        NOW,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &who(1),
        who(2).as_recipient(),
        "existing",
        None,
    )
    .unwrap();
    let ordinary_path = message_path(temp.path(), &ordinary.id);
    let mut m: Message = serde_json::from_slice(&std::fs::read(&ordinary_path).unwrap()).unwrap();
    m.id = request_id(who(1).sender(), &key).unwrap();
    m.thread = m.id.clone();
    let bytes = serde_json::to_vec(&m).unwrap();
    std::fs::write(message_path(temp.path(), &m.id), &bytes).unwrap();
    und(put(temp.path(), NOW, &real_fs(), &key, "new"));
    assert_eq!(
        std::fs::read(message_path(temp.path(), &m.id)).unwrap(),
        bytes
    );
}

#[test]
fn frontend_clock_guard_rejects_rollback_and_ages_a_stopped_clock() {
    und(frontend_time(NOW, Instant::now(), Ok(NOW - 1)));
    und(frontend_time(
        NOW,
        Instant::now(),
        Err(DirectiveError::undet("clock unavailable")),
    ));
    let started = Instant::now()
        .checked_sub(Duration::from_secs(WINDOW_SECS))
        .unwrap();
    let decision = frontend_time(NOW, started, Ok(NOW)).unwrap();
    assert!(decision >= NOW + WINDOW_SECS);
    und(validate(&mint(NOW), decision));
}

#[test]
fn captured_future_token_is_refused_before_rounding_or_any_authority_write() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let marker = base.path().join(".message-requests-initialized");
    let ledger = store::store_dir(base.path()).join("requests/ledger.json");
    let before = std::fs::read(&ledger).unwrap();
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW + 1),)
            .unwrap_err()
            .code,
        csq_sdk::SdkErrorCode::InvalidIdempotencyKey
    );
    assert_eq!(std::fs::read(&ledger).unwrap(), before);
    assert!(marker.exists());
}
#[test]
fn cardinality_guard_is_reached_with_valid_entries_below_byte_limit() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let dir = store::store_dir(base.path());
    let make_entry = |id: String| Entry {
        issued: NOW,
        intent: "a".repeat(64),
        record: "b".repeat(64),
        receipt: Receipt {
            id: id.clone(),
            thread: id,
            status: super::super::model::Status::Queued,
            created_at: NOW,
            surfaced_at: None,
            read_at: None,
            acked_at: None,
            ack_note_framed: None,
        },
        to: who(2).as_recipient(),
        committed: true,
    };
    let mut ledger = open(&dir, NOW, NOW, &real_fs(), false).unwrap();
    for _ in 0..CAPACITY {
        let id = uuid::Uuid::new_v4().to_string();
        ledger.entries.insert(id.clone(), make_entry(id));
    }
    let bytes = serde_json::to_vec(&ledger).unwrap();
    assert!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "fixture must isolate the count bound"
    );
    write_atomic_as(LABEL, &dir.join("requests/ledger.json"), &bytes, &real_fs()).unwrap();
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW)).unwrap(),
        Lookup::NotStored,
        "all 1024 entries must pass every other strict validation"
    );
    let id = uuid::Uuid::new_v4().to_string();
    ledger.entries.insert(id.clone(), make_entry(id));
    assert_eq!(ledger.entries.len(), CAPACITY + 1);
    let bytes = serde_json::to_vec(&ledger).unwrap();
    assert!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "count+1 fixture must remain below byte cap"
    );
    write_atomic_as(LABEL, &dir.join("requests/ledger.json"), &bytes, &real_fs()).unwrap();
    und(lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW)));
}

#[test]
fn expired_only_lookup_records_clock_floor_before_refusing_rollback() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    initialize(base.path(), NOW, &real_fs()).unwrap();
    expired_lookup(lookup(
        base.path(),
        NOW + WINDOW_SECS,
        &real_fs(),
        &who(1),
        &key,
    ));
    und(lookup(base.path(), NOW + 100, &real_fs(), &who(1), &key));
    let dir = store::store_dir(base.path());
    let bytes = std::fs::read(dir.join("requests/ledger.json")).unwrap();
    let ledger: Ledger = serde_json::from_slice(&bytes).unwrap();
    assert!(ledger.clock >= NOW + WINDOW_SECS);
    assert!(ledger.floor >= NOW);
}

#[test]
fn same_observed_epoch_send_and_lookup_preserve_original_receipt() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    let receipt = put(base.path(), NOW, &real_fs(), &key, "one").unwrap();
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &who(1), &key).unwrap(),
        Lookup::Stored(receipt.0, receipt.1)
    );
    let bytes = std::fs::read(store::store_dir(base.path()).join("requests/ledger.json")).unwrap();
    let ledger: Ledger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ledger.clock, NOW);
}
#[test]
fn carried_deadline_combines_preparation_with_actual_lock_wait_before_publication() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW - 10, &real_fs()).unwrap();
    let held =
        acquire_message_store_lock_as(LABEL, &store::store_dir(base.path()).join(".lock")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let child_barrier = barrier.clone();
    let path = base.path().to_owned();
    let child = std::thread::spawn(move || {
        let key = mint(NOW);
        let started = Instant::now()
            .checked_sub(Duration::from_secs(598))
            .unwrap();
        let captured = clock(NOW, started, Ok(NOW)).unwrap();
        child_barrier.wait();
        let replayed = replay(&path, captured, &real_fs(), &who(1), &key, intent("one"));
        let wait = LAST_LOCK_WAIT.with(|value| value.get());
        let sent = send(
            &path,
            captured,
            &real_fs(),
            &Limits::DEFAULT,
            &live,
            &who(1),
            who(2).as_recipient(),
            "peer",
            "one",
            None,
            &key,
        );
        (replayed, sent, wait)
    });
    barrier.wait();
    let hold = Instant::now();
    std::thread::sleep(Duration::from_millis(1250));
    drop(held);
    let (replayed, sent, wait) = child.join().unwrap();
    println!("request_composed_deadline_probe acquisition_wait_ms={} controlled_hold_ms={} synthetic_preparation_seconds=598 window_seconds={}", wait.as_millis(), hold.elapsed().as_millis(), WINDOW_SECS);
    assert!(wait >= Duration::from_secs(1));
    und(replayed);
    und(sent);
    assert_eq!(messages(base.path()), 0);
    let bytes = std::fs::read(store::store_dir(base.path()).join("requests/ledger.json")).unwrap();
    let ledger: Ledger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ledger.clock, NOW);
    assert_eq!(ledger.floor, NOW);
    und(lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW)));
}

#[test]
fn prepared_persistence_crossing_deadline_refuses_publication_and_stays_und() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    let delayed = std::cell::Cell::new(false);
    let real = real_fs();
    // The request window opened HEADROOM before the deadline. The durable Prepared write
    // that precedes the seam must finish inside it (each fsync is 180-300ms on a loaded
    // disk), and the seam then crosses whatever is LEFT, so "persisted, then deadline" is
    // an ordering the seam establishes rather than a race against a fixed 1.25s sleep.
    const HEADROOM: Duration = Duration::from_secs(15);
    let started = Instant::now()
        .checked_sub(Duration::from_secs(WINDOW_SECS) - HEADROOM)
        .unwrap();
    let replace = |a: &Path, b: &Path, identity: WrittenPrivateFile| {
        let prepared = b.file_name().is_some_and(|n| n == "ledger.json")
            && serde_json::from_slice::<Ledger>(&std::fs::read(a).unwrap())
                .is_ok_and(|ledger| ledger.entries.values().any(|entry| !entry.committed));
        (real.replace)(a, b, identity)?;
        if prepared && !delayed.replace(true) {
            let deadline = started + Duration::from_secs(WINDOW_SECS);
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(50),
            );
        }
        Ok(())
    };
    let fs = FsOps {
        replace: &replace,
        ..real_fs()
    };
    let captured = clock(NOW, started, Ok(NOW)).unwrap();
    und(send(
        base.path(),
        captured,
        &fs,
        &Limits::DEFAULT,
        &live,
        &who(1),
        who(2).as_recipient(),
        "peer",
        "one",
        None,
        &key,
    ));
    assert!(
        delayed.get(),
        "actual durable Prepared replacement must reach the seam"
    );
    assert_eq!(messages(base.path()), 0);
    und(lookup(base.path(), NOW, &real_fs(), &who(1), &key));
    und(put(base.path(), NOW, &real_fs(), &key, "one"));
    assert_eq!(messages(base.path()), 0);
}

fn seed_authority(
    base: &Path,
    token: &str,
    committed: bool,
    publish: bool,
) -> (Receipt, Recipient) {
    initialize(base, NOW, &real_fs()).unwrap();
    let from = who(1);
    let id = request_id(from.sender(), token).unwrap();
    let m = Message {
        schema: super::super::model::SCHEMA.into(),
        id: id.clone(),
        from: from.sender().clone(),
        to: who(2).as_recipient(),
        in_reply_to: None,
        thread: id.clone(),
        body: "one".into(),
        created_at: NOW,
        noticed_at: None,
        surfaced_at: None,
        read_at: None,
        acked_at: None,
        undeliverable_at: None,
        ack_note: None,
        ack_nonce: None,
    };
    let dir = store::store_dir(base);
    let _guard = acquire_message_store_lock_as(LABEL, &dir.join(".lock")).unwrap();
    let mut ledger = open(&dir, NOW, NOW, &real_fs(), false).unwrap();
    ledger.entries.insert(
        id.clone(),
        Entry {
            issued: issued(token).unwrap(),
            intent: digest("intent").unwrap(),
            record: record_digest(&m).unwrap(),
            receipt: m.receipt(),
            to: m.to,
            committed,
        },
    );
    persist(&dir.join("requests"), &ledger, &real_fs()).unwrap();
    if publish {
        write_atomic_as(
            LABEL,
            &dir.join(format!("{id}.json")),
            &serde_json::to_vec(&m).unwrap(),
            &real_fs(),
        )
        .unwrap();
    }
    (m.receipt(), m.to)
}

// Plants unix symlinks; Windows symlink creation needs a privilege CI does not hold.
#[cfg(unix)]
#[test]
fn bounds_and_symlinks_never_become_not_stored() {
    use std::os::unix::fs::symlink;
    for part in ["requests", "ledger", "marker", "messages", "oversized"] {
        let base = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        initialize(base.path(), NOW, &real_fs()).unwrap();
        let dir = store::store_dir(base.path());
        let target = external.path().join("sentinel");
        std::fs::write(&target, b"external").unwrap();
        let path = match part {
            "requests" => dir.join("requests"),
            "marker" => base.path().join(".message-requests-initialized"),
            "messages" => dir,
            _ => dir.join("requests/ledger.json"),
        };
        if part == "oversized" {
            std::fs::write(&path, vec![b' '; MAX_RECORD_BYTES as usize + 1]).unwrap();
        } else if path.is_dir() {
            std::fs::remove_dir_all(&path).unwrap();
            symlink(external.path(), &path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
            symlink(&target, &path).unwrap();
        }
        und(lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW)));
        assert_eq!(std::fs::read(target).unwrap(), b"external");
    }
}

#[test]
fn clock_floor_expiry_and_noncanonical_metadata_fail_closed() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    seed_authority(base.path(), &key, true, false);
    let fresh = mint(NOW + WINDOW_SECS);
    assert_eq!(
        lookup(base.path(), NOW + WINDOW_SECS, &real_fs(), &who(1), &fresh).unwrap(),
        Lookup::NotStored
    );
    expired_lookup(lookup(
        base.path(),
        NOW + WINDOW_SECS,
        &real_fs(),
        &who(1),
        &key,
    ));
    und(lookup(base.path(), NOW, &real_fs(), &who(1), &key));
    let path = store::store_dir(base.path()).join("requests/ledger.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    und(lookup(
        base.path(),
        NOW + WINDOW_SECS,
        &real_fs(),
        &who(1),
        &fresh,
    ));
}

#[test]
fn committed_outcome_survives_public_record_loss_and_is_sender_bound() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    let expected = seed_authority(base.path(), &key, true, true);
    std::fs::remove_file(store::store_dir(base.path()).join(format!("{}.json", expected.0.id)))
        .unwrap();
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &who(1), &key).unwrap(),
        Lookup::Stored(expected.0, expected.1)
    );
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &who(3), &key).unwrap(),
        Lookup::NotStored
    );
}

#[test]
fn independent_initialization_marker_refuses_lost_or_replaced_authority() {
    for loss in ["requests", "messages", "ledger", "marker", "generation"] {
        let base = TempDir::new().unwrap();
        initialize(base.path(), NOW, &real_fs()).unwrap();
        let dir = store::store_dir(base.path());
        match loss {
            "requests" => std::fs::remove_dir_all(dir.join("requests")).unwrap(),
            "messages" => std::fs::remove_dir_all(&dir).unwrap(),
            "ledger" => std::fs::remove_file(dir.join("requests/ledger.json")).unwrap(),
            "marker" => {
                std::fs::remove_file(base.path().join(".message-requests-initialized")).unwrap()
            }
            _ => {
                let mut ledger = open(&dir, NOW, NOW, &real_fs(), false).unwrap();
                ledger.init = mint(NOW);
                persist(&dir.join("requests"), &ledger, &real_fs()).unwrap();
            }
        }
        und(initialize(base.path(), NOW + 1, &real_fs()));
        und(lookup(
            base.path(),
            NOW + 1,
            &real_fs(),
            &who(1),
            &mint(NOW),
        ));
    }
}

#[test]
fn initialized_unknown_key_is_not_stored_and_missing_authority_is_und() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    und(lookup(base.path(), NOW, &real_fs(), &who(1), &key));
    initialize(base.path(), NOW, &real_fs()).unwrap();
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &who(1), &key).unwrap(),
        Lookup::NotStored
    );
}

#[test]
fn prepared_lookup_is_read_only_and_missing_record_stays_undetermined() {
    for publish in [false, true] {
        let base = TempDir::new().unwrap();
        let key = mint(NOW);
        let expected = seed_authority(base.path(), &key, false, publish);
        let path = store::store_dir(base.path()).join("requests/ledger.json");
        let before = std::fs::read(&path).unwrap();
        if publish {
            assert_eq!(
                lookup(base.path(), NOW, &real_fs(), &who(1), &key).unwrap(),
                Lookup::Stored(expected.0, expected.1)
            );
        } else {
            und(lookup(base.path(), NOW, &real_fs(), &who(1), &key));
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let ledger: Ledger = serde_json::from_slice(&before).unwrap();
        assert!(ledger.entries.values().all(|entry| !entry.committed));
    }
}

#[test]
fn same_observed_epoch_initialize_and_lookup_keep_raw_clock() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW)).unwrap(),
        Lookup::NotStored
    );
    let bytes = std::fs::read(store::store_dir(base.path()).join("requests/ledger.json")).unwrap();
    let ledger: Ledger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ledger.clock, NOW);
    assert_eq!(issued(&ledger.init).unwrap(), NOW);
    assert!(ledger.floor <= ledger.clock);
}

#[test]
fn stopped_clock_expiry_advances_floor_without_synthetic_clock() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let dir = store::store_dir(base.path());
    let guard = acquire_message_store_lock_as(LABEL, &dir.join(".lock")).unwrap();
    let ledger = open(&dir, NOW, NOW + WINDOW_SECS, &real_fs(), false).unwrap();
    assert_eq!(ledger.clock, NOW);
    assert_eq!(ledger.floor, NOW);
    drop(guard);
    und(lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW)));
}

#[cfg(test)]
fn exact_evidence(pid: u32, exact: Option<u64>) -> VerifiedSession {
    let mut sender = who(pid).sender().clone();
    sender.started_exact = exact;
    VerifiedSession::from_resolved(sender)
}
#[test]
fn changing_exact_evidence_never_splits_one_request_into_duplicate_records() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let key = mint(NOW);
    let coarse = exact_evidence(1, None);
    let exact = who(1);
    let initially_unknown = lookup(base.path(), NOW, &real_fs(), &coarse, &key);
    let coarse_first = send(
        base.path(),
        NOW,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &coarse,
        who(2).as_recipient(),
        "peer",
        "one",
        None,
        &key,
    );
    let original = send(
        base.path(),
        NOW,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &exact,
        who(2).as_recipient(),
        "peer",
        "one",
        None,
        &key,
    )
    .unwrap();
    // Both real publication attempts precede this oracle: omitting the guard creates two IDs.
    assert_eq!(
        messages(base.path()),
        1,
        "None to Some must not publish two records for one token"
    );
    und(initially_unknown);
    und(coarse_first);
    let before = std::fs::read(message_path(base.path(), &original.0.id)).unwrap();
    let rejected = with_key(Ok(NOW), Some(&key), |now, key| {
        send(
            base.path(),
            now,
            &real_fs(),
            &Limits::DEFAULT,
            &live,
            &coarse,
            who(2).as_recipient(),
            "peer",
            "one",
            None,
            key,
        )
    })
    .unwrap_err();
    assert_eq!(rejected.code, csq_sdk::SdkErrorCode::Undetermined);
    assert!(rejected
        .message
        .contains("sender identity unpinned; key refused"));
    assert!(rejected.message.contains(&format!("idempotency_key={key}")));
    assert!(rejected
        .message
        .contains("lookup-message --idempotency-key"));
    assert!(
        !rejected.message.contains("unkeyed"),
        "no nonexistent frontend command advice"
    );
    let hidden = with_key(Ok(NOW), Some(&key), |_, _| -> Result<(), DirectiveError> {
        Err(DirectiveError::undet(
            "private body /private/session/path; sender identity unpinned; key refused",
        ))
    })
    .unwrap_err();
    assert_eq!(hidden.code, csq_sdk::SdkErrorCode::Undetermined);
    assert!(hidden
        .message
        .starts_with("message store: request outcome undetermined;"));
    assert!(!hidden.message.contains("private body"));
    assert!(!hidden.message.contains("/private/session/path"));
    assert!(!hidden.message.contains("identity unpinned"));
    assert!(hidden.message.contains(&format!("idempotency_key={key}")));
    und(lookup(base.path(), NOW, &real_fs(), &coarse, &key));
    assert_eq!(
        lookup(base.path(), NOW, &real_fs(), &exact, &key).unwrap(),
        Lookup::Stored(original.0.clone(), original.1)
    );
    assert_eq!(
        replay(base.path(), NOW, &real_fs(), &exact, &key, intent("one")).unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        put(base.path(), NOW, &real_fs(), &key, "one").unwrap(),
        original
    );
    assert_eq!(messages(base.path()), 1);
    assert_eq!(
        std::fs::read(message_path(base.path(), &original.0.id)).unwrap(),
        before
    );
}

fn expired_lookup(result: Result<Lookup, DirectiveError>) {
    let error = result.unwrap_err();
    assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
    assert!(error.message.contains("unrecoverable"));
    assert!(!error.message.contains("retry"));
}

#[test]
fn supplied_invalid_keys_refuse_before_operation_or_ledger() {
    let base = TempDir::new().unwrap();
    for key in [
        "private-invalid-input".to_string(),
        mint(NOW + 1),
        mint(NOW + 6),
        mint(NOW - WINDOW_SECS),
    ] {
        let error = with_key::<()>(Ok(NOW), Some(&key), |_, _| {
            initialize(base.path(), NOW, &real_fs()).unwrap();
            panic!("invalid supplied key reached ledger admission");
        })
        .unwrap_err();
        assert_eq!(
            error.code,
            csq_sdk::SdkErrorCode::InvalidIdempotencyKey,
            "supplied key must be a definite admission error"
        );
        assert!(!error.message.contains(&key));
        assert!(!error.message.contains("retry the same call"));
        assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
    }
    let eligible = mint(NOW - WINDOW_SECS + 1);
    assert_eq!(
        with_key(Ok(NOW), Some(&eligible), |_, key| Ok(key.to_owned())).unwrap(),
        eligible
    );
}

#[test]
fn malformed_and_future_lookup_keys_leave_existing_authority_untouched() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let path = store::store_dir(base.path()).join("requests/ledger.json");
    let before = std::fs::read(&path).unwrap();
    for key in [
        "private-invalid-input".to_string(),
        mint(NOW + 1),
        mint(NOW + 6),
    ] {
        let error = lookup(base.path(), NOW, &real_fs(), &who(1), &key).unwrap_err();
        assert_eq!(error.code, csq_sdk::SdkErrorCode::InvalidIdempotencyKey);
        assert!(!error.message.contains(&key));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

fn p0_snapshot(base: &Path, id: Option<&str>) -> (Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
    let dir = store::store_dir(base);
    let marker = std::fs::read(base.join(".message-requests-initialized")).unwrap();
    let ledger = std::fs::read(dir.join("requests/ledger.json")).unwrap();
    let record = id.and_then(|id| {
        let path = message_path(base, id);
        path.exists().then(|| std::fs::read(path).unwrap())
    });
    (marker, ledger, record)
}

fn p0_recover_call(
    base: &Path,
    now: u64,
    key: &str,
) -> Result<(Receipt, Recipient), DirectiveError> {
    with_key_recovery(
        Ok(now),
        Some(key),
        |observed, token| {
            recover_existing(
                base,
                observed,
                &real_fs(),
                &who(1),
                token,
                Some(intent("one")),
            )
        },
        |captured, token| put(base, captured, &real_fs(), token, "one"),
    )
}

#[test]
fn p0_unknown_temporal_key_is_typed_invalid_without_retry_loop_or_writes() {
    for issued_at in [NOW + 1, NOW + 6, NOW - WINDOW_SECS, NOW - WINDOW_SECS - 1] {
        let base = TempDir::new().unwrap();
        let key = mint(issued_at);
        let error = p0_recover_call(base.path(), NOW, &key).unwrap_err();
        assert_eq!(error.code, csq_sdk::SdkErrorCode::InvalidIdempotencyKey);
        assert!(error.message.contains("resend WITHOUT idempotency_key"));
        assert!(!error.message.contains("retry the same call"));
        assert!(!error.message.contains("lookup-message"));
        assert!(!error.message.contains(&key));
        assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
    }
}

#[test]
fn p0_unknown_temporal_key_preserves_initialized_authority_bytes() {
    for issued_at in [NOW + 1, NOW - WINDOW_SECS] {
        let base = TempDir::new().unwrap();
        initialize(base.path(), NOW, &real_fs()).unwrap();
        let before = p0_snapshot(base.path(), None);
        let error = p0_recover_call(base.path(), NOW, &mint(issued_at)).unwrap_err();
        assert_eq!(error.code, csq_sdk::SdkErrorCode::InvalidIdempotencyKey);
        assert_eq!(p0_snapshot(base.path(), None), before);
        assert_eq!(messages(base.path()), 0);
    }
}

#[test]
fn p0_malformed_key_stops_before_recovery_callback_and_authority_write() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let before = p0_snapshot(base.path(), None);
    let malformed = "private-invalid\nrequest-token";
    let result = with_key_recovery::<()>(
        Ok(NOW),
        Some(malformed),
        |_, _| panic!("malformed token must stop before recovery"),
        |_, _| panic!("malformed token must stop before admission"),
    );
    let error = result.unwrap_err();
    assert_eq!(error.code, csq_sdk::SdkErrorCode::InvalidIdempotencyKey);
    assert!(!error.message.contains(malformed));
    assert!(!error.message.contains("retry the same call"));
    assert_eq!(p0_snapshot(base.path(), None), before);
    assert_eq!(messages(base.path()), 0);
}

#[test]
fn p0_committed_receipt_replays_before_future_or_age_admission_validation() {
    for observed in [NOW - 1, NOW - 301, NOW + WINDOW_SECS] {
        let base = TempDir::new().unwrap();
        let key = mint(NOW);
        let original = put(base.path(), NOW, &real_fs(), &key, "one").unwrap();
        let before = p0_snapshot(base.path(), Some(&original.0.id));
        let recovered = p0_recover_call(base.path(), observed, &key)
            .expect("retained positive receipt must precede temporal admission");
        assert_eq!(recovered, original);
        assert_eq!(messages(base.path()), 1);
        assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
    }
}

#[test]
fn p0_still_fresh_key_replays_original_receipt_despite_later_ledger_clock() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    // Explicit observed epochs model rollback; no wall-duration claim.
    let original = put(base.path(), NOW + 10, &real_fs(), &key, "one").unwrap();
    let before = p0_snapshot(base.path(), Some(&original.0.id));
    let recovered = p0_recover_call(base.path(), NOW + 5, &key)
        .expect("fresh key must recover its original receipt despite ledger rollback");
    assert_eq!(recovered, original);
    assert_eq!(messages(base.path()), 1);
    assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
}

fn p0_stage_prepared(base: &Path, key: &str, publish: bool) -> (Receipt, Recipient) {
    let real = real_fs();
    let public_writer_reached = std::cell::Cell::new(false);
    let dir = store::store_dir(base);
    let replace = |a: &Path, b: &Path, identity: WrittenPrivateFile| {
        let public = b.parent() == Some(dir.as_path())
            && b.file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(canonical_uuid);
        if public {
            public_writer_reached.set(true);
            if !publish {
                return Err(fail());
            }
        }
        (real.replace)(a, b, identity)?;
        if public {
            return Err(fail());
        }
        Ok(())
    };
    let fs = FsOps {
        replace: &replace,
        ..real_fs()
    };
    und(put(base, NOW, &fs, key, "one"));
    assert!(
        public_writer_reached.get(),
        "actual public replacement seam must execute"
    );
    let bytes = std::fs::read(dir.join("requests/ledger.json")).unwrap();
    let ledger: Ledger = serde_json::from_slice(&bytes).unwrap();
    let id = request_id(who(1).sender(), key).unwrap();
    let entry = ledger
        .entries
        .get(&id)
        .expect("durable Prepared entry must exist");
    assert!(!entry.committed);
    assert_eq!(entry.intent, intent_digest(intent("one")).unwrap());
    assert_eq!(message_path(base, &id).exists(), publish);
    (entry.receipt.clone(), entry.to)
}

#[test]
fn p0_prepared_matching_record_recovers_under_large_rollback_without_repair() {
    for observed in [NOW - 301, NOW + WINDOW_SECS] {
        let base = TempDir::new().unwrap();
        let key = mint(NOW);
        let original = p0_stage_prepared(base.path(), &key, true);
        let before = p0_snapshot(base.path(), Some(&original.0.id));
        let recovered = p0_recover_call(base.path(), observed, &key)
            .expect("retained positive receipt must precede temporal admission");
        assert_eq!(recovered, original);
        assert_eq!(messages(base.path()), 1);
        // Byte identity also proves no committed-flag repair and no clock/floor advance.
        assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
    }
}

#[test]
fn p0_prepared_missing_or_corrupt_record_stays_undetermined_without_republication() {
    for case in ["missing", "corrupt", "different"] {
        let base = TempDir::new().unwrap();
        let key = mint(NOW);
        let original = p0_stage_prepared(base.path(), &key, case != "missing");
        let path = message_path(base.path(), &original.0.id);
        if case == "corrupt" {
            std::fs::write(&path, "{").unwrap();
        } else if case == "different" {
            let mut record: Message =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            record.body = "different fixture body".into();
            std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        let before = p0_snapshot(base.path(), Some(&original.0.id));
        let before_count = messages(base.path());
        let error = p0_recover_call(base.path(), NOW - 301, &key)
            .expect_err("missing corrupt or different Prepared record must remain undetermined");
        assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
        assert!(error.message.contains(&format!("idempotency_key={key}")));
        und(lookup(base.path(), NOW - 301, &real_fs(), &who(1), &key));
        assert_eq!(messages(base.path()), before_count);
        assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
    }
}

#[test]
fn p0_positive_recovery_requires_original_sender_and_immutable_intent() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    let original = put(base.path(), NOW, &real_fs(), &key, "one").unwrap();
    let before = p0_snapshot(base.path(), Some(&original.0.id));
    let conflict = recover_existing(
        base.path(),
        NOW - 301,
        &real_fs(),
        &who(1),
        &key,
        Some(intent("different")),
    )
    .unwrap_err();
    assert_eq!(conflict.code, csq_sdk::SdkErrorCode::InvalidInput);
    assert_eq!(
        recover_existing(
            base.path(),
            NOW - 301,
            &real_fs(),
            &who(3),
            &key,
            Some(intent("one"))
        )
        .unwrap(),
        None
    );
    assert_eq!(messages(base.path()), 1);
    assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
}

#[test]
fn p0_genuine_generated_undetermined_key_remains_retryable_and_replays_once() {
    let base = TempDir::new().unwrap();
    let captured = std::cell::RefCell::new(String::new());
    let error = with_key_recovery::<(Receipt, Recipient)>(
        Ok(NOW),
        None,
        |_, _| panic!("automatic new key must not run supplied recovery"),
        |_, key| {
            *captured.borrow_mut() = key.to_owned();
            Err(uncertain())
        },
    )
    .unwrap_err();
    let key = captured.into_inner();
    validate(&key, NOW).unwrap();
    assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
    assert!(
        error.message.contains(&format!("idempotency_key={key}")),
        "genuine generated UND must retain the minted recovery key"
    );
    assert!(error
        .message
        .contains(&format!("retry the same call with key={key}")));
    assert!(error
        .message
        .contains(&format!("lookup-message --idempotency-key {key}")));
    assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
    let first = p0_recover_call(base.path(), NOW, &key).unwrap();
    let repeated = p0_recover_call(base.path(), NOW, &key).unwrap();
    assert_eq!(repeated, first);
    assert_eq!(messages(base.path()), 1);
}

#[test]
fn p0_lookup_returns_retained_positive_before_rollback_or_expiry_without_writes() {
    for prepared in [false, true] {
        for observed in [NOW - 301, NOW + WINDOW_SECS] {
            let base = TempDir::new().unwrap();
            let key = mint(NOW);
            let original = if prepared {
                p0_stage_prepared(base.path(), &key, true)
            } else {
                put(base.path(), NOW, &real_fs(), &key, "one").unwrap()
            };
            let before = p0_snapshot(base.path(), Some(&original.0.id));
            assert_eq!(
                recover_existing(base.path(), observed, &real_fs(), &who(1), &key, None).unwrap(),
                Some(original.clone()),
            );
            // Actual public lookup outcome path, not merely the private probe.
            assert_eq!(
                lookup(base.path(), observed, &real_fs(), &who(1), &key)
                    .expect("lookup retained positive must precede temporal validation"),
                Lookup::Stored(original.0.clone(), original.1),
            );
            assert_eq!(messages(base.path()), 1);
            assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
        }
    }
}

// Asserts POSIX lock-file modes; Windows locks are path-keyed mutexes with no mode bits.
#[cfg(unix)]
#[test]
fn p0_positive_recovery_refuses_missing_or_unsafe_original_lock_without_repair() {
    use std::os::unix::fs::PermissionsExt;
    for missing in [true, false] {
        let base = TempDir::new().unwrap();
        let key = mint(NOW);
        let original = put(base.path(), NOW, &real_fs(), &key, "one").unwrap();
        let lock = store::store_dir(base.path()).join(".lock");
        if missing {
            std::fs::remove_file(&lock).unwrap();
        } else {
            std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let before = p0_snapshot(base.path(), Some(&original.0.id));
        let error = p0_recover_call(base.path(), NOW - 301, &key)
            .expect_err("missing corrupt or different Prepared record must remain undetermined");
        assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
        if missing {
            assert!(
                !lock.exists(),
                "positive recovery must not recreate missing lock"
            );
        } else {
            assert_eq!(
                std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
                0o644,
                "positive recovery must not chmod unsafe lock"
            );
        }
        assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
        assert_eq!(messages(base.path()), 1);
    }
}

// Asserts dev/ino lock identity, which only the unix flock guard carries.
#[cfg(unix)]
#[test]
fn p0_readonly_original_lock_rejects_named_inode_substitution() {
    use crate::sessions::directives::{
        acquire_existing_message_store_lock_as, acquire_store_lock_attempts_as,
    };
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let path = store::store_dir(base.path()).join(".lock");
    let held = acquire_existing_message_store_lock_as(LABEL, &path).unwrap();
    assert!(
        held.matches_path(),
        "original readonly guard must actually be held"
    );
    assert!(
        acquire_store_lock_attempts_as(LABEL, &path, 1).is_err(),
        "actual original lock inode must be busy"
    );
    let old_path = base.path().join("held-original-lock");
    std::fs::rename(&path, &old_path).unwrap();
    assert_eq!(
        std::fs::metadata(&old_path).unwrap().nlink(),
        1,
        "rename must retain old inode link so inequality is the discriminator"
    );
    assert!(
        acquire_store_lock_attempts_as(LABEL, &old_path, 1).is_err(),
        "renamed original inode remains genuinely busy"
    );
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    let replacement = acquire_existing_message_store_lock_as(LABEL, &path).unwrap();
    assert!(
        replacement.matches_path(),
        "new named inode is independently acquirable"
    );
    assert_ne!(
        std::fs::metadata(&old_path).unwrap().ino(),
        std::fs::metadata(&path).unwrap().ino()
    );
    assert!(
        !held.matches_path(),
        "named replacement must not satisfy held original readonly lock"
    );
}

// Windows binds the path-keyed store mutex to the lock file's handle identity (volume
// serial + file index); a same-path substitution must refuse, as unix refuses an inode swap.
#[cfg(windows)]
#[test]
fn p0_windows_existing_lock_rejects_named_file_substitution() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let dir = store::store_dir(base.path());
    let path = dir.join(".lock");
    assert!(
        std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()),
        "initialization must leave a lock file for recovery to bind"
    );
    let held = acquire_existing_lock(&path).unwrap();
    assert!(held.matches_path(), "original lock identity must match");
    let old_path = base.path().join("held-original-lock");
    std::fs::rename(&path, &old_path).unwrap();
    std::fs::write(&path, b"").unwrap();
    assert!(
        std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()),
        "the replacement is a regular file, so only identity can discriminate"
    );
    assert!(
        !held.matches_path(),
        "a file swapped in at the same path must not satisfy the held identity"
    );
    drop(held);
    let replacement = acquire_existing_lock(&path).unwrap();
    assert!(
        replacement.matches_path(),
        "the new file is independently bindable"
    );
}

// A held Windows store mutex times out with the typed unix code, not `lock_unavailable`.
// The holder is another thread: Windows named mutexes are re-entrant on the owning thread.
#[cfg(windows)]
#[test]
fn p0_windows_existing_lock_timeout_carries_lock_timeout_cause() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let path = store::store_dir(base.path()).join(".lock");
    let held = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let holder = {
        let (path, held, release) = (path.clone(), held.clone(), release.clone());
        std::thread::spawn(move || {
            let guard =
                crate::platform::lock::try_lock_file_bounded(&path, 1, Duration::from_millis(1))
                    .unwrap()
                    .expect("holder must acquire the free mutex");
            held.wait();
            release.wait();
            drop(guard);
        })
    };
    held.wait();
    let result = acquire_existing_lock(&path);
    release.wait();
    holder.join().unwrap();
    let error = result.err().expect("a held mutex must not be acquired");
    assert_eq!(error.cause, Some(Cause::LockTimeout));
    assert!(error.message.contains("timed out"), "{}", error.message);
    assert!(
        acquire_existing_lock(&path).is_ok(),
        "the released mutex is acquirable, so the timeout was contention"
    );
}

// `check_store_dir_as` returns `Ok(false)` for an absent directory; both twins must refuse
// on it with the fixed authority message. Can fail: before the unix fix the `false` was
// discarded and the refusal came from the open as "...: entity not found", so the exact
// message assertion reddened on unix.
#[cfg(any(unix, windows))]
#[test]
fn sync_directory_refuses_an_absent_directory_with_the_fixed_reason() {
    let base = TempDir::new().unwrap();
    let absent = base.path().join("absent");
    assert!(
        !check_store_dir_as(LABEL, &absent).unwrap(),
        "fixture must exercise the `false` branch, not an error"
    );
    let error = sync_directory(&absent).expect_err("an absent directory must refuse");
    assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
    assert_eq!(error.message, "message store: sync request authority");
    assert!(!absent.exists(), "refusal must not create the directory");
}

// A directory or junction planted at the Windows `.lock` must refuse the keyed write, not
// let it proceed. Can fail: before the fix `ensure_windows_lock_file` treated AlreadyExists
// as success for a directory, so `put` stored the message and `expect_err` reddened. The
// junction row is refused earlier by the shared lock stat ("lock is a symlink"); it is kept
// so a regression in either layer reddens.
#[cfg(windows)]
#[test]
fn windows_planted_lock_object_refuses_keyed_writes_with_an_operator_reason() {
    for planted in ["directory", "junction"] {
        let base = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        std::fs::write(external.path().join("sentinel"), b"external").unwrap();
        initialize(base.path(), NOW, &real_fs()).unwrap();
        let lock = store::store_dir(base.path()).join(".lock");
        std::fs::remove_file(&lock).unwrap();
        if planted == "directory" {
            std::fs::create_dir(&lock).unwrap();
        } else {
            crate::platform::fs_symlink_windows::symlink_exclusive(external.path(), &lock).unwrap();
        }
        let error = put(base.path(), NOW, &real_fs(), &mint(NOW), "one")
            .expect_err("a planted lock object must refuse the keyed write");
        assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined, "{planted}");
        if planted == "directory" {
            assert_eq!(error.cause, Some(Cause::LockUnavailable));
            assert!(
                error.message.contains("not a regular file"),
                "operator reason missing: {}",
                error.message
            );
        }
        assert_eq!(messages(base.path()), 0, "{planted}: nothing may be stored");
        let still = std::fs::symlink_metadata(&lock).unwrap();
        assert!(
            still.is_dir() || still.file_type().is_symlink(),
            "{planted}: the planted object must be left for the operator"
        );
        assert_eq!(
            std::fs::read(external.path().join("sentinel")).unwrap(),
            b"external"
        );
    }
}

// A hard link to the Windows `.lock` shares its identity with a name the store does not
// control: the keyed write must refuse with the specific reason. Falsifier: drop the
// link-count check in `refuse_hard_linked_lock` and `put` stores the message.
#[cfg(windows)]
#[test]
fn windows_hard_linked_lock_refuses_keyed_writes_with_a_hard_link_reason() {
    let base = TempDir::new().unwrap();
    initialize(base.path(), NOW, &real_fs()).unwrap();
    let lock = store::store_dir(base.path()).join(".lock");
    let alias = base.path().join("lock-alias");
    std::fs::hard_link(&lock, &alias).unwrap();
    let error = put(base.path(), NOW, &real_fs(), &mint(NOW), "one")
        .expect_err("a hard-linked lock must refuse the keyed write");
    assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
    assert_eq!(error.cause, Some(Cause::LockUnavailable));
    assert!(
        error.message.contains("hard link"),
        "operator reason missing: {}",
        error.message
    );
    assert_eq!(messages(base.path()), 0, "nothing may be stored");
}

// Windows twin of `bounds_and_symlinks_never_become_not_stored`. A standard user cannot
// create a symlink without SeCreateSymbolicLinkPrivilege, but can create a junction, so the
// planted objects are junctions (to a directory, which is all a junction can target). Can
// fail: a reader that followed the junction would see the external directory, find no
// ledger there and return `NotStored` instead of Undetermined, reddening `und`; a writer
// that followed it would change the sentinel.
#[cfg(windows)]
#[test]
fn windows_bounds_and_junctions_never_become_not_stored() {
    use crate::platform::fs_symlink_windows::symlink_exclusive as junction;
    for part in ["requests", "ledger", "marker", "messages", "oversized"] {
        let base = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        initialize(base.path(), NOW, &real_fs()).unwrap();
        let dir = store::store_dir(base.path());
        let target = external.path().join("sentinel");
        std::fs::write(&target, b"external").unwrap();
        let path = match part {
            "requests" => dir.join("requests"),
            "marker" => base.path().join(".message-requests-initialized"),
            "messages" => dir,
            _ => dir.join("requests/ledger.json"),
        };
        if part == "oversized" {
            std::fs::write(&path, vec![b' '; MAX_RECORD_BYTES as usize + 1]).unwrap();
        } else {
            if path.is_dir() {
                std::fs::remove_dir_all(&path).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
            junction(external.path(), &path).unwrap();
            assert!(
                std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()),
                "{part}: fixture must plant a reparse point, not a plain directory"
            );
        }
        und(lookup(base.path(), NOW, &real_fs(), &who(1), &mint(NOW)));
        assert_eq!(std::fs::read(&target).unwrap(), b"external", "{part}");
        assert_eq!(
            std::fs::read_dir(external.path()).unwrap().count(),
            1,
            "{part}: nothing may be written through the junction"
        );
    }
}

// Platform-neutral: positive recovery never initializes, so a missing lock refuses and
// stays missing on every target. Can fail: a recovery path that created the lock (for
// example by routing through `under_lock`, which creates it on Windows) reddens
// `!lock.exists()`; one that proceeded without it reddens `expect_err`.
#[test]
fn p0_positive_recovery_refuses_missing_original_lock_without_creating_it() {
    let base = TempDir::new().unwrap();
    let key = mint(NOW);
    let original = put(base.path(), NOW, &real_fs(), &key, "one").unwrap();
    let lock = store::store_dir(base.path()).join(".lock");
    assert!(
        lock.exists(),
        "fixture: a stored request leaves a lock file"
    );
    std::fs::remove_file(&lock).unwrap();
    let before = p0_snapshot(base.path(), Some(&original.0.id));
    let error = p0_recover_call(base.path(), NOW - 301, &key)
        .expect_err("recovery without its original lock must remain undetermined");
    assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
    assert!(
        !lock.exists(),
        "positive recovery must not recreate missing lock"
    );
    assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
    assert_eq!(messages(base.path()), 1);
}

// Windows twin of the unsafe-lock half of
// `p0_positive_recovery_refuses_missing_or_unsafe_original_lock_without_repair`: Windows
// locks carry no mode bits, so "unsafe" is a junction or directory at `.lock`. Can fail:
// recovery that followed the junction, or replaced the planted object with a fresh file,
// reddens `expect_err` or the "left in place" assertion.
#[cfg(windows)]
#[test]
fn p0_windows_positive_recovery_refuses_planted_lock_without_repair() {
    for planted in ["directory", "junction"] {
        let base = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        std::fs::write(external.path().join("sentinel"), b"external").unwrap();
        let key = mint(NOW);
        let original = put(base.path(), NOW, &real_fs(), &key, "one").unwrap();
        let lock = store::store_dir(base.path()).join(".lock");
        std::fs::remove_file(&lock).unwrap();
        if planted == "directory" {
            std::fs::create_dir(&lock).unwrap();
        } else {
            crate::platform::fs_symlink_windows::symlink_exclusive(external.path(), &lock).unwrap();
        }
        let before = p0_snapshot(base.path(), Some(&original.0.id));
        let error = p0_recover_call(base.path(), NOW - 301, &key)
            .expect_err("recovery under a planted lock object must remain undetermined");
        assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined, "{planted}");
        let still = std::fs::symlink_metadata(&lock).unwrap();
        assert!(
            still.is_dir() || still.file_type().is_symlink(),
            "{planted}: the planted object must be left in place, not repaired"
        );
        assert_eq!(p0_snapshot(base.path(), Some(&original.0.id)), before);
        assert_eq!(messages(base.path()), 1);
        assert_eq!(
            std::fs::read(external.path().join("sentinel")).unwrap(),
            b"external"
        );
    }
}
