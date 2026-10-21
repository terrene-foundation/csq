//! Real JSON/filesystem fixtures exercising the production archive mutation path.
use super::*;
use crate::messaging::model::Surface;
use crate::sessions::directives::real_fs;
use std::collections::BTreeSet;
use tempfile::TempDir;

const START: u64 = 1_000_000;
const NOW: u64 = START + ARCHIVE_AFTER_SECS + 100;

fn id(n: usize) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}
fn recipient() -> Recipient {
    Recipient {
        pid: 2,
        started_at: 5_000,
        surface: Surface::Codex,
        started_exact: None,
    }
}
fn sender(pid: u32) -> Sender {
    Sender {
        pid,
        started_at: 5_000,
        surface: Surface::Codex,
        handle_dir_hash: format!("fixture{pid}"),
        handle_dir: format!("/fixture/{pid}"),
        name: None,
        started_exact: None,
    }
}
#[cfg(test)]
fn who() -> VerifiedSession {
    VerifiedSession::from_resolved(sender(2))
}
fn live(_: &Recipient) -> Liveness {
    Liveness::Live
}
fn record(n: usize, read: bool) -> Message {
    Message {
        schema: SCHEMA.into(),
        id: id(n),
        from: sender(1),
        to: recipient(),
        in_reply_to: None,
        thread: id(n),
        body: "fixture body".into(),
        created_at: START - 10,
        noticed_at: None,
        surfaced_at: None,
        read_at: read.then_some(START),
        acked_at: None,
        undeliverable_at: (!read).then_some(START),
        ack_note: None,
        ack_nonce: None,
    }
}
fn fixture() -> (TempDir, PathBuf, PathBuf) {
    let temp = TempDir::new().unwrap();
    let dir = store_dir(temp.path());
    let archive = archive_dir(&dir);
    ensure_dir_as(LABEL, &dir).unwrap();
    ensure_dir_as(LABEL, &archive).unwrap();
    (temp, dir, archive)
}
fn seed(dir: &Path, message: &Message) {
    save(dir, message, &real_fs()).unwrap();
    let loaded = load_one(dir, &message.id)
        .map_err(|e| e.into_err_as(LABEL))
        .expect("fixture must pass production record validation");
    assert_eq!(loaded.as_ref(), Some(message));
}
fn pass(base: &Path) -> Result<(), DirectiveError> {
    locked(
        base,
        NOW,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        |_, _| Ok(()),
    )
}
// Count message records, using the canonical filename filter already in production load_core.
fn names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.strip_suffix(".json").is_some_and(canonical_uuid))
        .collect()
}
fn bytes(dir: &Path, n: usize) -> Vec<u8> {
    std::fs::read(record_path(dir, &id(n))).unwrap()
}

#[test]
fn full_archive_moves_128_with_two_equal_duplicates_and_exact_126_oldest_evictions() {
    let (temp, dir, archive) = fixture();
    for n in 1..=ARCHIVE_CAPACITY {
        let mut m = record(n, true);
        // Reverse insertion order cannot change tie-breaking by canonical ID.
        if n > ARCHIVE_CAPACITY - 2 {
            m.read_at = Some(START + 1);
        }
        seed(&archive, &m);
    }
    let retained = bytes(&archive, 127);
    for n in ARCHIVE_CAPACITY - 1..=ARCHIVE_CAPACITY {
        std::fs::hard_link(record_path(&archive, &id(n)), record_path(&dir, &id(n))).unwrap();
    }
    let mut incoming_bytes = Vec::new();
    for n in 9_001..=9_126 {
        let mut m = record(n, true);
        m.read_at = Some(START + 10);
        seed(&dir, &m);
        incoming_bytes.push((n, bytes(&dir, n)));
    }
    let mut queued = record(20_001, false);
    queued.undeliverable_at = None;
    seed(&dir, &queued);
    let mut surfaced = queued.clone();
    surfaced.id = id(20_002);
    surfaced.thread = surfaced.id.clone();
    surfaced.surfaced_at = Some(START + 1);
    seed(&dir, &surfaced);
    let controls = [bytes(&dir, 20_001), bytes(&dir, 20_002)];
    // N existing + 126 new names (128 active minus 2 recovery duplicates) - 126 victims = M.
    let expected_archive = names(&archive).len() + incoming_bytes.len() - 126;
    assert_eq!(incoming_bytes.len(), ARCHIVE_BATCH - 2);
    assert_eq!(expected_archive, ARCHIVE_CAPACITY);

    pass(temp.path()).unwrap();
    assert_eq!(names(&archive).len(), expected_archive);
    assert_eq!(
        retained_archive_count(temp.path(), NOW).unwrap(),
        ARCHIVE_CAPACITY
    );
    assert_eq!(
        names(&dir),
        BTreeSet::from([
            format!("{}.json", queued.id),
            format!("{}.json", surfaced.id)
        ])
    );
    for n in 1..=126 {
        assert!(!record_path(&archive, &id(n)).exists());
    }
    assert_eq!(bytes(&archive, 127), retained);
    for (n, original) in incoming_bytes {
        assert_eq!(bytes(&archive, n), original);
    }
    assert_eq!([bytes(&dir, 20_001), bytes(&dir, 20_002)], controls);
    let history = inbox(temp.path(), NOW, &real_fs(), &live, &who(), false, None).unwrap();
    assert_eq!(history.len(), ARCHIVE_CAPACITY + 2);
    assert_eq!(
        history
            .iter()
            .map(|m| m.id.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        history.len()
    );
    assert_eq!(
        inbox(temp.path(), NOW, &real_fs(), &live, &who(), true, None)
            .unwrap()
            .len(),
        2
    );
    assert!(!archive.join("rejected").exists());

    let receipt = ack(
        temp.path(),
        NOW,
        &real_fs(),
        &live,
        &who(),
        &id(9_001),
        Some("done"),
    )
    .unwrap();
    assert_eq!(
        ack(
            temp.path(),
            NOW + 1,
            &real_fs(),
            &live,
            &who(),
            &id(9_001),
            Some("done")
        )
        .unwrap(),
        receipt
    );
    let (answer, to) = reply(
        temp.path(),
        NOW + 2,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &who(),
        &id(9_001),
        "answer",
    )
    .unwrap();
    assert_eq!(answer.thread, id(9_001));
    assert!(to.same_session(&sender(1).as_recipient()));
    let gone_ack = ack(
        temp.path(),
        NOW + 3,
        &real_fs(),
        &live,
        &who(),
        &id(1),
        None,
    )
    .unwrap_err();
    assert_eq!(gone_ack.code, SdkErrorCode::InvalidInput);
    assert_eq!(gone_ack.message, GONE_MESSAGE);
    let gone_reply = reply(
        temp.path(),
        NOW + 4,
        &real_fs(),
        &Limits::DEFAULT,
        &live,
        &who(),
        &id(1),
        "answer",
    )
    .unwrap_err();
    assert_eq!(gone_reply.code, SdkErrorCode::InvalidInput);
    assert_eq!(gone_reply.message, GONE_MESSAGE);
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY);
}

#[test]
fn full_archive_no_incoming_does_not_evict_oldest_ties() {
    let (temp, _, archive) = fixture();
    for n in (1..=ARCHIVE_CAPACITY).rev() {
        seed(&archive, &record(n, true));
    }
    let before = names(&archive);
    let oldest = bytes(&archive, 1);
    pass(temp.path()).unwrap();
    assert_eq!(names(&archive), before);
    assert_eq!(bytes(&archive, 1), oldest);
}

#[test]
fn full_archive_protects_unread_ended_and_limits_batch_to_available_victims() {
    let (temp, dir, archive) = fixture();
    for n in 1..=ARCHIVE_CAPACITY {
        seed(&archive, &record(n, false));
    }
    seed(&dir, &record(9_001, true));
    seed(&dir, &record(9_002, true));
    let before = names(&archive);
    pass(temp.path()).unwrap();
    assert_eq!(names(&archive), before);
    assert_eq!(
        names(&dir).len(),
        2,
        "valid mutation succeeds when no victims exist"
    );
    seed(&archive, &record(1, true));
    pass(temp.path()).unwrap();
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY);
    assert_eq!(
        names(&dir).len(),
        1,
        "one eligible victim permits only one new archive name"
    );
    assert!(!record_path(&archive, &id(1)).exists());
    for n in 2..=ARCHIVE_CAPACITY {
        assert!(record_path(&archive, &id(n)).exists());
    }
}

#[test]
fn first_link_failure_in_full_pass_preserves_all_retained_history() {
    let (temp, dir, archive) = fixture();
    for n in 1..=ARCHIVE_CAPACITY {
        seed(&archive, &record(n, true));
    }
    seed(&dir, &record(9_001, true));
    let mut queued = record(20_001, false);
    queued.undeliverable_at = None;
    seed(&dir, &queued);
    let before = names(&archive);
    let failed_source = record_path(&dir, &id(9_001));
    // Fault at the production boundary after loading, before archival hard_link.
    let fault = |_: &Recipient| {
        std::fs::remove_file(&failed_source).unwrap();
        Liveness::Live
    };
    let error = locked(
        temp.path(),
        NOW,
        &real_fs(),
        &Limits::DEFAULT,
        &fault,
        |_, _| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code, SdkErrorCode::Undetermined);
    assert_eq!(names(&archive), before);
    assert!(record_path(&dir, &queued.id).exists());
}

#[test]
fn unequal_collision_rolls_back_new_links_before_any_history_deletion() {
    let (temp, dir, archive) = fixture();
    let new = record(9_001, true);
    let conflicting = record(9_002, true);
    seed(&dir, &new);
    seed(&dir, &conflicting);
    for n in 1..ARCHIVE_CAPACITY {
        seed(&archive, &record(n, true));
    }
    let mut other = conflicting.clone();
    other.body = "different fixture body".into();
    seed(&archive, &other);
    let before = names(&archive);
    let prepared = prepare_records(&archive, MAX_ARCHIVED_RECORDS);
    let retained = prune_archive(&dir, NOW, &prepared).unwrap();
    // Exercise the actual production hard-link path in deterministic candidate order.
    let error =
        archive_terminal_records(&dir, NOW, &mut vec![new, conflicting], retained).unwrap_err();
    assert_eq!(error.code, SdkErrorCode::Undetermined);
    assert_eq!(names(&archive), before);
    assert_eq!(names(&dir).len(), 2);
    assert_eq!(bytes(&archive, 9_002), serde_json::to_vec(&other).unwrap());
    // Remove only the fixture's conflict; a subsequent real full mutation succeeds.
    std::fs::remove_file(record_path(&archive, &id(9_002))).unwrap();
    pass(temp.path()).unwrap();
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY);
    assert!(names(&dir).is_empty());
}

#[test]
fn interrupted_link_batch_recovers_exact_capacity_without_evicting_duplicate_history() {
    let (temp, dir, archive) = fixture();
    for n in 1..=ARCHIVE_CAPACITY {
        seed(&archive, &record(n, true));
    }
    for n in 9_001..=9_003 {
        let mut m = record(n, true);
        m.read_at = Some(START + 1);
        seed(&dir, &m);
        std::fs::hard_link(record_path(&dir, &m.id), record_path(&archive, &m.id)).unwrap();
    }
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY + 3);
    pass(temp.path()).unwrap();
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY);
    assert!(names(&dir).is_empty());
    for n in 1..=3 {
        assert!(!record_path(&archive, &id(n)).exists());
    }
    for n in 9_001..=9_003 {
        assert!(record_path(&archive, &id(n)).exists());
    }
}

#[test]
fn retained_archive_count_is_strict_read_only_and_uses_last_transition_retention() {
    let (temp, _, archive) = fixture();
    seed(&archive, &record(1, true));
    let mut expired = record(2, true);
    expired.created_at = NOW - RETENTION_SECS;
    expired.read_at = Some(NOW - RETENTION_SECS);
    seed(&archive, &expired);
    assert_eq!(retained_archive_count(temp.path(), NOW).unwrap(), 1);
    assert!(
        record_path(&archive, &expired.id).exists(),
        "read-only count cannot prune"
    );
    let bad_path = record_path(&archive, &id(3));
    std::fs::write(&bad_path, b"invalid fixture JSON").unwrap();
    assert_eq!(
        retained_archive_count(temp.path(), NOW).unwrap_err().code,
        SdkErrorCode::Undetermined
    );
    assert_eq!(std::fs::read(&bad_path).unwrap(), b"invalid fixture JSON");
    assert!(
        !archive.join("rejected").exists(),
        "strict count cannot quarantine"
    );
}

#[test]
fn interrupted_8110_archive_with_different_incoming_cohort_recovers_without_exceeding_8128() {
    let (temp, dir, archive) = fixture();
    for n in 1..=ARCHIVE_CAPACITY {
        seed(&archive, &record(n, true));
    }
    for n in 9_001..=9_110 {
        let mut m = record(n, true);
        m.read_at = Some(START + 1);
        seed(&dir, &m);
        std::fs::hard_link(record_path(&dir, &m.id), record_path(&archive, &m.id)).unwrap();
    }
    let mut incoming = Vec::new();
    for n in 10_001..=10_128 {
        let mut m = record(n, true);
        m.read_at = Some(START + 2);
        seed(&dir, &m);
        incoming.push(m);
    }
    assert_eq!(names(&archive).len(), 8_110);
    let prepared = prepare_records(&archive, MAX_ARCHIVED_RECORDS);
    let retained = prune_archive(&dir, NOW, &prepared).unwrap();
    // Production selector with the later eligible cohort first, independently of readdir.
    archive_terminal_records(&dir, NOW, &mut incoming, retained).unwrap();
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY);
    assert_eq!(
        incoming.len(),
        110,
        "only 18 new links fit the transient 8128 envelope"
    );
    for n in 1..=128 {
        assert!(!record_path(&archive, &id(n)).exists());
    }
    for n in 9_001..=9_110 {
        assert!(record_path(&archive, &id(n)).exists());
        assert!(record_path(&dir, &id(n)).exists());
    }
    pass(temp.path()).unwrap();
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY);
}

#[test]
fn interrupted_8128_archive_recovers_even_when_current_cohort_has_zero_link_room() {
    let (_temp, dir, archive) = fixture();
    for n in 1..=ARCHIVE_CAPACITY {
        seed(&archive, &record(n, true));
    }
    for n in 9_001..=9_128 {
        let mut m = record(n, true);
        m.read_at = Some(START + 1);
        seed(&dir, &m);
        std::fs::hard_link(record_path(&dir, &m.id), record_path(&archive, &m.id)).unwrap();
    }
    let new = record(10_001, true);
    seed(&dir, &new);
    let prepared = prepare_records(&archive, MAX_ARCHIVED_RECORDS);
    let retained = prune_archive(&dir, NOW, &prepared).unwrap();
    let mut cohort = vec![new];
    archive_terminal_records(&dir, NOW, &mut cohort, retained).unwrap();
    assert_eq!(names(&archive).len(), ARCHIVE_CAPACITY);
    assert_eq!(cohort.len(), 1);
    assert!(!record_path(&archive, &id(10_001)).exists());
    for n in 9_001..=9_128 {
        assert!(record_path(&archive, &id(n)).exists());
        assert!(record_path(&dir, &id(n)).exists());
    }
}

#[cfg(unix)]
#[test]
fn retained_archive_count_refuses_symlinked_messages_parent_without_external_mutation() {
    let temp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let external_archive = outside.path().join(ARCHIVE_DIR);
    ensure_dir_as(LABEL, &external_archive).unwrap();
    seed(&external_archive, &record(1, true));
    let before = bytes(&external_archive, 1);
    std::os::unix::fs::symlink(outside.path(), store_dir(temp.path())).unwrap();
    assert_eq!(
        retained_archive_count(temp.path(), NOW).unwrap_err().code,
        SdkErrorCode::Undetermined
    );
    assert_eq!(names(&external_archive).len(), 1);
    assert_eq!(bytes(&external_archive, 1), before);
}
