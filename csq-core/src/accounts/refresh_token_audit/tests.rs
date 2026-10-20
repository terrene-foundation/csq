use super::*;
use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
use crate::testing::identity_fixtures::fixture_uuid_for_slot;
use crate::types::{AccessToken, AccountNum, RefreshToken};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

const SENTINEL: &str = "SENTINEL-RT-7f3a9c41d2";

fn creds(refresh: &str) -> CredentialFile {
    CredentialFile::Anthropic(AnthropicCredentialFile {
        claude_ai_oauth: OAuthPayload {
            access_token: AccessToken::new(format!("at-for-{refresh}")),
            refresh_token: RefreshToken::new(refresh.into()),
            expires_at: 4_102_444_800_000,
            scopes: vec![],
            subscription_type: None,
            rate_limit_tier: None,
            extra: Default::default(),
        },
        extra: Default::default(),
    })
}

/// Bind `slot` to its fixture identity and write that identity's canonical credential.
fn bind(base: &Path, slot: u16, refresh: &str) {
    let uuid = fixture_uuid_for_slot(slot);
    let pp = crate::accounts::profiles::profiles_path(base);
    let mut pf = if pp.exists() {
        crate::accounts::profiles::load(&pp).unwrap()
    } else {
        crate::accounts::profiles::ProfilesFile::empty()
    };
    pf.by_slot.insert(slot.to_string(), uuid);
    crate::accounts::profiles::save(&pp, &pf).unwrap();
    let path = identity_store::credentials_path_for(base, uuid);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
    crate::platform::fs::secure_dir(path.parent().unwrap()).unwrap();
    crate::credentials::save(&path, &creds(refresh)).unwrap();
}

fn corrupt_canonical(base: &Path, slot: u16) {
    let path = identity_store::credentials_path_for(base, fixture_uuid_for_slot(slot));
    std::fs::write(&path, b"{ not json").unwrap();
    crate::platform::fs::secure_file(&path).unwrap();
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<String>>>);
struct Collect<'a>(&'a mut String);
impl tracing::field::Visit for Collect<'_> {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{}={v:?} ", f.name()));
    }
}
impl tracing::Subscriber for Events {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::TRACE)
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Collect(&mut line));
        self.0.lock().unwrap().push(line);
    }
}
/// A test that reaches the degraded-state warning callsite WITHOUT capturing it must hold the
/// shared capture lock (see `crate::testing::TRACING_CAPTURE_LOCK`): its first hit of that
/// callsite can cache it as disabled while another test's capture is active, which made the
/// capturing tests fail intermittently under parallel execution.
fn hold_capture_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::testing::TRACING_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn capture<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
    let _g = crate::testing::TRACING_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let ev = Events::default();
    let out = tracing::subscriber::with_default(ev.clone(), run);
    let lines = std::mem::take(&mut *ev.0.lock().unwrap());
    (out, lines)
}

#[test]
fn compare_visits_every_byte_even_on_first_byte_mismatch() {
    let mut visited = 0;
    assert!(!tokens_match(b"Xbcdefgh", b"abcdefgh", &mut visited));
    assert_eq!(visited, 8, "a mismatch at byte 0 must not stop the walk");
    let mut v2 = 0;
    assert!(!tokens_match(b"abc", b"abcdef", &mut v2));
    assert_eq!(
        v2, 6,
        "length difference folds into the verdict, walk is full"
    );
    let mut v3 = 0;
    assert!(tokens_match(b"abcdef", b"abcdef", &mut v3));
    assert_eq!(v3, 6);
}

#[test]
fn shared_refresh_token_warns_naming_both_slots_and_suppresses_exactly_one() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 2, SENTINEL);
    bind(dir.path(), 5, SENTINEL);
    bind(dir.path(), 7, "distinct-rt-seven");
    let (report, logs) = capture(|| run_startup_audit(dir.path()));
    assert_eq!(report.slots[&2], SlotState::Holder { others: vec![5] });
    assert_eq!(report.slots[&5], SlotState::Suppressed { holder: 2 });
    assert_eq!(report.slots[&7], SlotState::Clear);
    let sup = suppressed_slots(dir.path());
    assert_eq!(sup.len(), 1, "exactly one of the pair is suppressed");
    assert!(is_refresh_suppressed(dir.path(), 5));
    assert!(
        !is_refresh_suppressed(dir.path(), 2),
        "the holder keeps refreshing"
    );
    assert!(!is_refresh_suppressed(dir.path(), 7));
    let warn = logs
        .iter()
        .find(|l| l.contains("refresh_duplicate_grant_detected"))
        .expect("fixed-vocabulary warning");
    assert!(
        warn.contains("slot=5") && warn.contains("holder_slot=2"),
        "{warn}"
    );
    let lines = operator_lines(dir.path()).join("\n");
    assert!(
        lines.contains("slots 2 and 5") && lines.contains("csq login 5"),
        "{lines}"
    );
}

#[test]
fn distinct_tokens_report_nothing() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, "rt-one");
    bind(dir.path(), 2, "rt-two");
    let (report, logs) = capture(|| run_startup_audit(dir.path()));
    assert!(report.slots.values().all(|s| *s == SlotState::Clear));
    assert!(suppressed_slots(dir.path()).is_empty());
    assert!(!state_path(dir.path()).exists());
    assert!(logs.iter().all(|l| !l.contains("duplicate_grant")));
    assert!(operator_lines(dir.path()).is_empty());
}

#[test]
fn unreadable_canonical_is_undetermined_and_changes_no_suppression() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    run_startup_audit(dir.path());
    assert!(is_refresh_suppressed(dir.path(), 2));
    // Slot 2's saved credential becomes unreadable: UNDETERMINED, suppression kept.
    corrupt_canonical(dir.path(), 2);
    let report = run_startup_audit(dir.path());
    assert_eq!(report.slots[&2], SlotState::Undetermined);
    assert!(
        is_refresh_suppressed(dir.path(), 2),
        "never un-suppressed on a failed read"
    );
    assert!(operator_lines(dir.path())
        .join("\n")
        .contains("slot 2 UNDETERMINED"));
    // A never-suppressed slot that cannot be read is not suppressed either.
    let fresh = TempDir::new().unwrap();
    bind(fresh.path(), 1, SENTINEL);
    bind(fresh.path(), 2, SENTINEL);
    corrupt_canonical(fresh.path(), 2);
    let r = run_startup_audit(fresh.path());
    assert_eq!(r.slots[&2], SlotState::Undetermined);
    assert_eq!(r.slots[&1], SlotState::Clear);
    assert!(
        suppressed_slots(fresh.path()).is_empty(),
        "undetermined never suppresses"
    );
}

#[test]
fn login_clears_the_suppression_of_that_slot_only() {
    let dir = TempDir::new().unwrap();
    for s in [1, 2, 3] {
        bind(dir.path(), s, SENTINEL);
    }
    run_startup_audit(dir.path());
    assert_eq!(suppressed_slots(dir.path()).len(), 2);
    // Canonicals still collide here, so only an explicit clear can lift slot 3.
    clear_on_login(dir.path(), 3);
    assert!(!is_refresh_suppressed(dir.path(), 3));
    assert!(
        is_refresh_suppressed(dir.path(), 2),
        "other slots are untouched"
    );
}

#[test]
fn corrupt_state_file_falls_back_to_a_live_audit_and_is_never_rewritten() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    std::fs::write(state_path(dir.path()), b"garbage").unwrap();
    let (sup, logs) = capture(|| suppressed_slots(dir.path()));
    assert_eq!(
        sup,
        BTreeMap::from([(2u16, 1u16)]),
        "an unreadable state never means suppress nothing: the live audit decides this tick"
    );
    assert!(logs
        .iter()
        .any(|l| l.contains("refresh_suppression_state_unreadable")));
    run_startup_audit(dir.path());
    assert!(is_refresh_suppressed(dir.path(), 2));
    assert_eq!(
        std::fs::read(state_path(dir.path())).unwrap(),
        b"garbage",
        "r7: an unreadable primary is never overwritten, even when no slot is undetermined"
    );
}

#[test]
fn no_token_bytes_in_logs_operator_text_or_state() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 4, SENTINEL);
    bind(dir.path(), 9, SENTINEL);
    bind(dir.path(), 11, "other-rt");
    corrupt_canonical(dir.path(), 11);
    let (text, logs) = capture(|| {
        run_startup_audit(dir.path());
        let mut t = operator_lines(dir.path()).join("\n");
        t.push_str(&format!("{:?}", audit(dir.path())));
        t
    });
    let state = std::fs::read_to_string(state_path(dir.path())).unwrap();
    assert!(!logs.is_empty());
    let access = format!("at-for-{SENTINEL}");
    for hay in logs
        .iter()
        .map(String::as_str)
        .chain([text.as_str(), state.as_str()])
    {
        assert!(
            !hay.contains(SENTINEL) && !hay.contains(&access),
            "token bytes leaked: {hay}"
        );
    }
}

// ── r6 brake ───────────────────────────────────────────────────────────

fn set_binding(base: &Path, slot: &str, id: Option<IdentityId>) {
    let pp = crate::accounts::profiles::profiles_path(base);
    let mut pf = crate::accounts::profiles::load(&pp).unwrap();
    match id {
        Some(id) => pf.by_slot.insert(slot.to_string(), id),
        None => pf.by_slot.remove(slot),
    };
    crate::accounts::profiles::save(&pp, &pf).unwrap();
}

fn make_config(base: &Path, slot: u16) {
    let n = AccountNum::try_from(slot).unwrap();
    let dir = base.join(format!("config-{slot}"));
    std::fs::create_dir_all(&dir).unwrap();
    crate::accounts::markers::write_csq_account_legacy(&dir, n).unwrap();
    std::fs::write(dir.join("settings.json"), "{}").unwrap();
}

/// Run `f` on a helper thread and fail (instead of hanging the suite) if it blocks.
#[cfg(unix)]
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("the state reader blocked")
}

/// H-1: tokens becoming unequal NEVER release a suppression. The holder refreshes (its
/// canonical now differs), the daemon restarts (a fresh audit), and a login of ANOTHER
/// slot completes: the suppressed slot still must not present its stale grant.
#[test]
fn suppression_survives_holder_rotation_restart_audit_and_another_slots_login() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    bind(dir.path(), 7, "rt-seven");
    run_startup_audit(dir.path());
    assert!(is_refresh_suppressed(dir.path(), 2));
    bind(dir.path(), 1, "holder-rotated-rt");
    let report = run_startup_audit(dir.path());
    assert_eq!(report.slots[&2], SlotState::Clear, "tokens now differ");
    assert!(
        is_refresh_suppressed(dir.path(), 2),
        "a restart audit must not release the suppression"
    );
    clear_on_login(dir.path(), 7);
    assert!(
        is_refresh_suppressed(dir.path(), 2),
        "another slot's login must not release it"
    );
    clear_on_login(dir.path(), 2);
    assert!(
        !is_refresh_suppressed(dir.path(), 2),
        "that slot's own login does"
    );
}

/// Release (ii): the bound identity changing, or the slot being unbound, ends it.
#[test]
fn suppression_releases_when_the_bound_identity_changes_or_the_slot_is_unbound() {
    for unbind in [false, true] {
        let dir = TempDir::new().unwrap();
        bind(dir.path(), 1, SENTINEL);
        bind(dir.path(), 2, SENTINEL);
        run_startup_audit(dir.path());
        assert!(is_refresh_suppressed(dir.path(), 2));
        let other = if unbind {
            None
        } else {
            Some(fixture_uuid_for_slot(9))
        };
        set_binding(dir.path(), "2", other);
        assert!(
            !is_refresh_suppressed(dir.path(), 2),
            "unbind={unbind}: an unrelated binding is not suppressed"
        );
        assert!(suppressed_slots(dir.path()).is_empty());
    }
}

/// M1 + corr L-1: a verdict the audit read before a binding changed is dropped by `apply`.
#[test]
fn apply_drops_a_verdict_whose_binding_changed_since_the_audit_read_it() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    let report = audit(dir.path());
    assert_eq!(report.slots[&2], SlotState::Suppressed { holder: 1 });
    // Slot 2 re-binds (a login publishing, then clearing nothing) before apply locks.
    set_binding(dir.path(), "2", Some(fixture_uuid_for_slot(9)));
    apply(dir.path(), &report).unwrap();
    assert!(
        !is_refresh_suppressed(dir.path(), 2),
        "the stale verdict must not suppress the fresh binding"
    );
    assert!(suppressed_slots(dir.path()).is_empty());
}

#[test]
fn non_canonical_slot_keys_are_rejected() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    // "01" is not the key the writers mint; it must not collapse onto slot 1.
    set_binding(dir.path(), "01", Some(fixture_uuid_for_slot(5)));
    let path = identity_store::credentials_path_for(dir.path(), fixture_uuid_for_slot(5));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::platform::fs::secure_dir(path.parent().unwrap()).unwrap();
    crate::credentials::save(&path, &creds(SENTINEL)).unwrap();
    let report = audit(dir.path());
    assert_eq!(report.slots.len(), 1, "{:?}", report.slots);
    assert_eq!(report.slots[&1], SlotState::Clear);
    run_startup_audit(dir.path());
    assert!(suppressed_slots(dir.path()).is_empty());
    // A persisted entry under a non-canonical key never counts either.
    let id = fixture_uuid_for_slot(5);
    std::fs::write(
        state_path(dir.path()),
        format!(r#"{{"version":2,"suppressed":{{"01":{{"holder":1,"identity_uuid":"{id}"}}}}}}"#),
    )
    .unwrap();
    assert!(suppressed_slots(dir.path()).is_empty());
}

/// M1: `csq move` of a suppressed slot keeps the suppression on the moved identity, the
/// vacated number suppresses nothing, and an unrelated identity moved into the old number
/// is not suppressed.
#[test]
fn move_keeps_the_suppression_on_the_moved_identity_only() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    bind(dir.path(), 7, "rt-seven");
    for s in [1, 2, 7] {
        make_config(dir.path(), s);
    }
    run_startup_audit(dir.path());
    assert!(is_refresh_suppressed(dir.path(), 2));
    let a = |n: u16| AccountNum::try_from(n).unwrap();
    crate::accounts::move_slot::move_account(dir.path(), a(2), a(5)).unwrap();
    assert!(
        is_refresh_suppressed(dir.path(), 5),
        "the moved identity keeps its suppression"
    );
    assert!(
        !is_refresh_suppressed(dir.path(), 2),
        "the vacated number suppresses nothing"
    );
    // An unrelated identity (slot 7's) moves into the old number 2.
    crate::accounts::move_slot::move_account(dir.path(), a(7), a(2)).unwrap();
    assert!(!is_refresh_suppressed(dir.path(), 2));
    assert!(is_refresh_suppressed(dir.path(), 5));
    assert_eq!(suppressed_slots(dir.path()).len(), 1);
}

/// L3 + r7 item 2: a v1 entry is carried forward bound to the slot's current identity AND a
/// live collision is still found (union).
#[test]
fn a_v1_state_file_is_carried_forward_and_unioned_with_a_live_audit() {
    let _tracing = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, "rt-one");
    bind(dir.path(), 2, "rt-two");
    bind(dir.path(), 4, SENTINEL);
    bind(dir.path(), 5, SENTINEL);
    std::fs::write(
        state_path(dir.path()),
        br#"{"version":1,"suppressed":{"2":1}}"#,
    )
    .unwrap();
    assert_eq!(
        suppressed_slots(dir.path()),
        BTreeMap::from([(2u16, 1u16), (5u16, 4u16)]),
        "the v1 entry for slot 2 is carried forward; the live collision on 5 is found too"
    );
}

#[cfg(unix)]
#[test]
fn a_fifo_state_file_is_refused_without_blocking() {
    let _tracing = hold_capture_lock();
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    let c = std::ffi::CString::new(state_path(dir.path()).as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path owned by this frame.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let base = dir.path().to_path_buf();
    let sup = within(move || suppressed_slots(&base));
    assert_eq!(sup, BTreeMap::from([(2u16, 1u16)]), "live audit, no block");
    let base = dir.path().to_path_buf();
    within(move || {
        run_startup_audit(&base);
    });
    clear_on_login(dir.path(), 2);
}

#[cfg(unix)]
#[test]
fn a_symlinked_or_group_writable_state_file_is_refused() {
    let _tracing = hold_capture_lock();
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, "rt-one");
    bind(dir.path(), 2, "rt-two");
    let target = dir.path().join("elsewhere.json");
    // A private, owned, current-format file that WOULD suppress slot 2 if it were read
    // through the link (r7 L-7): refusing the link is the only way slot 2 stays unsuppressed.
    let target_id = fixture_uuid_for_slot(2);
    std::fs::write(
        &target,
        format!(
            r#"{{"version":2,"suppressed":{{"2":{{"holder":1,"identity_uuid":"{target_id}"}}}}}}"#
        ),
    )
    .unwrap();
    crate::platform::fs::secure_file(&target).unwrap();
    std::os::unix::fs::symlink(&target, state_path(dir.path())).unwrap();
    assert!(suppressed_slots(dir.path()).is_empty(), "symlink refused");
    std::fs::remove_file(state_path(dir.path())).unwrap();
    let id = fixture_uuid_for_slot(2);
    let body =
        format!(r#"{{"version":2,"suppressed":{{"2":{{"holder":1,"identity_uuid":"{id}"}}}}}}"#);
    std::fs::write(state_path(dir.path()), &body).unwrap();
    assert!(
        is_refresh_suppressed(dir.path(), 2),
        "control: a private owned v2 file is honoured"
    );
    std::fs::set_permissions(
        state_path(dir.path()),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(
        !is_refresh_suppressed(dir.path(), 2),
        "group/other-writable is refused and the live audit finds no collision"
    );
}

/// Never `unwrap_or_default` away prior entries: with the state unreadable and a slot
/// Undetermined, the audit cannot merge, so it leaves the file as it found it.
#[test]
fn an_unreadable_state_with_an_undetermined_slot_is_left_untouched() {
    let _tracing = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    run_startup_audit(dir.path());
    corrupt_canonical(dir.path(), 2);
    std::fs::write(state_path(dir.path()), b"garbage").unwrap();
    run_startup_audit(dir.path());
    assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), b"garbage");
}

#[test]
fn the_state_unreadable_warning_is_throttled_per_window() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    std::fs::write(state_path(dir.path()), b"garbage").unwrap();
    let (_, logs) = capture(|| {
        for _ in 0..4 {
            let _ = suppressed_slots(dir.path());
        }
    });
    let n = logs
        .iter()
        .filter(|l| l.contains("refresh_suppression_state_unreadable"))
        .count();
    assert_eq!(n, 1, "{logs:?}");
}

// ── r7 ─────────────────────────────────────────────────────────────────

const LAST_GOOD: &str = "refresh-suppressed.last-good.json";

fn last_good_path(base: &Path) -> PathBuf {
    base.join(LAST_GOOD)
}

/// Move the identity bound to `from` onto the vacant slot `to` the way `csq move` does to
/// `profiles.json`, WITHOUT any suppression re-key.
fn rebind_without_rekey(base: &Path, from: &str, to: &str) {
    let pp = crate::accounts::profiles::profiles_path(base);
    let mut pf = crate::accounts::profiles::load(&pp).unwrap();
    let id = pf.by_slot.remove(from).unwrap();
    pf.by_slot.insert(to.to_string(), id);
    crate::accounts::profiles::save(&pp, &pf).unwrap();
}

/// r7 item 1 (sec M2, corr L-4): an entry for identity I counts for whichever canonical
/// slot currently binds I, whether or not the re-key ever ran.
#[test]
fn suppression_follows_the_identity_to_its_new_slot_without_any_rekey() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    run_startup_audit(dir.path());
    assert!(is_refresh_suppressed(dir.path(), 2));
    rebind_without_rekey(dir.path(), "2", "5");
    assert_eq!(
        suppressed_slots(dir.path()),
        BTreeMap::from([(5u16, 1u16)]),
        "the moved identity is suppressed at its new number and the vacated one is not"
    );
}

/// r7 item 1 (sec M2c): first detection racing a move. `apply` re-keys the verdict
/// through the identity's CURRENT binding instead of dropping it.
#[test]
fn a_verdict_read_before_a_move_lands_on_the_identitys_new_slot() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    let report = audit(dir.path());
    assert_eq!(report.slots[&2], SlotState::Suppressed { holder: 1 });
    rebind_without_rekey(dir.path(), "2", "5");
    apply(dir.path(), &report).unwrap();
    assert_eq!(
        suppressed_slots(dir.path()),
        BTreeMap::from([(5u16, 1u16)]),
        "the moved identity must not escape because the move beat the persist"
    );
}

/// r7 item 1 (sec M2b): a failed re-key write leaves the moved identity suppressed.
#[test]
fn a_rekey_write_failure_still_leaves_the_moved_identity_suppressed() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    bind(dir.path(), 7, "rt-seven");
    for s in [1, 2, 7] {
        make_config(dir.path(), s);
    }
    run_startup_audit(dir.path());
    let a = |n: u16| AccountNum::try_from(n).unwrap();
    fail_state_writes_for_test(dir.path(), true);
    let moved = crate::accounts::move_slot::move_account(dir.path(), a(2), a(5));
    fail_state_writes_for_test(dir.path(), false);
    moved.unwrap();
    assert!(
        is_refresh_suppressed(dir.path(), 5),
        "the re-key write failed; the identity is still suppressed where it now lives"
    );
    assert!(!is_refresh_suppressed(dir.path(), 2));
}

/// r7 item 1 (corr L-4): the re-key's `protects` branch is never silent.
#[test]
fn rekey_on_move_with_a_foreign_lock_logs_a_fixed_tag() {
    let dir = TempDir::new().unwrap();
    let other = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    run_startup_audit(dir.path());
    let foreign = ProfilesFileLock::acquire(other.path()).unwrap();
    let ((), logs) = capture(|| rekey_on_move(&foreign, dir.path(), 2, 5));
    assert!(
        logs.iter()
            .any(|l| l.contains("refresh_suppression_rekey_skipped")),
        "{logs:?}"
    );
}

/// r7 item 2 (sec M1, corr L-1): suppress, the holder rotates, the primary file is
/// damaged: slot 2 stays suppressed through a tick lookup AND a startup audit, and the
/// damaged file is not rewritten.
#[test]
fn a_damaged_primary_keeps_the_suppression_after_the_holder_rotated() {
    let _tracing = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    run_startup_audit(dir.path());
    assert_eq!(
        std::fs::read(last_good_path(dir.path())).unwrap(),
        std::fs::read(state_path(dir.path())).unwrap(),
        "every successful write also writes the last-good copy"
    );
    bind(dir.path(), 1, "holder-rotated-rt");
    std::fs::write(state_path(dir.path()), b"garbage").unwrap();
    assert!(
        is_refresh_suppressed(dir.path(), 2),
        "a tick lookup with a damaged primary"
    );
    run_startup_audit(dir.path());
    assert!(
        is_refresh_suppressed(dir.path(), 2),
        "a startup audit with a damaged primary"
    );
    assert_eq!(
        std::fs::read(state_path(dir.path())).unwrap(),
        b"garbage",
        "an unreadable primary is never overwritten"
    );
}

/// r7 item 2: the doctor line for a damaged primary says what to do.
#[test]
fn a_damaged_primary_is_reported_with_a_repair_or_remove_instruction() {
    let _tracing = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    run_startup_audit(dir.path());
    std::fs::write(state_path(dir.path()), b"garbage").unwrap();
    let text = operator_lines(dir.path()).join("\n");
    assert!(
        text.contains("refresh-suppressed.json") && text.contains("repair or remove"),
        "{text}"
    );
}

/// r7 item 2 (sec M1 fix 2): v1 entries are carried forward bound to the slot's current
/// identity, never dropped because the pair no longer collides.
#[test]
fn v1_entries_carry_forward_and_are_rewritten_as_v2() {
    let _tracing = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, "rt-one");
    bind(dir.path(), 2, "rt-two");
    std::fs::write(
        state_path(dir.path()),
        br#"{"version":1,"suppressed":{"2":1}}"#,
    )
    .unwrap();
    assert_eq!(
        suppressed_slots(dir.path()),
        BTreeMap::from([(2u16, 1u16)]),
        "the v1 entry survives a holder rotation"
    );
    run_startup_audit(dir.path());
    let text = std::fs::read_to_string(state_path(dir.path())).unwrap();
    assert!(text.contains("\"version\":2"), "{text}");
    assert!(is_refresh_suppressed(dir.path(), 2));
}

/// r7 item 3 (corr L-2): a startup persist failure keeps the brake engaged in memory and
/// is retried; nothing is lost while the disk write keeps failing.
#[test]
fn a_failed_startup_persist_keeps_the_suppression_in_memory() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    fail_state_writes_for_test(dir.path(), true);
    run_startup_audit(dir.path());
    assert!(!state_path(dir.path()).exists());
    let held = suppressed_slots(dir.path());
    fail_state_writes_for_test(dir.path(), false);
    assert_eq!(
        held,
        BTreeMap::from([(2u16, 1u16)]),
        "an unpersisted first detection still suppresses"
    );
}

/// r7 item 4 (corr L-3, sec L1): a login that publishes a fresh grant and clears inside
/// the profiles lock cannot be raced by an audit that read the old shared grant.
#[test]
fn an_audit_cannot_reapply_a_verdict_over_a_concurrent_relogin() {
    let dir = TempDir::new().unwrap();
    bind(dir.path(), 1, SENTINEL);
    bind(dir.path(), 2, SENTINEL);
    let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
    let base = dir.path().to_path_buf();
    let audit_thread = std::thread::spawn(move || {
        run_startup_audit(&base);
    });
    // One-sided delay: it can only let a stale audit finish reading the shared grant
    // before the login publishes; it cannot make a correct audit fail.
    std::thread::sleep(std::time::Duration::from_millis(400));
    bind(dir.path(), 2, "fresh-grant-after-login");
    clear_on_login_locked(&lock, dir.path(), 2);
    drop(lock);
    audit_thread.join().unwrap();
    assert!(
        !is_refresh_suppressed(dir.path(), 2),
        "the freshly logged-in slot must not be suppressed again"
    );
}

// ── r7c: episode fingerprint and marks format ──

#[test]
fn a_fingerprint_separates_absent_regular_and_rewritten_files() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("record.json");
    assert_eq!(file_fingerprint(&path).as_deref(), Some("absent"));
    std::fs::write(&path, b"garbage").unwrap();
    let first = file_fingerprint(&path).unwrap();
    assert!(first.starts_with("file:"), "{first}");
    assert_eq!(
        file_fingerprint(&path).unwrap(),
        first,
        "stable while untouched"
    );
    // Same bytes, written again with a later modification time: a different episode.
    std::fs::write(&path, b"garbage").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000))
        .unwrap();
    assert_ne!(file_fingerprint(&path).unwrap(), first);
}

#[cfg(unix)]
#[test]
fn a_fingerprint_of_a_fifo_or_symlink_never_blocks_and_never_follows() {
    let dir = TempDir::new().unwrap();
    let fifo = dir.path().join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert!(file_fingerprint(&fifo).unwrap().starts_with("other:"));
    let target = dir.path().join("target");
    std::fs::write(&target, b"x").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let fp = file_fingerprint(&link).unwrap();
    assert!(fp.starts_with("symlink:"), "{fp}");
    assert!(fp.ends_with(target.to_str().unwrap()), "{fp}");
}

#[test]
fn marks_of_another_version_or_shape_do_not_count() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let path = reverified_path(base);
    for body in [
        br#"["00000000-0000-0000-0000-000000000000"]"#.as_slice(),
        br#"{"version":1,"episode":"e","identities":[]}"#.as_slice(),
        b"garbage".as_slice(),
    ] {
        std::fs::write(&path, body).unwrap();
        crate::platform::fs::secure_file(&path).unwrap();
        assert!(read_reverified(base).is_none());
    }
    std::fs::write(&path, br#"{"version":2,"episode":"e","identities":[]}"#).unwrap();
    crate::platform::fs::secure_file(&path).unwrap();
    assert!(read_reverified(base).is_some());
}

#[test]
fn a_failed_mark_clear_stops_the_write_and_leaves_the_record_untouched() {
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let mut state = StateFile::new();
    state.suppressed.insert(
        "2".to_string(),
        Entry {
            holder: 1,
            identity_uuid: fixture_uuid_for_slot(2),
        },
    );
    fail_reverified_clear_for_test(base, true);
    let failed = write_state(base, &state);
    fail_reverified_clear_for_test(base, false);
    assert!(failed.is_err(), "the clear failed, so the write must fail");
    assert!(
        !state_path(base).exists() && !last_good_path(base).exists(),
        "neither the primary nor the last-good copy may be written"
    );
    assert!(write_state(base, &state).is_ok());
    assert!(state_path(base).exists());
}

// ── r7d ──

#[test]
fn identical_metadata_with_different_bytes_gives_different_fingerprints() {
    let stamp = "1:2:7:1700000000.0:1700000000.0";
    let a = regular_file_fingerprint(stamp, Some(b"garbage"));
    let b = regular_file_fingerprint(stamp, Some(b"garbagf"));
    assert_ne!(a, b, "same stamp, one byte differs");
    assert_eq!(a, regular_file_fingerprint(stamp, Some(b"garbage")));
    assert_ne!(
        a,
        regular_file_fingerprint(stamp, None),
        "unread is not read"
    );
    assert_ne!(
        a,
        regular_file_fingerprint("1:2:7:1700000001.0:1700000000.0", Some(b"garbage")),
        "same bytes, other stamp"
    );
}

/// A non-empty directory at the marks path: the write fails closed, the record is untouched,
/// and the doctor lines name the path and the manual fix.
#[test]
fn an_obstructed_marks_path_fails_the_write_closed_and_doctor_names_it() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    bind(base, 1, "obstruction-one");
    let mut state = StateFile::new();
    state.suppressed.insert(
        "2".to_string(),
        Entry {
            holder: 1,
            identity_uuid: fixture_uuid_for_slot(2),
        },
    );
    let _lock = hold_capture_lock();
    write_state(base, &state).unwrap();
    drop(_lock);
    let before = std::fs::read(state_path(base)).unwrap();
    let obstruction = reverified_path(base);
    std::fs::create_dir(&obstruction).unwrap();
    std::fs::write(obstruction.join("keep"), b"x").unwrap();
    let (failed, events) = capture(|| write_state(base, &StateFile::new()));
    assert!(failed.is_err());
    assert!(
        events
            .iter()
            .any(|e| e.contains("refresh_suppression_reverified_clear_failed")),
        "{events:?}"
    );
    assert_eq!(
        std::fs::read(state_path(base)).unwrap(),
        before,
        "primary untouched"
    );
    let _tracing = hold_capture_lock();
    let lines = operator_lines(base);
    let line = lines
        .iter()
        .find(|l| l.contains(&obstruction.display().to_string()))
        .unwrap_or_else(|| panic!("no doctor line names the path: {lines:?}"));
    assert!(line.contains("Remove or repair that path"), "{line}");
    assert!(line.contains("next daemon tick"), "{line}");
    // Removing the obstruction ends it: the write succeeds and the line is gone.
    std::fs::remove_dir_all(&obstruction).unwrap();
    assert!(write_state(base, &StateFile::new()).is_ok());
    assert!(operator_lines(base)
        .iter()
        .all(|l| !l.contains(&obstruction.display().to_string())));
}

// ── r7e: the clear-blocked doctor line is state-based ──

fn clear_blocked_line(base: &Path) -> Option<String> {
    let marks = reverified_path(base).display().to_string();
    operator_lines(base)
        .into_iter()
        .find(|l| l.contains(&marks))
}

/// A sound record naming one suppression: the record is DETERMINED.
fn determined_record(base: &Path) {
    bind(base, 1, "blocked-one");
    let mut state = StateFile::new();
    state.suppressed.insert(
        "2".to_string(),
        Entry {
            holder: 1,
            identity_uuid: fixture_uuid_for_slot(2),
        },
    );
    write_state(base, &state).unwrap();
    assert!(!suppression_undetermined(base));
}

/// A garbage primary and no last-good copy: the record is UNDETERMINED.
fn undetermined_record(base: &Path) {
    bind(base, 1, "blocked-one");
    std::fs::write(state_path(base), b"garbage").unwrap();
    crate::platform::fs::secure_file(&state_path(base)).unwrap();
    let _ = std::fs::remove_file(last_good_path(base));
    assert!(suppression_undetermined(base));
}

fn plant_private_marks(base: &Path) {
    let path = reverified_path(base);
    std::fs::write(&path, b"{}").unwrap();
    crate::platform::fs::secure_file(&path).unwrap();
}

fn assert_blocked_line(line: Option<String>) {
    let line = line.expect("doctor must show the clear-blocked line");
    assert!(line.contains("Remove or repair that path"), "{line}");
    assert!(line.contains("next daemon tick"), "{line}");
}

#[test]
fn a_clean_state_shows_no_clear_blocked_line() {
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    determined_record(dir.path());
    assert!(
        clear_blocked_line(dir.path()).is_none(),
        "determined, no marks"
    );
    let dir = TempDir::new().unwrap();
    undetermined_record(dir.path());
    assert!(
        clear_blocked_line(dir.path()).is_none(),
        "undetermined, no marks"
    );
    plant_private_marks(dir.path());
    assert!(
        clear_blocked_line(dir.path()).is_none(),
        "private regular marks while undetermined are the legitimate state"
    );
}

/// Arm (i): a stale, perfectly private regular marks file with a DETERMINED record.
#[test]
fn a_stale_regular_marks_file_with_a_determined_record_shows_the_line() {
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    determined_record(dir.path());
    plant_private_marks(dir.path());
    assert_blocked_line(clear_blocked_line(dir.path()));
}

/// Arm (ii) holds at ANY time: shown while the record is undetermined too.
#[test]
fn a_non_empty_directory_at_the_marks_path_shows_the_line_even_when_undetermined() {
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    undetermined_record(dir.path());
    std::fs::create_dir(reverified_path(dir.path())).unwrap();
    std::fs::write(reverified_path(dir.path()).join("keep"), b"x").unwrap();
    assert_blocked_line(clear_blocked_line(dir.path()));
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_marks_path_shows_the_line_even_when_undetermined() {
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    undetermined_record(dir.path());
    let target = dir.path().join("target.json");
    std::fs::write(&target, b"{}").unwrap();
    crate::platform::fs::secure_file(&target).unwrap();
    std::os::unix::fs::symlink(&target, reverified_path(dir.path())).unwrap();
    assert_blocked_line(clear_blocked_line(dir.path()));
}

#[cfg(unix)]
#[test]
fn a_fifo_at_the_marks_path_shows_the_line_even_when_undetermined() {
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    undetermined_record(dir.path());
    let c = std::ffi::CString::new(reverified_path(dir.path()).to_str().unwrap()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert_blocked_line(clear_blocked_line(dir.path()));
}

#[cfg(unix)]
#[test]
fn a_group_readable_marks_file_shows_the_line_even_when_undetermined() {
    use std::os::unix::fs::PermissionsExt;
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    undetermined_record(dir.path());
    plant_private_marks(dir.path());
    std::fs::set_permissions(
        reverified_path(dir.path()),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_blocked_line(clear_blocked_line(dir.path()));
}

/// Restores the directory's permissions so the temp dir can be removed even on a panic.
#[cfg(unix)]
struct RestorePerms(std::path::PathBuf);
#[cfg(unix)]
impl Drop for RestorePerms {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// A clear blocked by PERMISSIONS (a read-only accounts dir), not by what sits at the path.
#[cfg(unix)]
#[test]
fn a_permissions_blocked_clear_fails_closed_and_shows_the_line() {
    use std::os::unix::fs::PermissionsExt;
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    determined_record(base);
    plant_private_marks(base);
    let before = std::fs::read(state_path(base)).unwrap();
    let _restore = RestorePerms(base.to_path_buf());
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        std::fs::File::create(base.join("probe")).is_err(),
        "the directory must be read-only for this process (not running as a privileged user)"
    );
    let failed = write_state(base, &StateFile::new());
    let line = clear_blocked_line(base);
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        failed.is_err(),
        "the clear was blocked, so the write must fail"
    );
    assert_eq!(
        std::fs::read(state_path(base)).unwrap(),
        before,
        "primary untouched"
    );
    assert_blocked_line(line);
}

// ── r7f: an uninspectable marks path is reported, never silent ──

/// The accounts dir without search permission: nothing inside it can be inspected.
#[cfg(unix)]
#[test]
fn an_uninspectable_marks_path_shows_the_line_with_a_fixed_kind() {
    use std::os::unix::fs::PermissionsExt;
    let _lock = hold_capture_lock();
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    determined_record(base);
    let _restore = RestorePerms(base.to_path_buf());
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o600)).unwrap();
    let inspected = std::fs::symlink_metadata(reverified_path(base));
    assert!(
        matches!(&inspected, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "inspection must really fail with permission denied for this process: {inspected:?}"
    );
    let lines = operator_lines(base);
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let marks = reverified_path(base).display().to_string();
    let line = lines
        .iter()
        .find(|l| l.contains(&marks))
        .unwrap_or_else(|| panic!("no line for an uninspectable path: {lines:?}"));
    assert!(line.contains("cannot inspect"), "{line}");
    assert!(line.contains("permission_denied"), "{line}");
    assert!(
        line.contains("check the accounts dir permissions"),
        "{line}"
    );
    assert!(!line.contains("os error"), "no raw error text: {line}");
}

#[test]
fn inspection_error_kinds_map_to_a_fixed_vocabulary() {
    use std::io::ErrorKind::*;
    assert_eq!(inspect_error_kind(PermissionDenied), "permission_denied");
    assert_eq!(inspect_error_kind(NotADirectory), "not_a_directory");
    assert_eq!(inspect_error_kind(Other), "io_error");
    assert_eq!(inspect_error_kind(TimedOut), "io_error");
}
