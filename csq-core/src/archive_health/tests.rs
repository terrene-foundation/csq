use super::*;
use std::collections::HashMap;

const NOW: i64 = 1_793_000_000; // fixed clock

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW as u64)
}
fn rfc(age_secs: i64) -> String {
    chrono::DateTime::from_timestamp(NOW - age_secs, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

struct Fake(HashMap<&'static str, LaunchdState>);
impl LaunchdProbe for Fake {
    fn state(&self, label: &str) -> LaunchdState {
        self.0
            .get(label)
            .cloned()
            .unwrap_or(LaunchdState::NotLoaded)
    }
}
/// Synthetic labels: shipped tests never carry an organisation label.
const LABEL_HOT: &str = "com.example.csq-archive.hot";
const LABEL_NIGHTLY: &str = "com.example.csq-archive.nightly";
const TEST_LABELS: [&str; 2] = [LABEL_HOT, LABEL_NIGHTLY];

fn loaded() -> Fake {
    Fake(
        TEST_LABELS
            .iter()
            .map(|l| (*l, LaunchdState::Loaded))
            .collect(),
    )
}

/// One regular LaunchAgent plist per label under the fake home.
fn write_agents(home: &Path, labels: &[&str]) {
    let dir = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&dir).unwrap();
    for label in labels {
        std::fs::write(dir.join(format!("{label}.plist")), "<plist/>").unwrap();
    }
}

fn home_with_archive() -> (tempfile::TempDir, PathBuf) {
    let h = tempfile::tempdir().unwrap();
    let d = archive_dir(h.path());
    std::fs::create_dir_all(d.join("log")).unwrap();
    write_agents(h.path(), &TEST_LABELS);
    (h, d)
}
fn checks(h: &Path, p: &dyn LaunchdProbe) -> ArchiveChecks {
    match check(h, now(), p) {
        ArchiveHealth::Configured(c) => *c,
        ArchiveHealth::NotConfigured => panic!("expected configured"),
    }
}
fn put(d: &Path, rel: &str, body: &str) {
    std::fs::write(d.join(rel), body).unwrap();
}

#[test]
fn not_configured_when_dir_absent() {
    let h = tempfile::tempdir().unwrap();
    assert_eq!(
        check(h.path(), now(), &loaded()),
        ArchiveHealth::NotConfigured
    );
    assert!(ArchiveHealth::NotConfigured.checks().is_none());
}

#[test]
fn jobs_ok_warn_unknown() {
    let (h, _d) = home_with_archive();
    assert_eq!(checks(h.path(), &loaded()).upload_jobs, CheckState::Ok);
    let mut m = loaded();
    m.0.insert(LABEL_NIGHTLY, LaunchdState::NotLoaded);
    match checks(h.path(), &m).upload_jobs {
        CheckState::Warn(r) => assert!(r.contains("nightly") && !r.contains(".hot"), "{r}"),
        o => panic!("{o:?}"),
    }
    let mut u = loaded();
    u.0.insert(LABEL_HOT, LaunchdState::Unknown("no launchd".into()));
    assert_eq!(
        checks(h.path(), &u).upload_jobs,
        CheckState::Unknown("no launchd".into())
    );
    // NotLoaded outranks Unknown.
    u.0.insert(LABEL_NIGHTLY, LaunchdState::NotLoaded);
    assert!(matches!(
        checks(h.path(), &u).upload_jobs,
        CheckState::Warn(_)
    ));
}

#[test]
fn upload_recent_states() {
    let (h, d) = home_with_archive();
    let p = loaded();
    // absent -> WARN
    assert!(matches!(
        checks(h.path(), &p).upload_recent,
        CheckState::Warn(_)
    ));
    // fresh -> OK
    put(
        &d,
        "log/last-success.json",
        &format!(r#"{{"last_success":"{}"}}"#, rfc(3600)),
    );
    assert_eq!(checks(h.path(), &p).upload_recent, CheckState::Ok);
    // just under / over the 26h boundary
    put(
        &d,
        "log/last-success.json",
        &format!(r#"{{"last_success":"{}"}}"#, rfc(STALE_AFTER_SECS - 1)),
    );
    assert_eq!(checks(h.path(), &p).upload_recent, CheckState::Ok);
    put(
        &d,
        "log/last-success.json",
        &format!(r#"{{"last_success":"{}"}}"#, rfc(STALE_AFTER_SECS)),
    );
    assert!(matches!(
        checks(h.path(), &p).upload_recent,
        CheckState::Warn(_)
    ));
    // 12-day-old (the incident)
    put(
        &d,
        "log/last-success.json",
        r#"{"last_success":"2026-10-15T23:10:06Z"}"#,
    );
    match checks(h.path(), &p).upload_recent {
        CheckState::Warn(r) => assert!(r.contains("d ago"), "{r}"),
        o => panic!("{o:?}"),
    }
    // malformed / missing field / bad ts / future -> UNKNOWN
    for body in [
        "not json".to_string(),
        r#"{"x":1}"#.to_string(),
        r#"{"last_success":"yesterday"}"#.to_string(),
        r#"{"last_success":7}"#.replace('7', &(NOW + 99_999).to_string()),
        r#"{"last_success":[1]}"#.to_string(),
    ] {
        put(&d, "log/last-success.json", &body);
        assert!(
            matches!(checks(h.path(), &p).upload_recent, CheckState::Unknown(_)),
            "{body}"
        );
    }
}

/// Production record shapes written by `delete-confirmed.sh`
/// (`dict(rec, event=..., at_ns=...)`; rec = {path, sha256, snapshot, size}).
fn rec(event: &str) -> String {
    format!(
        "{{\"at_ns\": {}, \"event\": \"{event}\", \"path\": \"a/b\", \"sha256\": \"00\", \"size\": 1, \"snapshot\": \"s\"}}\n",
        NOW * 1_000_000_000
    )
}
fn rec_at(event: &str, age_secs: i64) -> String {
    format!(
        "{{\"at_ns\": {}, \"event\": \"{event}\", \"path\": \"a/b\", \"sha256\": \"00\", \"size\": 1, \"snapshot\": \"s\"}}\n",
        (NOW - age_secs) * 1_000_000_000
    )
}
fn hb(age: i64) -> String {
    format!(r#"{{"last_success":"{}"}}"#, rfc(age))
}
/// All three heartbeats fresh, matching the contract exactly.
fn healthy(d: &Path) {
    put(d, "log/last-success.json", &hb(60));
    put(d, "log/heartbeat-A.json", &hb(60));
    put(d, "log/heartbeat-delete.json", &hb(60));
}
fn ids(c: &ArchiveChecks) -> Vec<&'static str> {
    c.findings().iter().map(|f| f.check).collect()
}
fn state_of(c: &ArchiveChecks, id: &str) -> CheckState {
    c.findings()
        .into_iter()
        .find(|f| f.check == id)
        .map_or(CheckState::Ok, |f| f.state)
}
#[cfg(unix)]
fn mkfifo(p: &Path) {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated path; mkfifo has no other preconditions.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}
#[cfg(unix)]
/// Runs `check` on a thread so a regression that blocks on a FIFO fails the
/// test instead of hanging the suite.
fn checks_bounded(h: &Path) -> ArchiveChecks {
    let (tx, rx) = std::sync::mpsc::channel();
    let home = h.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(checks(&home, &loaded()));
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("check() blocked on a special file")
}

#[test]
fn hot_heartbeat_warns_past_two_hours_and_when_absent() {
    let (h, d) = home_with_archive();
    healthy(&d);
    assert_eq!(
        state_of(&checks(h.path(), &loaded()), "upload_recent_hot"),
        CheckState::Ok
    );
    std::fs::remove_file(d.join("log/heartbeat-A.json")).unwrap();
    assert!(matches!(
        state_of(&checks(h.path(), &loaded()), "upload_recent_hot"),
        CheckState::Warn(_)
    ));
    put(&d, "log/heartbeat-A.json", &hb(7200 - 1));
    assert_eq!(
        state_of(&checks(h.path(), &loaded()), "upload_recent_hot"),
        CheckState::Ok
    );
    put(&d, "log/heartbeat-A.json", &hb(7200));
    assert!(
        matches!(state_of(&checks(h.path(), &loaded()), "upload_recent_hot"), CheckState::Warn(r) if r.contains("2h"))
    );
    put(&d, "log/heartbeat-A.json", "not json");
    assert!(matches!(
        state_of(&checks(h.path(), &loaded()), "upload_recent_hot"),
        CheckState::Unknown(_)
    ));
}

#[test]
fn delete_active_follows_the_delete_heartbeat() {
    let (h, d) = home_with_archive();
    let p = loaded();
    assert_eq!(
        state_of(&checks(h.path(), &p), "delete_active"),
        CheckState::Warn("local delete has never run / is not scheduled".into())
    );
    put(&d, "log/heartbeat-delete.json", &hb(STALE_AFTER_SECS - 1));
    assert_eq!(
        state_of(&checks(h.path(), &p), "delete_active"),
        CheckState::Ok
    );
    put(&d, "log/heartbeat-delete.json", &hb(STALE_AFTER_SECS));
    assert!(
        matches!(state_of(&checks(h.path(), &p), "delete_active"), CheckState::Warn(r) if r.contains("ago"))
    );
    // A fresh deleted.jsonl mtime alone proves nothing: only the heartbeat counts.
    std::fs::remove_file(d.join("log/heartbeat-delete.json")).unwrap();
    put(&d, "log/deleted.jsonl", &rec("deleted"));
    assert!(matches!(
        state_of(&checks(h.path(), &p), "delete_active"),
        CheckState::Warn(_)
    ));
}

#[test]
fn delete_tail_follows_the_writer_contract() {
    // Contract: heartbeat-delete.json is written ONLY when the delete step exits 0.
    // A failed_after_intent / aborted_* record NEWER than the heartbeat is a failed
    // run (a partial failure exits non-zero, so it wrote no heartbeat), even when a
    // later `deleted` follows it; a trailing `intent` older than 10 min is a run
    // that died mid-unlink. The next successful run rewrites the heartbeat and
    // clears both.
    let (h, d) = home_with_archive();
    let p = loaded();
    put(&d, "log/heartbeat-delete.json", &hb(60));
    let cases: [(&[(&str, i64)], bool); 10] = [
        (&[("intent", 100), ("deleted", 90)], false),
        (&[("intent", 30), ("failed_after_intent", 29)], true),
        (&[("intent", 30), ("aborted_tomb_left", 29)], true),
        (&[("intent", 30), ("aborted_restored", 29)], true),
        // partial failure then recovery inside the SAME run: still a failed run
        (
            &[
                ("intent", 30),
                ("failed_after_intent", 29),
                ("intent", 20),
                ("deleted", 19),
            ],
            true,
        ),
        // an old failure, superseded by a newer successful run (heartbeat newer): cleared
        (&[("intent", 3600), ("failed_after_intent", 3599)], false),
        (&[("deleted", 700), ("intent", 660)], true),
        (&[("deleted", 700), ("intent", 300)], false),
        (
            &[
                ("intent", 100),
                ("deleted", 90),
                ("intent", 30),
                ("failed_after_intent", 20),
            ],
            true,
        ),
        (&[], false),
    ];
    for (events, warn) in cases {
        let body: String = events.iter().map(|(e, a)| rec_at(e, *a)).collect();
        put(&d, "log/deleted.jsonl", &body);
        let st = state_of(&checks(h.path(), &p), "delete_active");
        assert_eq!(
            matches!(st, CheckState::Warn(_)),
            warn,
            "{events:?} -> {st:?}"
        );
        assert!(warn || st == CheckState::Ok, "{events:?} -> {st:?}");
    }
    // a failure record with no usable at_ns cannot be proven old: WARN
    put(
        &d,
        "log/deleted.jsonl",
        "{\"event\": \"failed_after_intent\"}\n",
    );
    assert!(matches!(
        state_of(&checks(h.path(), &p), "delete_active"),
        CheckState::Warn(_)
    ));
    // garbage lines are ignored
    put(
        &d,
        "log/deleted.jsonl",
        &format!("garbage\n{}", rec_at("deleted", 90)),
    );
    assert_eq!(
        state_of(&checks(h.path(), &p), "delete_active"),
        CheckState::Ok
    );
    // tail window: a fresh failure after a huge history of old successes
    let mut body: String = (0..1000).map(|_| rec_at("deleted", 5000)).collect();
    body.push_str(&rec_at("failed_after_intent", 10));
    put(&d, "log/deleted.jsonl", &body);
    assert!(matches!(
        state_of(&checks(h.path(), &p), "delete_active"),
        CheckState::Warn(_)
    ));
    // unreadable log (a directory) with a fresh heartbeat -> UNKNOWN, never OK
    std::fs::remove_file(d.join("log/deleted.jsonl")).unwrap();
    std::fs::create_dir(d.join("log/deleted.jsonl")).unwrap();
    assert!(matches!(
        state_of(&checks(h.path(), &p), "delete_active"),
        CheckState::Unknown(_)
    ));
}

#[test]
fn hints_name_the_right_logs_and_the_clearing_action() {
    let (h, _d) = home_with_archive();
    let c = checks(h.path(), &loaded());
    let hint = |id: &str| {
        c.findings()
            .into_iter()
            .find(|f| f.check == id)
            .unwrap()
            .hint
    };
    assert!(hint("upload_recent").contains("launchd-nightly.err"));
    assert!(hint("upload_recent_hot").contains("launchd-hot.err"));
    assert!(hint("delete_active").contains("next successful delete"));
}

#[test]
fn paused_reason_is_redacted_over_the_whole_line_before_truncation() {
    let (h, d) = home_with_archive();
    let filler = format!("{} ", "x".repeat(179)); // the key starts at char 180
    for key in [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        format!("sk-proj-{}", "Zq7".repeat(16)),
    ] {
        put(&d, "PAUSED", &format!("{filler}{key}\n"));
        match checks(h.path(), &loaded()).paused {
            CheckState::Warn(r) => {
                assert!(!r.contains(&key[..12]), "key prefix leaked: {r}");
                assert!(
                    r.chars().count() <= REASON_MAX_CHARS + 32,
                    "unbounded: {}",
                    r.len()
                );
            }
            o => panic!("{o:?}"),
        }
    }
}

#[test]
fn paused_reason_strips_every_format_char_including_the_tag_block() {
    let (h, d) = home_with_archive();
    put(
        &d,
        "PAUSED",
        "a\u{e0041}\u{e0001}\u{e007f}b\u{2028}\u{2029}\u{fff9}\u{0600}\u{110bd}\u{1d173}c\
         \u{fe00}\u{fe0f}\u{e0100}\u{e01ef}\u{34f}\u{115f}\u{1160}\u{3164}\u{ffa0}d\n",
    );
    match checks(h.path(), &loaded()).paused {
        CheckState::Warn(r) => assert!(r.ends_with(": abcd"), "{r:?}"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn paused_marker_present_but_unreadable_is_warn_not_unknown() {
    let (h, d) = home_with_archive();
    let p = loaded();
    assert_eq!(checks(h.path(), &p).paused, CheckState::Ok);
    std::fs::create_dir(d.join("PAUSED")).unwrap();
    assert_eq!(
        checks(h.path(), &p).paused,
        CheckState::Warn("archive paused (reason unreadable)".into())
    );
}

#[test]
fn paused_reason_is_redacted_and_stripped_of_format_chars() {
    let (h, d) = home_with_archive();
    let tok = "sk-ant-oat01-FAKETESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    put(
        &d,
        "PAUSED",
        &format!("2026-10-28 paused: {tok} \u{202e}evil\u{200b}x\u{feff}y\n"),
    );
    match checks(h.path(), &loaded()).paused {
        CheckState::Warn(r) => {
            assert!(!r.contains("AAAAAAAA"), "token leaked: {r}");
            for c in ['\u{202e}', '\u{200b}', '\u{feff}'] {
                assert!(!r.contains(c), "format char survived: {r:?}");
            }
        }
        o => panic!("{o:?}"),
    }
}

#[cfg(unix)]
#[test]
fn state_files_that_are_symlinks_or_fifos_never_follow_or_block() {
    use std::os::unix::fs::symlink;
    let (h, d) = home_with_archive();
    let secret = h.path().join("cred.json");
    std::fs::write(
        &secret,
        "sk-ant-oat01-FAKETESTBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    )
    .unwrap();
    // PAUSED -> symlink to a credential file: warn, reason NOT read
    symlink(&secret, d.join("PAUSED")).unwrap();
    let c = checks_bounded(h.path());
    assert!(
        matches!(&c.paused, CheckState::Warn(r) if !r.contains("BBBB")),
        "{:?}",
        c.paused
    );
    std::fs::remove_file(d.join("PAUSED")).unwrap();
    // PAUSED as a FIFO: warn promptly
    mkfifo(&d.join("PAUSED"));
    assert!(matches!(
        checks_bounded(h.path()).paused,
        CheckState::Warn(_)
    ));
    std::fs::remove_file(d.join("PAUSED")).unwrap();
    // last-success / heartbeat as FIFO or symlink: unknown promptly
    mkfifo(&d.join("log/last-success.json"));
    mkfifo(&d.join("log/heartbeat-delete.json"));
    symlink(&secret, d.join("log/heartbeat-A.json")).unwrap();
    let c = checks_bounded(h.path());
    for id in ["upload_recent", "delete_active", "upload_recent_hot"] {
        assert!(matches!(state_of(&c, id), CheckState::Unknown(_)), "{id}");
    }
    // deleted.jsonl as a FIFO (fresh heartbeat in place): unknown promptly
    std::fs::remove_file(d.join("log/heartbeat-delete.json")).unwrap();
    put(&d, "log/heartbeat-delete.json", &hb(60));
    mkfifo(&d.join("log/deleted.jsonl"));
    assert!(matches!(
        state_of(&checks_bounded(h.path()), "delete_active"),
        CheckState::Unknown(_)
    ));
}

#[test]
fn extreme_timestamps_do_not_panic_and_are_unknown() {
    let (h, d) = home_with_archive();
    for body in [
        r#"{"last_success":-9223372036854775808}"#,
        r#"{"last_success":9223372036854775807}"#,
        r#"{"last_success":1e300}"#,
    ] {
        put(&d, "log/last-success.json", body);
        assert!(
            matches!(
                checks(h.path(), &loaded()).upload_recent,
                CheckState::Unknown(_)
            ),
            "{body}"
        );
    }
}

#[test]
fn findings_list_only_non_ok_with_hints_and_serialize() {
    let (h, d) = home_with_archive();
    put(&d, "PAUSED", "paused: pending fix");
    let c = checks(h.path(), &Fake(HashMap::new()));
    assert_eq!(
        ids(&c),
        [
            "upload_jobs",
            "upload_recent",
            "upload_recent_hot",
            "delete_active",
            "paused"
        ]
    );
    assert!(c.any_warn());
    assert!(c.findings().iter().all(|f| !f.hint.is_empty()));
    let v = serde_json::to_value(&c).unwrap();
    assert_eq!(v["paused"]["state"], "warn");
    assert!(v["paused"]["reason"]
        .as_str()
        .unwrap()
        .contains("pending fix"));
    assert_eq!(v["upload_recent_hot"]["state"], "warn");
    assert_eq!(serde_json::to_value(CheckState::Ok).unwrap()["state"], "ok");
}

#[test]
fn all_healthy_has_no_findings() {
    let (h, d) = home_with_archive();
    healthy(&d);
    let c = checks(h.path(), &loaded());
    assert!(
        c.findings().is_empty() && !c.any_warn(),
        "{:?}",
        c.findings()
    );
}

#[test]
fn statusline_badges_cover_warn_and_file_unknown_but_not_skipped_launchd() {
    let (h, d) = home_with_archive();
    // nothing ever ran: stale + delete off. Skipped launchd stays silent.
    let c = checks(h.path(), &SkipLaunchd);
    assert!(matches!(c.upload_jobs, CheckState::Unknown(_)));
    assert_eq!(
        statusline_badges(&c),
        ["\u{26a0} backup stale", "\u{26a0} delete off"]
    );
    // paused: backup off first; the reason never reaches the badge
    put(&d, "PAUSED", "2026-10-28 paused: secret-looking-reason");
    let b = statusline_badges(&checks(h.path(), &SkipLaunchd));
    assert_eq!(b[0], "\u{26a0} backup off");
    assert!(b.iter().all(|x| !x.contains("secret")));
    std::fs::remove_file(d.join("PAUSED")).unwrap();
    // healthy: nothing
    healthy(&d);
    assert!(statusline_badges(&checks(h.path(), &SkipLaunchd)).is_empty());
    // a malformed last_success (UNKNOWN) shows the fixed `backup ?` badge
    put(&d, "log/last-success.json", "not json");
    assert_eq!(
        statusline_badges(&checks(h.path(), &SkipLaunchd)),
        ["\u{26a0} backup ?"]
    );
    // so does an unreadable heartbeat-delete
    put(&d, "log/last-success.json", &hb(60));
    std::fs::remove_file(d.join("log/heartbeat-delete.json")).unwrap();
    std::fs::create_dir(d.join("log/heartbeat-delete.json")).unwrap();
    assert_eq!(
        statusline_badges(&checks(h.path(), &SkipLaunchd)),
        ["\u{26a0} backup ?"]
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn system_probe_is_unknown_off_macos() {
    assert_eq!(
        SystemLaunchd.state("x"),
        LaunchdState::Unknown("no launchd".into())
    );
}

#[test]
fn home_of_base_requires_dot_claude_accounts() {
    assert_eq!(
        home_of_base(Path::new("/h/u/.claude/accounts")),
        Some(PathBuf::from("/h/u"))
    );
    assert_eq!(home_of_base(Path::new("/x/y")), None);
    assert_eq!(home_of_base(Path::new("/h/.other/accounts")), None);
}

#[test]
fn two_agents_for_one_role_are_unknown_and_never_a_guess() {
    let (h, _d) = home_with_archive();
    let dir = h.path().join("Library").join("LaunchAgents");
    std::fs::write(dir.join("com.other.csq-archive.hot.plist"), "<plist/>").unwrap();
    match checks(h.path(), &loaded()).upload_jobs {
        CheckState::Unknown(r) => {
            assert!(r.contains("csq-archive.hot"), "{r}");
            assert!(r.contains("refusing to pick one"), "{r}");
        }
        o => panic!("{o:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_agent_is_ignored_and_never_followed() {
    let (h, _d) = home_with_archive();
    let dir = h.path().join("Library").join("LaunchAgents");
    let elsewhere = h.path().join("elsewhere.plist");
    std::fs::write(&elsewhere, "<plist/>").unwrap();
    let hot = dir.join(format!("{LABEL_HOT}.plist"));
    std::fs::remove_file(&hot).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &hot).unwrap();
    // The probe would answer Loaded for this label, so only discovery ignoring
    // the symlink can produce the WARN: the hot role is ABSENT.
    match checks(h.path(), &loaded()).upload_jobs {
        CheckState::Warn(r) => assert!(r.contains("csq-archive.hot"), "{r}"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn absent_agents_warn_that_the_jobs_are_not_installed() {
    let (h, _d) = home_with_archive();
    std::fs::remove_dir_all(h.path().join("Library")).unwrap();
    match checks(h.path(), &loaded()).upload_jobs {
        CheckState::Warn(r) => {
            assert!(r.contains("csq-archive.hot"), "{r}");
            assert!(r.contains("csq-archive.nightly"), "{r}");
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn a_host_without_launchd_is_unknown_not_a_not_loaded_warning() {
    struct NoLaunchd;
    impl LaunchdProbe for NoLaunchd {
        fn state(&self, _label: &str) -> LaunchdState {
            LaunchdState::Unknown("no launchd".into())
        }
        fn unavailable(&self) -> Option<String> {
            Some("no launchd".into())
        }
    }
    // A home WITHOUT Library/: if discovery decided first, the absent agents
    // would WARN ("backup off"). The probe's unavailability must win.
    let h = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(archive_dir(h.path()).join("log")).unwrap();
    assert_eq!(
        checks(h.path(), &NoLaunchd).upload_jobs,
        CheckState::Unknown("no launchd".into())
    );
}

#[test]
fn an_ambiguous_role_never_hides_a_warn_from_the_other_role() {
    // hot ambiguous, nightly absent: the WARN must win, never a short-circuit.
    let (h, _d) = home_with_archive();
    let dir = h.path().join("Library").join("LaunchAgents");
    std::fs::remove_file(dir.join(format!("{LABEL_NIGHTLY}.plist"))).unwrap();
    std::fs::write(dir.join("com.other.csq-archive.hot.plist"), "<plist/>").unwrap();
    match checks(h.path(), &loaded()).upload_jobs {
        CheckState::Warn(r) => assert!(r.contains("nightly"), "{r}"),
        o => panic!("{o:?}"),
    }
    // the reverse order: nightly ambiguous, hot absent.
    std::fs::remove_file(dir.join("com.other.csq-archive.hot.plist")).unwrap();
    std::fs::write(dir.join("com.other.csq-archive.nightly.plist"), "<plist/>").unwrap();
    std::fs::remove_file(dir.join(format!("{LABEL_HOT}.plist"))).unwrap();
    match checks(h.path(), &loaded()).upload_jobs {
        CheckState::Warn(r) => assert!(r.contains("hot"), "{r}"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn an_unsafe_label_name_is_unknown_never_a_pick() {
    let (h, _d) = home_with_archive();
    let dir = h.path().join("Library").join("LaunchAgents");
    std::fs::write(dir.join("bad name.csq-archive.hot.plist"), "<plist/>").unwrap();
    match checks(h.path(), &loaded()).upload_jobs {
        CheckState::Unknown(r) => {
            assert!(r.contains("unsafe label name"), "{r}");
            // The name failed validation BECAUSE it is unsafe to render, so it
            // must not come back out on the surface that rejected it.
            assert!(!r.contains("bad name"), "the rejected name was echoed: {r}");
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn discovery_takes_only_a_regular_file_owned_by_this_uid() {
    // The OWNERSHIP half of the name is Unix-only: `Metadata::uid` has no
    // Windows equivalent, and the filter is compiled out there.
    let (h, _d) = home_with_archive();
    let dir = h.path().join("Library").join("LaunchAgents");
    let hot = dir.join(format!("{LABEL_HOT}.plist"));
    // a DIRECTORY carrying the role suffix is not a candidate.
    std::fs::remove_file(&hot).unwrap();
    std::fs::create_dir(&hot).unwrap();
    assert_eq!(
        discover_role_as(h.path(), "hot", current_uid()),
        RoleLabel::Absent
    );
    std::fs::remove_dir(&hot).unwrap();
    std::fs::write(&hot, "<plist/>").unwrap();
    #[cfg(unix)]
    {
        // the right name owned by ANOTHER uid is not a candidate either.
        assert_eq!(
            discover_role_as(h.path(), "hot", current_uid().wrapping_add(1)),
            RoleLabel::Absent
        );
    }
    assert!(matches!(
        discover_role_as(h.path(), "hot", current_uid()),
        RoleLabel::Found { .. }
    ));
}

#[cfg(unix)]
#[test]
fn an_unreadable_launch_agents_dir_is_unknown_not_absent() {
    use std::os::unix::fs::PermissionsExt;
    if current_uid() == 0 {
        return; // root reads a 000 directory; nothing to measure
    }
    let (h, _d) = home_with_archive();
    let dir = h.path().join("Library").join("LaunchAgents");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let got = discover_role(h.path(), "hot");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    match got {
        RoleLabel::Unknown(r) => assert!(r.contains("LaunchAgents unreadable"), "{r}"),
        o => panic!("{o:?}"),
    }
}

/// Linux only, not `unix`: APFS (macOS) REJECTS a non-UTF-8 file name at
/// `write`, so the fixture cannot be created there and the test measured the
/// filesystem, not the reader. Linux's ext4 stores arbitrary bytes, which is
/// the case the UTF-8 refusal exists for.
#[cfg(target_os = "linux")]
#[test]
fn a_non_utf8_agent_name_carrying_the_role_is_unknown() {
    use std::os::unix::ffi::OsStrExt;
    let (h, _d) = home_with_archive();
    let dir = h.path().join("Library").join("LaunchAgents");
    let name = std::ffi::OsStr::from_bytes(b"\xff.csq-archive.hot.plist");
    std::fs::write(dir.join(name), "<plist/>").unwrap();
    match discover_role(h.path(), "hot") {
        RoleLabel::Unknown(r) => assert!(r.contains("not valid UTF-8"), "{r}"),
        o => panic!("{o:?}"),
    }
}

/// Every unmeasurable role is named: reporting only the first left the second
/// role's UNKNOWN invisible behind it.
#[test]
fn an_unknown_reason_names_every_unmeasurable_role() {
    let (h, _d) = home_with_archive();
    let mut u = loaded();
    u.0.insert(LABEL_HOT, LaunchdState::Unknown("probe A failed".into()));
    u.0.insert(
        LABEL_NIGHTLY,
        LaunchdState::Unknown("probe B failed".into()),
    );
    match checks(h.path(), &u).upload_jobs {
        CheckState::Unknown(r) => {
            assert!(
                r.contains("probe A failed") && r.contains("probe B failed"),
                "{r}"
            );
        }
        o => panic!("{o:?}"),
    }
}

/// The not-loaded hint names the ONE discovered plist by its `$HOME`-relative
/// path, in double quotes, and says to review it before bootstrapping it.
/// Never the absolute home path: a hint is rendered by surfaces that would then
/// have to redact it again. `$HOME` and not `~`, in double quotes and not
/// single: a hint is a command the operator copies, and that is the only
/// spelling a shell expands.
#[test]
fn a_not_loaded_job_hints_review_then_bootstrap_of_that_exact_file() {
    let (h, _d) = home_with_archive();
    let mut m = loaded();
    m.0.insert(LABEL_NIGHTLY, LaunchdState::NotLoaded);
    let c = checks(h.path(), &m);
    let f = c
        .findings()
        .into_iter()
        .find(|f| f.check == "upload_jobs")
        .expect("a not-loaded job is a finding");
    let plist = "$HOME/Library/LaunchAgents/com.example.csq-archive.nightly.plist";
    assert_eq!(
        f.hint,
        format!("review \"{plist}\", then: launchctl bootstrap gui/$UID \"{plist}\"")
    );
    assert!(
        !f.hint.contains(h.path().to_str().unwrap()),
        "absolute home path in a hint: {:?}",
        f.hint
    );
    // A hint is a command an operator COPIES. Neither `~` nor `$` expands
    // inside single quotes, so no quoted `~`/`$` may appear: the path must be
    // carried by `$HOME` inside double quotes, which the shell does expand.
    assert!(
        !f.hint.contains("'~") && !f.hint.contains("'$"),
        "single-quoted expansion token in a hint: {:?}",
        f.hint
    );
}

#[test]
fn a_skipped_launchd_probe_never_reads_as_backup_off_on_the_statusline() {
    let (h, d) = home_with_archive();
    healthy(&d);
    std::fs::remove_dir_all(h.path().join("Library")).unwrap();
    let c = checks(h.path(), &SkipLaunchd);
    assert!(
        matches!(c.upload_jobs, CheckState::Unknown(_)),
        "{:?}",
        c.upload_jobs
    );
    assert!(!statusline_badges(&c).contains(&"\u{26a0} backup off"));
}
