use super::*;
use serde_json::{json, Value};
fn report() -> ImageReport {
    ImageReport::new(
        Platform::Linux,
        ChildIdentity {
            pid: 42,
            start_exact: 43,
        },
        SessionIdentity {
            pid: 44,
            started_at: 45,
            start_exact: 46,
            surface: ImageSurface::Codex,
            handle_sha256: "a".repeat(64),
        },
        BuildIdentity {
            edition: Edition::Enterprise,
            version: "1.2.3-alpha.1+build.02".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            source_state: SourceState::Clean,
            availability: Availability::Available,
            revision: Some("b".repeat(40)),
        },
        LoadedImage {
            kind: LoadedKind::Unavailable,
            identity: None,
        },
    )
    .unwrap()
}
fn changed(path: &[&str], value: Value) -> Vec<u8> {
    let mut raw = serde_json::to_value(report()).unwrap();
    let mut node = &mut raw;
    for name in &path[..path.len() - 1] {
        node = &mut node[*name];
    }
    node[path[path.len() - 1]] = value;
    serde_json::to_vec(&raw).unwrap()
}
#[test]
fn image_build_producer_decoder_share_strict_tokens() {
    for version in ["0.0.0", "1.2.3", "1.2.3-alpha.1+build.02", "1.0.0--+000"] {
        assert!(validate_build_version(version));
        assert!(ImageReport::decode(&changed(&["build", "version"], json!(version))).is_ok());
    }
    for version in [
        "",
        "1.2",
        "01.2.3",
        "1.2.3-01",
        "1.2.3-",
        "1.2.3+",
        "1.2.3+one..two",
        "1.2.3+one+two",
        "1.2.3\n",
        "1.2.3/secret",
        "1.2.3-α",
    ] {
        assert!(!validate_build_version(version));
        assert_eq!(
            ImageReport::decode(&changed(&["build", "version"], json!(version))),
            Err(ReportError::Malformed),
            "decoded build.version must reject non-SemVer/control text"
        );
    }
    for target in [
        "",
        "linux/secret",
        "linux\nsecret",
        "linux:secret",
        "linux α",
    ] {
        assert!(!validate_build_target(target));
        assert_eq!(
            ImageReport::decode(&changed(&["build", "target"], json!(target))),
            Err(ReportError::Malformed)
        );
    }
    for revision in [
        "a".repeat(39),
        "A".repeat(40),
        "g".repeat(64),
        "a".repeat(65),
    ] {
        assert!(!validate_revision(&revision));
        assert_eq!(
            ImageReport::decode(&changed(&["build", "revision"], json!(revision))),
            Err(ReportError::Malformed)
        );
    }
    assert!(!validate_build_version(&format!(
        "1.2.3+{}",
        "a".repeat(60)
    )));
    assert!(!validate_build_target(&"a".repeat(97)));
    assert!(validate_revision(&"a".repeat(64)));
}
struct RefusalCase {
    path: &'static [&'static str],
    value: Value,
}
#[test]
fn image_report_decoder_is_closed_and_checks_identity_ranges() {
    let cases = [
        RefusalCase {
            path: &["schema"],
            value: json!("csq.mcp_image.v99"),
        },
        RefusalCase {
            path: &["child", "pid"],
            value: json!(1),
        },
        RefusalCase {
            path: &["child", "start_exact"],
            value: json!(0),
        },
        RefusalCase {
            path: &["session", "start_exact"],
            value: json!(0),
        },
        RefusalCase {
            path: &["session", "handle_sha256"],
            value: json!("a".repeat(40)),
        },
        RefusalCase {
            path: &["session", "surface"],
            value: json!("unknown-model"),
        },
        RefusalCase {
            path: &["build", "edition"],
            value: json!("unknown-edition"),
        },
        RefusalCase {
            path: &["child", "raw_secret"],
            value: json!("RAW_PAYLOAD_CANARY"),
        },
        RefusalCase {
            path: &["session", "raw_path"],
            value: json!("RAW_PATH_CANARY"),
        },
        RefusalCase {
            path: &["build", "raw_arg"],
            value: json!("RAW_ARG_CANARY"),
        },
        RefusalCase {
            path: &["loaded", "raw_body"],
            value: json!("RAW_BODY_CANARY"),
        },
        RefusalCase {
            path: &["unrecognized"],
            value: json!(true),
        },
    ];
    for case in cases {
        assert_eq!(
            ImageReport::decode(&changed(case.path, case.value)),
            Err(ReportError::Malformed),
            "closed image report must refuse schema/field/range violation"
        );
    }
    let bytes = report().encode().unwrap();
    assert_eq!(ImageReport::decode(&bytes).unwrap(), report());
}
#[test]
fn image_report_provenance_availability_is_explicit() {
    let mut raw = serde_json::to_value(report()).unwrap();
    raw["build"]["source_state"] = json!("dirty");
    assert_eq!(
        ImageReport::decode(&serde_json::to_vec(&raw).unwrap()),
        Err(ReportError::Malformed)
    );
    raw["build"]["availability"] = json!("unavailable");
    assert_eq!(
        ImageReport::decode(&serde_json::to_vec(&raw).unwrap())
            .unwrap()
            .build()
            .source_state,
        SourceState::Dirty
    );
    raw["build"].as_object_mut().unwrap().remove("revision");
    raw["build"]["source_state"] = json!("unknown");
    let unbound = ImageReport::decode(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(unbound.build().availability, Availability::Unavailable);
    assert!(unbound.build().revision.is_none());
    assert!(serde_json::to_value(unbound).unwrap()["build"]
        .get("revision")
        .is_none());
}
#[test]
fn image_report_loaded_evidence_is_platform_scoped() {
    let identity = FileIdentity {
        dev: 1,
        ino: 2,
        size: 3,
        mtime_sec: -1,
        mtime_nsec: 4,
        ctime_sec: 5,
        ctime_nsec: 6,
    };
    let original = report();
    let loaded = LoadedImage {
        kind: LoadedKind::LinuxProcExe,
        identity: Some(identity.clone()),
    };
    assert!(ImageReport::new(
        Platform::Linux,
        original.child().clone(),
        original.session().clone(),
        original.build().clone(),
        loaded.clone()
    )
    .is_ok());
    assert_eq!(
        ImageReport::new(
            Platform::Macos,
            original.child().clone(),
            original.session().clone(),
            original.build().clone(),
            loaded
        ),
        Err(ReportError::Malformed),
        "non-Linux report must not claim independent Linux image evidence"
    );
    let mut invalid = identity;
    invalid.mtime_nsec = 1_000_000_000;
    assert_eq!(
        ImageReport::new(
            Platform::Linux,
            original.child().clone(),
            original.session().clone(),
            original.build().clone(),
            LoadedImage {
                kind: LoadedKind::LinuxProcExe,
                identity: Some(invalid)
            }
        ),
        Err(ReportError::Malformed)
    );
    assert_eq!(
        ImageReport::new(
            Platform::Macos,
            original.child().clone(),
            original.session().clone(),
            original.build().clone(),
            LoadedImage {
                kind: LoadedKind::Unavailable,
                identity: Some(FileIdentity {
                    dev: 1,
                    ino: 2,
                    size: 3,
                    mtime_sec: 4,
                    mtime_nsec: 5,
                    ctime_sec: 6,
                    ctime_nsec: 7
                })
            }
        ),
        Err(ReportError::Malformed)
    );
}
#[test]
fn image_report_byte_cap_precedes_parsing_and_errors_are_fixed() {
    assert_eq!(
        ImageReport::decode(&vec![b'x'; MAX_REPORT_BYTES + 1]),
        Err(ReportError::Limit),
        "oversize report must refuse before JSON parsing"
    );
    let error = ImageReport::decode(b"RAW_PATH_AND_BODY_CANARY").unwrap_err();
    assert_eq!(error, ReportError::Malformed);
    assert_eq!(error.to_string(), "MCP image report refused");
}

#[cfg(test)]
#[cfg(unix)]
mod file_tests {
    use super::*;
    use crate::{
        messaging::model::{Sender, Surface, VerifiedSession},
        sessions::directives::dirfd::DirFd,
    };
    use std::{
        fs,
        os::{
            fd::AsRawFd,
            unix::fs::{symlink, FileTypeExt, PermissionsExt},
        },
        path::{Path, PathBuf},
    };
    use tempfile::TempDir;

    fn fixture() -> (TempDir, VerifiedSession, ImageReport) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().canonicalize().unwrap();
        let who = VerifiedSession::from_resolved(Sender {
            pid: 44,
            started_at: 45,
            surface: Surface::Codex,
            handle_dir_hash: "a".repeat(64),
            handle_dir: path.to_string_lossy().into_owned(),
            name: None,
            started_exact: Some(46),
        });
        let mut raw = serde_json::to_value(report()).unwrap();
        raw["child"]["pid"] = json!(std::process::id());
        raw["child"]["start_exact"] =
            json!(crate::sessions::ancestor_start(std::process::id()).unwrap());
        (
            dir,
            who,
            ImageReport::decode(&serde_json::to_vec(&raw).unwrap()).unwrap(),
        )
    }
    fn report_dir(who: &VerifiedSession) -> PathBuf {
        who.handle_dir().join(DIRECTORY)
    }
    fn put(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Darwin/APFS cannot materialize this invalid-name fixture (EILSEQ).
    // The full invalid-byte filesystem oracle remains on other Unix targets;
    // Darwin retains the actual UTF8 directory/capacity control below.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn image_report_strict_raw_directory_counter_refuses_invalid_bytes_and_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let fd = DirFd::open(dir.path()).unwrap();
        for n in 0..17 {
            fs::write(dir.path().join(n.to_string()), []).unwrap();
        }
        let admitted = fd.names_strict(17).unwrap();
        assert!(admitted.complete);
        assert_eq!(admitted.names.len(), 17);
        fs::write(dir.path().join("sentinel"), []).unwrap();
        assert!(
            !fd.names_strict(17).unwrap().complete,
            "eighteenth raw entry must be overflow sentinel"
        );
        // APFS rejects these bytes before a directory entry can exist. Keep
        // the real invalid-dirent case on filesystems that can create it;
        // the capacity/overflow assertions above still execute on macOS.
        #[cfg(not(target_os = "macos"))]
        {
            use std::os::unix::ffi::OsStringExt;
            let invalid = tempfile::tempdir().unwrap();
            fs::write(
                invalid
                    .path()
                    .join(std::ffi::OsString::from_vec(vec![0xff])),
                [],
            )
            .unwrap();
            let fd = DirFd::open(invalid.path()).unwrap();
            assert!(
                !fd.names_strict(17).unwrap().complete,
                "non-UTF8 raw entries must not vanish before capacity"
            );
            let legacy = fd.names(17).unwrap();
            assert!(legacy.complete);
            assert!(legacy.names.is_empty());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn image_report_strict_raw_directory_counter_admits_utf8_and_refuses_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let fd = DirFd::open(dir.path()).unwrap();
        for n in 0..17 {
            fs::write(dir.path().join(n.to_string()), []).unwrap();
        }
        let admitted = fd.names_strict(17).unwrap();
        assert!(admitted.complete);
        assert_eq!(admitted.names.len(), 17);
        fs::write(dir.path().join("sentinel"), []).unwrap();
        assert!(
            !fd.names_strict(17).unwrap().complete,
            "eighteenth raw entry must be overflow sentinel"
        );
    }
    #[test]
    fn image_reports_publish_own_slot_and_reader_preserves_state() {
        let (_dir, who, report) = fixture();
        publish(&who, &report).unwrap();
        let path = report_dir(&who).join(report.filename());
        let before = fs::read(&path).unwrap();
        assert_eq!(
            read_reports(who.handle_dir()).unwrap(),
            vec![report.clone()]
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        publish(&who, &report).unwrap();
        assert_eq!(fs::read_dir(report_dir(&who)).unwrap().count(), 2);
        assert_eq!(read_reports(who.handle_dir()).unwrap(), vec![report]);
    }
    #[test]
    fn image_reports_refuse_unsafe_file_kinds_links_and_modes() {
        let (dir, who, report) = fixture();
        publish(&who, &report).unwrap();
        let path = report_dir(&who).join(report.filename());
        let bytes = report.encode().unwrap();
        let extra = dir.path().join("extra");
        fs::hard_link(&path, &extra).unwrap();
        assert_eq!(
            read_reports(who.handle_dir()),
            Err(ReportError::Unsafe),
            "hardlinked reports must be refused"
        );
        fs::remove_file(extra).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_reports(who.handle_dir()), Err(ReportError::Unsafe));
        fs::remove_file(&path).unwrap();
        let target = dir.path().join("target");
        put(&target, &bytes);
        symlink(&target, &path).unwrap();
        assert_eq!(read_reports(who.handle_dir()), Err(ReportError::Unsafe));
        fs::remove_file(&path).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let named = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: live NUL-terminated fixture path, fixed permissions, no pointer retained.
        assert_eq!(unsafe { libc::mkfifo(named.as_ptr(), 0o600) }, 0);
        assert_eq!(read_reports(who.handle_dir()), Err(ReportError::Unsafe));
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
        fs::remove_file(&path).unwrap();
        put(&path, &bytes);
        assert_eq!(read_reports(who.handle_dir()).unwrap(), vec![report]);
    }
    #[test]
    fn image_reports_reader_and_publisher_enforce_eight_file_cap() {
        let (_dir, who, own) = fixture();
        let directory = report_dir(&who);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        for n in 2..10 {
            let mut value = serde_json::to_value(report()).unwrap();
            value["child"]["pid"] = json!(n);
            value["child"]["start_exact"] = json!(n);
            put(
                &directory.join(format!("{n}-{n}.json")),
                &serde_json::to_vec(&value).unwrap(),
            );
        }
        assert_eq!(read_reports(who.handle_dir()).unwrap().len(), 8);
        assert_eq!(publish(&who, &own), Err(ReportError::Limit));
        let mut ninth = serde_json::to_value(report()).unwrap();
        ninth["child"]["pid"] = json!(10);
        ninth["child"]["start_exact"] = json!(10);
        put(
            &directory.join("10-10.json"),
            &serde_json::to_vec(&ninth).unwrap(),
        );
        assert_eq!(
            read_reports(who.handle_dir()),
            Err(ReportError::Limit),
            "ninth report must refuse the complete set"
        );
    }
    #[test]
    fn image_reports_refuse_wrong_session_or_child_without_publication() {
        let (_dir, who, own) = fixture();
        let mut raw = serde_json::to_value(&own).unwrap();
        raw["session"]["handle_sha256"] = json!("c".repeat(64));
        let wrong = ImageReport::decode(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(publish(&who, &wrong), Err(ReportError::Malformed));
        assert!(!report_dir(&who).exists());
        raw = serde_json::to_value(&own).unwrap();
        raw["child"]["start_exact"] = json!(own.child.start_exact + 1);
        let wrong = ImageReport::decode(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(publish(&who, &wrong), Err(ReportError::Malformed));
        assert!(!report_dir(&who).exists());
        publish(&who, &own).unwrap();
    }
    #[test]
    fn image_report_publication_unlocks_even_while_fork_child_retains_descriptor() {
        // Signal lock FIRST, then the shared env-test lock — the established
        // order between these two shared mutexes (see
        // `cli_deps::auto_update`'s `lock_signal_state_for_test` callers and
        // `codex_supervise`'s documented signal-then-env order). The reverse
        // order is an ABBA deadlock of the lib-test process under the default
        // parallel harness.
        let _signals = crate::platform::test_env::signal_lock();
        let _env = crate::platform::test_env::lock();
        // A child survives the publication boundary on both success and refusal.
        // Drop kills/reaps it on assertion failure as well as normal completion.
        struct ChildCustody {
            pid: libc::pid_t,
            _release: fs::File,
        }
        impl Drop for ChildCustody {
            fn drop(&mut self) {
                // SAFETY: owned child pid; no pointers retained. Kill prevents a
                // failed synchronization from leaving teardown blocked forever.
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                    while libc::waitpid(self.pid, std::ptr::null_mut(), 0) < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                    }
                }
            }
        }
        for refuse_after_lock in [false, true] {
            let (_dir, who, report) = fixture();
            let mut child = None;
            let result = super::super::files::publish_with_lock_observer(&who, &report, |lock| {
                use std::os::fd::FromRawFd;
                let mut ready = [0; 2];
                let mut release = [0; 2];
                // SAFETY: writable two-int arrays passed to pipe. All descriptors
                // become owned Files in the parent or are closed by the child.
                assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
                let ready_read = unsafe { fs::File::from_raw_fd(ready[0]) };
                let ready_write = unsafe { fs::File::from_raw_fd(ready[1]) };
                assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
                let release_read = unsafe { fs::File::from_raw_fd(release[0]) };
                let release_write = unsafe { fs::File::from_raw_fd(release[1]) };
                // SAFETY: child uses ONLY async-signal-safe libc calls and stack
                // scalars; it never unwinds, allocates, or touches Rust locks.
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe {
                        let duplicated = libc::dup(lock.as_raw_fd());
                        libc::close(ready[0]);
                        libc::close(release[1]);
                        let byte = [1u8];
                        if duplicated < 0 || libc::write(ready[1], byte.as_ptr().cast(), 1) != 1 {
                            libc::_exit(2);
                        }
                        libc::close(ready[1]);
                        let mut byte = [0u8];
                        // Retry interrupted reads without touching Rust or
                        // allocating in the post-fork child. The owned pipe's
                        // descriptor and one-byte buffer remain valid throughout.
                        while libc::read(release[0], byte.as_mut_ptr().cast(), 1) < 0 {}
                        libc::close(duplicated);
                        libc::_exit(0);
                    }
                }
                assert!(pid > 0, "fork fixture child");
                child = Some(ChildCustody {
                    pid,
                    _release: release_write,
                });
                drop(ready_write);
                drop(release_read);
                // Bound synchronization instead of timing sleeps; readiness proves
                // the child duplicated the acquired descriptor before publication.
                let mut poll = libc::pollfd {
                    fd: ready_read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
                use std::io::Read;
                let mut ready_read = ready_read;
                let mut byte = [0];
                ready_read.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [1]);
                if refuse_after_lock {
                    put(&report_dir(&who).join("not-a-report"), b"fixture");
                }
            });
            assert_eq!(
                result,
                if refuse_after_lock {
                    Err(ReportError::Unsafe)
                } else {
                    Ok(())
                }
            );
            // SAFETY: signal zero only checks the owned, unreaped child;
            // unlike waitpid(WNOHANG), this cannot consume custody and permit
            // PID reuse before ChildCustody's eventual kill-and-reap.
            assert_eq!(unsafe { libc::kill(child.as_ref().unwrap().pid, 0) }, 0);
            let contender = fs::File::open(report_dir(&who).join(".lock")).unwrap();
            // SAFETY: live fixture descriptor. The child is still blocked with
            // its duplicate, so close-only production code fails this assertion.
            assert_eq!(
                unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0,
                "publication must release before inherited descriptor closes"
            );
            assert_eq!(
                unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_UN) },
                0
            );
            drop(child);
        }
    }

    #[test]
    fn image_reports_missing_reader_and_busy_writer_do_not_mutate() {
        let (_dir, who, report) = fixture();
        assert_eq!(
            read_reports(who.handle_dir()),
            Err(ReportError::Unavailable)
        );
        assert!(!report_dir(&who).exists());
        publish(&who, &report).unwrap();
        let file = fs::File::open(report_dir(&who).join(".lock")).unwrap();
        // SAFETY: fixture-owned open descriptor; no pointers passed to flock.
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let path = report_dir(&who).join(report.filename());
        let before = fs::read(&path).unwrap();
        assert_eq!(publish(&who, &report), Err(ReportError::Busy));
        assert_eq!(fs::read(&path).unwrap(), before);
        // A flock belongs to the open file DESCRIPTION, so closing this descriptor does not
        // release it while any duplicate lives: a `fork()` made by a concurrent test in this
        // process (sessions::directives forks without exec) holds exactly such a duplicate
        // until that child exits. `straggler` is that duplicate, made deterministically; the
        // lock is then ended by `LOCK_UN` on the description, as `FixtureLockDir` does in
        // lifecycle_retry_tests, instead of by the race against a stranger's child.
        // SAFETY: dup of a live fixture-owned descriptor; the new descriptor is owned below.
        let duplicated = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(
            duplicated >= 0,
            "dup failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `duplicated` is a fresh descriptor nothing else owns.
        let straggler = unsafe { <fs::File as std::os::fd::FromRawFd>::from_raw_fd(duplicated) };
        drop(file);
        assert_eq!(
            publish(&who, &report),
            Err(ReportError::Busy),
            "a surviving duplicate keeps the description locked"
        );
        // SAFETY: owned live descriptor; LOCK_UN accesses no Rust memory.
        assert_eq!(
            unsafe { libc::flock(straggler.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        // The duplicate is still open here: only LOCK_UN can have released the lock.
        publish(&who, &report).unwrap();
        drop(straggler);
        fs::rename(&path, report_dir(&who).join("2-3.json")).unwrap();
        assert_eq!(read_reports(who.handle_dir()), Err(ReportError::Malformed));
    }
    #[test]
    fn image_reports_observer_brackets_one_checked_read_without_second_pass() {
        let (_dir, who, report) = fixture();
        publish(&who, &report).unwrap();
        let calls = std::cell::Cell::new(0usize);
        let mut value = serde_json::to_value(&report).unwrap();
        value["build"]["version"] = json!("2.0.0");
        let bytes = serde_json::to_vec(&value).unwrap();
        let changed = ImageReport::decode(&bytes).unwrap();
        let path = report_dir(&who).join(report.filename());
        let rows = read_reports_observed(who.handle_dir(), &|child| {
            assert_eq!(
                child,
                report.child(),
                "numeric filename child must be the observation subject"
            );
            let n = calls.get();
            // Isolated test mutation proves the before callback precedes the checked read.
            // The production observer contract is read-only.
            if n == 0 {
                put(&path, &bytes);
            }
            calls.set(n + 1);
            n
        })
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].report, changed,
            "before observation must precede report byte consumption"
        );
        assert_eq!(
            (rows[0].before, rows[0].after),
            (0, 1),
            "single checked report read must have distinct ordered observations"
        );
        assert_eq!(
            calls.get(),
            2,
            "report collection must not perform a repeated whole-set read"
        );
    }
}
