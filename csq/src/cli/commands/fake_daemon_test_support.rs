//! Shared `#[cfg(test)]` fixture: a fake, minimally-responsive csq daemon
//! for tests that exercise a code path gated on `daemon::detect_daemon`
//! reporting `Healthy` (C-R4-3's up-front daemon-health checks in both
//! `codex_supervise::validate_codex_relaunch_target`'s callers and
//! `swap::handoff_to_supervisor`).
//!
//! Governing task item 4 (test-helper hoist): this was previously defined
//! twice — `codex_supervise::tests::{FakeHealthyDaemon, spawn_fake_healthy_daemon}`
//! and an identical `swap::tests::{SwapFakeHealthyDaemon, spawn_swap_fake_healthy_daemon}`
//! — because at the time `swap.rs`'s C-R4-3 fix landed, hoisting the two into
//! one shared helper would have touched a sibling shard's file. Both call
//! sites now use this single definition.
//!
//! Writes THIS test process's own pid into the fake daemon's PID file (a
//! genuinely alive process whose OS-reported command starts with `csq-` —
//! this crate's cargo test binary naming — which `process::is_pid_foreign`
//! accepts as "ours", mirroring `daemon::detect::tests::detect_live_daemon_
//! returns_healthy`'s precedent) and answers exactly one `/api/health` GET
//! with this CLI's own [`csq_core::daemon::CLI_VERSION`], so
//! `version_drift_reason` sees no drift.
//!
//! SAFETY note (environment-safety, not memory-safety): on Linux,
//! `pid_file_path`/`socket_path` resolve through `$XDG_RUNTIME_DIR` rather
//! than `base_dir` whenever that env var is set (common on systemd-managed
//! CI runners) — overriding it to a fixture-local dir for the guard's
//! lifetime is load-bearing, not just isolation: without it this fixture
//! could silently write into (or read from) a REAL daemon's runtime dir on
//! such a host. The override is guarded by the shared cross-module
//! `csq_core::platform::test_env::lock()` mutex so two tests overriding the
//! same process-global env var never race.
//!
//! The short runtime dir is named `csq-fd-<pid-ns>-<owner-pid>-<random>`: a
//! `TempDir`'s `Drop` removes it on a normal exit, and the pid in the name
//! lets a later fixture spawn sweep dirs whose owner died WITHOUT running
//! `Drop` (SIGKILL, abort, `panic = "abort"`). The sweep removes only a real
//! same-uid directory whose named pid is provably dead (`kill(pid, 0)` →
//! `ESRCH`) AND whose name belongs to THIS pid namespace: a pid is meaningful
//! only inside its namespace, so a dir left by a process in another namespace
//! can read as `ESRCH` here while its owner is alive there. A live,
//! foreign-uid, foreign-namespace, symlinked, or pre-fix-named entry is kept.

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

/// Upper bound on pid-named fixture dirs one sweep pass examines; bounds the
/// spawn-time cost even when a host's temp root has accumulated a large
/// backlog of leaked dirs.
#[cfg(unix)]
const FIXTURE_SWEEP_CANDIDATE_BOUND: usize = 256;

/// This process's effective uid — the ownership key for a sweepable fixture
/// dir.
#[cfg(unix)]
fn fixture_sweep_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail; it returns the
    // calling process's effective uid.
    unsafe { libc::geteuid() as u32 }
}

/// The temp roots a fixture sweep covers: `temp_dir()` plus `/tmp` (the root
/// the short runtime dir is created in), deduped when the two name the same
/// path. Unix-only — the whole fixture is.
#[cfg(unix)]
fn fixture_sweep_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    let slash_tmp = PathBuf::from("/tmp");
    if !roots.iter().any(|root| root == &slash_tmp) {
        roots.push(slash_tmp);
    }
    roots
}

/// The pid-namespace inode this process runs in, or 0 when the platform has no
/// pid namespaces (macOS) or the link cannot be read.
///
/// A pid is meaningful only INSIDE its namespace: a dir left by a process in a
/// different namespace whose pid is long gone there reads as dead here
/// (`kill` → `ESRCH`) while its owner may still be alive. Names carry this
/// inode so the sweep only ever considers its OWN namespace's fixtures. On
/// Linux an unreadable namespace (0) disables the sweep entirely: a 0-named
/// dir from another degraded namespace would otherwise read as our own and be
/// deleted while its owner is alive (D237 R2 MED-2/LOW-E). macOS has no pid
/// namespaces, names every fixture dir with 0 by design, and keeps sweeping.
#[cfg(unix)]
fn fixture_pid_namespace() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // `/proc/self/ns/pid` is a symlink whose target is `pid:[<inode>]`.
        if let Ok(link) = std::fs::read_link("/proc/self/ns/pid") {
            if let Some(inner) = link
                .to_str()
                .and_then(|text| text.strip_prefix("pid:["))
                .and_then(|text| text.strip_suffix(']'))
            {
                if let Ok(ns) = inner.parse::<u64>() {
                    return ns;
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Extract `(pid-namespace inode, owner pid)` from a fixture dir name shaped
/// `csq-fd-<ns>-<pid>-<suffix>`. Returns `None` for every other name — the
/// pre-fix `csq-fd-<pid>-<suffix>` shape, `csq-fd-legacy`, and numbers that
/// overflow their type; all are kept by the sweep.
#[cfg(unix)]
fn fixture_dir_owner(name: &str) -> Option<(u64, i32)> {
    let rest = name.strip_prefix("csq-fd-")?;
    let (ns, rest) = rest.split_once('-')?;
    let (pid, _suffix) = rest.split_once('-')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(ns) || !digits(pid) {
        return None;
    }
    Some((ns.parse::<u64>().ok()?, pid.parse::<i32>().ok()?))
}

/// Answer "is this process provably gone?" via `kill(pid, 0)`, which sends
/// no signal and only performs the kernel's existence/permission check.
/// `ESRCH` is the ONLY outcome that proves death; anything else (0 = alive,
/// `EPERM` = alive but foreign, `EINVAL`, …) keeps the dir, so a reused pid
/// leaks the dir rather than risking another owner's data.
#[cfg(unix)]
fn fixture_owner_pid_is_dead(pid: i32) -> bool {
    // SAFETY: signal 0 delivers nothing and has no memory-safety
    // preconditions; the pid is validated by the kernel.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Linux: a 0 namespace means it could not be read, so no dir name can prove
/// it is ours — sweep nothing. Elsewhere the namespace field is 0 by design
/// (macOS has no pid namespaces), so the sweep proceeds.
#[cfg(unix)]
fn sweep_permitted_by_namespace(own_ns: u64) -> bool {
    #[cfg(target_os = "linux")]
    {
        own_ns != 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = own_ns;
        true
    }
}

/// Sweep `roots` for fixture dirs whose owning test process died without
/// running `TempDir`'s `Drop` (SIGKILL, abort).
///
/// A dir is removed ONLY when ALL hold:
/// - its name matches `csq-fd-<ns>-<pid>-*` and `<ns>` is THIS process's
///   pid-namespace inode (a pid is meaningful only inside its namespace); on
///   Linux a namespace that cannot be read (0) disables the sweep;
/// - `symlink_metadata` says it is a real directory (a symlink is never
///   followed or removed);
/// - it is owned by `owner_uid`; and
/// - its named pid is provably dead ([`fixture_owner_pid_is_dead`]).
///
/// Everything else — old-shape names, foreign namespaces, foreign owners, live
/// pids, unreadable entries — is kept. At most `max_candidates` pid-shaped
/// entries are examined per pass across all roots; returns the number removed.
#[cfg(unix)]
fn sweep_stale_fixture_dirs(roots: &[PathBuf], owner_uid: u32, max_candidates: usize) -> usize {
    sweep_stale_fixture_dirs_for_namespace(
        roots,
        owner_uid,
        max_candidates,
        fixture_pid_namespace(),
    )
}

/// The sweep, with the namespace as a PARAMETER so tests can prove the CALL
/// SITE's fail-closed behaviour, not only the predicate's: a Linux run whose
/// namespace cannot be read (0) must leave `csq-fd-0-<dead pid>-*` dirs alone,
/// because `/proc` cannot prove that name is ours.
#[cfg(unix)]
fn sweep_stale_fixture_dirs_for_namespace(
    roots: &[PathBuf],
    owner_uid: u32,
    max_candidates: usize,
    own_ns: u64,
) -> usize {
    use std::os::unix::fs::MetadataExt;

    if !sweep_permitted_by_namespace(own_ns) {
        return 0;
    }
    let mut examined = 0usize;
    let mut removed = 0usize;
    'roots: for root in roots {
        // An unreadable root has nothing to sweep and must not fail a spawn.
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some((ns, pid)) = fixture_dir_owner(name) else {
                continue;
            };
            if ns != own_ns {
                continue;
            }
            if examined >= max_candidates {
                break 'roots;
            }
            examined += 1;
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if !meta.file_type().is_dir() || meta.uid() != owner_uid {
                continue;
            }
            if !fixture_owner_pid_is_dead(pid) {
                continue;
            }
            if std::fs::remove_dir_all(entry.path()).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// Production entry point: one bounded sweep of the default roots, called
/// once per fixture spawn before the new runtime dir is created.
#[cfg(unix)]
fn sweep_stale_fixture_dirs_default() {
    let _ = sweep_stale_fixture_dirs(
        &fixture_sweep_roots(),
        fixture_sweep_uid(),
        FIXTURE_SWEEP_CANDIDATE_BOUND,
    );
}

#[cfg(unix)]
pub(crate) struct FakeHealthyDaemon {
    pid_path: PathBuf,
    // F-flaky: signals the accept loop to stop. Set in `Drop`, BEFORE the
    // pid file is removed — see this struct's `Drop` impl doc.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _listener_thread: std::thread::JoinHandle<()>,
    // Redirects `socket_path`/`pid_file_path` for THIS base only (an internal ticket):
    // no fixture mutates the process-global `$XDG_RUNTIME_DIR`.
    _registration: csq_core::daemon::paths::test_socket::Registration,
    #[cfg(target_os = "linux")]
    _runtime_dir: tempfile::TempDir,
}

#[cfg(unix)]
impl Drop for FakeHealthyDaemon {
    fn drop(&mut self) {
        // F-flaky: stop the accept loop before anything else — the thread
        // is NOT joined (a blocking `cargo test` teardown for every one of
        // this fixture's callers is not worth the latency), so this is a
        // best-effort signal; the loop's own `Duration::from_millis(5)`
        // poll means it notices within one tick and exits on its own.
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::remove_file(&self.pid_path);
    }
}

#[cfg(unix)]
pub(crate) fn spawn_fake_healthy_daemon(base_dir: &Path) -> FakeHealthyDaemon {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // A fixture dir's `TempDir` `Drop` never runs when the test process is
    // SIGKILLed or aborted, so dead owners leak `csq-fd-*` dirs. Sweep them
    // once per spawn (bounded; dead same-uid pid-named dirs only) before
    // creating ours, per the ownership rules in `sweep_stale_fixture_dirs`.
    sweep_stale_fixture_dirs_default();

    // Keep the Linux socket in an owned short directory, independent of a
    // runner's arbitrarily deep TMPDIR. State fixtures remain in base_dir.
    #[cfg(target_os = "linux")]
    let runtime_dir = tempfile::Builder::new()
        .prefix(&format!(
            "csq-fd-{}-{}-",
            fixture_pid_namespace(),
            std::process::id()
        ))
        .tempdir_in("/tmp")
        .expect("private short fake daemon runtime dir");

    #[cfg(target_os = "linux")]
    let (registration, _) =
        csq_core::daemon::paths::test_socket::register_in(base_dir, runtime_dir.path());
    #[cfg(not(target_os = "linux"))]
    let (registration, _) = csq_core::daemon::paths::test_socket::register(base_dir);

    let pid_path = csq_core::daemon::pid_file_path(base_dir);
    let sock_path = csq_core::daemon::socket_path(base_dir);
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent).expect("pid file parent dir");
    }
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).expect("socket parent dir");
    }
    // Defensive unlink — a stale socket left by an unrelated prior run (or,
    // off macOS, shared via `$XDG_RUNTIME_DIR`) must not collide with our
    // bind.
    let _ = std::fs::remove_file(&sock_path);

    std::fs::write(&pid_path, std::process::id().to_string()).expect("write fake pid file");

    let listener = UnixListener::bind(&sock_path).expect("bind fake daemon socket");
    // F-flaky (root cause of `handoff_refuses_and_withdraws_request_when_
    // recorded_supervisor_is_dead` intermittently reporting "csq daemon is
    // stale" under full-suite concurrency): the PRIOR version of this
    // thread called `listener.accept()` exactly ONCE and then returned,
    // which DROPS `listener` (moved into the closure) the instant that one
    // connection is handled — closing the socket to any FURTHER connect
    // attempt with `ECONNREFUSED`, which `unix_health_check` reports as
    // `Stale`. Any caller whose flow reaches `detect_daemon` more than
    // once against this fixture (directly, via a retry, or via a second
    // code path this fixture's callers evolve to add later) loses the
    // race the instant the first connection completes — under a
    // uncontended run the ONE health-check this test needs usually lands
    // before that happens; under heavy concurrent subprocess load (this
    // file spawns real child processes in nearly every test) the accept
    // thread can be scheduled late enough that a caller's OWN retry (or a
    // sibling call this function's callers did not anticipate) is the one
    // that hits the already-closed listener. Looping `accept()` for the
    // fixture's entire lifetime removes the one-shot fragility rather than
    // trying to prove which caller path is the second connection.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    listener
        .set_nonblocking(true)
        .expect("set fake daemon listener nonblocking");
    let thread = std::thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf);
                    let body = format!("{{\"version\":\"{}\"}}", csq_core::daemon::CLI_VERSION);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    FakeHealthyDaemon {
        pid_path,
        stop,
        _listener_thread: thread,
        _registration: registration,
        #[cfg(target_os = "linux")]
        _runtime_dir: runtime_dir,
    }
}

/// The "no daemon at all" counterpart to [`spawn_fake_healthy_daemon`]: a
/// test that needs `daemon::detect_daemon` to report `NotRunning` against a
/// FRESH tempdir registers that base with `daemon::paths::test_socket`, so
/// `pid_file_path`/`socket_path` resolve under the base instead of whatever
/// the ambient (or a sibling fixture's) runtime dir holds. It mutates no
/// process-global state and takes no env lock: a caller whose code reads
/// other process env holds `test_env::lock()` itself.
#[cfg(unix)]
pub(crate) struct NoDaemonEnvGuard {
    _registration: csq_core::daemon::paths::test_socket::Registration,
}

#[cfg(unix)]
pub(crate) fn spawn_no_daemon_env_guard(base_dir: &Path) -> NoDaemonEnvGuard {
    // `base_dir` is a fresh tempdir with no pid/socket file; registering it
    // makes `detect_daemon(base_dir)` genuinely observe `NotRunning` rather
    // than whatever the real runtime dir holds, with no process-global
    // mutation (an internal ticket).
    let (registration, _) = csq_core::daemon::paths::test_socket::register(base_dir);
    NoDaemonEnvGuard {
        _registration: registration,
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    #[test]
    fn fake_daemon_socket_is_healthy_beneath_an_overlong_state_root() {
        let root = tempfile::TempDir::new_in("/tmp").unwrap();
        let state = root.path().join("x".repeat(160));
        std::fs::create_dir(&state).unwrap();
        // macOS resolves its socket through the base path rather than XDG.
        // An owned short alias keeps the kernel address bounded while the
        // physical state still resides beneath the overlong directory.
        #[cfg(target_os = "macos")]
        let base = {
            let alias = root.path().join("s");
            std::os::unix::fs::symlink(&state, &alias).unwrap();
            assert_eq!(
                std::fs::canonicalize(&alias).unwrap(),
                std::fs::canonicalize(&state).unwrap(),
            );
            alias
        };
        #[cfg(not(target_os = "macos"))]
        let base = state.clone();
        let fixture = super::spawn_fake_healthy_daemon(&base);
        let socket = csq_core::daemon::socket_path(&base);
        assert!(!socket.starts_with(&state));
        assert!(socket.as_os_str().len() < 104);
        assert!(matches!(
            csq_core::daemon::detect_daemon(&base),
            csq_core::daemon::DetectResult::Healthy { .. },
        ));
        let runtime = socket.parent().unwrap().to_owned();
        #[cfg(target_os = "linux")]
        assert!(
            runtime
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!(
                    "csq-fd-{}-{}-",
                    super::fixture_pid_namespace(),
                    std::process::id()
                ))),
            "fixture runtime dir must embed the pid namespace and the owner pid: {}",
            runtime.display(),
        );
        drop(fixture);
        // Linux's fixture owns the short runtime; macOS's root owns the alias.
        #[cfg(target_os = "macos")]
        drop(root);
        assert!(!runtime.exists(), "owned runtime dir is removed on drop");
    }

    /// Spawn and REAP a short-lived child; the returned pid is certainly dead
    /// at the moment of return (barring an astronomically unlikely immediate
    /// reuse, which the sweep would treat as alive and keep — safe direction).
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        child.wait().expect("reap short-lived child");
        pid
    }

    fn sweep_in(root: &std::path::Path, owner_uid: u32, max_candidates: usize) -> usize {
        super::sweep_stale_fixture_dirs(&[root.to_path_buf()], owner_uid, max_candidates)
    }

    #[test]
    fn sweep_removes_a_dead_owner_dir() {
        let root = tempfile::TempDir::new().expect("temp root");
        let dir = root.path().join(format!(
            "csq-fd-{}-{}-dead",
            super::fixture_pid_namespace(),
            dead_pid()
        ));
        std::fs::create_dir(&dir).expect("create stale fixture dir");

        let removed = sweep_in(
            root.path(),
            super::fixture_sweep_uid(),
            super::FIXTURE_SWEEP_CANDIDATE_BOUND,
        );

        assert_eq!(removed, 1, "dead-owner dir must be swept");
        assert!(!dir.exists(), "dead-owner dir must be gone");
    }

    #[test]
    fn sweep_keeps_a_live_owner_dir() {
        let root = tempfile::TempDir::new().expect("temp root");
        let dir = root.path().join(format!(
            "csq-fd-{}-{}-live",
            super::fixture_pid_namespace(),
            std::process::id()
        ));
        std::fs::create_dir(&dir).expect("create live fixture dir");

        let removed = sweep_in(
            root.path(),
            super::fixture_sweep_uid(),
            super::FIXTURE_SWEEP_CANDIDATE_BOUND,
        );

        assert_eq!(removed, 0, "a live owner's dir must be kept");
        assert!(dir.is_dir(), "a live owner's dir must still exist");
    }

    /// D237 R2 MED-2/LOW-E: on Linux a 0 namespace means /proc could not be
    /// read, so no dir name proves ownership — the sweep must be disabled
    /// rather than treating every `csq-fd-0-*` dir as ours. macOS names every
    /// fixture dir with 0 by design and must keep sweeping.
    #[test]
    fn sweep_namespace_guard_fails_closed_on_linux() {
        assert!(
            super::sweep_permitted_by_namespace(7),
            "a readable namespace permits the sweep"
        );
        #[cfg(target_os = "linux")]
        assert!(
            !super::sweep_permitted_by_namespace(0),
            "an unreadable Linux namespace must disable the sweep"
        );
        #[cfg(not(target_os = "linux"))]
        assert!(
            super::sweep_permitted_by_namespace(0),
            "macOS has no pid namespaces; 0 is its only value"
        );
    }

    /// D237 R3 LOW-3: the CALL SITE, not only the predicate. A namespace of 0
    /// on Linux means `/proc` was unreadable, so a `csq-fd-0-<dead pid>-*` dir
    /// must SURVIVE the sweep — the predicate test alone could pass while the
    /// call site kept reading the real namespace or ignored the answer. On a
    /// platform where 0 is the only namespace (macOS), the SAME dir is swept:
    /// that half proves the dir shape matches the sweep, so the Linux half is
    /// discriminating rather than vacuous.
    #[test]
    fn sweep_call_site_obeys_an_unreadable_namespace() {
        let root = tempfile::TempDir::new().expect("temp root");
        let dir = root.path().join(format!("csq-fd-0-{}-deadns", dead_pid()));
        std::fs::create_dir(&dir).expect("create namespace-zero dir");

        let removed = super::sweep_stale_fixture_dirs_for_namespace(
            &[root.path().to_path_buf()],
            super::fixture_sweep_uid(),
            super::FIXTURE_SWEEP_CANDIDATE_BOUND,
            0,
        );

        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                removed, 0,
                "an unreadable Linux namespace must sweep nothing"
            );
            assert!(
                dir.is_dir(),
                "a csq-fd-0 dir must survive an unreadable-namespace sweep"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                removed, 1,
                "where 0 is the only namespace, the same dir IS swept"
            );
            assert!(!dir.exists(), "the swept dir is gone");
        }
    }

    #[test]
    fn sweep_keeps_a_foreign_namespace_dir() {
        // A pid is meaningful only inside its namespace: this dir's pid may be
        // dead HERE while its owner is alive in another namespace, so a
        // foreign-namespace name is never swept even with a provably dead pid.
        let root = tempfile::TempDir::new().expect("temp root");
        let foreign_ns = super::fixture_pid_namespace() ^ 1;
        let dir = root
            .path()
            .join(format!("csq-fd-{foreign_ns}-{}-otherns", dead_pid()));
        std::fs::create_dir(&dir).expect("create foreign-namespace dir");

        let removed = sweep_in(
            root.path(),
            super::fixture_sweep_uid(),
            super::FIXTURE_SWEEP_CANDIDATE_BOUND,
        );

        assert_eq!(removed, 0, "a foreign-namespace dir must be kept");
        assert!(dir.is_dir(), "a foreign-namespace dir must still exist");
    }

    #[test]
    fn sweep_keeps_a_foreign_uid_dir() {
        let root = tempfile::TempDir::new().expect("temp root");
        let dir = root.path().join(format!(
            "csq-fd-{}-{}-foreign",
            super::fixture_pid_namespace(),
            dead_pid()
        ));
        std::fs::create_dir(&dir).expect("create foreign fixture dir");
        // XOR flips the low bit, so this is never the process's own uid.
        let foreign_uid = super::fixture_sweep_uid() ^ 1;

        let removed = sweep_in(
            root.path(),
            foreign_uid,
            super::FIXTURE_SWEEP_CANDIDATE_BOUND,
        );

        assert_eq!(removed, 0, "a dir owned by another uid must be kept");
        assert!(dir.is_dir(), "a foreign-owned dir must still exist");
    }

    #[test]
    fn sweep_keeps_a_symlink() {
        let root = tempfile::TempDir::new().expect("temp root");
        let target = root.path().join("target");
        std::fs::create_dir(&target).expect("create symlink target");
        let link = root.path().join(format!(
            "csq-fd-{}-{}-link",
            super::fixture_pid_namespace(),
            dead_pid()
        ));
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let removed = sweep_in(
            root.path(),
            super::fixture_sweep_uid(),
            super::FIXTURE_SWEEP_CANDIDATE_BOUND,
        );

        assert_eq!(removed, 0, "a symlink must never be removed");
        assert!(
            link.symlink_metadata().is_ok(),
            "the symlink itself must still exist"
        );
        assert!(target.is_dir(), "the symlink target must be untouched");
    }

    #[test]
    fn sweep_keeps_names_without_a_parsable_pid() {
        let root = tempfile::TempDir::new().expect("temp root");
        let legacy = root.path().join("csq-fd-legacy");
        let malformed = root.path().join("csq-fd-not-a-pid-x");
        // The ONE-name-field shape every fixture wrote before the namespace
        // inode was added: its pid cannot be trusted to this namespace, so it
        // is kept (a leaked old dir is the safe direction).
        let pre_fix = root.path().join(format!("csq-fd-{}-old", dead_pid()));
        std::fs::create_dir(&legacy).expect("create legacy dir");
        std::fs::create_dir(&malformed).expect("create malformed dir");
        std::fs::create_dir(&pre_fix).expect("create pre-fix dir");

        let removed = sweep_in(
            root.path(),
            super::fixture_sweep_uid(),
            super::FIXTURE_SWEEP_CANDIDATE_BOUND,
        );

        assert_eq!(removed, 0, "names without a parsable pid are kept");
        assert!(
            legacy.is_dir() && malformed.is_dir() && pre_fix.is_dir(),
            "pre-fix-shaped dirs must still exist"
        );
    }

    #[test]
    fn sweep_respects_the_per_pass_candidate_bound() {
        let root = tempfile::TempDir::new().expect("temp root");
        let pid = dead_pid();
        for suffix in ["a", "b", "c"] {
            std::fs::create_dir(root.path().join(format!(
                "csq-fd-{}-{pid}-{suffix}",
                super::fixture_pid_namespace()
            )))
            .expect("create stale fixture dir");
        }

        let removed = sweep_in(root.path(), super::fixture_sweep_uid(), 2);

        assert_eq!(
            removed, 2,
            "only the bound's worth of candidates may be examined"
        );
        let remaining = std::fs::read_dir(root.path())
            .expect("read temp root")
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("csq-fd-"))
            })
            .count();
        assert_eq!(remaining, 1, "the pass must stop at the bound");
    }
}
