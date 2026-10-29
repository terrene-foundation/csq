//! Shared waiter integration with synthetic owned children only.
//!
//! The previous real csq-login E2E could reach capture_login_prior and the
//! operator's macOS keychain before its vendor stub, despite sandbox HOME.
//! Enroll the actual shared waiter and its causal owned-child tests instead.
//! Auth argv/discovery, canonical commit and native Windows remain separate.
//! Canonical fixture namespace matches the binary unit module exactly.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

#[path = "common/mod.rs"]
mod common;
use common::csq_bin;

/// Unique argv marker carried by the stub's `sleep`, so a surviving hung
/// stub can be found with `pgrep -f` after a failed run.
const STUB_MARKER: &str = "120.0731";

/// The watchdog budget this test gives `csq login`.
///
/// The test's hermeticity proof — "the stub ran, and csq pointed it at
/// config-1" — is the stub's own first-action record write, so the budget MUST
/// leave room for kernel-scheduled startup before the watchdog can kill the
/// stub. At 1 s it lost that race under load: the 2026-10-21 sign-off leg found
/// every timeout assertion passing while the record file was absent (the
/// watchdog had killed the stub before its first instruction ran).
///
/// Sized from measurement with the repo's 10x rule: worst stub startup 468 ms
/// over 50 launches under 16 busy loops on a saturated darwin fleet host
/// (2026-10-22), so 10 s is 21x the measured worst and 10x the budget that
/// failed. The test deadline below (60 s) stays far above it.
const LOGIN_TIMEOUT_SECS: &str = "10";

/// Owns the spawned `csq` and its whole process group (csq, the fake
/// `claude`, its `sleep`). On drop — normal return, assertion panic, or the
/// deadline path — it SIGKILLs the group so a regressed watchdog can never
/// leave `sleep` orphaned. ESRCH (already gone) and EPERM (zombie group,
/// Darwin) are tolerated.
///
/// Ordering invariant: the group is signalled only while the leader is still
/// UNREAPED. An unreaped (zombie) leader pins its pid as the pgid, so
/// `killpg(pgid)` can only reach our group. Once the leader is reaped the
/// kernel may hand that pid (hence pgid) to an unrelated process group, so
/// `reaped` makes every later `kill_group` a no-op. Exit is therefore
/// detected with `waitid(WNOWAIT)` (observe, do not reap), never `try_wait`.
struct GroupGuard {
    child: Child,
    reaped: bool,
    /// Number of `killpg` syscalls actually issued (asserted by the ordering test).
    kills: u32,
    /// Whether the leader was still unreaped (waitid found it) at the moment
    /// of the last `killpg` — i.e. whether the pgid was still pinned to us.
    pinned_at_last_kill: bool,
}

impl GroupGuard {
    fn new(child: Child) -> Self {
        GroupGuard {
            child,
            reaped: false,
            kills: 0,
            pinned_at_last_kill: false,
        }
    }

    /// `waitid(WNOWAIT)` on the leader: `(rc, info)`. rc 0 = the child still
    /// exists (running or an unreaped zombie); rc -1 (ECHILD) = already reaped.
    fn peek(&self) -> (libc::c_int, libc::siginfo_t) {
        // SAFETY: `siginfo_t` is plain-old-data; all-zero is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid writes only into `info`, which outlives the call; the
        // id is our own direct child.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        (rc, info)
    }

    /// True once the leader has exited. Does NOT reap it: with `WNOWAIT` the
    /// zombie stays, so the pgid stays pinned to our group.
    fn exited_unreaped(&self) -> bool {
        let (rc, info) = self.peek();
        assert_eq!(
            rc,
            0,
            "waitid(WNOWAIT) failed: {}",
            std::io::Error::last_os_error()
        );
        // WNOHANG with nothing to report leaves the zeroed struct (si_signo 0);
        // an exited child reports SIGCHLD.
        info.si_signo == libc::SIGCHLD
    }

    /// Poll for exit. On exit: SIGKILL the group while the zombie still pins
    /// the pgid, THEN reap and return the status.
    fn poll_exit(&mut self) -> Option<std::process::ExitStatus> {
        if self.reaped || !self.exited_unreaped() {
            return None;
        }
        self.kill_group();
        let status = self.child.wait().expect("reap csq login");
        self.reaped = true;
        Some(status)
    }

    fn kill_group(&mut self) {
        if self.reaped {
            // The pgid may already belong to someone else.
            return;
        }
        let pgid = self.child.id() as libc::pid_t;
        self.kills += 1;
        self.pinned_at_last_kill = self.peek().0 == 0;
        // SAFETY: plain syscall on a pgid we created via `process_group(0)`
        // and whose leader is still unreaped (see the ordering invariant);
        // no memory is touched.
        let rc = unsafe { libc::killpg(pgid, libc::SIGKILL) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ESRCH) | Some(libc::EPERM) => {}
                _ => eprintln!("killpg({pgid}) failed unexpectedly: {err}"),
            }
        }
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill_group();
        if !self.reaped {
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

/// Write an executable fake `claude` at `<dir>/claude` that hangs on any
/// invocation — mimicking `claude auth login` stuck waiting for a browser
/// callback that never arrives.
///
/// It first records `$CLAUDE_CONFIG_DIR` to `record`, so a test can prove which config
/// directory csq pointed the subprocess at (the per-slot isolation `handle_direct` owes it).
fn write_hanging_claude(dir: &std::path::Path, record: &std::path::Path) {
    let path = dir.join("claude");
    // `exec sleep` so the script process BECOMES sleep (same PID) instead of
    // forking a child: the watchdog's `child.kill()` then terminates the actual
    // sleeping process, leaving no orphan holding the inherited stdout pipe open
    // (an orphan would hold the stdout pipe open past the child's exit).
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n# fake claude: record WHICH config dir csq chose as the very first\n# action, as one atomic append before any other work, then hang like a stuck\n# OAuth callback. The proof that the stub ran therefore depends only on the\n# stub having started, not on how long the watchdog waits.\nprintf '%s\\n' \"$CLAUDE_CONFIG_DIR\" >> '{0}'\nexec sleep {1}\n",
            record.display(),
            STUB_MARKER
        ),
    )
    .unwrap();
    let mut perm = std::fs::metadata(&path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&path, perm).unwrap();
}

#[test]
fn login_direct_times_out_on_hung_claude_auth_login() {
    let home = TempDir::new().unwrap();
    let base = home.path().join(".claude").join("accounts");
    std::fs::create_dir_all(&base).unwrap();
    let stub = TempDir::new().unwrap();
    let record = stub.path().join("config-dir.txt");
    write_hanging_claude(stub.path(), &record);

    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    common::strip_ci_env(&mut cmd);
    cmd.env("HOME", home.path());
    // CSQ_HOME: `dirs::home_dir()` ignores `HOME` on Windows; the
    // test-utils-gated override is what actually sandboxes it there.
    cmd.env("CSQ_HOME", home.path());
    cmd.env("CSQ_BASE_DIR", &base);
    // Never shell `security` against the operator's real login keychain.
    cmd.env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1");
    // Sized from the stub's measured worst startup (see LOGIN_TIMEOUT_SECS);
    // the production default is 300s.
    cmd.env("CSQ_LOGIN_TIMEOUT_SECS", LOGIN_TIMEOUT_SECS);
    // This test drives `csq login` against a HUNG stub `claude` binary to prove
    // the subprocess timeout fires. `csq login` gained a an internal ticket drivability guard
    // that refuses claude (flow=browser_subprocess) when stdin is not a TTY —
    // correct in production, but here it would refuse before ever spawning the
    // stub, so the timeout path under test would never be reached.
    //
    // `CSQ_TEST_BYPASS_TTY` is the repo's existing mechanism for exactly this
    // (`cli.rs::check_test_bypass`), compiled OUT of production builds, so it
    // cannot weaken the guard for a real user.
    cmd.env("CSQ_TEST_BYPASS_TTY", "1");
    // PATH = stub dir FIRST → find_claude_binary (PATH-first) selects the
    // hanging fake, never the real `claude`. The standard bin dirs follow so
    // the stub's `/bin/sh` can resolve `sleep` (real `claude` is not in these).
    cmd.env("PATH", format!("{}:/usr/bin:/bin", stub.path().display()));
    for k in &["LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    cmd.args(["login", "1"]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Own process group: the guard can SIGKILL csq + the fake claude + its
    // `sleep` together on the deadline or any panic path.
    cmd.process_group(0);

    let start = Instant::now();
    let mut guard = GroupGuard::new(cmd.spawn().expect("spawn csq login"));
    // Drain the pipes on threads so a chatty child can never block on a full
    // pipe while this thread polls `try_wait`.
    let mut so = guard.child.stdout.take().unwrap();
    let mut se = guard.child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut so, &mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut se, &mut b);
        b
    });

    // The watchdog (LOGIN_TIMEOUT_SECS) must terminate the hung child; the
    // command must finish far short of the fake's 120s sleep. A hard 60s
    // deadline bounds the test; generous slack for CI/build load.
    let deadline = Duration::from_secs(60);
    let status = loop {
        if let Some(st) = guard.poll_exit() {
            break st;
        }
        if start.elapsed() >= deadline {
            // Kill the group now (also what Drop does) so the reader threads
            // reach EOF, then fail loudly.
            drop(guard);
            let _ = t_out.join();
            let _ = t_err.join();
            panic!("login did not time out within {deadline:?} (watchdog never fired)");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let elapsed = start.elapsed();
    // csq has exited and `poll_exit` already SIGKILLed any straggler in its
    // group (before reaping), so the reader threads reach EOF.
    let out = std::process::Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    };
    assert!(
        elapsed < deadline,
        "login took {elapsed:?}, past the {deadline:?} deadline"
    );
    assert!(
        !out.status.success(),
        "expected non-zero exit when the login subprocess is killed by the watchdog"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("did not complete within") || stderr.contains("was terminated"),
        "expected an actionable timeout message; got stderr:\n{stderr}"
    );

    // The vendor must run inside THIS login's private grant home — never the
    // caller's dir and never the slot's canonical config dir (which stays
    // untouched until a verified publication).
    let recorded = std::fs::read_to_string(&record).expect("the stub claude must have run");
    // The stub appends one terminated line per invocation; the FIRST line is
    // the one this login made. Taking the line (not the raw file) keeps the
    // record a bare path, so the append terminator can never become part of it.
    let recorded = recorded.lines().next().unwrap_or_default();
    // The recorded path is already canonical (the grant home is built from the
    // canonical base), and canonicalizing it here would panic if a refused
    // publication had since retained-then-swept the home.
    let recorded_dir = std::path::Path::new(recorded);
    let grants_root = std::fs::canonicalize(base.join(".login-grants")).unwrap();
    assert!(
        recorded_dir.starts_with(&grants_root)
            && recorded_dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("grant-")),
        "claude auth login must run in this login's private grant home, got {}",
        recorded_dir.display()
    );
    assert!(
        !base.join("config-1").exists(),
        "the vendor must never write into the slot's canonical config dir"
    );

    // The lock must be released on return (guard drop). A second attempt must
    // not report the slot as still-locked by the timed-out process.
    let lock_pid = base.join(".login-1.lock.pid");
    if lock_pid.exists() {
        let pid_txt = std::fs::read_to_string(&lock_pid).unwrap_or_default();
        if let Ok(pid) = pid_txt.trim().parse::<i32>() {
            // The holder PID (if any sidecar lingers) must not be alive.
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            assert!(
                !alive,
                "timed-out login left a live lock holder (PID {pid})"
            );
        }
    }
}

/// Ordering guard for `GroupGuard`: the group is killed while the exited
/// leader is still an unreaped zombie, and never again once it is reaped
/// (a reused pgid could belong to an unrelated group).
#[test]
fn group_guard_kills_before_reaping_and_never_after() {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "exit 0"]).process_group(0);
    let mut guard = GroupGuard::new(cmd.spawn().expect("spawn sh"));

    // Observe exit WITHOUT reaping: the child is still reapable afterwards.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !guard.exited_unreaped() {
        assert!(Instant::now() < deadline, "sh never exited");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!guard.reaped, "exit detection must not reap the leader");
    assert_eq!(guard.kills, 0);

    let status = guard.poll_exit().expect("exited leader must be reported");
    assert!(status.success());
    assert!(guard.reaped);
    assert_eq!(
        guard.kills, 1,
        "poll_exit must killpg exactly once, before the reap"
    );
    assert!(
        guard.pinned_at_last_kill,
        "killpg ran AFTER the leader was reaped: the pgid was no longer pinned"
    );

    // After the reap neither an explicit kill nor Drop may signal the pgid.
    guard.kill_group();
    assert_eq!(guard.kills, 1, "kill_group after the reap must be a no-op");
    assert!(guard.poll_exit().is_none());
    assert_eq!(guard.kills, 1);
}
#[path = "../src/login_child_custody.rs"]
mod login_child_custody;
// The custody module's tty tests are compiled into every crate that includes
// it (`#[cfg(all(test, unix))]` inside login_child_custody.rs) and name
// `crate::login_cancel_guard` at the crate root. The two sibling integration
// crates include that module too; this one included only the custody half, so
// the tty tests failed to resolve it (E0433). Nothing here calls the guard
// directly, hence the allow.
#[allow(dead_code)]
#[path = "../src/login_cancel_guard.rs"]
mod login_cancel_guard;
