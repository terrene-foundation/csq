//! Integration test: `csq login N` (direct Anthropic path, `handle_direct`)
//! applies a watchdog timeout to the `claude auth login` subprocess, so a hung
//! OAuth callback surfaces as an actionable error instead of blocking the login
//! (and its per-slot lock) forever.
//!
//! Regression guard for the 2026-07-24 production incident: `csq login 6`'s
//! `claude auth login` child hung on a 404'd OAuth callback, held `.login-6.lock`
//! indefinitely (a live-but-hung flock holder is never auto-reclaimed), and
//! blocked desktop re-auth.
//!
//! Determinism + safety: `find_claude_binary` is PATH-first
//! (`csq-core/src/accounts/login.rs:51`), so an `env_clear()` + `PATH=<stub-dir>`
//! guarantees the fake hanging `claude` is selected — the real binary is never
//! spawned (no browser), and the test is identical on macOS + Linux CI.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn csq_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_csq") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("csq")
}

/// Write an executable fake `claude` at `<dir>/claude` that hangs on any
/// invocation — mimicking `claude auth login` stuck waiting for a browser
/// callback that never arrives.
fn write_hanging_claude(dir: &std::path::Path) {
    let path = dir.join("claude");
    // `exec sleep` so the script process BECOMES sleep (same PID) instead of
    // forking a child: the watchdog's `child.kill()` then terminates the actual
    // sleeping process, leaving no orphan holding the inherited stdout pipe open
    // (an orphan would block the test's `cmd.output()` on pipe-EOF).
    std::fs::write(
        &path,
        "#!/bin/sh\n# fake claude: hang like a stuck OAuth callback\nexec sleep 600\n",
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
    write_hanging_claude(stub.path());

    let mut cmd = Command::new(csq_bin());
    cmd.env_clear();
    cmd.env("HOME", home.path());
    cmd.env("CSQ_BASE_DIR", &base);
    // Never shell `security` against the operator's real login keychain.
    cmd.env("CSQ_DISABLE_KEYCHAIN_MIRROR", "1");
    // Watchdog fires fast so the test is quick; the production default is 300s.
    cmd.env("CSQ_LOGIN_TIMEOUT_SECS", "1");
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

    let start = Instant::now();
    let out = cmd.output().expect("spawn csq login");
    let elapsed = start.elapsed();

    // The watchdog (1s) must terminate the hung child; the command must finish
    // far short of the fake's 600s sleep. Generous slack for CI/build load.
    assert!(
        elapsed < Duration::from_secs(60),
        "login did not time out — it hung for {elapsed:?} (watchdog never fired)"
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
