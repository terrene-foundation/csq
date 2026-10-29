// Real controlling-terminal tests for the attended login foreground handoff
// (an internal ticket). The test binary re-executes itself as a session leader whose
// controlling terminal is a fresh pty, so `group::spawn_attended` sees the same
// shape as `csq login N` typed in a terminal. No vendor, network or keychain.
use super::group;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ROLE: &str = "CSQ_PRIVATE_TTY_ROLE";
const ENTRY: &str = "login_child_custody::tty_tests::tty_session_entry";

fn open_pty() -> (libc::c_int, libc::c_int) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: valid out-pointers; the other arguments may be null.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    // Neither end may leak into any other child of the test binary; the helper
    // gets its slave through dup2 (which clears the flag on fd 0).
    for fd in [master, slave] {
        // SAFETY: fds just created by openpty.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    (master, slave)
}

/// Run the entry below as a session leader owning a pty; returns its exit
/// code and stdout. Keeps the master open for the helper's whole life.
fn run_in_pty_session(role: &str) -> (Option<i32>, String) {
    let (master, slave) = open_pty();
    let exe = std::env::current_exe().expect("test binary");
    let mut command = Command::new(exe);
    command
        .args([
            "--ignored",
            "--exact",
            ENTRY,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, role)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(slave, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn pty session helper");
    // SAFETY: the parent no longer needs its slave copy.
    unsafe { libc::close(slave) };
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll helper") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut output = String::new();
    {
        use std::io::Read;
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut output);
        }
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_string(&mut output);
        }
    }
    // SAFETY: closing the master we own.
    unsafe { libc::close(master) };
    (status.and_then(|s| s.code()), output)
}

/// Every role must print its sentinel, so a renamed, filtered or empty entry
/// cannot pass as a green: the exit code alone is not evidence it ran.
fn assert_role(role: &str) {
    let (code, output) = run_in_pty_session(role);
    assert_eq!(code, Some(0), "TTY_{role}: {output}");
    assert!(
        output.contains(&format!("TTY_SENTINEL role={role} ok")),
        "TTY_{role} sentinel missing (entry did not run?): {output}"
    );
}

#[test]
fn attended_vendor_keeps_running_and_terminal_returns_to_csq() {
    assert_role("fg");
}

#[test]
fn unattended_spawn_leaves_the_terminal_alone() {
    // Control: the plain `spawn` (desktop shape) must NOT take the terminal, so
    // a tty-touching vendor is stopped there. Proves the pty harness makes
    // SIGTTOU real, which is what gives the test above its discriminating power.
    assert_role("plain");
}

#[test]
fn leaked_unresolved_custody_still_returns_the_terminal() {
    assert_role("unresolved");
}

#[test]
fn suspended_vendor_is_cancelled_and_terminal_returns() {
    assert_role("suspend");
}

#[test]
fn killed_raw_mode_vendor_leaves_terminal_modes_restored() {
    assert_role("raw");
}

#[test]
fn stopped_non_leader_member_is_cancelled_and_terminal_returns() {
    assert_role("member_stop");
}

#[test]
fn dropping_custody_of_a_stopped_vendor_returns_the_terminal() {
    assert_role("drop_stop");
}

#[test]
fn sigttou_is_default_in_the_vendor_and_restored_in_csq() {
    assert_role("ttou");
}

#[test]
fn cli_suspend_prints_the_message_and_exits_130() {
    let (code, output) = run_in_pty_session("cli_suspend");
    assert_eq!(code, Some(0), "TTY_cli_suspend: {output}");
    assert!(
        output.contains("login cancelled (suspended)"),
        "suspended message missing: {output}"
    );
    assert!(
        output.contains("TTY_SENTINEL role=cli_suspend ok"),
        "{output}"
    );
}

#[test]
fn vendor_sigint_reports_login_cancelled_exit_130() {
    assert_role("sigint");
}

fn stopped(pid: u32) -> bool {
    // SAFETY: zeroed siginfo; WNOWAIT leaves the child's status to its owner.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let rc = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
        );
        if rc != 0 {
            return false;
        }
        #[cfg(target_os = "linux")]
        let observed = info.si_pid();
        #[cfg(target_os = "macos")]
        let observed = info.si_pid;
        observed == pid as libc::pid_t
    }
}

fn done(role: &str) -> ! {
    println!("TTY_SENTINEL role={role} ok");
    std::process::exit(0);
}

fn termios_of(fd: libc::c_int) -> libc::termios {
    // SAFETY: zeroed termios filled by tcgetattr on a live tty fd.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(fd, &mut t), 0, "tcgetattr");
        t
    }
}

/// The fixture's shell, pinned so it cannot depend on process-global state.
///
/// `cli::commands::login::native_same_slot_concurrent_login_refuses_before_probe`
/// points PATH at a private temp dir holding only a `kimi` probe, for the whole
/// length of its run. It takes `test_env::lock()`, but this module never takes
/// that lock, so while the two overlap a bare `Command::new("sh")` resolves
/// against a PATH with no `sh` in it and the spawn fails with ENOENT (an internal ticket:
/// the same panic on this role and on leaked_unresolved_custody). The absolute
/// interpreter and the pinned PATH also keep `stty` and `sleep` resolvable
/// inside the scripts below, so a clobbered PATH cannot turn a role into a
/// spurious RAW_NOT_EXERCISED either.
fn sh(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", script])
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn ttou_disposition() -> libc::sighandler_t {
    // SAFETY: query only (null new action).
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGTTOU, std::ptr::null(), &mut old);
        old.sa_sigaction
    }
}

fn fg_is(pgrp: libc::pid_t) -> bool {
    // SAFETY: query only.
    unsafe { libc::tcgetpgrp(0) == pgrp }
}

#[test]
#[ignore = "private subprocess dispatcher"]
fn tty_session_entry() {
    use super::{LoginWatchdog, OwnedLoginChild, RefusalReason};
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let role = role.to_str().expect("role").to_owned();
    // SAFETY: queries on this process's own controlling terminal.
    let own = unsafe { libc::getpgrp() };
    assert!(fg_is(own), "session starts foreground");
    let before = termios_of(0);
    // csq's own SIGTTOU disposition at entry: the custody must put back exactly this.
    let ttou_at_entry = ttou_disposition();
    let owned_run = |script: &str, secs: u64, census: Option<group::GroupCensus>| {
        let mut command = sh(script);
        let (child, group) = group::spawn_attended(&mut command).expect("spawn vendor");
        let watchdog = LoginWatchdog::new(Duration::from_secs(secs), super::DeliveryPhase::Unknown);
        let mut owner = OwnedLoginChild::adopt_group(child, group.clone(), watchdog, ());
        group::inject_census_for_test(census);
        let started = Instant::now();
        let graceful_group = group.clone();
        let result = owner.wait_vendor_cancelled(
            || Ok(true),
            |_| {},
            move || graceful_group.signal(group::GroupSignal::Kill),
            || false,
        );
        group::inject_census_for_test(None);
        (owner, result, started.elapsed())
    };
    match role.as_str() {
        "unresolved" => {
            // The leader exits, the census keeps refusing: custody ends
            // UNRESOLVED and Drop deliberately leaks the group handle.
            let survivor = Some(group::GroupCensus::Survivor(vec![1]));
            let (owner, result, _) = owned_run("exit 0", 30, survivor);
            assert!(result.is_err(), "census must refuse");
            assert!(owner.watchdog.custody_unresolved(), "unresolved branch");
            drop(owner);
            if !fg_is(own) {
                println!("FOREGROUND_LEAKED");
                std::process::exit(7);
            }
            done("unresolved")
        }
        "suspend" => {
            let (owner, result, elapsed) = owned_run("kill -STOP $$; sleep 20", 20, None);
            let reason = result.as_ref().err().map(|r| r.reason);
            if elapsed > Duration::from_secs(8) || reason != Some(RefusalReason::Cancelled) {
                println!("NOT_CANCELLED reason={reason:?} elapsed={elapsed:?}");
                std::process::exit(8);
            }
            if !fg_is(own) || !owner.custody_finalized() {
                println!("NOT_RESTORED_OR_NOT_FINALIZED");
                std::process::exit(9);
            }
            done("suspend")
        }
        "raw" => {
            // Private mktemp dir: no predictable /tmp path for a symlink to hijack.
            let marker_dir = tempfile::tempdir().expect("private marker dir");
            let marker = marker_dir.path().join("raw-ok");
            let script = format!(
                "stty raw -echo && echo raw-ok > {}; kill -KILL $$",
                marker.display()
            );
            let (_owner, _result, elapsed) = owned_run(&script, 20, None);
            let took_effect = std::fs::read_to_string(&marker).is_ok_and(|m| m.trim() == "raw-ok");
            drop(marker_dir);
            if !took_effect || elapsed > Duration::from_secs(8) {
                // Without this the restore assertion below could pass vacuously.
                println!("RAW_NOT_EXERCISED took_effect={took_effect} elapsed={elapsed:?}");
                std::process::exit(12);
            }
            let after = termios_of(0);
            // PENDIN is kernel bookkeeping set when ICANON toggles, not a mode.
            let mask = !(libc::PENDIN as libc::tcflag_t);
            let same = before.c_lflag & mask == after.c_lflag & mask
                && before.c_iflag == after.c_iflag
                && before.c_oflag == after.c_oflag
                && before.c_cc == after.c_cc;
            println!(
                "TERMIOS before(l={:#x} i={:#x} o={:#x}) after(l={:#x} i={:#x} o={:#x})",
                before.c_lflag,
                before.c_iflag,
                before.c_oflag,
                after.c_lflag,
                after.c_iflag,
                after.c_oflag
            );
            if !same || !fg_is(own) {
                println!("TERMIOS_OR_FOREGROUND_NOT_RESTORED same={same}");
                std::process::exit(10);
            }
            done("raw")
        }
        "member_stop" => {
            // The leader keeps running; a NON-leader member of its group stops ITSELF
            // (kill -STOP on a just-forked `$!` was observed lost on macOS: the child
            // stayed S+ in ps, so the stop never happened).
            let (owner, result, elapsed) = owned_run("sh -c 'kill -STOP $$' & wait", 20, None);
            let reason = result.as_ref().err().map(|r| r.reason);
            if elapsed > Duration::from_secs(8) || reason != Some(RefusalReason::Cancelled) {
                println!("MEMBER_STOP_NOT_CANCELLED reason={reason:?} elapsed={elapsed:?}");
                std::process::exit(13);
            }
            if !fg_is(own) || !owner.custody_finalized() {
                println!("NOT_RESTORED_OR_NOT_FINALIZED");
                std::process::exit(9);
            }
            done("member_stop")
        }
        "drop_stop" => {
            let mut command = sh("kill -STOP $$; sleep 20");
            let (child, group) = group::spawn_attended(&mut command).expect("spawn vendor");
            let watchdog =
                LoginWatchdog::new(Duration::from_secs(20), super::DeliveryPhase::Unknown);
            let owner = OwnedLoginChild::adopt_group(child, group, watchdog, ());
            let started = Instant::now();
            drop(owner); // Drop's own wait loop must notice the stop.
            if started.elapsed() > Duration::from_secs(8) || !fg_is(own) {
                println!("DROP_STOP_NOT_HANDLED elapsed={:?}", started.elapsed());
                std::process::exit(14);
            }
            done("drop_stop")
        }
        "ttou" => {
            // A vendor that inherited csq's SIG_IGN would survive this self-signal;
            // one with the default disposition is stopped (and then cancelled).
            let (_owner, result, elapsed) = owned_run("kill -TTOU $$", 20, None);
            let reason = result.as_ref().err().map(|r| r.reason);
            let csq_default = ttou_disposition() == ttou_at_entry;
            if reason != Some(RefusalReason::Cancelled)
                || elapsed > Duration::from_secs(8)
                || !csq_default
            {
                println!("TTOU reason={reason:?} csq_default={csq_default}");
                std::process::exit(15);
            }
            done("ttou")
        }
        "cli_suspend" => {
            let mut command = sh("kill -STOP $$; sleep 20");
            let error = crate::login_cancel_guard::spawn_cli_login(
                &mut command,
                Duration::from_secs(20),
                (),
                |_| {},
            )
            .expect_err("a suspended vendor is a cancelled login");
            let code = crate::login_cancel_guard::cli_error_exit_code(&error);
            if code != 130 || !fg_is(own) {
                println!("CLI_SUSPEND code={code}");
                std::process::exit(16);
            }
            done("cli_suspend")
        }
        "sigint" => {
            let mut command = sh("kill -INT $$");
            let error = crate::login_cancel_guard::spawn_cli_login(
                &mut command,
                Duration::from_secs(20),
                (),
                |_| {},
            )
            .expect_err("a vendor killed by SIGINT must not read as a login result");
            let code = crate::login_cancel_guard::cli_error_exit_code(&error);
            let cancelled = error
                .downcast_ref::<crate::login_cancel_guard::CliLoginCancelled>()
                .is_some()
                || error.chain().any(|c| {
                    c.downcast_ref::<crate::login_cancel_guard::CliLoginCancelled>()
                        .is_some()
                });
            if code != 130 || !cancelled || !fg_is(own) {
                println!("SIGINT_NOT_CANCELLED code={code} cancelled={cancelled}");
                std::process::exit(11);
            }
            done("sigint")
        }
        _ => {}
    }
    let attended = role == "fg";
    let mut command = sh("stty -echo; exit 0");
    let (mut child, group) = if attended {
        group::spawn_attended(&mut command)
    } else {
        group::spawn(&mut command)
    }
    .expect("spawn vendor stand-in");
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if stopped(pid) {
            // Report the stop, then kill the whole stand-in group so it cannot linger.
            let _ = group.signal(group::GroupSignal::Kill);
            let _ = child.wait();
            if attended {
                println!("STOPPED_BY_SIGTTOU");
                std::process::exit(2);
            }
            // plain spawn: the stop is the expected (bug-shaped) outcome.
            done("plain");
        }
        match group.try_reap(&mut child, true) {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                println!("REAP_ERROR {error}");
                std::process::exit(4);
            }
        }
        if Instant::now() >= deadline {
            let _ = group.signal(group::GroupSignal::Kill);
            println!("TIMEOUT");
            std::process::exit(5);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !attended {
        println!("plain spawn was not stopped; harness cannot show SIGTTOU");
        std::process::exit(6);
    }
    if !status.success() {
        println!("VENDOR_STATUS {status:?}");
        std::process::exit(3);
    }
    // SAFETY: query only.
    let fg = unsafe { libc::tcgetpgrp(0) };
    if fg != own {
        println!("FOREGROUND_NOT_RESTORED fg={fg} own={own}");
        std::process::exit(7);
    }
    done("fg")
}
