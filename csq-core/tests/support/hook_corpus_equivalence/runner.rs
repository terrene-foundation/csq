//! This runner captures a declared verdict protocol. It is NOT a filesystem,
//! network, spawn-attempt observer or an OS sandbox; only trusted corpora may run.
use super::model::*;
use std::{fs, path::Path};

pub fn run(corpus: &Corpus, digest: &str, root: &Path, invocation: &str) -> Result<Report, String> {
    validate(corpus)?;
    let snapshot = tempfile::TempDir::new().map_err(|_| "snapshot_dir")?;
    let mut closure_bytes = 0;
    // Freeze the owner-declared closure before either arm runs. No dependency discovery claim.
    for binding in &corpus.files {
        let source = root.join(&binding.path);
        let resolved = source.canonicalize().map_err(|_| "binding_missing")?;
        if !resolved.starts_with(root.canonicalize().map_err(|_| "corpus_root")?) {
            return Err("binding_outside_corpus".into());
        }
        let bytes = read_bounded(&resolved, MAX_MANIFEST)?;
        closure_bytes += bytes.len();
        if closure_bytes > 64 * 1024 * 1024 {
            return Err("closure_limit".into());
        }
        if hash(&bytes) != binding.sha256 {
            return Err("binding_pin_mismatch".into());
        }
        let destination = snapshot.path().join(&binding.path);
        fs::create_dir_all(destination.parent().ok_or("binding_parent")?)
            .map_err(|_| "snapshot_write")?;
        fs::write(destination, bytes).map_err(|_| "snapshot_write")?;
    }
    let required = corpus.cases.len();
    let supported = cfg!(any(target_os = "linux", target_os = "macos"))
        && corpus.profile == "verdict_output_v1";
    let mut report = Report {
        instrument_sha256: hash(
            &[
                include_bytes!("model.rs").as_slice(),
                include_bytes!("runner.rs").as_slice(),
                include_bytes!("strict_json.rs").as_slice(),
            ]
            .concat(),
        ),
        corpus_sha256: digest.into(),
        source_revision: corpus.source_revision.clone(),
        release: corpus.release.clone(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        invocation: invocation.into(),
        scope: "verdict/output oracle; effects and native activation unqualified".into(),
        required_cases: required,
        attempted_cases: 0,
        completed_cases: 0,
        unsupported_cases: if supported { 0 } else { required },
        planned_invocations: required * 2,
        attempted_invocations: 0,
        spawned_invocations: 0,
        oracle_conformant_cases: 0,
        differential_matched_cases: 0,
        protocol_equivalent: false,
        full_corpus_qualified: false,
        pairs: vec![],
    };
    if !supported {
        return Ok(report);
    }
    for case in &corpus.cases {
        let standalone = execute(&case.standalone, case, snapshot.path(), &corpus.files);
        let dispatched = execute(&case.dispatched, case, snapshot.path(), &corpus.files);
        let oracle = standalone.matches(&case.expected) && dispatched.matches(&case.expected);
        let differential = standalone.same(&dispatched);
        report.attempted_cases += 1;
        report.attempted_invocations += 2;
        report.spawned_invocations +=
            usize::from(standalone.spawned) + usize::from(dispatched.spawned);
        report.completed_cases +=
            usize::from(standalone.problem.is_none() && dispatched.problem.is_none());
        report.oracle_conformant_cases += usize::from(oracle);
        report.differential_matched_cases += usize::from(differential);
        report.pairs.push(Pair {
            id: case.id.clone(),
            standalone,
            dispatched,
            oracle_conformant: oracle,
            differential_matched: differential,
        });
    }
    report.protocol_equivalent = report.unsupported_cases == 0
        && report.completed_cases == required
        && report.oracle_conformant_cases == required
        && report.differential_matched_cases == required;
    Ok(report)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn execute(_: &Arm, _: &Case, _: &Path, _: &[Binding]) -> Captured {
    unreachable!("unsupported profiles never execute")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn execute(arm: &Arm, case: &Case, corpus_root: &Path, bindings: &[Binding]) -> Captured {
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let start = Instant::now();
    let cleanup = std::rc::Rc::new(std::cell::RefCell::new(Cleanup::default()));
    let mut capture = Captured {
        spawned: false,
        forced_cleanup: false,
        cleanup_unknown: false,
        direct_pid_signal: false,
        exit_code: None,
        stdout: vec![],
        stderr: vec![],
        elapsed_ms: 0,
        problem: None,
    };
    let result = (|| -> Result<(), String> {
        // Verify the actual executable immediately before spawning. This is not fd-exec attestation.
        if hash(&read_bounded(Path::new(&arm.program), 128 * 1024 * 1024)?) != arm.program_sha256 {
            return Err("program_pin_mismatch".into());
        }
        let fixture = tempfile::TempDir::new().map_err(|_| "fixture_dir")?;
        let fixture_root = fixture.path().canonicalize().map_err(|_| "fixture_root")?;
        for directory in [
            "home",
            "base",
            "tmp",
            "cwd",
            "config",
            "corpus",
            "empty-path",
        ] {
            fs::create_dir(fixture_root.join(directory)).map_err(|_| "fixture_setup")?;
        }
        // Each arm gets exact bytes even if its sibling mutates a script or library.
        let arm_corpus = fixture_root.join("corpus");
        for binding in bindings {
            let bytes = read_bounded(&corpus_root.join(&binding.path), MAX_MANIFEST)?;
            if hash(&bytes) != binding.sha256 {
                return Err("snapshot_pin_mismatch".into());
            }
            let target = arm_corpus.join(&binding.path);
            fs::create_dir_all(target.parent().ok_or("fixture_parent")?)
                .map_err(|_| "fixture_setup")?;
            fs::write(target, bytes).map_err(|_| "fixture_setup")?;
        }
        for (path, content) in &case.initial_files {
            let target = fixture_root.join("cwd").join(path);
            fs::create_dir_all(target.parent().ok_or("fixture_parent")?)
                .map_err(|_| "fixture_setup")?;
            fs::write(target, content).map_err(|_| "fixture_setup")?;
        }
        let mut command = Command::new(&arm.program);
        command
            .env_clear()
            .env("HOME", fixture_root.join("home"))
            .env("CSQ_BASE_DIR", fixture_root.join("base"))
            .env("TMPDIR", fixture_root.join("tmp"))
            .env("CLAUDE_CONFIG_DIR", fixture_root.join("config"))
            .env("XDG_CONFIG_HOME", fixture_root.join("config"))
            .env("PATH", fixture_root.join("empty-path"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir(fixture_root.join("cwd"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        for argument in &arm.args {
            command.arg(
                argument
                    .replace("${CORPUS_ROOT}", &arm_corpus.to_string_lossy())
                    .replace("${CASE_ROOT}", &fixture_root.to_string_lossy()),
            );
        }
        let child = command.spawn().map_err(|_| "spawn_failed")?;
        capture.spawned = true;
        let mut child = Reap(child, false, cleanup.clone());
        let mut stdin = child.0.stdin.take();
        let mut stdout = child.0.stdout.take().ok_or("stdout_missing")?;
        let mut stderr = child.0.stderr.take().ok_or("stderr_missing")?;
        for fd in [
            stdin.as_ref().ok_or("stdin_missing")?.as_raw_fd(),
            stdout.as_raw_fd(),
            stderr.as_raw_fd(),
        ] {
            // SAFETY: these descriptors are owned and live until capture completes.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err("nonblocking_failed".into());
            }
        }
        let deadline = Instant::now() + Duration::from_millis(case.timeout_ms);
        let mut written = 0;
        let mut out_eof = false;
        let mut err_eof = false;
        let mut exited = false;
        loop {
            if let Some(pipe) = stdin.as_mut() {
                match pipe.write(&case.stdin.as_bytes()[written..]) {
                    Ok(count) => written += count,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(_) => return Err("stdin_failed".into()),
                }
                if written == case.stdin.len() {
                    stdin.take();
                }
            }
            drain(&mut stdout, &mut capture.stdout, &mut out_eof)?;
            drain(&mut stderr, &mut capture.stderr, &mut err_eof)?;
            if !exited {
                exited = child.exited_unreaped()?;
            }
            if exited {
                // EOF may have become visible between the first drain and waitid.
                drain(&mut stdout, &mut capture.stdout, &mut out_eof)?;
                drain(&mut stderr, &mut capture.stderr, &mut err_eof)?;
            }
            if exited && out_eof && err_eof {
                capture.exit_code = child.reap()?.code();
                if written != case.stdin.len() {
                    return Err("stdin_incomplete".into());
                }
                return Ok(());
            }
            if exited {
                // Leader identity is retained until signaling; inherited pipes require
                // forced cleanup and therefore cannot be reported as normal completion.
                child.signal_owned()?;
                capture.exit_code = child.reap()?.code();
                return Err("forced_cleanup".into());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("timeout".into());
            }
            let mut fds = [
                libc::pollfd {
                    fd: if out_eof { -1 } else { stdout.as_raw_fd() },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if err_eof { -1 } else { stderr.as_raw_fd() },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stdin.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    events: libc::POLLOUT,
                    revents: 0,
                },
            ];
            // SAFETY: the fd array is valid for this bounded syscall. This is IO supervision, not a test sleep.
            if unsafe {
                libc::poll(
                    fds.as_mut_ptr(),
                    fds.len() as libc::nfds_t,
                    remaining.as_millis().clamp(1, 20) as i32,
                )
            } < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return Err("poll_failed".into());
            }
        }
    })();
    capture.elapsed_ms = start.elapsed().as_millis();
    capture.forced_cleanup = cleanup.borrow().requested;
    capture.cleanup_unknown = cleanup.borrow().unknown;
    capture.direct_pid_signal = cleanup.borrow().direct_pid_signal;
    capture.problem = if capture.cleanup_unknown {
        Some("cleanup_unknown".into())
    } else {
        result.err()
    };
    capture
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn drain(pipe: &mut impl std::io::Read, bytes: &mut Vec<u8>, eof: &mut bool) -> Result<(), String> {
    let mut buffer = [0; 1024];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => {
                *eof = true;
                return Ok(());
            }
            Ok(count) => {
                if bytes.len() + count > MAX_BYTES {
                    return Err("output_limit".into());
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(_) => return Err("capture_failed".into()),
        }
    }
}

/// Whether a failed `kill(-pgid, SIGKILL)` means the group has nothing left to
/// kill. `ESRCH` is the portable answer. macOS also answers `EPERM` when the
/// only members left are exited, unreaped zombies; but it answers `EPERM` too
/// when a live member belongs to another uid (the group had members and none
/// could be signalled). So `EPERM` counts as gone only after `ps` shows every
/// member of the group a zombie; a failed or unparsable `ps` is "not known to
/// be gone".
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_already_gone(errno: Option<i32>, pgid: i32) -> bool {
    errno == Some(libc::ESRCH)
        || (cfg!(target_os = "macos") && errno == Some(libc::EPERM) && group_all_zombies(pgid))
}

/// How long the process listing behind [`group_all_zombies`] may take.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const PS_LISTING_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The standard output of `cmd` when it exits successfully within `limit`;
/// `None` otherwise (a run that does not finish is killed and reaped). The
/// read happens in a thread so a wedged listing can never block the caller.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn output_within(mut cmd: std::process::Command, limit: std::time::Duration) -> Option<String> {
    use std::io::Read;
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = tx.send(stdout.read_to_string(&mut text).ok().map(|_| text));
    });
    let text = match rx.recv_timeout(limit) {
        Ok(Some(text)) => text,
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return None;
        }
    };
    let _ = reader.join();
    let status = child.wait().ok()?;
    status.success().then_some(text)
}

/// Whether `ps -A -o pgid=,stat=` shows every member of `pgid` a zombie. A
/// listing that fails or does not finish in time is "no": the group is not
/// proven gone.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_all_zombies(pgid: i32) -> bool {
    let mut c = std::process::Command::new("ps");
    c.args(["-A", "-o", "pgid=,stat="]);
    output_within(c, PS_LISTING_LIMIT).is_some_and(|text| all_members_zombie(&text, pgid))
}

/// The parse behind [`group_all_zombies`]: every `pgid stat` row of `pgid`
/// has a state starting with `Z`. A malformed row of the group fails closed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn all_members_zombie(ps_output: &str, pgid: i32) -> bool {
    for line in ps_output.lines() {
        let mut it = line.split_whitespace();
        let (Some(g), Some(stat)) = (it.next(), it.next()) else {
            continue;
        };
        if g.parse::<i32>().ok() == Some(pgid) && !stat.starts_with('Z') {
            return false;
        }
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct Cleanup {
    requested: bool,
    unknown: bool,
    direct_pid_signal: bool,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Reap(
    std::process::Child,
    bool,
    std::rc::Rc<std::cell::RefCell<Cleanup>>,
);
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Reap {
    fn exited_unreaped(&self) -> Result<bool, String> {
        if self.1 {
            return Err("identity_already_reaped".into());
        }
        // SAFETY: zero is valid initial siginfo storage; waitid targets our own
        // direct child and WNOWAIT retains the PID even after observing its exit.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        for _ in 0..16 {
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.0.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0
            {
                return Ok(unsafe { info.si_pid() } != 0);
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err("owned_child_identity_unavailable".into());
            }
        }
        Err("waitid_interrupted_limit".into())
    }
    fn signal_owned(&mut self) -> Result<(), String> {
        if self.1 {
            return Err("identity_already_reaped".into());
        }
        // Fail closed on lost identity (e.g. ECHILD); never signal a recycled PGID.
        self.exited_unreaped()?;
        self.2.borrow_mut().requested = true;
        // SAFETY: this fresh process-group leader is still our unreaped child.
        let group_signal = unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        if group_signal < 0
            && !group_already_gone(
                std::io::Error::last_os_error().raw_os_error(),
                self.0.id() as i32,
            )
        {
            self.2.borrow_mut().unknown = true;
        }
        // Direct child may have changed groups. Independently verify unreaped
        // identity before signaling only its PID; never signal its new group.
        self.exited_unreaped()?;
        self.2.borrow_mut().direct_pid_signal = true;
        if unsafe { libc::kill(self.0.id() as i32, libc::SIGKILL) } < 0 {
            return Err("direct_signal_failed".into());
        }
        Ok(())
    }
    fn reap(&mut self) -> Result<std::process::ExitStatus, String> {
        if !self.exited_unreaped()? {
            return Err("child_still_running".into());
        }
        let status = self.0.wait().map_err(|_| "wait_failed")?;
        self.1 = true;
        Ok(status)
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for Reap {
    fn drop(&mut self) {
        if !self.1 {
            let _ = self.signal_owned();
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
            loop {
                match self.exited_unreaped() {
                    Ok(true) => {
                        if self.reap().is_err() {
                            self.2.borrow_mut().unknown = true;
                        }
                        return;
                    }
                    Err(_) => {
                        self.2.borrow_mut().unknown = true;
                        return;
                    }
                    Ok(false) => (),
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    self.2.borrow_mut().unknown = true;
                    return;
                }
                // SAFETY: no descriptors; bounded lifecycle supervision deadline,
                // not a propagation sleep or an unbounded Child::wait.
                unsafe {
                    libc::poll(
                        std::ptr::null_mut(),
                        0,
                        remaining.as_millis().clamp(1, 10) as i32,
                    );
                }
            }
        }
    }
}

/// A group leader that has exited but is not yet reaped (a zombie) is the
/// normal state of a fast-exiting hook when cleanup runs. Signalling its group
/// must not make the cleanup report `unknown`: the owned PID was verified, and
/// the signal has nothing left to kill.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[test]
fn a_zombie_group_leader_does_not_make_cleanup_unknown() {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let cleanup = std::rc::Rc::new(std::cell::RefCell::new(Cleanup::default()));
    let mut guard = Reap(child, false, cleanup.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !guard.exited_unreaped().unwrap() {
        assert!(std::time::Instant::now() < deadline, "child never exited");
        // SAFETY: no descriptors; a bounded wait for the child to exit.
        unsafe { libc::poll(std::ptr::null_mut(), 0, 5) };
    }
    guard.signal_owned().unwrap();
    assert!(
        cleanup.borrow().requested,
        "the cleanup path was not reached"
    );
    assert!(
        !cleanup.borrow().unknown,
        "signalling the group of a zombie leader made the cleanup unknown"
    );
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[test]
fn changed_direct_child_group_uses_owned_pid_and_bounded_cleanup() {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    let fixture = tempfile::TempDir::new().unwrap();
    let script = fixture.path().join("group-hop.sh");
    fs::write(&script, "while :; do :; done\n").unwrap();
    // SAFETY: reads this test process's current group; does not signal it.
    let parent_group = unsafe { libc::getpgrp() };
    let mut command = Command::new("/bin/sh");
    command
        .arg(&script)
        .env_clear()
        .env("HOME", fixture.path())
        .env("CSQ_BASE_DIR", fixture.path())
        .env("PATH", fixture.path().join("empty"))
        .current_dir(fixture.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    // SAFETY: pre_exec uses only the async-signal-safe setpgid syscall. It moves
    // only this controlled child; cleanup will never signal the parent group.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, parent_group) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    let pid = child.id();
    assert_eq!(unsafe { libc::getpgid(pid as i32) }, parent_group); // mutation reached.
    let cleanup = std::rc::Rc::new(std::cell::RefCell::new(Cleanup::default()));
    let guard = Reap(child, false, cleanup.clone());
    let started = std::time::Instant::now();
    drop(guard);
    assert!(started.elapsed().as_millis() < 2000);
    assert!(cleanup.borrow().requested && cleanup.borrow().direct_pid_signal);
    assert!(!cleanup.borrow().unknown);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_group_with_a_live_member_is_not_gone() {
    let ps = "  100 Z\n  100 Ss\n  200 Z\n";
    assert!(!all_members_zombie(ps, 100), "a live member of 100 exists");
    assert!(
        all_members_zombie(ps, 200),
        "every member of 200 is a zombie"
    );
    assert!(all_members_zombie(ps, 300), "no member at all");
}

/// A wedged listing is given up on at the limit, never waited for.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_wedged_process_listing_is_given_up_on_at_the_limit() {
    let mut c = std::process::Command::new("sh");
    c.args(["-c", "exec sleep 20"]);
    let began = std::time::Instant::now();
    let out = output_within(c, std::time::Duration::from_millis(400));
    assert!(
        out.is_none(),
        "a listing that never finished returned output"
    );
    assert!(
        began.elapsed() < std::time::Duration::from_secs(5),
        "the caller waited for the wedged listing"
    );
    let mut ok = std::process::Command::new("sh");
    ok.args(["-c", "echo 7 Z"]);
    assert_eq!(
        output_within(ok, std::time::Duration::from_secs(5)).as_deref(),
        Some("7 Z\n")
    );
}
