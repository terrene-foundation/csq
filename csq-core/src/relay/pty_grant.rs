//! macOS process-local grant/unlock critical section.
//!
//! LOCK_WAIT bounds acquisition only. A caller that owns the guard still
//! performs synchronous native ioctls: their duration is NOT bounded here.

use std::io;
use std::os::fd::RawFd;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

// CHOSEN interactive lock-acquisition budget, enforced by the monotonic
// deadline below. This is not a worst-case native ioctl duration derived
// from a finite stress sample.
const LOCK_WAIT: Duration = Duration::from_secs(2);
const LOCK_TICK: Duration = Duration::from_millis(1);
static GRANT_LOCK: Mutex<()> = Mutex::new(());
pub(super) const TIMEOUT_OP: &str = "pty_grant_lock_timeout";

#[derive(Debug)]
struct GrantLockTimeout;
impl std::fmt::Display for GrantLockTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(TIMEOUT_OP)
    }
}
impl std::error::Error for GrantLockTimeout {}

pub(super) fn is_timeout(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<GrantLockTimeout>())
}

fn acquire() -> io::Result<MutexGuard<'static, ()>> {
    let deadline = Instant::now() + LOCK_WAIT;
    #[cfg(test)]
    probe(ProbeEvent::Attempt);
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, GrantLockTimeout));
        }
        match GRANT_LOCK.try_lock() {
            Ok(held) => return Ok(held),
            Err(TryLockError::Poisoned(_)) => {
                return Err(io::Error::other("pty_grant_lock_poisoned"));
            }
            Err(TryLockError::WouldBlock) => {
                #[cfg(test)]
                probe(ProbeEvent::Contended);
            }
        }
        std::thread::sleep(LOCK_TICK.min(deadline.saturating_duration_since(Instant::now())));
    }
}

pub(super) fn grant_unlock(master: RawFd) -> io::Result<()> {
    let _held = acquire()?;
    #[cfg(test)]
    probe(ProbeEvent::Entered);
    // SAFETY: the caller owns this master for the entire call. The same
    // process-wide guard covers both operations and every error return.
    if unsafe { libc::grantpt(master) } == -1 || unsafe { libc::unlockpt(master) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeEvent {
    Attempt,
    Contended,
    Entered,
}
#[cfg(test)]
type Probe = Box<dyn FnMut(ProbeEvent)>;
#[cfg(test)]
thread_local! {
    // Only a fixture's own caller thread installs a witness. This observes
    // the real production gate; it does not replace that gate or its ioctls.
    static PROBE: std::cell::RefCell<Option<Probe>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn set_probe(probe: impl FnMut(ProbeEvent) + 'static) {
    PROBE.with(|slot| *slot.borrow_mut() = Some(Box::new(probe)));
}
#[cfg(test)]
fn probe(event: ProbeEvent) {
    PROBE.with(|slot| {
        if let Some(probe) = slot.borrow_mut().as_mut() {
            probe(event);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::super::{open_relay_pty, pty_open_error, Pty, RelayError};
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    const CHILD_KEY: &str = "CSQ_PTY_GRANT_TEST_CHILD";
    const CASE_WAIT: Duration = Duration::from_secs(5);

    const MAX_CAPTURE: u64 = 64 * 1024;

    #[derive(Debug, PartialEq, Eq)]
    enum IsolatedVerdict {
        Passed,
        Causal,
        Undetermined,
    }

    fn read_capture(path: &std::path::Path) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let before = file.metadata()?;
        if !before.is_file() || before.len() > MAX_CAPTURE {
            return Err(io::Error::other("invalid_private_capture"));
        }
        let mut bytes = Vec::new();
        (&mut file).take(MAX_CAPTURE + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() as u64 != before.len()
            || after.len() != before.len()
            || before.modified()? != after.modified()?
        {
            return Err(io::Error::other("incomplete_private_capture"));
        }
        Ok(bytes)
    }

    // Instrument classifier only. A native exit is necessary but not enough
    // to credit a specific mutation: the expected target and exact assertion
    // site must be visible in complete private captures after actual reap.
    fn classify(
        reaped: bool,
        success: bool,
        stdout: Option<&[u8]>,
        stderr: Option<&[u8]>,
        target: &str,
        expected_site: &str,
    ) -> IsolatedVerdict {
        if !reaped {
            return IsolatedVerdict::Undetermined;
        }
        let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
            return IsolatedVerdict::Undetermined;
        };
        let (Ok(stdout), Ok(stderr)) = (std::str::from_utf8(stdout), std::str::from_utf8(stderr))
        else {
            return IsolatedVerdict::Undetermined;
        };
        let passed = format!("test {target} ... ok");
        let failed = format!("test {target} ... FAILED");
        let pass_count = stdout.lines().filter(|line| *line == passed).count();
        let fail_count = stdout.lines().filter(|line| *line == failed).count();
        if success {
            return if pass_count == 1 && fail_count == 0 && !stderr.contains(" panicked at ") {
                IsolatedVerdict::Passed
            } else {
                IsolatedVerdict::Undetermined
            };
        }
        if pass_count != 0 || fail_count != 1 {
            return IsolatedVerdict::Undetermined;
        }
        let lines: Vec<_> = stderr.lines().collect();
        let headers: Vec<_> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains(" panicked at "))
            .collect();
        if headers.len() != 1 {
            return IsolatedVerdict::Undetermined;
        }
        let (index, header) = headers[0];
        if !header.starts_with(&format!("thread '{target}'")) || !header.contains("pty_grant.rs:") {
            return IsolatedVerdict::Undetermined;
        }
        let site = lines[index + 1..]
            .iter()
            .copied()
            .find(|line| !line.is_empty());
        match site.and_then(|line| line.strip_prefix(expected_site)) {
            Some(rest) if rest.is_empty() || rest.starts_with(':') => IsolatedVerdict::Causal,
            _ => IsolatedVerdict::Undetermined,
        }
    }

    // Every fixture runs in a fresh process: holding the actual global gate
    // cannot make another concurrently-running relay test time out.
    fn isolated(name: &str, expected_site: &str, scenario: fn()) {
        let target = format!("relay::pty::pty_grant::tests::{name}");
        if std::env::var(CHILD_KEY).ok().as_deref() == Some(target.as_str()) {
            scenario();
            return;
        }
        let dir = tempfile::tempdir().expect("private case directory");
        let stdout = File::create(dir.path().join("stdout")).expect("private stdout");
        let stderr = File::create(dir.path().join("stderr")).expect("private stderr");
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command.env_clear();
        command
            .env("HOME", dir.path())
            .env("TMPDIR", dir.path())
            .env("CSQ_BASE_DIR", dir.path())
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env(CHILD_KEY, &target)
            .current_dir(dir.path())
            .args(["--exact", &target, "--nocapture"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut child = command.spawn().expect("owned isolated case");
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                _ => break None,
            }
        };
        let status = match status {
            Some(status) => status,
            None => {
                let _ = child.kill();
                let cleanup = Instant::now() + Duration::from_secs(2);
                let mut reaped = false;
                while Instant::now() < cleanup {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            reaped = true;
                            break;
                        }
                        Ok(None) => thread::sleep(Duration::from_millis(2)),
                        Err(_) => break,
                    }
                }
                panic!("PTY_GRANT_ISOLATED_UNDETERMINED: isolated deadline; actual_reap={reaped}");
            }
        };
        let stdout = read_capture(&dir.path().join("stdout")).ok();
        let stderr = read_capture(&dir.path().join("stderr")).ok();
        // Never replay child bytes/libtest records. The propagated site is a
        // compile-time fixture string, only after complete capture + actual reap.
        match classify(
            true,
            status.success(),
            stdout.as_deref(),
            stderr.as_deref(),
            &target,
            expected_site,
        ) {
            IsolatedVerdict::Passed => {}
            IsolatedVerdict::Causal => panic!("{expected_site}: confirmed after actual child reap"),
            IsolatedVerdict::Undetermined => {
                panic!("PTY_GRANT_ISOLATED_UNDETERMINED: unconfirmed child outcome")
            }
        }
    }

    fn positive_pty(result: io::Result<Pty>) {
        let pty = result.expect("actual production allocation");
        for fd in [pty.master.as_raw_fd(), pty.slave.as_raw_fd()] {
            // SAFETY: both live descriptors are owned by pty.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
            // SAFETY: isatty reads a live descriptor only.
            assert_eq!(unsafe { libc::isatty(fd) }, 1);
        }
    }

    #[test]
    fn actual_pty_grant_pair_serializes_concurrent_callers() {
        isolated(
            "actual_pty_grant_pair_serializes_concurrent_callers",
            "PTY_GRANT_SERIALIZATION_REQUIRED: second caller overlapped",
            || {
                let (entered_tx, entered_rx) = mpsc::channel();
                let (release_tx, release_rx) = mpsc::channel();
                let (first_done_tx, first_done_rx) = mpsc::channel();
                let first = thread::spawn(move || {
                    set_probe(move |event| {
                        if event == ProbeEvent::Entered {
                            let _ = entered_tx.send(());
                            release_rx
                                .recv_timeout(CASE_WAIT)
                                .expect("release first caller");
                        }
                    });
                    let result = Pty::open(None, None);
                    let _ = first_done_tx.send(result);
                });
                let first_entered = entered_rx.recv_timeout(CASE_WAIT);
                let (event_tx, event_rx) = mpsc::channel();
                let (second_done_tx, second_done_rx) = mpsc::channel();
                let second = thread::spawn(move || {
                    set_probe(move |event| {
                        if matches!(event, ProbeEvent::Contended | ProbeEvent::Entered) {
                            let _ = event_tx.send(event);
                        }
                    });
                    let result = Pty::open(None, None);
                    let _ = second_done_tx.send(result);
                });
                let second_observation = event_rx.recv_timeout(CASE_WAIT);
                // Release before assertions, including in the faithful
                // no-serialization mutant, so both original threads finish.
                let _ = release_tx.send(());
                let first_result = first_done_rx.recv_timeout(CASE_WAIT);
                let second_result = second_done_rx.recv_timeout(CASE_WAIT);
                if first_result.is_ok() {
                    first.join().expect("first caller ended");
                }
                if second_result.is_ok() {
                    second.join().expect("second caller ended");
                }
                assert!(
                    first_entered.is_ok(),
                    "PTY_GRANT_SERIALIZATION_REQUIRED: first admission"
                );
                positive_pty(first_result.expect("first caller completed"));
                positive_pty(second_result.expect("second caller completed"));
                assert!(
                    matches!(second_observation, Ok(ProbeEvent::Contended)),
                    "PTY_GRANT_SERIALIZATION_REQUIRED: second caller overlapped: {second_observation:?}"
                );
            },
        );
    }

    #[test]
    fn actual_pty_grant_lock_wait_has_a_fixed_deadline() {
        isolated(
            "actual_pty_grant_lock_wait_has_a_fixed_deadline",
            "PTY_GRANT_LOCK_DEADLINE_REQUIRED: waited for release",
            || {
                let held = GRANT_LOCK.lock().expect("own actual production gate");
                let (attempt_tx, attempt_rx) = mpsc::channel();
                let (done_tx, done_rx) = mpsc::channel();
                let worker = thread::spawn(move || {
                    set_probe(move |event| {
                        if event == ProbeEvent::Attempt {
                            let _ = attempt_tx.send(());
                        }
                    });
                    let began = Instant::now();
                    let result = Pty::open(None, None);
                    let _ = done_tx.send((began.elapsed(), result));
                });
                let attempted = attempt_rx.recv_timeout(CASE_WAIT);
                let timely = done_rx.recv_timeout(LOCK_WAIT + Duration::from_secs(1));
                drop(held);
                let completed_before_release = timely.is_ok();
                let outcome = timely.or_else(|_| done_rx.recv_timeout(CASE_WAIT));
                if outcome.is_ok() {
                    worker.join().expect("original caller ended");
                }
                assert!(
                    attempted.is_ok(),
                    "PTY_GRANT_LOCK_DEADLINE_REQUIRED: no actual attempt"
                );
                if !completed_before_release {
                    assert!(
                        matches!(&outcome, Ok((_, Ok(_)))),
                        "unconfirmed late deadline outcome"
                    );
                }
                assert!(
                    completed_before_release,
                    "PTY_GRANT_LOCK_DEADLINE_REQUIRED: waited for release"
                );
                let (elapsed, result) = outcome.expect("caller drained after release");
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("held gate must time out"),
                };
                assert!(
                    is_timeout(&error),
                    "PTY_GRANT_LOCK_DEADLINE_REQUIRED: wrong error"
                );
                assert_eq!(error.to_string(), TIMEOUT_OP);
                assert!(elapsed >= LOCK_WAIT && elapsed < LOCK_WAIT + Duration::from_secs(1));
            },
        );
    }

    #[test]
    fn actual_relay_pty_timeout_preserves_fixed_op_and_errno() {
        isolated(
            "actual_relay_pty_timeout_preserves_fixed_op_and_errno",
            "PTY_GRANT_TIMEOUT_MAPPING_REQUIRED: timeout flattened",
            || {
                let held = GRANT_LOCK.lock().expect("own actual production gate");
                let (done_tx, done_rx) = mpsc::channel();
                let (attempt_tx, attempt_rx) = mpsc::channel();
                let worker = thread::spawn(move || {
                    set_probe(move |event| {
                        if event == ProbeEvent::Attempt {
                            let _ = attempt_tx.send(());
                        }
                    });
                    let _ = done_tx.send(open_relay_pty(None, None));
                });
                let attempted = attempt_rx.recv_timeout(CASE_WAIT);
                let timely = done_rx.recv_timeout(LOCK_WAIT + Duration::from_secs(1));
                drop(held);
                let outcome = timely.or_else(|_| done_rx.recv_timeout(CASE_WAIT));
                if outcome.is_ok() {
                    worker.join().expect("actual relay caller ended");
                }
                assert!(attempted.is_ok(), "actual relay never reached held gate");
                assert!(
                    matches!(
                        outcome,
                        Ok(Err(RelayError::NotStarted {
                            op: TIMEOUT_OP,
                            errno: libc::ETIMEDOUT
                        }))
                    ),
                    "PTY_GRANT_TIMEOUT_MAPPING_REQUIRED: timeout flattened"
                );
                // An unrelated ETIMEDOUT, or a forged same-text custom error,
                // must keep ordinary openpty mapping rather than this tag.
                assert!(matches!(
                    pty_open_error(io::Error::from_raw_os_error(libc::ETIMEDOUT)),
                    RelayError::NotStarted {
                        op: "openpty",
                        errno: libc::ETIMEDOUT
                    }
                ));
                assert!(matches!(
                    pty_open_error(io::Error::other(TIMEOUT_OP)),
                    RelayError::NotStarted {
                        op: "openpty",
                        errno: 0
                    }
                ));
            },
        );
    }

    #[test]
    fn isolated_classifier_requires_the_exact_inner_assertion() {
        let target = "relay::pty::pty_grant::tests::fixture";
        let site = "EXPECTED_CAUSAL_SITE: precise boundary";
        let ok = format!("test {target} ... ok\n");
        let failed = format!("test {target} ... FAILED\n");
        let panic = format!(
            "thread '{target}' (1) panicked at csq-core/src/relay/pty_grant.rs:1:1:\n{site}\n"
        );
        assert_eq!(
            classify(true, true, Some(ok.as_bytes()), Some(b""), target, site),
            IsolatedVerdict::Passed
        );
        assert_eq!(
            classify(
                true,
                false,
                Some(failed.as_bytes()),
                Some(panic.as_bytes()),
                target,
                site
            ),
            IsolatedVerdict::Causal
        );
        let unrelated = panic.replace(site, "resource allocation refused");
        assert_eq!(
            classify(
                true,
                false,
                Some(failed.as_bytes()),
                Some(unrelated.as_bytes()),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
        assert_eq!(
            classify(true, false, None, Some(panic.as_bytes()), target, site),
            IsolatedVerdict::Undetermined
        );
        assert_eq!(
            classify(
                false,
                false,
                Some(failed.as_bytes()),
                Some(panic.as_bytes()),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
        assert_eq!(
            classify(
                true,
                false,
                Some(failed.as_bytes()),
                Some(b"EXPECTED_CAUSAL_SITE: precise boundary"),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
        let prefixed = panic.replace(site, "EXPECTED_CAUSAL_SITE: precise boundary-extra");
        assert_eq!(
            classify(
                true,
                false,
                Some(failed.as_bytes()),
                Some(prefixed.as_bytes()),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
        let wrong_target = panic.replace(target, "other_test");
        assert_eq!(
            classify(
                true,
                false,
                Some(failed.as_bytes()),
                Some(wrong_target.as_bytes()),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
        assert_eq!(
            classify(
                true,
                true,
                Some(failed.as_bytes()),
                Some(panic.as_bytes()),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
        let duplicate = format!("{panic}{panic}");
        assert_eq!(
            classify(
                true,
                false,
                Some(failed.as_bytes()),
                Some(duplicate.as_bytes()),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
        assert_eq!(
            classify(
                true,
                false,
                Some(failed.as_bytes()),
                Some(&[255]),
                target,
                site
            ),
            IsolatedVerdict::Undetermined
        );
    }

    #[test]
    fn isolated_capture_reader_requires_complete_bounded_files() {
        let dir = tempfile::tempdir().expect("instrument capture directory");
        let path = dir.path().join("capture");
        assert!(read_capture(&path).is_err());
        std::fs::write(&path, b"complete capture").expect("instrument capture");
        assert_eq!(
            read_capture(&path).expect("complete bounded capture"),
            b"complete capture"
        );
        std::fs::write(&path, vec![0u8; MAX_CAPTURE as usize + 1])
            .expect("oversized instrument capture");
        assert!(read_capture(&path).is_err());
    }
}
