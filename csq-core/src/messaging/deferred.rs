//! The deferred Codex wake: a send that could not wake its recipient NOW is retried until the
//! recipient can take it, with no keystroke from the operator.
//!
//! A send arms a record in the recipient's own handle dir ([`PENDING_FILE`]; the handle dir is
//! removed when the session exits, so the record cannot outlive it). The recipient's
//! supervisor (`csq run` for Codex) calls [`tick`] on a timer. Why the supervisor and not the
//! daemon: the wake path (`wake_target_for`, thread resolution, the bounded spawn) is the
//! `csq` crate's, which `csq-core::daemon` cannot call without a dependency cycle, while the
//! supervisor already owns a per-session poll thread, the child's liveness and the handle dir.
//! A recipient with no separate supervisor (the swap-exec path) is never armed: the sender
//! reports the honest immediate status instead.
//!
//! The record holds the recipient identity, counters and an optional expected queue item id:
//! never a body, path or output.
//! [`tick`] stops (removes the record) when the recipient is gone or is not the session this
//! handle dir belongs to, its messages are read or acked, csq's queued wake row has left the
//! queue (taken and matching that record's expected item), a wake succeeded, or retention expires.
//! Clearing checks the record's generation, which every re-arm bumps; the unread re-check
//! catches a message stored before its sender re-arms. At most one csq wake row per thread is ever queued: the
//! dedupe is in `wake::deliver_with`, which a retry goes through unchanged.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::messaging::limits::RETENTION_SECS;
use crate::messaging::model::Recipient;
use crate::messaging::wake::Delivery;

/// The record's file name inside the recipient's handle dir.
pub const PENDING_FILE: &str = ".csq-wake-pending";

/// Largest record read back.
const RECORD_CAP: u64 = 4096;

/// First retry delay. A fresh session's thread lock appears within seconds of launch, so the
/// first retries are quick; after that the wait is for a human-paced first turn.
pub const BACKOFF_BASE_SECS: u64 = 5;

/// Longest delay between retries. Each attempt costs one process-table read and one fd
/// enumeration, so a session idle for days is polled every 5 minutes, not every few seconds.
pub const BACKOFF_CAP_SECS: u64 = 300;

/// Attempt bound. Retention (7 days) is the binding stop; this is the backstop that exceeds
/// it: 7 days / 300 s cap = 2016 attempts at the cap, plus the ~7 ramp attempts, so 2100.
pub const MAX_ATTEMPTS: u32 = 2100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Armed {
    recipient: Recipient,
    armed_at: u64,
    attempts: u32,
    next_at: u64,
    /// Bumped by every [`arm`]; a clear only removes the record it read.
    #[serde(default)]
    generation: u64,
    /// Only this queue item can establish that this armed attempt was taken.
    /// Old records and attempts that queued nothing have no such evidence.
    #[serde(default)]
    expect_item: Option<String>,
}

/// Why a [`tick`] ended without an attempt, or what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// No record armed.
    Idle,
    /// Armed, but the next attempt is not due yet.
    Waiting,
    /// An attempt ran and the wake is still outstanding (record kept, next attempt scheduled).
    Retried(Delivery),
    /// Stopped: the wake was taken.
    Woken,
    /// Stopped: the recipient is gone.
    RecipientGone,
    /// Stopped: the record names a session other than the one this handle dir belongs to.
    NotOurs,
    /// Stopped: no unread message remains.
    NothingPending,
    /// Stopped: retention or the attempt bound ran out.
    Expired,
    /// The supervisor is shutting down: nothing was attempted or persisted.
    Stopped,
}

impl Tick {
    fn tag(self) -> &'static str {
        match self {
            Tick::Idle => "idle",
            Tick::Waiting => "waiting",
            Tick::Retried(_) => "retried",
            Tick::Woken => "woken",
            Tick::RecipientGone => "recipient_gone",
            Tick::NotOurs => "not_ours",
            Tick::NothingPending => "nothing_pending",
            Tick::Expired => "expired",
            Tick::Stopped => "stopped",
        }
    }
}

/// The delay after `attempts` failed attempts: `BASE * 2^(attempts-1)`, capped.
#[must_use]
pub fn backoff_secs(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(16);
    (BACKOFF_BASE_SECS << shift).min(BACKOFF_CAP_SECS)
}

/// Arm a deferred wake for `recipient` in `codex_home`. An already-armed record for the same
/// session is KEPT (its attempt count and age continue, so repeated sends do not reset the
/// retention clock) but its generation is bumped and its next attempt pulled in, so a tick
/// that is about to clear it notices the new message.
///
/// # Errors
/// The record could not be written.
pub fn arm(codex_home: &Path, recipient: &Recipient, now: u64) -> std::io::Result<()> {
    arm_with_item(codex_home, recipient, now, None)
}

/// Arm with the item observed after `CodexQueued` or `CodexWakePending`.
/// Callers must pass `None` after an attempt that queued nothing; a stale
/// sidecar alone never establishes the expected item of a fresh attempt.
///
/// # Errors
/// The record could not be written.
pub fn arm_with_item(
    codex_home: &Path,
    recipient: &Recipient,
    now: u64,
    expect_item: Option<String>,
) -> std::io::Result<()> {
    arm_internal(codex_home, recipient, now, expect_item, false)
}

/// Re-arm uncertainty without erasing the existing acknowledgement of this recipient.
/// Only an existing same-incarnation pending record supplies the fallback; a sidecar never
/// does. Callers use this for in-flight or unverified attempts that returned no new item ID.
///
/// # Errors
/// The record could not be written.
pub fn arm_preserving_item(
    codex_home: &Path,
    recipient: &Recipient,
    now: u64,
    expect_item: Option<String>,
) -> std::io::Result<()> {
    arm_internal(codex_home, recipient, now, expect_item, true)
}

fn arm_internal(
    codex_home: &Path,
    recipient: &Recipient,
    now: u64,
    expect_item: Option<String>,
    preserve_item: bool,
) -> std::io::Result<()> {
    let _guard = state_lock(codex_home)?;
    let soon = now.saturating_add(BACKOFF_BASE_SECS);
    let rec = match read_result(codex_home)? {
        Some(mut a) if same_bound_recipient(&a.recipient, recipient) => {
            a.generation = a.generation.wrapping_add(1);
            a.next_at = a.next_at.min(soon);
            a.expect_item = if preserve_item && recipient.started_exact.is_some() {
                expect_item.or(a.expect_item)
            } else {
                expect_item
            };
            a
        }
        _ => Armed {
            recipient: *recipient,
            armed_at: now,
            attempts: 0,
            next_at: soon,
            generation: 0,
            expect_item,
        },
    };
    write(codex_home, &rec)
}

/// Recipient correlation requires the exact stored process incarnation and surface.
/// Whole-second proximity alone cannot distinguish PID reuse.
fn same_bound_recipient(a: &Recipient, b: &Recipient) -> bool {
    a.same_session(b)
        && a.surface == crate::messaging::model::Surface::Codex
        && b.surface == crate::messaging::model::Surface::Codex
        && a.started_exact.is_some()
        && a.started_exact == b.started_exact
}

/// Whether a deferred wake is armed in `codex_home`.
#[must_use]
pub fn is_armed(codex_home: &Path) -> bool {
    read(codex_home).is_some()
}

/// Remove the record (a taken or no-longer-needed wake).
pub fn clear(codex_home: &Path) {
    if let Ok(_guard) = state_lock(codex_home) {
        let _ = std::fs::remove_file(codex_home.join(PENDING_FILE));
    }
}

/// Generation comparison retains a concurrent re-arm. The unread re-check
/// after clearing is what catches a message stored before its sender re-arms.
fn clear_if_unchanged(codex_home: &Path, seen: &Armed) -> bool {
    let Ok(_guard) = state_lock(codex_home) else {
        return false;
    };
    if read(codex_home).as_ref() == Some(seen) {
        #[cfg(test)]
        state_mutation_probe();
        std::fs::remove_file(codex_home.join(PENDING_FILE)).is_ok()
    } else {
        false
    }
}

/// Read the record: opened `O_NOFOLLOW | O_NONBLOCK`, the regular-file check on the OPEN
/// handle, the read bounded, so a symlink or FIFO planted in the handle dir is refused and
/// nothing can be swapped in between a check and the read.
fn read(codex_home: &Path) -> Option<Armed> {
    read_result(codex_home).ok().flatten()
}

fn read_result(codex_home: &Path) -> std::io::Result<Option<Armed>> {
    let Some(bytes) = crate::platform::fs::read_regular_nofollow_bounded(
        &codex_home.join(PENDING_FILE),
        RECORD_CAP,
    )?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(std::io::Error::other)
}

/// Only state mutations hold this lock; no wake or caller callback runs while held.
/// File locking is available on Unix and Windows; dropping the file releases the lock.
fn state_lock(home: &Path) -> std::io::Result<std::fs::File> {
    use std::time::{Duration, Instant};
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(home.join(".csq-wake-state.lock"))?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("state_lock_not_regular"));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::park_timeout(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "state_lock_timeout",
                ))
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

/// Write `bytes` to `target` through a 0600 tmp and an atomic rename; the tmp is removed on
/// every failure branch.
pub(crate) fn write_private_atomic(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = crate::platform::fs::unique_tmp_path(target);
    write_private_atomic_with_temp(target, bytes, &tmp)
}

fn write_private_atomic_with_temp(target: &Path, bytes: &[u8], tmp: &Path) -> std::io::Result<()> {
    // Retain the synced private writer through publication. Its cleanup owns only
    // the created entry; a create-new collision remains untouched.
    let writer = crate::platform::fs::write_new_private_synced_retained(tmp, bytes)
        .map_err(std::io::Error::other)?;
    writer.replace(target).map_err(std::io::Error::other)
}

#[cfg(test)]
std::thread_local! {
    static STATE_MUTATION_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn state_mutation_probe() {
    STATE_MUTATION_PROBE.with(|slot| {
        if let Some(probe) = slot.borrow_mut().take() {
            probe();
        }
    });
}

#[cfg(all(test, unix))]
fn with_state_mutation_probe<T>(probe: impl FnOnce() + 'static, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<Box<dyn FnOnce()>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE_MUTATION_PROBE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(STATE_MUTATION_PROBE.with(|slot| slot.replace(Some(Box::new(probe)))));
    action()
}

fn write(codex_home: &Path, a: &Armed) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(a).map_err(std::io::Error::other)?;
    write_private_atomic(&codex_home.join(PENDING_FILE), &bytes)
}

/// What a tick consults. All injected, so a test drives time and every outcome.
pub struct Deps<'a> {
    /// The recipient incarnation still validates as a live wake target.
    pub live: &'a dyn Fn(&Recipient) -> bool,
    /// The recipient is the session THIS handle dir belongs to (a record naming any other
    /// session, planted or stale, is cleared and ignored).
    pub owns: &'a dyn Fn(&Recipient) -> bool,
    /// Unread messages remain for the recipient; `None` when the store cannot be read (the
    /// attempt is skipped and rescheduled: an unreadable store never stops the retry).
    pub unread: &'a dyn Fn(&Recipient) -> Option<bool>,
    /// The sidecar still names this expected item and its queue row is absent.
    pub taken: &'a dyn Fn(&Recipient, &str) -> bool,
    /// One full wake attempt (`real_wake`).
    pub wake: &'a dyn Fn(&Recipient) -> (Delivery, Option<String>),
    /// The supervisor is shutting down: nothing further is attempted or persisted.
    pub stop: &'a dyn Fn() -> bool,
}

/// Run one retry step for the record in `codex_home` at time `now` (unix seconds).
pub fn tick(codex_home: &Path, now: u64, deps: &Deps<'_>) -> Tick {
    let t = tick_inner(codex_home, now, deps);
    if !matches!(t, Tick::Idle | Tick::Waiting) {
        // Fixed vocabulary only: no path, recipient or message text.
        tracing::debug!(event = "deferred_wake", outcome = t.tag());
    }
    t
}

fn tick_inner(codex_home: &Path, now: u64, deps: &Deps<'_>) -> Tick {
    let Some(mut a) = read(codex_home) else {
        return Tick::Idle;
    };
    if (deps.stop)() {
        return Tick::Stopped;
    }
    if now.saturating_sub(a.armed_at) >= RETENTION_SECS || a.attempts >= MAX_ATTEMPTS {
        clear_if_unchanged(codex_home, &a);
        return Tick::Expired;
    }
    if now < a.next_at {
        return Tick::Waiting;
    }
    if !(deps.live)(&a.recipient) {
        clear_if_unchanged(codex_home, &a);
        return Tick::RecipientGone;
    }
    if !(deps.owns)(&a.recipient) {
        clear_if_unchanged(codex_home, &a);
        return Tick::NotOurs;
    }
    if a.expect_item
        .as_deref()
        .is_some_and(|id| (deps.taken)(&a.recipient, id))
    {
        clear_if_unchanged(codex_home, &a);
        return Tick::Woken;
    }
    if (deps.unread)(&a.recipient) == Some(false) {
        // A message may arrive between the read above and this clear: the compare-and-delete
        // refuses when a send re-armed meanwhile, and the re-check catches one that landed
        // just after the clear.
        if clear_if_unchanged(codex_home, &a) {
            let unread = (deps.unread)(&a.recipient);
            if (deps.stop)() {
                return Tick::Stopped;
            }
            if unread == Some(true) && arm(codex_home, &a.recipient, now).is_err() {
                tracing::debug!(event = "deferred_wake", outcome = "rearm_failed");
            }
        }
        return Tick::NothingPending;
    }
    if (deps.stop)() {
        return Tick::Stopped;
    }
    let (d, expected_item) = (deps.wake)(&a.recipient);
    if (deps.stop)() {
        // Teardown races the persist below: never write into a handle dir being removed.
        return Tick::Stopped;
    }
    if d == Delivery::CodexWoken {
        clear_if_unchanged(codex_home, &a);
        return Tick::Woken;
    }
    // Re-read: a send may have re-armed (generation bump) while the wake ran; keep its record
    // and schedule on top of it rather than overwriting it with the stale copy.
    a.expect_item = match d {
        Delivery::CodexQueued | Delivery::CodexWakePending => expected_item,
        Delivery::CodexQueuedUnverified
        | Delivery::CodexRowNeverSeen
        | Delivery::CodexWakeInFlight => expected_item.or(a.expect_item),
        _ => None,
    };
    let Ok(_guard) = state_lock(codex_home) else {
        tracing::debug!(event = "deferred_wake", outcome = "state_lock_failed");
        return Tick::Retried(d);
    };
    let Some(cur) = read(codex_home) else {
        // Another successful send may have cleared it, or teardown removed it.
        // A late tick must not recreate a record that no longer exists.
        return Tick::Retried(d);
    };
    #[cfg(test)]
    state_mutation_probe();
    if !same_bound_recipient(&cur.recipient, &a.recipient) {
        return Tick::NotOurs;
    }
    if cur.generation != a.generation {
        // Preserve the newer sender's correlation as well as its generation.
        a = cur;
    }
    a.attempts += 1;
    a.next_at = now.saturating_add(backoff_secs(a.attempts));
    if write(codex_home, &a).is_err() {
        tracing::debug!(event = "deferred_wake", outcome = "persist_failed");
    }
    Tick::Retried(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::model::Surface;
    use std::cell::{Cell, RefCell};
    use tempfile::TempDir;

    fn who() -> Recipient {
        Recipient {
            pid: 7,
            started_at: 5_000,
            surface: Surface::Codex,
            started_exact: Some(1),
        }
    }

    #[test]
    fn cr6_uncertain_rearm_and_retry_keep_only_same_incarnation_ack() {
        let home = TempDir::new().unwrap();
        let recipient = who();
        arm_with_item(home.path(), &recipient, 1_000, Some("CR6-ACK".into())).unwrap();
        arm_preserving_item(home.path(), &recipient, 1_001, None).unwrap();
        let record = read(home.path()).unwrap();
        assert_eq!(record.expect_item.as_deref(), Some("CR6-ACK"));
        assert_eq!(record.armed_at, 1_000);
        assert_eq!(record.generation, 1);
        for (now, delivery) in [
            (1_005, Delivery::CodexQueuedUnverified),
            (1_010, Delivery::CodexRowNeverSeen),
            (1_020, Delivery::CodexWakeInFlight),
        ] {
            assert_eq!(
                tick(
                    home.path(),
                    now,
                    &Deps {
                        live: &|_| true,
                        owns: &|_| true,
                        unread: &|_| Some(true),
                        taken: &|_, id| {
                            assert_eq!(id, "CR6-ACK");
                            false
                        },
                        wake: &|_| (delivery, None),
                        stop: &|| false,
                    }
                ),
                Tick::Retried(delivery)
            );
            assert_eq!(
                read(home.path()).unwrap().expect_item.as_deref(),
                Some("CR6-ACK"),
                "no new acknowledgement cannot erase outstanding correlation"
            );
        }
        // A definite no-queue attempt still clears correlation; unrelated incarnations
        // cannot inherit it through the preserving API either.
        arm_with_item(home.path(), &recipient, 1_021, None).unwrap();
        assert!(read(home.path()).unwrap().expect_item.is_none());
        arm_with_item(home.path(), &recipient, 1_022, Some("CR6-ACK".into())).unwrap();
        for other in [
            Recipient {
                started_exact: Some(2),
                ..recipient
            },
            Recipient {
                started_exact: None,
                ..recipient
            },
            Recipient {
                surface: Surface::ClaudeCode,
                ..recipient
            },
        ] {
            arm_with_item(home.path(), &recipient, 1_022, Some("CR6-ACK".into())).unwrap();
            arm_preserving_item(home.path(), &other, 1_023, None).unwrap();
            let record = read(home.path()).unwrap();
            assert!(record.expect_item.is_none());
            assert_eq!(record.armed_at, 1_023);
            assert_eq!(record.attempts, 0);
        }
    }

    #[derive(Clone, Copy)]
    struct W {
        live: bool,
        owns: bool,
        unread: Option<bool>,
        taken: bool,
        stop: bool,
    }
    const OK: W = W {
        live: true,
        owns: true,
        unread: Some(true),
        taken: false,
        stop: false,
    };

    fn run(home: &Path, now: u64, w: W, wake: &dyn Fn(&Recipient) -> Delivery) -> Tick {
        tick(
            home,
            now,
            &Deps {
                live: &|_| w.live,
                owns: &|_| w.owns,
                unread: &|_| w.unread,
                taken: &|_, _| w.taken,
                wake: &|r| (wake(r), Some("ITEM1".to_string())),
                stop: &|| w.stop,
            },
        )
    }

    fn never(_: &Recipient) -> Delivery {
        panic!("must not wake")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn independent_process_sees_state_lock_held(home: &Path) -> bool {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::net::UnixStream;
        let path = home.join(".csq-wake-state.lock");
        let _leaf = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        let pfd = parent.as_raw_fd();
        let cfd = child.as_raw_fd();
        // SAFETY: child uses only async-signal-safe descriptor syscalls and _exit, never
        // Rust allocation/destructors or inherited mutexes after this multi-threaded fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(pfd);
                let fd = libc::open(
                    path.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                );
                if fd == -1 {
                    libc::_exit(2);
                }
                let result = libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB);
                #[cfg(target_os = "linux")]
                let error = *libc::__errno_location();
                #[cfg(target_os = "macos")]
                let error = *libc::__error();
                let byte = if result == 0 {
                    libc::flock(fd, libc::LOCK_UN);
                    0u8
                } else if error == libc::EWOULDBLOCK {
                    1u8
                } else {
                    libc::_exit(3);
                };
                if libc::write(cfd, (&byte as *const u8).cast(), 1) != 1 {
                    libc::_exit(4);
                }
                libc::_exit(0);
            }
        }
        drop(child);
        let mut byte = [0u8];
        let received = parent.read_exact(&mut byte);
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut status = 0;
        loop {
            // SAFETY: this is our unreaped child; the status pointer is writable.
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == pid {
                break;
            }
            if result == -1 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("owned child could not be reaped");
            }
            if std::time::Instant::now() >= end {
                // Fresh waitpid proved it is still our live, unreaped child.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                panic!("owned state-lock probe timed out");
            }
            std::thread::park_timeout(std::time::Duration::from_millis(10));
        }
        received.unwrap();
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        byte[0] == 1
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn race_probe(
        home: std::path::PathBuf,
        blocked: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> impl FnOnce() {
        move || {
            let held = independent_process_sees_state_lock_held(&home);
            blocked.store(held, std::sync::atomic::Ordering::SeqCst);
            if !held {
                arm_with_item(&home, &who(), 100, Some("NEW".into())).unwrap();
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn r7_compare_delete_cannot_delete_a_concurrent_rearm() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let seen = read(d.path()).unwrap();
        let blocked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        with_state_mutation_probe(race_probe(d.path().to_owned(), blocked.clone()), || {
            clear_if_unchanged(d.path(), &seen)
        });
        if blocked.load(std::sync::atomic::Ordering::SeqCst) {
            arm_with_item(d.path(), &who(), 100, Some("NEW".into())).unwrap();
        }
        assert_eq!(
            read(d.path()).map(|a| a.expect_item),
            Some(Some("NEW".into())),
            "fresh rearm must survive compare/delete"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn r7_reconcile_cannot_overwrite_a_concurrent_rearm() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let blocked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        with_state_mutation_probe(race_probe(d.path().to_owned(), blocked.clone()), || {
            run(d.path(), 100, OK, &|_| Delivery::QueuedOnly)
        });
        if blocked.load(std::sync::atomic::Ordering::SeqCst) {
            arm_with_item(d.path(), &who(), 100, Some("NEW".into())).unwrap();
        }
        assert_eq!(
            read(d.path()).unwrap().expect_item.as_deref(),
            Some("NEW"),
            "fresh rearm must survive reconcile/write"
        );
        assert_eq!(read(d.path()).unwrap().generation, 1);
    }

    #[test]
    fn private_atomic_temp_collision_preserves_foreign_regular_file() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("target");
        let tmp = d.path().join("planted-temp");
        std::fs::write(&tmp, b"foreign-entry").unwrap();
        assert!(write_private_atomic_with_temp(&target, b"replacement", &tmp).is_err());
        assert_eq!(std::fs::read(&tmp).unwrap(), b"foreign-entry");
        assert!(!target.exists());
    }

    #[test]
    fn private_atomic_replace_failure_removes_owned_temp() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("target-directory");
        let tmp = d.path().join("owned-temp");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"unchanged").unwrap();
        assert!(write_private_atomic_with_temp(&target, b"replacement", &tmp).is_err());
        assert!(!tmp.exists());
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"unchanged"
        );
    }

    #[test]
    fn private_atomic_replaces_existing_file_with_retained_writer() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("target");
        let tmp = d.path().join("owned-temp");
        std::fs::write(&target, b"previous").unwrap();
        write_private_atomic_with_temp(&target, b"replacement", &tmp).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement");
        assert!(!tmp.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn r7_private_temp_symlink_never_changes_its_victim_or_is_removed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let d = TempDir::new().unwrap();
        let target = d.path().join("target");
        let tmp = d.path().join("planted-temp");
        let victim = d.path().join("victim");
        std::fs::write(&victim, "sentinel").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&victim, &tmp).unwrap();
        let result = write_private_atomic_with_temp(&target, b"replacement", &tmp);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "sentinel");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(result.is_err());
        assert!(
            std::fs::symlink_metadata(&tmp).unwrap().is_symlink(),
            "foreign entry must remain"
        );
        assert!(!target.exists());
    }

    #[test]
    fn r7_arm_refuses_an_unreadable_existing_record() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(PENDING_FILE), b"{bad record").unwrap();
        assert!(arm(d.path(), &who(), 0).is_err());
        assert_eq!(
            std::fs::read(d.path().join(PENDING_FILE)).unwrap(),
            b"{bad record"
        );
    }

    #[test]
    fn backoff_ramps_then_caps() {
        let v: Vec<u64> = (1..=8).map(backoff_secs).collect();
        assert_eq!(v, [5, 10, 20, 40, 80, 160, 300, 300]);
        assert_eq!(backoff_secs(u32::MAX), 300);
    }

    /// Fresh session shape: the first tries fail (no thread / no rollout), a later one is
    /// taken. Fake clock; the record is kept until the wake lands, then removed.
    #[test]
    fn retries_on_schedule_until_woken() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 1000).unwrap();
        arm(d.path(), &who(), 5000).unwrap(); // a second send does not reset the clock
        assert_eq!(read(d.path()).unwrap().armed_at, 1000);
        let calls = Cell::new(0u32);
        let script = RefCell::new(vec![
            Delivery::CodexWoken,
            Delivery::CodexNoTurnYet,
            Delivery::QueuedOnly,
        ]);
        let wake = |_: &Recipient| {
            calls.set(calls.get() + 1);
            script.borrow_mut().pop().unwrap()
        };
        assert_eq!(run(d.path(), 1004, OK, &wake), Tick::Waiting);
        assert_eq!(calls.get(), 0);
        assert_eq!(
            run(d.path(), 1005, OK, &wake),
            Tick::Retried(Delivery::QueuedOnly)
        );
        assert_eq!(run(d.path(), 1009, OK, &wake), Tick::Waiting);
        assert_eq!(
            run(d.path(), 1010, OK, &wake),
            Tick::Retried(Delivery::CodexNoTurnYet)
        );
        assert_eq!(run(d.path(), 1019, OK, &wake), Tick::Waiting);
        assert_eq!(run(d.path(), 1020, OK, &wake), Tick::Woken);
        assert!(!is_armed(d.path()));
        assert_eq!(calls.get(), 3);
        assert_eq!(run(d.path(), 1036, OK, &wake), Tick::Idle);
    }

    #[test]
    fn stops_when_recipient_is_gone_and_never_wakes() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let w = W { live: false, ..OK };
        assert_eq!(run(d.path(), 100, w, &never), Tick::RecipientGone);
        assert!(!is_armed(d.path()));
    }

    /// A record naming a session other than the one this handle dir belongs to (planted, or
    /// left by a swap) wakes nothing and is removed.
    #[test]
    fn a_planted_record_for_another_session_wakes_nothing() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let w = W { owns: false, ..OK };
        assert_eq!(run(d.path(), 100, w, &never), Tick::NotOurs);
        assert!(!is_armed(d.path()));
    }

    #[test]
    fn stops_when_messages_are_read_or_acked() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let w = W {
            unread: Some(false),
            ..OK
        };
        assert_eq!(run(d.path(), 100, w, &never), Tick::NothingPending);
        assert!(!is_armed(d.path()));
    }

    /// The wake row left the queue (taken) while the model has not read yet: no second wake.
    #[test]
    fn a_taken_wake_is_not_woken_again() {
        let d = TempDir::new().unwrap();
        arm_with_item(d.path(), &who(), 0, Some("ITEM1".to_string())).unwrap();
        let w = W { taken: true, ..OK };
        assert_eq!(run(d.path(), 100, w, &never), Tick::Woken);
        assert!(!is_armed(d.path()));
    }

    /// A previous sidecar is not evidence that an attempt which queued nothing
    /// has been consumed. The retry must continue after QueuedOnly.
    #[test]
    fn queued_only_arm_ignores_a_stale_taken_item() {
        let d = TempDir::new().unwrap();
        std::fs::write(
            d.path().join(".csq-wake-item"),
            br#"{"thread":"old-thread","id":"OLD"}"#,
        )
        .unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let w = W { taken: true, ..OK };
        assert_eq!(
            run(d.path(), 100, w, &|_| Delivery::QueuedOnly),
            Tick::Retried(Delivery::QueuedOnly)
        );
        assert!(is_armed(d.path()));
    }

    #[test]
    fn queued_retry_records_its_item_before_checking_consumption() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let w = W { taken: true, ..OK };
        assert_eq!(
            run(d.path(), 100, w, &|_| Delivery::CodexQueued),
            Tick::Retried(Delivery::CodexQueued)
        );
        assert_eq!(
            read(d.path()).unwrap().expect_item.as_deref(),
            Some("ITEM1")
        );
        assert_eq!(run(d.path(), 105, w, &never), Tick::Woken);
    }

    /// A failed record write leaves an old sidecar, but this retry has no item evidence.
    #[test]
    fn r7_retry_uses_attempt_item_not_a_stale_sidecar() {
        let d = TempDir::new().unwrap();
        arm_with_item(d.path(), &who(), 0, Some("OLD".into())).unwrap();
        std::fs::write(
            d.path().join(".csq-wake-item"),
            br#"{"thread":"T","id":"OLD"}"#,
        )
        .unwrap();
        let result = tick(
            d.path(),
            100,
            &Deps {
                live: &|_| true,
                owns: &|_| true,
                unread: &|_| Some(true),
                taken: &|_, _| false,
                wake: &|_| (Delivery::CodexQueued, None),
                stop: &|| false,
            },
        );
        assert_eq!(result, Tick::Retried(Delivery::CodexQueued));
        assert_eq!(read(d.path()).unwrap().expect_item, None);
        let result = tick(
            d.path(),
            105,
            &Deps {
                live: &|_| true,
                owns: &|_| true,
                unread: &|_| Some(true),
                taken: &|_, _| panic!("old item cannot stop this retry"),
                wake: &|_| (Delivery::CodexWakePending, Some("NEW".into())),
                stop: &|| false,
            },
        );
        assert_eq!(result, Tick::Retried(Delivery::CodexWakePending));
        assert_eq!(read(d.path()).unwrap().expect_item.as_deref(), Some("NEW"));
    }

    #[test]
    fn a_fresh_queued_only_arm_clears_old_item_correlation() {
        let d = TempDir::new().unwrap();
        arm_with_item(d.path(), &who(), 0, Some("OLD".to_string())).unwrap();
        arm(d.path(), &who(), 50).unwrap();
        assert_eq!(read(d.path()).unwrap().expect_item, None);
        let w = W { taken: true, ..OK };
        assert_eq!(
            run(d.path(), 100, w, &|_| Delivery::CodexNoTurnYet),
            Tick::Retried(Delivery::CodexNoTurnYet)
        );
    }

    #[test]
    fn a_concurrent_rearm_retains_its_new_item_correlation() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let wake = |_: &Recipient| {
            arm_with_item(d.path(), &who(), 100, Some("NEW".to_string())).unwrap();
            Delivery::CodexQueued
        };
        assert_eq!(
            run(d.path(), 100, OK, &wake),
            Tick::Retried(Delivery::CodexQueued)
        );
        assert_eq!(read(d.path()).unwrap().expect_item.as_deref(), Some("NEW"));
    }

    #[test]
    fn unreadable_store_neither_stops_nor_stacks() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let w = W { unread: None, ..OK };
        assert_eq!(
            run(d.path(), 100, w, &|_| Delivery::CodexWakePending),
            Tick::Retried(Delivery::CodexWakePending)
        );
        assert!(is_armed(d.path()));
    }

    /// A row never observed present proves nothing: the record stays armed.
    #[test]
    fn row_never_seen_does_not_clear_the_record() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        assert_eq!(
            run(d.path(), 100, OK, &|_| Delivery::CodexRowNeverSeen),
            Tick::Retried(Delivery::CodexRowNeverSeen)
        );
        assert!(is_armed(d.path()));
    }

    /// A send re-arms while the tick is deciding to clear: the record survives.
    #[test]
    fn a_message_arriving_during_the_clear_decision_is_not_lost() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let home = d.path().to_path_buf();
        let first = Cell::new(true);
        let rearm = move |_: &Recipient| {
            // The send lands once, during the first unread read; later reads see no change.
            if first.replace(false) {
                arm(&home, &who(), 50).unwrap();
            }
            Some(false)
        };
        let t = tick(
            d.path(),
            100,
            &Deps {
                live: &|_| true,
                owns: &|_| true,
                unread: &rearm,
                taken: &|_, _| false,
                wake: &|r| (never(r), None),
                stop: &|| false,
            },
        );
        assert_eq!(t, Tick::NothingPending);
        assert!(
            is_armed(d.path()),
            "compare-and-delete must keep the re-armed record"
        );
    }

    /// Teardown: a stop observed after the wake means nothing is persisted.
    #[test]
    fn stop_after_the_wake_persists_nothing() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let stop = Cell::new(false);
        let before = std::fs::read(d.path().join(PENDING_FILE)).unwrap();
        let t = tick(
            d.path(),
            100,
            &Deps {
                live: &|_| true,
                owns: &|_| true,
                unread: &|_| Some(true),
                taken: &|_, _| false,
                wake: &|_| {
                    stop.set(true);
                    (Delivery::QueuedOnly, None)
                },
                stop: &|| stop.get(),
            },
        );
        assert_eq!(t, Tick::Stopped);
        assert_eq!(std::fs::read(d.path().join(PENDING_FILE)).unwrap(), before);
        let w = W { stop: true, ..OK };
        assert_eq!(run(d.path(), 100, w, &never), Tick::Stopped);
    }

    #[test]
    fn stop_during_unread_recheck_never_rearms_a_cleared_record() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let reads = Cell::new(0);
        let stop = Cell::new(false);
        let out = tick(
            d.path(),
            100,
            &Deps {
                live: &|_| true,
                owns: &|_| true,
                unread: &|_| {
                    reads.set(reads.get() + 1);
                    if reads.get() == 1 {
                        Some(false)
                    } else {
                        stop.set(true);
                        Some(true)
                    }
                },
                taken: &|_, _| false,
                wake: &|_| panic!("nothing should wake"),
                stop: &|| stop.get(),
            },
        );
        assert_eq!(out, Tick::Stopped);
        assert!(!is_armed(d.path()));
    }

    #[test]
    fn retention_and_attempt_bound_expire_the_record() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let wake = |_: &Recipient| Delivery::QueuedOnly;
        assert_eq!(run(d.path(), RETENTION_SECS, OK, &wake), Tick::Expired);
        assert!(!is_armed(d.path()));
        let mut a = Armed {
            recipient: who(),
            armed_at: 0,
            attempts: MAX_ATTEMPTS,
            next_at: 0,
            generation: 0,
            expect_item: None,
        };
        write(d.path(), &a).unwrap();
        assert_eq!(run(d.path(), 10, OK, &wake), Tick::Expired);
        a.attempts = 0;
        write(d.path(), &a).unwrap();
        assert!(matches!(run(d.path(), 10, OK, &wake), Tick::Retried(_)));
    }

    #[test]
    fn a_garbage_record_is_not_read() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(PENDING_FILE), b"{not json").unwrap();
        assert!(!is_armed(d.path()));
    }

    /// B4: a symlink in the record's place is refused (never followed).
    #[cfg(unix)]
    #[test]
    fn a_symlinked_record_is_refused() {
        let d = TempDir::new().unwrap();
        arm(d.path(), &who(), 0).unwrap();
        let real = d.path().join("real");
        std::fs::rename(d.path().join(PENDING_FILE), &real).unwrap();
        std::os::unix::fs::symlink(&real, d.path().join(PENDING_FILE)).unwrap();
        assert!(!is_armed(d.path()));
    }

    /// B4: a FIFO in the record's place is refused WITHOUT blocking on a writer.
    #[cfg(unix)]
    #[test]
    fn a_fifo_record_is_refused_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let d = TempDir::new().unwrap();
        let p = d.path().join(PENDING_FILE);
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path; `mkfifo` touches no other memory.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            let _ = tx.send(is_armed(p.parent().unwrap()));
        });
        let r = rx.recv_timeout(std::time::Duration::from_secs(5));
        assert_eq!(r, Ok(false), "a FIFO read must return, refused");
        h.join().unwrap();
    }

    /// End to end over the real wake path: the stub `codex` first refuses with `no rollout
    /// found` (a fresh session, no turn yet), then queues. Exactly one csq row is ever in the
    /// queue, and it drains. Fake clock throughout.
    #[cfg(unix)]
    #[test]
    fn no_rollout_then_queued_leaves_one_row_then_drained() {
        use crate::messaging::wake::{deliver_with, Launcher, WakeSpec};
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;
        let home = TempDir::new().unwrap();
        let sq = TempDir::new().unwrap();
        let bin = TempDir::new().unwrap();
        let conn = rusqlite::Connection::open(sq.path().join("queue_1.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE queued_items (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, \
             payload_json TEXT NOT NULL, queue_order INTEGER NOT NULL, \
             created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);",
        )
        .unwrap();
        let stub = bin.path().join("codex");
        let flag = bin.path().join("seen");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ ! -e '{f}' ]; then : > '{f}'; \
                 echo 'thread/queue/add failed: no rollout found for thread id T' >&2; exit 1; fi\n\
                 echo 'Queued message ITEM1 for thread T'\n",
                f = flag.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let spec = WakeSpec::for_test(home.path(), sq.path());
        let rows = || -> i64 {
            conn.query_row("SELECT COUNT(*) FROM queued_items", [], |r| r.get(0))
                .unwrap()
        };
        let wake = |_: &Recipient| {
            deliver_with(
                &spec,
                &|| true,
                Some("T"),
                1,
                Launcher {
                    program: stub.as_os_str(),
                    path: Some(std::ffi::OsStr::new("/usr/bin:/bin")),
                    home: None,
                },
                Duration::from_secs(120),
                Duration::from_secs(120),
                std::time::Instant::now() + Duration::from_secs(300),
            )
        };
        arm(home.path(), &who(), 1000).unwrap();
        // Attempt 1: no turn yet -> refused, nothing queued, still armed.
        assert_eq!(
            run(home.path(), 1005, OK, &wake),
            Tick::Retried(Delivery::CodexNoTurnYet)
        );
        assert_eq!(rows(), 0);
        // The first turn happens; codex now accepts. The row exists when the stub exits, then
        // is taken.
        conn.execute(
            "INSERT INTO queued_items VALUES ('ITEM1','T', \
             '{\"UserInput\":{\"content\":[{\"type\":\"text\",\"text\":\"csq: 1 peer message(s) waiting\"}]}}',1,0,0)",
            [],
        )
        .unwrap();
        let sqp = sq.path().to_path_buf();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let taker = std::thread::spawn(move || {
            seen_rx
                .recv_timeout(Duration::from_secs(120))
                .expect("the drain watcher must observe the queued row first");
            rusqlite::Connection::open(sqp.join("queue_1.sqlite"))
                .unwrap()
                .execute("DELETE FROM queued_items WHERE id='ITEM1'", [])
                .unwrap();
        });
        let result = crate::messaging::wake::with_first_seen_signal(seen_tx, || {
            run(home.path(), 1010, OK, &wake)
        });
        taker.join().unwrap();
        assert_eq!(result, Tick::Woken);
        assert_eq!(rows(), 0, "drained");
        assert!(!is_armed(home.path()));
    }
}
