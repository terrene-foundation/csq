//! The Codex wake on `send` (spec 32 §5.1).
//!
//! A wake runs `codex -c sqlite_home=<target> queue --thread <id> --message <notice>` with
//! `CODEX_HOME=<target handle dir>`. The message queued is a FIXED notice, never the body, so
//! the body is absent from argv by construction ([`notice`] takes only a count).
//!
//! Where the spawn's paths come from: [`WakeSpec`] has private fields and exactly one
//! non-test constructor, [`WakeSpec::from_target`], which takes a [`WakeTarget`]. A
//! `WakeTarget` is only produced by `sessions::wake_target_ok`, so argv and env are built from
//! a validated, canonical pair and from nothing else. [`deliver`] calls the caller's
//! `still_live` check immediately before the spawn and refuses to spawn when it is false.
//!
//! Every outcome is a distinct [`Delivery`]; none of them fails or loses the message
//! (INV-32-04) because the message is already stored `queued` before a wake is attempted.
//! Nothing here logs a path, a body or the child's output. The child's stdin is null; its
//! stdout and stderr are read (bounded) only to parse the queued item id and to match the
//! `no rollout found` refusal, and are never logged or returned.
//!
//! `codex queue` exiting 0 means the row was WRITTEN to `<sqlite_home>/queue_1.sqlite`
//! (`queued_items`), not that the session took it (observed codex-cli 0.160.1: a live fresh
//! TUI drains its row within ~2 s; a session resumed after an interrupted turn can hold rows
//! indefinitely). [`deliver`] observes this attempt's acknowledged id and thread in that DB
//! read-only, including while the helper runs, and reports `codex_woken` only after SEEN
//! present then absent. A later nonzero exit or timeout never cancels a witnessed write.
//! A spawned helper with no usable acknowledgement leaves the queue outcome unknown.

//! # Host process precondition (in-process embedding)
//!
//! the host process must not ignore SIGCHLD or reap children it did not spawn while a wake is in flight.
//! The pre-spawn getter refuses SIG_IGN and SA_NOCLDWAIT. It cannot prevent
//! another host component from reaping this child or changing policy mid-flight.
//! That is a csq embedding limitation, independent of provider CLI/model capability.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::sessions::WakeTarget;

/// Wall-clock budget for one wake attempt. Derivation: the measured idle wake returned in a
/// few hundred ms (the 13 s in spec 32 §5.1 is the model's reply, which `queue` does not
/// wait for); a hung daemon attach is the failure this bounds, and a `send` is interactive.
pub const WAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The shared deadline starts in `wake_via` BEFORE `target_of`: recipient lookup, launch
/// validation and filesystem/process reads consume this allocation too. Thread resolution
/// then uses up to two `FD_ENUM_TIMEOUT` enumerations (5 s each); lock wait, queue spawn
/// ([`WAKE_TIMEOUT`], 5 s) and drain watch ([`DRAIN_WAIT`], 6 s) draw from what remains.
/// These are allocations, not additive guarantees: `target_of` and thread discovery are
/// synchronous calls without this deadline argument, and OS filesystem/process scheduling
/// is not bounded here. If they exhaust the allocation, `deliver_with` opens no wake lock
/// and spawns nothing. Drain polls (at most 100 ms) and sqlite busy waits (at most 200 ms)
/// are cut to the remaining budget; synchronous filesystem calls can still finish after it.
/// A new queue observation past the overall deadline is not accepted. The observed typical
/// wake is ~2-3 s (OBSERVED, not a bound).
pub const WAKE_TOTAL: Duration = Duration::from_secs(20);

/// How long after `codex queue` returns an acknowledgement its row is watched for a take.
/// Derivation from the two outcomes it separates (OBSERVED, codex-cli 0.160.1, macOS): a
/// healthy fresh TUI drained its row in about 2 s (observed typical, NOT a bound); a stuck
/// resumed session never drained (rows older than 30 min). 6 s leaves roughly 4 s of margin
/// over the observed drain and is far below the stuck case, so it separates them; a slow-but-
/// healthy drain beyond 6 s reads `codex_queued`, an honest "not yet taken", never a false
/// `codex_woken`. Worst-case blocking of one send is [`WAKE_TIMEOUT`] + `DRAIN_WAIT` = 11 s.
pub const DRAIN_WAIT: Duration = Duration::from_secs(6);

const DRAIN_POLL: Duration = Duration::from_millis(100);

/// The `codex` stderr fragment for a thread with no turn yet. A DOCUMENTED FRAGILITY: it is
/// matched against codex-cli 0.160.1's `thread/queue/add failed: ... no rollout found for
/// thread id ...`; another codex version may word it differently, in which case the failure
/// leaves the spawned outcome `codex_queued_unverified` (the message is still stored).
const NO_ROLLOUT: &str = "no rollout found";

const POLL: Duration = Duration::from_millis(20);

crate::all_enum::declare_all_enum! {
/// The `delivery` value of a `send` receipt (spec 32 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// No wake was attempted: target not validated, no socket or no exact thread id.
    QueuedOnly,
    /// This attempt's exact row was seen present and then taken from the queue.
    CodexWoken,
    /// Nothing was spawned: the target was gone, setup failed, or the budget expired.
    CodexWakeFailed,
    /// This attempt's exact row is still in the queue after [`DRAIN_WAIT`]: queued
    /// in Codex, not yet taken by the session.
    CodexQueued,
    /// A child was spawned but its write or consumption could not be verified (including
    /// timeout, nonzero exit, unreadable DB, unknown item, or a stopped target). Never woken.
    CodexQueuedUnverified,
    /// A csq wake notice is already pending for this thread: nothing was spawned. Wire status
    /// `codex_queued`, reason `wake_pending`.
    CodexWakePending,
    /// Another wake holds the recipient lock, so this attempt queued nothing in Codex.
    /// Wire status `queued_only`, reason `wake_in_flight`.
    CodexWakeInFlight,
    /// No wake could be made now (no thread id yet, or the thread has no turn) and a deferred
    /// wake is armed: csq retries until the session can take it (`messaging::deferred`).
    /// Wire status `codex_wake_pending`.
    CodexWakeDeferred,
    /// The child acknowledged this item but the row was never observed present, so absence
    /// proves nothing (it may never have been written, or was taken before the first read).
    /// Wire status `codex_queued_unverified`, reason `row_never_seen`.
    CodexRowNeverSeen,
    /// The thread has no turn yet, so Codex cannot queue to it. Wire status `queued_only`,
    /// reason `codex_no_turn_yet`.
    CodexNoTurnYet,
    /// The fixed notice was handed to Claude Code's inbox socket; not proof of reading.
    ClaudeWoken,
    /// The Claude socket post failed; the peer message remains stored.
    ClaudeWakeFailed,
    /// Another wake held the recipient lock for this attempt's whole wait, so this attempt posted
    /// nothing. It is NOT a claim that the holder's post covers this message: the holder may exit
    /// without posting again, so the message may not have been nudged and the sender may retry
    /// or escalate. Wire status `queued_only`, reason `wake_contended`.
    ClaudeWakeContended,
    /// A recent successful notice still covers unread messages of this incarnation.
    /// This attempt posted nothing; it is not proof of reading or of a new model turn.
    ClaudeWakePending,
    /// No post: this incarnation exhausted its durable six-reservation/ten-minute budget.
    ClaudeWakeRateLimited,
    /// The sender asked for no wake (`wake:false` / `--no-wake`) and NO wake was attempted. A
    /// Claude Code recipient surfaces the stored message on its next natural turn through its
    /// per-turn hook; a Codex recipient has no such hook, so a Codex send is never labelled
    /// this (it is woken and carries `wake_override`).
    StoredNoWake,
}
}

impl Delivery {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Delivery::QueuedOnly => "queued_only",
            Delivery::ClaudeWoken => "claude_woken",
            Delivery::ClaudeWakeFailed => "claude_wake_failed",
            // Nothing was posted, so the status is the "nothing attempted" one and the reason
            // carries the lock contention: `claude_wake_failed` would report a failed post.
            Delivery::ClaudeWakeContended => "queued_only",
            Delivery::ClaudeWakePending => "claude_wake_pending",
            Delivery::ClaudeWakeRateLimited => "claude_wake_rate_limited",
            Delivery::StoredNoWake => "stored_no_wake",
            Delivery::CodexWoken => "codex_woken",
            Delivery::CodexWakeFailed => "codex_wake_failed",
            Delivery::CodexQueued | Delivery::CodexWakePending => "codex_queued",
            Delivery::CodexQueuedUnverified | Delivery::CodexRowNeverSeen => {
                "codex_queued_unverified"
            }
            Delivery::CodexWakeDeferred => "codex_wake_pending",
            Delivery::CodexNoTurnYet | Delivery::CodexWakeInFlight => "queued_only",
        }
    }

    /// The additive `delivery_reason` tag, when the status carries one.
    #[must_use]
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Delivery::CodexWakePending => Some("wake_pending"),
            Delivery::CodexWakeInFlight => Some("wake_in_flight"),
            Delivery::CodexNoTurnYet => Some("codex_no_turn_yet"),
            Delivery::CodexRowNeverSeen => Some("row_never_seen"),
            Delivery::ClaudeWakeContended => Some("wake_contended"),
            _ => None,
        }
    }

    /// `status` or `status:reason`: the single static string the MCP backend carries
    /// (split again by `mcp::insert_delivery`).
    #[must_use]
    pub fn tagged(self) -> &'static str {
        match self {
            Delivery::CodexWakePending => "codex_queued:wake_pending",
            Delivery::CodexWakeInFlight => "queued_only:wake_in_flight",
            Delivery::CodexNoTurnYet => "queued_only:codex_no_turn_yet",
            Delivery::CodexRowNeverSeen => "codex_queued_unverified:row_never_seen",
            Delivery::ClaudeWakeContended => "queued_only:wake_contended",
            other => other.as_str(),
        }
    }
}

/// The two paths a wake spawn may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeSpec {
    codex_home: PathBuf,
    sqlite_home: PathBuf,
    session: Option<SessionIdentity>,
}

impl WakeSpec {
    /// The only production constructor: both paths come from a validated target.
    #[must_use]
    pub fn from_target(t: &WakeTarget) -> Self {
        Self {
            codex_home: t.codex_home().to_path_buf(),
            sqlite_home: t.sqlite_home().to_path_buf(),
            session: Some(SessionIdentity {
                pid: t.pid(),
                exact_start: t.exact_start(),
            }),
        }
    }

    /// A spec over two arbitrary dirs, for tests in this crate.
    #[cfg(all(test, unix))]
    pub(crate) fn for_test(codex_home: &Path, sqlite_home: &Path) -> Self {
        Self {
            codex_home: codex_home.to_path_buf(),
            sqlite_home: sqlite_home.to_path_buf(),
            session: None,
        }
    }

    /// The target's `CODEX_HOME`.
    #[must_use]
    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }
}

/// The fixed notice. It takes a count and nothing else, so no body text can reach argv.
#[must_use]
pub fn notice(n: usize) -> String {
    format!(
        "csq: {n} peer message(s) waiting \u{2014} call csq inbox(mark: \"read\"); \
         you may answer with the reply tool if it relates to your task"
    )
}

/// Resolve only candidates whose held-lock and top-level provenance `holds` confirms.
/// A confirmed explicit resume MAIN wins before fd ambiguity or child recency. Unconfirmed
/// launch/captured ids cannot bypass ambiguous discovery, and a discovered child is rejected.
#[must_use]
pub fn resolve_thread_id(
    from_launch: Option<String>,
    discover: &dyn Fn() -> crate::providers::codex::thread_id::ThreadDiscovery,
    captured: &dyn Fn() -> Option<String>,
    holds: &dyn Fn(&str) -> bool,
) -> Option<String> {
    use crate::providers::codex::thread_id::ThreadDiscovery;
    if let Some(id) = from_launch.as_ref().filter(|id| holds(id)) {
        return Some(id.clone());
    }
    let discovered = match discover() {
        ThreadDiscovery::Found(id) => Some(id).filter(|id| holds(id)),
        ThreadDiscovery::Ambiguous => return None,
        ThreadDiscovery::NoEvidence => None,
    };
    discovered
        .or_else(|| from_launch.filter(|id| holds(id)))
        .or_else(|| captured().filter(|id| holds(id)))
}

/// The argv (after the program) of a wake. Pure; the tests pin it.
#[must_use]
pub fn wake_argv(spec: &WakeSpec, thread: &str, n: usize) -> Vec<OsString> {
    wake_argv_with_notice(spec, thread, n, None)
}

fn wake_argv_with_notice(
    spec: &WakeSpec,
    thread: &str,
    n: usize,
    summary: Option<&super::store::PendingNotice>,
) -> Vec<OsString> {
    let mut sqlite = OsString::from("sqlite_home=");
    sqlite.push(spec.sqlite_home.as_os_str());
    vec![
        "-c".into(),
        sqlite,
        "queue".into(),
        "--thread".into(),
        thread.into(),
        "--message".into(),
        summary
            .map_or_else(|| notice(n), super::frame::render_sender_notice)
            .into(),
    ]
}

/// How the `codex` child is launched: the program and the two env values allowlisted besides
/// `CODEX_HOME` (the child's env is cleared first).
#[derive(Debug, Clone, Copy)]
pub struct Launcher<'a> {
    /// The `codex` program (a name resolved through `path`, or an absolute path).
    pub program: &'a OsStr,
    /// `PATH` for the child, if any.
    pub path: Option<&'a OsStr>,
    /// `HOME` for the child, if any.
    pub home: Option<&'a OsStr>,
}

/// Attempt one wake. `thread` is `None` when no exact id was found. `still_live` is called
/// immediately before the spawn; false means the target incarnation is gone.
/// Host precondition: the host process must not ignore SIGCHLD or reap children it did not spawn while a wake is in flight.
pub fn deliver(
    spec: &WakeSpec,
    still_live: &dyn Fn() -> bool,
    thread: Option<&str>,
    n: usize,
    launcher: Launcher<'_>,
    timeout: Duration,
) -> Delivery {
    deliver_with(
        spec,
        still_live,
        thread,
        n,
        launcher,
        timeout,
        DRAIN_WAIT,
        Instant::now() + WAKE_TOTAL,
    )
}

/// [`deliver`] with the post-queue drain watch and the overall `deadline` injected: the lock
/// wait, the spawn budget and the drain watch are each cut to what remains of `deadline`.
#[allow(clippy::too_many_arguments)]
pub fn deliver_with(
    spec: &WakeSpec,
    still_live: &dyn Fn() -> bool,
    thread: Option<&str>,
    n: usize,
    launcher: Launcher<'_>,
    timeout: Duration,
    drain_wait: Duration,
    deadline: Instant,
) -> Delivery {
    deliver_with_item(
        spec, still_live, thread, n, launcher, timeout, drain_wait, deadline,
    )
    .0
}

/// Delivery plus the acknowledged item durably retained by this attempt under its wake lock.
/// A failed sidecar write yields no correlation; an older sidecar is never substituted.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn deliver_with_item(
    spec: &WakeSpec,
    still_live: &dyn Fn() -> bool,
    thread: Option<&str>,
    n: usize,
    launcher: Launcher<'_>,
    timeout: Duration,
    drain_wait: Duration,
    deadline: Instant,
) -> (Delivery, Option<String>) {
    deliver_with_recorder(
        spec,
        still_live,
        thread,
        n,
        launcher,
        timeout,
        drain_wait,
        deadline,
        &record_item,
    )
}

/// Deliver a stored sender summary; only sockets may receive its framed body preview.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn deliver_with_notice(
    spec: &WakeSpec,
    still_live: &dyn Fn() -> bool,
    thread: Option<&str>,
    summary: &super::store::PendingNotice,
    launcher: Launcher<'_>,
    timeout: Duration,
    drain_wait: Duration,
    deadline: Instant,
) -> (Delivery, Option<String>) {
    deliver_with_notice_recorder(
        spec,
        still_live,
        thread,
        summary.count,
        Some(summary),
        launcher,
        timeout,
        drain_wait,
        deadline,
        &record_item,
    )
}

#[allow(clippy::too_many_arguments)]
fn deliver_with_recorder(
    spec: &WakeSpec,
    still_live: &dyn Fn() -> bool,
    thread: Option<&str>,
    n: usize,
    launcher: Launcher<'_>,
    timeout: Duration,
    drain_wait: Duration,
    deadline: Instant,
    record: &dyn Fn(&Path, &str, &str, &QueueEvidence) -> std::io::Result<()>,
) -> (Delivery, Option<String>) {
    deliver_with_notice_recorder(
        spec, still_live, thread, n, None, launcher, timeout, drain_wait, deadline, record,
    )
}

#[allow(clippy::too_many_arguments)]
fn deliver_with_notice_recorder(
    spec: &WakeSpec,
    still_live: &dyn Fn() -> bool,
    thread: Option<&str>,
    n: usize,
    summary: Option<&super::store::PendingNotice>,
    launcher: Launcher<'_>,
    timeout: Duration,
    drain_wait: Duration,
    deadline: Instant,
    record: &dyn Fn(&Path, &str, &str, &QueueEvidence) -> std::io::Result<()>,
) -> (Delivery, Option<String>) {
    let item = std::cell::RefCell::new(None);
    let delivery = deliver_observed(
        spec,
        still_live,
        thread,
        n,
        summary,
        launcher,
        timeout,
        drain_wait,
        deadline,
        record,
        &|id| *item.borrow_mut() = Some(id.to_owned()),
    );
    let expected = if matches!(
        delivery,
        Delivery::CodexQueued
            | Delivery::CodexWakePending
            | Delivery::CodexQueuedUnverified
            | Delivery::CodexRowNeverSeen
    ) {
        item.into_inner()
    } else {
        None
    };
    (delivery, expected)
}

#[allow(clippy::too_many_arguments)]
fn deliver_observed(
    spec: &WakeSpec,
    still_live: &dyn Fn() -> bool,
    thread: Option<&str>,
    n: usize,
    summary: Option<&super::store::PendingNotice>,
    launcher: Launcher<'_>,
    timeout: Duration,
    drain_wait: Duration,
    deadline: Instant,
    record: &dyn Fn(&Path, &str, &str, &QueueEvidence) -> std::io::Result<()>,
    observed: &dyn Fn(&str),
) -> Delivery {
    let left = || deadline.saturating_duration_since(Instant::now());
    let Some(thread) = thread else {
        return Delivery::QueuedOnly;
    };
    if left().is_zero() || !still_live() {
        return Delivery::CodexWakeFailed;
    }
    let db = spec.sqlite_home.join(QUEUE_DB);
    // ONE wake at a time per recipient handle dir, shared by live sends and the deferred
    // retry: the dedupe check and the spawn that writes the row are one critical section, so
    // two concurrent wakes cannot both see "nothing pending". `flock` is released by the
    // kernel when the holder dies, so there is no stale lock to detect. The wait is bounded
    // by the wake budget; a timeout proves only contention, not a queued Codex row.
    #[cfg(unix)]
    let _guard = match lock_wake(&spec.codex_home, timeout.min(left())) {
        Ok(Some(g)) => g,
        Ok(None) => return Delivery::CodexWakeInFlight,
        Err(e) => {
            // NAMED, never silent: a lock failure under table pressure is otherwise
            // indistinguishable from a spawn failure in the Delivery alone.
            tracing::warn!(
                error_kind = "wake_lock_failed",
                errno = e.raw_os_error().unwrap_or(0),
                "wake lock could not be acquired"
            );
            return Delivery::CodexWakeFailed;
        }
    };
    // One pending csq wake per thread: a stuck session accumulates one, not one per send.
    if let Some((delivery, id)) = pending_bound(spec, thread, deadline) {
        observed(&id);
        #[cfg(unix)]
        if crate::providers::codex::managed_backend::is_configured(&spec.codex_home) {
            return start_managed_pending(spec, thread, &id, delivery, deadline, still_live);
        }
        return delivery;
    }
    if left().is_zero() || !still_live() {
        return Delivery::CodexWakeFailed;
    }
    let mut evidence = QueueEvidence {
        session: spec.session,
        ..QueueEvidence::default()
    };
    let exit = match queue_once_observed(
        spec,
        thread,
        n,
        summary,
        launcher,
        timeout.min(left()),
        &mut |stdout, child_deadline| {
            evidence.observe(&db, thread, stdout, child_deadline.min(deadline));
        },
    ) {
        Ok(e) => {
            #[cfg(all(test, unix))]
            record_exit_probe(Some(thread), &e);
            e
        }
        Err(d) => return d, // All errors here precede spawning; a spawned child is uncertain.
    };
    let id = match interpret(&exit, thread) {
        Ok(id) => id,
        Err(d) => return d,
    };
    // An acknowledgement survives a timeout or nonzero exit. It cannot, however, authorize
    // recreating state in a departed recipient's handle dir or a new verification past budget.
    if !still_live() {
        return Delivery::CodexQueuedUnverified;
    }
    // ACK is correlation, not proof of visibility or consumption. Retain it even when
    // the read failed, so uncertainty cannot create another queue item on every retry.
    let verified = evidence.id.as_deref() == Some(id.as_str())
        && evidence.identity_valid()
        && !left().is_zero();
    if verified && evidence.taken {
        return Delivery::CodexWoken;
    }
    if !verified {
        evidence.seen = false;
        evidence.taken = false;
    }
    if record(&spec.codex_home, thread, &id, &evidence).is_err() {
        tracing::debug!(event = "wake_item_record", outcome = "write_failed");
    } else {
        observed(&id);
    }
    #[cfg(unix)]
    if crate::providers::codex::managed_backend::is_configured(&spec.codex_home) {
        let _ = start_managed_pending(
            spec,
            thread,
            &id,
            Delivery::CodexQueuedUnverified,
            deadline,
            still_live,
        );
    }
    if !verified {
        return Delivery::CodexQueuedUnverified;
    }
    #[cfg(unix)]
    drop(_guard);
    watch_drain_reader(
        &db,
        &mut evidence.reader,
        &id,
        Some(thread),
        drain_wait.min(left()),
        deadline,
        evidence.seen,
        still_live,
    )
}

/// The ONE start gate. Every path that starts an already-queued csq notice
/// calls this under the shared wake lock, so the facts it decides on are read
/// fresh at start time:
///
/// - the sidecar names THIS item and thread, belongs to THIS session
///   incarnation, is marked seen, and was written for THIS physical handle;
/// - the sidecar names the SAME queue database the reader opened, the row is
///   still present there, and the database identity did not change;
/// - the row's text is the csq notice (never a user prompt), matching
///   `delete_notice`'s exact-wording check on its first line.
///
/// The native idle/`canAcceptDirectInput` facts are re-checked inside
/// `start_existing_queue_item`'s own connection, also under this lock.
#[cfg(unix)]
fn validate_start_item(
    codex_home: &Path,
    sqlite_home: &Path,
    thread: &str,
    id: &str,
    expected_session: Option<SessionIdentity>,
    deadline: Instant,
) -> std::io::Result<QueueRead> {
    let refuse = |reason: &str| std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason);
    let item = read_item(codex_home).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no recorded csq wake item")
    })?;
    if item.id != id || item.thread != thread {
        return Err(refuse("not the recorded csq wake item"));
    }
    if item.session != expected_session {
        return Err(refuse("wake item belongs to another session incarnation"));
    }
    if !item.seen {
        return Err(refuse("wake item was never observed queued"));
    }
    if item.handle != handle_identity(codex_home) {
        return Err(refuse("wake handle identity changed"));
    }
    let db = sqlite_home.join(QUEUE_DB);
    let reader =
        QueueRead::open(&db, deadline).ok_or_else(|| refuse("wake queue database unavailable"))?;
    if item.queue != Some(reader.identity) {
        return Err(refuse("wake item names another queue database"));
    }
    if reader.present(id, Some(thread), deadline) != Some(true) || !reader.identity_valid() {
        return Err(refuse("wake item is not present in the bound queue"));
    }
    let text = reader
        .notice_text(id, Some(thread))
        .ok_or_else(|| refuse("wake item has no readable text"))?;
    if !text_is_csq_notice(&text) {
        return Err(refuse("queued row is not the csq notice"));
    }
    Ok(reader)
}

/// Explicitly start the existing notice on its owning native backend. Automatic
/// queue dispatch intentionally skips Interrupted; this supported RPC does not.
#[cfg(unix)]
fn start_managed_pending(
    spec: &WakeSpec,
    thread: &str,
    id: &str,
    fallback: Delivery,
    deadline: Instant,
    still_live: &dyn Fn() -> bool,
) -> Delivery {
    if !still_live() || Instant::now() >= deadline {
        return Delivery::CodexQueuedUnverified;
    }
    // Both start paths decide on the SAME fresh facts, under the caller's
    // wake lock: sidecar identity/session/seen/handle, the bound queue DB and
    // its row, and the queued text being the csq notice.
    let Ok(reader) = validate_start_item(
        &spec.codex_home,
        &spec.sqlite_home,
        thread,
        id,
        spec.session,
        deadline,
    ) else {
        return Delivery::CodexQueuedUnverified;
    };
    let db = spec.sqlite_home.join(QUEUE_DB);
    // Snapshot the physical handle: the start must not cross a handle swap.
    let handle_before = handle_identity(&spec.codex_home);
    let Some(session) = spec.session else {
        return Delivery::CodexQueuedUnverified;
    };
    let recipient = crate::providers::codex::managed_backend::LauncherIdentity {
        pid: session.pid,
        started_exact: session.exact_start,
    };
    let started = crate::providers::codex::managed_backend::start_existing_queue_item(
        &spec.codex_home,
        &spec.sqlite_home,
        &recipient,
        thread,
        id,
        crate::providers::codex::managed_backend::StartAdmission::AdmitAnyStatus,
        deadline
            .saturating_duration_since(Instant::now())
            .min(WAKE_TIMEOUT),
    );
    if !still_live() || Instant::now() >= deadline {
        return Delivery::CodexQueuedUnverified;
    }
    if started.is_err() {
        return fallback;
    }
    if handle_identity(&spec.codex_home) != handle_before || !reader.identity_valid() {
        return Delivery::CodexQueuedUnverified;
    }
    watch_drain_reader(
        &db,
        &mut Some(reader),
        id,
        Some(thread),
        DRAIN_WAIT,
        deadline,
        true,
        still_live,
    )
}

/// Start a queued notice on the owning NATIVE backend under the SAME wake
/// lock every other wake path takes. Used by the child-completion watcher,
/// which must never race a live send's queue/start.
///
/// `WouldBlock` means another wake holds the recipient; the caller does
/// nothing and the notice stays queued for the next opportunity.
#[cfg(unix)]
pub fn start_queued_notice_native(
    codex_home: &Path,
    sqlite_home: &Path,
    recipient: &crate::providers::codex::managed_backend::LauncherIdentity,
    thread: &str,
    item: &str,
    wait: Duration,
) -> std::io::Result<String> {
    let guard = lock_wake(codex_home, wait)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::WouldBlock, "wake lock is held"))?;
    let deadline = Instant::now() + wait;
    // Defense in depth: only the wake path's OWN recorded notice is startable.
    // A queue may hold user-submitted prompts; the watcher must never start
    // one. The gate reads every fact fresh under the lock, and the native
    // idle/canAcceptDirectInput facts are re-read inside the start's own
    // connection, also under this lock.
    let reader = validate_start_item(
        codex_home,
        sqlite_home,
        thread,
        item,
        Some(SessionIdentity {
            pid: recipient.pid,
            exact_start: recipient.started_exact,
        }),
        deadline,
    )?;
    let started = crate::providers::codex::managed_backend::start_existing_queue_item(
        codex_home,
        sqlite_home,
        recipient,
        thread,
        item,
        crate::providers::codex::managed_backend::StartAdmission::RequireIdle,
        wait,
    );
    if started.is_err() {
        drop(guard);
        return started;
    }
    // The same drain/clear step the live-send path runs, with its OWN bounded
    // window: the lock + validation + start already spent part of `wait`, and
    // a real start must never be reported "not confirmed" because a shared
    // deadline had passed.
    let delivery = watch_drain_reader(
        &sqlite_home.join(QUEUE_DB),
        &mut Some(reader),
        item,
        Some(thread),
        DRAIN_WAIT,
        Instant::now() + DRAIN_WAIT,
        true,
        &|| true,
    );
    drop(guard);
    match delivery {
        Delivery::CodexWoken => started,
        other => Err(std::io::Error::other(format!(
            "native queue start not confirmed: {}",
            other.as_str()
        ))),
    }
}

/// What the `codex queue` child left behind once it exited.
struct Exit {
    ok: bool,
    completed: bool,
    stdout: String,
    stderr: String,
}

/// Spawn `codex queue` and wait (bounded by `timeout`) for it to exit. The child's stdout and
/// stderr use nonblocking pipes on Unix. Polling and reads never wait for descendant EOF;
/// retained memory is capped and each drain is bounded. Non-Unix retains private output files.
#[cfg(all(test, unix))]
fn queue_once(
    spec: &WakeSpec,
    thread: &str,
    n: usize,
    launcher: Launcher<'_>,
    timeout: Duration,
) -> Result<Exit, Delivery> {
    queue_once_observed(spec, thread, n, None, launcher, timeout, &mut |_, _| {})
}

#[allow(clippy::too_many_arguments)]
fn queue_once_observed(
    spec: &WakeSpec,
    thread: &str,
    n: usize,
    summary: Option<&super::store::PendingNotice>,
    launcher: Launcher<'_>,
    timeout: Duration,
    observe: &mut dyn FnMut(&str, Instant),
) -> Result<Exit, Delivery> {
    #[cfg(unix)]
    if crate::providers::codex::managed_backend::is_configured(&spec.codex_home) {
        let session = spec.session.ok_or(Delivery::CodexQueuedUnverified)?;
        let recipient = crate::providers::codex::managed_backend::LauncherIdentity {
            pid: session.pid,
            started_exact: session.exact_start,
        };
        let fallback = super::store::PendingNotice::count_only(n);
        let id = crate::providers::codex::managed_backend::enqueue_summary(
            &spec.codex_home,
            &spec.sqlite_home,
            &recipient,
            thread,
            summary.unwrap_or(&fallback),
            timeout,
        )
        .map_err(|_| Delivery::CodexQueuedUnverified)?;
        let stdout = format!("Queued message {id} for thread {thread}\n");
        observe(&stdout, Instant::now() + timeout);
        return Ok(Exit {
            ok: true,
            completed: true,
            stdout,
            stderr: String::new(),
        });
    }
    if timeout.is_zero() {
        return Err(Delivery::CodexWakeFailed);
    }
    let deadline = Instant::now() + timeout;
    #[cfg(not(unix))]
    let (Ok(out_f), Ok(err_f)) = (
        unlinked_file(&spec.codex_home),
        unlinked_file(&spec.codex_home),
    ) else {
        return Err(Delivery::CodexWakeFailed);
    };
    #[cfg(not(unix))]
    let (Ok(out_c), Ok(err_c)) = (out_f.try_clone(), err_f.try_clone()) else {
        return Err(Delivery::CodexWakeFailed);
    };
    let mut cmd = Command::new(launcher.program);
    cmd.args(wake_argv_with_notice(spec, thread, n, summary))
        .env_clear()
        .env("CODEX_HOME", &spec.codex_home)
        .stdin(Stdio::null());
    #[cfg(unix)]
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(not(unix))]
    cmd.stdout(Stdio::from(out_c)).stderr(Stdio::from(err_c));
    if let Some(p) = launcher.path {
        cmd.env("PATH", p);
    }
    if let Some(h) = launcher.home {
        cmd.env("HOME", h);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own SESSION: `setsid` makes the child a session and group leader (so a timeout's
        // `kill(-pid)` still reaches the whole group) AND drops the sender's controlling
        // terminal. Without that, for up to the wake budget the child (argv[0] `codex`, the
        // target's `CODEX_HOME`) is listed on macOS as a session owning the target's home, and
        // the woken model's own caller resolution reads `undetermined`.
        // SAFETY: the closure runs between fork and exec and calls only `setsid`, which is
        // async-signal-safe and touches no memory.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    if Instant::now() >= deadline {
        return Err(Delivery::CodexWakeFailed);
    }
    // Reject auto-reaping senders before creating a child or process group. A child
    // remains wait-owned through group cleanup; only afterwards may it be reaped.
    #[cfg(unix)]
    if !child_wait_policy_safe() {
        return Err(Delivery::QueuedOnly);
    }
    // The SPAWN is retried on transient table pressure (see `transient_start_error`):
    // nothing has been sent or recorded, so the retry is the SAME attempt. A static
    // exhaustion still refuses, now NAMED instead of silent.
    let mut start_retries = 0usize;
    let mut child = loop {
        match cmd.spawn() {
            Ok(child) => break child,
            Err(e)
                if transient_start_error(&e)
                    && start_retries < START_RETRIES
                    && Instant::now() < deadline =>
            {
                start_retries += 1;
                #[cfg(all(test, unix))]
                START_RETRY_EVENTS.with(|c| c.set(c.get() + 1));
                tracing::warn!(
                    error_kind = "wake_spawn_retry",
                    errno = e.raw_os_error().unwrap_or(0),
                    "wake helper spawn hit transient table pressure; retrying"
                );
                // The hook fires AFTER the failed attempt and BEFORE the pause, so a
                // row releases its held write descriptor on the EVENT itself.
                #[cfg(all(test, unix))]
                SPAWN_RETRY_HOOK.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().as_mut() {
                        hook();
                    }
                });
                // Capped at the time left before the deadline (D237 R2 corr L-b), so
                // the documented immediate refusal near the deadline stays true.
                std::thread::sleep(
                    START_RETRY_PAUSE.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(e) => {
                tracing::warn!(
                    error_kind = "wake_spawn_failed",
                    errno = e.raw_os_error().unwrap_or(0),
                    "wake helper could not be spawned"
                );
                return Err(Delivery::CodexWakeFailed);
            }
        }
    };
    drop(cmd);
    #[cfg(unix)]
    let mut output = match PipeOutput::new(&mut child) {
        Ok(output) => output,
        Err(_) => {
            kill_group(&mut child);
            return Ok(Exit {
                ok: false,
                completed: false,
                stdout: String::new(),
                stderr: String::new(),
            });
        }
    };
    loop {
        // Probe without reaping. Cleanup signals only an owned group; an auto-reaped child
        // (Gone) has no recoverable status and must never be signalled. Its write is unknown.
        #[cfg(unix)]
        {
            let drained = output.drain();
            observe(&String::from_utf8_lossy(&output.stdout), deadline);
            if drained.is_err() {
                kill_group(&mut child);
                return Ok(output.exit(false, false));
            }
            match child_state(&child) {
                ChildState::ExitedUnreaped => {
                    kill_group_signal(&child);
                    let drained = output.drain();
                    let status = child.wait();
                    observe(&String::from_utf8_lossy(&output.stdout), deadline);
                    return Ok(output.exit(
                        status.as_ref().is_ok_and(|s| s.success()),
                        drained.is_ok() && status.is_ok(),
                    ));
                }
                ChildState::Gone => return Ok(output.exit(false, false)),
                ChildState::Running => {}
            }
        }
        #[cfg(not(unix))]
        match child.try_wait() {
            Ok(Some(st)) => {
                let stdout = read_capped(&out_f);
                observe(&stdout, deadline);
                return Ok(Exit {
                    ok: st.success(),
                    completed: true,
                    stdout,
                    stderr: read_capped(&err_f),
                });
            }
            Err(_) => {
                kill_group(&mut child);
                return Ok(Exit {
                    ok: false,
                    completed: false,
                    stdout: read_capped(&out_f),
                    stderr: read_capped(&err_f),
                });
            }
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            kill_group(&mut child);
            #[cfg(unix)]
            {
                let _ = output.drain();
                return Ok(output.exit(false, false));
            }
            #[cfg(not(unix))]
            return Ok(Exit {
                ok: false,
                completed: false,
                stdout: read_capped(&out_f),
                stderr: read_capped(&err_f),
            });
        }
        #[cfg(unix)]
        if output.poll(deadline).is_err() {
            kill_group(&mut child);
            let _ = output.drain();
            return Ok(output.exit(false, false));
        }
        #[cfg(not(unix))]
        std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// The queue database inside the target's `sqlite_home`.
const QUEUE_DB: &str = "queue_1.sqlite";

/// Most bytes read from a child's stdout or stderr.
const OUTPUT_CAP: u64 = 4096;

/// Pipes remain bounded even when a descendant keeps a write end open forever.
#[cfg(unix)]
struct PipeOutput {
    out: std::process::ChildStdout,
    err: std::process::ChildStderr,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    out_eof: bool,
    err_eof: bool,
}

#[cfg(unix)]
impl PipeOutput {
    fn new(child: &mut std::process::Child) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let out = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("missing_stdout"))?;
        let err = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("missing_stderr"))?;
        for fd in [out.as_raw_fd(), err.as_raw_fd()] {
            // SAFETY: these are owned, open pipe descriptors; fcntl only changes their flags.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags == -1 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }
        Ok(Self {
            out,
            err,
            stdout: Vec::new(),
            stderr: Vec::new(),
            out_eof: false,
            err_eof: false,
        })
    }

    fn exit(&self, ok: bool, completed: bool) -> Exit {
        Exit {
            ok,
            completed,
            stdout: String::from_utf8_lossy(&self.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&self.stderr).into_owned(),
        }
    }

    fn drain(&mut self) -> std::io::Result<()> {
        fn drain_one(
            reader: &mut impl std::io::Read,
            kept: &mut Vec<u8>,
            eof: &mut bool,
        ) -> std::io::Result<()> {
            let mut buffer = [0u8; 4096];
            // A flooding descendant cannot monopolize this loop or defeat the deadline.
            for _ in 0..16 {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        *eof = true;
                        break;
                    }
                    Ok(n) => {
                        let retain = n.min((OUTPUT_CAP as usize).saturating_sub(kept.len()));
                        kept.extend_from_slice(&buffer[..retain]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }
        drain_one(&mut self.out, &mut self.stdout, &mut self.out_eof)?;
        drain_one(&mut self.err, &mut self.stderr, &mut self.err_eof)
    }

    fn poll(&self, deadline: Instant) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let mut fds = [
            libc::pollfd {
                fd: if self.out_eof {
                    -1
                } else {
                    self.out.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if self.err_eof {
                    -1
                } else {
                    self.err.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait = deadline.saturating_duration_since(Instant::now()).min(POLL);
        let millis = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: fds is a writable array of two valid pollfd values and timeout is bounded.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }
}

/// An unlinked, private, read-write temp file in `dir` (the recipient's handle dir).
#[cfg(not(unix))]
fn unlinked_file(dir: &Path) -> std::io::Result<std::fs::File> {
    let path = crate::platform::fs::unique_tmp_path(&dir.join(".csq-wake-out"));
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let f = o.open(&path)?;
    if std::fs::remove_file(&path).is_err() {
        tracing::debug!(event = "wake_out_file", outcome = "unlink_failed");
    }
    Ok(f)
}

/// The first [`OUTPUT_CAP`] bytes of what the child wrote. A file, so the read ends at the
/// current end of file even if a straggler still holds the descriptor open.
#[cfg(not(unix))]
fn read_capped(mut f: &std::fs::File) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(0)).is_ok() {
        let _ = f.take(OUTPUT_CAP).read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Turn an exited `codex queue` into the queued item id, or the final [`Delivery`].
fn interpret(e: &Exit, thread: &str) -> Result<String, Delivery> {
    // The known queue protocol acknowledges a WRITE. Later failure does not undo it.
    if let Some(id) = parse_item_id(&e.stdout, thread) {
        return Ok(id);
    }
    // Only the known negative protocol can establish that the spawned helper refused the
    // operation. A timeout, lost child status or arbitrary nonzero exit cannot prove that.
    if e.completed
        && !e.ok
        && e.stderr.contains("thread/queue/add failed:")
        && e.stderr.contains(NO_ROLLOUT)
    {
        return Err(Delivery::CodexNoTurnYet);
    }
    Err(Delivery::CodexQueuedUnverified)
}

/// Guard for the recipient's wake lock, released on `Drop`. Releasing
/// EXPLICITLY matters for the same reason as the login lock (G2b item 2):
/// POSIX flock is bound to the open file description, so a fork from any
/// thread of the holding process keeps the lock alive past this close
/// until the child execs (`FD_CLOEXEC`) or exits; `LOCK_UN` on any
/// duplicate releases the whole description.
#[cfg(unix)]
pub(crate) struct WakeLock(std::fs::File);

#[cfg(unix)]
impl Drop for WakeLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the guard owns a live descriptor created only after a
        // successful LOCK_EX; flock touches no Rust memory.
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
            tracing::warn!(
                error_kind = "wake_lock_unlock_failed",
                errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                "wake lock could not be released"
            );
        }
    }
}

#[cfg(all(test, unix))]
thread_local! {
    /// Per-thread count of `EWOULDBLOCK` wake-lock attempts, plus a one-shot
    /// signal fired when the count first reaches 1. Test-only: a test that holds
    /// the lock releases it only after the waiter has genuinely MET the held
    /// lock, instead of racing the waiter's pre-lock steps.
    static WAKE_LOCK_BUSY: std::cell::RefCell<(u32, Option<std::sync::mpsc::Sender<()>>)> =
        const { std::cell::RefCell::new((0, None)) };
}

#[cfg(all(test, unix))]
fn note_wake_lock_busy() {
    WAKE_LOCK_BUSY.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.0 += 1;
        if slot.0 == 1 {
            if let Some(signal) = slot.1.take() {
                let _ = signal.send(());
            }
        }
    });
}

#[cfg(all(test, unix))]
struct WakeLockBusySignalRestore;

#[cfg(all(test, unix))]
impl Drop for WakeLockBusySignalRestore {
    fn drop(&mut self) {
        WAKE_LOCK_BUSY.with(|slot| slot.borrow_mut().1 = None);
    }
}

/// Run `action` with a one-shot "the wake lock was busy" signal armed on this
/// thread; it fires on the FIRST `EWOULDBLOCK` the action's [`lock_wake`] sees.
#[cfg(all(test, unix))]
fn with_wake_lock_busy_signal<T>(
    signal: std::sync::mpsc::Sender<()>,
    action: impl FnOnce() -> T,
) -> T {
    WAKE_LOCK_BUSY.with(|slot| slot.borrow_mut().1 = Some(signal));
    let _restore = WakeLockBusySignalRestore;
    action()
}

/// A START-step failure caused by TRANSIENT table pressure, not by the scenario:
/// the wake lock could not be opened, or the helper could not be forked/exec'd,
/// because this PROCESS is momentarily out of file descriptors, process slots or
/// memory, or because a sibling fork still holds a write descriptor on the
/// freshly written helper (ETXTBSY, the race documented in `cli_deps::cli_shim`).
/// Nothing has been spawned, locked or recorded at either site, so retrying the
/// same start is not a new attempt and creates nothing. The retry is bounded by
/// BOTH `START_RETRIES` and the caller's wait deadline, so a static exhaustion or
/// a zero/short wait still ends in the same refusal immediately.
const START_RETRIES: usize = 10;
const START_RETRY_PAUSE: Duration = Duration::from_millis(50);

// Test-only count of retried START steps (D237 R2 corr/sec L1): a pressure row
// must assert the retry ACTUALLY fired, so a slow runner where the pressure had
// already cleared cannot make the row pass vacuously. THREAD-LOCAL (D237 R2
// corr MED): both retry sites run synchronously on the caller's thread, so a
// sibling test's retry can never satisfy this row's assertion.
#[cfg(all(test, unix))]
thread_local! {
    static START_RETRY_EVENTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    // Test-only: invoked on the SPAWN retry path, after the attempt that failed,
    // so a row can release its held write descriptor on the EVENT (the first
    // failed exec) instead of on a timer that a loaded setup can outrun.
    static SPAWN_RETRY_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(all(test, unix))]
fn start_retry_events() -> usize {
    START_RETRY_EVENTS.with(std::cell::Cell::get)
}
#[cfg(all(test, unix))]
fn reset_start_retry_events() {
    START_RETRY_EVENTS.with(|c| c.set(0));
}
// Linux-only: their sole caller is the ETXTBSY row, and macOS never produces
// ETXTBSY (it execs a file held open for writing), so on darwin these would be
// dead code under `-D warnings`.
#[cfg(all(test, unix, target_os = "linux"))]
fn with_spawn_retry_hook<T>(hook: Box<dyn FnMut()>, body: impl FnOnce() -> T) -> T {
    SPAWN_RETRY_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
    let _restore = SpawnRetryHookRestore;
    body()
}
#[cfg(all(test, unix, target_os = "linux"))]
struct SpawnRetryHookRestore;
#[cfg(all(test, unix, target_os = "linux"))]
impl Drop for SpawnRetryHookRestore {
    fn drop(&mut self) {
        SPAWN_RETRY_HOOK.with(|slot| *slot.borrow_mut() = None);
    }
}

fn transient_start_error(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            e.raw_os_error(),
            Some(c) if c == libc::EAGAIN
                || c == libc::EMFILE
                || c == libc::ENFILE
                || c == libc::ENOMEM
                || c == libc::ETXTBSY
        )
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// `flock` the recipient's wake lock file, waiting at most `wait`. `Ok(None)`: still held by
/// another wake when the wait ended.
#[cfg(unix)]
fn lock_wake(home: &Path, wait: Duration) -> std::io::Result<Option<WakeLock>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let deadline = Instant::now() + wait;
    // The OPEN is retried on transient table pressure (see `transient_start_error`):
    // a sibling thread's fd burst must not turn this wake into `CodexWakeFailed`.
    let mut retries = 0usize;
    let f = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(home.join(LOCK_FILE))
        {
            Ok(f) => break f,
            Err(e)
                if transient_start_error(&e)
                    && retries < START_RETRIES
                    && Instant::now() < deadline =>
            {
                retries += 1;
                #[cfg(all(test, unix))]
                START_RETRY_EVENTS.with(|c| c.set(c.get() + 1));
                tracing::warn!(
                    error_kind = "wake_lock_open_retry",
                    errno = e.raw_os_error().unwrap_or(0),
                    "wake lock open hit transient table pressure; retrying"
                );
                // Capped at the time left before the deadline (D237 R2 corr L-b).
                std::thread::sleep(
                    START_RETRY_PAUSE.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(e) => return Err(e),
        }
    };
    loop {
        // SAFETY: `flock` takes a valid open descriptor and an integer; it touches no memory.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(WakeLock(f)));
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) && e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
        #[cfg(all(test, unix))]
        note_wake_lock_busy();
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(POLL);
    }
}

/// The lock file name in the recipient's handle dir.
#[cfg(unix)]
const LOCK_FILE: &str = ".csq-wake.lock";

/// The sidecar naming the queue row csq itself last queued for the session.
const ITEM_FILE: &str = ".csq-wake-item";

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Debug)]
struct SessionIdentity {
    pid: u32,
    exact_start: u64,
}

#[cfg(all(test, unix))]
const TEST_SESSION: SessionIdentity = SessionIdentity {
    pid: 42,
    exact_start: 1_000_000_001,
};

#[derive(serde::Serialize, serde::Deserialize)]
struct Item {
    thread: String,
    id: String,
    #[serde(default)]
    queue: Option<QueueIdentity>,
    #[serde(default)]
    handle: Option<QueueIdentity>,
    #[serde(default)]
    seen: bool,
    #[serde(default)]
    session: Option<SessionIdentity>,
}

fn handle_identity(home: &Path) -> Option<QueueIdentity> {
    let meta = std::fs::symlink_metadata(home).ok()?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(QueueIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn record_item(
    home: &Path,
    thread: &str,
    id: &str,
    evidence: &QueueEvidence,
) -> std::io::Result<()> {
    let handle = handle_identity(home)
        .ok_or_else(|| std::io::Error::other("wake handle identity unavailable"))?;
    let queue = evidence.reader.as_ref().map(|r| r.identity);
    let bytes = serde_json::to_vec(&Item {
        thread: thread.to_string(),
        id: id.to_string(),
        queue,
        handle: Some(handle),
        seen: evidence.seen && evidence.id.as_deref() == Some(id),
        session: evidence.session,
    })
    .map_err(std::io::Error::other)?;
    if handle_identity(home) != Some(handle) {
        return Err(std::io::Error::other("wake handle identity changed"));
    }
    crate::messaging::deferred::write_private_atomic(&home.join(ITEM_FILE), &bytes)?;
    if handle_identity(home) != Some(handle) {
        return Err(std::io::Error::other("wake handle identity changed"));
    }
    Ok(())
}

#[cfg(all(test, unix))]
fn record_legacy_item(home: &Path, thread: &str, id: &str) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(&Item {
        thread: thread.to_owned(),
        id: id.to_owned(),
        queue: None,
        handle: None,
        seen: false,
        session: None,
    })
    .map_err(std::io::Error::other)?;
    crate::messaging::deferred::write_private_atomic(&home.join(ITEM_FILE), &bytes)
}

fn read_item(home: &Path) -> Option<Item> {
    let bytes =
        crate::platform::fs::read_regular_nofollow_bounded(&home.join(ITEM_FILE), 1024).ok()??;
    serde_json::from_slice(&bytes).ok()
}

/// The private sidecar's recorded item. Read it only to correlate an outcome
/// that actually queued or deduped; it is not evidence for a QueuedOnly attempt.
#[must_use]
pub fn recorded_item_id(home: &Path) -> Option<String> {
    read_item(home).map(|it| it.id)
}

/// Prove consumption only for this validated target's exact process incarnation,
/// previously witnessed item/thread, physical handle and unchanged queue database.
#[must_use]
pub fn queued_item_taken_for_target(target: &WakeTarget, expected: &str) -> bool {
    queued_item_taken_for_target_with(target, expected, &|| target.still_live())
}

fn queued_item_taken_for_target_with(
    target: &WakeTarget,
    expected: &str,
    still_live: &dyn Fn() -> bool,
) -> bool {
    let deadline = Instant::now() + Duration::from_millis(200);
    still_live()
        && queued_item_taken_bound(
            target.codex_home(),
            target.sqlite_home(),
            expected,
            SessionIdentity {
                pid: target.pid(),
                exact_start: target.exact_start(),
            },
        )
        && still_live()
        && Instant::now() < deadline
}

fn queued_item_taken_bound(
    codex_home: &Path,
    sqlite_home: &Path,
    expected: &str,
    session: SessionIdentity,
) -> bool {
    let Some(it) = read_item(codex_home) else {
        return false;
    };
    let Some(recorded_session) = it.session else {
        return false;
    };
    if recorded_session.pid != session.pid || recorded_session.exact_start != session.exact_start {
        return false;
    }
    if it.id != expected
        || !it.seen
        || it.handle.is_none()
        || handle_identity(codex_home) != it.handle
    {
        return false;
    }
    let deadline = Instant::now() + Duration::from_millis(200);
    let Some(reader) = QueueRead::open(&sqlite_home.join(QUEUE_DB), deadline) else {
        return false;
    };
    if it.queue != Some(reader.identity) {
        return false;
    }
    reader.present(&it.id, Some(&it.thread), deadline) == Some(false)
        && reader.identity_valid()
        && handle_identity(codex_home) == it.handle
        && Instant::now() < deadline
}

/// The item id in native `Queued message <item-id> for thread <thread-id>.`.
/// The managed backend adapter also supplies the same frame without the period.
/// The id is a bound
/// parameter later, but is still restricted to a plain token.
fn parse_item_id(stdout: &str, thread: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let ack = line.trim().strip_prefix("Queued message ")?;
        let (id, acknowledged_thread) = ack.split_once(" for thread ")?;
        let acknowledged_thread = acknowledged_thread
            .strip_suffix('.')
            .unwrap_or(acknowledged_thread);
        let plain = !id.is_empty()
            && id.len() <= 64
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        (plain && acknowledged_thread == thread).then(|| id.to_owned())
    })
}

/// Evidence belongs only to the item acknowledged by THIS child for THIS thread. A stale
/// sidecar or another queue row never supplies the id, and first absence proves no take.
#[derive(Default)]
struct QueueEvidence {
    session: Option<SessionIdentity>,
    id: Option<String>,
    seen: bool,
    taken: bool,
    reader: Option<QueueRead>,
    identity_changed: bool,
}

impl QueueEvidence {
    fn identity_valid(&self) -> bool {
        !self.identity_changed && self.reader.as_ref().is_none_or(QueueRead::identity_valid)
    }

    fn observe(&mut self, db: &Path, thread: &str, stdout: &str, deadline: Instant) {
        if self.id.is_none() {
            self.id = parse_item_id(stdout, thread);
        }
        let Some(id) = self.id.as_deref() else {
            return;
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if self.taken || left.is_zero() {
            return;
        }
        if self.identity_changed {
            return;
        }
        if self.reader.is_none() {
            self.reader = QueueRead::open(
                db,
                deadline.min(Instant::now() + Duration::from_millis(200)),
            );
        }
        let Some(reader) = self.reader.as_mut() else {
            return;
        };
        let present = reader.present(id, Some(thread), deadline);
        if !reader.identity_valid() {
            self.identity_changed = true;
            return;
        }
        if Instant::now() >= deadline {
            return;
        }
        match present {
            Some(true) => {
                signal_first_seen(self.seen);
                self.seen = true;
            }
            Some(false) if self.seen => self.taken = true,
            _ => {}
        }
    }
}

/// One admitted database, retained through child polling and drain. Path metadata is
/// compared before/after every observation: replacing a regular DB must not look like
/// consumption, and a detached old connection must not verify the replacement queue.
/// These checks are cooperative; double metadata reads do not atomically exclude a hostile
/// same-uid path swap and restoration between them.
struct QueueRead {
    path: PathBuf,
    connection: rusqlite::Connection,
    identity: QueueIdentity,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct QueueIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl QueueIdentity {
    fn at(path: &Path) -> Option<Self> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some(Self {
                dev: meta.dev(),
                ino: meta.ino(),
            })
        }
        // No equivalent stable file identity is implemented on this unsupported wake platform.
        #[cfg(not(unix))]
        {
            let _ = meta;
            None
        }
    }
}

impl QueueRead {
    fn open(path: &Path, deadline: Instant) -> Option<Self> {
        if Instant::now() >= deadline {
            return None;
        }
        let identity = QueueIdentity::at(path)?;
        let connection = open_ro_bounded(path, deadline)?;
        if QueueIdentity::at(path) != Some(identity) || Instant::now() >= deadline {
            return None;
        }
        Some(Self {
            path: path.to_path_buf(),
            connection,
            identity,
        })
    }

    fn identity_valid(&self) -> bool {
        QueueIdentity::at(&self.path) == Some(self.identity)
    }

    fn present(&self, id: &str, thread: Option<&str>, deadline: Instant) -> Option<bool> {
        match self.probe(id, thread, deadline, deadline) {
            Probe::Present(present) => Some(present),
            Probe::Busy | Probe::Failed => None,
        }
    }

    /// One bounded read. `Busy` is a writer holding the database past this slice (in
    /// rollback-journal mode a commit in progress blocks readers, and a slow disk stretches
    /// it to seconds; in WAL mode, which Codex's queue DB uses, a reader is blocked only by
    /// recovery or a checkpoint, so Busy is rarer there); it is distinct from
    /// `Failed` so a drain watch can keep polling inside its own window instead of
    /// reporting a consumption it merely failed to observe.
    fn probe(&self, id: &str, thread: Option<&str>, slice: Instant, overall: Instant) -> Probe {
        if !self.identity_valid() || Instant::now() >= slice {
            return Probe::Failed;
        }
        if self
            .connection
            .busy_timeout(
                slice
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(200)),
            )
            .is_err()
        {
            return Probe::Failed;
        }
        let read = row_present(&self.connection, id, thread);
        #[cfg(test)]
        QUEUE_READ_PROBE.with(|slot| {
            if let Some(probe) = slot.borrow().as_ref() {
                probe();
            }
        });
        // A busy read spends its whole slice by construction, so classify it before any
        // deadline check. The slice bounds how long one read may BLOCK; a read that
        // succeeds just past it (SQLite's busy handler sleeps in coarse steps) is still a
        // true observation, valid while the overall budget holds.
        if let Err(rusqlite::Error::SqliteFailure(e, _)) = &read {
            if matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) {
                return Probe::Busy;
            }
        }
        match read {
            Ok(present) if self.identity_valid() && Instant::now() < overall => {
                Probe::Present(present)
            }
            _ => Probe::Failed,
        }
    }
}

/// The queued row's own text when its payload is codex's `UserInput` shape
/// with exactly one text part. `None` on any other shape or a changed DB.
#[cfg(unix)]
fn row_notice_text(conn: &rusqlite::Connection, id: &str, thread: Option<&str>) -> Option<String> {
    let payload: String = conn
        .query_row(
            "SELECT payload_json FROM queued_items WHERE id = ?1 AND (?2 IS NULL OR thread_id = ?2)",
            rusqlite::params![id, thread],
            |r| r.get(0),
        )
        .ok()?;
    let value: serde_json::Value = serde_json::from_str(&payload).ok()?;
    let content = value.get("UserInput")?.get("content")?.as_array()?;
    if content.len() != 1 {
        return None;
    }
    let part = &content[0];
    if part.get("type").and_then(serde_json::Value::as_str) != Some("text") {
        return None;
    }
    part.get("text")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

impl QueueRead {
    /// The queued row's text, read through the same identity-checked
    /// connection as `present`.
    #[cfg(unix)]
    fn notice_text(&self, id: &str, thread: Option<&str>) -> Option<String> {
        if !self.identity_valid() {
            return None;
        }
        row_notice_text(&self.connection, id, thread)
    }
}

/// The fixed notice's tail, shared with [`notice`] so the shape check cannot
/// drift from the wording csq actually queues.
#[cfg(unix)]
const NOTICE_TAIL: &str = " peer message(s) waiting \u{2014} call csq inbox(mark: \"read\"); you may answer with the reply tool if it relates to your task";

/// True iff the text's FIRST line is exactly [`notice`] for some count. A
/// queued preview/sender notice is the pointer line followed by csq's own
/// frame; anything else (a user prompt) is not startable by the wake path.
#[cfg(all(unix, test))]
fn text_is_csq_notice_for_test(text: &str) -> bool {
    text_is_csq_notice(text)
}

#[cfg(unix)]
fn text_is_csq_notice(text: &str) -> bool {
    let Some(first) = text.lines().next() else {
        return false;
    };
    let Some(rest) = first.strip_prefix("csq: ") else {
        return false;
    };
    let Some(number) = rest.strip_suffix(NOTICE_TAIL) else {
        return false;
    };
    number
        .parse::<usize>()
        .ok()
        .is_some_and(|n| notice(n) == first)
}

enum Probe {
    Present(bool),
    Busy,
    Failed,
}

fn row_present(
    conn: &rusqlite::Connection,
    id: &str,
    thread: Option<&str>,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM queued_items WHERE id = ?1 AND (?2 IS NULL OR thread_id = ?2))",
        rusqlite::params![id, thread],
        |r| r.get(0),
    )
}

// TEST-ONLY evidence for the last delivery attempt: the drained child-output
// sizes and whether the ACK is parseable for the requested thread. It records
// SIZES and a boolean, never content, so a failing assertion can name its own
// cause without printing arbitrary child output.
#[cfg(all(test, unix))]
thread_local! {
    static LAST_WAKE_EXIT: std::cell::RefCell<Option<(usize, usize, bool)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn record_exit_probe(thread: Option<&str>, exit: &Exit) {
    let ack = thread.is_some_and(|t| parse_item_id(&exit.stdout, t).is_some());
    LAST_WAKE_EXIT
        .with(|slot| *slot.borrow_mut() = Some((exit.stdout.len(), exit.stderr.len(), ack)));
}

/// The most recent drained exit's `(stdout_bytes, stderr_bytes, ack_parseable)`.
#[cfg(all(test, unix))]
fn last_wake_exit() -> Option<(usize, usize, bool)> {
    LAST_WAKE_EXIT.with(|slot| *slot.borrow())
}

fn signal_first_seen(seen: bool) {
    #[cfg(all(any(test, feature = "test-utils"), unix))]
    if !seen {
        FIRST_SEEN_SIGNAL.with(|signal| {
            if let Some(signal) = signal.borrow_mut().take() {
                let _ = signal.send(());
            }
        });
    }
    let _ = seen;
}

#[cfg(all(test, unix))]
fn open_ro(db: &Path) -> Option<rusqlite::Connection> {
    open_ro_bounded(db, Instant::now() + Duration::from_millis(200))
}

fn open_ro_bounded(db: &Path, deadline: Instant) -> Option<rusqlite::Connection> {
    // SQLite NOFOLLOW also rejects symlinked directory components (e.g. macOS /var).
    // Resolve the parent, never the leaf: the regular-leaf check and SQLite's open still
    // refer to the same final name, and a symlink swapped in there remains a refusal.
    let db = db.parent()?.canonicalize().ok()?.join(db.file_name()?);
    // The leaf must be a regular file: a symlink swapped in for the queue DB is not opened.
    if !std::fs::symlink_metadata(&db).ok()?.file_type().is_file() {
        return None;
    }
    #[cfg(test)]
    QUEUE_OPEN_PROBE.with(|slot| {
        if let Some(probe) = slot.borrow_mut().take() {
            probe();
        }
    });
    let c = rusqlite::Connection::open_with_flags(&db, queue_read_flags()).ok()?;
    c.busy_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()?;
    Some(c)
}

#[cfg(test)]
std::thread_local! {
    /// Runs inside every `QueueRead::probe` after the SQL read returned and before the result
    /// is classified; a test uses it to make a successful read outlast its slice.
    static QUEUE_READ_PROBE: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn with_queue_read_probe<T>(probe: impl Fn() + 'static, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<Box<dyn Fn()>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            QUEUE_READ_PROBE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(QUEUE_READ_PROBE.with(|slot| slot.replace(Some(Box::new(probe)))));
    action()
}

#[cfg(test)]
std::thread_local! {
    static QUEUE_OPEN_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn with_queue_open_probe<T>(probe: impl FnOnce() + 'static, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<Box<dyn FnOnce()>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            QUEUE_OPEN_PROBE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(QUEUE_OPEN_PROBE.with(|slot| slot.replace(Some(Box::new(probe)))));
    action()
}

fn queue_read_flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
}

/// Poll for the row `id` until `wait` ends: gone is `CodexWoken`, still there is
/// `CodexQueued`, and any read failure is `CodexQueuedUnverified` (never woken).
#[cfg(all(test, unix))]
fn watch_drain(db: &Path, id: &str, wait: Duration) -> Delivery {
    watch_drain_until(db, id, None, wait, Instant::now() + WAKE_TOTAL, false)
}

#[cfg(all(test, unix))]
fn watch_drain_until(
    db: &Path,
    id: &str,
    thread: Option<&str>,
    wait: Duration,
    overall: Instant,
    seen: bool,
) -> Delivery {
    watch_drain_reader(db, &mut None, id, thread, wait, overall, seen, &|| true)
}

#[allow(clippy::too_many_arguments)]
fn watch_drain_reader(
    db: &Path,
    reader: &mut Option<QueueRead>,
    id: &str,
    thread: Option<&str>,
    wait: Duration,
    overall: Instant,
    mut seen: bool,
    still_live: &dyn Fn() -> bool,
) -> Delivery {
    let deadline = (Instant::now() + wait).min(overall);
    loop {
        if !still_live() || Instant::now() >= overall {
            return Delivery::CodexQueuedUnverified;
        }
        if reader.is_none() {
            // A zero drain window permits one immediate verification, under the overall budget.
            *reader = QueueRead::open(db, overall.min(Instant::now() + Duration::from_millis(200)));
        }
        let Some(queue) = reader.as_ref() else {
            return Delivery::CodexQueuedUnverified;
        };
        let present = match queue.probe(
            id,
            thread,
            overall.min(Instant::now() + Duration::from_millis(200)),
            overall,
        ) {
            Probe::Present(present) => present,
            // A writer is mid-commit: wait out the drain window, never past `overall`.
            Probe::Busy if still_live() && Instant::now() < deadline.min(overall) => {
                std::thread::sleep(
                    DRAIN_POLL.min(deadline.saturating_duration_since(Instant::now())),
                );
                continue;
            }
            Probe::Busy | Probe::Failed => return Delivery::CodexQueuedUnverified,
        };
        // Metadata and SQLite are synchronous cooperative work; no verification returned
        // after the overall budget may produce a consumption/presence claim.
        if !still_live() || Instant::now() >= overall {
            return Delivery::CodexQueuedUnverified;
        }
        if !present {
            return if seen {
                Delivery::CodexWoken
            } else {
                Delivery::CodexRowNeverSeen
            };
        }
        signal_first_seen(seen);
        seen = true;
        if Instant::now() >= deadline {
            return if still_live() && Instant::now() < overall {
                Delivery::CodexQueued
            } else {
                Delivery::CodexQueuedUnverified
            };
        }
        std::thread::sleep(DRAIN_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

#[cfg(all(any(test, feature = "test-utils"), unix))]
std::thread_local! {
    static FIRST_SEEN_SIGNAL: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
}

/// Installs a test-only, per-thread first-present-row handshake for wakes run by `action`.
/// Restores the prior observer even when the fixture panics; other tests cannot receive it.
#[cfg(all(any(test, feature = "test-utils"), unix))]
#[doc(hidden)]
pub fn with_first_seen_signal<T>(
    signal: std::sync::mpsc::Sender<()>,
    action: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<std::sync::mpsc::Sender<()>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            FIRST_SEEN_SIGNAL.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(FIRST_SEEN_SIGNAL.with(|slot| slot.replace(Some(signal))));
    action()
}

/// Coalesce an acknowledged attempt without promoting unknown visibility to a take.
/// Legacy sidecars without incarnation/handle bindings cannot suppress a production wake.
fn pending_bound(spec: &WakeSpec, thread: &str, deadline: Instant) -> Option<(Delivery, String)> {
    let item = read_item(&spec.codex_home)?;
    if item.thread != thread || item.session != spec.session {
        return None;
    }
    if spec.session.is_some()
        && (item.handle.is_none() || item.handle != handle_identity(&spec.codex_home))
    {
        return None;
    }
    let db = spec.sqlite_home.join(QUEUE_DB);
    let uncertain = || Some((Delivery::CodexQueuedUnverified, item.id.clone()));
    let Some(reader) = QueueRead::open(
        &db,
        deadline.min(Instant::now() + Duration::from_millis(200)),
    ) else {
        return uncertain();
    };
    if item.queue.is_some() && item.queue != Some(reader.identity) {
        return uncertain();
    }
    match reader.present(&item.id, Some(thread), deadline) {
        Some(true) => {
            let evidence = QueueEvidence {
                session: spec.session,
                id: Some(item.id.clone()),
                seen: true,
                reader: Some(reader),
                ..QueueEvidence::default()
            };
            if record_item(&spec.codex_home, thread, &item.id, &evidence).is_err() {
                return uncertain();
            }
            Some((Delivery::CodexWakePending, item.id))
        }
        // Authoritative absence in the same bound DB releases this dedupe key even
        // if its ACK was never observed. That permits recovery, not a consumption
        // claim: deferred's separately bound take check still requires `seen`.
        Some(false) if item.queue == Some(reader.identity) => None,
        _ => uncertain(),
    }
}

/// Read the process disposition without changing it. Auto-reaping makes ownership
/// of a just-exited child's process-group id unverifiable, so do not spawn then.
#[cfg(unix)]
fn child_wait_policy_safe() -> bool {
    // SAFETY: sigaction writes the initialized plain-data result; a null second
    // argument queries only and never installs a handler or changes signal policy.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) == 0
            && action.sa_sigaction != libc::SIG_IGN
            && action.sa_flags & libc::SA_NOCLDWAIT == 0
    }
}

/// What `waitid(WNOWAIT | WNOHANG)` says about the wake child.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildState {
    /// Exited and still a zombie: unreaped, so its pid (the process-group id) cannot be
    /// reassigned until [`Child::wait`].
    ExitedUnreaped,
    /// Alive: `waitid` succeeded with no pid in the result.
    Running,
    /// `waitid` failed with `ECHILD`: the child is not ours to wait for (auto-reaped by a
    /// `SIGCHLD = SIG_IGN` disposition), so its pid may belong to something else by now.
    Gone,
}

/// Probe the child without blocking and without reaping it. An `EINTR` or any other failure
/// reads as `Running`: the next poll asks again, and the timeout path re-probes before it
/// signals anything.
#[cfg(unix)]
fn child_state(child: &std::process::Child) -> ChildState {
    let pid = libc::id_t::from(child.id());
    // SAFETY: `siginfo_t` is plain data for which all-zero is valid; `waitid` writes only
    // into it, and `WNOHANG | WNOWAIT` neither blocks nor reaps.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        if r == -1 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                ChildState::Gone
            } else {
                ChildState::Running
            };
        }
        #[cfg(target_os = "macos")]
        let who = info.si_pid;
        #[cfg(not(target_os = "macos"))]
        let who = info.si_pid();
        if who != 0 {
            ChildState::ExitedUnreaped
        } else {
            ChildState::Running
        }
    }
}

/// SIGKILL `target` (`kill(2)` semantics: a negative `target` is a process group).
#[cfg(unix)]
fn sigkill(target: i32) {
    // SAFETY: `kill` takes plain integers and touches no memory.
    unsafe {
        libc::kill(target, libc::SIGKILL);
    }
}

/// SIGKILL the wake's whole process group (its pid is the group id: `setsid` made it leader).
#[cfg(unix)]
fn kill_group_signal(child: &std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        sigkill(-pid);
    }
}

/// The timeout path. On Unix it signals only after a fresh [`child_state`] probe shows the
/// child is still ours (`Running` or an unreaped zombie); `Gone` sends nothing.
///
/// The ONLY signal sent is the group kill `kill(-pgid)`. Before spawning, the
/// sender's read-only SIGCHLD check refuses SIG_IGN and SA_NOCLDWAIT. The child
/// is observed with WNOWAIT, and stays unreaped until AFTER the group signal;
/// Within csq's sole-waiter ownership, its PID cannot be reassigned in this
/// interval. This assumes no external child reaper or concurrent disposition writer.
fn kill_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    kill_group_with(child, &mut sigkill);
    #[cfg(not(unix))]
    {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// [`kill_group`] with the signal sender injected, so a test can see EVERY target signalled.
#[cfg(unix)]
fn kill_group_with(child: &mut std::process::Child, send: &mut dyn FnMut(i32)) {
    if child_state(child) == ChildState::Gone {
        return;
    }
    if let Ok(pid) = i32::try_from(child.id()) {
        send(-pid);
    }
    let _ = child.wait();
}

// ── Claude Code wake (spec 32a §5.2) ────────────────────────────────

/// Wall-clock budget for the WHOLE post (connect, peer check and write share one deadline).
/// Derivation from the two outcomes it separates. HEALTHY: connect plus a ~150-byte write to a
/// live Claude Code 2.1.290 socket measured 0.05 ms (a Python client on macOS, 2026-10-06;
/// `healthy_post_is_far_under_the_budget` bounds the Rust path at 1/20 of this budget), and a
/// loaded host (load average ~135 observed) stretches that by tens of ms at most. FAILURE: a connect against a full listen backlog never completes on
/// Linux (non-blocking `connect` answers `EAGAIN` forever), so only this deadline ends it.
/// 2 s sits >=1000x over the healthy case and keeps an interactive `send` under a human-visible
/// pause. (Claude Code's own 30 s first-line close is NOT a bound on this: it starts after the
/// connection is accepted, which a full backlog never reaches.)
pub const CLAUDE_SOCKET_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a Claude wake failed. Fixed vocabulary: the only text a wake failure ever logs, so no
/// path, body or OS error string can reach a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeWakeFail {
    /// The target incarnation was no longer the one validated.
    Gone,
    /// The registered path was not a socket owned by this uid.
    NotOurSocket,
    /// `connect` failed (no listener, refused, or permission).
    Connect,
    /// The peer behind the socket is not this uid.
    PeerUid,
    /// The same-UID listener was not the validated recipient process.
    PeerPid,
    /// The line could not be fully written.
    Write,
    /// The post did not finish within its budget.
    Timeout,
    /// The socket's directory is not one Claude Code binds sockets in, or is not owned by this
    /// uid and closed to group and world writes.
    DirRefused,
    /// The recipient's wake lock could not be opened or locked, so no wake holds it.
    Lock,
}

impl ClaudeWakeFail {
    /// The log tag.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Gone => "claude_wake_target_gone",
            Self::NotOurSocket => "claude_wake_not_our_socket",
            Self::Connect => "claude_wake_connect_failed",
            Self::PeerUid => "claude_wake_peer_uid",
            Self::PeerPid => "claude_wake_peer_pid",
            Self::Write => "claude_wake_write_failed",
            Self::Timeout => "claude_wake_timeout",
            Self::DirRefused => "claude_wake_dir_refused",
            Self::Lock => "claude_wake_lock_failed",
        }
    }
}

/// The one line posted to a Claude Code inbox socket. It takes a count and nothing else, so no
/// body text can reach it. The shape is Claude Code's documented inject form
/// `{"type":"user","message":{"role":"user","content":...}}` (verified live, spec 32a §5.2); no
/// `{"type":"auth"}` line precedes it, because the docs make auth optional on macOS and Linux
/// and the token is per-session, published only to the session's own children.
#[must_use]
pub fn claude_line(n: usize) -> String {
    claude_line_text(&notice(n))
}

fn claude_line_text(text: &str) -> String {
    let mut line = serde_json::json!({
        "type": "user",
        "message": {"role": "user", "content": text},
    })
    .to_string();
    line.push('\n');
    line
}

/// A Claude Code recipient that passed [`ClaudeWakeTarget::resolve`]: its registry record
/// or one unambiguous producer-derived candidate named a socket for the resolved process. The connected peer UID and PID are checked
/// again before a notice is written; a registry path alone does not bind a listener. Fields are private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeWakeTarget {
    pid: u32,
    /// Full-precision start of `pid` ([`crate::sessions::ancestor_start`]) when validated.
    start: u64,
    socket: PathBuf,
    /// Recipient process configuration directory; never taken from the sender environment.
    config_dir: PathBuf,
}

impl ClaudeWakeTarget {
    /// The registered inbox socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Whether the process is still the incarnation validated: its exact start is unchanged.
    #[must_use]
    pub fn still_live(&self) -> bool {
        self.still_live_with(&crate::sessions::ancestor_start)
    }

    /// [`Self::still_live`] over an injected start reader (the process table is the one input a
    /// caller's test cannot fake any other way).
    #[must_use]
    pub fn still_live_with(&self, start_of: &dyn Fn(u32) -> Option<u64>) -> bool {
        start_of(self.pid) == Some(self.start)
    }

    /// The recipient's socket from its registry record `<config_dir>/sessions/<pid>.json`
    /// (`config_dir`: the `CLAUDE_CONFIG_DIR` of the process, from the process table, not from
    /// the caller). `None` (a `queued_only` send) unless every check holds: the process is
    /// listed with a whole-second start within `START_TOLERANCE_SECS` of `started_at` and
    /// an exact start matching the stored resolve-time value; the record is a regular file (bounded, no-follow read) whose `pid` and
    /// `startedAt` bind to that process by the same rule `list_sessions` uses; and it carries an
    /// absolute `messagingSocketPath`. Whether that path is a socket of ours is checked at post
    /// time by [`deliver_claude_coalesced`], not here. When optional JSON publication is absent,
    /// producer-derived candidate lookup selects exactly one permitted default socket;
    /// unreadable or invalid present metadata never authorizes that fallback.
    #[must_use]
    pub fn resolve(
        pid: u32,
        started_at: u64,
        stored_exact: Option<u64>,
        info_of: &dyn Fn(
            u32,
        ) -> Result<
            Option<(crate::sessions::SessionInfo, u64)>,
            crate::sessions::Undetermined,
        >,
        now_secs: u64,
    ) -> Option<Self> {
        Self::resolve_with_socket_lookup(
            pid,
            started_at,
            stored_exact,
            info_of,
            now_secs,
            &discover_claude_socket,
        )
    }

    fn resolve_with_socket_lookup(
        pid: u32,
        started_at: u64,
        stored_exact: Option<u64>,
        info_of: &dyn Fn(
            u32,
        ) -> Result<
            Option<(crate::sessions::SessionInfo, u64)>,
            crate::sessions::Undetermined,
        >,
        now_secs: u64,
        socket_of: &dyn Fn(u32) -> Option<PathBuf>,
    ) -> Option<Self> {
        let Ok(Some((info, exact))) = info_of(pid) else {
            tracing::debug!(
                reason = "claude_wake_not_listed",
                "claude wake target refused"
            );
            return None;
        };
        if !info
            .started_at
            .is_some_and(|s| crate::sessions::same_start(s, started_at))
        {
            tracing::debug!(
                reason = "claude_wake_start_mismatch",
                "claude wake target refused"
            );
            return None;
        }
        // Full-precision bind: the exact start stored when the recipient was resolved must equal
        // the one read now. An absent stored start never binds (same rule as the Codex wake).
        if stored_exact != Some(exact) {
            tracing::debug!(
                reason = "claude_wake_exact_start_mismatch",
                "claude wake target refused"
            );
            return None;
        }
        let path = info.config_dir.join("sessions").join(format!("{pid}.json"));
        let bytes = match crate::platform::fs::read_regular_nofollow_bounded(
            &path,
            crate::sessions::MAX_REGISTRY_BYTES,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // Optional registry JSON is not published in every Claude Code role.
                // A producer candidate is admitted here; connected peer PID is authority at post.
                let socket = socket_of(pid)?;
                let Ok(Some((fresh, fresh_exact))) = info_of(pid) else {
                    return None;
                };
                if fresh.pid != pid || fresh_exact != exact || fresh.config_dir != info.config_dir {
                    return None;
                }
                return Some(Self {
                    pid,
                    start: exact,
                    socket,
                    config_dir: info.config_dir,
                });
            }
            Err(_) => {
                tracing::debug!(
                    reason = "claude_wake_registry_unreadable",
                    "claude wake target refused"
                );
                return None;
            }
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            tracing::debug!(
                reason = "claude_wake_registry_not_json",
                "claude wake target refused"
            );
            return None;
        };
        if v.get("pid").and_then(serde_json::Value::as_u64) != Some(u64::from(pid)) {
            tracing::debug!(
                reason = "claude_wake_registry_pid_mismatch",
                "claude wake target refused"
            );
            return None;
        }
        let Some(reg_secs) = v
            .get("startedAt")
            .and_then(serde_json::Value::as_u64)
            .map(|ms| ms / 1000)
        else {
            tracing::debug!(
                reason = "claude_wake_registry_start_missing",
                "claude wake target refused"
            );
            return None;
        };
        if !crate::sessions::registry_start_in_window(reg_secs, started_at, now_secs) {
            tracing::debug!(
                reason = "claude_wake_registry_start_window",
                "claude wake target refused"
            );
            return None;
        }
        let Some(path) = v
            .get("messagingSocketPath")
            .and_then(serde_json::Value::as_str)
        else {
            tracing::debug!(
                reason = "claude_wake_socket_key_missing",
                "claude wake target refused"
            );
            return None;
        };
        let socket = PathBuf::from(path);
        if !socket.is_absolute() {
            tracing::debug!(
                reason = "claude_wake_socket_path_not_absolute",
                "claude wake target refused"
            );
            return None;
        }
        Some(Self {
            pid,
            start: exact,
            socket,
            config_dir: info.config_dir,
        })
    }
}

/// Only producer-derived candidates are inspected; a filename is not listener authority.
/// Canonical directory/leaf checks admit a path, then delivery binds its connected peer PID.
#[cfg(unix)]
fn discover_claude_socket(pid: u32) -> Option<PathBuf> {
    let deadline = Instant::now() + CLAUDE_SOCKET_TIMEOUT;
    let dirs = claude_socket_dirs();
    let paths: Vec<_> = dirs.iter().map(|d| d.join(format!("{pid}.sock"))).collect();
    let result = select_claude_socket(pid, &paths, &dirs);
    (Instant::now() < deadline).then_some(result).flatten()
}

#[cfg(not(unix))]
fn discover_claude_socket(_pid: u32) -> Option<PathBuf> {
    None
}

#[cfg(unix)]
fn select_claude_socket(pid: u32, paths: &[PathBuf], allowed: &[PathBuf]) -> Option<PathBuf> {
    let name = format!("{pid}.sock");
    let candidates: std::collections::BTreeSet<_> = paths
        .iter()
        .filter(|p| p.is_absolute() && p.file_name() == Some(OsStr::new(&name)))
        .filter_map(|p| canonical_socket_in(p, allowed))
        .filter(|p| is_our_socket(p))
        .collect();
    (candidates.len() == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

/// Producer-derived socket directories: `$XDG_RUNTIME_DIR/cc-socks`, sender
/// `$TMPDIR/cc-socks`, `/tmp/cc-socks`, and `/tmp/cc-socks-<uid>`. Only absolute sender
/// environment paths are admitted. Canonical parents must belong to this UID and have no
/// group/world write bits; the socket leaf must also belong to this UID. These path checks
/// admit candidates, while the connected peer UID/PID and exact target start bind delivery.
/// Different sender/recipient environment paths can still leave no discoverable candidate.
#[must_use]
pub fn claude_socket_dirs() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let mut v = vec![
            PathBuf::from("/tmp/cc-socks"),
            PathBuf::from(format!("/tmp/cc-socks-{uid}")),
        ];
        if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            v.push(x.join("cc-socks"));
        }
        if let Some(t) = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            v.push(t.join("cc-socks"));
        }
        v
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

/// The canonical path to post to, or `None`: `socket`'s parent canonicalizes to one of `allowed`
/// (each canonicalized too, so `/tmp` -> `/private/tmp` on macOS compares equal) AND that
/// directory is owned by this uid with no group or world write bit. The returned path is the
/// canonical parent plus the registered file name, so the connect uses exactly the path that was
/// checked. A swap of the directory's CONTENTS after this call is still possible; the owner
/// check on the socket and the connected peer UID/PID checks bound the endpoint used.
#[cfg(unix)]
fn canonical_socket_in(socket: &Path, allowed: &[PathBuf]) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let name = socket.file_name()?;
    let parent = std::fs::canonicalize(socket.parent()?).ok()?;
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    allowed
        .iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .any(|c| {
            c == parent
                && std::fs::symlink_metadata(&c)
                    .is_ok_and(|m| m.is_dir() && m.uid() == me && m.mode() & 0o022 == 0)
        })
        .then(|| parent.join(name))
}

/// Conservative duration for which a successful Claude notice may cover unread messages.
pub const CLAUDE_COALESCE_SECS: u64 = 20;
#[cfg(unix)]
const CLAUDE_RATE_WINDOW_SECS: u64 = 600;
#[cfg(unix)]
const CLAUDE_RATE_MAX: usize = 6;

#[cfg(unix)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaudeNotice {
    version: u8,
    pid: u32,
    start: u64,
    posted_at: u64,
    pending_ids: Vec<String>,
    successful_posts: Vec<u64>,
    reservations: Vec<u64>,
    /// A crash or uncertain finalization conservatively consumes this reserved slot.
    reserved_at: Option<u64>,
}

#[cfg(unix)]
fn claude_notice_path(home: &Path, pid: u32) -> PathBuf {
    home.join(format!(".csq-claude-wake-{pid}.json"))
}

#[cfg(unix)]
fn valid_claude_ids(ids: &[String]) -> bool {
    !ids.is_empty()
        && ids.len() <= super::limits::MAX_PENDING_PER_RECIPIENT
        && ids
            .iter()
            .all(|id| crate::sessions::directives::canonical_uuid(id))
        && ids.iter().collect::<std::collections::BTreeSet<_>>().len() == ids.len()
}

#[cfg(unix)]
fn read_claude_notice(path: &Path) -> Option<ClaudeNotice> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() || md.uid() != uid || md.mode() & 0o077 != 0 {
        return None;
    }
    let bytes = crate::platform::fs::read_regular_nofollow_bounded(path, 4096).ok()??;
    let state: ClaudeNotice = serde_json::from_slice(&bytes).ok()?;
    (state.version == 2
        && (state.pending_ids.is_empty() || valid_claude_ids(&state.pending_ids))
        && state.reservations.len() <= CLAUDE_RATE_MAX
        && state.successful_posts.len() <= state.reservations.len())
    .then_some(state)
}

/// Post or conservatively coalesce one fixed notice under the recipient's existing wake
/// lock. `pending_ids` must read the actual store, not a cached count. Suppression requires
/// a prior successful post for this exact incarnation less than 20 seconds ago, with at
/// least one of its pre-post unread records still unread. A read/ack followed by a new send
/// therefore cannot reuse the old notice. Unknown store or sidecar evidence never dedupes.
/// An authoritative empty unread set returns `queued_only` without posting or reserving:
/// the sender's earlier count may have become stale while the recipient read its inbox.
/// `ClaudeWakePending` means no new socket write, not a model receipt.
///
/// Bounds. The budget bounds ONE socket post (and the success finalization right after it), not
/// the call: the post that follows the holder's final store read gets its own. The lock wait is
/// bounded by the same caller budget but does not consume it, so the durable bookkeeping under the
/// lock cannot spend the post's time. A waiter whose wait expires posts nothing at all and reports
/// `ClaudeWakeContended` rather than a failure. That outcome claims no coverage: the holder's
/// final store read runs only after its own first post succeeded, so a message may be left
/// un-nudged, and the receipt says only that nothing was posted by this attempt. The
/// store reads and the durable notice writes that precede a post are disk latency rather than
/// delivery latency, and must not be able to spend the post's time before the post is attempted.
/// Synchronous callbacks and filesystem calls are not bounded, so the worst case for one call is
/// the lock bound, plus the post bound, plus unbounded filesystem time.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn deliver_claude_coalesced(
    target: &ClaudeWakeTarget,
    allowed_dirs: &[PathBuf],
    still_live: &dyn Fn() -> bool,
    n: usize,
    timeout: Duration,
    now: u64,
    pending_ids: &dyn Fn() -> Option<Vec<String>>,
) -> Delivery {
    deliver_claude_coalesced_text(
        target,
        allowed_dirs,
        still_live,
        &notice(n),
        timeout,
        now,
        pending_ids,
    )
}

/// Post a safely framed stored summary through the validated Claude socket.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn deliver_claude_coalesced_with_notice(
    target: &ClaudeWakeTarget,
    allowed_dirs: &[PathBuf],
    still_live: &dyn Fn() -> bool,
    summary: &super::store::PendingNotice,
    timeout: Duration,
    now: u64,
    pending_ids: &dyn Fn() -> Option<Vec<String>>,
) -> Delivery {
    deliver_claude_coalesced_text(
        target,
        allowed_dirs,
        still_live,
        &super::frame::render_preview_notice(summary),
        timeout,
        now,
        pending_ids,
    )
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn deliver_claude_coalesced_text(
    target: &ClaudeWakeTarget,
    allowed_dirs: &[PathBuf],
    still_live: &dyn Fn() -> bool,
    text: &str,
    timeout: Duration,
    now: u64,
    pending_ids: &dyn Fn() -> Option<Vec<String>>,
) -> Delivery {
    use std::os::unix::fs::MetadataExt;
    // The directory comes from the validated recipient process. Canonicalize it and refuse
    // foreign/group/world-writable state storage; do not create a directory or follow a lock.
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let Ok(home) = std::fs::canonicalize(&target.config_dir) else {
        return claude_failed(ClaudeWakeFail::DirRefused);
    };
    if !std::fs::symlink_metadata(&home)
        .is_ok_and(|md| md.is_dir() && md.uid() == uid && md.mode() & 0o022 == 0)
    {
        return claude_failed(ClaudeWakeFail::DirRefused);
    }
    match std::fs::symlink_metadata(home.join(LOCK_FILE)) {
        Ok(md) if !md.is_file() || md.uid() != uid || md.mode() & 0o022 != 0 => {
            return claude_failed(ClaudeWakeFail::DirRefused);
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return claude_failed(ClaudeWakeFail::DirRefused);
        }
        _ => {}
    }
    // The lock wait is bounded by the same caller budget, but it does not consume it: the post's
    // budget starts only where the post does (below), so the bookkeeping that runs under the lock
    // cannot spend the post's time.
    let _guard = match lock_wake(&home, timeout) {
        Ok(Some(g)) => g,
        // A contended lock is not evidence of a successful earlier notice, and it is not a
        // failure either; nor is it evidence the holder will cover this message (it may exit
        // without a second post), so the outcome claims no coverage.
        Ok(None) => return Delivery::ClaudeWakeContended,
        // The lock could not be opened or flocked: no holder exists, so nothing will post for
        // this message. That is a failure, never a benign contended outcome — and it is NAMED
        // with the same fixed vocabulary as the codex wake path (D237 R2 sec L3), so the cause
        // of a failure under table pressure is never silent again.
        Err(e) => {
            tracing::warn!(
                error_kind = "claude_wake_lock_failed",
                errno = e.raw_os_error().unwrap_or(0),
                "claude wake lock could not be acquired"
            );
            return claude_failed(ClaudeWakeFail::Lock);
        }
    };
    let evidence_at = Instant::now();
    let observed_ids = pending_ids();
    // Evidence gathered after the caller's budget cannot support a coalescing claim: the store
    // may have moved on while the read was late, so the ids it returned are no longer proof that
    // the recipient is still covered. This gates only the `covered` decision below, never the
    // delivery -- a late read must not cost the recipient its notice.
    let evidence_late = evidence_at.elapsed() > timeout;
    // A delayed sender's count can outlive a hook/inbox read of its entire cohort.
    // An authoritative empty store is not unknown evidence: do not enqueue another
    // native prompt, and do not consume a reservation for a write we will not attempt.
    if observed_ids.as_ref().is_some_and(Vec::is_empty) {
        return Delivery::QueuedOnly;
    }
    // The raw read is kept: the holder's final read below compares against it to tell a message
    // that was already covered by this post from one that arrived after the evidence read.
    let ids = observed_ids.clone().filter(|ids| valid_claude_ids(ids));
    let path = claude_notice_path(&home, target.pid);
    let state = read_claude_notice(&path);
    // An existing unreadable state cannot safely reset the rate budget.
    if state.is_none() {
        match std::fs::symlink_metadata(&path) {
            Ok(md) => {
                let expired = u64::try_from(md.mtime())
                    .ok()
                    .and_then(|mtime| now.checked_sub(mtime))
                    .is_some_and(|age| age >= CLAUDE_RATE_WINDOW_SECS);
                if !md.is_file() || md.uid() != uid || !expired {
                    return claude_rate_limited();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return claude_rate_limited(),
        }
    }
    let mut recent = state
        .as_ref()
        .filter(|s| s.pid == target.pid && s.start == target.start)
        .map(|s| s.reservations.clone())
        .unwrap_or_default();
    // Clock rollback retains rather than forgives a consumed slot.
    recent.retain(|t| {
        now.checked_sub(*t)
            .is_none_or(|age| age < CLAUDE_RATE_WINDOW_SECS)
    });
    let covered = !evidence_late
        && ids.as_ref().is_some_and(|ids| {
            state.as_ref().is_some_and(|state| {
                state.pid == target.pid
                    && state.start == target.start
                    && now
                        .checked_sub(state.posted_at)
                        .is_some_and(|age| age < CLAUDE_COALESCE_SECS)
                    && ids.iter().any(|id| state.pending_ids.contains(id))
            })
        });
    if !still_live() {
        return claude_failed(ClaudeWakeFail::Gone);
    }
    if covered {
        return Delivery::ClaudeWakePending;
    }
    if recent.len() >= CLAUDE_RATE_MAX {
        return claude_rate_limited();
    }
    // Reserve under the SAME lock before posting. Persistence failure or a crash must
    // never create a fresh unlimited budget. Finalize successes only after actual writes.
    let mut successes = live_claude_successes(state.as_ref(), target, now);
    let last_post = state.as_ref().map_or(0, |s| s.posted_at);
    {
        let reserved = reserved_claude_state(target, now, last_post, successes.clone(), {
            let mut slots = recent.clone();
            slots.push(now);
            slots
        });
        let Ok(bytes) = serde_json::to_vec(&reserved) else {
            return claude_failed(ClaudeWakeFail::Write);
        };
        if write_state_durable(&path, &bytes).is_err() {
            return claude_rate_limited();
        }
    }
    #[cfg(all(test, unix))]
    CLAUDE_WAKE_PREPOST_PROBE.with(|slot| {
        if let Some(probe) = slot.borrow_mut().take() {
            probe();
        }
    });
    // Everything above is durable bookkeeping (lock, reads, fsync + rename + directory fsync of
    // the reservation); the record exists before the first byte is written, and the post's budget
    // starts only here, so the post gets the full production timeout on any disk.
    let deadline = Instant::now() + timeout;
    let delivery = deliver_claude_socket_text(
        target.socket(),
        target.pid,
        allowed_dirs,
        still_live,
        text,
        deadline.saturating_duration_since(Instant::now()),
    );
    if delivery == Delivery::ClaudeWoken {
        // Socket success consumes a rate slot even if the target exits or the callback
        // finishes after the budget. Evidence that arrived after the budget cannot grant an
        // unread cohort, so a late read is recorded as an empty one.
        let cohort_live = !evidence_late && still_live() && Instant::now() < deadline;
        record_claude_success(
            &path,
            target,
            now,
            ids.as_deref(),
            cohort_live,
            &mut successes,
            &mut recent,
        );
        // The holder's final read, as late as the lock allows. A message stored after the evidence
        // read above is not behind the notice just written, and the sender whose own notice lost
        // the lock wait is exactly the one whose message arrived while this lock was held: read
        // the store once more and post once more (inside the rate cap) for anything the post above
        // did not cover. This narrows the gap; it is not a guarantee a contending waiter may rely
        // on (this read runs only after a successful first post, and a message stored during the
        // second post is not covered), which is why the waiter reports `ClaudeWakeContended` and
        // claims no coverage.
        let rechecked_at = Instant::now();
        let recheck = pending_ids();
        let recheck_late = rechecked_at.elapsed() > timeout;
        // An unknown final read after a known first read cannot show nothing is new, so it is
        // unseen. When both reads are unknown, the first post was already made without evidence
        // and a second one would add no information while doubling the rate spend. "Known" is
        // the FILTERED first read (`ids`), the same filter the final read passed through: ids
        // that fail `valid_claude_ids` on both reads are unknown on both, never a known first
        // read followed by an unknown final one. An authoritative EMPTY final read is known
        // evidence that nothing is unread (the same reading the first read gets above), so it
        // is never unseen: no second reservation, no second post.
        let recheck_empty = recheck.as_ref().is_some_and(Vec::is_empty);
        let recheck_ids = recheck.filter(|ids| valid_claude_ids(ids));
        let unseen = match recheck_ids.as_ref() {
            Some(ids) => ids
                .iter()
                .any(|id| !observed_ids.as_ref().is_some_and(|seen| seen.contains(id))),
            None => !recheck_empty && ids.is_some(),
        };
        if unseen && recent.len() < CLAUDE_RATE_MAX {
            let reserved = reserved_claude_state(target, now, now, successes.clone(), {
                let mut slots = recent.clone();
                slots.push(now);
                slots
            });
            let reserved_ok = serde_json::to_vec(&reserved)
                .ok()
                .is_some_and(|bytes| write_state_durable(&path, &bytes).is_ok());
            if reserved_ok {
                let second_deadline = Instant::now() + timeout;
                let second = deliver_claude_socket_text(
                    target.socket(),
                    target.pid,
                    allowed_dirs,
                    still_live,
                    text,
                    second_deadline.saturating_duration_since(Instant::now()),
                );
                if second == Delivery::ClaudeWoken {
                    let cohort_live =
                        !recheck_late && still_live() && Instant::now() < second_deadline;
                    record_claude_success(
                        &path,
                        target,
                        now,
                        recheck_ids.as_deref(),
                        cohort_live,
                        &mut successes,
                        &mut recent,
                    );
                }
            } else {
                // The second post is skipped because its reservation could not be persisted
                // (a post without a durable reservation could escape the rate cap).
                tracing::warn!(
                    reason = "claude_wake_recheck_reserve_failed",
                    "claude wake recheck post skipped"
                );
            }
        }
    }
    delivery
}

/// The successful posts of `state` that still count for this recipient incarnation.
#[cfg(unix)]
fn live_claude_successes(
    state: Option<&ClaudeNotice>,
    target: &ClaudeWakeTarget,
    now: u64,
) -> Vec<u64> {
    state
        .filter(|s| s.pid == target.pid && s.start == target.start)
        .map(|s| {
            s.successful_posts
                .iter()
                .copied()
                .filter(|t| {
                    now.checked_sub(*t)
                        .is_none_or(|age| age < CLAUDE_RATE_WINDOW_SECS)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The record written BEFORE a post is attempted: it counts `now` as a reservation and claims no
/// cohort (an empty `pending_ids` can never satisfy the coalescing test), so a crash between it
/// and the post leaves a conservative record rather than a free slot. `posted_at` carries the
/// last post that actually succeeded, which is 0 for the first ever attempt.
#[cfg(unix)]
fn reserved_claude_state(
    target: &ClaudeWakeTarget,
    now: u64,
    posted_at: u64,
    successful_posts: Vec<u64>,
    reservations: Vec<u64>,
) -> ClaudeNotice {
    ClaudeNotice {
        version: 2,
        pid: target.pid,
        start: target.start,
        posted_at,
        pending_ids: Vec::new(),
        successful_posts,
        reservations,
        reserved_at: Some(now),
    }
}

/// Record a post that just succeeded: `now` joins the successful posts and the reservations, and
/// the cohort is stored only when `cohort_live` holds, because evidence that could not support a
/// coverage claim must never suppress a later wake. The reservation's slot stays counted whether
/// or not this write lands.
///
/// This write is not gated through [`write_state_durable`]: unlike the reservation it precedes no
/// delivery, and a record lost to a power failure only costs one extra nudge (the surviving
/// reservation claims no cohort), so it does not need the directory fsync.
#[cfg(unix)]
fn record_claude_success(
    path: &Path,
    target: &ClaudeWakeTarget,
    now: u64,
    cohort: Option<&[String]>,
    cohort_live: bool,
    successes: &mut Vec<u64>,
    reservations: &mut Vec<u64>,
) {
    let pending_ids = if cohort_live {
        cohort.map(<[String]>::to_vec).unwrap_or_default()
    } else {
        Vec::new()
    };
    successes.push(now);
    reservations.push(now);
    let state = ClaudeNotice {
        version: 2,
        pid: target.pid,
        start: target.start,
        posted_at: now,
        pending_ids,
        successful_posts: successes.clone(),
        reservations: reservations.clone(),
        reserved_at: None,
    };
    if serde_json::to_vec(&state)
        .ok()
        .is_none_or(|bytes| super::deferred::write_private_atomic(path, &bytes).is_err())
    {
        // Keep the reservation; it conservatively consumes the uncertain slot.
        tracing::warn!(
            reason = "claude_wake_notice_state_failed",
            "claude wake state not saved"
        );
    }
}

/// Publish the private wake state durably: [`super::deferred::write_private_atomic`] (0600 tmp,
/// `sync_all`, atomic rename) plus an fsync of the containing directory.
/// `platform::fs::atomic_replace` renames but never fsyncs the directory, so without the second
/// step the new name itself can be lost in a power failure -- and the reservation is the record
/// that must exist before the first notice byte, so it is written through here rather than
/// through the bare atomic write.
///
/// A filesystem that refuses to fsync a directory (`EINVAL`/`ENOTSUP`, some network mounts) is
/// reported and tolerated: the rename already happened and every process sees it, and refusing
/// the wake would trade a delivery for a durability the medium does not offer. Any other error is
/// returned, so an unreserved post is never attempted.
#[cfg(unix)]
fn write_state_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    super::deferred::write_private_atomic(path, bytes)?;
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    let synced = std::fs::File::open(dir).and_then(|handle| handle.sync_all());
    #[cfg(all(test, unix))]
    CLAUDE_WAKE_DIRSYNC_PROBE.with(|seen| {
        if synced.is_ok() {
            seen.borrow_mut().push(dir.to_path_buf());
        }
    });
    match synced {
        Ok(()) => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP)) => {
            tracing::warn!(
                reason = "claude_wake_state_dir_sync_unsupported",
                "wake state directory fsync not supported"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(all(test, unix))]
std::thread_local! {
    /// Runs after the durable pre-post bookkeeping and before the socket post's budget starts; a
    /// test uses it to make that bookkeeping outlast the production post timeout.
    static CLAUDE_WAKE_PREPOST_PROBE: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
    /// The directories whose fsync completed inside [`write_state_durable`], in order. A test
    /// asserts the reservation path asked the filesystem to make its rename durable. The
    /// recording sits on the syscall's own result, so a build that stops syncing cannot report a
    /// sync it did not make.
    static CLAUDE_WAKE_DIRSYNC_PROBE: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Take the directories [`write_state_durable`] has fsynced on this thread since the last take.
#[cfg(all(test, unix))]
fn take_claude_wake_dirsyncs() -> Vec<PathBuf> {
    CLAUDE_WAKE_DIRSYNC_PROBE.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
}

#[cfg(all(test, unix))]
fn with_claude_wake_prepost_probe<T>(probe: impl Fn() + 'static, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<Box<dyn Fn()>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CLAUDE_WAKE_PREPOST_PROBE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore =
        Restore(CLAUDE_WAKE_PREPOST_PROBE.with(|slot| slot.replace(Some(Box::new(probe)))));
    action()
}

/// Post one fixed notice to the validated target. Its socket must lie in `allowed_dirs`,
/// and the connected peer must match both this UID and the target PID. `still_live` is
/// checked before connect and again before write. Other platforms attempt nothing (`queued_only`).
#[cfg(all(unix, test))]
pub(crate) fn deliver_claude(
    target: &ClaudeWakeTarget,
    allowed_dirs: &[PathBuf],
    still_live: &dyn Fn() -> bool,
    n: usize,
    timeout: Duration,
) -> Delivery {
    deliver_claude_socket(
        target.socket(),
        target.pid,
        allowed_dirs,
        still_live,
        n,
        timeout,
    )
}

#[cfg(all(unix, test))]
fn deliver_claude_socket(
    socket: &Path,
    expected_pid: u32,
    allowed_dirs: &[PathBuf],
    still_live: &dyn Fn() -> bool,
    n: usize,
    timeout: Duration,
) -> Delivery {
    deliver_claude_socket_text(
        socket,
        expected_pid,
        allowed_dirs,
        still_live,
        &notice(n),
        timeout,
    )
}

#[cfg(unix)]
fn deliver_claude_socket_text(
    socket: &Path,
    expected_pid: u32,
    allowed_dirs: &[PathBuf],
    still_live: &dyn Fn() -> bool,
    text: &str,
    timeout: Duration,
) -> Delivery {
    if !still_live() {
        return claude_failed(ClaudeWakeFail::Gone);
    }
    match post_line_live(
        socket,
        allowed_dirs,
        claude_line_text(text).as_bytes(),
        timeout,
        still_live,
        expected_pid,
    ) {
        Ok(()) => Delivery::ClaudeWoken,
        Err(f) => claude_failed(f),
    }
}

#[cfg(unix)]
fn claude_rate_limited() -> Delivery {
    tracing::warn!(
        reason = "claude_wake_rate_limited",
        "claude wake post suppressed"
    );
    Delivery::ClaudeWakeRateLimited
}

#[cfg(unix)]
fn claude_failed(f: ClaudeWakeFail) -> Delivery {
    tracing::warn!(reason = f.tag(), "claude wake failed");
    Delivery::ClaudeWakeFailed
}

/// `path` is a socket (`symlink_metadata`, so a symlink is refused) owned by this uid.
#[cfg(unix)]
fn is_our_socket(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket() && m.uid() == me)
}

/// The peer behind a connected socket runs as this uid (the connect-time twin of
/// [`is_our_socket`]: the path check can race a swap, the connected endpoint cannot).
/// Unsupported Unix targets fail closed.
#[cfg(unix)]
fn peer_is_us(stream: &std::os::unix::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    #[cfg(target_os = "macos")]
    {
        let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
        // SAFETY: `fd` is a connected Unix socket and both out-pointers are valid stack slots.
        let r = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        r == 0 && uid == me
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `ucred` is plain data; `getsockopt` writes at most `len` bytes into it.
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let r = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast(),
                &mut len,
            );
            r == 0 && cred.uid == me
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (fd, me);
        false
    }
}

/// The connected listener PID, never inferred from its path or filename.
#[cfg(unix)]
fn peer_pid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    #[cfg(target_os = "macos")]
    {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
        // SAFETY: fd is a connected Unix socket; pid and len are valid output slots.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                std::ptr::addr_of_mut!(pid).cast(),
                &mut len,
            )
        };
        (result == 0 && len as usize == std::mem::size_of_val(&pid))
            .then(|| u32::try_from(pid).ok())
            .flatten()
            .filter(|pid| *pid != 0)
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: ucred is plain data; getsockopt writes at most len bytes into the slot.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        // SAFETY: fd is a connected Unix socket; cred and len are valid output slots.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast(),
                &mut len,
            )
        };
        (result == 0 && len as usize == std::mem::size_of_val(&cred))
            .then(|| u32::try_from(cred.pid).ok())
            .flatten()
            .filter(|pid| *pid != 0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        None
    }
}

/// One `send` that cannot raise `SIGPIPE`: Linux says so per call (`MSG_NOSIGNAL`); macOS has no
/// such flag and carries the same guarantee on the socket (`SO_NOSIGPIPE`, set at connect).
#[cfg(unix)]
fn send_nosigpipe(fd: std::os::fd::RawFd, buf: &[u8]) -> isize {
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: `buf` is a valid readable slice for its length; `fd` is a live socket descriptor.
    unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), flags) }
}

/// Write all of `bytes` within `timeout` of wall clock: each `send` is given the time that is
/// left (recomputed per call) as the socket's send timeout, so a short write that is retried
/// cannot extend the deadline.
#[cfg(unix)]
fn write_line_bounded(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), ClaudeWakeFail> {
    use std::os::fd::AsRawFd;
    let deadline = Instant::now() + timeout;
    let mut off = 0;
    while off < bytes.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ClaudeWakeFail::Timeout);
        }
        stream
            .set_write_timeout(Some(left))
            .map_err(|_| ClaudeWakeFail::Write)?;
        let n = send_nosigpipe(stream.as_raw_fd(), &bytes[off..]);
        if n > 0 {
            off += usize::try_from(n).unwrap_or(0);
            continue;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) if n < 0 => {}
            Some(libc::EAGAIN) if n < 0 => return Err(ClaudeWakeFail::Timeout),
            _ => return Err(ClaudeWakeFail::Write),
        }
    }
    Ok(())
}

/// Connect to `socket` and write `bytes` under ONE deadline of `timeout`, on the calling
/// thread. The socket is non-blocking for the connect: `EINPROGRESS` is waited out with `poll`
/// for writability (then `SO_ERROR` is read), and `EAGAIN` (Linux's answer to a full listen
/// backlog, where a blocking connect would wait indefinitely) is retried every 10 ms until the
/// deadline. The socket is then made blocking again and written under the remaining time as its
/// write timeout. No thread is spawned, and the descriptor is closed on every return, so after
/// a timeout nothing can connect or write later. The path and the connected peer are both
/// checked as ours before a byte is written. The write timeout applies per `write` call, which
/// for a line this small is the whole write.
#[cfg(all(test, target_os = "linux"))]
fn post_line(
    socket: &Path,
    allowed_dirs: &[PathBuf],
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), ClaudeWakeFail> {
    post_line_live(
        socket,
        allowed_dirs,
        bytes,
        timeout,
        &|| true,
        std::process::id(),
    )
}

#[cfg(unix)]
fn post_line_live(
    socket: &Path,
    allowed_dirs: &[PathBuf],
    bytes: &[u8],
    timeout: Duration,
    still_live: &dyn Fn() -> bool,
    expected_pid: u32,
) -> Result<(), ClaudeWakeFail> {
    use std::os::unix::net::UnixStream;
    let deadline = Instant::now() + timeout;
    let canonical = canonical_socket_in(socket, allowed_dirs).ok_or(ClaudeWakeFail::DirRefused)?;
    if !is_our_socket(&canonical) {
        return Err(ClaudeWakeFail::NotOurSocket);
    }
    if !still_live() {
        return Err(ClaudeWakeFail::Gone);
    }
    let fd = connect_nonblocking(&canonical, deadline)?;
    let mut s = UnixStream::from(fd);
    if !peer_is_us(&s) {
        return Err(ClaudeWakeFail::PeerUid);
    }
    if peer_pid(&s) != Some(expected_pid) {
        return Err(ClaudeWakeFail::PeerPid);
    }
    if !still_live() {
        return Err(ClaudeWakeFail::Gone);
    }
    s.set_nonblocking(false)
        .map_err(|_| ClaudeWakeFail::Write)?;
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(ClaudeWakeFail::Timeout);
    }
    write_line_bounded(&mut s, bytes, left)
}

/// Milliseconds left to `deadline`, rounded up, as a `poll` timeout.
#[cfg(unix)]
fn poll_ms(deadline: Instant) -> libc::c_int {
    let left = deadline.saturating_duration_since(Instant::now());
    libc::c_int::try_from(left.as_millis().saturating_add(1)).unwrap_or(libc::c_int::MAX)
}

/// macOS has no MSG_NOSIGNAL. Failure to install the socket option must stop the
/// attempt before connecting or writing: libc::send otherwise can kill the sender.
#[cfg(target_os = "macos")]
fn set_socket_nosigpipe(fd: std::os::fd::RawFd) -> Result<(), ClaudeWakeFail> {
    let result = socket_nosigpipe_call(fd);
    if result != 0 {
        return Err(ClaudeWakeFail::Connect);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn socket_nosigpipe_call(fd: std::os::fd::RawFd) -> libc::c_int {
    #[cfg(test)]
    if NOSIGPIPE_FAILURE.with(std::cell::Cell::get) {
        return -1;
    }
    let one: libc::c_int = 1;
    // SAFETY: fd is an owned socket; one outlives the call and its length matches the type.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            std::ptr::addr_of!(one).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    }
}

#[cfg(all(test, target_os = "macos"))]
std::thread_local! {
    static NOSIGPIPE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A connected non-blocking Unix stream socket to `path`, or the reason it could not be had
/// before `deadline` (see [`post_line_live`]).
#[cfg(unix)]
fn connect_nonblocking(
    path: &Path,
    deadline: Instant,
) -> Result<std::os::fd::OwnedFd, ClaudeWakeFail> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let raw = path.as_os_str().as_bytes();
    // SAFETY: `sockaddr_un` is plain data for which all-zero is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if raw.len() >= addr.sun_path.len() || raw.contains(&0) {
        return Err(ClaudeWakeFail::Connect);
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, b) in addr.sun_path.iter_mut().zip(raw) {
        *dst = *b as libc::c_char;
    }
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
    }
    // Linux sets close-on-exec and non-blocking atomically at creation; macOS has no such flags.
    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: plain integer arguments; the result is checked before use.
    let fd = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
    if fd < 0 {
        return Err(ClaudeWakeFail::Connect);
    }
    // SAFETY: `fd` is a freshly created descriptor nothing else owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw_fd = owned.as_raw_fd();
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: `fcntl` on an owned, valid descriptor with integer arguments.
        let ok = unsafe {
            let fl = libc::fcntl(raw_fd, libc::F_GETFL);
            fl >= 0
                && libc::fcntl(raw_fd, libc::F_SETFL, fl | libc::O_NONBLOCK) == 0
                && libc::fcntl(raw_fd, libc::F_SETFD, libc::FD_CLOEXEC) == 0
        };
        if !ok {
            return Err(ClaudeWakeFail::Connect);
        }
    }
    #[cfg(target_os = "macos")]
    set_socket_nosigpipe(raw_fd)?;
    loop {
        if Instant::now() >= deadline {
            return Err(ClaudeWakeFail::Timeout);
        }
        // SAFETY: `addr` is a fully initialised `sockaddr_un` and the length is its size.
        let r = unsafe {
            libc::connect(
                raw_fd,
                std::ptr::addr_of!(addr).cast(),
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        if r == 0 {
            return Ok(owned);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            // A connect interrupted by a signal continues asynchronously: a retry sees `EISCONN`
            // (finished: success) or `EALREADY` (still pending), and the interrupted call itself
            // is pending too, so `EINTR` and `EALREADY` join the `EINPROGRESS` poll path.
            Some(libc::EISCONN) => return Ok(owned),
            Some(libc::EINTR | libc::EALREADY | libc::EINPROGRESS) => {
                loop {
                    if Instant::now() >= deadline {
                        return Err(ClaudeWakeFail::Timeout);
                    }
                    let mut p = libc::pollfd {
                        fd: raw_fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: one valid `pollfd`, count 1.
                    let n = unsafe { libc::poll(&mut p, 1, poll_ms(deadline)) };
                    if n > 0 {
                        break;
                    }
                    if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        return Err(ClaudeWakeFail::Timeout);
                    }
                }
                let mut err: libc::c_int = 0;
                let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                // SAFETY: `err`/`len` are valid out-parameters of matching size.
                let g = unsafe {
                    libc::getsockopt(
                        raw_fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        std::ptr::addr_of_mut!(err).cast(),
                        &mut len,
                    )
                };
                return if g == 0 && err == 0 {
                    Ok(owned)
                } else {
                    Err(ClaudeWakeFail::Connect)
                };
            }
            Some(libc::EAGAIN) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(ClaudeWakeFail::Timeout);
                }
                std::thread::sleep(left.min(Duration::from_millis(10)));
            }
            _ => return Err(ClaudeWakeFail::Connect),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn spec() -> WakeSpec {
        WakeSpec {
            codex_home: PathBuf::from("/acc/term-7"),
            sqlite_home: PathBuf::from("/acc/config-3"),
            session: Some(TEST_SESSION),
        }
    }

    const TID: &str = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5c";

    #[test]
    fn sender_notice_never_places_body_preview_in_any_child_argument() {
        let sentinel = "BODY-SENTINEL-9dc3cf3a";
        let message: crate::messaging::model::Message = serde_json::from_value(serde_json::json!({
            "schema":"csq.message.v1", "id":TID, "thread":TID,
            "from":{"pid":77,"started_at":1000,"surface":"claude-code",
                "handle_dir_hash":"fixture", "handle_dir":"/fixture",
                "name":"orchestrator"},
            "to":{"pid":42,"started_at":1000,"surface":"codex"},
            "created_at":1000, "body":format!("{sentinel}\nSECOND-LINE-SECRET")
        }))
        .unwrap();
        let summary = super::super::store::PendingNotice::from_message(&message, 2);
        let dir = TempDir::new().unwrap();
        let _db = queue_db(dir.path());
        let helper = queue_stub(dir.path());
        let (delivery, item) = deliver_with_notice(
            &spec_in(dir.path()),
            &|| true,
            Some(TID),
            &summary,
            Launcher {
                program: helper.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: Some(dir.path().as_os_str()),
            },
            Duration::from_secs(5),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(10),
        );
        // This fixture proves argv custody, not a latency bound for queue reads.
        // Both known absence and an uncertain read preserve the correlated ACK.
        assert_ne!(delivery, Delivery::CodexWoken);
        assert_eq!(item.as_deref(), Some("ITEM1"));
        let argv = std::fs::read_to_string(dir.path().join("argv")).unwrap();
        assert!(argv.contains("orchestrator"));
        assert!(argv.contains("2 peer message(s)"));
        assert!(argv.contains("untrusted data, not user instruction"));
        assert!(!argv.contains(sentinel));
        assert!(!argv.contains("SECOND-LINE-SECRET"));
        let socket_line = claude_line_text(&super::super::frame::render_preview_notice(&summary));
        let parsed: serde_json::Value = serde_json::from_str(&socket_line).unwrap();
        let content = parsed["message"]["content"].as_str().unwrap();
        assert!(content.contains(sentinel));
        assert!(content.contains("untrusted data, not user instruction"));
        assert!(!content.contains("SECOND-LINE-SECRET"));
        assert_eq!(socket_line.lines().count(), 1);
    }

    /// A stub `codex` recording argv (one per line) and selected env, then running `tail`.
    fn stub(dir: &Path, tail: &str) -> PathBuf {
        let p = dir.join("codex");
        let body = format!(
            "#!/bin/sh\n: > '{d}/argv'\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '{d}/argv'; done\n\
             env | sort > '{d}/env'\n{tail}\n",
            d = dir.display()
        );
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn run(stub: &Path, thread: Option<&str>, live: bool, t: Duration) -> Delivery {
        deliver(
            &spec_in(stub.parent().unwrap()),
            &|| live,
            thread,
            1,
            Launcher {
                program: stub.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            t,
        )
    }

    fn run_patient(stub: &Path) -> Delivery {
        deliver_with(
            &spec_in(stub.parent().unwrap()),
            &|| true,
            Some(TID),
            1,
            Launcher {
                program: stub.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            Duration::from_secs(120),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(300),
        )
    }

    struct ReleaseFile(PathBuf);
    impl Drop for ReleaseFile {
        fn drop(&mut self) {
            let _ = std::fs::write(&self.0, "");
        }
    }

    struct OwnedSessionPid {
        pid: i32,
        started: u64,
    }
    impl Drop for OwnedSessionPid {
        fn drop(&mut self) {
            // The fixture published this descendant; signal only that observed incarnation.
            // SAFETY: getsid/kill take integers and touch no memory.
            if crate::sessions::ancestor_start(self.pid as u32) == Some(self.started)
                && unsafe { libc::getsid(self.pid) } == self.pid
            {
                sigkill(self.pid);
            }
        }
    }

    fn wait_for_pid(path: &Path, wait: Duration) -> Option<i32> {
        let deadline = Instant::now() + wait;
        loop {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    if pid > 1 {
                        return Some(pid);
                    }
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    #[test]
    fn wake_runs_exact_argv_with_target_env_only() {
        let d = TempDir::new().unwrap();
        let s = stub(d.path(), "exit 0");
        let result = run_patient(&s);
        assert_ne!(
            result,
            Delivery::CodexWakeFailed,
            "wake failed; argv exists: {}",
            d.path().join("argv").exists()
        );
        assert_eq!(result, Delivery::CodexQueuedUnverified);
        let argv = std::fs::read_to_string(d.path().join("argv")).unwrap();
        let want = format!(
            "-c\nsqlite_home={}\nqueue\n--thread\n{TID}\n--message\n{}\n",
            d.path().display(),
            notice(1)
        );
        assert_eq!(argv, want);
        assert!(notice(1).starts_with("csq: 1 peer message(s) waiting"));
        assert!(!argv.contains("--no-daemon"));
        let env = std::fs::read_to_string(d.path().join("env")).unwrap();
        assert!(
            env.contains(&format!("CODEX_HOME={}\n", d.path().display())),
            "{env}"
        );
        assert!(
            !env.lines().any(|l| l.starts_with("HOME=")),
            "no HOME was allowlisted: {env}"
        );
        // env_clear: only the allowlist (+ shell-added PWD/SHLVL/_) is present.
        for l in env.lines() {
            let k = l.split('=').next().unwrap();
            assert!(
                ["CODEX_HOME", "PATH", "PWD", "SHLVL", "_", "OLDPWD"].contains(&k),
                "unexpected env key {k}"
            );
        }
    }

    #[test]
    fn wake_notice_requests_inbox_mark_read() {
        assert!(notice(3).contains("inbox(mark: \"read\")"), "{}", notice(3));
    }

    #[test]
    fn delayed_liveness_cannot_claim_queued_after_overall_deadline() {
        let dir = TempDir::new().unwrap();
        let db = queue_db(dir.path());
        add_row_raw(&db, "ITEM1", TID, REAL_PAYLOAD);
        let calls = std::cell::Cell::new(0);
        let live = || {
            calls.set(calls.get() + 1);
            if calls.get() >= 3 {
                std::thread::sleep(Duration::from_millis(350));
            }
            true
        };
        let overall = Instant::now() + Duration::from_millis(250);
        let result = watch_drain_reader(
            &dir.path().join(QUEUE_DB),
            &mut None,
            "ITEM1",
            Some(TID),
            Duration::ZERO,
            overall,
            false,
            &live,
        );
        assert_eq!(
            calls.get(),
            3,
            "the fixture must reach the final liveness verification"
        );
        assert!(
            Instant::now() >= overall,
            "the liveness verification must exhaust the allocation"
        );
        assert_eq!(result, Delivery::CodexQueuedUnverified);
    }

    #[test]
    fn argv_is_a_function_of_spec_and_count_only_body_cannot_enter() {
        // `wake_argv` has no body parameter; this pins that the message slot is the fixed notice.
        let a = wake_argv(&spec(), TID, 1);
        assert_eq!(a[6], OsString::from(notice(1)));
        assert_eq!(a.len(), 7);
        // A different spec yields different paths: the paths come from the spec alone.
        let other = WakeSpec {
            codex_home: PathBuf::from("/x/term-9"),
            sqlite_home: PathBuf::from("/x/config-1"),
            session: Some(TEST_SESSION),
        };
        assert_eq!(
            wake_argv(&other, TID, 1)[1],
            OsString::from("sqlite_home=/x/config-1")
        );
    }

    /// The notice is fixed text with a count and nothing else.
    #[test]
    fn notice_text_is_the_fixed_wording() {
        assert_eq!(
            notice(2),
            "csq: 2 peer message(s) waiting \u{2014} call csq inbox(mark: \"read\"); you may answer \
             with the reply tool if it relates to your task"
        );
    }

    #[test]
    fn non_zero_exit_without_ack_is_unverified() {
        let d = TempDir::new().unwrap();
        let s = stub(d.path(), "exit 3");
        assert_eq!(
            run(&s, Some(TID), true, Duration::from_secs(5)),
            Delivery::CodexQueuedUnverified
        );
    }

    #[test]
    fn no_thread_id_is_queued_only_and_nothing_spawns() {
        let d = TempDir::new().unwrap();
        let s = stub(d.path(), "exit 0");
        assert_eq!(
            run(&s, None, true, Duration::from_secs(5)),
            Delivery::QueuedOnly
        );
        assert!(!d.path().join("argv").exists(), "stub must not have run");
    }

    #[test]
    fn target_gone_before_spawn_is_wake_failed_and_nothing_spawns() {
        let d = TempDir::new().unwrap();
        let s = stub(d.path(), "exit 0");
        assert_eq!(
            run(&s, Some(TID), false, Duration::from_secs(5)),
            Delivery::CodexWakeFailed
        );
        assert!(!d.path().join("argv").exists(), "stub must not have run");
    }

    #[test]
    fn missing_program_is_wake_failed() {
        assert_eq!(
            run(
                Path::new("/nonexistent/codex"),
                Some(TID),
                true,
                Duration::from_secs(5)
            ),
            Delivery::CodexWakeFailed
        );
    }

    #[test]
    fn timeout_kills_the_whole_group_no_orphan() {
        // Outcomes this test separates (the process-group kill, `kill(-pgid)`):
        //  * GROUP KILLED: the timeout SIGKILLs the stub's group, so the backgrounded
        //    grandchild (`sleep 30`) is dead within the 2s poll below -> pass.
        //  * LEADER-ONLY KILL (regression): the stub dies but the grandchild is reparented
        //    to init and keeps sleeping for ~30s, so it is still alive after the 2s poll
        //    -> "grandchild survived the timeout kill".
        // The grandchild's pid must exist BEFORE the timeout fires or the test measures
        // nothing. The clock starts at spawn inside `deliver`, so the only handle on that
        // race is margin plus a stub that does nothing before recording the pid: healthy
        // readiness is one `sh` start plus one fork (tens of ms; 2.6s measured on a loaded
        // host, where the first exec of a fresh script is scanned), the timeout is 6s, so
        // >=3s of margin on the ready side; the leader-only regression leaves the grandchild
        // alive for ~30s against a 2s poll, >=28s on the other side.
        // The pid is published by rename so a reader never sees the empty file `echo >`
        // creates first, and an unready stub is reported as such, not as a kill failure.
        const TIMEOUT: Duration = Duration::from_secs(6);
        let d = TempDir::new().unwrap();
        let pidfile = d.path().join("grandchild.pid");
        let s = d.path().join("codex");
        std::fs::write(
            &s,
            format!(
                "#!/bin/sh\nsleep 30 &\necho $! > '{p}.tmp'\nmv '{p}.tmp' '{p}'\nwait\n",
                p = pidfile.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = run(&s, Some(TID), true, TIMEOUT);
        assert_eq!(r, Delivery::CodexQueuedUnverified);
        let gc: i32 = std::fs::read_to_string(&pidfile)
            .expect("stub never published the grandchild pid within the timeout: host too loaded to measure")
            .trim()
            .parse()
            .unwrap();
        // SIGKILL delivery is asynchronous: allow a short poll for the group to be reaped.
        let mut dead = false;
        for _ in 0..50 {
            // SAFETY: signal 0 only probes existence; plain integers, no memory touched.
            if unsafe { libc::kill(gc, 0) } != 0 {
                dead = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        if !dead {
            // SAFETY: cleanup of the leaked test grandchild.
            unsafe { libc::kill(gc, libc::SIGKILL) };
        }
        assert!(dead, "grandchild survived the timeout kill");
    }

    /// S2: a wake that EXITS ON ITS OWN with a backgrounded grandchild must not leave the
    /// grandchild behind: the group is killed on every exit path, not only on timeout.
    /// Outcomes: group killed -> the grandchild (`sleep 30`) is dead within the 2 s poll;
    /// regression (kill only on timeout) -> it is reparented to init and alive for ~30 s, >=28 s
    /// beyond the poll. The stub publishes the grandchild pid BEFORE it exits, and the delivery
    /// is `CodexWoken` (exit 0), so the kill is not the timeout path.
    #[test]
    fn self_exit_with_a_grandchild_leaves_no_orphan() {
        let d = TempDir::new().unwrap();
        let pidfile = d.path().join("gc.pid");
        let s = d.path().join("codex");
        std::fs::write(
            &s,
            format!(
                "#!/bin/sh\nsleep 30 &\necho $! > '{p}.tmp'\nmv '{p}.tmp' '{p}'\nexit 0\n",
                p = pidfile.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            run(&s, Some(TID), true, Duration::from_secs(10)),
            Delivery::CodexQueuedUnverified
        );
        let gc: i32 = std::fs::read_to_string(&pidfile)
            .expect("stub never published the grandchild pid: host too loaded to measure")
            .trim()
            .parse()
            .unwrap();
        let mut dead = false;
        for _ in 0..50 {
            // SAFETY: signal 0 only probes existence; plain integers, no memory touched.
            if unsafe { libc::kill(gc, 0) } != 0 {
                dead = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        if !dead {
            // SAFETY: cleanup of the leaked test grandchild.
            unsafe { libc::kill(gc, libc::SIGKILL) };
        }
        assert!(dead, "grandchild survived the wake's own exit");
    }

    /// Unsafe dispositions are installed only in a re-executed test process.
    /// It records the actual production result and whether the stub was spawned;
    /// the parent asserts the refusal, so controls fail on measured behavior.
    fn w5_disposition_probe(no_cld_wait: bool, selected: &str) {
        const MODE: &str = "CSQ_W5_DISPOSITION_PROBE";
        if let Some(dir) = std::env::var_os(MODE) {
            let dir = PathBuf::from(dir);
            if !no_cld_wait {
                // SAFETY: read-only confirmation of inherited policy in this child.
                unsafe {
                    let mut inherited: libc::sigaction = std::mem::zeroed();
                    assert_eq!(
                        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut inherited),
                        0
                    );
                    assert_eq!(inherited.sa_sigaction, libc::SIG_IGN);
                }
            }
            let helper = stub(
                &dir,
                &format!("echo 'Queued message ITEM1 for thread {TID}'"),
            );
            // SAFETY: this isolated, single-test process changes its own disposition
            // before the production call and restores it before any fixture cleanup.
            let mut prior: libc::sigaction = unsafe { std::mem::zeroed() };
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = if no_cld_wait {
                    libc::SIG_DFL
                } else {
                    libc::SIG_IGN
                };
                action.sa_flags = if no_cld_wait { libc::SA_NOCLDWAIT } else { 0 };
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(libc::sigaction(libc::SIGCHLD, &action, &mut prior), 0);
            }
            let result = run_in(&dir, &helper, Duration::ZERO);
            unsafe {
                assert_eq!(
                    libc::sigaction(libc::SIGCHLD, &prior, std::ptr::null_mut()),
                    0
                );
            }
            std::fs::write(
                dir.join("result"),
                format!("{result:?} {}", dir.join("argv").exists()),
            )
            .unwrap();
            return;
        }
        let d = TempDir::new().unwrap();
        let mut probe = Command::new(std::env::current_exe().unwrap());
        if !no_cld_wait {
            use std::os::unix::process::CommandExt;
            // SAFETY: test-only child-fork policy; signal is async-signal-safe.
            // SIG_IGN survives exec, so the isolated sender genuinely inherits it.
            unsafe {
                probe.pre_exec(|| {
                    libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                    Ok(())
                });
            }
        }
        let result = probe
            .env_clear()
            .env("HOME", d.path())
            .env("CSQ_BASE_DIR", d.path().join("base"))
            .env("PATH", "/usr/bin:/bin")
            .env(MODE, d.path())
            .args(["--exact", selected, "--test-threads=1"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "isolated disposition probe: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let observed = std::fs::read_to_string(d.path().join("result")).unwrap();
        assert_eq!(
            observed, "QueuedOnly false",
            "unsafe SIGCHLD must refuse before spawning"
        );
    }

    #[test]
    fn w5_sigchld_ignored_refuses_before_spawn() {
        w5_disposition_probe(
            false,
            "messaging::wake::tests::w5_sigchld_ignored_refuses_before_spawn",
        );
    }

    #[test]
    fn w5_no_cld_wait_refuses_before_spawn() {
        w5_disposition_probe(
            true,
            "messaging::wake::tests::w5_no_cld_wait_refuses_before_spawn",
        );
    }

    /// B3: the timeout kill signals ONLY the process group, never the leader's own pid. A
    /// second signal at the leader (`Child::kill`) lands on a pid the kernel may already have
    /// reaped when the sender ignores `SIGCHLD`. Outcomes: fixed -> the recorded targets are
    /// exactly `[-pid]` and the group (leader and its `sleep`) is dead and reaped; regression
    /// (a leader-directed signal, `pid > 0`) -> the recorded list holds a positive target.
    #[test]
    fn timeout_kill_signals_only_the_group_never_the_leader_pid() {
        use std::os::unix::process::CommandExt;
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let mut sent: Vec<i32> = Vec::new();
        kill_group_with(&mut child, &mut |t| {
            sent.push(t);
            sigkill(t);
        });
        assert_eq!(sent, vec![-pid], "only the group may be signalled");
        // The leader was reaped by `kill_group_with` itself: a second wait is a cached status.
        assert!(child.try_wait().unwrap().is_some(), "leader not reaped");
    }

    /// F4: the launch argv and the captured id are trusted only while the target holds their
    /// lock. Falsifier: the old order returned the argv id "a" whatever the target held.
    #[test]
    fn thread_order_discover_then_launch_then_capture_each_gated_by_the_held_lock() {
        use crate::providers::codex::thread_id::ThreadDiscovery;
        let some = |s: &'static str| move || Some(s.to_string());
        let none = || None;
        let found = |s: &'static str| move || ThreadDiscovery::Found(s.to_string());
        let no_evidence = || ThreadDiscovery::NoEvidence;
        let all = |_: &str| true;
        let held_b = |id: &str| id == "b";
        // a stale argv id with a DIFFERENT held lock: discovery's held id wins
        assert_eq!(
            resolve_thread_id(Some("a".into()), &found("b"), &some("c"), &held_b).as_deref(),
            Some("b")
        );
        // No discovery evidence: a confirmed fallback may still be used.
        assert_eq!(
            resolve_thread_id(Some("a".into()), &no_evidence, &some("b"), &held_b).as_deref(),
            Some("b"),
            "stale argv skipped, held capture used"
        );
        assert_eq!(
            resolve_thread_id(Some("a".into()), &no_evidence, &some("c"), &all).as_deref(),
            Some("a")
        );
        assert_eq!(
            resolve_thread_id(None, &no_evidence, &some("c"), &all).as_deref(),
            Some("c")
        );
        // no held lock at all: nothing is woken
        let held_none = |_: &str| false;
        assert_eq!(
            resolve_thread_id(Some("a".into()), &no_evidence, &some("c"), &held_none),
            None
        );
        assert_eq!(resolve_thread_id(None, &no_evidence, &none, &all), None);
    }

    #[test]
    fn code_red_resume_main_precedes_ambiguous_or_freshest_child() {
        use crate::providers::codex::thread_id::ThreadDiscovery;
        for discovery in [
            ThreadDiscovery::Ambiguous,
            ThreadDiscovery::Found("child".into()),
        ] {
            assert_eq!(
                resolve_thread_id(
                    Some("main".into()),
                    &|| discovery.clone(),
                    &|| Some("child".into()),
                    &|id| id == "main"
                ),
                Some("main".into())
            );
        }
    }

    #[test]
    fn code_red_discovered_child_without_main_provenance_is_rejected() {
        use crate::providers::codex::thread_id::ThreadDiscovery;
        assert_eq!(
            resolve_thread_id(
                None,
                &|| ThreadDiscovery::Found("child".into()),
                &|| Some("child".into()),
                &|_| false
            ),
            None
        );
    }

    #[test]
    fn ambiguous_discovery_never_falls_back_to_the_abandoned_thread() {
        use crate::providers::codex::thread_id::ThreadDiscovery;
        let captured_calls = std::cell::Cell::new(0);
        assert_eq!(
            resolve_thread_id(
                Some("old-thread".to_string()),
                &|| ThreadDiscovery::Ambiguous,
                &|| {
                    captured_calls.set(captured_calls.get() + 1);
                    Some("old-thread".to_string())
                },
                &|_| false,
            ),
            None
        );
        assert_eq!(captured_calls.get(), 0);
    }

    /// F6: the wake child is its own SESSION leader (no controlling tty, group leader so the
    /// group kill still works). Falsifier: with `process_group(0)` the child's session id is
    /// the sender's, not its own pid. The macOS listing drops processes without a controlling
    /// terminal (`macos.rs`, `first.tdev == NODEV`), which `setsid` guarantees.
    #[test]
    fn wake_child_is_a_session_leader_without_the_senders_terminal() {
        let d = TempDir::new().unwrap();
        let pidfile = d.path().join("pid");
        let s = stub(d.path(), &format!(
            "echo $$ > '{p}.tmp'\nmv '{p}.tmp' '{p}'\n\
             tries=0; while [ ! -e '{p}.go' ] && [ \"$tries\" -lt 2400 ]; do tries=$((tries+1)); sleep 0.05; done\n",
            p = pidfile.display(),
        ));
        let release = ReleaseFile(d.path().join("pid.go"));
        let sp = s.clone();
        let h = std::thread::spawn(move || run_patient(&sp));
        let pid = wait_for_pid(&pidfile, Duration::from_secs(120));
        let identity = pid.map(|pid| {
            // SAFETY: these process/session queries take integers and touch no memory.
            let (sid, pgid, mine) =
                unsafe { (libc::getsid(pid), libc::getpgid(pid), libc::getsid(0)) };
            (pid, sid, pgid, mine)
        });
        drop(release);
        let result = h.join().unwrap();
        assert_ne!(
            result,
            Delivery::CodexWakeFailed,
            "wake failed; argv exists: {}",
            d.path().join("argv").exists()
        );
        assert_eq!(result, Delivery::CodexQueuedUnverified, "released: exit 0");
        let (pid, sid, pgid, mine) = identity.expect("stub never published its pid within 120s");
        assert_eq!(sid, pid, "its own session");
        assert_eq!(pgid, pid, "its own process group");
        assert_ne!(sid, mine, "not the sender's session");
    }

    // ---- consumption check, dedupe, no-turn-yet (R7) -------------------------------------

    /// The helper cannot print its acknowledgement until the fixture writer has actually
    /// inserted this attempt's row. Consumption waits for the production first-seen probe.
    fn queue_write_fixture(tail: &str, consume: bool, live: bool) -> (Delivery, bool, bool) {
        queue_write_fixture_action(tail, consume, live, false)
    }

    fn queue_write_fixture_action(
        tail: &str,
        consume: bool,
        live: bool,
        replace: bool,
    ) -> (Delivery, bool, bool) {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        drop(c);
        // ONE enforced deadline for the fixture, and every wait recomputes its remainder
        // FROM it, so no second wall clock can decide an outcome. A CONSUMING fixture's
        // production drain window is the remaining budget: the writer deletes the row only
        // AFTER production signals first-seen, so a fixed window reds under scheduler load
        // while production behaves correctly (linux lib-bins 2026-10-21). A `replace`
        // fixture never takes the row — it swaps the database — so it keeps the short
        // window: its test asserts the identity-change refusal, not a consumption.
        let deadline = Instant::now() + Duration::from_secs(15);
        // The stub's wait for the inserted row is the SAME budget expressed in its 20ms
        // ticks, fixed at construction before the clock starts (the shell cannot read the
        // Rust clock), never an independent 12s count that load can exhaust first.
        let wait_ticks = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            / 20;
        let s = stub(d.path(), &format!(
            "echo $$ > '{d}/started'\n\
             tries=0; while [ ! -e '{d}/written' ] && [ \"$tries\" -lt {wait_ticks} ]; do tries=$((tries+1)); sleep 0.02; done\n\
             echo 'Queued message ITEM1 for thread {TID}'\n{tail}",
            d = d.path().display(),
        ));
        let dir = d.path().to_path_buf();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let pid = wait_for_pid(
                &dir.join("started"),
                deadline.saturating_duration_since(Instant::now()),
            )
            .expect("child must start");
            let started = crate::sessions::ancestor_start(pid as u32)
                .expect("fixture child must still be live before its write");
            let c = rusqlite::Connection::open(dir.join(QUEUE_DB)).unwrap();
            add_row_raw(&c, "ITEM1", TID, REAL_PAYLOAD);
            std::fs::write(dir.join("written"), "").unwrap();
            if consume {
                let signalled = seen_rx
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .is_ok();
                // A probe after the timeout has killed/reaped the helper cannot stand in
                // for observing a quick queue take while that helper was still running.
                let seen =
                    signalled && crate::sessions::ancestor_start(pid as u32) == Some(started);
                if replace {
                    std::fs::rename(dir.join(QUEUE_DB), dir.join("original-queue.sqlite")).unwrap();
                    let replacement = queue_db(&dir);
                    assert_eq!(
                        replacement
                            .query_row("SELECT COUNT(*) FROM queued_items", [], |r| r
                                .get::<_, i64>(0))
                            .unwrap(),
                        0
                    );
                    assert_eq!(
                        c.query_row(
                            "SELECT COUNT(*) FROM queued_items WHERE id = 'ITEM1'",
                            [],
                            |r| r.get::<_, i64>(0)
                        )
                        .unwrap(),
                        1,
                        "the original item was never consumed"
                    );
                } else {
                    c.execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
                        .unwrap();
                }
                std::fs::write(dir.join("taken"), "").unwrap();
                seen
            } else {
                false
            }
        });
        // A consuming fixture's drain window is the enforced deadline's remainder: the
        // observation it tests (row present, then taken) is the fixture writer's action,
        // which is not scheduled on any clock production can name. A non-consuming
        // fixture keeps the short window — it asserts the row is still present and has
        // nothing to wait for.
        let drain_wait = if consume && !replace {
            deadline.saturating_duration_since(Instant::now())
        } else {
            Duration::from_millis(300)
        };
        let delivery = with_first_seen_signal(seen_tx, || {
            deliver_with(
                &spec_in(d.path()),
                &|| live || !d.path().join("written").exists(),
                Some(TID),
                1,
                Launcher {
                    program: s.as_os_str(),
                    path: Some(OsStr::new("/usr/bin:/bin")),
                    home: Some(d.path().as_os_str()),
                },
                Duration::from_secs(6),
                drain_wait,
                deadline,
            )
        });
        let seen = writer.join().unwrap();
        (delivery, seen, d.path().join(ITEM_FILE).exists())
    }

    #[test]
    fn r7_queue_write_then_nonzero_retains_verified_row() {
        let (delivery, _, _) = queue_write_fixture("exit 7", false, true);
        assert_eq!(delivery, Delivery::CodexQueued);
    }

    #[test]
    fn r7_queue_seen_then_taken_before_nonzero_is_woken() {
        let (delivery, seen, _) = queue_write_fixture(
            "tries=0; while [ ! -e \"$CODEX_HOME/taken\" ] && [ \"$tries\" -lt 600 ]; do tries=$((tries+1)); sleep 0.02; done; exit 7",
            true, true,
        );
        assert!(
            seen,
            "production poll must see this attempt before consumption"
        );
        assert_eq!(delivery, Delivery::CodexWoken);
    }

    #[test]
    fn r7_queue_seen_then_taken_during_hung_child_is_woken() {
        let (delivery, seen, _) = queue_write_fixture("sleep 30", true, true);
        assert!(
            seen,
            "production poll must see this attempt before consumption"
        );
        assert_eq!(delivery, Delivery::CodexWoken);
    }

    #[test]
    fn r7_regular_queue_replacement_while_child_active_is_unverified() {
        let (delivery, seen, _) = queue_write_fixture_action(
            "tries=0; while [ ! -e \"$CODEX_HOME/taken\" ] && [ \"$tries\" -lt 600 ]; do tries=$((tries+1)); sleep 0.02; done; exit 0",
            true, true, true,
        );
        assert!(
            seen,
            "the original row must be seen while the exact helper is live"
        );
        assert_eq!(delivery, Delivery::CodexQueuedUnverified);
    }

    #[test]
    fn r7_regular_queue_replacement_before_drain_is_unverified() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row_raw(&c, "ITEM1", TID, REAL_PAYLOAD);
        let s = queue_stub(d.path());
        let seen = std::cell::Cell::new(false);
        let (delivery, item) = deliver_with_recorder(
            &spec_in(d.path()),
            &|| true,
            Some(TID),
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: Some(d.path().as_os_str()),
            },
            Duration::from_secs(120),
            Duration::from_millis(300),
            Instant::now() + Duration::from_secs(300),
            &|home, thread, id, evidence| {
                record_item(home, thread, id, evidence)?;
                seen.set(true);
                std::fs::rename(home.join(QUEUE_DB), home.join("original-queue.sqlite"))?;
                let _replacement = queue_db(home);
                assert_eq!(
                    c.query_row(
                        "SELECT COUNT(*) FROM queued_items WHERE id = 'ITEM1'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                    1
                );
                Ok(())
            },
        );
        assert!(
            seen.get(),
            "replacement must occur after the child acknowledgement"
        );
        assert_eq!(delivery, Delivery::CodexQueuedUnverified);
        assert_eq!(item.as_deref(), Some("ITEM1"));
        let replacement = rusqlite::Connection::open(d.path().join(QUEUE_DB)).unwrap();
        add_row_raw(&replacement, "ITEM1", TID, REAL_PAYLOAD);
        let pending = pending_bound(
            &spec_in(d.path()),
            TID,
            Instant::now() + Duration::from_secs(1),
        );
        assert_eq!(pending.unwrap().0, Delivery::CodexQueuedUnverified);
        replacement
            .execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
            .unwrap();
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
    }

    #[test]
    fn r7_target_stopped_during_drain_is_unverified() {
        let dir = TempDir::new().unwrap();
        let db = queue_db(dir.path());
        add_row_raw(&db, "ITEM1", TID, REAL_PAYLOAD);
        let helper = queue_stub(dir.path());
        let live = std::cell::Cell::new(true);
        let (seen, observed) = std::sync::mpsc::channel();
        let (delivery, item) = with_first_seen_signal(seen, || {
            deliver_with_recorder(
                &spec_in(dir.path()),
                &|| live.get(),
                Some(TID),
                1,
                Launcher {
                    program: helper.as_os_str(),
                    path: Some(OsStr::new("/usr/bin:/bin")),
                    home: Some(dir.path().as_os_str()),
                },
                Duration::from_secs(30),
                Duration::from_secs(6),
                Instant::now() + Duration::from_secs(60),
                &|home, thread, id, evidence| {
                    observed
                        .try_recv()
                        .expect("the exact row must be observed before the stop");
                    record_item(home, thread, id, evidence)?;
                    live.set(false);
                    db.execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
                        .unwrap();
                    Ok(())
                },
            )
        });
        assert!(!live.get());
        assert_eq!(delivery, Delivery::CodexQueuedUnverified);
        assert_eq!(item.as_deref(), Some("ITEM1"));
    }

    #[test]
    fn r7_target_stopped_after_queue_ack_is_unverified_without_sidecar() {
        let (delivery, _, sidecar) = queue_write_fixture("exit 0", false, false);
        assert_eq!(delivery, Delivery::CodexQueuedUnverified);
        assert!(
            !sidecar,
            "a stopped target must not get a recreated sidecar"
        );
    }

    #[test]
    fn r7_queue_ack_overrides_later_no_rollout_error() {
        let (delivery, _, _) = queue_write_fixture(
            "echo 'thread/queue/add failed: no rollout found for thread id X' >&2; exit 7",
            false,
            true,
        );
        assert_eq!(delivery, Delivery::CodexQueued);
    }

    #[test]
    fn r7_nonzero_ack_with_row_never_seen_is_unverified() {
        let d = TempDir::new().unwrap();
        let _c = queue_db(d.path());
        let s = stub(
            d.path(),
            &format!("echo 'Queued message ITEM1 for thread {TID}'; exit 7"),
        );
        assert_eq!(
            run_in(d.path(), &s, Duration::ZERO),
            Delivery::CodexRowNeverSeen
        );
        assert_eq!(recorded_item_id(d.path()).as_deref(), Some("ITEM1"));
    }

    #[test]
    fn w3_observed_partial_ack_cannot_verify_a_distinct_final_ack() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "csq notice");
        let release = d.path().join("release-final-ack");
        let partial_written = d.path().join("partial-ack-written");
        let s = stub(d.path(), &format!(
            "/usr/bin/printf 'Queued message ITEM1 for thread {TID}'; : > '{}'; while [ ! -e '{}' ]; do sleep 0.01; done; printf '%s\\n' '-invalidated' 'Queued message ITEM2 for thread {TID}'",
            partial_written.display(), release.display()
        ));
        let (tx, rx) = std::sync::mpsc::channel();
        let release_thread = std::thread::spawn(move || {
            // Require the actual first-present-row handshake, not a startup timer.
            // The observer drops its sole sender if the bounded wake returns unseen.
            let observed = rx.recv().is_ok();
            if observed {
                std::fs::write(release, "go").unwrap();
            }
            observed
        });
        eprintln!(
            "W3_CONCURRENCY available_parallelism={:?}",
            std::thread::available_parallelism().map(usize::from),
        );
        let started = Instant::now();
        let (delivery, item) = with_first_seen_signal(tx, || {
            deliver_with_item(
                &spec_in(d.path()),
                &|| true,
                Some(TID),
                1,
                Launcher {
                    program: s.as_os_str(),
                    path: Some(OsStr::new("/usr/bin:/bin")),
                    home: Some(d.path().as_os_str()),
                },
                Duration::from_secs(6),
                Duration::from_millis(100),
                Instant::now() + Duration::from_secs(8),
            )
        });
        assert!(
            release_thread.join().unwrap(),
            "first partial ACK row was not actually observed: delivery={delivery:?}, item={item:?}, \
             argv_written={}, partial_ack_written={}, elapsed={:?}",
            d.path().join("argv").exists(),
            partial_written.exists(),
            started.elapsed(),
        );
        assert_eq!(
            delivery,
            Delivery::CodexQueuedUnverified,
            "ITEM1 evidence must not prove ITEM2 absent/consumed"
        );
        assert_eq!(item.as_deref(), Some("ITEM2"));
        let retained = read_item(d.path()).unwrap();
        assert_eq!(retained.id, "ITEM2");
        assert!(
            !retained.seen,
            "ITEM1 visibility cannot prove ITEM2 visibility"
        );
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM2",
            TEST_SESSION
        ));
    }

    #[test]
    fn r7_queue_ack_for_another_thread_cannot_verify_this_attempt() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row_raw(&c, "ITEM1", TID, REAL_PAYLOAD);
        let s = stub(
            d.path(),
            "echo 'Queued message ITEM1 for thread wrong-thread'; exit 7",
        );
        assert_eq!(
            run_in(d.path(), &s, Duration::ZERO),
            Delivery::CodexQueuedUnverified
        );
        assert!(!d.path().join(ITEM_FILE).exists());
    }

    #[test]
    fn r7_same_id_row_on_another_thread_cannot_prove_a_write() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row_raw(&c, "ITEM1", "wrong-thread", REAL_PAYLOAD);
        let s = queue_stub(d.path());
        assert_eq!(
            run_in(d.path(), &s, Duration::ZERO),
            Delivery::CodexRowNeverSeen
        );
    }

    #[test]
    fn r7_queue_open_finishing_after_deadline_cannot_claim_verified_row() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row_raw(&c, "ITEM1", TID, REAL_PAYLOAD);
        let reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = reached.clone();
        let result = with_queue_open_probe(
            move || {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(500));
            },
            || {
                watch_drain_until(
                    &d.path().join(QUEUE_DB),
                    "ITEM1",
                    Some(TID),
                    Duration::from_secs(1),
                    Instant::now() + Duration::from_millis(250),
                    false,
                )
            },
        );
        assert!(reached.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(result, Delivery::CodexQueuedUnverified);
    }

    #[test]
    fn r7_unknown_spawn_result_never_substitutes_a_stale_item() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row_raw(&c, "OLD", "wrong-thread", REAL_PAYLOAD);
        record_legacy_item(d.path(), TID, "OLD").unwrap();
        let s = stub(d.path(), "exit 7");
        let (delivery, item) = deliver_with_item(
            &spec_in(d.path()),
            &|| true,
            Some(TID),
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: Some(d.path().as_os_str()),
            },
            Duration::from_secs(120),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(300),
        );
        assert_eq!(delivery, Delivery::CodexQueuedUnverified);
        assert_eq!(item, None);
        assert_eq!(recorded_item_id(d.path()).as_deref(), Some("OLD"));
    }

    fn spec_in(dir: &Path) -> WakeSpec {
        WakeSpec {
            codex_home: dir.to_path_buf(),
            sqlite_home: dir.to_path_buf(),
            session: Some(TEST_SESSION),
        }
    }

    /// A real sqlite queue with codex-cli 0.160.1's `queued_items` schema.
    fn queue_db(dir: &Path) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(dir.join(QUEUE_DB)).unwrap();
        c.execute_batch(
            "CREATE TABLE queued_items (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, \
             payload_json TEXT NOT NULL, queue_order INTEGER NOT NULL, \
             created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);",
        )
        .unwrap();
        c
    }

    /// A `payload_json` row written by codex-cli 0.160.1 `queue --message` (captured live).
    const REAL_PAYLOAD: &str = r#"{"UserInput":{"content":[{"type":"text","text":"csq: 1 peer message(s) waiting — fixture","text_elements":[]}],"client_id":"01a10f64-7978-7ce1-b833-598edb3871fc"}}"#;

    fn add_row_raw(c: &rusqlite::Connection, id: &str, thread: &str, payload: &str) {
        c.execute(
            "INSERT INTO queued_items VALUES (?1, ?2, ?3, 1, 0, 0)",
            rusqlite::params![id, thread, payload],
        )
        .unwrap();
    }

    fn add_row(c: &rusqlite::Connection, id: &str, thread: &str, text: &str) {
        let payload =
            format!(r#"{{"UserInput":{{"content":[{{"type":"text","text":"{text}"}}]}}}}"#);
        c.execute(
            "INSERT INTO queued_items VALUES (?1, ?2, ?3, 1, 0, 0)",
            rusqlite::params![id, thread, payload],
        )
        .unwrap();
    }

    fn queue_stub(dir: &Path) -> PathBuf {
        stub(
            dir,
            &format!("echo 'Queued message ITEM1 for thread {TID}'"),
        )
    }

    fn run_in(dir: &Path, s: &Path, drain: Duration) -> Delivery {
        deliver_with(
            &spec_in(dir),
            &|| true,
            Some(TID),
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            Duration::from_secs(120),
            drain,
            Instant::now() + Duration::from_secs(300),
        )
    }

    /// The row is consumed while the watch runs: `codex_woken`. Red proof: the pre-fix code
    /// returned `CodexWoken` on exit 0 alone, so the `stays` test below fails against it.
    #[test]
    fn drained_row_is_woken() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "csq: 1 peer message(s) waiting");
        let s = queue_stub(d.path());
        let dir = d.path().to_path_buf();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            seen_rx
                .recv_timeout(Duration::from_secs(120))
                .expect("watch never observed its row");
            rusqlite::Connection::open(dir.join(QUEUE_DB))
                .unwrap()
                .execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
                .unwrap();
        });
        let r = with_first_seen_signal(seen_tx, || {
            deliver_with(
                &spec_in(d.path()),
                &|| true,
                Some(TID),
                1,
                Launcher {
                    program: s.as_os_str(),
                    path: Some(OsStr::new("/usr/bin:/bin")),
                    home: None,
                },
                Duration::from_secs(120),
                Duration::from_secs(120),
                Instant::now() + Duration::from_secs(300),
            )
        });
        h.join().unwrap();
        assert_eq!(r, Delivery::CodexWoken);
    }

    #[test]
    fn r7_first_seen_handshake_drives_consumption() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "csq: 1 peer message(s) waiting");
        let dir = d.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let taker = std::thread::spawn(move || {
            let signalled = rx.recv_timeout(Duration::from_secs(120)).is_ok();
            rusqlite::Connection::open(dir.join(QUEUE_DB))
                .unwrap()
                .execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
                .unwrap();
            signalled
        });
        let result = with_first_seen_signal(tx, || {
            watch_drain(&d.path().join(QUEUE_DB), "ITEM1", Duration::from_secs(60))
        });
        assert!(
            taker.join().unwrap(),
            "watch must publish first-seen before the taker drains"
        );
        assert_eq!(result, Delivery::CodexWoken);
    }

    /// A consumer's commit that outlasts one 200ms read slice (a slow disk stretches a
    /// DELETE commit to seconds) leaves the reader BUSY, not unable to verify: the watch
    /// keeps polling inside its drain window and reports the consumption once the commit
    /// lands. The fixture is a ROLLBACK-JOURNAL database on purpose: that is the mode in
    /// which a writer's commit blocks readers, so it is the deterministic way to hold the
    /// reader BUSY. Production (Codex's queue DB) is WAL, where a reader sees the
    /// pre-commit snapshot instead (`wal_consumer_commit_is_woken` below). Red proof: the
    /// pre-fix code mapped that BUSY to `CodexQueuedUnverified`.
    #[test]
    fn busy_reader_during_slow_consumer_commit_is_woken_not_unverified() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "csq: 1 peer message(s) waiting");
        drop(c);
        let dir = d.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let taker = std::thread::spawn(move || {
            rx.recv_timeout(Duration::from_secs(120))
                .expect("watch never observed its row");
            let c = rusqlite::Connection::open(dir.join(QUEUE_DB)).unwrap();
            c.execute_batch("BEGIN EXCLUSIVE; DELETE FROM queued_items WHERE id = 'ITEM1';")
                .unwrap();
            // The commit stays pending for three read slices; the lock is released only
            // by the COMMIT below, so the reader is BUSY for the whole span.
            std::thread::sleep(Duration::from_millis(600));
            c.execute_batch("COMMIT;").unwrap();
        });
        let result = with_first_seen_signal(tx, || {
            watch_drain(&d.path().join(QUEUE_DB), "ITEM1", Duration::from_secs(60))
        });
        taker.join().unwrap();
        assert_eq!(result, Delivery::CodexWoken);
    }

    /// Production mode: Codex's queue DB is WAL, so a consumer's slow commit does not block the
    /// reader, which keeps seeing the row until the commit lands and then sees it gone.
    #[test]
    fn wal_consumer_commit_is_woken() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        c.pragma_update(None, "journal_mode", "WAL").unwrap();
        add_row(&c, "ITEM1", TID, "csq: 1 peer message(s) waiting");
        let dir = d.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let taker = std::thread::spawn(move || {
            rx.recv_timeout(Duration::from_secs(120))
                .expect("watch never observed its row");
            let c = rusqlite::Connection::open(dir.join(QUEUE_DB)).unwrap();
            c.execute_batch("BEGIN IMMEDIATE; DELETE FROM queued_items WHERE id = 'ITEM1';")
                .unwrap();
            std::thread::sleep(Duration::from_millis(600));
            c.execute_batch("COMMIT;").unwrap();
        });
        let result = with_first_seen_signal(tx, || {
            watch_drain(&d.path().join(QUEUE_DB), "ITEM1", Duration::from_secs(60))
        });
        taker.join().unwrap();
        drop(c);
        assert_eq!(result, Delivery::CodexWoken);
    }

    /// A read that SUCCEEDS but returns after its 200ms slice (SQLite's busy handler sleeps in
    /// coarse steps; a stalled host does the same) is still a true observation while the
    /// overall budget holds. Every read here is delayed past its slice, so a probe that
    /// validated against the slice would discard each one and report `Unverified`.
    #[test]
    fn successful_read_returning_past_its_slice_is_still_a_valid_observation() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "csq: 1 peer message(s) waiting");
        drop(c);
        let dir = d.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let taker = std::thread::spawn(move || {
            rx.recv_timeout(Duration::from_secs(120))
                .expect("watch never observed its row");
            rusqlite::Connection::open(dir.join(QUEUE_DB))
                .unwrap()
                .execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
                .unwrap();
        });
        let result = with_queue_read_probe(
            || std::thread::sleep(Duration::from_millis(260)),
            || {
                with_first_seen_signal(tx, || {
                    watch_drain(&d.path().join(QUEUE_DB), "ITEM1", Duration::from_secs(60))
                })
            },
        );
        taker.join().unwrap();
        assert_eq!(result, Delivery::CodexWoken);
    }

    /// The row never drains: `codex_queued`, NOT `codex_woken`.
    #[test]
    fn stuck_row_is_queued_not_woken() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "unrelated");
        let s = queue_stub(d.path());
        assert_eq!(
            run_in(d.path(), &s, Duration::from_millis(400)),
            Delivery::CodexQueued
        );
    }

    #[test]
    fn failed_item_record_never_correlates_the_previous_sidecar() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row_raw(&c, "ITEM1", TID, REAL_PAYLOAD);
        record_legacy_item(d.path(), "wrong-thread", "OLD").unwrap();
        let s = queue_stub(d.path());
        let spec = WakeSpec::for_test(d.path(), d.path());
        let launcher = Launcher {
            program: s.as_os_str(),
            path: Some(OsStr::new("/usr/bin:/bin")),
            home: Some(d.path().as_os_str()),
        };
        let (delivery, expected) = deliver_with_recorder(
            &spec,
            &|| true,
            Some(TID),
            1,
            launcher,
            Duration::from_secs(120),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(300),
            &|_, _, _, _| Err(std::io::Error::other("injected write failure")),
        );
        assert_eq!(delivery, Delivery::CodexQueued);
        assert_eq!(recorded_item_id(d.path()).as_deref(), Some("OLD"));
        assert_eq!(expected, None, "a pending NEW item cannot arm using OLD");
    }

    #[test]
    fn cr6_known_replaced_queue_identity_survives_uncertain_record() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row_raw(&c, "ITEM1", TID, REAL_PAYLOAD);
        let reader = QueueRead::open(
            &d.path().join(QUEUE_DB),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let original = reader.identity;
        std::fs::rename(d.path().join(QUEUE_DB), d.path().join("old.sqlite")).unwrap();
        let replacement = queue_db(d.path());
        add_row_raw(&replacement, "ITEM1", TID, REAL_PAYLOAD);
        assert!(!reader.identity_valid());
        record_item(
            d.path(),
            TID,
            "ITEM1",
            &QueueEvidence {
                session: Some(TEST_SESSION),
                id: Some("ITEM1".into()),
                seen: false,
                reader: Some(reader),
                identity_changed: true,
                ..QueueEvidence::default()
            },
        )
        .unwrap();
        assert!(read_item(d.path()).unwrap().queue == Some(original));
        assert_eq!(
            pending_bound(
                &spec_in(d.path()),
                TID,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
            .0,
            Delivery::CodexQueuedUnverified
        );
        replacement
            .execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
            .unwrap();
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
    }

    #[test]
    fn cr6_ack_without_database_retains_correlation_and_coalesces() {
        let d = TempDir::new().unwrap();
        let helper = queue_stub(d.path());
        let spec = spec_in(d.path());
        let launcher = Launcher {
            program: helper.as_os_str(),
            path: Some(OsStr::new("/usr/bin:/bin")),
            home: Some(d.path().as_os_str()),
        };
        let first = deliver_with_item(
            &spec,
            &|| true,
            Some(TID),
            1,
            launcher,
            Duration::from_secs(5),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(10),
        );
        let drain = match last_wake_exit() {
            Some((out, err, ack)) => format!(
                "drained_stdout_bytes={out}; drained_stderr_bytes={err}; ack_parseable={ack}"
            ),
            None => "last_wake_exit=none".to_owned(),
        };
        assert_eq!(
            first,
            (Delivery::CodexQueuedUnverified, Some("ITEM1".into())),
            "first delivery mismatch: left={first:?}; argv_exists={}; env_exists={}; {drain}",
            d.path().join("argv").exists(),
            d.path().join("env").exists()
        );
        let item = read_item(d.path()).expect("uncertain ACK must survive");
        assert!(!item.seen);
        assert_eq!(item.session, Some(TEST_SESSION));
        assert!(!d.path().join(QUEUE_DB).exists());
        std::fs::remove_file(d.path().join("argv")).unwrap();
        let second = deliver_with_item(
            &spec,
            &|| true,
            Some(TID),
            2,
            launcher,
            Duration::from_secs(5),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(
            second,
            first,
            "second delivery mismatch: left={second:?}; argv_exists={}; env_exists={}              (an uncertain ACK must not spawn another helper)",
            d.path().join("argv").exists(),
            d.path().join("env").exists()
        );
        assert!(
            !d.path().join("argv").exists(),
            "uncertainty must not spawn another helper; env_exists={}",
            d.path().join("env").exists()
        );
    }

    #[test]
    fn cr6_unseen_absent_ack_recovers_without_claiming_consumption() {
        use crate::messaging::deferred::{self, Deps, Tick};
        use crate::messaging::model::{Recipient, Surface};

        let d = TempDir::new().unwrap();
        let _db = queue_db(d.path());
        let reader = QueueRead::open(
            &d.path().join(QUEUE_DB),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        record_item(
            d.path(),
            TID,
            "OLD",
            &QueueEvidence {
                session: Some(TEST_SESSION),
                id: Some("OLD".into()),
                seen: false,
                reader: Some(reader),
                ..QueueEvidence::default()
            },
        )
        .unwrap();
        let recipient = Recipient {
            pid: TEST_SESSION.pid,
            started_at: 1000,
            surface: Surface::Codex,
            started_exact: Some(TEST_SESSION.exact_start),
        };
        deferred::arm_with_item(d.path(), &recipient, 100, Some("OLD".into())).unwrap();
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "OLD",
            TEST_SESSION
        ));
        let helper = queue_stub(d.path());
        let spec = spec_in(d.path());
        let wake = |_: &Recipient| {
            deliver_with_item(
                &spec,
                &|| true,
                Some(TID),
                1,
                Launcher {
                    program: helper.as_os_str(),
                    path: Some(OsStr::new("/usr/bin:/bin")),
                    home: Some(d.path().as_os_str()),
                },
                Duration::from_secs(5),
                Duration::ZERO,
                Instant::now() + Duration::from_secs(10),
            )
        };
        let taken =
            |_: &Recipient, id: &str| queued_item_taken_bound(d.path(), d.path(), id, TEST_SESSION);
        let outcome = deferred::tick(
            d.path(),
            105,
            &Deps {
                live: &|r| *r == recipient,
                owns: &|r| *r == recipient,
                unread: &|_| Some(true),
                taken: &taken,
                wake: &wake,
                stop: &|| false,
            },
        );
        assert!(
            d.path().join("argv").exists(),
            "absent unseen ACK must allow a fresh attempt"
        );
        assert_eq!(outcome, Tick::Retried(Delivery::CodexRowNeverSeen));
        assert_eq!(recorded_item_id(d.path()).as_deref(), Some("ITEM1"));
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
        let pending: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.path().join(deferred::PENDING_FILE)).unwrap())
                .unwrap();
        assert_eq!(pending["expect_item"], "ITEM1");
        assert_eq!(pending["attempts"], 1);
        assert_eq!(pending["next_at"], 110);
    }

    #[test]
    fn cr6_ack_becomes_observed_before_consumption_can_be_proven() {
        let d = TempDir::new().unwrap();
        let helper = queue_stub(d.path());
        let spec = spec_in(d.path());
        let launcher = Launcher {
            program: helper.as_os_str(),
            path: Some(OsStr::new("/usr/bin:/bin")),
            home: Some(d.path().as_os_str()),
        };
        let result = deliver_with_item(
            &spec,
            &|| true,
            Some(TID),
            1,
            launcher,
            Duration::from_secs(5),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(result.1.as_deref(), Some("ITEM1"));
        let c = queue_db(d.path());
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
        add_row_raw(&c, "ITEM1", TID, REAL_PAYLOAD);
        let pending = pending_bound(&spec, TID, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(pending.0, Delivery::CodexWakePending);
        assert!(read_item(d.path()).unwrap().seen);
        c.execute("DELETE FROM queued_items WHERE id = 'ITEM1'", [])
            .unwrap();
        assert!(queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
        let mut wrong = spec.clone();
        wrong.session.as_mut().unwrap().exact_start += 1;
        assert!(pending_bound(&wrong, TID, Instant::now() + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn unreadable_queue_db_is_unverified_never_woken() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(QUEUE_DB), b"not a sqlite database at all").unwrap();
        let s = queue_stub(d.path());
        assert_eq!(
            run_in(d.path(), &s, Duration::from_millis(400)),
            Delivery::CodexQueuedUnverified
        );
        // A missing DB is the same third outcome.
        let d2 = TempDir::new().unwrap();
        let s2 = queue_stub(d2.path());
        assert_eq!(
            run_in(d2.path(), &s2, Duration::from_millis(400)),
            Delivery::CodexQueuedUnverified
        );
    }

    #[test]
    fn unparseable_item_id_is_unverified() {
        let d = TempDir::new().unwrap();
        let _c = queue_db(d.path());
        let s = stub(d.path(), "echo 'something else entirely'");
        assert_eq!(
            run_in(d.path(), &s, Duration::from_millis(400)),
            Delivery::CodexQueuedUnverified
        );
    }

    #[test]
    fn pending_csq_wake_spawns_nothing() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        // Codex 0.160.1's real payload shape (captured 2026-10-06), em dash literal.
        add_row_raw(&c, "OLD", TID, REAL_PAYLOAD);
        record_item(
            d.path(),
            TID,
            "OLD",
            &QueueEvidence {
                session: Some(TEST_SESSION),
                id: Some("OLD".into()),
                seen: true,
                reader: QueueRead::open(
                    &d.path().join(QUEUE_DB),
                    Instant::now() + Duration::from_secs(1),
                ),
                ..QueueEvidence::default()
            },
        )
        .unwrap();
        let s = queue_stub(d.path());
        let r = run_in(d.path(), &s, Duration::from_millis(400));
        assert_eq!(r, Delivery::CodexWakePending);
        assert_eq!(r.as_str(), "codex_queued");
        assert_eq!(r.reason(), Some("wake_pending"));
        assert!(
            !d.path().join("argv").exists(),
            "the stub must not have run"
        );
    }

    #[test]
    fn native_queue_ack_period_is_exactly_correlated() {
        for suffix in ["", "."] {
            assert_eq!(
                parse_item_id(
                    &format!("Queued message ITEM1 for thread {TID}{suffix}"),
                    TID
                )
                .as_deref(),
                Some("ITEM1")
            );
        }
        for suffix in ["..", ". extra", "wrong"] {
            assert!(parse_item_id(
                &format!("Queued message ITEM1 for thread {TID}{suffix}"),
                TID
            )
            .is_none());
        }
    }

    /// Owned native-format queue writer: a real private SQLite row is inserted
    /// by the child before its acknowledgement, using the native trailing period.
    #[test]
    fn native_queue_retry_writer_fixture() {
        if std::env::var("CSQ_NATIVE_QUEUE_RETRY_FIXTURE").as_deref() != Ok("1") {
            return;
        }
        let home = PathBuf::from(std::env::var_os("CODEX_HOME").unwrap());
        let connection = rusqlite::Connection::open(home.join(QUEUE_DB)).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        add_row_raw(&connection, &id, TID, REAL_PAYLOAD);
        // libtest writes its test-name prefix without a newline under --nocapture.
        // Put the native frame on its own line, exactly as the real CLI emits it.
        println!("\nQueued message {id} for thread {TID}.");
    }

    #[test]
    fn native_queue_ack_retries_leave_exactly_one_pending_item() {
        let dir = TempDir::new().unwrap();
        let connection = queue_db(dir.path());
        let executable = std::env::current_exe().unwrap();
        let quoted = format!("'{}'", executable.to_str().unwrap().replace('\'', "'\\''"));
        let writer = stub(dir.path(), &format!("CSQ_NATIVE_QUEUE_RETRY_FIXTURE=1 {quoted} --exact messaging::wake::tests::native_queue_retry_writer_fixture --nocapture --test-threads=1"));
        let first = run_in(dir.path(), &writer, Duration::ZERO);
        let id = recorded_item_id(dir.path());
        let mut retries = Vec::new();
        for _ in 0..6 {
            retries.push(run_in(dir.path(), &writer, Duration::ZERO));
        }
        let rows: u64 = connection
            .query_row(
                "SELECT COUNT(*) FROM queued_items WHERE thread_id=?1",
                [TID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            rows, 1,
            "six retries must reuse one native-format acknowledged item"
        );
        assert_eq!(first, Delivery::CodexQueued);
        assert!(id.is_some(), "native ACK must persist before retries");
        assert_eq!(recorded_item_id(dir.path()), id);
        assert!(retries
            .iter()
            .all(|result| *result == Delivery::CodexWakePending));
    }

    /// Only a csq notice on THIS thread dedupes: a user's own queued text, or a csq notice on
    /// another thread, does not suppress the wake.
    #[test]
    fn foreign_rows_do_not_suppress_the_wake() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "A", TID, "please review the PR");
        // A row with csq-shaped text on THIS thread that csq did not queue (no sidecar id).
        add_row_raw(&c, "B", TID, REAL_PAYLOAD);
        let s = queue_stub(d.path());
        let r = run_in(d.path(), &s, Duration::from_millis(300));
        assert!(d.path().join("argv").exists(), "the wake must have spawned");
        // ITEM1 was never in the queue: absence proves nothing, so this is NOT woken.
        assert_eq!(r, Delivery::CodexRowNeverSeen);
        assert_eq!(r.tagged(), "codex_queued_unverified:row_never_seen");
    }

    #[test]
    fn no_rollout_is_queued_only_with_reason() {
        let d = TempDir::new().unwrap();
        let s = stub(
            d.path(),
            "echo 'thread/queue/add failed: no rollout found for thread id X' >&2; exit 1",
        );
        let r = run_in(d.path(), &s, Duration::from_millis(300));
        assert_eq!(r, Delivery::CodexNoTurnYet);
        assert_eq!(r.as_str(), "queued_only");
        assert_eq!(r.reason(), Some("codex_no_turn_yet"));
        assert_eq!(r.tagged(), "queued_only:codex_no_turn_yet");
        // An arbitrary spawned failure cannot establish that no queue write happened.
        let s2 = stub(d.path(), "echo boom >&2; exit 1");
        assert_eq!(
            run_in(d.path(), &s2, Duration::from_millis(300)),
            Delivery::CodexQueuedUnverified
        );
    }

    /// B1: a `setsid` descendant that inherited the child's stdout (an auto-started
    /// app-server) outlives the group kill and keeps the descriptor open. The wake must return
    /// without waiting for it to close. The owned grandchild sleeps 60 s; its recorded
    /// incarnation is captured before the child may acknowledge readiness and is killed by
    /// a drop guard. Atomic PID publication and private errors make setup failure explicit.
    /// The explicit 30 s threshold separates a
    /// bounded wake from a blocking pipe read waiting on that 60 s descendant.
    #[test]
    fn a_setsid_grandchild_holding_stdout_cannot_block_the_wake() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "x");
        let pidfile = d.path().join("escaped.pid");
        let errors = d.path().join("escaped.stderr");
        let ready = d.path().join("escaped.ready");
        let s = stub(
            d.path(),
            &format!(
                "perl -e 'use POSIX; my $child = fork(); defined $child or die \"fork: $!\"; exit 0 if $child; POSIX::setsid() != -1 or die \"setsid: $!\"; open my $f, \">\", \"$ARGV[0].tmp\" or die \"open: $!\"; print $f \"$$\\n\" or die \"print: $!\"; close $f or die \"close: $!\"; rename \"$ARGV[0].tmp\", $ARGV[0] or die \"rename: $!\"; exec \"sleep\", \"60\"; die \"exec: $!\"' '{p}' 2>'{e}' &\n\
                 tries=0; while [ ! -e '{r}' ] && [ \"$tries\" -lt 400 ]; do tries=$((tries+1)); sleep 0.025; done\n\
                 [ -e '{r}' ] || {{ echo 'fixture: escaped descendant not ready' >> '{e}'; exit 1; }}\n\
                 echo 'Queued message ITEM1 for thread {TID}'",
                p = pidfile.display(), e = errors.display(), r = ready.display(),
            ),
        );
        let thread_errors = errors.clone();
        let thread_ready = ready.clone();
        let cleanup = std::thread::spawn(move || {
            let pid = wait_for_pid(&pidfile, Duration::from_secs(15)).unwrap_or_else(|| {
                panic!(
                    "escaped descendant never published its atomic pid: {:?}",
                    std::fs::read_to_string(&thread_errors)
                )
            });
            let started = crate::sessions::ancestor_start(pid as u32)
                .expect("escaped descendant disappeared before identity capture");
            let owned = OwnedSessionPid { pid, started };
            // SAFETY: getsid observes the fixture process; it changes no process state.
            assert_eq!(
                unsafe { libc::getsid(pid) },
                pid,
                "descendant must have escaped the wake group"
            );
            std::fs::write(thread_ready, b"ready").unwrap();
            owned
        });
        let t0 = Instant::now();
        let r = deliver_with(
            &spec_in(d.path()),
            &|| true,
            Some(TID),
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            Duration::from_secs(20),
            Duration::from_millis(300),
            Instant::now() + Duration::from_secs(40),
        );
        let took = t0.elapsed();
        let owned = cleanup.join().unwrap();
        drop(owned);
        assert!(
            ready.exists(),
            "fixture readiness must precede measurement: {:?}",
            std::fs::read_to_string(&errors)
        );
        assert!(took < Duration::from_secs(30), "blocked {took:?}");
        assert_eq!(
            r,
            Delivery::CodexQueued,
            "fixture child errors: {:?}",
            std::fs::read_to_string(&errors)
        );
    }

    /// A controlled child observes pipe output, floods beyond the retained cap, then exits.
    #[test]
    fn r7_unix_output_is_pipe_and_flood_is_capped() {
        let d = TempDir::new().unwrap();
        let s = stub(d.path(), "perl -e '-p STDOUT && -p STDERR or die; print \"x\" x 1048576; print STDERR \"e\" x 1048576;'\n");
        let result = queue_once(
            &spec_in(d.path()),
            TID,
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            Duration::from_secs(120),
        )
        .unwrap_or_else(|d| panic!("{d:?}"));
        assert!(result.ok, "fixture requires both descriptors to be pipes");
        assert_eq!(result.stdout.len(), OUTPUT_CAP as usize);
        assert_eq!(result.stderr.len(), OUTPUT_CAP as usize);
        assert!(result.stdout.bytes().all(|b| b == b'x'));
        assert!(result.stderr.bytes().all(|b| b == b'e'));
    }

    #[test]
    fn r7_timeout_retains_ack_and_bounded_partial_output() {
        let d = TempDir::new().unwrap();
        let ack = format!("Queued message ITEM1 for thread {TID}");
        let s = stub(
            d.path(),
            &format!(
            "echo '{ack}'\nperl -e 'print \"x\" x 1048576; print STDERR \"e\" x 1048576;'\nsleep 30"
        ),
        );
        let result = queue_once(
            &spec_in(d.path()),
            TID,
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: Some(d.path().as_os_str()),
            },
            Duration::from_secs(6),
        )
        .unwrap_or_else(|d| panic!("spawned timeout must retain output, got {d:?}"));
        assert!(!result.completed);
        assert!(!result.ok);
        assert!(result.stdout.starts_with(&ack));
        assert_eq!(result.stdout.len(), OUTPUT_CAP as usize);
        assert_eq!(result.stderr.len(), OUTPUT_CAP as usize);
        assert_eq!(interpret(&result, TID).as_deref(), Ok("ITEM1"));
    }

    /// I1: two concurrent wakes for one session queue ONE row. The stub is slow so both would
    /// pass an unlocked dedupe check. Red proof: without `lock_wake` it spawns twice.
    #[test]
    fn concurrent_wakes_queue_one_row() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "csq: 1 peer message(s) waiting");
        let spawns = d.path().join("spawns");
        let s = stub(
            d.path(),
            &format!(
                "echo x >> '{}'\nsleep 0.4\necho 'Queued message ITEM1 for thread {TID}'",
                spawns.display()
            ),
        );
        let go = |dir: PathBuf, s: PathBuf| {
            std::thread::spawn(move || run_in(&dir, &s, Duration::from_millis(600)))
        };
        let (a, b) = (
            go(d.path().into(), s.clone()),
            go(d.path().into(), s.clone()),
        );
        let (ra, rb) = (a.join().unwrap(), b.join().unwrap());
        let n = std::fs::read_to_string(&spawns).unwrap().lines().count();
        assert_eq!(n, 1, "{ra:?} {rb:?}");
        let mut got = [ra, rb];
        got.sort_by_key(|d| d.as_str());
        assert!(got.contains(&Delivery::CodexWakePending), "{got:?}");
        assert!(got.contains(&Delivery::CodexQueued), "{got:?}");
    }

    /// N2: a symlink in place of the queue DB is not opened.
    #[test]
    fn a_symlinked_queue_db_is_unverified() {
        let d = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let _c = queue_db(other.path());
        std::os::unix::fs::symlink(other.path().join(QUEUE_DB), d.path().join(QUEUE_DB)).unwrap();
        let s = queue_stub(d.path());
        assert_eq!(
            run_in(d.path(), &s, Duration::from_millis(300)),
            Delivery::CodexQueuedUnverified
        );
    }

    /// The overall deadline cuts every sub-step: an already-expired deadline spawns nothing
    /// and cannot wait out the drain.
    #[test]
    fn an_expired_deadline_bounds_the_whole_wake() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "x");
        let s = queue_stub(d.path());
        let r = deliver_with(
            &spec_in(d.path()),
            &|| true,
            Some(TID),
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            Duration::from_secs(5),
            Duration::from_secs(6),
            Instant::now(),
        );
        assert_eq!(r, Delivery::CodexWakeFailed);
        assert!(
            !d.path().join("argv").exists(),
            "expired wake must not spawn"
        );
        assert!(
            !d.path().join(LOCK_FILE).exists(),
            "expired wake must not open a lock"
        );
    }

    #[test]
    fn r7_lock_timeout_is_unqueued_in_flight_and_spawns_nothing() {
        let d = TempDir::new().unwrap();
        let _holder = lock_wake(d.path(), Duration::ZERO).unwrap().unwrap();
        let s = queue_stub(d.path());
        let result = deliver_with(
            &spec_in(d.path()),
            &|| true,
            Some(TID),
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            Duration::from_millis(40),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(20),
        );
        assert_eq!(result.as_str(), "queued_only");
        assert_eq!(result.reason(), Some("wake_in_flight"));
        assert_eq!(result.tagged(), "queued_only:wake_in_flight");
        assert!(!d.path().join("argv").exists());
        assert!(!d.path().join(ITEM_FILE).exists());
    }

    #[test]
    fn r7_target_gone_after_queue_never_records_item() {
        let d = TempDir::new().unwrap();
        let s = queue_stub(d.path());
        let result = deliver_with(
            &spec_in(d.path()),
            &|| !d.path().join("argv").exists(),
            Some(TID),
            1,
            Launcher {
                program: s.as_os_str(),
                path: Some(OsStr::new("/usr/bin:/bin")),
                home: None,
            },
            Duration::from_secs(120),
            Duration::ZERO,
            Instant::now() + Duration::from_secs(300),
        );
        assert!(d.path().join("argv").exists(), "queue child must have run");
        assert!(
            !d.path().join(ITEM_FILE).exists(),
            "gone incarnation must not get an item sidecar"
        );
        assert_eq!(result, Delivery::CodexQueuedUnverified);
    }

    #[test]
    fn r7_queue_open_refuses_leaf_swapped_to_symlink() {
        let d = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let _c = queue_db(other.path());
        let leaf = d.path().canonicalize().unwrap().join(QUEUE_DB);
        std::fs::write(&leaf, "regular at admission").unwrap();
        let swap_leaf = leaf.clone();
        let destination = other.path().join(QUEUE_DB);
        let reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = reached.clone();
        let result = with_queue_open_probe(
            move || {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                std::fs::remove_file(&swap_leaf).unwrap();
                std::os::unix::fs::symlink(destination, &swap_leaf).unwrap();
            },
            || open_ro(&leaf),
        );
        assert!(
            reached.load(std::sync::atomic::Ordering::SeqCst),
            "production metadata admission must run"
        );
        assert!(
            result.is_none(),
            "actual SQLite open must refuse the replaced leaf"
        );
    }

    #[test]
    fn queued_item_taken_needs_a_record_and_an_absent_row() {
        let d = TempDir::new().unwrap();
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "x");
        let helper = queue_stub(d.path());
        assert_eq!(
            run_in(d.path(), &helper, Duration::ZERO),
            Delivery::CodexQueued
        );
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
        c.execute("DELETE FROM queued_items", []).unwrap();
        assert!(queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
        std::fs::write(d.path().join(QUEUE_DB), b"garbage").unwrap();
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "ITEM1",
            TEST_SESSION
        ));
    }

    #[test]
    fn w4_late_post_liveness_cannot_prove_consumption() {
        struct Owned(Option<std::process::Child>);
        impl Drop for Owned {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let root = TempDir::new().unwrap();
        let child = Owned(Some(
            Command::new("/bin/sleep")
                .arg("30")
                .env_clear()
                .env("HOME", root.path())
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let pid = child.0.as_ref().unwrap().id();
        let home = root.path().join(format!("term-{pid}"));
        let sqlite = root.path().join("config-3");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&sqlite).unwrap();
        crate::accounts::markers::write_live_pid(&home, pid).unwrap();
        let target = crate::sessions::wake_target_ok(
            root.path(),
            pid,
            &home,
            &crate::sessions::CodexLaunch {
                thread_id: Some(TID.to_owned()),
                sqlite_home: Some(sqlite.canonicalize().unwrap()),
            },
        )
        .unwrap();
        let c = queue_db(&sqlite);
        add_row(&c, "ITEM1", TID, "notice");
        let helper = queue_stub(&home);
        let spec = WakeSpec::from_target(&target);
        assert_eq!(
            deliver_with(
                &spec,
                &|| target.still_live(),
                Some(TID),
                1,
                Launcher {
                    program: helper.as_os_str(),
                    path: Some(OsStr::new("/usr/bin:/bin")),
                    home: Some(root.path().as_os_str())
                },
                Duration::from_secs(10),
                Duration::ZERO,
                Instant::now() + Duration::from_secs(10)
            ),
            Delivery::CodexQueued
        );
        c.execute("DELETE FROM queued_items", []).unwrap();
        assert!(
            queued_item_taken_for_target(&target, "ITEM1"),
            "live same incarnation proves consumption"
        );
        let calls = std::cell::Cell::new(0usize);
        let result = queued_item_taken_for_target_with(&target, "ITEM1", &|| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 1 {
                std::thread::sleep(Duration::from_millis(350));
            }
            target.still_live()
        });
        assert_eq!(calls.get(), 2, "actual pre/post liveness callbacks ran");
        assert!(target.still_live(), "owned target remains live");
        assert!(
            !result,
            "late positive post-liveness must not claim consumption"
        );
        drop(child);
    }

    #[test]
    fn w4_owned_target_stopping_during_queue_read_cannot_prove_consumption() {
        struct Owned(Option<std::process::Child>);
        impl Drop for Owned {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let root = TempDir::new().unwrap();
        let mut child = Owned(Some(
            Command::new("/bin/sleep")
                .arg("30")
                .env_clear()
                .env("HOME", root.path())
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let pid = child.0.as_ref().unwrap().id();
        let home = root.path().join(format!("term-{pid}"));
        let sqlite = root.path().join("config-3");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&sqlite).unwrap();
        crate::accounts::markers::write_live_pid(&home, pid).unwrap();
        let target = crate::sessions::wake_target_ok(
            root.path(),
            pid,
            &home,
            &crate::sessions::CodexLaunch {
                thread_id: Some(TID.to_owned()),
                sqlite_home: Some(sqlite.canonicalize().unwrap()),
            },
        )
        .unwrap();
        let c = queue_db(&sqlite);
        add_row(&c, "ITEM1", TID, "notice");
        let helper = queue_stub(&home);
        let spec = WakeSpec::from_target(&target);
        assert_eq!(
            deliver_with(
                &spec,
                &|| target.still_live(),
                Some(TID),
                1,
                Launcher {
                    program: helper.as_os_str(),
                    path: Some(OsStr::new("/usr/bin:/bin")),
                    home: Some(root.path().as_os_str())
                },
                Duration::from_secs(10),
                Duration::ZERO,
                Instant::now() + Duration::from_secs(10)
            ),
            Delivery::CodexQueued
        );
        c.execute("DELETE FROM queued_items", []).unwrap();
        assert!(
            queued_item_taken_for_target(&target, "ITEM1"),
            "live same incarnation proves consumption"
        );
        add_row(&c, "ITEM1", TID, "notice");
        let db = sqlite.join(QUEUE_DB);
        let observed = with_queue_open_probe(
            move || {
                let mut stopped = child.0.take().unwrap();
                stopped.kill().unwrap();
                stopped.wait().unwrap();
                rusqlite::Connection::open(&db)
                    .unwrap()
                    .execute("DELETE FROM queued_items", [])
                    .unwrap();
            },
            || queued_item_taken_for_target(&target, "ITEM1"),
        );
        assert!(
            !target.still_live(),
            "probe actually terminated the owned target"
        );
        assert!(
            !observed,
            "stopped target and same-database cleanup are not consumption"
        );
    }

    #[test]
    fn w4_replaced_database_cannot_establish_deferred_consumption() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        add_row(&c, "ITEM1", TID, "notice");
        assert_eq!(
            run_in(d.path(), &queue_stub(d.path()), Duration::ZERO),
            Delivery::CodexQueued
        );
        let recorded = read_item(d.path()).unwrap();
        assert!(recorded.seen && recorded.queue.is_some() && recorded.handle.is_some());
        std::fs::rename(d.path().join(QUEUE_DB), d.path().join("old-queue.sqlite")).unwrap();
        let _replacement = queue_db(d.path());
        assert!(
            !queued_item_taken_bound(d.path(), d.path(), "ITEM1", TEST_SESSION),
            "replacement absence is not consumption"
        );
    }

    #[test]
    fn w4_unseen_legacy_and_relocated_handle_records_are_not_consumption() {
        let d = TempDir::new().unwrap();
        let c = queue_db(d.path());
        let helper = queue_stub(d.path());
        assert_eq!(
            run_in(d.path(), &helper, Duration::ZERO),
            Delivery::CodexRowNeverSeen
        );
        assert!(!read_item(d.path()).unwrap().seen);
        assert!(
            !queued_item_taken_bound(d.path(), d.path(), "ITEM1", TEST_SESSION),
            "never seen"
        );
        record_legacy_item(d.path(), TID, "ITEM1").unwrap();
        assert!(
            !queued_item_taken_bound(d.path(), d.path(), "ITEM1", TEST_SESSION),
            "legacy"
        );
        std::fs::write(d.path().join(ITEM_FILE), b"{ malformed").unwrap();
        assert!(
            !queued_item_taken_bound(d.path(), d.path(), "ITEM1", TEST_SESSION),
            "malformed"
        );
        add_row(&c, "ITEM1", TID, "notice");
        assert_eq!(
            run_in(d.path(), &helper, Duration::ZERO),
            Delivery::CodexQueued
        );
        c.execute("DELETE FROM queued_items", []).unwrap();
        let other = TempDir::new().unwrap();
        std::fs::copy(d.path().join(ITEM_FILE), other.path().join(ITEM_FILE)).unwrap();
        assert!(
            !queued_item_taken_bound(other.path(), d.path(), "ITEM1", TEST_SESSION),
            "different handle incarnation"
        );
    }

    /// The START steps (wake-lock open, helper spawn) retry TRANSIENT table
    /// pressure instead of reporting `CodexWakeFailed`: on a loaded runner a
    /// sibling thread's fd burst reds a scenario that never reached the queue.
    /// The pressure is installed only in a re-executed single-test process (the
    /// w5 disposition pattern), so no sibling test sees the lowered limit; the
    /// parent asserts the production result AND that a retry actually fired.
    #[test]
    fn w4_transient_fd_pressure_during_start_retries_instead_of_wake_failed() {
        const MODE: &str = "CSQ_W4_FD_PRESSURE_PROBE";
        if let Some(dir) = std::env::var_os(MODE) {
            let dir = PathBuf::from(dir);
            let _queue = queue_db(&dir);
            let helper = queue_stub(&dir);
            reset_start_retry_events();
            let result = with_transient_fd_pressure(|| run_in(&dir, &helper, Duration::ZERO));
            // A retry MUST have fired (D237 R2 corr/sec L1): a runner slow enough to
            // clear the burst before the first attempt must not pass vacuously.
            assert!(
                start_retry_events() >= 1,
                "the fd-pressure probe never exercised a retry"
            );
            std::fs::write(dir.join("result"), format!("{result:?}")).unwrap();
            return;
        }
        let d = TempDir::new().unwrap();
        let mut probe = Command::new(std::env::current_exe().unwrap());
        probe
            .env_clear()
            .env("HOME", d.path())
            .env("CSQ_BASE_DIR", d.path().join("base"))
            .env("PATH", "/usr/bin:/bin")
            .env(MODE, d.path())
            .args([
                "--exact",
                "messaging::wake::tests::w4_transient_fd_pressure_during_start_retries_instead_of_wake_failed",
                "--test-threads=1",
            ]);
        let probe_child = probe
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let result = probe_output_with_timeout(probe_child, Duration::from_secs(120));
        assert!(
            result.status.success(),
            "isolated fd-pressure probe: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(d.path().join("result")).unwrap(),
            "CodexRowNeverSeen",
            "a transient fd burst during start must be ridden out, not reported as a wake failure"
        );
    }

    /// Deterministic ETXTBSY instance (D237 R2 corr H1): the documented
    /// sibling-fork race — a process still holding a write descriptor on the
    /// freshly written helper makes execve fail ETXTBSY. THIS test holds that
    /// descriptor and releases it on the EVENT of the call's first failed exec
    /// (D237 R2 corr MED): a timer would let a loaded setup outrun the hold and
    /// make the spawn succeed first try. Linux only: macOS execs a file open for
    /// writing (measured in `codex::ancestry`'s gate row), so the race and this
    /// row do not exist there.
    #[cfg(target_os = "linux")]
    #[test]
    fn w4_a_spawn_busy_on_the_stub_retries_instead_of_wake_failed() {
        let d = TempDir::new().unwrap();
        let _queue = queue_db(d.path());
        let helper = queue_stub(d.path());
        let holder = std::fs::OpenOptions::new()
            .write(true)
            .open(&helper)
            .expect("hold the stub for writing");
        // The hold is EFFECTIVE: a plain spawn must fail busy (it never execs).
        let busy = Command::new(&helper)
            .spawn()
            .err()
            .and_then(|e| e.raw_os_error());
        assert_eq!(
            busy,
            Some(libc::ETXTBSY),
            "the held stub must fail exec busy"
        );
        reset_start_retry_events();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release = std::thread::spawn(move || {
            // Wait for the FIRST failed spawn attempt, not for wall time.
            let _ = release_rx.recv_timeout(Duration::from_secs(60));
            drop(holder);
        });
        let hook = Box::new(move || {
            let _ = release_tx.send(());
        });
        let delivery = with_spawn_retry_hook(hook, || run_in(d.path(), &helper, Duration::ZERO));
        release.join().unwrap();
        assert_eq!(
            delivery,
            Delivery::CodexRowNeverSeen,
            "a busy exec must be ridden out, not reported as a wake failure"
        );
        assert!(
            start_retry_events() >= 1,
            "the spawn retry must actually have fired"
        );
    }

    /// Run a re-executed probe under a HARD deadline (D237 R2 sec L2, corr L-a).
    /// The Child STAYS in the parent (`try_wait`), so expiry kills through the
    /// handle this process owns — never a numeric pid that could have been
    /// recycled — and then REAPS it. The pipe readers are detached on expiry (the
    /// killed child's pipes close, so they finish on their own); this bounds a
    /// wedged probe without claiming the reader threads cannot outlive the panic.
    fn probe_output_with_timeout(
        mut child: std::process::Child,
        limit: Duration,
    ) -> std::process::Output {
        let mut stdout_pipe = child.stdout.take().expect("piped stdout");
        let mut stderr_pipe = child.stderr.take().expect("piped stderr");
        let stdout_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout_pipe, &mut bytes);
            bytes
        });
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stderr_pipe, &mut bytes);
            bytes
        });
        let deadline = Instant::now() + limit;
        let status = loop {
            match child.try_wait().expect("probe wait") {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    // The readers are DETACHED here: no join on the panic path.
                    panic!("isolated probe exceeded {limit:?}; killed and reaped");
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        // The child has exited, so its pipe ends are closed and the reads return.
        let stdout = stdout_reader.join().unwrap_or_default();
        let stderr = stderr_reader.join().unwrap_or_default();
        std::process::Output {
            status,
            stdout,
            stderr,
        }
    }

    /// Hold this process's fd table full for 300 ms while `body` runs: the soft
    /// RLIMIT_NOFILE is lowered for the window (restored after), so the burst is
    /// bounded and deterministic. Only ever called from a single-test probe.
    fn with_transient_fd_pressure<T>(body: impl FnOnce() -> T) -> T {
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: getrlimit/setrlimit read and write only the plain-data limit struct.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let old_soft = limit.rlim_cur;
        limit.rlim_cur = old_soft.min(64);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let full = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hog = {
            let full = std::sync::Arc::clone(&full);
            std::thread::spawn(move || {
                let mut held = Vec::new();
                while let Ok(f) = std::fs::File::open("/dev/null") {
                    held.push(f);
                }
                full.store(true, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(300));
                drop(held);
            })
        };
        while !full.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::yield_now();
        }
        let out = body();
        hog.join().unwrap();
        limit.rlim_cur = old_soft;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        out
    }

    #[test]
    fn r5_no_public_constant_path_only_consumption_api() {
        let retired_signature = ["pub fn ", "queued_item_taken("].concat();
        assert!(!include_str!("wake.rs").contains(&retired_signature));
    }

    #[test]
    fn stale_sidecar_cannot_establish_consumption_of_a_different_expected_item() {
        let d = TempDir::new().unwrap();
        let _c = queue_db(d.path());
        record_legacy_item(d.path(), TID, "OLD").unwrap();
        assert!(!queued_item_taken_bound(
            d.path(),
            d.path(),
            "FRESH",
            TEST_SESSION
        ));
    }
}

#[cfg(all(test, unix))]
mod r8_tests {
    use super::*;
    use crate::testing::socket_fixture::short_root;
    use tempfile::TempDir;
    // ── Claude Code wake (spec 32a §5.2) ────────────────────────────

    use std::io::Read;
    use std::os::unix::net::{UnixListener, UnixStream};

    fn deliver_claude(
        socket: &Path,
        allowed: &[PathBuf],
        live: &dyn Fn() -> bool,
        n: usize,
        timeout: Duration,
    ) -> Delivery {
        super::deliver_claude_socket(socket, std::process::id(), allowed, live, n, timeout)
    }

    #[test]
    fn same_uid_wrong_listener_pid_receives_no_notice() {
        let d = socket_root();
        let listener = UnixListener::bind(sock(&d)).unwrap();
        let reader = serve_once(listener);
        let target = ClaudeWakeTarget {
            pid: std::process::id().checked_add(1).unwrap(),
            start: 777,
            socket: sock(&d),
            config_dir: d.path().to_path_buf(),
        };
        let result = super::deliver_claude(&target, &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT);
        let received = reader.join().unwrap();
        assert_eq!(
            result,
            Delivery::ClaudeWakeFailed,
            "a same-UID replacement listener must be refused"
        );
        assert!(received.is_empty(), "the wrong listener received a notice");
    }

    /// A private short `/tmp` root for a test that binds a Unix socket. A unix
    /// path is limited to ~104 bytes, independent of the runner's `TMPDIR`,
    /// which may be arbitrarily deep. State that never reaches a socket can
    /// stay in the ordinary `TempDir::new()` root.
    fn socket_root() -> TempDir {
        short_root("csq-wake-").unwrap()
    }

    /// A short socket path (a unix path is limited to ~104 bytes).
    fn sock(d: &TempDir) -> PathBuf {
        d.path().join("c.sock")
    }

    /// The allowed-directory list for a test whose sockets live directly in `d`.
    fn allow(d: &TempDir) -> Vec<PathBuf> {
        vec![d.path().to_path_buf()]
    }

    /// Accept one connection and return everything it sends until EOF.
    fn serve_once(l: UnixListener) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            got
        })
    }

    #[test]
    fn claude_line_is_one_json_line_with_the_fixed_notice_and_nothing_else() {
        let line = claude_line(1);
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "type": "user",
                "message": {"role": "user", "content": notice(1)},
            })
        );
    }

    /// The core red-proofed assertion: the exact single line arrives, and `Woken` is reported.
    /// Falsifier: with no wake (the pre-change `queued_only`) nothing connects, so `serve_once`
    /// never returns and the delivery is not `ClaudeWoken`.
    #[test]
    fn claude_wake_posts_exactly_the_one_fixed_line() {
        let d = socket_root();
        let l = UnixListener::bind(sock(&d)).unwrap();
        let h = serve_once(l);
        let r = deliver_claude(&sock(&d), &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT);
        assert_eq!(r, Delivery::ClaudeWoken);
        let got = String::from_utf8(h.join().unwrap()).unwrap();
        assert_eq!(got, claude_line(1), "exactly one fixed line, nothing else");
        assert!(
            !got.contains("SECRET-BODY"),
            "no body text can reach the socket"
        );
    }

    #[test]
    fn claude_wake_refuses_a_regular_file_and_a_symlink_to_a_socket() {
        let d = socket_root();
        let file = d.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            deliver_claude(&file, &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWakeFailed
        );
        // A real, listening socket reached through a symlink is refused too, and nothing connects.
        let l = UnixListener::bind(sock(&d)).unwrap();
        l.set_nonblocking(true).unwrap();
        let link = d.path().join("l.sock");
        std::os::unix::fs::symlink(sock(&d), &link).unwrap();
        assert_eq!(
            deliver_claude(&link, &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWakeFailed
        );
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the symlinked path never connected"
        );
    }

    #[test]
    fn claude_wake_refuses_a_gone_target_and_connects_to_nothing() {
        let d = socket_root();
        let l = UnixListener::bind(sock(&d)).unwrap();
        l.set_nonblocking(true).unwrap();
        assert_eq!(
            deliver_claude(&sock(&d), &allow(&d), &|| false, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWakeFailed
        );
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn target_rechecked_after_socket_checks_before_connect() {
        let d = socket_root();
        let l = UnixListener::bind(sock(&d)).unwrap();
        l.set_nonblocking(true).unwrap();
        let checks = std::cell::Cell::new(0);
        let live = || {
            checks.set(checks.get() + 1);
            checks.get() == 1
        };
        assert_eq!(
            deliver_claude(&sock(&d), &allow(&d), &live, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWakeFailed
        );
        assert_eq!(checks.get(), 2);
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn claude_wake_to_a_dead_listener_is_failed_not_woken() {
        let d = socket_root();
        drop(UnixListener::bind(sock(&d)).unwrap()); // the socket file stays, nothing listens
        assert!(sock(&d).exists());
        assert_eq!(
            deliver_claude(&sock(&d), &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWakeFailed
        );
    }

    /// A listener that accepts and never reads: the write is bounded by its timeout instead of
    /// hanging. Outcomes: healthy (a reader) finishes immediately; a non-reader blocks the
    /// 16 MiB write (far over any socket buffer) until the 300 ms budget, so the elapsed time
    /// sits at >=300 ms and well under the 10 s ceiling asserted.
    #[test]
    fn a_listener_that_never_reads_is_bounded_by_the_timeout() {
        let d = socket_root();
        let l = UnixListener::bind(sock(&d)).unwrap();
        let _held = std::thread::spawn(move || {
            let c = l.accept().unwrap();
            std::thread::sleep(Duration::from_secs(12));
            drop(c);
        });
        let mut s = UnixStream::connect(sock(&d)).unwrap();
        let big = vec![b'x'; 16 * 1024 * 1024];
        let t0 = Instant::now();
        let r = write_line_bounded(&mut s, &big, Duration::from_millis(300));
        let el = t0.elapsed();
        assert_eq!(r, Err(ClaudeWakeFail::Timeout));
        assert!(el >= Duration::from_millis(250), "{el:?}");
        assert!(el < Duration::from_secs(10), "{el:?}");
    }

    /// `ClaudeWoken` means handed over, not read: a listener that accepts and never reads
    /// still receives the whole (small) line into the socket buffer, so the post succeeds.
    #[test]
    fn woken_means_handed_to_the_socket_not_read_by_the_receiver() {
        let d = socket_root();
        let l = UnixListener::bind(sock(&d)).unwrap();
        let _held = std::thread::spawn(move || {
            let c = l.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            drop(c);
        });
        assert_eq!(
            deliver_claude(&sock(&d), &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWoken
        );
    }

    #[test]
    fn peer_is_us_accepts_our_own_listener() {
        let d = socket_root();
        let l = UnixListener::bind(sock(&d)).unwrap();
        let s = UnixStream::connect(sock(&d)).unwrap();
        let _a = l.accept().unwrap();
        assert!(peer_is_us(&s));
        assert!(is_our_socket(&sock(&d)));
    }

    fn with_producer_runtime<T>(dir: &Path, action: impl FnOnce() -> T) -> T {
        let _env = crate::platform::test_env::lock();
        struct Restore(Option<OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
                    None => std::env::remove_var("XDG_RUNTIME_DIR"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("XDG_RUNTIME_DIR"));
        std::env::set_var("XDG_RUNTIME_DIR", dir);
        action()
    }

    #[test]
    fn public_missing_registry_producer_matching_peer_receives_notice() {
        // Unix-domain socket admission includes the full encoded path.
        // Isolate this fixture from arbitrary-length fleet TMPDIR values.
        let dir = short_root("csqw-").unwrap();
        let socket_dir = dir.path().join("cc-socks");
        std::fs::create_dir(&socket_dir).unwrap();
        let pid = std::process::id();
        let socket = socket_dir.join(format!("{pid}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        with_producer_runtime(dir.path(), || {
            let now = 1_800_000_000;
            let target = ClaudeWakeTarget::resolve(
                pid,
                now - 100,
                Some(777),
                &|_| Ok(Some((info(dir.path(), pid, Some(now - 100)), 777))),
                now,
            )
            .expect("public resolution must discover its producer-derived socket without JSON");
            assert_eq!(target.socket(), socket.canonicalize().unwrap());
            assert_eq!(
                super::deliver_claude(
                    &target,
                    &claude_socket_dirs(),
                    &|| true,
                    1,
                    CLAUDE_SOCKET_TIMEOUT
                ),
                Delivery::ClaudeWoken
            );
            let (mut accepted, _) = listener.accept().unwrap();
            let mut line = String::new();
            accepted.read_to_string(&mut line).unwrap();
            assert_eq!(line, claude_line(1));
        });
    }

    #[test]
    fn public_missing_registry_producer_wrong_peer_receives_no_notice() {
        // Unix-domain socket admission includes the full encoded path.
        // Isolate this fixture from arbitrary-length fleet TMPDIR values.
        let dir = short_root("csqw-").unwrap();
        let socket_dir = dir.path().join("cc-socks");
        std::fs::create_dir(&socket_dir).unwrap();
        // Not a possible OS pid; no unrelated host socket can share this producer filename.
        let wrong_pid = u32::MAX;
        let socket = socket_dir.join(format!("{wrong_pid}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        with_producer_runtime(dir.path(), || {
            let now = 1_800_000_000;
            let target = ClaudeWakeTarget::resolve(
                wrong_pid,
                now - 100,
                Some(777),
                &|_| Ok(Some((info(dir.path(), wrong_pid, Some(now - 100)), 777))),
                now,
            )
            .unwrap();
            assert_eq!(
                super::deliver_claude(
                    &target,
                    &claude_socket_dirs(),
                    &|| true,
                    1,
                    CLAUDE_SOCKET_TIMEOUT
                ),
                Delivery::ClaudeWakeFailed
            );
            let (mut accepted, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            accepted.read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty());
        });
    }

    fn private_socket_root() -> TempDir {
        // The full Unix socket path must fit SUN_LEN even with a long ambient TMPDIR.
        short_root("csqw-").unwrap()
    }

    #[test]
    fn missing_registry_matching_peer_receives_notice() {
        let dir = private_socket_root();
        let pid = std::process::id();
        let socket = dir.path().join(format!("{pid}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        let now = 1_800_000_000;
        let target = ClaudeWakeTarget::resolve_with_socket_lookup(
            pid,
            now - 100,
            Some(777),
            &|_| Ok(Some((info(dir.path(), pid, Some(now - 100)), 777))),
            now,
            &|who| {
                select_claude_socket(who, std::slice::from_ref(&socket), &[dir.path().to_owned()])
            },
        )
        .expect("optional registry absence must permit the verified producer candidate");
        assert_eq!(
            super::deliver_claude(
                &target,
                &[dir.path().to_owned()],
                &|| true,
                1,
                CLAUDE_SOCKET_TIMEOUT
            ),
            Delivery::ClaudeWoken
        );
        let (mut accepted, _) = listener.accept().unwrap();
        let mut line = String::new();
        accepted.read_to_string(&mut line).unwrap();
        assert_eq!(line, claude_line(1));
    }

    #[test]
    fn missing_registry_wrong_peer_receives_no_notice() {
        let dir = private_socket_root();
        let wrong_pid = std::process::id().checked_add(1).unwrap();
        let socket = dir.path().join(format!("{wrong_pid}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        let now = 1_800_000_000;
        let target = ClaudeWakeTarget::resolve_with_socket_lookup(
            wrong_pid,
            now - 100,
            Some(777),
            &|_| Ok(Some((info(dir.path(), wrong_pid, Some(now - 100)), 777))),
            now,
            &|who| {
                select_claude_socket(who, std::slice::from_ref(&socket), &[dir.path().to_owned()])
            },
        )
        .unwrap();
        assert_eq!(
            super::deliver_claude(
                &target,
                &[dir.path().to_owned()],
                &|| true,
                1,
                CLAUDE_SOCKET_TIMEOUT
            ),
            Delivery::ClaudeWakeFailed
        );
        let (mut accepted, _) = listener.accept().unwrap();
        let mut bytes = Vec::new();
        accepted.read_to_end(&mut bytes).unwrap();
        assert!(
            bytes.is_empty(),
            "a candidate name must not authorize another listener PID"
        );
    }

    #[test]
    fn invalid_present_registry_never_uses_candidate_fallback() {
        let dir = TempDir::new().unwrap();
        let pid = std::process::id();
        std::fs::create_dir(dir.path().join("sessions")).unwrap();
        std::fs::write(
            dir.path().join("sessions").join(format!("{pid}.json")),
            b"not JSON",
        )
        .unwrap();
        let now = 1_800_000_000;
        let target = ClaudeWakeTarget::resolve_with_socket_lookup(
            pid,
            now - 100,
            Some(777),
            &|_| Ok(Some((info(dir.path(), pid, Some(now - 100)), 777))),
            now,
            &|_| panic!("present invalid metadata cannot authorize discovery"),
        );
        assert!(target.is_none());
    }

    #[test]
    fn discovery_refuses_unknown_wrong_pid_and_ambiguous_paths() {
        let first = private_socket_root();
        let second = private_socket_root();
        let pid = std::process::id();
        let a = first.path().join(format!("{pid}.sock"));
        let b = second.path().join(format!("{pid}.sock"));
        let _one = UnixListener::bind(&a).unwrap();
        let _two = UnixListener::bind(&b).unwrap();
        let allowed = [first.path().to_owned(), second.path().to_owned()];
        assert!(select_claude_socket(pid, &[], &allowed).is_none());
        assert!(select_claude_socket(pid + 1, std::slice::from_ref(&a), &allowed).is_none());
        assert!(select_claude_socket(pid, &[a.clone(), b], &allowed).is_none());
        assert_eq!(
            select_claude_socket(pid, &[a.clone(), a.clone()], &allowed),
            Some(a.canonicalize().unwrap())
        );
    }

    #[test]
    fn missing_registry_discovery_rechecks_exact_incarnation() {
        let dir = TempDir::new().unwrap();
        let pid = std::process::id();
        let reads = std::cell::Cell::new(0);
        let now = 1_800_000_000;
        let target = ClaudeWakeTarget::resolve_with_socket_lookup(
            pid,
            now - 100,
            Some(777),
            &|_| {
                reads.set(reads.get() + 1);
                let exact = if reads.get() == 1 { 777 } else { 778 };
                Ok(Some((info(dir.path(), pid, Some(now - 100)), exact)))
            },
            now,
            &|_| Some(dir.path().join(format!("{pid}.sock"))),
        );
        assert!(
            target.is_none(),
            "a reused PID cannot inherit the first lookup's socket"
        );
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn claude_target_still_live_needs_the_same_exact_start() {
        let t = ClaudeWakeTarget {
            pid: 9,
            start: 500,
            socket: PathBuf::from("/s"),
            config_dir: PathBuf::from("/config"),
        };
        assert!(t.still_live_with(&|_| Some(500)));
        assert!(!t.still_live_with(&|_| Some(501)), "a reused pid");
        assert!(!t.still_live_with(&|_| None), "unreadable start");
    }

    fn info(config: &Path, pid: u32, started: Option<u64>) -> crate::sessions::SessionInfo {
        crate::sessions::SessionInfo {
            pid,
            cwd: PathBuf::from("/w"),
            config_dir: config.to_path_buf(),
            account_id: None,
            started_at: started,
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        }
    }

    const NOW: u64 = 1_800_000_000;

    fn registry(cfg: &Path, pid: u32, body: &str) {
        let dir = cfg.join("sessions");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{pid}.json")), body).unwrap();
    }

    fn resolve_with(
        cfg: &Path,
        pid: u32,
        started: u64,
        listed: Option<u64>,
        stored_exact: Option<u64>,
    ) -> Option<ClaudeWakeTarget> {
        let i = info(cfg, pid, listed);
        ClaudeWakeTarget::resolve(
            pid,
            started,
            stored_exact,
            &|_| Ok(Some((i.clone(), 777))),
            NOW,
        )
    }

    /// A fresh `socks` directory standing in for `/tmp/cc-socks` (mode 0700, ours).
    fn socks(d: &TempDir) -> (PathBuf, Vec<PathBuf>) {
        let s = d.path().join("socks");
        std::fs::create_dir_all(&s).unwrap();
        (s.clone(), vec![s])
    }

    #[test]
    fn claude_target_comes_from_the_recipients_own_registry_record() {
        let d = TempDir::new().unwrap();
        let (sd, _) = socks(&d);
        let sock = sd.join("42.sock");
        registry(
            d.path(),
            42,
            &format!(
                r#"{{"pid":42,"startedAt":{},"messagingSocketPath":"{}"}}"#,
                (NOW - 100) * 1000,
                sock.display()
            ),
        );
        let t = resolve_with(d.path(), 42, NOW - 100, Some(NOW - 100), Some(777)).unwrap();
        assert_eq!(t.socket(), sock.as_path());
        assert!(t.still_live_with(&|_| Some(777)));
    }

    /// Every way the registry can fail to bind is `None` (a `queued_only` send), never a post.
    /// Falsifier: the exact-start cases fail if the bind compared seconds only.
    #[test]
    fn claude_target_is_none_when_the_registry_cannot_bind_it() {
        let ms = (NOW - 100) * 1000;
        let good =
            |sock: &str| format!(r#"{{"pid":42,"startedAt":{ms},"messagingSocketPath":"{sock}"}}"#);
        // (name, listed start, stored exact, registry written)
        let cases: Vec<(&str, Option<u64>, Option<u64>, bool)> = vec![
            ("absent record", Some(NOW - 100), Some(777), false),
            ("unreadable listed start", None, Some(777), true),
            (
                "absent stored exact never binds",
                Some(NOW - 100),
                None,
                true,
            ),
            (
                "a different exact start (reused pid)",
                Some(NOW - 100),
                Some(778),
                true,
            ),
            (
                "started long before the record",
                Some(NOW - 5_000),
                Some(777),
                true,
            ),
        ];
        for (name, listed, stored, written) in cases {
            let d = TempDir::new().unwrap();
            if written {
                registry(d.path(), 42, &good("/tmp/cc-socks/42.sock"));
            }
            assert!(
                resolve_with(d.path(), 42, NOW - 100, listed, stored).is_none(),
                "{name}"
            );
        }
        let bodies: Vec<(&str, String)> = vec![
            ("no socket key", format!(r#"{{"pid":42,"startedAt":{ms}}}"#)),
            (
                "socket key not a string",
                format!(r#"{{"pid":42,"startedAt":{ms},"messagingSocketPath":7}}"#),
            ),
            (
                "pid of another session",
                good("/tmp/cc-socks/42.sock").replace("\"pid\":42", "\"pid\":43"),
            ),
            ("relative socket path", good("socks/42.sock")),
            ("not json", "not json".into()),
        ];
        for (name, body) in bodies {
            let d = TempDir::new().unwrap();
            registry(d.path(), 42, &body);
            assert!(
                resolve_with(d.path(), 42, NOW - 100, Some(NOW - 100), Some(777)).is_none(),
                "{name}"
            );
        }
        // A symlinked record is not followed (the unreadable-registry branch).
        let d = TempDir::new().unwrap();
        let real = d.path().join("real.json");
        std::fs::write(&real, good("/tmp/cc-socks/42.sock")).unwrap();
        std::fs::create_dir_all(d.path().join("sessions")).unwrap();
        std::os::unix::fs::symlink(&real, d.path().join("sessions/42.json")).unwrap();
        assert!(resolve_with(d.path(), 42, NOW - 100, Some(NOW - 100), Some(777)).is_none());
        // A process that is not listed at all.
        assert!(ClaudeWakeTarget::resolve(42, NOW - 100, Some(777), &|_| Ok(None), NOW).is_none());
        assert!(ClaudeWakeTarget::resolve(
            42,
            NOW - 100,
            Some(777),
            &|_| Err(crate::sessions::Undetermined),
            NOW
        )
        .is_none());
    }

    /// Post-time directory confinement (spec 32a 5.2): a socket outside the allowed directories,
    /// in a symlinked directory that leads out, or in an allowed directory that is group/world
    /// writable, is `claude_wake_failed` and nothing connects. Falsifier: with the check
    /// removed, each of these listeners would receive the line.
    #[test]
    fn claude_post_is_refused_outside_trusted_directories_and_never_connects() {
        use std::os::unix::fs::PermissionsExt;
        // CI TMPDIR can be deeper than sockaddr_un::sun_path permits. A short,
        // private root lets the real listeners reach the confinement checks.
        let d = short_root("cw-").unwrap();
        let (sd, allowed) = socks(&d);
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let l_out = UnixListener::bind(elsewhere.join("a.sock")).unwrap();
        l_out.set_nonblocking(true).unwrap();
        let link = sd.join("out");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        for (name, path) in [
            ("unrelated directory", elsewhere.join("a.sock")),
            ("symlinked directory that leads out", link.join("a.sock")),
        ] {
            assert_eq!(
                deliver_claude(&path, &allowed, &|| true, 1, CLAUDE_SOCKET_TIMEOUT),
                Delivery::ClaudeWakeFailed,
                "{name}"
            );
        }
        assert_eq!(
            l_out.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        // The allowed directory itself group-writable: refused although the path matches.
        let l_in = UnixListener::bind(sd.join("b.sock")).unwrap();
        l_in.set_nonblocking(true).unwrap();
        std::fs::set_permissions(&sd, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            deliver_claude(
                &sd.join("b.sock"),
                &allowed,
                &|| true,
                1,
                CLAUDE_SOCKET_TIMEOUT
            ),
            Delivery::ClaudeWakeFailed,
            "group-writable allowed dir"
        );
        assert_eq!(
            l_in.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        std::fs::set_permissions(&sd, std::fs::Permissions::from_mode(0o700)).unwrap();
        l_in.set_nonblocking(false).unwrap();
        let h = std::thread::spawn(move || {
            let (mut c, _) = l_in.accept().unwrap();
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            got
        });
        assert_eq!(
            deliver_claude(
                &sd.join("b.sock"),
                &allowed,
                &|| true,
                1,
                CLAUDE_SOCKET_TIMEOUT
            ),
            Delivery::ClaudeWoken,
            "the same socket in a trusted directory is posted to"
        );
        assert_eq!(h.join().unwrap(), claude_line(1).into_bytes());
    }

    #[test]
    fn real_socket_dirs_name_the_producer_locations() {
        let _env = crate::platform::test_env::lock();
        let v = claude_socket_dirs();
        assert!(v.contains(&PathBuf::from("/tmp/cc-socks")));
        assert!(v
            .iter()
            .any(|p| p.to_string_lossy().starts_with("/tmp/cc-socks-")));
    }

    /// Generated ALL contains every variant; tagged wire values must distinguish them even
    /// when two variants deliberately share the same status string.
    #[test]
    fn all_variants_are_distinct_by_identity_with_a_wire_string() {
        let mut keys: Vec<_> = Delivery::ALL.iter().map(|d| d.tagged()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), Delivery::ALL.len());
        assert!(Delivery::ALL.iter().all(|d| !d.as_str().is_empty()));
    }

    /// INVEST-1: writing to a peer that has gone is an error value, never a signal.
    #[test]
    fn writing_to_a_closed_peer_is_an_error_not_a_signal() {
        let (mut a, b) = UnixStream::pair().unwrap();
        drop(b);
        let r = write_line_bounded(&mut a, claude_line(1).as_bytes(), Duration::from_secs(1));
        assert_eq!(r, Err(ClaudeWakeFail::Write));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn nosigpipe_option_failure_connects_and_writes_nothing() {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                NOSIGPIPE_FAILURE.with(|slot| slot.set(self.0));
            }
        }
        let d = socket_root();
        let listener = UnixListener::bind(sock(&d)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let _restore = Restore(NOSIGPIPE_FAILURE.with(|slot| slot.replace(true)));
        assert_eq!(
            deliver_claude(&sock(&d), &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWakeFailed
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "option failure must precede connect and send"
        );
    }

    /// F2's HEALTHY outcome: connect plus write to a live listener. The elapsed time is printed
    /// (`--nocapture`) and bounded at 1/20 of the budget; the measured values are in the
    /// constant's doc.
    #[test]
    fn healthy_post_is_far_under_the_budget() {
        let d = socket_root();
        let l = UnixListener::bind(sock(&d)).unwrap();
        let h = serve_once(l);
        let t0 = Instant::now();
        assert_eq!(
            deliver_claude(&sock(&d), &allow(&d), &|| true, 1, CLAUDE_SOCKET_TIMEOUT),
            Delivery::ClaudeWoken
        );
        let el = t0.elapsed();
        println!("healthy claude post: {el:?}");
        h.join().unwrap();
        assert!(el < CLAUDE_SOCKET_TIMEOUT / 20, "{el:?}");
    }

    #[cfg(target_os = "linux")]
    /// A listener created with `listen(fd, 0)` from the start (a re-`listen` on a std listener
    /// is not honoured on macOS, which kept accepting 64+ connections).
    fn listener_backlog0(path: &Path) -> UnixListener {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: plain syscalls on a descriptor created here and owned by the result; the
        // `sockaddr_un` is zero-initialised and filled within its bounds.
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            assert!(fd >= 0);
            let owned = OwnedFd::from_raw_fd(fd);
            let mut a: libc::sockaddr_un = std::mem::zeroed();
            a.sun_family = libc::AF_UNIX as libc::sa_family_t;
            for (dst, b) in a.sun_path.iter_mut().zip(path.as_os_str().as_bytes()) {
                *dst = *b as libc::c_char;
            }
            #[cfg(target_os = "macos")]
            {
                a.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
            }
            let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            assert_eq!(libc::bind(fd, std::ptr::addr_of!(a).cast(), len), 0);
            assert_eq!(libc::listen(fd, 0), 0);
            UnixListener::from(owned)
        }
    }

    /// H1: a listener whose backlog is full and never accepts. Linux only: macOS measured
    /// 2026-10-06 (mac-mini, Darwin 25.x) accepts 64+ queued connects on a `listen(fd, 0)`
    /// socket without ever refusing or blocking, so the full-backlog state this test needs
    /// cannot be reached there; the deadline logic it exercises is OS-independent. The post ends at
    /// its deadline (`EAGAIN` forever -> `Timeout`), spawns no thread, and nothing is written later: after the timeout every queued
    /// connection is drained and none carries a byte. Falsifier: a blocking connect hangs on
    /// Linux and never returns; a connect that wrote after its deadline leaves bytes here.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_full_backlog_is_bounded_spawns_no_thread_and_writes_nothing_late() {
        let d = socket_root();
        let l = listener_backlog0(&sock(&d));
        let mut held = Vec::new();
        for _ in 0..64 {
            match connect_nonblocking(&sock(&d), Instant::now() + Duration::from_millis(60)) {
                Ok(fd) => held.push(fd),
                Err(_) => break,
            }
        }
        assert!(
            !held.is_empty() && held.len() < 64,
            "backlog never filled: {} held",
            held.len()
        );
        let t0 = Instant::now();
        let r = post_line(
            &sock(&d),
            &allow(&d),
            claude_line(1).as_bytes(),
            Duration::from_millis(400),
        );
        let el = t0.elapsed();
        #[cfg(target_os = "linux")]
        assert_eq!(r, Err(ClaudeWakeFail::Timeout));
        #[cfg(not(target_os = "linux"))]
        assert!(matches!(
            r,
            Err(ClaudeWakeFail::Timeout | ClaudeWakeFail::Connect)
        ));
        assert!(el < Duration::from_secs(3), "{el:?}");
        assert!(el >= Duration::from_millis(350), "{el:?}");
        // No helper thread exists (threads of this process are listed in /proc).
        for e in std::fs::read_dir("/proc/self/task").unwrap() {
            // Every test thread in this process is listed here and one may exit between the
            // listing and this read; a vanished thread cannot be a surviving helper.
            let comm = match std::fs::read_to_string(e.unwrap().path().join("comm")) {
                Ok(comm) => comm,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("read thread comm: {error}"),
            };
            assert!(!comm.contains("csq-claude-wake"), "{comm}");
        }
        // Nothing arrives later: let any straggler run, then drain every queued connection.
        std::thread::sleep(Duration::from_millis(200));
        l.set_nonblocking(true).unwrap();
        while let Ok((mut c, _)) = l.accept() {
            c.set_nonblocking(true).unwrap();
            let mut b = [0u8; 16];
            let n = c.read(&mut b).unwrap_or(0);
            assert_eq!(n, 0, "a late write reached the listener");
        }
    }
}

#[cfg(all(test, unix))]
mod w2_tests {
    use super::*;
    use crate::messaging::{
        limits::{Limits, Liveness},
        model::{Recipient, Sender, Surface, VerifiedSession},
        store,
    };
    use crate::sessions::directives::real_fs;
    use crate::testing::socket_fixture::short_root;
    use std::io::Read;
    use std::os::unix::{
        fs::{symlink, PermissionsExt},
        net::UnixListener,
    };
    use tempfile::TempDir;

    const NOW: u64 = 5_100;

    /// Test-only scheduling margin on top of the ENFORCED production socket
    /// budget. A loaded sign-off host can leave a spawned test thread
    /// unscheduled for seconds, so a row that raced ordinary thread
    /// coordination against the bare 2s production value can red with no
    /// product defect. The stretch never reaches a property assertion: these
    /// rows count posts and delivery kinds, and the one row that pins the
    /// production lock wait itself (`a_waiter_deferred_to_the_holder_...`)
    /// keeps the enforced 2s on the waiter whose expiry IS the property.
    const SCHEDULING_STRETCH: u32 = 10;

    /// A test-step deadline: the enforced production budget times the named
    /// scheduling margin above. It is a FAILURE DETECTOR for a stuck
    /// handshake, never a measured typical and never a product bound.
    fn step_bound() -> Duration {
        CLAUDE_SOCKET_TIMEOUT * SCHEDULING_STRETCH
    }

    /// Join a spawned thread and report a panic as a NAMED failure of this test
    /// instead of re-raising it from the thread with `join().unwrap()`. Inside
    /// `std::thread::scope`, a thread panic raised while the scope is already
    /// unwinding for another failure aborts the whole test process, taking the
    /// remaining tests down with it.
    fn collected<T>(thread: &str, result: std::thread::Result<T>) -> T {
        match result {
            Ok(value) => value,
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".into());
                panic!("{thread} panicked: {message}");
            }
        }
    }

    struct World {
        home: TempDir,
        base: TempDir,
        target: ClaudeWakeTarget,
        to: Recipient,
        sender: VerifiedSession,
        receiver: VerifiedSession,
    }
    impl World {
        fn new() -> Self {
            // The inbox socket lives directly in `home`; a deep runner TMPDIR
            // would push its pathname past `sun_path`.
            let home = short_root("csq-w2-").unwrap();
            let base = TempDir::new().unwrap();
            let receiver = VerifiedSession::from_resolved(Sender {
                pid: std::process::id(),
                started_at: 5_000,
                surface: Surface::ClaudeCode,
                handle_dir_hash: "receiver".into(),
                handle_dir: home.path().to_str().unwrap().into(),
                name: None,
                started_exact: Some(777),
            });
            let sender = VerifiedSession::from_resolved(Sender {
                pid: std::process::id().checked_add(1).unwrap(),
                started_at: 5_000,
                surface: Surface::Codex,
                handle_dir_hash: "sender".into(),
                handle_dir: base.path().to_str().unwrap().into(),
                name: None,
                started_exact: Some(888),
            });
            let to = receiver.as_recipient();
            let target = ClaudeWakeTarget {
                pid: to.pid,
                start: 777,
                socket: home.path().join("c.sock"),
                config_dir: home.path().to_path_buf(),
            };
            Self {
                home,
                base,
                target,
                to,
                sender,
                receiver,
            }
        }
        fn send(&self, now: u64) -> String {
            store::send(
                self.base.path(),
                now,
                &real_fs(),
                &Limits::DEFAULT,
                &|_| Liveness::Live,
                &self.sender,
                self.to,
                "peer body remains in the store",
                None,
            )
            .unwrap()
            .id
        }
        fn wake(&self, now: u64) -> Delivery {
            self.wake_with(now, &|| {
                store::pending_ids(self.base.path(), now, &self.to).ok()
            })
        }
        /// A wake whose store reads are the caller's, at the ENFORCED production budget. Used
        /// where the 2s post budget itself is the property under test.
        fn wake_with(&self, now: u64, pending_ids: &dyn Fn() -> Option<Vec<String>>) -> Delivery {
            self.wake_with_bound(now, CLAUDE_SOCKET_TIMEOUT, pending_ids)
        }
        /// A wake whose caller budget AND store reads are the caller's. The final-recheck row uses
        /// the test step bound: its property is the recheck coverage, never the 2s post budget, so
        /// a loaded host must not be able to make the message the TEST stores inside that measured
        /// window (`recheck_late`) and so record an empty cohort on a correct product.
        fn wake_with_bound(
            &self,
            now: u64,
            timeout: Duration,
            pending_ids: &dyn Fn() -> Option<Vec<String>>,
        ) -> Delivery {
            deliver_claude_coalesced(
                &self.target,
                &[self.home.path().to_path_buf()],
                &|| true,
                1,
                timeout,
                now,
                pending_ids,
            )
        }
        /// A wake with a caller-chosen budget. The lock/coalescing rows use the test step bound
        /// here because their property is serialization, never the 2s post budget; a loaded host
        /// must not be able to turn an on-time evidence read "late" and make a loser post.
        fn wake_with_budget(&self, now: u64, timeout: Duration) -> Delivery {
            deliver_claude_coalesced(
                &self.target,
                &[self.home.path().to_path_buf()],
                &|| true,
                1,
                timeout,
                now,
                &|| store::pending_ids(self.base.path(), now, &self.to).ok(),
            )
        }
        fn state(&self) -> PathBuf {
            claude_notice_path(self.home.path(), self.to.pid)
        }
        fn listen(&self) -> UnixListener {
            let l = UnixListener::bind(self.target.socket()).unwrap();
            l.set_nonblocking(true).unwrap();
            l
        }
    }
    fn posts(l: &UnixListener) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            match l.accept() {
                Ok((mut stream, _)) => {
                    let mut text = String::new();
                    stream.read_to_string(&mut text).unwrap();
                    out.push(text);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("accept: {e}"),
            }
        }
        out
    }

    /// The socket post owns the production budget: a slow pre-post bookkeeping stretch (fsync at
    /// the measured slow-host class, ~2.5s) must not leave the post with no time. Red proof: with the
    /// deadline started before the bookkeeping, the injected delay spends it and the delivery is
    /// `ClaudeWakeFailed` while the listener sees nothing.
    #[test]
    fn slow_pre_post_bookkeeping_does_not_consume_the_post_budget() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW);
        let d = with_claude_wake_prepost_probe(
            || std::thread::sleep(Duration::from_millis(2500)),
            || w.wake(NOW),
        );
        assert_eq!(d, Delivery::ClaudeWoken);
        assert_eq!(posts(&l), vec![claude_line(1)]);
    }

    /// The reservation is published durably: `write_private_atomic` renames but never fsyncs the
    /// directory, so the record that must exist before the first notice byte goes through a helper
    /// that fsyncs its parent too. Red proof: on the bare atomic write the recorder is empty at the
    /// pre-post probe -- the rename happened, the durability step did not.
    #[test]
    fn the_reservation_syncs_its_directory_before_the_notice_is_posted() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW);
        let _ = take_claude_wake_dirsyncs();
        // The probe is `'static`, so the reading travels through an owned counter.
        let synced = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = std::sync::Arc::clone(&synced);
        let d = with_claude_wake_prepost_probe(
            move || {
                observed.store(
                    take_claude_wake_dirsyncs().len(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            },
            || w.wake(NOW),
        );
        assert_eq!(d, Delivery::ClaudeWoken);
        assert!(
            synced.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the reservation's directory fsync must complete before the post is attempted"
        );
        assert_eq!(posts(&l).len(), 1);
    }

    /// A second sender whose lock wait expires is deferred to the holder, never failed, and the
    /// holder's final store read before it releases the lock posts once more for what its own post
    /// did not cover. Red proof: without the re-check the holder reads the store once, the waiter
    /// reports a failure, and a message stored after the first post is behind no notice at all.
    #[test]
    fn a_waiter_deferred_to_the_holder_is_covered_by_the_holders_final_recheck() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW); // the holder's own cohort, read before the probe blocks
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (recheck_tx, recheck_rx) = std::sync::mpsc::channel();
        let (ids_tx, ids_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (probe_tx, probe_rx) = std::sync::mpsc::channel();
        // The holder owns its channel ends: a `Receiver` is `!Sync`, so a spawned closure can only
        // hold one by value. A test failure drops the senders, which unblocks the holder's waits
        // immediately (`recv_timeout` returns `Disconnected`), so no deadlock outlives the failure.
        let world = &w;
        std::thread::scope(|scope| {
            let holder = scope.spawn(move || {
                with_claude_wake_prepost_probe(
                    move || {
                        // Signal that the lock is held, then WAIT for the test's release instead
                        // of sleeping for the incident host's measured 2.5s disk class. The
                        // waiter's whole ENFORCED lock wait must expire against a HELD lock, so
                        // how much wall-clock the harness spends spawning that waiter must not
                        // decide the outcome: the release is an event, sent after it returned.
                        let _ = held_tx.send(());
                        let _ = probe_rx.recv_timeout(step_bound());
                    },
                    move || {
                        let reads = std::cell::Cell::new(0u32);
                        // The HOLDER runs at the test step bound, never the 2s post budget: the
                        // test stores `late_id` inside this call's measured window, and a loaded
                        // host must not be able to make that read `recheck_late` and record an
                        // empty cohort. The WAITER keeps the enforced 2s: its expiry is the
                        // property this row pins.
                        world.wake_with_bound(NOW, step_bound(), &|| {
                            let n = reads.get();
                            reads.set(n + 1);
                            if n == 1 {
                                // The read that follows the first post: hand it to the test, then
                                // hold it open until the test has stored the late message, so the
                                // order (post, then this read, then the store) is the test's and
                                // not the scheduler's.
                                let _ = recheck_tx.send(());
                                let _ = release_rx.recv_timeout(step_bound());
                            }
                            let ids = store::pending_ids(world.base.path(), NOW, &world.to).ok();
                            if n == 1 {
                                let _ = ids_tx.send(ids.clone());
                            }
                            ids
                        })
                    },
                )
            });
            held_rx
                .recv_timeout(step_bound())
                .expect("holder holds the wake lock");
            // A concurrent sender: its message is stored while the lock is held, then its own
            // wake attempt waits and cannot get the lock before its bound.
            let waiter = scope.spawn(|| {
                let id = w.send(NOW);
                (id, w.wake(NOW))
            });
            // The waiter keeps the ENFORCED production lock wait: its expiry is the property
            // under test. The holder is still blocked in its probe, so that wait always expires.
            let waiter_result = waiter.join();
            // Release the holder's probe only now, after the waiter returned Contended: its first
            // post and final read can no longer race the waiter's outcome.
            let _ = probe_tx.send(());
            // Stored strictly after the holder's first post: only the holder's final read can put
            // it behind a notice. That read is held open here, so the order is the test's.
            let signalled = recheck_rx.recv_timeout(step_bound());
            let late_id = w.send(NOW);
            let _ = release_tx.send(());
            let holder_result = holder.join();
            let (waiter_id, waiter_delivery) = collected("waiter", waiter_result);
            let holder_delivery = collected("holder", holder_result);
            assert_eq!(
                waiter_delivery,
                Delivery::ClaudeWakeContended,
                "a lost lock wait is contended (no coverage claimed), never failed"
            );
            signalled.expect("holder read the store again before releasing the lock");
            let seen = ids_rx
                .recv_timeout(step_bound())
                .expect("holder published its final read");
            assert_eq!(holder_delivery, Delivery::ClaudeWoken);
            assert_eq!(
                posts(&l).len(),
                2,
                "the holder posts once more for the ids its first post did not cover"
            );
            for id in [&waiter_id, &late_id] {
                assert!(
                    seen.as_ref().is_some_and(|ids| ids.contains(id)),
                    "the final read saw {id}: {seen:?}"
                );
                let state = read_claude_notice(&w.state()).unwrap();
                assert!(
                    state.pending_ids.contains(id),
                    "the second post covers {id}: {:?}",
                    state.pending_ids
                );
            }
        });
    }

    #[test]
    fn r1_success_floor_survives_reads_new_threads_and_expired_coalescing() {
        for read_between in [false, true] {
            let w = World::new();
            let l = w.listen();
            for i in 0..7 {
                let now = NOW + i * 21;
                w.send(now);
                let expected = if i < 6 {
                    Delivery::ClaudeWoken
                } else {
                    Delivery::ClaudeWakeRateLimited
                };
                assert_eq!(w.wake(now), expected, "send {i}, read={read_between}");
                if read_between {
                    store::inbox(
                        w.base.path(),
                        now,
                        &real_fs(),
                        &|_| Liveness::Live,
                        &w.receiver,
                        true,
                        Some(store::Mark::Read),
                    )
                    .unwrap();
                }
            }
            assert_eq!(posts(&l).len(), 6);
            // Rate-window recovery must have an unread cohort; the read-between branch
            // consumed every earlier record and no longer permits an empty-inbox notice.
            w.send(NOW + 600);
            assert_eq!(w.wake(NOW + 600), Delivery::ClaudeWoken);
            assert_eq!(posts(&l).len(), 1);
        }
        // An ordinary slow reply cadence remains admitted after the oldest slot expires.
        let w = World::new();
        let l = w.listen();
        for i in 0..8 {
            let now = NOW + i * 101;
            w.send(now);
            assert_eq!(w.wake(now), Delivery::ClaudeWoken);
        }
        assert_eq!(posts(&l).len(), 8);
    }
    #[test]
    fn r1_mcp_rate_limited_status_remains_distinct() {
        assert_eq!(
            Delivery::ClaudeWakeRateLimited.as_str(),
            "claude_wake_rate_limited"
        );
        assert_eq!(
            Delivery::ClaudeWakeRateLimited.tagged(),
            "claude_wake_rate_limited"
        );
        assert_eq!(Delivery::ClaudeWakeRateLimited.reason(), None);
    }

    #[test]
    fn r1_malformed_state_blocks_then_recovers_after_window() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW);
        std::fs::write(w.state(), "malformed").unwrap();
        std::fs::set_permissions(w.state(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::File::open(w.state())
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW)),
            )
            .unwrap();
        assert_eq!(w.wake(NOW), Delivery::ClaudeWakeRateLimited);
        assert!(posts(&l).is_empty());
        assert_eq!(w.wake(NOW + 600), Delivery::ClaudeWoken);
        assert_eq!(posts(&l).len(), 1);
        let state = read_claude_notice(&w.state()).unwrap();
        assert_eq!(state.reservations, vec![NOW + 600]);
        assert_eq!(state.successful_posts, vec![NOW + 600]);
    }

    #[test]
    fn r2_actual_unreadable_store_cannot_bypass_success_floor() {
        let w = World::new();
        let l = w.listen();
        let id = w.send(NOW);
        std::fs::write(
            store::store_dir(w.base.path()).join(format!("{id}.json")),
            "broken",
        )
        .unwrap();
        assert!(store::pending_ids(w.base.path(), NOW, &w.to).is_err());
        for i in 0..7 {
            assert_eq!(
                w.wake(NOW + i * 21),
                if i < 6 {
                    Delivery::ClaudeWoken
                } else {
                    Delivery::ClaudeWakeRateLimited
                }
            );
        }
        assert_eq!(posts(&l).len(), 6);
        let state = read_claude_notice(&w.state()).unwrap();
        assert!(state.pending_ids.is_empty());
        assert_eq!(state.successful_posts.len(), 6);
    }

    #[test]
    fn r1_failed_reservations_cap_and_recover_with_clock_rollback() {
        let w = World::new();
        w.send(NOW);
        // A genuine nonexistent Unix endpoint fails all six actual socket attempts.
        for i in 0..6 {
            assert_eq!(w.wake(NOW + i), Delivery::ClaudeWakeFailed);
            let state = read_claude_notice(&w.state()).unwrap();
            assert_eq!(state.reservations.len(), (i + 1) as usize);
            assert!(state.successful_posts.is_empty());
        }
        assert_eq!(w.wake(NOW + 6), Delivery::ClaudeWakeRateLimited);
        assert_eq!(w.wake(NOW - 1), Delivery::ClaudeWakeRateLimited);
        assert_eq!(
            read_claude_notice(&w.state()).unwrap().reservations.len(),
            6
        );
        let l = w.listen();
        assert_eq!(w.wake(NOW + 600), Delivery::ClaudeWoken);
        assert_eq!(posts(&l), [claude_line(1)]);
        let state = read_claude_notice(&w.state()).unwrap();
        assert_eq!(state.reservations.len(), 6);
        assert_eq!(state.successful_posts, vec![NOW + 600]);
    }

    #[test]
    fn five_actual_sends_produce_one_post_and_truthful_receipts() {
        let w = World::new();
        let l = w.listen();
        for i in 0..5 {
            w.send(NOW + i);
            assert_eq!(
                w.wake(NOW + i),
                if i == 0 {
                    Delivery::ClaudeWoken
                } else {
                    Delivery::ClaudeWakePending
                }
            );
        }
        assert_eq!(posts(&l), [claude_line(1)]);
        assert_eq!(
            store::pending_ids(w.base.path(), NOW + 5, &w.to)
                .unwrap()
                .len(),
            5
        );
        let inbox = store::inbox(
            w.base.path(),
            NOW + 5,
            &real_fs(),
            &|_| Liveness::Live,
            &w.receiver,
            true,
            None,
        )
        .unwrap();
        assert_eq!(inbox.len(), 5);
        assert!(inbox
            .iter()
            .all(|m| m.status == crate::messaging::model::Status::Queued));
        let md = std::fs::metadata(w.state()).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        assert_eq!(Delivery::ClaudeWakePending.as_str(), "claude_wake_pending");
        assert_eq!(Delivery::ClaudeWakePending.tagged(), "claude_wake_pending");
        assert_eq!(Delivery::ClaudeWakePending.reason(), None);
    }

    #[test]
    fn simultaneous_actual_sends_serialize_one_successful_notice() {
        let w = std::sync::Arc::new(World::new());
        let l = w.listen();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(5));
        let threads: Vec<_> = (0..5)
            .map(|_| {
                let w = w.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    w.send(NOW);
                    barrier.wait();
                    // Serialization is the property, so the lock wait is the test step bound: the
                    // production 2s value only decides how long a LOSER waits, and a loaded host
                    // must not convert an on-time evidence read into a "late" one whose missing
                    // cohort lets a second thread post.
                    w.wake_with_budget(NOW, step_bound())
                })
            })
            .collect();
        // Join EVERY sender before asserting, and report a thread panic as a named failure: a
        // joined scoped thread that panics while another assertion is unwinding would abort the
        // whole test process.
        let deliveries: Vec<_> = threads
            .into_iter()
            .enumerate()
            .map(|(i, t)| collected(&format!("sender thread {i}"), t.join()))
            .collect();
        assert_eq!(
            deliveries
                .iter()
                .filter(|d| **d == Delivery::ClaudeWoken)
                .count(),
            1,
            "exactly one attempt may post: {deliveries:?}"
        );
        // The holder's durable pre-post bookkeeping (lock, store read, fsync + rename +
        // directory fsync of the reservation) can outlast a loser's whole lock wait on a
        // slow-disk host -- the incident class this module models in
        // `a_waiter_deferred_to_the_holder_is_covered_by_the_holders_final_recheck`. A
        // loser that cannot take the lock for its whole wait reports `ClaudeWakeContended`
        // and posts nothing; one that acquires after the post coalesces and reports
        // `ClaudeWakePending`. Which of the two happens is scheduling, so the test must
        // not demand one of them behind a wall-clock margin.
        assert_eq!(
            deliveries
                .iter()
                .filter(
                    |d| **d == Delivery::ClaudeWakePending || **d == Delivery::ClaudeWakeContended
                )
                .count(),
            4,
            "every loser posts nothing, coalesced or contended: {deliveries:?}"
        );
        assert_eq!(
            posts(&l),
            [claude_line(1)],
            "the wake lock admits exactly one post"
        );
        assert_eq!(
            store::pending_ids(w.base.path(), NOW, &w.to).unwrap().len(),
            5
        );
        // Coverage is proven deterministically with the lock free: the winner's post still
        // covers unread ids of this incarnation, so a fresh wake coalesces and posts again
        // only if that coverage record was lost.
        assert_eq!(
            w.wake_with_budget(NOW + 1, step_bound()),
            Delivery::ClaudeWakePending
        );
        assert!(
            posts(&l).is_empty(),
            "a coalescing wake must not post a second notice"
        );
    }

    /// A waiter whose holder finishes INSIDE its wait must take the lock and
    /// coalesce. A single-try lock regression reports `ClaudeWakeContended` as
    /// soon as its one attempt meets a held lock, so it reds here.
    #[test]
    fn a_waiter_whose_holder_releases_inside_the_wait_takes_the_lock_and_coalesces() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW);
        // The first wake posts the notice; the unread id is then covered, so a
        // waiter that ACQUIRES the lock must coalesce instead of posting again.
        // The coalescing decision treats an evidence read slower than the caller
        // budget as unknown, so the budget here is the test step bound: a loaded
        // host must not turn an on-time read "late" and make the waiter post.
        // The late-evidence property has its own row.
        assert_eq!(w.wake_with_budget(NOW, step_bound()), Delivery::ClaudeWoken);
        assert_eq!(posts(&l), [claude_line(1)]);
        // The test holds the wake lock while the waiter starts, and releases on the
        // waiter's START signal: event-synchronised, never a sleep. The waiter's
        // wait budget is the production wait times the SAME named scheduling margin
        // as every other step bound here, so a delay between the signal and the
        // release can never expire it; it bounds the test, never a product path.
        let waiter_budget = CLAUDE_SOCKET_TIMEOUT * SCHEDULING_STRETCH;
        let guard = lock_wake(w.home.path(), CLAUDE_SOCKET_TIMEOUT)
            .unwrap()
            .expect("fixture acquires the wake lock");
        let (busy_tx, busy_rx) = std::sync::mpsc::channel();
        let world = &w;
        std::thread::scope(|scope| {
            let waiter = scope.spawn(move || {
                with_wake_lock_busy_signal(busy_tx, || {
                    deliver_claude_coalesced(
                        &world.target,
                        &[world.home.path().to_path_buf()],
                        &|| true,
                        1,
                        waiter_budget,
                        NOW + 1,
                        &|| store::pending_ids(world.base.path(), NOW + 1, &world.to).ok(),
                    )
                })
            });
            // Release ONLY after the waiter has MET the held lock (its first
            // EWOULDBLOCK attempt), so a single-try lock regression cannot slip
            // past: it would return Contended as soon as that attempt fails.
            busy_rx
                .recv_timeout(step_bound())
                .expect("the waiter must meet the held wake lock before the release");
            drop(guard);
            let delivery = collected("waiter", waiter.join());
            assert_eq!(
                delivery,
                Delivery::ClaudeWakePending,
                "a waiter that outlives the holder acquires the lock and coalesces"
            );
        });
        assert!(
            posts(&l).is_empty(),
            "a coalescing waiter must not post a second notice"
        );
    }

    #[test]
    fn sidecar_save_failure_refuses_post_without_rate_reservation() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW);
        // A directory cannot be atomically replaced by the state file. This exercises a
        // genuine persistence failure without fake success callbacks or permission skips.
        std::fs::create_dir(w.state()).unwrap();
        assert_eq!(w.wake(NOW), Delivery::ClaudeWakeRateLimited);
        assert_eq!(w.wake(NOW + 1), Delivery::ClaudeWakeRateLimited);
        assert!(posts(&l).is_empty());
        assert!(w.state().is_dir());
    }

    #[test]
    fn read_or_ack_then_new_send_cannot_reuse_old_notice() {
        for ack in [false, true] {
            let w = World::new();
            let l = w.listen();
            let old = w.send(NOW);
            assert_eq!(w.wake(NOW), Delivery::ClaudeWoken);
            if ack {
                store::ack(
                    w.base.path(),
                    NOW + 1,
                    &real_fs(),
                    &|_| Liveness::Live,
                    &w.receiver,
                    &old,
                    None,
                )
                .unwrap();
            } else {
                store::inbox(
                    w.base.path(),
                    NOW + 1,
                    &real_fs(),
                    &|_| Liveness::Live,
                    &w.receiver,
                    true,
                    Some(store::Mark::Read),
                )
                .unwrap();
            }
            assert!(store::pending_ids(w.base.path(), NOW + 1, &w.to)
                .unwrap()
                .is_empty());
            w.send(NOW + 2);
            assert_eq!(w.wake(NOW + 2), Delivery::ClaudeWoken, "ack={ack}");
            assert_eq!(posts(&l), [claude_line(1), claude_line(1)]);
        }
    }

    #[test]
    fn notice_dedup_delayed_claude_sender_does_not_enqueue_an_empty_inbox_turn() {
        let w = World::new();
        let l = w.listen();
        let first = w.send(NOW);
        let second = w.send(NOW + 1);
        assert_eq!(w.wake(NOW + 1), Delivery::ClaudeWoken);
        // This private socket protocol fixture fetches both durable peer records after
        // its first notice. A second sender still holds its pre-read count of one.
        let native_queue = posts(&l);
        assert_eq!(native_queue, [claude_line(1)]);
        let inbox = store::inbox(
            w.base.path(),
            NOW + 2,
            &real_fs(),
            &|_| Liveness::Live,
            &w.receiver,
            true,
            Some(store::Mark::Read),
        )
        .unwrap();
        assert_eq!(inbox.len(), 2);
        assert!(inbox.iter().any(|m| m.id == first));
        assert!(inbox.iter().any(|m| m.id == second));
        let before = read_claude_notice(&w.state()).unwrap().reservations;
        assert_eq!(
            w.wake(NOW + 3),
            Delivery::QueuedOnly,
            "a proven empty inbox must suppress the stale native notice"
        );
        assert!(posts(&l).is_empty(), "no empty-inbox native turn is queued");
        assert_eq!(read_claude_notice(&w.state()).unwrap().reservations, before);
        let history = store::inbox(
            w.base.path(),
            NOW + 3,
            &real_fs(),
            &|_| Liveness::Live,
            &w.receiver,
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            history.len(),
            2,
            "notice suppression never deletes peer records"
        );
        assert!(history
            .iter()
            .all(|m| m.status == super::super::model::Status::Read));
        w.send(NOW + 4);
        assert_eq!(w.wake(NOW + 4), Delivery::ClaudeWoken);
        assert_eq!(
            posts(&l),
            [claude_line(1)],
            "a new cohort still gets a notice"
        );
    }

    #[test]
    fn expiry_future_clock_and_incarnation_do_not_dedupe() {
        for change in ["expiry", "future", "incarnation"] {
            let mut w = World::new();
            let l = w.listen();
            w.send(NOW);
            assert_eq!(w.wake(NOW), Delivery::ClaudeWoken);
            let now = match change {
                "expiry" => NOW + CLAUDE_COALESCE_SECS,
                "future" => NOW - 1,
                _ => {
                    w.target.start += 1;
                    NOW + 1
                }
            };
            assert_eq!(w.wake(now), Delivery::ClaudeWoken, "change={change}");
            assert_eq!(posts(&l).len(), 2);
        }
    }

    #[test]
    fn invalid_unreadable_and_unknown_evidence_never_dedupe() {
        for damage in [
            "malformed",
            "version",
            "pid",
            "start",
            "id",
            "duplicate",
            "oversize",
            "public",
            "symlink",
            "store",
        ] {
            let w = World::new();
            let l = w.listen();
            let id = w.send(NOW);
            assert_eq!(w.wake(NOW), Delivery::ClaudeWoken);
            let mut state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(w.state()).unwrap()).unwrap();
            match damage {
                "malformed" => std::fs::write(w.state(), "{broken").unwrap(),
                "version" => {
                    state["version"] = 99.into();
                    std::fs::write(w.state(), state.to_string()).unwrap();
                }
                "pid" => {
                    state["pid"] = 1.into();
                    std::fs::write(w.state(), state.to_string()).unwrap();
                }
                "start" => {
                    state["start"] = 0.into();
                    std::fs::write(w.state(), state.to_string()).unwrap();
                }
                "id" => {
                    state["pending_ids"] = serde_json::json!(["invalid"]);
                    std::fs::write(w.state(), state.to_string()).unwrap();
                }
                "duplicate" => {
                    state["pending_ids"] = serde_json::json!([id, id]);
                    std::fs::write(w.state(), state.to_string()).unwrap();
                }
                "oversize" => std::fs::write(w.state(), " ".repeat(4097)).unwrap(),
                "public" => {
                    std::fs::set_permissions(w.state(), std::fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                "symlink" => {
                    std::fs::remove_file(w.state()).unwrap();
                    let sentinel = w.home.path().join("sentinel");
                    std::fs::write(&sentinel, "unchanged").unwrap();
                    symlink(sentinel, w.state()).unwrap();
                }
                "store" => {
                    std::fs::write(
                        store::store_dir(w.base.path()).join(format!("{id}.json")),
                        "broken",
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let reset = matches!(damage, "pid" | "start" | "store");
            assert_eq!(
                w.wake(NOW + 1),
                if reset {
                    Delivery::ClaudeWoken
                } else {
                    Delivery::ClaudeWakeRateLimited
                },
                "damage={damage}"
            );
            assert_eq!(posts(&l).len(), if reset { 2 } else { 1 });
            if damage == "symlink" {
                assert_eq!(
                    std::fs::read_to_string(w.home.path().join("sentinel")).unwrap(),
                    "unchanged"
                );
            }
            if damage == "store" {
                assert!(
                    read_claude_notice(&w.state())
                        .unwrap()
                        .pending_ids
                        .is_empty(),
                    "unknown evidence must not retain an old cohort"
                );
            }
        }
    }

    #[test]
    fn failed_posts_are_not_persisted_and_liveness_precedes_pending() {
        let w = World::new();
        w.send(NOW);
        assert_eq!(w.wake(NOW), Delivery::ClaudeWakeFailed);
        let failed = read_claude_notice(&w.state()).unwrap();
        assert!(failed.successful_posts.is_empty());
        assert_eq!(failed.reserved_at, Some(NOW));
        let l = w.listen();
        assert_eq!(w.wake(NOW + 1), Delivery::ClaudeWoken);
        let before = std::fs::read(w.state()).unwrap();
        assert_eq!(
            deliver_claude_coalesced(
                &w.target,
                &[w.home.path().to_path_buf()],
                &|| false,
                1,
                CLAUDE_SOCKET_TIMEOUT,
                NOW + 2,
                &|| store::pending_ids(w.base.path(), NOW + 2, &w.to).ok()
            ),
            Delivery::ClaudeWakeFailed
        );
        assert_eq!(std::fs::read(w.state()).unwrap(), before);
        assert_eq!(posts(&l).len(), 1);
    }

    #[test]
    fn r3_recipient_exit_or_deadline_after_notice_persists_success_count() {
        use std::cell::RefCell;
        use std::os::unix::net::UnixStream;
        for mode in ["fresh-exit", "old-state-exit", "deadline"] {
            let w = World::new();
            let l = w.listen();
            w.send(NOW);
            let old = (mode == "old-state-exit").then_some(
                serde_json::to_string(&ClaudeNotice {
                    version: 2,
                    pid: w.target.pid,
                    start: w.target.start,
                    posted_at: NOW - 1000,
                    pending_ids: Vec::new(),
                    successful_posts: Vec::new(),
                    reservations: Vec::new(),
                    reserved_at: None,
                })
                .unwrap(),
            );
            if let Some(ref old) = old {
                std::fs::write(w.state(), old).unwrap();
                std::fs::set_permissions(w.state(), std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let connection = RefCell::new(None::<UnixStream>);
            let received = RefCell::new(Vec::<u8>::new());
            let observe = || {
                let mut connection = connection.borrow_mut();
                if connection.is_none() {
                    match l.accept() {
                        Ok((s, _)) => {
                            s.set_nonblocking(true).unwrap();
                            *connection = Some(s);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
                        Err(e) => panic!("accept: {e}"),
                    }
                }
                let mut buffer = [0u8; 4096];
                loop {
                    match connection.as_mut().unwrap().read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => received.borrow_mut().extend_from_slice(&buffer[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("read: {e}"),
                    }
                }
                !received.borrow().is_empty()
            };
            // The enforced production limit, in every mode. "deadline" crosses it by the
            // sleep in `live`, which runs only after the notice bytes arrived, so the order
            // (bytes, then deadline) holds however slow the host's durable pre-send writes
            // are; a shortened 100ms limit instead expired during those writes on a slow disk.
            let timeout = CLAUDE_SOCKET_TIMEOUT;
            let live = || {
                if !observe() {
                    return true;
                }
                // This flips only after actual notice bytes arrive, not on an invocation count.
                if mode == "deadline" {
                    std::thread::sleep(timeout + Duration::from_millis(20));
                    true
                } else {
                    false
                }
            };
            let delivery = deliver_claude_coalesced(
                &w.target,
                &[w.home.path().to_path_buf()],
                &live,
                1,
                timeout,
                NOW,
                &|| store::pending_ids(w.base.path(), NOW, &w.to).ok(),
            );
            assert_eq!(
                delivery,
                Delivery::ClaudeWoken,
                "bytes already handed over: {mode}"
            );
            // Drain independently, so the negative control still proves bytes arrived when
            // its removed post-success callback would otherwise never observe them.
            observe();
            assert_eq!(*received.borrow(), claude_line(1).into_bytes());
            let state = read_claude_notice(&w.state()).unwrap();
            assert_eq!(
                state.successful_posts,
                vec![NOW],
                "actual post counted: {mode}"
            );
            assert!(state.reserved_at.is_none());
            assert!(state.pending_ids.is_empty());
        }
    }

    #[test]
    fn zero_budget_wake_lock_tries_uncontended_and_refuses_contended() {
        let home = TempDir::new().unwrap();
        let guard = lock_wake(home.path(), Duration::ZERO)
            .unwrap()
            .expect("zero budget still tries an uncontended lock once");
        assert!(lock_wake(home.path(), Duration::ZERO).unwrap().is_none());
        drop(guard);
    }

    fn record_test_item(home: &Path, thread: &str, id: &str) {
        let item = Item {
            thread: thread.to_owned(),
            id: id.to_owned(),
            queue: None,
            handle: None,
            seen: true,
            session: None,
        };
        let bytes = serde_json::to_vec(&item).unwrap();
        crate::messaging::deferred::write_private_atomic(&home.join(ITEM_FILE), &bytes).unwrap();
    }

    /// Defense in depth: the watcher may only start the item the wake path
    /// recorded; a foreign queued submission is refused.
    #[test]
    fn child_start_refuses_a_foreign_queue_item() {
        let home = TempDir::new().unwrap();
        record_test_item(
            home.path(),
            "01a0f6f5-1ba8-7202-94c4-bb7233a1f783",
            "01a11624-fed4-71e1-b2a0-cbceaf8db0ff",
        );
        let recipient = crate::providers::codex::managed_backend::LauncherIdentity {
            pid: std::process::id(),
            started_exact: 1,
        };
        let error = start_queued_notice_native(
            home.path(),
            home.path(),
            &recipient,
            "01a0f6f5-1ba8-7202-94c4-bb7233a1f783",
            "01a11628-eeee-71e1-b2a0-cbceaf8db0ff",
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// No recorded sidecar means there is nothing the wake path may start.
    #[test]
    fn child_start_refuses_without_a_recorded_item() {
        let home = TempDir::new().unwrap();
        let recipient = crate::providers::codex::managed_backend::LauncherIdentity {
            pid: std::process::id(),
            started_exact: 1,
        };
        let error = start_queued_notice_native(
            home.path(),
            home.path(),
            &recipient,
            "01a0f6f5-1ba8-7202-94c4-bb7233a1f783",
            "01a11624-fed4-71e1-b2a0-cbceaf8db0ff",
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    // ── R2 fix-wave rows ─────────────────────────────────────────────────

    const R2_MAIN: &str = "01a0f6f5-1ba8-7202-94c4-bb7233a1f783";
    const R2_ITEM: &str = "01a11624-fed4-71e1-b2a0-cbceaf8db0ff";

    fn r2_payload(text: &str) -> String {
        serde_json::json!({"UserInput":{"content":[{"type":"text","text":text}]}}).to_string()
    }

    /// The codex-cli `queued_items` schema, created inside this module so the
    /// w2 tests do not depend on another test module's fixture helpers.
    fn r2_queue_db(dir: &Path) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(dir.join(QUEUE_DB)).unwrap();
        c.execute_batch(
            "CREATE TABLE queued_items (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, \
             payload_json TEXT NOT NULL, queue_order INTEGER NOT NULL, \
             created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);",
        )
        .unwrap();
        c
    }

    fn r2_add_row(c: &rusqlite::Connection, id: &str, thread: &str, payload: &str) {
        c.execute(
            "INSERT INTO queued_items VALUES (?1, ?2, ?3, 1, 0, 0)",
            rusqlite::params![id, thread, payload],
        )
        .unwrap();
    }

    /// Lay down a real queue DB row and the REAL recorded sidecar for it.
    fn r2_fixture(root: &Path, text: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let sqlite = root.join("state");
        std::fs::create_dir_all(&sqlite).unwrap();
        let c = r2_queue_db(&sqlite);
        r2_add_row(&c, R2_ITEM, R2_MAIN, &r2_payload(text));
        let db = sqlite.join(QUEUE_DB);
        let reader = QueueRead::open(&db, Instant::now() + Duration::from_secs(2)).unwrap();
        record_item(
            &home,
            R2_MAIN,
            R2_ITEM,
            &QueueEvidence {
                session: Some(TEST_SESSION),
                id: Some(R2_ITEM.to_owned()),
                seen: true,
                reader: Some(reader),
                ..QueueEvidence::default()
            },
        )
        .unwrap();
        (home, sqlite)
    }

    #[test]
    fn fixwave_r2_gate_accepts_a_real_recorded_notice() {
        let d = TempDir::new().unwrap();
        let (home, sqlite) = r2_fixture(d.path(), &notice(1));
        let reader = validate_start_item(
            &home,
            &sqlite,
            R2_MAIN,
            R2_ITEM,
            Some(TEST_SESSION),
            Instant::now() + Duration::from_secs(2),
        )
        .expect("a real recorded notice is startable");
        assert!(reader.identity_valid());
    }

    /// A row whose text is a user prompt is NOT startable. This is the row
    /// that reds when the gate stops calling `text_is_csq_notice`.
    #[test]
    fn fixwave_r2_gate_refuses_a_non_notice_row() {
        let d = TempDir::new().unwrap();
        let (home, sqlite) = r2_fixture(d.path(), "please refactor the parser");
        let error = match validate_start_item(
            &home,
            &sqlite,
            R2_MAIN,
            R2_ITEM,
            Some(TEST_SESSION),
            Instant::now() + Duration::from_secs(2),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a non-notice row must be refused"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// A sidecar recorded for another session incarnation is refused.
    #[test]
    fn fixwave_r2_gate_refuses_a_foreign_session() {
        let d = TempDir::new().unwrap();
        let (home, sqlite) = r2_fixture(d.path(), &notice(1));
        let other = SessionIdentity {
            pid: TEST_SESSION.pid + 1,
            exact_start: TEST_SESSION.exact_start,
        };
        let error = match validate_start_item(
            &home,
            &sqlite,
            R2_MAIN,
            R2_ITEM,
            Some(other),
            Instant::now() + Duration::from_secs(2),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a foreign session must be refused"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    fn r2_send(
        socket: &mut tungstenite::WebSocket<std::os::unix::net::UnixStream>,
        value: serde_json::Value,
    ) {
        socket
            .send(tungstenite::Message::Text(value.to_string().into()))
            .unwrap();
    }

    fn r2_receive(
        socket: &mut tungstenite::WebSocket<std::os::unix::net::UnixStream>,
    ) -> serde_json::Value {
        loop {
            match socket.read() {
                Ok(tungstenite::Message::Text(text)) => {
                    return serde_json::from_str(&text).unwrap()
                }
                Ok(_) => continue,
                Err(error) => panic!("native fixture read failed: {error}"),
            }
        }
    }

    /// Accept one connection and complete the `initialize` handshake.
    #[cfg(unix)]
    fn r2_initialized(
        listener: &std::os::unix::net::UnixListener,
        home: &Path,
    ) -> tungstenite::WebSocket<std::os::unix::net::UnixStream> {
        let stream = listener.accept().unwrap().0;
        // BSD/macOS accept() inherits O_NONBLOCK from the listener; the
        // handshake below is blocking.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut socket = tungstenite::accept(stream).unwrap();
        let request = r2_receive(&mut socket);
        assert_eq!(request["method"], "initialize");
        r2_send(
            &mut socket,
            serde_json::json!({"id":request["id"],"result":{"codexHome":home}}),
        );
        let _ = r2_receive(&mut socket); // the "initialized" notification
        socket
    }

    /// The live-send path (start_managed_pending) exists to start a notice
    /// whose automatic dispatch was skipped because the turn was Interrupted.
    /// Its admission must NOT require an idle main: the server here reports
    /// `interrupted` and the start must still reach thread/queue/start.
    #[test]
    fn fixwave_r2_live_path_starts_an_interrupted_main() {
        use crate::providers::codex::managed_backend::{LauncherIdentity, ManagedBackendPlan};
        let d = short_root("csq-r2-").unwrap();
        let home = d.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let state = d.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let plan = ManagedBackendPlan::prepare(&home, &state).unwrap();
        let plan_home = std::fs::canonicalize(&home).unwrap();
        let plan_state = plan.sqlite_home().to_path_buf();
        let socket_path = std::path::PathBuf::from(
            plan.endpoint_url()
                .strip_prefix("unix://")
                .unwrap()
                .to_owned(),
        );
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let recipient = LauncherIdentity::capture(std::process::id()).unwrap();
        let session = SessionIdentity {
            pid: recipient.pid,
            exact_start: recipient.started_exact,
        };
        let server_home = plan_home.clone();
        let server_state = plan_state.clone();
        let server = std::thread::spawn(move || {
            // Connection 1: the binding publication handshake.
            let _publish = r2_initialized(&listener, &server_home);
            // Connection 2: the start.
            let mut socket = r2_initialized(&listener, &server_home);
            socket
                .get_ref()
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = r2_receive(&mut socket);
            let request = if request["method"] == "thread/read" {
                // An idle-admission client re-reads the target first; answer
                // truthfully: this main is interrupted, not idle.
                r2_send(
                    &mut socket,
                    serde_json::json!({"id":request["id"],"result":{"thread":
                        {"id":R2_MAIN,
                         "source":"cli","status":{"type":"interrupted"},
                         "canAcceptDirectInput":false}}}),
                );
                r2_receive(&mut socket)
            } else {
                request
            };
            if request["method"] == "thread/queue/start" {
                r2_send(
                    &mut socket,
                    serde_json::json!({"id":request["id"],"result":
                        {"turn":{"id":"01a11627-dddd-71e1-b2a0-cbceaf8db0ff"}}}),
                );
                // Consume the row so the drain observes it taken.
                if let Ok(c) = rusqlite::Connection::open(server_state.join(QUEUE_DB)) {
                    let _ = c.execute(
                        "DELETE FROM queued_items WHERE id = ?1",
                        rusqlite::params![R2_ITEM],
                    );
                }
            }
        });
        // The row and the REAL sidecar.
        let c = r2_queue_db(&plan_state);
        r2_add_row(&c, R2_ITEM, R2_MAIN, &r2_payload(&notice(1)));
        drop(c);
        let db = plan_state.join(QUEUE_DB);
        let reader = QueueRead::open(&db, Instant::now() + Duration::from_secs(2)).unwrap();
        record_item(
            &plan_home,
            R2_MAIN,
            R2_ITEM,
            &QueueEvidence {
                session: Some(session),
                id: Some(R2_ITEM.to_owned()),
                seen: true,
                reader: Some(reader),
                ..QueueEvidence::default()
            },
        )
        .unwrap();
        let mut binding = plan
            .publish_binding(
                &LauncherIdentity::capture(std::process::id()).unwrap(),
                Duration::from_secs(3),
            )
            .unwrap();
        binding.publish_recipient(&recipient).unwrap();
        let spec = WakeSpec {
            codex_home: plan_home.clone(),
            sqlite_home: plan_state.clone(),
            session: Some(session),
        };
        let delivery = start_managed_pending(
            &spec,
            R2_MAIN,
            R2_ITEM,
            Delivery::CodexQueuedUnverified,
            Instant::now() + Duration::from_secs(5),
            &|| true,
        );
        let _ = server.join();
        assert_eq!(
            delivery,
            Delivery::CodexWoken,
            "the interrupted-turn live path must start the notice"
        );
    }

    /// F8: the gate's text check re-derives the wording from `notice`, while
    /// the native writer queues `frame::notice_pointer`. They must stay
    /// byte-identical; editing one alone must red here.
    #[test]
    fn fixwave_r2_notice_pointer_matches_the_wake_notice_bytes() {
        for n in [1usize, 2, 12, 999] {
            let summary = crate::messaging::store::PendingNotice::count_only(n);
            assert!(
                text_is_csq_notice(&crate::messaging::frame::render_preview_notice(&summary)),
                "the queued notice text must satisfy the gate's check for n={n}"
            );
        }
    }

    /// F3: the gate's ACCEPT path, end to end through the child-completion
    /// start, with a real sidecar + queue row: the call must return the turn
    /// the server reports. Without this, a broken session derivation would
    /// silently kill every watcher start with the suite green.
    #[test]
    fn fixwave_r2_child_start_returns_ok_on_a_real_notice() {
        use crate::providers::codex::managed_backend::{LauncherIdentity, ManagedBackendPlan};
        let d = short_root("csq-r2-").unwrap();
        let home = d.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let state = d.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let plan = ManagedBackendPlan::prepare(&home, &state).unwrap();
        let plan_home = std::fs::canonicalize(&home).unwrap();
        let plan_state = plan.sqlite_home().to_path_buf();
        let socket_path = std::path::PathBuf::from(
            plan.endpoint_url()
                .strip_prefix("unix://")
                .unwrap()
                .to_owned(),
        );
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let recipient = LauncherIdentity::capture(std::process::id()).unwrap();
        let session = SessionIdentity {
            pid: recipient.pid,
            exact_start: recipient.started_exact,
        };
        let server_home = plan_home.clone();
        let server_state = plan_state.clone();
        let server = std::thread::spawn(move || {
            let _publish = r2_initialized(&listener, &server_home);
            let mut socket = r2_initialized(&listener, &server_home);
            let read = r2_receive(&mut socket);
            assert_eq!(read["method"], "thread/read");
            r2_send(
                &mut socket,
                serde_json::json!({"id":read["id"],"result":{"thread":
                    {"id":R2_MAIN,"source":"cli","status":{"type":"idle"},
                     "canAcceptDirectInput":true}}}),
            );
            let start = r2_receive(&mut socket);
            assert_eq!(start["method"], "thread/queue/start");
            r2_send(
                &mut socket,
                serde_json::json!({"id":start["id"],"result":
                    {"turn":{"id":"01a11627-dddd-71e1-b2a0-cbceaf8db0ff"}}}),
            );
            if let Ok(c) = rusqlite::Connection::open(server_state.join(QUEUE_DB)) {
                let _ = c.execute(
                    "DELETE FROM queued_items WHERE id = ?1",
                    rusqlite::params![R2_ITEM],
                );
            }
        });
        let c = r2_queue_db(&plan_state);
        r2_add_row(&c, R2_ITEM, R2_MAIN, &r2_payload(&notice(1)));
        drop(c);
        let db = plan_state.join(QUEUE_DB);
        let reader = QueueRead::open(&db, Instant::now() + Duration::from_secs(2)).unwrap();
        record_item(
            &plan_home,
            R2_MAIN,
            R2_ITEM,
            &QueueEvidence {
                session: Some(session),
                id: Some(R2_ITEM.to_owned()),
                seen: true,
                reader: Some(reader),
                ..QueueEvidence::default()
            },
        )
        .unwrap();
        let mut binding = plan
            .publish_binding(
                &LauncherIdentity::capture(std::process::id()).unwrap(),
                Duration::from_secs(3),
            )
            .unwrap();
        binding.publish_recipient(&recipient).unwrap();
        let turn = start_queued_notice_native(
            &plan_home,
            &plan_state,
            &recipient,
            R2_MAIN,
            R2_ITEM,
            Duration::from_secs(5),
        );
        let _ = server.join();
        assert_eq!(
            turn.expect("the gate must accept its own real notice"),
            "01a11627-dddd-71e1-b2a0-cbceaf8db0ff"
        );
    }

    /// A legacy or stale sidecar (no session/handle/queue identity) is
    /// refused BEFORE any socket work, even when its id and thread match the
    /// request exactly.
    #[test]
    fn fixwave_child_start_refuses_a_legacy_sidecar() {
        let home = TempDir::new().unwrap();
        record_test_item(
            home.path(),
            "01a0f6f5-1ba8-7202-94c4-bb7233a1f783",
            "01a11624-fed4-71e1-b2a0-cbceaf8db0ff",
        );
        let recipient = crate::providers::codex::managed_backend::LauncherIdentity {
            pid: std::process::id(),
            started_exact: 1,
        };
        let error = start_queued_notice_native(
            home.path(),
            home.path(),
            &recipient,
            "01a0f6f5-1ba8-7202-94c4-bb7233a1f783",
            "01a11624-fed4-71e1-b2a0-cbceaf8db0ff",
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// The start gate accepts only a row whose text is the csq notice.
    #[test]
    fn fixwave_only_the_notice_text_is_startable() {
        for n in [1usize, 12, 999] {
            assert!(text_is_csq_notice_for_test(&notice(n)));
            assert!(text_is_csq_notice_for_test(&format!(
                "{}\n[peer msg 1 from csq-cx] body",
                notice(n)
            )));
        }
        for text in [
            "",
            "user prompt",
            "csq: one peer message(s) waiting",
            &notice(1).replace("csq: 1", "csq: 1 "),
            &format!("{}x", notice(1)),
        ] {
            assert!(!text_is_csq_notice_for_test(text), "refused: {text:?}");
        }
    }

    /// The child-completion watcher must take the SAME wake lock as a live
    /// send: a held lock refuses the start with `WouldBlock` before any
    /// socket work, so a child completion cannot race an in-flight wake.
    #[test]
    fn child_start_takes_the_wake_lock() {
        let home = TempDir::new().unwrap();
        let holder = lock_wake(home.path(), Duration::ZERO)
            .unwrap()
            .expect("uncontended wake lock");
        let recipient = crate::providers::codex::managed_backend::LauncherIdentity {
            pid: std::process::id(),
            started_exact: 1,
        };
        let error = start_queued_notice_native(
            home.path(),
            home.path(),
            &recipient,
            "01a0f6f5-1ba8-7202-94c4-bb7233a1f783",
            "01a11624-fed4-71e1-b2a0-cbceaf8db0ff",
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        drop(holder);
    }

    /// G2b item 2 — same class as the login lock: a forked child inherits
    /// the wake-lock descriptor, so close-alone is not the release point.
    /// Dropping the guard MUST release explicitly (LOCK_UN).
    #[cfg(unix)]
    #[test]
    fn fork_child_does_not_hold_the_wake_lock_past_drop() {
        let home = TempDir::new().unwrap();
        let guard = lock_wake(home.path(), Duration::ZERO)
            .unwrap()
            .expect("uncontended wake lock");
        let child = crate::fork_harness::ForkedChild::spawn();
        drop(guard);
        assert!(
            lock_wake(home.path(), Duration::ZERO).unwrap().is_some(),
            "an inherited duplicate kept the wake lock alive past the guard's drop — \
             Drop must LOCK_UN, not rely on close"
        );
        drop(child);
    }

    /// A lock that cannot be opened or flocked proves no holder exists, so nothing will post for
    /// this message: the outcome is a failure, never a benign contended label.
    /// Falsifier: mapping `lock_wake`'s `Err` to a contended/deferred outcome returns that
    /// outcome here instead of `ClaudeWakeFailed`.
    #[test]
    fn unopenable_wake_lock_fails_closed_not_contended() {
        use std::os::unix::fs::PermissionsExt;
        let w = World::new();
        let _l = w.listen();
        w.send(NOW);
        let lock = w.home.path().join(LOCK_FILE);
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o400)).unwrap();
        // Precondition, so the test cannot pass vacuously where the mode is not enforced
        // (e.g. a privileged runner): the lock really cannot be opened for writing.
        assert!(
            lock_wake(w.home.path(), Duration::ZERO).is_err(),
            "fixture: a 0400 lock file must refuse the read-write open"
        );
        assert_eq!(w.wake(NOW), Delivery::ClaudeWakeFailed);
    }

    /// The holder's final store read that returns no evidence cannot show that every message
    /// stored while the lock was held is behind the first post, so it is treated as unseen and
    /// the holder posts once more (inside the rate cap).
    /// Falsifier: treating an unknown re-check as "nothing new" leaves one post, not two.
    #[test]
    fn unknown_holder_recheck_is_treated_as_unseen() {
        let w = World::new();
        let l = w.listen();
        let id = w.send(NOW);
        let reads = std::cell::Cell::new(0_u32);
        let d = w.wake_with(NOW, &|| {
            reads.set(reads.get() + 1);
            (reads.get() == 1).then(|| vec![id.clone()])
        });
        assert_eq!(d, Delivery::ClaudeWoken);
        assert_eq!(reads.get(), 2, "the holder read the store once more");
        assert_eq!(
            posts(&l).len(),
            2,
            "an unknown final read is unseen, so the holder posts again"
        );
    }

    /// Ids that fail `valid_claude_ids` on BOTH reads are unknown evidence on both, so the first
    /// post was already made without evidence and the holder does not post a second time.
    /// Falsifier: comparing the filtered final read against the UNFILTERED first read
    /// (`observed_ids.is_some()`) counts the invalid first read as known and posts twice.
    #[test]
    fn invalid_ids_on_both_holder_reads_do_not_post_twice() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW);
        let reads = std::cell::Cell::new(0_u32);
        let d = w.wake_with(NOW, &|| {
            reads.set(reads.get() + 1);
            Some(vec!["not-a-canonical-uuid".to_string()])
        });
        assert!(
            !valid_claude_ids(&["not-a-canonical-uuid".to_string()]),
            "fixture: the ids must fail the validity filter"
        );
        assert_eq!(d, Delivery::ClaudeWoken);
        assert_eq!(reads.get(), 2, "the holder read the store once more");
        assert_eq!(
            posts(&l).len(),
            1,
            "unknown evidence on both reads adds no second post"
        );
    }

    /// An authoritative EMPTY final read shows nothing is unread, exactly as an authoritative
    /// empty first read does (`QueuedOnly`, no reservation): the holder neither reserves nor posts
    /// a second time.
    /// Falsifier: letting `valid_claude_ids` turn `Some(vec![])` into unknown evidence makes the
    /// holder treat it as unseen, reserve a second slot and post twice.
    #[test]
    fn authoritative_empty_holder_recheck_does_not_post_twice() {
        let w = World::new();
        let l = w.listen();
        let id = w.send(NOW);
        let reads = std::cell::Cell::new(0_u32);
        let d = w.wake_with(NOW, &|| {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                Some(vec![id.clone()])
            } else {
                Some(Vec::new())
            }
        });
        assert!(
            valid_claude_ids(std::slice::from_ref(&id)),
            "fixture: the first read must be valid evidence"
        );
        assert_eq!(d, Delivery::ClaudeWoken);
        assert_eq!(reads.get(), 2, "the holder read the store once more");
        assert_eq!(
            posts(&l).len(),
            1,
            "an authoritative empty final read adds no second post"
        );
        assert_eq!(
            read_claude_notice(&w.state()).unwrap().reservations.len(),
            1,
            "an authoritative empty final read consumes no second reservation"
        );
    }

    /// Fixed-vocabulary capture of every tracing event's fields, for the reserve-failed test.
    struct WakeEventText(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    struct WakeFieldText(String);

    impl tracing::field::Visit for WakeFieldText {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={:?} ", f.name(), v);
        }
    }

    impl tracing::Subscriber for WakeEventText {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            let mut v = WakeFieldText(String::new());
            e.record(&mut v);
            self.0.lock().unwrap().push(v.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn capture_wake_events<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
        let _g = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let out = tracing::subscriber::with_default(WakeEventText(events.clone()), run);
        let got = events.lock().unwrap().clone();
        (out, got)
    }

    /// When the holder's final read shows an unseen id but the second reservation cannot be
    /// persisted, the second post is skipped (a post without a durable reservation could escape
    /// the rate cap) and the skip is logged under its fixed tag.
    /// Falsifier: removing the `claude_wake_recheck_reserve_failed` warn leaves no such event;
    /// posting without the reservation shows a second post.
    #[test]
    fn holder_recheck_reserve_failure_skips_the_second_post_and_logs() {
        let w = World::new();
        let l = w.listen();
        let first = w.send(NOW);
        let second = w.send(NOW);
        let state = w.state();
        let reads = std::cell::Cell::new(0_u32);
        let (d, events) = capture_wake_events(|| {
            w.wake_with(NOW, &|| {
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    return Some(vec![first.clone()]);
                }
                // The final read: make the state path unreplaceable (a non-empty directory) so
                // the second reservation's atomic rename fails, then report an unseen id.
                std::fs::remove_file(&state).unwrap();
                std::fs::create_dir(&state).unwrap();
                std::fs::write(state.join("occupant"), b"").unwrap();
                Some(vec![first.clone(), second.clone()])
            })
        });
        assert_eq!(d, Delivery::ClaudeWoken, "the first post stands");
        assert_eq!(reads.get(), 2, "the holder read the store once more");
        assert!(
            state.is_dir(),
            "fixture: the state path stayed unreplaceable"
        );
        assert_eq!(posts(&l).len(), 1, "no post without a durable reservation");
        assert!(
            events
                .iter()
                .any(|e| e.contains("reason=\"claude_wake_recheck_reserve_failed\"")),
            "the skipped second post is logged under its fixed tag: {events:?}"
        );
    }

    #[test]
    fn lock_contention_and_late_store_evidence_do_not_claim_pending() {
        let w = World::new();
        let l = w.listen();
        w.send(NOW);
        assert_eq!(w.wake(NOW), Delivery::ClaudeWoken);
        // Establish the held-lock fixture with a bounded wait, then verify contention.
        // A zero-budget setup may lose to a transient inherited descriptor in parallel
        // subprocess tests; the production call below still has its original 5ms budget.
        let guard = lock_wake(w.home.path(), Duration::from_secs(2))
            .unwrap()
            .expect("fixture wake lock acquired within two seconds");
        assert!(lock_wake(w.home.path(), Duration::ZERO).unwrap().is_none());
        assert_eq!(
            deliver_claude_coalesced(
                &w.target,
                &[w.home.path().to_path_buf()],
                &|| true,
                1,
                Duration::from_millis(5),
                NOW + 1,
                &|| store::pending_ids(w.base.path(), NOW + 1, &w.to).ok()
            ),
            // The lock is held, so this attempt posts nothing and claims no coverage.
            Delivery::ClaudeWakeContended
        );
        // The guard now releases explicitly on drop (G2b item 2); this test's own
        // LOCK_UN has retired with it. The shared open-file description is still
        // what a raw-fork test can inherit, so the class is fixed in WakeLock.
        drop(guard);
        // The read is late by construction, not by load: `thread::sleep` never returns early, so
        // the injected 600ms always exceeds this 500ms budget, while the post this call still owes
        // the recipient gets a budget no scheduler stall of a few milliseconds can spend. A 20ms
        // read against a 5ms budget made a green row depend on host load.
        let late_budget = Duration::from_millis(500);
        let store_reads = std::cell::Cell::new(0u32);
        assert_eq!(
            deliver_claude_coalesced(
                &w.target,
                &[w.home.path().to_path_buf()],
                &|| true,
                1,
                late_budget,
                NOW + 1,
                &|| {
                    let reads = store_reads.get();
                    store_reads.set(reads + 1);
                    if reads == 0 {
                        std::thread::sleep(Duration::from_millis(600));
                    }
                    store::pending_ids(w.base.path(), NOW + 1, &w.to).ok()
                }
            ),
            // Evidence that arrived after the budget cannot claim coverage: the state below
            // would have made this a `ClaudeWakePending` (no post) if the late read counted.
            // It no longer refuses the delivery either -- the post owns its own budget, so the
            // notice lands and the listener sees a second post.
            Delivery::ClaudeWoken
        );
        assert!(
            store_reads.get() >= 2,
            "the late evidence read ran, and the holder read the store again before releasing \
             the lock: {}",
            store_reads.get()
        );
        assert_eq!(posts(&l).len(), 2);
        // A late read grants no cohort, so the success record can suppress no later wake.
        let state = read_claude_notice(&w.state()).unwrap();
        assert!(
            state.pending_ids.is_empty(),
            "late evidence grants no unread cohort: {:?}",
            state.pending_ids
        );
        assert_eq!(state.successful_posts, vec![NOW, NOW + 1]);
    }

    #[test]
    fn shared_config_directory_cannot_coalesce_another_recipient() {
        let w = World::new();
        let l = w.listen();
        let id = w.send(NOW);
        assert_eq!(w.wake(NOW), Delivery::ClaudeWoken);
        let mut other = w.target.clone();
        other.pid += 1;
        let mine = std::fs::read(w.state()).unwrap();
        let other_state = claude_notice_path(w.home.path(), other.pid);
        std::fs::write(&other_state, &mine).unwrap();
        std::fs::set_permissions(&other_state, std::fs::Permissions::from_mode(0o600)).unwrap();
        let reader = std::thread::spawn(move || {
            let (mut s, _) = loop {
                match l.accept() {
                    Ok(v) => break v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            let mut got = String::new();
            s.read_to_string(&mut got).unwrap();
            got
        });
        // The only queued connection is the first successful post. The second attempt
        // must pass the endpoint PID gate and fail, never borrow the first notice.
        assert_eq!(
            deliver_claude_coalesced(
                &other,
                &[w.home.path().to_path_buf()],
                &|| true,
                1,
                CLAUDE_SOCKET_TIMEOUT,
                NOW + 1,
                &|| Some(vec![id.clone()])
            ),
            Delivery::ClaudeWakeFailed
        );
        assert_eq!(reader.join().unwrap(), claude_line(1));
        assert_eq!(std::fs::read(w.state()).unwrap(), mine);
    }
}
