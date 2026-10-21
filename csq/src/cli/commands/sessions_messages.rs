//! `csq sessions send | ack-message | inbox --messages [--hook]` — cross-CLI session
//! messaging (spec 32 §4.1, §5.2).
//!
//! The store, limits, framing and lifecycle live in `csq_core::messaging`; this module is
//! the envelope-emitting CLI surface. `send`, `ack-message` and `inbox --messages` each emit
//! ONE spec 30 envelope line (`csq.message_receipt.v1` / `csq.message_inbox.v1`), exit 0 iff
//! `ok`. The sender is ALWAYS the session `resolve_caller_from_env` proves (INV-32-01):
//! no argument, environment variable or message text can name it, and the store only takes
//! the resulting `VerifiedSession`. Bodies leave this module only as the frame's
//! `framed_body` (INV-32-05).
//!
//! `inbox --messages --hook <event>` is the one command here whose stdout is raw Claude Code
//! hook JSON rather than an envelope (spec 32 §5.2).

use std::io::Read;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

use anyhow::Result;
use csq_core::messaging::hook::{self, HookEvent};
use csq_core::messaging::limits::{Limits, Liveness};
use csq_core::messaging::model::{MessageView, Receipt, Recipient, Surface, VerifiedSession};
use csq_core::messaging::registry::{self, Candidate};
use csq_core::messaging::request::{self, Intent, Lookup};
use csq_core::messaging::store::{self, Mark};
use csq_core::messaging::wake::{self, Delivery};
use csq_core::sdk::messages::{MessageInboxEntry, MessageInboxPayload, MessageReceipt, MessageRow};
use csq_core::sdk::{
    self, Envelope, SdkError, SdkErrorCode, SCHEMA_MESSAGE_INBOX_V1, SCHEMA_MESSAGE_RECEIPT_V1,
};
use csq_core::sessions::directives::{real_fs, DirectiveError, FsOps, UndeterminedCause as Cause};
use csq_core::sessions::{same_start, CallerError, CliKind, PidLookup};
use serde::Serialize;

/// Upper bound on a message read from stdin (`--message -`): 256 KiB, far above the
/// 4 000-character body cap, so the store's own check is what refuses an oversize body.
const MAX_STDIN_BYTES: u64 = 256 * 1024;

fn err(code: SdkErrorCode, message: &str) -> DirectiveError {
    DirectiveError {
        code,
        message: message.to_string(),
        cause: None,
        attempts: None,
        next_allowed_at: None,
    }
}

/// Build the envelope for one operation result.
fn build<T: Serialize>(
    schema: &'static str,
    result: Result<T, DirectiveError>,
) -> Envelope<serde_json::Value> {
    match result {
        Ok(payload) => match serde_json::to_value(payload) {
            Ok(v) => Envelope::success(schema, None, v),
            Err(_) => Envelope::failure(
                schema,
                None,
                SdkError::trusted(SdkErrorCode::Undetermined, "result could not be serialized"),
            ),
        },
        Err(e) => Envelope::failure(schema, None, SdkError::trusted(e.code, e.message)),
    }
}

fn finish<T: Serialize>(schema: &'static str, result: Result<T, DirectiveError>) -> Result<()> {
    let code = sdk::emit(&build(schema, result))?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

// ── argument-error routing ──────────────────────────────────────────

/// What `main` does with an argument error on `csq sessions …`.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseErrorAction {
    /// Not a messaging command: let the directive surface (or clap) decide.
    NotMine,
    /// Emit this schema's `invalid_input` envelope, exit 1.
    Envelope(&'static str),
    /// A surfacing hook: print nothing and exit 0, because a hook must never break a turn.
    HookSilent,
}

/// Classify the argv of a failed parse. A literal `--` ends the options, so nothing after
/// it names a verb or a flag (a misattributed schema would lie about which command failed).
#[must_use]
pub fn parse_error_action(args: &[String]) -> ParseErrorAction {
    let head: Vec<&str> = args
        .iter()
        .skip(1)
        .map(String::as_str)
        .take_while(|a| *a != "--")
        .collect();
    let mut positional = head.iter().filter(|a| !a.starts_with('-'));
    if positional.next().copied() != Some("sessions") {
        return ParseErrorAction::NotMine;
    }
    match positional.next().copied() {
        Some("send" | "ack-message" | "lookup-message") => {
            ParseErrorAction::Envelope(SCHEMA_MESSAGE_RECEIPT_V1)
        }
        // Any `inbox` argv naming `--hook` is a hook invocation, with or without `--messages`:
        // a failure envelope on stdout would break the Claude Code turn that ran it.
        Some("inbox")
            if head
                .iter()
                .any(|a| *a == "--hook" || a.starts_with("--hook=")) =>
        {
            ParseErrorAction::HookSilent
        }
        Some("inbox") if head.contains(&"--messages") => {
            ParseErrorAction::Envelope(SCHEMA_MESSAGE_INBOX_V1)
        }
        _ => ParseErrorAction::NotMine,
    }
}

// ── identity, targets, liveness ─────────────────────────────────────

pub(crate) fn caller_error(e: CallerError) -> DirectiveError {
    match e {
        CallerError::Undetermined(m) => {
            err(SdkErrorCode::Undetermined, &m).with_cause(Cause::SenderIdentity)
        }
        CallerError::TargetMismatch => err(
            SdkErrorCode::TargetMismatch,
            "caller is not running inside that session",
        ),
    }
}

/// The calling session: the §2.2 resolver against the real process table, then its
/// messaging identity. This is the ONLY way this module obtains a `VerifiedSession`.
pub(crate) fn resolve_verified() -> Result<VerifiedSession, DirectiveError> {
    csq_core::sessions::resolve_caller_from_env()
        .map_err(caller_error)?
        .verified()
        .map_err(caller_error)
}

pub(crate) fn now_secs() -> Result<u64, DirectiveError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| {
            err(
                SdkErrorCode::Undetermined,
                "system clock is before the unix epoch",
            )
            .with_cause(Cause::Clock)
        })
}

pub(crate) fn kind_of(s: Surface) -> CliKind {
    match s {
        Surface::ClaudeCode => CliKind::Claude,
        Surface::Codex => CliKind::Codex,
    }
}

pub(crate) fn surface_of(k: CliKind) -> Surface {
    match k {
        CliKind::Claude => Surface::ClaudeCode,
        CliKind::Codex => Surface::Codex,
    }
}

/// `<pid>:<started_at>`, both decimal.
pub(crate) fn parse_target(t: &str) -> Result<(u32, u64), DirectiveError> {
    let bad = || {
        err(
            SdkErrorCode::InvalidInput,
            "target must be <pid>:<started_at>",
        )
    };
    let (p, s) = t.split_once(':').ok_or_else(bad)?;
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
    if !digits(p) || !digits(s) {
        return Err(bad());
    }
    Ok((p.parse().map_err(|_| bad())?, s.parse().map_err(|_| bad())?))
}

/// The live session named by `(pid, started_at)`: the surface is not part of a target id,
/// so both CLIs are asked about that one pid. Exactly one match is the recipient; a pid
/// that no CLI owns at that start is `target_mismatch`; a lookup that could not be made is
/// `undetermined` and never read as "no such session".
pub(crate) fn resolve_target(
    pid: u32,
    started_at: u64,
    lookup: &dyn Fn(CliKind, u32) -> PidLookup,
) -> Result<Recipient, DirectiveError> {
    let mut found = Vec::new();
    let mut unknown = false;
    for kind in [CliKind::Claude, CliKind::Codex] {
        match lookup(kind, pid) {
            Ok(Some(info)) => match info.started_at {
                Some(s) if same_start(s, started_at) => found.push(kind),
                Some(_) => {}
                None => unknown = true,
            },
            Ok(None) => {}
            Err(_) => unknown = true,
        }
    }
    // One kind that matches positively at the same start is decisive: a lookup that failed for
    // the OTHER kind (always on Windows for Codex, transiently elsewhere) cannot make that
    // positive match wrong, only a second positive match can (ambiguity).
    match (found.as_slice(), unknown) {
        ([kind], _) => Ok(Recipient {
            pid,
            started_at,
            surface: surface_of(*kind),
            started_exact: None,
        }),
        ([], false) => Err(err(
            SdkErrorCode::TargetMismatch,
            "no live session with that pid and start time",
        )),
        _ => Err(err(
            SdkErrorCode::Undetermined,
            "the target session could not be identified",
        )),
    }
}

/// [`resolve_target`] plus the recipient's full-precision start, so the wake can bind to the
/// exact incarnation (spec 32 section 5.1). `exact_of(kind, pid, started_at)` is consulted only
/// for either surface; `None` from it leaves the
/// recipient without an exact start, which means no wake, never a failed send.
pub(crate) fn resolve_target_exact(
    pid: u32,
    started_at: u64,
    lookup: &dyn Fn(CliKind, u32) -> PidLookup,
    exact_of: &dyn Fn(CliKind, u32, u64) -> Option<u64>,
) -> Result<Recipient, DirectiveError> {
    let mut r = resolve_target(pid, started_at, lookup)?;
    r.started_exact = exact_of(kind_of(r.surface), pid, started_at);
    Ok(r)
}

/// The real exact-start reader: the bracketed pair from `session_info_exact_for_pid_kind`,
/// kept only when its listed start still names `started_at`.
pub(crate) fn real_exact_of(kind: CliKind, pid: u32, started_at: u64) -> Option<u64> {
    match csq_core::sessions::session_info_exact_for_pid_kind(kind, pid) {
        Ok(Some((i, e))) if i.started_at.is_some_and(|s| same_start(s, started_at)) => Some(e),
        _ => None,
    }
}

/// Whether recipient `r` still exists, read for its own pid only. A lookup that could not
/// be made, or a session whose start time is unreadable, is `Unknown`, never `Ended`.
pub(crate) fn real_liveness(r: &Recipient) -> Liveness {
    liveness_from(r, &csq_core::sessions::session_info_for_pid_kind)
}

fn liveness_from(r: &Recipient, lookup: &dyn Fn(CliKind, u32) -> PidLookup) -> Liveness {
    match lookup(kind_of(r.surface), r.pid) {
        Ok(Some(info)) => match info.started_at {
            Some(s) if same_start(s, r.started_at) => Liveness::Live,
            Some(_) => Liveness::Ended,
            None => Liveness::Unknown,
        },
        Ok(None) => Liveness::Ended,
        Err(_) => Liveness::Unknown,
    }
}

// ── wire conversion ─────────────────────────────────────────────────

fn status_str(s: csq_core::messaging::Status) -> String {
    s.as_str().to_string()
}

fn receipt_dto(r: &Receipt) -> MessageReceipt {
    MessageReceipt::new(&r.id, &r.thread, status_str(r.status), r.created_at)
        .with_surfaced_at(r.surfaced_at)
        .with_read_at(r.read_at)
        .with_acked_at(r.acked_at)
        .with_ack_note_framed(r.ack_note_framed.clone())
}

/// One inbox row. The body is `framed_body` only; the raw body is not reachable from a view.
fn entry_dto(v: &MessageView) -> MessageInboxEntry {
    let row = MessageRow::new(
        &v.id,
        &v.thread,
        v.from_surface.as_str(),
        v.from_pid,
        v.created_at,
        &v.framed_body,
    )
    .with_in_reply_to(v.in_reply_to.clone())
    .with_from_name(v.from_name.clone())
    .with_already_shown(v.already_shown);
    let receipt = MessageReceipt::new(&v.id, &v.thread, status_str(v.status), v.created_at)
        .with_surfaced_at(v.surfaced_at)
        .with_read_at(v.read_at)
        .with_acked_at(v.acked_at)
        .with_ack_note_framed(v.ack_note_framed.clone());
    MessageInboxEntry::new(row, receipt)
}

// ── send ────────────────────────────────────────────────────────────

/// What a `send` target names: a session by `(pid, started_at)`, or by registry name.
#[derive(Debug, PartialEq, Eq)]
enum SendTarget {
    Pair(u32, u64),
    Name(String),
}

/// `<pid>:<started_at>` or a name. A name has no `:` (its charset excludes it), so the two
/// forms cannot be confused; a target with a `:` is parsed strictly as a pair, and anything
/// else is checked as a name by the resolver (an invalid one is `invalid_input`).
fn parse_send_target(t: &str) -> Result<SendTarget, DirectiveError> {
    if t.contains(':') {
        let (p, s) = parse_target(t)?;
        Ok(SendTarget::Pair(p, s))
    } else {
        Ok(SendTarget::Name(t.to_string()))
    }
}

/// The live sessions with their registry names, and whether the listing was whole.
type NameListing = Result<(Vec<Candidate>, bool), DirectiveError>;

/// The real listing for name resolution: both CLIs, enriched with names, repo and branch.
pub(crate) fn real_candidates(base_dir: &Path) -> NameListing {
    let result = (|| {
        let home = csq_core::platform::home::home_dir()
            .ok_or_else(|| err(SdkErrorCode::Undetermined, "home directory unknown"))?;
        let listing =
            csq_core::sessions::list_rows_for_names(base_dir, &home).ok_or_else(|| {
                err(
                    SdkErrorCode::Undetermined,
                    "the process table could not be read",
                )
            })?;
        if listing.restricted {
            return Err(err(
                SdkErrorCode::Undetermined,
                "process information is restricted for this caller",
            ));
        }
        // A repo lookup that fell back is carried on its own candidate (`label_fallback`), so only
        // a default-shaped name for THAT session resolves `undetermined`; the listing stays
        // complete for every other name.
        let cands = registry::candidates_from_rows(&listing.rows);
        Ok((cands, listing.is_complete()))
    })();
    result.map_err(|e: DirectiveError| e.with_cause(Cause::RegistryRead))
}

fn read_stdin_bounded(mut input: impl Read) -> Result<String, DirectiveError> {
    let mut buf = Vec::new();
    input
        .by_ref()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|_| err(SdkErrorCode::Undetermined, "stdin could not be read"))?;
    if buf.len() as u64 > MAX_STDIN_BYTES {
        return Err(err(SdkErrorCode::InvalidInput, "message is too large"));
    }
    String::from_utf8(buf)
        .map_err(|_| err(SdkErrorCode::InvalidInput, "message is not valid UTF-8"))
}

// ── Codex wake (spec 32 §5.1) ───────────────────────────────────────

/// Whether a stored exact start binds to the listed one: only an equal PRESENT value does.
/// An absent stored start (`None`) never binds, so a record without the field is never woken.
fn exact_binds(stored: Option<u64>, listed: u64) -> bool {
    stored == Some(listed)
}

/// The Codex target's wake inputs, validated; `None` unless every check holds.
type WakeInputs = (
    csq_core::sessions::WakeTarget,
    csq_core::sessions::CodexLaunch,
);

/// The validated wake target of Codex session `r`, or `None`. Reads the target's own launch
/// for THAT incarnation only, then validates it; nothing here comes from the caller (not the
/// caller's `CODEX_HOME`, which names the SENDER's handle dir).
fn wake_target_for(base_dir: &Path, r: &Recipient) -> Option<WakeInputs> {
    wake_target_with(
        base_dir,
        r,
        &|pid| csq_core::sessions::session_info_exact_for_pid_kind(CliKind::Codex, pid),
        &csq_core::sessions::codex_launch_for_session,
    )
}

/// [`wake_target_for`] over injected process-table reads (`info_of`: the listed session of a
/// pid with its exact start; `launch_of`: its launch argv bound to that incarnation).
fn wake_target_with(
    base_dir: &Path,
    r: &Recipient,
    info_of: &dyn Fn(
        u32,
    ) -> Result<
        Option<(csq_core::sessions::SessionInfo, u64)>,
        csq_core::sessions::Undetermined,
    >,
    launch_of: &dyn Fn(u32, u64, u64) -> Option<csq_core::sessions::CodexLaunch>,
) -> Option<WakeInputs> {
    let (info, exact) = match info_of(r.pid) {
        // The stored exact start must equal the listed one: seconds alone cannot tell
        // two processes that reused this pid within one second. A record without an
        // exact start (written before the field, or unreadable at send) never matches.
        Ok(Some((i, e)))
            if i.started_at.is_some_and(|s| same_start(s, r.started_at))
                && exact_binds(r.started_exact, e) =>
        {
            (i, e)
        }
        _ => return None,
    };
    let launch = launch_of(r.pid, r.started_at, exact)?;
    let target = csq_core::sessions::wake_target_ok(base_dir, r.pid, &info.config_dir, &launch)?;
    Some((target, launch))
}

/// Wake `r` by the mechanism of its surface: `codex` for a Codex recipient (§5.1), `claude` for
/// a Claude Code one (§5.2). The one place the surface decides, shared by the real wake and the
/// matrix fixture so a swapped arm fails both.
fn dispatch(
    r: &Recipient,
    codex: &dyn Fn(&Recipient) -> Delivery,
    claude: &dyn Fn(&Recipient) -> Delivery,
) -> Delivery {
    match r.surface {
        Surface::Codex => codex(r),
        Surface::ClaudeCode => claude(r),
    }
}

/// Wake the Claude Code session `r` through its own inbox socket (spec 32a §5.2): `queued_only`
/// unless its registry record names a socket bound to the same process.
fn real_claude_wake(base_dir: &Path, r: &Recipient) -> Delivery {
    // Claude Code's inbox socket is a Unix socket: nothing is looked up on other platforms.
    #[cfg(not(unix))]
    {
        let _ = (base_dir, r);
        Delivery::QueuedOnly
    }
    #[cfg(unix)]
    {
        let Ok(now) = now_secs() else {
            return Delivery::QueuedOnly;
        };
        let notice = store::pending_notice(base_dir, now, r)
            .unwrap_or_else(|_| store::PendingNotice::count_only(1));
        if notice.count == 0 {
            return Delivery::QueuedOnly;
        }
        claude_wake_via_pending(
            r,
            &|pid| csq_core::sessions::session_info_exact_for_pid_kind(CliKind::Claude, pid),
            &csq_core::sessions::ancestor_start,
            &wake::claude_socket_dirs(),
            now,
            wake::CLAUDE_SOCKET_TIMEOUT,
            &|| csq_core::messaging::store::pending_ids(base_dir, now, r).ok(),
            &notice,
        )
    }
}

/// [`real_claude_wake`] over an injected process-table read.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn claude_wake_via_pending(
    r: &Recipient,
    info_of: &dyn Fn(
        u32,
    ) -> Result<
        Option<(csq_core::sessions::SessionInfo, u64)>,
        csq_core::sessions::Undetermined,
    >,
    start_of: &dyn Fn(u32) -> Option<u64>,
    allowed_dirs: &[PathBuf],
    now: u64,
    timeout: std::time::Duration,
    pending_ids: &dyn Fn() -> Option<Vec<String>>,
    notice: &store::PendingNotice,
) -> Delivery {
    let Some(target) =
        wake::ClaudeWakeTarget::resolve(r.pid, r.started_at, r.started_exact, info_of, now)
    else {
        return Delivery::QueuedOnly;
    };
    wake::deliver_claude_coalesced_with_notice(
        &target,
        allowed_dirs,
        &|| target.still_live_with(start_of),
        notice,
        timeout,
        now,
        pending_ids,
    )
}

// Existing socket-binding tests intentionally have no stored message cohort.
#[cfg(all(unix, test))]
fn claude_wake_via(
    r: &Recipient,
    info_of: &dyn Fn(
        u32,
    ) -> Result<
        Option<(csq_core::sessions::SessionInfo, u64)>,
        csq_core::sessions::Undetermined,
    >,
    start_of: &dyn Fn(u32) -> Option<u64>,
    allowed_dirs: &[PathBuf],
    now: u64,
    timeout: std::time::Duration,
) -> Delivery {
    claude_wake_via_pending(
        r,
        info_of,
        start_of,
        allowed_dirs,
        now,
        timeout,
        &|| None,
        &store::PendingNotice::count_only(1),
    )
}

/// Wake the Codex session `r` if, and only if, its target validates and exactly one thread id
/// is known. `WakeTarget::still_live` runs immediately before the spawn, so a target whose
/// Codex pid or supervisor was replaced since validation is refused.
pub(crate) fn real_wake(base_dir: &Path, r: &Recipient) -> Delivery {
    let started = std::time::Instant::now();
    tracing::debug!(
        event = "message_request",
        stage = "wake",
        outcome = "start",
        elapsed_ms = 0u64
    );
    let delivery = dispatch(r, &|r| real_wake_with_stop(base_dir, r, &|| false), &|r| {
        real_claude_wake(base_dir, r)
    });
    tracing::debug!(
        event = "message_request",
        stage = "wake",
        outcome = delivery.as_str(),
        elapsed_ms = started.elapsed().as_millis() as u64
    );
    delivery
}

/// The supervisor retry uses its stop flag throughout the actual wake and settlement.
pub(crate) fn real_wake_with_stop(
    base_dir: &Path,
    r: &Recipient,
    stop: &dyn Fn() -> bool,
) -> Delivery {
    real_wake_with_stop_item(base_dir, r, stop).0
}

pub(crate) fn real_wake_with_stop_item(
    base_dir: &Path,
    r: &Recipient,
    stop: &dyn Fn() -> bool,
) -> (Delivery, Option<String>) {
    if r.surface == Surface::ClaudeCode {
        return (
            if stop() {
                Delivery::QueuedOnly
            } else {
                real_claude_wake(base_dir, r)
            },
            None,
        );
    }
    let (path, home_env) = (std::env::var_os("PATH"), std::env::var_os("HOME"));
    wake_via_with_item(
        base_dir,
        r,
        &wake_target_for,
        wake::Launcher {
            program: std::ffi::OsStr::new("codex"),
            path: path.as_deref(),
            home: home_env.as_deref(),
        },
        &csq_core::providers::codex::thread_id::held_lock_ids,
        &csq_core::providers::codex::thread_id::discover_thread_id_outcome,
        wake::WAKE_TIMEOUT,
        stop,
    )
}

/// [`real_wake`] with the target lookup and the launcher injected (a stub `codex` in tests).
#[cfg(all(test, unix))]
#[allow(clippy::too_many_arguments)]
fn wake_via(
    base_dir: &Path,
    r: &Recipient,
    target_of: &dyn Fn(&Path, &Recipient) -> Option<WakeInputs>,
    launcher: wake::Launcher<'_>,
    held_locks_of: &dyn Fn(u32, &Path) -> Option<std::collections::HashSet<String>>,
    discover: &dyn Fn(u32, &Path, &Path) -> csq_core::providers::codex::thread_id::ThreadDiscovery,
    timeout: std::time::Duration,
    stop: &dyn Fn() -> bool,
) -> Delivery {
    wake_via_with_item(
        base_dir,
        r,
        target_of,
        launcher,
        held_locks_of,
        discover,
        timeout,
        stop,
    )
    .0
}

#[allow(clippy::too_many_arguments)]
fn wake_via_with_item(
    base_dir: &Path,
    r: &Recipient,
    target_of: &dyn Fn(&Path, &Recipient) -> Option<WakeInputs>,
    launcher: wake::Launcher<'_>,
    held_locks_of: &dyn Fn(u32, &Path) -> Option<std::collections::HashSet<String>>,
    discover: &dyn Fn(u32, &Path, &Path) -> csq_core::providers::codex::thread_id::ThreadDiscovery,
    timeout: std::time::Duration,
    stop: &dyn Fn() -> bool,
) -> (Delivery, Option<String>) {
    use csq_core::messaging::wake::WakeSpec;
    use csq_core::providers::codex::thread_id as tid;
    // ONE deadline for the whole wake: thread resolution and `deliver_with` draw from it.
    let deadline = std::time::Instant::now() + wake::WAKE_TOTAL;
    if stop() {
        return (Delivery::QueuedOnly, None);
    }
    let Some((target, launch)) = target_of(base_dir, r) else {
        return (Delivery::QueuedOnly, None);
    };
    let spec = WakeSpec::from_target(&target);
    let home = spec.codex_home().to_path_buf();
    // The pid can hold its main plus finished or running subagents. Membership
    // alone is not main-thread provenance; classify using native source metadata.
    let held = std::cell::OnceCell::new();
    let main = std::cell::OnceCell::new();
    let selected = || {
        main.get_or_init(|| {
            #[cfg(unix)]
            if csq_core::providers::codex::managed_backend::is_configured(&home) {
                use csq_core::providers::codex::managed_backend as managed;
                if !target.still_live() || stop() {
                    return tid::ThreadDiscovery::Ambiguous;
                }
                let recipient = managed::LauncherIdentity {
                    pid: target.pid(),
                    started_exact: target.exact_start(),
                };
                let metadata = managed::loaded_thread_metadata(
                    &home,
                    target.sqlite_home(),
                    &recipient,
                    deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .min(timeout),
                );
                let selected = metadata.and_then(|rows| managed::unique_loaded_cli_thread(&rows));
                return match selected {
                    Ok(id)
                        if target.still_live()
                            && !stop()
                            && launch
                                .thread_id
                                .as_ref()
                                .is_none_or(|expected| expected == &id) =>
                    {
                        tid::ThreadDiscovery::Found(id)
                    }
                    _ => tid::ThreadDiscovery::Ambiguous,
                };
            }
            let held = held.get_or_init(|| {
                held_locks_of(
                    target.pid(),
                    &std::fs::canonicalize(home.join("thread-writer-locks"))
                        .unwrap_or_else(|_| home.join("thread-writer-locks")),
                )
            });
            let roles = held.as_ref().and_then(|h| {
                tid::read_thread_roles(
                    &launch.sqlite_home.clone().unwrap_or_else(|| home.clone()),
                    h,
                )
            });
            tid::select_main_thread(held.as_ref(), launch.thread_id.as_deref(), roles.as_ref())
        })
    };
    let holds = |id: &str| matches!(selected(), tid::ThreadDiscovery::Found(main) if main == id);
    let thread = wake::resolve_thread_id(
        launch.thread_id.clone(),
        &|| {
            if let tid::ThreadDiscovery::Found(id) = selected() {
                return tid::ThreadDiscovery::Found(id.clone());
            }
            let (Ok(sessions), Ok(locks)) = (
                std::fs::canonicalize(home.join("sessions")),
                std::fs::canonicalize(home.join("thread-writer-locks")),
            ) else {
                return tid::ThreadDiscovery::Ambiguous;
            };
            discover(target.pid(), &sessions, &locks)
        },
        &|| tid::read_captured_thread_id(&home),
        &holds,
    );
    if let Some(id) = thread.as_deref().filter(|_| !stop() && target.still_live()) {
        // Correct an old subagent capture only after this incarnation's MAIN is proven.
        let _ = tid::write_captured_thread_id(&home, id);
    }
    // A retry can race the recipient reading its inbox after the supervisor's initial
    // unread check. Re-read the authoritative store immediately before queueing so a
    // stale retry cannot start an empty Codex turn. Unknown or unreadable store state
    // remains eligible: suppressing on uncertainty could strand a real message.
    if !stop()
        && store::store_dir(base_dir).is_dir()
        && now_secs()
            .ok()
            .is_some_and(|now| nothing_unseen(base_dir, now, r))
    {
        return (Delivery::QueuedOnly, None);
    }
    let still_live = || !stop() && target.still_live();
    let notice = if store::store_dir(base_dir).is_dir() {
        now_secs()
            .ok()
            .and_then(|now| store::pending_notice(base_dir, now, r).ok())
            .unwrap_or_else(|| store::PendingNotice::count_only(1))
    } else {
        store::PendingNotice::count_only(1)
    };
    if notice.count == 0 {
        return (Delivery::QueuedOnly, None);
    }
    let (d, expected_item) = wake::deliver_with_notice(
        &spec,
        &still_live,
        thread.as_deref(),
        &notice,
        launcher,
        timeout,
        wake::DRAIN_WAIT,
        deadline,
    );
    if stop() {
        return (d, None);
    }
    // A deferred wake is armed only where a retrier exists: a recipient with a csq supervisor
    // other than the Codex pid (the swap-exec path has none), on a platform whose supervisor
    // runs the retry thread (unix).
    let retrier = cfg!(unix) && target.has_retrier();
    let settled = settle(
        d,
        retrier,
        &|| {
            if stop() {
                return false;
            }
            now_secs().is_ok_and(|now| {
                let arm = if matches!(
                    d,
                    Delivery::CodexQueuedUnverified
                        | Delivery::CodexRowNeverSeen
                        | Delivery::CodexWakeInFlight
                ) {
                    csq_core::messaging::deferred::arm_preserving_item
                } else {
                    csq_core::messaging::deferred::arm_with_item
                };
                let ok = !stop() && arm(&home, r, now, expected_item.clone()).is_ok();
                if !ok {
                    tracing::debug!(event = "deferred_wake", outcome = "arm_failed");
                }
                ok
            })
        },
        &|| csq_core::messaging::deferred::clear(&home),
    );
    (settled, expected_item)
}

/// Turn the immediate wake outcome into the status the sender reports, arming (or clearing)
/// the deferred wake. `arm` returns whether the record was written.
///
/// - `QueuedOnly` (no thread id yet) and `CodexNoTurnYet` become `CodexWakeDeferred` only if
///   a retry is really armed; otherwise they stay as the honest immediate status.
/// - Queued, unverified and in-flight outcomes keep their honest immediate status and arm
///   a re-check. Unverified acknowledgement is not evidence of recipient consumption.
/// - `CodexWoken` clears any armed record: the wake was taken.
fn settle(d: Delivery, retrier: bool, arm: &dyn Fn() -> bool, clear: &dyn Fn()) -> Delivery {
    match d {
        Delivery::QueuedOnly | Delivery::CodexNoTurnYet => {
            if retrier && arm() {
                Delivery::CodexWakeDeferred
            } else {
                d
            }
        }
        Delivery::CodexQueued
        | Delivery::CodexWakePending
        | Delivery::CodexQueuedUnverified
        | Delivery::CodexRowNeverSeen
        | Delivery::CodexWakeInFlight => {
            if retrier {
                let _ = arm();
            }
            d
        }
        Delivery::CodexWoken => {
            clear();
            d
        }
        other => other,
    }
}

/// One deferred-wake retry step for the session whose handle dir is `handle_dir`; called by the
/// recipient's own supervisor on a timer. A record is acted on only if its recipient still
/// validates as a live wake target AND that target's handle dir is this supervisor's own
/// (swaps relaunch the child, so identity is re-read from the process table at tick time).
#[cfg(unix)]
pub(crate) fn deferred_wake_tick(
    base_dir: &Path,
    handle_dir: &Path,
    stop: &dyn Fn() -> bool,
) -> csq_core::messaging::deferred::Tick {
    deferred_wake_tick_with(
        base_dir,
        handle_dir,
        &|r| wake_target_for(base_dir, r),
        &|r| real_wake_with_stop_item(base_dir, r, stop),
        stop,
    )
}

#[cfg(unix)]
fn deferred_wake_tick_with(
    base_dir: &Path,
    handle_dir: &Path,
    target_of: &dyn Fn(&Recipient) -> Option<WakeInputs>,
    wake_fn: &dyn Fn(&Recipient) -> (Delivery, Option<String>),
    stop: &dyn Fn() -> bool,
) -> csq_core::messaging::deferred::Tick {
    use csq_core::messaging::deferred::{tick, Deps, Tick};
    let Ok(now) = now_secs() else {
        return Tick::Idle;
    };
    let mine = std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
    let live = |r: &Recipient| target_of(r).is_some();
    let owns = |r: &Recipient| {
        target_of(r).is_some_and(|(t, _)| {
            std::fs::canonicalize(t.codex_home()).unwrap_or_else(|_| t.codex_home().to_path_buf())
                == mine
        })
    };
    let taken = |r: &Recipient, expected: &str| {
        target_of(r).is_some_and(|(t, _)| wake::queued_item_taken_for_target(&t, expected))
    };
    let unread = |r: &Recipient| unseen_queued(base_dir, now, r);
    tick(
        handle_dir,
        now,
        &Deps {
            live: &live,
            owns: &owns,
            unread: &unread,
            taken: &taken,
            wake: wake_fn,
            stop,
        },
    )
}

fn send_payload(
    result: Result<MessageReceipt, DirectiveError>,
    protection: bool,
) -> Result<Result<serde_json::Value, DirectiveError>, DirectiveError> {
    let result = result.and_then(|receipt| {
        let mut payload = serde_json::to_value(receipt)
            .map_err(|_| err(SdkErrorCode::Undetermined, "receipt serialization failed"))?;
        if !protection {
            payload["warning"] = serde_json::json!(request::UNPROTECTED_WARNING);
        }
        Ok(payload)
    });
    if protection {
        result.map(Ok)
    } else {
        Ok(result)
    }
}

/// Store `body` from the resolved caller to `target`. No sender parameter exists: `caller`
/// is the only source of the sender block (INV-32-01).
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn send_result(
    base_dir: &Path,
    clock: &dyn Fn() -> Result<request::Clock, DirectiveError>,
    fs: &FsOps<'_>,
    live: &dyn Fn(&Recipient) -> Liveness,
    caller: &dyn Fn() -> Result<VerifiedSession, DirectiveError>,
    candidates: &dyn Fn() -> NameListing,
    resolve: &dyn Fn(u32, u64) -> Result<Recipient, DirectiveError>,
    wake: &dyn Fn(&Recipient) -> Delivery,
    target: &str,
    body: &str,
    reply_to: Option<&str>,
    key: &str,
    protection: bool,
) -> Result<MessageReceipt, DirectiveError> {
    send_result_with_admission_clock(
        base_dir, clock, None, fs, live, caller, candidates, resolve, wake, target, body, reply_to,
        key, protection,
    )
}
/// [`send_result_wake`] for a sender that wants the wake (`wake:true`).
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn send_result_with_admission_clock(
    base_dir: &Path,
    clock: &dyn Fn() -> Result<request::Clock, DirectiveError>,
    wall: Option<&dyn Fn() -> Result<u64, DirectiveError>>,
    fs: &FsOps<'_>,
    live: &dyn Fn(&Recipient) -> Liveness,
    caller: &dyn Fn() -> Result<VerifiedSession, DirectiveError>,
    candidates: &dyn Fn() -> NameListing,
    resolve: &dyn Fn(u32, u64) -> Result<Recipient, DirectiveError>,
    wake: &dyn Fn(&Recipient) -> Delivery,
    target: &str,
    body: &str,
    reply_to: Option<&str>,
    key: &str,
    protection: bool,
) -> Result<MessageReceipt, DirectiveError> {
    send_result_wake(
        base_dir, clock, wall, fs, live, caller, candidates, resolve, wake, target, body, reply_to,
        key, protection, true,
    )
}
#[allow(clippy::too_many_arguments)]
fn send_result_wake(
    base_dir: &Path,
    clock: &dyn Fn() -> Result<request::Clock, DirectiveError>,
    wall: Option<&dyn Fn() -> Result<u64, DirectiveError>>,
    fs: &FsOps<'_>,
    live: &dyn Fn(&Recipient) -> Liveness,
    caller: &dyn Fn() -> Result<VerifiedSession, DirectiveError>,
    candidates: &dyn Fn() -> NameListing,
    resolve: &dyn Fn(u32, u64) -> Result<Recipient, DirectiveError>,
    wake: &dyn Fn(&Recipient) -> Delivery,
    target: &str,
    body: &str,
    reply_to: Option<&str>,
    key: &str,
    protection: bool,
    send_wake: bool,
) -> Result<MessageReceipt, DirectiveError> {
    let from = caller().map_err(|e| e.with_cause(Cause::SenderIdentity))?;
    let degraded = !protection;
    let intent = Intent::Send {
        target,
        parent: reply_to,
        body,
        wake: send_wake,
    };
    let replay = if degraded {
        None
    } else {
        let now = clock().map_err(|e| e.with_cause(Cause::Clock))?;
        request::replay_with_admission_clock(
            base_dir,
            match wall {
                Some(wall) => request::AdmissionClock::new(now, wall),
                None => request::AdmissionClock::asserted(now),
            },
            fs,
            &from,
            key,
            intent,
        )?
    };
    if let Some((r, to)) = replay {
        let delivery = wake(&to);
        return Ok(receipt_dto(&r)
            .with_to(to.pid, to.started_at)
            .with_to_surface(Some(to.surface.as_str().into()))
            .with_delivery(Some(delivery.as_str().into()))
            .with_delivery_reason(delivery.reason().map(str::to_string))
            .with_wake_override(wake_override(send_wake, &to)));
    }
    let raw_target = target;
    let target = parse_send_target(target)?;
    // A name only SELECTS a `(pid, started_at)`; the recipient is then re-verified for that
    // exact pair, and the stored sender is the resolved caller, never a name (spec 32a 4.3).
    let mut label_source: Option<&'static str> = None;
    let (pid, started_at) = match target {
        SendTarget::Pair(p, s) => (p, s),
        SendTarget::Name(n) => {
            let started = std::time::Instant::now();
            tracing::debug!(
                event = "message_request",
                stage = "registry_read",
                outcome = "start",
                elapsed_ms = 0u64
            );
            let selected = (|| {
                let (live, complete) = candidates()?;
                let me = from.as_recipient();
                registry::resolve_recipient_by_name(
                    &live,
                    complete,
                    &n,
                    Some((me.pid, me.started_at)),
                )
            })()
            .map_err(|e: DirectiveError| e.with_cause(Cause::RegistryRead));
            tracing::debug!(
                event = "message_request",
                stage = "registry_read",
                outcome = if selected.is_ok() {
                    "complete"
                } else {
                    "error"
                },
                cause = selected
                    .as_ref()
                    .err()
                    .and_then(|e| e.cause)
                    .unwrap_or(Cause::Unknown)
                    .as_str(),
                elapsed_ms = started.elapsed().as_millis() as u64
            );
            let c = selected?;
            label_source = Some(c.name_source.as_str());
            (c.pid, c.started_at)
        }
    };
    let to = resolve(pid, started_at)?;
    let (r, to) = if degraded {
        (
            store::send(
                base_dir,
                clock().map_err(|e| e.with_cause(Cause::Clock))?.observed(),
                fs,
                &Limits::DEFAULT,
                live,
                &from,
                to,
                body,
                reply_to,
            )?,
            to,
        )
    } else {
        let now = clock().map_err(|e| e.with_cause(Cause::Clock))?;
        request::send_with_admission_clock(
            base_dir,
            match wall {
                Some(wall) => request::AdmissionClock::new(now, wall),
                None => request::AdmissionClock::asserted(now),
            },
            fs,
            &Limits::DEFAULT,
            live,
            &from,
            to,
            raw_target,
            body,
            reply_to,
            key,
            send_wake,
        )?
    };
    // The message is stored `queued` before any wake: a wake outcome only labels the receipt
    // and can neither fail nor lose the send (INV-32-04). Both surfaces use the wake seam.
    let delivery = wake(&to);
    Ok(receipt_dto(&r)
        .with_to(to.pid, to.started_at)
        .with_to_surface(Some(to.surface.as_str().to_string()))
        .with_to_label_source(label_source.map(str::to_string))
        .with_delivery(Some(delivery.as_str().to_string()))
        .with_delivery_reason(delivery.reason().map(str::to_string))
        .with_wake_override(wake_override(send_wake, &to)))
}

/// The wake of `r` when the sender wants one, else `stored_no_wake` with NO wake attempted
/// (`--no-wake`): a stored Claude Code message surfaces on the recipient's next natural turn
/// through its per-turn hook. A Codex recipient has no such hook (spec 32a §5.2), so it is
/// woken regardless; [`wake_override`] reports that on the receipt.
fn wake_if(wake: bool, base_dir: &Path, r: &Recipient) -> Delivery {
    if wake || r.surface == Surface::Codex {
        real_wake(base_dir, r)
    } else {
        Delivery::StoredNoWake
    }
}

/// Whether `r` has a never-shown (queued) message: a message already surfaced needs no wake.
/// `None` when the store cannot be counted (uncertainty keeps a wake eligible).
/// Its only production caller is the Unix deferred-wake tick; the test module uses it everywhere.
#[cfg(any(unix, all(test, feature = "test-utils")))]
fn unseen_queued(base_dir: &Path, now: u64, r: &Recipient) -> Option<bool> {
    csq_core::messaging::store::pending_count(base_dir, now, r)
        .ok()
        .map(|c| c.queued > 0)
}

/// True only when the store is fully readable and holds NO never-shown message for `r`.
fn nothing_unseen(base_dir: &Path, now: u64, r: &Recipient) -> bool {
    csq_core::messaging::store::pending_count(base_dir, now, r)
        .ok()
        .is_some_and(|c| c.unreadable == 0 && c.queued == 0)
}

/// `Some("codex_no_turn_hook")` when `--no-wake` is overridden because `r` is a Codex session.
fn wake_override(wake: bool, r: &Recipient) -> Option<String> {
    (!wake && r.surface == Surface::Codex)
        .then(|| csq_core::messaging::mcp::WAKE_OVERRIDE_CODEX.to_string())
}

/// `csq sessions send <pid>:<started_at>|<name> --message <text|-> [--reply-to <id>]
/// [--no-wake]`.
pub fn send(
    base_dir: &Path,
    target: &str,
    message: &str,
    reply_to: Option<&str>,
    key: Option<&str>,
    wake: bool,
) -> Result<()> {
    let auto = key.is_none();
    let started = std::time::Instant::now();
    let prepared = std::cell::RefCell::new(None::<(String, VerifiedSession)>);
    finish(
        SCHEMA_MESSAGE_RECEIPT_V1,
        request::with_key_recovery(
            now_secs(),
            key,
            |now, key| {
                parse_send_target(target)?;
                let body = if message == "-" {
                    read_stdin_bounded(std::io::stdin().lock())?
                } else {
                    message.to_owned()
                };
                let from = resolve_verified()?;
                request::protection(true, &from)?;
                let result = request::recover_existing(
                    base_dir,
                    now,
                    &real_fs(),
                    &from,
                    key,
                    Some(Intent::Send {
                        target,
                        parent: reply_to,
                        body: &body,
                        wake,
                    }),
                )?;
                *prepared.borrow_mut() = Some((body, from));
                result
                    .map(|(r, to)| {
                        let delivery = wake_if(wake, base_dir, &to);
                        send_payload(
                            Ok(receipt_dto(&r)
                                .with_to(to.pid, to.started_at)
                                .with_to_surface(Some(to.surface.as_str().into()))
                                .with_delivery(Some(delivery.as_str().into()))
                                .with_delivery_reason(delivery.reason().map(str::to_string))
                                .with_wake_override(wake_override(wake, &to))),
                            true,
                        )
                    })
                    .transpose()
            },
            |now, key| {
                let body = prepared.borrow();
                let message = body
                    .as_ref()
                    .map(|(body, _)| body.as_str())
                    .unwrap_or(message);
                let fs = real_fs();
                send_input(
                    base_dir,
                    target,
                    message,
                    reply_to,
                    now,
                    key,
                    started,
                    auto,
                    wake,
                    body.is_some(),
                    body.as_ref().map(|(_, from)| from.clone()),
                    &InputSeams {
                        fs: &fs,
                        live: &real_liveness,
                        candidates: &|| real_candidates(base_dir),
                        resolve: &|p, s| {
                            resolve_target_exact(
                                p,
                                s,
                                &csq_core::sessions::session_info_for_pid_kind,
                                &real_exact_of,
                            )
                        },
                        wake_with: &wake_if,
                    },
                )
            },
        )
        .and_then(|result| result),
    )
}

/// The environment `send_input` reads, injectable so the `wake` passthrough is testable
/// without a live process table.
struct InputSeams<'a> {
    fs: &'a FsOps<'a>,
    live: &'a dyn Fn(&Recipient) -> Liveness,
    candidates: &'a dyn Fn() -> NameListing,
    resolve: &'a dyn Fn(u32, u64) -> Result<Recipient, DirectiveError>,
    /// `(send_wake, base_dir, recipient)`: the production gate is [`wake_if`].
    wake_with: &'a dyn Fn(bool, &Path, &Recipient) -> Delivery,
}

#[allow(clippy::too_many_arguments)]
fn send_input(
    base_dir: &Path,
    target: &str,
    message: &str,
    reply_to: Option<&str>,
    now: u64,
    key: &str,
    started: std::time::Instant,
    auto: bool,
    wake: bool,
    body_prepared: bool,
    prepared_sender: Option<VerifiedSession>,
    seams: &InputSeams<'_>,
) -> Result<Result<serde_json::Value, DirectiveError>, DirectiveError> {
    parse_send_target(target)
        .and_then(|_| {
            if message == "-" && !body_prepared {
                read_stdin_bounded(std::io::stdin().lock())
            } else {
                Ok(message.to_string())
            }
        })
        .and_then(|body| {
            let from = match prepared_sender {
                Some(from) => from,
                None => resolve_verified()?,
            };
            let protection = request::protection(!auto, &from)?;
            let degraded = !protection;
            let result = csq_core::messaging::request_retry::run_with_admission_clock(
                protection,
                key,
                &now_secs,
                |key| {
                    request::recover_existing_for_retry(
                        base_dir,
                        now_secs().map_err(|e| e.with_cause(Cause::Clock))?,
                        seams.fs,
                        &from,
                        key,
                        Some(Intent::Send {
                            target,
                            parent: reply_to,
                            body: &body,
                            wake,
                        }),
                    )
                    .map(|record| {
                        record.map(|(r, to)| {
                            let delivery = (seams.wake_with)(wake, base_dir, &to);
                            receipt_dto(&r)
                                .with_to(to.pid, to.started_at)
                                .with_to_surface(Some(to.surface.as_str().into()))
                                .with_delivery(Some(delivery.as_str().into()))
                                .with_delivery_reason(delivery.reason().map(str::to_string))
                                .with_wake_override(wake_override(wake, &to))
                        })
                    })
                },
                |key, admitted, capture| {
                    send_result_wake(
                        base_dir,
                        &|| {
                            if degraded {
                                now_secs().map(Into::into)
                            } else {
                                request::clock(now, started, capture())
                            }
                        },
                        Some(admitted),
                        seams.fs,
                        seams.live,
                        &|| Ok(from.clone()),
                        seams.candidates,
                        seams.resolve,
                        &|r| (seams.wake_with)(wake, base_dir, r),
                        target,
                        &body,
                        reply_to,
                        key,
                        protection,
                        wake,
                    )
                },
            );
            send_payload(result, protection)
        })
}

pub fn lookup(base_dir: &Path, key: &str) -> Result<()> {
    let result = (|| {
        let from = resolve_verified()?;
        match request::lookup_with_admission_clock(
            base_dir,
            request::AdmissionClock::new(now_secs()?.into(), &now_secs),
            &real_fs(),
            &from,
            key,
        )? {
            Lookup::NotStored => Err(err(SdkErrorCode::NotFound, "request was not stored")),
            Lookup::Stored(r, to) => Ok(receipt_dto(&r)
                .with_to(to.pid, to.started_at)
                .with_to_surface(Some(to.surface.as_str().into()))),
        }
    })();
    finish(SCHEMA_MESSAGE_RECEIPT_V1, result)
}

// ── name ────────────────────────────────────────────────────────────

/// Set (`Some`) or clear (`None`) the OWN name of the session whose handle dir `handle_dir`
/// returns. The handle dir comes from the caller proof alone: this function takes no target,
/// and nothing it is given can redirect the write. Returns the line to print.
fn name_result(
    handle_dir: &dyn Fn() -> Result<std::path::PathBuf, DirectiveError>,
    name: Option<&str>,
) -> Result<String, DirectiveError> {
    let to_err = |e: registry::NameError| {
        let code = match e {
            registry::NameError::Invalid | registry::NameError::Reserved => {
                SdkErrorCode::InvalidInput
            }
            registry::NameError::Io => SdkErrorCode::Undetermined,
        };
        err(code, &e.to_string())
    };
    match name {
        Some(n) => {
            // Validate before resolving anything: an invalid name never touches the disk.
            let n = registry::validate_name(n).map_err(to_err)?;
            registry::write_own_name(&handle_dir()?, &n).map_err(to_err)?;
            Ok(format!("session name set: {n}"))
        }
        None => {
            registry::clear_own_name(&handle_dir()?).map_err(to_err)?;
            Ok("session name cleared".to_string())
        }
    }
}

/// `csq sessions name <name>` / `csq sessions name --clear`. Prints one line on success;
/// on refusal prints `error: <code>: <message>` to stderr and exits 1.
pub fn name(name: Option<&str>, clear: bool) -> Result<()> {
    let resolved = || {
        csq_core::sessions::resolve_caller_from_env()
            .map(|c| c.handle_dir().to_path_buf())
            .map_err(caller_error)
    };
    match name_result(&resolved, if clear { None } else { name }) {
        Ok(line) => {
            println!("{line}");
            Ok(())
        }
        Err(e) => {
            eprintln!("error: {}: {}", e.code.as_str(), e.message);
            std::process::exit(1);
        }
    }
}

// ── ack-message ─────────────────────────────────────────────────────

fn ack_result(
    base_dir: &Path,
    now: u64,
    fs: &FsOps<'_>,
    live: &dyn Fn(&Recipient) -> Liveness,
    caller: &dyn Fn() -> Result<VerifiedSession, DirectiveError>,
    id: &str,
    note: Option<&str>,
) -> Result<MessageReceipt, DirectiveError> {
    let who = caller()?;
    store::ack(base_dir, now, fs, live, &who, id, note).map(|r| receipt_dto(&r))
}

/// `csq sessions ack-message <id> [--note …]`.
pub fn ack(base_dir: &Path, id: &str, note: Option<&str>) -> Result<()> {
    let result = now_secs().and_then(|now| {
        ack_result(
            base_dir,
            now,
            &real_fs(),
            &real_liveness,
            &resolve_verified,
            id,
            note,
        )
    });
    finish(SCHEMA_MESSAGE_RECEIPT_V1, result)
}

// ── inbox --messages ────────────────────────────────────────────────

#[cfg(test)]
fn inbox_result(
    base_dir: &Path,
    now: u64,
    fs: &FsOps<'_>,
    live: &dyn Fn(&Recipient) -> Liveness,
    caller: &dyn Fn() -> Result<VerifiedSession, DirectiveError>,
    pending: bool,
    mark: Option<Mark>,
) -> Result<MessageInboxPayload, DirectiveError> {
    inbox_result_with_options(base_dir, now, fs, live, caller, pending, mark, false)
}

#[allow(clippy::too_many_arguments)]
fn inbox_result_with_options(
    base_dir: &Path,
    now: u64,
    fs: &FsOps<'_>,
    live: &dyn Fn(&Recipient) -> Liveness,
    caller: &dyn Fn() -> Result<VerifiedSession, DirectiveError>,
    pending: bool,
    mark: Option<Mark>,
    include_surfaced: bool,
) -> Result<MessageInboxPayload, DirectiveError> {
    let who = caller()?;
    let views = store::inbox_with_options(
        base_dir,
        now,
        fs,
        live,
        &who,
        pending,
        mark,
        include_surfaced,
    )?;
    Ok(MessageInboxPayload::new(
        views.iter().map(entry_dto).collect(),
    ))
}

/// `csq sessions inbox --messages [--pending] [--mark-surfaced|--mark-read]`.
pub fn inbox(base_dir: &Path, pending: bool, mark: Option<Mark>) -> Result<()> {
    inbox_with_options(base_dir, pending, mark, false)
}

/// Inbox with explicit full-body replay for previously surfaced messages.
pub fn inbox_with_options(
    base_dir: &Path,
    pending: bool,
    mark: Option<Mark>,
    include_surfaced: bool,
) -> Result<()> {
    let result = now_secs().and_then(|now| {
        inbox_result_with_options(
            base_dir,
            now,
            &real_fs(),
            &real_liveness,
            &resolve_verified,
            pending,
            mark,
            include_surfaced,
        )
    });
    finish(SCHEMA_MESSAGE_INBOX_V1, result)
}

// ── --hook ──────────────────────────────────────────────────────────

/// The hook output, or `None` when there is nothing to print.
///
/// FAIL-OPEN BY DESIGN (zero-tolerance Rule 3's "acceptable" carve-out): every error here
/// becomes `None` because a Claude Code hook that fails or prints garbage can break the
/// user's turn, and a missed notice is recoverable (the message stays queued; the statusline
/// count and `inbox --messages --pending` still reach it, and so does the MCP `inbox` tool
/// once the server is registered). Each swallowed error logs a FIXED tag, never a body, path
/// or token (`security.md` §2).
///
/// Native hook context is checked for EVERY registered event before caller, clock or store
/// access. Child and unresolved events cannot consume the main session's mailbox. The
/// continuation flag suppresses only `Stop`, to avoid a repeated Stop-hook loop.
fn hook_output(
    base_dir: &Path,
    event: &str,
    context: &dyn Fn() -> HookContext,
    now: &dyn Fn() -> Result<u64, DirectiveError>,
    fs: &FsOps<'_>,
    caller: &dyn Fn() -> Result<VerifiedSession, DirectiveError>,
) -> Option<String> {
    let Some(event) = HookEvent::parse(event) else {
        tracing::warn!(
            reason = "hook_unknown_event",
            "message hook printed nothing"
        );
        return None;
    };
    let context = context();
    if context.origin != HookOrigin::Main {
        tracing::warn!(
            reason = "hook_origin_not_main",
            "message hook printed nothing"
        );
        return None;
    }
    if event == HookEvent::Stop && context.stop_active {
        return None;
    }
    let who = match caller() {
        Ok(w) => w,
        Err(_) => {
            tracing::warn!(
                reason = "hook_caller_unresolved",
                "message hook printed nothing"
            );
            return None;
        }
    };
    let Ok(now) = now() else {
        tracing::warn!(
            reason = "hook_clock_unreadable",
            "message hook printed nothing"
        );
        return None;
    };
    // No process table beyond the caller proof: an unknown liveness never evicts.
    let unknown = |_: &Recipient| Liveness::Unknown;
    match hook::surface(base_dir, now, fs, &unknown, &who, event) {
        Ok(out) => out,
        Err(_) => {
            tracing::warn!(
                reason = "hook_store_unreadable",
                "message hook printed nothing"
            );
            None
        }
    }
}

/// Byte cap on native hook input. Post-tool payloads can include large tool results;
/// input exceeding this cap is unresolved and leaves delivery to a later main event.
const MAX_HOOK_STDIN_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookOrigin {
    Main,
    Subagent,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HookContext {
    origin: HookOrigin,
    stop_active: bool,
}

impl HookContext {
    const UNKNOWN: Self = Self {
        origin: HookOrigin::Unknown,
        stop_active: true,
    };
}

/// Parse native input once. Claude's `agent_id` identifies a subagent; `agent_type`
/// alone also occurs for main sessions started with `--agent` and is not an origin proof.
/// Absent continuation flags remain compatible with older main-session payloads.
fn hook_context_from(input: impl Read) -> HookContext {
    let mut buf = Vec::new();
    if input
        .take(MAX_HOOK_STDIN_BYTES + 1)
        .read_to_end(&mut buf)
        .is_err()
        || buf.len() as u64 > MAX_HOOK_STDIN_BYTES
    {
        return HookContext::UNKNOWN;
    }
    let Ok(serde_json::Value::Object(payload)) = serde_json::from_slice(&buf) else {
        return HookContext::UNKNOWN;
    };
    let origin = match payload.get("agent_id") {
        None => HookOrigin::Main,
        Some(serde_json::Value::String(id)) if !id.is_empty() => HookOrigin::Subagent,
        Some(_) => HookOrigin::Unknown,
    };
    HookContext {
        origin,
        stop_active: payload
            .get("stop_hook_active")
            .is_some_and(|flag| flag.as_bool() != Some(false)),
    }
}

/// A terminal has no native payload: do not read it or treat it as a main-session hook.
fn hook_context_from_source(is_terminal: bool, input: impl Read) -> HookContext {
    if is_terminal {
        return HookContext::UNKNOWN;
    }
    hook_context_from(input)
}

fn real_hook_context() -> HookContext {
    use std::io::IsTerminal;
    let stdin = std::io::stdin();
    hook_context_from_source(stdin.is_terminal(), stdin.lock())
}

/// Write the hook output, ignoring every write error. `println!` panics on a closed stdout;
/// `writeln!` on the locked handle returns `Err` instead (Rust ignores SIGPIPE), which is
/// dropped, so the exit status stays 0.
fn emit_hook_output(out: Option<String>, w: &mut impl std::io::Write) {
    if let Some(s) = out {
        let _ = writeln!(w, "{s}");
        let _ = w.flush();
    }
}

/// `csq sessions inbox --messages --hook <event>`: print hook JSON when messages are queued
/// and nothing otherwise. Returns normally on EVERY outcome so the process exits 0 (a hook
/// must never break the session): the work runs under `catch_unwind` with a silent panic hook
/// installed for its duration (so a panic message cannot print a path to stderr), and the
/// output goes through [`emit_hook_output`], which cannot panic on a closed stdout.
pub fn hook(base_dir: &Path, event: &str) -> Result<()> {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hook_output(
            base_dir,
            event,
            &real_hook_context,
            &now_secs,
            &real_fs(),
            &resolve_verified,
        )
    }))
    .unwrap_or_else(|_| {
        tracing::warn!(reason = "hook_panicked", "message hook printed nothing");
        None
    });
    std::panic::set_hook(previous);
    emit_hook_output(out, &mut std::io::stdout().lock());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(unix, feature = "test-utils"))]
    include!("sessions_clock_admission_tests.rs");
    use super::*;
    use csq_core::messaging::frame::end_line;
    use csq_core::sessions::{resolve_caller, SessionInfo, Visibility};
    use std::path::PathBuf;
    use tempfile::TempDir;

    const T0: u64 = 1_000_000;

    fn info(pid: u32, dir: &Path, started_at: Option<u64>) -> SessionInfo {
        SessionInfo {
            pid,
            cwd: PathBuf::from("/"),
            config_dir: dir.to_path_buf(),
            account_id: None,
            started_at,
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        }
    }

    /// A caller proved through the REAL resolver over an injected process table: the only
    /// way to hold a `VerifiedSession` outside csq-core.
    fn caller(kind: CliKind, pid: u32, started_at: u64, dir: &Path) -> VerifiedSession {
        resolve_caller(
            kind,
            &[info(pid, dir, Some(started_at))],
            &[],
            Visibility::WHOLE,
            dir.to_str(),
            &|_| Some(Some(Vec::new())),
            &|_, _| Some(false),
            &|_| Some(started_at),
        )
        .unwrap()
        .verified()
        .unwrap()
    }

    fn live(_: &Recipient) -> Liveness {
        Liveness::Live
    }

    /// No names are known: a pid-pair send never consults the listing.
    fn no_names() -> NameListing {
        Err(err(SdkErrorCode::Undetermined, "no listing in this test"))
    }

    fn to_rcp(
        pid: u32,
        surface: Surface,
    ) -> impl Fn(u32, u64) -> Result<Recipient, DirectiveError> {
        move |p, s| {
            assert_eq!(p, pid);
            Ok(Recipient {
                pid: p,
                started_at: s,
                surface,
                started_exact: None,
            })
        }
    }

    /// Tests that spawn processes (the matrix) hold the WRITE side; every test that holds a
    /// store lock (all `World` tests) holds the READ side. A child forked while another test
    /// held a store lock inherits that lock's descriptor until it execs, so a concurrent spawn
    /// could make the try-once hook lock read busy and print nothing.
    static SPAWN: std::sync::RwLock<()> = std::sync::RwLock::new(());

    struct World {
        _spawn: std::sync::RwLockReadGuard<'static, ()>,
        base: TempDir,
        a_dir: TempDir,
        b_dir: TempDir,
    }
    fn world() -> World {
        World {
            _spawn: SPAWN.read().unwrap_or_else(|e| e.into_inner()),
            base: TempDir::new().unwrap(),
            a_dir: TempDir::new().unwrap(),
            b_dir: TempDir::new().unwrap(),
        }
    }
    #[test]
    fn auto_unpinned_cli_success_warns_and_explicit_key_keeps_identity_cause() {
        let w = world();
        let a = w.a();
        assert!(a.as_recipient().started_exact.is_none());
        let woke = std::cell::Cell::new(0);
        let run = |key: &str, auto: bool, liveness: &dyn Fn(&Recipient) -> Liveness| {
            let protection = request::protection(!auto, &a)?;
            send_result(
                w.base.path(),
                &|| Ok(T0.into()),
                &real_fs(),
                liveness,
                &|| Ok(a.clone()),
                &no_names,
                &to_rcp(200, Surface::ClaudeCode),
                &|_| {
                    woke.set(woke.get() + 1);
                    Delivery::QueuedOnly
                },
                "200:6000",
                "ordinary send",
                None,
                key,
                protection,
            )
        };
        let mut ids = Vec::new();
        for _ in 0..2 {
            let result = request::with_key(Ok(T0), None, |_, key| {
                send_payload(run(key, true, &live), false)
            })
            .and_then(|r| r);
            let envelope = serde_json::to_value(build(SCHEMA_MESSAGE_RECEIPT_V1, result)).unwrap();
            assert_eq!(envelope["ok"], true, "{envelope}");
            assert_eq!(envelope["warning"], request::UNPROTECTED_WARNING);
            assert!(envelope.get("idempotency_key").is_none());
            ids.push(envelope["id"].clone());
        }
        assert_ne!(ids[0], ids[1]);
        assert_eq!(woke.get(), 2);
        let key = request::mint(T0);
        let result = request::with_key(Ok(T0), Some(&key), |_, key| {
            send_payload(run(key, false, &live), true)
        })
        .and_then(|r| r);
        let envelope = serde_json::to_value(build(SCHEMA_MESSAGE_RECEIPT_V1, result)).unwrap();
        assert_eq!(envelope["error"]["code"], "undetermined");
        let text = envelope["error"]["message"].as_str().unwrap();
        assert!(text.contains("sender identity unpinned; key refused"));
        assert!(text.contains(&format!("idempotency_key={key}")));
        assert!(text.contains("retry the same call"));
        let result = request::with_key(Ok(T0), None, |_, key| {
            send_payload(run(key, true, &|_| Liveness::Unknown), false)
        })
        .and_then(|r| r);
        let envelope = serde_json::to_value(build(SCHEMA_MESSAGE_RECEIPT_V1, result)).unwrap();
        assert_eq!(envelope["error"]["code"], "undetermined");
        assert!(!envelope.to_string().contains("idempotency_key="));
        assert!(!envelope.to_string().contains("retry the same call"));
        let invalid = request::with_key(
            Ok(T0),
            Some("invalid-raw-secret"),
            |_, _| -> Result<(), DirectiveError> { panic!("invalid explicit key cannot degrade") },
        )
        .unwrap_err();
        assert_eq!(invalid.code, SdkErrorCode::InvalidIdempotencyKey);
        assert!(!invalid.message.contains("invalid-raw-secret"));
        assert_eq!(woke.get(), 2);
        assert!(!w.base.path().join("messages/requests").exists());
    }

    #[test]
    fn supplied_cli_key_admission_helper_returns_definite_errors() {
        for key in [
            "private-invalid-input".to_string(),
            request::mint(T0 + 6),
            request::mint(T0 - 600),
        ] {
            let result = request::with_key::<serde_json::Value>(Ok(T0), Some(&key), |_, _| {
                panic!("invalid supplied key must not execute the admission helper callback");
            });
            let envelope = serde_json::to_value(build(SCHEMA_MESSAGE_RECEIPT_V1, result)).unwrap();
            assert_eq!(envelope["error"]["code"], "invalid_idempotency_key");
            let message = envelope["error"]["message"].as_str().unwrap();
            assert!(!message.contains(&key));
            assert!(!message.contains("retry the same call"));
        }
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn keyed_cli_stdin_elapsed_and_epoch_jumps_fail_before_publication() {
        for case in ["stdin_elapsed", "forward_epoch", "backward_epoch"] {
            let w = world();
            let a = request::pin_test_session(w.a(), 5_000);
            let key = request::mint(T0);
            let started = if case == "stdin_elapsed" {
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(600))
                    .unwrap()
            } else {
                std::time::Instant::now()
            };
            let fresh = match case {
                "forward_epoch" => T0 + 600,
                "backward_epoch" => T0 - 1,
                _ => T0,
            };
            let clock = || request::clock(T0, started, Ok(fresh));
            let woke = std::cell::Cell::new(0);
            let result = request::with_key(Ok(T0), Some(&key), |_, key| {
                send_result(
                    w.base.path(),
                    &clock,
                    &real_fs(),
                    &live,
                    &|| Ok(a.clone()),
                    &|| panic!("expired attempt cannot resolve a name"),
                    &|_, _| panic!("expired attempt cannot resolve a target"),
                    &|_| {
                        woke.set(woke.get() + 1);
                        Delivery::QueuedOnly
                    },
                    "200:6000",
                    "must not publish",
                    None,
                    key,
                    true,
                )
            });
            let envelope = serde_json::to_value(build(SCHEMA_MESSAGE_RECEIPT_V1, result)).unwrap();
            assert_eq!(envelope["ok"], false, "{case}: {envelope}");
            assert_eq!(envelope["error"]["code"], "undetermined");
            let text = envelope["error"]["message"].as_str().unwrap();
            assert!(text.contains(&format!("idempotency_key={key}")));
            assert!(text.contains("retry the same call"));
            assert_eq!(woke.get(), 0);
            assert!(store::inbox(
                w.base.path(),
                T0 + 602,
                &real_fs(),
                &live,
                &w.b(),
                false,
                None
            )
            .unwrap()
            .is_empty());
        }
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn keyed_cli_replay_skips_ended_name_and_wakes_original_target() {
        let w = world();
        let a = request::pin_test_session(w.a(), 5_000);
        let key = request::mint(T0);
        let started = std::time::Instant::now();
        let clock = || request::clock(T0, started, Ok(T0));
        let woke = std::cell::RefCell::new(Vec::new());
        let wake = |to: &Recipient| {
            woke.borrow_mut().push(to.pid);
            Delivery::QueuedOnly
        };
        let first = send_result(
            w.base.path(),
            &clock,
            &real_fs(),
            &live,
            &|| Ok(a.clone()),
            &|| Ok((vec![cand(200, 6000, Surface::ClaudeCode, "original")], true)),
            &to_rcp(200, Surface::ClaudeCode),
            &wake,
            "original",
            "hello",
            None,
            &key,
            true,
        )
        .unwrap();
        let replay = send_result(
            w.base.path(),
            &clock,
            &real_fs(),
            &|_| Liveness::Ended,
            &|| Ok(a.clone()),
            &|| panic!("no new name resolution"),
            &|_, _| panic!("no new target resolution"),
            &wake,
            "original",
            "hello",
            None,
            &key,
            true,
        )
        .unwrap();
        assert_eq!(first.id, replay.id);
        assert_eq!(replay.to_pid, Some(200));
        assert_eq!(woke.borrow().as_slice(), &[200, 200]);
        // Lookup uses the same observed epoch as send and replay, without advancing the fixture clock.
        let lookup = request::lookup(w.base.path(), T0, &real_fs(), &a, &key).unwrap();
        match lookup {
            Lookup::Stored(r, to) => {
                assert_eq!(r.id, first.id);
                assert_eq!(to.pid, 200);
            }
            Lookup::NotStored => panic!("committed send must be found"),
        }
        let envelope = serde_json::to_value(build(SCHEMA_MESSAGE_RECEIPT_V1, Ok(replay))).unwrap();
        assert_eq!(envelope["schema"], SCHEMA_MESSAGE_RECEIPT_V1);
        assert_eq!(envelope["ok"], true);
    }

    #[test]
    fn keyed_cli_undetermined_keeps_token_in_existing_error_envelope() {
        let w = world();
        let key = request::mint(T0);
        let result = request::with_key(Ok(T0), Some(&key), |now, key| {
            send_result(
                w.base.path(),
                &|| Ok(now.into()),
                &real_fs(),
                &live,
                &|| {
                    Err(err(
                        SdkErrorCode::Undetermined,
                        "controlled caller uncertainty",
                    ))
                },
                &no_names,
                &to_rcp(200, Surface::ClaudeCode),
                &|_| panic!("failed send never wakes"),
                "200:6000",
                "hello",
                None,
                key,
                false,
            )
        });
        let envelope = serde_json::to_value(build(SCHEMA_MESSAGE_RECEIPT_V1, result)).unwrap();
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"]["code"], "undetermined");
        let message = envelope["error"]["message"].as_str().unwrap();
        assert!(message.contains(&format!("idempotency_key={key}")));
        assert!(message.contains(&format!(
            "csq sessions lookup-message --idempotency-key {key}"
        )));
        assert!(message.contains("retry the same call"));
        assert_eq!(
            parse_error_action(&["csq", "sessions", "lookup-message"].map(str::to_string)),
            ParseErrorAction::Envelope(SCHEMA_MESSAGE_RECEIPT_V1)
        );
    }

    impl World {
        fn a(&self) -> VerifiedSession {
            caller(
                CliKind::Codex,
                100,
                5_000,
                &self.a_dir.path().canonicalize().unwrap(),
            )
        }
        fn b(&self) -> VerifiedSession {
            caller(
                CliKind::Claude,
                200,
                6_000,
                &self.b_dir.path().canonicalize().unwrap(),
            )
        }
        fn send(&self, body: &str) -> Result<MessageReceipt, DirectiveError> {
            let a = self.a();
            send_result(
                self.base.path(),
                &|| Ok(T0.into()),
                &real_fs(),
                &live,
                &|| Ok(a.clone()),
                &no_names,
                &to_rcp(200, Surface::ClaudeCode),
                &|_| Delivery::QueuedOnly,
                "200:6000",
                body,
                None,
                &request::mint(T0),
                false,
            )
        }
        fn inbox(&self, pending: bool, mark: Option<Mark>) -> MessageInboxPayload {
            let b = self.b();
            inbox_result(
                self.base.path(),
                T0 + 5,
                &real_fs(),
                &live,
                &|| Ok(b.clone()),
                pending,
                mark,
            )
            .unwrap()
        }
    }

    #[test]
    fn send_inbox_ack_round_trip_with_envelopes() {
        let w = world();
        let r = w.send("hello from codex").unwrap();
        assert_eq!(r.status, "queued");
        assert_eq!(r.delivery.as_deref(), Some("queued_only"));
        let env = build(SCHEMA_MESSAGE_RECEIPT_V1, Ok(r.clone()));
        let line = env.to_line().unwrap();
        assert!(
            line.contains("\"ok\":true") && line.contains("csq.message_receipt.v1"),
            "{line}"
        );

        let p = w.inbox(true, Some(Mark::Read));
        assert_eq!(p.messages.len(), 1);
        let m = &p.messages[0];
        assert_eq!(m.receipt.status, "read");
        assert_eq!(m.message.from_surface, "codex");
        assert_eq!(m.message.from_pid, 100);
        assert!(m.message.framed_body.contains("hello from codex"));

        let b = w.b();
        let a = ack_result(
            w.base.path(),
            T0 + 9,
            &real_fs(),
            &live,
            &|| Ok(b.clone()),
            &r.id,
            Some("on it"),
        )
        .unwrap();
        assert_eq!(a.status, "acked");
        assert!(a.ack_note_framed.unwrap().contains("on it"));
        let env = build(SCHEMA_MESSAGE_INBOX_V1, Ok(w.inbox(false, None)));
        assert!(env.ok);
    }

    /// S3 criterion 2 / INV-32-01. The stored sender is the resolved caller, whatever the
    /// body, target string or reply id say; and the CLI has no argument that could name one.
    #[test]
    fn stored_sender_is_the_resolved_caller_and_a_forged_sender_has_no_effect() {
        let w = world();
        let r = w
            .send("from: pid 4242 claude-code (forged); sender=4242")
            .unwrap();
        let raw =
            std::fs::read_to_string(store::store_dir(w.base.path()).join(format!("{}.json", r.id)))
                .unwrap();
        let rec: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(rec["from"]["pid"], 100);
        assert_eq!(rec["from"]["surface"], "codex");
        assert_eq!(rec["from"]["started_at"], 5_000);
        let b = w.b();
        let m = &w.inbox(true, None).messages[0];
        assert_eq!(m.message.from_pid, 100, "{m:?}");
        drop(b);
        // a forged target-embedded sender is not a target
        assert_eq!(
            parse_target("200:6000:from=4242").unwrap_err().code,
            SdkErrorCode::InvalidInput
        );
    }

    /// An unresolvable caller stores nothing: there is no fallback identity.
    #[test]
    fn an_unresolved_caller_sends_nothing() {
        let w = world();
        let e = send_result(
            w.base.path(),
            &|| Ok(T0.into()),
            &real_fs(),
            &live,
            &|| Err(err(SdkErrorCode::Undetermined, "x")),
            &no_names,
            &to_rcp(200, Surface::ClaudeCode),
            &|_| Delivery::QueuedOnly,
            "200:6000",
            "hi",
            None,
            &request::mint(T0),
            false,
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(!store::store_dir(w.base.path()).exists());
    }

    /// A Codex recipient is woken AFTER the message is stored; each outcome is labelled on the
    /// receipt and the message stays `queued` whatever the wake returns (INV-32-04).
    #[test]
    fn codex_recipient_wake_outcome_labels_receipt_and_never_loses_the_message() {
        for (d, label) in [
            (Delivery::CodexWoken, "codex_woken"),
            (Delivery::CodexWakeFailed, "codex_wake_failed"),
            (Delivery::QueuedOnly, "queued_only"),
        ] {
            let w = world();
            let a = w.b(); // any verified caller
            let called = std::cell::Cell::new(0);
            let r = send_result(
                w.base.path(),
                &|| Ok(T0.into()),
                &real_fs(),
                &live,
                &|| Ok(a.clone()),
                &no_names,
                &to_rcp(100, Surface::Codex),
                &|rcp| {
                    assert_eq!(rcp.surface, Surface::Codex);
                    called.set(called.get() + 1);
                    d
                },
                "100:5000",
                "hello codex",
                None,
                &request::mint(T0),
                false,
            )
            .unwrap();
            assert_eq!(called.get(), 1);
            assert_eq!(r.delivery.as_deref(), Some(label));
            assert_eq!(r.status, "queued");
        }
    }

    /// Claude Code uses the wake seam after storage and retains the message for every outcome.
    #[test]
    fn claude_recipient_wake_outcome_labels_receipt() {
        for (d, label, reason) in [
            (Delivery::ClaudeWoken, "claude_woken", None),
            (Delivery::ClaudeWakeFailed, "claude_wake_failed", None),
            (Delivery::ClaudeWakePending, "claude_wake_pending", None),
            (
                Delivery::ClaudeWakeRateLimited,
                "claude_wake_rate_limited",
                None,
            ),
            (Delivery::QueuedOnly, "queued_only", None),
            // A lost lock wait: not woken, and no coverage by the holder is claimed.
            (
                Delivery::ClaudeWakeContended,
                "queued_only",
                Some("wake_contended"),
            ),
        ] {
            let w = world();
            let a = w.b();
            let called = std::cell::Cell::new(0);
            let r = send_result(
                w.base.path(),
                &|| Ok(T0.into()),
                &real_fs(),
                &live,
                &|| Ok(a.clone()),
                &no_names,
                &to_rcp(100, Surface::ClaudeCode),
                &|rcp| {
                    assert_eq!(rcp.surface, Surface::ClaudeCode);
                    called.set(called.get() + 1);
                    d
                },
                "100:5000",
                "hello claude",
                None,
                &request::mint(T0),
                false,
            )
            .unwrap();
            assert_eq!(called.get(), 1);
            assert_eq!(r.delivery.as_deref(), Some(label));
            assert_eq!(r.delivery_reason.as_deref(), reason);
        }
    }

    #[cfg(unix)]
    #[test]
    fn claude_wake_via_posts_the_notice_to_the_registered_socket() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        let cfg = TempDir::new().unwrap();
        // The inbox socket lives directly in `sd`; a deep runner TMPDIR would
        // push its pathname past `sun_path`.
        let sd = csq_core::testing::socket_fixture::short_root("csq-msg-").unwrap();
        let sock = sd.path().join("c.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let pid = std::process::id();
        let now = 1_800_000_000u64;
        let started = now - 100;
        std::fs::create_dir_all(cfg.path().join("sessions")).unwrap();
        std::fs::write(
            cfg.path().join("sessions").join(format!("{pid}.json")),
            format!(
                r#"{{"pid":{pid},"startedAt":{},"messagingSocketPath":{}}}"#,
                started * 1000,
                serde_json::to_string(sock.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        let info = SessionInfo {
            pid,
            cwd: PathBuf::from("/w"),
            config_dir: cfg.path().to_path_buf(),
            account_id: None,
            started_at: Some(started),
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        };
        let r = Recipient {
            pid,
            started_at: started,
            surface: Surface::ClaudeCode,
            started_exact: Some(777),
        };
        let reader = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut got = String::new();
            c.read_to_string(&mut got).unwrap();
            got
        });
        // The process table is injected at both reads: the listed process and its exact start (777).
        let d = claude_wake_via(
            &r,
            &|_| Ok(Some((info.clone(), 777))),
            &|_| Some(777),
            &[sd.path().to_path_buf()],
            now,
            wake::CLAUDE_SOCKET_TIMEOUT,
        );
        assert_eq!(d, Delivery::ClaudeWoken);
        assert_eq!(
            reader.join().unwrap(),
            wake::claude_line(1),
            "exactly the one fixed line"
        );
        // No registry record: queued_only, and the listener never saw a connection.
        let empty = TempDir::new().unwrap();
        let none = SessionInfo {
            config_dir: empty.path().to_path_buf(),
            ..info.clone()
        };
        assert_eq!(
            claude_wake_via(
                &r,
                &|_| Ok(Some((none.clone(), 777))),
                &|_| Some(777),
                &[sd.path().to_path_buf()],
                now,
                wake::CLAUDE_SOCKET_TIMEOUT
            ),
            Delivery::QueuedOnly
        );
        // A target whose start moved between validation and the post (a reused pid) is refused.
        let l2 = UnixListener::bind(sd.path().join("d.sock")).unwrap();
        l2.set_nonblocking(true).unwrap();
        std::fs::write(
            cfg.path().join("sessions").join(format!("{pid}.json")),
            format!(
                r#"{{"pid":{pid},"startedAt":{},"messagingSocketPath":{}}}"#,
                started * 1000,
                serde_json::to_string(sd.path().join("d.sock").to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        let moved = std::cell::Cell::new(0u64);
        let start_of = |_: u32| {
            moved.set(moved.get() + 1);
            Some(777 + moved.get())
        };
        assert_eq!(
            claude_wake_via(
                &r,
                &|_| Ok(Some((info.clone(), 777))),
                &start_of,
                &[sd.path().to_path_buf()],
                now,
                wake::CLAUDE_SOCKET_TIMEOUT
            ),
            Delivery::ClaudeWakeFailed
        );
        assert_eq!(
            l2.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "nothing connected"
        );
    }

    #[test]
    fn r8_dispatch_chooses_only_the_recipient_surface() {
        for surface in [Surface::Codex, Surface::ClaudeCode] {
            let r = Recipient {
                pid: 7,
                started_at: 50,
                surface,
                started_exact: Some(777),
            };
            let codex = |target: &Recipient| {
                assert_eq!(target.surface, Surface::Codex);
                Delivery::CodexQueued
            };
            let claude = |target: &Recipient| {
                assert_eq!(target.surface, Surface::ClaudeCode);
                Delivery::ClaudeWoken
            };
            let want = match surface {
                Surface::Codex => Delivery::CodexQueued,
                Surface::ClaudeCode => Delivery::ClaudeWoken,
            };
            assert_eq!(dispatch(&r, &codex, &claude), want);
        }
    }

    /// C3: the wake binds to the incarnation by full-precision start. Falsifier: comparing
    /// only seconds (always equal here), or treating an absent stored start as a match
    /// (`stored.map_or(true, ..)`), fails the second and third assertions.
    /// The real send path (`send_result_wake`) with the production wake gate (`wake_if`) over a
    /// recipient pid that cannot exist, so a wake that WAS attempted would be visible as a
    /// `queued_only` label and no real session can be woken.
    fn send_through_gate(
        w: &World,
        to: Surface,
        send_wake: bool,
        key: &str,
        protection: bool,
    ) -> Result<MessageReceipt, DirectiveError> {
        let a = if protection {
            request::pin_test_session(w.a(), 5_000)
        } else {
            w.a()
        };
        let started = std::time::Instant::now();
        let clock = || request::clock(T0, started, Ok(T0));
        send_result_wake(
            w.base.path(),
            &clock,
            None,
            &real_fs(),
            &live,
            &|| Ok(a.clone()),
            &no_names,
            &to_rcp(200, to),
            &|r| wake_if(send_wake, Path::new("/nonexistent-csq-no-wake"), r),
            "200:6000",
            "hello",
            None,
            key,
            protection,
            send_wake,
        )
    }

    #[test]
    fn cli_send_path_no_wake_labels_claude_and_overrides_for_codex() {
        let w = world();
        let claude =
            send_through_gate(&w, Surface::ClaudeCode, false, &request::mint(T0), false).unwrap();
        assert_eq!(claude.delivery.as_deref(), Some("stored_no_wake"));
        assert_eq!(claude.wake_override, None);
        // The same send with the default is NOT stored_no_wake (the gate really discriminates).
        let woken =
            send_through_gate(&w, Surface::ClaudeCode, true, &request::mint(T0), false).unwrap();
        assert_ne!(woken.delivery.as_deref(), Some("stored_no_wake"));
        let codex =
            send_through_gate(&w, Surface::Codex, false, &request::mint(T0), false).unwrap();
        assert_ne!(
            codex.delivery.as_deref(),
            Some("stored_no_wake"),
            "Codex is woken"
        );
        assert_eq!(codex.wake_override.as_deref(), Some("codex_no_turn_hook"));
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn cli_keyed_retry_flipping_wake_is_refused_and_a_same_wake_replay_stays_no_wake() {
        let w = world();
        let key = request::mint(T0);
        let first = send_through_gate(&w, Surface::ClaudeCode, false, &key, true).unwrap();
        assert_eq!(first.delivery.as_deref(), Some("stored_no_wake"));
        let replay = send_through_gate(&w, Surface::ClaudeCode, false, &key, true).unwrap();
        assert_eq!(replay.id, first.id);
        assert_eq!(replay.delivery.as_deref(), Some("stored_no_wake"));
        assert!(
            send_through_gate(&w, Surface::ClaudeCode, true, &key, true).is_err(),
            "same key with a different wake must be refused"
        );
    }

    /// `send_input` threads the sender's `wake` into the wake gate on BOTH the first send and a
    /// keyed replay: the recording seam sees exactly the flag passed in, so hard-wiring `true`
    /// (or `false`) on either path goes RED. The gate returns a fixed `Delivery`, so no host
    /// process table is read.
    #[cfg(feature = "test-utils")]
    #[test]
    fn send_input_passes_the_wake_choice_to_the_wake_gate_on_send_and_replay() {
        let seen = std::cell::RefCell::new(Vec::new());
        for wake in [false, true] {
            let w = world();
            let a = request::pin_test_session(w.a(), 5_000);
            let fs = real_fs();
            let gate = |send_wake: bool, _: &Path, _: &Recipient| {
                seen.borrow_mut().push(send_wake);
                if send_wake {
                    Delivery::QueuedOnly
                } else {
                    Delivery::StoredNoWake
                }
            };
            let rcp = to_rcp(200, Surface::ClaudeCode);
            let now = now_secs().unwrap();
            let key = request::mint(now);
            let mut ids = Vec::new();
            for _ in 0..2 {
                let out = send_input(
                    w.base.path(),
                    "200:6000",
                    "hello",
                    None,
                    now,
                    &key,
                    std::time::Instant::now(),
                    true,
                    wake,
                    true,
                    Some(a.clone()),
                    &InputSeams {
                        fs: &fs,
                        live: &live,
                        candidates: &no_names,
                        resolve: &rcp,
                        wake_with: &gate,
                    },
                )
                .unwrap()
                .unwrap();
                let label = if wake {
                    "queued_only"
                } else {
                    "stored_no_wake"
                };
                assert_eq!(out["delivery"], label, "wake={wake}: {out}");
                ids.push(out["id"].clone());
            }
            assert_eq!(
                ids[0], ids[1],
                "the keyed replay returns the original message"
            );
        }
        assert_eq!(*seen.borrow(), vec![false, false, true, true]);
    }

    /// A message already surfaced needs no wake: only a never-shown (queued) one does. Reverting
    /// either predicate to the unread (`pending`) count turns both assertions RED.
    #[cfg(feature = "test-utils")]
    #[test]
    fn a_surfaced_only_record_needs_no_wake() {
        use csq_core::messaging::store::{self, Mark};
        let w = world();
        send_through_gate(&w, Surface::ClaudeCode, true, &request::mint(T0), false).unwrap();
        let to = to_rcp(200, Surface::ClaudeCode)(200, 6_000).unwrap();
        assert_eq!(unseen_queued(w.base.path(), T0, &to), Some(true));
        assert!(!nothing_unseen(w.base.path(), T0, &to));
        store::inbox(
            w.base.path(),
            T0,
            &real_fs(),
            &live,
            &w.b(),
            true,
            Some(Mark::Surfaced),
        )
        .unwrap();
        assert_eq!(unseen_queued(w.base.path(), T0, &to), Some(false));
        assert!(nothing_unseen(w.base.path(), T0, &to));
    }

    #[test]
    fn no_wake_skips_the_wake_seam_and_labels_stored_no_wake() {
        // `wake_if(false, ..)` must return before `real_wake`, which would read the live
        // process table; a recipient that cannot exist proves nothing was attempted.
        let r = Recipient {
            pid: u32::MAX - 1,
            started_at: 1,
            surface: Surface::ClaudeCode,
            started_exact: None,
        };
        let d = wake_if(false, Path::new("/nonexistent-csq-no-wake"), &r);
        assert_eq!(d, Delivery::StoredNoWake);
        assert_eq!(d.as_str(), "stored_no_wake");
        assert_eq!(d.reason(), None);
    }

    #[test]
    fn exact_binding_requires_an_equal_present_start() {
        assert!(exact_binds(Some(42_000_001), 42_000_001));
        assert!(
            !exact_binds(Some(42_000_001), 42_900_000),
            "same second, different process"
        );
        assert!(!exact_binds(None, 42_000_001), "absent never binds");
    }

    /// C3: the exact start is captured for either surface, and an unreadable one
    /// leaves the send intact with no exact start (so no wake later).
    #[test]
    fn resolve_exact_captures_for_both_surfaces_and_degrades_to_none() {
        let codex_only = |k: CliKind, _p: u32| -> PidLookup {
            Ok((k == CliKind::Codex).then(|| pid_info(Some(50))))
        };
        let r = resolve_target_exact(7, 50, &codex_only, &|_, _, _| Some(9_999)).unwrap();
        assert_eq!((r.surface, r.started_exact), (Surface::Codex, Some(9_999)));
        let r = resolve_target_exact(7, 50, &codex_only, &|_, _, _| None).unwrap();
        assert_eq!(r.started_exact, None);
        let claude_only = |k: CliKind, _p: u32| -> PidLookup {
            Ok((k == CliKind::Claude).then(|| pid_info(Some(50))))
        };
        let r = resolve_target_exact(7, 50, &claude_only, &|k, _, _| {
            assert_eq!(k, CliKind::Claude);
            Some(8_888)
        })
        .unwrap();
        assert_eq!(
            (r.surface, r.started_exact),
            (Surface::ClaudeCode, Some(8_888))
        );
        let r = resolve_target_exact(7, 50, &claude_only, &|_, _, _| None).unwrap();
        assert_eq!(r.started_exact, None);
    }

    fn cand(pid: u32, started_at: u64, surface: Surface, name: &str) -> Candidate {
        Candidate {
            pid,
            started_at,
            surface,
            name: name.to_string(),
            name_source: registry::NameSource::SelfSet,
            repo: Some("repo".into()),
            branch: Some("main".into()),
            label_fallback: false,
        }
    }

    impl World {
        /// A send from `a` (Codex 100) addressed by `target` over a listing of `names`.
        fn send_to(
            &self,
            target: &str,
            names: Vec<Candidate>,
            complete: bool,
        ) -> Result<MessageReceipt, DirectiveError> {
            let a = self.a();
            send_result(
                self.base.path(),
                &|| Ok(T0.into()),
                &real_fs(),
                &live,
                &|| Ok(a.clone()),
                &|| Ok((names.clone(), complete)),
                &|p, s| {
                    Ok(Recipient {
                        pid: p,
                        started_at: s,
                        surface: Surface::ClaudeCode,
                        started_exact: None,
                    })
                },
                &|_| Delivery::QueuedOnly,
                target,
                "by name",
                None,
                &request::mint(T0),
                false,
            )
        }
    }

    /// The own name lands in the RESOLVED caller's handle dir and nowhere else, whatever the
    /// environment says (the resolver is the only source of the directory), and an invalid
    /// name is refused before the resolver is even asked.
    #[test]
    fn name_writes_only_the_resolved_callers_handle_dir() {
        let mine = TempDir::new().unwrap();
        let decoy = TempDir::new().unwrap();
        // A forged environment names the decoy; the resolver (injected) proves `mine`.
        let resolved = || Ok(mine.path().to_path_buf());
        let line = name_result(&resolved, Some("Worker-1")).unwrap();
        assert_eq!(line, "session name set: Worker-1");
        assert_eq!(
            registry::read_own_name(mine.path()).as_deref(),
            Some("Worker-1")
        );
        assert_eq!(registry::read_own_name(decoy.path()), None);
        assert_eq!(std::fs::read_dir(decoy.path()).unwrap().count(), 0);
        let asked = std::cell::Cell::new(0);
        let counting = || {
            asked.set(asked.get() + 1);
            Ok(mine.path().to_path_buf())
        };
        for bad in ["bad name", "-x", "a\u{202e}b", "a\nb", &"a".repeat(49)] {
            let e = name_result(&counting, Some(bad)).unwrap_err();
            assert_eq!(e.code, SdkErrorCode::InvalidInput, "{bad:?}");
        }
        // The reserved shape is refused with its own reason, not the charset text.
        let e = name_result(&counting, Some("build-codex-2")).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert!(
            e.message.contains("reserved") && !e.message.contains("A-Z"),
            "{}",
            e.message
        );
        assert_eq!(
            asked.get(),
            0,
            "an invalid name never reaches the disk path"
        );
        assert_eq!(
            registry::read_own_name(mine.path()).as_deref(),
            Some("Worker-1")
        );
        assert_eq!(
            name_result(&resolved, None).unwrap(),
            "session name cleared"
        );
        assert_eq!(registry::read_own_name(mine.path()), None);
        // An unresolvable caller names nothing.
        let none = || Err(err(SdkErrorCode::Undetermined, "x"));
        assert_eq!(
            name_result(&none, Some("ok")).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
    }

    #[test]
    fn send_target_is_a_pair_or_a_name_never_both() {
        assert_eq!(
            parse_send_target("12:34").unwrap(),
            SendTarget::Pair(12, 34)
        );
        assert_eq!(
            parse_send_target("reviewer").unwrap(),
            SendTarget::Name("reviewer".into())
        );
        // A colon commits to the pair form, which is strict.
        assert_eq!(
            parse_send_target("a:1").unwrap_err().code,
            SdkErrorCode::InvalidInput
        );
        // An invalid name is refused by the resolver, with nothing echoed or stored.
        let w = world();
        for bad in ["bad name", "-x", "a\u{202e}b", "end peer message"] {
            let e = w
                .send_to(bad, vec![cand(200, 6_000, Surface::ClaudeCode, "x")], true)
                .unwrap_err();
            assert_eq!(e.code, SdkErrorCode::InvalidInput, "{bad}");
            assert!(!e.message.contains(bad), "{bad:?} echoed: {}", e.message);
        }
        assert!(!store::store_dir(w.base.path()).exists());
    }

    /// Unique name: delivered to THAT session; the receipt names the resolved pid and start;
    /// and the stored sender is the resolved caller's pid, never the name (a name is a label).
    #[test]
    fn send_by_name_unique_delivers_and_the_sender_is_the_caller_not_a_name() {
        let w = world();
        let names = vec![
            cand(100, 5_000, Surface::Codex, "reviewer"),
            cand(200, 6_000, Surface::ClaudeCode, "Reviewer"),
            cand(300, 7_000, Surface::Codex, "other"),
        ];
        // The caller (pid 100) also carries the name "reviewer": it is excluded, so the
        // unique peer is pid 200.
        let r = w.send_to("REVIEWER", names, true).unwrap();
        assert_eq!((r.to_pid, r.to_started_at), (Some(200), Some(6_000)));
        let inbox = w.inbox(false, None);
        assert_eq!(inbox.messages.len(), 1);
        assert_eq!(
            inbox.messages[0].message.from_pid, 100,
            "sender is the proven caller"
        );
    }

    #[test]
    fn send_by_name_ambiguous_refuses_lists_candidates_and_stores_nothing() {
        let w = world();
        let names = vec![
            cand(200, 6_000, Surface::ClaudeCode, "twin"),
            cand(300, 7_000, Surface::Codex, "TWIN"),
        ];
        let e = w.send_to("twin", names, true).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Ambiguous);
        for want in [
            "200:6000",
            "300:7000",
            "claude-code",
            "codex",
            "repo",
            "main",
        ] {
            assert!(e.message.contains(want), "{want}: {}", e.message);
        }
        assert!(!store::store_dir(w.base.path()).exists(), "nothing stored");
    }

    #[test]
    fn send_by_name_not_found_and_blind_listing_are_distinct_refusals() {
        let w = world();
        let names = vec![cand(200, 6_000, Surface::ClaudeCode, "someone")];
        let e = w.send_to("ghost", names.clone(), true).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::NotFound);
        assert!(e.message.contains("someone"), "{}", e.message);
        let e = w.send_to("ghost", names, false).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(!store::store_dir(w.base.path()).exists());
    }

    /// B2: a listing that could not read every process (unreadable pids fold into
    /// `complete == false` through `RowsListing::is_complete`) never sends by name, even
    /// to a unique visible match whose unreadable twin may be the intended one, and never
    /// reports `not_found`. Falsifier: ignoring `complete` sends to the visible squatter.
    #[test]
    fn an_incomplete_listing_is_undetermined_for_zero_and_for_one_visible_match() {
        let w = world();
        let visible = vec![cand(200, 6_000, Surface::ClaudeCode, "target")];
        for name in ["target", "ghost"] {
            let e = w.send_to(name, visible.clone(), false).unwrap_err();
            assert_eq!(e.code, SdkErrorCode::Undetermined, "{name}");
        }
        assert!(
            !store::store_dir(w.base.path()).exists(),
            "nothing was sent"
        );
        // Control: the same listing, whole, sends.
        assert!(w.send_to("target", visible, true).is_ok());
    }

    #[test]
    fn target_parsing() {
        assert_eq!(parse_target("12:34").unwrap(), (12, 34));
        for bad in [
            "", "12", "12:", ":34", "a:1", "1:b", "1:2:3", "-1:2", "1: 2",
        ] {
            assert_eq!(
                parse_target(bad).unwrap_err().code,
                SdkErrorCode::InvalidInput,
                "{bad}"
            );
        }
    }

    fn pid_info(started: Option<u64>) -> SessionInfo {
        info(7, Path::new("/x"), started)
    }

    #[test]
    fn target_resolution_distinguishes_match_ended_and_unknown() {
        let only_codex = |k: CliKind, _| match k {
            CliKind::Codex => Ok(Some(pid_info(Some(50)))),
            CliKind::Claude => Ok(None),
        };
        let r = resolve_target(7, 50, &only_codex).unwrap();
        assert_eq!(r.surface, Surface::Codex);
        // start within tolerance still matches; a different start is not this session
        assert!(resolve_target(7, 51, &only_codex).is_ok());
        assert_eq!(
            resolve_target(7, 99, &only_codex).unwrap_err().code,
            SdkErrorCode::TargetMismatch
        );
        let none = |_, _| Ok(None);
        assert_eq!(
            resolve_target(7, 50, &none).unwrap_err().code,
            SdkErrorCode::TargetMismatch
        );
        // a lookup that could not be made is never "no such session"
        let flaky = |k: CliKind, _| match k {
            CliKind::Codex => Err(csq_core::sessions::Undetermined),
            CliKind::Claude => Ok(None),
        };
        assert_eq!(
            resolve_target(7, 50, &flaky).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        // F6: a positive Claude match at the same start is decisive over a Codex lookup error
        let claude_match_codex_err = |k: CliKind, _| match k {
            CliKind::Codex => Err(csq_core::sessions::Undetermined),
            CliKind::Claude => Ok(Some(pid_info(Some(50)))),
        };
        let r = resolve_target(7, 50, &claude_match_codex_err).unwrap();
        assert_eq!(r.surface, Surface::ClaudeCode);
        // ...but not when its start differs: then nothing matched and the error stands
        assert_eq!(
            resolve_target(7, 99, &claude_match_codex_err)
                .unwrap_err()
                .code,
            SdkErrorCode::Undetermined
        );
        // both CLIs claiming one pid is ambiguous
        let both = |_, _| Ok(Some(pid_info(Some(50))));
        assert_eq!(
            resolve_target(7, 50, &both).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        let nostart = |_, _| Ok(Some(pid_info(None)));
        assert_eq!(
            resolve_target(7, 50, &nostart).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
    }

    #[test]
    fn liveness_never_reads_an_unreadable_lookup_as_ended() {
        let r = Recipient {
            pid: 7,
            started_at: 50,
            surface: Surface::Codex,
            started_exact: None,
        };
        assert_eq!(
            liveness_from(&r, &|_, _| Ok(Some(pid_info(Some(50))))),
            Liveness::Live
        );
        assert_eq!(
            liveness_from(&r, &|_, _| Ok(Some(pid_info(Some(900))))),
            Liveness::Ended
        );
        assert_eq!(liveness_from(&r, &|_, _| Ok(None)), Liveness::Ended);
        assert_eq!(
            liveness_from(&r, &|_, _| Err(csq_core::sessions::Undetermined)),
            Liveness::Unknown
        );
        assert_eq!(
            liveness_from(&r, &|_, _| Ok(Some(pid_info(None)))),
            Liveness::Unknown
        );
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_errors_route_by_command() {
        use ParseErrorAction as A;
        let f = |p: &[&str]| parse_error_action(&argv(p));
        assert_eq!(
            f(&["csq", "sessions", "send", "--bogus"]),
            A::Envelope(SCHEMA_MESSAGE_RECEIPT_V1)
        );
        assert_eq!(
            f(&["csq", "--json", "sessions", "ack-message"]),
            A::Envelope(SCHEMA_MESSAGE_RECEIPT_V1)
        );
        assert_eq!(
            f(&["csq", "sessions", "inbox", "--messages", "--bogus"]),
            A::Envelope(SCHEMA_MESSAGE_INBOX_V1)
        );
        assert_eq!(
            f(&[
                "csq",
                "sessions",
                "inbox",
                "--messages",
                "--hook",
                "Stop",
                "--bogus"
            ]),
            A::HookSilent
        );
        // F3: `--hook` without `--messages` is still a hook: silent, never an envelope
        assert_eq!(
            f(&["csq", "sessions", "inbox", "--hook", "Stop"]),
            A::HookSilent
        );
        assert_eq!(
            f(&["csq", "sessions", "inbox", "--hook=Stop", "--bogus"]),
            A::HookSilent
        );
        assert_eq!(f(&["csq", "sessions", "inbox", "--bogus"]), A::NotMine);
        assert_eq!(f(&["csq", "sessions", "--", "send"]), A::NotMine);
        assert_eq!(f(&["csq", "swap", "send"]), A::NotMine);
        assert_eq!(f(&["csq"]), A::NotMine);
    }

    // ── hook ────────────────────────────────────────────────────────

    fn hook_for(w: &World, event: &str) -> Option<String> {
        let b = w.b();
        hook_output(
            w.base.path(),
            event,
            &|| hook_context_from(b"{}".as_slice()),
            &|| Ok(T0 + 5),
            &real_fs(),
            &|| Ok(b.clone()),
        )
    }

    #[test]
    fn subagent_post_tool_hook_leaves_main_mailbox_untouched_then_main_delivers_once() {
        let w = world();
        let receipt = w.send("main mailbox body").unwrap();
        let path = store::store_dir(w.base.path()).join(format!("{}.json", receipt.id));
        let before = std::fs::read(&path).unwrap();
        let b = w.b();
        let child = hook_output(
            w.base.path(),
            "PostToolUse",
            &|| {
                hook_context_from(
                    br#"{"session_id":"same-session","agent_id":"child-1","agent_type":"reviewer"}"#
                        .as_slice(),
                )
            },
            &|| Ok(T0 + 5),
            &real_fs(),
            &|| Ok(b.clone()),
        );
        assert_eq!(
            child, None,
            "a subagent must not receive the main mailbox body"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let queued: serde_json::Value = serde_json::from_slice(&before).unwrap();
        for field in ["noticed_at", "surfaced_at", "read_at", "acked_at"] {
            assert!(queued[field].is_null(), "child changed {field}");
        }
        // `agent_type` alone can describe the main session's --agent selection.
        let main = || {
            hook_context_from(
                br#"{"session_id":"same-session","agent_type":"reviewer"}"#.as_slice(),
            )
        };
        let output = hook_output(
            w.base.path(),
            "PostToolUse",
            &main,
            &|| Ok(T0 + 5),
            &real_fs(),
            &|| Ok(b.clone()),
        )
        .expect("the main session must still receive its queued message");
        let output: serde_json::Value = serde_json::from_str(&output).unwrap();
        let body = output["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        assert!(body.contains(&receipt.id));
        assert_eq!(body.matches("main mailbox body").count(), 1);
        let shown: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(shown["surfaced_at"], T0 + 5);
        for field in ["noticed_at", "read_at", "acked_at"] {
            assert!(shown[field].is_null(), "main surfacing changed {field}");
        }
        assert_eq!(hook_for(&w, "PostToolUse"), None);
    }

    #[test]
    fn child_and_unknown_hook_contexts_return_before_caller_clock_and_store() {
        let w = world();
        let receipt = w.send("not for a child").unwrap();
        let path = store::store_dir(w.base.path()).join(format!("{}.json", receipt.id));
        let before = std::fs::read(&path).unwrap();
        let mut payloads = vec![
            r#"{"agent_id":"child"}"#.to_string(),
            r#"{"agent_id":""}"#.to_string(),
            r#"{"agent_id":null}"#.to_string(),
            r#"{"agent_id":123}"#.to_string(),
            "".to_string(),
            "not json".to_string(),
            "[]".to_string(),
            "null".to_string(),
        ];
        payloads.push(format!(r#"{{"pad":"{}"}}"#, "x".repeat(70_000)));
        for event in ["PostToolUse", "UserPromptSubmit", "Stop"] {
            for payload in &payloads {
                assert_eq!(
                    hook_output(
                        w.base.path(),
                        event,
                        &|| hook_context_from(payload.as_bytes()),
                        &|| panic!("a child or unknown event reached the clock"),
                        &real_fs(),
                        &|| panic!("a child or unknown event reached caller resolution"),
                    ),
                    None,
                    "{event} must suppress this context",
                );
                assert_eq!(std::fs::read(&path).unwrap(), before);
            }
        }
    }

    #[test]
    fn hook_prints_only_when_queued_and_only_once() {
        let w = world();
        assert_eq!(hook_for(&w, "UserPromptSubmit"), None);
        w.send("ping").unwrap();
        let out = hook_for(&w, "Stop").unwrap();
        let j: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(j["decision"], "block");
        let reason = j["reason"].as_str().unwrap();
        assert!(
            reason.starts_with("csq: 1 peer message(s) waiting"),
            "{reason}"
        );
        assert!(reason.contains("inbox(mark: \"read\")"), "{reason}");
        assert!(
            reason.contains("untrusted data") && reason.contains("Preview: ping"),
            "{reason}"
        );
        // Follow the pointer's explicit read marking: the next tool hook must not
        // inject the same body again. The MCP default remains read-only.
        let pending = w.inbox(true, Some(Mark::Read));
        assert_eq!(pending.messages.len(), 1);
        assert!(pending.messages[0].message.framed_body.contains("ping"));
        assert!(!pending.messages[0].message.already_shown);
        for e in ["Stop", "PostToolUse", "UserPromptSubmit"] {
            assert_eq!(hook_for(&w, e), None, "{e}");
        }
    }

    /// F8: with `stop_hook_active` the Stop hook prints nothing and marks nothing; the message is
    /// still queued and a later, non-continuing Stop shows it.
    #[test]
    fn stop_hook_active_prints_nothing_and_leaves_the_message_queued() {
        let w = world();
        w.send("ping").unwrap();
        let b = w.b();
        let active = hook_output(
            w.base.path(),
            "Stop",
            &|| hook_context_from(br#"{"stop_hook_active":true}"#.as_slice()),
            &|| Ok(T0 + 5),
            &real_fs(),
            &|| Ok(b.clone()),
        );
        assert_eq!(active, None);
        assert_eq!(w.inbox(true, None).messages.len(), 1, "still queued");
        // the flag only governs Stop: another event still surfaces
        let other = hook_output(
            w.base.path(),
            "PostToolUse",
            &|| hook_context_from(br#"{"stop_hook_active":true}"#.as_slice()),
            &|| Ok(T0 + 5),
            &real_fs(),
            &|| Ok(b.clone()),
        );
        assert!(other.is_some());
    }

    #[test]
    fn stop_payload_parsing_is_bounded_and_cannot_prove_false_on_error() {
        let p = |s: &str| hook_context_from(s.as_bytes()).stop_active;
        assert!(!p(r#"{"stop_hook_active": false, "session_id": "x"}"#));
        assert!(p(r#"{"stop_hook_active": true}"#));
        // an absent flag is a payload without the continuation concept: not active
        assert!(!p(r#"{"session_id": "x"}"#));
        // garbage, empty and non-boolean cannot prove it false
        assert!(p("not json"));
        assert!(p(""));
        assert!(p(r#"{"stop_hook_active": "false"}"#));
        let big = format!(
            r#"{{"stop_hook_active": false, "pad": "{}"}}"#,
            "a".repeat(70_000)
        );
        assert!(p(&big), "oversize payload is refused, not parsed");
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("x"))
            }
        }
        assert_eq!(hook_context_from(Failing), HookContext::UNKNOWN);
    }

    #[test]
    fn terminal_hook_context_never_reads_and_empty_redirected_context_is_unknown() {
        struct Terminal;
        impl Read for Terminal {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("terminal stdin must never be read")
            }
        }
        assert_eq!(
            hook_context_from_source(true, Terminal),
            HookContext::UNKNOWN
        );
        assert_eq!(
            hook_context_from_source(false, b"".as_slice()),
            HookContext::UNKNOWN
        );
    }

    /// #2: a closed stdout must not panic (a panic would exit 101 through `main`).
    #[test]
    fn emit_ignores_a_closed_stdout() {
        struct Closed;
        impl std::io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
        emit_hook_output(Some("{}".into()), &mut Closed);
        let mut ok = Vec::new();
        emit_hook_output(Some("x".into()), &mut ok);
        assert_eq!(ok, b"x\n");
        emit_hook_output(None, &mut ok);
        assert_eq!(ok, b"x\n");
    }

    /// A hook must never break the session: every failure exits quietly. A bad store record is
    /// quarantined and the valid message next to it still surfaces.
    #[test]
    fn hook_fails_open_on_every_error() {
        let w = world();
        w.send("ping").unwrap();
        assert_eq!(hook_for(&w, "SessionStart"), None);
        assert_eq!(hook_for(&w, ""), None);
        let none = hook_output(
            w.base.path(),
            "Stop",
            &|| hook_context_from(b"{}".as_slice()),
            &|| Ok(T0),
            &real_fs(),
            &|| Err(err(SdkErrorCode::Undetermined, "x")),
        );
        assert_eq!(none, None);
        let b = w.b();
        assert_eq!(
            hook_output(
                w.base.path(),
                "Stop",
                &|| hook_context_from(b"{}".as_slice()),
                &|| Err(err(SdkErrorCode::Undetermined, "clock")),
                &real_fs(),
                &|| Ok(b.clone())
            ),
            None
        );
        // A malformed record next to a valid queued message (commit 35ecf5c1): the hook still
        // exits 0 and the valid message surfaces; the bad record is quarantined under the
        // store lock instead of silencing every later hook. Falsifier: a hook that returns
        // `None` on any store error fails the `Some` assertion; one that leaves the file in
        // place fails the quarantine assertions.
        let dir = store::store_dir(w.base.path());
        let bad = dir.join("0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d.json");
        std::fs::write(&bad, "{not json").unwrap();
        let out = hook_for(&w, "PostToolUse").expect("the valid message must still surface");
        let j: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            j["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap()
                .contains("ping"),
            "{out}"
        );
        assert!(!bad.exists(), "the bad record is moved out of the store");
        let rejected = dir.join("rejected");
        assert!(
            std::fs::read_dir(&rejected).unwrap().count() >= 1,
            "the bad record is quarantined under {}",
            rejected.display()
        );
    }

    /// S3 criterion 6 at the CLI surface: the body in the inbox envelope and in the hook is
    /// the frame's rendering, so control characters are gone and csq's terminator is the
    /// only one.
    #[test]
    fn token_cli_wire_stub_and_explicit_replay_keep_receipt_transitions() {
        let w = world();
        w.send("cli replay body").unwrap();
        let who = w.b();
        hook::surface(
            w.base.path(),
            T0 + 1,
            &real_fs(),
            &live,
            &who,
            HookEvent::PostToolUse,
        )
        .unwrap()
        .unwrap();
        let caller = || Ok(who.clone());
        let replay = inbox_result_with_options(
            w.base.path(),
            T0 + 2,
            &real_fs(),
            &live,
            &caller,
            true,
            None,
            true,
        )
        .unwrap();
        assert!(replay.messages[0]
            .message
            .framed_body
            .contains("cli replay body"));
        assert!(!replay.messages[0].message.already_shown);
        let stub = inbox_result_with_options(
            w.base.path(),
            T0 + 3,
            &real_fs(),
            &live,
            &caller,
            true,
            Some(Mark::Read),
            false,
        )
        .unwrap();
        assert_eq!(stub.messages[0].message.framed_body, "[csq: already shown; recover full body with inbox include_surfaced:true (CLI --include-surfaced).]");
        assert!(stub.messages[0].message.already_shown);
        assert_eq!(stub.messages[0].receipt.status, "read");
    }

    #[test]
    fn inbox_and_hook_bodies_are_framed() {
        let w = world();
        let r = w.send("line one\nline two").unwrap();
        let m = &w.inbox(true, None).messages[0];
        assert!(m.message.framed_body.starts_with("[peer msg "), "{:?}", m);
        assert!(m.message.framed_body.ends_with(&end_line(&r.id)));
        let out = hook_for(&w, "PostToolUse").unwrap();
        assert!(out.contains(&end_line(&r.id)), "{out}");
    }

    // ── G-MATRIX: four directions, several concurrent sessions ──────────────────────────

    /// Serialises the one test that sets `CODEX_HOME` / `CLAUDE_CONFIG_DIR` for the process.
    #[cfg(unix)]
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    mod matrix {
        use super::*;
        use csq_core::sessions::{ancestor_start, CodexLaunch};
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Child, Command, Stdio};

        const TID1: &str = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f01";
        const TID2: &str = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f02";

        /// One live Codex session: a REAL child process that is its own csq supervisor, so
        /// `wake_target_ok` validates it for real (`supervisor == pid`) over a real
        /// `term-<pid>` dir and `.live-pid`. Two of these have distinct homes and threads.
        struct Codex {
            child: Child,
            pid: u32,
            home: PathBuf,
            sqlite: PathBuf,
            thread: &'static str,
            exact: u64,
        }
        impl Drop for Codex {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        fn codex(base: &Path, n: u16, thread: &'static str) -> Codex {
            let child = Command::new("/bin/sleep")
                .arg("120")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", base)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            let home = base.join(format!("term-{pid}"));
            let sqlite = base.join(format!("config-{n}"));
            std::fs::create_dir(&home).unwrap();
            std::fs::create_dir(home.join("sessions")).unwrap();
            std::fs::create_dir(home.join("thread-writer-locks")).unwrap();
            std::fs::create_dir_all(&sqlite).unwrap();
            let state = rusqlite::Connection::open(sqlite.join("state_5.sqlite")).unwrap();
            state
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS threads(id TEXT PRIMARY KEY, source TEXT);",
                )
                .unwrap();
            state
                .execute("INSERT OR REPLACE INTO threads VALUES(?1,'cli')", [thread])
                .unwrap();
            csq_core::accounts::markers::write_live_pid(&home, pid).unwrap();
            let exact = ancestor_start(pid).expect("start of a live child");
            Codex {
                child,
                pid,
                home,
                sqlite,
                thread,
                exact,
            }
        }

        struct Fix {
            _spawn: std::sync::RwLockWriteGuard<'static, ()>,
            base: TempDir,
            _claude_dirs: [TempDir; 2],
            x1: Codex,
            x2: Codex,
            c: [(u32, PathBuf); 2],
            rec: TempDir,
            socks: TempDir,
            /// Every `(pid, locks dir)` the wake asked the fd table about.
            locks_seen: std::cell::RefCell<Vec<(u32, PathBuf)>>,
        }
        const C_START: u64 = 6_000;
        const C_EXACT: u64 = 777;
        const X_START: u64 = 5_000;

        fn fix() -> Fix {
            fix_slots(3, 4)
        }

        /// Two Codex sessions on accounts `n1` and `n2`; equal numbers share ONE `config-N`.
        fn fix_slots(n1: u16, n2: u16) -> Fix {
            let spawn = SPAWN.write().unwrap_or_else(|e| e.into_inner());
            let base = TempDir::new().unwrap();
            let root = base.path().canonicalize().unwrap();
            let x1 = codex(&root, n1, TID1);
            let x2 = codex(&root, n2, TID2);
            let d = [TempDir::new().unwrap(), TempDir::new().unwrap()];
            let c = [
                (300, d[0].path().canonicalize().unwrap()),
                (std::process::id(), d[1].path().canonicalize().unwrap()),
            ];
            let rec = TempDir::new().unwrap();
            let stub = rec.path().join("codex");
            std::fs::write(
                &stub,
                format!(
                    "#!/bin/sh\n: > '{d}/argv'\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '{d}/argv'; done\nenv | sort > '{d}/env'\nexit 0\n",
                    d = rec.path().display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            Fix {
                _spawn: spawn,
                base,
                _claude_dirs: d,
                x1,
                x2,
                c,
                rec,
                // Unix socket paths must fit SUN_LEN even under a long CI TMPDIR.
                // The shared short-root fixture pins the socket root's mode at
                // creation and keeps it independent of the ambient TMPDIR.
                socks: csq_core::testing::socket_fixture::short_root("csq-msg-").unwrap(),
                locks_seen: std::cell::RefCell::new(Vec::new()),
            }
        }

        /// The locks directory a wake for `x` must ask about: its OWN canonical home plus the
        /// Codex subdir name (`thread-writer-locks`).
        fn locks_dir_of(x: &Codex) -> PathBuf {
            x.home.canonicalize().unwrap().join("thread-writer-locks")
        }

        impl Fix {
            fn root(&self) -> PathBuf {
                self.base.path().canonicalize().unwrap()
            }
            fn claude(&self, i: usize) -> VerifiedSession {
                caller(CliKind::Claude, self.c[i].0, C_START, &self.c[i].1)
            }
            fn codex_caller(&self, x: &Codex) -> VerifiedSession {
                caller(CliKind::Codex, x.pid, X_START, &x.home)
            }
            fn rcp_claude(&self, i: usize) -> Recipient {
                Recipient {
                    pid: self.c[i].0,
                    started_at: C_START,
                    surface: Surface::ClaudeCode,
                    started_exact: Some(777),
                }
            }
            fn rcp_codex(x: &Codex) -> Recipient {
                Recipient {
                    pid: x.pid,
                    started_at: X_START,
                    surface: Surface::Codex,
                    started_exact: Some(x.exact),
                }
            }
            /// A send addressed BY NAME over the given live listing.
            fn send_named(
                &self,
                from: VerifiedSession,
                name: &str,
                live_names: &[Candidate],
                t: u64,
            ) -> Result<MessageReceipt, DirectiveError> {
                send_result(
                    &self.root(),
                    &|| Ok(t.into()),
                    &real_fs(),
                    &live,
                    &|| Ok(from.clone()),
                    &|| Ok((live_names.to_vec(), true)),
                    &|p, _| {
                        Ok(if p == self.x1.pid {
                            Fix::rcp_codex(&self.x1)
                        } else if p == self.x2.pid {
                            Fix::rcp_codex(&self.x2)
                        } else {
                            self.rcp_claude(usize::from(p == self.c[1].0))
                        })
                    },
                    &|r| self.wake(r),
                    name,
                    "by name",
                    None,
                    &request::mint(t),
                    false,
                )
            }
            /// The injected process table: each Codex pid lists ITS OWN home and launch.
            fn wake(&self, r: &Recipient) -> Delivery {
                dispatch(r, &|r| self.wake_with(r, &|x| x.thread), &|r| {
                    self.claude_wake(r)
                })
            }
            /// `launch_thread` is the thread id each target's launch argv claims; the lock
            /// the target really holds is always its own `x.thread`.
            fn wake_with(
                &self,
                r: &Recipient,
                launch_thread: &dyn Fn(&Codex) -> &'static str,
            ) -> Delivery {
                self.wake_with_stop(r, launch_thread, &|| false)
            }
            fn wake_with_stop(
                &self,
                r: &Recipient,
                launch_thread: &dyn Fn(&Codex) -> &'static str,
                stop: &dyn Fn() -> bool,
            ) -> Delivery {
                let root = self.root();
                let table: Vec<(&Codex, csq_core::sessions::SessionInfo)> = [&self.x1, &self.x2]
                    .into_iter()
                    .map(|x| (x, info(x.pid, &x.home, Some(X_START))))
                    .collect();
                let info_of = |pid: u32| {
                    Ok(table
                        .iter()
                        .find(|(x, _)| x.pid == pid)
                        .map(|(x, i)| (i.clone(), x.exact)))
                };
                let launch_of = |pid: u32, _s: u64, _e: u64| {
                    [&self.x1, &self.x2]
                        .into_iter()
                        .find(|x| x.pid == pid)
                        .map(|x| CodexLaunch {
                            thread_id: Some(launch_thread(x).to_string()),
                            sqlite_home: Some(x.sqlite.clone()),
                        })
                };
                let program = self.rec.path().join("codex");
                wake_via(
                    &root,
                    r,
                    &|b, r| wake_target_with(b, r, &info_of, &launch_of),
                    wake::Launcher {
                        program: program.as_os_str(),
                        path: Some(std::ffi::OsStr::new("/usr/bin:/bin")),
                        home: None,
                    },
                    // The fd table of `pid` reports a held lock ONLY under the pid's own locks
                    // directory; any other directory reads as holding nothing, so a lock check
                    // bound to the wrong home cannot confirm an id.
                    &|pid, locks| {
                        self.locks_seen
                            .borrow_mut()
                            .push((pid, locks.to_path_buf()));
                        [&self.x1, &self.x2]
                            .into_iter()
                            .find(|x| x.pid == pid && locks_dir_of(x) == locks)
                            .map(|x| std::iter::once(x.thread.to_string()).collect())
                    },
                    &|_, _, _| csq_core::providers::codex::thread_id::ThreadDiscovery::NoEvidence,
                    std::time::Duration::from_secs(10),
                    stop,
                )
            }
            fn claude_wake(&self, r: &Recipient) -> Delivery {
                let infos: Vec<_> = self
                    .c
                    .iter()
                    .map(|(pid, dir)| (*pid, info(*pid, dir, Some(C_START))))
                    .collect();
                let info_of = |pid: u32| {
                    Ok(infos
                        .iter()
                        .find(|(p, _)| *p == pid)
                        .map(|(_, i)| (i.clone(), C_EXACT)))
                };
                claude_wake_via(
                    r,
                    &info_of,
                    &|_| Some(C_EXACT),
                    &[self.socks.path().to_path_buf()],
                    C_START + 100,
                    wake::CLAUDE_SOCKET_TIMEOUT,
                )
            }
            /// Publish Claude session `i`'s inbox socket in its registry record and listen on it.
            fn claude_socket(&self, i: usize) -> std::os::unix::net::UnixListener {
                let (pid, dir) = &self.c[i];
                let sock = self.socks.path().join(format!("{pid}.sock"));
                let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
                std::fs::create_dir_all(dir.join("sessions")).unwrap();
                std::fs::write(
                    dir.join("sessions").join(format!("{pid}.json")),
                    format!(
                        r#"{{"pid":{pid},"startedAt":{},"messagingSocketPath":"{}"}}"#,
                        C_START * 1000,
                        sock.display()
                    ),
                )
                .unwrap();
                l
            }
            fn send(
                &self,
                from: VerifiedSession,
                to: Recipient,
                body: &str,
                t: u64,
            ) -> MessageReceipt {
                let target = format!("{}:{}", to.pid, to.started_at);
                send_result(
                    &self.root(),
                    &|| Ok(t.into()),
                    &real_fs(),
                    &live,
                    &|| Ok(from.clone()),
                    &no_names,
                    &|_, _| Ok(to),
                    &|r| self.wake(r),
                    &target,
                    body,
                    None,
                    &request::mint(t),
                    false,
                )
                .unwrap()
            }
            fn inbox_of(&self, who: VerifiedSession) -> Vec<MessageView> {
                store::inbox(&self.root(), T0 + 50, &real_fs(), &live, &who, false, None).unwrap()
            }
            fn argv(&self) -> String {
                std::fs::read_to_string(self.rec.path().join("argv")).unwrap()
            }
            fn env(&self) -> String {
                std::fs::read_to_string(self.rec.path().join("env")).unwrap()
            }
        }

        fn assert_wake_for(f: &Fix, target: &Codex, other: &Codex) {
            let (argv, env) = (f.argv(), f.env());
            // the lock check was bound to the RECIPIENT's home, not the sender's or the other
            // session's: every lookup for the target's pid named exactly its own locks dir
            let seen = f.locks_seen.borrow();
            let mine: Vec<_> = seen.iter().filter(|(p, _)| *p == target.pid).collect();
            assert!(!mine.is_empty(), "the held-lock check never ran: {seen:?}");
            for (_, locks) in mine {
                assert_eq!(*locks, locks_dir_of(target), "locks dir of the recipient");
            }
            assert!(
                seen.iter().all(|(p, _)| *p != other.pid),
                "no lookup for the other session's pid: {seen:?}"
            );
            drop(seen);
            f.locks_seen.borrow_mut().clear();
            assert!(
                argv.contains(&format!("sqlite_home={}\n", target.sqlite.display())),
                "{argv}"
            );
            assert!(
                argv.contains(&format!("--thread\n{}\n", target.thread)),
                "{argv}"
            );
            assert!(
                env.contains(&format!("CODEX_HOME={}\n", target.home.display())),
                "{env}"
            );
            let mut foreign = vec![other.home.display().to_string(), other.thread.to_string()];
            // two sessions on one account legitimately share `config-N`
            if other.sqlite != target.sqlite {
                foreign.push(other.sqlite.display().to_string());
            }
            for leaked in foreign {
                assert!(
                    !argv.contains(&leaked) && !env.contains(&leaked),
                    "leaked {leaked}"
                );
            }
        }

        #[test]
        fn matrix_c_to_c_lands_in_the_right_claude_inbox_with_no_wake() {
            let f = fix();
            let r = f.send(f.claude(0), f.rcp_claude(1), "c1 to c2", T0);
            assert_eq!(r.delivery.as_deref(), Some("queued_only"));
            assert!(
                !f.rec.path().join("argv").exists(),
                "a Claude recipient must never spawn codex"
            );
            let c2 = f.inbox_of(f.claude(1));
            assert_eq!(c2.len(), 1);
            assert_eq!(
                (c2[0].from_pid, c2[0].from_surface),
                (300, Surface::ClaudeCode)
            );
            assert!(
                f.inbox_of(f.claude(0)).is_empty(),
                "the sender's own inbox stays empty"
            );
            assert!(f.inbox_of(f.codex_caller(&f.x1)).is_empty());
            assert!(f.inbox_of(f.codex_caller(&f.x2)).is_empty());
        }

        /// C->C with a published socket: the recipient's OWN socket receives exactly the one
        /// fixed line (not the body), nothing spawns, the receipt says `claude_woken`.
        /// Red proof: swapping the `dispatch` arms sends this recipient down the Codex path
        /// (`queued_only`, no line), failing both assertions.
        #[test]
        fn matrix_c_to_c_socket_present_is_claude_woken() {
            use std::io::Read;
            let f = fix();
            let l = f.claude_socket(1);
            let other = f.claude_socket(0); // the sender's own socket must stay silent
            other.set_nonblocking(true).unwrap();
            let h = std::thread::spawn(move || {
                let (mut c, _) = l.accept().unwrap();
                let mut got = String::new();
                c.read_to_string(&mut got).unwrap();
                got
            });
            let r = f.send(f.claude(0), f.rcp_claude(1), "SECRET-BODY", T0);
            assert_eq!(r.delivery.as_deref(), Some("claude_woken"));
            let got = h.join().unwrap();
            assert_eq!(got, wake::claude_line(1));
            assert!(!got.contains("SECRET-BODY"));
            assert_eq!(
                other.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(!f.rec.path().join("argv").exists(), "no codex spawn");
        }

        /// C->C with no socket published: `queued_only`, nothing connects.
        #[test]
        fn matrix_c_to_c_socket_absent_is_queued_only() {
            let f = fix();
            let r = f.send(f.claude(0), f.rcp_claude(1), "c1 to c2", T0);
            assert_eq!(r.delivery.as_deref(), Some("queued_only"));
        }

        #[test]
        fn matrix_c_to_x_wakes_only_the_recipient_codex() {
            let f = fix();
            let r = f.send(f.claude(0), Fix::rcp_codex(&f.x2), "c1 to x2", T0);
            assert_eq!(r.delivery.as_deref(), Some("codex_queued_unverified"));
            assert_wake_for(&f, &f.x2, &f.x1);
            assert_eq!(f.inbox_of(f.codex_caller(&f.x2)).len(), 1);
            assert!(f.inbox_of(f.codex_caller(&f.x1)).is_empty());
            assert!(f.inbox_of(f.claude(1)).is_empty());
        }

        /// A recipient can read the message after storage but before the wake reaches its
        /// queue. The wake must re-check the authoritative store and suppress the stale
        /// notice, rather than starting a turn that finds an empty inbox.
        ///
        /// Red control: removing the final store re-check in `wake_via_with_item` causes the
        /// fixture launcher to run and returns a queued/unverified delivery.
        #[test]
        fn codex_wake_rechecks_store_before_queueing_after_a_racing_read() {
            let f = fix();
            let root = f.root();
            let to = Fix::rcp_codex(&f.x2);
            let receipt = send_result(
                &root,
                &|| Ok(T0.into()),
                &real_fs(),
                &live,
                &|| Ok(f.claude(0)),
                &no_names,
                &|_, _| Ok(to),
                &|r| {
                    let who = f.codex_caller(&f.x2);
                    let read = store::inbox(
                        &root,
                        T0 + 1,
                        &real_fs(),
                        &live,
                        &who,
                        true,
                        Some(Mark::Read),
                    )
                    .expect("the recipient read must commit before wake");
                    assert_eq!(read.len(), 1);
                    f.wake(r)
                },
                &format!("{}:{}", to.pid, to.started_at),
                "read before wake",
                None,
                &request::mint(T0),
                false,
            )
            .unwrap();
            assert_eq!(receipt.delivery.as_deref(), Some("queued_only"));
            assert!(
                !f.rec.path().join("argv").exists(),
                "a stale retry must not start an empty Codex turn"
            );
        }

        impl Fix {
            /// The injected process table as a target lookup (what `wake_target_for` does
            /// against the real one).
            fn target_of(&self, r: &Recipient) -> Option<WakeInputs> {
                let table: Vec<(&Codex, csq_core::sessions::SessionInfo)> = [&self.x1, &self.x2]
                    .into_iter()
                    .map(|x| (x, info(x.pid, &x.home, Some(X_START))))
                    .collect();
                let info_of = |pid: u32| {
                    Ok(table
                        .iter()
                        .find(|(x, _)| x.pid == pid)
                        .map(|(x, i)| (i.clone(), x.exact)))
                };
                let launch_of = |pid: u32, _s: u64, _e: u64| {
                    [&self.x1, &self.x2]
                        .into_iter()
                        .find(|x| x.pid == pid)
                        .map(|x| CodexLaunch {
                            thread_id: Some(x.thread.to_string()),
                            sqlite_home: Some(x.sqlite.clone()),
                        })
                };
                wake_target_with(&self.root(), r, &info_of, &launch_of)
            }
        }

        #[cfg(feature = "test-utils")]
        fn queue_table(dir: &Path) -> rusqlite::Connection {
            let c = rusqlite::Connection::open(dir.join("queue_1.sqlite")).unwrap();
            c.execute_batch(
                "CREATE TABLE queued_items (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, \
                 payload_json TEXT NOT NULL, queue_order INTEGER NOT NULL, \
                 created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);",
            )
            .unwrap();
            c
        }

        /// The whole `send` path reaches `codex_woken`: the stub codex queues ITEMW, which is
        /// present when it exits and is then taken by the "session".
        #[cfg(feature = "test-utils")]
        #[test]
        fn matrix_send_reaches_codex_woken_when_the_queued_row_is_seen_then_taken() {
            let f = fix();
            let db = queue_table(&f.x2.sqlite);
            db.execute(
                "INSERT INTO queued_items VALUES ('ITEMW', ?1, '{}', 1, 0, 0)",
                [TID2],
            )
            .unwrap();
            let stub = f.rec.path().join("codex");
            std::fs::write(
                &stub,
                format!(
                    "#!/bin/sh\n: > '{d}/argv'\necho 'Queued message ITEMW for thread {TID2}'\n",
                    d = f.rec.path().display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            let sq = f.x2.sqlite.clone();
            let (seen, observed) = std::sync::mpsc::channel();
            let taker = std::thread::spawn(move || {
                observed
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .unwrap();
                rusqlite::Connection::open(sq.join("queue_1.sqlite"))
                    .unwrap()
                    .execute("DELETE FROM queued_items WHERE id = 'ITEMW'", [])
                    .unwrap();
            });
            let r = wake::with_first_seen_signal(seen, || {
                f.send(f.claude(0), Fix::rcp_codex(&f.x2), "hi", T0)
            });
            taker.join().unwrap();
            assert_eq!(r.delivery.as_deref(), Some("codex_woken"));
            assert!(f.rec.path().join("argv").exists(), "the wake ran");
        }

        #[cfg(feature = "test-utils")]
        #[test]
        fn code_red_idle_main_wake_no_children_finished_children_running_children() {
            use csq_core::providers::codex::thread_id::{self as tid, ThreadDiscovery};
            for (case, children, resumed) in [
                ("never", false, true),
                ("finished", true, true),
                ("running", true, true),
                ("fresh", true, false),
            ] {
                let f = fix();
                let db = queue_table(&f.x2.sqlite);
                db.execute(
                    "INSERT INTO queued_items VALUES ('ITEMMAIN',?1,'{}',1,0,0)",
                    [TID2],
                )
                .unwrap();
                let child1 = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f03";
                let child2 = "0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f04";
                let state = rusqlite::Connection::open(f.x2.sqlite.join("state_5.sqlite")).unwrap();
                for id in [child1, child2] {
                    state
                        .execute(
                            "INSERT INTO threads VALUES(?1,?2)",
                            [id, "{\"subagent\":{\"thread_spawn\":{\"parent_thread_id\":\"0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f02\",\"depth\":1}}}"],
                        )
                        .unwrap();
                }
                if children {
                    tid::write_captured_thread_id(&f.x2.home, child1).unwrap();
                }
                let stub = f.rec.path().join("codex");
                std::fs::write(&stub,format!("#!/bin/sh\n: > '{d}/argv'\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '{d}/argv'; done\necho 'Queued message ITEMMAIN for thread {TID2}'\n",d=f.rec.path().display())).unwrap();
                std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
                let sq = f.x2.sqlite.clone();
                let (seen, observed) = std::sync::mpsc::channel();
                let taker = std::thread::spawn(move || {
                    if observed
                        .recv_timeout(std::time::Duration::from_secs(3))
                        .is_err()
                    {
                        return false;
                    }
                    rusqlite::Connection::open(sq.join("queue_1.sqlite"))
                        .unwrap()
                        .execute(
                            "DELETE FROM queued_items WHERE id='ITEMMAIN' AND thread_id=?1",
                            [TID2],
                        )
                        .unwrap()
                        == 1
                });
                let r = Fix::rcp_codex(&f.x2);
                let held: std::collections::HashSet<String> = if children {
                    [TID2, child1, child2]
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                } else {
                    [TID2].into_iter().map(str::to_owned).collect()
                };
                let program = stub.as_os_str();
                let delivery = wake::with_first_seen_signal(seen, || {
                    wake_via(
                        &f.root(),
                        &r,
                        &|_, r| {
                            let (target, mut launch) = f.target_of(r)?;
                            if !resumed {
                                launch.thread_id = None;
                            }
                            Some((target, launch))
                        },
                        wake::Launcher {
                            program,
                            path: Some(std::ffi::OsStr::new("/usr/bin:/bin")),
                            home: None,
                        },
                        &|_, _| Some(held.clone()),
                        &|_, _, _| ThreadDiscovery::Found(child1.into()),
                        std::time::Duration::from_secs(10),
                        &|| false,
                    )
                });
                let consumed = taker.join().unwrap();
                assert_eq!(
                    delivery,
                    Delivery::CodexWoken,
                    "case {case}: private queue consumption must belong to MAIN"
                );
                assert!(consumed, "case {case}: MAIN private queue item consumed");
                let argv = std::fs::read_to_string(f.rec.path().join("argv")).unwrap();
                assert!(
                    argv.contains(&format!("--thread\n{TID2}\n")),
                    "case {case}: {argv}"
                );
                assert!(
                    !argv.contains(child1) && !argv.contains(child2),
                    "children must never receive wake argv"
                );
                assert_eq!(
                    tid::read_captured_thread_id(&f.x2.home).as_deref(),
                    Some(TID2),
                    "verified MAIN repairs stale child capture"
                );
            }
        }

        #[test]
        fn supervisor_stop_before_wake_skips_target_discovery_and_spawn() {
            let f = fix();
            let r = Fix::rcp_codex(&f.x2);
            let delivery = f.wake_with_stop(
                &r,
                &|_| panic!("a stopped retry must not inspect launch state"),
                &|| true,
            );
            assert_eq!(delivery, Delivery::QueuedOnly);
            assert!(!f.rec.path().join("argv").exists());
            assert!(!csq_core::messaging::deferred::is_armed(&f.x2.home));
        }

        #[test]
        fn supervisor_stop_during_target_resolution_prevents_spawn_and_arming() {
            let f = fix();
            let stop = std::cell::Cell::new(false);
            let r = Fix::rcp_codex(&f.x2);
            let _ = f.wake_with_stop(
                &r,
                &|x| {
                    stop.set(true);
                    x.thread
                },
                &|| stop.get(),
            );
            assert!(stop.get(), "target resolution reached the stop handshake");
            assert!(!f.rec.path().join("argv").exists());
            assert!(!csq_core::messaging::deferred::is_armed(&f.x2.home));
        }

        #[test]
        fn ambiguous_discovery_and_competing_top_level_locks_refuse_launch_fallback() {
            use csq_core::providers::codex::thread_id::ThreadDiscovery;
            let f = fix();
            let r = Fix::rcp_codex(&f.x2);
            let program = f.rec.path().join("codex");
            for discovery in [ThreadDiscovery::Ambiguous, ThreadDiscovery::NoEvidence] {
                let delivery = wake_via(
                    &f.root(),
                    &r,
                    &|_, r| f.target_of(r),
                    wake::Launcher {
                        program: program.as_os_str(),
                        path: Some(std::ffi::OsStr::new("/usr/bin:/bin")),
                        home: None,
                    },
                    &|_, _| Some([TID1.to_string(), TID2.to_string()].into_iter().collect()),
                    &|_, _, _| discovery.clone(),
                    std::time::Duration::from_secs(10),
                    &|| false,
                );
                assert_eq!(delivery, Delivery::QueuedOnly);
                assert!(!f.rec.path().join("argv").exists());
            }
        }

        #[cfg(feature = "test-utils")]
        fn w4_session_evidence_probe(change_pid: bool) {
            let f = fix();
            let db = queue_table(&f.x2.sqlite);
            db.execute(
                "INSERT INTO queued_items VALUES ('ITEMW4', ?1, '{}', 1, 0, 0)",
                [TID2],
            )
            .unwrap();
            let stub = f.rec.path().join("codex");
            std::fs::write(
                &stub,
                format!("#!/bin/sh\necho 'Queued message ITEMW4 for thread {TID2}'\n"),
            )
            .unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            let r = Fix::rcp_codex(&f.x2);
            let target = f.target_of(&r).unwrap().0;
            assert_eq!(f.wake_with(&r, &|x| x.thread), Delivery::CodexQueued);
            db.execute("DELETE FROM queued_items", []).unwrap();
            assert!(
                wake::queued_item_taken_for_target(&target, "ITEMW4"),
                "same actual target incarnation proves consumption"
            );
            let sidecar = target.codex_home().join(".csq-wake-item");
            let mut record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
            assert_eq!(
                record["session"]["pid"].as_u64(),
                Some(u64::from(target.pid()))
            );
            assert_eq!(record["session"]["exact_start"].as_u64(), Some(f.x2.exact));
            if change_pid {
                record["session"]["pid"] = serde_json::json!(target.pid() + 1);
            } else {
                let exact = record["session"]["exact_start"].as_u64().unwrap();
                let other = if exact % 1_000_000 == 999_999 {
                    exact - 1
                } else {
                    exact + 1
                };
                assert_eq!(
                    other / 1_000_000,
                    exact / 1_000_000,
                    "same-second adversary"
                );
                record["session"]["exact_start"] = serde_json::json!(other);
            }
            std::fs::write(&sidecar, serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(
                !wake::queued_item_taken_for_target(&target, "ITEMW4"),
                "wrong exact session identity cannot prove consumption"
            );
        }

        #[cfg(feature = "test-utils")]
        #[test]
        fn w4_wrong_pid_refuses_actual_target_consumption() {
            w4_session_evidence_probe(true);
        }

        #[cfg(feature = "test-utils")]
        #[test]
        fn w4_same_second_wrong_exact_start_refuses_actual_target_consumption() {
            w4_session_evidence_probe(false);
        }

        #[test]
        fn a_queued_only_attempt_arms_without_correlating_a_stale_item() {
            let mut f = fix();
            let supervised_home = f.root().join(format!("term-{}", std::process::id()));
            std::fs::rename(&f.x2.home, &supervised_home).unwrap();
            f.x2.home = supervised_home;
            csq_core::accounts::markers::write_live_pid(&f.x2.home, std::process::id()).unwrap();
            csq_core::accounts::markers::write_live_cc_pid(&f.x2.home, f.x2.pid).unwrap();
            let r = Fix::rcp_codex(&f.x2);
            assert!(f.target_of(&r).unwrap().0.has_retrier());
            std::fs::write(
                f.x2.home.join(".csq-wake-item"),
                serde_json::to_vec(&serde_json::json!({"thread": TID2, "id": "STALE"})).unwrap(),
            )
            .unwrap();
            assert_eq!(wake::recorded_item_id(&f.x2.home).as_deref(), Some("STALE"));
            assert_eq!(f.wake_with(&r, &|_| TID1), Delivery::CodexWakeDeferred);
            assert!(!f.rec.path().join("argv").exists());
            let armed: serde_json::Value = serde_json::from_slice(
                &std::fs::read(f.x2.home.join(csq_core::messaging::deferred::PENDING_FILE))
                    .unwrap(),
            )
            .unwrap();
            assert!(
                armed["expect_item"].is_null(),
                "queued nothing, so stale item is not evidence"
            );
        }

        #[test]
        fn w5_auto_reap_refusal_arms_actual_cli_retry() {
            const MODE: &str = "CSQ_W5_CLI_DISPOSITION_PROBE";
            if let Some(mode) = std::env::var_os(MODE) {
                let mut f = fix();
                let supervised_home = f.root().join(format!("term-{}", std::process::id()));
                std::fs::rename(&f.x2.home, &supervised_home).unwrap();
                f.x2.home = supervised_home;
                csq_core::accounts::markers::write_live_pid(&f.x2.home, std::process::id())
                    .unwrap();
                csq_core::accounts::markers::write_live_cc_pid(&f.x2.home, f.x2.pid).unwrap();
                let r = Fix::rcp_codex(&f.x2);
                assert!(f.target_of(&r).unwrap().0.has_retrier());
                // SAFETY: only this re-executed, single-test process installs the
                // unsafe policy, restoring it immediately after the real CLI wake.
                let mut prior: libc::sigaction = unsafe { std::mem::zeroed() };
                unsafe {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    let no_wait = mode == "no-cld-wait";
                    action.sa_sigaction = if no_wait {
                        libc::SIG_DFL
                    } else {
                        libc::SIG_IGN
                    };
                    action.sa_flags = if no_wait { libc::SA_NOCLDWAIT } else { 0 };
                    libc::sigemptyset(&mut action.sa_mask);
                    assert_eq!(libc::sigaction(libc::SIGCHLD, &action, &mut prior), 0);
                }
                let delivery = f.wake_with(&r, &|x| x.thread);
                unsafe {
                    assert_eq!(
                        libc::sigaction(libc::SIGCHLD, &prior, std::ptr::null_mut()),
                        0
                    );
                }
                let pending =
                    std::fs::read(f.x2.home.join(csq_core::messaging::deferred::PENDING_FILE))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
                let observed = serde_json::json!({
                    "delivery": format!("{delivery:?}"), "wire": delivery.as_str(),
                    "armed": pending.is_some(), "no_observed_item": pending.as_ref().is_some_and(|v| v["expect_item"].is_null()),
                    "spawned": f.rec.path().join("argv").exists()
                });
                std::fs::write(
                    std::env::var_os("CSQ_W5_CLI_RESULT").unwrap(),
                    serde_json::to_vec(&observed).unwrap(),
                )
                .unwrap();
                return;
            }
            for mode in ["ignored", "no-cld-wait"] {
                let d = TempDir::new().unwrap();
                let result_path = d.path().join("result.json");
                let mut probe = Command::new(std::env::current_exe().unwrap());
                if mode == "ignored" {
                    use std::os::unix::process::CommandExt;
                    // SAFETY: async-signal-safe setter in this test's forked child only.
                    unsafe {
                        probe.pre_exec(|| {
                            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                            Ok(())
                        });
                    }
                }
                let result = probe.env_clear().env("HOME", d.path()).env("CSQ_BASE_DIR", d.path().join("base"))
                    .env("PATH", "/usr/bin:/bin").env(MODE, mode).env("CSQ_W5_CLI_RESULT", &result_path)
                    .args(["--exact", "cli::commands::sessions_messages::tests::matrix::w5_auto_reap_refusal_arms_actual_cli_retry", "--test-threads=1"])
                    .output().unwrap();
                assert!(
                    result.status.success(),
                    "isolated actual CLI probe: {}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                let observed: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&result_path).unwrap()).unwrap();
                assert_eq!(
                    observed,
                    serde_json::json!({"delivery":"CodexWakeDeferred", "wire":"codex_wake_pending", "armed":true, "no_observed_item":true, "spawned":false}),
                    "actual CLI retry must arm without claiming an observed queue row: {mode}"
                );
            }
        }

        #[test]
        fn settle_arms_only_where_a_retrier_exists_and_stays_honest_otherwise() {
            use std::cell::Cell;
            let armed = Cell::new(0u32);
            let cleared = Cell::new(0u32);
            let arm_ok = || {
                armed.set(armed.get() + 1);
                true
            };
            let clr = || cleared.set(cleared.get() + 1);
            // no thread / no turn: deferred only when armed
            assert_eq!(
                settle(Delivery::QueuedOnly, true, &arm_ok, &clr),
                Delivery::CodexWakeDeferred
            );
            assert_eq!(
                settle(Delivery::CodexNoTurnYet, true, &arm_ok, &clr),
                Delivery::CodexWakeDeferred
            );
            assert_eq!(armed.get(), 2);
            // no retrier (swap-exec) or an arm failure: the honest immediate status
            assert_eq!(
                settle(Delivery::QueuedOnly, false, &arm_ok, &clr),
                Delivery::QueuedOnly
            );
            assert_eq!(
                settle(Delivery::CodexNoTurnYet, false, &arm_ok, &clr),
                Delivery::CodexNoTurnYet
            );
            assert_eq!(armed.get(), 2, "never armed without a retrier");
            let arm_fail = || false;
            assert_eq!(
                settle(Delivery::QueuedOnly, true, &arm_fail, &clr),
                Delivery::QueuedOnly
            );
            assert_eq!(
                settle(Delivery::CodexNoTurnYet, true, &arm_fail, &clr),
                Delivery::CodexNoTurnYet
            );
            // queued / wake_pending keep their status and arm a re-check
            assert_eq!(
                settle(Delivery::CodexQueued, true, &arm_ok, &clr),
                Delivery::CodexQueued
            );
            assert_eq!(
                settle(Delivery::CodexWakePending, true, &arm_ok, &clr),
                Delivery::CodexWakePending
            );
            assert_eq!(armed.get(), 4);
            assert_eq!(
                settle(Delivery::CodexQueued, false, &arm_ok, &clr),
                Delivery::CodexQueued
            );
            assert_eq!(armed.get(), 4);
            // a taken wake clears any armed record
            assert_eq!(
                settle(Delivery::CodexWoken, true, &arm_ok, &clr),
                Delivery::CodexWoken
            );
            assert_eq!(cleared.get(), 1);
            assert_eq!(
                settle(Delivery::CodexWakeFailed, true, &arm_ok, &clr),
                Delivery::CodexWakeFailed
            );
        }

        /// CODE RED 6: queue acknowledgement uncertainty must retain the supervisor's
        /// retry marker. Old settle leaves this marker absent while reporting uncertainty.
        #[test]
        fn cr6_unverified_queue_outcomes_arm_durable_retry_without_claiming_taken() {
            use csq_core::messaging::deferred::{arm_with_item, is_armed, PENDING_FILE};
            let home = TempDir::new().unwrap();
            let recipient = Recipient {
                pid: 7,
                started_at: 5_000,
                surface: Surface::Codex,
                started_exact: Some(5_000_001),
            };
            for delivery in [
                Delivery::CodexQueuedUnverified,
                Delivery::CodexRowNeverSeen,
                Delivery::CodexWakeInFlight,
            ] {
                let expected =
                    (delivery != Delivery::CodexWakeInFlight).then(|| "CR6-ACK-ITEM".to_string());
                let result = settle(
                    delivery,
                    true,
                    &|| arm_with_item(home.path(), &recipient, 1_000, expected.clone()).is_ok(),
                    &|| panic!("uncertain queue outcome cannot clear a pending wake"),
                );
                assert_eq!(result, delivery, "preserve immediate status uncertainty");
                assert!(
                    is_armed(home.path()),
                    "{delivery:?}: durable retry must be armed"
                );
                let record: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(home.path().join(PENDING_FILE)).unwrap())
                        .unwrap();
                assert_eq!(record["expect_item"].as_str(), expected.as_deref());
                assert_eq!(
                    record["recipient"]["started_exact"].as_u64(),
                    recipient.started_exact
                );
                assert_eq!(record["armed_at"], 1_000);
                assert_eq!(record["next_at"], 1_005);
                csq_core::messaging::deferred::clear(home.path());
                assert!(!is_armed(home.path()));
                let calls = std::cell::Cell::new(0);
                for retrier in [false, true] {
                    let result = settle(
                        delivery,
                        retrier,
                        &|| {
                            calls.set(calls.get() + 1);
                            false
                        },
                        &|| {
                            panic!("failed arm must retain honest uncertainty");
                        },
                    );
                    assert_eq!(result, delivery);
                }
                assert_eq!(calls.get(), 1, "arm only where a retrier exists");
            }
        }

        /// Exercise the CLI wake itself with an acknowledgement fixture and an unavailable
        /// queue database. The helper is csq-owned, sandboxed and never invokes native Codex.
        #[test]
        fn cr6_acknowledged_unverified_cli_wake_arms_supervised_retry() {
            use csq_core::messaging::deferred::{is_armed, PENDING_FILE};
            let mut f = fix();
            let supervised_home = f.root().join(format!("term-{}", std::process::id()));
            std::fs::rename(&f.x2.home, &supervised_home).unwrap();
            f.x2.home = supervised_home;
            csq_core::accounts::markers::write_live_pid(&f.x2.home, std::process::id()).unwrap();
            csq_core::accounts::markers::write_live_cc_pid(&f.x2.home, f.x2.pid).unwrap();
            let recipient = Fix::rcp_codex(&f.x2);
            let target = f.target_of(&recipient).unwrap().0;
            assert!(
                target.has_retrier(),
                "recipient really has a separate supervisor"
            );
            assert!(!f.x2.sqlite.join("queue_1.sqlite").exists());
            let program = f.rec.path().join("codex");
            std::fs::write(
                &program,
                format!("#!/bin/sh\necho spawn >> \"$HOME/spawns\"\necho 'Queued message CR6-ACK-ITEM for thread {TID2}'\n"),
            )
            .unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
            let attempt = || {
                wake_via_with_item(
                    &f.root(),
                    &recipient,
                    &|_, r| f.target_of(r),
                    wake::Launcher {
                        program: program.as_os_str(),
                        path: Some(std::ffi::OsStr::new("/usr/bin:/bin")),
                        home: Some(f.rec.path().as_os_str()),
                    },
                    &|_, _| Some([TID2.to_owned()].into_iter().collect()),
                    &|_, _, _| csq_core::providers::codex::thread_id::ThreadDiscovery::NoEvidence,
                    std::time::Duration::from_secs(10),
                    &|| false,
                )
            };
            let (delivery, expected) = attempt();
            assert_eq!(delivery, Delivery::CodexQueuedUnverified);
            assert_eq!(delivery.as_str(), "codex_queued_unverified");
            assert!(
                is_armed(&f.x2.home),
                "uncertain acknowledgement must arm the supervisor"
            );
            assert_eq!(
                expected.as_deref(),
                Some("CR6-ACK-ITEM"),
                "item must come from this native-shaped acknowledgement"
            );
            let pending: serde_json::Value =
                serde_json::from_slice(&std::fs::read(f.x2.home.join(PENDING_FILE)).unwrap())
                    .unwrap();
            assert_eq!(pending["expect_item"].as_str(), Some("CR6-ACK-ITEM"));
            let (retry_delivery, retry_item) = attempt();
            assert_eq!(retry_delivery, Delivery::CodexQueuedUnverified);
            assert_eq!(retry_item.as_deref(), Some("CR6-ACK-ITEM"));
            assert_eq!(
                std::fs::read_to_string(f.rec.path().join("spawns"))
                    .unwrap()
                    .lines()
                    .count(),
                1,
                "unknown visibility of acknowledged item must suppress duplicate enqueue"
            );
            assert!(
                !wake::queued_item_taken_for_target(&target, "CR6-ACK-ITEM"),
                "unavailable DB and unobserved row cannot prove recipient consumption"
            );
            assert!(
                !f.x2.sqlite.join("queue_1.sqlite").exists(),
                "verification never creates native queue state"
            );
        }

        #[test]
        fn cr6_unverified_retry_keeps_ack_correlation_and_expires_without_taken_proof() {
            use csq_core::messaging::deferred::{self, Deps, Tick, PENDING_FILE};
            let home = TempDir::new().unwrap();
            let recipient = Recipient {
                pid: 7,
                started_at: 5_000,
                surface: Surface::Codex,
                started_exact: Some(5_000_001),
            };
            let expected = "CR6-ACK-ITEM";
            assert_eq!(
                settle(
                    Delivery::CodexQueuedUnverified,
                    true,
                    &|| deferred::arm_with_item(
                        home.path(),
                        &recipient,
                        1_000,
                        Some(expected.into())
                    )
                    .is_ok(),
                    &|| panic!("unverified acknowledgement cannot clear retry")
                ),
                Delivery::CodexQueuedUnverified
            );
            let attempts = std::cell::Cell::new(0);
            let taken_checks = std::cell::Cell::new(0);
            let deps = Deps {
                live: &|r| r.same_session(&recipient),
                owns: &|r| r.same_session(&recipient),
                unread: &|_| Some(true),
                taken: &|_, id| {
                    assert_eq!(id, expected, "only acknowledged item may be checked");
                    taken_checks.set(taken_checks.get() + 1);
                    false
                },
                wake: &|_| {
                    attempts.set(attempts.get() + 1);
                    (Delivery::CodexQueuedUnverified, Some(expected.into()))
                },
                stop: &|| false,
            };
            for (now, count, next_at) in [(1_005, 1, 1_010), (1_010, 2, 1_020)] {
                assert_eq!(
                    deferred::tick(home.path(), now, &deps),
                    Tick::Retried(Delivery::CodexQueuedUnverified)
                );
                let record: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(home.path().join(PENDING_FILE)).unwrap())
                        .unwrap();
                assert_eq!(
                    record["expect_item"].as_str(),
                    Some(expected),
                    "unverified retry must keep acknowledged item correlation"
                );
                assert_eq!(record["attempts"], count);
                assert_eq!(record["next_at"], next_at);
                assert_eq!(
                    record["armed_at"], 1_000,
                    "retry cannot reset retention age"
                );
            }
            assert_eq!(taken_checks.get(), 2);
            assert_eq!(attempts.get(), 2);
            assert_eq!(deferred::tick(home.path(), 1_011, &deps), Tick::Waiting);
            assert_eq!(
                deferred::tick(
                    home.path(),
                    1_000 + csq_core::messaging::limits::RETENTION_SECS,
                    &deps
                ),
                Tick::Expired
            );
            assert!(!deferred::is_armed(home.path()));
            assert_eq!(
                attempts.get(),
                2,
                "expired uncertainty never queues another wake"
            );
            assert_eq!(taken_checks.get(), 2, "expiry is not recipient consumption");
        }

        /// The supervisor tick reads the file `arm` wrote (through an ALIAS of the handle
        /// dir, as a non-canonical `handle_dir_abs` would be), acts on the owned recipient,
        /// clears a recipient that no longer validates, and ignores a planted record that
        /// names the OTHER session.
        #[test]
        fn matrix_supervisor_tick_reads_the_armed_record_and_checks_ownership() {
            use csq_core::messaging::deferred::{arm, is_armed, Tick};
            let f = fix();
            let alias_dir = TempDir::new().unwrap();
            let alias = alias_dir.path().join("alias-of-x1-home");
            std::os::unix::fs::symlink(&f.x1.home, &alias).unwrap();
            let r1 = Fix::rcp_codex(&f.x1);
            let r2 = Fix::rcp_codex(&f.x2);
            let past = now_secs().unwrap() - 100;
            // an unread message for x1 so the retry has something to deliver
            f.send(f.claude(0), r1, "pending", T0);
            // (1) owned recipient: the tick wakes and the taken wake clears the record
            arm(&f.x1.home, &r1, past).unwrap();
            let t = deferred_wake_tick_with(
                &f.root(),
                &alias,
                &|r| f.target_of(r),
                &|_| (Delivery::CodexWoken, None),
                &|| false,
            );
            assert_eq!(t, Tick::Woken, "{t:?}");
            assert!(!is_armed(&f.x1.home));
            // (2) a record naming the OTHER session, planted in x1's dir: nothing wakes
            arm(&f.x1.home, &r2, past).unwrap();
            let t = deferred_wake_tick_with(
                &f.root(),
                &alias,
                &|r| f.target_of(r),
                &|_| panic!("a planted record must wake nothing"),
                &|| false,
            );
            assert_eq!(t, Tick::NotOurs);
            assert!(!is_armed(&f.x1.home));
            // (3) the recipient no longer validates: cleared, nothing wakes
            arm(&f.x1.home, &r1, past).unwrap();
            let t = deferred_wake_tick_with(
                &f.root(),
                &alias,
                &|_| None,
                &|_| panic!("a gone recipient must wake nothing"),
                &|| false,
            );
            assert_eq!(t, Tick::RecipientGone);
            assert!(!is_armed(&f.x1.home));
        }

        #[test]
        fn matrix_x_to_c_resolves_the_sender_from_codex_home_and_stores_it() {
            let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
            let f = fix();
            // the sender's surface comes from CODEX_HOME alone
            let home = f.x1.home.to_str().unwrap();
            assert_eq!(
                csq_core::sessions::caller_kind(None, Some(home)).unwrap(),
                (CliKind::Codex, home)
            );
            assert!(csq_core::sessions::caller_kind(Some("/c"), Some(home)).is_err());
            let r = f.send(f.codex_caller(&f.x1), f.rcp_claude(0), "x1 to c1", T0);
            assert_eq!(r.delivery.as_deref(), Some("queued_only"));
            assert!(!f.rec.path().join("argv").exists());
            let c1 = f.inbox_of(f.claude(0));
            assert_eq!(c1.len(), 1);
            assert_eq!(
                (c1[0].from_pid, c1[0].from_surface),
                (f.x1.pid, Surface::Codex)
            );
            assert!(f.inbox_of(f.claude(1)).is_empty());
        }

        /// X(term-sup1) -> X(term-sup2). The process environment is the SENDER's: its
        /// `CODEX_HOME` names `term-sup1`, and the wake must still be built from the
        /// RECIPIENT's target alone.
        #[test]
        fn matrix_x_to_x_wakes_the_recipient_home_never_the_senders() {
            let _shared_env = csq_core::platform::test_env::lock();
            let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
            let f = fix();
            let prev = std::env::var_os("CODEX_HOME");
            std::env::set_var("CODEX_HOME", &f.x1.home);
            let r = f.send(f.codex_caller(&f.x1), Fix::rcp_codex(&f.x2), "x1 to x2", T0);
            match prev {
                Some(v) => std::env::set_var("CODEX_HOME", v),
                None => std::env::remove_var("CODEX_HOME"),
            }
            assert_eq!(r.delivery.as_deref(), Some("codex_queued_unverified"));
            assert_wake_for(&f, &f.x2, &f.x1);
            let got = f.inbox_of(f.codex_caller(&f.x2));
            assert_eq!(got.len(), 1);
            assert_eq!(
                (got[0].from_pid, got[0].from_surface),
                (f.x1.pid, Surface::Codex)
            );
            assert!(f.inbox_of(f.codex_caller(&f.x1)).is_empty());
        }

        /// INVEST-NOW: two Codex sessions on ONE account (the same `config-3` / sqlite_home),
        /// distinct `term-<sup>` dirs and thread ids. C->X and X->X must each wake exactly the
        /// intended thread, for either target. In production the two homes' `thread-writer-locks`
        /// are symlinks to ONE shared dir (`codex-thread-writer-locks`, `CODEX_SHARED_STATE` in
        /// `session/handle_dir.rs`), so the directory does not tell the sessions apart: the PID
        /// holding `<thread-id>.lock` does. This fixture gives each home its own canonical locks
        /// dir and the injected fd table answers only for the asking pid's own entries; that
        /// models the per-pid holder check, and the test asserts the dir the wake asked about.
        /// Falsifier (executed): pointing `wake_via`'s lock check at the sender's `CODEX_HOME`
        /// fails both the delivery and the recorded-dir assertions, on the X->X leg where the
        /// env names the sender.
        #[test]
        fn matrix_same_slot_c_to_x_and_x_to_x_wake_exactly_the_intended_thread() {
            let _shared_env = csq_core::platform::test_env::lock();
            let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
            let f = fix_slots(3, 3);
            assert_eq!(f.x1.sqlite, f.x2.sqlite, "one shared config-N");
            assert_ne!(f.x1.home, f.x2.home);
            for target in [&f.x1, &f.x2] {
                let other = if target.pid == f.x1.pid { &f.x2 } else { &f.x1 };
                // C -> X
                let r = f.send(f.claude(0), Fix::rcp_codex(target), "c to x", T0);
                assert_eq!(r.delivery.as_deref(), Some("codex_queued_unverified"));
                assert_wake_for(&f, target, other);
                // X(other) -> X(target), with the sender's own CODEX_HOME in the process env
                // (what a real MCP caller has): the wake must still bind to the target's home
                let prev = std::env::var_os("CODEX_HOME");
                std::env::set_var("CODEX_HOME", &other.home);
                let r = f.send(
                    f.codex_caller(other),
                    Fix::rcp_codex(target),
                    "x to x",
                    T0 + 1,
                );
                match prev {
                    Some(v) => std::env::set_var("CODEX_HOME", v),
                    None => std::env::remove_var("CODEX_HOME"),
                }
                assert_eq!(r.delivery.as_deref(), Some("codex_queued_unverified"));
                assert_wake_for(&f, target, other);
            }
        }

        /// F4 at the glue level: a launch argv naming the OTHER session's thread (stale after
        /// `/new` or a resume) is never woken; the target that holds no matching lock gets
        /// `queued_only` and nothing is spawned.
        #[test]
        fn matrix_a_stale_launch_thread_is_never_woken() {
            let f = fix_slots(3, 3);
            let stale = |x: &Codex| if x.pid == f.x1.pid { TID2 } else { TID1 };
            let d = f.wake_with(&Fix::rcp_codex(&f.x1), &stale);
            // No thread is confirmed, so nothing spawns. The fixture target is its own
            // supervisor (no retrier), so nothing is armed and the status stays honest.
            assert_eq!(d, Delivery::QueuedOnly);
            assert!(!f.rec.path().join("argv").exists(), "nothing spawned");
        }

        fn named(pid: u32, start: u64, surface: Surface, name: &str) -> Candidate {
            Candidate {
                pid,
                started_at: start,
                surface,
                name: name.to_string(),
                name_source: registry::NameSource::SelfSet,
                repo: Some("repo".into()),
                branch: Some("main".into()),
                label_fallback: false,
            }
        }

        /// C->X and X->X by name, with three peers sharing one self-set name: both are
        /// REFUSED as ambiguous, nothing is stored, no codex is spawned. The control sends
        /// to the one peer that remains once the caller is excluded and it is delivered
        /// and woken (so the refusal is the ambiguity, not a broken fixture).
        #[test]
        fn matrix_by_name_shared_name_is_ambiguous_for_c_to_x_and_x_to_x() {
            let f = fix();
            let shared = [
                named(f.x1.pid, X_START, Surface::Codex, "shared"),
                named(f.x2.pid, X_START, Surface::Codex, "shared"),
                named(f.c[1].0, C_START, Surface::ClaudeCode, "SHARED"),
                named(f.c[0].0, C_START, Surface::ClaudeCode, "c1"),
            ];
            // C -> X: the Claude caller sees THREE peers named shared.
            let e = f
                .send_named(f.claude(0), "shared", &shared, T0)
                .unwrap_err();
            assert_eq!(e.code, SdkErrorCode::Ambiguous, "{}", e.message);
            assert!(
                e.message.contains(&format!("{}:{X_START}", f.x1.pid)),
                "{}",
                e.message
            );
            // X -> X: the Codex caller x1 still sees two (x2 and c2).
            let e = f
                .send_named(f.codex_caller(&f.x1), "shared", &shared, T0 + 1)
                .unwrap_err();
            assert_eq!(e.code, SdkErrorCode::Ambiguous, "{}", e.message);
            assert!(
                !f.rec.path().join("argv").exists(),
                "a refused send never spawns codex"
            );
            for who in [
                f.claude(0),
                f.claude(1),
                f.codex_caller(&f.x1),
                f.codex_caller(&f.x2),
            ] {
                assert!(f.inbox_of(who).is_empty(), "ambiguity stored nothing");
            }
            // Control: only x2 shares the name with the caller x1 -> unique, delivered, woken.
            let only_x2 = [
                named(f.x1.pid, X_START, Surface::Codex, "shared"),
                named(f.x2.pid, X_START, Surface::Codex, "shared"),
            ];
            let r = f
                .send_named(f.codex_caller(&f.x1), "shared", &only_x2, T0 + 2)
                .unwrap();
            assert_eq!(r.delivery.as_deref(), Some("codex_queued_unverified"));
            assert_eq!(r.to_pid, Some(f.x2.pid));
            assert_wake_for(&f, &f.x2, &f.x1);
            assert_eq!(f.inbox_of(f.codex_caller(&f.x2)).len(), 1);
            assert!(f.inbox_of(f.codex_caller(&f.x1)).is_empty());
        }

        /// Unique names, every direction that is not X->X (the shared-name test's control
        /// covers that): each send lands in exactly the named session's inbox, Codex
        /// recipients are woken, Claude recipients are not, and the receipt names who was
        /// reached. Falsifier: resolving to the wrong candidate fails the inbox assertions.
        #[test]
        fn matrix_by_name_unique_c_to_c_c_to_x_and_x_to_c_deliver_to_the_named_session() {
            let f = fix();
            let live = [
                named(f.c[0].0, C_START, Surface::ClaudeCode, "alpha"),
                named(f.c[1].0, C_START, Surface::ClaudeCode, "bravo"),
                named(f.x1.pid, X_START, Surface::Codex, "x-one"),
                named(f.x2.pid, X_START, Surface::Codex, "x-two"),
            ];
            // C -> C
            let r = f.send_named(f.claude(0), "bravo", &live, T0).unwrap();
            assert_eq!(
                (r.to_pid, r.to_surface.as_deref()),
                (Some(f.c[1].0), Some("claude-code"))
            );
            assert_eq!(r.delivery.as_deref(), Some("queued_only"));
            assert!(
                !f.rec.path().join("argv").exists(),
                "a Claude recipient is never woken"
            );
            assert_eq!(f.inbox_of(f.claude(1)).len(), 1);
            // C -> X
            let r = f.send_named(f.claude(0), "X-TWO", &live, T0 + 1).unwrap();
            assert_eq!(
                (r.to_pid, r.to_label_source.as_deref()),
                (Some(f.x2.pid), Some("self"))
            );
            assert_eq!(r.delivery.as_deref(), Some("codex_queued_unverified"));
            assert_wake_for(&f, &f.x2, &f.x1);
            assert_eq!(f.inbox_of(f.codex_caller(&f.x2)).len(), 1);
            assert!(f.inbox_of(f.codex_caller(&f.x1)).is_empty());
            // X -> C
            let r = f
                .send_named(f.codex_caller(&f.x1), "alpha", &live, T0 + 2)
                .unwrap();
            assert_eq!(
                (r.to_pid, r.delivery.as_deref()),
                (Some(f.c[0].0), Some("queued_only"))
            );
            let got = f.inbox_of(f.claude(0));
            assert_eq!(got.len(), 1);
            assert_eq!(
                (got[0].from_pid, got[0].from_surface),
                (f.x1.pid, Surface::Codex)
            );
            assert!(
                f.inbox_of(f.claude(1)).len() == 1,
                "bravo still holds only its own"
            );
        }

        #[test]
        fn matrix_inboxes_are_isolated_across_all_four_sessions() {
            let f = fix();
            f.send(f.claude(0), f.rcp_claude(1), "to c2", T0);
            f.send(f.claude(1), Fix::rcp_codex(&f.x1), "to x1", T0 + 1);
            f.send(
                f.codex_caller(&f.x1),
                Fix::rcp_codex(&f.x2),
                "to x2",
                T0 + 2,
            );
            f.send(f.codex_caller(&f.x2), f.rcp_claude(0), "to c1", T0 + 3);
            let body = |v: Vec<MessageView>| -> Vec<String> {
                v.iter().map(|m| m.framed_body.clone()).collect()
            };
            for (who, want) in [
                (f.claude(0), "to c1"),
                (f.claude(1), "to c2"),
                (f.codex_caller(&f.x1), "to x1"),
                (f.codex_caller(&f.x2), "to x2"),
            ] {
                let got = body(f.inbox_of(who));
                assert_eq!(got.len(), 1, "{want}: {got:?}");
                assert!(got[0].contains(want), "{want}: {got:?}");
            }
        }
    }
}
