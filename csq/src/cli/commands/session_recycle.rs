//! `csq session recycle` / `csq session memory` (spec 36).
//!
//! A recycle names the CURRENT terminal by default, resolved through the same admission helper as
//! `csq sessions name` ([`csq_core::sessions::resolve_caller_from_env`]). `--to` names ANOTHER
//! session instead: that ask goes over the daemon's Unix socket (design
//! `internal-design-docs` §B), is fresh-only, and
//! has NO fallback that writes the target's request file — a refused ask writes nothing.

use anyhow::Result;
use csq_core::session::recycle::{
    self, check_idle, check_supervised, now_rfc3339, validate_reason, validate_session_id,
    verify_session_binding, Mode, SessionProbe, Tag,
};
/// The requester record the daemon re-derives; built only by the socket path.
#[cfg(unix)]
use csq_core::session::recycle_consent::RequesterRecord;
use csq_core::session::recycle_foreign;
#[cfg(unix)]
use csq_core::session::recycle_foreign::{ForeignAsk, Issued, Reply};
use std::path::{Path, PathBuf};

/// The one daemon route a foreign ask may take (design §B). Unix-only, like the socket it
/// rides on: on Windows this const has no caller and would trip `dead_code` under `-D warnings`.
#[cfg(unix)]
const FOREIGN_ROUTE: &str = "/api/recycle/foreign";
/// The transport refusal when the daemon answers with something we cannot use (a version-skewed
/// 404, a truncated body, a tag this build does not know). Distinct from
/// `xrecycle_daemon_unavailable`, which is A4's "the daemon is not running".
///
/// Unix-only, like the transport that produces it: no Windows caller exists.
#[cfg(unix)]
const INVALID_REPLY: Tag = "xrecycle_daemon_response_invalid";

/// The testable core of `csq session recycle`: every refusal is a fixed tag.
/// `resolve` yields `(handle dir, claude pid)` of the calling Claude Code terminal.
pub(crate) fn queue(
    resolve: &dyn Fn() -> Result<(PathBuf, u32), Tag>,
    probe: &dyn SessionProbe,
    session_id: Option<&str>,
    reason: Option<&str>,
    fresh: bool,
    now: &str,
) -> Result<&'static str, Tag> {
    let id = session_id.ok_or("recycle_session_id_required")?;
    validate_session_id(id)?;
    let reason = reason.unwrap_or("");
    validate_reason(reason)?;
    let (handle, claude_pid) = resolve()?;
    check_supervised(&handle, claude_pid)?;
    check_idle(&handle)?;
    // The id must be the conversation THIS terminal's claude runs (Claude Code's own
    // registry), not merely a transcript that exists in the shared projects dir.
    verify_session_binding(probe, claude_pid, &handle, id)?;
    // A fresh request's VERB-SIDE precondition is the HANDOVER alone: written and stamped for
    // THIS session. The committed boundary is deliberately NOT checked here — it can only be
    // true after the Stop that ENDS the requesting turn, and a session asks mid-turn (last
    // event PostToolUse). The full readiness predicate is re-run by the SUPERVISOR at the
    // quiet point (`recycle_supervise.rs`), after that Stop, where it can pass.
    if fresh {
        recycle::handover_written_at(&handle, id)?;
    }
    let mode = if fresh { Mode::Fresh } else { Mode::Resume };
    // The write re-checks idle UNDER the per-target lock the daemon's foreign issue holds, so a
    // foreign request issued after the check above cannot be overwritten by this one (nor the
    // reverse). The early `check_idle` stays: it refuses before the handover gate and the
    // consent-lock write are attempted at all.
    recycle::queue_request_locked(&handle, id, reason, now, mode)?;
    Ok("queued")
}

/// The caller-side ports of a foreign ask, grouped so the seam stays readable: the caller's own
/// identity (`resolve` + `start_of` + `own_session`) and the daemon transport (`post`).
#[cfg(unix)]
pub(crate) struct ForeignPorts<'a> {
    /// The CALLER's `(handle dir, claude pid)`.
    pub resolve: &'a dyn Fn() -> Result<(PathBuf, u32), Tag>,
    /// That pid's start time (the second half of the design §A.2 identity). Production passes
    /// [`csq_core::sessions::ancestor_start`] — the FULL-PRECISION reader the ancestry walk
    /// requires — never the one-second `process_start_time`.
    pub start_of: &'a dyn Fn(u32) -> Option<u64>,
    /// That process's own registry row — never a self-chosen id.
    pub own_session: &'a dyn Fn(u32, &Path) -> Result<String, Tag>,
    /// The daemon transport.
    pub post: &'a dyn Fn(&str) -> Result<Reply, Tag>,
}

/// The testable core of `csq session recycle --to`: every refusal is a fixed tag, and the ask that
/// reaches `ports.post` carries only fields the daemon itself re-derives and re-checks.
///
/// Unix-only: its only production caller is the socket arm of `recycle_foreign`.
#[cfg(unix)]
pub(crate) fn foreign_queue(
    ports: &ForeignPorts<'_>,
    target_handle: &str,
    target_session: Option<&str>,
    reason: Option<&str>,
    fresh: bool,
) -> Result<Issued, Tag> {
    // Argument shape first: nothing is resolved or sent for an ask this CLI cannot honour.
    let target_session = target_session.ok_or("recycle_session_id_required")?;
    validate_session_id(target_session)?;
    // No free text crosses into another session's request file (design §B: `reason` stays empty).
    if reason.is_some() {
        return Err("recycle_reason_not_accepted");
    }
    // A foreign request is FRESH-only (AC 6). Requiring the flag keeps the intent explicit:
    // omitting it must never quietly turn a resume expectation into a fresh restart.
    if !fresh {
        return Err("recycle_foreign_requires_fresh");
    }
    if !Path::new(target_handle).is_absolute() {
        return Err("recycle_target_handle_invalid");
    }
    let (handle, pid) = (ports.resolve)()?;
    // Pid AND start time, both read now (design §A.2): the daemon matches the start time at the
    // ancestor hop that reaches the requester, so a recycled pid cannot stand in for it. A pid
    // whose start time cannot be read is refused rather than sent without one.
    let start = (ports.start_of)(pid).ok_or("xrecycle_requester_unverified")?;
    // The requester's identity is the conversation ITS OWN registry row names — the daemon
    // re-derives the same row before it acts (§B step 1), so a mislabelled caller is refused
    // there too.
    let own = (ports.own_session)(pid, &handle)?;
    let ask = ForeignAsk {
        target_handle: target_handle.to_string(),
        target_session: target_session.to_string(),
        requester: RequesterRecord {
            session_id: own,
            handle: handle.display().to_string(),
        },
        requester_pid: pid,
        requester_start: Some(start),
        ttl_secs: None,
    };
    let body = serde_json::to_string(&ask).map_err(|_| INVALID_REPLY)?;
    let reply = (ports.post)(&body)?;
    match (reply.ok, reply.issued) {
        (true, Some(issued)) => Ok(issued),
        // `ok` with no nonce is a reply we cannot act on, never a success.
        (true, None) => Err(INVALID_REPLY),
        (false, _) => Err(known_tag(reply.tag.as_deref().unwrap_or_default())),
    }
}

/// The fixed vocabulary a reply may name (design §E). A tag this build does not know — a newer
/// daemon's, or a corrupted body — is NOT echoed to the terminal; it is a malformed reply.
///
/// Unix-only: both callers are the socket path.
#[cfg(unix)]
fn known_tag(tag: &str) -> Tag {
    const KNOWN: &[Tag] = &[
        "xrecycle_requester_unverified",
        "xrecycle_requester_surface_unsupported",
        "xrecycle_consent_expired",
        "xrecycle_consent_spent",
        "xrecycle_not_consented",
        "xrecycle_target_not_supervised",
        "xrecycle_target_mismatch",
        "xrecycle_target_busy",
        "xrecycle_request_stale",
        "xrecycle_replay",
        "xrecycle_rate_limited",
        "xrecycle_target_exited",
        // Target-side conditions the daemon reports verbatim: the target's consent file is
        // unreadable, or the daemon could not write into the target's handle dir.
        "xrecycle_consent_unreadable",
        "recycle_serialize_failed",
        "recycle_file_write_failed",
        recycle_foreign::DAEMON_UNAVAILABLE,
    ];
    KNOWN
        .iter()
        .copied()
        .find(|k| *k == tag)
        .unwrap_or(INVALID_REPLY)
}

/// Maps the CLI↔daemon transport onto the fixed vocabulary. A daemon we cannot reach is A4's
/// `xrecycle_daemon_unavailable`; one that answers with anything unusable is
/// `xrecycle_daemon_response_invalid`. Neither path writes the request file — the socket is the
/// only entry point, so a down daemon means the ask did not happen (A4).
#[cfg(unix)]
fn map_transport(
    r: Result<
        csq_core::daemon::client::DaemonResponse,
        csq_core::daemon::client::DaemonClientError,
    >,
) -> Result<Reply, Tag> {
    use csq_core::daemon::client::DaemonClientError;
    match r {
        Ok(resp) if (200..300).contains(&resp.status) => {
            serde_json::from_str(&resp.body).map_err(|_| INVALID_REPLY)
        }
        Ok(_) => Err(INVALID_REPLY),
        Err(DaemonClientError::Connect(_) | DaemonClientError::Io(_)) => {
            Err(recycle_foreign::DAEMON_UNAVAILABLE)
        }
        Err(_) => Err(INVALID_REPLY),
    }
}

/// Used only by the unix registry probes; on Windows it has no caller.
#[cfg(unix)]
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Prints the verb's one-word outcome, or the fixed tag, and exits 1 — the shape every recycle
/// verb reports in.
fn report(r: Result<String, Tag>) -> Result<()> {
    match r {
        Ok(line) => {
            println!("{line}");
            Ok(())
        }
        Err(tag) => {
            eprintln!("error: {tag}");
            std::process::exit(1);
        }
    }
}

/// Windows has no supervisor, so the registry is never consulted (`check_supervised` refuses first).
#[cfg(not(unix))]
struct NoRegistry;
#[cfg(not(unix))]
impl SessionProbe for NoRegistry {
    fn session_id_of(&self, _: u32, _: Option<&Path>) -> Result<String, Tag> {
        Err("recycle_session_unknown")
    }
    fn held_by_other(&self, _: &str, _: u32) -> Result<bool, Tag> {
        Err("recycle_session_unknown")
    }
}

fn resolve_current() -> Result<(PathBuf, u32), Tag> {
    // The listed-session arm, reduced to the three outcomes the decision needs.
    let listed = || match csq_core::sessions::resolve_caller_from_env() {
        Ok(caller) if caller.kind() == csq_core::sessions::CliKind::Claude => {
            Listed::Resolved(caller.handle_dir().to_path_buf(), caller.pid())
        }
        Ok(_) => Listed::Refused("recycle_surface_unsupported"),
        // The ONLY retryable class: the listing was complete and positively carries no row
        // for this handle dir — the shape a HEADLESS session has (no controlling terminal,
        // so the lister never makes it a row). Every other class is a DECISION, not a gap:
        // `TargetMismatch` means a nearer session sits between (retrying would let a nested
        // session recycle its parent), and `Undetermined` means the process table could not
        // be read — retrying would bypass exactly the gate that refused it.
        Err(e) => classify_listed_error(&e),
    };
    resolve_current_with(std::env::var_os("CLAUDE_CONFIG_DIR"), &listed, &|dir| {
        csq_core::session::recycle::resolve_headless_caller(
            dir,
            &csq_core::session::recycle::read_supervisor,
            &csq_core::sessions::ancestor_path_of_current,
            &csq_core::sessions::hop_is_session,
        )
    })
}

/// What the listed-session resolution decided, reduced to the three outcomes the caller
/// decision distinguishes.
enum Listed {
    /// A live session owns this handle dir; its `(handle dir, claude pid)`.
    Resolved(PathBuf, u32),
    /// The listing is COMPLETE and positively carries no row for this handle dir.
    Unlisted,
    /// A positive refusal (nested session, unreadable table, wrong surface) — never retried.
    Refused(Tag),
}

/// The caller decision with its inputs and ports injected, so every branch is testable
/// without process-global environment or a live process tree.
fn resolve_current_with(
    handle_var: Option<std::ffi::OsString>,
    listed: &dyn Fn() -> Listed,
    headless: &dyn Fn(&Path) -> Result<u32, Tag>,
) -> Result<(PathBuf, u32), Tag> {
    match listed() {
        Listed::Resolved(dir, pid) => Ok((dir, pid)),
        Listed::Refused(tag) => Err(tag),
        Listed::Unlisted => {
            let dir = handle_var
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .ok_or("recycle_caller_undetermined")?;
            headless(&dir).map(|pid| (dir, pid))
        }
    }
}

/// The resolver's error, classified for the caller decision. Extracted from the closure so the
/// rule that decides "retry by another proof or refuse" is testable on its own: a future edit
/// that sent `TargetMismatch` to `Unlisted` would otherwise pass every other test — that swap
/// is exactly the nesting hole this class split exists to close.
fn classify_listed_error(e: &csq_core::sessions::CallerError) -> Listed {
    match e {
        csq_core::sessions::CallerError::HandleDirUnlisted => Listed::Unlisted,
        other => Listed::Refused(caller_tag(other)),
    }
}

/// The caller resolver's diagnosis as a fixed-vocabulary tag. The `Undetermined` REASON
/// string is deliberately dropped: it is free text that can name a path, and the operator
/// only needs the class.
fn caller_tag(e: &csq_core::sessions::CallerError) -> Tag {
    match e {
        csq_core::sessions::CallerError::TargetMismatch => "recycle_caller_target_mismatch",
        csq_core::sessions::CallerError::Undetermined(_) => "recycle_caller_undetermined",
        // Unreachable from `resolve_current` (that class is routed to `Listed::Unlisted`
        // before it gets here); kept so this match stays EXHAUSTIVE if a future caller
        // passes a raw resolver error.
        csq_core::sessions::CallerError::HandleDirUnlisted => "recycle_caller_undetermined",
    }
}

/// `csq session recycle --session-id <uuid> [--reason <text>] [--fresh]`.
pub fn recycle(
    base_dir: &Path,
    session_id: Option<&str>,
    reason: Option<&str>,
    fresh: bool,
) -> Result<()> {
    #[cfg(unix)]
    let probe = recycle::RegistryProbe {
        base: base_dir.to_path_buf(),
        home: home_dir(),
    };
    #[cfg(not(unix))]
    let probe = {
        let _ = base_dir;
        NoRegistry
    };
    report(
        queue(
            &resolve_current,
            &probe,
            session_id,
            reason,
            fresh,
            &now_rfc3339(),
        )
        .map(str::to_string),
    )
}

/// `csq session recycle --to <target handle> --session-id <target session> --fresh`.
pub fn recycle_foreign(
    base_dir: &Path,
    target_handle: &str,
    target_session: Option<&str>,
    reason: Option<&str>,
    fresh: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        let probe = recycle::RegistryProbe {
            base: base_dir.to_path_buf(),
            home: home_dir(),
        };
        let sock = csq_core::daemon::paths::socket_path(base_dir);
        let own = |pid: u32, handle: &Path| probe.session_id_of(pid, Some(handle));
        let post = |body: &str| {
            map_transport(csq_core::daemon::client::http_post_unix_json(
                &sock,
                FOREIGN_ROUTE,
                body,
            ))
        };
        report(
            foreign_queue(
                &ForeignPorts {
                    resolve: &resolve_current,
                    start_of: &csq_core::sessions::ancestor_start,
                    own_session: &own,
                    post: &post,
                },
                target_handle,
                target_session,
                reason,
                fresh,
            )
            .map(|_| "queued".to_string()),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (base_dir, target_handle, target_session, reason, fresh);
        // No Unix socket and no supervised session on this platform: the ask cannot be made.
        report(Err(recycle_foreign::DAEMON_UNAVAILABLE))
    }
}

/// `csq session consent` — the TARGET's own opt-in for a cross-session recycle (design §A, A1).
///
/// Run from the TARGET's terminal. The consent is written into the CALLER's own handle dir and
/// bound to the caller's CURRENT session id, so a peer can never grant consent on the target's
/// behalf and a `/clear` voids a stale grant. The named requester record (session id + handle)
/// is verified against Claude Code's own registry before it is stored.
pub(crate) fn consent(
    base_dir: &Path,
    to: Option<&str>,
    requester_handle: Option<&str>,
    ttl_secs: Option<i64>,
    max_uses: Option<u32>,
    revoke: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        report(consent_inner(
            base_dir,
            to,
            requester_handle,
            ttl_secs,
            max_uses,
            revoke,
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = (base_dir, to, requester_handle, ttl_secs, max_uses, revoke);
        // The daemon route that consumes a consent is Unix-only; there is nothing to grant for.
        report(Err(recycle_foreign::DAEMON_UNAVAILABLE))
    }
}

/// The consent verb's ports, so its ORDERING is testable without a real registry or terminal:
/// revocation must not need a live session, and the requester verification must run before the
/// lock the daemon's issue-time spend contends for.
#[cfg(unix)]
pub(crate) struct ConsentPorts<'a> {
    /// The CALLER's `(handle dir, claude pid)`.
    pub resolve: &'a dyn Fn() -> Result<(PathBuf, u32), Tag>,
    /// The session the caller's pid runs NOW, when the registry knows it.
    pub own_session: &'a dyn Fn(u32, &Path) -> Option<String>,
    /// Whether the named requester record is a LIVE conversation.
    pub verify: &'a dyn Fn(&str, &Path) -> Result<(), Tag>,
}

#[cfg(unix)]
fn consent_inner(
    base_dir: &Path,
    to: Option<&str>,
    requester_handle: Option<&str>,
    ttl_secs: Option<i64>,
    max_uses: Option<u32>,
    revoke: bool,
) -> Result<String, Tag> {
    let ports = ConsentPorts {
        resolve: &resolve_current,
        own_session: &|pid, handle| {
            csq_core::sessions::lifecycle::registry_session_id(
                pid,
                base_dir,
                &home_dir(),
                Some(handle),
            )
        },
        verify: &|session_id, handle| verify_requester_record(base_dir, session_id, handle),
    };
    consent_with(&ports, to, requester_handle, ttl_secs, max_uses, revoke)
}

#[cfg(unix)]
fn consent_with(
    ports: &ConsentPorts<'_>,
    to: Option<&str>,
    requester_handle: Option<&str>,
    ttl_secs: Option<i64>,
    max_uses: Option<u32>,
    revoke: bool,
) -> Result<String, Tag> {
    use csq_core::session::recycle_consent as consent_mod;

    let (handle, pid) = (ports.resolve)()?;
    // Serialize with the daemon's issue-time spend. Bounded: a wedged holder is a refusal.
    let take_lock = || {
        csq_core::platform::lock::try_lock_file_bounded_nofollow(
            &consent_mod::consent_lock_path(&handle),
            50,
            std::time::Duration::from_millis(20),
        )
        .map_err(|_| "xrecycle_consent_unreadable")?
        .ok_or("xrecycle_consent_unreadable")
    };

    if revoke {
        // Revocation is keyed by the handle dir ALONE: a crashed or `/clear`ed conversation
        // still has a consent to withdraw, so it must not require a registry row.
        let _lock = take_lock()?;
        return if consent_mod::revoke_consent(&handle) {
            Ok("consent revoked".to_string())
        } else {
            Err("xrecycle_consent_unreadable")
        };
    }

    // A GRANT binds to the conversation this terminal runs NOW.
    let own = (ports.own_session)(pid, &handle).ok_or("recycle_session_unknown")?;
    let now = chrono::Utc::now().timestamp();
    // Verify and build BEFORE the lock: the requester check walks the whole process table and
    // must not hold the lock a concurrent foreign issue contends for.
    let record = consent_record(
        &own,
        to,
        requester_handle,
        ttl_secs,
        max_uses,
        now,
        ports.verify,
    )?;
    let _lock = take_lock()?;
    consent_mod::write_consent(&handle, &record)?;
    // Fixed wording only: no paths, no tokens.
    Ok(format!(
        "consent granted: max_uses={} ttl_secs={}",
        record.max_uses,
        record.expires_at_unix.saturating_sub(now)
    ))
}

/// The pure half of a grant: validate the named requester, verify it, and build the record.
#[cfg(unix)]
fn consent_record(
    own_session: &str,
    to: Option<&str>,
    requester_handle: Option<&str>,
    ttl_secs: Option<i64>,
    max_uses: Option<u32>,
    now_unix: i64,
    verify: &dyn Fn(&str, &Path) -> Result<(), Tag>,
) -> Result<csq_core::session::recycle_consent::ConsentRecord, Tag> {
    use csq_core::session::recycle_consent as consent_mod;

    let to = to.ok_or("xrecycle_consent_requires_requester")?;
    recycle::validate_session_id(to)?;
    let requester_handle = requester_handle.ok_or("xrecycle_consent_requires_requester")?;
    let requester_handle = Path::new(requester_handle);
    if !requester_handle.is_absolute() {
        return Err("xrecycle_requester_unverified");
    }
    // Store the CANONICAL spelling. The registry comparison canonicalizes both sides, so a
    // grant stored as typed (a symlink or `/tmp` vs `/private/tmp` spelling) would verify at
    // grant time and then never match at issue time — a fail-closed but undiagnosable trap.
    let requester_handle =
        std::fs::canonicalize(requester_handle).unwrap_or_else(|_| requester_handle.to_path_buf());
    let requester_handle = requester_handle.as_path();
    verify(to, requester_handle)?;
    let ttl = ttl_secs
        .unwrap_or(consent_mod::DEFAULT_CONSENT_TTL_SECS)
        .clamp(1, consent_mod::MAX_CONSENT_TTL_SECS);
    Ok(consent_mod::ConsentRecord {
        v: consent_mod::CONSENT_VERSION,
        target_session_id: own_session.to_string(),
        allow: vec![consent_mod::RequesterRecord {
            session_id: to.to_string(),
            handle: requester_handle.display().to_string(),
        }],
        expires_at_unix: now_unix.saturating_add(ttl),
        // Floored AND capped: a typo must neither mint a zero-use grant nor an effectively
        // unlimited one (R2 L4).
        max_uses: max_uses
            .unwrap_or(1)
            .clamp(1, consent_mod::MAX_CONSENT_USES),
        used: 0,
    })
}

/// Whether `session_id` + `handle` name a LIVE Claude conversation in Claude Code's registry.
///
/// The record is machine-checkable, never a self-chosen label: the pid must carry a registry row
/// naming exactly this session id and handle dir.
#[cfg(unix)]
fn verify_requester_record(base_dir: &Path, session_id: &str, handle: &Path) -> Result<(), Tag> {
    let home = home_dir();
    for info in csq_core::sessions::list() {
        if csq_core::sessions::lifecycle::registry_session_id(
            info.pid,
            base_dir,
            &home,
            Some(handle),
        )
        .is_some_and(|actual| actual == session_id)
        {
            return Ok(());
        }
    }
    Err("xrecycle_requester_unverified")
}

/// Human / JSON view of a memory record (the same fields the statusline and doctor read).
pub(crate) fn memory_view(handle: &Path, json: bool) -> String {
    let now = now_rfc3339();
    match recycle::read_memory(handle) {
        Ok(Some(_)) if recycle::fresh_memory(handle, &now).is_none() => {
            "memory_sample_stale".to_string()
        }
        Ok(Some(rec)) if json => serde_json::to_string(&rec).unwrap_or_default(),
        Ok(Some(rec)) => match rec.rss_bytes {
            Some(n) => format!(
                "{:?}: rss {:.2} GiB (warn at {:.2} GiB), sampled {}",
                rec.state,
                n as f64 / (1u64 << 30) as f64,
                rec.warn_bytes as f64 / (1u64 << 30) as f64,
                rec.sampled_at
            ),
            None => format!(
                "Unknown: {} (sampled {})",
                rec.tag.as_deref().unwrap_or("memory_sample_failed"),
                rec.sampled_at
            ),
        },
        Ok(None) => "memory_not_sampled".to_string(),
        Err(tag) => tag.to_string(),
    }
}

/// `csq session memory [--json]`.
pub fn memory(json: bool) -> Result<()> {
    if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
        println!("rss_unsupported_platform");
        return Ok(());
    }
    match super::current_config_dir() {
        Some(handle) => println!("{}", memory_view(&handle, json)),
        None => println!("memory_not_sampled"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    struct P {
        own: Result<String, Tag>,
        shared: Result<bool, Tag>,
    }
    impl SessionProbe for P {
        fn session_id_of(&self, _: u32, _: Option<&Path>) -> Result<String, Tag> {
            self.own.clone()
        }
        fn held_by_other(&self, _: &str, _: u32) -> Result<bool, Tag> {
            self.shared
        }
    }
    fn ok_probe() -> P {
        P {
            own: Ok(ID.into()),
            shared: Ok(false),
        }
    }

    fn supervised_handle() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let h = d.path().to_path_buf();
        recycle::write_supervisor(&h, 4242, Ok(()), &h).unwrap();
        (d, h)
    }

    #[test]
    fn no_session_id_is_refused_before_anything_else() {
        let called = std::cell::Cell::new(false);
        let r = || {
            called.set(true);
            Err("never")
        };
        assert_eq!(
            queue(&r, &ok_probe(), None, None, false, "t"),
            Err("recycle_session_id_required")
        );
        assert!(!called.get(), "must not even resolve the caller");
    }

    #[test]
    fn fresh_is_refused_before_anything_is_queued() {
        // The verb-side gate is the HANDOVER: no record ⇒ refused, and nothing is queued.
        // (Full readiness — including the committed boundary — is the supervisor's check at
        // the quiet point, where it can actually pass.)
        let (_d, h) = supervised_handle();
        let r = || Ok((h.clone(), 4242));
        assert_eq!(
            queue(&r, &ok_probe(), Some(ID), None, true, "t"),
            Err("recycle_handover_unreadable")
        );
        assert!(
            !h.join(recycle::REQUEST_FILE).exists(),
            "a refused fresh request writes nothing"
        );
    }

    #[test]
    fn each_caller_error_class_reports_its_own_fixed_tag() {
        use csq_core::sessions::CallerError;
        // The classes must stay DISTINGUISHABLE: `TargetMismatch` is a decision (a nearer
        // session sits between), and the headless retry must never be reachable from it.
        assert_eq!(
            caller_tag(&CallerError::TargetMismatch),
            "recycle_caller_target_mismatch"
        );
        assert_eq!(
            caller_tag(&CallerError::Undetermined("free text".into())),
            "recycle_caller_undetermined"
        );
        assert_eq!(
            caller_tag(&CallerError::HandleDirUnlisted),
            "recycle_caller_undetermined"
        );
    }

    #[test]
    fn only_the_unlisted_class_is_retryable() {
        use csq_core::sessions::CallerError;
        // The classification ITSELF is the security rule: swapping any of these three would
        // reopen the nesting hole or block the headless path, and every other test would
        // still pass.
        assert!(matches!(
            classify_listed_error(&CallerError::HandleDirUnlisted),
            Listed::Unlisted
        ));
        assert!(matches!(
            classify_listed_error(&CallerError::TargetMismatch),
            Listed::Refused("recycle_caller_target_mismatch")
        ));
        assert!(matches!(
            classify_listed_error(&CallerError::Undetermined("why".into())),
            Listed::Refused("recycle_caller_undetermined")
        ));
    }

    #[test]
    fn the_headless_fallback_is_reachable_only_from_the_unlisted_class() {
        use std::cell::Cell;
        use std::ffi::OsString;
        let calls = Cell::new(0u32);
        let headless = |_d: &Path| {
            calls.set(calls.get() + 1);
            Ok(4242u32)
        };
        // A platform-absolute handle dir: "/tmp/handle" is relative on Windows, where the
        // resolver correctly refuses it as undetermined.
        let abs = std::env::temp_dir().join("handle");
        let dir = abs.clone().into_os_string();

        // 1. The listed path wins and the fallback is never consulted.
        let listed = || Listed::Resolved(abs.clone(), 11);
        assert_eq!(
            resolve_current_with(Some(dir.clone()), &listed, &headless),
            Ok((abs.clone(), 11))
        );
        assert_eq!(
            calls.get(),
            0,
            "a listed session must not reach the fallback"
        );

        // 2. A nested session (TargetMismatch) and the both-env/undetermined classes arrive
        //    as Refused: refused with their tag, and the fallback is NOT reached — this is
        //    the branch that would otherwise let a nested session recycle its parent.
        let nested = || Listed::Refused("recycle_caller_target_mismatch");
        assert_eq!(
            resolve_current_with(Some(dir.clone()), &nested, &headless),
            Err("recycle_caller_target_mismatch")
        );
        let undetermined = || Listed::Refused("recycle_caller_undetermined");
        assert_eq!(
            resolve_current_with(Some(dir.clone()), &undetermined, &headless),
            Err("recycle_caller_undetermined")
        );
        assert_eq!(calls.get(), 0, "a positive refusal must never be retried");

        // 3. Unlisted + an absolute handle dir: the headless proof runs.
        let unlisted = || Listed::Unlisted;
        assert_eq!(
            resolve_current_with(Some(dir.clone()), &unlisted, &headless),
            Ok((abs.clone(), 4242))
        );
        assert_eq!(calls.get(), 1);

        // 4. Unlisted with no environment, or a RELATIVE one: refused, proof not attempted.
        assert_eq!(
            resolve_current_with(None, &unlisted, &headless),
            Err("recycle_caller_undetermined")
        );
        assert_eq!(
            resolve_current_with(Some(OsString::from("relative/dir")), &unlisted, &headless),
            Err("recycle_caller_undetermined")
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_fresh_request_no_longer_needs_the_markers_project_root() {
        // The verb used to read the supervisor marker's `cwd` to find the readiness CLI.
        // That call moved to the supervisor (which uses its own launch cwd), so a marker
        // written before the fresh contract — no `cwd` — must no longer refuse the request;
        // only the handover gate decides here.
        let (_d, h) = supervised_handle();
        let p = h.join(recycle::SUPERVISOR_FILE);
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("cwd");
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        std::fs::write(
            h.join("coc-context-state.json"),
            serde_json::to_vec(&serde_json::json!({
                "handover": {"state": "written", "seed_sha256": "a".repeat(64), "session_id": ID}
            }))
            .unwrap(),
        )
        .unwrap();
        let r = || Ok((h.clone(), 4242));
        assert_eq!(
            queue(&r, &ok_probe(), Some(ID), None, true, "t"),
            Ok("queued")
        );
    }

    #[test]
    fn bad_id_or_reason_is_refused() {
        let (_d, h) = supervised_handle();
        let r = || Ok((h.clone(), 4242));
        let p = ok_probe();
        assert_eq!(
            queue(&r, &p, Some("--continue"), None, false, "t"),
            Err("recycle_session_id_invalid")
        );
        assert_eq!(
            queue(&r, &p, Some(ID), Some("a\nb"), false, "t"),
            Err("recycle_reason_invalid")
        );
        assert_eq!(
            queue(&r, &p, Some(ID), Some(&"x".repeat(201)), false, "t"),
            Err("recycle_reason_invalid")
        );
        assert!(!h.join(recycle::REQUEST_FILE).exists());
    }

    #[test]
    fn unsupervised_terminal_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let r = || Ok((d.path().to_path_buf(), 4242));
        let p = ok_probe();
        assert_eq!(
            queue(&r, &p, Some(ID), None, false, "t"),
            Err("recycle_unsupervised")
        );
        assert!(!d.path().join(recycle::REQUEST_FILE).exists());
        // A marker for a different claude pid is also unsupervised.
        recycle::write_supervisor(d.path(), 1, Ok(()), d.path()).unwrap();
        assert_eq!(
            queue(&r, &p, Some(ID), None, false, "t"),
            Err("recycle_unsupervised")
        );
    }

    #[test]
    fn a_launch_with_unclassifiable_argv_is_refused_up_front() {
        let d = tempfile::tempdir().unwrap();
        recycle::write_supervisor(d.path(), 4242, Err("recycle_argv_unclassifiable"), d.path())
            .unwrap();
        let r = || Ok((d.path().to_path_buf(), 4242));
        assert_eq!(
            queue(&r, &ok_probe(), Some(ID), None, false, "t"),
            Err("recycle_argv_unclassifiable")
        );
        assert!(!d.path().join(recycle::REQUEST_FILE).exists());
    }

    #[test]
    fn a_session_id_that_is_not_this_terminals_own_is_refused() {
        let (_d, h) = supervised_handle();
        let r = || Ok((h.clone(), 4242));
        let foreign = P {
            own: Ok(OTHER.into()),
            shared: Ok(false),
        };
        assert_eq!(
            queue(&r, &foreign, Some(ID), None, false, "t"),
            Err("recycle_session_id_mismatch")
        );
        let unknown = P {
            own: Err("recycle_session_unknown"),
            shared: Ok(false),
        };
        assert_eq!(
            queue(&r, &unknown, Some(ID), None, false, "t"),
            Err("recycle_session_unknown")
        );
        let shared = P {
            own: Ok(ID.into()),
            shared: Ok(true),
        };
        assert_eq!(
            queue(&r, &shared, Some(ID), None, false, "t"),
            Err("recycle_session_id_shared")
        );
        assert!(
            !h.join(recycle::REQUEST_FILE).exists(),
            "nothing queued for any of them"
        );
    }

    #[test]
    fn a_second_request_while_one_is_queued_is_refused() {
        let (_d, h) = supervised_handle();
        let r = || Ok((h.clone(), 4242));
        assert_eq!(
            queue(&r, &ok_probe(), Some(ID), None, false, "t"),
            Ok("queued")
        );
        assert_eq!(
            queue(&r, &ok_probe(), Some(ID), None, false, "t"),
            Err("recycle_already_queued")
        );
    }

    #[test]
    fn unresolvable_caller_is_refused() {
        let r = || Err("recycle_caller_unresolved");
        assert_eq!(
            queue(&r, &ok_probe(), Some(ID), None, false, "t"),
            Err("recycle_caller_unresolved")
        );
    }

    // ── `--to`: the requester side of a cross-session ask (design §B, A4) ──────────

    #[cfg(unix)]
    fn reply_ok() -> Reply {
        Reply {
            ok: true,
            tag: None,
            issued: Some(Issued {
                nonce: "0123456789abcdef0123456789abcdef".into(),
                expires_at_unix: 1_000,
            }),
        }
    }

    #[cfg(unix)]
    fn reply_tag(t: &str) -> Reply {
        Reply {
            ok: false,
            tag: Some(t.into()),
            issued: None,
        }
    }

    /// The caller's start time the CLI sends; the daemon checks it at the chain hop.
    #[cfg(unix)]
    fn start_of(_: u32) -> Option<u64> {
        Some(1_700_000_000)
    }

    /// Build the ports with the standard start-time stub.
    #[cfg(unix)]
    fn ports<'a>(
        resolve: &'a dyn Fn() -> Result<(PathBuf, u32), Tag>,
        own_session: &'a dyn Fn(u32, &Path) -> Result<String, Tag>,
        post: &'a dyn Fn(&str) -> Result<Reply, Tag>,
    ) -> ForeignPorts<'a> {
        ForeignPorts {
            resolve,
            start_of: &start_of,
            own_session,
            post,
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_foreign_ask_is_fresh_only_and_carries_no_free_text() {
        // Every refusal here happens before anything is resolved or sent.
        let touched = std::cell::Cell::new(false);
        let resolved = || {
            touched.set(true);
            Err("never")
        };
        let own = |_: u32, _: &Path| {
            touched.set(true);
            Err("never")
        };
        let post = |_: &str| {
            touched.set(true);
            Err("never")
        };
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &own, &post),
                "/h/target",
                Some(ID),
                None,
                false
            ),
            Err("recycle_foreign_requires_fresh")
        );
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &own, &post),
                "/h/target",
                Some(ID),
                Some("rss 3G"),
                true
            ),
            Err("recycle_reason_not_accepted")
        );
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &own, &post),
                "/h/target",
                None,
                None,
                true
            ),
            Err("recycle_session_id_required")
        );
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &own, &post),
                "/h/target",
                Some("--continue"),
                None,
                true
            ),
            Err("recycle_session_id_invalid")
        );
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &own, &post),
                "relative",
                Some(ID),
                None,
                true
            ),
            Err("recycle_target_handle_invalid")
        );
        assert!(
            !touched.get(),
            "nothing may be resolved or sent for an ask this CLI refuses"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_foreign_ask_carries_the_callers_own_registry_identity_and_the_named_target() {
        let sent = std::cell::RefCell::new(String::new());
        let seen = std::cell::RefCell::new((0u32, String::new()));
        let resolved = || Ok((PathBuf::from("/h/me"), 4242));
        let own = |pid: u32, handle: &Path| {
            *seen.borrow_mut() = (pid, handle.display().to_string());
            Ok(OTHER.into())
        };
        let post = |body: &str| {
            *sent.borrow_mut() = body.to_string();
            Ok(reply_ok())
        };
        let issued = foreign_queue(
            &ports(&resolved, &own, &post),
            "/h/target",
            Some(ID),
            None,
            true,
        )
        .unwrap();
        assert_eq!(issued.expires_at_unix, 1_000);
        assert_eq!(
            *seen.borrow(),
            (4242, "/h/me".to_string()),
            "the requester id comes from the CALLER's own registry row"
        );
        let v: serde_json::Value = serde_json::from_str(&sent.borrow()).unwrap();
        assert_eq!(v["target_handle"], "/h/target");
        assert_eq!(v["target_session"], ID);
        assert_eq!(v["requester"]["session_id"], OTHER);
        assert_eq!(v["requester"]["handle"], "/h/me");
        assert_eq!(v["requester_pid"], 4242);
        assert!(
            v["ttl_secs"].is_null(),
            "the TTL is the daemon's default (A2), not a client choice"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_caller_whose_own_session_is_unknown_is_refused_before_the_socket() {
        let posted = std::cell::Cell::new(false);
        let resolved = || Ok((PathBuf::from("/h/me"), 4242));
        let unknown = |_: u32, _: &Path| Err("recycle_session_unknown");
        let post = |_: &str| {
            posted.set(true);
            Ok(reply_ok())
        };
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &unknown, &post),
                "/h/target",
                Some(ID),
                None,
                true
            ),
            Err("recycle_session_unknown")
        );
        assert!(!posted.get(), "nothing is sent for an unidentified caller");
    }

    #[cfg(unix)]
    #[test]
    fn a_caller_whose_start_time_cannot_be_read_is_refused_before_the_socket() {
        // The start time is the anti-reuse half of the identity: without it the daemon cannot
        // match the ancestor hop, so the CLI must not send a pid-only ask.
        let posted = std::cell::Cell::new(false);
        let resolved = || Ok((PathBuf::from("/h/me"), 4242));
        let own = |_: u32, _: &Path| Ok(OTHER.to_string());
        let post = |_: &str| {
            posted.set(true);
            Ok(reply_ok())
        };
        let no_start = ForeignPorts {
            resolve: &resolved,
            start_of: &|_| None,
            own_session: &own,
            post: &post,
        };
        assert_eq!(
            foreign_queue(&no_start, "/h/target", Some(ID), None, true),
            Err("xrecycle_requester_unverified")
        );
        assert!(!posted.get(), "nothing is sent without the start time");
    }

    #[cfg(unix)]
    #[test]
    fn the_daemons_verdict_is_reported_and_an_unknown_tag_is_never_echoed() {
        let resolved = || Ok((PathBuf::from("/h/me"), 4242));
        let own = |_: u32, _: &Path| Ok(OTHER.to_string());
        let refused = |tag: &'static str| {
            let post = move |_: &str| Ok(reply_tag(tag));
            foreign_queue(
                &ports(&resolved, &own, &post),
                "/h/target",
                Some(ID),
                None,
                true,
            )
        };
        assert_eq!(
            refused("xrecycle_not_consented"),
            Err("xrecycle_not_consented")
        );
        assert_eq!(refused("xrecycle_target_busy"), Err("xrecycle_target_busy"));
        // A tag this build does not know — and any arbitrary string — is a malformed reply,
        // never echoed to the terminal.
        assert_eq!(refused("xrecycle_brand_new_tag"), Err(INVALID_REPLY));
        assert_eq!(refused("/etc/passwd"), Err(INVALID_REPLY));
    }

    #[cfg(unix)]
    #[test]
    fn an_ok_reply_without_an_issued_nonce_is_a_malformed_reply_not_a_success() {
        let resolved = || Ok((PathBuf::from("/h/me"), 4242));
        let own = |_: u32, _: &Path| Ok(OTHER.to_string());
        let post = |_: &str| {
            Ok(Reply {
                ok: true,
                tag: None,
                issued: None,
            })
        };
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &own, &post),
                "/h/target",
                Some(ID),
                None,
                true
            ),
            Err(INVALID_REPLY)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_down_daemon_is_unavailable_and_writes_no_request_file() {
        use csq_core::daemon::client::{DaemonClientError, DaemonResponse};
        // A4: the tag names the transport condition exactly.
        let io = || std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "x");
        assert_eq!(
            map_transport(Err(DaemonClientError::Connect(io()))),
            Err(recycle_foreign::DAEMON_UNAVAILABLE)
        );
        assert_eq!(
            map_transport(Err(DaemonClientError::Io(io()))),
            Err(recycle_foreign::DAEMON_UNAVAILABLE)
        );
        // A daemon that ANSWERS unusably is a different condition, never "unavailable".
        assert_eq!(
            map_transport(Err(DaemonClientError::HttpStatus(404))),
            Err(INVALID_REPLY)
        );
        assert_eq!(
            map_transport(Ok(DaemonResponse {
                status: 200,
                body: "not json".into()
            })),
            Err(INVALID_REPLY)
        );
        assert_eq!(
            map_transport(Ok(DaemonResponse {
                status: 200,
                body: serde_json::to_string(&reply_ok()).unwrap()
            })),
            Ok(reply_ok())
        );
        // And no fallback (A4): a refused ask leaves the target's handle dir untouched.
        let d = tempfile::tempdir().unwrap();
        let resolved = || Ok((PathBuf::from("/h/me"), 4242));
        let own = |_: u32, _: &Path| Ok(OTHER.to_string());
        let down = |_: &str| Err(recycle_foreign::DAEMON_UNAVAILABLE);
        assert_eq!(
            foreign_queue(
                &ports(&resolved, &own, &down),
                &d.path().display().to_string(),
                Some(ID),
                None,
                true
            ),
            Err(recycle_foreign::DAEMON_UNAVAILABLE)
        );
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            0,
            "a down daemon must not be answered by writing the request file from this side"
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervised_terminal_queues_a_0600_request() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, h) = supervised_handle();
        let r = || Ok((h.clone(), 4242));
        assert_eq!(
            queue(
                &r,
                &ok_probe(),
                Some(ID),
                Some("rss 3G"),
                false,
                "2026-11-03T00:00:00Z"
            ),
            Ok("queued")
        );
        let p = h.join(recycle::REQUEST_FILE);
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["session_id"], ID);
        assert_eq!(v["reason"], "rss 3G");
        assert_eq!(v["requested_at"], "2026-11-03T00:00:00Z");
        assert!(v["request_id"].as_str().is_some_and(|s| s.len() == 36));
    }

    #[cfg(unix)]
    #[test]
    fn a_consent_names_a_verified_requester_and_bounds_its_use_and_ttl() {
        use csq_core::session::recycle_consent as consent_mod;
        let ok = |_: &str, _: &Path| Ok(());
        let rec = consent_record(ID, Some(OTHER), Some("/h/req"), None, None, 1_000, &ok).unwrap();
        assert_eq!(
            rec.target_session_id, ID,
            "bound to the caller's own session"
        );
        assert_eq!(rec.max_uses, 1, "A1 default is a single use");
        assert_eq!(
            rec.expires_at_unix,
            1_000 + consent_mod::DEFAULT_CONSENT_TTL_SECS
        );
        assert_eq!(rec.allow.len(), 1);
        assert_eq!(rec.allow[0].session_id, OTHER);
        assert_eq!(rec.allow[0].handle, "/h/req");
        assert_eq!(rec.used, 0);
        // A TTL above the cap and a zero use count are clamped, never stored as asked.
        let rec = consent_record(
            ID,
            Some(OTHER),
            Some("/h/req"),
            Some(9_999_999),
            Some(0),
            1_000,
            &ok,
        )
        .unwrap();
        assert_eq!(
            rec.expires_at_unix,
            1_000 + consent_mod::MAX_CONSENT_TTL_SECS
        );
        assert_eq!(rec.max_uses, 1);
        // R2 L4: a typo mints neither a zero-use nor an unlimited grant.
        let rec = consent_record(
            ID,
            Some(OTHER),
            Some("/h/req"),
            None,
            Some(u32::MAX),
            1_000,
            &ok,
        )
        .unwrap();
        assert_eq!(rec.max_uses, consent_mod::MAX_CONSENT_USES);
    }

    #[cfg(unix)]
    #[test]
    fn a_grant_stores_the_canonical_requester_handle() {
        // R2 L7: the registry comparison canonicalizes both sides, so a grant stored as typed
        // (a symlink or `/tmp` vs `/private/tmp` spelling) verifies at grant time and then
        // never matches at issue time — fail-closed but undiagnosable. Store the real path.
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("term-9");
        std::fs::create_dir_all(&real).unwrap();
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let ok = |_: &str, _: &Path| Ok(());
        let rec = consent_record(
            ID,
            Some(OTHER),
            Some(alias.to_str().unwrap()),
            None,
            None,
            1_000,
            &ok,
        )
        .unwrap();
        // The code stores the CANONICAL spelling; a tempdir under a symlinked root (macOS
        // `/tmp` -> `/private/tmp`) differs from `real` textually, so canonicalise the expectation.
        let expected = std::fs::canonicalize(&real).unwrap();
        assert_eq!(rec.allow[0].handle, expected.display().to_string());
    }

    #[cfg(unix)]
    fn consent_ports<'a>(
        resolve: &'a dyn Fn() -> Result<(PathBuf, u32), Tag>,
        own: &'a dyn Fn(u32, &Path) -> Option<String>,
        verify: &'a dyn Fn(&str, &Path) -> Result<(), Tag>,
    ) -> ConsentPorts<'a> {
        ConsentPorts {
            resolve,
            own_session: own,
            verify,
        }
    }

    #[cfg(unix)]
    #[test]
    fn revoking_a_consent_needs_no_live_session() {
        // R2 L3: a crashed or `/clear`ed target must still be able to withdraw its consent.
        use csq_core::session::recycle_consent as consent_mod;
        let d = tempfile::tempdir().unwrap();
        let handle = d.path().to_path_buf();
        let rec = consent_mod::ConsentRecord {
            v: consent_mod::CONSENT_VERSION,
            target_session_id: ID.into(),
            allow: vec![consent_mod::RequesterRecord {
                session_id: OTHER.into(),
                handle: "/h/req".into(),
            }],
            expires_at_unix: chrono::Utc::now().timestamp() + 600,
            max_uses: 1,
            used: 0,
        };
        consent_mod::write_consent(&handle, &rec).unwrap();
        let resolve = || Ok((handle.clone(), 4242));
        let no_session = |_: u32, _: &Path| None;
        let verify = |_: &str, _: &Path| Ok(());
        let ports = consent_ports(&resolve, &no_session, &verify);
        assert_eq!(
            consent_with(&ports, Some(OTHER), Some("/h/req"), None, None, true),
            Ok("consent revoked".to_string()),
            "revocation must not need a registry row"
        );
        assert!(!handle.join(consent_mod::CONSENT_FILE).exists());
        // A GRANT still needs the live session it binds to.
        assert_eq!(
            consent_with(&ports, Some(OTHER), Some("/h/req"), None, None, false),
            Err("recycle_session_unknown")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_grant_verifies_the_requester_before_taking_the_lock() {
        // R2 L5: the requester check walks the whole process table; holding the lock the
        // daemon's issue-time spend contends for while doing it turns a grant into spurious
        // `xrecycle_target_busy` refusals. The lock is HELD here, so the grant must still have
        // run its verification before it reaches the lock.
        use csq_core::session::recycle_consent as consent_mod;
        let d = tempfile::tempdir().unwrap();
        let handle = d.path().to_path_buf();
        let guard = csq_core::platform::lock::try_lock_file_bounded_nofollow(
            &consent_mod::consent_lock_path(&handle),
            50,
            std::time::Duration::from_millis(20),
        )
        .unwrap()
        .expect("the fixture takes the lock");
        let verified = std::cell::Cell::new(false);
        let resolve = || Ok((handle.clone(), 4242));
        let own = |_: u32, _: &Path| Some(ID.to_string());
        let verify = |_: &str, _: &Path| {
            verified.set(true);
            Ok(())
        };
        let ports = consent_ports(&resolve, &own, &verify);
        assert_eq!(
            consent_with(&ports, Some(OTHER), Some("/h/req"), None, None, false),
            Err("xrecycle_consent_unreadable"),
            "a held lock refuses the write"
        );
        assert!(
            verified.get(),
            "the requester verification must run BEFORE the lock is taken"
        );
        drop(guard);
    }

    #[cfg(unix)]
    #[test]
    fn an_unverified_or_incomplete_consent_request_is_refused() {
        let yes = |_: &str, _: &Path| Ok(());
        let no = |_: &str, _: &Path| Err("xrecycle_requester_unverified");
        assert_eq!(
            consent_record(ID, None, Some("/h/req"), None, None, 0, &yes),
            Err("xrecycle_consent_requires_requester")
        );
        assert_eq!(
            consent_record(ID, Some(OTHER), None, None, None, 0, &yes),
            Err("xrecycle_consent_requires_requester")
        );
        assert_eq!(
            consent_record(ID, Some(OTHER), Some("relative/path"), None, None, 0, &yes),
            Err("xrecycle_requester_unverified"),
            "the record's handle must be absolute"
        );
        assert_eq!(
            consent_record(ID, Some(OTHER), Some("/h/req"), None, None, 0, &no),
            Err("xrecycle_requester_unverified"),
            "a pair the registry does not confirm is never stored"
        );
        assert_eq!(
            consent_record(
                ID,
                Some("not-a-session"),
                Some("/h/req"),
                None,
                None,
                0,
                &yes
            ),
            Err("recycle_session_id_invalid")
        );
    }

    #[test]
    fn memory_view_reads_what_the_supervisor_writes_and_hides_a_stale_sample() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(memory_view(d.path(), false), "memory_not_sampled");
        let stale = recycle::memory_record(Ok(3 << 30), 5 << 29, "2020-01-01T00:00:00Z");
        recycle::write_memory(d.path(), &stale).unwrap();
        assert_eq!(memory_view(d.path(), false), "memory_sample_stale");
        let rec = recycle::memory_record(Ok(3 << 30), 5 << 29, &now_rfc3339());
        recycle::write_memory(d.path(), &rec).unwrap();
        assert!(memory_view(d.path(), false).starts_with("Warn: rss 3.00 GiB"));
        let j: serde_json::Value = serde_json::from_str(&memory_view(d.path(), true)).unwrap();
        assert_eq!(j["state"], "warn");
        let u = recycle::memory_record(Err("rss_sample_failed"), 5 << 29, &now_rfc3339());
        recycle::write_memory(d.path(), &u).unwrap();
        assert!(memory_view(d.path(), false).contains("rss_sample_failed"));
    }
}
