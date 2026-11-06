//! The daemon side of a cross-session recycle request (design
//! `internal-design-docs`, ROOT-ratified 2026-11-04
//! with amendments A1-A4).
//!
//! The socket is the only accepted entry point (design §B). The target's supervisor accepts a
//! foreign request only when the record matches a LIVE consent for the pair field-for-field, so a
//! request that does not reproduce a valid consent is refused — but a forger who can READ the
//! consent file can reproduce one; the supervisor checks no registry row and no writer provenance.
//! That is design §F's stated residual (same uid already means same power), not a capability
//! boundary. This module is the daemon's half — it decides, mints the single-use nonce and writes
//! the request.
//!
//! Layer 1 (umask before bind), layer 2 (`SO_PEERCRED` / `LOCAL_PEERCRED` peer-UID) and the per-user
//! socket dir are already provided by [`crate::daemon::server`] for every route; this module adds no
//! listener and never speaks TCP (`security.md` MUST-7, MUST NOT 3).
//!
//! What this buys, and what it does not: on one host, same uid already means same power — any
//! process running as this user can SIGKILL the target. Consent, TTL, nonce and identity binding are
//! INTENT, ACCIDENT and ATTRIBUTION controls, never a capability boundary (design §0).

use super::recycle::{now_rfc3339, write_json_private, Mode, Tag, REQUEST_FILE};
use super::recycle_consent::{
    consent_allows, read_consent, write_consent, ConsentRecord, RequesterRecord,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Default lifetime of an issued request (A2). Re-checked by the supervisor at the kill point.
pub const DEFAULT_TTL_SECS: i64 = 120;
/// A request may not outlive the supervisor's quiet-wait cap, or it would expire before a target
/// that needs the full wait could ever act on it.
pub const MAX_TTL_SECS: i64 = 600;
/// The tag a requester sees when the daemon is not running (A4). There is NO fallback that writes
/// the request file from the requester side.
pub const DAEMON_UNAVAILABLE: Tag = "xrecycle_daemon_unavailable";
/// Schema version of a FOREIGN request. The self-request writer stays on v1, so a pre-upgrade
/// supervisor (which accepts `v == 1` only) refuses a foreign request as unreadable instead of
/// misreading it as a self resume; the supervisor's `read_request` accepts both shapes.
pub const FOREIGN_REQUEST_VERSION: u32 = 2;
/// Issue-time throttle window: at most ONE issued foreign request per (requester, target) per
/// this many seconds. Refused asks never record, so only ISSUED requests consume the window.
pub const RATE_WINDOW_SECS: i64 = 120;

/// What a requester sends over the socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignAsk {
    /// Absolute path of the target's handle dir, as the requester believes it.
    pub target_handle: String,
    /// The session id the requester believes the target currently runs.
    pub target_session: String,
    /// The requester's own identity: its conversation, never a peer-chosen name.
    pub requester: RequesterRecord,
    /// The requester's claude pid, cross-checked against Claude Code's own registry so the
    /// claimed conversation must be the one that process actually runs.
    pub requester_pid: u32,
    /// The requester's process start time (the same clock as `sessions::process_start_time`),
    /// captured when the ask is made. With [`Self::requester_pid`] this is design §A.2's
    /// identity: the daemon matches it at the chain hop that reaches the requester, so a
    /// recycled pid cannot stand in for the original process.
    #[serde(default)]
    pub requester_start: Option<u64>,
    /// Optional requested lifetime, clamped to `[1, MAX_TTL_SECS]`.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

/// What the daemon hands back and records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    /// Single-use nonce the supervisor refuses a second time.
    pub nonce: String,
    /// Unix seconds after which the request must not be acted on.
    pub expires_at_unix: i64,
}

/// The `/api/recycle/foreign` reply. ONE type for both ends of the socket — the daemon serialises
/// it and the requester's CLI deserialises it — so a change on either side fails to compile rather
/// than drifting into a silently unparseable reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    /// Fixed vocabulary (design §E) when `ok` is false; `None` on success.
    pub tag: Option<String>,
    /// The single-use nonce and expiry when `ok` is true; `None` on refusal.
    pub issued: Option<Issued>,
}

/// Decides whether the daemon may issue this request. Pure.
///
/// `target_session_now` is what the TARGET's supervisor currently runs — resolved by the caller from
/// Claude Code's registry, never taken from the ask. Order: target binding ⇒ requester shape ⇒
/// consent. Every refusal is a fixed tag.
pub fn accept(
    ask: &ForeignAsk,
    target_session_now: &str,
    consent: Option<&ConsentRecord>,
    now_unix: i64,
) -> Result<Issued, Tag> {
    if ask.target_session != target_session_now {
        return Err("xrecycle_target_mismatch");
    }
    if ask.requester.session_id.is_empty()
        || ask.requester.handle.is_empty()
        || !Path::new(&ask.requester.handle).is_absolute()
    {
        return Err("xrecycle_requester_unverified");
    }
    if !Path::new(&ask.target_handle).is_absolute() {
        // A malformed TARGET handle is not an identity fault: it is an ask that cannot name a
        // target at all.
        return Err("xrecycle_target_mismatch");
    }
    consent_allows(consent, target_session_now, &ask.requester, now_unix)?;
    let ttl = ask
        .ttl_secs
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(1, MAX_TTL_SECS);
    Ok(Issued {
        // 32 hex chars: within the 16..=64 the supervisor's reader enforces.
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        expires_at_unix: now_unix.saturating_add(ttl),
    })
}

/// Cross-checks the claimed requester against Claude Code's own registry: the process
/// `requester_pid` must have a registry row naming EXACTLY the claimed session id and handle.
///
/// Pure over the resolver so it is testable without a registry. A claimed conversation that the
/// process does not run is `xrecycle_requester_unverified` — a requester may not name someone
/// else's session, and a stale pid that was reused by another session resolves to that other id
/// and is refused too.
pub fn verify_requester(
    ask: &ForeignAsk,
    resolve: &dyn Fn(u32, &Path) -> Option<String>,
) -> Result<(), Tag> {
    let Some(actual) = resolve(ask.requester_pid, Path::new(&ask.requester.handle)) else {
        return Err("xrecycle_requester_unverified");
    };
    if actual != ask.requester.session_id {
        return Err("xrecycle_requester_unverified");
    }
    Ok(())
}

/// Writes the issued request into the TARGET's handle dir (0600, atomic) so the target's supervisor
/// consumes it exactly as it consumes its own. The write is unconditional once `accept` returned
/// `Ok`; the target's consent was re-read and one use was spent under the consent lock before this.
pub fn issue(
    target_handle: &Path,
    ask: &ForeignAsk,
    issued: &Issued,
    now: &str,
) -> Result<(), Tag> {
    let req = super::recycle::RecycleRequest {
        v: FOREIGN_REQUEST_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        session_id: ask.target_session.clone(),
        reason: String::new(),
        requested_at: now.to_string(),
        mode: Mode::Fresh,
        requested_by: Some(ask.requester.clone()),
        nonce: Some(issued.nonce.clone()),
        expires_at_unix: Some(issued.expires_at_unix),
    };
    write_json_private(target_handle, REQUEST_FILE, &req)
}

/// In-memory issue-time throttle. One window per (requester, target) pair, held by the daemon
/// process; it resets if the daemon restarts, which is acceptable for an accident control.
#[derive(Debug, Default)]
pub struct RateWindow {
    last_issued: std::collections::HashMap<(String, String), i64>,
}

impl RateWindow {
    /// An empty window.
    pub fn new() -> Self {
        Self::default()
    }

    fn key(ask: &ForeignAsk) -> (String, String) {
        // CANONICAL spelling: `check_supervised` and the registry canonicalize both paths, so
        // two spellings of ONE directory (`//x/term-1`, `/x/./term-1`, a symlink) must share one
        // window — otherwise a pair's allowance multiplies by the number of spellings.
        let canon = |p: &str| {
            std::fs::canonicalize(p)
                .map(|c| c.display().to_string())
                .unwrap_or_else(|_| p.to_string())
        };
        (
            format!(
                "{}|{}",
                canon(&ask.requester.handle),
                ask.requester.session_id
            ),
            canon(&ask.target_handle),
        )
    }

    /// Whether a request for this pair may be issued at `now_unix`.
    pub fn allows(&self, ask: &ForeignAsk, now_unix: i64) -> bool {
        self.last_issued
            .get(&Self::key(ask))
            .is_none_or(|last| now_unix.saturating_sub(*last) >= RATE_WINDOW_SECS)
    }

    /// Records an issued request. Called ONLY once the request is on disk, so a refused ask
    /// never consumes the window.
    pub fn record(&mut self, ask: &ForeignAsk, now_unix: i64) {
        self.last_issued.insert(Self::key(ask), now_unix);
    }
}

/// Whether the claimed requester is an ANCESTOR of the socket peer, with the requester's start
/// time matching at that hop. The peer is the short-lived `csq session recycle --to` process,
/// so equality with the peer can never hold in production; the agent that ran the CLI is the
/// requester.
///
/// The walk is [`crate::sessions::ancestor_path_with`], the repo's ONE reader for "is X an
/// ancestor of Y": it carries the pid-reuse defences (each hop's start re-read after its parent
/// and required unchanged; a backward clock refuses) that a hand-rolled walk would miss.
///
/// `start_of` MUST be the walk's FULL-PRECISION reader ([`crate::sessions::ancestor_start`],
/// one kernel clock), never the one-second `started_at`: the walk compares with NO tolerance, and
/// a one-second value cannot tell a pid reused within the same second from the original. The CLI
/// therefore stamps `requester_start` from the same reader, and the incarnation check below is an
/// exact equality on it.
///
/// Fails closed: a missing peer credential, a missing `requester_start`, an unreadable hop or a
/// chain the walk cannot establish all return `false` (the caller refuses).
pub fn peer_chain_reaches(
    peer_pid: Option<u32>,
    ask: &ForeignAsk,
    parent_of: &dyn Fn(u32) -> Option<u32>,
    start_of: &dyn Fn(u32) -> Option<u64>,
) -> bool {
    let (Some(peer), Some(expected_start)) = (peer_pid, ask.requester_start) else {
        return false;
    };
    match crate::sessions::ancestor_path_with(ask.requester_pid, peer, parent_of, start_of) {
        // The hop that reached the requester must be the SAME incarnation the CLI named. Both
        // sides read `ancestor_start`, so the comparison is exact — see the doc above.
        Some(Some(_)) => start_of(ask.requester_pid) == Some(expected_start),
        _ => false,
    }
}

/// SHA-256 (lowercase hex) of a nonce: what the audit chain records instead of the nonce itself.
/// The chain is durable and exportable; the live single-use nonce is not.
pub fn nonce_digest(nonce: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(nonce.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The daemon's whole decision for one ask, in load-bearing order:
/// the socket peer's ancestry FIRST (the only identity the kernel vouches for), then the
/// requester's registry row, then whether the target is a LIVE relaunchable session, then the
/// session it actually runs, then the target's consent, throttle and use (in [`serve`]). Pure
/// over `resolve` and `hop`, so every tag is testable without a registry or a socket.
pub fn decide(
    ask: &ForeignAsk,
    now_unix: i64,
    peer_pid: Option<u32>,
    resolve: &dyn Fn(u32, &Path) -> Option<String>,
    parent_of: &dyn Fn(u32) -> Option<u32>,
    start_of: &dyn Fn(u32) -> Option<u64>,
    rate: &mut RateWindow,
) -> Result<Issued, Tag> {
    if !peer_chain_reaches(peer_pid, ask, parent_of, start_of) {
        return Err("xrecycle_requester_unverified");
    }
    verify_requester(ask, resolve)?;
    let target = Path::new(&ask.target_handle);
    let Some(marker) = super::recycle::read_supervisor(target) else {
        return Err("xrecycle_target_not_supervised");
    };
    // The FULL supervisor predicate: the marker must name a live `csq run` (pid + start) and be
    // relaunchable. `read_supervisor` alone accepts a stale marker left by a dead supervisor.
    if super::recycle::check_supervised(target, marker.child_pid).is_err() {
        return Err("xrecycle_target_not_supervised");
    }
    // The session binding itself is decided by `accept` (one owner for the rule); `decide`'s
    // job is to resolve the target's REAL session from the registry and hand it over, so an ask
    // can never pick the conversation it addresses.
    let Some(target_now) = resolve(marker.child_pid, target) else {
        return Err("xrecycle_target_not_supervised");
    };
    serve(target, ask, &target_now, now_unix, rate)
}

/// The whole daemon-side step for one ask: lock the target's consent, decide, refuse a busy
/// target, throttle, spend one use and write.
///
/// Order chosen by ROOT (2026-11-04): a use is spent BEFORE the request is written, and a failed
/// request write restores the pre-image, so a crash cannot leave a request whose use was never
/// spent. Returns the tag of whichever check refused; nothing is written on refusal.
pub fn serve(
    target_handle: &Path,
    ask: &ForeignAsk,
    target_session_now: &str,
    now_unix: i64,
    rate: &mut RateWindow,
) -> Result<Issued, Tag> {
    // One lock per target serializes every consent read-modify-write AND every issue decision,
    // so two concurrent asks cannot both pass a spent or busy check. Bounded: a wedged holder
    // refuses as busy instead of stalling the daemon worker.
    let _lock = crate::platform::lock::try_lock_file_bounded_nofollow(
        &super::recycle_consent::consent_lock_path(target_handle),
        50,
        std::time::Duration::from_millis(20),
    )
    .map_err(|_| "xrecycle_target_busy")?
    .ok_or("xrecycle_target_busy")?;
    let consent = read_consent(target_handle)?;
    let issued = accept(ask, target_session_now, consent.as_ref(), now_unix)?;
    // A queued or in-flight recycle for this target is never overwritten, including the
    // target's own self-request. Judged AFTER the pure checks so each refusal keeps its own tag.
    super::recycle::check_idle(target_handle).map_err(|_| "xrecycle_target_busy")?;
    // The throttle is checked only once the ask is otherwise acceptable, and recorded only once
    // the request is on disk, so a refused ask never consumes the window.
    if !rate.allows(ask, now_unix) {
        return Err("xrecycle_rate_limited");
    }
    let Some(prior) = consent else {
        return Err("xrecycle_not_consented");
    };
    spend_and_write(target_handle, ask, &issued, &prior)?;
    rate.record(ask, now_unix);
    Ok(issued)
}

/// Spends one use, then writes the request. A failed request write RESTORES the pre-image, so a
/// failed write never burns a use (ROOT ruling: one order, both failure points tested).
fn spend_and_write(
    target_handle: &Path,
    ask: &ForeignAsk,
    issued: &Issued,
    prior: &ConsentRecord,
) -> Result<(), Tag> {
    spend_and_write_with(target_handle, prior, &|| {
        issue(target_handle, ask, issued, &now_rfc3339())
    })
}

/// [`spend_and_write`] with the request write injected, so the ORDER — the spend is ON DISK
/// before the request exists — is observable. End-state assertions cannot see the order; the
/// injected writer can read the consent at the instant the real writer would run.
fn spend_and_write_with(
    target_handle: &Path,
    prior: &ConsentRecord,
    write_request: &dyn Fn() -> Result<(), Tag>,
) -> Result<(), Tag> {
    let mut spent = prior.clone();
    spent.used += 1;
    write_consent(target_handle, &spent)?;
    if let Err(tag) = write_request() {
        if write_consent(target_handle, prior).is_err() {
            // The request was never written and the use could not be given back: a burned use
            // is the SAFE direction, but it must not vanish silently (zero-tolerance Rule 3).
            tracing::warn!(
                error_kind = "recycle_consent_restore_failed",
                "the spent use could not be restored; the request was NOT written"
            );
        }
        return Err(tag);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const TARGET: &str = "123e4567-e89b-12d3-a456-426614174000";
    const REQ: &str = "99999999-8888-7777-6666-555555555555";
    /// The socket peer (the short-lived `csq session recycle --to` process) in these tests.
    const PEER: u32 = 9001;
    /// The requester's start time, as captured by the CLI when it made the ask.
    const REQ_START: u64 = 1_700_000_000;

    /// A platform-ABSOLUTE handle: a leading `/` is root-without-prefix on Windows, where
    /// `Path::is_absolute` is false and `validate` (correctly) refuses the ask.
    fn abs_handle(leaf: &str) -> String {
        std::env::temp_dir()
            .join(leaf)
            .to_string_lossy()
            .into_owned()
    }

    fn ask() -> ForeignAsk {
        ForeignAsk {
            target_handle: abs_handle("h-target"),
            target_session: TARGET.into(),
            requester: RequesterRecord {
                session_id: REQ.into(),
                handle: abs_handle("h-req"),
            },
            ttl_secs: None,
            requester_pid: 4242,
            requester_start: Some(REQ_START),
        }
    }

    /// The ancestry a daemon sees in the normal shape: the peer's parent is the requester.
    fn hop(pid: u32) -> Option<(u32, u64)> {
        match pid {
            PEER => Some((4242, 1_700_000_100)),
            4242 => Some((1, REQ_START)),
            _ => None,
        }
    }

    /// The walk takes `parent_of` and `start_of` SEPARATELY, so production can hand it
    /// `sessions::parent_pid` + `sessions::ancestor_start` (the full-precision pair every other
    /// production caller uses). These two derive them from a `(ppid, start)` fixture.
    fn hop_parent(pid: u32) -> Option<u32> {
        hop(pid).map(|(p, _)| p)
    }

    fn hop_start(pid: u32) -> Option<u64> {
        hop(pid).map(|(_, s)| s)
    }

    /// [`super::peer_chain_reaches`] over one `(ppid, start)`-per-pid fixture.
    fn reaches(peer: Option<u32>, ask: &ForeignAsk, f: impl Fn(u32) -> Option<(u32, u64)>) -> bool {
        let parent_of = |pid: u32| f(pid).map(|(p, _)| p);
        let start_of = |pid: u32| f(pid).map(|(_, s)| s);
        super::peer_chain_reaches(peer, ask, &parent_of, &start_of)
    }

    fn consent(used: u32) -> ConsentRecord {
        ConsentRecord {
            v: 1,
            target_session_id: TARGET.into(),
            allow: vec![ask().requester],
            expires_at_unix: 100_000,
            max_uses: 1,
            used,
        }
    }

    #[test]
    fn the_daemon_issues_only_for_a_consented_pair_and_the_named_target_session() {
        let now = 1_000;
        let issued = accept(&ask(), TARGET, Some(&consent(0)), now).unwrap();
        assert_eq!(
            issued.expires_at_unix,
            now + DEFAULT_TTL_SECS,
            "A2 default is 120 s"
        );
        assert!(issued.nonce.len() >= 16 && issued.nonce.chars().all(|c| c.is_ascii_hexdigit()));
        // A target session the ask does not name is refused: a requester may not pick.
        assert_eq!(
            accept(
                &ask(),
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                Some(&consent(0)),
                now
            ),
            Err("xrecycle_target_mismatch")
        );
        // No consent, spent consent, and a requester the consent does not name.
        assert_eq!(
            accept(&ask(), TARGET, None, now),
            Err("xrecycle_not_consented")
        );
        assert_eq!(
            accept(&ask(), TARGET, Some(&consent(1)), now),
            Err("xrecycle_consent_spent")
        );
        // An empty allow list is MALFORMED on disk (write_consent refuses it); if one
        // ever reaches the decision it simply names nobody.
        let mut c = consent(0);
        c.allow = vec![];
        assert_eq!(
            accept(&ask(), TARGET, Some(&c), now),
            Err("xrecycle_not_consented")
        );
    }

    #[test]
    fn the_requester_must_be_the_process_that_runs_the_conversation_it_claims() {
        let a = ask();
        let ok = |_pid: u32, _h: &Path| Some(REQ.to_string());
        assert_eq!(verify_requester(&a, &ok), Ok(()));
        // The pid runs a different conversation.
        let other = |_pid: u32, _h: &Path| Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string());
        assert_eq!(
            verify_requester(&a, &other),
            Err("xrecycle_requester_unverified")
        );
        // No registry row at all (dead pid, or a handle the row does not name).
        let none = |_pid: u32, _h: &Path| None;
        assert_eq!(
            verify_requester(&a, &none),
            Err("xrecycle_requester_unverified")
        );
        // The resolver is asked about the CLAIMED pid and the CLAIMED handle.
        let seen = std::cell::RefCell::new((0u32, String::new()));
        let probe = |pid: u32, h: &Path| {
            *seen.borrow_mut() = (pid, h.display().to_string());
            Some(REQ.to_string())
        };
        verify_requester(&a, &probe).unwrap();
        assert_eq!(*seen.borrow(), (4242, abs_handle("h-req")));
    }

    /// A supervised target handle with a live marker and a consent for `ask()`'s requester.
    fn target_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        super::super::recycle::write_supervisor(d.path(), 777, Ok(()), d.path()).unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        super::super::recycle_consent::write_consent(d.path(), &live).unwrap();
        d
    }

    fn ask_at(dir: &Path) -> ForeignAsk {
        let mut a = ask();
        a.target_handle = dir.display().to_string();
        a
    }

    #[test]
    fn decide_refuses_in_order_requester_then_target_then_session_then_consent() {
        let d = target_dir();
        let a = ask_at(d.path());
        let now = chrono::Utc::now().timestamp();
        // The resolver answers for the requester (4242) and for the target child (777).
        let resolve = |pid: u32, _h: &Path| match pid {
            4242 => Some(REQ.to_string()),
            777 => Some(TARGET.to_string()),
            _ => None,
        };
        let mut window = RateWindow::new();
        // Happy path.
        assert!(decide(
            &a,
            now,
            Some(PEER),
            &resolve,
            &hop_parent,
            &hop_start,
            &mut window
        )
        .is_ok());
        // 1. Requester first: an unverified caller learns NOTHING about the target, even when
        //    the target handle is nonsense and the session id is wrong. (Absolute-but-wrong on
        //    purpose: a bare `/...` is RELATIVE on Windows and would pass this test for the
        //    wrong reason.)
        let mut wrong = a.clone();
        wrong.target_handle = abs_handle("definitely-not-a-handle");
        wrong.target_session = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into();
        let nobody = |_pid: u32, _h: &Path| None;
        assert_eq!(
            decide(
                &wrong,
                now,
                Some(PEER),
                &nobody,
                &hop_parent,
                &hop_start,
                &mut window
            ),
            Err("xrecycle_requester_unverified"),
            "the requester is judged before the target is even read"
        );
        // 2. Verified requester, unsupervised target.
        let missing = |pid: u32, _h: &Path| match pid {
            4242 => Some(REQ.to_string()),
            _ => None,
        };
        assert_eq!(
            decide(
                &wrong,
                now,
                Some(PEER),
                &missing,
                &hop_parent,
                &hop_start,
                &mut window
            ),
            Err("xrecycle_target_not_supervised")
        );
        // 3. Supervised, but the ask names another session.
        let mut other_session = a.clone();
        other_session.target_session = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into();
        assert_eq!(
            decide(
                &other_session,
                now,
                Some(PEER),
                &resolve,
                &hop_parent,
                &hop_start,
                &mut window
            ),
            Err("xrecycle_target_mismatch")
        );
        // 4. Consent: revoke it and the same ask is refused.
        super::super::recycle_consent::revoke_consent(d.path());
        assert_eq!(
            decide(
                &a,
                now,
                Some(PEER),
                &resolve,
                &hop_parent,
                &hop_start,
                &mut window
            ),
            Err("xrecycle_not_consented")
        );
    }

    #[test]
    fn decide_writes_nothing_unless_every_check_passes() {
        let d = target_dir();
        let a = ask_at(d.path());
        let now = chrono::Utc::now().timestamp();
        let nobody = |_pid: u32, _h: &Path| None;
        let mut window = RateWindow::new();
        assert!(decide(
            &a,
            now,
            Some(PEER),
            &nobody,
            &hop_parent,
            &hop_start,
            &mut window
        )
        .is_err());
        assert!(
            !d.path().join(REQUEST_FILE).exists(),
            "refusal wrote a request"
        );
        let resolve = |pid: u32, _h: &Path| match pid {
            4242 => Some(REQ.to_string()),
            777 => Some(TARGET.to_string()),
            _ => None,
        };
        decide(
            &a,
            now,
            Some(PEER),
            &resolve,
            &hop_parent,
            &hop_start,
            &mut window,
        )
        .unwrap();
        assert!(d.path().join(REQUEST_FILE).exists());
    }

    #[test]
    fn the_ttl_is_clamped_to_the_quiet_wait_cap() {
        let mut a = ask();
        a.ttl_secs = Some(99_999);
        assert_eq!(
            accept(&a, TARGET, Some(&consent(0)), 0)
                .unwrap()
                .expires_at_unix,
            MAX_TTL_SECS
        );
        a.ttl_secs = Some(0);
        assert_eq!(
            accept(&a, TARGET, Some(&consent(0)), 0)
                .unwrap()
                .expires_at_unix,
            1
        );
    }

    #[test]
    fn a_relative_handle_is_never_issued() {
        let mut a = ask();
        a.requester.handle = "term-1".into();
        assert_eq!(
            accept(&a, TARGET, Some(&consent(0)), 0),
            Err("xrecycle_requester_unverified")
        );
        let mut a = ask();
        a.target_handle = "relative".into();
        assert_eq!(
            accept(&a, TARGET, Some(&consent(0)), 0),
            Err("xrecycle_target_mismatch"),
            "a malformed TARGET handle is a target fault, not an identity one"
        );
    }

    #[test]
    fn serve_writes_a_request_the_target_supervisor_will_accept() {
        let d = tempfile::tempdir().unwrap();
        // The consent must be LIVE when it is written: write_consent refuses an
        // already-expired grant rather than storing a dead one.
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        super::super::recycle_consent::write_consent(d.path(), &live).unwrap();
        let issued = serve(d.path(), &ask(), TARGET, 1_000, &mut RateWindow::new()).unwrap();
        let req = super::super::recycle::read_request(d.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            req.mode,
            Mode::Fresh,
            "a third party may only ask for FRESH"
        );
        assert_eq!(req.session_id, TARGET);
        assert_eq!(req.nonce.as_deref(), Some(issued.nonce.as_str()));
        assert_eq!(req.expires_at_unix, Some(issued.expires_at_unix));
        assert_eq!(req.requested_by, Some(ask().requester));
        assert_eq!(req.reason, "", "no free text crosses the boundary");
        // The request file is private: the supervisor's bounded read requires no
        // group/other bit, and the daemon must never write one that has them.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.path().join(REQUEST_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the issued request must be 0600");
        }
        // And the pure verdict agrees it may act.
        assert_eq!(
            super::super::recycle::foreign_verdict(&req, Some(&live), 1_000, &[]),
            Ok(())
        );
    }

    #[test]
    fn a_foreign_request_is_v2_so_a_v1_reader_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        write_consent(d.path(), &live).unwrap();
        serve(
            d.path(),
            &ask(),
            TARGET,
            chrono::Utc::now().timestamp(),
            &mut RateWindow::new(),
        )
        .unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.path().join(REQUEST_FILE)).unwrap()).unwrap();
        assert_eq!(raw["v"], FOREIGN_REQUEST_VERSION);
        // The v1 reader's acceptance rule (`read_request` on dev): anything but `v == 1` is
        // `recycle_request_unreadable`. A pre-upgrade supervisor therefore REFUSES this file
        // instead of silently acting on it as a self resume.
        assert_ne!(
            raw["v"].as_u64(),
            Some(1),
            "a v1-only reader must not accept a foreign request"
        );
    }

    #[test]
    fn the_nonce_digest_is_a_sha256_hex_of_the_nonce() {
        let digest = nonce_digest("0123456789abcdef0123456789abcdef");
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_ne!(digest, nonce_digest("0123456789abcdef0123456789abcdee"));
    }

    #[test]
    fn serve_writes_nothing_when_it_refuses() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            serve(d.path(), &ask(), TARGET, 1_000, &mut RateWindow::new()),
            Err("xrecycle_not_consented")
        );
        assert!(!PathBuf::from(d.path()).join(REQUEST_FILE).exists());
    }

    #[test]
    fn the_peer_must_reach_the_requester_through_its_ancestors() {
        let a = ask();
        // The normal shape: claude → csq CLI. The peer's PARENT is the requester.
        assert!(reaches(Some(PEER), &a, hop));
        // The requester can be further up than one hop. Starts move BACKWARD up the chain, as a
        // real parent always started no later than its child; the walk refuses otherwise.
        let grandparent = |pid: u32| match pid {
            PEER => Some((5555, 1_700_000_100)),
            5555 => Some((4242, 1_700_000_050)),
            4242 => Some((1, REQ_START)),
            _ => None,
        };
        assert!(reaches(Some(PEER), &a, grandparent));
        // A pid that is NOT an ancestor (here: a sibling) never reaches the requester.
        let sibling = |pid: u32| match pid {
            PEER => Some((1, 1_700_000_100)),
            _ => None,
        };
        assert!(!reaches(Some(PEER), &a, sibling));
        // Fail closed: no kernel peer credential, or no start time to match against.
        assert!(!reaches(None, &a, hop));
        let mut no_start = a.clone();
        no_start.requester_start = None;
        assert!(!reaches(Some(PEER), &no_start, hop));
        // A recycled requester pid: the hop's start time no longer agrees.
        let reused = |pid: u32| match pid {
            PEER => Some((4242, 1_700_000_100)),
            4242 => Some((1, REQ_START + 5)),
            _ => None,
        };
        assert!(!reaches(Some(PEER), &a, reused));
        // A chain that cannot be walked refuses rather than guessing.
        let broken = |pid: u32| {
            if pid == PEER {
                Some((4242, 0))
            } else {
                None
            }
        };
        assert!(!reaches(Some(PEER), &a, broken));
    }

    #[test]
    fn decide_refuses_when_the_socket_peer_does_not_reach_the_requester() {
        // Security R2 M4: the unit matrix proves the PREDICATE; this proves its USE. Delete the
        // binding from `decide` and this ask proceeds to the consent/target checks, so the
        // refusal is no longer `xrecycle_requester_unverified` — the test reds.
        let d = target_dir();
        let a = ask_at(d.path());
        let now = chrono::Utc::now().timestamp();
        let resolve = |pid: u32, _h: &Path| match pid {
            4242 => Some(REQ.to_string()),
            777 => Some(TARGET.to_string()),
            _ => None,
        };
        let sibling = |pid: u32| match pid {
            PEER => Some((1, 1_700_000_100)),
            _ => None,
        };
        let parent_of = |pid: u32| sibling(pid).map(|(p, _)| p);
        let start_of = |pid: u32| sibling(pid).map(|(_, s)| s);
        assert_eq!(
            decide(
                &a,
                now,
                Some(PEER),
                &resolve,
                &parent_of,
                &start_of,
                &mut RateWindow::new()
            ),
            Err("xrecycle_requester_unverified"),
            "a peer that cannot reach the requester must never get past the binding"
        );
    }

    #[test]
    fn a_requester_pid_reused_within_the_same_second_is_refused() {
        // Security R2 M1 / correctness M3: the walk documents a FULL-PRECISION start and no
        // tolerance. Two incarnations a few ticks apart are indistinguishable to the one-second
        // `started_at`, so a comparison through `same_start` (tolerance ±1 s) would accept the
        // reuse. This fixture keeps the WALK happy (the parent started before the child) and
        // makes only the incarnation check decisive.
        let mut a = ask();
        a.requester_start = Some(1_700_000_000_100_050);
        let near = |pid: u32| match pid {
            PEER => Some((4242, 1_700_000_000_100_060)),
            // The requester pid now names its SECOND incarnation: one tick later, same second.
            4242 => Some((1, 1_700_000_000_100_051)),
            _ => None,
        };
        assert!(
            !reaches(Some(PEER), &a, near),
            "a same-second re-use must not pass: the walk's contract forbids a tolerance here"
        );
    }

    #[test]
    fn an_issued_request_spends_the_use_before_it_is_written() {
        let d = tempfile::tempdir().unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        write_consent(d.path(), &live).unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut rate = RateWindow::new();
        serve(d.path(), &ask(), TARGET, now, &mut rate).unwrap();
        let after = read_consent(d.path()).unwrap().unwrap();
        assert_eq!(after.used, 1, "the use is spent at ISSUE time");
        // The request already issued under that use is STILL acceptable to the target: the
        // kill-point check must not read the spent use as a refusal.
        let req = super::super::recycle::read_request(d.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::recycle::foreign_verdict(&req, Some(&after), now, &[]),
            Ok(())
        );
        // A second issue is refused as spent, and writes nothing.
        std::fs::remove_file(d.path().join(REQUEST_FILE)).unwrap();
        assert_eq!(
            serve(
                d.path(),
                &ask(),
                TARGET,
                now + RATE_WINDOW_SECS + 1,
                &mut rate
            ),
            Err("xrecycle_consent_spent")
        );
        assert!(!d.path().join(REQUEST_FILE).exists());
    }

    #[test]
    fn one_issue_per_pair_per_window_and_a_throttled_ask_spends_nothing() {
        let d = tempfile::tempdir().unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        live.max_uses = 5;
        write_consent(d.path(), &live).unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut rate = RateWindow::new();
        serve(d.path(), &ask(), TARGET, now, &mut rate).unwrap();
        std::fs::remove_file(d.path().join(REQUEST_FILE)).unwrap();
        // Inside the window the same pair is throttled...
        assert_eq!(
            serve(d.path(), &ask(), TARGET, now + 1, &mut rate),
            Err("xrecycle_rate_limited")
        );
        assert_eq!(
            read_consent(d.path()).unwrap().unwrap().used,
            1,
            "a throttled ask does not spend a use"
        );
        // ...and once the window passes it is issued again.
        serve(d.path(), &ask(), TARGET, now + RATE_WINDOW_SECS, &mut rate).unwrap();
        assert_eq!(read_consent(d.path()).unwrap().unwrap().used, 2);
    }

    #[cfg(unix)]
    #[test]
    fn the_rate_window_keys_one_directory_under_every_spelling() {
        // R2 L1: every other gate canonicalizes the target, so a symlink alias must share its
        // window too — otherwise a pair's allowance doubles per spelling.
        let d = tempfile::tempdir().unwrap();
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(d.path(), &alias).unwrap();
        let mut a = ask();
        a.target_handle = d.path().display().to_string();
        let mut w = RateWindow::new();
        assert!(w.allows(&a, 1_000));
        w.record(&a, 1_000);
        let mut spelled = a.clone();
        spelled.target_handle = alias.display().to_string();
        assert!(
            !w.allows(&spelled, 1_060),
            "one directory, one window — a spelling alias must not double the allowance"
        );
    }

    #[test]
    fn a_queued_request_makes_the_target_busy_and_is_never_overwritten() {
        let d = tempfile::tempdir().unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        live.max_uses = 2;
        write_consent(d.path(), &live).unwrap();
        // The target queued its OWN request; a foreign ask must not replace it.
        super::super::recycle::write_request(d.path(), TARGET, "", "t", Mode::Resume).unwrap();
        let before = std::fs::read(d.path().join(REQUEST_FILE)).unwrap();
        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            serve(d.path(), &ask(), TARGET, now, &mut RateWindow::new()),
            Err("xrecycle_target_busy")
        );
        assert_eq!(
            std::fs::read(d.path().join(REQUEST_FILE)).unwrap(),
            before,
            "the queued request is untouched, byte for byte"
        );
        assert_eq!(
            read_consent(d.path()).unwrap().unwrap().used,
            0,
            "a refusal spends nothing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_consent_write_writes_no_request() {
        use super::super::recycle_consent::CONSENT_FILE;
        let d = tempfile::tempdir().unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        write_consent(d.path(), &live).unwrap();
        let issued = accept(&ask(), TARGET, Some(&live), chrono::Utc::now().timestamp()).unwrap();
        // A DIRECTORY at the consent path refuses the consent's temp+rename while the handle dir
        // — and so the request write — stays fully writable. A read-only handle dir fails BOTH
        // writes and cannot see the difference this test exists for (mutation A7 proved that).
        let consent_path = d.path().join(CONSENT_FILE);
        std::fs::remove_file(&consent_path).unwrap();
        std::fs::create_dir(&consent_path).unwrap();
        let res = spend_and_write(d.path(), &ask(), &issued, &live);
        assert!(res.is_err(), "the consent write must refuse");
        assert!(
            !d.path().join(REQUEST_FILE).exists(),
            "no request may be written when the use could not be spent"
        );
    }

    #[test]
    fn the_use_is_on_disk_before_the_request_is_written() {
        // R2 correctness L3: the ROOT-ruled order is spend -> write, so a crash between them
        // leaves a spent use and NO request (fail-safe), never a request whose use was never
        // spent. Only reading the consent from INSIDE the request write can prove the order.
        let d = tempfile::tempdir().unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        write_consent(d.path(), &live).unwrap();
        let seen = std::cell::Cell::new(0);
        let res = spend_and_write_with(d.path(), &live, &|| {
            seen.set(read_consent(d.path()).unwrap().unwrap().used);
            Err("recycle_file_write_failed")
        });
        assert_eq!(
            seen.get(),
            1,
            "the spend must be on disk BEFORE the request write runs"
        );
        assert_eq!(res, Err("recycle_file_write_failed"));
        // The failed write restores the pre-image.
        assert_eq!(read_consent(d.path()).unwrap().unwrap().used, 0);
    }

    #[test]
    fn a_failed_request_write_restores_the_spent_use() {
        let d = tempfile::tempdir().unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        write_consent(d.path(), &live).unwrap();
        let issued = accept(&ask(), TARGET, Some(&live), chrono::Utc::now().timestamp()).unwrap();
        // A DIRECTORY at the request path makes the atomic rename fail while the consent file
        // stays writable.
        std::fs::create_dir(d.path().join(REQUEST_FILE)).unwrap();
        assert!(spend_and_write(d.path(), &ask(), &issued, &live).is_err());
        assert_eq!(
            read_consent(d.path()).unwrap().unwrap().used,
            0,
            "the spent use is put back when the request was not written"
        );
    }

    #[cfg(unix)]
    #[test]
    fn decide_requires_a_live_supervisor_not_merely_a_marker() {
        let d = tempfile::tempdir().unwrap();
        // A marker left behind by a supervisor that is gone: its csq_pid is a child we reaped.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let dead = child.id();
        child.wait().unwrap();
        super::super::recycle::write_json_private(
            d.path(),
            super::super::recycle::SUPERVISOR_FILE,
            &super::super::recycle::SupervisorMarker {
                v: 1,
                csq_pid: dead,
                csq_start: 1,
                child_pid: 777,
                relaunch_ok: true,
                relaunch_tag: None,
                cwd: Some(d.path().display().to_string()),
            },
        )
        .unwrap();
        let mut live = consent(0);
        live.expires_at_unix = chrono::Utc::now().timestamp() + 600;
        write_consent(d.path(), &live).unwrap();
        let a = ask_at(d.path());
        let resolve = |pid: u32, _h: &Path| match pid {
            4242 => Some(REQ.to_string()),
            777 => Some(TARGET.to_string()),
            _ => None,
        };
        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            decide(
                &a,
                now,
                Some(PEER),
                &resolve,
                &hop_parent,
                &hop_start,
                &mut RateWindow::new()
            ),
            Err("xrecycle_target_not_supervised"),
            "a stale marker is not a live supervisor"
        );
        assert!(!d.path().join(REQUEST_FILE).exists());
    }
}
