//! The unix supervision loop behind spec 36: wait on the claude child, sample its
//! memory, honour a recycle request. See [`super::recycle`] for the pure parts.

use super::recycle::{
    file_age, foreign_verdict, guard_manifest_refusal, list_descendants, memory_record,
    now_rfc3339, parse_warn_bytes, read_request, read_result, read_turn_state, reconcile_artifacts,
    relaunch_command, remove_request, resolve_transcript, sample_rss_bytes, snapshot_artifacts,
    stop_child, subagent_age, terminate_descendants, verify_artifacts, verify_session_binding,
    wait_for_quiet, write_memory, write_result, write_supervisor, FreshContext, LaunchArtifact,
    Mode, Outcome, QuietOutcome, QuietParams, QuietProbe, RecycleRequest, RecycleResult,
    RelaunchPlan, SessionProbe, SignalWindow, Tag, TurnState, SAMPLE_INTERVAL, SUPERVISOR_FILE,
    WARN_ENV,
};
use crate::sessions::lifecycle::{self, LaunchTicket};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// Timing knobs; [`Timing::default`] is the production set (spec 36 §36.5).
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Loop cadence while waiting for the child.
    pub poll: Duration,
    /// RSS sampling cadence.
    pub sample_interval: Duration,
    /// Quiet-point constants.
    pub quiet: QuietParams,
    /// SIGTERM-to-SIGKILL grace for the claude child.
    pub stop_grace: Duration,
    /// SIGTERM-to-SIGKILL grace for the child's descendants.
    pub descendant_grace: Duration,
    /// A relaunched child that exits non-zero inside this window is a failed recycle.
    pub settle: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            poll: Duration::from_millis(200),
            sample_interval: SAMPLE_INTERVAL,
            quiet: QuietParams::default(),
            stop_grace: Duration::from_secs(10),
            descendant_grace: Duration::from_secs(3),
            settle: Duration::from_secs(15),
        }
    }
}

/// Side effects owned by the caller (audit emitter, launch gates, owner ping, terminal).
pub struct Hooks<'a> {
    /// End the old audit run record and start a new one (called once per recycle).
    pub rotate_audit: &'a mut dyn FnMut(),
    /// Re-run the launch gates for the relaunch; `Err(tag)` ⇒ abort with the child untouched.
    pub preflight: &'a mut dyn FnMut() -> Result<(), Tag>,
    /// P2: verify the relaunch command honours a Gate that attached since the
    /// launch; `Err(tag)` ⇒ loud failed path (the child is already stopped).
    pub gate_recheck: &'a mut dyn FnMut(&Command) -> Result<(), Tag>,
    /// Send one owner ping (fixed text); the caller decides what to log on failure.
    pub notify_owner: &'a mut dyn FnMut(&str),
    /// Resolve the capability layer's fresh-relaunch context for (project root, config dir,
    /// session id) — the capability layer's readiness CLI. `Err(tag)` BEFORE the stop aborts with the child
    /// untouched; after it, the supervisor relaunches in RESUME mode instead of leaving the
    /// session dead. Production wires this to [`super::recycle::fresh_context_at`].
    pub fresh: &'a mut dyn FnMut(&Path, &Path, &str) -> Result<FreshContext, Tag>,
    /// Loud terminal lines.
    pub out: &'a mut dyn Write,
}

/// Static facts about the supervised launch.
pub struct Launch<'a> {
    /// The handle dir as passed to `csq run`.
    pub handle: &'a Path,
    /// Directory the child runs in (its transcript slug).
    pub cwd: PathBuf,
    /// Account slot, for the manual-resume hint.
    pub account: Option<u16>,
    /// The handle dir as shown to the operator (home abbreviated to `~`).
    pub display_handle: String,
    /// Timing.
    pub timing: Timing,
    /// The relaunch plan, or why there is none (⇒ recycle is disabled for this launch).
    pub plan: Result<RelaunchPlan, Tag>,
    /// Launch-time files recorded for re-verification, or why they could not be.
    pub artifacts: Result<Vec<LaunchArtifact>, Tag>,
    /// Session-id source (Claude Code's registry in production).
    pub probe: &'a dyn SessionProbe,
}

/// How supervision ended.
pub enum Exit {
    /// The child ended normally (or by its own signal).
    Exited(ExitStatus),
    /// Recycle failed; the handle dir MUST be kept. Carries the dead child's status if any.
    RecycleFailed(Option<ExitStatus>),
    /// `try_wait` itself failed.
    WaitFailed,
    /// A SIGINT/SIGTERM/SIGHUP arrived in the stop-to-spawn window. The replacement child was
    /// spawned and the signal forwarded to it; the caller must re-raise the signal on csq.
    Interrupted(i32),
}

impl Exit {
    /// Whether the caller must keep the handle dir (a failed recycle leaves the
    /// operator a manual-resume path that needs it).
    pub fn keeps_handle(&self) -> bool {
        matches!(self, Exit::RecycleFailed(_) | Exit::Interrupted(_))
    }
}

struct Sup<'a, 'h> {
    launch: &'a Launch<'a>,
    spec: &'a Command,
    hooks: &'a mut Hooks<'h>,
    child: Child,
    start: Option<u64>,
    ticket: Option<LaunchTicket>,
    warn_bytes: u64,
    last_rss: Option<u64>,
    next_sample: Instant,
    settling: Option<(Instant, RecycleResult)>,
    recycle_enabled: bool,
    /// Launch-time artifacts, re-recorded when the launch gates rewrite one of them.
    artifacts: Vec<LaunchArtifact>,
    /// Descendants seen at launch settle (MCP servers), before any turn.
    baseline: Option<HashSet<(u32, u64)>>,
    launched_at: Instant,
    /// (dev, ino) of a request entry that could not be removed; skipped until it changes.
    latched: Option<(u64, u64)>,
    /// Set when the fresh handover could not be minted after the stop and the session was
    /// relaunched in RESUME mode instead. The finished result then reports
    /// [`Outcome::FreshFellBackToResume`] with this tag instead of `recycled`.
    fell_back_to_resume: Option<Tag>,
    /// Nonces of earlier consumed foreign requests, carried into every result this consume
    /// writes so a re-delivery of any of them is refused as a replay.
    carried_nonces: Vec<String>,
    /// The nonce of the request THIS consume took, when it was a foreign one. Results built
    /// without the request (`fail()` after a post-stop failure) must still name it: the nonce
    /// is the only replay evidence on disk once the request file is gone.
    consumed_nonce: Option<String>,
}

/// Whether a fresh context carries EXACTLY ONE proof variable and that proof is structurally
/// valid for the OLD session.
///
/// The supervisor asserts this itself rather than trusting the hook's producer: a future hook
/// returning an empty `env` would otherwise exec a fresh session with no proof and nothing would
/// catch it (spec 36.10: "a fresh exec NEVER happens without a valid proof").
fn fresh_proof_ok(ctx: &FreshContext, expected_session: &str) -> bool {
    let mut proofs = ctx
        .env
        .iter()
        .filter(|(key, _)| key.as_os_str() == std::ffi::OsStr::new(super::recycle::PROOF_ENV))
        .map(|(_, value)| value);
    let Some(value) = proofs.next() else {
        return false;
    };
    if proofs.next().is_some() {
        return false;
    }
    value
        .to_str()
        .is_some_and(|text| super::recycle::validate_proof(text, expected_session).is_ok())
}

fn result(outcome: Outcome, req: Option<&RecycleRequest>, tag: Option<Tag>) -> RecycleResult {
    RecycleResult {
        v: 1,
        outcome,
        request_id: req.map(|r| r.request_id.clone()),
        session_id: req.map(|r| r.session_id.clone()),
        requested_at: req.map(|r| r.requested_at.clone()),
        old_pid: None,
        new_pid: None,
        rss_before_bytes: None,
        tag: tag.map(str::to_string),
        mode: req.map(|r| r.mode).unwrap_or_default(),
        nonce: req.and_then(|r| r.nonce.clone()),
        prior_nonces: Vec::new(),
        at: now_rfc3339(),
    }
}

/// Adds this consume's carried history and its own nonce to a result about to be written.
///
/// [`result`] copies the nonce only when it is given the request; `fail()` and the
/// unreadable-state paths build results WITHOUT one, and the request file is already gone by
/// then — the nonce on disk is the ONLY replay evidence left, so no later write may drop it.
fn carry_consume(r: &RecycleResult, history: &[String], consumed: Option<&str>) -> RecycleResult {
    let mut out = r.clone();
    if out.prior_nonces.is_empty() {
        out.prior_nonces = history.to_vec();
    }
    if out.nonce.is_none() {
        out.nonce = consumed.map(str::to_string);
    }
    out
}

fn request_identity(handle: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = handle
        .join(super::recycle::REQUEST_FILE)
        .symlink_metadata()
        .ok()?;
    Some((m.dev(), m.ino()))
}

/// Supervises `first` (spawned from `spec`) until it exits for good.
pub fn supervise(
    spec: &Command,
    first: Child,
    ticket: Option<LaunchTicket>,
    launch: &Launch<'_>,
    hooks: &mut Hooks<'_>,
) -> Exit {
    let warn_bytes =
        parse_warn_bytes(std::env::var(WARN_ENV).ok().as_deref()).unwrap_or_else(|t| {
            tracing::warn!(error_kind = t, "using the default memory warn threshold");
            super::recycle::DEFAULT_WARN_BYTES
        });
    let start = crate::sessions::process_start_time(first.id());
    let relaunch: Result<(), Tag> = match (&launch.plan, &launch.artifacts) {
        (Err(t), _) | (_, Err(t)) => Err(*t),
        _ => Ok(()),
    };
    let marker_ok = match write_supervisor(launch.handle, first.id(), relaunch, &launch.cwd) {
        Ok(()) => true,
        Err(_) => {
            tracing::warn!(
                error_kind = "recycle_supervisor_marker_failed",
                "recycle disabled for this session"
            );
            false
        }
    };
    let mut s = Sup {
        launch,
        spec,
        hooks,
        child: first,
        start,
        ticket,
        warn_bytes,
        last_rss: None,
        next_sample: Instant::now(),
        settling: None,
        recycle_enabled: marker_ok && relaunch.is_ok(),
        artifacts: launch.artifacts.clone().unwrap_or_default(),
        baseline: None,
        launched_at: Instant::now(),
        latched: None,
        fell_back_to_resume: None,
        carried_nonces: Vec::new(),
        consumed_nonce: None,
    };
    let exit = s.run();
    match std::fs::remove_file(launch.handle.join(SUPERVISOR_FILE)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => tracing::warn!(
            error_kind = "recycle_supervisor_marker_remove_failed",
            "supervisor marker left behind"
        ),
    }
    exit
}

impl Sup<'_, '_> {
    fn run(&mut self) -> Exit {
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return self.on_exit(status),
                Ok(None) => {}
                Err(_) => {
                    tracing::warn!(
                        error_kind = "supervise_wait_failed",
                        "wait on claude failed"
                    );
                    return Exit::WaitFailed;
                }
            }
            self.settle_check();
            self.sample_baseline();
            if Instant::now() >= self.next_sample {
                self.sample();
                self.next_sample = Instant::now() + self.launch.timing.sample_interval;
            }
            if self.recycle_enabled {
                if let Some(exit) = self.poll_request() {
                    return exit;
                }
            }
            std::thread::sleep(self.launch.timing.poll);
        }
    }

    fn poll_request(&mut self) -> Option<Exit> {
        if let Some(l) = self.latched {
            if request_identity(self.launch.handle) == Some(l) {
                return None; // already reported; same unremovable entry
            }
            self.latched = None;
        }
        // Cheap UNLOCKED peek: an idle supervisor must not open and lock a file every poll.
        if matches!(read_request(self.launch.handle), Ok(None)) {
            return None;
        }
        // Something is there (a request, or a file that does not read as one): serialise the
        // CONSUME with every writer — and with any OTHER supervisor on this handle dir, which
        // nothing else excludes — under the SAME per-target consent lock the daemon's issue and
        // the CLI's self request take. Contention is retried on the next poll; the supervisor
        // never blocks on it, and the lock is dropped before the long recycle work below.
        let consumed = {
            let Ok(Some(_guard)) = crate::platform::lock::try_lock_file_bounded_nofollow(
                &super::recycle_consent::consent_lock_path(self.launch.handle),
                5,
                std::time::Duration::from_millis(20),
            ) else {
                return None;
            };
            self.begin_consume()
        };
        match consumed {
            Some(req) => self.recycle(req),
            None => None,
        }
    }

    fn on_exit(&mut self, status: ExitStatus) -> Exit {
        if let Some((_, mut pending)) = self.settling.take() {
            lifecycle::waited(self.ticket.as_ref(), &status);
            if status.success() {
                // The operator quit the relaunched session themselves: not a failure.
                pending.outcome = self.relaunched_outcome(&mut pending);
                pending.at = now_rfc3339();
                self.write(&pending);
                return Exit::Exited(status);
            }
            let id = pending.session_id.clone();
            self.fail(
                id.as_deref(),
                "recycle_new_child_exited_early",
                pending.old_pid,
            );
            return Exit::RecycleFailed(Some(status));
        }
        lifecycle::waited(self.ticket.as_ref(), &status);
        Exit::Exited(status)
    }

    /// Records the descendants present once the child has settled after (re)launch: its MCP
    /// servers, before any turn. Anything else alive at the quiet check is busy.
    fn sample_baseline(&mut self) {
        if self.baseline.is_none() && self.launched_at.elapsed() >= self.launch.timing.settle {
            match list_descendants(self.child.id()) {
                Ok(d) => self.baseline = Some(d.into_iter().collect()),
                Err(_) => tracing::warn!(
                    error_kind = "recycle_baseline_unreadable",
                    "descendant baseline unavailable"
                ),
            }
        }
    }

    fn settle_check(&mut self) {
        let done = self
            .settling
            .as_ref()
            .is_some_and(|(t, _)| t.elapsed() >= self.launch.timing.settle);
        if done {
            if let Some((_, mut r)) = self.settling.take() {
                r.outcome = self.relaunched_outcome(&mut r);
                r.at = now_rfc3339();
                self.write(&r);
            }
        }
    }

    /// The outcome a relaunch that reached its settle window reports: the plain recycle, or the
    /// RESUME fallback that kept the session alive when the capability layer was not ready.
    fn relaunched_outcome(&self, r: &mut RecycleResult) -> Outcome {
        match self.fell_back_to_resume {
            Some(tag) => {
                r.tag = Some(tag.to_string());
                Outcome::FreshFellBackToResume
            }
            None => Outcome::Recycled,
        }
    }

    fn write(&mut self, r: &RecycleResult) {
        // Every result this consume writes carries the nonce history AND its own nonce, so a
        // captured request stays recognisable as a replay after later recycles overwrite the
        // file — even when the result was built without the request (`fail()`).
        let carried = carry_consume(r, &self.carried_nonces, self.consumed_nonce.as_deref());
        if write_result(self.launch.handle, &carried).is_err() {
            tracing::warn!(
                error_kind = "recycle_result_write_failed",
                "recycle result not recorded"
            );
        }
    }

    fn sample(&mut self) {
        let rss = sample_rss_bytes(self.child.id());
        if let Ok(n) = rss {
            self.last_rss = Some(n);
        }
        let rec = memory_record(rss, self.warn_bytes, &now_rfc3339());
        if write_memory(self.launch.handle, &rec).is_err() {
            tracing::warn!(
                error_kind = "memory_file_write_failed",
                "memory view not updated"
            );
        }
    }

    /// The tag a child-exit-during-the-wait reports: spec 36 §E names `xrecycle_target_exited`
    /// for a foreign ask, while the self path keeps the long-standing `recycle_child_exited`.
    /// The tag lands in the target's result file (the operator's record); the requester's CLI
    /// has already printed the daemon's reply and exited, so it never reads this tag.
    fn child_exited_tag(&self, req: &RecycleRequest) -> Tag {
        if req.requested_by.is_some() {
            "xrecycle_target_exited"
        } else {
            "recycle_child_exited"
        }
    }

    fn abort_req(&mut self, outcome: Outcome, req: Option<&RecycleRequest>, tag: Tag) {
        let mut r = result(outcome, req, Some(tag));
        r.old_pid = Some(self.child.id());
        r.rss_before_bytes = self.last_rss;
        self.write(&r);
        let _ = writeln!(
            self.hooks.out,
            "csq: RECYCLE ABORTED ({tag}); the session was left running and was not restarted."
        );
    }

    /// Blocks (bounded by `settle`) until the launch-settle descendant baseline exists.
    fn ensure_baseline(&mut self) -> Result<HashSet<(u32, u64)>, Tag> {
        loop {
            self.sample_baseline();
            if let Some(b) = &self.baseline {
                return Ok(b.clone());
            }
            if self.launched_at.elapsed() >= self.launch.timing.settle * 4 {
                return Err("recycle_baseline_unreadable");
            }
            std::thread::sleep(self.launch.timing.poll);
            if !matches!(self.child.try_wait(), Ok(None)) {
                return Err("recycle_child_exited");
            }
        }
    }

    /// Re-decides a cross-session request (design slice 2). `Ok(())` for the terminal's own
    /// request. `prior_nonces` is the bounded history of EARLIER consumed nonces, read before
    /// this consume writes its own `waiting` result; the kill-point re-check passes `&[]` because
    /// the replay question was answered at consume and this request's own nonce is not a replay.
    fn foreign_gate(&self, req: &RecycleRequest, prior_nonces: &[String]) -> Result<(), Tag> {
        if req.requested_by.is_none() {
            return Ok(());
        }
        let consent = super::recycle_consent::read_consent(self.launch.handle)?;
        foreign_verdict(
            req,
            consent.as_ref(),
            chrono::Utc::now().timestamp(),
            prior_nonces,
        )
    }

    /// The CONSUME step, run with the per-target consent lock held by [`poll_request`]: read the
    /// request, remember its nonce and the history, write `waiting`, remove the request.
    ///
    /// The lock is what makes a double consume impossible. The supervisor marker is an atomic
    /// OVERWRITE (no exclusive create), so two `csq run` supervisors can own one handle dir; they
    /// (and the daemon's issue and the CLI's self request) all serialise here, and the loser
    /// re-reads and finds nothing. Without the lock this read→remove is read-then-unlink and both
    /// could act on one request.
    fn begin_consume(&mut self) -> Option<RecycleRequest> {
        let handle = self.launch.handle;
        match read_request(handle) {
            Ok(None) => None,
            Ok(Some(_)) if self.settling.is_some() => {
                remove_request(handle);
                let _ = writeln!(
                    self.hooks.out,
                    "csq: RECYCLE REQUEST REJECTED (recycle_in_flight); the previous recycle is still settling."
                );
                None
            }
            Ok(Some(req)) => {
                // EVERY result this consume writes must name the nonce it took — including the
                // ones built without the request (`fail()` after a post-stop failure).
                self.consumed_nonce = req.nonce.clone();
                // The nonce history of earlier foreign recycles, read BEFORE this consume
                // writes its own `waiting` result: that record carries THIS request's nonce, so
                // reading it afterwards would make every first consume look like a replay. An
                // unreadable result makes a FOREIGN request unjudgeable — it could hide a
                // replay — so it refuses with the child untouched (guard-reader-writer-parity
                // MUST-2).
                let prior_result = match read_result(handle) {
                    Ok(prior) => prior,
                    Err(_) => {
                        if req.requested_by.is_some() {
                            self.abort_req(
                                Outcome::AbortedRequestUnreadable,
                                Some(&req),
                                "recycle_result_unreadable",
                            );
                            return None;
                        }
                        None
                    }
                };
                self.carried_nonces = prior_result
                    .as_ref()
                    .map(|r| {
                        let mut history = r.prior_nonces.clone();
                        if let Some(nonce) = &r.nonce {
                            history.push(nonce.clone());
                        }
                        let excess = history
                            .len()
                            .saturating_sub(super::recycle::MAX_CARRIED_NONCES);
                        history.drain(..excess);
                        history
                    })
                    .unwrap_or_default();
                // The Waiting result goes BEFORE the request file is removed: from the moment
                // the request is consumed `check_idle` already sees a recycle in flight, so no
                // second request can be queued in a gap between the two.
                // A new request starts with no fallback carried over from an earlier recycle.
                self.fell_back_to_resume = None;
                let mut waiting = result(Outcome::Waiting, Some(&req), None);
                waiting.old_pid = Some(self.child.id());
                waiting.rss_before_bytes = self.last_rss;
                self.write(&waiting);
                if !remove_request(handle) {
                    self.latched = request_identity(handle);
                    self.abort_req(
                        Outcome::AbortedRequestUnreadable,
                        Some(&req),
                        "recycle_request_unremovable",
                    );
                    return None;
                }
                Some(req)
            }
            Err(tag) => {
                if !remove_request(handle) {
                    self.latched = request_identity(handle);
                }
                self.abort_req(Outcome::AbortedRequestUnreadable, None, tag);
                None
            }
        }
    }

    /// Handles one consumed request. `Some` ends supervision.
    fn recycle(&mut self, req: RecycleRequest) -> Option<Exit> {
        let handle = self.launch.handle;
        let id = req.session_id.clone();
        // A CROSS-SESSION request (design slice 2) is judged FIRST: consent, expiry and
        // replay, before identity, the quiet wait, the gates, the stop or any relaunch.
        // A refusal here leaves the child untouched.
        if let Err(tag) = self.foreign_gate(&req, &self.carried_nonces) {
            self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
            return None;
        }
        // A FRESH relaunch no longer resolves its proof here: the proof is single-use and must
        // be minted as late as possible, so the ordering is (1) a GATE before the stop, proof
        // discarded, and (2) the authoritative call AFTER the stop, immediately before exec.
        if let Err(tag) = verify_session_binding(self.launch.probe, self.child.id(), handle, &id) {
            self.abort_req(Outcome::AbortedIdentity, Some(&req), tag);
            return None;
        }
        let transcript = match resolve_transcript(handle, &self.launch.cwd, &id) {
            Ok(p) => p,
            Err(tag) => {
                self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
                return None;
            }
        };
        let baseline = match self.ensure_baseline() {
            Ok(b) => b,
            Err("recycle_child_exited") => {
                let tag = self.child_exited_tag(&req);
                self.abort_req(Outcome::AbortedChildExited, Some(&req), tag);
                return None;
            }
            Err(tag) => {
                self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
                return None;
            }
        };
        let mut probe = RealProbe {
            started: Instant::now(),
            transcript,
            sup: self,
        };
        let quiet = probe.sup.launch.timing.quiet;
        match wait_for_quiet(&mut probe, &quiet, &baseline) {
            QuietOutcome::Quiet => {}
            QuietOutcome::ChildExited => {
                let tag = self.child_exited_tag(&req);
                self.abort_req(Outcome::AbortedChildExited, Some(&req), tag);
                return None;
            }
            QuietOutcome::TimedOut => {
                self.abort_req(Outcome::AbortedNotQuiet, Some(&req), "recycle_not_quiet");
                return None;
            }
            QuietOutcome::Unresolved(tag) => {
                self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
                return None;
            }
        }
        // ── every refusal below leaves the child untouched ──
        // The session id can change while we waited (`/clear`): re-verify at the kill point.
        if let Err(tag) = verify_session_binding(self.launch.probe, self.child.id(), handle, &id) {
            self.abort_req(Outcome::AbortedIdentity, Some(&req), tag);
            return None;
        }
        // The capability layer's GATE for a fresh relaunch, BEFORE the stop: a not-ready verdict
        // here leaves the child untouched. The proof this call mints is DISCARDED — the capability layer's
        // tokens are single-use, and the authoritative one is minted after the stop.
        if req.mode == Mode::Fresh {
            if let Err(tag) = (self.hooks.fresh)(&self.launch.cwd, handle, &id) {
                self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
                return None;
            }
        }
        let plan = match &self.launch.plan {
            Ok(p) => p.clone(),
            Err(tag) => {
                self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
                return None;
            }
        };
        // The gates run FIRST (the Gate preflight rewrites its own `--settings` file); an artifact
        // they rewrote is re-recorded from their own write, anything else that differs from the
        // launch record is a change by someone else.
        let before = snapshot_artifacts(&self.artifacts);
        if let Err(tag) = (self.hooks.preflight)() {
            self.abort_req(Outcome::AbortedGate, Some(&req), tag);
            return None;
        }
        let after = snapshot_artifacts(&self.artifacts);
        match reconcile_artifacts(&self.artifacts, &before, &after) {
            Ok(fresh) => self.artifacts = fresh,
            Err(tag) => {
                self.abort_req(Outcome::AbortedGate, Some(&req), tag);
                return None;
            }
        }
        let captured = match list_descendants(self.child.id()) {
            Ok(d) => d,
            Err(tag) => {
                self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
                return None;
            }
        };
        // A cross-session request is re-judged HERE, immediately before the kill point: the
        // consent may have been revoked and the TTL may have run out during a quiet wait of up
        // to 600 s or during the gates above (design §D / A2 / A3). The replay check is skipped
        // — the nonce in the result file is this request's own, written when it was consumed.
        if let Err(tag) = self.foreign_gate(&req, &[]) {
            self.abort_req(Outcome::AbortedUnresolved, Some(&req), tag);
            return None;
        }
        let Some(window) = SignalWindow::open() else {
            self.abort_req(
                Outcome::AbortedUnresolved,
                Some(&req),
                "recycle_signal_handlers_failed",
            );
            return None;
        };
        let old_pid = self.child.id();
        let _ = writeln!(
            self.hooks.out,
            "csq: recycling this session now. An unsent prompt in the input box is not preserved."
        );
        let mut pending = result(Outcome::InProgress, Some(&req), None);
        pending.old_pid = Some(old_pid);
        pending.rss_before_bytes = self.last_rss;
        self.write(&pending);
        let status = match stop_child(&mut self.child, self.start, self.launch.timing.stop_grace) {
            Ok(s) => s,
            Err("recycle_child_exited") => {
                // It ended on its own between the quiet point and the stop: nothing to stop and
                // NOTHING to relaunch; the main loop reports the exit.
                let tag = self.child_exited_tag(&req);
                self.abort_req(Outcome::AbortedChildExited, Some(&req), tag);
                return None;
            }
            Err("recycle_kill_failed") => {
                // SIGTERM was delivered but the escalation failed: the old process's state is
                // unknown, and NOTHING was relaunched. Say so; keep supervising what is there.
                let mut r = result(Outcome::Failed, Some(&req), Some("recycle_kill_failed"));
                r.old_pid = Some(old_pid);
                self.write(&r);
                let _ = writeln!(
                    self.hooks.out,
                    "csq: RECYCLE FAILED (recycle_kill_failed): the old process may be stopping or still running and was NOT relaunched."
                );
                return None;
            }
            Err(tag) => {
                self.abort_req(Outcome::AbortedIdentity, Some(&req), tag);
                return None;
            }
        };
        lifecycle::waited(self.ticket.as_ref(), &status);
        terminate_descendants(&captured, self.launch.timing.descendant_grace);
        (self.hooks.rotate_audit)();
        // Verified again IMMEDIATELY before the spawn: the old child is already gone, so a
        // change here cannot be undone by aborting; it ends in the loud failure path.
        if let Err(tag) = verify_artifacts(&self.artifacts) {
            self.fail(Some(&id), tag, Some(old_pid));
            return Some(Exit::RecycleFailed(Some(status)));
        }
        // X1: the guard manifest is verified AGAIN at the spawn instant, exactly
        // as the first launch's `commit` does. The gate check ran before the
        // stop; the stop window is the one interval only this check covers.
        if let Err(tag) = guard_manifest_refusal(self.launch.handle, &self.launch.cwd) {
            self.fail(Some(&id), tag, Some(old_pid));
            return Some(Exit::RecycleFailed(Some(status)));
        }
        // The AUTHORITATIVE proof: minted after the stop, immediately before exec, so it can
        // neither expire across the quiet wait nor be reused. If it fails here the session would
        // otherwise be left dead, so the verified RESUME path takes over (ROOT ruling
        // 2026-11-04): same identity, licence and launch gates, no fresh handover, and the
        // readiness tag is carried into the result as `fresh_fell_back_to_resume`.
        let (next_fresh, fell_back) = match req.mode {
            Mode::Resume => (None, None),
            Mode::Fresh => match (self.hooks.fresh)(&self.launch.cwd, handle, &id) {
                Ok(ctx) if fresh_proof_ok(&ctx, &id) => (Some(ctx), None),
                // A context that cannot carry a VALID proof must never exec. The resume path
                // takes over, exactly as for a mint that failed (spec 36.10: a fresh exec NEVER
                // happens without one).
                Ok(_) => (None, Some("recycle_proof_invalid")),
                Err(tag) => (None, Some(tag)),
            },
        };
        if let Some(tag) = fell_back {
            self.fell_back_to_resume = Some(tag);
            let _ = writeln!(
                self.hooks.out,
                "csq: WARNING: fresh relaunch unavailable ({tag}); resuming the conversation instead."
            );
        }
        let next = relaunch_command(self.spec, &plan, &id, next_fresh.as_ref());
        // an internal ticket: the carried TMPDIR may point at a directory that was removed
        // since the first launch; re-ensure it (and set it explicitly before
        // the spawn), refusing rather than execing with an unverified temp dir.
        let mut next = match super::recycle::relaunch_with_session_tmpdir(handle, next) {
            Ok(cmd) => cmd,
            Err(tag) => {
                self.fail(Some(&id), tag, Some(old_pid));
                return Some(Exit::RecycleFailed(Some(status)));
            }
        };
        // P2: a Gate can attach after the preflight; a relaunch whose command
        // is not Gate-pinned cannot honour it.
        if let Err(tag) = (self.hooks.gate_recheck)(&next) {
            self.fail(Some(&id), tag, Some(old_pid));
            return Some(Exit::RecycleFailed(Some(status)));
        }
        // The SAME bounded ETXTBSY tolerance as a readiness spawn, and the stakes are higher:
        // the old child is already stopped, so a transient writer of the relaunch program (a
        // `claude` upgrade landing mid-relaunch) must not leave a dead session.
        let child = match super::recycle::spawn_relaunch(&mut next, &mut |_| {}) {
            Ok(c) => c,
            Err(_) => {
                self.fail(Some(&id), "recycle_spawn_failed", Some(old_pid));
                return Some(Exit::RecycleFailed(Some(status)));
            }
        };
        self.start = crate::sessions::process_start_time(child.id());
        self.ticket = lifecycle::capture_child(handle, &child);
        if let Ok(abs) = std::fs::canonicalize(handle) {
            if crate::accounts::markers::write_live_cc_pid(&abs, child.id()).is_err() {
                tracing::warn!(
                    error_kind = "live_cc_pid_write_failed",
                    "child pid marker not updated"
                );
            }
        }
        if write_supervisor(handle, child.id(), Ok(()), &self.launch.cwd).is_err() {
            // The marker still names the DEAD child: the verb would refuse the new one as
            // unsupervised, and a stale marker must not keep honouring requests.
            self.recycle_enabled = false;
            let _ = writeln!(
                self.hooks.out,
                "csq: WARNING: the supervisor marker could not be updated; session recycle is disabled for the rest of this session."
            );
        }
        let new_pid = child.id();
        self.child = child;
        self.baseline = None;
        self.launched_at = Instant::now();
        pending.new_pid = Some(new_pid);
        pending.at = now_rfc3339();
        if let Some(sig) = window.pending() {
            // A signal landed while the old child was down: the replacement exists, so say so,
            // hand the signal to it (it was spawned after the signal, so it never saw it) and let
            // the caller re-raise it on csq.
            pending.outcome = Outcome::Interrupted;
            pending.tag = Some("recycle_interrupted_by_signal".into());
            self.write(&pending);
            // Never fall back to pid 0: `kill(0, sig)` signals csq's entire
            // process group. The child pid is always our own un-reaped child,
            // so the conversion failing is not expected; if it ever does, skip
            // the signal and say so rather than widening the blast radius.
            let target = i32::try_from(new_pid).ok().filter(|pid| *pid > 1);
            let _ = writeln!(
                self.hooks.out,
                "csq: RECYCLE INTERRUPTED by signal {sig}: the replacement session (pid {new_pid}) was started and the signal {}.",
                if target.is_some() {
                    "was forwarded to it"
                } else {
                    "could NOT be forwarded to it"
                }
            );
            // SAFETY: `new_pid` is our own un-reaped child; the signal number came from the handler.
            if let Some(pid) = target {
                unsafe { libc::kill(pid, sig) };
            }
            let deadline = Instant::now() + self.launch.timing.stop_grace;
            while Instant::now() < deadline && matches!(self.child.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(25));
            }
            return Some(Exit::Interrupted(sig));
        }
        self.write(&pending);
        self.settling = Some((Instant::now(), pending));
        let _ = writeln!(
            self.hooks.out,
            "csq: session recycled in place (resuming {id})."
        );
        self.next_sample = Instant::now();
        None
    }

    /// Loud failure: banner, `failed` result, best-effort owner ping. The caller keeps the handle dir.
    fn fail(&mut self, id: Option<&str>, tag: Tag, old_pid: Option<u32>) {
        let mut r = result(Outcome::Failed, None, Some(tag));
        r.session_id = id.map(str::to_string);
        r.old_pid = old_pid;
        self.write(&r);
        let handle = &self.launch.display_handle;
        let sid = id.unwrap_or("<session-id>");
        let csq_run = self
            .launch
            .account
            .map(|n| format!("\n    or:  csq run {n}"))
            .unwrap_or_default();
        let _ = writeln!(
            self.hooks.out,
            "\n!!! csq: SESSION RECYCLE FAILED ({tag}) !!!\n\
             The old Claude Code process was stopped and no replacement is running.\n\
             Your conversation is intact. Resume it manually:\n    \
             CLAUDE_CONFIG_DIR={handle} claude --resume {sid}{csq_run}\n\
             The handle dir was kept (not removed).\n"
        );
        (self.hooks.notify_owner)(&format!(
            "csq: session recycle FAILED ({tag}). Resume with: claude --resume {sid}"
        ));
    }
}

struct RealProbe<'a, 'b, 'c> {
    started: Instant,
    transcript: PathBuf,
    sup: &'a mut Sup<'b, 'c>,
}

impl QuietProbe for RealProbe<'_, '_, '_> {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
    fn sleep(&mut self, d: Duration) {
        // Keep the memory view fresh while waiting.
        if Instant::now() >= self.sup.next_sample {
            self.sup.sample();
            self.sup.next_sample = Instant::now() + self.sup.launch.timing.sample_interval;
        }
        std::thread::sleep(d);
    }
    fn child_alive(&mut self) -> bool {
        matches!(self.sup.child.try_wait(), Ok(None))
    }
    fn transcript_age(&mut self) -> Result<Duration, Tag> {
        file_age(&self.transcript)
    }
    fn turn_state(&mut self) -> Result<TurnState, Tag> {
        read_turn_state(&self.transcript)
    }
    fn subagent_age(&mut self) -> Result<Duration, Tag> {
        subagent_age(&self.transcript)
    }
    fn descendants(&mut self) -> Result<Vec<(u32, u64)>, Tag> {
        list_descendants(self.sup.child.id())
    }
}

#[cfg(test)]
mod tests {
    use super::super::recycle::*;
    use super::super::recycle_consent::{
        revoke_consent, write_consent, ConsentRecord, RequesterRecord,
    };
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn kill9(pid: u32) {
        // SAFETY: test-owned stub child pid; SIGKILL has no pointer arguments.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }

    fn alive(pid: u32) -> bool {
        // SAFETY: signal 0 only probes existence.
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    /// The RELAUNCH spawn carries the same bounded ETXTBSY tolerance as a readiness spawn, and
    /// the release happens INSIDE attempt 2 — strictly after attempt 1 failed, strictly before
    /// attempt 2 runs — so the retry is exercised by construction, not by a timing race.
    /// LINUX ONLY: Darwin's exec does not fail while a writer holds the file.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_transiently_busy_relaunch_program_is_retried() {
        use std::sync::Mutex;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("claude");
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let writer = Mutex::new(Some(
            std::fs::OpenOptions::new().write(true).open(&p).unwrap(),
        ));
        let mut seen = 0u32;
        let mut cmd = std::process::Command::new(&p);
        let mut child = spawn_relaunch(&mut cmd, &mut |attempt| {
            seen = attempt;
            if attempt == 2 {
                writer.lock().unwrap().take();
            }
        })
        .expect("a relaunch must not die on a transient writer");
        assert!(
            seen >= 2,
            "the first attempt failed and the second one was needed"
        );
        let _ = child.wait();
    }

    /// Ceiling of every condition wait in these tests. It bounds a wait that
    /// returns as soon as its condition holds, so it never slows a passing run;
    /// it only has to outlast a heavily loaded sign-off host (a 30 s ceiling
    /// timed out there while the stub had simply not been scheduled yet).
    const WAIT_CEILING: Duration = Duration::from_secs(120);

    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + WAIT_CEILING;
        while Instant::now() < end {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for {what}");
    }

    fn fast() -> Timing {
        Timing {
            poll: Duration::from_millis(20),
            sample_interval: Duration::from_millis(50),
            quiet: QuietParams {
                dwell: Duration::from_millis(150),
                poll: Duration::from_millis(20),
                max_wait: Duration::from_secs(5),
            },
            stop_grace: Duration::from_millis(500),
            descendant_grace: Duration::from_millis(300),
            settle: Duration::from_millis(400),
        }
    }

    struct Probe {
        own: Result<String, Tag>,
        shared: bool,
    }
    impl SessionProbe for Probe {
        fn session_id_of(&self, _: u32, _: Option<&Path>) -> Result<String, Tag> {
            self.own.clone()
        }
        fn held_by_other(&self, _: &str, _: u32) -> Result<bool, Tag> {
            Ok(self.shared)
        }
    }

    struct Rig {
        dir: tempfile::TempDir,
        handle: PathBuf,
        cwd: PathBuf,
        log: PathBuf,
        script: PathBuf,
        transcript: PathBuf,
    }

    fn entry(v: serde_json::Value) -> String {
        format!("{v}\n")
    }
    fn ended_transcript() -> String {
        entry(serde_json::json!({"type":"user"}))
            + &entry(
                serde_json::json!({"type":"assistant","message":{"stop_reason":"end_turn","content":[{"type":"text"}]}}),
            )
    }
    fn tool_use_transcript() -> String {
        entry(serde_json::json!({"type":"user"}))
            + &entry(
                serde_json::json!({"type":"assistant","message":{"stop_reason":"tool_use","content":[{"type":"tool_use"}]}}),
            )
    }

    fn rig(body: &str) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let handle = dir.path().join("term-1");
        let cwd = dir.path().join("work");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        let slug_dir = handle.join("projects").join(cwd_slug(&cwd));
        std::fs::create_dir_all(&slug_dir).unwrap();
        let transcript = slug_dir.join(format!("{ID}.jsonl"));
        std::fs::write(&transcript, ended_transcript()).unwrap();
        let log = dir.path().join("argv.log");
        let script = dir.path().join("stub-claude");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$$ $*\" >> \"{}\"\n{body}\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        Rig {
            dir,
            handle,
            cwd,
            log,
            script,
            transcript,
        }
    }

    #[derive(Default)]
    struct Seen {
        audit: u32,
        pings: Vec<String>,
        out: Vec<u8>,
        gates: u32,
    }

    type GateRecheck = Box<dyn FnMut(&Command) -> Result<(), Tag>>;
    type FreshRig = Box<dyn FnMut(&Path, &Path, &str) -> Result<FreshContext, Tag>>;

    struct Opts<'a> {
        args: &'a [&'a str],
        timing: Timing,
        probe: Probe,
        gate: Box<dyn FnMut() -> Result<(), Tag>>,
        gate_recheck: GateRecheck,
        on_rotate: Box<dyn FnMut()>,
        artifacts: Result<Vec<LaunchArtifact>, Tag>,
        fresh: FreshRig,
    }
    fn opts<'a>(args: &'a [&'a str]) -> Opts<'a> {
        Opts {
            args,
            timing: fast(),
            probe: Probe {
                own: Ok(ID.into()),
                shared: false,
            },
            gate: Box::new(|| Ok(())),
            on_rotate: Box::new(|| {}),
            artifacts: Ok(vec![]),
            gate_recheck: Box::new(|_| Ok(())),
            // The closed seam, exactly as production ships it until the capability layer's contract lands.
            fresh: Box::new(|_, _, _| Err("recycle_fresh_context_unavailable")),
        }
    }

    fn run(rig: &Rig, o: Opts<'_>, seen: &mut Seen) -> Exit {
        // Signal windows are process-wide: one supervised recycle at a time in this test binary.
        let _serial = WINDOW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut spec = Command::new(&rig.script);
        spec.args(o.args).current_dir(&rig.cwd);
        let user: Vec<OsString> = o.args.iter().map(OsString::from).collect();
        let plan = build_plan(&spec, &user);
        let first = spec.spawn().unwrap();
        let launch = Launch {
            handle: &rig.handle,
            cwd: rig.cwd.clone(),
            account: Some(7),
            display_handle: "~/.claude/accounts/term-1".into(),
            timing: o.timing,
            plan,
            artifacts: o.artifacts,
            probe: &o.probe,
        };
        let Seen {
            audit,
            pings,
            out,
            gates,
        } = seen;
        let mut on_rotate = o.on_rotate;
        let mut rotate = || {
            *audit += 1;
            on_rotate();
        };
        let mut notify = |t: &str| pings.push(t.to_string());
        let mut gate = o.gate;
        let mut preflight = || {
            *gates += 1;
            gate()
        };
        let mut gate_recheck = o.gate_recheck;
        let mut fresh = o.fresh;
        let mut hooks = Hooks {
            rotate_audit: &mut rotate,
            preflight: &mut preflight,
            gate_recheck: &mut gate_recheck,
            notify_owner: &mut notify,
            fresh: &mut fresh,
            out,
        };
        supervise(&spec, first, None, &launch, &mut hooks)
    }

    fn started(rig: &Rig) -> impl Fn() -> bool {
        let log = rig.log.clone();
        move || log.exists()
    }

    /// Helper thread: wait for the stub, write a request, wait for a result matching `pred`,
    /// return it after killing `victim(result)`.
    fn drive(
        rig: &Rig,
        pred: impl Fn(&RecycleResult) -> bool + Send + 'static,
        victim: impl Fn(&RecycleResult) -> u32 + Send + 'static,
    ) -> std::thread::JoinHandle<RecycleResult> {
        let handle = rig.handle.clone();
        let up = started(rig);
        std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
            wait_for("result", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| pred(&x))
            });
            let res = read_result(&handle).unwrap().unwrap();
            kill9(victim(&res));
            res
        })
    }

    fn log_lines(r: &Rig) -> Vec<String> {
        std::fs::read_to_string(&r.log)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    fn abort_case(own: Result<String, Tag>, shared: bool, tag: &str, outcome: Outcome) {
        let r = rig("exec sleep 8");
        let helper = drive(&r, move |x| x.outcome == outcome, |x| x.old_pid.unwrap());
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.probe = Probe { own, shared };
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(res.tag.as_deref(), Some(tag));
        assert_eq!(log_lines(&r).len(), 1, "the child was never relaunched");
        assert_eq!(
            (s.audit, s.gates),
            (0, 0),
            "nothing was stopped or re-gated"
        );
        assert!(String::from_utf8(s.out)
            .unwrap()
            .contains("RECYCLE ABORTED"));
    }

    #[test]
    fn a_fresh_request_without_the_capability_context_never_kills_the_child() {
        // 60 s, like dev's other explicitly-killed stubs: the stub must outlive the
        // supervisor's decision even on a saturated host, or the outcome races its exit.
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            // The VERB refuses fresh while the capability contract is unlanded, so the
            // request is written directly: even a request that exists must abort BEFORE
            // the child is touched, with the fixed tag and no kill.
            let req = serde_json::json!({
                "v": 1, "request_id": "deadbeef", "session_id": ID,
                "reason": "fresh", "requested_at": now_rfc3339(), "mode": "fresh"
            });
            write_raw_request(&handle, &req);
            wait_for("result", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::AbortedUnresolved)
            });
            let res = read_result(&handle).unwrap().unwrap();
            kill9(res.old_pid.unwrap());
            res
        });
        let mut s = Seen::default();
        let o = opts(&[]);
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(
            res.tag.as_deref(),
            Some("recycle_fresh_context_unavailable")
        );
        assert_eq!(res.mode, Mode::Fresh);
        assert_eq!(log_lines(&r).len(), 1, "the child was never relaunched");
        assert_eq!(
            (s.audit, s.gates),
            (0, 0),
            "nothing was stopped or re-gated for a fresh request"
        );
    }

    /// The fresh request body used by the two ordering tests below.
    fn fresh_request() -> serde_json::Value {
        serde_json::json!({
            "v": 1, "request_id": "deadbeef", "session_id": ID,
            "reason": "fresh", "requested_at": now_rfc3339(), "mode": "fresh"
        })
    }

    #[test]
    fn a_proof_that_fails_after_the_stop_relaunches_in_resume_mode() {
        // ROOT ruling 2026-11-04: the stop-to-exec window must never leave a dead session, so a
        // readiness failure AFTER the stop falls back to the verified resume path.
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_raw_request(&handle, &fresh_request());
            wait_for("fallback result", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::FreshFellBackToResume)
            });
            let res = read_result(&handle).unwrap().unwrap();
            kill9(res.new_pid.unwrap());
            res
        });
        // First call is the pre-stop gate; the second is the authoritative one, which fails.
        let mut calls = 0u32;
        let fresh = Box::new(move |_root: &Path, _cfg: &Path, _sid: &str| {
            calls += 1;
            if calls == 1 {
                Ok(FreshContext {
                    prompt: OsString::from("P"),
                    env: vec![],
                })
            } else {
                Err("recycle_not_ready")
            }
        });
        let mut s = Seen::default();
        let o = Opts { fresh, ..opts(&[]) };
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(res.outcome, Outcome::FreshFellBackToResume);
        assert_eq!(res.tag.as_deref(), Some("recycle_not_ready"));
        assert_eq!(s.audit, 1, "the old child was stopped exactly once");
        let argv = log_lines(&r);
        assert!(
            argv.iter().any(|l| l.contains("--resume")),
            "the fallback must RESUME the same conversation: {argv:?}"
        );
        assert!(
            String::from_utf8(s.out)
                .unwrap()
                .contains("resuming the conversation instead"),
            "the fallback is announced, never silent"
        );
    }

    /// A fresh context WITHOUT a valid proof must never exec: the supervisor asserts the
    /// invariant itself, so a hook that "succeeds" with an empty env falls back to RESUME.
    ///
    /// Discriminating check: removing the `fresh_proof_ok` guard execs the fresh argv (no
    /// `--resume`, the fixed prompt in argv) and this test fails on both assertions.
    #[test]
    fn a_fresh_context_without_a_valid_proof_never_execs_fresh() {
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_raw_request(&handle, &fresh_request());
            wait_for("fallback result", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::FreshFellBackToResume)
            });
            let res = read_result(&handle).unwrap().unwrap();
            kill9(res.new_pid.unwrap());
            res
        });
        // BOTH calls succeed — but with no proof in the environment.
        let fresh = Box::new(|_root: &Path, _cfg: &Path, _sid: &str| {
            Ok(FreshContext {
                prompt: OsString::from("FRESH-PROMPT-SENTINEL"),
                env: vec![],
            })
        });
        let mut s = Seen::default();
        let o = Opts { fresh, ..opts(&[]) };
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(res.outcome, Outcome::FreshFellBackToResume);
        assert_eq!(res.tag.as_deref(), Some("recycle_proof_invalid"));
        let argv = log_lines(&r);
        assert!(
            argv.iter().any(|l| l.contains("--resume")),
            "a proof-less context must fall back to RESUME, never exec fresh: {argv:?}"
        );
        assert!(
            !argv.iter().any(|l| l.contains("FRESH-PROMPT-SENTINEL")),
            "the fresh prompt must not appear in a resume relaunch: {argv:?}"
        );
    }

    #[test]
    fn a_proof_minted_after_the_stop_relaunches_fresh_with_no_conversation_flag() {
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_raw_request(&handle, &fresh_request());
            wait_for("recycled result", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::Recycled)
            });
            let res = read_result(&handle).unwrap().unwrap();
            kill9(res.new_pid.unwrap());
            res
        });
        let fresh = Box::new(|_root: &Path, _cfg: &Path, sid: &str| {
            Ok(FreshContext {
                prompt: OsString::from("Context recycle: fixed prompt"),
                env: vec![(
                    OsString::from(super::super::recycle::PROOF_ENV),
                    // Structurally valid for the OLD session: the supervisor now checks.
                    OsString::from(format!("v1,{},tok_1,{sid},1700000000", "a".repeat(64))),
                )],
            })
        });
        let mut s = Seen::default();
        let o = Opts { fresh, ..opts(&[]) };
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(res.outcome, Outcome::Recycled);
        let argv = log_lines(&r);
        let last = argv.last().expect("the relaunch was logged");
        assert!(
            !last.contains("--resume"),
            "a fresh relaunch must not select a conversation: {last}"
        );
        assert!(
            last.contains("Context recycle:"),
            "the fixed prompt is ONE positional: {last}"
        );
    }

    const REQID: &str = "99999999-8888-7777-6666-555555555555";

    /// A platform-ABSOLUTE handle: a leading `/` is root-without-prefix on Windows, where
    /// `Path::is_absolute` is false and the request/consent validators (correctly) refuse it.
    fn abs_handle(leaf: &str) -> String {
        std::env::temp_dir()
            .join(leaf)
            .to_string_lossy()
            .into_owned()
    }

    fn requester() -> RequesterRecord {
        RequesterRecord {
            session_id: REQID.into(),
            handle: abs_handle("h-req"),
        }
    }

    fn consent_for() -> ConsentRecord {
        ConsentRecord {
            v: 1,
            target_session_id: ID.into(),
            allow: vec![requester()],
            expires_at_unix: chrono::Utc::now().timestamp() + 600,
            max_uses: 1,
            used: 0,
        }
    }

    /// Writes a raw request JSON ATOMICALLY, 0600 at creation.
    ///
    /// `write` then `set_permissions` leaves two real windows against a supervisor polling the
    /// handle dir: the bounded read can see the file before the chmod (and must call it
    /// unreadable), and the supervisor can consume+remove it before the chmod (ENOENT — the
    /// macOS flake this replaced). Writing a private temp and renaming means the supervisor sees
    /// either no file or the whole file, so there is no window to wait out.
    fn write_raw_request(handle: &Path, value: &serde_json::Value) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let tmp = handle.join(".tmp-test-request");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .unwrap();
        f.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
        f.sync_all().unwrap();
        drop(f);
        std::fs::rename(&tmp, handle.join(REQUEST_FILE)).unwrap();
    }

    fn write_foreign(handle: &Path, nonce: &str, exp: i64) {
        let req = serde_json::json!({
            // v2 is the FOREIGN shape (a v1 reader refuses it as unreadable — see
            // `read_request`); the self-request fixtures above stay on v1.
            "v": 2, "request_id": "deadbeef", "session_id": ID, "reason": "x",
            "requested_at": now_rfc3339(), "mode": "fresh",
            "requested_by": {"session_id": REQID, "handle": abs_handle("h-req")},
            "nonce": nonce, "expires_at_unix": exp
        });
        write_raw_request(handle, &req);
    }

    /// One foreign request through a live supervisor; asserts the child is never touched.
    fn foreign_case(
        consent: Option<ConsentRecord>,
        ttl_off: i64,
        prior_result_nonce: Option<&'static str>,
        expect: &'static str,
    ) {
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let h = handle.clone();
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            if let Some(c) = consent {
                write_consent(&h, &c).unwrap();
            }
            if let Some(n) = prior_result_nonce {
                let mut prior = result(Outcome::Recycled, None, None);
                prior.nonce = Some(n.to_string());
                write_result(&h, &prior).unwrap();
            }
            write_foreign(
                &h,
                "abcdef0123456789",
                chrono::Utc::now().timestamp() + ttl_off,
            );
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut last = None;
            while Instant::now() < deadline {
                last = read_result(&h).ok().flatten();
                if last.as_ref().is_some_and(|x| {
                    x.outcome == Outcome::AbortedUnresolved && x.tag.as_deref() == Some(expect)
                }) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let res = last.unwrap_or_else(|| panic!("no result at all; wanted {expect}"));
            if res.tag.as_deref() != Some(expect) {
                panic!("the supervisor decided {:?}/{:?}, but this request must be refused as {expect}", res.outcome, res.tag);
            }
            kill9(res.old_pid.unwrap());
            res
        });
        let mut s = Seen::default();
        let o = opts(&[]);
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(res.tag.as_deref(), Some(expect));
        assert_eq!(log_lines(&r).len(), 1, "the child was never relaunched");
        assert_eq!(
            (s.audit, s.gates),
            (0, 0),
            "nothing was stopped or re-gated"
        );
        assert_eq!(
            res.nonce.as_deref(),
            Some("abcdef0123456789"),
            "the nonce is recorded"
        );
    }

    #[test]
    fn a_foreign_request_without_consent_never_kills_the_child() {
        foreign_case(None, 30, None, "xrecycle_not_consented");
    }

    #[test]
    fn a_foreign_request_past_its_ttl_never_kills_the_child() {
        // A2: quietly waiting longer than the TTL must not act, even with a valid consent.
        foreign_case(Some(consent_for()), -1, None, "xrecycle_request_stale");
    }

    #[test]
    fn a_replayed_foreign_nonce_never_kills_the_child() {
        foreign_case(
            Some(consent_for()),
            30,
            Some("abcdef0123456789"),
            "xrecycle_replay",
        );
    }

    #[test]
    fn a_foreign_request_inside_its_ttl_gets_past_the_consent_and_ttl_gates() {
        // A2's other half: a valid consent and a live TTL are NOT refused as stale or
        // unconsented — the request reaches the next gate. Today that is the unwired
        // capability seam, and reaching it is what proves the foreign gates let it through.
        foreign_case(
            Some(consent_for()),
            30,
            None,
            "recycle_fresh_context_unavailable",
        );
    }

    #[test]
    fn a_failed_result_keeps_the_consumed_nonce_and_the_history() {
        // Security R2 M2: `fail()` builds its result WITHOUT the request, and the request file
        // is already gone by then. If the nonce did not land on disk, a re-delivered copy of
        // the request would be judged against a history lacking it and accepted as fresh.
        let failed = result(
            Outcome::Failed,
            None,
            Some("recycle_new_child_exited_early"),
        );
        let carried = carry_consume(&failed, &["older".to_string()], Some("N"));
        assert_eq!(
            carried.nonce.as_deref(),
            Some("N"),
            "a post-stop failure must still name the nonce it consumed"
        );
        assert_eq!(carried.prior_nonces, vec!["older".to_string()]);
        // A SELF consume carries no nonce at all, and a result that already names one keeps it.
        assert_eq!(carry_consume(&failed, &[], None).nonce, None);
        let mut waiting = failed.clone();
        waiting.nonce = Some("M".to_string());
        waiting.prior_nonces = vec!["p".to_string()];
        let carried = carry_consume(&waiting, &["ignored".to_string()], Some("N"));
        assert_eq!(carried.nonce.as_deref(), Some("M"));
        assert_eq!(carried.prior_nonces, vec!["p".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn a_consume_cannot_start_while_the_per_target_lock_is_held() {
        // ROOT ruling (a): the supervisor marker is an atomic OVERWRITE with no exclusive
        // create, so two `csq run` supervisors can own one handle dir. The consume is therefore
        // serialised under the SAME per-target consent lock the writers take. Holding the lock
        // must stop the consume; remove that lock and the request is consumed within the first
        // polls, so both assertions below fail.
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let lock = crate::platform::lock::try_lock_file_bounded_nofollow(
            &crate::session::recycle_consent::consent_lock_path(&handle),
            50,
            std::time::Duration::from_millis(20),
        )
        .unwrap()
        .expect("the fixture holds the lock");
        let (obs_tx, obs_rx) = std::sync::mpsc::channel();
        let h = handle.clone();
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&h, ID, "r", &now_rfc3339(), Mode::Resume).unwrap();
            // Several poll intervals with the lock held: nothing may be consumed.
            std::thread::sleep(std::time::Duration::from_millis(300));
            let request_still_there = h.join(super::super::recycle::REQUEST_FILE).exists();
            let result_under_lock = read_result(&h).ok().flatten().map(|x| x.outcome);
            let _ = obs_tx.send((request_still_there, result_under_lock));
            drop(lock);
            // Released: the supervisor consumes and recycles the stub; end it normally.
            wait_for("recycled result", || {
                read_result(&h)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::Recycled)
            });
            let res = read_result(&h).unwrap().unwrap();
            kill9(res.new_pid.unwrap());
        });
        let mut s = Seen::default();
        let o = opts(&[]);
        let exit = run(&r, o, &mut s);
        helper.join().unwrap();
        let (request_still_there, result_under_lock) = obs_rx.recv().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert!(
            request_still_there,
            "a consume must not start while the per-target lock is held"
        );
        assert_eq!(
            result_under_lock, None,
            "no result may be written under the lock"
        );
    }

    /// A2/A3's DISCRIMINATING shape: the request is valid at pick-up (the pre-stop gate runs —
    /// `gates == 1` proves it), so the refusal can only come from the re-check immediately
    /// before the kill point. `during_gate` mutates the world between the two gates.
    fn foreign_kill_point_case(
        during_gate: impl FnOnce(PathBuf) + 'static,
        ttl_off: i64,
        expect: &'static str,
    ) {
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let h = handle.clone();
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_consent(&h, &consent_for()).unwrap();
            write_foreign(
                &h,
                "abcdef0123456789",
                chrono::Utc::now().timestamp() + ttl_off,
            );
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut last = None;
            while Instant::now() < deadline {
                last = read_result(&h).ok().flatten();
                if last.as_ref().is_some_and(|x| {
                    x.outcome == Outcome::AbortedUnresolved && x.tag.as_deref() == Some(expect)
                }) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let res = last.unwrap_or_else(|| panic!("no result at all; wanted {expect}"));
            assert_eq!(
                res.tag.as_deref(),
                Some(expect),
                "the supervisor decided {:?}/{:?}; the kill point must refuse as {expect}",
                res.outcome,
                res.tag
            );
            kill9(res.old_pid.unwrap());
            res
        });
        let mut during_gate = Some(during_gate);
        let gate_handle = r.handle.clone();
        let mut o = opts(&[]);
        // The capability seam is OPEN: the pre-stop fresh gate must pass for the flow to reach
        // the kill point. The post-stop call is never made — the request is refused first.
        o.fresh = Box::new(|_, _, _| {
            Ok(FreshContext {
                prompt: OsString::from("unused"),
                env: vec![],
            })
        });
        o.gate = Box::new(move || {
            if let Some(f) = during_gate.take() {
                f(gate_handle.clone());
            }
            Ok(())
        });
        let mut s = Seen::default();
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(
            s.gates, 1,
            "the pre-stop gate ran, so the FIRST foreign gate passed on a live TTL/consent: the \
             refusal is the kill-point re-check, not the pick-up gate"
        );
        assert_eq!(s.audit, 0, "nothing was stopped");
        assert_eq!(log_lines(&r).len(), 1, "the child was never relaunched");
        assert_eq!(res.nonce.as_deref(), Some("abcdef0123456789"));
    }

    #[test]
    fn a_request_that_goes_stale_during_the_gates_is_refused_at_the_kill_point() {
        // A2: the pick-up gate sees a live TTL; only the re-check before the kill can refuse it.
        // Remove that re-check and this test kills the child — the helper then times out
        // waiting for xrecycle_request_stale.
        //
        // The TTL must outlive PICK-UP on a loaded host, and the gate must outlive the TTL. A
        // cold mirror running four test threads took >1 s to pick a request up, so both margins
        // are seconds, not tenths: 4 s TTL, 4.6 s in the gate. If pick-up ever did outlast the
        // TTL, the `gates == 1` assertion below fails loudly rather than passing for the wrong
        // reason.
        foreign_kill_point_case(
            |_| std::thread::sleep(Duration::from_millis(4600)),
            4,
            "xrecycle_request_stale",
        );
    }

    #[test]
    fn a_consent_revoked_during_the_gates_is_refused_at_the_kill_point() {
        // A3: revocation between the pick-up gate and the stop must stop the kill.
        foreign_kill_point_case(
            |h| assert!(revoke_consent(&h), "the revocation lands"),
            30,
            "xrecycle_not_consented",
        );
    }

    #[test]
    fn a_foreign_well_formed_session_id_never_kills_the_child() {
        abort_case(
            Ok(OTHER.into()),
            false,
            "recycle_session_id_mismatch",
            Outcome::AbortedIdentity,
        );
    }

    #[test]
    fn an_unknown_session_binding_never_kills_the_child() {
        abort_case(
            Err("recycle_session_unknown"),
            false,
            "recycle_session_unknown",
            Outcome::AbortedIdentity,
        );
    }

    #[test]
    fn a_session_held_by_another_live_process_never_kills_the_child() {
        abort_case(
            Ok(ID.into()),
            true,
            "recycle_session_id_shared",
            Outcome::AbortedIdentity,
        );
    }

    #[test]
    fn recycle_resumes_the_bound_session_without_replaying_the_prompt() {
        let r = rig("exec sleep 8");
        let helper = drive(
            &r,
            |x| x.outcome == Outcome::Recycled,
            |x| x.new_pid.unwrap(),
        );
        let mut s = Seen::default();
        let exit = run(&r, opts(&["-c", "--model", "m", "kickoff prompt"]), &mut s);
        let res = helper.join().unwrap();
        assert!(
            matches!(exit, Exit::Exited(_)),
            "kill of the NEW child ends supervision"
        );
        assert_eq!(
            (s.audit, s.gates),
            (1, 1),
            "audit rotated once, gates re-run once"
        );
        assert!(s.pings.is_empty());
        assert_ne!(res.old_pid, res.new_pid);
        assert_eq!(res.session_id.as_deref(), Some(ID));
        assert!(res.request_id.is_some() && res.requested_at.is_some());
        let lines = log_lines(&r);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].ends_with("-c --model m kickoff prompt"),
            "{lines:?}"
        );
        assert!(
            lines[1].ends_with(&format!("--model m --resume {ID}")),
            "{lines:?}"
        );
        assert!(
            !lines[1].contains("kickoff") && !lines[1].contains(" -c"),
            "{lines:?}"
        );
        assert!(!r.handle.join(REQUEST_FILE).exists(), "request consumed");
        assert!(
            read_memory(&r.handle).unwrap().is_some(),
            "memory view written while supervising"
        );
        assert!(
            !r.handle.join(SUPERVISOR_FILE).exists(),
            "marker removed on exit"
        );
        drop(r.dir);
    }

    #[test]
    fn a_refused_launch_gate_leaves_the_child_untouched() {
        let r = rig("exec sleep 8");
        let helper = drive(
            &r,
            |x| x.outcome == Outcome::AbortedGate,
            |x| x.old_pid.unwrap(),
        );
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.gate = Box::new(|| Err("recycle_gate_launch_blocked"));
        let exit = run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(res.tag.as_deref(), Some("recycle_gate_launch_blocked"));
        assert_eq!((s.gates, s.audit), (1, 0));
        assert_eq!(log_lines(&r).len(), 1);
    }

    #[test]
    fn a_changed_launch_artifact_leaves_the_child_untouched() {
        let r = rig("exec sleep 8");
        let f = r.dir.path().join("scaffold.md");
        std::fs::write(&f, b"rules").unwrap();
        let rec = record_artifacts(&[
            OsString::from("--append-system-prompt-file"),
            f.clone().into_os_string(),
        ])
        .unwrap();
        std::fs::write(&f, b"swapped").unwrap();
        let helper = drive(
            &r,
            |x| x.outcome == Outcome::AbortedGate,
            |x| x.old_pid.unwrap(),
        );
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.artifacts = Ok(rec);
        run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert_eq!(res.tag.as_deref(), Some("recycle_launch_artifact_changed"));
        // R2 item 3a: the gates run FIRST (they rewrite their own files), then the check; the
        // refusal still precedes the stop, so nothing rotated and nothing was relaunched.
        assert_eq!(
            (s.gates, s.audit),
            (1, 0),
            "refused after the gates, before the stop"
        );
        assert_eq!(log_lines(&r).len(), 1);
    }

    #[test]
    fn a_pending_tool_use_aborts_at_the_cap_and_leaves_the_session_running() {
        let r = rig("exec sleep 8");
        std::fs::write(&r.transcript, tool_use_transcript()).unwrap();
        let mut t = fast();
        t.quiet.max_wait = Duration::from_millis(300);
        let helper = drive(
            &r,
            |x| x.outcome == Outcome::AbortedNotQuiet,
            |x| x.old_pid.unwrap(),
        );
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.timing = t;
        run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert_eq!(res.tag.as_deref(), Some("recycle_not_quiet"));
        assert_eq!((s.audit, s.gates), (0, 0));
        assert_eq!(log_lines(&r).len(), 1, "never relaunched");
        assert!(
            !r.handle.join(REQUEST_FILE).exists(),
            "request deleted on abort"
        );
    }

    #[test]
    fn a_child_that_exits_while_the_request_waits_writes_a_result() {
        let r = rig("exec sleep 1");
        std::fs::write(&r.transcript, tool_use_transcript()).unwrap();
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "m", &now_rfc3339(), Mode::Resume).unwrap();
        });
        let mut s = Seen::default();
        run(&r, opts(&[]), &mut s);
        helper.join().unwrap();
        let res = read_result(&r.handle).unwrap().unwrap();
        assert_eq!(res.outcome, Outcome::AbortedChildExited);
        assert_eq!(s.audit, 0);
    }

    #[test]
    fn a_request_during_the_settle_window_is_rejected_not_double_recycled() {
        let r = rig("exec sleep 60");
        let mut t = fast();
        t.settle = Duration::from_secs(3);
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "one", &now_rfc3339(), Mode::Resume).unwrap();
            wait_for("relaunched", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.new_pid.is_some())
            });
            assert_eq!(
                check_idle(&handle),
                Err("recycle_in_flight"),
                "the verb refuses too"
            );
            write_request(&handle, ID, "two", &now_rfc3339(), Mode::Resume).unwrap();
            wait_for("second request consumed", || {
                !handle.join(REQUEST_FILE).exists()
            });
            let res = read_result(&handle).unwrap().unwrap();
            kill9(res.new_pid.unwrap());
            res
        });
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.timing = t;
        run(&r, o, &mut s);
        let res = helper.join().unwrap();
        assert_eq!(
            res.outcome,
            Outcome::InProgress,
            "the first recycle's state was not clobbered"
        );
        assert_eq!(log_lines(&r).len(), 2, "no second relaunch");
        assert_eq!(s.audit, 1);
        assert!(String::from_utf8(s.out)
            .unwrap()
            .contains("RECYCLE REQUEST REJECTED"));
    }

    #[test]
    fn failed_relaunch_keeps_handle_writes_failed_pings_and_prints_banner() {
        let r = rig("case \" $* \" in *\" --resume \"*) exit 3;; esac\nexec sleep 8");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
        });
        let mut s = Seen::default();
        let exit = run(&r, opts(&[]), &mut s);
        helper.join().unwrap();
        assert!(matches!(exit, Exit::RecycleFailed(Some(_))));
        assert!(exit.keeps_handle());
        assert!(r.handle.is_dir(), "handle dir kept");
        let res = read_result(&r.handle).unwrap().unwrap();
        assert_eq!(res.outcome, Outcome::Failed);
        assert_eq!(res.tag.as_deref(), Some("recycle_new_child_exited_early"));
        let banner = String::from_utf8(s.out).unwrap();
        assert!(
            banner.contains(&format!("claude --resume {ID}")),
            "{banner}"
        );
        assert!(banner.contains("csq run 7"), "{banner}");
        assert!(banner.contains("~/.claude/accounts/term-1"), "{banner}");
        assert!(
            !banner.contains(r.dir.path().to_str().unwrap()),
            "no absolute path: {banner}"
        );
        assert_eq!(s.pings.len(), 1);
        assert!(s.pings[0].contains("recycle_new_child_exited_early"));
        assert!(!Exit::Exited(std::process::ExitStatus::default()).keeps_handle());
    }

    /// P2: a Gate that appears after the preflight is refused at the spawn
    /// instant with the loud failed path, and no replacement is spawned.
    #[test]
    fn a_gate_that_appears_after_the_preflight_refuses_the_relaunch() {
        let r = rig("exec sleep 8");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
        });
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.gate_recheck = Box::new(|_| Err("recycle_gate_attached_refused"));
        let exit = run(&r, o, &mut s);
        helper.join().unwrap();
        assert!(matches!(exit, Exit::RecycleFailed(Some(_))));
        let res = read_result(&r.handle).unwrap().unwrap();
        assert_eq!(res.outcome, Outcome::Failed);
        assert_eq!(res.tag.as_deref(), Some("recycle_gate_attached_refused"));
        assert_eq!(log_lines(&r).len(), 1, "no replacement spawn");
        assert_eq!(s.pings.len(), 1);
    }

    #[test]
    fn a_clean_user_exit_inside_the_settle_window_is_not_a_failure() {
        let r = rig("case \" $* \" in *\" --resume \"*) exit 0;; esac\nexec sleep 8");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
        });
        let mut s = Seen::default();
        let exit = run(&r, opts(&[]), &mut s);
        helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(st) if st.success()));
        assert!(!exit.keeps_handle());
        assert!(
            s.pings.is_empty(),
            "no owner ping for the operator quitting"
        );
        assert_eq!(
            read_result(&r.handle).unwrap().unwrap().outcome,
            Outcome::Recycled
        );
    }

    #[test]
    fn unreadable_request_fails_toward_not_killing_and_a_directory_is_reported_once() {
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            std::fs::create_dir(handle.join(REQUEST_FILE)).unwrap();
            wait_for("abort result", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::AbortedRequestUnreadable)
            });
            std::thread::sleep(Duration::from_millis(500)); // 25 supervisor polls
            kill9(read_result(&handle).unwrap().unwrap().old_pid.unwrap());
        });
        let mut s = Seen::default();
        let exit = run(&r, opts(&[]), &mut s);
        helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        assert_eq!(log_lines(&r).len(), 1);
        assert_eq!(s.audit, 0);
        let out = String::from_utf8(s.out).unwrap();
        assert_eq!(
            out.matches("RECYCLE ABORTED").count(),
            1,
            "latched, not repeated: {out}"
        );
    }

    #[test]
    fn a_launch_that_cannot_be_relaunched_disables_recycle_and_ignores_requests() {
        let r = rig("exec sleep 60");
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            wait_for("marker", || handle.join(SUPERVISOR_FILE).exists());
            let m: SupervisorMarker =
                serde_json::from_slice(&std::fs::read(handle.join(SUPERVISOR_FILE)).unwrap())
                    .unwrap();
            assert!(!m.relaunch_ok);
            assert_eq!(
                m.relaunch_tag.as_deref(),
                Some("recycle_argv_unclassifiable")
            );
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            assert!(
                handle.join(REQUEST_FILE).exists(),
                "a disabled supervisor never consumes requests"
            );
            kill9(m.child_pid);
        });
        let mut s = Seen::default();
        run(&r, opts(&["-p", "x"]), &mut s);
        helper.join().unwrap();
        assert_eq!(log_lines(&r).len(), 1);
        assert_eq!((s.audit, s.gates), (0, 0));
    }

    #[test]
    fn descendants_of_the_stopped_child_are_terminated_after_the_stop() {
        // The stub outlives the whole recycle (the helper kills both launches):
        // with `sleep 8` a loaded host let the first child exit on its own
        // before the request was consumed, so "recycled" never came.
        let r = rig("sleep 60 </dev/null >/dev/null 2>&1 &\necho $! > \"$0.bg\"\nexec sleep 60");
        let bg = PathBuf::from(format!("{}.bg", r.script.display()));
        let (handle, bg2) = (r.handle.clone(), bg.clone());
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("bg spawned", || {
                bg2.exists() && std::fs::read_to_string(&bg2).is_ok_and(|s| !s.trim().is_empty())
            });
            let first_bg: u32 = std::fs::read_to_string(&bg2)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(alive(first_bg));
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
            wait_for("recycled", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.new_pid.is_some())
            });
            wait_for("old descendant gone", || !alive(first_bg));
            let res = read_result(&handle).unwrap().unwrap();
            // reap the NEW launch's own background sleep and child
            wait_for("second bg", || {
                std::fs::read_to_string(&bg2)
                    .is_ok_and(|s| s.trim().parse::<u32>().is_ok_and(|p| p != first_bg))
            });
            kill9(
                std::fs::read_to_string(&bg2)
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap(),
            );
            kill9(res.new_pid.unwrap());
        });
        let mut s = Seen::default();
        run(&r, opts(&[]), &mut s);
        helper.join().unwrap();
    }

    #[test]
    fn stop_child_escalates_to_sigkill_and_refuses_on_identity_mismatch() {
        use std::os::unix::process::ExitStatusExt;
        let r = rig("trap : TERM\necho ready >> \"$0.ready\"\nwhile :; do sleep 1 >/dev/null 2>&1 </dev/null; done");
        let mut child = Command::new(&r.script).spawn().unwrap();
        let ready = PathBuf::from(format!("{}.ready", r.script.display()));
        wait_for("trap installed", || ready.exists());
        let start = crate::sessions::process_start_time(child.id());
        assert!(start.is_some());
        assert_eq!(
            stop_child(
                &mut child,
                Some(start.unwrap() + 1000),
                Duration::from_millis(200)
            )
            .unwrap_err(),
            "recycle_pid_identity_changed"
        );
        assert_eq!(
            stop_child(&mut child, None, Duration::from_millis(200)).unwrap_err(),
            "recycle_pid_identity_changed"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "unverified identity must not signal"
        );
        let status = stop_child(&mut child, start, Duration::from_millis(300)).unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "TERM ignored, so KILL after the grace"
        );
    }

    #[test]
    fn a_failed_supervisor_marker_write_really_disables_recycle() {
        let r = rig("exec sleep 60");
        // A directory where the marker must be published: the replace fails.
        std::fs::create_dir(r.handle.join(SUPERVISOR_FILE)).unwrap();
        let handle = r.handle.clone();
        let up = started(&r);
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            assert!(handle.join(REQUEST_FILE).exists(), "never consumed");
            // the stub is the only claude child: find it from the log
            let line = std::fs::read_to_string(handle.parent().unwrap().join("argv.log")).unwrap();
            kill9(line.split_whitespace().next().unwrap().parse().unwrap());
        });
        let mut s = Seen::default();
        run(&r, opts(&[]), &mut s);
        helper.join().unwrap();
        assert_eq!((s.audit, s.gates), (0, 0));
        assert_eq!(log_lines(&r).len(), 1);
    }

    fn first_pid(r: &Rig) -> u32 {
        let l = std::fs::read_to_string(&r.log).unwrap();
        l.split_whitespace().next().unwrap().parse().unwrap()
    }

    /// Item 2: a REAL SIGTERM sent to the process inside the stop-to-spawn window (the audit
    /// rotation hook runs there) must not kill csq; the replacement is spawned, the signal is
    /// forwarded to it, and a terminal result + banner are written.
    #[test]
    fn a_real_sigterm_in_the_stop_to_spawn_window_is_flagged_forwarded_and_reported() {
        let r = rig("exec sleep 8");
        let (handle, up) = (r.handle.clone(), started(&r));
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
        });
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.on_rotate = Box::new(|| {
            // SAFETY: raising SIGTERM at our own process while the window's handler is installed.
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        });
        let exit = run(&r, o, &mut s);
        helper.join().unwrap();
        assert!(matches!(exit, Exit::Interrupted(sig) if sig == libc::SIGTERM));
        assert!(exit.keeps_handle());
        let res = read_result(&r.handle).unwrap().unwrap();
        assert_eq!(res.outcome, Outcome::Interrupted);
        assert_eq!(res.tag.as_deref(), Some("recycle_interrupted_by_signal"));
        let new_pid = res.new_pid.unwrap();
        assert_eq!(log_lines(&r).len(), 2, "the replacement WAS spawned");
        assert!(
            !alive(new_pid),
            "the forwarded SIGTERM stopped the replacement"
        );
        let out = String::from_utf8(s.out).unwrap();
        assert!(out.contains("RECYCLE INTERRUPTED by signal 15"), "{out}");
        assert!(
            !SignalWindow::handler_installed(libc::SIGTERM),
            "dispositions restored"
        );
    }

    /// Item 5: a descendant that appears AFTER launch settle (a background shell task) is busy.
    #[test]
    fn a_background_child_started_after_launch_keeps_the_session_not_quiet() {
        let r = rig(
            "sleep 1 </dev/null >/dev/null 2>&1\nsleep 60 </dev/null >/dev/null 2>&1 &\necho $! > \"$0.bg\"\nexec sleep 60",
        );
        let bg = PathBuf::from(format!("{}.bg", r.script.display()));
        let (handle, bg2) = (r.handle.clone(), bg.clone());
        let helper = std::thread::spawn(move || {
            wait_for("bg spawned", || {
                std::fs::read_to_string(&bg2).is_ok_and(|s| s.trim().parse::<u32>().is_ok())
            });
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
            wait_for("not quiet", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::AbortedNotQuiet)
            });
            let res = read_result(&handle).unwrap().unwrap();
            kill9(
                std::fs::read_to_string(&bg2)
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap(),
            );
            kill9(res.old_pid.unwrap());
        });
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.timing.quiet.max_wait = Duration::from_millis(800);
        run(&r, o, &mut s);
        helper.join().unwrap();
        assert_eq!(log_lines(&r).len(), 1, "never relaunched");
        assert_eq!((s.audit, s.gates), (0, 0));
    }

    /// Item 10: from the moment the request is consumed a recycle is already visible as in flight.
    #[test]
    fn no_second_request_can_be_queued_between_consuming_the_request_and_the_waiting_result() {
        let r = rig("exec sleep 60");
        let (handle, up) = (r.handle.clone(), started(&r));
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
            let mut gap = false;
            let end = Instant::now() + WAIT_CEILING;
            while Instant::now() < end {
                if read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.new_pid.is_some())
                {
                    break;
                }
                if !handle.join(REQUEST_FILE).exists() && check_idle(&handle).is_ok() {
                    gap = true;
                }
            }
            wait_for("recycled", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::Recycled)
            });
            kill9(read_result(&handle).unwrap().unwrap().new_pid.unwrap());
            gap
        });
        let mut s = Seen::default();
        run(&r, opts(&[]), &mut s);
        assert!(
            !helper.join().unwrap(),
            "no window where no request AND no in-flight result"
        );
    }

    /// Item 11: a marker that cannot be refreshed after the relaunch disables recycle.
    #[test]
    fn a_stale_supervisor_marker_after_the_relaunch_disables_recycle() {
        let r = rig("exec sleep 60");
        let (handle, up) = (r.handle.clone(), started(&r));
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "one", &now_rfc3339(), Mode::Resume).unwrap();
            wait_for("waiting", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.outcome == Outcome::Waiting)
            });
            // Make the marker un-replaceable before the relaunch refreshes it.
            std::fs::remove_file(handle.join(SUPERVISOR_FILE)).unwrap();
            std::fs::create_dir(handle.join(SUPERVISOR_FILE)).unwrap();
            wait_for("relaunched", || {
                read_result(&handle)
                    .ok()
                    .flatten()
                    .is_some_and(|x| x.new_pid.is_some())
            });
            write_request(&handle, ID, "two", &now_rfc3339(), Mode::Resume).unwrap();
            std::thread::sleep(Duration::from_millis(600)); // well past the settle window
            let still_there = handle.join(REQUEST_FILE).exists();
            kill9(read_result(&handle).unwrap().unwrap().new_pid.unwrap());
            still_there
        });
        let mut s = Seen::default();
        run(&r, opts(&[]), &mut s);
        assert!(
            helper.join().unwrap(),
            "a disabled supervisor never consumes the second request"
        );
        assert!(String::from_utf8(s.out)
            .unwrap()
            .contains("session recycle is disabled"));
        assert_eq!(log_lines(&r).len(), 2);
    }

    /// Item 3: the gates rewrite their own settings file; that is re-recorded, not "changed".
    #[test]
    fn an_artifact_the_gates_rewrite_is_re_recorded_and_the_recycle_proceeds() {
        let r = rig("exec sleep 8");
        let f = r.dir.path().join("settings.json");
        std::fs::write(&f, b"v1").unwrap();
        let rec =
            record_artifacts(&[OsString::from("--settings"), f.clone().into_os_string()]).unwrap();
        let helper = drive(
            &r,
            |x| x.outcome == Outcome::Recycled,
            |x| x.new_pid.unwrap(),
        );
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.artifacts = Ok(rec);
        o.gate = Box::new(move || {
            std::fs::write(&f, b"rewritten by the gate").unwrap();
            Ok(())
        });
        run(&r, o, &mut s);
        helper.join().unwrap();
        assert_eq!(log_lines(&r).len(), 2, "relaunched");
    }

    /// Item 3b: an artifact changed between the stop and the spawn ends in the loud failure
    /// path, never a relaunch on swapped bytes.
    #[test]
    fn an_artifact_changed_between_the_stop_and_the_spawn_is_never_relaunched_on() {
        let r = rig("exec sleep 8");
        let f = r.dir.path().join("scaffold.md");
        std::fs::write(&f, b"rules").unwrap();
        let rec = record_artifacts(&[
            OsString::from("--append-system-prompt-file"),
            f.clone().into_os_string(),
        ])
        .unwrap();
        let (handle, up) = (r.handle.clone(), started(&r));
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
        });
        let mut s = Seen::default();
        let mut o = opts(&[]);
        o.artifacts = Ok(rec);
        o.on_rotate = Box::new(move || std::fs::write(&f, b"swapped in the window").unwrap());
        let exit = run(&r, o, &mut s);
        helper.join().unwrap();
        assert!(matches!(exit, Exit::RecycleFailed(_)));
        let res = read_result(&r.handle).unwrap().unwrap();
        assert_eq!(res.tag.as_deref(), Some("recycle_launch_artifact_changed"));
        assert_eq!(log_lines(&r).len(), 1, "no relaunch on changed bytes");
    }

    /// Item 9: the child ended after the quiet point and before the stop: nothing is relaunched.
    #[test]
    fn a_child_that_exits_between_the_quiet_point_and_the_stop_is_never_relaunched() {
        let r = rig("exec sleep 60");
        let (handle, up) = (r.handle.clone(), started(&r));
        let helper = std::thread::spawn(move || {
            wait_for("stub started", up);
            write_request(&handle, ID, "memory", &now_rfc3339(), Mode::Resume).unwrap();
        });
        let pid_src = r.log.clone();
        let mut s = Seen::default();
        let mut o = opts(&[]);
        // The gates run after the quiet point and before the stop: end the child there.
        o.gate = Box::new(move || {
            let l = std::fs::read_to_string(&pid_src).unwrap();
            kill9(l.split_whitespace().next().unwrap().parse().unwrap());
            std::thread::sleep(Duration::from_millis(200));
            Ok(())
        });
        let exit = run(&r, o, &mut s);
        helper.join().unwrap();
        assert!(matches!(exit, Exit::Exited(_)));
        let res = read_result(&r.handle).unwrap().unwrap();
        assert_eq!(res.outcome, Outcome::AbortedChildExited);
        assert_eq!(log_lines(&r).len(), 1, "never relaunched");
        assert_eq!(s.audit, 0);
        let _ = first_pid(&r);
    }

    #[test]
    fn stop_child_on_an_already_exited_child_is_an_error_not_a_success() {
        let mut c = Command::new("true").spawn().unwrap();
        c.wait().unwrap();
        assert_eq!(
            stop_child(&mut c, Some(1), Duration::from_millis(100)).unwrap_err(),
            "recycle_child_exited"
        );
    }
}
