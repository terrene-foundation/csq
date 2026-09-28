//! Codex supervisor record + cross-slot swap-request primitives.
//!
//! `csq run`/`csq exec` on the Codex surface supervises its `codex` child so
//! that `csq swap` — invoked as a `!`-shell-out from INSIDE that codex
//! session — can hand the swap back to the supervisor instead of exec'ing
//! over its own (child) process image, which would leave the codex TUI the
//! user is looking at untouched and tombstoned out from under it (see
//! `providers::codex::ancestry` and `swap.rs::refuse_or_handoff_if_inside_live_codex_ancestor`).
//!
//! This module owns THREE on-disk primitives (the third, [`SWAP_INFLIGHT_FILE`],
//! added by the FM-2 fix below — an earlier revision of this doc claimed
//! "exactly two", which stopped being true the moment that fix landed).
//! [`SupervisorRecord`] and the initial [`SwapRequest`] write are written via
//! the canonical secure-write pipeline (`unique_tmp_path` -> `secure_file` ->
//! `atomic_replace`, tmp cleaned up on every failure branch per
//! `security.md` §5a — neither file carries secret content, but the
//! pipeline is reused for atomicity and permission consistency); the
//! request-to-in-flight hand-off ([`take_swap_request`]) is a plain
//! `rename(2)`, which is atomic on the same filesystem without needing that
//! pipeline (see that function's doc comment):
//!
//! - [`SupervisorRecord`] — written once by the supervisor at startup,
//!   naming itself by PID **plus** its own process start time. The start
//!   time is the anti-PID-recycling nonce: a bare PID match is not proof
//!   that the process holding that PID today is the process that wrote
//!   the record (`discovery_pid_liveness_is_not_daemon_identity`). Reused
//!   here rather than invented: `providers::codex::ancestry` already
//!   trusts `ps` output for process identity on this platform.
//! - [`SwapRequest`] — written once by `csq swap` when it detects a live,
//!   verified supervisor and wants a cross-slot swap performed on its
//!   behalf, then signalled via `signal_supervisor`.
//! - [`SWAP_INFLIGHT_FILE`] — the request, atomically renamed in place by
//!   [`take_swap_request`] the instant it is consumed, marking the swap as
//!   validated-or-being-validated. See that constant's doc comment (FM-2).
//!
//! Everything past "write/read/verify these files" — spawning and
//! supervising the actual `codex` child, forwarding signals, relaunching
//! through `launch_codex`, and thread-id discovery for `codex resume` — is
//! NOT implemented in this module. See the workspace note this change
//! shipped with for the sharding rationale.

use crate::audit::{op_emit, AccountSwapPayload, EventKind, EventPayload, OpOutcome, RecordId};
use crate::error::PlatformError;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use std::path::Path;

/// Filename (inside a codex handle dir) holding the live supervisor's
/// self-recorded identity.
pub const SUPERVISOR_FILE: &str = ".csq-supervisor";

/// Filename (inside a codex handle dir) holding a pending cross-slot swap
/// request, if any.
pub const SWAP_REQUEST_FILE: &str = ".csq-swap-request";

/// Filename (inside a codex handle dir) marking a swap request that has been
/// CONSUMED and is now either being validated or already in flight — the
/// current child may or may not yet be torn down for relaunch.
///
/// C-R4-1 (FM-2, closed for real): an earlier revision of this fix wrote
/// this marker via a SEPARATE call (`mark_swap_inflight`, now removed)
/// AFTER `validate_codex_relaunch_target` succeeded — a check that itself
/// runs a multi-second daemon-health probe plus credential/config checks.
/// That left the exact window this file exists to close wide open: from
/// the instant [`take_swap_request`] deletes [`SWAP_REQUEST_FILE`] to the
/// instant validation finishes (up to ~4s), [`swap_request_pending`] saw
/// NEITHER file and reported "nothing pending" — a second `!csq swap`
/// landing in that window would write a fresh request into a handle dir
/// about to be renamed out from under it, report false success, and never
/// be read by anyone.
///
/// The fix: [`take_swap_request`] now performs an ATOMIC `rename(2)` of
/// [`SWAP_REQUEST_FILE`] directly into this file, as the SAME step that
/// consumes the request — there is no window in which neither file exists,
/// because a rename is one filesystem operation. From that point:
/// - if validation SUCCEEDS, the marker is left in place through teardown
///   and relaunch, and disappears only when the whole handle dir is
///   tombstoned (`codex_supervise::tombstone_handle_dir`);
/// - if validation REFUSES the target, the caller MUST call
///   [`clear_swap_inflight`] to remove it, or the terminal is left durably
///   reporting "swap pending" with no request file left for a retry.
pub const SWAP_INFLIGHT_FILE: &str = ".csq-swap-inflight";

/// How long an unconsumed [`SwapRequest`] may sit before [`swap_request_pending`]
/// treats it as STALE rather than genuinely pending (FM-3).
///
/// Derivation (two named outcomes, per `tooling-self-verification.md` Rule 3):
/// a HEALTHY hand-off is consumed within one tick of the supervisor's
/// `POLL_MS = 25ms` loop (`codex_supervise.rs`), so a legitimate request is
/// gone in well under a second. A request whose writer died before
/// signalling (or whose `SIGUSR1` was lost) never gets consumed and sits
/// forever — the only question is how long a genuinely slow-but-alive
/// writer (the gap between `csq swap`'s file write and its `kill(2)` call)
/// is allowed, which this codebase already treats as bounded in the
/// low-single-digit seconds (`GRACEFUL_STOP_MS = 3_000`). 10s sits with more
/// than 10x headroom over the healthy (sub-second) case while still being
/// far short of the alternative (the user has to restart their terminal) —
/// the dead-writer case this constant exists to unblock.
const STALE_REQUEST_SECS: u64 = 10;

/// C-R4-9/S-F4: how far a [`SwapRequest::requested_at`] may sit AHEAD of this
/// process's own clock before [`request_is_stale`] discards it as stale
/// rather than treating "not yet arrived" as "not stale, wait forever".
///
/// Derivation (two named outcomes, per `tooling-self-verification.md` Rule
/// 3): the writer (`csq swap`) and the reader (this supervisor) are two
/// processes on the SAME host, so genuine clock skew between them is
/// whatever `SystemTime::now()` drifts by across two calls microseconds
/// apart — well under 1s in practice, and this constant does not need to be
/// tight against that case since a request that is merely "written a moment
/// ago, read a moment later" is timestamped in the PAST relative to the
/// reader almost always (the writer stamps `requested_at` before the
/// reader's `SystemTime::now()` call, not after). A request whose
/// `requested_at` is meaningfully in the FUTURE (an attacker-planted or
/// corrupt timestamp — same-user threat model, see `SwapRequest::parse`'s
/// `is_uuid_shaped` rejection for the sibling case) has no legitimate
/// same-host origin at all. 2s sits comfortably above genuine intra-host
/// clock skew while rejecting anything a real writer could not have
/// produced.
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 2;

/// A live supervisor's self-recorded identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorRecord {
    pub pid: u32,
    /// This process's own start time, as reported by `ps -o lstart=`,
    /// captured once at write time. Opaque string — compared for
    /// equality only, never parsed.
    pub start_time: String,
}

impl SupervisorRecord {
    fn to_line(&self) -> String {
        format!("{}\n{}\n", self.pid, self.start_time)
    }

    fn parse(s: &str) -> Option<Self> {
        let mut lines = s.lines();
        let pid = lines.next()?.trim().parse::<u32>().ok()?;
        let start_time = lines.next()?.trim().to_string();
        if start_time.is_empty() {
            // An unreadable start time at write time is recorded as
            // "cannot verify this record later" (see `write_supervisor_record`),
            // never as a wildcard that verifies against anything.
            return None;
        }
        Some(Self { pid, start_time })
    }
}

/// Returns `pid`'s process start time as reported by `ps -o lstart=`, or
/// `None` when it cannot be determined (non-unix, process gone, or `ps`
/// unavailable). Deliberately the SAME instrument
/// `providers::codex::ancestry` already trusts for process identity on
/// this platform, so the two never drift apart on what "the same process"
/// means.
#[cfg(unix)]
pub fn process_start_time(pid: u32) -> Option<String> {
    // FM-14: absolute path + a scrubbed environment on BOTH the write side
    // (this function, called from `write_supervisor_record`) and the verify
    // side (`verify_supervisor_alive`, which also calls this same function)
    // — a PATH-shadowed `ps` (a same-user-writable earlier `PATH` entry) or
    // a locale/timezone env var could otherwise change `lstart`'s output
    // format out from under the equality check `verify_supervisor_alive`
    // performs, or substitute an attacker-controlled binary entirely.
    let output = std::process::Command::new("/bin/ps")
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("PATH", "/usr/bin:/bin")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(not(unix))]
pub fn process_start_time(_pid: u32) -> Option<String> {
    // Windows: not yet implemented, matching `providers::codex::ancestry`'s
    // documented gap. Callers must treat `None` as "cannot verify" rather
    // than as evidence of anything.
    None
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    // Signal 0 delivers nothing; a zero return means the PID exists and is
    // signalable by us.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn pid_is_alive(_pid: u32) -> bool {
    false
}

/// Writes this process's own supervisor record into `handle_dir`.
///
/// FM-14: if this process's own start time cannot be determined, NOTHING is
/// written — the caller (`codex_supervise::run_supervised_unix`) falls back
/// to unsupervised spawn+wait with a single warning that in-terminal
/// `csq swap` is unavailable this session. A record that can never be
/// re-verified would be worse than no record: `verify_supervisor_alive`
/// fails closed on it anyway (see that function's doc comment), so writing
/// it would only cost a wasted file write and a misleading "supervision
/// active" impression.
pub fn write_supervisor_record(handle_dir: &Path) -> Result<SupervisorRecord, PlatformError> {
    let pid = std::process::id();
    write_supervisor_record_with(handle_dir, pid, process_start_time(pid))
}

/// Seam for [`write_supervisor_record`] — takes `start_time` as a plain
/// `Option` so the "start time unavailable → Err" branch is testable without
/// forcing the real `ps` invocation to fail.
fn write_supervisor_record_with(
    handle_dir: &Path,
    pid: u32,
    start_time: Option<String>,
) -> Result<SupervisorRecord, PlatformError> {
    let start_time = start_time.ok_or_else(|| {
        PlatformError::Io(std::io::Error::other(
            "could not determine this process's start time (ps -o lstart= failed) — \
             cross-slot swap-in-terminal is unavailable for this session",
        ))
    })?;
    let record = SupervisorRecord { pid, start_time };
    write_atomic_secure(&handle_dir.join(SUPERVISOR_FILE), &record.to_line())?;
    Ok(record)
}

/// Reads the supervisor record from `handle_dir`, if any and well-formed.
pub fn read_supervisor_record(handle_dir: &Path) -> Option<SupervisorRecord> {
    let s = std::fs::read_to_string(handle_dir.join(SUPERVISOR_FILE)).ok()?;
    SupervisorRecord::parse(&s)
}

/// Verifies that the recorded supervisor is genuinely the live process
/// that wrote the record — not a recycled PID that happens to match.
/// Fails CLOSED: a missing record, a dead PID, or an unreadable/mismatched
/// start time all return `false`. There is no "verified" outcome reachable
/// without an exact start-time match.
pub fn verify_supervisor_alive(handle_dir: &Path) -> bool {
    let Some(record) = read_supervisor_record(handle_dir) else {
        return false;
    };
    if !pid_is_alive(record.pid) {
        return false;
    }
    match process_start_time(record.pid) {
        Some(current) => current == record.start_time,
        None => false,
    }
}

/// A pending cross-slot swap request, handed from `csq swap` (running as a
/// codex child) to the codex supervisor holding that handle dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapRequest {
    pub target_slot: u16,
    /// The exact codex thread/session id to resume, when discovered.
    /// `None` means: relaunch fresh on the target slot rather than guess
    /// with `codex resume --last` (see the module doc on thread-id
    /// discovery — NOT implemented by this file).
    pub thread_id: Option<String>,
    pub requested_at: String,
    /// C-F6: a 128-bit CSPRNG nonce (32 lowercase hex chars), minted fresh
    /// by [`gen_swap_nonce`] at request-write time. [`SwapVerdict`] binds to
    /// THIS, not to `requested_at` — an earlier revision argued uniqueness
    /// from "at most one live request per handle dir, second-resolution
    /// timestamp", which is true today but is an argument about CALLER
    /// discipline (`swap_request_pending`'s admission check), not a property
    /// of the identifier itself; a nonce needs no such argument.
    pub nonce: String,
    /// The audit chain's `chain_id` at the moment `csq swap` persisted the
    /// AccountSwap INTENT record for this request — empty when no INTENT
    /// was recorded (`begin_swap_audit` returned `Ok(None)`, e.g. the
    /// source slot marker was absent). Carried so the supervisor can write
    /// the CORRELATED OUTCOME onto the SAME chain `csq swap` appended the
    /// intent to, rather than guessing at `base_dir`'s current chain state
    /// (which `chain_id.json` may have moved past by the time the
    /// supervisor's relaunch resolves).
    pub chain_id: String,
    /// The `correlation_id` `csq swap` generated for this request's INTENT
    /// record (empty iff `chain_id` is empty — see that field's doc).
    /// [`SwapAuditCorrelation::from_request`] is the single place that
    /// decides "is there a correlated outcome to write" from this pair.
    pub correlation_id: String,
    /// The slot `csq swap` was running under when it wrote the INTENT —
    /// `AccountSwapPayload::from_slot`. Only meaningful when
    /// `correlation_id` is non-empty (see that field's doc); `0` otherwise
    /// (not a valid `AccountNum`, never parsed as one on that path).
    pub from_slot: u16,
}

/// Test/fixture convenience: a fresh nonce, no audit correlation
/// (`chain_id`/`correlation_id` empty, `from_slot` = 0 — never consulted
/// when `correlation_id` is empty, see [`SwapAuditCorrelation::from_request`]).
/// Production call sites that DO carry a correlation
/// (`handoff_to_supervisor_write_and_signal`) set every field explicitly
/// rather than relying on this.
impl Default for SwapRequest {
    fn default() -> Self {
        Self {
            target_slot: 0,
            thread_id: None,
            requested_at: String::new(),
            nonce: gen_swap_nonce(),
            chain_id: String::new(),
            correlation_id: String::new(),
            from_slot: 0,
        }
    }
}

impl SwapRequest {
    fn to_line(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.target_slot,
            self.thread_id.as_deref().unwrap_or(""),
            self.requested_at,
            self.nonce,
            self.chain_id,
            self.correlation_id,
            self.from_slot,
        )
    }

    fn parse(s: &str) -> Option<Self> {
        let mut lines = s.lines();
        let target_slot = lines.next()?.trim().parse::<u16>().ok()?;
        let thread_id_raw = lines.next()?.trim();
        let thread_id = if thread_id_raw.is_empty() {
            None
        } else if is_uuid_shaped(thread_id_raw) {
            Some(thread_id_raw.to_string())
        } else {
            // S-F1: a thread_id that is not UUID-shaped is REJECTED — the
            // whole record is treated as corrupt (same "corrupt == no
            // request" posture `take_swap_request` already documents),
            // never silently truncated to `None` or carried forward
            // verbatim. Without this, an attacker-controlled handle-dir
            // write (same-user threat model) could plant a thread_id of
            // e.g. `--dangerously-bypass-approvals-and-sandbox` and have it
            // walk straight into the relaunch's `codex resume <id>` argv.
            return None;
        };
        let requested_at = lines.next()?.trim().to_string();
        let nonce = lines.next()?.trim().to_string();
        if !is_swap_nonce_shaped(&nonce) {
            // A corrupt/missing/malformed nonce invalidates the whole
            // record — same "corrupt == no request" posture as the
            // thread_id check above. Without this, a same-user
            // attacker-planted empty (or wrong-length, or mixed-case)
            // nonce would make `SwapVerdict` binding ambiguous or admit a
            // shape [`gen_swap_nonce`] itself never produces (an
            // attacker-controlled length could, in principle, be crafted to
            // collide with a DIFFERENT genuine request's nonce under a
            // byte-for-byte comparison that only checked "is hex", not
            // "is exactly this shape").
            return None;
        }
        let chain_id = lines.next()?.trim().to_string();
        let correlation_id = lines.next()?.trim().to_string();
        let from_slot = lines.next()?.trim().parse::<u16>().ok()?;
        Some(Self {
            target_slot,
            thread_id,
            requested_at,
            nonce,
            chain_id,
            correlation_id,
            from_slot,
        })
    }
}

/// Validates the exact shape [`gen_swap_nonce`] produces: exactly 32
/// lowercase hex characters (128 bits, hex-encoded). Stricter than a bare
/// "is this hex" check (which `is_ascii_hexdigit` alone would allow at any
/// length, and in either case) — a same-user attacker-planted nonce of the
/// wrong length or mixed case must invalidate the whole [`SwapRequest`], the
/// same "corrupt == no request" posture [`is_uuid_shaped`] already applies
/// to `thread_id`.
fn is_swap_nonce_shaped(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Generates a fresh 128-bit CSPRNG nonce, hex-encoded (32 lowercase hex
/// chars). Used to bind a [`SwapRequest`] to its eventual [`SwapVerdict`]
/// (C-F6) — deliberately the same OS-CSPRNG source (`getrandom`) already
/// trusted elsewhere in this crate for security-bearing identifiers (see
/// `oauth::pkce::generate_verifier`), rather than a timestamp or counter.
///
/// # Panics
///
/// Panics only if the OS CSPRNG is unavailable — a condition that cannot
/// occur on any supported csq platform (macOS, Linux, Windows).
pub fn gen_swap_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable — cannot generate swap nonce");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The correlated `AccountSwap` audit OUTCOME a [`SwapRequest`] entitles the
/// supervisor to write, derived from the request's own `chain_id` /
/// `correlation_id` / `from_slot` — never re-derived from `base_dir`'s
/// current chain state, which may have moved past the moment `csq swap`
/// persisted the INTENT (see [`SwapRequest::chain_id`]'s doc).
///
/// PRIMARY DIRECTIVE (round 6): the supervisor — not `csq swap` — is the
/// authority for this OUTCOME. `csq swap` persists the INTENT and hands the
/// chain/correlation identity across in the request line; `csq swap` itself
/// NEVER writes the OUTCOME for an accepted or timed-out swap (an intent
/// with no outcome is the defined-unknown state `scan_orphan_intents` /
/// `csq doctor` already surface) — only the supervisor does, and only once
/// per request, via [`SwapAuditCorrelation::write_outcome_once`].
#[derive(Debug, Clone)]
pub struct SwapAuditCorrelation {
    chain_id: String,
    correlation_id: String,
    from_slot: u16,
    to_slot: u16,
    /// Guards against a double-write: `cmd.spawn()` succeeding writes `Ok`
    /// exactly once; a LATER, unrelated failure several stack frames up
    /// (e.g. a `try_wait()` OS error surfacing as `Err` from the SAME
    /// recursive `relaunch()` call, well after this correlation's own
    /// spawn already succeeded) must not ALSO write `Failed` for the same
    /// `correlation_id` — that would append two OUTCOME records for one
    /// INTENT, breaking the 1:1 pairing `scan_orphan_intents` relies on.
    /// `Rc`, not `Arc`: this whole protocol is one synchronous,
    /// single-threaded recursive call stack (`drive_child`'s poll loop
    /// blocks; there is no concurrent writer).
    written: std::rc::Rc<std::cell::Cell<bool>>,
}

impl SwapAuditCorrelation {
    /// Returns `None` when `req` carries no INTENT to correlate against
    /// (`correlation_id` empty — `csq swap`'s `begin_swap_audit` returned
    /// `Ok(None)`, e.g. the source slot marker was absent). Writing an
    /// OUTCOME with no corresponding INTENT would itself be an orphan in
    /// the other direction, so callers MUST check for `None` and skip the
    /// write entirely rather than substitute a placeholder identity.
    pub fn from_request(req: &SwapRequest) -> Option<Self> {
        if req.correlation_id.is_empty() {
            return None;
        }
        Some(Self {
            chain_id: req.chain_id.clone(),
            correlation_id: req.correlation_id.clone(),
            from_slot: req.from_slot,
            to_slot: req.target_slot,
            written: std::rc::Rc::new(std::cell::Cell::new(false)),
        })
    }

    /// Writes the correlated `AccountSwap` OUTCOME once. A second call
    /// (from a later, unrelated failure branch — see the `written` field's
    /// doc, above) is a silent no-op, never a second chain record. `reason` MUST
    /// already be redacted (`RedactedString::from_untrusted` /
    /// `redact_tokens`) by the caller — this function does not re-scrub it.
    pub fn write_outcome_once(&self, base_dir: &Path, outcome: OpOutcome) {
        // D-F4/S-LOW-6: `written` is set to `true` ONLY after `emit_outcome`
        // itself confirms success — never up front. The prior revision
        // called `self.written.replace(true)` as its FIRST step, so a
        // conversion failure or an `emit_outcome` error would ALSO mark this
        // correlation "written", silently poisoning every later, genuinely
        // correct call for the same correlation_id (the exact double-write
        // guard this struct exists for, inverted into a double-SUPPRESS
        // guard). `.get()` peeks without mutating; only a confirmed success
        // below calls `.set(true)`.
        if self.written.get() {
            return;
        }
        let from_slot = match crate::types::AccountNum::try_from(self.from_slot) {
            Ok(v) => v,
            Err(e) => {
                // Item 8 (S-LOW-3): `audit_error_kind` is the fixed-vocabulary
                // tag for the ERROR VALUE (`CredentialError::error_kind_tag`);
                // `error_kind` above it names the FAILURE SITE. Neither
                // interpolates the error's `Display` via `%e`.
                tracing::warn!(
                    error_kind = "swap_outcome_write_skipped_invalid_from_slot",
                    audit_error_kind = e.error_kind_tag(),
                    from_slot = self.from_slot,
                    "SwapAuditCorrelation::write_outcome_once: from_slot did not \
                     convert to a valid AccountNum — OUTCOME not written; the \
                     correlated INTENT is left as an orphan for scan_orphan_intents"
                );
                return;
            }
        };
        let to_slot = match crate::types::AccountNum::try_from(self.to_slot) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error_kind = "swap_outcome_write_skipped_invalid_to_slot",
                    audit_error_kind = e.error_kind_tag(),
                    to_slot = self.to_slot,
                    "SwapAuditCorrelation::write_outcome_once: to_slot did not \
                     convert to a valid AccountNum — OUTCOME not written; the \
                     correlated INTENT is left as an orphan for scan_orphan_intents"
                );
                return;
            }
        };
        let correlation_id = match RecordId::try_new(self.correlation_id.clone()) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error_kind = "swap_outcome_write_skipped_invalid_correlation_id",
                    audit_error_kind = e.fixed_tag(),
                    "SwapAuditCorrelation::write_outcome_once: correlation_id did \
                     not parse as a valid RecordId — OUTCOME not written; the \
                     correlated INTENT is left as an orphan for scan_orphan_intents"
                );
                return;
            }
        };
        // D-F3/S-M-1 (round 7): the chain, not this struct's own fields, is
        // the authority for whether this write is allowed at all — verify
        // BEFORE building the payload or calling `emit_outcome`. A rejected
        // check does NOT set `written`: nothing was written, so a later,
        // genuinely-authorized retry (e.g. after the chain state that
        // caused the rejection is corrected) must still be able to proceed.
        let check = crate::audit::SwapCorrelationCheck {
            correlation_id: &self.correlation_id,
            from_slot,
            to_slot,
        };
        if !crate::audit::verify_swap_correlation(base_dir, &check) {
            tracing::warn!(
                error_kind = "swap_outcome_correlation_rejected",
                // D-F7 (item 10): `verify_swap_correlation`'s `SwapCorrelationCheck`
                // carries only `correlation_id`/`from_slot`/`to_slot` — no
                // `nonce` field is ever consulted by this check (the nonce
                // lives entirely in the SEPARATE `SwapVerdict`/
                // `take_swap_verdict` matching path). "slot/nonce mismatch"
                // named a condition this check cannot produce.
                "SwapAuditCorrelation::write_outcome_once: the committed chain does \
                 not authorize this OUTCOME write (no matching single INTENT, a \
                 slot mismatch, an already-resolved OUTCOME, or a chain reset \
                 since the INTENT was written) — OUTCOME not written"
            );
            return;
        }
        let payload = EventPayload::AccountSwap(AccountSwapPayload { from_slot, to_slot });
        // S-LOW-B / C-N2 (round 8b): the `check` above (`verify_swap_correlation`)
        // is an out-of-lock fast-fail — it cannot make two concurrent writers
        // for this `correlation_id` mutually exclusive, since both can observe
        // "no OUTCOME yet" before either appends. `precheck` re-runs the
        // IDENTICAL authorization scan (`verify_swap_correlation_in_file`)
        // against the exact `(csq_runs_dir, chain_id)` the pending append
        // targets, evaluated INSIDE `.chain-lock` by
        // `emit_outcome_with_precheck` — so the second concurrent writer
        // observes the first's just-appended OUTCOME and refuses.
        let base_dir_for_precheck = base_dir;
        let precheck = move |csq_runs_dir: &Path, chain_id: &str| -> bool {
            let Ok(chain_state) =
                crate::audit::key_custody::chain_state::ChainState::load(base_dir_for_precheck)
            else {
                return false;
            };
            let chain_file = csq_runs_dir.join(format!("{chain_id}.jsonl"));
            crate::audit::intent_scan::verify_swap_correlation_in_file(
                base_dir_for_precheck,
                &chain_file,
                chain_id,
                &chain_state,
                &check,
            )
        };
        match op_emit::emit_outcome_with_precheck(
            base_dir,
            &self.chain_id,
            EventKind::AccountSwap,
            payload,
            correlation_id,
            outcome,
            &precheck,
        ) {
            Ok(true) => self.written.set(true),
            Ok(false) => {
                tracing::warn!(
                    error_kind = "swap_outcome_write_skipped_precheck_or_degrade",
                    "SwapAuditCorrelation::write_outcome_once: OUTCOME not written \
                     (in-lock authorization precheck refused it, or the chain is \
                     degraded/keychain-unavailable) — the correlated INTENT is left \
                     as an orphan for scan_orphan_intents (run `csq doctor`)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error_kind = "swap_outcome_emit_failed",
                    audit_error_kind = e.fixed_tag(),
                    "SwapAuditCorrelation::write_outcome_once: emit_outcome failed — \
                     OUTCOME not written; the correlated INTENT is left as an \
                     orphan for scan_orphan_intents (run `csq doctor`)"
                );
            }
        }
    }
}

/// Validates the canonical UUID shape (`8-4-4-4-12` hex groups) of a
/// [`SwapRequest::thread_id`]. Deliberately a LOCAL copy of the same check
/// `providers::codex::thread_id::is_uuid` performs (that module is owned by
/// a sibling shard in this same change) rather than a cross-module
/// dependency: this module's whole contract is "two on-disk primitives,
/// nothing else" (see module doc), and the check is three lines. Does NOT
/// validate the version/variant nibbles — any RFC 4122-shaped string is
/// accepted, matching the sibling implementation's own documented scope.
fn is_uuid_shaped(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        let expect_dash = matches!(i, 8 | 13 | 18 | 23);
        if expect_dash {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Atomically writes a swap request into `handle_dir`, overwriting any
/// existing one. Callers MUST check [`swap_request_pending`] first when the
/// "refuse a second pending request" behavior is required (Rule 6 of the
/// governing task) — this function itself does not refuse.
pub fn write_swap_request(handle_dir: &Path, req: &SwapRequest) -> Result<(), PlatformError> {
    write_atomic_secure(&handle_dir.join(SWAP_REQUEST_FILE), &req.to_line())
}

/// S-L2 (round 5): like [`write_swap_request`], but refuses to write when a
/// request or in-flight marker is ALREADY present, rather than overwriting
/// it. `handoff_to_supervisor_write_and_signal` (`swap.rs`) now runs its
/// admission checks (supervisor-record read, both ancestor-chain checks)
/// BEFORE writing anything, so the window between its caller's
/// `swap_request_pending` precondition check and this write is no longer
/// negligible — it is however long the ancestry walk takes. A CONCURRENT
/// `!csq swap` landing in that window must not have its request silently
/// clobbered.
///
/// Returns `Ok(true)` on a successful write, `Ok(false)` when a request or
/// in-flight marker was already present (no write performed), `Err` on any
/// other I/O failure. Uses `create_new` (`O_EXCL`-equivalent) directly on
/// [`SWAP_REQUEST_FILE`] rather than the tmp-then-`atomic_replace` pipeline
/// [`write_swap_request`] uses — that pipeline's `atomic_replace` step
/// always overwrites, which is exactly what this function exists to
/// refuse.
pub fn write_swap_request_if_absent(
    handle_dir: &Path,
    req: &SwapRequest,
) -> Result<bool, PlatformError> {
    if handle_dir.join(SWAP_INFLIGHT_FILE).exists() {
        return Ok(false);
    }
    let path = handle_dir.join(SWAP_REQUEST_FILE);
    if try_create_swap_request(&path, req)? {
        return Ok(true);
    }
    // C-F4/S-M3: the file already exists. A genuinely concurrent writer's
    // request is refused untouched (the existing behaviour) — but a request
    // whose writer died before signalling (the SAME "lost writer" case
    // `request_is_stale` already exists to detect) must not wedge every
    // future swap forever just because it happens to be sitting in the
    // create-new path rather than the read path `swap_request_pending`
    // checks. Tombstone (rename off) so a concurrent reader mid-open never
    // observes a half-removed file, then retry ONCE.
    //
    // D-F8 (round 7): TWO writers can both reach this point having judged
    // the SAME pre-rename content stale (this read + the pre-rename read
    // below are not under any lock). Without re-verification, the SECOND
    // writer's `rename` can pick up the FIRST writer's brand-new, genuinely
    // fresh request (already written via its own `try_create_swap_request`
    // retry) instead of the file that was actually judged stale, and then
    // destroy it — a live request destroyed by a stale-request cleanup that
    // raced it. `judge_existing_request_for_tombstone` captures WHAT was
    // judged stale (a nonce, or "corrupt"); after the rename, the RENAMED
    // file is re-parsed and compared against that judgment before it is
    // ever deleted.
    if let Some(judgment) = judge_existing_request_for_tombstone(&path) {
        return tombstone_and_retry(&path, judgment, req);
    }
    Ok(false)
}

/// D-F8 (round 7): performs the rename-then-verify tombstone step and, on
/// confirmation, the create-new retry — split out from
/// [`write_swap_request_if_absent`] so the race it defends against (a
/// SECOND caller's rename picking up a DIFFERENT, fresher request than the
/// one `judgment` was captured for) is directly testable: a test can capture
/// a judgment against one content, mutate `path` to hold different content
/// (simulating a second tombstone-and-retry cycle completing first), and
/// call this function to assert the fresh content survives.
fn tombstone_and_retry(
    path: &Path,
    judgment: TombstoneJudgment,
    req: &SwapRequest,
) -> Result<bool, PlatformError> {
    let tombstone = unique_tmp_path(path);
    if std::fs::rename(path, &tombstone).is_err() {
        return Ok(false);
    }
    let renamed_meta = std::fs::metadata(&tombstone).ok();
    let renamed_identity = renamed_meta.as_ref().map(fs_identity);
    let renamed_contents = std::fs::read_to_string(&tombstone).ok();
    let renamed_req = renamed_contents.as_deref().and_then(SwapRequest::parse);
    // S-LOW-E / C-B3 / C-B4 (round 8b): the content-only re-check below
    // cannot tell "the SAME file I judged" from "a DIFFERENT file that
    // merely re-produces the same judgeable shape" — a CorruptAndOld
    // judgment matches ANY unparseable file, and a nonce collision, while
    // unlikely, is coincidental content equality rather than physical
    // identity. `fs_identity` (dev+ino / volume+file-index) is what a
    // same-filesystem `rename` PRESERVES, so comparing it against what was
    // captured at judgment time (before this rename) catches the case the
    // content check cannot: a racing writer replaced `path` with a file
    // that happens to parse — or fail to parse — the same way.
    let identity_confirmed = match (&judgment, renamed_identity) {
        (TombstoneJudgment::StaleWithNonce(_, expected), Some(actual)) => *expected == actual,
        (TombstoneJudgment::CorruptAndOld(expected), Some(actual)) => *expected == actual,
        _ => false,
    };
    let content_confirmed = match (&judgment, &renamed_req) {
        (TombstoneJudgment::StaleWithNonce(expected, _), Some(renamed_req)) => {
            renamed_req.nonce == *expected
        }
        // Item 6 (D-F6): a `None` (still-unparseable) renamed content alone
        // is NOT sufficient — `identity_confirmed` above degrades to an
        // automatic pass on the dev/ino axis whenever `birth_ns` is
        // unavailable (no filesystem birth-time support; see
        // `FsIdentity`'s doc), and an in-place content REWRITE of the SAME
        // inode (no rename, no unlink) leaves dev+ino — and any already-
        // captured birth time — completely unchanged. That composition
        // would let a racing writer overwrite `path` in place with fresh
        // (still-corrupt) content and have it silently confirmed as "the
        // same old file that was judged", exactly the false-confirm this
        // whole mechanism exists to prevent (`judge_existing_request_for_
        // tombstone`'s own doc: "A YOUNG unparseable file says NO"). Re-
        // derive that SAME staleness bound against the RENAMED file's
        // mtime — if a racing writer's in-place rewrite also refreshed the
        // mtime (as any real write does), this now correctly refuses.
        (TombstoneJudgment::CorruptAndOld(_), None) => renamed_meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age > std::time::Duration::from_secs(STALE_REQUEST_SECS)),
        _ => false,
    };
    if identity_confirmed && content_confirmed {
        let _ = std::fs::remove_file(&tombstone);
        return try_create_swap_request(path, req);
    }
    // D-F8: the renamed content and/or filesystem identity does NOT match
    // what was judged stale — a racing tombstone attempt (this call, or a
    // sibling in-flight call) picked up someone else's fresh request.
    // Restore it via a hard link (fails closed if `path` already exists —
    // never clobber whatever now legitimately occupies it) and refuse;
    // THIS writer's own request is not written.
    //
    // S-LOW-E (round 8b): a FAILED restore used to be entirely silent —
    // `path` would be left without the racing writer's request and nothing
    // would say why. Spec 02's "Tombstone rename-then-verify" claimed
    // "nothing is silently destroyed", which was true of the BYTES (the
    // tombstoned copy stays on disk under `tombstone`'s own name) but not
    // of the OPERATOR's visibility into what happened — this warn is what
    // makes the failure discoverable rather than merely non-fatal.
    match std::fs::hard_link(&tombstone, path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tombstone);
        }
        Err(e) => {
            tracing::warn!(
                error_kind = "swap_request_tombstone_restore_failed",
                io_error_kind = ?e.kind(),
                "tombstone_and_retry: a racing writer's request was picked up \
                 by this rename (content and/or filesystem-identity mismatch \
                 against what was judged stale), and restoring it via \
                 hard_link ALSO failed — the racing writer's request is not \
                 visible at its expected path. The tombstoned copy remains \
                 on disk (not deleted) rather than being silently lost; an \
                 operator inspecting stuck swap paths can recover it."
            );
        }
    }
    Ok(false)
}

/// Filesystem identity captured for the tombstone-restore race (S-LOW-E /
/// C-B3 / C-B4, round 8b): `(dev, ino)` on Unix — the pair a same-
/// filesystem `rename` preserves, so comparing it before-judgment vs
/// after-rename detects a racing writer's file being picked up in place of
/// the one actually judged, which the content-only re-check in
/// [`tombstone_and_retry`] cannot (a `CorruptAndOld` judgment matches ANY
/// unparseable file; a nonce match is coincidental content equality, not
/// physical identity). `(0, 0)` on non-Unix (the Windows equivalent,
/// `volume_serial_number`/`file_index`, sits behind the unstable
/// `windows_by_handle` feature on stable Rust — see [`fs_identity`]'s doc)
/// — this makes the identity check trivially satisfied there (never MORE
/// restrictive than the content check), so behaviour on an unsupported
/// platform is unchanged from before this fix, not stricter.
///
/// `birth_ns` closes a gap dev+ino ALONE has: measured directly against
/// this repo's own CI host (`stat` before/after a `rm` + recreate at the
/// same path), tmpfs hands the SAME inode number back to a BRAND NEW file
/// almost immediately — dev+ino alone would then falsely treat a reused
/// inode as "the same file", exactly the false-confirm this whole fix
/// exists to prevent. `Metadata::created()` (nanosecond-precision file
/// birth time, confirmed supported on that same host) reliably differs
/// between the original file and whatever new file later reused its inode,
/// because creating a new file always stamps a new birth time. `None` when
/// the platform/filesystem does not report it — treated as an automatic
/// match on that field alone, same "never more restrictive than pre-fix"
/// posture as the non-Unix `(0, 0)` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FsIdentity {
    dev: u64,
    ino: u64,
    birth_ns: Option<i128>,
}

fn fs_identity(meta: &std::fs::Metadata) -> FsIdentity {
    let birth_ns = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FsIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            birth_ns,
        }
    }
    #[cfg(not(unix))]
    {
        // `MetadataExt::volume_serial_number` / `file_index` (the Windows
        // equivalent of dev+ino) sit behind the unstable `windows_by_handle`
        // feature on stable Rust (confirmed via windows-gnu clippy: E0658).
        // `(0, 0)` here is not a weaker Windows-specific carve-out — see
        // this function's doc: it makes the dev/ino half of the identity
        // check trivially satisfied, so `tombstone_and_retry` falls back to
        // the content check PLUS `birth_ns` (which Windows does report) on
        // every non-Unix platform — never stricter, never laxer than
        // pre-fix behaviour on the dev/ino axis specifically.
        FsIdentity {
            dev: 0,
            ino: 0,
            birth_ns,
        }
    }
}

/// D-F8 (round 7): what the current content at `path` was judged to be —
/// captured so [`write_swap_request_if_absent`] (via [`tombstone_and_retry`])
/// can re-verify the SAME content is still there immediately AFTER the
/// atomic rename, before deleting anything.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TombstoneJudgment {
    /// The content parsed as a [`SwapRequest`] that [`request_is_stale`]
    /// judged dead — carries its nonce AND its filesystem identity
    /// (S-LOW-E / C-B3 / C-B4, round 8b — see [`FsIdentity`]'s doc) for the
    /// post-rename re-check.
    StaleWithNonce(String, FsIdentity),
    /// The content did not parse (corrupt) AND its mtime was old enough.
    /// Carries the filesystem identity captured at judgment time.
    CorruptAndOld(FsIdentity),
}

/// C-F4/S-M3: whether the existing [`SWAP_REQUEST_FILE`] at `path` may be
/// safely tombstoned to unblock a new writer. Two cases say yes:
///
/// - it PARSES and [`request_is_stale`] says its writer is presumed dead
///   (the same staleness posture [`swap_request_pending`] already applies
///   on the READ side — this is that same posture applied on the WRITE
///   side, where a create-if-absent failure previously had no such escape);
/// - it does NOT parse (corrupt) AND its mtime is older than
///   [`STALE_REQUEST_SECS`] — a corrupt-and-OLD file has the same "nobody
///   is coming back for this" shape as a stale-but-parseable one.
///
/// A YOUNG unparseable file says NO — it may be a concurrent writer's
/// request in the middle of being written (a partial write this same-host,
/// same-user process raced), and the caller's refusal message names the
/// file for the operator to inspect (`describe_stuck_swap_paths` in
/// `swap.rs`) rather than this function guessing and discarding it.
fn judge_existing_request_for_tombstone(path: &Path) -> Option<TombstoneJudgment> {
    // S-LOW-E / C-B3 / C-B4 (round 8b): metadata AND content are read from
    // the SAME open file handle, so the captured `FsIdentity` is guaranteed
    // to describe the exact inode the content below came from (a
    // metadata-then-separate-read would leave a window for `path` to be
    // replaced in between the two calls).
    let mut file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let identity = fs_identity(&metadata);
    let mut contents = String::new();
    {
        use std::io::Read as _;
        file.read_to_string(&mut contents).ok()?;
    }
    if let Some(req) = SwapRequest::parse(&contents) {
        return if request_is_stale(&req) {
            Some(TombstoneJudgment::StaleWithNonce(req.nonce, identity))
        } else {
            None
        };
    }
    let modified = metadata.modified().ok()?;
    match std::time::SystemTime::now().duration_since(modified) {
        Ok(age) if age > std::time::Duration::from_secs(STALE_REQUEST_SECS) => {
            Some(TombstoneJudgment::CorruptAndOld(identity))
        }
        // mtime in the future — same fail-toward-refuse posture applied inline
        // throughout this function.
        _ => None,
    }
}

/// The `O_EXCL`-style create-if-absent write itself, factored out so
/// [`write_swap_request_if_absent`] can retry it once after tombstoning a
/// stale/corrupt-and-old existing request (C-F4/S-M3).
fn try_create_swap_request(path: &Path, req: &SwapRequest) -> Result<bool, PlatformError> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut f) => {
            use std::io::Write as _;
            if let Err(e) = f.write_all(req.to_line().as_bytes()) {
                drop(f);
                let _ = std::fs::remove_file(path);
                return Err(PlatformError::Io(e));
            }
            drop(f);
            if let Err(e) = secure_file(path) {
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(PlatformError::Io(e)),
    }
}

/// Whether a swap request is already pending in `handle_dir` — either a
/// fresh, unconsumed [`SwapRequest`] (FM-3: stale ones age out, see below) or
/// an in-flight relaunch already underway (FM-2: [`SWAP_INFLIGHT_FILE`]).
pub fn swap_request_pending(handle_dir: &Path) -> bool {
    if handle_dir.join(SWAP_INFLIGHT_FILE).exists() {
        return true;
    }
    let path = handle_dir.join(SWAP_REQUEST_FILE);
    let Ok(s) = std::fs::read_to_string(&path) else {
        return false;
    };
    // A corrupt request is not "pending" in the sense this function answers
    // — `take_swap_request` will consume-and-discard it as no-request the
    // next time `SIGUSR1` fires (see that function's doc comment), so a
    // fresh write in the meantime should proceed rather than refuse.
    let Some(req) = SwapRequest::parse(&s) else {
        return false;
    };
    !request_is_stale(&req)
}

/// FM-3: a request older than [`STALE_REQUEST_SECS`] is presumed to have
/// lost its writer (it died before signalling, or its `SIGUSR1` was
/// dropped) rather than genuinely pending. An unparseable timestamp fails
/// the SAME way — toward "stale", i.e. toward unblocking the terminal —
/// because the alternative (treating it as fresh forever) is the exact
/// wedge this function exists to break.
fn request_is_stale(req: &SwapRequest) -> bool {
    let Ok(requested_at) = chrono::DateTime::parse_from_rfc3339(&req.requested_at) else {
        return true;
    };
    // csq-core has no ambient clock (`chrono` here carries no `clock`
    // feature) — use `std::time::SystemTime::now()` and compare durations,
    // never `chrono::Utc::now()`.
    let requested_at: std::time::SystemTime = requested_at.into();
    match std::time::SystemTime::now().duration_since(requested_at) {
        Ok(age) => age > std::time::Duration::from_secs(STALE_REQUEST_SECS),
        // C-R4-9/S-F4: `duration_since` errors when `requested_at` is AFTER
        // `now` — genuine intra-host clock skew (tolerated up to
        // `CLOCK_SKEW_TOLERANCE_SECS`) is not yet stale, but anything
        // FURTHER in the future has no legitimate same-host origin and must
        // be discarded rather than treated as "not stale, wait forever" (a
        // wedge identical in shape to the one `STALE_REQUEST_SECS` itself
        // exists to break).
        Err(future) => {
            future.duration() > std::time::Duration::from_secs(CLOCK_SKEW_TOLERANCE_SECS)
        }
    }
}

/// Public wrapper for `request_is_stale` — `codex_supervise::drive_child`
/// (a different crate) checks staleness on an ALREADY-[`take_swap_request`]-
/// consumed request as a defense-in-depth measure: a request can, in
/// principle, sit unconsumed past `STALE_REQUEST_SECS` before its
/// `SIGUSR1` is ever noticed (the supervisor busy inside `graceful_stop`, or
/// simply slow to reach its next poll tick), so the staleness check the
/// WRITE side ([`write_swap_request_if_absent`]'s tombstone-retry) already
/// applies is re-checked once more at the point of actually acting on it.
pub fn is_swap_request_stale(req: &SwapRequest) -> bool {
    request_is_stale(req)
}

/// D-F6/D-F7 (round 7): the elapsed wall-clock time since `req.requested_at`
/// was stamped, or `None` when it cannot be parsed, or when it is further in
/// the future than `CLOCK_SKEW_TOLERANCE_SECS` tolerates (the same
/// fail-toward-refuse posture `request_is_stale` applies to an unparseable
/// or impossible timestamp — see that function's doc). Reused by
/// [`remaining_validation_budget`] (D-F6) and by
/// `codex_supervise::drive_child`'s post-accept consume-wait cap (D-F7), so
/// both budgets are measured against the SAME notion of "how old is this
/// request" rather than two independently-derived readings.
pub fn request_age(req: &SwapRequest) -> Option<std::time::Duration> {
    let requested_at = chrono::DateTime::parse_from_rfc3339(&req.requested_at).ok()?;
    let requested_at: std::time::SystemTime = requested_at.into();
    match std::time::SystemTime::now().duration_since(requested_at) {
        Ok(age) => Some(age),
        Err(future) => {
            if future.duration() <= std::time::Duration::from_secs(CLOCK_SKEW_TOLERANCE_SECS) {
                Some(std::time::Duration::ZERO)
            } else {
                None
            }
        }
    }
}

/// D-F6/S-LOW-1 (round 7): reserved so that even a validation admitted at
/// EXACTLY its dynamic deadline still leaves room for the verdict write,
/// [`VERDICT_CONSUME_WAIT_MS`]'s wait, and `csq swap`'s own read of the
/// verdict file before [`VERDICT_WAIT_TIMEOUT_SECS`]'s wait expires.
///
/// Derivation (two named outcomes, margin on each side per
/// `tooling-self-verification.md` Rule 3): the healthy case is a verdict
/// write (near-instant, sub-millisecond) plus a `csq swap` waiter already
/// blocked in its poll loop (25ms tick, see `VERDICT_POLL_MS`) — comfortably
/// under 200ms end to end. The bound this margin protects is
/// `VERDICT_WAIT_TIMEOUT_SECS` (10,000ms); 1,500ms leaves >7x headroom over
/// the healthy round-trip while still reserving real slack against the
/// worst case this whole mechanism exists to avoid: a validation that
/// resolves so close to the wire that its verdict is written after `csq
/// swap` has already given up and reported UNDETERMINED.
const VALIDATION_MARGIN_MS: u64 = 1_500;

/// D-F6/S-LOW-1 (round 7): the floor under which a request's remaining
/// budget is not worth attempting validation at all — refuse immediately
/// ("validation budget exhausted before it could start") rather than spend
/// any of it on a call that cannot possibly resolve in time. Set well below
/// [`VALIDATION_MARGIN_MS`] (a request that already has less time left than
/// the margin itself reserves has no budget to spend), and comfortably above
/// zero so a request landing at EXACTLY the wire is refused deterministically
/// rather than racing a zero-duration `recv_timeout`.
const MIN_VALIDATION_BUDGET_MS: u64 = 200;

/// D-F6/S-LOW-1 (round 7): the time budget remaining for `validate(..)` to
/// run to completion, given `req`'s age, before it would blow
/// [`VERDICT_WAIT_TIMEOUT_SECS`]'s wire (minus `VALIDATION_MARGIN_MS` of
/// reserved slack). Replaces the prior fixed [`VALIDATION_DEADLINE_SECS`]
/// bound, which measured only the validation CALL's own elapsed time and
/// ignored how much of the request's age was already spent before validation
/// even started — a request aged 3s that then took 7.5s to validate (10.5s
/// total) previously cleared the fixed 8s deadline check (7.5s < 8s) despite
/// having already blown `csq swap`'s 10s wire by the time its verdict could
/// be written.
///
/// Returns `None` when the remaining budget is at or below
/// `MIN_VALIDATION_BUDGET_MS` (including when `req`'s age cannot be
/// determined at all — fail toward refusing rather than granting an
/// undefined budget), signalling "refuse without even attempting
/// validation."
pub fn remaining_validation_budget(req: &SwapRequest) -> Option<std::time::Duration> {
    let age_ms = request_age(req)?.as_millis().min(u128::from(u64::MAX)) as u64;
    let wire_ms = VERDICT_WAIT_TIMEOUT_SECS.saturating_mul(1_000);
    let budget_ms = wire_ms
        .saturating_sub(VALIDATION_MARGIN_MS)
        .saturating_sub(age_ms);
    if budget_ms <= MIN_VALIDATION_BUDGET_MS {
        None
    } else {
        Some(std::time::Duration::from_millis(budget_ms))
    }
}

/// C-R4-1 (FM-2, closed for real): reads and ATOMICALLY consumes the
/// pending swap request, if any, by `rename(2)`-ing it directly into
/// [`SWAP_INFLIGHT_FILE`] — the rename IS the consume step, so there is no
/// window between "request gone" and "in-flight marker present" for a
/// second `!csq swap` to land in (see that constant's doc comment for the
/// window this closes, and what the earlier, non-atomic revision of this
/// fix got wrong).
///
/// Returns `None` when there is no request file, when the rename itself
/// fails (e.g. no such file — a concurrent consumer already took it), and
/// when the file is present but unparseable. A corrupt request is treated
/// as "no request" rather than guessed at, but the marker it was renamed
/// into is immediately cleared in that case too — nothing is genuinely in
/// flight for a corrupt request, so leaving the marker up would wedge every
/// future [`swap_request_pending`] check for no reason.
///
/// Callers that receive `Some(_)` and subsequently REFUSE the swap target
/// MUST call [`clear_swap_inflight`] — this function does not know whether
/// its caller will proceed or refuse.
pub fn take_swap_request(handle_dir: &Path) -> Option<SwapRequest> {
    let path = handle_dir.join(SWAP_REQUEST_FILE);
    let inflight = handle_dir.join(SWAP_INFLIGHT_FILE);
    std::fs::rename(&path, &inflight).ok()?;
    let s = std::fs::read_to_string(&inflight).ok();
    let req = s.as_deref().and_then(SwapRequest::parse);
    if req.is_none() {
        let _ = std::fs::remove_file(&inflight);
    }
    req
}

/// C-R4-1 (FM-2): clears the in-flight marker [`take_swap_request`] left
/// behind, when the swap TARGET it named is subsequently REFUSED (invalid
/// slot, unhealthy daemon, stale credentials, spawn-gate refusal). The
/// request itself is already gone (consumed atomically into the marker),
/// so without this the terminal is left durably reporting "swap pending"
/// via [`swap_request_pending`] with no request file remaining for a retry
/// to land against.
pub fn clear_swap_inflight(handle_dir: &Path) {
    let _ = std::fs::remove_file(handle_dir.join(SWAP_INFLIGHT_FILE));
}

/// Filename (inside a codex handle dir) holding the supervisor's verdict on
/// the swap request it most recently consumed — written by
/// `codex_supervise::drive_child` AFTER `validate_codex_relaunch_target`
/// resolves and, for an accepted verdict, BEFORE the current child is torn
/// down.
///
/// F1 (round 5): before this file existed, `csq swap` decided its own
/// reported outcome from a DUPLICATE set of cheap pre-checks (daemon
/// health, credential presence, ancestor-chain shape) run in
/// `handoff_to_supervisor` — checks that can diverge from what the
/// supervisor's OWN `validate_codex_relaunch_target` call decides moments
/// later, in a different process, up to several seconds after
/// `take_swap_request`'s atomic consume. `csq swap` printed "Switching..."
/// and returned success the instant it had signalled the supervisor,
/// regardless of what the supervisor went on to decide — a swap the
/// supervisor refused (stale credentials discovered only inside the
/// multi-second admission check, a daemon that went unhealthy in the
/// window between the two processes' checks) was reported as SUCCESS to
/// the terminal that asked for it.
///
/// The supervisor is now the single source of truth: `csq swap` waits
/// (bounded, see [`VERDICT_WAIT_TIMEOUT_SECS`]) for this file via
/// [`wait_for_swap_verdict`] and reports FROM it, never from its own
/// pre-checks. Written via the same secure-write pipeline as
/// [`SupervisorRecord`]/[`SwapRequest`] (see the module doc).
pub const SWAP_VERDICT_FILE: &str = ".csq-swap-verdict";

/// How long `csq swap` waits for [`SWAP_VERDICT_FILE`] after signalling the
/// supervisor, before giving up and reporting the outcome as UNDETERMINED —
/// never as accepted, never as refused. A timeout is its own third outcome
/// (see [`wait_for_swap_verdict`]'s doc).
///
/// C-F7: `validate_codex_relaunch_target` itself carries NO enforced
/// deadline — it is a synchronous daemon-health probe plus credential/config
/// checks with no internal timeout, so its worst case is bounded only by
/// whatever the daemon-health probe's own transport does (which this module
/// does not own and does not control). This constant is therefore a
/// TYPICAL-case figure, not a derived worst-case-with-margin bound: on a
/// HEALTHY host, a `~4-5s` validation is the ordinary case (in the same
/// low-single-digit-seconds range `GRACEFUL_STOP_MS`, 3s, already assumes
/// elsewhere in this protocol), and 10s gives roughly 2x headroom over that
/// TYPICAL case. A validation that is merely slow rather than dead can
/// legitimately exceed it — `wait_for_swap_verdict`'s `None` return is
/// exactly the "go check the terminal, do not guess" outcome for that case,
/// never a claim that the supervisor has failed. A supervisor that crashed
/// after taking the signal (or was never listening) never writes this file
/// at all, and is indistinguishable from "still validating" by this
/// mechanism alone.
pub const VERDICT_WAIT_TIMEOUT_SECS: u64 = 10;

/// C-F7: an overall deadline `codex_supervise::drive_child` enforces on the
/// WHOLE `validate(req.target_slot)` call — `validate_codex_relaunch_target`
/// itself carries no internal timeout (see [`VERDICT_WAIT_TIMEOUT_SECS`]'s
/// doc), so an admission check that is merely SLOW rather than dead can run
/// long enough that, by the time it finally resolves and a verdict is
/// written, `csq swap`'s own [`VERDICT_WAIT_TIMEOUT_SECS`] wait has ALREADY
/// expired — the supervisor accepted the swap, but the terminal that asked
/// for it already gave up and reported "undetermined". Enforcing a shorter
/// deadline HERE converts that race into a deterministic refusal instead:
/// a validation that overruns this bound is treated as
/// [`SwapOutcome::Refused`] ("validation timed out") regardless of what it
/// eventually returns, leaving margin for the verdict write + the bounded
/// wait for its consumption to reach `csq swap` before ITS OWN bound
/// expires.
///
/// Derivation (two named outcomes, margin stated on each side per
/// `tooling-self-verification.md` Rule 3): the HEALTHY case is
/// [`VERDICT_WAIT_TIMEOUT_SECS`]'s own doc, "a `~4-5s` validation is the
/// ordinary case" — 8s leaves that case ≥3s of headroom before this bound
/// fires at all. The bound this constant must stay UNDER is
/// `VERDICT_WAIT_TIMEOUT_SECS` (10s); 8s leaves 2s of margin on the OTHER
/// side — room for the verdict write (near-instant) plus whatever fraction
/// of `csq swap`'s wait had already elapsed by the time this deadline
/// fires — before that 10s bound expires too. Both margins are strictly
/// positive and neither touches the other's boundary.
pub const VALIDATION_DEADLINE_SECS: u64 = 8;

/// Poll interval for [`wait_for_swap_verdict`]. Matches `codex_supervise.rs`'s
/// own `POLL_MS` (25ms) supervisor-side tick — the verdict cannot appear
/// faster than the supervisor's own poll loop notices the signal, so
/// polling faster than that buys nothing.
const VERDICT_POLL_MS: u64 = 25;

/// The supervisor's decision on a swap request, once
/// `validate_codex_relaunch_target` has resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapOutcome {
    /// The target passed admission; the current child is being (or has
    /// been) torn down for relaunch.
    Accepted,
    /// The target was refused. Fixed-vocabulary, redacted reason (the
    /// write call site routes the originating `anyhow::Error` through
    /// `csq_core::error::redact_tokens` — never the raw `Display`, which
    /// may echo an upstream error body).
    Refused(String),
}

/// The supervisor's verdict on a specific, already-consumed [`SwapRequest`].
///
/// C-F6: bound to the request's [`SwapRequest::nonce`] — a 128-bit CSPRNG
/// value ([`gen_swap_nonce`]) — rather than [`SwapRequest::requested_at`].
/// An earlier revision bound this to the timestamp and argued its
/// uniqueness from `swap_request_pending`'s "at most one request live per
/// handle dir at a time" admission check: that IS true today, but it is a
/// property of CALLER discipline (a check that could change, or be bypassed
/// by a future write path), not a property of the identifier itself — and
/// `requested_at`'s second-resolution granularity means two requests
/// written within the same wall-clock second, however that were to happen,
/// would be genuinely indistinguishable. A nonce needs no such argument:
/// its uniqueness is unconditional, not contingent on an admission check
/// elsewhere continuing to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapVerdict {
    /// Copied from the originating [`SwapRequest::nonce`].
    pub nonce: String,
    pub outcome: SwapOutcome,
}

impl SwapVerdict {
    fn to_line(&self) -> String {
        match &self.outcome {
            SwapOutcome::Accepted => format!("{}\naccepted\n", self.nonce),
            SwapOutcome::Refused(reason) => format!("{}\nrefused\n{}\n", self.nonce, reason),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        let mut lines = s.lines();
        let nonce = lines.next()?.trim().to_string();
        if nonce.is_empty() {
            return None;
        }
        match lines.next()?.trim() {
            "accepted" => Some(Self {
                nonce,
                outcome: SwapOutcome::Accepted,
            }),
            "refused" => {
                let reason = lines.next()?.trim();
                if reason.is_empty() {
                    return None;
                }
                Some(Self {
                    nonce,
                    outcome: SwapOutcome::Refused(reason.to_string()),
                })
            }
            _ => None,
        }
    }
}

/// Atomically writes the supervisor's verdict for the request identified by
/// `verdict.nonce`. Called from `codex_supervise::drive_child`
/// immediately after `validate_codex_relaunch_target` resolves — for an
/// [`SwapOutcome::Accepted`] verdict, BEFORE the current child is torn down
/// (`graceful_stop`), so a `csq swap` waiting on this file never observes
/// "accepted" any later than the point past which the current session is
/// already committed to going away.
pub fn write_swap_verdict(handle_dir: &Path, verdict: &SwapVerdict) -> Result<(), PlatformError> {
    write_atomic_secure(&handle_dir.join(SWAP_VERDICT_FILE), &verdict.to_line())
}

/// Reads and consumes the verdict for `expected_nonce`, if present and
/// matching. A verdict present for a DIFFERENT request id (stale — an
/// earlier, already-resolved request; or a foreign write) is IGNORED:
/// returns `None` WITHOUT removing the file, since it may still be the
/// live answer some OTHER waiter needs. A verdict matching
/// `expected_nonce` is consumed (removed) so a later, unrelated
/// request never re-reads a stale accept/refuse that happens to still be
/// on disk.
pub fn take_swap_verdict(handle_dir: &Path, expected_nonce: &str) -> Option<SwapVerdict> {
    let path = handle_dir.join(SWAP_VERDICT_FILE);
    let s = std::fs::read_to_string(&path).ok()?;
    let verdict = SwapVerdict::parse(&s)?;
    if verdict.nonce != expected_nonce {
        return None;
    }
    let _ = std::fs::remove_file(&path);
    Some(verdict)
}

/// Blocks (bounded by `timeout`) waiting for the supervisor's verdict on the
/// request identified by `expected_nonce`. Returns `Some(verdict)` the
/// instant it is observed, or `None` once `timeout` elapses first.
///
/// `None` is its own THIRD outcome — undetermined, never accepted and never
/// refused. Callers MUST NOT report a timeout as either polarity: the
/// supervisor may still resolve the swap after this call returns (a slow
/// but alive validation, or a wedged-but-not-dead supervisor) — the correct
/// disposition is "check the terminal", not a guess in either direction.
pub fn wait_for_swap_verdict(
    handle_dir: &Path,
    expected_nonce: &str,
    timeout: std::time::Duration,
) -> Option<SwapVerdict> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(v) = take_swap_verdict(handle_dir, expected_nonce) {
            return Some(v);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(VERDICT_POLL_MS));
    }
}

/// How long the supervisor waits, after writing an [`SwapOutcome::Accepted`]
/// verdict, for `csq swap`'s [`take_swap_verdict`] to CONSUME (remove) it
/// before proceeding to tear down the outgoing child.
///
/// Derivation (two named outcomes, margin stated on each side per
/// `tooling-self-verification.md` Rule 3): the healthy case is a `csq swap`
/// process already blocked inside its own `wait_for_swap_verdict` poll
/// (25ms tick, see `VERDICT_POLL_MS`) at the moment this file is written
/// — it observes and consumes within one or two ticks, comfortably under
/// 100ms. The failing case this bound guards against is `csq swap` NOT
/// reading in time before `codex_supervise::run_supervised` calls
/// `tombstone_handle_dir` (which renames the whole handle dir, verdict file
/// included, out from under a waiter still polling the ORIGINAL path) —
/// once that rename happens the verdict is unrecoverable regardless of how
/// much longer this wait ran, so there is no "larger bound helps" case to
/// trade off against; 1000ms is therefore sized purely against the healthy
/// case (>10x headroom) rather than against a worst case that does not
/// exist for this wait. A `csq swap` that is merely slow to poll (loaded
/// host) or was never invoked at all (e.g. a supervisor accepting a
/// same-process test harness's synthetic request) legitimately exceeds it —
/// see this function's own return value for why that is not treated as an
/// error.
pub const VERDICT_CONSUME_WAIT_MS: u64 = 1_000;

/// D-F7 (round 7): the ACTUAL bound `codex_supervise::drive_child` passes to
/// [`wait_for_verdict_consumed`] — `min(remaining wire time from `req`'s age,
/// [`VERDICT_CONSUME_WAIT_MS`])`, never [`VERDICT_CONSUME_WAIT_MS`] alone.
///
/// [`VERDICT_CONSUME_WAIT_MS`]'s own doc already establishes there is no
/// "larger bound helps" case once `csq swap`'s [`VERDICT_WAIT_TIMEOUT_SECS`]
/// wire has passed — a waiter that already gave up will never read the
/// verdict regardless of how much longer this wait runs. This function
/// closes the gap that left in that doc: when a request's own age has
/// ALREADY consumed most or all of that wire by the time the verdict is
/// about to be written, waiting the full fixed constant stalls the
/// supervisor's teardown for no benefit — the wire will already have passed
/// by the time the wait would return either way. Capping to whatever wire
/// time remains (zero when none does) means the supervisor never waits
/// longer than the interval in which a `csq swap` waiter could still
/// plausibly be listening.
pub fn consume_wait_bound(req: &SwapRequest) -> std::time::Duration {
    let cap = std::time::Duration::from_millis(VERDICT_CONSUME_WAIT_MS);
    let Some(age) = request_age(req) else {
        // Unparseable/impossible age — no basis to shrink the cap; fall back
        // to the fixed constant rather than guessing a stricter bound.
        return cap;
    };
    let wire = std::time::Duration::from_secs(VERDICT_WAIT_TIMEOUT_SECS);
    let remaining = wire.saturating_sub(age);
    remaining.min(cap)
}

/// Blocks (bounded by [`VERDICT_CONSUME_WAIT_MS`]) until the verdict file
/// written by [`write_swap_verdict`] at `handle_dir` has been consumed
/// (removed by [`take_swap_verdict`]) or the bound elapses first. Returns
/// `true` if consumption was observed within the bound, `false` if the
/// bound elapsed with the file still present.
///
/// A `false` return is NOT an error and MUST NOT change the accepted
/// verdict already written — a wedged, absent, or merely slow waiter must
/// never block the swap (or the supervisor's own teardown) indefinitely.
/// It only means the caller proceeded before consumption was confirmed; in
/// `codex_supervise::drive_child`'s accepted branch that narrows, but does
/// not close, the same race this wait exists to shrink (see
/// [`VERDICT_CONSUME_WAIT_MS`]'s doc for the race itself: `csq swap`'s
/// `wait_for_swap_verdict` losing to `tombstone_handle_dir`'s rename of the
/// handle dir).
pub fn wait_for_verdict_consumed(handle_dir: &Path, timeout: std::time::Duration) -> bool {
    let path = handle_dir.join(SWAP_VERDICT_FILE);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if !path.exists() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(VERDICT_POLL_MS));
    }
}

/// Sends `sig` to `pid`. Thin wrapper so callers never reach for raw
/// `libc::kill` outside this module.
#[cfg(unix)]
pub fn signal_supervisor(pid: u32, sig: libc::c_int) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `write -> secure_file -> atomic_replace`, cleaning up the tmp file on
/// every failure branch (`security.md` §5a). Neither file this module
/// writes carries secret content, but the pipeline is reused for
/// atomicity: a reader must never observe a partially-written record.
fn write_atomic_secure(target: &Path, contents: &str) -> Result<(), PlatformError> {
    let tmp = unique_tmp_path(target);
    if let Err(e) = std::fs::write(&tmp, contents.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(PlatformError::Io(e));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = atomic_replace(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn tmp_handle_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("tempdir")
    }

    /// Sets `path`'s mtime to `now - age` via `utimensat` — mirrors
    /// `audit::sweep::tests::set_mtime_age` (that helper is private to its
    /// own module, so this inlines the same small shape rather than
    /// exposing it cross-module for one test).
    #[cfg(unix)]
    fn set_mtime_age(path: &Path, age: std::time::Duration) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let target_time = std::time::SystemTime::now()
            .checked_sub(age)
            .unwrap_or(std::time::UNIX_EPOCH);
        let secs = target_time
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as libc::time_t)
            .unwrap_or(0);
        let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path_c is a valid null-terminated C string; timespec
        // values are valid. Only mutates this test's own tmpfile's mtime.
        unsafe {
            let times = [
                libc::timespec {
                    tv_sec: secs,
                    tv_nsec: 0,
                },
                libc::timespec {
                    tv_sec: secs,
                    tv_nsec: 0,
                },
            ];
            libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), 0);
        }
    }

    // ── item 6 (D-F6): a CorruptAndOld tombstone judgment must ALSO
    //    require the RENAMED file's mtime to still be old — not merely
    //    that it is (still) unparseable ─────────────────────────────────
    //
    // RED — EXECUTED: with the `content_confirmed` arm reverted to the
    // pre-fix `(TombstoneJudgment::CorruptAndOld(_), None) => true`,
    // `cargo test -p csq-core --lib \
    // session::codex_supervisor::tests::tombstone_refuses_a_corrupt_and_old_judgment_when_the_renamed_file_is_young \
    // -- --exact` failed:
    // `a racing writer's YOUNG corrupt rewrite of the SAME inode must NOT
    // be confirmed as the OLD file that was judged ... left: true` (the
    // pre-fix code returned `Ok(true)` — CONFIRMED — and silently
    // tombstoned the racing writer's fresh content away). GREEN with the
    // mtime re-check restored.
    #[cfg(unix)]
    #[test]
    fn tombstone_refuses_a_corrupt_and_old_judgment_when_the_renamed_file_is_young() {
        let dir = tmp_handle_dir();
        let path = dir.path().join(SWAP_REQUEST_FILE);
        std::fs::write(&path, b"not a valid swap request line").unwrap();
        set_mtime_age(
            &path,
            std::time::Duration::from_secs(STALE_REQUEST_SECS + 5),
        );

        let judgment = judge_existing_request_for_tombstone(&path)
            .expect("an old, corrupt file must judge as tombstone-eligible");
        assert!(
            matches!(judgment, TombstoneJudgment::CorruptAndOld(_)),
            "got {judgment:?}"
        );

        // Simulate a racing writer overwriting the SAME inode IN PLACE
        // (no unlink, no rename) with fresh — still unparseable — content,
        // in the window between judgment and `tombstone_and_retry`'s own
        // rename. dev+ino (and any already-captured birth time) are
        // UNCHANGED by an in-place rewrite, so the identity check alone
        // cannot see this; only the mtime distinguishes it.
        std::fs::write(&path, b"different corrupt content, still unparseable").unwrap();
        set_mtime_age(&path, std::time::Duration::from_secs(1));

        let req = SwapRequest {
            target_slot: 9,
            ..Default::default()
        };
        let confirmed =
            tombstone_and_retry(&path, judgment, &req).expect("must not error, only refuse");
        assert!(
            !confirmed,
            "a racing writer's YOUNG corrupt rewrite of the SAME inode must NOT \
             be confirmed as the OLD file that was judged"
        );
        let surviving = std::fs::read_to_string(&path).expect("path must exist after refusal");
        assert_eq!(
            surviving, "different corrupt content, still unparseable",
            "the racing writer's fresh content must survive at `path` \
             (restored via hard_link), never be silently tombstoned away"
        );
    }

    // Unix-only: needs a real process start time, which `process_start_time`
    // provides only on unix (the supervised swap is unix-only by design).
    #[cfg(unix)]
    #[test]
    fn supervisor_record_round_trips() {
        let dir = tmp_handle_dir();
        let written = write_supervisor_record(dir.path()).expect("write");
        let read_back = read_supervisor_record(dir.path()).expect("read back");
        assert_eq!(written, read_back);
    }

    // Unix-only: needs a real process start time, which `process_start_time`
    // provides only on unix (the supervised swap is unix-only by design).
    #[cfg(unix)]
    #[test]
    fn verify_supervisor_alive_true_for_this_live_process() {
        let dir = tmp_handle_dir();
        write_supervisor_record(dir.path()).expect("write");
        assert!(
            verify_supervisor_alive(dir.path()),
            "the writing process is alive and its start time is stable \
             within the same process lifetime — this must verify"
        );
    }

    #[test]
    fn verify_supervisor_alive_false_when_no_record() {
        let dir = tmp_handle_dir();
        assert!(!verify_supervisor_alive(dir.path()));
    }

    #[test]
    fn verify_supervisor_alive_false_for_corrupt_record() {
        let dir = tmp_handle_dir();
        std::fs::write(
            dir.path().join(SUPERVISOR_FILE),
            "not-a-number\nsomething\n",
        )
        .unwrap();
        assert!(!verify_supervisor_alive(dir.path()));
    }

    /// A recycled-PID probe: write a record naming a PID that is
    /// genuinely alive right now (so `pid_is_alive` alone would say
    /// "yes"), but with a start-time string that could not possibly be
    /// this process's own. This is the case the anti-recycling nonce
    /// exists for — mechanism is exercised for real, not asserted.
    #[test]
    fn verify_supervisor_alive_false_on_start_time_mismatch() {
        let dir = tmp_handle_dir();
        let pid = std::process::id();
        let record = SupervisorRecord {
            pid,
            start_time: "Thu Jan  1 00:00:00 1970".to_string(),
        };
        std::fs::write(dir.path().join(SUPERVISOR_FILE), record.to_line()).unwrap();
        assert!(
            !verify_supervisor_alive(dir.path()),
            "a live PID with the WRONG recorded start time must fail closed, \
             exactly the recycled-PID case this nonce defends against"
        );
    }

    /// A genuinely stale record: the PID it names has exited. Spawns a
    /// real short-lived process, records ITS pid+start-time, waits for
    /// it to exit, then verifies the record now reads as dead.
    #[test]
    fn verify_supervisor_alive_false_after_process_exits() {
        let dir = tmp_handle_dir();
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        // Best-effort start time for the child; may be empty if `ps`
        // races the child's exit, which is fine — the pid-liveness check
        // below is what actually invalidates the record.
        let start_time = process_start_time(pid).unwrap_or_else(|| "unknown".to_string());
        let record = SupervisorRecord { pid, start_time };
        std::fs::write(dir.path().join(SUPERVISOR_FILE), record.to_line()).unwrap();
        let status = child.wait().expect("wait for child exit");
        assert!(status.success());
        assert!(!verify_supervisor_alive(dir.path()));
    }

    // ── S-L2 (round 5): create-if-absent write ───────────────────────────

    #[test]
    fn write_swap_request_if_absent_succeeds_when_nothing_present() {
        let dir = tmp_handle_dir();
        let req = SwapRequest {
            target_slot: 3,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        let wrote = write_swap_request_if_absent(dir.path(), &req).expect("write");
        assert!(wrote, "must write when nothing was present");
        let taken = take_swap_request(dir.path()).expect("take");
        assert_eq!(taken, req);
    }

    /// The discriminating case: a request ALREADY present (from a
    /// concurrent writer) must NOT be clobbered — before this fix,
    /// `write_swap_request` always overwrote unconditionally.
    #[test]
    fn write_swap_request_if_absent_refuses_when_a_request_already_exists() {
        let dir = tmp_handle_dir();
        let first = SwapRequest {
            target_slot: 3,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        write_swap_request(dir.path(), &first).expect("write first request");

        let second = SwapRequest {
            target_slot: 9,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        let wrote = write_swap_request_if_absent(dir.path(), &second).expect("call succeeds");
        assert!(
            !wrote,
            "must refuse to write when a request is already present"
        );
        let taken = take_swap_request(dir.path()).expect("take");
        assert_eq!(
            taken, first,
            "the FIRST (concurrent writer's) request must survive untouched"
        );
    }

    #[test]
    fn write_swap_request_if_absent_refuses_when_in_flight_marker_present() {
        let dir = tmp_handle_dir();
        let first = SwapRequest {
            target_slot: 3,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        write_swap_request(dir.path(), &first).expect("write first request");
        take_swap_request(dir.path()).expect("consume into in-flight marker");
        assert!(dir.path().join(SWAP_INFLIGHT_FILE).exists());

        let second = SwapRequest {
            target_slot: 9,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        let wrote = write_swap_request_if_absent(dir.path(), &second).expect("call succeeds");
        assert!(
            !wrote,
            "must refuse to write while an in-flight marker is present"
        );
        assert!(
            !dir.path().join(SWAP_REQUEST_FILE).exists(),
            "no request file must be created while a swap is already in flight"
        );
    }

    // ── C-F4/S-M3: tombstone-retry on a stale/corrupt-and-old existing
    //    request ────────────────────────────────────────────────────────────

    /// The discriminating case named in the governing brief: a STALE
    /// (parseable, but past `STALE_REQUEST_SECS`) request must not wedge a
    /// NEW writer forever — `write_swap_request_if_absent` must tombstone it
    /// and succeed, not just refuse like the concurrent-fresh-writer case.
    #[test]
    fn write_swap_request_if_absent_tombstones_a_stale_request_and_succeeds() {
        let dir = tmp_handle_dir();
        let stale = SwapRequest {
            target_slot: 3,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(STALE_REQUEST_SECS + 5),
            ..Default::default()
        };
        write_swap_request(dir.path(), &stale).expect("write stale request directly");

        let fresh = SwapRequest {
            target_slot: 9,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        let wrote = write_swap_request_if_absent(dir.path(), &fresh)
            .expect("must not error — the stale request is tombstoned, not a genuine conflict");
        assert!(
            wrote,
            "a stale request must be tombstoned and the new one written"
        );
        let taken = take_swap_request(dir.path()).expect("take");
        assert_eq!(
            taken, fresh,
            "the NEW writer's request must be the one that lands, not the stale one"
        );
    }

    /// D-F8 (round 7): the two-writer race `tombstone_and_retry` exists to
    /// close. A judgment is captured against a STALE request (as
    /// `judge_existing_request_for_tombstone` would, pre-rename); before the
    /// rename actually runs, `path` is mutated to hold a DIFFERENT, FRESH
    /// request (simulating a second, racing tombstone-and-retry cycle that
    /// completed first). The rename in `tombstone_and_retry` therefore picks
    /// up the FRESH content, not the stale content the judgment describes —
    /// it MUST detect the mismatch, restore the fresh content via hard_link,
    /// and refuse (return `Ok(false)`), never silently destroying it.
    #[test]
    fn tombstone_and_retry_restores_a_fresh_request_that_raced_the_rename() {
        let dir = tmp_handle_dir();
        let path = dir.path().join(SWAP_REQUEST_FILE);

        let stale = SwapRequest {
            target_slot: 3,
            requested_at: rfc3339_seconds_ago(STALE_REQUEST_SECS + 5),
            ..Default::default()
        };
        write_swap_request(dir.path(), &stale).expect("write stale request directly");
        // Capture the judgment BEFORE the race — this is exactly what
        // `write_swap_request_if_absent` would have captured pre-rename.
        let judgment =
            judge_existing_request_for_tombstone(&path).expect("stale request must be judged");

        // Simulate a SIBLING tombstone-and-retry cycle winning the race:
        // the stale content is replaced with a FRESH, unrelated request
        // (different nonce) before THIS call's rename executes.
        let racing_fresh = SwapRequest {
            target_slot: 11,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        std::fs::remove_file(&path).unwrap();
        write_swap_request(dir.path(), &racing_fresh).expect("write racing fresh request");

        let this_writer_req = SwapRequest {
            target_slot: 9,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        let wrote = tombstone_and_retry(&path, judgment, &this_writer_req).expect("must not error");
        assert!(
            !wrote,
            "this writer's own request must NOT be written — the racing \
             fresh request occupies `path` and must be preserved instead"
        );
        let surviving = std::fs::read_to_string(&path).expect("path must be restored");
        let surviving_req = SwapRequest::parse(&surviving).expect("restored content must parse");
        assert_eq!(
            surviving_req, racing_fresh,
            "the racing writer's fresh request must survive at `path` — it \
             must never be silently destroyed by an unrelated tombstone \
             cycle's rename"
        );
    }

    /// S-LOW-E / C-B3 / C-B4 (round 8b): the CORRUPT-AND-OLD counterpart of
    /// the race above — one the CONTENT check alone cannot catch. A
    /// `CorruptAndOld` judgment's content re-check is `renamed_req == None`,
    /// which is true for ANY unparseable file, not just the specific one
    /// that was judged. Here the judged file is replaced, before the
    /// rename, by a DIFFERENT unparseable file (a racing writer's own
    /// mid-write corrupt content) — content-only re-verification would see
    /// "still doesn't parse" and confirm, deleting the racing writer's
    /// in-progress file. The `FsIdentity` (dev/ino) comparison this fix adds
    /// is what tells the two apart: the rename picks up a DIFFERENT inode
    /// than the one `judge_existing_request_for_tombstone` captured.
    #[test]
    fn tombstone_and_retry_restores_a_racing_corrupt_file_with_the_same_unparseable_shape() {
        let dir = tmp_handle_dir();
        let path = dir.path().join(SWAP_REQUEST_FILE);

        std::fs::write(&path, "garbage-v1\n").unwrap();
        let old =
            std::time::SystemTime::now() - std::time::Duration::from_secs(STALE_REQUEST_SECS + 5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let judgment = judge_existing_request_for_tombstone(&path)
            .expect("old corrupt file must be tombstone-eligible");

        // Simulate a racing writer's OWN mid-write corrupt content landing
        // at the same path, with the SAME "does not parse" shape but
        // DIFFERENT bytes and (critically) a different inode.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "garbage-v2-different-bytes\n").unwrap();

        let this_writer_req = SwapRequest {
            target_slot: 9,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        let wrote = tombstone_and_retry(&path, judgment, &this_writer_req).expect("must not error");
        assert!(
            !wrote,
            "this writer's own request must NOT be written — the racing \
             corrupt file occupies `path` and must be preserved instead"
        );
        let surviving = std::fs::read_to_string(&path).expect("path must be restored");
        assert_eq!(
            surviving, "garbage-v2-different-bytes\n",
            "the racing writer's own (different) corrupt content must \
             survive at `path` — a content-only re-check cannot tell it \
             apart from the file that was actually judged stale, since \
             both are merely \"does not parse\"; only the filesystem \
             identity comparison catches this"
        );
    }

    /// The counterpart: a YOUNG (just-written) unparseable file must NOT be
    /// tombstoned — it may be a concurrent writer's request mid-write. The
    /// refusal is what lets the caller's message name the file rather than
    /// this function silently discarding data it cannot yet classify.
    #[test]
    fn write_swap_request_if_absent_refuses_a_young_corrupt_request() {
        let dir = tmp_handle_dir();
        std::fs::write(
            dir.path().join(SWAP_REQUEST_FILE),
            "garbage\nnot-parseable\n",
        )
        .unwrap();

        let fresh = SwapRequest {
            target_slot: 9,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        let wrote = write_swap_request_if_absent(dir.path(), &fresh).expect("call succeeds");
        assert!(
            !wrote,
            "a YOUNG corrupt request must be refused, not silently tombstoned"
        );
        assert!(
            dir.path().join(SWAP_REQUEST_FILE).exists(),
            "the young corrupt file must be left in place for the caller's \
             refusal message to name"
        );
    }

    /// An OLD (mtime past `STALE_REQUEST_SECS`) corrupt file has the same
    /// "nobody is coming back for this" shape as a stale-but-parseable one
    /// and must be tombstoned too — this is the unit-level proof for the
    /// `judge_existing_request_for_tombstone` branch that
    /// `write_swap_request_if_absent`'s black-box tests above cannot reach
    /// without an actual `STALE_REQUEST_SECS`-long sleep.
    #[test]
    fn should_tombstone_existing_request_true_for_old_corrupt_file() {
        let dir = tmp_handle_dir();
        let path = dir.path().join(SWAP_REQUEST_FILE);
        std::fs::write(&path, "garbage\n").unwrap();
        let old =
            std::time::SystemTime::now() - std::time::Duration::from_secs(STALE_REQUEST_SECS + 5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(
            judge_existing_request_for_tombstone(&path).is_some(),
            "an old corrupt file must be tombstone-eligible"
        );
    }

    #[test]
    fn should_tombstone_existing_request_false_for_young_corrupt_file() {
        let dir = tmp_handle_dir();
        let path = dir.path().join(SWAP_REQUEST_FILE);
        std::fs::write(&path, "garbage\n").unwrap();
        assert!(
            judge_existing_request_for_tombstone(&path).is_none(),
            "a fresh corrupt file must NOT be tombstone-eligible — it may be \
             a concurrent writer mid-write"
        );
    }

    #[test]
    fn swap_request_round_trips_with_thread_id() {
        let dir = tmp_handle_dir();
        assert!(!swap_request_pending(dir.path()));
        let req = SwapRequest {
            target_slot: 11,
            // S-F1: `thread_id` must be UUID-shaped or `SwapRequest::parse`
            // rejects the whole record — this fixture's ORIGINAL value
            // ("thread-abc-123") was not, and correctly failed round-trip
            // once that check landed. A genuine UUID is what this test's
            // round-trip intent actually needs.
            thread_id: Some("0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5b".to_string()),
            // FM-3: `swap_request_pending` now ages requests out after
            // `STALE_REQUEST_SECS` — a fresh timestamp is required for the
            // `assert!(swap_request_pending(...))` below to mean anything
            // (a fixed historical literal would read as stale the moment
            // more than 10s of wall-clock separates it from "now").
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        write_swap_request(dir.path(), &req).expect("write swap request");
        assert!(swap_request_pending(dir.path()));
        let taken = take_swap_request(dir.path()).expect("take");
        assert_eq!(taken, req);
        assert!(
            !dir.path().join(SWAP_REQUEST_FILE).exists(),
            "take_swap_request must consume (rename away) the request file"
        );
        // C-R4-1: consuming now atomically marks in-flight (see
        // `take_swap_request_atomically_marks_inflight_with_no_gap`), so
        // `swap_request_pending` reads true here, not false — clearing it
        // is the caller's job on a refusal (`clear_swap_inflight`), not
        // something `take_swap_request` itself does.
        assert!(swap_request_pending(dir.path()));
        clear_swap_inflight(dir.path());
        assert!(!swap_request_pending(dir.path()));
    }

    #[test]
    fn swap_request_round_trips_without_thread_id() {
        let dir = tmp_handle_dir();
        let req = SwapRequest {
            target_slot: 4,
            thread_id: None,
            requested_at: "2026-09-26T00:00:00Z".to_string(),
            ..Default::default()
        };
        write_swap_request(dir.path(), &req).expect("write swap request");
        let taken = take_swap_request(dir.path()).expect("take");
        assert_eq!(taken, req);
    }

    #[test]
    fn take_swap_request_none_when_absent() {
        let dir = tmp_handle_dir();
        assert!(take_swap_request(dir.path()).is_none());
    }

    #[test]
    fn take_swap_request_consumes_corrupt_file_as_none() {
        let dir = tmp_handle_dir();
        std::fs::write(dir.path().join(SWAP_REQUEST_FILE), "garbage\n").unwrap();
        assert!(take_swap_request(dir.path()).is_none());
        assert!(
            !dir.path().join(SWAP_REQUEST_FILE).exists(),
            "a corrupt request must still be consumed, or it wedges every future check"
        );
    }

    /// S-F1: a `thread_id` that is not UUID-shaped must make the WHOLE
    /// request unparseable (treated as corrupt, per the same
    /// "corrupt == no request" posture as the garbage-file case above) —
    /// never silently accepted and carried into a relaunch's `codex resume
    /// <id>` argv. Regression for a same-user attacker planting
    /// `--dangerously-bypass-approvals-and-sandbox` as the thread_id.
    #[test]
    fn take_swap_request_rejects_non_uuid_thread_id() {
        let dir = tmp_handle_dir();
        // Hand-write the on-disk shape directly (bypassing `write_swap_request`,
        // which only ever writes a real UUID or empty) — this is exactly the
        // same-user-attacker-write this check defends against.
        std::fs::write(
            dir.path().join(SWAP_REQUEST_FILE),
            "9\n--dangerously-bypass-approvals-and-sandbox\n2026-09-26T00:00:00Z\n",
        )
        .unwrap();
        assert!(
            take_swap_request(dir.path()).is_none(),
            "a non-UUID thread_id must invalidate the whole request"
        );
        assert!(
            !dir.path().join(SWAP_REQUEST_FILE).exists(),
            "the malicious request must still be consumed, not left to wedge future checks"
        );
    }

    /// A well-formed thread_id (genuine UUID shape) is unaffected — this is
    /// the RED/GREEN counterpart proving `is_uuid_shaped` does not simply
    /// reject everything.
    #[test]
    fn take_swap_request_accepts_uuid_shaped_thread_id() {
        let dir = tmp_handle_dir();
        let req = SwapRequest {
            target_slot: 9,
            thread_id: Some("0198f1a2-3b4c-7d5e-8f9a-0b1c2d3e4f5a".to_string()),
            requested_at: "2026-09-26T00:00:00Z".to_string(),
            ..Default::default()
        };
        write_swap_request(dir.path(), &req).expect("write swap request");
        let taken = take_swap_request(dir.path()).expect("take");
        assert_eq!(taken, req);
    }

    /// csq-core has no ambient clock (`chrono` here carries no `clock`
    /// feature) — build an RFC3339 timestamp from `std::time::SystemTime`
    /// instead of `chrono::Utc::now()`.
    fn rfc3339_seconds_ago(secs: u64) -> String {
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        chrono::DateTime::<chrono::Utc>::from(past)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    fn rfc3339_millis_ago(ms: u64) -> String {
        let past = std::time::SystemTime::now() - std::time::Duration::from_millis(ms);
        chrono::DateTime::<chrono::Utc>::from(past)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    // ── D-F6/D-F7 (round 7): dynamic, per-request budgets ───────────────────

    #[test]
    fn remaining_validation_budget_shrinks_with_request_age() {
        let fresh = SwapRequest {
            requested_at: rfc3339_millis_ago(0),
            ..Default::default()
        };
        let aged = SwapRequest {
            requested_at: rfc3339_millis_ago(8_000),
            ..Default::default()
        };
        let fresh_budget = remaining_validation_budget(&fresh).expect("fresh request has budget");
        let aged_budget =
            remaining_validation_budget(&aged).expect("aged request still has budget");
        assert!(
            aged_budget < fresh_budget,
            "an older request must leave LESS validation budget: aged={aged_budget:?} fresh={fresh_budget:?}"
        );
    }

    #[test]
    fn remaining_validation_budget_none_once_wire_is_effectively_spent() {
        let exhausted = SwapRequest {
            requested_at: rfc3339_seconds_ago(VERDICT_WAIT_TIMEOUT_SECS),
            ..Default::default()
        };
        assert!(
            remaining_validation_budget(&exhausted).is_none(),
            "a request as old as the whole wire must have no budget left"
        );
    }

    /// C-N1/C-N3 (round 8b): the boundary spec's "consume_wait_bound's cap
    /// is unreachable on the accepted path" note derives from — an 8.4s-aged
    /// request leaves only 100ms of nominal budget (10s wire − 1.5s margin
    /// − 8.4s age), BELOW `MIN_VALIDATION_BUDGET_MS` (200ms), so validation
    /// must be refused BEFORE it can even start. This is the boundary one
    /// tick before the 8.5s ceiling (`wire − margin`) past which an
    /// ACCEPTED request cannot age — see specs/02-csq-handle-dir-model.md
    /// § "Dynamic validation and consume-wait budgets" for the full
    /// derivation this pins.
    #[test]
    fn remaining_validation_budget_returns_none_past_the_min_budget_floor() {
        let just_under_floor = SwapRequest {
            requested_at: rfc3339_millis_ago(8_400),
            ..Default::default()
        };
        assert!(
            remaining_validation_budget(&just_under_floor).is_none(),
            "an 8.4s-aged request leaves only ~100ms of nominal budget — \
             below the 200ms MIN_VALIDATION_BUDGET_MS floor — and must \
             return None, not a razor-thin Some(duration)"
        );
    }

    #[test]
    fn consume_wait_bound_caps_to_remaining_wire_for_an_aged_request() {
        let aged = SwapRequest {
            // 9.9s old — under 100ms of the 10s wire remains.
            requested_at: rfc3339_millis_ago(9_900),
            ..Default::default()
        };
        let bound = consume_wait_bound(&aged);
        assert!(
            bound < std::time::Duration::from_millis(VERDICT_CONSUME_WAIT_MS),
            "an aged request must cap BELOW the fixed constant: {bound:?}"
        );
    }

    #[test]
    fn consume_wait_bound_uses_the_fixed_constant_for_a_fresh_request() {
        let fresh = SwapRequest {
            requested_at: rfc3339_millis_ago(0),
            ..Default::default()
        };
        assert_eq!(
            consume_wait_bound(&fresh),
            std::time::Duration::from_millis(VERDICT_CONSUME_WAIT_MS),
            "a fresh request has ample wire remaining — the bound is just the fixed constant"
        );
    }

    // ── C-R4-1 (FM-2, closed): the consume step ITSELF marks in flight,
    //    atomically — no window where neither file exists ─────────────────

    #[test]
    fn take_swap_request_atomically_marks_inflight_with_no_gap() {
        let dir = tmp_handle_dir();
        let req = SwapRequest {
            target_slot: 5,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        write_swap_request(dir.path(), &req).expect("write swap request");
        assert!(swap_request_pending(dir.path()));

        // `take_swap_request` now performs the rename itself — there is no
        // separate `mark_swap_inflight` call a caller could delay past a
        // multi-second validation step (that was C-R4-1's whole finding).
        let taken = take_swap_request(dir.path()).expect("take");
        assert_eq!(taken, req);
        assert!(
            !dir.path().join(SWAP_REQUEST_FILE).exists(),
            "the original request file must be gone (renamed away)"
        );
        assert!(
            swap_request_pending(dir.path()),
            "the in-flight marker must ALREADY be present the instant the \
             request is consumed — this is what closes the FM-2 window, a \
             second `!csq swap` landing right now must see pending=true \
             even though `take_swap_request` already returned"
        );
    }

    #[test]
    fn clear_swap_inflight_unwedges_a_refused_target() {
        let dir = tmp_handle_dir();
        let req = SwapRequest {
            target_slot: 5,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        write_swap_request(dir.path(), &req).expect("write swap request");
        take_swap_request(dir.path()).expect("take");
        assert!(swap_request_pending(dir.path()));

        // C-R4-1: on a REFUSED target, the caller must clear the marker or
        // the terminal is wedged "swap pending" forever with no request
        // file left for a retry to land against.
        clear_swap_inflight(dir.path());
        assert!(
            !swap_request_pending(dir.path()),
            "clearing the in-flight marker after a refusal must unwedge \
             `swap_request_pending`"
        );
    }

    #[test]
    fn take_swap_request_clears_marker_for_a_corrupt_request() {
        let dir = tmp_handle_dir();
        std::fs::write(dir.path().join(SWAP_REQUEST_FILE), "garbage\n").unwrap();
        assert!(take_swap_request(dir.path()).is_none());
        assert!(
            !dir.path().join(SWAP_INFLIGHT_FILE).exists(),
            "a corrupt request renamed into the in-flight marker must have \
             that marker cleared immediately — nothing is genuinely in \
             flight for a request nobody will ever validate"
        );
    }

    // ── FM-3: staleness ─────────────────────────────────────────────────────

    #[test]
    fn swap_request_pending_false_when_stale() {
        let dir = tmp_handle_dir();
        let old = rfc3339_seconds_ago(STALE_REQUEST_SECS + 5);
        write_swap_request(
            dir.path(),
            &SwapRequest {
                target_slot: 2,
                thread_id: None,
                requested_at: old,
                ..Default::default()
            },
        )
        .expect("write swap request");
        assert!(
            !swap_request_pending(dir.path()),
            "a request older than STALE_REQUEST_SECS must not block a fresh write \
             — its writer is presumed dead"
        );
    }

    #[test]
    fn swap_request_pending_true_when_fresh() {
        let dir = tmp_handle_dir();
        let now = rfc3339_seconds_ago(0);
        write_swap_request(
            dir.path(),
            &SwapRequest {
                target_slot: 2,
                thread_id: None,
                requested_at: now,
                ..Default::default()
            },
        )
        .expect("write swap request");
        assert!(
            swap_request_pending(dir.path()),
            "a request well within STALE_REQUEST_SECS must still be pending"
        );
    }

    // ── C-R4-9/S-F4: a FUTURE-stamped request is stale beyond clock skew ────

    #[test]
    fn swap_request_pending_false_for_far_future_timestamp() {
        let dir = tmp_handle_dir();
        // Same-host clock skew is sub-second in practice (see
        // `CLOCK_SKEW_TOLERANCE_SECS`'s derivation) — an hour in the future
        // has no legitimate same-host origin and must be discarded, not
        // treated as "not yet stale, wait forever".
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let future_rfc3339 = chrono::DateTime::<chrono::Utc>::from(future)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        write_swap_request(
            dir.path(),
            &SwapRequest {
                target_slot: 2,
                thread_id: None,
                requested_at: future_rfc3339,
                ..Default::default()
            },
        )
        .expect("write swap request");
        assert!(
            !swap_request_pending(dir.path()),
            "a request stamped an hour in the future must be discarded as \
             stale, not acted on and not treated as perpetually pending"
        );
    }

    #[test]
    fn swap_request_pending_true_within_clock_skew_tolerance() {
        let dir = tmp_handle_dir();
        // 1s ahead of `now` is well within `CLOCK_SKEW_TOLERANCE_SECS` (2s)
        // — genuine intra-host clock skew, not a corrupt/malicious stamp.
        let slightly_future = std::time::SystemTime::now() + std::time::Duration::from_secs(1);
        let rfc3339 = chrono::DateTime::<chrono::Utc>::from(slightly_future)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        write_swap_request(
            dir.path(),
            &SwapRequest {
                target_slot: 2,
                thread_id: None,
                requested_at: rfc3339,
                ..Default::default()
            },
        )
        .expect("write swap request");
        assert!(
            swap_request_pending(dir.path()),
            "a request only 1s ahead of `now` (within clock-skew tolerance) \
             must still be treated as pending, not discarded"
        );
    }

    #[test]
    fn swap_request_pending_false_for_unparseable_timestamp() {
        let dir = tmp_handle_dir();
        write_swap_request(
            dir.path(),
            &SwapRequest {
                target_slot: 2,
                thread_id: None,
                requested_at: "not-a-timestamp".to_string(),
                ..Default::default()
            },
        )
        .expect("write swap request");
        assert!(
            !swap_request_pending(dir.path()),
            "an unparseable requested_at must fail toward stale (unblock), not toward pending forever"
        );
    }

    // ── FM-14: an unavailable start time refuses supervision, not a broken
    //    record ──────────────────────────────────────────────────────────────

    #[test]
    fn write_supervisor_record_with_errs_on_missing_start_time() {
        let dir = tmp_handle_dir();
        let result = write_supervisor_record_with(dir.path(), 4242, None);
        assert!(
            result.is_err(),
            "an undeterminable start time must refuse to write a record, not \
             write a permanently-unverifiable one"
        );
        assert!(
            !dir.path().join(SUPERVISOR_FILE).exists(),
            "no record file must be left behind when start time is unavailable"
        );
    }

    #[test]
    fn write_supervisor_record_with_succeeds_with_a_start_time() {
        let dir = tmp_handle_dir();
        let result =
            write_supervisor_record_with(dir.path(), 4242, Some("Thu Jan  1 00:00:00 1970".into()));
        assert!(result.is_ok(), "{result:?}");
        assert!(dir.path().join(SUPERVISOR_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn signal_supervisor_delivers_to_a_real_child() {
        // A child that ignores SIGUSR1 via a trap, then exits 0 once
        // signalled — proves delivery rather than merely that `kill`
        // returned success against a PID.
        let mut child = Command::new("sh")
            .args(["-c", "trap 'exit 0' USR1; while true; do sleep 0.05; done"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn signal-trapping child");
        let pid = child.id();
        // Give the shell a moment to install the trap before signalling.
        std::thread::sleep(std::time::Duration::from_millis(150));
        signal_supervisor(pid, libc::SIGUSR1).expect("send SIGUSR1");
        let status = child.wait().expect("wait for child");
        assert!(
            status.success(),
            "child must exit 0 via its USR1 trap, proving the signal was delivered: {status:?}"
        );
    }

    // ── F1 (round 5): the verdict protocol ───────────────────────────────

    #[test]
    fn swap_verdict_round_trips_accepted() {
        let dir = tmp_handle_dir();
        let verdict = SwapVerdict {
            nonce: "2026-09-26T00:00:00Z".to_string(),
            outcome: SwapOutcome::Accepted,
        };
        write_swap_verdict(dir.path(), &verdict).expect("write verdict");
        let taken = take_swap_verdict(dir.path(), "2026-09-26T00:00:00Z").expect("take verdict");
        assert_eq!(taken, verdict);
        assert!(
            !dir.path().join(SWAP_VERDICT_FILE).exists(),
            "a verdict matching the expected request id must be consumed (removed)"
        );
    }

    #[test]
    fn swap_verdict_round_trips_refused_with_reason() {
        let dir = tmp_handle_dir();
        let verdict = SwapVerdict {
            nonce: "2026-09-26T00:00:01Z".to_string(),
            outcome: SwapOutcome::Refused("account 9 has no codex credentials".to_string()),
        };
        write_swap_verdict(dir.path(), &verdict).expect("write verdict");
        let taken = take_swap_verdict(dir.path(), "2026-09-26T00:00:01Z").expect("take verdict");
        assert_eq!(taken, verdict);
    }

    /// A verdict present for a DIFFERENT request id (a stale write from an
    /// earlier, already-resolved request) must be IGNORED — never read as
    /// the answer to a fresh request that happens to be waiting at the same
    /// time. This is the RED this test proves: before `take_swap_verdict`
    /// checked `nonce`, ANY well-formed verdict file would have been
    /// handed back regardless of which request it belonged to.
    #[test]
    fn take_swap_verdict_ignores_a_verdict_for_a_different_nonce() {
        let dir = tmp_handle_dir();
        write_swap_verdict(
            dir.path(),
            &SwapVerdict {
                nonce: "2026-09-26T00:00:00Z".to_string(),
                outcome: SwapOutcome::Accepted,
            },
        )
        .expect("write verdict");
        assert!(
            take_swap_verdict(dir.path(), "2026-09-26T00:00:05Z").is_none(),
            "a verdict bound to an unrelated request id must not be handed back"
        );
        assert!(
            dir.path().join(SWAP_VERDICT_FILE).exists(),
            "an ignored (nonce-mismatched) verdict must be left on disk, not \
             consumed — it may still be the live answer for whichever \
             request actually owns it"
        );
    }

    #[test]
    fn wait_for_swap_verdict_returns_none_on_timeout_with_nothing_written() {
        let dir = tmp_handle_dir();
        let start = std::time::Instant::now();
        let result = wait_for_swap_verdict(
            dir.path(),
            "2026-09-26T00:00:00Z",
            std::time::Duration::from_millis(120),
        );
        assert!(
            result.is_none(),
            "no verdict was ever written — this must be the timeout outcome, \
             never a guessed accept/refuse"
        );
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(120),
            "must actually wait out the bound, not return immediately"
        );
    }

    /// The genuinely discriminating case: a verdict written by a SEPARATE
    /// thread partway through the wait must be observed before the bound
    /// elapses — proving `wait_for_swap_verdict` polls rather than checking
    /// once and giving up.
    #[test]
    fn wait_for_swap_verdict_observes_a_verdict_written_mid_wait() {
        let dir = tmp_handle_dir();
        let dir_path = dir.path().to_path_buf();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            write_swap_verdict(
                &dir_path,
                &SwapVerdict {
                    nonce: "2026-09-26T00:00:02Z".to_string(),
                    outcome: SwapOutcome::Accepted,
                },
            )
            .expect("write verdict from writer thread");
        });
        let result = wait_for_swap_verdict(
            dir.path(),
            "2026-09-26T00:00:02Z",
            std::time::Duration::from_secs(5),
        );
        writer.join().expect("writer thread");
        assert_eq!(
            result,
            Some(SwapVerdict {
                nonce: "2026-09-26T00:00:02Z".to_string(),
                outcome: SwapOutcome::Accepted,
            }),
            "must observe the verdict once the writer thread produces it, \
             well inside the 5s bound"
        );
    }

    // ── round 6, item 1: wait for the verdict to be CONSUMED before the
    //    caller tears anything down ──────────────────────────────────────

    #[test]
    fn wait_for_verdict_consumed_returns_true_once_a_separate_thread_takes_it() {
        let dir = tmp_handle_dir();
        write_swap_verdict(
            dir.path(),
            &SwapVerdict {
                nonce: "2026-09-26T00:00:03Z".to_string(),
                outcome: SwapOutcome::Accepted,
            },
        )
        .expect("write verdict");
        let dir_path = dir.path().to_path_buf();
        let taker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            take_swap_verdict(&dir_path, "2026-09-26T00:00:03Z")
                .expect("taker thread must observe the verdict")
        });
        let consumed = wait_for_verdict_consumed(dir.path(), std::time::Duration::from_millis(500));
        taker.join().expect("taker thread");
        assert!(
            consumed,
            "must report consumption once a separate thread's take_swap_verdict \
             removes the file, well inside the 500ms bound"
        );
    }

    #[test]
    fn wait_for_verdict_consumed_returns_false_on_timeout_if_never_taken() {
        let dir = tmp_handle_dir();
        write_swap_verdict(
            dir.path(),
            &SwapVerdict {
                nonce: "2026-09-26T00:00:04Z".to_string(),
                outcome: SwapOutcome::Accepted,
            },
        )
        .expect("write verdict");
        let start = std::time::Instant::now();
        let consumed = wait_for_verdict_consumed(dir.path(), std::time::Duration::from_millis(120));
        assert!(
            !consumed,
            "nothing ever consumed the verdict — this must be the bound-elapsed \
             outcome, never a false 'consumed'"
        );
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(120),
            "must actually wait out the bound, not return immediately"
        );
        assert!(
            dir.path().join(SWAP_VERDICT_FILE).exists(),
            "an unconsumed verdict must be left on disk — this function never \
             removes it itself"
        );
    }

    // ── C-F6: nonce presence/shape gates the whole request ──────────────

    #[test]
    fn take_swap_request_rejects_empty_nonce() {
        let dir = tmp_handle_dir();
        // Hand-write the on-disk shape with an empty nonce line — the same
        // "corrupt == no request" posture as the non-UUID-thread_id case.
        std::fs::write(
            dir.path().join(SWAP_REQUEST_FILE),
            "9\n\n2026-09-26T00:00:00Z\n\n\n\n0\n",
        )
        .unwrap();
        assert!(
            take_swap_request(dir.path()).is_none(),
            "an empty nonce must invalidate the whole request"
        );
    }

    #[test]
    fn take_swap_request_rejects_non_hex_nonce() {
        let dir = tmp_handle_dir();
        std::fs::write(
            dir.path().join(SWAP_REQUEST_FILE),
            "9\n\n2026-09-26T00:00:00Z\nnot-hex-at-all!!\n\n\n0\n",
        )
        .unwrap();
        assert!(
            take_swap_request(dir.path()).is_none(),
            "a non-hex nonce must invalidate the whole request"
        );
    }

    /// D-F item (round 7): a nonce that IS all-hex but the wrong length
    /// (short of the 32 chars [`gen_swap_nonce`] always produces) must
    /// still invalidate the whole request — the prior check only asked "is
    /// this hex", never "is this exactly the shape a real writer produces".
    #[test]
    fn take_swap_request_rejects_short_hex_nonce() {
        let dir = tmp_handle_dir();
        std::fs::write(
            dir.path().join(SWAP_REQUEST_FILE),
            "9\n\n2026-09-26T00:00:00Z\nabcd\n\n\n0\n",
        )
        .unwrap();
        assert!(
            take_swap_request(dir.path()).is_none(),
            "a short (non-32-char) hex nonce must invalidate the whole request"
        );
    }

    /// D-F item (round 7): uppercase hex is rejected — [`gen_swap_nonce`]
    /// only ever emits lowercase, so an uppercase nonce is never one this
    /// process wrote and must not be trusted as a genuine identity.
    #[test]
    fn take_swap_request_rejects_uppercase_hex_nonce() {
        let dir = tmp_handle_dir();
        let uppercase_nonce = "A".repeat(32);
        std::fs::write(
            dir.path().join(SWAP_REQUEST_FILE),
            format!("9\n\n2026-09-26T00:00:00Z\n{uppercase_nonce}\n\n\n0\n"),
        )
        .unwrap();
        assert!(
            take_swap_request(dir.path()).is_none(),
            "an uppercase-hex nonce must invalidate the whole request"
        );
    }

    /// The counterpart: a genuine 32-lowercase-hex nonce (the exact shape
    /// [`gen_swap_nonce`] produces) round-trips normally — proving the
    /// tightened check does not merely reject everything.
    #[test]
    fn take_swap_request_accepts_genuine_32_char_lowercase_hex_nonce() {
        let dir = tmp_handle_dir();
        let nonce = gen_swap_nonce();
        assert_eq!(nonce.len(), 32);
        std::fs::write(
            dir.path().join(SWAP_REQUEST_FILE),
            format!("9\n\n2026-09-26T00:00:00Z\n{nonce}\n\n\n0\n"),
        )
        .unwrap();
        let taken = take_swap_request(dir.path()).expect("a well-shaped nonce must round-trip");
        assert_eq!(taken.nonce, nonce);
    }

    // ── PRIMARY DIRECTIVE (round 6): SwapAuditCorrelation ────────────────

    #[test]
    fn swap_audit_correlation_none_when_correlation_id_empty() {
        let req = SwapRequest {
            target_slot: 5,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            ..Default::default()
        };
        assert!(
            SwapAuditCorrelation::from_request(&req).is_none(),
            "a request with no recorded INTENT (empty correlation_id) must \
             not entitle the supervisor to write a correlated OUTCOME"
        );
    }

    #[test]
    fn swap_audit_correlation_some_when_correlation_id_present() {
        let req = SwapRequest {
            target_slot: 5,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            chain_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            correlation_id: "01ARZ3NDEKTSV4RRFFQ69G5FAW".to_string(),
            from_slot: 2,
            ..Default::default()
        };
        assert!(SwapAuditCorrelation::from_request(&req).is_some());
    }

    /// The correlated OUTCOME actually lands on the chain, paired with the
    /// INTENT `csq swap` would have written — and a SECOND call for the
    /// SAME [`SwapAuditCorrelation`] is a silent no-op, never a second
    /// chain record (the double-write guard this struct exists for).
    #[test]
    fn swap_audit_correlation_write_outcome_once_pairs_with_intent_and_is_idempotent() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let chain_id = crate::audit::op_emit::load_chain_id(base);
        let correlation_id = crate::audit::op_emit::gen_correlation_id().expect("correlation_id");
        let from_slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let to_slot = crate::types::AccountNum::try_from(2u16).unwrap();
        let nonce = gen_swap_nonce();
        let payload = crate::audit::EventPayload::AccountSwap(crate::audit::AccountSwapPayload {
            from_slot,
            to_slot,
        });
        crate::audit::op_emit::emit_intent(
            base,
            &chain_id,
            crate::audit::EventKind::AccountSwap,
            payload,
            correlation_id.clone(),
        )
        .expect("intent write must succeed");

        let req = SwapRequest {
            target_slot: 2,
            thread_id: None,
            requested_at: rfc3339_seconds_ago(0),
            chain_id: chain_id.clone(),
            correlation_id: correlation_id.as_str().to_string(),
            from_slot: 1,
            nonce,
        };
        let corr = SwapAuditCorrelation::from_request(&req).expect("correlation present");

        corr.write_outcome_once(base, OpOutcome::Ok);
        let orphans_after_first =
            crate::audit::scan_orphan_intents(base).expect("scan must succeed");
        assert!(
            orphans_after_first.is_empty(),
            "the intent must be paired by the outcome write — no orphan left: {orphans_after_first:?}"
        );

        let result = crate::audit::verify::verify_chain(
            base,
            &crate::audit::verify::VerifyConfig::default(),
            None,
        )
        .expect("chain must verify");
        let count_after_first = result.verified_count;

        // Second call: a DIFFERENT outcome, to make a double-write
        // unmistakable if the guard fails.
        corr.write_outcome_once(
            base,
            OpOutcome::Failed {
                reason: crate::audit::RedactedString::from_trusted("should never be written"),
            },
        );
        let result2 = crate::audit::verify::verify_chain(
            base,
            &crate::audit::verify::VerifyConfig::default(),
            None,
        )
        .expect("chain must still verify");
        assert_eq!(
            result2.verified_count, count_after_first,
            "a second write_outcome_once call must be a silent no-op — no \
             second OUTCOME record for the same correlation_id"
        );
    }

    /// D-F4/S-LOW-6: a FAILED write attempt (here: an invalid `from_slot`
    /// that never even reaches `emit_outcome`) must NOT poison `written` —
    /// a later, genuinely correct call for the SAME correlation MUST still
    /// be allowed to write. Before this fix, `written` was set on ENTRY
    /// (before any fallible step), so this exact sequence would have left
    /// the intent orphaned FOREVER: the first (failed) call marked it
    /// "written" and the second (valid) call silently no-op'd.
    #[test]
    fn write_outcome_once_does_not_poison_a_retry_after_a_failed_attempt() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let chain_id = crate::audit::op_emit::load_chain_id(base);
        let correlation_id = crate::audit::op_emit::gen_correlation_id().expect("correlation_id");
        let from_slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let to_slot = crate::types::AccountNum::try_from(2u16).unwrap();
        let payload = crate::audit::EventPayload::AccountSwap(crate::audit::AccountSwapPayload {
            from_slot,
            to_slot,
        });
        crate::audit::op_emit::emit_intent(
            base,
            &chain_id,
            crate::audit::EventKind::AccountSwap,
            payload,
            correlation_id.clone(),
        )
        .expect("intent write must succeed");

        // Constructed directly (same module, private fields accessible from
        // `mod tests`) with an INVALID `from_slot: 0` — `AccountNum::try_from`
        // rejects it, so `write_outcome_once` must return WITHOUT writing
        // anything and WITHOUT poisoning `written`.
        let written = std::rc::Rc::new(std::cell::Cell::new(false));
        let broken_corr = SwapAuditCorrelation {
            chain_id: chain_id.clone(),
            correlation_id: correlation_id.as_str().to_string(),
            from_slot: 0,
            to_slot: 2,
            written: written.clone(),
        };
        broken_corr.write_outcome_once(base, OpOutcome::Ok);
        let orphans_after_failed_attempt =
            crate::audit::scan_orphan_intents(base).expect("scan must succeed");
        assert_eq!(
            orphans_after_failed_attempt.len(),
            1,
            "the failed attempt must not have written anything — the intent \
             is still orphaned: {orphans_after_failed_attempt:?}"
        );

        // A second correlation sharing the SAME `written` cell, with the
        // slot fixed — this must succeed. If the first (failed) attempt had
        // poisoned `written`, this would silently no-op and the assertion
        // below would fail.
        let fixed_corr = SwapAuditCorrelation {
            chain_id,
            correlation_id: correlation_id.as_str().to_string(),
            from_slot: 1,
            to_slot: 2,
            written,
        };
        fixed_corr.write_outcome_once(base, OpOutcome::Ok);
        let orphans_after_retry =
            crate::audit::scan_orphan_intents(base).expect("scan must succeed");
        assert!(
            orphans_after_retry.is_empty(),
            "the retry (with a valid slot) must be allowed to write and \
             resolve the intent: {orphans_after_retry:?}"
        );
    }

    /// S-LOW-B / C-N2 (round 8b): two INDEPENDENT writers (simulating two
    /// separate supervisor processes — each builds its own
    /// `SwapAuditCorrelation` with its own `written` cell, entirely inside
    /// its own thread, so no in-process no-op guard is shared) racing
    /// `write_outcome_once` for the SAME `correlation_id` must produce
    /// EXACTLY ONE `AccountSwap` OUTCOME record.
    ///
    /// Before this fix, the "exactly one OUTCOME per (correlation_id, kind)"
    /// authorization check (`verify_swap_correlation`) ran OUTSIDE
    /// `.chain-lock`: both writers could read "no OUTCOME yet" before either
    /// appended, and both would then append — two OUTCOME records for one
    /// INTENT, breaking the 1:1 pairing `scan_orphan_intents` relies on. The
    /// fix moves the identical scan (`verify_swap_correlation_in_file`)
    /// INSIDE the lock via `emit_outcome_with_precheck`'s `precheck`
    /// closure, so the second writer to acquire `.chain-lock` observes the
    /// first's just-appended OUTCOME and is refused with `Ok(false)`
    /// (`PrecheckRefused`) rather than appending a duplicate.
    #[test]
    fn concurrent_writers_for_one_correlation_produce_exactly_one_outcome() {
        let _env_guard = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().to_path_buf();

        let chain_id = crate::audit::op_emit::load_chain_id(&base);
        let correlation_id = crate::audit::op_emit::gen_correlation_id().expect("correlation_id");
        let from_slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let to_slot = crate::types::AccountNum::try_from(2u16).unwrap();
        let payload = crate::audit::EventPayload::AccountSwap(crate::audit::AccountSwapPayload {
            from_slot,
            to_slot,
        });
        crate::audit::op_emit::emit_intent(
            &base,
            &chain_id,
            crate::audit::EventKind::AccountSwap,
            payload,
            correlation_id.clone(),
        )
        .expect("intent write must succeed");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let base_a = base.clone();
        let chain_id_a = chain_id.clone();
        let corr_id_a = correlation_id.as_str().to_string();
        let barrier_a = barrier.clone();
        let ta = std::thread::spawn(move || {
            // `SwapAuditCorrelation` carries an `Rc` (deliberately `!Send` —
            // see its `written` field doc), so it is constructed ENTIRELY
            // inside this thread rather than moved across the spawn
            // boundary — it never crosses a thread, only its inputs
            // (`String`/`u16`, all `Send`) do.
            let corr = SwapAuditCorrelation {
                chain_id: chain_id_a,
                correlation_id: corr_id_a,
                from_slot: 1,
                to_slot: 2,
                written: std::rc::Rc::new(std::cell::Cell::new(false)),
            };
            barrier_a.wait();
            corr.write_outcome_once(&base_a, OpOutcome::Ok);
        });

        let base_b = base.clone();
        let chain_id_b = chain_id.clone();
        let corr_id_b = correlation_id.as_str().to_string();
        let barrier_b = barrier;
        let tb = std::thread::spawn(move || {
            let corr = SwapAuditCorrelation {
                chain_id: chain_id_b,
                correlation_id: corr_id_b,
                from_slot: 1,
                to_slot: 2,
                written: std::rc::Rc::new(std::cell::Cell::new(false)),
            };
            barrier_b.wait();
            corr.write_outcome_once(&base_b, OpOutcome::Ok);
        });

        ta.join().expect("writer A thread must not panic");
        tb.join().expect("writer B thread must not panic");

        // Count OUTCOME records for this correlation_id DIRECTLY — a bare
        // `scan_orphan_intents` empty result only proves >=1 OUTCOME exists,
        // not exactly 1 (a duplicate would ALSO leave zero orphans).
        //
        // `chain_id` above was loaded BEFORE `emit_intent`'s first write, so
        // on a fresh tempdir it is the empty-string sentinel (no `chain.json`
        // yet) — the genesis write during `emit_intent` mints the REAL
        // chain_id and names the JSONL file after it. Re-load here, now that
        // `chain.json` exists, to get the filename the writes actually used.
        let genesis_chain_id = crate::audit::op_emit::load_chain_id(&base);
        let chain_jsonl = base
            .join("csq-runs")
            .join(format!("{genesis_chain_id}.jsonl"));
        let content = std::fs::read_to_string(&chain_jsonl).unwrap();
        let outcome_count = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<crate::audit::types::SignedRecord>(l).ok())
            .filter(|r| {
                r.kind == crate::audit::EventKind::AccountSwap
                    && matches!(
                        &r.op_phase,
                        Some(crate::audit::types::OpPhase::Outcome { correlation_id: c, .. })
                            if c.as_str() == correlation_id.as_str()
                    )
            })
            .count();
        assert_eq!(
            outcome_count, 1,
            "exactly one OUTCOME record must land for this correlation_id \
             even under two concurrent writers; got {outcome_count}"
        );
    }
}
