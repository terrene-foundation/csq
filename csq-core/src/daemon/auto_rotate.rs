//! Background auto-rotation loop — handle-dir-native (PR-A1, v2.0.1).
//!
//! Scans all `accounts/term-<pid>` handle dirs every 30 seconds and
//! repoints the active account whenever the current account's 5-hour
//! quota exceeds the configured threshold.
//!
//! # PR-A1 structural fix (an internal journal entry, Option A); M4-8 retirement
//!
//! v2.0.0 shipped `rotation::swap::swap_to(base_dir, config_dir, target)`
//! which writes target account M's `.credentials.json` INTO `config-N/`.
//! Under the handle-dir model (spec 02, INV-01),
//! `config-<N>/.credentials.json` is PERMANENT account-N credentials —
//! overwriting it corrupts identity for every terminal whose
//! `term-<pid>/` symlinks back through that config-N. PR-A1 replaced
//! that guard (which refused to run when any `term-*/` exists) with the
//! structural fix: walk `term-<pid>/` handle dirs and call
//! `handle_dir::repoint_handle_dir`, which atomically repoints symlinks
//! WITHOUT touching `config-<N>/`. M4-8 (Phase 4, an internal ticket) deletes
//! the `rotation::swap::swap_to` writer entirely so the legacy path
//! cannot resurface from any code site.
//!
//! # Cooldown map
//!
//! The cooldown is keyed on the *handle-dir path* (not the account
//! number and not the config dir) so each terminal session has an
//! independent cooldown. This prevents one busy session from blocking
//! rotation of other sessions.
//!
//! # claude_home requirement
//!
//! `repoint_handle_dir` must re-materialize `settings.json` after the
//! repoint (it deep-merges `~/.claude/settings.json` with the new
//! slot's overlay). If `claude_home` cannot be resolved at spawn time,
//! the rotator logs a WARN and becomes a no-op — fail-safe is "don't
//! rotate" rather than "rotate with an empty settings base".
//!
//! # Shutdown
//!
//! The loop respects the shared `CancellationToken` so it exits within
//! one tick interval after `shutdown.cancel()`.

use crate::accounts::identity_store::IdentityId;
use crate::accounts::markers;
use crate::accounts::AccountSource;
use crate::providers::catalog::Surface;
use crate::quota::state as quota_state;
use crate::rotation::config as rotation_config;
use crate::session::handle_dir::repoint_handle_dir;
use crate::types::AccountNum;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Tick interval: 30 seconds.
pub const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Startup delay: 15 seconds. Lets the usage poller run its first tick
/// and populate `quota.json` before we attempt any rotation decision.
pub const STARTUP_DELAY: Duration = Duration::from_secs(15);

/// S-H-A/D-F1: the retry cooldown applied when a repoint SUCCEEDS but
/// `reconcile_keychain_to_marker` reports the keychain did NOT end up
/// agreeing with the marker (`WriteFailed`/`KeychainUnknown`/
/// `MarkerUnreadable`) — deliberately SHORTER than the configured
/// `cooldown_secs` (a successful repoint's own cooldown), because the
/// symlink switch already landed; only the keychain mirror is in doubt,
/// and that is worth retrying sooner than a full rotation cycle.
const RECONCILE_DESYNC_RETRY_COOLDOWN: Duration = Duration::from_secs(30);

/// S-H-A/D-F1 decision seam: whether a [`crate::credentials::keychain::ReconcileOutcome`]
/// confirms the keychain genuinely followed a successful repoint — factored
/// out as a PURE function of the outcome so it is directly unit-testable
/// with a synthetic `ReconcileOutcome`, no `security` subprocess, no lock,
/// no tick harness. Only `AlreadyCurrent`/`Reconciled` confirm it;
/// `MarkerUnreadable`/`WriteFailed`/`KeychainUnknown` do not.
fn reconcile_outcome_confirms_rotation(
    outcome: &crate::credentials::keychain::ReconcileOutcome,
) -> bool {
    matches!(
        outcome,
        crate::credentials::keychain::ReconcileOutcome::AlreadyCurrent { .. }
            | crate::credentials::keychain::ReconcileOutcome::Reconciled { .. }
    )
}

/// K3/C-F8 (`keychain-fix-r8.md`) decision seam: the operator-facing tail of
/// the WARN emitted when `repoint_handle_dir` returns `Err`, factored out as
/// a PURE function of its three inputs so it is directly unit-testable with
/// synthetic values — no `security` subprocess, no lock, no tick harness.
/// Precedence, highest first:
///
/// 1. `refused_item` (`Some`) — the S7 pre-flight refusal fires BEFORE any
///    symlink mutation, so it gets its own message naming the blocked item,
///    folding the reconcile outcome in (D-F2) rather than reporting the
///    blocked item alone.
/// 2. `mixed_links` (`true`, `refused_item` `None`) — the handle dir's OWN
///    symlinks were ALSO left mixed across two accounts by a
///    partially-rolled-back repoint. C-F8: the prior version REPLACED
///    `reconcile_line` with the mixed-links line, silently discarding
///    whatever `reconcile_outcome` itself said (a `WriteFailed`/
///    `KeychainUnknown` detail is lost, and the operator sees only "links
///    are mixed" with no explanation of the keychain's own disagreement).
///    Two independently-checked things — fold both in, mirroring `csq
///    swap`'s own C-F8 fix (`csq/src/cli/commands/swap.rs`) so the two
///    operator-facing vocabularies never drift apart again.
/// 3. Neither — the reconcile line alone.
fn repoint_failure_operator_line(
    refused_item: Option<&str>,
    mixed_links: bool,
    reconcile_outcome: &crate::credentials::keychain::ReconcileOutcome,
    reconcile_line: String,
) -> String {
    if let Some(item) = refused_item {
        crate::credentials::keychain::repoint_refused_real_file_operator_line(item, &reconcile_line)
    } else if mixed_links {
        match reconcile_outcome.marker_account() {
            Some(m) => format!(
                "{} {reconcile_line}",
                crate::credentials::keychain::mixed_links_operator_line(m)
            ),
            None => reconcile_line,
        }
    } else {
        reconcile_line
    }
}

/// Handle to a running auto-rotation task.
pub struct AutoRotateHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns the auto-rotation background task on the current tokio runtime.
///
/// `claude_home` is `Option<PathBuf>` so callers that cannot resolve
/// `~/.claude` (rare sandbox / missing $HOME) can pass `None`. The
/// rotator logs a single WARN at spawn time and becomes a no-op for
/// every tick — fail-safe is "don't rotate" rather than "rotate with
/// an empty base settings file that would overwrite user customization".
pub fn spawn(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
) -> AutoRotateHandle {
    spawn_with_config(
        base_dir,
        claude_home,
        shutdown,
        TICK_INTERVAL,
        STARTUP_DELAY,
    )
}

/// round 7c D4: the SAME validation transport the refresher's custodian
/// harvest uses (`refresher.rs`'s own `http_get` construction) — built once
/// here so `spawn`/`spawn_with_config` need no new public parameter (every
/// existing caller keeps its 3-arg call site).
fn default_http_get() -> crate::daemon::usage_poller::HttpGetFn {
    std::sync::Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
        crate::http::get_bearer_node(url, token, headers)
    })
}

/// C-F6 (`keychain-fix-r8.md`): injectable seam for the opportunistic
/// per-handle-dir custodian harvest (`custodian::reconcile_account`),
/// mirroring the same [`HttpGetFn`]-style Transport Injection Pattern this
/// module already uses for `http_get` (see the daemon-architecture skill's
/// "Transport Injection Pattern" table). `reconcile_account` itself does a
/// live keychain `security` subprocess read plus (when a candidate exists) a
/// live validation HTTP call — neither of which a hermetic test may exercise
/// (COMMON.md hard limits). Injecting the call itself, not just its HTTP
/// transport, is what makes the RateLimited short-circuit in
/// [`tick_with_deps`] directly testable: a test can script a `RateLimited`
/// return on the first handle dir and assert the closure is never invoked
/// again for the second.
///
/// [`HttpGetFn`]: crate::daemon::usage_poller::HttpGetFn
type ReconcileAccountFn = std::sync::Arc<
    dyn Fn(
            &Path,
            AccountNum,
            &str,
            &crate::daemon::usage_poller::HttpGetFn,
        ) -> crate::daemon::custodian::ReconcileOutcome
        + Send
        + Sync,
>;

/// Production implementation of [`ReconcileAccountFn`]: calls the real
/// custodian.
fn default_reconcile_account() -> ReconcileAccountFn {
    std::sync::Arc::new(crate::daemon::custodian::reconcile_account)
}

/// Like [`spawn`] but with explicit intervals for testing.
pub fn spawn_with_config(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) -> AutoRotateHandle {
    if claude_home.is_none() {
        warn!(
            "auto-rotation: claude_home is None — rotator will be a no-op. \
             Cannot repoint handle dirs without a known ~/.claude path \
             (materialize_handle_settings requires it). Check that $HOME is set."
        );
    }

    let cooldowns: HashMap<PathBuf, Instant> = HashMap::new();
    let http_get = default_http_get();

    let join = tokio::spawn(async move {
        run_loop(
            base_dir,
            claude_home,
            shutdown,
            interval,
            startup_delay,
            cooldowns,
            http_get,
        )
        .await;
    });

    AutoRotateHandle { join }
}

async fn run_loop(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
    mut cooldowns: HashMap<PathBuf, Instant>,
    http_get: crate::daemon::usage_poller::HttpGetFn,
) {
    info!(
        interval_secs = interval.as_secs(),
        startup_delay_secs = startup_delay.as_secs(),
        "auto-rotation loop starting"
    );

    tokio::select! {
        _ = shutdown.cancelled() => {
            info!("auto-rotation cancelled during startup delay");
            return;
        }
        _ = tokio::time::sleep(startup_delay) => {}
    }

    loop {
        // C-F6 (`keychain-fix-r8.md`): `tick_with_http` performs synchronous
        // I/O throughout — disk reads via `quota_state`, and (through
        // `custodian::reconcile_account`, invoked below) a keychain
        // `security` subprocess read plus a node-subprocess HTTPS validation
        // call, mirroring the blocking work `refresher.rs` dispatches with
        // its own `tokio::task::spawn_blocking` around the SAME
        // `custodian::reconcile_account` call (csq-core/src/daemon/refresher.rs,
        // ~line 996). `tick_with_http` stays a plain fn (not `async`) so the
        // unit tests below keep calling it directly with no tokio runtime;
        // this production loop is the sole caller that owns a runtime and
        // must not let that synchronous work — up to the bounded ~20s
        // per-handle-dir keychain lock this function can also take — occupy
        // one of its worker threads. `cooldowns` is moved into the blocking
        // closure and handed back out; a clone taken just before the move is
        // the fallback if the closure panics, so a single bad tick cannot
        // wipe every handle dir's cooldown state.
        let base_dir_for_tick = base_dir.clone();
        let claude_home_for_tick = claude_home.clone();
        let http_get_for_tick = http_get.clone();
        let cooldowns_before_tick = cooldowns.clone();
        cooldowns = match tokio::task::spawn_blocking(move || {
            tick_with_http(
                &base_dir_for_tick,
                claude_home_for_tick.as_deref(),
                &mut cooldowns,
                &http_get_for_tick,
            );
            cooldowns
        })
        .await
        {
            Ok(c) => c,
            Err(join_err) => {
                warn!(
                    error_kind = "auto_rotate_tick_panicked",
                    panicked = join_err.is_panic(),
                    "auto-rotation tick task panicked (non-fatal); cooldown state for this cycle is unchanged"
                );
                cooldowns_before_tick
            }
        };

        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("auto-rotation cancelled, exiting loop");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// Same-surface filter for auto-rotation candidates (INV-P11).
///
/// Auto-rotation must NEVER cross surfaces — a handle-dir bound to a
/// `Surface::ClaudeCode` account cannot be silently rotated to a
/// `Surface::Codex` account because the two surfaces execute different
/// CLI binaries with different `HOME`-like env contracts. Cross-surface
/// rotation is explicitly a `csq swap` action (an internal journal entry H3; spec 07
/// INV-P11).
///
/// PR-C1 flip: pre-C1 this function trivially accepted every candidate
/// (all providers were `Surface::ClaudeCode`). Now that `Surface::Codex`
/// is a reachable variant via the catalog stub, this function enforces
/// the invariant against a concrete surface comparison.
fn same_surface_as_active(active_surface: Surface, candidate_surface: Surface) -> bool {
    active_surface == candidate_surface
}

/// Returns `true` if the account currently bound to `handle_dir` is a 3P slot.
///
/// Belt-and-suspenders guard (VP-final F1): reads `config-<account>/settings.json`
/// for the handle dir's current account and returns `true` if `env.ANTHROPIC_BASE_URL`
/// is present. If the current account is a 3P slot, the rotator MUST NOT rotate: doing
/// so would repoint the handle dir's symlinks such that CC picks up Anthropic OAuth
/// tokens AND the 3P `env.ANTHROPIC_BASE_URL` from `config-<N>/settings.json` —
/// sending Anthropic OAuth tokens to a 3P endpoint (live token exfiltration).
///
/// Returns `false` on any I/O or parse error (fail-safe: a missing or unparseable
/// settings.json means no 3P binding — allow the rotation check to proceed).
fn handle_dir_is_3p(base_dir: &Path, current_account: AccountNum) -> bool {
    // Single source of truth for the env-transport discriminator: shared with
    // `cli::commands::swap`'s routing guard so the daemon rotator and the manual
    // `csq swap` path never disagree on which slots are in-flight-repoint-unsafe.
    crate::providers::settings::slot_pins_anthropic_base_url(base_dir, current_account.get())
}

/// Admit only existing term directories strictly beneath the canonical base.
/// Canonicalization failure has no raw-path fallback: admission precedes marker
/// reads, cooldown lookup and every rebind/keychain operation. This is a path
/// check, not an open-directory-handle guarantee against concurrent replacement.
fn contained_handle_dir(canonical_base: &Path, candidate: &Path) -> Option<PathBuf> {
    let handle = candidate.canonicalize().ok()?;
    if handle == canonical_base || !handle.starts_with(canonical_base) {
        return None;
    }
    if !handle.is_dir() || !handle.file_name()?.to_str()?.starts_with("term-") {
        return None;
    }
    Some(handle)
}

// T1: cfg(test) seam signalled right after `tick`'s PRE-LOCK decision
// (current account resolved, 3P-checked, cooldown-checked, threshold
// cleared, rotation target found) and immediately before the bounded
// per-handle-dir lock is attempted. Replaces sleep-based timing in the
// S-M2/H2 lock-wait tests: instead of a background thread sleeping a
// fixed duration and HOPING `tick` has not yet reached the lock attempt,
// a test registers a closure here that performs the concurrent mutation
// (or signals a thread already holding the lock to do so) DETERMINISTICALLY
// at the exact point in `tick`'s control flow the S-M2/H2 re-check exists
// to guard against — no timing assumption, no flakiness window.
//
// Thread-local (not a global `Mutex`) because the hook is set and consumed
// on the SAME test thread that calls `tick`; `tick` itself is never called
// concurrently with itself in a way that would need cross-thread hook
// storage. Reset to `None` by every test that sets it (mirrors the
// `RepointFaultGuard`-style reset discipline in `session::handle_dir`).
#[cfg(test)]
thread_local! {
    static PRE_LOCK_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

// Only called by the three `#[cfg(target_os = "macos")]` lock-wait tests
// below (the seam matters only for the macOS bounded-lock path this repo
// actually has); `#[allow(dead_code)]` elsewhere rather than gating this
// fn itself on macOS, since a future non-macOS caller would otherwise
// silently regain the seam for free.
#[cfg(test)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn set_pre_lock_test_hook_for_test(hook: Option<Box<dyn FnMut()>>) {
    PRE_LOCK_TEST_HOOK.with(|c| *c.borrow_mut() = hook);
}

#[cfg(test)]
fn run_pre_lock_test_hook() {
    PRE_LOCK_TEST_HOOK.with(|c| {
        if let Some(hook) = c.borrow_mut().as_mut() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_pre_lock_test_hook() {}

/// Runs a single auto-rotation tick.
///
/// Exposed `pub` for both unit tests and integration tests.
///
/// When `claude_home` is `None`, returns immediately (no-op). This is the
/// fail-safe path for environments where $HOME is unavailable — the rotator
/// cannot safely repoint without knowing where `~/.claude/settings.json` lives.
pub fn tick(
    base_dir: &Path,
    claude_home: Option<&Path>,
    cooldowns: &mut HashMap<PathBuf, Instant>,
) {
    tick_with_http(base_dir, claude_home, cooldowns, &default_http_get())
}

/// [`tick`]'s real body — takes the validation transport explicitly (round
/// 7c D4) so [`tick`] itself stays a 3-arg call every existing test/caller
/// keeps using unchanged, while the production loop (`run_loop`) and any
/// test that DOES want to exercise the pre-lock harvest can inject one.
/// Delegates to [`tick_with_deps`] with the real custodian call — see that
/// function's doc for the C-F6 RateLimited short-circuit this split exists
/// to test.
fn tick_with_http(
    base_dir: &Path,
    claude_home: Option<&Path>,
    cooldowns: &mut HashMap<PathBuf, Instant>,
    http_get: &crate::daemon::usage_poller::HttpGetFn,
) {
    tick_with_deps(
        base_dir,
        claude_home,
        cooldowns,
        http_get,
        &default_reconcile_account(),
        &crate::daemon::server::harvest_gate::ip_rate_limit_gate(),
    )
}

/// Test-only seam (C-F6, `keychain-fix-r8.md`): drives a single tick with a
/// SCRIPTED custodian call so the RateLimited short-circuit is directly
/// testable — see [`tick_with_deps`]'s doc. Uses the real (non-mocked)
/// `http_get` transport since a scripted `reconcile_account` never reaches
/// it.
///
/// `keychain-fix-r10.md` S-M-1/C-B2 (item 2), C-B1/S-L-5: takes `gate`
/// explicitly rather than defaulting to the process-wide singleton — a
/// caller passes a fresh
/// [`crate::daemon::server::harvest_gate::new_ip_rate_limit_gate`] to assert
/// this tick's own producer/consumer behaviour without touching state
/// shared with every other test in this binary (`ip_rate_limit_gate`'s doc).
#[cfg(test)]
pub(crate) fn tick_with_reconcile_for_test(
    base_dir: &Path,
    claude_home: Option<&Path>,
    cooldowns: &mut HashMap<PathBuf, Instant>,
    reconcile: &ReconcileAccountFn,
    gate: &crate::daemon::server::harvest_gate::IpRateLimitGate,
) {
    tick_with_deps(
        base_dir,
        claude_home,
        cooldowns,
        &default_http_get(),
        reconcile,
        gate,
    )
}

/// [`tick_with_http`]'s real body — additionally takes the custodian
/// reconcile call as an injectable seam (C-F6) so the per-tick
/// `rate_limited_this_tick` short-circuit below (mirroring `refresher.rs`'s
/// own `rate_limited_this_tick`) is testable without a live keychain or
/// network call: a test scripts the first handle dir's call to return
/// `RateLimited` and asserts the closure is never invoked for any
/// subsequent handle dir in the same tick.
///
/// `keychain-fix-r10.md` S-M-1/C-B2 (item 2), C-B1/S-L-5: `gate` is the SAME
/// shared, IP-wide gate `refresher.rs`'s custodian call and
/// `daemon::server::run_with` share (D-F6) — made an explicit parameter
/// (mirroring `run_with`'s own split) rather than hardwired to the
/// process-wide singleton, so a test can inject a fresh gate and observe
/// this function's read AND write of it in isolation.
fn tick_with_deps(
    base_dir: &Path,
    claude_home: Option<&Path>,
    cooldowns: &mut HashMap<PathBuf, Instant>,
    http_get: &crate::daemon::usage_poller::HttpGetFn,
    reconcile: &ReconcileAccountFn,
    gate: &crate::daemon::server::harvest_gate::IpRateLimitGate,
) {
    // Fail-safe: without claude_home we cannot re-materialize settings.json
    // after repoint. Do not rotate.
    let claude_home = match claude_home {
        Some(p) => p,
        None => {
            debug!("auto-rotation: claude_home is None, skipping tick (no-op)");
            return;
        }
    };

    let canonical_base = match base_dir.canonicalize() {
        Ok(path) if path.is_dir() => path,
        _ => {
            warn!(
                error_kind = "auto_rotate_invalid_base",
                "auto-rotation: base admission failed"
            );
            return;
        }
    };
    let base_dir = canonical_base.as_path();

    // Load config fresh on every tick so changes to rotation.json
    // take effect within one tick interval without restarting the daemon.
    let cfg = match rotation_config::load(base_dir) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "auto-rotation: failed to load rotation config, skipping tick");
            return;
        }
    };

    if !cfg.enabled {
        debug!("auto-rotation disabled, skipping tick");
        return;
    }

    let cooldown_duration = Duration::from_secs(cfg.cooldown_secs);

    // Scan term-* handle dirs under base_dir (PR-A1: walk handle dirs,
    // not config-* dirs). Each term-<pid>/ is a running terminal session;
    // we repoint its symlinks, never touching config-N/.
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "auto-rotation: failed to read base_dir");
            return;
        }
    };

    let mut rotated = 0usize;
    let mut skipped = 0usize;
    // C-F6 (`keychain-fix-r8.md`): mirrors `refresher.rs`'s own
    // `rate_limited_this_tick` — once the custodian's validate call for ANY
    // handle dir this tick comes back 429, Anthropic is rate-limiting this
    // IP, and every remaining handle dir's opportunistic harvest below would
    // just add another throttled request. Set once, never cleared within a
    // tick.
    //
    // D-F6 (`keychain-fix-r9.md`): seeded from the shared, IP-wide gate
    // (`server.rs`'s `harvest_gate` module, via the injected `gate`
    // parameter) rather than starting `false` every tick — a 429 observed
    // moments ago by the refresher's own custodian call or by the on-demand
    // harvest route is honoured immediately here too, instead of this tick
    // re-discovering it the hard way via its own throttled request.
    let mut rate_limited_this_tick =
        crate::daemon::server::harvest_gate::gate_is_rate_limited(gate);

    for entry in entries.flatten() {
        let candidate = entry.path();
        // Preserve the scanned namespace as well as the resolved term-* shape.
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("term-"))
        {
            continue;
        }
        let Some(handle_dir) = contained_handle_dir(base_dir, &candidate) else {
            warn!(
                error_kind = "auto_rotate_invalid_handle",
                "auto-rotation: handle admission failed; skipping before side effects"
            );
            skipped += 1;
            continue;
        };

        // Read which account this handle dir is currently bound to.
        // The symlink `term-<pid>/.csq-account` → `config-<current>/.csq-account`
        // resolves to the current account's canonical marker. M4-7 (an internal ticket
        // Phase 4): the marker's CONTENT is a UUID whenever a `by_slot` mapping
        // exists, so this MUST resolve through `resolve_marker_to_slot` (which
        // accepts both numeric and UUID content) rather than the numeric-only
        // `read_csq_account` — the latter silently returned `None` for every
        // handle dir bound to a modern slot, making the rotator a structural
        // no-op (`guard-reader-writer-parity.md`). Failing closed (skip) on an
        // unresolvable marker is unchanged and correct — an unresolvable marker
        // means we don't know what account this dir is bound to, so we must
        // not act on it.
        let current_account = match markers::resolve_marker_to_slot(base_dir, &handle_dir) {
            Some(a) => a,
            None => {
                debug!(dir = %handle_dir.display(), "auto-rotation: no .csq-account marker in handle dir, skipping");
                skipped += 1;
                continue;
            }
        };

        // VP-final F1 (belt-and-suspenders): if the current account is a 3P slot,
        // skip rotation entirely for this handle dir. Rotating a 3P handle dir would
        // send Anthropic OAuth tokens to the 3P ANTHROPIC_BASE_URL endpoint — live
        // token exfiltration. The primary guard is in find_target (3P accounts are
        // filtered from candidates), but this secondary check prevents the rotator
        // from ever calling repoint_handle_dir when the CURRENT slot is already 3P.
        if handle_dir_is_3p(base_dir, current_account) {
            debug!(
                dir = %handle_dir.display(),
                account = current_account.get(),
                "auto-rotation: current account is a 3P slot — skipping (VP-F1)"
            );
            skipped += 1;
            continue;
        }

        // Check per-handle-dir cooldown (keyed on handle_dir path, not account).
        if let Some(&last_rotated) = cooldowns.get(&handle_dir) {
            if last_rotated.elapsed() < cooldown_duration {
                debug!(
                    dir = %handle_dir.display(),
                    remaining_secs = (cooldown_duration - last_rotated.elapsed()).as_secs(),
                    "auto-rotation: in cooldown, skipping"
                );
                skipped += 1;
                continue;
            }
        }

        // Check quota for current account.
        let quota = match quota_state::load_state(base_dir) {
            Ok(q) => q,
            Err(e) => {
                warn!(error = %e, "auto-rotation: failed to load quota state");
                skipped += 1;
                continue;
            }
        };

        let five_hour_pct = quota
            .get(current_account.get())
            .map(|q| q.five_hour_pct())
            .unwrap_or(0.0);

        if five_hour_pct < cfg.threshold_percent {
            debug!(
                dir = %handle_dir.display(),
                account = current_account.get(),
                pct = five_hour_pct,
                threshold = cfg.threshold_percent,
                "auto-rotation: below threshold, skipping"
            );
            skipped += 1;
            continue;
        }

        // Account has exceeded the threshold — find a better account.
        // M3-4 deep-analyst HIGH-3 fix: `find_target` now returns
        // `Option<(AccountNum, IdentityId)>` so the selection logic and the
        // repoint logic share ONE consistent UUID resolution.  Candidates whose
        // UUID is unresolvable at selection time are skipped (not rotated to).
        let target_pair = find_target(base_dir, current_account, &cfg.exclude_accounts);

        let (target, target_identity) = match target_pair {
            Some(t) => t,
            None => {
                debug!(
                    dir = %handle_dir.display(),
                    account = current_account.get(),
                    "auto-rotation: no better account available, skipping"
                );
                skipped += 1;
                continue;
            }
        };

        // round 7c D4: opportunistically harvest CURRENT's own live keychain
        // candidates BEFORE taking the per-dir swap lock — same process, no
        // IPC (unlike `csq swap`'s D5, which is a separate process and must
        // ask the daemon via D3's `/api/harvest-account`). This is what
        // makes a `WriteDecision::RefuseUnharvested` from the forced write
        // below self-healing rather than permanently stuck: if CURRENT's
        // keychain item is a login CC self-refreshed independently, this
        // call adopts it into the store first, so the marker account's own
        // canonical (`KnownTokens::marker_account_canonical`) now matches
        // it. Best-effort: no UUID mapping means nothing to harvest into,
        // and any other outcome is silently absorbed — the existing
        // Err-from-`force_swap_write_before_repoint` arm below still
        // handles a genuine RefuseUnharvested (skip + WARN + cooldown).
        // C-F6: honour a rate limit observed earlier THIS tick — skip the
        // opportunistic harvest (and its live validation call) entirely
        // rather than adding another throttled request.
        //
        // `keychain-fix-r10.md` S-M-1/C-B2 (item 2), C-B1/S-L-5: a
        // RateLimited outcome observed HERE also marks the shared, IP-wide
        // gate (`server.rs`'s `harvest_gate` module) — mirroring what
        // `refresher.rs`'s own custodian call already does — so the
        // refresher's next tick, an on-demand harvest, or this rotator's own
        // next tick all short-circuit too, instead of each independently
        // rediscovering the same 429.
        if !rate_limited_this_tick {
            if let Some(uuid) =
                crate::accounts::profiles::resolve_slot_to_uuid(base_dir, current_account.get())
            {
                if matches!(
                    reconcile(base_dir, current_account, &uuid.to_string(), http_get,),
                    crate::daemon::custodian::ReconcileOutcome::RateLimited
                ) {
                    rate_limited_this_tick = true;
                    crate::daemon::server::harvest_gate::gate_mark_rate_limited(gate);
                }
            }
        }

        // T1: pre-lock decision is now complete (current account, 3P checks,
        // cooldown, threshold, and rotation target all resolved above). A
        // test may register a hook here to deterministically inject a
        // concurrent mutation before the bounded lock attempt below —
        // exactly the window the S-M2/H2 re-check exists to guard against.
        // A no-op in production (`run_pre_lock_test_hook`'s non-test body is
        // empty).
        run_pre_lock_test_hook();

        // PR-A1 structural fix: repoint the handle dir's symlinks to the
        // target account. This atomically updates `.credentials.json`,
        // `.csq-account`, `.claude.json`, and `.quota-cursor` symlinks
        // and re-materializes `settings.json`. config-N/.credentials.json
        // is NEVER written (INV-01 preserved).
        //
        // M3-4: `target_identity` is the UUID that `find_target` resolved
        // for this candidate at selection time.  Used for INFO telemetry
        // (not re-resolved here — avoids the TOCTOU race from HIGH-3).
        //
        // A4a — keychain treatment on the rotation event (review finding,
        // race-interleaving lens). `repoint_handle_dir` rewrites the Anthropic
        // symlinks but NOT the macOS keychain item CC reads (current CC is
        // keychain-first). Without the same treatment `csq swap` applies, after the
        // repoint this dir holds symlink=target while the PREVIOUS account's token
        // lingers in the keychain — the exact stale-token persistence and
        // cross-account-corruption risk v4's forced write below closes.
        //
        // v4 A1 ("switch now or say so"): read X and force-write it BEFORE
        // the repoint, under the per-dir swap lock (bounded — auto-rotation
        // must not hang a tick on a contended lock indefinitely; a
        // `NotNeeded`/`Acquired` outcome proceeds, a `TimedOut`/`Failed`
        // outcome performs NO mutation and is retried next tick).
        // M3-7/guard-reader-writer-parity.md MUST-1/F5: source the target's
        // token via the shared `target_token_for_forced_write` helper, so
        // this and `csq swap`'s same-surface route can never drift apart on
        // how the resolver is invoked — never a hardcoded config-N guess,
        // which a UUID-keyed slot's config-N copy may be stale or absent
        // for. H2: the actual read happens AFTER the lock below (the
        // S-M2/H2 re-check block), not here — this decision point is made
        // before a lock that can wait up to ~20s, so reading the target's
        // credentials here would be exactly the stale-decision window S-M2
        // exists to close.
        // v4 A1: hold the bounded per-dir swap lock across the WHOLE
        // [write X -> repoint] span — the daemon custodian's harvest must
        // never observe this dir between the two. `TimedOut`/`Failed`
        // performs NO mutation (nothing to restore) and retries next tick;
        // R9-3(c): does NOT call `record_keychain_account_hint` here (see
        // that function's doc — a daemon-context guess must never replace a
        // CLI-confirmed hint).
        use crate::credentials::keychain::BoundedLockOutcome;
        let lock_outcome =
            crate::credentials::keychain::lock_handle_dir_for_swap_bounded(&handle_dir);
        let _rebind_guard = match lock_outcome {
            BoundedLockOutcome::Acquired(guard) => Some(guard),
            BoundedLockOutcome::NotNeeded => None,
            BoundedLockOutcome::TimedOut | BoundedLockOutcome::Failed => {
                // D-F3 (lock-timeout parity): this is a failure arm exactly
                // like the keychain-read-failure and repoint-failure arms
                // below, and a persistent blocker here (a lock file another
                // process never releases, or a broken lock path) must not
                // retry on every single tick with no backoff either — set
                // the same cooldown every other failure arm sets, so a
                // stuck dir is retried at the cooldown cadence rather than
                // spinning the bounded ~20s wait every tick.
                warn!(
                    error_kind = "keychain_sync_lock_timed_out",
                    dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                    "auto-rotation: could not acquire the per-handle-dir keychain lock; \
                     rotation NOT performed this tick (nothing changed) — will retry after cooldown"
                );
                cooldowns.insert(handle_dir.clone(), Instant::now());
                skipped += 1;
                continue;
            }
        };

        // S-M2: the decision above (current account, 3P skip, threshold,
        // target) was made BEFORE this lock, which can wait up to ~20s
        // (`lock_handle_dir_for_swap_bounded`'s bound). Re-resolve the
        // marker and re-check 3P now that the lock is held — a `csq swap`
        // in this same window, or a slot rebind to 3P, must not be
        // clobbered by a decision made against stale state. No write has
        // happened yet, so skipping here performs NO mutation.
        let post_lock_account = match markers::resolve_marker_to_slot(base_dir, &handle_dir) {
            Some(a) => a,
            None => {
                debug!(
                    dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                    "auto-rotation: marker became unreadable while waiting for the lock, skipping (S-M2)"
                );
                skipped += 1;
                continue;
            }
        };
        if post_lock_account != current_account {
            debug!(
                dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                from = current_account.get(),
                now = post_lock_account.get(),
                "auto-rotation: account changed while waiting for the lock, skipping (S-M2)"
            );
            skipped += 1;
            continue;
        }
        if handle_dir_is_3p(base_dir, post_lock_account) {
            debug!(
                dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                account = post_lock_account.get(),
                "auto-rotation: slot became 3P while waiting for the lock, skipping (S-M2)"
            );
            skipped += 1;
            continue;
        }
        // H2: `target` itself was chosen by `find_target` BEFORE this lock
        // — the SAME stale-decision window S-M2 already re-checks for the
        // CURRENT account applies equally to the TARGET: a concurrent
        // rebind could have turned `target` into a 3P slot while this tick
        // waited for the lock. Re-reading `target_creds` under the lock
        // (rather than trusting the pre-lock read) additionally protects
        // against a concurrent CREDENTIAL change on the target account
        // landing between the two reads. No write has happened yet, so
        // skipping here performs NO mutation.
        if handle_dir_is_3p(base_dir, target) {
            debug!(
                dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                account = target.get(),
                "auto-rotation: rotation TARGET became 3P while waiting for the lock, skipping (H2)"
            );
            skipped += 1;
            continue;
        }
        let target_creds =
            crate::accounts::identity_store::target_token_for_forced_write(base_dir, target);

        // C-F2 (`keychain-fix-r8.md`): the H2 check just above only proves
        // `target` is still an Anthropic-capable slot, not that its OWN
        // canonical token is still live — `find_target` selected it as
        // `Valid` before this tick took the lock, and a concurrent refresh
        // failure, logout, or an expiry landing during the bounded ~20s wait
        // can leave it `ExpiredOrInvalid`/`Unreadable` by the time we read it
        // here. `force_swap_write_before_repoint` cannot tell "target is
        // genuinely non-Anthropic" (for which `Intended::Strip` is correct)
        // apart from "target IS Anthropic but its token is untrustworthy
        // right now" — passing `None` for either produces the identical
        // `Intended::Strip` (see `TargetToken`'s doc, corrected below: the
        // two cases are NOT interchangeable for this caller). Refuse the
        // rotation outright rather than let an untrustworthy-but-Anthropic
        // target reach Strip semantics it was never meant for. No mutation
        // has happened yet, so skipping here performs NO mutation.
        if !matches!(
            target_creds,
            crate::accounts::identity_store::TargetToken::Valid(_)
        ) {
            warn!(
                error_kind = "auto_rotate_target_token_invalidated_under_lock",
                dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                account = target.get(),
                "auto-rotation: rotation TARGET's own token stopped being valid while \
                 waiting for the lock; rotation NOT performed this tick (nothing changed) \
                 — will retry after cooldown (C-F2)"
            );
            cooldowns.insert(handle_dir.clone(), Instant::now());
            skipped += 1;
            continue;
        }

        // v5 ("keychain follows the links", 2026-09-26 owner directive):
        // every `Ok(_)` write outcome (Applied, AbsentWriteFailed, or
        // WriteFailedUnknown) proceeds to the repoint below identically —
        // `reconcile_keychain_to_marker` is the SOLE compensating action for
        // whatever the repoint does next, so this call site no longer
        // branches on the write's own outcome.
        if let Err(_msg) = crate::credentials::keychain::force_swap_write_before_repoint(
            base_dir,
            &handle_dir,
            target_creds.as_valid_str(),
        ) {
            // F6/S4: this arm is reached when the keychain READ itself
            // failed (Unreadable) or the caller's own lock/read plumbing
            // errored. NOTHING was mutated. The switch is NOT performed.
            //
            // D-F3: a persistent blocker (keychain locked every tick, e.g. a
            // headless/SSH session) must not retry on every single tick
            // with no backoff — set the same cooldown a successful rotation
            // gets, so a stuck dir is retried at the cooldown cadence
            // rather than every tick.
            warn!(
                error_kind = "keychain_force_sync_unreadable_no_rotation",
                dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                "auto-rotation: keychain read/write failed; rotation NOT performed this tick (nothing changed) — will retry after cooldown"
            );
            cooldowns.insert(handle_dir.clone(), Instant::now());
            skipped += 1;
            continue;
        }

        // B2: `reconcile_keychain_to_marker` is the SOLE compensating
        // action for whatever the repoint did — run it on BOTH outcomes,
        // never only on `Err`. A successful repoint's own keychain write
        // happened before it (under the same lock), but that write's own
        // outcome (`ForcedSyncResult`) may itself have been
        // `AbsentWriteFailed`/`WriteFailedUnknown` — an `Ok(())` repoint
        // does NOT prove the keychain mirror actually landed, so this call
        // site no longer trusts a bare `Ok(())` to mean "keychain agrees
        // too". Always passing `forced_write` (built from EXACTLY what this
        // call attempted, via `target_creds.as_valid_str()`) lets reconcile
        // classify X by IDENTITY (PRIMARY DIRECTIVE) rather than re-deriving
        // it from scratch.
        let forced_write = Some(crate::credentials::keychain::ForcedWriteAttempt {
            account: target,
            raw_json: target_creds.as_valid_str(),
        });
        let repoint_result = repoint_handle_dir(base_dir, claude_home, &handle_dir, target);
        let reconcile_outcome = crate::credentials::keychain::reconcile_keychain_to_marker(
            base_dir,
            &handle_dir,
            forced_write,
        );
        let reconcile_line = crate::credentials::keychain::reconcile_outcome_operator_line(
            &reconcile_outcome,
            Some(current_account),
        );
        match repoint_result {
            // S-H-A/D-F1: a repoint `Ok(())` is not itself proof the
            // keychain followed — only `AlreadyCurrent`/`Reconciled` mean
            // that. Every other reconcile outcome on a successful repoint
            // is logged at WARN (not INFO), is NOT counted as `rotated`,
            // and gets the shorter `RECONCILE_DESYNC_RETRY_COOLDOWN`
            // instead of the full rotation cooldown, so this dir is
            // retried sooner rather than waiting a full cycle.
            Ok(()) if reconcile_outcome_confirms_rotation(&reconcile_outcome) => {
                info!(
                    dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                    from = current_account.get(),
                    to = target.get(),
                    identity = %target_identity,
                    threshold = cfg.threshold_percent,
                    pct = five_hour_pct,
                    "auto-rotation: repointed handle dir to new account; {reconcile_line}"
                );
                cooldowns.insert(handle_dir.clone(), Instant::now());
                rotated += 1;
            }
            Ok(()) => {
                warn!(
                    dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                    from = current_account.get(),
                    to = target.get(),
                    identity = %target_identity,
                    "auto-rotation: repoint succeeded but the keychain did not confirm following it; NOT counted as rotated — {reconcile_line}"
                );
                let short_retry_at = Instant::now()
                    .checked_sub(cooldown_duration.saturating_sub(RECONCILE_DESYNC_RETRY_COOLDOWN))
                    .unwrap_or_else(Instant::now);
                cooldowns.insert(handle_dir.clone(), short_retry_at);
                skipped += 1;
            }
            Err(e) => {
                // B3: the handle dir's OWN symlinks may ALSO be left mixed
                // across two accounts by a partially-rolled-back repoint —
                // a signal independent of the keychain reconcile above.
                let mixed_links = crate::credentials::keychain::repoint_left_mixed_links(
                    &e,
                    base_dir,
                    &handle_dir,
                );
                let operator_line_tail = repoint_failure_operator_line(
                    e.repoint_refused_item(),
                    mixed_links,
                    &reconcile_outcome,
                    reconcile_line,
                );
                warn!(
                    dir = %crate::cli_deps::sanitize::redact_path(&handle_dir),
                    account = current_account.get(),
                    error_kind = e.error_kind_tag(),
                    "auto-rotation: repoint failed; {operator_line_tail}"
                );
                // D-F3: a persistent repoint failure (e.g. a real file
                // blocking an ACCOUNT_BOUND_ITEMS symlink) must not retry
                // every tick with no backoff.
                cooldowns.insert(handle_dir.clone(), Instant::now());
                skipped += 1;
            }
        }
    }

    if rotated > 0 || skipped > 0 {
        info!(rotated, skipped, "auto-rotation tick complete");
    } else {
        debug!("auto-rotation tick: no handle dirs processed");
    }
}

/// Finds the best rotation target, respecting the user's exclusion list
/// and the same-surface filter.
///
/// Additionally filters out any accounts in `exclude_accounts`. If the
/// first candidate is in the exclusion list, we iterate until we find
/// one that isn't — or return None if no eligible account exists.
///
/// # v2.1 scope (PR-C9a round-1 CRITICAL fix, an internal journal entry)
///
/// Auto-rotate is **ClaudeCode-only** in v2.1. Pre-C9a this function
/// used [`discovery::discover_anthropic`], which returned no records for
/// Codex handle dirs — `active_surface` then fell back to
/// `Surface::ClaudeCode`, the same-surface filter admitted ClaudeCode
/// candidates, and the rotator called [`repoint_handle_dir`] on a Codex
/// handle dir, corrupting the live codex process (INV-P11 violation).
///
/// The fix is two-part:
///
/// 1. Use [`discovery::discover_all`] so Codex slots contribute an
///    `AccountInfo` with `surface = Surface::Codex` and `active_surface`
///    is resolved correctly.
/// 2. Short-circuit (return `None`) if the current account's surface is
///    not `ClaudeCode`. Codex rotation, if ever added, requires an
///    exec-replace pathway (an internal journal entry §Q1 INV-P05 amendment, pending
///    human approval) that the repoint-based rotator cannot deliver —
///    so the explicit refusal here is the correct v2.1 semantics.
///
/// Belt-and-suspenders: [`repoint_handle_dir`] also refuses to act on a
/// Codex-shape handle dir (presence of `auth.json` / `config.toml` /
/// `sessions` symlinks), so any future caller that forgets the
/// surface check is caught before symlinks are rewritten.
///
/// # M3-4 deep-analyst HIGH-3 fix
///
/// Returns `Option<(AccountNum, IdentityId)>` so that the selection logic
/// and the repoint logic share ONE consistent UUID resolution.  Candidates
/// whose `resolve_slot_to_uuid` returns `None` at selection time are
/// SKIPPED.  This prevents the race window where the rotator selects a
/// candidate based on quota at tick entry, then `resolve_slot_to_uuid`
/// returns `None` at repoint time (concurrent `profiles.json` write),
/// causing a silent fallback to legacy or a repoint to a non-existent UUID
/// path.  If `profiles.json` has slots WITHOUT UUIDs (legacy-only or
/// partial-Pass-0 state), `find_target` filters those candidates out.
/// Documented as the structural defense against the HIGH-3 race class.
fn find_target(
    base_dir: &Path,
    current: AccountNum,
    exclude_accounts: &[u16],
) -> Option<(AccountNum, IdentityId)> {
    use crate::accounts::discovery;
    use crate::accounts::profiles;
    use crate::quota::state as qs;

    let accounts = discovery::discover_all(base_dir);
    let quota = qs::load_state(base_dir).ok()?;

    // Build a combined exclusion set: current + user list.
    let extra_excludes: Vec<AccountNum> = exclude_accounts
        .iter()
        .filter_map(|&id| AccountNum::try_from(id).ok())
        .collect();

    let excluded_ids: std::collections::HashSet<u16> = extra_excludes
        .iter()
        .map(|a| a.get())
        .chain(std::iter::once(current.get()))
        .collect();

    // Determine the current terminal's surface so the same-surface filter
    // (INV-P11) can reject cross-surface candidates. `discover_all`
    // includes Codex slots, so a Codex handle dir yields an accurate
    // `Surface::Codex` value here rather than falling back to ClaudeCode.
    //
    // Fallback to `Surface::ClaudeCode` still applies when discovery
    // returns NO record for the current account (orphaned handle dir
    // pointing at a deleted slot). In that case the caller has bigger
    // problems and the rotator's behaviour is moot — the repoint will
    // fail on the missing config-<N> dir downstream regardless.
    let active_surface = accounts
        .iter()
        .find(|a| a.id == current.get())
        .map(|a| a.surface)
        .unwrap_or(Surface::ClaudeCode);

    // v2.1 scope: auto-rotate is ClaudeCode-only. If the current handle
    // dir is bound to a Codex slot (or any future non-ClaudeCode surface),
    // refuse to rotate. Cross-surface Codex↔Codex rotation requires an
    // exec-replace pathway that the repoint-based rotator cannot provide.
    if active_surface != Surface::ClaudeCode {
        debug!(
            current = current.get(),
            surface = ?active_surface,
            "auto-rotation: current account is non-ClaudeCode surface, skipping \
             (v2.1 scope: Codex rotation requires explicit csq swap)"
        );
        return None;
    }

    // Collect candidates: has credentials, Anthropic source only (VP-final R1
    // CRITICAL: exclude 3P slots — stale credentials/N.json from a prior OAuth
    // binding can co-exist with a 3P settings.json; rotating to that slot would
    // point Anthropic OAuth tokens at a 3P endpoint via env.ANTHROPIC_BASE_URL),
    // not current, not excluded, AND passes the same-surface filter (INV-P11).
    //
    // M3-4 HIGH-3: also require `resolve_slot_to_uuid` to return `Some` at
    // selection time.  Candidates without a resolvable UUID are skipped.
    // This collapses the selection view and the repoint view into one consistent
    // UUID resolution, preventing the TOCTOU race between tick entry and
    // `repoint_handle_dir` execution.  Slots in legacy-only or partial-Pass-0
    // state (no UUID in profiles.json) are filtered out here as a structural
    // defense; the caller receives only candidates the rotator can safely
    // target with identity-keyed symlinks.
    //
    // NOTE: `discover_anthropic` classifies slots with `credentials/N.json` as
    // `AccountSource::Anthropic` even when `config-N/settings.json` also sets
    // `env.ANTHROPIC_BASE_URL` (a stale credential from a prior OAuth binding
    // on a now-3P slot). We therefore double-check the config dir's settings.json
    // directly to catch this co-existence case.
    let candidates: Vec<(AccountNum, IdentityId, f64, u64)> = accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .filter(|a| matches!(a.source, AccountSource::Anthropic))
        .filter_map(|a| {
            let num = AccountNum::try_from(a.id).ok()?;
            if excluded_ids.contains(&num.get()) {
                return None;
            }
            // VP-final R1 CRITICAL: check config-N/settings.json for 3P binding.
            // A stale credentials/N.json can co-exist with a 3P settings.json —
            // discover_anthropic marks the slot Anthropic because it finds the
            // credential file, but the slot is actually 3P. Rotating to it would
            // send Anthropic OAuth tokens to env.ANTHROPIC_BASE_URL. Reject it.
            if handle_dir_is_3p(base_dir, num) {
                return None;
            }
            // INV-P11: same-surface filter. Auto-rotation never crosses
            // surfaces; that's an explicit `csq swap` operation.
            if !same_surface_as_active(active_surface, a.surface) {
                return None;
            }
            // M3-4 HIGH-3: require a resolvable UUID at selection time.
            // Slots without a UUID in profiles.json are skipped to prevent
            // the TOCTOU race where selection succeeds but repoint finds
            // no UUID and either falls back silently to legacy or targets
            // a non-existent identity path.
            let uuid = profiles::resolve_slot_to_uuid(base_dir, num.get())?;
            // round 7c D4: a candidate whose own canonical token is not
            // Valid (unreadable/expired/non-Anthropic) is never a rotation
            // TARGET — rotating to it would force-write nothing (D1's
            // `force_sync_account_changed` skips a non-Valid `new_credentials_json`
            // via its None/Strip branch) while the repoint below still
            // proceeds, leaving the handle dir pointed at an account with
            // no live login. `force_swap_write_before_repoint`/D5's swap
            // sibling enforce the same rule at their own selection points.
            crate::accounts::identity_store::target_token_for_forced_write(base_dir, num)
                .as_valid_str()?;
            let pct = quota
                .get(num.get())
                .map(|q| q.five_hour_pct())
                .unwrap_or(0.0);
            let resets_at = quota
                .get(num.get())
                .and_then(|q| q.five_hour.as_ref().map(|w| w.resets_at))
                .unwrap_or(u64::MAX);
            Some((num, uuid, pct, resets_at))
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Prefer non-exhausted accounts (pct < 100), pick lowest usage.
    let non_exhausted: Vec<_> = candidates
        .iter()
        .filter(|(_, _, pct, _)| *pct < 100.0)
        .collect();

    if !non_exhausted.is_empty() {
        return non_exhausted
            .iter()
            .min_by(|(_, _, a, _), (_, _, b, _)| {
                a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(num, uuid, _, _)| (*num, *uuid));
    }

    // All exhausted — pick earliest reset.
    candidates
        .iter()
        .min_by_key(|(_, _, _, resets)| *resets)
        .map(|(num, uuid, _, _)| (*num, *uuid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::markers;
    use crate::credentials::{
        self, file as cred_file, AnthropicCredentialFile, CredentialFile, OAuthPayload,
    };
    use crate::quota::{state as quota_state, AccountQuota, UsageWindow};
    use crate::rotation::config::{save as save_rotation_config, RotationConfig};
    use crate::session::handle_dir::create_handle_dir;
    use crate::types::{AccessToken, AccountNum, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    /// S-H-A/D-F1: only `AlreadyCurrent`/`Reconciled` confirm the keychain
    /// followed a successful repoint; every other outcome must NOT.
    #[test]
    fn reconcile_outcome_confirms_rotation_only_on_already_current_or_reconciled() {
        let acct = AccountNum::try_from(2u16).unwrap();
        assert!(reconcile_outcome_confirms_rotation(
            &crate::credentials::keychain::ReconcileOutcome::AlreadyCurrent {
                marker_account: acct
            }
        ));
        assert!(reconcile_outcome_confirms_rotation(
            &crate::credentials::keychain::ReconcileOutcome::Reconciled {
                marker_account: acct
            }
        ));
        assert!(!reconcile_outcome_confirms_rotation(
            &crate::credentials::keychain::ReconcileOutcome::MarkerUnreadable
        ));
        assert!(!reconcile_outcome_confirms_rotation(
            &crate::credentials::keychain::ReconcileOutcome::WriteFailed {
                marker_account: acct
            }
        ));
        assert!(!reconcile_outcome_confirms_rotation(
            &crate::credentials::keychain::ReconcileOutcome::KeychainUnknown {
                marker_account: acct,
                reason: crate::credentials::keychain::KeychainUnknownReason::ForeignLogin,
            }
        ));
    }

    /// C-F8 (`keychain-fix-r8.md`): `mixed_links` alone (no `refused_item`)
    /// must FOLD `reconcile_line` into the mixed-links wording, never
    /// replace it — the prior version's `mixed_links_operator_line(m)` on
    /// its own silently discarded whatever the reconcile outcome said.
    ///
    /// RED: reverting to the pre-fix `Some(m) =>
    /// mixed_links_operator_line(m)` (dropping the `format!("{} {reconcile_line}",
    /// ...)`) makes this test's `msg.contains("terminal and keychain both on 2")`
    /// assertion fail — the reconcile line's own content is gone.
    #[test]
    fn repoint_failure_operator_line_mixed_links_folds_in_reconcile_line() {
        let acct = AccountNum::try_from(2u16).unwrap();
        let reconcile_outcome = crate::credentials::keychain::ReconcileOutcome::AlreadyCurrent {
            marker_account: acct,
        };
        let reconcile_line = crate::credentials::keychain::reconcile_outcome_operator_line(
            &reconcile_outcome,
            Some(acct),
        );
        let msg =
            repoint_failure_operator_line(None, true, &reconcile_outcome, reconcile_line.clone());
        assert!(
            msg.contains("links are mixed across accounts"),
            "mixed_links wording must be present: {msg}"
        );
        assert!(
            msg.contains(&reconcile_line),
            "the reconcile line's own content must be folded in, not discarded: {msg}"
        );
    }

    /// C-F8 precedence: `refused_item` (`Some`) wins over `mixed_links` even
    /// when both are true — `repoint_refused_real_file_operator_line` (which
    /// already folds `reconcile_line` in) is used, never
    /// `mixed_links_operator_line`.
    #[test]
    fn repoint_failure_operator_line_refused_item_takes_precedence_over_mixed_links() {
        let acct = AccountNum::try_from(2u16).unwrap();
        let reconcile_outcome = crate::credentials::keychain::ReconcileOutcome::AlreadyCurrent {
            marker_account: acct,
        };
        let reconcile_line = crate::credentials::keychain::reconcile_outcome_operator_line(
            &reconcile_outcome,
            Some(acct),
        );
        let msg = repoint_failure_operator_line(
            Some(".credentials.json"),
            true,
            &reconcile_outcome,
            reconcile_line.clone(),
        );
        assert!(
            msg.contains("is a regular file, not a link"),
            "refused_item must win precedence: {msg}"
        );
        assert!(
            !msg.contains("links are mixed across accounts"),
            "mixed_links_operator_line must NOT be used when refused_item is Some: {msg}"
        );
        assert!(
            msg.contains(&reconcile_line),
            "the refused-item message must still fold in the reconcile line: {msg}"
        );
    }

    // ── helpers ──────────────────────────────────────────────────────────

    fn make_creds(access: &str, refresh: &str) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    /// Sets up a fully-mapped account: legacy `credentials/<N>.json` AND
    /// `profiles.json::by_slot[N]` AND `identities/<UUID>/credentials.json`.
    ///
    /// Post-M4-4 (Phase 4 reader flip), the discovery layer's
    /// `discover_anthropic` reads through `by_slot`. In production the M3-7
    /// `phase3_gate_check` guarantees that every legacy slot has a by_slot
    /// entry with seeded identity-keyed credentials before the daemon
    /// serves any request. This helper mirrors that production invariant
    /// for the auto-rotate tick tests, which exercise post-gate state.
    ///
    /// For tests that need an UN-mapped slot (e.g. M3-4 AC8 HIGH-3 filter),
    /// use [`setup_account_legacy_only`] instead.
    fn setup_account(base: &Path, account: u16) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = make_creds(&format!("at-{account}"), &format!("rt-{account}"));
        // Legacy canonical: required for downgrade safety + readers that
        // haven't been migrated yet.
        credentials::save(&cred_file::canonical_path(base, target), &creds).unwrap();
        // by_slot + identity-keyed creds: required by post-M4-4 readers.
        setup_slot_uuid(base, account);
    }

    /// Legacy-only account setup: writes ONLY `credentials/<N>.json`. No
    /// `by_slot` entry, no identity-keyed credentials. Used by tests that
    /// exercise the legacy-fallback discovery branch or the M3-4 HIGH-3
    /// UUID filter.
    fn setup_account_legacy_only(base: &Path, account: u16) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = make_creds(&format!("at-{account}"), &format!("rt-{account}"));
        credentials::save(&cred_file::canonical_path(base, target), &creds).unwrap();
    }

    fn setup_quota(base: &Path, account: u16, five_hour_pct: f64) {
        let mut quota = quota_state::load_state_salvage(base);
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: five_hour_pct,
                    // Far-future reset so clear_expired doesn't drop these
                    // during the load cycle. Year 2100 = 4102444800 seconds.
                    resets_at: 4_102_444_800,
                }),
                ..Default::default()
            },
        );
        quota_state::save_state(base, &quota).unwrap();
    }

    /// Creates `config-<account>/` with a .csq-account marker.
    fn setup_config_dir(base: &Path, account: u16) -> PathBuf {
        let config_dir = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        let target = AccountNum::try_from(account).unwrap();
        markers::write_csq_account_legacy(&config_dir, target).unwrap();
        config_dir
    }

    /// Creates a `term-<pid>/` handle dir with symlinks pointing at
    /// `config-<account>/`. Uses `create_handle_dir` so the structure
    /// matches production exactly. The `claude_home` is a fresh temp dir
    /// so shared-items symlinks don't escape into `~/.claude`.
    fn setup_handle_dir(base: &Path, claude_home: &Path, pid: u32, account: u16) -> PathBuf {
        let account_num = AccountNum::try_from(account).unwrap();
        create_handle_dir(base, claude_home, account_num, pid).unwrap()
    }

    /// Registers a deterministic UUID for `slot` in `profiles.json::by_slot`
    /// AND seeds `identities/<UUID>/credentials.json` (post-M4-4: the reader
    /// flip routes through the identity-keyed path when `by_slot` is populated,
    /// so the legacy `credentials/<N>.json` seeded by `setup_account` is
    /// no longer read).
    ///
    /// M3-4 HIGH-3: `find_target` now requires `resolve_slot_to_uuid` to return
    /// `Some` for every candidate — slots without a UUID are filtered out.
    /// Legacy tests that expect `tick` to rotate MUST call this helper for every
    /// slot that should be a valid rotation candidate.
    ///
    /// M4-4: the discovery layer's `discover_anthropic` now reads from
    /// `identities/<UUID>/credentials.json` when `by_slot[N]` resolves. The
    /// `phase3_gate_check` guarantees this file is seeded in production; tests
    /// satisfy the same invariant by seeding it here alongside the by_slot
    /// mapping.
    ///
    /// Uses the same deterministic UUID derivation as
    /// `testing::identity_fixtures::fixture_uuid_for_slot` so tests are consistent
    /// with the identity fixture surface.
    fn setup_slot_uuid(base: &Path, slot: u16) -> IdentityId {
        use crate::accounts::identity_store::{self, IdentityId};
        use crate::accounts::profiles::{self, ProfilesFile};
        use uuid::Uuid;

        // Deterministic UUID: same derivation as fixture_uuid_for_slot.
        const FIXTURE_SEED: [u8; 14] = [
            0xC5, 0xA1, 0x7E, 0x3F, 0xB8, 0x42, 0xD9, 0x11, 0xAE, 0x60, 0xF3, 0x02, 0x88, 0x5D,
        ];
        let slot_bytes = slot.to_be_bytes();
        let mut bytes = [0u8; 16];
        bytes[0] = slot_bytes[0];
        bytes[1] = slot_bytes[1];
        bytes[2..16].copy_from_slice(&FIXTURE_SEED);
        let uuid = IdentityId::from(Uuid::from_bytes(bytes));

        let path = profiles::profiles_path(base);
        let mut pf = if path.exists() {
            profiles::load(&path).unwrap_or_else(|_| ProfilesFile::empty())
        } else {
            ProfilesFile::empty()
        };
        pf.by_slot.insert(slot.to_string(), uuid);
        profiles::save(&path, &pf).unwrap();

        // M4-4: also seed identities/<UUID>/credentials.json so the post-flip
        // reader finds credentials for this slot. Mirror the legacy creds
        // that setup_account writes; both paths carry the same content per
        // the M2-2 identity-FIRST/legacy-SECOND write-order invariant.
        let creds = make_creds(&format!("at-{slot}"), &format!("rt-{slot}"));
        let identity_path = identity_store::credentials_path_for(base, uuid);
        credentials::save(&identity_path, &creds).unwrap();

        uuid
    }

    // ── adapted existing tests ────────────────────────────────────────────

    /// Creates `config-<account>/` with a UUID-content `.csq-account` marker
    /// (the M4-7 writer shape — `markers::write_csq_account`) instead of the
    /// legacy decimal `setup_config_dir` writes. Provisions the same
    /// `by_slot[account]` mapping `setup_slot_uuid` writes via the shared
    /// `write_uuid_account_marker` fixture helper
    /// (`guard-reader-writer-parity.md`).
    fn setup_config_dir_uuid(base: &Path, account: u16) -> PathBuf {
        let config_dir = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        crate::testing::identity_fixtures::write_uuid_account_marker(base, &config_dir, account);
        config_dir
    }

    /// M4-7 regression (`guard-reader-writer-parity.md`): production
    /// `.csq-account` markers are UUID content whenever a `by_slot` mapping
    /// exists (`markers::write_csq_account`, written by `csq run` /
    /// `finalize_login`) — NOT the legacy decimal content every other
    /// fixture in this suite writes via `setup_config_dir`. Before the fix,
    /// `tick` read the marker with `markers::read_csq_account` (numeric-only)
    /// and silently skipped every handle dir bound to a modern (UUID-marker)
    /// slot, making auto-rotation a structural no-op on any host that had
    /// ever run `csq run` post-M4-7.
    #[test]
    fn tick_resolves_uuid_marker_and_rotates() {
        // Arrange: account 1 at 97% (above threshold), account 2 the better
        // candidate. BOTH slots get UUID-content markers — the shape a
        // modern install actually has on disk.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir_uuid(dir.path(), 1);
        setup_config_dir_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10099, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: handle dir repointed to account 2. Read via the same
        // UUID-tolerant resolver `tick` itself now uses, so the assertion
        // doesn't silently pass by re-using the narrow reader under test.
        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "tick must resolve a UUID .csq-account marker and rotate — \
             before the fix this handle dir was silently skipped"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            cooldowns.contains_key(&canonical_handle),
            "cooldown entry should be set for the handle dir on a UUID-marker rotation"
        );
    }

    /// round 7c D-F7 (g)-mirror: `find_target_skips_target_with_expired_token`
    /// (above) proves the FILTER in isolation; this proves the same rule
    /// holds through the full `tick()` entrypoint — the only candidate has
    /// an expired own token, so `tick` must leave the handle dir's marker
    /// exactly where it started rather than repointing to an account with
    /// no live login.
    #[test]
    fn tick_skips_rotation_when_only_candidate_has_expired_token() {
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_config_dir_uuid(dir.path(), 1);
        setup_quota(dir.path(), 1, 97.0);

        // Slot 2: quota-attractive (5% vs slot 1's 97%), UUID-mapped, but its
        // own canonical token is EXPIRED.
        setup_account(dir.path(), 2);
        setup_config_dir_uuid(dir.path(), 2);
        setup_quota(dir.path(), 2, 5.0);
        let uuid2 = crate::accounts::profiles::resolve_slot_to_uuid(dir.path(), 2).unwrap();
        let expired = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at-2-expired".into()),
                refresh_token: RefreshToken::new("rt-2-expired".into()),
                expires_at: 1, // long past
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(
            &crate::accounts::identity_store::credentials_path_for(dir.path(), uuid2),
            &expired,
        )
        .unwrap();

        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10199, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "tick must NOT rotate to a candidate whose own canonical token is expired, \
             even though it is quota-attractive — round 7c D4"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            !cooldowns.contains_key(&canonical_handle),
            "no cooldown entry should be set when tick performs no rotation"
        );
    }

    #[test]
    fn tick_disabled_config_no_swaps() {
        // Arrange: two accounts, account 1 over threshold, rotation DISABLED
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 99.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10001, 1);

        let cfg = RotationConfig {
            enabled: false,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: handle dir still bound to account 1 (no repoint happened)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_enabled_below_threshold_no_swap() {
        // Arrange: account 1 at 50% — below the 95% default threshold
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 50.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10002, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: no repoint, still on account 1
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_missing_config_uses_defaults_disabled() {
        // When no rotation.json exists, defaults have enabled=false.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 99.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10003, 1);

        // Act: no rotation.json written — defaults have enabled=false
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: default config has enabled=false — no rotation
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
    }

    // ── handle-dir-native repoint tests (PR-A1) ──────────────────────────

    #[test]
    fn tick_enabled_above_threshold_repoints_handle_dir() {
        // Arrange: account 1 at 97% — above threshold
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        // M3-4 HIGH-3: find_target now requires a resolvable UUID for each candidate.
        setup_slot_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10004, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: handle dir's .csq-account symlink now resolves to account 2
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle dir should be repointed to account 2"
        );
        // Cooldown entry keyed on the CANONICAL handle_dir path (VP-final F2:
        // tick canonicalizes the path before inserting into cooldowns).
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            cooldowns.contains_key(&canonical_handle),
            "cooldown entry should be set for the handle dir (canonical key)"
        );
    }

    #[test]
    fn tick_respects_cooldown_per_handle_dir() {
        // Arrange: account 1 at 97%, cooldown active after first tick
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        // M3-4 HIGH-3: find_target now requires a resolvable UUID for each candidate.
        setup_slot_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10005, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();

        // First tick: rotates to account 2
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "first tick should repoint to account 2"
        );

        // Simulate account 2 also going over threshold
        setup_quota(dir.path(), 2, 98.0);
        setup_quota(dir.path(), 1, 10.0); // account 1 recovered
                                          // Manually repoint back to account 2 to simulate post-first-tick state
        let acc2 = AccountNum::try_from(2u16).unwrap();
        markers::write_csq_account_legacy(&handle_dir.join(".csq-account"), acc2).ok();

        // Second tick: cooldown prevents rotation (keyed on handle_dir)
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Still on account 2 because cooldown is active for this handle dir
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle dir should stay on account 2 during cooldown"
        );
    }

    #[test]
    fn tick_no_better_account_no_swap() {
        // Only one account — nothing to rotate to
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_quota(dir.path(), 1, 97.0);
        setup_config_dir(dir.path(), 1);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10006, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // No other account — should stay on account 1, no cooldown entry
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert!(cooldowns.is_empty());
    }

    #[test]
    fn tick_respects_exclude_accounts() {
        // Account 2 excluded — should rotate to 3 instead
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_account(dir.path(), 3);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 20.0);
        setup_quota(dir.path(), 3, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        setup_config_dir(dir.path(), 3);
        // M3-4 HIGH-3: slots 2 and 3 are candidates; both need UUIDs.
        setup_slot_uuid(dir.path(), 2);
        setup_slot_uuid(dir.path(), 3);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10007, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            exclude_accounts: vec![2],
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Should have repointed to account 3 (not 2, which was excluded)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(3u16).unwrap())
        );
    }

    // ── PR-A1 invariant tests ─────────────────────────────────────────────

    #[test]
    fn auto_rotate_walks_handle_dirs_not_config_dirs() {
        // Arrange: config-1 has a sentinel credential file. A handle dir
        // (term-10008) is on account 1 over threshold. After tick, the
        // sentinel in config-1/.credentials.json MUST be unchanged
        // (INV-01), while the handle dir's .csq-account resolves to account 2.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir_1 = setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        // M3-4 HIGH-3: slot 2 is the only candidate; needs UUID.
        setup_slot_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10008, 1);

        // Write a sentinel into config-1/.credentials.json that we can
        // verify is untouched after the tick.
        let live_cred = config_dir_1.join(".credentials.json");
        std::fs::write(&live_cred, b"account-1-creds-sentinel").unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert 1: config-1/.credentials.json is UNCHANGED (INV-01)
        let contents = std::fs::read(&live_cred).unwrap();
        assert_eq!(
            contents, b"account-1-creds-sentinel",
            "config-N/.credentials.json MUST NOT be rewritten by the rotator (INV-01)"
        );

        // Assert 2: handle dir's .csq-account symlink now resolves to account 2
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle dir should be repointed to account 2"
        );
    }

    #[test]
    fn auto_rotate_preserves_config_n_when_repointing() {
        // Arrange: config-1 and config-2 have distinct credential bytes.
        // Handle dir on account 1, account 1 over threshold.
        // After tick, BOTH config dirs' credential files must be byte-identical
        // to their pre-tick content.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_dir_1 = setup_config_dir(dir.path(), 1);
        let config_dir_2 = setup_config_dir(dir.path(), 2);
        let _handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10009, 1);

        let cred_path_1 = config_dir_1.join(".credentials.json");
        let cred_path_2 = config_dir_2.join(".credentials.json");
        std::fs::write(&cred_path_1, b"creds-account-1-distinct").unwrap();
        std::fs::write(&cred_path_2, b"creds-account-2-distinct").unwrap();

        let pre_creds_1 = std::fs::read(&cred_path_1).unwrap();
        let pre_creds_2 = std::fs::read(&cred_path_2).unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: both config dirs' credential files are byte-identical pre/post
        let post_creds_1 = std::fs::read(&cred_path_1).unwrap();
        let post_creds_2 = std::fs::read(&cred_path_2).unwrap();
        assert_eq!(
            pre_creds_1, post_creds_1,
            "config-1/.credentials.json MUST NOT be modified by the rotator"
        );
        assert_eq!(
            pre_creds_2, post_creds_2,
            "config-2/.credentials.json MUST NOT be modified by the rotator"
        );
    }

    /// PR-C1: `same_surface_as_active` now does a real `Surface == Surface`
    /// comparison (INV-P11). Same-surface accepts; cross-surface rejects.
    #[test]
    fn same_surface_filter_accepts_matching_surface() {
        assert!(same_surface_as_active(
            Surface::ClaudeCode,
            Surface::ClaudeCode
        ));
        assert!(same_surface_as_active(Surface::Codex, Surface::Codex));
    }

    /// INV-P11 negative path: cross-surface rotation MUST be rejected —
    /// auto-rotation never crosses surfaces; that's a `csq swap` action.
    #[test]
    fn same_surface_filter_rejects_cross_surface() {
        assert!(!same_surface_as_active(Surface::ClaudeCode, Surface::Codex));
        assert!(!same_surface_as_active(Surface::Codex, Surface::ClaudeCode));
    }

    #[test]
    fn tick_noop_when_claude_home_none() {
        // Arrange: handle dir on account 1, account 1 over threshold,
        // but claude_home is None.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 10010, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act: pass None for claude_home
        let mut cooldowns = HashMap::new();
        tick(dir.path(), None, &mut cooldowns);

        // Assert: handle dir is unchanged (tick is a no-op when claude_home is None)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "tick with claude_home=None must be a no-op"
        );
        assert!(
            cooldowns.is_empty(),
            "no cooldown entries should be set when tick is a no-op"
        );
    }

    #[test]
    fn tick_cooldown_keyed_on_handle_dir_not_account() {
        // Two handle dirs both pointing at account 1. Account 1 over threshold.
        // Both should get their own independent cooldown map entries keyed on
        // their own path — not on the account number.
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        // M3-4 HIGH-3: slot 2 is the rotation candidate; needs UUID.
        setup_slot_uuid(dir.path(), 2);
        let handle_dir_a = setup_handle_dir(dir.path(), claude_home.path(), 10011, 1);
        let handle_dir_b = setup_handle_dir(dir.path(), claude_home.path(), 10012, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: both handle dirs were repointed (both had account 1 over threshold)
        assert_eq!(
            markers::read_csq_account(&handle_dir_a),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle_dir_a should be repointed to account 2"
        );
        assert_eq!(
            markers::read_csq_account(&handle_dir_b),
            Some(AccountNum::try_from(2u16).unwrap()),
            "handle_dir_b should be repointed to account 2"
        );

        // Assert: cooldown map has TWO entries, each keyed on a distinct canonical
        // handle dir path (VP-final F2: tick canonicalizes before inserting).
        let canonical_a = std::fs::canonicalize(&handle_dir_a).unwrap_or(handle_dir_a.clone());
        let canonical_b = std::fs::canonicalize(&handle_dir_b).unwrap_or(handle_dir_b.clone());
        assert_eq!(
            cooldowns.len(),
            2,
            "cooldown map must have one entry per handle dir, not per account"
        );
        assert!(
            cooldowns.contains_key(&canonical_a),
            "cooldown keyed on handle_dir_a canonical path"
        );
        assert!(
            cooldowns.contains_key(&canonical_b),
            "cooldown keyed on handle_dir_b canonical path"
        );
        // Verify the two canonical keys are different paths (not the same account key)
        assert_ne!(
            canonical_a, canonical_b,
            "two distinct handle dirs must have distinct canonical cooldown keys"
        );
    }

    // ── VP-final F1: 3P slot exfiltration guard ───────────────────────────

    /// Regression guard: VP-final R1 CRITICAL.
    ///
    /// Setup:
    /// - Slot 1: Anthropic — credentials/1.json + config-1 with no 3P settings
    /// - Slot 2: Z.AI — credentials/2.json (leftover from prior OAuth binding)
    /// - `config-2/settings.json` with `ANTHROPIC_BASE_URL=https://api.zai.io`
    ///
    /// Slot 1 is over threshold. `find_target` must return `None` because the only
    /// other candidate (slot 2) is a 3P slot and must be excluded.
    #[test]
    fn find_target_skips_3p_slots_with_stale_anthropic_creds() {
        // Arrange: slot 1 = Anthropic (clean), slot 2 = 3P (stale OAuth creds)
        let dir = TempDir::new().unwrap();

        // Slot 1: Anthropic — has canonical credentials
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 97.0);

        // Slot 2: 3P slot — stale credentials/2.json from prior OAuth binding
        // plus config-2/settings.json marking it as a 3P endpoint.
        setup_account(dir.path(), 2); // writes credentials/2.json (stale)
        let config_2 = setup_config_dir(dir.path(), 2);
        // Write 3P settings.json to mark this as a 3P slot
        std::fs::write(
            config_2.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.zai.io","ANTHROPIC_AUTH_TOKEN":"k"}}"#,
        )
        .unwrap();
        setup_quota(dir.path(), 2, 10.0);

        let account_1 = AccountNum::try_from(1u16).unwrap();

        // Act: find_target with slot 1 as current (over threshold)
        let target = find_target(dir.path(), account_1, &[]);

        // Assert: slot 2 must be excluded (3P), so no valid target
        assert_eq!(
            target, None,
            "find_target must return None when only remaining candidate is a 3P slot \
             (VP-final R1 CRITICAL: prevents token exfiltration to 3P endpoint)"
        );
    }

    /// round 7c D4: `find_target` must never pick a candidate whose own
    /// canonical token is not Valid (here: expired) — the rotation would
    /// repoint the handle dir's symlinks to an account with no live login,
    /// which `force_sync_account_changed`'s D1 routing would then either
    /// refuse to mirror (leaving the keychain stale) or, pre-D1, silently
    /// strip the keychain item entirely.
    #[test]
    fn find_target_skips_target_with_expired_token() {
        let dir = TempDir::new().unwrap();

        // Slot 1 = current, over threshold, low usage elsewhere makes slot 2
        // attractive on quota grounds alone.
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 97.0);

        // Slot 2: otherwise-eligible candidate, but its OWN identity-keyed
        // canonical token is EXPIRED.
        setup_account(dir.path(), 2);
        setup_config_dir(dir.path(), 2);
        setup_quota(dir.path(), 2, 5.0);
        let uuid2 = crate::accounts::profiles::resolve_slot_to_uuid(dir.path(), 2).unwrap();
        let expired = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at-2-expired".into()),
                refresh_token: RefreshToken::new("rt-2-expired".into()),
                expires_at: 1, // long past
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(
            &crate::accounts::identity_store::credentials_path_for(dir.path(), uuid2),
            &expired,
        )
        .unwrap();

        let account_1 = AccountNum::try_from(1u16).unwrap();
        let target = find_target(dir.path(), account_1, &[]);

        assert_eq!(
            target, None,
            "find_target must skip a candidate whose own canonical token is expired \
             (round 7c D4: only Valid TargetToken candidates are ever chosen)"
        );
    }

    // round 7c D4: a test asserting "`http_get` is never called when the
    // current account has no UUID mapping" was DELIBERATELY NOT added here.
    // Under the hermetic `keychain_mirror_disabled()` guard there are never
    // any live keychain candidates to harvest regardless of whether
    // `reconcile_account` is even invoked, so no hermetic fixture can red
    // against removing the `if let Some(uuid)` guard around the pre-lock
    // harvest call (`instrument-discipline.md` MUST-2 — a mutation that
    // cannot red leaves the claim unresolved, not proven). The guard is a
    // wasted-call optimisation (skip a call already known to return
    // `NoCandidates`), documented at its call site; `tick_resolves_uuid_marker_and_rotates`
    // and the other `tick`-driving tests above already exercise the
    // pre-lock harvest call site end to end (via `tick`'s delegation to
    // `tick_with_http`) for the UUID-mapped case without regressing.

    /// Additional belt-and-suspenders guard: tick skips handle dirs whose
    /// current account is a 3P slot (VP-final F1 secondary check).
    #[test]
    fn tick_skips_handle_dir_when_current_account_is_3p() {
        // Arrange: handle dir bound to slot 9 which is a 3P slot.
        // Slot 1 exists as a low-usage Anthropic account (would be chosen if
        // the rotator didn't bail on the 3P current-account check).
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();

        // Slot 1: Anthropic — available
        setup_account(dir.path(), 1);
        let config_1 = setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);

        // Slot 9: 3P — will be the current slot for the handle dir
        let config_9 = dir.path().join("config-9");
        std::fs::create_dir_all(&config_9).unwrap();
        let acct9 = AccountNum::try_from(9u16).unwrap();
        markers::write_csq_account_legacy(&config_9, acct9).unwrap();
        std::fs::write(
            config_9.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io","ANTHROPIC_AUTH_TOKEN":"k"}}"#,
        )
        .unwrap();
        // Stale credentials/9.json from a prior OAuth binding
        setup_account(dir.path(), 9);
        setup_quota(dir.path(), 9, 97.0);

        // Create handle dir pointing at slot 9
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 30001, 9);

        // Snapshot config-1 creds to verify they are untouched
        let cred_1_path = config_1.join(".credentials.json");
        std::fs::write(&cred_1_path, b"anthropic-slot-1-sentinel").unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert: handle dir still bound to slot 9 (not rotated to slot 1)
        assert_eq!(
            markers::read_csq_account(&handle_dir),
            Some(acct9),
            "tick must skip handle dir when current account is a 3P slot"
        );
        assert!(
            cooldowns.is_empty(),
            "no cooldown should be set when 3P handle dir is skipped"
        );
        // config-1 credentials untouched
        assert_eq!(
            std::fs::read(&cred_1_path).unwrap(),
            b"anthropic-slot-1-sentinel",
            "config-1 creds must not be touched when 3P handle dir is skipped"
        );
    }

    // ── C-F6 (`keychain-fix-r8.md`): rate-limit short-circuit ─────────────

    /// C-F6: once the opportunistic custodian harvest for one handle dir
    /// comes back `RateLimited` within a tick, no LATER handle dir in the
    /// SAME tick may call the custodian again — mirrors `refresher.rs`'s own
    /// `rate_limited_this_tick`. Two handle dirs, both above threshold, both
    /// eligible to rotate to the SAME low-usage target; the scripted
    /// reconcile closure returns `RateLimited` on its first invocation and
    /// records every invocation's account number.
    ///
    /// RED: before this fix, the reconcile call at the harvest call site
    /// ignored its own return value entirely (`let _ = ...`), so a
    /// `RateLimited` outcome from handle dir A never prevented the identical
    /// call for handle dir B — this test's `assert_eq!(calls.len(), 1, ...)`
    /// fails with `calls.len() == 2` against that code (mutation: quoted
    /// below).
    #[test]
    fn tick_honours_rate_limit_across_handle_dirs_in_one_tick() {
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();

        // Slot 1: low-usage Anthropic target both handle dirs will select.
        // `setup_account` seeds the by_slot UUID mapping `find_target`'s
        // HIGH-3 filter and `resolve_slot_to_uuid` both require.
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);

        // Slots 2 and 3: high-usage Anthropic accounts, each with its own
        // live handle dir, both above threshold.
        setup_account(dir.path(), 2);
        setup_config_dir(dir.path(), 2);
        setup_quota(dir.path(), 2, 97.0);
        setup_account(dir.path(), 3);
        setup_config_dir(dir.path(), 3);
        setup_quota(dir.path(), 3, 97.0);

        let handle_a = setup_handle_dir(dir.path(), claude_home.path(), 40001, 2);
        let handle_b = setup_handle_dir(dir.path(), claude_home.path(), 40002, 3);
        let _ = (handle_a, handle_b);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let calls: std::sync::Arc<std::sync::Mutex<Vec<u16>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls_for_closure = std::sync::Arc::clone(&calls);
        let reconcile: ReconcileAccountFn =
            std::sync::Arc::new(move |_base, account, _uuid, _http_get| {
                calls_for_closure.lock().unwrap().push(account.get());
                crate::daemon::custodian::ReconcileOutcome::RateLimited
            });

        let mut cooldowns = HashMap::new();
        // `keychain-fix-r10.md` item 2: a FRESH gate, never the process-wide
        // singleton (`ip_rate_limit_gate()`'s doc — shared with every other
        // test in this binary for its 600s cooldown).
        let gate = crate::daemon::server::harvest_gate::new_ip_rate_limit_gate();
        tick_with_reconcile_for_test(
            dir.path(),
            Some(claude_home.path()),
            &mut cooldowns,
            &reconcile,
            &gate,
        );

        // `keychain-fix-r10.md` C-B1/S-L-5: this tick's OWN observed
        // RateLimited must also mark the shared gate, so a later refresher
        // tick / on-demand harvest / auto-rotate tick short-circuits too
        // instead of independently rediscovering the same 429.
        assert!(
            crate::daemon::server::harvest_gate::gate_is_rate_limited(&gate),
            "a RateLimited outcome observed by auto_rotate must mark the shared gate"
        );

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(
            recorded.len(),
            1,
            "exactly one handle dir's reconcile call should run this tick \
             once the first comes back RateLimited; got {recorded:?}"
        );
    }

    /// `keychain-fix-r10.md` item 2, C-B1/S-L-5 — the CONSUMER half: a gate
    /// already marked BEFORE this tick starts (e.g. by the refresher's own
    /// custodian call, or by `daemon::server::run_with`'s on-demand harvest)
    /// must suppress this tick's opportunistic harvest entirely — the
    /// injected `reconcile` closure must never be invoked, for ANY handle
    /// dir.
    ///
    /// RED: dropping the `if !rate_limited_this_tick` guard around the
    /// harvest call site (i.e. always calling `reconcile` regardless of the
    /// seeded gate) makes `calls.lock().unwrap().len()` come back `1`
    /// instead of the required `0`.
    #[test]
    fn tick_pre_marked_gate_suppresses_harvest_entirely() {
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();

        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);
        setup_account(dir.path(), 2);
        setup_config_dir(dir.path(), 2);
        setup_quota(dir.path(), 2, 97.0);

        let handle_a = setup_handle_dir(dir.path(), claude_home.path(), 40011, 2);
        let _ = handle_a;

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let calls: std::sync::Arc<std::sync::Mutex<Vec<u16>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls_for_closure = std::sync::Arc::clone(&calls);
        let reconcile: ReconcileAccountFn =
            std::sync::Arc::new(move |_base, account, _uuid, _http_get| {
                calls_for_closure.lock().unwrap().push(account.get());
                crate::daemon::custodian::ReconcileOutcome::NoCandidates
            });

        // Fresh gate, pre-marked BEFORE the tick — simulating a 429 the
        // refresher (or an on-demand harvest) already observed this cycle.
        let gate = crate::daemon::server::harvest_gate::new_ip_rate_limit_gate();
        crate::daemon::server::harvest_gate::gate_mark_rate_limited(&gate);

        let mut cooldowns = HashMap::new();
        tick_with_reconcile_for_test(
            dir.path(),
            Some(claude_home.path()),
            &mut cooldowns,
            &reconcile,
            &gate,
        );

        assert!(
            calls.lock().unwrap().is_empty(),
            "a pre-marked gate must suppress the opportunistic harvest call entirely"
        );
    }

    // ── VP-final F2: cooldown canonicalization ────────────────────────────

    /// Regression guard: VP-final F2.
    ///
    /// If the base_dir is accessed via a symlinked path alias (e.g. macOS
    /// /var/folders/... vs /private/var/folders/...), `entry.path()` returns
    /// a path under the alias. Without canonicalization the cooldowns HashMap
    /// would have two independent entries for the same physical directory.
    ///
    /// First rotate through an actual base alias and assert the exact canonical
    /// cooldown key. Then make the reverse rotation eligible and tick through the
    /// physical base: the marker and complete cooldown map must remain unchanged.
    #[cfg(unix)]
    #[test]
    fn cooldown_key_canonicalizes_symlinked_base_dir() {
        let real_dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        let aliases = TempDir::new().unwrap();
        let alias = aliases.path().join("accounts-alias");
        std::os::unix::fs::symlink(real_dir.path(), &alias).unwrap();

        setup_account(real_dir.path(), 1);
        setup_account(real_dir.path(), 2);
        setup_quota(real_dir.path(), 1, 97.0);
        setup_quota(real_dir.path(), 2, 10.0);
        setup_config_dir(real_dir.path(), 1);
        setup_config_dir(real_dir.path(), 2);
        // M3-4 HIGH-3: slot 2 is the rotation candidate; needs UUID.
        setup_slot_uuid(real_dir.path(), 2);
        let handle_dir = setup_handle_dir(real_dir.path(), claude_home.path(), 30002, 1);
        let canonical_handle = handle_dir.canonicalize().unwrap();
        assert_ne!(alias.join("term-30002"), canonical_handle);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 3600, // 1-hour cooldown — won't expire during test
            ..RotationConfig::default()
        };
        save_rotation_config(real_dir.path(), &cfg).unwrap();

        // First tick: handle dir should rotate (above threshold) and one
        // cooldown entry should be stored with the CANONICAL path as key.
        let mut cooldowns = HashMap::new();
        tick(&alias, Some(claude_home.path()), &mut cooldowns);

        assert_eq!(
            cooldowns.len(),
            1,
            "cooldown map must have exactly one entry after first tick"
        );

        assert!(
            cooldowns.contains_key(&canonical_handle),
            "first tick must store the exact canonical handle key"
        );
        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        assert_eq!(
            markers::resolve_marker_to_slot(real_dir.path(), &handle_dir),
            Some(account2),
            "first tick must successfully rotate to account 2"
        );
        let marker = handle_dir.join(".csq-account");
        let marker_target = std::fs::read_link(&marker).unwrap();
        let marker_bytes = std::fs::read(&marker).unwrap();
        let cooldowns_before = cooldowns.clone();

        // Second tick: even if the handle dir's account (now 2) is above
        // threshold again, the 1-hour cooldown must block re-rotation.
        setup_quota(real_dir.path(), 2, 98.0);
        setup_quota(real_dir.path(), 1, 5.0);

        assert_eq!(
            find_target(real_dir.path(), account2, &cfg.exclude_accounts).map(|pair| pair.0),
            Some(account1),
            "without cooldown the second tick must have an eligible reverse rotation"
        );
        tick(real_dir.path(), Some(claude_home.path()), &mut cooldowns);

        assert_eq!(
            markers::resolve_marker_to_slot(real_dir.path(), &handle_dir),
            Some(account2),
            "cooldown through the physical base must prevent a second rotation"
        );
        assert_eq!(std::fs::read_link(&marker).unwrap(), marker_target);
        assert_eq!(std::fs::read(&marker).unwrap(), marker_bytes);
        assert_eq!(
            cooldowns, cooldowns_before,
            "second tick must preserve the exact canonical key and first rotation instant"
        );
    }

    #[test]
    fn contained_handle_dir_refuses_base_itself_missing_nonterm_and_file() {
        let root = TempDir::new().unwrap();
        let base = root.path().join("term-base");
        std::fs::create_dir(&base).unwrap();
        let base = base.canonicalize().unwrap();
        assert!(contained_handle_dir(&base, &base).is_none());
        assert!(contained_handle_dir(&base, &base.join("term-missing")).is_none());
        std::fs::create_dir(base.join("not-a-handle")).unwrap();
        assert!(contained_handle_dir(&base, &base.join("not-a-handle")).is_none());
        std::fs::write(base.join("term-file"), b"synthetic test input").unwrap();
        assert!(contained_handle_dir(&base, &base.join("term-file")).is_none());
        std::fs::create_dir(base.join("term-valid")).unwrap();
        assert_eq!(
            contained_handle_dir(&base, &base.join("term-valid")),
            Some(base.join("term-valid"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn contained_handle_dir_refuses_base_alias_and_dangling_symlink() {
        let root = TempDir::new().unwrap();
        let base = root.path().join("term-base");
        std::fs::create_dir(&base).unwrap();
        let base = base.canonicalize().unwrap();
        std::os::unix::fs::symlink(&base, base.join("term-self")).unwrap();
        std::os::unix::fs::symlink(root.path().join("absent"), base.join("term-dangling")).unwrap();
        assert!(contained_handle_dir(&base, &base.join("term-self")).is_none());
        assert!(contained_handle_dir(&base, &base.join("term-dangling")).is_none());
        assert!(!root.path().join("absent").exists());
    }

    #[cfg(unix)]
    #[test]
    fn tick_refuses_scanned_symlink_escaping_base_before_side_effects() {
        use std::collections::BTreeMap;
        // All paths and all credential-shaped bytes are synthetic TEST INPUT.
        // cfg(test) disables host keychain reads/deletes/writes independently of HOME.
        let root = TempDir::new().unwrap();
        let base = root.path().join("accounts");
        // A string-prefix sibling must not count as component-wise containment.
        let outside = root.path().join("accounts-sibling").join("term-9000");
        let claude_home = root.path().join("claude-home");
        for dir in [&base, &outside, &claude_home] {
            std::fs::create_dir_all(dir).unwrap();
        }
        setup_account(&base, 1);
        setup_account(&base, 2);
        setup_quota(&base, 1, 97.0);
        setup_quota(&base, 2, 10.0);
        let config1 = setup_config_dir(&base, 1);
        setup_config_dir(&base, 2);
        setup_slot_uuid(&base, 2);
        std::os::unix::fs::symlink(config1.join(".csq-account"), outside.join(".csq-account"))
            .unwrap();
        std::os::unix::fs::symlink(
            base.join("credentials/1.json"),
            outside.join(".credentials.json"),
        )
        .unwrap();
        std::fs::write(outside.join("settings.json"), b"{}").unwrap();
        std::fs::write(outside.join(".claude.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&outside, base.join("term-9000")).unwrap();
        save_rotation_config(
            &base,
            &RotationConfig {
                enabled: true,
                threshold_percent: 95.0,
                ..RotationConfig::default()
            },
        )
        .unwrap();
        let current = AccountNum::try_from(1u16).unwrap();
        assert_eq!(
            markers::resolve_marker_to_slot(&base, &outside),
            Some(current)
        );
        assert!(!handle_dir_is_3p(&base, current));
        assert_eq!(
            find_target(&base, current, &[]).map(|(slot, _)| slot),
            Some(AccountNum::try_from(2u16).unwrap())
        );

        // Snapshot immediate entries without following symlinks. Comparing the
        // directory mtime also catches create/remove side effects with no leftovers.
        let snapshot = || {
            std::fs::read_dir(&outside)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let meta = std::fs::symlink_metadata(&path).unwrap();
                    let (link, bytes) = if meta.file_type().is_symlink() {
                        (Some(std::fs::read_link(&path).unwrap()), None)
                    } else {
                        assert!(meta.is_file());
                        (None, Some(std::fs::read(&path).unwrap()))
                    };
                    (path, (link, bytes, meta.modified().unwrap()))
                })
                .collect::<BTreeMap<_, _>>()
        };
        let before = snapshot();
        let before_mtime = std::fs::metadata(&outside).unwrap().modified().unwrap();
        let mut cooldowns = HashMap::new();
        tick(&base, Some(&claude_home), &mut cooldowns);
        assert_eq!(
            snapshot(),
            before,
            "outside entries must not be rebound or touched"
        );
        assert_eq!(
            std::fs::metadata(&outside).unwrap().modified().unwrap(),
            before_mtime
        );
        for name in [
            ".swap-lock",
            ".swap.lock",
            ".csq-account.swap-tmp",
            ".credentials.json.swap-tmp",
        ] {
            assert!(
                std::fs::symlink_metadata(outside.join(name)).is_err(),
                "no outside lock or temporary publication"
            );
        }
        assert!(
            cooldowns.is_empty(),
            "foreign handle must not gain a cooldown"
        );
    }

    // ── PR-C9a CRITICAL: auto-rotate must never fire on a Codex handle dir ─

    /// Builds a minimal Codex slot on disk: `credentials/codex-<N>.json`,
    /// `config-<N>/.csq-account`, and `config-<N>/config.toml` (required by
    /// `create_handle_dir_codex` so the symlink set contains the Codex
    /// shape that `repoint_handle_dir`'s guard watches for).
    fn setup_codex_slot(base: &Path, account: u16) {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile};
        let acct = AccountNum::try_from(account).unwrap();

        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some(format!("uuid-{account}")),
                access_token: format!("eyJaccess.codex-{account}.sig"),
                refresh_token: Some(format!("rt_codex_{account}")),
                id_token: Some(format!("eyJid.codex-{account}.sig")),
                extra: HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: HashMap::new(),
        });
        let cred_path = base
            .join("credentials")
            .join(format!("codex-{account}.json"));
        credentials::save(&cred_path, &creds).unwrap();

        let config_dir = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        markers::write_csq_account_legacy(&config_dir, acct).unwrap();
        // Minimal config.toml so create_handle_dir_codex's symlink target
        // exists (create_handle_dir_codex silently skips missing targets,
        // but the Codex-shape guard in repoint_handle_dir keys on
        // `auth.json` and `config.toml` existing as symlinks).
        std::fs::write(
            config_dir.join("config.toml"),
            "cli_auth_credentials_store = \"file\"\nmodel = \"gpt-5.4\"\n",
        )
        .unwrap();
    }

    /// Regression guard: an internal journal entry finding 1 (CRITICAL).
    ///
    /// A handle dir bound to a Codex slot MUST NOT be rotated by the
    /// auto-rotater. Pre-fix, `find_target` used `discover_anthropic`,
    /// so `active_surface` fell back to `Surface::ClaudeCode` for a
    /// Codex-bound handle dir; same-surface filter admitted ClaudeCode
    /// candidates; repoint_handle_dir then corrupted the Codex handle
    /// dir's ACCOUNT_BOUND_ITEMS while leaving the Codex symlinks
    /// (`auth.json`, `config.toml`, `sessions`, `history.jsonl`) pointing
    /// at the old config-<N>. This test pins the fix: a Codex handle dir
    /// under quota pressure MUST NOT be rotated, regardless of how
    /// tempting the ClaudeCode candidates look.
    #[cfg(unix)]
    #[test]
    fn auto_rotate_refuses_to_rotate_codex_handle_dir() {
        use crate::session::handle_dir::create_handle_dir_codex;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();

        // Codex slot 5, "over threshold" by any reasonable reading of
        // the 5h window: populate quota.json so the tick DOES think it
        // should rotate (i.e. pre-fix it would have tried).
        setup_codex_slot(dir.path(), 5);
        setup_quota(dir.path(), 5, 99.0);

        // Tempting ClaudeCode candidate at slot 1 (low usage). Pre-fix
        // the rotator would have picked this one.
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);

        // Create a Codex handle dir bound to slot 5.
        let acct5 = AccountNum::try_from(5u16).unwrap();
        let handle_dir = create_handle_dir_codex(dir.path(), acct5, 40001).unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Act
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // Assert 1: the handle dir is still bound to slot 5 via its
        // .csq-account symlink. (In the Codex handle-dir layout,
        // `.csq-account` symlinks to `config-<N>/.csq-account`.)
        let marker = markers::read_csq_account(&handle_dir);
        assert_eq!(
            marker,
            Some(acct5),
            "Codex handle dir MUST NOT be rotated by auto-rotate \
             (v2.1 scope: Codex requires explicit csq swap)"
        );

        // Assert 2: no cooldown entry was recorded (the skip happened
        // before the repoint attempt).
        assert!(
            cooldowns.is_empty(),
            "no cooldown entry should be set when tick skips a Codex handle dir"
        );

        // Assert 3: the Codex symlink set is intact — `auth.json`,
        // `config.toml` still present (would have been left dangling
        // pre-fix if repoint had rewritten the ClaudeCode-shape items).
        assert!(
            handle_dir.join("auth.json").symlink_metadata().is_ok(),
            "Codex auth.json symlink must survive the tick"
        );
        assert!(
            handle_dir.join("config.toml").symlink_metadata().is_ok(),
            "Codex config.toml symlink must survive the tick"
        );
    }

    /// Regression guard: an internal journal entry finding 1 second half.
    ///
    /// `find_target` must return `None` for a Codex current account
    /// regardless of what candidates exist. Before the fix, a Codex
    /// current account falling back to `Surface::ClaudeCode` would
    /// let same-surface filter admit Claude slots.
    #[test]
    fn find_target_returns_none_for_codex_current_account() {
        let dir = TempDir::new().unwrap();

        // Codex slot 3 as the current account.
        setup_codex_slot(dir.path(), 3);
        setup_quota(dir.path(), 3, 99.0);

        // Tempting ClaudeCode candidate at slot 1.
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 5.0);

        let acct3 = AccountNum::try_from(3u16).unwrap();
        let target = find_target(dir.path(), acct3, &[]);

        assert_eq!(
            target, None,
            "find_target MUST return None when current account is non-ClaudeCode \
             (auto-rotate is ClaudeCode-only in v2.1)"
        );
    }

    /// Regression guard: Codex slot must not be picked as a ClaudeCode
    /// rotation target. Prior to PR-C9a, `discover_anthropic` excluded
    /// Codex — but the fix switches `find_target` to `discover_all`,
    /// which now includes Codex accounts. This test pins the invariant
    /// that the same-surface filter correctly drops Codex candidates
    /// when the current handle dir is on ClaudeCode.
    #[test]
    fn find_target_skips_codex_candidates_for_claudecode_current() {
        let dir = TempDir::new().unwrap();

        // Current: ClaudeCode slot 1 (over threshold).
        setup_account(dir.path(), 1);
        setup_config_dir(dir.path(), 1);
        setup_quota(dir.path(), 1, 99.0);

        // Only candidate: Codex slot 2 (would be tempting if ClaudeCode
        // candidates were missing).
        setup_codex_slot(dir.path(), 2);
        setup_quota(dir.path(), 2, 5.0);

        let acct1 = AccountNum::try_from(1u16).unwrap();
        let target = find_target(dir.path(), acct1, &[]);

        assert_eq!(
            target, None,
            "Codex candidate must not be picked for a ClaudeCode handle dir \
             (INV-P11 same-surface filter)"
        );
    }

    // ── M3-4 HIGH-3 acceptance criteria tests ────────────────────────────────

    /// M3-4 AC7: `find_target` returns an `(AccountNum, IdentityId)` tuple when
    /// a valid UUID-keyed candidate is available.
    ///
    /// Confirms the HIGH-3 fix: the selection-view and repoint-view share ONE
    /// UUID resolution.  The returned `IdentityId` must match the UUID that
    /// `setup_slot_uuid` registered for slot 2.
    #[test]
    fn auto_rotate_find_target_returns_account_and_identity_tuple() {
        use crate::accounts::profiles;

        // Arrange: slot 1 over threshold (current), slot 2 low-usage candidate.
        let dir = TempDir::new().unwrap();

        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);

        // Register a UUID for slot 2 so it passes the HIGH-3 UUID filter.
        let uuid2 = setup_slot_uuid(dir.path(), 2);

        let account1 = AccountNum::try_from(1u16).unwrap();

        // Act
        let result = find_target(dir.path(), account1, &[]);

        // Assert: returns Some((slot-2, uuid-for-slot-2))
        let (picked_account, picked_identity) = result
            .expect("AC7: find_target must return Some when a UUID-keyed candidate is available");
        assert_eq!(
            picked_account.get(),
            2,
            "AC7: find_target must pick slot 2 (lowest usage non-exhausted candidate)"
        );
        assert_eq!(
            picked_identity, uuid2,
            "AC7: returned IdentityId must match the UUID registered for slot 2 \
             (proves selection-view and repoint-view share ONE UUID resolution)"
        );

        // Also confirm the UUID is queryable from profiles.json — proves the
        // returned identity is the profiles-keyed one, not a fabricated value.
        let from_profiles = profiles::resolve_slot_to_uuid(dir.path(), 2);
        assert_eq!(
            from_profiles.as_ref(),
            Some(&uuid2),
            "AC7: returned IdentityId must match profiles.json::by_slot[2]"
        );
    }

    /// M3-4 AC8: `find_target` skips candidates that have no UUID in
    /// `profiles.json::by_slot` (legacy-only or Partial-Pass-0 state).
    ///
    /// The HIGH-3 filter prevents the TOCTOU race where a candidate is selected
    /// without a UUID, then `repoint_handle_dir` cannot resolve the UUID at
    /// repoint time and either silently falls back or targets a non-existent path.
    #[test]
    fn auto_rotate_find_target_skips_candidates_with_unresolvable_uuid() {
        // Arrange: slot 1 over threshold (current), slot 2 has NO UUID in
        // profiles.json (legacy-only state). No valid candidate exists.
        //
        // Post-M4-4: slot 1 needs by_slot + identity-keyed credentials so
        // it's discoverable as the current slot. Slot 2 uses
        // `setup_account_legacy_only` so it has NO by_slot entry — the
        // M3-4 HIGH-3 UUID filter is exercised when the candidate appears
        // in the legacy fallback branch but lacks a UUID at find_target
        // resolution time.
        let dir = TempDir::new().unwrap();

        setup_account(dir.path(), 1);
        setup_account_legacy_only(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        // Deliberately NOT calling setup_slot_uuid for slot 2:
        // no profiles.json entry → resolve_slot_to_uuid returns None.

        let account1 = AccountNum::try_from(1u16).unwrap();

        // Act
        let result = find_target(dir.path(), account1, &[]);

        // Assert: returns None — slot 2 was filtered out by the UUID check.
        assert_eq!(
            result, None,
            "AC8 HIGH-3: find_target must return None when the only candidate \
             has no resolvable UUID (prevents TOCTOU race between selection and repoint)"
        );
    }

    // ── v5 "keychain follows the links" + S-M2 re-check tests ──────────

    /// Required test (e) (round-5b brief): a PERSISTENT repoint failure
    /// (the S7 pre-flight refusal — a real file blocks an
    /// `ACCOUNT_BOUND_ITEMS` symlink) sets a cooldown, and a second tick
    /// WITHIN that cooldown window does not retry the repoint even after
    /// the blocking condition is removed — proving the cooldown, not the
    /// blocker, is what prevented the second attempt.
    #[test]
    fn tick_persistent_repoint_failure_sets_cooldown_second_tick_does_not_retry() {
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir_uuid(dir.path(), 1);
        setup_config_dir_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 40001, 1);

        // Trip the S7 pre-flight refusal: place a REAL file at
        // `.current-account` where `repoint_handle_dir` expects an
        // `ACCOUNT_BOUND_ITEMS` symlink (mirrors
        // `repoint_handle_dir_refuses_when_item_is_a_real_file_not_symlink`
        // in `session::handle_dir`'s own tests). `.current-account` is not
        // guaranteed to exist yet at handle-dir-creation time (K1: written
        // later by the first quota poll or a swap from elsewhere), so the
        // pre-emptive removal is best-effort.
        let _ = std::fs::remove_file(handle_dir.join(".current-account"));
        std::fs::write(handle_dir.join(".current-account"), "blocking real file").unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        // First tick: repoint refused, cooldown MUST be set, marker unchanged.
        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "first tick: repoint refused, still on account 1"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            cooldowns.contains_key(&canonical_handle),
            "a persistent repoint failure must set the cooldown (D-F3)"
        );

        // Remove the blocker and restore a proper symlink to config-1's own
        // `.current-account` (creating that target file if it doesn't
        // already exist) — if cooldown were NOT respected, the second tick
        // would now succeed and rotate to account 2.
        std::fs::remove_file(handle_dir.join(".current-account")).unwrap();
        let config_1_current = dir.path().join("config-1").join(".current-account");
        if !config_1_current.exists() {
            std::fs::write(&config_1_current, "1").unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&config_1_current, handle_dir.join(".current-account")).unwrap();

        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "second tick, within the cooldown window: must NOT retry the \
             repoint even though the blocker is now gone — the cooldown is \
             what prevented it, not the (now-absent) blocker"
        );
    }

    /// Lock-timeout cooldown parity: a `BoundedLockOutcome::Failed` (this
    /// test forces it deterministically — no waiting on the real ~20s
    /// bound) is a failure arm exactly like the keychain-read-failure and
    /// repoint-failure arms, and MUST set the same per-handle-dir cooldown
    /// they do — before this fix it was the ONLY failure arm that did not,
    /// so a persistent lock-acquire failure (a broken `.swap-lock` path, or
    /// another process that never releases it) spun the full bounded wait
    /// on every single tick with no backoff.
    ///
    /// Forces `Failed` (not `TimedOut`) by pre-creating `.swap-lock` as a
    /// DIRECTORY: `lock_bounded_with_params`'s `open_lock_file` opens with
    /// `O_CREAT`, which fails immediately with `EISDIR` against a directory
    /// — no polling, no 20s wait.
    #[test]
    #[cfg(target_os = "macos")]
    fn tick_lock_acquire_failure_sets_cooldown() {
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir_uuid(dir.path(), 1);
        setup_config_dir_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 40005, 1);

        // Force `lock_handle_dir_for_swap_bounded` to return `Failed`
        // immediately: `.swap-lock` exists as a directory, so opening it
        // as a lock file fails with EISDIR rather than blocking.
        //
        // `keychain-fix-r11.md` S-MEDIUM-1/D-4: `setup_handle_dir` ->
        // `create_handle_dir` now itself acquires (and releases) the
        // per-dir swap lock during creation, to resolve any stale
        // pending-clear entry for a reused PID's service — the lock
        // acquire/release leaves `.swap-lock` on disk as a FILE (flock does
        // not delete its lock file on release), so a bare `create_dir`
        // here would fail with `AlreadyExists` rather than the intended
        // `EISDIR`. Remove it first so this test's own directory-shaped
        // `.swap-lock` is what `lock_handle_dir_for_swap_bounded` actually
        // opens.
        let _ = std::fs::remove_file(handle_dir.join(".swap-lock"));
        std::fs::create_dir(handle_dir.join(".swap-lock")).unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "lock-acquire failure: nothing mutated, still on account 1"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            cooldowns.contains_key(&canonical_handle),
            "a lock-acquire failure must set the cooldown just like every \
             other failure arm (D-F3 parity) — before this fix it did not"
        );
    }

    /// T1: signals the mutator thread (already blocked on `go_rx`, already
    /// holding the per-dir swap lock) to perform its mutation and release
    /// the lock, from INSIDE `tick`'s pre-lock-decision hook. Registers the
    /// hook, does NOT wait for the mutator to finish (fire-and-forget —
    /// `tick`'s own bounded lock-acquire loop is what blocks until the
    /// mutator's `drop(guard)` releases it, so ordering is guaranteed by
    /// the lock itself, not by a timing guess). Resets the hook to `None`
    /// after `tick` returns so it never leaks into a later test. Only
    /// called by the three `#[cfg(target_os = "macos")]` tests below (the
    /// lock they synchronize on is itself a no-op on non-macOS —
    /// `lock_handle_dir_for_swap_bounded`'s `NotNeeded` stub), so this
    /// helper is macOS-only too, else it is dead code elsewhere.
    #[cfg(target_os = "macos")]
    fn set_pre_lock_go_signal(go_tx: std::sync::mpsc::Sender<()>) {
        set_pre_lock_test_hook_for_test(Some(Box::new(move || {
            let _ = go_tx.send(());
        })));
    }

    /// Required test (c) (round-5b brief): the account this handle dir is
    /// bound to CHANGES while `tick` waits on the per-dir lock (S-M2). The
    /// re-check after lock acquisition must see the NEW marker and skip —
    /// no write, no cooldown insert (nothing was attempted).
    ///
    /// T1: no sleep — the mutator thread is spawned already holding the
    /// per-dir lock and blocked on `go_rx.recv()`; `tick`'s pre-lock-test
    /// hook (fired right after tick's own pre-lock decision, before its
    /// bounded lock attempt) sends the "go" signal. `tick`'s bounded
    /// lock-acquire loop then genuinely blocks until the mutator's
    /// `drop(guard)` releases it — the lock itself, not a sleep duration,
    /// is what orders "mutation happens before tick's post-lock re-check".
    #[test]
    #[cfg(target_os = "macos")]
    fn tick_marker_changes_while_waiting_for_lock_skips_no_write() {
        use crate::credentials::keychain::lock_handle_dir_for_swap;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_account(dir.path(), 3);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_quota(dir.path(), 3, 10.0);
        setup_config_dir_uuid(dir.path(), 1);
        setup_config_dir_uuid(dir.path(), 2);
        setup_config_dir_uuid(dir.path(), 3);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 40002, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        // Acquire the SAME per-dir lock `tick` will bounded-wait on, on
        // THIS thread, before `tick` is ever called — guarantees the
        // contention this test exists to exercise.
        let guard = lock_handle_dir_for_swap(&handle_dir).expect("acquire the swap lock");
        let base = dir.path().to_path_buf();
        let claude_home_path = claude_home.path().to_path_buf();
        let hd = handle_dir.clone();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let mutator = std::thread::spawn(move || {
            // Simulates a `csq swap` in this same terminal landing while
            // this tick waits for the lock: wait for tick's pre-lock
            // decision to fire (proving it used the STALE account-1 view),
            // then move the marker to account 3 and release the lock.
            go_rx.recv().expect("pre-lock hook must signal go");
            crate::session::handle_dir::repoint_handle_dir(
                &base,
                &claude_home_path,
                &hd,
                AccountNum::try_from(3u16).unwrap(),
            )
            .expect("repoint to account 3 while this thread holds the lock");
            drop(guard);
        });
        set_pre_lock_go_signal(go_tx);

        // Call `tick` CONCURRENTLY with the mutator — it must block/poll on
        // the still-held lock until the mutator above releases it.
        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
        set_pre_lock_test_hook_for_test(None);

        mutator.join().expect("mutator thread must not panic");

        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(3u16).unwrap()),
            "S-M2: tick must see the marker as it is NOW (account 3, moved \
             while tick waited for the lock) and skip — never overwrite the \
             swap that just happened"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            !cooldowns.contains_key(&canonical_handle),
            "S-M2 skip performs NO mutation, so it must not set a cooldown either"
        );
    }

    /// Required test (d) (round-5b brief): the handle dir's slot is
    /// rebound to a 3P provider WHILE `tick` waits on the per-dir lock
    /// (S-M2). The post-lock re-check must see the slot is now 3P and
    /// skip — auto-rotation must never force-write an Anthropic OAuth
    /// token toward a slot whose `ANTHROPIC_BASE_URL` now points at a 3P
    /// endpoint.
    ///
    /// T1: see `tick_marker_changes_while_waiting_for_lock_skips_no_write`'s
    /// doc for why this is signal-based rather than sleep-based.
    #[test]
    #[cfg(target_os = "macos")]
    fn tick_slot_becomes_3p_while_waiting_for_lock_skips() {
        use crate::credentials::keychain::lock_handle_dir_for_swap;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        let config_1 = setup_config_dir_uuid(dir.path(), 1);
        setup_config_dir_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 40003, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let guard = lock_handle_dir_for_swap(&handle_dir).expect("acquire the swap lock");
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let mutator = std::thread::spawn(move || {
            // Simulates the CURRENT slot (1) being rebound to a 3P
            // provider (e.g. `csq setkey` or a provider bind) while this
            // tick waits for the lock.
            go_rx.recv().expect("pre-lock hook must signal go");
            std::fs::write(
                config_1.join("settings.json"),
                r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io","ANTHROPIC_AUTH_TOKEN":"k"}}"#,
            )
            .unwrap();
            drop(guard);
        });
        set_pre_lock_go_signal(go_tx);

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
        set_pre_lock_test_hook_for_test(None);

        mutator.join().expect("mutator thread must not panic");

        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "S-M2: slot flipped to 3P while waiting for the lock — tick must \
             skip, never repoint/force-write toward it"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            !cooldowns.contains_key(&canonical_handle),
            "S-M2 3P-flip skip performs NO mutation, so it must not set a cooldown either"
        );
    }

    /// H2: `find_target` chose the rotation TARGET (slot 2) BEFORE the
    /// bounded lock — the SAME stale-decision window S-M2 already re-checks
    /// for the CURRENT account applies to the TARGET too. A concurrent
    /// rebind of the TARGET to a 3P provider while `tick` waits for the
    /// lock must be caught by the post-lock re-check and skip — rotating
    /// TOWARD a slot whose `ANTHROPIC_BASE_URL` now points at a 3P endpoint
    /// would force-write an Anthropic OAuth token at that endpoint.
    ///
    /// T1: see `tick_marker_changes_while_waiting_for_lock_skips_no_write`'s
    /// doc for why this is signal-based rather than sleep-based.
    #[test]
    #[cfg(target_os = "macos")]
    fn tick_rotation_target_becomes_3p_while_waiting_for_lock_skips() {
        use crate::credentials::keychain::lock_handle_dir_for_swap;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir_uuid(dir.path(), 1);
        let config_2 = setup_config_dir_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 40004, 1);

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let guard = lock_handle_dir_for_swap(&handle_dir).expect("acquire the swap lock");
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let mutator = std::thread::spawn(move || {
            // Simulates the TARGET slot (2, chosen by the pre-lock
            // `find_target`) being rebound to a 3P provider while this
            // tick waits for the lock — e.g. a concurrent `csq setkey 2`.
            go_rx.recv().expect("pre-lock hook must signal go");
            std::fs::write(
                config_2.join("settings.json"),
                r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io","ANTHROPIC_AUTH_TOKEN":"k"}}"#,
            )
            .unwrap();
            drop(guard);
        });
        set_pre_lock_go_signal(go_tx);

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
        set_pre_lock_test_hook_for_test(None);

        mutator.join().expect("mutator thread must not panic");

        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "H2: the ROTATION TARGET flipped to 3P while waiting for the lock \
             — tick must skip, never repoint/force-write toward it"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            !cooldowns.contains_key(&canonical_handle),
            "H2 target-3P-flip skip performs NO mutation, so it must not set a cooldown either"
        );
    }

    /// C-F2 (`keychain-fix-r8.md`): `find_target` chose the rotation TARGET
    /// (slot 2) as `Valid` BEFORE the bounded lock — the same stale-decision
    /// window H2 already re-checks for a 3P flip applies equally to the
    /// target's OWN token going from Valid to expired while `tick` waits for
    /// the lock (a concurrent refresh failure, or a `csq logout 2` landing
    /// in that window). The post-lock re-check must refuse the rotation
    /// (skip + cooldown) rather than let `force_swap_write_before_repoint`
    /// see `None` and treat the target as though it were POSITIVELY
    /// non-Anthropic (`Intended::Strip`'s contract) — no delete, no repoint.
    ///
    /// T1: see `tick_marker_changes_while_waiting_for_lock_skips_no_write`'s
    /// doc for why this is signal-based rather than sleep-based.
    #[test]
    #[cfg(target_os = "macos")]
    fn tick_rotation_target_token_expires_while_waiting_for_lock_refuses() {
        use crate::credentials::keychain::lock_handle_dir_for_swap;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 97.0);
        setup_quota(dir.path(), 2, 10.0);
        setup_config_dir_uuid(dir.path(), 1);
        setup_config_dir_uuid(dir.path(), 2);
        let handle_dir = setup_handle_dir(dir.path(), claude_home.path(), 40006, 1);
        let uuid2 = crate::accounts::profiles::resolve_slot_to_uuid(dir.path(), 2).unwrap();

        let cfg = RotationConfig {
            enabled: true,
            threshold_percent: 95.0,
            cooldown_secs: 300,
            ..RotationConfig::default()
        };
        save_rotation_config(dir.path(), &cfg).unwrap();

        let guard = lock_handle_dir_for_swap(&handle_dir).expect("acquire the swap lock");
        let base = dir.path().to_path_buf();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let mutator = std::thread::spawn(move || {
            // Simulates the TARGET slot's (2, chosen Valid by the pre-lock
            // `find_target`) own canonical token expiring — e.g. a
            // concurrent refresh failure or `csq logout 2` — while this
            // tick waits for the lock.
            go_rx.recv().expect("pre-lock hook must signal go");
            let expired = CredentialFile::Anthropic(AnthropicCredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: AccessToken::new("at-2-expired-under-lock".into()),
                    refresh_token: RefreshToken::new("rt-2-expired-under-lock".into()),
                    expires_at: 1, // long past
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: HashMap::new(),
                },
                extra: HashMap::new(),
            });
            credentials::save(
                &crate::accounts::identity_store::credentials_path_for(&base, uuid2),
                &expired,
            )
            .unwrap();
            drop(guard);
        });
        set_pre_lock_go_signal(go_tx);

        let mut cooldowns = HashMap::new();
        tick(dir.path(), Some(claude_home.path()), &mut cooldowns);
        set_pre_lock_test_hook_for_test(None);

        mutator.join().expect("mutator thread must not panic");

        assert_eq!(
            markers::resolve_marker_to_slot(dir.path(), &handle_dir),
            Some(AccountNum::try_from(1u16).unwrap()),
            "C-F2: the ROTATION TARGET's own token expired while waiting for \
             the lock — tick must refuse, never repoint/strip toward it"
        );
        let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
        assert!(
            cooldowns.contains_key(&canonical_handle),
            "C-F2 refusal is a genuine failure arm (like a lock-acquire \
             failure) and MUST set the cooldown so this dir is not retried \
             every single tick"
        );
    }

    // ── C-F7 rotation half (`keychain-fix-r8.md`/`keychain-fix-r8c.md`):
    // auto_rotate mirrors of the swap-level (a)/(b)/(d) scripted-executor
    // tests in `csq/src/cli/commands/swap.rs`'s `handle_e2e` module ────────
    //
    // `ScriptedKeychainExecutor` covers X's OWN item — the `find`/`add`
    // calls `force_swap_write_before_repoint`/`reconcile_keychain_to_marker`
    // make — NOT the opportunistic pre-lock harvest scan
    // (`harvest_account_candidates`), which reads via `run_security_bounded`
    // directly with no test seam at all (COMMON.md's "never call real
    // `security`" hard limit). Every test below therefore uses the real
    // `tick()` entry point (not `tick_with_reconcile_for_test`): the
    // handle dir's PID is a made-up test value, never a live process, so
    // `harvest_account_candidates`' `kill(pid, 0)` liveness check finds it
    // dead and the harvest scan returns zero candidates without ever
    // reaching `read_raw_keychain` — the SAME reason the other ~30 tests in
    // this file already call `tick()` safely on both macOS and Linux CI.
    #[cfg(target_os = "macos")]
    mod scripted_executor_tests {
        use super::*;
        use crate::credentials::keychain::{
            clear_test_keychain_executor, set_test_keychain_executor, RawContentClassification,
            ScriptedKeychainExecutor,
        };
        use std::rc::Rc;

        /// Clears the thread-local executor override on drop (mirrors
        /// `swap.rs`'s `handle_e2e::ExecutorGuard`) so a panicking assertion
        /// in one test can never leak a scripted executor into the next
        /// test on the same worker thread.
        struct ExecutorGuard;
        impl Drop for ExecutorGuard {
            fn drop(&mut self) {
                clear_test_keychain_executor();
            }
        }

        fn install_executor(
            find_result: RawContentClassification,
        ) -> (Rc<ScriptedKeychainExecutor>, ExecutorGuard) {
            install_scripted(ScriptedKeychainExecutor::scripted(find_result))
        }

        fn install_scripted(
            exec: ScriptedKeychainExecutor,
        ) -> (Rc<ScriptedKeychainExecutor>, ExecutorGuard) {
            let exec = Rc::new(exec);
            set_test_keychain_executor(exec.clone());
            (exec, ExecutorGuard)
        }

        /// Common two-account fixture: slot 1 (current, above threshold),
        /// slot 2 (target, low usage) — both with UUID-content markers, the
        /// shape `find_target`'s HIGH-3 filter and `repoint_handle_dir`
        /// require.
        fn setup_source_and_target(dir: &Path, claude_home: &Path, pid: u32) -> PathBuf {
            setup_account(dir, 1);
            setup_account(dir, 2);
            setup_quota(dir, 1, 97.0);
            setup_quota(dir, 2, 10.0);
            setup_config_dir_uuid(dir, 1);
            setup_config_dir_uuid(dir, 2);
            let cfg = RotationConfig {
                enabled: true,
                threshold_percent: 95.0,
                cooldown_secs: 300,
                ..RotationConfig::default()
            };
            save_rotation_config(dir, &cfg).unwrap();
            setup_handle_dir(dir, claude_home, pid, 1)
        }

        /// (a) [`keychain-fix-r8.md`'s C-F7, auto_rotate mirror]: the
        /// pre-repoint forced write lands (X now holds the target's token),
        /// but `repoint_handle_dir` itself refuses — here via its own
        /// pre-flight guard (target `config-2` missing `.csq-account`). B2
        /// (`reconcile_keychain_to_marker` runs on BOTH outcomes) then
        /// re-reads the UNMOVED marker (still account 1) and must write X
        /// back to match it — "keychain matches marker" checked via
        /// `last_add_payload()`, mirroring `swap.rs`'s `t_a_...` test.
        ///
        /// RED: before B2 landed (`reconcile only on Err` — this test would
        /// still exercise the Err arm, so it is not itself B2's regression
        /// guard; see `t_b_...` below for that), a caller that trusted a
        /// repoint's own `Err` alone without folding the reconcile line in
        /// would leave X on the target's token — this test's second
        /// `assert!(!payload.contains("rt-2"), ...)` is the guard.
        #[test]
        fn t_a_repoint_fails_keychain_reconciles_to_marker() {
            let _env_lock = crate::platform::test_env::lock();
            let dir = TempDir::new().unwrap();
            let claude_home = TempDir::new().unwrap();
            let handle_dir = setup_source_and_target(dir.path(), claude_home.path(), 50001);

            std::fs::remove_file(dir.path().join("config-2").join(".csq-account")).expect(
                "fixture: remove target .csq-account to force the repoint precondition to fail",
            );

            // X starts absent; the pre-repoint forced write (target=2)
            // succeeds and becomes the scripted executor's `current` state.
            let (exec, _guard) = install_executor(RawContentClassification::Absent);

            let mut cooldowns = HashMap::new();
            tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

            assert_eq!(
                markers::resolve_marker_to_slot(dir.path(), &handle_dir),
                Some(AccountNum::try_from(1u16).unwrap()),
                "a failed repoint precondition must leave the marker on the SOURCE account"
            );
            let payload = exec
                .last_add_payload()
                .expect("reconcile must write X back toward the (unmoved) marker account");
            assert!(
                payload.contains("rt-1"),
                "keychain must end up matching the marker (source account 1's token), \
                 not left holding the target's — last add payload: {payload}"
            );
            assert!(
                !payload.contains("rt-2"),
                "keychain must not be left on the target's token after a failed repoint: {payload}"
            );
        }

        /// (b) [`keychain-fix-r8.md`'s C-F7, auto_rotate mirror]: repoint
        /// SUCCEEDS, but the pre-repoint forced write left X's disk state
        /// UNKNOWN (`ForcedSyncResult::WriteFailedUnknown` — a scripted
        /// `add()` failure over KNOWN `Content`). B2's post-repoint
        /// `reconcile_keychain_to_marker` re-reads X (still the STALE
        /// source-account content, since the scripted `find()` result is
        /// static) against the NOW-current marker (target, since the
        /// repoint itself succeeded) — they disagree, so this rotation must
        /// NOT be counted as `rotated` (the SHORT `RECONCILE_DESYNC_RETRY_COOLDOWN`
        /// cooldown is set, not a full-cycle one) even though the marker DID move.
        ///
        /// RED: reverting the `Ok(()) if reconcile_outcome_confirms_rotation(...)`
        /// guard to bare `Ok(()) => { ...; rotated += 1 }` (treating every
        /// successful repoint as a confirmed rotation) makes this test's
        /// cooldown-staleness assertion fail — the cooldown would be set to
        /// `Instant::now()` (near-zero elapsed) instead of the backdated
        /// short-retry instant.
        #[test]
        fn t_b_repoint_ok_forced_write_unknown_not_counted_as_rotated() {
            let _env_lock = crate::platform::test_env::lock();
            let dir = TempDir::new().unwrap();
            let claude_home = TempDir::new().unwrap();
            let handle_dir = setup_source_and_target(dir.path(), claude_home.path(), 50002);

            let source_cf = make_creds("at-1", "rt-1");

            // X currently holds the SOURCE account's own token (a KNOWN,
            // Content classification) — decide_cc_keychain_write reaches
            // apply_cc_keychain_write's write branch, whose scripted add()
            // is set to fail: WriteFailedUnknown, not Unreadable/Absent.
            let (_exec, _guard) = install_scripted(
                ScriptedKeychainExecutor::scripted(RawContentClassification::Content(
                    serde_json::to_string(&source_cf).unwrap(),
                ))
                .with_add_failing(),
            );

            let mut cooldowns = HashMap::new();
            tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

            assert_eq!(
                markers::resolve_marker_to_slot(dir.path(), &handle_dir),
                Some(AccountNum::try_from(2u16).unwrap()),
                "the repoint itself must have succeeded (symlinks moved to the target)"
            );
            let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
            let cooldown_set_at = *cooldowns.get(&canonical_handle).expect(
                "a repoint whose reconcile could not confirm must still set A cooldown \
                 (retried sooner, not never)",
            );
            assert!(
                cooldown_set_at.elapsed() >= RECONCILE_DESYNC_RETRY_COOLDOWN,
                "an UNCONFIRMED rotation must use the SHORT backdated retry cooldown, \
                 not the full-cycle Instant::now() a confirmed rotation would set — \
                 elapsed only {:?}",
                cooldown_set_at.elapsed()
            );
        }

        /// (d) [`keychain-fix-r8.md`'s C-F7, auto_rotate mirror]: X holds a
        /// valid Anthropic identity matching NO known account (rule 3,
        /// `ForcedSyncResult::ForeignLoginUnharvested`). Per
        /// `force_swap_write_before_repoint`'s own doc this is "not branched
        /// on directly" — the refusal comes from `decide()`'s re-read of X,
        /// regardless of the opportunistic harvest's own outcome (which
        /// finds zero candidates here — see this module's header comment).
        /// The rotation MUST refuse with ZERO keychain mutation: no `add`,
        /// no `delete`, marker unmoved, mirroring `swap.rs`'s
        /// `t_d_unmatched_token_harvest_ownership_unknown_refuses_no_mutation`.
        #[test]
        fn t_d_unmatched_token_ownership_unknown_skips_no_mutation() {
            let _env_lock = crate::platform::test_env::lock();
            let dir = TempDir::new().unwrap();
            let claude_home = TempDir::new().unwrap();
            let handle_dir = setup_source_and_target(dir.path(), claude_home.path(), 50003);

            let foreign = make_creds("at-FOREIGN", "rt-FOREIGN");
            let (exec, _guard) = install_executor(RawContentClassification::Content(
                serde_json::to_string(&foreign).unwrap(),
            ));

            let mut cooldowns = HashMap::new();
            tick(dir.path(), Some(claude_home.path()), &mut cooldowns);

            assert_eq!(
                markers::resolve_marker_to_slot(dir.path(), &handle_dir),
                Some(AccountNum::try_from(1u16).unwrap()),
                "an unmatched foreign login must refuse the rotation — marker must not move"
            );
            assert!(
                exec.calls().iter().all(|(verb, ..)| *verb == "find"),
                "no add/delete call may occur on an unresolved refusal — got {:?}",
                exec.calls()
            );
            let canonical_handle = std::fs::canonicalize(&handle_dir).unwrap_or(handle_dir.clone());
            assert!(
                cooldowns.contains_key(&canonical_handle),
                "the refusal is a genuine failure arm and must set a cooldown so this \
                 dir is not retried every single tick"
            );
        }
    }
}
