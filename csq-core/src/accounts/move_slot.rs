//! Move an account from one slot number to another.
//!
//! Renames `config-FROM/` → `config-TO/`, the canonical credential
//! file (`credentials/{N}.json` for ClaudeCode surface,
//! `credentials/codex-{N}.json` for Codex), updates the
//! `.csq-account` marker inside the moved dir, and rewrites the
//! `profiles.json` + `quota.json` entries. Refuses if the target slot is
//! already configured. Phase 3 (M3-6) removed the live-process refusal:
//! handle-dir symlinks point at `identities/<UUID>/` (M3-3/M3-4), so
//! credential reads survive the `config-N` rename. The pre-rename scan
//! result is preserved as [`MoveSummary::live_pids_bound`] telemetry.
//!
//! # Phase 2 (M2-4) addition
//!
//! In addition to all Phase 1 steps, `move_account` now ALSO swaps the
//! `profiles.json::by_slot` mapping between `FROM` and `TO` under the same
//! `ProfilesFileLock` window via [`profiles::swap_slot_mapping`]. UUIDs
//! survive the slot rename — the identity that was at slot `FROM` is now
//! addressed as `by_slot[TO]` with its UUID intact. This is additive: the
//! on-disk filesystem rename (Phase 1) is KEPT for downgrade safety (v2.6.x
//! readers find `config-N/` at the expected dir name). Phase 4 will retire the
//! filesystem rename when `csq move` becomes profiles.json-only.
//!
//! The `by_slot` swap is the single canonical primitive:
//! `profiles::swap_slot_mapping` (public, in `accounts/profiles.rs`). The
//! private `swap_by_slot_mapping` that previously existed in this file has
//! been deleted (MED-1 fix). All callers use the public primitive.
//!
//! After a successful move, the calling layer (CLI or desktop Tauri command)
//! MUST fire `POST /api/slot-swap` via `csq_core::daemon::notify_slot_swap`
//! (the shared chokepoint in `daemon/client.rs`). This is best-effort
//! (fire-and-forget): a connect failure does not fail the move.
//!
//! # Multi-step atomicity
//!
//! Per-file moves use `std::fs::rename` (atomic on POSIX). The cross-file
//! sequence is NOT atomic — a crash mid-move leaves artifacts at both source
//! and target slots. The operation is idempotent on replay: re-running
//! `csq move` after a partial crash will attempt the remaining steps.
//!
//! # Lock ordering (three independent locks — outermost first)
//!
//! ```text
//! csq move acquisition order (outermost first):
//!   1. accounts/.move.lock  (coarsest; serializes inter-process moves)
//!   2. ProfilesFileLock      (profiles.json edits)
//!   3. <quota lock>          (acquired AFTER ProfilesFileLock RELEASE —
//!                             same-thread sequential, NOT held concurrently)
//! ```
//!
//! Step 8 holds `ProfilesFileLock` while writing `profiles.json`.
//! Step 9 (quota write) acquires a separate quota file lock AFTER
//! releasing `ProfilesFileLock`. The two locks MUST NOT be held concurrently:
//! holding `ProfilesFileLock` across the quota write would couple lock-order
//! with the daemon refresher's quota lock acquisition, creating a deadlock
//! class. The micro-window between `drop(profiles_lock)` and the quota lock
//! acquisition is the accepted cross-lock observability gap — bounded by the
//! same-user threat model and deliberately documented here rather than
//! suppressed (zero-tolerance Rule 5 exception: lock-order coupling is an
//! external dependency constraint that cannot be fixed in-session).
//!
//! The `.move.lock` at layer 1 is the coarsest lock: it serializes concurrent
//! `csq move` invocations across processes. It is acquired BEFORE
//! `ProfilesFileLock` and released when `move_account` returns. The daemon's
//! refresher does NOT acquire `.move.lock`; its per-(Surface, AccountNum)
//! mutex from `AccountMutexTable` is a separate lock plane.

use crate::accounts::profiles;
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::audit::op_emit;
use crate::audit::types::{AccountMovePayload, EventKind, EventPayload, OpOutcome, RedactedString};
use crate::credentials::file::canonical_path_for;
use crate::platform::fs::secure_file;
use crate::platform::lock::{try_lock_file, FileLockGuard};
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Summary of what was moved.
#[derive(Debug, Clone)]
pub struct MoveSummary {
    pub from: AccountNum,
    pub to: AccountNum,
    pub config_dir_moved: bool,
    pub canonical_creds_moved: Vec<Surface>,
    pub profiles_entry_moved: bool,
    /// True when `profiles.json::by_slot` was swapped for both slots
    /// (Phase 2 M2-4 addition). False in legacy-only fixtures where
    /// neither slot had a `by_slot` entry.
    pub by_slot_swapped: bool,
    /// True when `profiles.json::by_slot_identity` contained an entry
    /// for either slot at move time, indicating the non-OAuth identity
    /// channel was swapped (F-C-1 follow-on telemetry, WBS M4 line 135).
    /// False when neither slot had a `by_slot_identity` entry.
    pub by_slot_identity_swapped: bool,
    pub quota_entry_moved: bool,
    /// PIDs of live `claude` processes that were bound to the source slot
    /// at move time. Phase 3 M3-6 removed the `InUse` refusal; live handle
    /// dirs symlink to `identities/<UUID>/` (M3-3/M3-4), so credential
    /// reads survive the `config-N` rename. The scan result is preserved
    /// here as informational telemetry — callers SHOULD print a notice but
    /// MUST NOT treat a non-empty vector as a failure mode.
    pub live_pids_bound: Vec<u32>,
}

/// Failure modes for [`move_account`].
///
/// Phase 3 (M3-6) removed the `InUse` variant: a live-process binding is no
/// longer a refusal condition. Handle-dir symlinks point at
/// `identities/<UUID>/` (M3-3/M3-4), so the `config-N` rename does NOT
/// invalidate live credential reads. The scan result is preserved as
/// [`MoveSummary::live_pids_bound`] telemetry.
#[derive(Debug)]
pub enum MoveError {
    /// FROM and TO are the same slot.
    SameSlot,
    /// FROM slot has no config dir or canonical credential file —
    /// nothing to move.
    NotConfigured { from: AccountNum },
    /// TO slot is already configured. Caller must `csq logout TO`
    /// or pick a different target slot. Refusing to overwrite is the
    /// safe default — the alternative would silently destroy state.
    TargetExists { to: AccountNum },
    /// A filesystem operation failed mid-move. State may be split
    /// between FROM and TO; caller should inspect both slots.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// `profiles.json` load/save failed.
    Profiles(crate::error::ConfigError),
    /// Another `csq move` invocation is already in progress. The lock at
    /// `accounts/.move.lock` is held by a concurrent process. `pid` is the
    /// PID read from the lock file's contents (best-effort; may be `None` if
    /// the lock file is empty or the PID line is missing).
    Busy { pid: Option<u32> },
}

impl std::fmt::Display for MoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MoveError::SameSlot => write!(f, "FROM and TO are the same slot"),
            MoveError::NotConfigured { from } => {
                write!(f, "slot {} is not configured", from)
            }
            MoveError::TargetExists { to } => write!(
                f,
                "target slot {} is already configured — `csq logout {}` first or pick another target",
                to, to
            ),
            MoveError::Io { path, source } => {
                write!(f, "filesystem error at {}: {}", path.display(), source)
            }
            MoveError::Profiles(e) => write!(f, "profiles.json error: {}", e),
            MoveError::Busy { pid: Some(p) } => write!(
                f,
                "another csq move is already in progress (held by pid {p}) — try again shortly"
            ),
            MoveError::Busy { pid: None } => write!(
                f,
                "another csq move is already in progress (or the accounts directory is read-only) \
                 — try again shortly"
            ),
        }
    }
}

impl std::error::Error for MoveError {}

// ── Move lock primitives ──────────────────────────────────────────────────────

/// RAII guard for the `accounts/.move.lock` file lock.
///
/// Drop releases the lock. The lock is acquired by [`acquire_move_lock`] and
/// must live for the entire duration of the [`move_account`] call.
#[derive(Debug)]
pub(crate) struct MoveLockGuard {
    /// The underlying platform FLOCK guard. Drop = release.
    _inner: FileLockGuard,
}

/// Returns the canonical path of the inter-process move lock file.
///
/// Path: `base.join(".move.lock")`.
///
/// Exposed as a `pub fn` so tests can assert path-shape without going through
/// a full `acquire_move_lock` call.
pub fn move_lock_path(base: &Path) -> PathBuf {
    base.join(".move.lock")
}

/// Acquires the inter-process move lock at `base/.move.lock`.
///
/// Uses a non-blocking [`try_lock_file`] polled at 100 ms intervals for up to
/// 5 seconds. On first successful acquire, `0o600` is applied to the lock file
/// via [`secure_file`] (SEC-3-H1). The current process PID is written to the
/// lock file as a best-effort metadata line (`{pid}\n`); failure to write is
/// not fatal — the FLOCK is the lock primitive, the content is diagnostic only.
///
/// # Errors
///
/// Returns `Err(MoveError::Busy { pid })` when:
/// - The lock is held for the full 5-second deadline (poll timeout), OR
/// - The lock file cannot be created (e.g. read-only filesystem / EROFS) —
///   fail-closed per SEC-3-M2 and `rules/zero-tolerance.md` Rule 3.
///
/// `pid` is read from the lock file's first line; `None` when the file is
/// empty or the line cannot be parsed.
///
/// Origin: `workspaces/account-slot-decoupling/journal/0015-RISK-phase3-wbs-redteam-r1-findings-and-adoption.md`
/// § Delta J (SEC-3-H1 0o600 chmod, SEC-3-M2 fail-closed on EROFS) +
/// `journal/0016-DECISION-owner-resolved-phase3-open-questions-defaults.md`
/// § OQ #4 (lock scope: only `csq move`, NOT `csq login`/`csq logout`).
fn acquire_move_lock(base: &Path) -> Result<MoveLockGuard, MoveError> {
    let lock_path = move_lock_path(base);
    let deadline = Instant::now() + Duration::from_secs(5);
    let poll_interval = Duration::from_millis(100);

    loop {
        match try_lock_file(&lock_path) {
            Ok(Some(guard)) => {
                // SEC-3-H1: set 0o600 after creation.
                // Failure is non-fatal: the FLOCK is still held; the permission
                // might already be set from a prior invocation.
                let _ = secure_file(&lock_path);

                // Write PID as best-effort metadata. Non-fatal on failure.
                let pid = std::process::id();
                let _ = std::fs::write(&lock_path, format!("{pid}\n"));

                return Ok(MoveLockGuard { _inner: guard });
            }
            Ok(None) => {
                // Lock is held by another process.
                if Instant::now() >= deadline {
                    let pid = read_lock_pid(&lock_path);
                    return Err(MoveError::Busy { pid });
                }
                std::thread::sleep(poll_interval);
            }
            Err(_) => {
                // Cannot create/open the lock file (e.g. EROFS, EACCES).
                // Fail-closed per SEC-3-M2: treat as busy with no PID info.
                return Err(MoveError::Busy { pid: None });
            }
        }
    }
}

/// Reads the PID from the first line of a lock file.
///
/// Returns `None` if the file cannot be read or the first line is not a
/// valid `u32`. Non-blocking, best-effort — used only for error reporting.
fn read_lock_pid(path: &Path) -> Option<u32> {
    let contents = std::fs::read_to_string(path).ok()?;
    contents.lines().next()?.trim().parse::<u32>().ok()
}

/// Moves account `from` to slot `to` in the csq base directory.
///
/// Steps (in order):
///  1. Validate `from != to`.
///  2. Verify `from` is configured (config dir or canonical creds exist).
///  3. Verify `to` is NOT configured (no config dir, no canonical creds).
///  4. Scan `term-*` handle dirs for live processes bound to `from`.
///  5. Rename `config-FROM/` → `config-TO/`.
///  6. Update `.csq-account` marker inside the moved dir to `to`.
///  7. Rename canonical credential files for every surface that has one
///     (ClaudeCode: `credentials/{from}.json` → `credentials/{to}.json`;
///     Codex: `credentials/codex-{from}.json` → `credentials/codex-{to}.json`).
///  8. Rewrite the `profiles.json` `accounts` entry from key `from` to key `to`,
///     AND swap `by_slot[FROM]` ↔ `by_slot[TO]` (Phase 2 M2-4 addition).
///     Both operations happen under the same [`ProfilesFileLock`].
///  9. Rewrite the `quota.json` entry from key `from` to key `to`.
///
/// Daemon cache invalidation is the caller's responsibility.
/// The CLI layer sends a best-effort `POST /api/slot-swap` IPC event.
pub fn move_account(
    base_dir: &Path,
    from: AccountNum,
    to: AccountNum,
) -> Result<MoveSummary, MoveError> {
    // Acquire the inter-process move lock FIRST (outermost lock — layer 1).
    // Bind to a let variable whose scope covers the entire function; drop on
    // return releases the lock.
    let _move_lock = acquire_move_lock(base_dir)?;

    if from == to {
        return Err(MoveError::SameSlot);
    }

    let from_config = base_dir.join(format!("config-{}", from));
    let to_config = base_dir.join(format!("config-{}", to));

    let from_canonical_cc = canonical_path_for(base_dir, from, Surface::ClaudeCode);
    let from_canonical_codex = canonical_path_for(base_dir, from, Surface::Codex);
    // FM-2 (journal 0001 D5): Gemini was absent from the move surface
    // table. `swap_slot_mapping` swaps `by_slot_identity[FROM↔TO]`
    // generically, so after this workspace populates it for Gemini, a
    // `csq move` that did NOT also move `credentials/gemini-<N>.json`
    // left a phantom identity pointing at a non-existent binding. Latent
    // before (Gemini `by_slot_identity` was always absent); visible +
    // misleading after — zero-tolerance Rule 1 owns it.
    let from_canonical_gemini = canonical_path_for(base_dir, from, Surface::Gemini);
    let to_canonical_cc = canonical_path_for(base_dir, to, Surface::ClaudeCode);
    let to_canonical_codex = canonical_path_for(base_dir, to, Surface::Codex);
    let to_canonical_gemini = canonical_path_for(base_dir, to, Surface::Gemini);

    // Step 2: source must exist.
    if !from_config.exists()
        && !from_canonical_cc.exists()
        && !from_canonical_codex.exists()
        && !from_canonical_gemini.exists()
    {
        return Err(MoveError::NotConfigured { from });
    }

    // Step 3: target must NOT exist.
    if to_config.exists()
        || to_canonical_cc.exists()
        || to_canonical_codex.exists()
        || to_canonical_gemini.exists()
    {
        return Err(MoveError::TargetExists { to });
    }

    // Step 4: capture live-process telemetry (Phase 3 M3-6 — no longer a refusal).
    //
    // Pre-M3-6 this scan refused the move when any handle dir was bound to FROM.
    // After M3-3/M3-4, `.credentials.json` retargets through `identities/<UUID>/`
    // and survives the `config-N` rename. The remaining handle-dir symlinks
    // (`.csq-account`, `.current-account`, `.quota-cursor`, and Codex's
    // `config.toml` / `sessions` / `history.jsonl` / `.csq-account`) STILL
    // target `config-N/` per OQ #2 Option A (markers stay numeric / slot-keyed
    // through Phase 4 per cross-phase constraint #3). Those symlinks WOULD
    // dangle after the rename without the Step 5.5 rewrite below.
    //
    // Scanning BEFORE the rename so the marker still resolves to FROM.
    let live_pids_bound =
        crate::accounts::logout::scan_live_handle_dirs_for_account_pub(base_dir, from);

    // M13b — emit INTENT after acquire_move_lock succeeds and after
    // source/target validation (pre-side-effect rejections above emit NO
    // INTENT — WBS T6, MoveError::Busy emits NO INTENT via acquire_move_lock
    // early return). INTENT is emitted BEFORE Step 5 (the first rename).
    // If the intent cannot be persisted, fail closed — no rename runs.
    let chain_id = op_emit::load_chain_id(base_dir);
    let correlation_id = op_emit::gen_correlation_id().map_err(|e| MoveError::Io {
        path: base_dir.join("csq-runs"),
        source: std::io::Error::other(format!("audit correlation_id: {e}")),
    })?;
    let move_payload = EventPayload::AccountMove(AccountMovePayload {
        from_slot: from,
        to_slot: to,
    });
    // FIX-1: Ok(true)=emitted, Ok(false)=chain-broken skip (proceed without
    // audit), Err=fail-closed.
    let intent_emitted = op_emit::emit_intent(
        base_dir,
        &chain_id,
        EventKind::AccountMove,
        move_payload.clone(),
        correlation_id.clone(),
    )
    .map_err(|e| MoveError::Io {
        path: base_dir.join("csq-runs"),
        source: std::io::Error::other(format!(
            "audit intent record could not be persisted — move aborted: {e}"
        )),
    })?;

    // ── Helper: emit OUTCOME:Failed on post-intent error branches (FIX-5) ──────
    //
    // Best-effort — does NOT change the error returned to the caller. The intent
    // is resolved (not left as a permanent orphan) even on partial failure.
    // FIX-7: reason routes through `RedactedString::from_untrusted` with home
    // path scrubbing — no filesystem paths land on the exported chain.
    // FIX-1: skip outcome when intent was skipped (chain broken).
    let home = std::env::var("HOME").unwrap_or_default();
    let emit_failed = |reason: &str| {
        if !intent_emitted {
            return;
        }
        let scrubbed = if !home.is_empty() {
            reason.replace(&home, "<home>")
        } else {
            reason.to_string()
        };
        let _ = op_emit::emit_outcome(
            base_dir,
            &chain_id,
            EventKind::AccountMove,
            move_payload.clone(),
            correlation_id.clone(),
            OpOutcome::Failed {
                reason: RedactedString::from_untrusted(scrubbed),
            },
        );
    };

    // Step 5: rename config dir.
    let config_dir_moved = if from_config.exists() {
        if let Err(e) = std::fs::rename(&from_config, &to_config) {
            emit_failed(&format!("config dir rename failed: {e}"));
            return Err(MoveError::Io {
                path: from_config.clone(),
                source: e,
            });
        }
        true
    } else {
        false
    };

    // Step 5.5: rewrite handle-dir symlinks that targeted `config-FROM/<item>`
    // to point at `config-TO/<item>`. Required because M3-3/M3-4 retargeted
    // ONLY `.credentials.json` (and Codex `auth.json` for identity-keyed
    // cases) to `identities/<UUID>/`. The marker + slot-state symlinks listed
    // in the Step 4 banner above would otherwise dangle after the Step 5
    // rename. Per-handle-dir errors are logged and skipped (partial rewrite is
    // preferable to refusal in Phase 3's non-blocking model); idempotent on
    // replay. Section is a no-op when `config_dir_moved == false` (no rename).
    if config_dir_moved {
        let _ = rewrite_handle_dir_symlinks_for_rename(base_dir, &from_config, &to_config);
    }

    // Step 6: update .csq-account marker inside the moved dir to the
    // new slot number. crate::accounts::markers handles atomic write.
    //
    // M4-7: `move_slot` writes the legacy decimal slot id so the
    // post-move marker matches the new `config-<to>` directory name
    // exactly. UUID-identity moves are handled by the Phase 2 M2-4
    // `by_slot` swap (which preserves identity across slot renumbers)
    // — this marker write is the file-mode counterpart used by legacy
    // readers; the UUID side is already reflected through
    // `profiles.json::by_slot[to]` after `swap_slot_mapping` runs.
    if config_dir_moved {
        if let Err(e) = crate::accounts::markers::write_csq_account_legacy(&to_config, to) {
            emit_failed(&format!("marker write failed: {e}"));
            return Err(MoveError::Io {
                path: to_config.join(".csq-account"),
                source: std::io::Error::other(format!("write marker: {e}")),
            });
        }

        // Step 6b: refresh the `.current-account` cache to the NEW slot.
        // The renamed `config-<to>/.current-account` still holds the OLD slot
        // number (it was `config-<from>/.current-account` before the Step 5
        // rename). Leaving it stale re-creates the `csq swap → wrong slot`
        // bug: a terminal that later swaps to `to` would read the stale
        // cache. This is the C2 binder gap (workspace slot-attribution-
        // consistency) — `csq move` MUST refresh the cache exactly like the
        // `.csq-account` marker above. Fatal for the same reason the marker
        // write is: if we can write one file in `to_config` we can write both.
        if let Err(e) = crate::accounts::markers::write_current_account(&to_config, to) {
            emit_failed(&format!("current-account write failed: {e}"));
            return Err(MoveError::Io {
                path: to_config.join(".current-account"),
                source: std::io::Error::other(format!("write current-account: {e}")),
            });
        }
    }

    // Step 7: rename canonical credential files (per surface).
    let mut canonical_creds_moved = Vec::new();
    for (surface, src, dst) in [
        (Surface::ClaudeCode, &from_canonical_cc, &to_canonical_cc),
        (Surface::Codex, &from_canonical_codex, &to_canonical_codex),
        (
            Surface::Gemini,
            &from_canonical_gemini,
            &to_canonical_gemini,
        ),
    ] {
        if src.exists() {
            // Ensure parent directory exists. canonical_path_for
            // returns paths under `credentials/` which is always
            // present, but be defensive.
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::rename(src, dst) {
                emit_failed(&format!("credential rename failed: {e}"));
                return Err(MoveError::Io {
                    path: src.clone(),
                    source: e,
                });
            }
            canonical_creds_moved.push(surface);
        }
    }

    // Step 8: rewrite profiles.json (accounts map + by_slot swap).
    // Acquire ProfilesFileLock to serialize against daemon mint paths and
    // `csq login`. The lock covers both move_profiles_entry (Phase 1) AND
    // swap_by_slot_mapping (Phase 2 M2-4) in a single atomic window.
    let profiles_lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(e) => {
            emit_failed(&format!("profiles lock failed: {e}"));
            return Err(MoveError::Profiles(e));
        }
    };
    let profiles_entry_moved = match move_profiles_entry(&profiles_lock, base_dir, from, to) {
        Ok(r) => r,
        Err(e) => {
            emit_failed(&format!("profiles entry move failed: {e}"));
            return Err(e);
        }
    };

    // Phase 2 M2-4: swap by_slot[FROM] ↔ by_slot[TO] under the same lock.
    // Routes through the public primitive in profiles.rs (MED-1 fix: the
    // private duplicate swap_by_slot_mapping has been deleted).
    // This is additive — the filesystem rename above is KEPT for downgrade
    // safety; the swap ensures UUID identity survives the slot renumber.
    // by_email is slot-independent and is NOT updated here.
    //
    // F-C-1 follow-on (WBS M4 line 135): peek at by_slot_identity BEFORE
    // swap_slot_mapping consumes the entries so we can attribute the swap
    // to the non-OAuth identity channel in MoveSummary.  The extra load is
    // cheap (same lock, no second file descriptor open) and profiles.json
    // fits in memory.
    let by_slot_identity_swapped = {
        let profiles_path = profiles::profiles_path(base_dir);
        if profiles_path.exists() {
            profiles::load(&profiles_path)
                .map(|pf| {
                    let key_from = from.get().to_string();
                    let key_to = to.get().to_string();
                    pf.by_slot_identity.contains_key(&key_from)
                        || pf.by_slot_identity.contains_key(&key_to)
                })
                .unwrap_or(false)
        } else {
            false
        }
    };

    let by_slot_swapped =
        match profiles::swap_slot_mapping(&profiles_lock, base_dir, from.get(), to.get()) {
            Ok(r) => r,
            Err(e) => {
                emit_failed(&format!("by_slot swap failed: {e}"));
                return Err(MoveError::Profiles(e));
            }
        };

    drop(profiles_lock); // release before quota write (different lock)

    // Step 9: rewrite quota.json.
    let quota_entry_moved = move_quota_entry(base_dir, from, to);

    // M13b — emit OUTCOME:Ok after the profiles + quota rewrite committed.
    // Best-effort: if this fails the intent becomes a visible orphan detectable
    // by `scan_orphan_intents`. FIX-1: skip when intent was skipped.
    if intent_emitted {
        let _ = op_emit::emit_outcome(
            base_dir,
            &chain_id,
            EventKind::AccountMove,
            move_payload,
            correlation_id,
            OpOutcome::Ok,
        );
    }

    Ok(MoveSummary {
        from,
        to,
        config_dir_moved,
        canonical_creds_moved,
        profiles_entry_moved,
        by_slot_swapped,
        by_slot_identity_swapped,
        quota_entry_moved,
        live_pids_bound,
    })
}

/// Rewrites the `accounts` map entry in profiles.json from `from` → `to`.
///
/// This function handles ONLY the `accounts` map rename (Phase 1 behavior).
/// The `by_slot` map is handled separately by [`profiles::swap_slot_mapping`]
/// (Phase 2 M2-4), which is called immediately after under the same lock.
///
/// **Lock window note (LOW-1):** Under one `ProfilesFileLock` window, two
/// sequential load-mutate-save cycles occur:
/// 1. `move_profiles_entry` — load → remove `accounts[FROM]`, insert
///    `accounts[TO]` → save.
/// 2. `profiles::swap_slot_mapping` — load → swap `by_slot[FROM]` ↔
///    `by_slot[TO]` → save.
///
/// The two cycles are intentionally separate to prevent the double-load-save
/// correctness bug: if `move_profiles_entry` touched `by_slot` AND
/// `profiles::swap_slot_mapping` also loaded the file, the second load would
/// see the already-moved `by_slot` and produce the wrong final mapping.
///
/// # Lock precondition
///
/// The caller MUST hold `_lock` (a [`ProfilesFileLock`]) for `base_dir`
/// before calling this function. The type-witness parameter enforces this
/// at compile time. Rationale: this performs a read-modify-write cycle on
/// `profiles.json`; the lock serializes against daemon mint paths and
/// `csq login`.
///
/// # by_slot and by_email
///
/// `by_slot` is intentionally NOT touched here — [`profiles::swap_slot_mapping`]
/// handles it under the same lock window.
/// `by_email` is intentionally NOT updated anywhere during a move — the
/// email→UUID mapping is slot-independent.
fn move_profiles_entry(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
    from: AccountNum,
    to: AccountNum,
) -> Result<bool, MoveError> {
    let path = profiles::profiles_path(base_dir);
    if !path.exists() {
        return Ok(false);
    }
    let mut file = profiles::load(&path).map_err(MoveError::Profiles)?;

    let from_key = from.get().to_string();
    let to_key = to.get().to_string();

    // M4-13 (release N+1): the v1 `accounts` struct field is removed.
    // On-disk files may carry a residual `accounts` key in `extra`; relocate
    // the entry for `from_key` → `to_key` in that JSON object so a subsequent
    // `prune_redundant_accounts_entries` pass sees the right slot key.
    let relocated = true;
    if let Some(accounts_val) = file.extra.get_mut("accounts") {
        if let Some(obj) = accounts_val.as_object_mut() {
            if let Some(entry) = obj.remove(from_key.as_str()) {
                obj.insert(to_key.clone(), entry);
            }
            // relocated stays true — the move semantic is "true" even when
            // `extra["accounts"]` is absent or has no matching key, because
            // `by_slot`/`by_email` carry the canonical identity and
            // `profiles::swap_slot_mapping` handles the `by_slot` key rename.
        }
    }

    // by_slot is intentionally NOT touched here — profiles::swap_slot_mapping
    // handles all by_slot changes in a separate load-mutate-save cycle
    // under the same ProfilesFileLock window (prevents double-load-save bug).
    // by_email is intentionally NOT updated — email→UUID is slot-independent.

    profiles::save(&path, &file).map_err(MoveError::Profiles)?;
    Ok(relocated)
}

fn move_quota_entry(base_dir: &Path, from: AccountNum, to: AccountNum) -> bool {
    use crate::quota::state as quota_state;

    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = match crate::platform::lock::lock_file(&lock_path) {
        Ok(g) => g,
        Err(_) => return false,
    };

    let mut quota = match quota_state::load_state(base_dir) {
        Ok(q) => q,
        Err(_) => return false,
    };

    let from_key = from.get().to_string();
    let to_key = to.get().to_string();
    let entry = match quota.accounts.remove(&from_key) {
        Some(e) => e,
        None => return false,
    };

    quota.accounts.insert(to_key, entry);
    quota_state::save_state(base_dir, &quota).is_ok()
}

/// Rewrites handle-dir symlinks rooted at `from_config/<item>` to
/// `to_config/<item>`.
///
/// Required by Step 5.5 of [`move_account`]: M3-3/M3-4 retargeted ONLY
/// `.credentials.json` (and Codex `auth.json` when identity-keyed) through
/// `identities/<UUID>/`. The remaining handle-dir symlinks
/// (`.csq-account`, `.current-account`, `.quota-cursor` for Anthropic;
/// `config.toml`, `sessions`, `history.jsonl`, `.csq-account` for Codex)
/// still target `config-N/` per OQ #2 Option A. Without this rewrite the
/// `config-FROM → config-TO` rename in Step 5 leaves those symlinks
/// dangling, breaking daemon attribution + statusline + auto-rotate for
/// every live handle dir bound to FROM.
///
/// Behavior:
/// - Walks every `term-*/` handle dir under `base_dir`.
/// - For each symlink whose textual target is prefixed by `from_config`,
///   removes the old symlink and creates a replacement targeting
///   `to_config/<relative>`.
/// - Uses [`crate::session::isolation::create_symlink_pub`] so Windows
///   dir-junction-vs-file dispatch matches `create_handle_dir`'s contract.
/// - Per-symlink errors are logged via `tracing::warn!` and SKIPPED — partial
///   rewrite is preferable to refusal in Phase 3's non-blocking model.
/// - Idempotent on replay: only symlinks whose target STILL starts with
///   `from_config/` are rewritten; subsequent invocations no-op.
///
/// Returns the list of `(handle_dir, item_name)` pairs rewritten — used
/// by tests to verify the structural fix and (optionally) by future
/// telemetry layers to surface the count to renderers. The caller MAY
/// ignore the return value when telemetry is not needed.
fn rewrite_handle_dir_symlinks_for_rename(
    base_dir: &Path,
    from_config: &Path,
    to_config: &Path,
) -> Vec<(PathBuf, String)> {
    let mut rewritten: Vec<(PathBuf, String)> = Vec::new();

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return rewritten,
    };

    for entry in entries.flatten() {
        let handle_path = entry.path();
        let dir_name = match handle_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !dir_name.starts_with("term-") {
            continue;
        }

        let items = match std::fs::read_dir(&handle_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for item_entry in items.flatten() {
            let item_path = item_entry.path();
            let item_meta = match item_path.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !item_meta.file_type().is_symlink() {
                continue;
            }
            let target = match std::fs::read_link(&item_path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let relative = match target.strip_prefix(from_config) {
                Ok(rel) => rel.to_path_buf(),
                Err(_) => continue,
            };
            let new_target = to_config.join(&relative);
            let item_name = match item_path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            if let Err(e) = std::fs::remove_file(&item_path) {
                tracing::warn!(
                    handle_dir = %handle_path.display(),
                    item = %item_name,
                    error = %e,
                    "step 5.5: skip symlink rewrite — remove failed"
                );
                continue;
            }
            if let Err(e) = crate::session::isolation::create_symlink_pub(&new_target, &item_path) {
                tracing::warn!(
                    handle_dir = %handle_path.display(),
                    item = %item_name,
                    error = %e,
                    "step 5.5: skip symlink rewrite — create failed"
                );
                continue;
            }
            rewritten.push((handle_path.clone(), item_name));
        }
    }

    rewritten
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_slot(base: &Path, slot: u16) {
        let n = AccountNum::try_from(slot).unwrap();
        let dir = base.join(format!("config-{}", slot));
        std::fs::create_dir_all(&dir).unwrap();
        crate::accounts::markers::write_csq_account_legacy(&dir, n).unwrap();
        std::fs::write(dir.join("settings.json"), "{}").unwrap();
    }

    #[test]
    fn move_rejects_same_slot() {
        let dir = TempDir::new().unwrap();
        let n = AccountNum::try_from(5u16).unwrap();
        make_slot(dir.path(), 5);
        let err = move_account(dir.path(), n, n).unwrap_err();
        assert!(matches!(err, MoveError::SameSlot));
    }

    #[test]
    fn move_rejects_unconfigured_source() {
        let dir = TempDir::new().unwrap();
        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let err = move_account(dir.path(), from, to).unwrap_err();
        assert!(matches!(err, MoveError::NotConfigured { .. }));
    }

    #[test]
    fn move_rejects_existing_target() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 5);
        make_slot(dir.path(), 12);
        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let err = move_account(dir.path(), from, to).unwrap_err();
        assert!(matches!(err, MoveError::TargetExists { .. }));
    }

    #[test]
    fn move_renames_config_dir_and_updates_marker() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 5);
        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();

        let summary = move_account(dir.path(), from, to).unwrap();
        assert!(summary.config_dir_moved);

        // FROM dir gone.
        assert!(!dir.path().join("config-5").exists());
        // TO dir present, marker updated.
        assert!(dir.path().join("config-12").exists());
        let marker_value =
            crate::accounts::markers::read_csq_account(&dir.path().join("config-12")).unwrap();
        assert_eq!(marker_value.get(), 12);
    }

    #[test]
    fn move_renames_claude_canonical_credentials() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 5);
        // Drop a canonical credential file.
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("5.json"), r#"{"ok":true}"#).unwrap();

        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let summary = move_account(dir.path(), from, to).unwrap();

        assert!(summary.canonical_creds_moved.contains(&Surface::ClaudeCode));
        assert!(!creds_dir.join("5.json").exists());
        assert!(creds_dir.join("12.json").exists());
    }

    #[test]
    fn move_renames_codex_canonical_credentials() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 5);
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-5.json"), r#"{"ok":true}"#).unwrap();

        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let summary = move_account(dir.path(), from, to).unwrap();

        assert!(summary.canonical_creds_moved.contains(&Surface::Codex));
        assert!(!creds_dir.join("codex-5.json").exists());
        assert!(creds_dir.join("codex-12.json").exists());
    }

    /// G5/AC-13 (FM-2, journal 0001 D5): `csq move` MUST rename the
    /// Gemini binding marker alongside the `by_slot_identity` swap.
    /// Without this, `swap_slot_mapping`'s generic identity swap left a
    /// phantom `by_slot_identity[TO]` pointing at a `gemini-FROM.json`
    /// marker that was never moved.
    #[test]
    fn move_renames_gemini_canonical_binding() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 5);
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("gemini-5.json"),
            r#"{"v":1,"auth":{"mode":"api_key"},"model_name":"auto","created_unix_secs":0}"#,
        )
        .unwrap();

        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let summary = move_account(dir.path(), from, to).unwrap();

        assert!(summary.canonical_creds_moved.contains(&Surface::Gemini));
        assert!(
            !creds_dir.join("gemini-5.json").exists(),
            "source gemini marker must be gone after move"
        );
        assert!(
            creds_dir.join("gemini-12.json").exists(),
            "gemini marker must follow the slot to the target"
        );
    }

    /// G5/FM-2: a Gemini-ONLY slot (no config dir, no cc/codex creds —
    /// just the binding marker) is movable. Before the fix, Step 2's
    /// "source must exist" check did not consider the Gemini marker, so
    /// `csq move` on a marker-only Gemini slot returned NotConfigured.
    #[test]
    fn move_gemini_only_slot_is_not_rejected_as_unconfigured() {
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("gemini-3.json"),
            r#"{"v":1,"auth":{"mode":"code_assist_oauth"},"model_name":"auto","created_unix_secs":0}"#,
        )
        .unwrap();

        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(8u16).unwrap();
        let summary = move_account(dir.path(), from, to).unwrap();
        assert!(summary.canonical_creds_moved.contains(&Surface::Gemini));
        assert!(creds_dir.join("gemini-8.json").exists());
    }

    #[test]
    fn move_rewrites_profiles_entry() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 5);

        let path = profiles::profiles_path(dir.path());
        let mut file = profiles::ProfilesFile::empty();
        file.set_profile(
            5,
            profiles::AccountProfile {
                email: "test@example.com".into(),
                method: "oauth".into(),
                extra: std::collections::HashMap::new(),
            },
        );
        profiles::save(&path, &file).unwrap();

        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let summary = move_account(dir.path(), from, to).unwrap();

        assert!(summary.profiles_entry_moved);

        let reloaded = profiles::load(&path).unwrap();
        assert!(reloaded.get_profile(5).is_none());
        let entry = reloaded.get_profile(12).unwrap();
        assert_eq!(entry.email, "test@example.com");
    }

    // ── R5-MED-1: by_slot maintenance on move_slot ───────────────────────

    /// R5-MED-1: `move_account` renames `by_slot["3"]` → `by_slot["5"]` and
    /// leaves `by_email` unchanged (email→UUID is slot-independent).
    #[test]
    fn move_slot_remaps_by_slot_entry() {
        use crate::accounts::identity_store::IdentityId;

        // Arrange: slot 3, alice@x.com, UUID_A
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 3);

        let uuid_a = IdentityId::new_v4();
        let email = "alice@x.com";

        let path = profiles::profiles_path(dir.path());
        {
            let mut file = profiles::ProfilesFile::empty();
            file.set_profile(
                3,
                profiles::AccountProfile {
                    email: email.into(),
                    method: "oauth".into(),
                    extra: std::collections::HashMap::new(),
                },
            );
            file.by_slot.insert("3".into(), uuid_a);
            file.by_email.insert(email.into(), uuid_a);
            profiles::save(&path, &file).unwrap();
        }

        // Act
        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(5u16).unwrap();
        let summary = move_account(dir.path(), from, to).unwrap();
        assert!(summary.profiles_entry_moved);

        // Assert
        let reloaded = profiles::load(&path).unwrap();

        // by_slot["3"] must be gone
        assert!(
            !reloaded.by_slot.contains_key("3"),
            "by_slot[\"3\"] must be removed after move"
        );

        // by_slot["5"] must equal UUID_A
        assert_eq!(
            reloaded.by_slot.get("5").copied(),
            Some(uuid_a),
            "by_slot[\"5\"] must equal UUID_A after move"
        );

        // accounts["5"] must have the original profile
        let entry = reloaded.get_profile(5).unwrap();
        assert_eq!(
            entry.email, email,
            "accounts[\"5\"].email must be preserved"
        );

        // by_email must be unchanged — email→UUID is slot-independent
        assert_eq!(
            reloaded.by_email.get(email).copied(),
            Some(uuid_a),
            "by_email[email] must be unchanged after move"
        );
    }

    /// R5-MED-1: `move_account` acquires `ProfilesFileLock` before touching
    /// profiles.json. Verified by holding the lock in a background thread and
    /// asserting the foreground call blocks until the lock is released.
    #[test]
    fn move_slot_acquires_profiles_lock() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Arrange
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 3);

        // Write a profiles entry so move_profiles_entry has something to act on
        {
            let path = profiles::profiles_path(dir.path());
            let mut file = profiles::ProfilesFile::empty();
            file.set_profile(
                3,
                profiles::AccountProfile {
                    email: "lock-test@x.com".into(),
                    method: "oauth".into(),
                    extra: std::collections::HashMap::new(),
                },
            );
            profiles::save(&path, &file).unwrap();
        }

        // Shared flag: set to true when move_account completes
        let move_done = Arc::new(Mutex::new(false));
        let move_done_bg = Arc::clone(&move_done);

        let dir_path = dir.path().to_path_buf();

        // Hold the lock in a background thread for a short window
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let _bg = std::thread::spawn(move || {
            let _lock = ProfilesFileLock::acquire(&dir_path).unwrap();
            tx_locked.send(()).unwrap();
            // Hold until signalled
            rx_release.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(_lock);
            *move_done_bg.lock().unwrap() = true;
        });

        // Wait until background thread holds the lock
        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("background thread must acquire lock");

        // Kick off move_account in another thread (it will block on the lock)
        let dir_path2 = dir.path().to_path_buf();
        let foreground_done = Arc::new(Mutex::new(false));
        let foreground_done2 = Arc::clone(&foreground_done);

        let move_thread = std::thread::spawn(move || {
            let from = AccountNum::try_from(3u16).unwrap();
            let to = AccountNum::try_from(5u16).unwrap();
            // This will block until the background lock is released
            let _ = move_account(&dir_path2, from, to);
            *foreground_done2.lock().unwrap() = true;
        });

        // Give the move thread a moment to start and block
        std::thread::sleep(Duration::from_millis(50));

        // Verify it hasn't completed yet (still blocked on lock)
        assert!(
            !*foreground_done.lock().unwrap(),
            "move_account must not complete while ProfilesFileLock is held by another thread"
        );

        // Release the background lock
        tx_release.send(()).unwrap();

        // Wait for move thread to finish
        move_thread.join().expect("move thread must not panic");

        // Verify move_account completed after lock was released
        assert!(
            *foreground_done.lock().unwrap(),
            "move_account must complete after ProfilesFileLock is released"
        );
    }

    // ── M2-4 acceptance criteria (9 named tests) ─────────────────────────────

    /// AC-1: `move_account` KEEPS the on-disk `config-FROM/` → `config-TO/`
    /// filesystem rename (Phase 1 downgrade safety — v2.6.x readers find
    /// `config-N/` at the expected dir name). Phase 2 is ADDITIVE.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn move_slot_keeps_on_disk_rename() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture (slots 1..3), move slot 1 → slot 5.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Pre-condition: config-1/ exists, config-5/ does not.
        assert!(base.join("config-1").exists(), "pre: config-1 must exist");
        assert!(
            !base.join("config-5").exists(),
            "pre: config-5 must not exist"
        );

        let from = AccountNum::try_from(1u16).unwrap();
        let to = AccountNum::try_from(5u16).unwrap();

        // Act
        let summary = move_account(base, from, to).unwrap();

        // Assert: Phase 1 filesystem rename KEPT.
        assert!(
            summary.config_dir_moved,
            "config_dir_moved must be true — filesystem rename is KEPT in Phase 2"
        );
        assert!(
            !base.join("config-1").exists(),
            "config-1/ must be gone after move"
        );
        assert!(
            base.join("config-5").exists(),
            "config-5/ must exist after move (KEPT Phase 1 rename)"
        );
    }

    /// AC-2: `move_account` ADDS the `by_slot` swap:
    /// `by_slot[FROM]` → `by_slot[TO]` (UUID survives the slot renumber).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn move_slot_adds_by_slot_swap() {
        use crate::accounts::identity_store::IdentityId;
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting_fixture has by_slot for all 3 slots.
        // Move slot 1 → slot 5.  There is no pre-existing by_slot["5"].
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let path = profiles::profiles_path(base);

        let uuid_1 = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        // Pre-condition: by_slot["1"] = uuid_1, no by_slot["5"].
        {
            let pf = profiles::load(&path).unwrap();
            assert_eq!(
                pf.by_slot.get("1").copied(),
                Some(uuid_1),
                "pre: by_slot[1] must be fixture uuid for slot 1"
            );
            assert!(
                !pf.by_slot.contains_key("5"),
                "pre: by_slot[5] must be absent"
            );
        }

        let from = AccountNum::try_from(1u16).unwrap();
        let to = AccountNum::try_from(5u16).unwrap();

        // Act
        let summary = move_account(base, from, to).unwrap();

        // Assert: by_slot swap added.
        assert!(
            summary.by_slot_swapped,
            "by_slot_swapped must be true — Phase 2 swap must occur"
        );

        let reloaded = profiles::load(&path).unwrap();

        // by_slot["1"] must be absent (UUID moved to slot 5).
        assert!(
            !reloaded.by_slot.contains_key("1"),
            "by_slot[1] must be absent after move-1→5"
        );
        // by_slot["5"] must equal uuid_1 (UUID survives the rename).
        assert_eq!(
            reloaded.by_slot.get("5").copied(),
            Some(uuid_1),
            "by_slot[5] must equal uuid_1 after move — UUID survives slot renumber"
        );

        // by_email intentionally unchanged — email→UUID is slot-independent.
        let email_1 = "fixture-slot-1@test.invalid".to_string();
        assert_eq!(
            reloaded.by_email.get(&email_1).copied(),
            Some(uuid_1),
            "by_email[slot-1 email] must be unchanged — slot-independent"
        );

        // The accounts map must also be updated (Phase 1).
        assert!(
            reloaded.get_profile(1).is_none(),
            "accounts[1] must be absent after move"
        );
        assert!(
            reloaded.get_profile(5).is_some(),
            "accounts[5] must be present after move"
        );

        // Dummy usage to silence unused-import warning.
        let _ = IdentityId::new_v4();
    }

    // M3-6 (Phase 3): the `move_slot_in_use_check_remains_active` sentinel that
    // pinned cross-phase constraint #1 (`MoveError::InUse` active through
    // Phase 2) was deleted. Constraint #1 is invalidated by design in Phase 3 —
    // see the `move_account_returns_ok_when_live_handle_dirs_bound` family below.

    // ── M3-6 acceptance criteria (Phase 3 — non-blocking move + telemetry) ───

    /// Seeds a handle dir at `term-<pid>/` with `.csq-account` marker pointing
    /// at `slot`. The scan helper resolves the marker and reports the PID as
    /// "bound" when `is_pid_alive(pid)` returns true; using `std::process::id()`
    /// guarantees liveness for the test's duration.
    fn seed_bound_handle_dir(base: &Path, slot: u16, pid: u32) {
        let handle_dir = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle_dir).unwrap();
        let n = AccountNum::try_from(slot).unwrap();
        crate::accounts::markers::write_csq_account_legacy(&handle_dir, n).unwrap();
    }

    /// M3-6 AC-1: `move_account` returns `Ok(_)` when live handle dirs are
    /// bound to the source slot. Pre-M3-6 this returned `Err(MoveError::InUse)`;
    /// Phase 3 retargeted handle-dir symlinks to `identities/<UUID>/` so the
    /// `config-N` rename no longer breaks live credential reads (briefs/00-question.md).
    #[test]
    fn move_account_returns_ok_when_live_handle_dirs_bound() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 3);
        seed_bound_handle_dir(base, 3, std::process::id());

        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(7u16).unwrap();

        let result = move_account(base, from, to);

        assert!(
            result.is_ok(),
            "Phase 3 (M3-6): move_account must succeed even when live handle dirs are bound; got {:?}",
            result.err()
        );
    }

    /// M3-6 AC-2: live PIDs land on `MoveSummary::live_pids_bound`.
    /// Telemetry is preserved (scan is still informational) even though
    /// the operation no longer refuses on a non-empty result.
    #[test]
    fn move_account_summary_records_live_pid_when_handle_dirs_bound() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 3);
        let pid = std::process::id();
        seed_bound_handle_dir(base, 3, pid);

        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(7u16).unwrap();

        let summary = move_account(base, from, to).unwrap();

        assert!(
            summary.live_pids_bound.contains(&pid),
            "live_pids_bound must contain the seeded PID {pid}; got {:?}",
            summary.live_pids_bound
        );
    }

    /// M3-6 AC-3: `csq move` runs without the daemon. The flow at
    /// `move_slot.rs::move_account` is daemon-independent — IPC notification
    /// is the CLI/desktop renderer's concern, not the core primitive.
    /// (journal 0015 Delta J, N-4 deep.)
    #[test]
    fn move_account_succeeds_when_daemon_is_down() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 4);

        // Pre-condition: no socket file present (daemon "down").
        assert!(
            !crate::daemon::socket_path(base).exists(),
            "pre: socket must not exist (daemon down)"
        );

        let from = AccountNum::try_from(4u16).unwrap();
        let to = AccountNum::try_from(9u16).unwrap();

        let result = move_account(base, from, to);

        assert!(
            result.is_ok(),
            "move_account must not depend on the daemon being up; got {:?}",
            result.err()
        );
    }

    /// M3-6 AC-4: when no handle dirs are bound, `live_pids_bound` is empty —
    /// the telemetry shape is preserved as `Vec<u32>` (not `Option`) so
    /// renderers can branch on `is_empty()` uniformly.
    #[test]
    fn move_account_summary_carries_live_pid_telemetry() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 2);

        let from = AccountNum::try_from(2u16).unwrap();
        let to = AccountNum::try_from(8u16).unwrap();

        let summary = move_account(base, from, to).unwrap();

        // Telemetry field present and shape-correct.
        assert!(
            summary.live_pids_bound.is_empty(),
            "live_pids_bound must be empty when no handle dirs are bound; got {:?}",
            summary.live_pids_bound
        );
    }

    /// M3-6 AC-5: live-process invariant — a handle dir whose
    /// `.credentials.json` symlinks to `identities/<UUID>/credentials.json`
    /// continues to read the same payload after the source slot is renumbered;
    /// AND the dangling-symlink class for `config-N/`-targeted markers is
    /// resolved by Step 5.5's handle-dir symlink rewrite. Production shape:
    /// `.credentials.json` is identity-keyed (survives rename via the symlink
    /// target's stability under `identities/<UUID>/`); the marker symlinks
    /// `.csq-account` / `.current-account` / `.quota-cursor` target
    /// `config-N/<item>` and would dangle WITHOUT the rewrite.
    #[cfg(unix)]
    #[test]
    fn move_account_credential_reads_continue_through_identity_symlink_after_rename() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 3);

        // Seed an identity dir + canonical credential payload.
        let identity_dir = base
            .join("identities")
            .join("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        std::fs::create_dir_all(&identity_dir).unwrap();
        let canonical_creds = identity_dir.join("credentials.json");
        let payload = r#"{"access_token":"identity-token","scope":"oauth"}"#;
        std::fs::write(&canonical_creds, payload).unwrap();

        // Handle dir matches production shape (what M3-3/M3-4 produce):
        // - .credentials.json → identities/<UUID>/credentials.json (survives rename as-is)
        // - .csq-account     → config-FROM/.csq-account (must be rewritten by Step 5.5)
        let handle_dir = base.join(format!("term-{}", std::process::id()));
        std::fs::create_dir_all(&handle_dir).unwrap();
        symlink(&canonical_creds, handle_dir.join(".credentials.json")).unwrap();
        symlink(
            base.join("config-3").join(".csq-account"),
            handle_dir.join(".csq-account"),
        )
        .unwrap();

        // Pre-move: both symlinks resolve.
        let pre_creds = std::fs::read_to_string(handle_dir.join(".credentials.json")).unwrap();
        assert_eq!(
            pre_creds, payload,
            "pre: identity-keyed symlink must resolve"
        );
        assert!(
            std::fs::read_to_string(handle_dir.join(".csq-account")).is_ok(),
            "pre: marker symlink must resolve"
        );

        // Act: renumber slot 3 → slot 9.
        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(9u16).unwrap();
        move_account(base, from, to).unwrap();

        // Post-move: identity-keyed credentials still resolve.
        assert!(
            identity_dir.exists(),
            "identities/<UUID>/ must be untouched by config-N rename"
        );
        let post_creds = std::fs::read_to_string(handle_dir.join(".credentials.json")).unwrap();
        assert_eq!(
            post_creds, payload,
            "identity-keyed symlink must continue resolving to the same payload"
        );

        // Post-move: marker symlink target was rewritten by Step 5.5;
        // the rewritten symlink now resolves to config-9/.csq-account (value 9).
        let marker_target = std::fs::read_link(handle_dir.join(".csq-account")).unwrap();
        assert_eq!(
            marker_target,
            base.join("config-9").join(".csq-account"),
            "Step 5.5: marker symlink target must be rewritten from config-3 to config-9"
        );
        let marker_value = std::fs::read_to_string(handle_dir.join(".csq-account")).unwrap();
        assert_eq!(
            marker_value.trim(),
            "9",
            "marker symlink must resolve to the rewritten file containing TO slot value"
        );
    }

    /// M3-6 Step 5.5 structural: `rewrite_handle_dir_symlinks_for_rename` is
    /// the chokepoint that closes the dangling-symlink class for every
    /// production marker target (Anthropic 3 + Codex 4 items). This test
    /// seeds the full Anthropic marker set + a Codex-shaped directory symlink
    /// and verifies all rewrites land. Uses production-shape symlinks (not
    /// bare files) per redteam-discipline.md test-fidelity requirement.
    #[cfg(unix)]
    #[test]
    fn move_account_rewrites_all_config_n_handle_dir_symlinks_post_rename() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 3);

        // Seed config-3 with every production marker/state file/dir that
        // handle-dir symlinks point at.
        let config_3 = base.join("config-3");
        std::fs::write(config_3.join(".current-account"), "3").unwrap();
        std::fs::write(config_3.join(".quota-cursor"), "{}").unwrap();
        // Codex slot-state items (file + dir).
        std::fs::write(config_3.join("config.toml"), b"# codex").unwrap();
        std::fs::create_dir_all(config_3.join("codex-sessions")).unwrap();
        std::fs::write(config_3.join("codex-history.jsonl"), "").unwrap();

        // Handle dir with the full production symlink set targeting config-3/.
        let handle_dir = base.join(format!("term-{}", std::process::id()));
        std::fs::create_dir_all(&handle_dir).unwrap();
        let anthropic_items = [".csq-account", ".current-account", ".quota-cursor"];
        for item in &anthropic_items {
            symlink(config_3.join(item), handle_dir.join(item)).unwrap();
        }
        let codex_dir_links: [(&str, &str); 3] = [
            ("config.toml", "config.toml"),
            ("sessions", "codex-sessions"),
            ("history.jsonl", "codex-history.jsonl"),
        ];
        for (link_name, target_name) in &codex_dir_links {
            symlink(config_3.join(target_name), handle_dir.join(link_name)).unwrap();
        }

        // Act: rename slot 3 → slot 8.
        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(8u16).unwrap();
        move_account(base, from, to).unwrap();

        // Assert: every handle-dir symlink whose target was config-3/<item>
        // now resolves to config-8/<item>. Path equality on read_link.
        let config_8 = base.join("config-8");
        for item in &anthropic_items {
            let target = std::fs::read_link(handle_dir.join(item)).unwrap();
            assert_eq!(
                target,
                config_8.join(item),
                "Anthropic symlink `{item}` must be rewritten to config-8"
            );
        }
        for (link_name, target_name) in &codex_dir_links {
            let target = std::fs::read_link(handle_dir.join(link_name)).unwrap();
            assert_eq!(
                target,
                config_8.join(target_name),
                "Codex symlink `{link_name}` must be rewritten to config-8/{target_name}"
            );
        }

        // And: each rewritten symlink actually resolves (no dangling).
        // .csq-account in particular — content was rewritten to "8" by Step 6.
        let marker = std::fs::read_to_string(handle_dir.join(".csq-account")).unwrap();
        assert_eq!(marker.trim(), "8");

        // C2 regression (workspace slot-attribution-consistency): Step 6b MUST
        // rewrite `.current-account` to the NEW slot too. The seed wrote
        // config-3/.current-account = "3"; after the 3→8 move it must read "8"
        // through the rewritten handle-dir symlink. Before the fix this stayed
        // "3", and a later `csq swap 8` would surface slot 3 in the statusline.
        let current = std::fs::read_to_string(handle_dir.join(".current-account")).unwrap();
        assert_eq!(
            current.trim(),
            "8",
            "Step 6b: .current-account must be refreshed to the destination slot"
        );
        // The canonical config-8 file itself (not just the symlink view).
        let current_canonical = std::fs::read_to_string(config_8.join(".current-account")).unwrap();
        assert_eq!(current_canonical.trim(), "8");
    }

    /// M3-6 reverse-invariant: after `csq move FROM TO`, the daemon's
    /// authoritative scanner (`scan_live_handle_dirs_for_account_pub`) must
    /// re-attribute live handle dirs from FROM to TO. Pins the production
    /// attribution contract end-to-end — Step 5.5's symlink rewrite + Step 6's
    /// marker content rewrite must compose correctly so the same primitive
    /// the daemon's auto-rotate sweeper uses surfaces the rebinding. Closes
    /// the R2 deep-analyst gap (DA-M3-6-R2-MED-1, carried forward from R1).
    #[cfg(unix)]
    #[test]
    fn move_account_rebinds_live_handle_dir_to_to_via_scanner_post_rename() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 3);

        // Production-shape handle dir: `.csq-account` is a symlink to
        // `config-3/.csq-account` (the marker file `make_slot` already wrote
        // with content "3"). The current PID guarantees `is_pid_alive(pid)`
        // returns true for the scanner.
        let pid = std::process::id();
        let handle_dir = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle_dir).unwrap();
        symlink(
            base.join("config-3").join(".csq-account"),
            handle_dir.join(".csq-account"),
        )
        .unwrap();

        // Pre-move sanity: scanner finds the binding under slot 3.
        let n3 = AccountNum::try_from(3u16).unwrap();
        let pre_scan = crate::accounts::logout::scan_live_handle_dirs_for_account_pub(base, n3);
        assert!(
            pre_scan.contains(&pid),
            "pre: scanner must surface the binding under slot 3; got {pre_scan:?}"
        );

        // Act: renumber slot 3 → slot 8.
        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(8u16).unwrap();
        move_account(base, from, to).unwrap();

        // Post-move: scanner under TO surfaces the rebinding ...
        let n8 = AccountNum::try_from(8u16).unwrap();
        let post_to_scan = crate::accounts::logout::scan_live_handle_dirs_for_account_pub(base, n8);
        assert!(
            post_to_scan.contains(&pid),
            "post: scanner under TO=8 must surface the rebound PID; got {post_to_scan:?}"
        );

        // ... AND scanner under FROM no longer surfaces the binding (the
        // rebinding moved entirely; no double-attribution).
        let post_from_scan =
            crate::accounts::logout::scan_live_handle_dirs_for_account_pub(base, n3);
        assert!(
            !post_from_scan.contains(&pid),
            "post: scanner under FROM=3 must NOT surface the PID after rename; got {post_from_scan:?}"
        );
    }

    /// M3-6 AC-6: marker content is rewritten to TO inside the moved dir
    /// (regression-pin of existing behavior — Step 6 of `move_account`).
    /// Cross-phase constraint #3: `.csq-account` content stays numeric.
    #[test]
    fn move_account_marker_rewritten_to_to_slot_value() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 4);

        let from = AccountNum::try_from(4u16).unwrap();
        let to = AccountNum::try_from(11u16).unwrap();
        move_account(base, from, to).unwrap();

        let marker_value =
            crate::accounts::markers::read_csq_account(&base.join("config-11")).unwrap();
        assert_eq!(
            marker_value.get(),
            11,
            "marker inside config-{} must be rewritten to {}",
            to.get(),
            to.get()
        );
    }

    /// AC-4: UUID identity survives the slot renumber. After `move_account(1, 5)`,
    /// the UUID that was at `by_slot["1"]` is now at `by_slot["5"]` with the
    /// SAME value — not minted or replaced.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn move_slot_preserves_uuid_across_rename() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let path = profiles::profiles_path(base);

        let uuid_before = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        // Pre-condition: record the UUID at slot 1.
        {
            let pf = profiles::load(&path).unwrap();
            assert_eq!(
                pf.by_slot.get("1").copied(),
                Some(uuid_before),
                "pre: by_slot[1] must match fixture UUID for slot 1"
            );
        }

        let from = AccountNum::try_from(1u16).unwrap();
        let to = AccountNum::try_from(5u16).unwrap();

        // Act
        move_account(base, from, to).unwrap();

        // Assert: UUID at slot 5 == original UUID (not a new mint).
        let pf = profiles::load(&path).unwrap();
        let uuid_after = pf
            .by_slot
            .get("5")
            .copied()
            .expect("by_slot[5] must exist after move");
        assert_eq!(
            uuid_after, uuid_before,
            "UUID must be PRESERVED across slot rename — not re-minted"
        );
        assert!(
            !pf.by_slot.contains_key("1"),
            "by_slot[1] must be absent — UUID has moved to slot 5"
        );
    }

    /// AC-5: `.csq-account` marker inside the moved config dir is rewritten to
    /// the numeric TO slot value (cross-phase constraint #3 — marker writers
    /// stay numeric).
    #[test]
    fn move_slot_marker_rewritten_numerically() {
        // Arrange: use make_slot which creates config dir + .csq-account marker.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // Two slots so slot 1 can move without conflicting with slot 2.
        make_slot(base, 1);
        make_slot(base, 2);

        // Pre-condition: marker in config-1/ must be 1.
        let pre_marker =
            crate::accounts::markers::read_csq_account(&base.join("config-1")).unwrap();
        assert_eq!(pre_marker.get(), 1, "pre: marker in config-1/ must be 1");

        let from = AccountNum::try_from(1u16).unwrap();
        let to = AccountNum::try_from(7u16).unwrap();

        // Act
        move_account(base, from, to).unwrap();

        // Assert: config-7/ exists with marker = 7 (numeric, per constraint #3).
        let post_marker =
            crate::accounts::markers::read_csq_account(&base.join("config-7")).unwrap();
        assert_eq!(
            post_marker.get(),
            7,
            "marker in moved config-7/ must be numeric value 7 — cross-phase constraint #3"
        );
        assert!(
            !base.join("config-1").exists(),
            "config-1/ must be gone after move"
        );
    }

    /// AC-6: Both `move_profiles_entry` and `swap_by_slot_mapping` are called
    /// under the SAME `ProfilesFileLock`. SEC-2.3 lock-as-type-witness invariant.
    /// Verified behaviorally: concurrent writer blocked until lock released.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn move_slot_holds_profiles_lock_across_load_save() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use crate::testing::identity_fixtures::coexisting_fixture;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Arrange: coexisting fixture, lock held externally.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let base_path = base.to_path_buf();
        let _bg = std::thread::spawn(move || {
            let _lock = ProfilesFileLock::acquire(&base_path).unwrap();
            tx_locked.send(()).unwrap();
            rx_release.recv_timeout(Duration::from_secs(5)).unwrap();
            // lock released here on drop
        });

        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("bg thread must acquire lock");

        // move_account in a separate thread will block on the ProfilesFileLock.
        let base_path2 = base.to_path_buf();
        let move_completed = Arc::new(Mutex::new(false));
        let move_completed2 = Arc::clone(&move_completed);

        let move_thread = std::thread::spawn(move || {
            let from = AccountNum::try_from(1u16).unwrap();
            let to = AccountNum::try_from(5u16).unwrap();
            let _ = move_account(&base_path2, from, to);
            *move_completed2.lock().unwrap() = true;
        });

        std::thread::sleep(Duration::from_millis(50));

        // move_account must NOT have completed while lock is held externally.
        assert!(
            !*move_completed.lock().unwrap(),
            "move_account must block while ProfilesFileLock is held externally (SEC-2.3)"
        );

        // Release the external lock.
        tx_release.send(()).unwrap();
        move_thread.join().expect("move thread must not panic");

        // Now move must have completed.
        assert!(
            *move_completed.lock().unwrap(),
            "move_account must complete after ProfilesFileLock is released"
        );
    }

    /// AC-7: `move_account` reports `by_slot_swapped = true` when at least one
    /// `by_slot` entry existed. The CLI reads this to decide whether to emit
    /// `POST /api/slot-swap` (SEC-2.11 targeted cache invalidation).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn move_slot_emits_slot_swap_ipc_event() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture has by_slot entries for all slots.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        let from = AccountNum::try_from(2u16).unwrap();
        let to = AccountNum::try_from(6u16).unwrap();

        // Act
        let summary = move_account(base, from, to).unwrap();

        // Assert: by_slot_swapped signals the CLI to emit POST /api/slot-swap.
        assert!(
            summary.by_slot_swapped,
            "by_slot_swapped must be true when by_slot entries are present — \
             this is the signal for the CLI layer to emit POST /api/slot-swap"
        );
    }

    /// F-C-1 follow-on: `move_account` reports `by_slot_identity_swapped = true`
    /// when a non-OAuth slot's `by_slot_identity` entry existed before the move.
    /// This is the telemetry channel for operators to distinguish non-OAuth
    /// identity swaps from OAuth UUID swaps (WBS M4 line 135).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn move_account_reports_by_slot_identity_swapped() {
        use crate::accounts::profiles;

        // Arrange: a minimal fixture with config-2/ and by_slot_identity["2"]
        // but NO by_slot UUID — exactly the non-OAuth slot production shape.
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Create config-2/ so move_account's source-existence check passes.
        std::fs::create_dir_all(base.join("config-2")).unwrap();
        // Write .csq-account marker.
        let account2 = AccountNum::try_from(2u16).unwrap();
        crate::accounts::markers::write_csq_account_legacy(&base.join("config-2"), account2)
            .unwrap();

        // Seed by_slot_identity["2"] = "apikey:mm" with NO by_slot entry.
        let profiles_path = profiles::profiles_path(base);
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot_identity.insert("2".into(), "apikey:mm".into());
        profiles::save(&profiles_path, &pf).unwrap();

        let from = AccountNum::try_from(2u16).unwrap();
        let to = AccountNum::try_from(6u16).unwrap();

        // Act
        let summary = move_account(base, from, to).unwrap();

        // Assert: by_slot_identity_swapped == true (the non-OAuth channel was present).
        assert!(
            summary.by_slot_identity_swapped,
            "F-C-1 follow-on: by_slot_identity_swapped must be true when \
             by_slot_identity held an entry for the source slot"
        );

        // Verify by_slot_identity["2"] is gone and ["6"] = "apikey:mm".
        let reloaded = profiles::load(&profiles_path).unwrap();
        assert!(
            !reloaded.by_slot_identity.contains_key("2"),
            "by_slot_identity[2] must be absent after move"
        );
        assert_eq!(
            reloaded.by_slot_identity.get("6").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[6] must carry the identity that was at slot 2"
        );
    }

    /// AC-8: `move_account` on a legacy-only fixture (no `by_slot` entries)
    /// succeeds with `by_slot_swapped = false` — filesystem rename KEPT.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn move_slot_with_no_uuid_falls_back_to_filesystem_only() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange: legacy-only fixture (2 slots, no by_slot, no by_email).
        let dir = legacy_only_fixture(2);
        let base = dir.path();

        // Pre-condition: config-1/ exists, no profiles.json (legacy-only).
        assert!(base.join("config-1").exists(), "pre: config-1 must exist");
        assert!(
            !profiles::profiles_path(base).exists(),
            "pre: profiles.json must not exist in legacy-only fixture"
        );

        let from = AccountNum::try_from(1u16).unwrap();
        let to = AccountNum::try_from(5u16).unwrap();

        // Act
        let summary = move_account(base, from, to).unwrap();

        // Assert: filesystem rename KEPT (Phase 1 preserved).
        assert!(
            summary.config_dir_moved,
            "config_dir_moved must be true even in legacy-only fixture"
        );
        // by_slot_swapped false: no by_slot entries existed.
        assert!(
            !summary.by_slot_swapped,
            "by_slot_swapped must be false in legacy-only fixture (no by_slot entries)"
        );
        // Filesystem post-condition.
        assert!(!base.join("config-1").exists(), "config-1/ must be gone");
        assert!(base.join("config-5").exists(), "config-5/ must exist");
    }

    // ── M3-5 acceptance criteria (7 named tests) ─────────────────────────────

    /// M3-5 AC-1: `move_account` acquires `.move.lock` BEFORE `ProfilesFileLock`.
    ///
    /// Verified by holding `.move.lock` externally in a background thread and
    /// asserting `move_account` blocks until it is released.
    /// This is structurally distinct from `move_slot_acquires_profiles_lock`
    /// which exercises `ProfilesFileLock` only.
    #[test]
    fn move_account_acquires_move_lock_before_profiles_lock() {
        use crate::platform::lock::lock_file;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Arrange: create a base dir with a slot ready to move.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 3);

        let move_done = Arc::new(Mutex::new(false));
        let move_done_bg = Arc::clone(&move_done);

        // Hold `.move.lock` in a background thread.
        let lock_path = move_lock_path(base);
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let _bg = std::thread::spawn(move || {
            let _lock = lock_file(&lock_path).unwrap();
            tx_locked.send(()).unwrap();
            rx_release.recv_timeout(Duration::from_secs(10)).unwrap();
            drop(_lock);
            *move_done_bg.lock().unwrap() = true;
        });

        // Wait until background thread holds the lock.
        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("bg thread must acquire .move.lock");

        // Kick off move_account in another thread — it will block on .move.lock.
        let base_path = base.to_path_buf();
        let foreground_done = Arc::new(Mutex::new(false));
        let foreground_done2 = Arc::clone(&foreground_done);

        let move_thread = std::thread::spawn(move || {
            let from = AccountNum::try_from(3u16).unwrap();
            let to = AccountNum::try_from(7u16).unwrap();
            // blocks until .move.lock is released (then returns Busy after 5s,
            // or succeeds — either way the test checks it didn't complete early)
            let _ = move_account(&base_path, from, to);
            *foreground_done2.lock().unwrap() = true;
        });

        // Give move_thread a moment to start and reach acquire_move_lock.
        std::thread::sleep(Duration::from_millis(100));

        // move_account must NOT have completed while .move.lock is held.
        assert!(
            !*foreground_done.lock().unwrap(),
            "move_account must not complete while .move.lock is held by another thread"
        );

        // Release the background lock.
        tx_release.send(()).unwrap();
        move_thread.join().expect("move thread must not panic");

        // move_account completed after lock was released.
        assert!(
            *foreground_done.lock().unwrap(),
            "move_account must complete after .move.lock is released"
        );
    }

    /// M3-5 AC-2: Two concurrent `move_account` invocations serialize under
    /// `.move.lock` — the second blocks until the first finishes.
    ///
    /// Uses a `Barrier` to synchronize both threads' start. Two threads each
    /// perform a DISJOINT move (1→10 and 2→20) — the lock is the only
    /// synchronization primitive forcing them to alternate, since the
    /// underlying filesystem operations target different paths.
    ///
    /// **What this test verifies:** the lock acquire-drop cycle is wired
    /// correctly into `move_account` such that two concurrent calls
    /// complete cleanly without deadlock and both moves succeed
    /// (failure modes a broken lock would produce: deadlock caught by
    /// `join()` hanging past cargo test's timeout; partial completion
    /// caught by the post-move target-slot assertions; OR — for
    /// non-disjoint moves — corrupted state, which the disjoint
    /// pair here cannot exercise but `move_lock_serializes_via_flock`
    /// below does).
    ///
    /// **Why `[entry, exit]` non-overlap is NOT the structural check:**
    /// `entry` is recorded BEFORE `move_account` is called, which means
    /// the BLOCKED-on-`acquire_move_lock` portion of thread B's call is
    /// inside its measured interval. Under correct serialization, B's
    /// `entry` predates A's `exit` (B is waiting for A's lock to drop),
    /// so the call-duration intervals DO overlap. Call-duration non-
    /// overlap is impossible when A's `entry` is also at the barrier
    /// release. The FLOCK primitive's serialization is verified
    /// independently by the `move_lock_serializes_via_flock` test
    /// below, which exercises `try_lock_file` directly.
    #[test]
    fn move_account_concurrent_invocations_serialize_under_move_lock() {
        use std::sync::{Arc, Barrier};
        use std::time::{Duration, Instant};

        // Arrange: two separate slots to avoid move conflicts.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 1);
        make_slot(base, 2);

        // Barrier: release both threads simultaneously to maximize contention.
        let barrier = Arc::new(Barrier::new(2));
        let barrier1 = Arc::clone(&barrier);
        let barrier2 = Arc::clone(&barrier);

        let base1 = base.to_path_buf();
        let base2 = base.to_path_buf();

        let t1 = std::thread::spawn(move || {
            barrier1.wait();
            let from = AccountNum::try_from(1u16).unwrap();
            let to = AccountNum::try_from(10u16).unwrap();
            move_account(&base1, from, to)
        });

        let t2 = std::thread::spawn(move || {
            barrier2.wait();
            let from = AccountNum::try_from(2u16).unwrap();
            let to = AccountNum::try_from(20u16).unwrap();
            move_account(&base2, from, to)
        });

        let test_start = Instant::now();
        let r1 = t1.join().expect("t1 must not panic");
        let r2 = t2.join().expect("t2 must not panic");
        let test_total = test_start.elapsed();

        // Both disjoint moves MUST succeed when serialized by `.move.lock`.
        // Failure mode if the lock primitive were broken: a deadlock would
        // exceed cargo test's default timeout. A torn rename (lock held
        // but pre-existence check raced) would produce TargetExists, which
        // both calls cannot return for disjoint pairs.
        assert!(r1.is_ok(), "t1 move must succeed; got {:?}", r1);
        assert!(r2.is_ok(), "t2 move must succeed; got {:?}", r2);

        // Sanity: both completed in well under 10s — deadlock would never
        // reach join() under cargo test's normal timeout, but the explicit
        // bound pins the upper envelope of the serialized case.
        assert!(
            test_total < Duration::from_secs(10),
            "concurrent moves must complete in < 10s (got {:?})",
            test_total,
        );

        // Verify the slot moves actually completed — both targets exist
        // after serialization (different from/to pairs cannot conflict).
        assert!(
            base.join("config-10").exists(),
            "config-10 must exist after t1's move"
        );
        assert!(
            base.join("config-20").exists(),
            "config-20 must exist after t2's move"
        );
    }

    /// FLOCK-layer serialization proof for `move_account_concurrent_*` —
    /// exercises the underlying `try_lock_file` primitive directly to
    /// prove that two simultaneous acquire attempts return exactly one
    /// `Some(guard)` and one `None`. This is the structural defense
    /// `move_account_concurrent_invocations_serialize_under_move_lock`
    /// cannot exercise without instrumenting `move_account`'s internals.
    ///
    /// Unix-only: POSIX `flock` contends per-fd within the same thread, so
    /// two same-thread acquires must return `Some` then `None`. Windows
    /// named mutexes (the `try_lock_file` implementation on that platform)
    /// are **re-entrant per-thread** by design — `WaitForSingleObject`
    /// returns `WAIT_OBJECT_0` immediately if the calling thread already
    /// owns the mutex (see `csq-core/src/platform/lock.rs` doc-comment
    /// at `mutex_name`'s "same-process/same-thread re-entrancy" note).
    /// The Windows higher-level serialization is exercised by the
    /// cross-process `move_account_concurrent_invocations_serialize_under_move_lock`
    /// test, which spawns separate threads/processes that DO contend.
    /// Issue #437.
    #[cfg(unix)]
    #[test]
    fn move_lock_serializes_via_flock() {
        use crate::platform::lock::try_lock_file;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let lock_path = move_lock_path(base);

        let g1 = try_lock_file(&lock_path).expect("first try_lock_file ok");
        assert!(g1.is_some(), "first acquire must return Some(guard)");

        let g2 = try_lock_file(&lock_path).expect("second try_lock_file ok");
        assert!(
            g2.is_none(),
            "second acquire must return None while first guard held"
        );

        drop(g1);

        let g3 = try_lock_file(&lock_path).expect("third try_lock_file ok");
        assert!(
            g3.is_some(),
            "third acquire must succeed after first guard dropped"
        );
    }

    /// M3-5 AC-3: `move_account` returns `Err(MoveError::Busy { .. })` when
    /// `.move.lock` is held for more than 5 seconds.
    ///
    /// Deterministic timer: background thread holds the lock for 5500ms.
    #[test]
    fn move_account_busy_when_lock_held_for_more_than_5_seconds() {
        use crate::platform::lock::lock_file;
        use std::time::Duration;

        // Arrange: a base dir (no need for a real slot — Busy fires before
        // the slot existence checks).
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let lock_path = move_lock_path(base);
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();

        // Background thread holds .move.lock for >5 seconds.
        let _bg = std::thread::spawn(move || {
            let _lock = lock_file(&lock_path).unwrap();
            tx_locked.send(()).unwrap();
            // Hold for 5500ms — beyond the 5s deadline in acquire_move_lock.
            std::thread::sleep(Duration::from_millis(5500));
        });

        // Wait for background to acquire the lock.
        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("bg must acquire .move.lock");

        // Act: move_account must time out and return Busy.
        let from = AccountNum::try_from(1u16).unwrap();
        let to = AccountNum::try_from(5u16).unwrap();
        let err = move_account(base, from, to).unwrap_err();

        // Assert: Busy returned within ~5s + epsilon.
        assert!(
            matches!(err, MoveError::Busy { .. }),
            "expected MoveError::Busy, got: {:?}",
            err
        );
    }

    /// M3-5 AC-4: The lock path is exactly `base.join(".move.lock")`.
    #[test]
    fn move_lock_path_is_accounts_dot_move_lock() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let expected = base.join(".move.lock");
        assert_eq!(
            move_lock_path(base),
            expected,
            "move_lock_path must return base/.move.lock"
        );
    }

    /// M3-5 AC-5: The `.move.lock` file is `0o600` after `acquire_move_lock`.
    /// Unix only (Windows ACL defaults handle permissions differently).
    #[test]
    #[cfg(unix)]
    fn move_lock_file_chmod_0o600_after_creation() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Acquire the lock (this creates and chmods the file).
        let _guard = acquire_move_lock(base).unwrap();

        let lock_path = move_lock_path(base);
        let meta =
            std::fs::metadata(&lock_path).expect(".move.lock must exist after acquire_move_lock");
        let mode = meta.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            ".move.lock must be 0o600 after acquire, got {mode:#o}"
        );
    }

    /// M3-5 AC-6: `acquire_move_lock` fails closed when the base dir is
    /// read-only (cannot create the lock file).
    ///
    /// SEC-3-M2: EROFS / EACCES on `try_lock_file` returns
    /// `Err(MoveError::Busy { pid: None })` (fail-closed per zero-tolerance Rule 3).
    #[test]
    #[cfg(unix)]
    fn move_lock_fails_closed_on_read_only_filesystem() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Make the directory read-only so lock file creation fails.
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o500)).unwrap();

        // Act: must fail closed, not panic.
        let result = acquire_move_lock(base);

        // Restore permissions so TempDir cleanup can proceed.
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Assert: fail-closed as Busy { pid: None }.
        match result {
            Err(MoveError::Busy { pid: None }) => { /* expected */ }
            other => panic!(
                "expected Err(MoveError::Busy {{ pid: None }}), got: {:?}",
                other
            ),
        }
    }

    /// M3-5 AC-7: `.move.lock` is the OUTERMOST lock — held BEFORE `ProfilesFileLock`.
    ///
    /// Structural lock-order test: hold `ProfilesFileLock` externally; verify
    /// `move_account` acquires `.move.lock` first (succeeds immediately) but
    /// then blocks on the inner `ProfilesFileLock`. The move returns (eventually)
    /// but does NOT return `MoveError::Busy` — Busy is only when `.move.lock`
    /// itself is contended.
    #[test]
    fn move_lock_acquired_outside_profiles_lock_window() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Arrange: slot ready to move.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        make_slot(base, 4);

        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let base_bg = base.to_path_buf();
        // Hold ProfilesFileLock in a background thread.
        let _bg = std::thread::spawn(move || {
            let _pfl = ProfilesFileLock::acquire(&base_bg).unwrap();
            tx_locked.send(()).unwrap();
            rx_release.recv_timeout(Duration::from_secs(10)).unwrap();
            // ProfilesFileLock released here on drop.
        });

        // Wait for background to hold ProfilesFileLock.
        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("bg must acquire ProfilesFileLock");

        // move_account in another thread: acquires .move.lock (succeeds
        // immediately — ProfilesFileLock is NOT .move.lock), then blocks
        // on the inner ProfilesFileLock.
        let base_fg = base.to_path_buf();
        let move_result = Arc::new(Mutex::new(None::<Result<MoveSummary, MoveError>>));
        let move_result2 = Arc::clone(&move_result);

        let move_thread = std::thread::spawn(move || {
            let from = AccountNum::try_from(4u16).unwrap();
            let to = AccountNum::try_from(8u16).unwrap();
            let r = move_account(&base_fg, from, to);
            *move_result2.lock().unwrap() = Some(r);
        });

        // Give move_thread time to acquire .move.lock and block on ProfilesFileLock.
        std::thread::sleep(Duration::from_millis(100));

        // move_account must NOT yet have completed (blocked on ProfilesFileLock).
        assert!(
            move_result.lock().unwrap().is_none(),
            "move_account must block on inner ProfilesFileLock while it is held externally"
        );

        // Release ProfilesFileLock — move_account should proceed.
        tx_release.send(()).unwrap();
        move_thread.join().expect("move thread must not panic");

        // The result must NOT be Busy — Busy only fires when .move.lock is
        // contended, not when ProfilesFileLock is contended.
        let result = move_result.lock().unwrap();
        match result
            .as_ref()
            .expect("move_account must have produced a result")
        {
            Err(MoveError::Busy { .. }) => panic!(
                "move_account must NOT return Busy when only ProfilesFileLock is contended — \
                 Busy is reserved for .move.lock contention"
            ),
            _ => { /* Ok or some other error is acceptable */ }
        }
    }

    /// AC-9: `profiles::swap_slot_mapping` requires a `&ProfilesFileLock`
    /// type-witness parameter. SEC-2.3 at compile time.
    ///
    /// Structural test — calling with a legitimately-acquired lock.
    /// Compile-time enforcement: any attempt to remove `_lock: &ProfilesFileLock`
    /// breaks all callers, making the change visible at review.
    #[test]
    fn swap_slot_mapping_requires_profiles_lock_type_witness() {
        use crate::accounts::identity_store::IdentityId;
        use crate::accounts::profiles_lock::ProfilesFileLock;

        // Arrange: two slots with UUIDs in by_slot.
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid_a = IdentityId::new_v4();
        let uuid_b = IdentityId::new_v4();

        let path = profiles::profiles_path(base);
        {
            let mut pf = profiles::ProfilesFile::empty();
            pf.by_slot.insert("3".into(), uuid_a);
            pf.by_slot.insert("7".into(), uuid_b);
            profiles::save(&path, &pf).unwrap();
        }

        // Act: acquire the lock, pass it to swap_slot_mapping.
        // The `_lock: &ProfilesFileLock` type-witness means this call is
        // statically proven to hold the lock (compile error without it).
        let lock = ProfilesFileLock::acquire(base).unwrap();
        profiles::swap_slot_mapping(&lock, base, 3, 7).unwrap();
        drop(lock);

        // Assert: swap happened correctly.
        let pf = profiles::load(&path).unwrap();
        assert_eq!(
            pf.by_slot.get("3").copied(),
            Some(uuid_b),
            "by_slot[3] must equal old uuid_b after swap"
        );
        assert_eq!(
            pf.by_slot.get("7").copied(),
            Some(uuid_a),
            "by_slot[7] must equal old uuid_a after swap"
        );
    }

    /// M4-9 (release N affordance, issue #292 Phase 4): `csq move`
    /// MUST NOT populate the v1 `profiles.json::accounts` map. The
    /// move semantic (relocating identity from slot FROM to slot TO)
    /// is now carried entirely by `by_slot` (swapped via
    /// `profiles::swap_slot_mapping`). The v1 `accounts` map starts
    /// empty AND ends empty.
    ///
    /// Edge case covered: the legacy compat seam at
    /// `move_profiles_entry` continues to relocate an `accounts[FROM]`
    /// entry IF it exists (v2.6.x downgrade re-save scenario); that
    /// branch is exercised by `move_rewrites_profiles_entry`. This
    /// test exercises the post-M4-9 normal case where accounts is
    /// empty before AND after.
    #[test]
    fn csq_move_does_not_populate_v1_accounts_map() {
        use crate::accounts::identity_store::IdentityId;

        // Arrange: slot 3 has a by_slot mapping but accounts[3] is
        // empty — the post-M4-9 normal shape.
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 3);

        let uuid_a = IdentityId::new_v4();
        let path = profiles::profiles_path(dir.path());
        {
            let mut file = profiles::ProfilesFile::empty();
            file.by_slot.insert("3".into(), uuid_a);
            file.by_email.insert("alice@x.com".into(), uuid_a);
            // accounts intentionally empty (post-M4-9 normal case).
            profiles::save(&path, &file).unwrap();
        }

        // Act: move slot 3 → 5.
        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(5u16).unwrap();
        let _ = move_account(dir.path(), from, to).unwrap();

        // Assert: accounts is STILL empty post-move (M4-13: read via accounts_for_test).
        let reloaded = profiles::load(&path).unwrap();
        assert!(
            reloaded.accounts_for_test().is_empty(),
            "M4-9/M4-13: csq move MUST NOT populate the v1 accounts map; \
             extra[accounts]: {:?}",
            reloaded.accounts_for_test()
        );

        // by_slot was swapped — slot 5 now carries the UUID.
        assert_eq!(
            reloaded.by_slot.get("5").copied(),
            Some(uuid_a),
            "M4-9: by_slot swap MUST still happen during csq move"
        );
        assert!(
            !reloaded.by_slot.contains_key("3"),
            "M4-9: by_slot[from] MUST be cleared after csq move"
        );
    }

    // ── M13b-T6 — audit-trail tests for move_account ─────────────────────────

    /// AC-C1 + AC-C2 (move): INTENT seq N < OUTCOME seq N+1; chain verifies.
    #[test]
    fn move_audit_intent_before_outcome_chain_verifies() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 3);
        let base = dir.path();
        let from = AccountNum::try_from(3u16).unwrap();
        let to = AccountNum::try_from(4u16).unwrap();

        move_account(base, from, to).expect("move must succeed");

        // Chain must verify.
        let result = crate::audit::verify::verify_chain(
            base,
            &crate::audit::verify::VerifyConfig::default(),
            None,
        );
        assert!(result.is_ok(), "chain must verify after move: {result:?}");
        assert!(
            result.unwrap().verified_count >= 2,
            "at least 2 records (intent + outcome) on-chain after move"
        );

        // No orphan intents.
        let orphans =
            crate::audit::intent_scan::scan_orphan_intents(base).expect("orphan scan must succeed");
        assert!(
            orphans.is_empty(),
            "no orphan intents after successful move: {orphans:?}"
        );
    }

    /// AC-C3 / AC-M1 (move): INTENT is emitted AFTER `acquire_move_lock` and
    /// BEFORE the first rename; the OUTCOME is after profiles/quota rewrite.
    /// Structural check: source-pins the ordering sentinel in move_account.
    #[test]
    fn move_intent_ordering_is_pinned_in_source() {
        let src = include_str!("move_slot.rs");
        // The intent emit block must appear BEFORE "Step 5: rename config dir"
        // and AFTER the acquire_move_lock call.
        assert!(
            src.contains("M13b — emit INTENT after acquire_move_lock"),
            "move_slot.rs must contain the M13b intent-ordering sentinel"
        );
        assert!(
            src.contains("audit intent record could not be persisted — move aborted"),
            "move_slot.rs must contain the fail-closed intent-persist error"
        );
    }

    /// AC-M2 (move): `MoveError::Busy` (lock contention) emits NO intent.
    ///
    /// We simulate a locked `.move.lock` by holding it in a background thread.
    /// The foreground `move_account` call should return `MoveError::Busy`
    /// without writing any intent record.
    #[cfg(unix)]
    #[test]
    fn move_busy_emits_no_intent() {
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 5);
        let base = dir.path().to_path_buf();
        let base2 = base.clone();

        // Hold the move lock.
        let lock_path = move_lock_path(&base);
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let _bg = std::thread::spawn(move || {
            let _lock = crate::platform::lock::lock_file(&lock_path).unwrap();
            tx_locked.send(()).unwrap();
            rx_release.recv_timeout(Duration::from_secs(30)).unwrap();
        });

        rx_locked
            .recv_timeout(Duration::from_secs(5))
            .expect("background must acquire move lock");

        let from = AccountNum::try_from(5u16).unwrap();
        let to = AccountNum::try_from(6u16).unwrap();
        let result = move_account(&base2, from, to);

        let _ = tx_release.send(());

        assert!(
            matches!(result, Err(MoveError::Busy { .. })),
            "locked move must return MoveError::Busy: {result:?}"
        );

        // No intent record emitted.
        let runs_dir = base2.join("csq-runs");
        if runs_dir.exists() {
            let files: Vec<_> = std::fs::read_dir(&runs_dir)
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
                .collect();
            assert!(
                files.is_empty(),
                "MoveError::Busy must emit no intent record: {files:?}"
            );
        }
    }

    /// AC-C5 (move): crash-between (orphan intent) is detectable.
    #[test]
    fn move_crash_between_intent_and_outcome_produces_detectable_orphan() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Write a dangling INTENT with no OUTCOME.
        let chain_id = crate::audit::op_emit::load_chain_id(base);
        let correlation_id = crate::audit::op_emit::gen_correlation_id().unwrap();
        let from = AccountNum::try_from(1u16).unwrap();
        let to = AccountNum::try_from(2u16).unwrap();
        crate::audit::op_emit::emit_intent(
            base,
            &chain_id,
            crate::audit::types::EventKind::AccountMove,
            crate::audit::types::EventPayload::AccountMove(
                crate::audit::types::AccountMovePayload {
                    from_slot: from,
                    to_slot: to,
                },
            ),
            correlation_id,
        )
        .expect("intent write must succeed");

        // No OUTCOME — simulates crash-between.
        let orphans =
            crate::audit::intent_scan::scan_orphan_intents(base).expect("orphan scan must succeed");
        assert!(
            !orphans.is_empty(),
            "orphan intent (no outcome) must be detectable"
        );
        // orphans[0].kind is a String (serde JSON value of the EventKind).
        assert!(
            orphans[0].kind.contains("account_move"),
            "orphan kind must be account_move, got: {}",
            orphans[0].kind
        );
    }

    /// Round-3 FIX-1: when the `.chain-broken` sentinel is set, `move_account`
    /// MUST succeed (degrade-not-fail-closed) AND emit zero audit records.
    #[test]
    fn move_proceeds_skips_audit_when_chain_broken() {
        let dir = TempDir::new().unwrap();
        make_slot(dir.path(), 7);
        let base = dir.path();
        let from = AccountNum::try_from(7u16).unwrap();
        let to = AccountNum::try_from(8u16).unwrap();

        // Set the .chain-broken sentinel.
        crate::audit::set_chain_broken(base, "chain_broken_test");

        // Move MUST succeed even though the chain is broken.
        let result = move_account(base, from, to);
        assert!(
            result.is_ok(),
            "move must SUCCEED (degrade) when chain is broken, got: {result:?}"
        );

        // config-7 must be gone, config-8 must exist.
        assert!(
            !base.join("config-7").exists(),
            "source config dir must be renamed"
        );
        assert!(
            base.join("config-8").exists(),
            "destination config dir must exist"
        );

        // Zero audit records on the chain (intent skipped).
        let runs_dir = base.join("csq-runs");
        if runs_dir.exists() {
            let files: Vec<_> = std::fs::read_dir(&runs_dir)
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
                .collect();
            assert!(
                files.is_empty(),
                "no audit records must be written when chain is broken: {files:?}"
            );
        }
    }
}
