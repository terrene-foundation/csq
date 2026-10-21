//! Broker check — per-account token refresh with lock coordination.
//!
//! Called periodically (every 5 minutes) by the daemon or statusline.
//! Uses try-lock to ensure only one process refreshes at a time.

use super::sentinel;
use crate::accounts::{anthropic_identity as ai, identity_store, profiles};
use crate::credentials::{self, file, CredentialFile};
use crate::error::{BrokerError, CsqError};
use crate::http::codex as http_codex;
use crate::platform::lock;
use crate::types::AccountNum;
use std::path::Path;
use tracing::{debug, warn};

/// Refresh window: refresh if token expires within this many seconds.
/// 2 hours = 7200 seconds, per ADR-006.
pub const REFRESH_WINDOW_SECS: u64 = 7200;

#[cfg(test)]
thread_local! {
    static BROKER_SENTINEL_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static CODEX_AFTER_REFRESH_LOCK_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Result of a broker check.
#[derive(Debug)]
pub enum BrokerResult {
    /// Token is still valid, no action taken.
    Valid,
    /// Token was refreshed successfully.
    Refreshed,
    /// Another process is already refreshing (lock contention).
    /// The caller should NOT set a cooldown — the lock holder is
    /// doing the work and we'll pick up the result on the next tick.
    Skipped,
    /// Anthropic returned a rate-limit error (429 / `rate_limit_error`)
    /// for the primary refresh. Sibling recovery was suppressed to
    /// avoid further hammering the throttled endpoint. The caller
    /// MUST set a cooldown so the next tick does not retry immediately.
    RateLimited,
    /// Total failure — LOGIN-NEEDED.
    Failed(BrokerError),
}

/// Performs a broker check for a single account.
///
/// 1. Reads canonical credentials
/// 2. Checks if token is near expiry (2-hour window)
/// 3. Acquires per-account try-lock (skips if contention)
/// 4. Refreshes token via HTTP and writes to canonical (M3-7: live-mirror
///    fanout retired; handle-dir symlinks resolve to identity path)
///
/// The `http_post` parameter allows injection of the HTTP transport.
pub fn broker_check<F>(
    base_dir: &Path,
    account: AccountNum,
    http_post: F,
) -> Result<BrokerResult, CsqError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String> + Clone,
{
    // Capture slot custody before any credential read so a concurrent rebind
    // cannot attribute old healthy bytes or clear a new identity's failure.
    let captured = ai::capture_anthropic_binding(base_dir, account);
    // A busy profiles lock is contention, not a custody change: remember it so
    // the refusal below reports its own fixed-vocabulary tag.
    let capture_busy = matches!(captured, Err(ai::IdentityError::BindingBusy));
    // R3 corr L-1: the refusal tag alone said only "custody could not be
    // captured", hiding a persistent lock I/O fault (`Io`) behind a message
    // an operator reads as a custody race. The Debug variant name is fixed
    // vocabulary (unit variants, or slot numbers) — never a raw OS message.
    let capture_refusal = captured.as_ref().err().map(|error| format!("{error:?}"));
    let captured = captured.ok();
    // RN1-C (M4-12): resolve UUID-keyed identity path when by_slot is populated.
    // The numeric credentials/N.json path is retired as a WRITE destination;
    // post-login accounts have credentials ONLY at identities/<UUID>/credentials.json.
    // Mirrors the pattern already used in broker_codex_check (lines 236-242).
    // Fail-closed when no UUID mapping exists: return NoCredentials so the
    // daemon surfaces LOGIN-NEEDED rather than silently reading a stale numeric file.
    let canonical_path = match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => {
            // ROOT ruling A: a post-commit writer that could not take the
            // canonical lock leaves a durable rescue record; the next
            // refresher tick is where it is adopted. This is that tick.
            adopt_pending_rescue(base_dir, uuid);
            // D237 round-2 H-a (correctness N1 / security M3): a rescue that
            // is STILL pending after the adoption attempt means the canonical
            // file may hold the PRE-rotation refresh token, which the provider
            // has already consumed. Presenting it again is the token replay
            // the rescue protocol exists to prevent (a reuse-detecting
            // provider can revoke the whole grant family, including the
            // rescued pair), so NO provider request may run while the record
            // is unadopted. This is a skip with a fixed-vocabulary status —
            // never LOGIN-NEEDED, never a `broker_failed` sentinel: the pair
            // is durable and adoption retries next tick.
            if rescue_pending_for(base_dir, Some(uuid)) {
                warn!(
                    account = %account,
                    error_kind = "rescue_pending",
                    "refresh skipped: a rescued rotation is still pending adoption; \
                     no provider request is made and LOGIN-NEEDED is not set"
                );
                return Ok(BrokerResult::Skipped);
            }
            identity_store::credentials_path_for(base_dir, uuid)
        }
        None => {
            // Legacy install with no by_slot entry — fall back to numeric path.
            // Pre-RN1-C accounts never went through commit_anthropic_login, so the numeric
            // file is the authoritative read source until they re-login or Pass 0 runs.
            file::canonical_path(base_dir, account)
        }
    };
    let creds = match credentials::load(&canonical_path) {
        Ok(c) => c,
        Err(e) => return Err(CsqError::Credential(e)),
    };

    // Check if token needs refresh
    if !creds
        .expect_anthropic()
        .claude_ai_oauth
        .is_expired_within(REFRESH_WINDOW_SECS)
    {
        // Auto-clear stale broker_failed sentinel — if the daemon checked
        // this slot and the creds are healthy, any prior failure flag is
        // obsolete. Without this, a sentinel from a transient outage
        // (e.g. a prior refresh attempt that hit `token_invalidated`)
        // persists until the next genuine pre-expiry refresh window
        // (which may be days away).
        if let Some(binding) = captured.as_ref() {
            clear_broker_failed_for_current(base_dir, account, binding, &canonical_path, &creds);
        }
        return Ok(BrokerResult::Valid);
    }

    debug!(account = %account, "token near expiry, attempting refresh");

    // Capture authority before reservation/HTTP. Rebinding cannot redirect the
    // result, and exact-version drift after waiting makes this attempt refuse.
    let binding = match captured {
        Some(binding)
            if identity_store::credentials_path_for(base_dir, binding.identity())
                == canonical_path =>
        {
            binding
        }
        _ if capture_busy => {
            warn!(
                error_kind = "refresh_identity_authority_busy",
                account = account.get(),
                "refresh skipped: the profiles lock is busy; retried next tick"
            );
            return Ok(BrokerResult::Skipped);
        }
        _ => {
            warn!(
                error_kind = "refresh_identity_authority_refused",
                account = account.get(),
                reason = capture_refusal.as_deref().unwrap_or("none"),
                "refresh source custody could not be captured"
            );
            return Ok(BrokerResult::Skipped);
        }
    };

    // Legacy custody permits only this captured UUID's rotating grant. It is
    // not organization ownership proof and cannot merge or redirect identities.
    // The daemon separately verifies the existing canonical access token for
    // an in-place context upgrade; render paths do not run that verifier.

    // Try-lock per account (non-blocking). Lock file co-located with the
    // resolved canonical credential file so lock and credential are always
    // in the same directory — avoids split-directory lock coordination bugs.
    let lock_path = canonical_path.with_extension("refresh-lock");
    let guard = match lock::try_lock_file(&lock_path)? {
        Some(g) => g,
        None => {
            debug!(account = %account, "refresh lock held by another process, skipping");
            return Ok(BrokerResult::Skipped);
        }
    };

    // CRITICAL: Re-read canonical INSIDE the lock to prevent token ping-pong.
    // Another process may have refreshed between our first read and lock acquisition.
    // If we don't re-read, we'd call refresh with a stale RT that Anthropic has
    // already invalidated, forcing recovery and potentially corrupting state.
    // Use the SAME resolved canonical_path as the initial read (UUID or legacy).
    let creds = match credentials::load(&canonical_path) {
        Ok(c) => c,
        Err(e) => {
            drop(guard);
            return Err(CsqError::Credential(e));
        }
    };
    if !creds
        .expect_anthropic()
        .claude_ai_oauth
        .is_expired_within(REFRESH_WINDOW_SECS)
    {
        debug!(account = %account, "another process refreshed already, returning Valid");
        // Auto-clear stale broker_failed sentinel — see early-return Valid above.
        clear_broker_failed_for_current(base_dir, account, &binding, &canonical_path, &creds);
        drop(guard);
        return Ok(BrokerResult::Valid);
    }

    // Duplicate-grant brake, identity-anchored and checked where the token is presented
    // (r7 item 1): the captured binding names the identity whose canonical holds the refresh
    // token, so a `csq move` after the tick's snapshot cannot carry a suppressed identity
    // to a slot number the snapshot did not list.
    if let Some(holder) = crate::accounts::refresh_token_audit::identity_suppression_holder(
        base_dir,
        binding.identity(),
    ) {
        crate::accounts::refresh_token_audit::warn_suppressed_throttled(
            base_dir,
            account.get(),
            holder,
        );
        drop(guard);
        return Ok(BrokerResult::Skipped);
    }

    // Attempt refresh
    match do_refresh(base_dir, account, &binding, &creds, http_post) {
        Ok(None) => {
            warn!(
                error_kind = "refresh_lineage_write_refused",
                account = account.get(),
                "rotated token lineage could not be committed"
            );
            drop(guard);
            Ok(BrokerResult::Skipped)
        }
        Ok(Some(saved_version)) => {
            // The pair was durably saved to its original UUID even if the slot
            // moved during HTTP. Only current custody may clear this slot's
            // sentinel or attribute that successful rotation to its account.
            let outcome = classify_saved_pair_custody(base_dir, account, &binding, saved_version);
            match outcome {
                SavedPairCustody::Current => {}
                SavedPairCustody::CustodyChanged => warn!(
                    error_kind = "refresh_lineage_saved_original_identity",
                    account = account.get(),
                    "rotated pair retained at original identity after slot custody changed"
                ),
                SavedPairCustody::ConcurrentWrite => warn!(
                    error_kind = "refresh_lineage_saved_concurrent_write",
                    account = account.get(),
                    "rotated pair saved; a fresher concurrent write moved the canonical \
                     content, so this attempt does not clear the sentinel"
                ),
                SavedPairCustody::Busy => warn!(
                    error_kind = "refresh_lineage_saved_custody_busy",
                    account = account.get(),
                    "rotated pair saved; the profiles lock was busy so custody was not \
                     re-verified and the sentinel is untouched"
                ),
                SavedPairCustody::LockError { parent_refused } => warn!(
                    error_kind = "refresh_lineage_saved_custody_lock_error",
                    account = account.get(),
                    reason = if parent_refused {
                        "profiles_lock_parent_refused"
                    } else {
                        "profiles_lock_refused"
                    },
                    "rotated pair saved; the profiles lock failed with an I/O error \
                     (not contention), so custody was not re-verified and the sentinel \
                     is untouched"
                ),
            }
            let current = outcome == SavedPairCustody::Current;
            drop(guard);
            Ok(if current {
                BrokerResult::Refreshed
            } else {
                BrokerResult::Skipped
            })
        }
        Err(RefreshFailure::TransportOutcomeUnknown(primary_err)) => {
            // D237 ruling F: the provider may or may not have rotated the
            // grant; the old credential is untouched. That is not evidence
            // of a re-login condition, so neither `broker_failed` nor a
            // LOGIN-NEEDED result is set — the next tick retries.
            warn!(
                account = %account,
                error_kind = "refresh_transport_outcome_unknown",
                reason = crate::error::error_kind_tag(&primary_err),
                "refresh transport failed before a response was delivered; \
                 the provider outcome is unknown, retried next tick"
            );
            drop(guard);
            Ok(BrokerResult::Skipped)
        }
        Err(RefreshFailure::PreCommitLockRefused { io_kind }) => {
            // D237 round-2 H-b (correctness N2): the bounded PRE-COMMIT
            // canonical lock was busy. Nothing was consumed provider-side and
            // nothing was written, so this is contention — skip the tick.
            // It MUST NOT set `broker_failed` or surface LOGIN-NEEDED: lock
            // contention alone is not evidence the user must log in.
            //
            // R3 corr L-1: this arm is reached ONLY for a contention-class
            // refusal (the derived budget expired: `WouldBlock`/`TimedOut`).
            // A non-contention lock I/O fault (`PermissionDenied`, `ReadOnly-
            // Filesystem`, `StorageFull`, …) is NOT contention — it would
            // never clear on a later tick — and falls through to the terminal
            // arm, where the typed `credentials_canonical_lock_refused` tag
            // (carrying the io_kind) reaches the broker-failed sentinel and
            // therefore `csq status` / `csq doctor`.
            warn!(
                account = %account,
                error_kind = "refresh_pre_commit_lock_busy",
                io_kind = ?io_kind,
                "refresh skipped: the pre-commit canonical lock is busy; \
                 nothing was consumed and LOGIN-NEEDED is not set"
            );
            drop(guard);
            Ok(BrokerResult::Skipped)
        }
        Err(RefreshFailure::LocalRuntimeMissing) => {
            // D237 round-2 security L2: a missing node/bun is a KNOWN local
            // environment fault, not an unknown provider outcome. It is
            // surfaced with its own fixed-vocabulary tag (the daemon's
            // WARN-only sink and the usage poller's existing
            // `ERR_NO_JS_RUNTIME` health classification both carry it) and
            // NEVER sets `broker_failed` / LOGIN-NEEDED — the credential is
            // untouched and the operator fixes the host.
            warn!(
                account = %account,
                error_kind = "refresh_transport_unavailable",
                reason = "no_js_runtime",
                "refresh skipped: no JS runtime (node/bun) is available to \
                 perform the request; install node or bun. LOGIN-NEEDED is not set"
            );
            drop(guard);
            Ok(BrokerResult::Skipped)
        }
        Err(RefreshFailure::Failed(primary_err)) => {
            // Reader parity: while a rescued post-commit pair is pending, a
            // refresh failure is not evidence the user must log in — the
            // canonical may simply still hold the pre-rotation pair.
            if rescue_pending_for(base_dir, Some(binding.identity())) {
                warn!(
                    account = %account,
                    error_kind = "refresh_rescue_pending",
                    "refresh failed while a rescued pair is pending; \
                     not marking LOGIN-NEEDED"
                );
                drop(guard);
                return Ok(BrokerResult::Skipped);
            }
            // R3 corr L-8 / sec L-3: the attribution acquire is bounded
            // (`PROFILES_LOCK_BUDGET`), and its failure MUST be logged —
            // a silent skip would drop a genuine refresh failure with no
            // trace at all. A non-contention lock fault is named as such.
            let profiles_guard = match crate::accounts::profiles_lock::ProfilesFileLock::acquire(
                base_dir,
            ) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    warn!(
                        account = %account,
                        error_kind = "refresh_sentinel_custody_lock_refused",
                        reason = crate::accounts::profiles_lock::failure_reason(&error),
                        contention = crate::accounts::profiles_lock::failure_is_contention(&error),
                        "refresh failure not attributed: the profiles lock could not \
                         be taken, so custody was not re-verified and no sentinel was set"
                    );
                    None
                }
            };
            let still_current = profiles_guard.as_ref().is_some_and(|profiles_lock| {
                ai::binding_matches_locked(profiles_lock, base_dir, &binding).unwrap_or(false)
            });
            if !still_current {
                drop(guard);
                return Ok(BrokerResult::Skipped);
            }
            // On rate-limit errors, do NOT escalate — the throttled
            // endpoint will simply reject another request. Return
            // `RateLimited` so the refresher distinguishes this from
            // the "another process holds the lock" Skipped variant and
            // applies a cooldown. Preserving the existing broker_failed
            // flag state is correct: being throttled is not a re-login
            // condition.
            if is_rate_limited(&primary_err) {
                warn!(
                    account = %account,
                    "primary refresh hit rate limit"
                );
                drop(guard);
                return Ok(BrokerResult::RateLimited);
            }

            // M3-7: sibling-credential recovery retired. Pre-M3-7,
            // `recover_from_siblings` scanned `config-N/.credentials.json`
            // mirrors for a fresher RT that CC may have refreshed directly.
            // Post-M3-7 the mirror is gone — handle dirs read through
            // identity-keyed symlinks (M3-3/M3-4) and the daemon writes
            // canonical IS the only credential write path. A failed
            // primary refresh is therefore terminal for this tick:
            // surface broker_failed and let the user re-login.
            // R3 corr L-1: the CsqError-level tag for a credential failure is
            // the generic "credential". A canonical-lock I/O fault must be
            // identifiable on the sentinel / doctor surface, so it carries
            // the TYPED tag (and its io kind rides the error's Display).
            let reason_tag = match &primary_err {
                CsqError::Credential(
                    error @ crate::error::CredentialError::CanonicalLockRefused { .. },
                ) => error.error_kind_tag(),
                _ => crate::error::error_kind_tag(&primary_err),
            };
            warn!(
                account = %account,
                error_kind = reason_tag,
                "primary refresh failed; sibling-recovery retired in Phase 3"
            );
            #[cfg(test)]
            BROKER_SENTINEL_TEST_HOOK.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook();
                }
            });
            let _ = sentinel::set_broker_failed(base_dir, account, reason_tag);
            drop(guard);
            // R1 M3-Sec fix-wave: `primary_err.to_string()` Display chain can
            // include `serde_json::Error` or upstream HTTP body bytes that
            // echo the submitted refresh token back. Redact before storing
            // in the `reason` field (which is surfaced via `RefreshStatus`
            // → IPC → frontend). Per security.md MUST Rule 8 / an internal journal entry
            Ok(BrokerResult::Failed(BrokerError::RefreshFailed {
                account: account.get(),
                reason: crate::error::redact_tokens(&primary_err.to_string()),
            }))
        }
    }
}

/// What a successful lineage save found when custody was re-checked under the
/// profiles lock. Only `Current` may clear the sentinel or count as a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SavedPairCustody {
    Current,
    /// The slot's identity clause moved: the pair stays at its original UUID.
    CustodyChanged,
    /// Custody unchanged, canonical content fresher than the saved pair.
    ConcurrentWrite,
    /// The profiles lock was CONTENDED for its whole derived budget: custody
    /// was not re-verified this tick.
    Busy,
    /// The profiles lock failed with a NON-contention I/O error (EACCES,
    /// EROFS, ENOSPC, a path that is a directory, …). This is not "busy":
    /// it will not clear on a later tick, and the operator must be able to
    /// see it (R3 corr L-1). `parent_refused` names which acquisition step
    /// failed; both are sentinel-neutral (the pair was saved; only the
    /// sentinel clear is withheld).
    LockError {
        parent_refused: bool,
    },
}

/// Re-check custody under the profiles lock after a lineage save and, only when
/// it is exactly current, clear the slot's sentinel.
fn classify_saved_pair_custody(
    base_dir: &Path,
    account: AccountNum,
    binding: &ai::CapturedBinding,
    saved_version: ai::CredentialVersion,
) -> SavedPairCustody {
    match crate::accounts::profiles_lock::ProfilesFileLock::acquire(base_dir) {
        Err(error) => {
            // R3 corr L-1: only the derived-budget expiry is contention. A
            // lock-file I/O failure must not be reported as "busy" — it will
            // not clear on a later tick and the log carries which step failed.
            if crate::accounts::profiles_lock::failure_is_contention(&error) {
                SavedPairCustody::Busy
            } else {
                SavedPairCustody::LockError {
                    parent_refused: crate::accounts::profiles_lock::failure_reason(&error)
                        == "profiles_lock_parent_refused",
                }
            }
        }
        Ok(lock) => {
            if !ai::binding_custody_matches_locked(&lock, base_dir, binding).unwrap_or(false) {
                SavedPairCustody::CustodyChanged
            } else if ai::capture_anthropic_binding_locked(&lock, base_dir, account)
                .map(|current| current.credential_version() != saved_version)
                .unwrap_or(true)
            {
                // Custody is unchanged but the canonical content moved past the
                // pair this call saved: another writer (a custodian adopt, a
                // Legacy->Known upgrade) wrote fresher bytes in the window.
                SavedPairCustody::ConcurrentWrite
            } else {
                #[cfg(test)]
                BROKER_SENTINEL_TEST_HOOK.with(|hook| {
                    if let Some(hook) = hook.borrow_mut().take() {
                        hook();
                    }
                });
                sentinel::clear_broker_failed(base_dir, account);
                SavedPairCustody::Current
            }
        }
    }
}

fn clear_broker_failed_for_current(
    base: &Path,
    account: AccountNum,
    original: &ai::CapturedBinding,
    path: &Path,
    observed: &CredentialFile,
) {
    if identity_store::credentials_path_for(base, original.identity()) != path {
        return;
    }
    let Ok(profiles) = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base) else {
        return;
    };
    if !ai::binding_custody_matches_locked(&profiles, base, original).unwrap_or(false) {
        return;
    }
    let Ok(current) = ai::capture_anthropic_binding_locked(&profiles, base, account) else {
        return;
    };
    let observed_version = observed
        .anthropic()
        .and_then(|c| ai::CredentialVersion::for_credentials(c).ok());
    if observed_version == Some(current.credential_version()) {
        sentinel::clear_broker_failed(base, account);
    }
}

/// Adopts a pending post-commit rescue record for `uuid`, if any.
///
/// Cheap on the normal path: one `stat`-shaped read of the rescue record
/// before the canonical read; the commit lock is taken only when a record
/// actually exists. A refused adoption (live holder, unreadable record) is
/// logged and left PENDING — readers then refuse to conclude "login
/// needed" while the record exists (see [`rescue_pending_for`]).
fn adopt_pending_rescue(base_dir: &Path, uuid: crate::accounts::identity_store::IdentityId) {
    let Some(identity_dir) = identity_store::credentials_path_for(base_dir, uuid)
        .parent()
        .map(Path::to_path_buf)
    else {
        return;
    };
    if crate::credentials::rescue::rescue_record_pending(&identity_dir).is_none() {
        return;
    }
    match crate::credentials::rescue::adopt_rescue_record(base_dir, &uuid.to_string()) {
        Ok(_) => {}
        Err(error) => warn!(
            error_kind = "rescue_adopt_refused",
            reason = error.error_kind_tag(),
            "pending rescue record could not be adopted on this tick; retried next tick"
        ),
    }
}

/// Whether a rescue record is PENDING for `uuid`.
///
/// ROOT ruling A / reader parity: while one is pending, no reader may
/// conclude "no credential" or "login needed" — the durable pair exists and
/// simply has not been installed yet.
fn rescue_pending_for(
    base_dir: &Path,
    uuid: Option<crate::accounts::identity_store::IdentityId>,
) -> bool {
    let Some(uuid) = uuid else { return false };
    // Gate on PROVABILITY, not mere presence (R3 corr M-1 / sec M-C): a record
    // whose witness cannot satisfy today's canonical is superseded and must
    // not block refresh forever; unreadable state still fails closed.
    crate::credentials::rescue::rescue_blocks_refresh(base_dir, uuid)
}

/// Distinguishes a refresh failure whose PROVIDER OUTCOME IS UNKNOWN from a
/// failure the provider itself reported.
///
/// D237 ruling F: an unknown outcome must never set `broker_failed` or
/// surface LOGIN-NEEDED. The local Node transport can die after the request
/// reached Anthropic (a parent-side wait deadline), in which case the old
/// credential is preserved but the grant may already be rotated; the same
/// error is also what a spawn failure produces. Neither is evidence the
/// user must log in.
enum RefreshFailure {
    /// The PRE-COMMIT canonical lock was busy for its whole bounded budget.
    ///
    /// Nothing reached the provider and no local state changed, so this is
    /// contention, never a re-login condition (D237 round-2 H-b). Constructed
    /// ONLY for the contention-class io kinds (`WouldBlock`/`TimedOut`); any
    /// other lock fault is a real local failure and takes the terminal arm
    /// (R3 corr L-1), which is sentinel-visible.
    PreCommitLockRefused { io_kind: std::io::ErrorKind },
    /// The local JS runtime (node/bun) is missing, so NO request could be
    /// made at all (D237 round-2 security L2).
    ///
    /// Distinct from [`RefreshFailure::TransportOutcomeUnknown`]: a spawn
    /// failure after the request may have reached the provider is an unknown
    /// OUTCOME, while a missing runtime is a KNOWN local environment fault.
    /// It is surfaced with its own fixed-vocabulary tag, never sets
    /// `broker_failed`, and never reports LOGIN-NEEDED.
    LocalRuntimeMissing,
    /// The local transport failed before a response was delivered.
    TransportOutcomeUnknown(CsqError),
    /// The provider answered, or a local step after a delivered response
    /// failed; the ordinary terminal-failure classification applies.
    Failed(CsqError),
}

/// Performs the actual token refresh and writes canonical.
///
/// M3-7: live-mirror fanout retired. `save_canonical_for` writes
/// `identities/<UUID>/credentials.json` (primary) + `credentials/N.json`
/// (legacy canonical). Handle dirs read credentials through their symlink
/// which resolves (post-M3-3/M3-4) to the identity path — no fanout needed.
fn do_refresh<F>(
    base_dir: &Path,
    account: AccountNum,
    binding: &ai::CapturedBinding,
    creds: &CredentialFile,
    http_post: F,
) -> Result<Option<ai::CredentialVersion>, RefreshFailure>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    let source = creds
        .anthropic()
        .ok_or_else(ai::credential_refusal)
        .map_err(|error| RefreshFailure::Failed(error.into()))?;
    // Directory custody is checked/repaired before a rotating grant can be
    // consumed. A post-HTTP security refusal cannot burn a still-live RT.
    //
    // D237 round-2 H-b (correctness N2): the preflight's bounded canonical
    // lock is a PRE-COMMIT refusal. It gets its own classification so the
    // broker maps it to Skipped instead of the terminal failure arm, which
    // would set `broker_failed` (a false LOGIN-NEEDED) with no provider
    // contact at all.
    let prepared = ai::prepare_anthropic_refresh(base_dir, binding).map_err(|error| {
        match error {
            // R3 corr L-1: ONLY a lock the holder failed to TAKE within the
            // derived budget is contention. A non-contention lock I/O fault
            // (`PermissionDenied`, `ReadOnlyFilesystem`, `StorageFull`, a
            // path that is a directory, …) will NOT clear on the next tick;
            // reporting it as "busy" hides a permanent local fault forever.
            // Those fall through to the terminal arm, which sets the typed
            // `credentials_canonical_lock_refused` sentinel reason — the
            // surface `csq status` and `csq doctor` read.
            crate::error::CredentialError::CanonicalLockRefused { io_kind, .. }
                if matches!(
                    io_kind,
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                RefreshFailure::PreCommitLockRefused { io_kind }
            }
            error => RefreshFailure::Failed(error.into()),
        }
    })?;
    // Any `Err` out of the transport closure is LOCAL — spawn, stdin write,
    // parent wait deadline, pipe read. Provider-side rejections arrive as
    // `Ok(body)` and are classified inside `refresh_token`. So the flag is a
    // structural test for "no response was delivered", never a string match.
    //
    // L2 exception: the ONE local failure whose outcome is KNOWN is a
    // missing JS runtime — the transport rejects before any process exists.
    // It gets its own classification so the daemon surfaces a distinct
    // status instead of a permanent "unknown outcome" retry.
    let transport_failed = std::cell::Cell::new(false);
    let runtime_missing = std::cell::Cell::new(false);
    let probe_transport = |url: &str, body: &str| match http_post(url, body) {
        Ok(response) => Ok(response),
        Err(error) => {
            if error == crate::http::ERR_NO_JS_RUNTIME {
                runtime_missing.set(true);
            }
            transport_failed.set(true);
            Err(error)
        }
    };
    let (refreshed, lineage) =
        ai::refresh_captured_anthropic_with(&prepared, source, probe_transport).map_err(
            |error| {
                if runtime_missing.get() {
                    RefreshFailure::LocalRuntimeMissing
                } else if transport_failed.get() {
                    RefreshFailure::TransportOutcomeUnknown(error.into())
                } else {
                    RefreshFailure::Failed(error.into())
                }
            },
        )?;
    // From here the provider has rotated the refresh token: any error before the
    // pair is durable drops it, so each exit carries one distinct tag instead of
    // reading as an ordinary credential failure.
    let discarded = |error: CsqError| {
        let identity_dir = identity_store::credentials_path_for(base_dir, binding.identity())
            .parent()
            .map(Path::to_path_buf);
        let rescued = identity_dir.as_deref().is_some_and(|identity_dir| {
            crate::credentials::rescue::rescue_record_pending(identity_dir).is_some()
        });
        if rescued {
            // The pair is durable in its rescue record and the next tick (or
            // daemon start) adopts it. This is NOT a discard, and saying so
            // keeps operators from chasing a nonexistent token loss.
            warn!(
                error_kind = "refresh_rotated_pair_rescued",
                account = account.get(),
                "rotated token pair is durably rescued; the next tick adopts it"
            );
        } else {
            warn!(
                error_kind = "refresh_rotated_pair_discarded",
                account = account.get(),
                "rotated token pair could not be saved after the refresh response"
            );
        }
        RefreshFailure::Failed(error)
    };
    let saved_version = ai::CredentialVersion::for_credentials(&refreshed)
        .map_err(|_| discarded(ai::credential_refusal().into()))?;
    match file::save_anthropic_canonical_guarded(
        base_dir,
        binding,
        &refreshed,
        file::AnthropicWriteWitness::RefreshLineage(&lineage),
        None,
    )
    .map_err(|error| discarded(error.into()))?
    {
        file::GuardedWriteOutcome::Written => {}
        file::GuardedWriteOutcome::NotFresher | file::GuardedWriteOutcome::BindingChanged => {
            return Ok(None)
        }
    }

    // This records an actual provider refresh whose canonical write succeeded;
    // healthy tokens and failed/skipped attempts never reach this boundary.
    // WARN makes this fixed-field receipt visible in the daemon's WARN-only sink.
    warn!(
        event_kind = "oauth_refresh_succeeded",
        account = account.get(),
        provider = "anthropic",
        surface = "claude",
        process_id = std::process::id(),
        "OAuth token refreshed and canonical credentials saved"
    );

    Ok(Some(saved_version))
}

/// Codex sibling of [`broker_check`].
///
/// Performs a single Codex slot's pre-expiry refresh per spec 07
/// §7.5 INV-P01:
///
/// 1. Loads `identities/<UUID>/credentials-codex.json` when
///    `profiles.json::by_slot[N]` is populated (M4-4); falls back to
///    `credentials/codex-<N>.json` when no UUID mapping exists.
/// 2. Decodes the JWT `exp` claim from `tokens.access_token`.
/// 3. If exp is more than 2h away ([`REFRESH_WINDOW_SECS`]),
///    returns [`BrokerResult::Valid`] without HTTP.
/// 4. Acquires the per-slot try-lock (`refresh-lock` next to the
///    canonical credential file). Lock contention →
///    [`BrokerResult::Skipped`].
/// 5. Re-reads canonical inside the lock to absorb a refresh another
///    process may have just landed (mirrors `broker_check`'s
///    re-read-inside-lock guard against ping-pong).
/// 6. Calls `http_codex::refresh_with_http_meta` with the injected
///    transport. The transport returns body + Date header so we can
///    emit `clock_skew_detected` per INV-P01.
/// 7. On `code: "token_expired"` / `"refresh_token_reused"` →
///    [`BrokerResult::Failed`] with the typed
///    [`BrokerError::CodexTokenExpired`] / [`BrokerError::CodexRefreshReused`]
///    variant. Sets the broker_failed flag so subsequent reads (and
///    the statusline LOGIN-NEEDED indicator) see it. Maps to
///    `LOGIN_REQUIRED:` at the IPC boundary via the existing
///    `From<CsqError> for String` impl in `error.rs`.
/// 8. On HTTP 429 → [`BrokerResult::RateLimited`].
/// 9. On success: builds a merged [`CredentialFile::Codex`]
///    (preserving `auth_mode`, `openai_api_key`, `extra`) and writes
///    via [`file::save_canonical_for`] which already coordinates the
///    per-account write mutex (INV-P09) and flips the canonical from
///    0o400 → write at 0o600 → 0o400 (INV-P08). The pre-M3-7
///    `config-<N>/codex-auth.json` mirror write is retired; handle
///    dirs read through their identity-keyed symlink (spec 07 §7.2.2).
///
/// Unlike Anthropic [`broker_check`], there is NO sibling-recovery
/// pass: Codex's RT is single-use (openai/codex#10332), so reading
/// a sibling's RT and trying it would burn a second token. A failed
/// refresh is terminal — the user re-authenticates via
/// `csq login N --provider codex`.
pub fn broker_codex_check<F>(
    base_dir: &Path,
    account: AccountNum,
    http_post: F,
) -> Result<BrokerResult, CsqError>
where
    F: FnOnce(&str, &str) -> Result<crate::http::NodeHttpResponse, String>,
{
    use crate::providers::catalog::Surface;

    // M4-4: resolve through UUID-keyed identity path when by_slot is
    // populated, matching tick's read path so broker_codex_check sees
    // the same credential file that tick's expiry check reads.
    // Legacy fallback: if no UUID mapping exists, use numeric path.
    let captured_profiles =
        crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(base_dir))?;
    let captured_uuid = captured_profiles.by_slot.get(&account.to_string()).copied();
    let captured_generation = captured_profiles
        .slot_binding_generations
        .get(&account.to_string())
        .copied()
        .unwrap_or(0);
    let canonical_path = match captured_uuid {
        Some(uuid) => {
            // ROOT ruling A: adopt a rescued post-commit Codex pair before
            // reading, so a deferred rotation is installed on this tick.
            adopt_pending_rescue(base_dir, uuid);
            // D237 round-2 H-a (correctness N1 / security M3), Codex arm:
            // Codex's refresh token is SINGLE-USE, so replaying the canonical's
            // pre-rotation token while its successor sits in a pending record
            // is terminal — the provider answers `refresh_token_reused` and the
            // rescued pair dies with the family. No provider request while the
            // record is unadopted; skip with a fixed-vocabulary status, never
            // LOGIN-NEEDED and never a `broker_failed` sentinel.
            if rescue_pending_for(base_dir, Some(uuid)) {
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "rescue_pending",
                    "codex refresh skipped: a rescued rotation is still pending adoption; \
                     no provider request is made and LOGIN-NEEDED is not set"
                );
                return Ok(BrokerResult::Skipped);
            }
            crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid)
        }
        None => file::canonical_path_for(base_dir, account, Surface::Codex),
    };
    let creds = credentials::load(&canonical_path)?;
    let codex = creds
        .codex()
        .ok_or_else(|| codex_shape_mismatch_err(account, &canonical_path))?;

    let now_s = now_secs();
    if !codex_is_expired_within(codex, REFRESH_WINDOW_SECS, now_s) {
        // Auto-clear stale broker_failed sentinel — symmetric to broker_check's
        // Anthropic Valid path. See that branch for rationale.
        if !with_current_codex_authority(
            base_dir,
            account,
            captured_uuid,
            captured_generation,
            &creds,
            || sentinel::clear_broker_failed(base_dir, account),
        )? {
            return Ok(BrokerResult::Skipped);
        }
        return Ok(BrokerResult::Valid);
    }

    debug!(account = %account, surface = "codex", "codex token near expiry, attempting refresh");

    // Per-slot try-lock (sibling of Anthropic's `refresh-lock`).
    let lock_path = canonical_path.with_extension("refresh-lock");
    let guard = match lock::try_lock_file(&lock_path)? {
        Some(g) => g,
        None => {
            debug!(
                account = %account,
                surface = "codex",
                "codex refresh lock held by another process, skipping"
            );
            return Ok(BrokerResult::Skipped);
        }
    };

    #[cfg(test)]
    CODEX_AFTER_REFRESH_LOCK_TEST_HOOK.with(|hook| {
        let hook = hook.borrow_mut().take();
        if let Some(hook) = hook {
            hook();
        }
    });
    // Re-read INSIDE the lock — a sibling process may have refreshed.
    let creds = credentials::load(&canonical_path)?;
    let codex = creds
        .codex()
        .ok_or_else(|| codex_shape_mismatch_err(account, &canonical_path))?;
    let now_s = now_secs();
    if !codex_is_expired_within(codex, REFRESH_WINDOW_SECS, now_s) {
        debug!(account = %account, surface = "codex", "another process refreshed already");
        // Auto-clear stale broker_failed sentinel — see early-return Valid above.
        if !with_current_codex_authority(
            base_dir,
            account,
            captured_uuid,
            captured_generation,
            &creds,
            || sentinel::clear_broker_failed(base_dir, account),
        )? {
            return Ok(BrokerResult::Skipped);
        }
        drop(guard);
        return Ok(BrokerResult::Valid);
    }

    let refresh_token = match codex.tokens.refresh_token.as_deref() {
        Some(rt) if !rt.is_empty() => rt,
        _ => {
            // Reader parity (ROOT ruling A): a rescued post-commit pair may
            // hold the refresh token this canonical lacks. Refuse to
            // conclude LOGIN-NEEDED while one is pending.
            if rescue_pending_for(base_dir, captured_uuid) {
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "codex_refresh_rescue_pending",
                    "codex canonical has no refresh token but a rescued pair is pending; \
                     not marking LOGIN-NEEDED"
                );
                drop(guard);
                return Ok(BrokerResult::Skipped);
            }
            // Codex slot has no refresh token → user must re-login.
            // Set the failed flag so the statusline / dashboard reflect it.
            drop(guard);
            warn!(
                account = %account,
                surface = "codex",
                error_kind = "codex_token_expired",
                "codex refresh: missing refresh token (LOGIN-NEEDED)"
            );
            log_codex_failure_sentinel_authority(
                account,
                with_current_codex_authority(
                    base_dir,
                    account,
                    captured_uuid,
                    captured_generation,
                    &creds,
                    || {
                        let _ =
                            sentinel::set_broker_failed(base_dir, account, "codex_token_expired");
                    },
                ),
            );
            return Ok(BrokerResult::Failed(BrokerError::CodexTokenExpired {
                account: account.get(),
            }));
        }
    };

    // No UUID means there is no canonical destination for a rotated pair.
    // Refuse BEFORE consuming the provider's single-use refresh token.
    let uuid = captured_uuid.ok_or(crate::error::CredentialError::NoCredentials(account.get()))?;
    let (new_tokens, server_date) =
        match http_codex::refresh_with_http_meta(refresh_token, http_post) {
            Ok(pair) => pair,
            Err(http_codex::CodexHttpError::TokenExpired) => {
                // Reader parity: a pending rescued pair means the canonical
                // this request came from may already be stale; do not turn a
                // superseded-grant answer into a re-login demand.
                if rescue_pending_for(base_dir, captured_uuid) {
                    warn!(
                        account = %account,
                        surface = "codex",
                        error_kind = "codex_refresh_rescue_pending",
                        "codex refresh reported token_expired while a rescued pair is pending; \
                         not marking LOGIN-NEEDED"
                    );
                    drop(guard);
                    return Ok(BrokerResult::Skipped);
                }
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "codex_token_expired",
                    "codex refresh: token_expired (LOGIN-NEEDED)"
                );
                log_codex_failure_sentinel_authority(
                    account,
                    with_current_codex_authority(
                        base_dir,
                        account,
                        captured_uuid,
                        captured_generation,
                        &creds,
                        || {
                            let _ = sentinel::set_broker_failed(
                                base_dir,
                                account,
                                "codex_token_expired",
                            );
                        },
                    ),
                );
                drop(guard);
                return Ok(BrokerResult::Failed(BrokerError::CodexTokenExpired {
                    account: account.get(),
                }));
            }
            Err(http_codex::CodexHttpError::RefreshReused) => {
                // Reader parity: same rule as the token_expired arm — a
                // pending rescue outranks a reused-token answer, because the
                // canonical read may predate the rescue.
                if rescue_pending_for(base_dir, captured_uuid) {
                    warn!(
                        account = %account,
                        surface = "codex",
                        error_kind = "codex_refresh_rescue_pending",
                        "codex refresh reported refresh_token_reused while a rescued pair is \
                         pending; not marking LOGIN-NEEDED"
                    );
                    drop(guard);
                    return Ok(BrokerResult::Skipped);
                }
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "codex_refresh_reused",
                    "codex refresh: refresh_token_reused (LOGIN-NEEDED)"
                );
                log_codex_failure_sentinel_authority(
                    account,
                    with_current_codex_authority(
                        base_dir,
                        account,
                        captured_uuid,
                        captured_generation,
                        &creds,
                        || {
                            let _ = sentinel::set_broker_failed(
                                base_dir,
                                account,
                                "codex_refresh_reused",
                            );
                        },
                    ),
                );
                drop(guard);
                return Ok(BrokerResult::Failed(BrokerError::CodexRefreshReused {
                    account: account.get(),
                }));
            }
            Err(http_codex::CodexHttpError::Upstream { status: 429, .. }) => {
                warn!(
                    account = %account,
                    surface = "codex",
                    "codex refresh: rate limited"
                );
                drop(guard);
                return Ok(BrokerResult::RateLimited);
            }
            Err(http_codex::CodexHttpError::Transport) => {
                // D237 ruling F: the Node transport failed locally, so the
                // provider may or may not have rotated the single-use grant.
                // The old credential is untouched; do NOT set broker_failed
                // and do NOT report LOGIN-NEEDED — retry next tick.
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "codex_refresh_transport_outcome_unknown",
                    "codex refresh transport failed before a response was delivered; \
                     provider outcome unknown, retried next tick"
                );
                drop(guard);
                return Ok(BrokerResult::Skipped);
            }
            Err(other) => {
                // Reader parity: a provider-answered failure while a rescued
                // pair is pending is not a re-login condition either — the
                // canonical read this request came from may be superseded.
                if rescue_pending_for(base_dir, captured_uuid) {
                    warn!(
                        account = %account,
                        surface = "codex",
                        error_kind = "codex_refresh_rescue_pending",
                        "codex refresh failed while a rescued pair is pending; \
                         not marking LOGIN-NEEDED"
                    );
                    drop(guard);
                    return Ok(BrokerResult::Skipped);
                }
                // Convert into a BrokerError. Display only the fixed-vocabulary
                // tag, never the raw upstream body — `CodexHttpError::Display`
                // is already body-fragment-safe (see http::codex tests), but
                // the warn-log site emits an `error_kind` rather than `error`
                // formatter to defend against any future Display refactor.
                let broker_err = other.into_broker(account.get());
                // Compute the kind tag inline rather than wrapping into
                // CsqError just to call `error_kind_tag` — avoids needing a
                // Clone bound on BrokerError.
                let kind: &'static str = match &broker_err {
                    BrokerError::CodexTokenExpired { .. } => "codex_token_expired",
                    BrokerError::CodexRefreshReused { .. } => "codex_refresh_reused",
                    BrokerError::CodexTokenInvalidated { .. } => "codex_token_invalidated",
                    BrokerError::RefreshTokenInvalid { .. } => "broker_token_invalid",
                    BrokerError::RefreshFailed { .. } => "broker_refresh_failed",
                };
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = kind,
                    "codex refresh failed"
                );
                log_codex_failure_sentinel_authority(
                    account,
                    with_current_codex_authority(
                        base_dir,
                        account,
                        captured_uuid,
                        captured_generation,
                        &creds,
                        || {
                            let _ = sentinel::set_broker_failed(base_dir, account, kind);
                        },
                    ),
                );
                drop(guard);
                return Ok(BrokerResult::Failed(broker_err));
            }
        };

    // Clock-skew check (INV-P01). After a successful refresh we have the
    // server's `Date` header — compare to local clock. Warn (but do not
    // fail) when drift exceeds 5 min, because that's the threshold beyond
    // which the daemon's 2h pre-expiry window starts to risk overlap with
    // codex-cli's on-expiry threshold.
    if let Some(date) = server_date.as_deref() {
        if let Some(server_secs) = http_codex::parse_http_date_secs(date) {
            let local = now_secs();
            let drift = local.abs_diff(server_secs);
            if drift > http_codex::CLOCK_SKEW_WARN_SECS {
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "clock_skew_detected",
                    drift_secs = drift,
                    "local clock differs from server `Date` header by > 5 min — \
                     INV-P01 pre-expiry refresh may miss codex on-expiry threshold"
                );
            }
        }
    }

    // Build the merged credential file. Preserves `auth_mode`,
    // `openai_api_key`, `extra` from the existing file; updates the
    // token triple from the refresh response. `last_refresh` is set to
    // ISO-8601 of now so a sibling read can sanity-check freshness.
    let merged = merge_codex_refresh(&creds, &new_tokens);

    // Commit to the UUID and exact source read before HTTP. Re-login at that
    // same UUID can replace the canonical while HTTP is in flight; a stale
    // response must not overwrite that winner or clear its failure sentinel.
    match file::save_codex_refresh_for_uuid(base_dir, uuid, &creds, &merged) {
        Ok(true) => {}
        Ok(false) => {
            drop(guard);
            return Ok(BrokerResult::Skipped);
        }
        Err(error) => {
            // D237 C1: a save that could not take the canonical lock leaves
            // the pair in its durable rescue record. That is a DEFERRED
            // rotation, not a lost one — report Skipped with a distinct tag
            // and let the next tick adopt it.
            if rescue_pending_for(base_dir, Some(uuid)) {
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "codex_rotated_pair_rescued",
                    "rotated codex pair is durably rescued; the next tick adopts it"
                );
                drop(guard);
                return Ok(BrokerResult::Skipped);
            }
            drop(guard);
            return Err(error.into());
        }
    }
    // A rebound slot may now describe another UUID. Original-UUID rotation
    // stays durable, but only unchanged custody can authorize this slot clear.
    log_codex_failure_sentinel_authority(
        account,
        with_current_codex_authority(
            base_dir,
            account,
            captured_uuid,
            captured_generation,
            &merged,
            || sentinel::clear_broker_failed(base_dir, account),
        ),
    );
    drop(guard);
    Ok(BrokerResult::Refreshed)
}

/// Upstream failure or successful canonical rotation keeps its actual result.
/// Failure-sentinel mutation is best-effort and authority refusal is observable.
fn log_codex_failure_sentinel_authority(account: AccountNum, result: Result<bool, CsqError>) {
    match result {
        Ok(true) => (),
        Ok(false) => warn!(
            account = %account,
            surface = "codex",
            error_kind = "codex_refresh_sentinel_authority_busy_or_changed",
            "codex failure sentinel unchanged: authority is busy or changed"
        ),
        Err(_) => warn!(
            account = %account,
            surface = "codex",
            error_kind = "codex_refresh_sentinel_authority_read_refused",
            "codex failure sentinel unchanged: authority could not be safely read"
        ),
    }
}

/// Profiles -> canonical lock order; no HTTP or slot mutex acquisition here.
/// The sentinel action is bounded and stays inside the exact-custody window.
fn with_current_codex_authority<F: FnOnce()>(
    base: &Path,
    account: AccountNum,
    captured_uuid: Option<crate::accounts::identity_store::IdentityId>,
    captured_generation: u64,
    expected: &CredentialFile,
    action: F,
) -> Result<bool, CsqError> {
    let Some(_profiles_guard) =
        crate::accounts::profiles_lock::ProfilesFileLock::try_acquire(base)?
    else {
        return Ok(false);
    };
    let profiles =
        crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(base))?;
    if profiles.by_slot.get(&account.to_string()).copied() != captured_uuid
        || profiles
            .slot_binding_generations
            .get(&account.to_string())
            .copied()
            .unwrap_or(0)
            != captured_generation
    {
        return Ok(false);
    }
    let (path, canonical_lock) = match captured_uuid {
        Some(uuid) => (
            identity_store::credentials_codex_path_for(base, uuid),
            identity_store::credentials_path_for(base, uuid).with_extension("lock"),
        ),
        None => {
            // Numeric credentials are still a supported legacy read authority.
            // They authorize only this content-matched sentinel action, never
            // single-use HTTP refresh without an original UUID destination.
            let path =
                file::canonical_path_for(base, account, crate::providers::catalog::Surface::Codex);
            let canonical_lock = path.with_extension("lock");
            (path, canonical_lock)
        }
    };
    // Bounded credential lock: a wedged holder must not pin a refresher.
    let _canonical_guard = match crate::platform::lock::lock_credential_file(&canonical_lock)? {
        Some(guard) => guard,
        None => {
            return Err(crate::error::PlatformError::LockTimeout {
                path: canonical_lock,
                timeout_ms: crate::platform::lock::CREDENTIAL_LOCK_BUDGET_MS,
            }
            .into())
        }
    };
    if captured_uuid.is_some_and(|uuid| identity_store::is_identity_removed(base, uuid)) {
        return Ok(false);
    }
    let current = credentials::load(&path)?;
    if !file::codex_credentials_match(&current, expected) {
        return Ok(false);
    }
    action();
    Ok(true)
}

fn codex_shape_mismatch_err(account: AccountNum, path: &Path) -> CsqError {
    CsqError::Credential(crate::error::CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: format!(
            "expected Codex credential variant for slot {account}; got Anthropic shape — \
             discovery filenames disagree with payload (operator should re-run \
             `csq login {account} --provider codex` or remove the bad file)"
        ),
    })
}

/// Returns true if the Codex slot's access-token JWT exp claim is
/// within `buffer_secs` of `now_s` (or is undecodeable, which is
/// treated as "needs refresh now").
fn codex_is_expired_within(
    codex: &crate::credentials::CodexCredentialFile,
    buffer_secs: u64,
    now_s: u64,
) -> bool {
    match http_codex::jwt_exp_secs(&codex.tokens.access_token) {
        Some(exp) => exp <= now_s + buffer_secs,
        // Undecodeable JWT — be safe, refresh.
        None => true,
    }
}

/// Builds a fresh `CredentialFile::Codex` from the existing one plus
/// new tokens from `/oauth/token`. Preserves every field except the
/// token triple + `last_refresh`.
///
/// Honors OpenAI's single-use refresh-token semantics: if the response
/// omits a new refresh_token (which the parser allows via `Option`),
/// we keep the existing one — but in production this never happens
/// because `/oauth/token` always returns a rotated RT.
fn merge_codex_refresh(
    existing: &CredentialFile,
    new_tokens: &http_codex::CodexTokens,
) -> CredentialFile {
    let mut next = existing.clone();
    if let Some(c) = next.codex_mut() {
        c.tokens.access_token = new_tokens.access_token.clone();
        if let Some(rt) = &new_tokens.refresh_token {
            c.tokens.refresh_token = Some(rt.clone());
        }
        if let Some(id) = &new_tokens.id_token {
            c.tokens.id_token = Some(id.clone());
        }
        // account_id is set on first login and does not change on refresh —
        // preserve the existing value rather than overwriting from the
        // (possibly absent) field on the refresh response.
        c.last_refresh = Some(rfc3339_now());
    }
    next
}

fn rfc3339_now() -> String {
    let secs = now_secs();
    // YYYY-MM-DDTHH:MM:SSZ assembled from secs since epoch — avoids a
    // chrono dependency. Uses the same days-since-epoch math as
    // http::codex::parse_http_date_secs.
    let days = secs / 86_400;
    let s = secs % 86_400;
    let hour = s / 3_600;
    let minute = (s % 3_600) / 60;
    let second = s % 60;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let mut remaining = days;
    let mut year: u32 = 1970;
    loop {
        let yr_len: u64 =
            if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
                366
            } else {
                365
            };
        if remaining < yr_len {
            break;
        }
        remaining -= yr_len;
        year += 1;
    }
    let mut month_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
        month_days[1] = 29;
    }
    let mut month: u32 = 1;
    for &d in &month_days {
        if remaining < d {
            break;
        }
        remaining -= d;
        month += 1;
    }
    let day = (remaining as u32) + 1;
    (year, month, day)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns `true` if `e` looks like an Anthropic rate-limit error.
///
/// We match on the Display string because the refresh error path
/// wraps structured response bodies through `OAuthError::Exchange`
/// without preserving the HTTP status. Anthropic returns
/// `{"error":{"type":"rate_limit_error", ...}}` for 429s, which
/// `extract_oauth_error` stringifies as `rate_limit_error: ...`.
fn is_rate_limited(e: &CsqError) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("rate_limit") || msg.contains("rate limit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::markers;
    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Provisions a deterministic UUID mapping in `profiles.json::by_slot` for
    /// the given account number. Required because `save_canonical_for` is
    /// fail-closed (M4-12): it returns `Err(NoCredentials)` when no UUID
    /// mapping exists, which would cause broker_check / broker_codex_check
    /// to fail at the canonical write step after a successful refresh.
    fn provision_uuid_for_account(base: &std::path::Path, account: u16) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(account.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
    }

    /// Writes credentials to the UUID-keyed identity path when by_slot is populated.
    /// RN1-C: broker_check reads the UUID path, so test setup must seed it.
    fn save_creds_uuid(base: &std::path::Path, account: u16, creds: &CredentialFile) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_path, creds).unwrap();
        if creds.anthropic().is_some() {
            let metadata = uuid_path.parent().unwrap().join("identity.json");
            let account_uuid = uuid::Uuid::from_u128(0x1000 + u128::from(account));
            let organization_uuid = uuid::Uuid::from_u128(0x2000 + u128::from(account));
            std::fs::write(
                &metadata,
                serde_json::to_vec(&serde_json::json!({
                    "email": "verified@example.test", "provider": "anthropic",
                    "created_at": "2026-01-01T00:00:00Z", "key_id": null,
                    "account_uuid": account_uuid, "organization_uuid": organization_uuid
                }))
                .unwrap(),
            )
            .unwrap();
            crate::platform::fs::secure_file(&metadata).unwrap();
            crate::platform::fs::secure_dir(&base.join("identities")).unwrap();
            crate::platform::fs::secure_dir(uuid_path.parent().unwrap()).unwrap();
            let path = profiles::profiles_path(base);
            let mut pf = profiles::load(&path).unwrap();
            pf.anthropic_contexts
                .retain(|entry| entry.identity_uuid != uuid);
            pf.anthropic_contexts.push(ai::AnthropicContextEntry {
                email: "verified@example.test".into(),
                account_uuid,
                organization_uuid,
                identity_uuid: uuid,
                extra: Default::default(),
            });
            profiles::save(&path, &pf).unwrap();
        }
    }

    fn make_creds(access: &str, refresh: &str, expires_at: u64) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                // An expired credential remains a real exact-version grant;
                // zero represents missing expiry in the authority reader.
                expires_at: expires_at.max(1),
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn mock_refresh_success(_url: &str, _body: &str) -> Result<Vec<u8>, String> {
        Ok(
            br#"{"access_token":"at-refreshed","refresh_token":"rt-refreshed","expires_in":18000}"#
                .to_vec(),
        )
    }

    /// A PROVIDER rejection, in the shape production actually sees it:
    /// `post_json_node` returns the response body on any HTTP status
    /// (`post_json_node`'s doc: "the caller classifies the response"), so a
    /// 401 arrives as `Ok(body)`, never as a transport `Err`. The `Err`
    /// channel is reserved for LOCAL transport failures, which
    /// [`broker_check`] classifies as an unknown provider outcome (D237
    /// ruling F) rather than a re-login condition.
    fn mock_refresh_failure(_url: &str, _body: &str) -> Result<Vec<u8>, String> {
        Ok(br#"{"error":{"type":"invalid_grant","message":"refresh token rejected"}}"#.to_vec())
    }

    #[test]
    fn broker_check_valid_token_no_refresh() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();

        // Far-future expiry
        let creds = make_creds("at-1", "rt-1", 9999999999999);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Valid));
    }

    #[test]
    fn broker_check_expired_token_refreshes() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 2);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        // Also seed numeric path so existing read fallback is covered.
        let creds = make_creds("at-2", "rt-2", 0);
        save_creds_uuid(dir.path(), 2, &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // Verify canonical was updated — read from UUID-keyed identity path.
        // M4-12: save_canonical_for writes to identities/<UUID>/credentials.json;
        // numeric path (credentials/2.json) is no longer the write destination.
        let uuid2 = crate::testing::identity_fixtures::fixture_uuid_for_slot(2);
        let uuid_path2 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid2);
        let updated = credentials::load(&uuid_path2).unwrap();
        assert_eq!(
            updated
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed"
        );
    }

    #[test]
    fn broker_check_failed_sets_flag() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        let creds = make_creds("at-3", "rt-3", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_failure).unwrap();
        assert!(matches!(result, BrokerResult::Failed(_)));
        assert!(sentinel::is_broker_failed(dir.path(), account));
    }

    /// D237 ruling F: a LOCAL transport failure has an UNKNOWN provider
    /// outcome. It must not set `broker_failed` (LOGIN-NEEDED) — the old
    /// credential is preserved and the next tick retries.
    ///
    /// RED mutation: fold `RefreshFailure::TransportOutcomeUnknown` back into
    /// the terminal arm — the sentinel assertion fails.
    #[test]
    fn broker_check_transport_error_is_not_login_needed() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();
        let creds = make_creds("at-5", "rt-5", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, |_url, _body| {
            Err("node http transport: child exceeded the parent wait deadline".into())
        })
        .unwrap();
        assert!(
            matches!(result, BrokerResult::Skipped),
            "an unknown-outcome refresh must retry, not report failure: {result:?}"
        );
        assert!(
            !sentinel::is_broker_failed(dir.path(), account),
            "an unknown transport outcome is not a re-login condition"
        );
    }

    /// D237 round-2 security L2: a missing JS runtime is a KNOWN local
    /// environment fault, not an unknown provider outcome. It must be
    /// classified distinctly (`refresh_transport_unavailable`,
    /// `reason=no_js_runtime`) while still never setting `broker_failed`.
    ///
    /// RED mutation: drop the `ERR_NO_JS_RUNTIME` branch in `do_refresh` — the
    /// captured tag becomes `refresh_transport_outcome_unknown`.
    #[test]
    fn broker_check_missing_js_runtime_has_its_own_status() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(9u16).unwrap();
        let creds = make_creds("at-9", "rt-9", now_secs_test() + 60);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);

        let (result, events) = capture_events(|| {
            broker_check(dir.path(), account, |_url, _body| {
                Err(crate::http::ERR_NO_JS_RUNTIME.to_string())
            })
        });
        assert!(matches!(result.unwrap(), BrokerResult::Skipped));
        assert!(
            !sentinel::is_broker_failed(dir.path(), account),
            "a missing runtime is not a re-login condition"
        );
        let kinds: Vec<String> = events
            .iter()
            .filter_map(|fields| fields.get("error_kind").cloned())
            .collect();
        assert!(
            kinds
                .iter()
                .any(|kind| kind == "refresh_transport_unavailable"),
            "the missing runtime must carry its own status tag, got {kinds:?}"
        );
        assert!(
            !kinds
                .iter()
                .any(|kind| kind == "refresh_transport_outcome_unknown"),
            "a missing runtime is not an unknown provider outcome, got {kinds:?}"
        );
    }

    /// Captures tracing event fields for one closure (thread-scoped
    /// subscriber; the same pattern as the identity tests).
    fn capture_events<T>(run: impl FnOnce() -> T) -> (T, Vec<BTreeMap<String, String>>) {
        #[derive(Debug, Default)]
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
        }
        struct Capture(Arc<std::sync::Mutex<Vec<BTreeMap<String, String>>>>);
        impl tracing::Subscriber for Capture {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
                Some(tracing::metadata::LevelFilter::TRACE)
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
        }
        let _guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let out = tracing::subscriber::with_default(Capture(Arc::clone(&events)), run);
        let captured = std::mem::take(&mut *events.lock().unwrap());
        (out, captured)
    }

    /// Plants a v2 rescue record that PROVES the current canonical was
    /// consumed (R3 3(a): its witness source equals the canonical as it is
    /// now), then keeps it PENDING for the current tick by holding its
    /// writer-liveness sidecar so adoption defers it.
    ///
    /// Returns the record path and the holder; the caller MUST keep the
    /// holder alive until the tick under test returns.
    fn plant_provable_pending_rescue(
        base: &Path,
        provider: &str,
        uuid: crate::accounts::identity_store::IdentityId,
        canonical: &CredentialFile,
    ) -> (std::path::PathBuf, crate::platform::lock::HeldOnOtherThread) {
        use crate::credentials::rescue::{write_rescue_record, RescueWitness};
        let identity_dir = identity_store::credentials_path_for(base, uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        let payload = match provider {
            "anthropic" => make_creds("rescued-at", "rescued-rt", now_secs_test() + 3600),
            _ => {
                let mut codex = canonical.clone();
                if let Some(codex) = codex.codex_mut() {
                    codex.tokens.access_token = "at-rescued".into();
                    codex.tokens.refresh_token = Some("rt-rescued".into());
                }
                codex
            }
        };
        let witness = match provider {
            "anthropic" => RescueWitness::Anthropic(ai::RescueLineageWitness {
                kind: ai::RescueWitnessKind::Refresh,
                source_version: ai::CredentialVersion::for_credentials(
                    canonical.anthropic().unwrap(),
                )
                .unwrap(),
                result_version: ai::CredentialVersion::for_credentials(
                    payload.anthropic().unwrap(),
                )
                .unwrap(),
                context: None,
                legacy_email: None,
            }),
            _ => RescueWitness::Codex {
                expected_source: serde_json::to_value(canonical).unwrap(),
            },
        };
        let record = write_rescue_record(
            &identity_dir,
            provider,
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&payload).unwrap(),
            &witness,
        )
        .unwrap();
        let holder = hold_live_writer_sidecar(&record);
        (record, holder)
    }

    /// Makes `record`'s writer LIVE the way `write_login_prelock_rescue`
    /// does on every OS: the `.json.writer` sidecar FILE is created
    /// explicitly (a Windows lock is a named mutex that creates no file, and
    /// `rescue_writer_is_live` reads a missing sidecar as "no live writer"),
    /// and its lock is held on ANOTHER thread (a Windows lock is re-entrant
    /// on the holding thread, so a same-thread hold reads as a dead writer).
    fn hold_live_writer_sidecar(record: &Path) -> crate::platform::lock::HeldOnOtherThread {
        let sidecar = record.with_extension("json.writer");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&sidecar)
            .expect("create the writer sidecar");
        crate::platform::lock::HeldOnOtherThread::hold(&sidecar)
    }

    /// Reader parity: while a rescued post-commit pair is PENDING, a
    /// provider rejection must not become LOGIN-NEEDED. The record is written
    /// DURING the provider call (the only window left once the pre-flight
    /// gate makes a provable record block before HTTP).
    #[test]
    fn broker_check_provider_failure_with_pending_rescue_is_not_login_needed() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();
        let creds = make_creds("at-6", "rt-6", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let identity_dir = identity_store::credentials_path_for(dir.path(), uuid)
            .parent()
            .unwrap()
            .to_path_buf();

        // The record appears WHILE the provider call is in flight — after the
        // pre-flight gate, which is the only window a provable record no
        // longer blocks (R3 3(a)).
        let base = dir.path().to_path_buf();
        let in_flight_creds = creds.clone();
        let result = broker_check(dir.path(), account, move |_url, _body| {
            let (_record, _writer_alive) =
                plant_provable_pending_rescue(&base, "anthropic", uuid, &in_flight_creds);
            Ok(
                br#"{"error":{"type":"invalid_grant","message":"refresh token rejected"}}"#
                    .to_vec(),
            )
        })
        .unwrap();
        assert!(
            matches!(result, BrokerResult::Skipped),
            "a pending rescue outranks a provider rejection for LOGIN-NEEDED: {result:?}"
        );
        assert!(!sentinel::is_broker_failed(dir.path(), account));
        assert!(
            crate::credentials::rescue::rescue_record_pending(&identity_dir).is_some(),
            "the in-flight record must be reported, never ignored or deleted"
        );
    }

    /// D237 ruling F for Codex: `CodexHttpError::Transport` is a local
    /// failure with an unknown provider outcome; no sentinel, no
    /// LOGIN-NEEDED.
    #[test]
    fn broker_codex_check_transport_error_is_not_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 60;
        let acc = install_codex_account(dir.path(), 18, exp, Some("rt_transport"));
        let result = broker_codex_check(dir.path(), acc, |_url, _body| {
            Err("node http transport: child exceeded the parent wait deadline".into())
        })
        .unwrap();
        assert!(
            matches!(result, BrokerResult::Skipped),
            "an unknown-outcome codex refresh must retry: {result:?}"
        );
        assert!(!sentinel::is_broker_failed(dir.path(), acc));
    }

    /// Reader parity for Codex: a missing refresh token in the canonical is
    /// NOT login-needed while a pending rescue record exists (the record
    /// may hold the token). R3 3(a): the record must PROVE the current
    /// canonical was consumed; the pre-flight gate then blocks before the
    /// missing-token arm. A live writer sidecar keeps it pending here.
    #[test]
    fn codex_missing_refresh_token_with_pending_rescue_is_not_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 60;
        let acc = install_codex_account(dir.path(), 19, exp, None);
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(19);
        let identity_dir =
            crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid)
                .parent()
                .unwrap()
                .to_path_buf();
        let canonical = credentials::load(
            &crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid),
        )
        .unwrap();
        let (_record, _writer_alive) =
            plant_provable_pending_rescue(dir.path(), "codex", uuid, &canonical);

        let result = broker_codex_check(dir.path(), acc, |_url, _body| {
            panic!("a pending rescue must not reach HTTP")
        })
        .unwrap();
        assert!(
            matches!(result, BrokerResult::Skipped),
            "a pending rescue outranks the missing-token LOGIN-NEEDED: {result:?}"
        );
        assert!(!sentinel::is_broker_failed(dir.path(), acc));
        assert!(crate::credentials::rescue::rescue_record_pending(&identity_dir).is_some());
    }

    /// D237 round-2 H-a (correctness N1): while a rescue record is STILL
    /// pending after the adoption attempt, the canonical may hold the
    /// PRE-rotation refresh token, which the provider already consumed. The
    /// broker MUST NOT present it again — a reuse-detecting provider can
    /// revoke the whole grant family, killing the rescued pair too.
    ///
    /// RED mutation: delete the `rescue_pending_for` gate after
    /// `adopt_pending_rescue` in `broker_check` — the closure is called and
    /// the zero-HTTP assertion fails.
    #[test]
    fn broker_check_pending_rescue_makes_zero_http_calls() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(7u16).unwrap();
        // Near expiry: without the gate this tick would refresh.
        let creds = make_creds("at-7", "rt-7", now_secs_test() + 60);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        // R3 3(a): only a record that can PROVE the current canonical was
        // consumed blocks the tick. A live writer sidecar keeps adoption from
        // resolving it during this test.
        let (record, _writer_alive) =
            plant_provable_pending_rescue(dir.path(), "anthropic", uuid, &creds);

        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let result = broker_check(dir.path(), account, move |_url, _body| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(br#"{"access_token":"a","refresh_token":"r","expires_in":18000}"#.to_vec())
        })
        .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a pending rescue must block the provider request entirely"
        );
        assert!(
            matches!(result, BrokerResult::Skipped),
            "a pending rescue skips the tick: {result:?}"
        );
        assert!(!sentinel::is_broker_failed(dir.path(), account));
        assert!(
            record.exists(),
            "the provable record stays PENDING while its writer is live"
        );
    }

    /// R3 3(a): an UNPARSEABLE record proves nothing about the current
    /// canonical, so it must not block the tick forever. The status surface
    /// reports it as UNADOPTABLE with the sign-in action while it exists, and
    /// the next adoption QUARANTINES it — it never installs, never replays,
    /// never sets LOGIN-NEEDED by itself.
    ///
    /// RED mutation: make `RescueRecord::is_self_resolving` ignore
    /// `is_unparseable` — the `Unadoptable` assertion fails. Revert the
    /// gate's provability rule (block on any record) — the quarantine
    /// assertion fails because the tick skips instead of adopting.
    #[test]
    fn unparseable_rescue_is_reported_unadoptable_and_quarantined_on_adoption() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(21u16).unwrap();
        let creds = make_creds("at-21", "rt-21", now_secs_test() + 60);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let identity_dir = identity_store::credentials_path_for(dir.path(), uuid)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::write(
            crate::credentials::rescue::rescue_record_path(&identity_dir),
            b"not json",
        )
        .unwrap();

        // The status surface (which never adopts) reports it as unadoptable
        // with the sign-in action while the record exists.
        let rows = crate::credentials::rescue::pending_rescues(dir.path());
        assert_eq!(rows.len(), 1, "the affected slot must be visible: {rows:?}");
        assert_eq!(rows[0].slot, Some(account.get()));
        assert_eq!(
            rows[0].state,
            crate::credentials::rescue::RescuePendingState::Unadoptable
        );
        assert_eq!(
            rows[0].status_line(),
            "slot 21: a saved login could not be restored; sign in again for this account"
        );

        // The tick quarantines it (it can never be re-gated) and proceeds:
        // an unparseable record proves nothing about the canonical.
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let result = broker_check(dir.path(), account, move |_url, _body| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(br#"{"access_token":"a","refresh_token":"r","expires_in":18000}"#.to_vec())
        })
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "an unparseable record must not block the provider request"
        );
        assert!(matches!(result, BrokerResult::Refreshed), "{result:?}");
        assert!(
            !sentinel::is_broker_failed(dir.path(), account),
            "quarantining a corrupt record is not a re-login condition"
        );
        assert!(
            crate::credentials::rescue::rescue_record_pending(&identity_dir).is_none(),
            "the unparseable record is quarantined, never installed"
        );
    }

    /// An ADOPTABLE record (intact v2 + witness) reports the TRANSIENT state,
    /// never the sign-in-again text, and the blocked tick still makes ZERO
    /// HTTP calls with no sentinel.
    ///
    /// R3 corr L-6: the fixture must DISCRIMINATE the gate. The canonical is
    /// VALID and EXPIRED (so absent the gate the tick demonstrably reaches
    /// the provider) and the record's witness source IS that canonical, so
    /// the record is genuinely adoptable. It stays pending because its writer
    /// is still live (the sidecar liveness lock held below) — adoption
    /// defers it, the gate then blocks the provider request.
    ///
    /// RED mutations: (a) drop the `rescue_pending_for` gate — `calls` is 1
    /// (before the fix the unreadable canonical could have made the fixture
    /// pass for the wrong reason); (b) give `RescuePendingState::Adoptable`
    /// the unadoptable message — the `!contains("sign in again")` assertion
    /// fails.
    #[test]
    fn adoptable_rescue_shows_transient_status_with_zero_http() {
        use crate::credentials::rescue::{RescuePendingState, RescueWitness};

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(22u16).unwrap();
        // Expired: the refresh path would request HTTP on its own.
        let creds = make_creds("at-22", "rt-22", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let canonical = identity_store::credentials_path_for(dir.path(), uuid);
        let identity_dir = canonical.parent().unwrap().to_path_buf();
        // The classification re-runs the writer's stored-context gate, which
        // reads identity.json. A LegacyUnknown context (provider + email) is
        // the state a pre-Known install leaves, and the witness records the
        // same legacy email, so the record is genuinely installable.
        crate::accounts::identity_store::write_anthropic_metadata_new(
            dir.path(),
            uuid,
            &serde_json::json!({"provider": "anthropic", "email": "same@test.invalid"}),
        )
        .unwrap();

        // The witness's SOURCE is the live canonical: adoption can prove it.
        let rescued = make_creds("rescued-at", "rescued-rt", now_secs_test() + 3600);
        let witness = RescueWitness::Anthropic(ai::RescueLineageWitness {
            kind: ai::RescueWitnessKind::Refresh,
            source_version: ai::CredentialVersion::for_credentials(creds.anthropic().unwrap())
                .unwrap(),
            result_version: ai::CredentialVersion::for_credentials(rescued.anthropic().unwrap())
                .unwrap(),
            context: None,
            legacy_email: Some("same@test.invalid".into()),
        });
        let record_path = crate::credentials::rescue::write_rescue_record(
            &identity_dir,
            "anthropic",
            &uuid.to_string(),
            "post_commit_lock_timeout",
            &serde_json::to_value(&rescued).unwrap(),
            &witness,
        )
        .unwrap();
        // The writer is still publishing: hold its liveness sidecar so
        // adoption defers and the record remains pending for this tick.
        let _writer_alive = hold_live_writer_sidecar(&record_path);

        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let result = broker_check(dir.path(), account, move |_url, _body| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(br#"{"access_token":"a","refresh_token":"r","expires_in":18000}"#.to_vec())
        })
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a still-pending rescue must block the provider request"
        );
        assert!(matches!(result, BrokerResult::Skipped), "{result:?}");
        assert!(
            !sentinel::is_broker_failed(dir.path(), account),
            "a pending rescue is never LOGIN-NEEDED"
        );

        let rows = crate::credentials::rescue::pending_rescues(dir.path());
        assert_eq!(rows.len(), 1, "the affected slot must be visible: {rows:?}");
        assert_eq!(rows[0].state, RescuePendingState::Adoptable);
        assert!(
            rows[0].status_line().contains("retries it automatically"),
            "adoptable shows the transient status: {}",
            rows[0].status_line()
        );
        assert!(
            !rows[0].status_line().contains("sign in again"),
            "a transient block must not prescribe a sign-in: {}",
            rows[0].status_line()
        );
    }

    /// D237 round-2 H-b (correctness N2): a PRE-COMMIT canonical-lock expiry
    /// consumed nothing provider-side. It must map to Skipped with its own
    /// status — never `broker_failed` (a false LOGIN-NEEDED) and never HTTP.
    ///
    /// RED mutation: classify the preflight refusal as `RefreshFailure::Failed`
    /// again (or make `prepare_anthropic_refresh` return the generic
    /// `Corrupt` refusal) — the sentinel assertion fails.
    #[test]
    fn broker_check_pre_commit_lock_busy_skips_without_login_needed() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(8u16).unwrap();
        let creds = make_creds("at-8", "rt-8", now_secs_test() + 60);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let canonical = identity_store::credentials_path_for(dir.path(), uuid);

        let lock_path = canonical.with_extension("lock");
        let holder = crate::accounts::profiles_lock::HeldOnOtherThread::hold(move || {
            lock::try_lock_file(&lock_path)
                .expect("try_lock_file")
                .expect("test must hold the canonical lock")
        });

        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let started = std::time::Instant::now();
        let result = broker_check(dir.path(), account, move |_url, _body| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(br#"{"access_token":"a","refresh_token":"r","expires_in":18000}"#.to_vec())
        })
        .unwrap();
        let elapsed = started.elapsed();
        drop(holder);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a pre-commit lock expiry must not reach the provider"
        );
        assert!(
            matches!(result, BrokerResult::Skipped),
            "pre-commit lock contention skips the tick: {result:?}"
        );
        assert!(
            !sentinel::is_broker_failed(dir.path(), account),
            "lock contention is not a re-login condition"
        );
        assert!(
            elapsed < crate::credentials::rescue::CREDENTIAL_COMMIT_LOCK_BUDGET,
            "the preflight must keep the 500 ms class budget, not the commit budget: {elapsed:?}"
        );
    }

    /// R3 corr L-1: a NON-contention canonical-lock I/O fault (EACCES/EISDIR/
    /// EROFS/ENOSPC) is not contention. It must not report "busy; retried
    /// next tick" — no later tick clears it — and must reach the sentinel
    /// surface (`csq status` / `csq doctor`) with its typed tag; no provider
    /// request may run.
    ///
    /// RED on the pre-fix classifier: every `CanonicalLockRefused` became
    /// `PreCommitLockRefused`, so the sentinel stayed unset and the only tag
    /// was `refresh_pre_commit_lock_busy`.
    #[cfg(unix)]
    #[test]
    fn broker_check_non_contention_lock_error_is_visible_not_busy() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(12u16).unwrap();
        let creds = make_creds("at-12", "rt-12", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let lock_path =
            identity_store::credentials_path_for(dir.path(), uuid).with_extension("lock");
        if lock_path.exists() {
            std::fs::remove_file(&lock_path).unwrap();
        }
        // A directory at the lock path makes the lock OPEN fail with a
        // non-contention io error on Unix (EISDIR; EACCES behaves alike).
        std::fs::create_dir(&lock_path).unwrap();

        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let (result, events) = capture_events(|| {
            broker_check(dir.path(), account, move |_url, _body| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(br#"{"access_token":"a","refresh_token":"r","expires_in":18000}"#.to_vec())
            })
        });
        let result = result.unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a pre-commit lock I/O fault must not reach the provider"
        );
        assert!(
            matches!(result, BrokerResult::Failed(_)),
            "a permanent local lock fault is a failure, not a silent busy skip: {result:?}"
        );
        assert_eq!(
            sentinel::read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("credentials_canonical_lock_refused"),
            "the typed lock-refusal reason must reach the sentinel / doctor surface"
        );
        let kinds: Vec<String> = events
            .iter()
            .filter_map(|fields| fields.get("error_kind").cloned())
            .collect();
        assert!(
            !kinds
                .iter()
                .any(|kind| kind == "refresh_pre_commit_lock_busy"),
            "a non-contention fault must not be reported as busy, got {kinds:?}"
        );
    }

    /// R3 corr L-1 (capture arm): a profiles-lock I/O fault makes custody
    /// capture fail. The refusal must NAME its cause (`reason`) instead of
    /// reading as a generic custody race — otherwise a permanent lock fault
    /// is invisible in the daemon log.
    ///
    /// RED on the pre-fix code: the warn carried no `reason` field, so a
    /// transient race and a broken lock file looked identical.
    #[cfg(unix)]
    #[test]
    fn refresh_authority_refusal_names_its_cause() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(14u16).unwrap();
        let creds = make_creds("at-14", "rt-14", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        let lock_path = crate::accounts::profiles_lock::ProfilesFileLock::lock_path(dir.path());
        if lock_path.exists() {
            std::fs::remove_file(&lock_path).unwrap();
        }
        std::fs::create_dir(&lock_path).unwrap();

        let (result, events) = capture_events(|| {
            broker_check(dir.path(), account, |_url, _body| {
                panic!("no provider request without custody")
            })
        });
        assert!(matches!(result.unwrap(), BrokerResult::Skipped));
        let refused = events
            .iter()
            .find(|fields| {
                fields.get("error_kind").map(String::as_str)
                    == Some("refresh_identity_authority_refused")
            })
            .expect("the authority refusal must be logged");
        assert_eq!(
            refused.get("reason").map(String::as_str),
            Some("Io"),
            "the refusal must name the lock I/O cause: {refused:?}"
        );
    }

    /// R3 corr L-8 / sec L-3: a failure-attribution lock refusal is LOGGED —
    /// a silent skip loses both the failure and the lock fault. The lock is
    /// broken from inside the provider mock, after custody capture.
    ///
    /// RED on the pre-fix code: `.ok()` dropped the error, so the event list
    /// carried no lock tag at all.
    #[cfg(unix)]
    #[test]
    fn refresh_sentinel_attribution_lock_error_is_logged() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(15u16).unwrap();
        let creds = make_creds("at-15", "rt-15", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        let lock_path = crate::accounts::profiles_lock::ProfilesFileLock::lock_path(dir.path());

        let (result, events) = capture_events(|| {
            broker_check(dir.path(), account, move |_url, _body| {
                // Custody capture is done by now; break every later acquire.
                let _ = std::fs::remove_file(&lock_path);
                std::fs::create_dir(&lock_path).unwrap();
                Ok(
                    br#"{"error":{"type":"invalid_grant","message":"refresh token rejected"}}"#
                        .to_vec(),
                )
            })
        });
        assert!(matches!(result.unwrap(), BrokerResult::Skipped));
        let kinds: Vec<String> = events
            .iter()
            .filter_map(|fields| fields.get("error_kind").cloned())
            .collect();
        assert!(
            kinds
                .iter()
                .any(|kind| kind == "refresh_sentinel_custody_lock_refused"),
            "the lock refusal must be logged, got {kinds:?}"
        );
    }

    /// R3 corr L-1 (sentinel-clear arm): after a successful rotation, custody
    /// is re-verified under the profiles lock. A lock I/O failure there must
    /// classify as `LockError`, not `Busy` — the pre-fix code called every
    /// acquisition error "busy".
    ///
    /// RED on the pre-fix classifier: the directory-at-lock-path case below
    /// produced a real `profiles_lock_refused` ConfigError and was reported
    /// as `SavedPairCustody::Busy`.
    #[cfg(unix)]
    #[test]
    fn saved_pair_custody_reports_lock_io_error_not_busy() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(13u16).unwrap();
        let creds = make_creds("at-13", "rt-13", 0);
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(dir.path(), account.get(), &creds);
        // Capture BEFORE breaking the lock path: capture itself takes it.
        let binding = ai::capture_anthropic_binding(dir.path(), account).unwrap();
        let version = binding.credential_version();

        let lock_path = ProfilesFileLock::lock_path(dir.path());
        if lock_path.exists() {
            std::fs::remove_file(&lock_path).unwrap();
        }
        std::fs::create_dir(&lock_path).unwrap();
        assert_eq!(
            classify_saved_pair_custody(dir.path(), account, &binding, version),
            SavedPairCustody::LockError {
                parent_refused: false
            },
            "a lock-file I/O fault is not contention"
        );
    }

    /// D237 round-2 H-a, Codex arm: the single-use refresh token must never be
    /// replayed while its successor sits in a pending record.
    ///
    /// RED mutation: delete the `rescue_pending_for` gate after
    /// `adopt_pending_rescue` in `broker_codex_check` — the closure is called.
    #[test]
    fn broker_codex_check_pending_rescue_makes_zero_http_calls() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 60;
        let acc = install_codex_account(dir.path(), 20, exp, Some("rt_pending"));
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(20);
        let identity_dir =
            crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid)
                .parent()
                .unwrap()
                .to_path_buf();
        let canonical = credentials::load(
            &crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid),
        )
        .unwrap();
        let (_record, _writer_alive) =
            plant_provable_pending_rescue(dir.path(), "codex", uuid, &canonical);

        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let result = broker_codex_check(dir.path(), acc, move |_url, _body| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err("must not run".into())
        })
        .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a pending codex rescue must block the provider request entirely"
        );
        assert!(matches!(result, BrokerResult::Skipped));
        assert!(!sentinel::is_broker_failed(dir.path(), acc));
        assert!(crate::credentials::rescue::rescue_record_pending(&identity_dir).is_some());
    }

    #[test]
    fn broker_check_success_clears_flag() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(4u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 4);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        let creds = make_creds("at-4", "rt-4", 0);
        save_creds_uuid(dir.path(), 4, &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        // Set flag first
        sentinel::set_broker_failed(dir.path(), account, "test_reason").unwrap();
        assert!(sentinel::is_broker_failed(dir.path(), account));
        assert_eq!(
            sentinel::read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("test_reason")
        );

        // Successful refresh clears it
        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));
        assert!(!sentinel::is_broker_failed(dir.path(), account));
    }

    /// M3-7 regression-pin: broker_check no longer fans out to
    /// `config-<N>/.credentials.json` mirrors. Pre-M3-7, this test
    /// asserted the new token landed in every config-N mirror. Post-M3-7,
    /// the mirror writers are retired; the test now asserts the mirrors
    /// remain at their seed content (not overwritten with the refreshed
    /// token). Handle dirs see refreshed credentials via their identity-
    /// keyed symlinks instead.
    #[test]
    fn broker_check_does_not_fan_out_to_config_dirs() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 5);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        let creds = make_creds("at-5", "rt-5", 0);
        save_creds_uuid(dir.path(), 5, &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        // Set up two config dirs for the same account with seed credentials
        let config_a = dir.path().join("config-51");
        let config_b = dir.path().join("config-52");
        std::fs::create_dir_all(&config_a).unwrap();
        std::fs::create_dir_all(&config_b).unwrap();
        markers::write_csq_account_legacy(&config_a, account).unwrap();
        markers::write_csq_account_legacy(&config_b, account).unwrap();
        credentials::save(&config_a.join(".credentials.json"), &creds).unwrap();
        credentials::save(&config_b.join(".credentials.json"), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // M3-7: live mirrors stay at seed content — fanout retired.
        let a = credentials::load(&config_a.join(".credentials.json")).unwrap();
        let b = credentials::load(&config_b.join(".credentials.json")).unwrap();
        assert_eq!(
            a.expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-5",
            "M3-7: config-N/.credentials.json mirror MUST NOT be overwritten by fanout"
        );
        assert_eq!(
            b.expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-5",
            "M3-7: config-N/.credentials.json mirror MUST NOT be overwritten by fanout"
        );

        // M4-12: UUID-keyed identity path carries the refreshed token
        // (numeric path is no longer the write destination).
        let uuid5 = crate::testing::identity_fixtures::fixture_uuid_for_slot(5);
        let uuid_path5 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid5);
        let canonical = credentials::load(&uuid_path5).unwrap();
        assert_eq!(
            canonical
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed",
            "M4-12: UUID-keyed identity path MUST receive the refreshed token"
        );
    }

    /// RN1-C regression: broker_check MUST read from identities/<UUID>/credentials.json
    /// when by_slot is populated, NOT from the retired numeric credentials/N.json path.
    ///
    /// Setup: only identities/<UUID>/credentials.json exists (expired token).
    /// credentials/N.json does NOT exist — simulates a post-RN1-C account.
    /// Assert: broker_check returns Ok(Refreshed), not NotFound/Err.
    ///
    /// Pre-fix: broker_check read file::canonical_path (numeric) → file not found
    /// → every Anthropic slot hit LOGIN_REQUIRED on the first daemon tick.
    #[test]
    fn broker_check_reads_uuid_path_when_by_slot_populated() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(20u16).unwrap();

        // Provision UUID mapping in by_slot (what commit_anthropic_login/Pass0 write).
        provision_uuid_for_account(dir.path(), 20);
        let uuid20 = crate::testing::identity_fixtures::fixture_uuid_for_slot(20);

        // Write expired credentials ONLY to the UUID-keyed path.
        // The numeric credentials/20.json does NOT exist.
        let creds = make_creds("at-uuid-only", "rt-uuid-only", 0);
        save_creds_uuid(dir.path(), account.get(), &creds);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid20);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_path, &creds).unwrap();

        // Verify the numeric path does NOT exist.
        let numeric_path = file::canonical_path(dir.path(), account);
        assert!(
            !numeric_path.exists(),
            "test precondition: numeric credentials/N.json must NOT exist"
        );

        // Act: broker_check should read UUID path, find expired token, refresh.
        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(
            matches!(result, BrokerResult::Refreshed),
            "broker_check must resolve UUID path when by_slot populated, got {result:?}"
        );

        // Assert: UUID-keyed path carries the refreshed token.
        let updated = credentials::load(&uuid_path).unwrap();
        assert_eq!(
            updated
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed",
            "UUID-keyed credentials.json must carry the refreshed access_token"
        );
    }

    #[test]
    fn broker_concurrent_exactly_one_refresh() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 6);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        let creds = make_creds("at-6", "rt-6", 0);
        save_creds_uuid(dir.path(), 6, &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let refresh_count = Arc::new(AtomicU32::new(0));
        let base = dir.path().to_path_buf();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let base = base.clone();
                let count = Arc::clone(&refresh_count);
                thread::spawn(move || {
                    let result = broker_check(&base, account, |url, body| {
                        count.fetch_add(1, Ordering::SeqCst);
                        // Small delay to increase contention window
                        thread::sleep(std::time::Duration::from_millis(10));
                        mock_refresh_success(url, body)
                    });
                    result.unwrap()
                })
            })
            .collect();

        for h in handles {
            match h.join().unwrap() {
                BrokerResult::Refreshed | BrokerResult::Skipped | BrokerResult::Valid => {}
                other => panic!("unexpected: {other:?}"),
            }
        }

        // With the re-read-inside-lock logic (C6 fix), the first thread
        // that acquires the lock performs the single refresh. Every
        // subsequent thread either:
        //   (a) sees the lock held and returns Skipped without touching
        //       http_post, or
        //   (b) waits for the lock, re-reads canonical, finds it no
        //       longer near-expiry, and returns Valid without touching
        //       http_post.
        //
        // Either way, exactly one thread ever calls the http_post
        // closure. Any number >1 means the lock is not coordinating
        // correctly and must be investigated — not hidden with a
        // looser bound.
        let total_calls = refresh_count.load(Ordering::SeqCst);
        assert_eq!(
            total_calls, 1,
            "expected exactly 1 refresh call with lock coordination, got {total_calls}"
        );
    }

    // ── broker_codex_check (PR-C4) ───────────────────────────────

    use crate::credentials::{CodexCredentialFile, CodexTokensFile};
    use crate::providers::catalog::Surface;

    /// Builds a JWT-shape `<header>.<payload>.<sig>` whose payload's
    /// `exp` claim is `exp_secs`. Header + sig are deterministic stubs.
    fn make_codex_jwt(exp_secs: u64) -> String {
        let payload = format!(r#"{{"exp":{exp_secs},"sub":"test"}}"#);
        let payload_b64 = base64url_encode(payload.as_bytes());
        // header={"alg":"HS256"} → base64url no-padding.
        let header_b64 = "eyJhbGciOiJIUzI1NiJ9";
        format!("{header_b64}.{payload_b64}.testsig")
    }

    fn base64url_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in data {
            buf = (buf << 8) | (b as u32);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let idx = ((buf >> bits) & 0x3f) as usize;
                out.push(ALPHABET[idx] as char);
            }
        }
        if bits > 0 {
            let idx = ((buf << (6 - bits)) & 0x3f) as usize;
            out.push(ALPHABET[idx] as char);
        }
        out
    }

    fn install_codex_account(
        base: &std::path::Path,
        account: u16,
        access_token_exp_secs: u64,
        refresh_token: Option<&str>,
    ) -> AccountNum {
        let num = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-test".into()),
                access_token: make_codex_jwt(access_token_exp_secs),
                refresh_token: refresh_token.map(|s| s.into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        });
        // M4-12: provision UUID mapping so save_canonical_for (called by
        // broker_codex_check after a successful refresh) can locate the
        // identity write path.
        provision_uuid_for_account(base, account);
        credentials::save(&file::canonical_path_for(base, num, Surface::Codex), &creds).unwrap();
        // M4-4: broker_codex_check now resolves UUID when by_slot is populated.
        // Write the same credentials to the UUID-keyed path so broker_codex_check
        // loads the correct (test-controlled) JWT for expiry checks.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let uuid_codex_path =
            crate::accounts::identity_store::credentials_codex_path_for(base, uuid);
        std::fs::create_dir_all(uuid_codex_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_codex_path, &creds).unwrap();
        num
    }

    fn now_secs_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn broker_codex_legacy_numeric_valid_has_locked_content_authority() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = install_codex_account(
            base,
            12,
            now_secs_test() + 12 * 3600,
            Some("fake-legacy-rt"),
        );
        let profiles_path = profiles::profiles_path(base);
        let mut pf = profiles::load(&profiles_path).unwrap();
        pf.by_slot.remove(&account.to_string());
        profiles::save(&profiles_path, &pf).unwrap();
        let numeric = file::canonical_path_for(base, account, Surface::Codex);
        let expected = credentials::load(&numeric).unwrap();
        let before = std::fs::read(&numeric).unwrap();
        let actions = std::cell::Cell::new(0);
        assert!(
            with_current_codex_authority(base, account, None, 0, &expected, || {
                let probe_lock = numeric.with_extension("lock");
                let probe_base = base.to_path_buf();
                // Windows named mutexes are recursive for the owning thread;
                // probe competing custody from a different thread on every OS.
                std::thread::spawn(move || {
                    assert!(
                        lock::try_lock_file(&probe_lock).unwrap().is_none(),
                        "numeric canonical lock must cover the sentinel action"
                    );
                    assert!(
                        crate::accounts::profiles_lock::ProfilesFileLock::try_acquire(&probe_base)
                            .unwrap()
                            .is_none()
                    );
                })
                .join()
                .unwrap();
                actions.set(actions.get() + 1);
            })
            .unwrap(),
            "legacy numeric content must retain authority"
        );
        assert_eq!(actions.get(), 1);
        sentinel::set_broker_failed(base, account, "codex_refresh_reused").unwrap();
        let result = broker_codex_check(base, account, |_url, _body| {
            panic!("healthy numeric token must not invoke HTTP")
        })
        .unwrap();
        assert!(
            matches!(result, BrokerResult::Valid),
            "healthy legacy numeric token must report Valid"
        );
        assert!(!sentinel::is_broker_failed(base, account));
        assert_eq!(std::fs::read(&numeric).unwrap(), before);

        let mut changed = expected.clone();
        changed.codex_mut().unwrap().tokens.refresh_token = Some("fake-winner-rt".into());
        credentials::save(&numeric, &changed).unwrap();
        assert!(
            !with_current_codex_authority(base, account, None, 0, &expected, || actions
                .set(actions.get() + 1))
            .unwrap()
        );
        pf.by_slot.insert(
            account.to_string(),
            crate::testing::identity_fixtures::fixture_uuid_for_slot(12),
        );
        profiles::save(&profiles_path, &pf).unwrap();
        assert!(
            !with_current_codex_authority(base, account, None, 0, &changed, || actions
                .set(actions.get() + 1))
            .unwrap()
        );
        assert_eq!(
            actions.get(),
            1,
            "stale numeric content or later UUID binding must not authorize actions"
        );
        assert_eq!(
            serde_json::to_value(credentials::load(&numeric).unwrap()).unwrap(),
            serde_json::to_value(changed).unwrap()
        );
    }

    #[test]
    fn broker_codex_legacy_numeric_missing_rt_reports_expired_and_warns() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = install_codex_account(base, 12, now_secs_test() + 3600, None);
        let profiles_path = profiles::profiles_path(base);
        let mut pf = profiles::load(&profiles_path).unwrap();
        pf.by_slot.remove(&account.to_string());
        profiles::save(&profiles_path, &pf).unwrap();
        let numeric = file::canonical_path_for(base, account, Surface::Codex);
        let before = std::fs::read(&numeric).unwrap();
        let (result, events) = capture_broker_events(|| {
            broker_codex_check(base, account, |_url, _body| {
                panic!("missing refresh token must not invoke HTTP")
            })
        });
        assert!(
            matches!(
                result.unwrap(),
                BrokerResult::Failed(BrokerError::CodexTokenExpired { account: 12 })
            ),
            "missing legacy refresh token must report Failed expired"
        );
        assert_eq!(
            sentinel::read_broker_failed_reason(base, account).as_deref(),
            Some("codex_token_expired")
        );
        assert!(
            events
                .iter()
                .any(|event| event.level == tracing::Level::WARN
                    && event.error_kind.as_deref() == Some("codex_token_expired")
                    && event
                        .message
                        .as_deref()
                        .is_some_and(|message| message.contains("LOGIN-NEEDED"))),
            "missing refresh token needs a fixed-tag LOGIN-NEEDED warning: {events:?}"
        );
        assert_eq!(std::fs::read(&numeric).unwrap(), before);
    }

    #[test]
    fn broker_codex_missing_uuid_refuses_before_single_use_refresh_http() {
        let dir = TempDir::new().unwrap();
        let account = install_codex_account(
            dir.path(),
            12,
            now_secs_test() + 3600,
            Some("fake-single-use-rt"),
        );
        let profiles_path = profiles::profiles_path(dir.path());
        let mut pf = profiles::load(&profiles_path).unwrap();
        pf.by_slot.remove(&account.to_string());
        profiles::save(&profiles_path, &pf).unwrap();
        let numeric = file::canonical_path_for(dir.path(), account, Surface::Codex);
        let before = std::fs::read(&numeric).unwrap();
        let calls = std::cell::Cell::new(0);
        let result = broker_codex_check(dir.path(), account, |_url, _body| {
            calls.set(calls.get() + 1);
            Ok(crate::http::NodeHttpResponse {
                status: 200,
                body: format!(r#"{{"access_token":"{}","refresh_token":"fake-rotated-rt","expires_in":3600}}"#, make_codex_jwt(now_secs_test() + 12 * 3600)).into_bytes(),
                date: None,
            })
        });
        assert_eq!(
            calls.get(),
            0,
            "missing UUID must refuse before consuming a single-use refresh token"
        );
        assert!(matches!(
            result,
            Err(CsqError::Credential(
                crate::error::CredentialError::NoCredentials(12)
            ))
        ));
        assert_eq!(std::fs::read(&numeric).unwrap(), before);
    }

    #[test]
    fn broker_codex_sentinel_custody_preserves_owner_and_warns_on_refusal() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let account = install_codex_account(
            base,
            12,
            now_secs_test() + 12 * 3600,
            Some("fake-custody-rt"),
        );
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(12);
        let path = identity_store::credentials_codex_path_for(base, uuid);
        let healthy = credentials::load(&path).unwrap();
        sentinel::set_broker_failed(base, account, "another_operation_failure").unwrap();
        // Healthy early return: a concurrent profiles owner is still authority;
        // this observation cannot clear its slot diagnostic.
        let held = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        let calls = std::cell::Cell::new(0);
        let result = broker_codex_check(base, account, |_url, _body| {
            calls.set(calls.get() + 1);
            Err("unexpected fake HTTP".into())
        })
        .unwrap();
        assert_eq!(
            sentinel::read_broker_failed_reason(base, account).as_deref(),
            Some("another_operation_failure"),
            "early healthy clear must retain another operation's sentinel"
        );
        assert!(matches!(result, BrokerResult::Skipped));
        assert_eq!(calls.get(), 0);
        drop(held);

        let mut expired = healthy.clone();
        expired.codex_mut().unwrap().tokens.access_token = make_codex_jwt(now_secs_test() + 3600);
        expired.codex_mut().unwrap().tokens.refresh_token = None;
        credentials::save(&path, &expired).unwrap();
        // No refresh token: failure publication is also an authority-bearing
        // write, not permission to overwrite a concurrent diagnostic.
        let held = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        let result = broker_codex_check(base, account, |_url, _body| {
            calls.set(calls.get() + 1);
            Err("unexpected fake HTTP".into())
        })
        .unwrap();
        assert_eq!(
            sentinel::read_broker_failed_reason(base, account).as_deref(),
            Some("another_operation_failure"),
            "missing-RT setter must retain another operation's sentinel"
        );
        assert!(matches!(
            result,
            BrokerResult::Failed(BrokerError::CodexTokenExpired { account: 12 })
        ));
        assert_eq!(calls.get(), 0);
        drop(held);

        // First read is expired; a genuine intervening write makes the locked
        // re-read healthy. The held profiles owner still forbids its clear.
        expired.codex_mut().unwrap().tokens.refresh_token = Some("fake-custody-rt".into());
        credentials::save(&path, &expired).unwrap();
        let hook_count = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = hook_count.clone();
        let hook_path = path.clone();
        let hook_healthy = healthy.clone();
        CODEX_AFTER_REFRESH_LOCK_TEST_HOOK.with(|hook| {
            assert!(hook
                .borrow_mut()
                .replace(Box::new(move || {
                    observed.set(observed.get() + 1);
                    credentials::save(&hook_path, &hook_healthy).unwrap();
                }))
                .is_none());
        });
        struct ResetCodexHook;
        impl Drop for ResetCodexHook {
            fn drop(&mut self) {
                CODEX_AFTER_REFRESH_LOCK_TEST_HOOK.with(|hook| {
                    hook.borrow_mut().take();
                });
            }
        }
        let _reset = ResetCodexHook;
        let held = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        let result = broker_codex_check(base, account, |_url, _body| {
            calls.set(calls.get() + 1);
            Err("unexpected fake HTTP".into())
        })
        .unwrap();
        assert_eq!(
            hook_count.get(),
            1,
            "the locked re-read fixture must execute"
        );
        assert_eq!(
            sentinel::read_broker_failed_reason(base, account).as_deref(),
            Some("another_operation_failure"),
            "locked healthy clear must retain another operation's sentinel"
        );
        assert!(matches!(result, BrokerResult::Skipped));
        assert_eq!(calls.get(), 0);
        drop(held);

        // A real failed HTTP response while profiles is busy logs a fixed tag.
        credentials::save(&path, &expired).unwrap();
        let held = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(base);
        let (result, events) = capture_broker_events(|| {
            broker_codex_check(base, account, |_url, _body| {
                calls.set(calls.get() + 1);
                Ok(crate::http::NodeHttpResponse {
                    status: 401,
                    body: br#"{"error":{"code":"refresh_token_reused"}}"#.to_vec(),
                    date: None,
                })
            })
        });
        assert!(matches!(
            result.unwrap(),
            BrokerResult::Failed(BrokerError::CodexRefreshReused { .. })
        ));
        assert_eq!(calls.get(), 1);
        assert!(
            events
                .iter()
                .any(|event| event.level == tracing::Level::WARN
                    && event.error_kind.as_deref()
                        == Some("codex_refresh_sentinel_authority_busy_or_changed")),
            "busy sentinel authority must be observable: {events:?}"
        );
        assert_eq!(
            sentinel::read_broker_failed_reason(base, account).as_deref(),
            Some("another_operation_failure")
        );
        drop(held);

        // An actual post-HTTP reader failure logs its category, never raw parse
        // content; no stale failure is published over the same sentinel.
        let (result, events) = capture_broker_events(|| {
            broker_codex_check(base, account, |_url, _body| {
                calls.set(calls.get() + 1);
                std::fs::write(profiles::profiles_path(base), b"PRIVATE-PARSE-MARKER").unwrap();
                Ok(crate::http::NodeHttpResponse {
                    status: 401,
                    body: br#"{"error":{"code":"token_expired"}}"#.to_vec(),
                    date: None,
                })
            })
        });
        assert!(matches!(
            result.unwrap(),
            BrokerResult::Failed(BrokerError::CodexTokenExpired { .. })
        ));
        assert_eq!(calls.get(), 2);
        assert!(
            events
                .iter()
                .any(|event| event.level == tracing::Level::WARN
                    && event.error_kind.as_deref()
                        == Some("codex_refresh_sentinel_authority_read_refused")),
            "unreadable sentinel authority must be observable: {events:?}"
        );
        assert!(!format!("{events:?}").contains("PRIVATE-PARSE-MARKER"));
        assert_eq!(
            sentinel::read_broker_failed_reason(base, account).as_deref(),
            Some("another_operation_failure")
        );
        // The fixture's deliberate external writes do not get rolled back.
        assert_eq!(
            std::fs::read(profiles::profiles_path(base)).unwrap(),
            b"PRIVATE-PARSE-MARKER"
        );
        assert!(file::codex_credentials_match(
            &credentials::load(&path).unwrap(),
            &expired
        ));
    }

    /// JWT exp far in the future (> 2h) → no refresh, returns Valid.
    #[test]
    fn broker_codex_check_valid_token_no_refresh() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 6 * 3600; // 6h ahead
        let acc = install_codex_account(dir.path(), 11, exp, Some("rt_alive"));

        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let mock =
            move |_url: &str, _body: &str| -> Result<crate::http::NodeHttpResponse, String> {
                calls_c.fetch_add(1, Ordering::SeqCst);
                Ok(crate::http::NodeHttpResponse {
                    status: 200,
                    body: b"{}".to_vec(),
                    date: None,
                })
            };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(result, BrokerResult::Valid));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Codex broker_check must not POST when token is fresh"
        );
    }

    /// Regression: a Valid result MUST clear any stale broker_failed
    /// sentinel. Without this, a transient `token_invalidated` or
    /// `refresh_reused` flag from earlier in the slot's history persists
    /// until the next pre-expiry refresh window (≥ 9.9 days for fresh
    /// codex tokens), contradicting `csq doctor`'s reported state.
    /// Origin: 2026-05-22 — slot 12 showed LOGIN-NEEDED in `csq doctor`
    /// for hours after a successful `csq login` because the daemon
    /// refresher Valid-branch never cleared the stale flag.
    #[test]
    fn broker_codex_check_valid_clears_stale_broker_failed_sentinel() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 6 * 3600; // 6h ahead
        let acc = install_codex_account(dir.path(), 17, exp, Some("rt_alive"));

        // Seed a stale sentinel as if a prior failed refresh had set it.
        sentinel::set_broker_failed(dir.path(), acc, "codex_token_invalidated").unwrap();
        assert!(sentinel::is_broker_failed(dir.path(), acc));

        let mock = |_url: &str, _body: &str| -> Result<crate::http::NodeHttpResponse, String> {
            Ok(crate::http::NodeHttpResponse {
                status: 200,
                body: b"{}".to_vec(),
                date: None,
            })
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(result, BrokerResult::Valid));
        assert!(
            !sentinel::is_broker_failed(dir.path(), acc),
            "stale broker_failed sentinel MUST be cleared when Codex creds are healthy"
        );
    }

    #[test]
    fn broker_codex_refresh_same_uuid_relogin_wins_and_sentinel_is_preserved() {
        let dir = TempDir::new().unwrap();
        let acc = install_codex_account(dir.path(), 12, now_secs_test() + 3600, Some("rt_old"));
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(12);
        let path = crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid);
        let mut winner = credentials::load(&path).unwrap();
        winner.codex_mut().unwrap().tokens.access_token =
            make_codex_jwt(now_secs_test() + 12 * 3600);
        winner.codex_mut().unwrap().tokens.refresh_token = Some("rt_relogin_winner".into());
        let response_at = make_codex_jwt(now_secs_test() + 24 * 3600);
        let response = format!(
            r#"{{"access_token":"{response_at}","refresh_token":"rt_stale_response","expires_in":3600}}"#
        );
        let calls = std::cell::Cell::new(0);
        let result = broker_codex_check(dir.path(), acc, |_url, _body| {
            calls.set(calls.get() + 1);
            file::save_codex_canonical_for_uuid(dir.path(), uuid, &winner).unwrap();
            sentinel::set_broker_failed(dir.path(), acc, "codex_token_invalidated").unwrap();
            Ok(crate::http::NodeHttpResponse {
                status: 200,
                body: response.into_bytes(),
                date: None,
            })
        })
        .unwrap();
        assert_eq!(calls.get(), 1, "the interleaved HTTP path must execute");
        assert!(matches!(result, BrokerResult::Skipped));
        assert_eq!(
            serde_json::to_value(credentials::load(&path).unwrap()).unwrap(),
            serde_json::to_value(winner).unwrap()
        );
        assert!(sentinel::is_broker_failed(dir.path(), acc));
    }

    #[test]
    fn broker_codex_refresh_stale_failure_cannot_replace_relogin_sentinel() {
        let dir = TempDir::new().unwrap();
        let acc = install_codex_account(dir.path(), 12, now_secs_test() + 3600, Some("rt_old"));
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(12);
        let path = crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid);
        let mut winner = credentials::load(&path).unwrap();
        winner.codex_mut().unwrap().tokens.access_token =
            make_codex_jwt(now_secs_test() + 12 * 3600);
        winner.codex_mut().unwrap().tokens.refresh_token = Some("rt_relogin_winner".into());
        let calls = std::cell::Cell::new(0);
        let result = broker_codex_check(dir.path(), acc, |_url, _body| {
            calls.set(calls.get() + 1);
            file::save_codex_canonical_for_uuid(dir.path(), uuid, &winner).unwrap();
            sentinel::set_broker_failed(dir.path(), acc, "codex_refresh_reused").unwrap();
            Ok(crate::http::NodeHttpResponse {
                status: 401,
                body: br#"{"error":{"code":"token_invalidated"}}"#.to_vec(),
                date: None,
            })
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            result,
            BrokerResult::Failed(BrokerError::CodexTokenInvalidated { .. })
        ));
        assert_eq!(
            sentinel::read_broker_failed_reason(dir.path(), acc).as_deref(),
            Some("codex_refresh_reused")
        );
        assert_eq!(
            serde_json::to_value(credentials::load(&path).unwrap()).unwrap(),
            serde_json::to_value(winner).unwrap()
        );
    }

    #[test]
    fn broker_codex_refresh_rebound_slot_preserves_both_uuid_authorities() {
        let dir = TempDir::new().unwrap();
        let acc =
            install_codex_account(dir.path(), 12, now_secs_test() + 3600, Some("rt_original"));
        install_codex_account(
            dir.path(),
            13,
            now_secs_test() + 12 * 3600,
            Some("rt_other_identity"),
        );
        let original = crate::testing::identity_fixtures::fixture_uuid_for_slot(12);
        let replacement = crate::testing::identity_fixtures::fixture_uuid_for_slot(13);
        let replacement_path =
            crate::accounts::identity_store::credentials_codex_path_for(dir.path(), replacement);
        let replacement_before = std::fs::read(&replacement_path).unwrap();
        let response_at = make_codex_jwt(now_secs_test() + 24 * 3600);
        let response = format!(
            r#"{{"access_token":"{response_at}","refresh_token":"rt_rotated_original","expires_in":3600}}"#
        );
        let calls = std::cell::Cell::new(0);
        let result = broker_codex_check(dir.path(), acc, |_url, _body| {
            calls.set(calls.get() + 1);
            let _authority =
                crate::accounts::profiles_lock::ProfilesFileLock::acquire(dir.path()).unwrap();
            let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
            let mut profiles = crate::accounts::profiles::load(&profiles_path).unwrap();
            profiles.by_slot.insert(acc.to_string(), replacement);
            profiles.slot_binding_generations.insert(acc.to_string(), 1);
            crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
            sentinel::set_broker_failed(dir.path(), acc, "codex_token_invalidated").unwrap();
            Ok(crate::http::NodeHttpResponse {
                status: 200,
                body: response.into_bytes(),
                date: None,
            })
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(
            matches!(result, BrokerResult::Refreshed),
            "durable original-UUID rotation must report Refreshed despite a rebound slot"
        );
        assert_eq!(std::fs::read(replacement_path).unwrap(), replacement_before);
        let original_path =
            crate::accounts::identity_store::credentials_codex_path_for(dir.path(), original);
        assert_eq!(
            credentials::load(&original_path)
                .unwrap()
                .codex()
                .unwrap()
                .tokens
                .refresh_token
                .as_deref(),
            Some("rt_rotated_original")
        );
        assert_eq!(
            crate::accounts::profiles::resolve_slot_to_uuid(dir.path(), acc.get()),
            Some(replacement)
        );
        assert!(sentinel::is_broker_failed(dir.path(), acc));
    }

    /// JWT exp within 2h pre-expiry window → refreshes via injected
    /// transport; canonical credentials/codex-N.json gets the new
    /// access + refresh + id tokens.
    #[test]
    fn broker_codex_check_expiring_token_refreshes_and_writes_new_tokens() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 3600; // 1h ahead → inside 2h window
        let acc = install_codex_account(dir.path(), 12, exp, Some("rt_old"));

        // Build the response with a NEW JWT whose exp is way in the
        // future, so a follow-up read would say "Valid".
        let new_exp = now_secs_test() + 6 * 3600;
        let new_at = make_codex_jwt(new_exp);
        let body = format!(
            r#"{{"access_token":"{new_at}","refresh_token":"rt_new","id_token":"{new_at}","expires_in":3600}}"#
        );
        // NO `Date` header, deliberately. This test is about the tokens the
        // refresh WRITES, and it asserts nothing about the server clock — but it
        // used to send `Mon, 01 Jan 2024 00:00:00 GMT`, which was roughly "now"
        // when it was written and has since decayed into ~1.7 YEARS of drift.
        // That silently turned a normal-refresh fixture into one that fires the
        // clock-skew `warn!` on every run, with no subscriber installed to see
        // it — a wall-clock time-bomb of exactly the shape `testing.md` MUST
        // Rule 1 forbids, and one that gets worse every year it is left alone.
        //
        // `None` states the intent directly: no server date, so no skew check.
        // The Date-bearing paths are covered where they belong — a skewed date
        // in `broker_codex_check_clock_skew_emits_warn_but_succeeds` and a
        // missing/invalid one in
        // `broker_codex_check_missing_or_invalid_date_emits_no_clock_skew_warn`.
        let mock =
            move |_url: &str, _body: &str| -> Result<crate::http::NodeHttpResponse, String> {
                Ok(crate::http::NodeHttpResponse {
                    status: 200,
                    body: body.clone().into_bytes(),
                    date: None,
                })
            };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // M4-12: UUID-keyed identity path carries the new tokens.
        let uuid12 = crate::testing::identity_fixtures::fixture_uuid_for_slot(12);
        let path = crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid12);
        let saved = credentials::load(&path).unwrap();
        let codex = saved.codex().expect("must be Codex variant");
        assert_eq!(codex.tokens.access_token, new_at);
        assert_eq!(codex.tokens.refresh_token.as_deref(), Some("rt_new"));
        // last_refresh stamped in RFC-3339-ish UTC.
        assert!(
            codex
                .last_refresh
                .as_deref()
                .map(|s| s.contains('T') && s.ends_with('Z'))
                .unwrap_or(false),
            "last_refresh must be set: {:?}",
            codex.last_refresh
        );
    }

    /// `code: "token_expired"` from upstream → Failed(CodexTokenExpired) +
    /// broker_failed flag with `codex_token_expired` reason. This is the
    /// LOGIN-NEEDED path (FR-CORE-03 step 5).
    #[test]
    fn broker_codex_check_token_expired_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60); // already expired
        let acc = install_codex_account(dir.path(), 13, exp, Some("rt_dead"));

        let mock = |_url: &str, _body: &str| -> Result<crate::http::NodeHttpResponse, String> {
            Ok(crate::http::NodeHttpResponse {
                status: 401,
                body: br#"{"error":{"code":"token_expired"}}"#.to_vec(),
                date: None,
            })
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        match result {
            BrokerResult::Failed(BrokerError::CodexTokenExpired { account: a }) => {
                assert_eq!(a, 13);
            }
            other => panic!("expected Failed(CodexTokenExpired), got {other:?}"),
        }

        // broker_failed flag MUST be set with the codex-specific reason.
        assert!(sentinel::is_broker_failed(dir.path(), acc));
        let reason = sentinel::read_broker_failed_reason(dir.path(), acc);
        assert_eq!(reason.as_deref(), Some("codex_token_expired"));
    }

    /// `code: "token_invalidated"` → Failed(CodexTokenInvalidated).
    ///
    /// Observed 2026-05-22: ChatGPT returns this when a newer login on
    /// the same account minted a replacement chain. Even though the
    /// refresh-token-handed `/oauth/token` endpoint may also return this,
    /// the routing parity with token_expired / refresh_token_reused is
    /// required so the broker_failed sentinel reason and the dashboard
    /// surface the actionable kind tag.
    #[test]
    fn broker_codex_check_token_invalidated_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 12, exp, Some("rt_invalidated"));

        let mock = |_url: &str, _body: &str| -> Result<crate::http::NodeHttpResponse, String> {
            Ok(crate::http::NodeHttpResponse {
                status: 401,
                body: br#"{"error":{"message":"Your authentication token has been invalidated. Please try signing in again.","type":"invalid_request_error","code":"token_invalidated","param":null},"status":401}"#.to_vec(),
                date: None,
            })
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        match result {
            BrokerResult::Failed(BrokerError::CodexTokenInvalidated { account: a }) => {
                assert_eq!(a, 12);
            }
            other => panic!("expected Failed(CodexTokenInvalidated), got {other:?}"),
        }
        let reason = sentinel::read_broker_failed_reason(dir.path(), acc);
        assert_eq!(reason.as_deref(), Some("codex_token_invalidated"));
    }

    /// `code: "refresh_token_reused"` → Failed(CodexRefreshReused).
    #[test]
    fn broker_codex_check_refresh_reused_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 14, exp, Some("rt_reused"));

        let mock = |_url: &str, _body: &str| -> Result<crate::http::NodeHttpResponse, String> {
            Ok(crate::http::NodeHttpResponse {
                status: 401,
                body: br#"{"error":{"code":"refresh_token_reused"}}"#.to_vec(),
                date: None,
            })
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        match result {
            BrokerResult::Failed(BrokerError::CodexRefreshReused { account: a }) => {
                assert_eq!(a, 14);
            }
            other => panic!("expected Failed(CodexRefreshReused), got {other:?}"),
        }
        let reason = sentinel::read_broker_failed_reason(dir.path(), acc);
        assert_eq!(reason.as_deref(), Some("codex_refresh_reused"));
    }

    /// Codex slot with no refresh_token → cannot refresh → Failed
    /// (CodexTokenExpired) without contacting the network.
    #[test]
    fn broker_codex_check_missing_refresh_token_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 15, exp, None);

        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let mock =
            move |_url: &str, _body: &str| -> Result<crate::http::NodeHttpResponse, String> {
                calls_c.fetch_add(1, Ordering::SeqCst);
                Ok(crate::http::NodeHttpResponse {
                    status: 200,
                    body: b"{}".to_vec(),
                    date: None,
                })
            };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(
            result,
            BrokerResult::Failed(BrokerError::CodexTokenExpired { .. })
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no HTTP call when there is no refresh_token to send"
        );
    }

    /// Two concurrent refresh attempts on the same Codex slot — exactly
    /// one fires the upstream. Mirrors `broker_concurrent_exactly_one_refresh`
    /// for Anthropic. The lock-coordinated re-read inside the lock means
    /// the second arrival sees a fresh token and returns Valid (or Skipped
    /// if the lock-holder is still working).
    #[test]
    fn broker_codex_check_concurrent_exactly_one_refresh() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 16, exp, Some("rt_seed"));

        let counter = Arc::new(AtomicU32::new(0));
        let base = dir.path().to_path_buf();

        let new_exp = now_secs_test() + 6 * 3600;
        let new_at = make_codex_jwt(new_exp);
        let body = format!(
            r#"{{"access_token":"{new_at}","refresh_token":"rt_new","id_token":"{new_at}","expires_in":3600}}"#
        );
        let body_arc = Arc::new(body);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let base = base.clone();
                let count = Arc::clone(&counter);
                let body = Arc::clone(&body_arc);
                thread::spawn(move || {
                    let body_local = (*body).clone();
                    broker_codex_check(&base, acc, move |_u, _b| {
                        count.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(std::time::Duration::from_millis(10));
                        Ok(crate::http::NodeHttpResponse {
                            status: 200,
                            body: body_local.into_bytes(),
                            date: None,
                        })
                    })
                })
            })
            .collect();

        for h in handles {
            match h.join().unwrap().unwrap() {
                BrokerResult::Refreshed | BrokerResult::Skipped | BrokerResult::Valid => {}
                other => panic!("unexpected: {other:?}"),
            }
        }

        let total = counter.load(Ordering::SeqCst);
        assert_eq!(
            total, 1,
            "exactly one Codex refresh fires under lock coordination, got {total}"
        );
    }

    // Test-only structured capture. Never installs a global subscriber, reads
    // RUST_LOG, emits the expected event itself, or captures credential payloads.
    #[derive(Clone, Debug)]
    struct BrokerEvent {
        level: tracing::Level,
        error_kind: Option<String>,
        event_kind: Option<String>,
        provider: Option<String>,
        account_num: Option<u64>,
        process_id: Option<u64>,
        message: Option<String>,
        field_names: Vec<String>,
        surface: Option<String>,
        account: Option<String>,
        drift_secs: Option<u64>,
    }

    impl tracing::field::Visit for BrokerEvent {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "error_kind" => self.error_kind = Some(value.to_owned()),
                "event_kind" => self.event_kind = Some(value.to_owned()),
                "provider" => self.provider = Some(value.to_owned()),
                "surface" => self.surface = Some(value.to_owned()),
                "account" => self.account = Some(value.to_owned()),
                "message" => self.message = Some(value.to_owned()),
                _ => {}
            }
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            match field.name() {
                "drift_secs" => self.drift_secs = Some(value),
                "account" => self.account_num = Some(value),
                "process_id" => self.process_id = Some(value),
                _ => {}
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "account" {
                self.account = Some(format!("{value:?}"));
            } else if field.name() == "message" {
                self.message = Some(format!("{value:?}"));
            }
        }
    }

    struct BrokerCapture {
        events: Arc<std::sync::Mutex<Vec<BrokerEvent>>>,
        next_span: std::sync::atomic::AtomicU64,
        max_level: tracing::level_filters::LevelFilter,
    }

    impl tracing::Subscriber for BrokerCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= self.max_level
        }
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(self.max_level)
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed))
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut captured = BrokerEvent {
                level: *event.metadata().level(),
                error_kind: None,
                event_kind: None,
                provider: None,
                account_num: None,
                process_id: None,
                message: None,
                field_names: event
                    .metadata()
                    .fields()
                    .iter()
                    .map(|field| field.name().to_owned())
                    .collect(),
                surface: None,
                account: None,
                drift_secs: None,
            };
            event.record(&mut captured);
            self.events.lock().unwrap().push(captured);
        }
    }

    fn capture_broker_events<T>(run: impl FnOnce() -> T) -> (T, Vec<BrokerEvent>) {
        capture_broker_events_at(tracing::level_filters::LevelFilter::TRACE, run)
    }

    fn capture_broker_events_at<T>(
        max_level: tracing::level_filters::LevelFilter,
        run: impl FnOnce() -> T,
    ) -> (T, Vec<BrokerEvent>) {
        // Held for the whole scope, INCLUDING the drop of the dispatcher guard
        // inside `with_default` — releasing early would leave exactly the window
        // this lock exists to close.
        // Shared with every capturing test in the crate: the race is on
        // tracing's process-global max-level filter (see the lock's doc), and
        // it reproduced on CI's macos leg at 08e26839 as a zero-event capture
        // right after the refresh was asserted to have run.
        let _capture_guard = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = BrokerCapture {
            events: Arc::clone(&events),
            next_span: std::sync::atomic::AtomicU64::new(1),
            max_level,
        };
        // broker_codex_check and its injected transport execute synchronously on
        // this thread; the scoped default is removed before assertions run.
        let result = tracing::subscriber::with_default(subscriber, run);
        let captured = events.lock().unwrap().clone();
        (result, captured)
    }

    #[test]
    fn broker_refresh_success_event_requires_canonical_save() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(21u16).unwrap();
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(
            dir.path(),
            account.get(),
            &make_creds("synthetic-at", "synthetic-rt", 0),
        );
        let calls = AtomicU32::new(0);
        // A real WARN-only subscriber must receive the production success event.
        // Reverting that event to INFO makes this capture empty, even though the
        // injected OAuth refresh and canonical write still succeed.
        let (result, events) =
            capture_broker_events_at(tracing::level_filters::LevelFilter::WARN, || {
                broker_check(dir.path(), account, |url, body| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    mock_refresh_success(url, body)
                })
            });
        assert!(matches!(result.unwrap(), BrokerResult::Refreshed));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let canonical = identity_store::credentials_path_for(dir.path(), uuid);
        let updated = credentials::load(&canonical).unwrap();
        assert_eq!(
            updated
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed"
        );
        let successes: Vec<_> = events
            .iter()
            .filter(|event| event.event_kind.as_deref() == Some("oauth_refresh_succeeded"))
            .collect();
        assert_eq!(
            successes.len(),
            1,
            "WARN-only sink must receive refresh success"
        );
        let event = successes[0];
        assert_eq!(event.level, tracing::Level::WARN);
        assert_eq!(event.account_num, Some(u64::from(account.get())));
        assert_eq!(event.provider.as_deref(), Some("anthropic"));
        assert_eq!(event.surface.as_deref(), Some("claude"));
        assert_eq!(event.process_id, Some(u64::from(std::process::id())));
        assert_eq!(
            event.message.as_deref(),
            Some("OAuth token refreshed and canonical credentials saved")
        );
        let mut fields = event.field_names.clone();
        fields.sort();
        assert_eq!(
            fields,
            [
                "account",
                "event_kind",
                "message",
                "process_id",
                "provider",
                "surface"
            ]
        );
        let rendered = format!("{event:?}");
        for secret in [
            "synthetic-at",
            "synthetic-rt",
            "at-refreshed",
            "rt-refreshed",
        ] {
            assert!(
                !rendered.contains(secret),
                "success event must not contain credentials"
            );
        }

        // A second check sees the saved token as Valid: no HTTP or success event.
        let (result, events) = capture_broker_events(|| {
            broker_check(dir.path(), account, |_url, _body| {
                panic!("Valid must not refresh")
            })
        });
        assert!(matches!(result.unwrap(), BrokerResult::Valid));
        assert!(!events
            .iter()
            .any(|event| event.event_kind.as_deref() == Some("oauth_refresh_succeeded")));
    }

    #[test]
    fn broker_refresh_success_event_absent_on_failed_attempts() {
        let _env_guard = crate::platform::test_env::lock();
        // All transports are private callbacks; no provider requests occur.
        for failure in ["http", "malformed", "rate_limit", "save"] {
            let dir = TempDir::new().unwrap();
            let account = AccountNum::try_from(21u16).unwrap();
            provision_uuid_for_account(dir.path(), account.get());
            save_creds_uuid(
                dir.path(),
                account.get(),
                &make_creds("synthetic-at", "synthetic-rt", 0),
            );
            let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
            let canonical = identity_store::credentials_path_for(dir.path(), uuid);
            let calls = AtomicU32::new(0);
            let (result, events) = capture_broker_events(|| {
                broker_check(dir.path(), account, |url, body| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    match failure {
                        "http" => mock_refresh_failure(url, body),
                        "malformed" => Ok(b"not-json".to_vec()),
                        "rate_limit" => Ok(br#"{"error":{"type":"rate_limit_error"}}"#.to_vec()),
                        "save" => {
                            // Sabotage only the private canonical destination after
                            // the locked read: provider success, real write failure.
                            std::fs::remove_file(&canonical).unwrap();
                            std::fs::create_dir(&canonical).unwrap();
                            mock_refresh_success(url, body)
                        }
                        _ => unreachable!(),
                    }
                })
            });
            let result = result.unwrap();
            if failure == "rate_limit" {
                assert!(matches!(result, BrokerResult::RateLimited));
            } else if failure == "save" {
                // The deliberate loss of canonical authority after HTTP prevents
                // attribution to this slot, while still emitting no success event.
                assert!(matches!(result, BrokerResult::Skipped));
            } else {
                assert!(matches!(result, BrokerResult::Failed(_)), "case {failure}");
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(
                !events
                    .iter()
                    .any(|event| event.event_kind.as_deref() == Some("oauth_refresh_succeeded")),
                "case {failure}"
            );
            if failure == "save" {
                assert!(canonical.is_dir());
            } else {
                let unchanged = credentials::load(&canonical).unwrap();
                assert_eq!(unchanged.expect_anthropic().claude_ai_oauth.expires_at, 1);
            }
        }
    }

    #[test]
    fn broker_refresh_success_event_absent_on_lock_contention() {
        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(21u16).unwrap();
        provision_uuid_for_account(dir.path(), account.get());
        save_creds_uuid(
            dir.path(),
            account.get(),
            &make_creds("synthetic-at", "synthetic-rt", 0),
        );
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let canonical = identity_store::credentials_path_for(dir.path(), uuid);
        // Held on another thread: a Windows mutex is re-entrant for its holder.
        let refresh_lock = canonical.with_extension("refresh-lock");
        let _lock = crate::accounts::profiles_lock::HeldOnOtherThread::hold(move || {
            lock::try_lock_file(&refresh_lock).unwrap().unwrap()
        });
        let (result, events) = capture_broker_events(|| {
            broker_check(dir.path(), account, |_url, _body| {
                panic!("Skipped must not refresh")
            })
        });
        assert!(matches!(result.unwrap(), BrokerResult::Skipped));
        assert!(!events
            .iter()
            .any(|event| event.event_kind.as_deref() == Some("oauth_refresh_succeeded")));
    }

    /// Successful refresh with a server `Date` header far from local time
    /// — the broker must succeed (clock-skew is a warn, not a failure)
    /// AND emit the `clock_skew_detected` log tag at WARN.
    #[test]
    fn broker_codex_check_clock_skew_emits_warn_but_succeeds() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 3600;
        let acc = install_codex_account(dir.path(), 17, exp, Some("rt_skew"));

        // Server reports it's 1970 — local clock is decades ahead, so
        // |drift| > 5min by a wide margin.
        let new_exp = now_secs_test() + 6 * 3600;
        let new_at = make_codex_jwt(new_exp);
        let body =
            format!(r#"{{"access_token":"{new_at}","refresh_token":"rt_new","expires_in":3600}}"#);
        let calls = Arc::new(AtomicU32::new(0));
        let mock_calls = Arc::clone(&calls);
        let mock = move |_u: &str, _b: &str| -> Result<crate::http::NodeHttpResponse, String> {
            mock_calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::http::NodeHttpResponse {
                status: 200,
                body: body.into_bytes(),
                date: Some("Thu, 01 Jan 1970 00:00:00 GMT".to_string()),
            })
        };

        let (result, events) = capture_broker_events(|| broker_codex_check(dir.path(), acc, mock));
        let result = result.unwrap();
        assert!(
            matches!(result, BrokerResult::Refreshed),
            "clock skew is a warning, not a failure: got {result:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let warnings: Vec<_> = events
            .iter()
            .filter(|event| event.error_kind.as_deref() == Some("clock_skew_detected"))
            .collect();
        assert_eq!(
            warnings.len(),
            1,
            "Refreshed must still emit the clock-skew event"
        );
        let warning = warnings[0];
        assert_eq!(warning.level, tracing::Level::WARN);
        assert_eq!(warning.surface.as_deref(), Some("codex"));
        assert_eq!(warning.account.as_deref(), Some(acc.to_string().as_str()));
        assert!(warning.drift_secs.unwrap() > http_codex::CLOCK_SKEW_WARN_SECS);
    }

    #[test]
    fn broker_codex_check_missing_or_invalid_date_emits_no_clock_skew_warn() {
        for date in [None, Some("not-an-http-date")] {
            let dir = TempDir::new().unwrap();
            let acc = install_codex_account(
                dir.path(),
                17,
                now_secs_test() + 3600,
                Some("synthetic-test-rt"),
            );
            let new_at = make_codex_jwt(now_secs_test() + 6 * 3600);
            let body = format!(
                r#"{{"access_token":"{new_at}","refresh_token":"synthetic-new-rt","expires_in":3600}}"#
            );
            let calls = AtomicU32::new(0);
            let (result, events) = capture_broker_events(|| {
                broker_codex_check(dir.path(), acc, |_url, _body| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(crate::http::NodeHttpResponse {
                        status: 200,
                        body: body.into_bytes(),
                        date: date.map(str::to_owned),
                    })
                })
            });
            assert!(matches!(result.unwrap(), BrokerResult::Refreshed));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!events
                .iter()
                .any(|event| { event.error_kind.as_deref() == Some("clock_skew_detected") }));
        }
    }

    // ── R2-MED-1: codex_is_expired_within boundary conditions ────────────────

    /// Builds a minimal `CodexCredentialFile` whose `access_token` JWT exp
    /// claim is `exp_secs`. Used by the boundary tests below.
    fn minimal_codex_cred_with_exp(exp_secs: u64) -> crate::credentials::CodexCredentialFile {
        crate::credentials::CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: None,
                access_token: make_codex_jwt(exp_secs),
                refresh_token: Some("rt_boundary_test".into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        }
    }

    /// Mutation guard: `exp == now + REFRESH_WINDOW_SECS` satisfies the
    /// predicate `exp <= now + buffer_secs` and MUST trigger a refresh.
    ///
    /// A mutation that flips `<=` to `<` would make this return false,
    /// missing the boundary case and failing this test.
    #[test]
    fn codex_is_expired_within_at_exact_boundary_triggers_refresh() {
        let now_s = now_secs_test();
        let exp = now_s + REFRESH_WINDOW_SECS;
        let cred = minimal_codex_cred_with_exp(exp);
        assert!(
            codex_is_expired_within(&cred, REFRESH_WINDOW_SECS, now_s),
            "exp == now + REFRESH_WINDOW_SECS must trigger refresh (boundary condition); \
             exp={exp}, now={now_s}, buffer={REFRESH_WINDOW_SECS}"
        );
    }

    /// Mutation guard: `exp == now + REFRESH_WINDOW_SECS + 1` is strictly
    /// outside the window and MUST NOT trigger a refresh.
    ///
    /// A mutation that flips `<=` to `>=` (or similar) would make this
    /// return true, spuriously triggering a refresh and failing this test.
    #[test]
    fn codex_is_expired_within_one_second_beyond_boundary_does_not_trigger_refresh() {
        let now_s = now_secs_test();
        let exp = now_s + REFRESH_WINDOW_SECS + 1;
        let cred = minimal_codex_cred_with_exp(exp);
        assert!(
            !codex_is_expired_within(&cred, REFRESH_WINDOW_SECS, now_s),
            "exp == now + REFRESH_WINDOW_SECS + 1 must NOT trigger refresh (one second outside \
             boundary); exp={exp}, now={now_s}, buffer={REFRESH_WINDOW_SECS}"
        );
    }
    #[test]
    fn broker_check_busy_profiles_lock_reports_busy_not_custody_unavailable() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        provision_uuid_for_account(dir.path(), 1);
        save_creds_uuid(dir.path(), 1, &make_creds("busy-at", "busy-rt", 0));
        // Another thread: a Windows mutex is re-entrant for its holding thread.
        let _held = crate::accounts::profiles_lock::HeldOnOtherThread::profiles(dir.path());
        let calls = AtomicU32::new(0);
        let (result, events) = capture_broker_events(|| {
            broker_check(dir.path(), account, |url, body| {
                calls.fetch_add(1, Ordering::SeqCst);
                mock_refresh_success(url, body)
            })
        });
        assert!(matches!(result.unwrap(), BrokerResult::Skipped));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let kinds: Vec<_> = events
            .iter()
            .filter_map(|e| e.error_kind.as_deref())
            .collect();
        assert!(
            kinds.contains(&"refresh_identity_authority_busy"),
            "{kinds:?}"
        );
        assert!(
            !kinds.contains(&"refresh_identity_authority_refused"),
            "{kinds:?}"
        );
    }

    /// sec LOW-1 lead (R1 fix wave): an unreadable state under the canonical
    /// lock decides nothing about a pair the provider already rotated, so the
    /// writer RETAINS its rescue record (the old contract discarded it here).
    #[test]
    fn broker_check_post_http_save_fault_keeps_rotated_pair_rescued() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        provision_uuid_for_account(dir.path(), 1);
        save_creds_uuid(dir.path(), 1, &make_creds("fault-at", "fault-rt", 0));
        let identity = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let metadata = identity_store::identity_path(dir.path(), identity).join("identity.json");
        let (result, events) = capture_broker_events(|| {
            broker_check(dir.path(), account, |url, body| {
                // An external fault lands after the provider rotated the pair:
                // the identity metadata becomes unreadable, so the save refuses.
                std::fs::write(&metadata, b"{").unwrap();
                mock_refresh_success(url, body)
            })
        });
        assert!(
            !matches!(result, Ok(BrokerResult::Refreshed)),
            "a deferred pair is not a refresh: {result:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| e.error_kind.as_deref() == Some("refresh_rotated_pair_rescued")),
            "{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| e.error_kind.as_deref() == Some("refresh_rotated_pair_discarded")),
            "{events:?}"
        );
        assert!(
            crate::credentials::rescue::rescue_record_pending(metadata.parent().unwrap()).is_some(),
            "the rotated pair's only copy must be retained"
        );
    }

    #[test]
    fn saved_pair_custody_separates_concurrent_write_busy_and_custody_change() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        provision_uuid_for_account(dir.path(), 1);
        let creds = make_creds("saved-at", "saved-rt", 4102444800000);
        save_creds_uuid(dir.path(), 1, &creds);
        let binding = ai::capture_anthropic_binding(dir.path(), account).unwrap();
        let saved = binding.credential_version();
        sentinel::set_broker_failed(dir.path(), account, "tag").unwrap();
        // Another writer moved the canonical content, custody unchanged.
        save_creds_uuid(
            dir.path(),
            1,
            &make_creds("fresher-at", "fresher-rt", 4102444800000),
        );
        assert_eq!(
            classify_saved_pair_custody(dir.path(), account, &binding, saved),
            SavedPairCustody::ConcurrentWrite
        );
        assert!(
            sentinel::is_broker_failed(dir.path(), account),
            "a concurrent write must not clear the sentinel"
        );
        // Exactly current: the pair this call saved is what is there.
        let current = ai::capture_anthropic_binding(dir.path(), account).unwrap();
        assert_eq!(
            classify_saved_pair_custody(
                dir.path(),
                account,
                &current,
                current.credential_version()
            ),
            SavedPairCustody::Current
        );
        assert!(!sentinel::is_broker_failed(dir.path(), account));
    }

    #[test]
    fn broker_org_identity_regression_success_and_failure_sentinels_hold_original_custody() {
        for success in [false, true] {
            for rebind in [false, true] {
                let dir = TempDir::new().unwrap();
                let account = AccountNum::try_from(1u16).unwrap();
                provision_uuid_for_account(dir.path(), 1);
                provision_uuid_for_account(dir.path(), 2);
                save_creds_uuid(
                    dir.path(),
                    1,
                    &make_creds("fake-source-access", "fake-source-refresh", 0),
                );
                save_creds_uuid(
                    dir.path(),
                    2,
                    &make_creds("fake-sibling-access", "fake-sibling-refresh", 0),
                );
                sentinel::set_broker_failed(dir.path(), account, "old_failure").unwrap();
                let held = Arc::new(std::sync::atomic::AtomicBool::new(false));
                if !rebind {
                    let base = dir.path().to_path_buf();
                    let observed = Arc::clone(&held);
                    BROKER_SENTINEL_TEST_HOOK.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            // Probe from another thread: the broker holds the
                            // lock on THIS thread, and a Windows mutex is
                            // re-entrant for its holder.
                            assert!(
                                crate::accounts::profiles_lock::on_other_thread(|| {
                                    crate::accounts::profiles_lock::ProfilesFileLock::try_acquire(
                                        &base,
                                    )
                                    .unwrap()
                                    .is_none()
                                }),
                                "profile authority must span the actual sentinel mutation"
                            );
                            observed.store(true, Ordering::SeqCst);
                        }));
                    });
                }
                let calls = AtomicU32::new(0);
                let result = broker_check(dir.path(), account, |url, body| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if rebind {
                        let _lock =
                            crate::accounts::profiles_lock::ProfilesFileLock::acquire(dir.path())
                                .unwrap();
                        let path = profiles::profiles_path(dir.path());
                        let mut pf = profiles::load(&path).unwrap();
                        pf.by_slot.insert(
                            "1".into(),
                            crate::testing::identity_fixtures::fixture_uuid_for_slot(2),
                        );
                        *pf.slot_binding_generations.entry("1".into()).or_default() += 1;
                        profiles::save(&path, &pf).unwrap();
                        sentinel::set_broker_failed(dir.path(), account, "new_identity_failure")
                            .unwrap();
                    }
                    if success {
                        mock_refresh_success(url, body)
                    } else {
                        mock_refresh_failure(url, body)
                    }
                })
                .unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                if rebind {
                    assert!(matches!(result, BrokerResult::Skipped));
                    assert_eq!(
                        sentinel::read_broker_failed_reason(dir.path(), account).as_deref(),
                        Some("new_identity_failure")
                    );
                } else {
                    assert!(held.load(Ordering::SeqCst));
                    if success {
                        assert!(matches!(result, BrokerResult::Refreshed));
                        assert!(!sentinel::is_broker_failed(dir.path(), account));
                    } else {
                        assert!(matches!(result, BrokerResult::Failed(_)));
                        assert!(sentinel::is_broker_failed(dir.path(), account));
                    }
                }
            }
        }
    }

    #[test]
    fn broker_org_identity_regression_healthy_old_snapshot_cannot_clear_rebound_slot_sentinel() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        provision_uuid_for_account(dir.path(), 1);
        provision_uuid_for_account(dir.path(), 2);
        let healthy = make_creds(
            "fake-old-healthy-access",
            "fake-old-healthy-refresh",
            4102444800000,
        );
        save_creds_uuid(dir.path(), 1, &healthy);
        save_creds_uuid(
            dir.path(),
            2,
            &make_creds("fake-new-access", "fake-new-refresh", 0),
        );
        let captured = ai::capture_anthropic_binding(dir.path(), account).unwrap();
        let source_path = identity_store::credentials_path_for(dir.path(), captured.identity());
        sentinel::set_broker_failed(dir.path(), account, "refresh_identity_org_unknown").unwrap();
        // The current Known binding may clear a genuinely healthy observation.
        clear_broker_failed_for_current(dir.path(), account, &captured, &source_path, &healthy);
        assert!(!sentinel::is_broker_failed(dir.path(), account));
        {
            let _lock =
                crate::accounts::profiles_lock::ProfilesFileLock::acquire(dir.path()).unwrap();
            let path = profiles::profiles_path(dir.path());
            let mut pf = profiles::load(&path).unwrap();
            pf.by_slot.insert(
                "1".into(),
                crate::testing::identity_fixtures::fixture_uuid_for_slot(2),
            );
            *pf.slot_binding_generations.entry("1".into()).or_default() += 1;
            profiles::save(&path, &pf).unwrap();
            sentinel::set_broker_failed(dir.path(), account, "new_identity_failure").unwrap();
        }
        clear_broker_failed_for_current(dir.path(), account, &captured, &source_path, &healthy);
        assert_eq!(
            sentinel::read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("new_identity_failure")
        );
        let calls = AtomicU32::new(0);
        let result = broker_check(
            dir.path(),
            AccountNum::try_from(2u16).unwrap(),
            |url, body| {
                calls.fetch_add(1, Ordering::SeqCst);
                mock_refresh_success(url, body)
            },
        )
        .unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn broker_org_identity_regression_legacy_refresh_preserves_own_uuid_without_org_upgrade() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        provision_uuid_for_account(dir.path(), account.get());
        let identity = crate::testing::identity_fixtures::fixture_uuid_for_slot(account.get());
        let canonical = identity_store::credentials_path_for(dir.path(), identity);
        std::fs::create_dir_all(canonical.parent().unwrap()).unwrap();
        crate::platform::fs::secure_dir(&dir.path().join("identities")).unwrap();
        crate::platform::fs::secure_dir(canonical.parent().unwrap()).unwrap();
        let source = make_creds("legacy-secret-access", "legacy-secret-refresh", 1);
        credentials::save(&canonical, &source).unwrap();
        let metadata = canonical.parent().unwrap().join("identity.json");
        std::fs::write(&metadata, br#"{"email":"legacy@example.test","provider":"anthropic","created_at":"2026-01-01T00:00:00Z","key_id":null}"#).unwrap();
        crate::platform::fs::secure_file(&metadata).unwrap();
        assert!(matches!(
            ai::capture_anthropic_binding(dir.path(), account)
                .unwrap()
                .context(),
            ai::StoredAnthropicContext::LegacyUnknown
        ));
        let metadata_before = std::fs::read(&metadata).unwrap();
        let profiles_before = std::fs::read(profiles::profiles_path(dir.path())).unwrap();
        sentinel::set_broker_failed(dir.path(), account, "previous_failure").unwrap();
        let calls = AtomicU32::new(0);
        let (result, events) = capture_broker_events(|| {
            broker_check(dir.path(), account, |url, body| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert!(body.contains("legacy-secret-refresh"));
                mock_refresh_success(url, body)
            })
        });
        let result = result.unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let saved = credentials::load(&canonical).unwrap();
        assert_eq!(
            saved
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed"
        );
        assert_eq!(
            saved
                .expect_anthropic()
                .claude_ai_oauth
                .refresh_token
                .expose_secret(),
            "rt-refreshed"
        );
        assert_eq!(std::fs::read(&metadata).unwrap(), metadata_before);
        assert_eq!(
            std::fs::read(profiles::profiles_path(dir.path())).unwrap(),
            profiles_before
        );
        assert_eq!(
            sentinel::read_broker_failed_reason(dir.path(), account),
            None
        );
        assert!(events
            .iter()
            .any(|event| { event.event_kind.as_deref() == Some("oauth_refresh_succeeded") }));
        let logs = format!("{events:?}");
        for secret in ["legacy-secret-access", "legacy-secret-refresh"] {
            assert!(!logs.contains(secret));
        }
        assert!(!identity_store::identity_path(dir.path(), identity)
            .join("token-owner-verified-v2")
            .exists());
    }

    #[test]
    fn broker_org_identity_regression_legacy_upgrade_during_rotation_retains_returned_pair() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        provision_uuid_for_account(dir.path(), 1);
        let identity = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let canonical = identity_store::credentials_path_for(dir.path(), identity);
        std::fs::create_dir_all(canonical.parent().unwrap()).unwrap();
        crate::platform::fs::secure_dir(&dir.path().join("identities")).unwrap();
        crate::platform::fs::secure_dir(canonical.parent().unwrap()).unwrap();
        let source = make_creds("legacy-upgrade-at", "legacy-upgrade-rt", 1);
        credentials::save(&canonical, &source).unwrap();
        let metadata = canonical.parent().unwrap().join("identity.json");
        crate::platform::fs::write_new_private(&metadata,
            br#"{"email":"legacy@example.test","provider":"anthropic","created_at":"2026-01-01T00:00:00Z","key_id":null}"#).unwrap();
        let http_profile: crate::daemon::usage_poller::HttpGetFn = Arc::new(|url, token, _| {
            assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
            assert_eq!(token, "legacy-upgrade-at");
            Ok((200, br#"{"account":{"uuid":"11111111-1111-4111-8111-111111111111","email":"legacy@example.test"},"organization":{"uuid":"22222222-2222-4222-8222-222222222222"}}"#.to_vec()))
        });
        let calls = AtomicU32::new(0);
        let result = broker_check(dir.path(), account, |url, body| {
            assert!(body.contains("legacy-upgrade-rt"));
            assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 0);
            // The real authenticated upgrade occurs after refresh preflight,
            // while the provider is consuming the original rotating grant.
            let proof =
                ai::verify_anthropic_context_with(source.anthropic().unwrap(), &http_profile)
                    .unwrap();
            ai::upgrade_verified_legacy_identity(dir.path(), identity, &proof).unwrap();
            mock_refresh_success(url, body)
        })
        .unwrap();
        assert!(
            matches!(result, BrokerResult::Skipped),
            "the old Legacy capture cannot attribute a Known slot success"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let saved = credentials::load(&canonical).unwrap();
        assert_eq!(
            saved
                .expect_anthropic()
                .claude_ai_oauth
                .refresh_token
                .expose_secret(),
            "rt-refreshed"
        );
        assert_eq!(
            saved
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed"
        );
        assert_eq!(
            profiles::resolve_slot_to_uuid(dir.path(), 1),
            Some(identity)
        );
        assert!(matches!(
            ai::read_stored_anthropic_context(dir.path(), identity).unwrap(),
            ai::StoredAnthropicContext::Known(_)
        ));
        assert!(!identity_store::identity_path(dir.path(), identity)
            .join("token-owner-verified-v2")
            .exists());
    }

    #[test]
    fn broker_org_identity_regression_rotating_refresh_rebind_preserves_original_uuid_without_upgrade(
    ) {
        let dir = TempDir::new().unwrap();
        provision_uuid_for_account(dir.path(), 1);
        provision_uuid_for_account(dir.path(), 2);
        let source = make_creds("fake-old-access", "fake-old-refresh", 0);
        let sibling = make_creds("fake-sibling-access", "fake-sibling-refresh", 0);
        save_creds_uuid(dir.path(), 1, &source);
        save_creds_uuid(dir.path(), 2, &sibling);
        let id1 = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let id2 = crate::testing::identity_fixtures::fixture_uuid_for_slot(2);
        let path1 = identity_store::credentials_path_for(dir.path(), id1);
        let path2 = identity_store::credentials_path_for(dir.path(), id2);
        let before1 = std::fs::read(&path1).unwrap();
        let before2 = std::fs::read(&path2).unwrap();
        let old_rt_live = std::sync::atomic::AtomicBool::new(true);
        let result = broker_check(
            dir.path(),
            AccountNum::try_from(1u16).unwrap(),
            |url, body| {
                assert!(body.contains("fake-old-refresh"));
                assert!(
                    old_rt_live.swap(false, Ordering::SeqCst),
                    "the fake provider accepts the original RT only once"
                );
                let lock =
                    crate::accounts::profiles_lock::ProfilesFileLock::acquire(dir.path()).unwrap();
                let path = crate::accounts::profiles::profiles_path(dir.path());
                let mut profiles = crate::accounts::profiles::load(&path).unwrap();
                profiles.by_slot.insert("1".into(), id2);
                crate::accounts::profiles::save(&path, &profiles).unwrap();
                drop(lock);
                mock_refresh_success(url, body)
            },
        )
        .unwrap();
        assert!(matches!(result, BrokerResult::Skipped));
        assert!(
            !old_rt_live.load(Ordering::SeqCst),
            "the fake provider rotated away the original RT"
        );
        let saved = credentials::load(&path1).unwrap();
        assert_eq!(
            saved
                .expect_anthropic()
                .claude_ai_oauth
                .refresh_token
                .expose_secret(),
            "rt-refreshed"
        );
        assert_eq!(
            saved
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed"
        );
        assert_ne!(std::fs::read(path1).unwrap(), before1);
        assert_eq!(std::fs::read(path2).unwrap(), before2);
        assert!(!identity_store::identity_path(dir.path(), id1)
            .join("token-owner-verified-v2")
            .exists());
    }
    #[cfg(unix)]
    #[test]
    fn broker_org_identity_regression_permissive_identity_directory_repaired_before_rotation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        provision_uuid_for_account(dir.path(), 1);
        save_creds_uuid(
            dir.path(),
            1,
            &make_creds("fake-old-access", "fake-old-refresh", 0),
        );
        let identities = dir.path().join("identities");
        std::fs::set_permissions(&identities, std::fs::Permissions::from_mode(0o755)).unwrap();
        let called = std::cell::Cell::new(false);
        let outcome = broker_check(
            dir.path(),
            AccountNum::try_from(1u16).unwrap(),
            |url, body| {
                assert_eq!(
                    std::fs::metadata(&identities).unwrap().permissions().mode() & 0o077,
                    0
                );
                assert!(body.contains("fake-old-refresh"));
                called.set(true);
                mock_refresh_success(url, body)
            },
        )
        .unwrap();
        assert!(called.get());
        assert!(matches!(outcome, BrokerResult::Refreshed));
        let id = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        assert_eq!(
            credentials::load(&identity_store::credentials_path_for(dir.path(), id))
                .unwrap()
                .expect_anthropic()
                .claude_ai_oauth
                .refresh_token
                .expose_secret(),
            "rt-refreshed"
        );
    }
}
