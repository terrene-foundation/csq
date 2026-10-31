//! Synchronous, custody-bound API-pool execution with durable worst-case admission.
use super::execution_ledger::{BudgetError, BudgetLedger, Reservation, ReserveResult};
use super::execution_pricing::{prepare, Pricing};
use super::execution_transport::{HttpPoolTransport, PoolTransport, TransportError};
use super::{ExecutionAdmission, KeySource, Pool, PoolError, PoolName};
use crate::providers::model_manifest::ModelManifest;
use chrono::{DateTime, Utc};
use csq_sdk::{Completion, SdkError, SdkErrorCode};
use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

/// Literal single-completion request. Pool execution never resolves an account slot.
#[derive(Clone, Debug)]
pub struct PoolExecRequest {
    pub provider: String,
    pub model: String,
    pub prompt: String,
    pub system: Option<String>,
    pub max_tokens: u64,
    pub max_input_bytes: usize,
    pub timeout_secs: u64,
}

type Result<T> = std::result::Result<T, SdkError>;

static SYSTEM_MONOTONIC: fn() -> Instant = Instant::now;
static SYSTEM_UTC: fn() -> DateTime<Utc> = Utc::now;

/// The one clock behind every deadline and UTC decision of a pool execution:
/// admission and request deadlines, custody acquisition and re-checks, the
/// reservation and settlement timestamps, quota cooldowns, the accounting
/// window of resolve and rebaseline, and the candidate-unavailable timeout
/// classification. Production uses [`PoolClock::system`]; the monotonic reading
/// and the UTC reading are the only two clock sources on this path, so a test
/// that drives one injected clock drives all of them.
///
/// Real time still passes in places that wait on the outside world, and those
/// waits are bounded by values this clock decided, not by this clock: the HTTP
/// transport (`recv_timeout` over a worker and real sockets), the custody lock
/// retry sleeps (sized from this clock's remaining budget, slept for real) and
/// SQLite's fixed 5 second `busy_timeout`, which is set once on the connection
/// and derived from no deadline. One more fixed 5 second real-time limit sits
/// wholly outside this clock: the Windows boot-stamp query (`store.rs`, a bounded
/// PowerShell child) polls a private real `Instant::now()` deadline. The
/// enforced deadlines are unchanged.
pub(crate) struct PoolClock<'a> {
    monotonic: &'a dyn Fn() -> Instant,
    utc: &'a dyn Fn() -> DateTime<Utc>,
}
impl<'a> PoolClock<'a> {
    #[cfg(test)]
    pub(crate) fn new(
        monotonic: &'a dyn Fn() -> Instant,
        utc: &'a dyn Fn() -> DateTime<Utc>,
    ) -> Self {
        Self { monotonic, utc }
    }
    /// The real monotonic and UTC clocks; the only production constructor.
    pub(crate) fn system() -> PoolClock<'static> {
        PoolClock {
            monotonic: &SYSTEM_MONOTONIC,
            utc: &SYSTEM_UTC,
        }
    }
    fn utc(&self) -> DateTime<Utc> {
        (self.utc)()
    }
    pub(crate) fn now(&self) -> Instant {
        (self.monotonic)()
    }
    fn monotonic(&self) -> &'a dyn Fn() -> Instant {
        self.monotonic
    }
}

#[derive(Default)]
struct Ineligible {
    held: bool,
    capped: bool,
    unresolved: bool,
    no_cap: bool,
    below_hold: bool,
    attempted: usize,
    unreadable: usize,
}

/// Executes against stored, admitted pool keys only; no subscription or environment fallback.
pub fn execute(base: &Path, request: PoolExecRequest) -> Result<Completion> {
    execute_with_transport(base, request, &HttpPoolTransport)
}

/// Continues a caller's existing monotonic deadline, including time spent reading input.
/// The request's own timeout remains an upper bound even if the caller permits longer.
pub fn execute_with_deadline(
    base: &Path,
    request: PoolExecRequest,
    deadline: Instant,
) -> Result<Completion> {
    execute_inner(
        base,
        request,
        &HttpPoolTransport,
        &PoolClock::system(),
        Some(deadline),
    )
}

/// Conservatively settles the current key's unresolved holds at their full bounds.
/// Custody binds the current name to its private fingerprint; no key identity is exposed.
pub fn resolve(base: &Path, name: &PoolName) -> Result<()> {
    resolve_with_clock(base, name, &PoolClock::system())
}

fn resolve_with_clock(base: &Path, name: &PoolName, clock: &PoolClock<'_>) -> Result<()> {
    let pool = Pool::new(base);
    let resolved = pool.with_resolution_identity_with_clock(
        name,
        accounting_deadline(clock),
        clock,
        |fingerprint, generation, anchor, salt_id| {
            BudgetLedger::with_bound(base, anchor, salt_id, |ledger| {
                ledger.resolve(fingerprint, generation, clock.utc().timestamp())
            })
        },
    );
    match resolved {
        Err(PoolError::KeyMissing) => Err(fixed(SdkErrorCode::NotFound, "pool_key_not_found")),
        Err(error) => Err(custody_error(error)),
        Ok(result) => result.map(|_| ()).map_err(budget_error),
    }
}

/// Explicitly rebaselines admission time without changing reservations or spend.
pub fn rebaseline_clock(base: &Path) -> Result<()> {
    rebaseline_clock_with_clock(base, &PoolClock::system())
}

fn rebaseline_clock_with_clock(base: &Path, clock: &PoolClock<'_>) -> Result<()> {
    with_ledger(&Pool::new(base), base, clock, |ledger| {
        ledger.rebaseline_clock(clock.utc().timestamp())
    })?;
    tracing::info!(event_kind = "pool_clock_rebaselined");
    Ok(())
}

pub(crate) fn execute_with_transport(
    base: &Path,
    request: PoolExecRequest,
    transport: &dyn PoolTransport,
) -> Result<Completion> {
    execute_inner(base, request, transport, &PoolClock::system(), None)
}

/// Test entry: one injected monotonic clock drives the deadlines AND the UTC
/// reading, which is that clock's elapsed time added to the caller's UTC anchor.
/// The anchor is explicit so no test verdict reads the real wall clock.
#[cfg(test)]
fn execute_with_clock(
    anchor_utc: DateTime<Utc>,
    base: &Path,
    request: PoolExecRequest,
    transport: &dyn PoolTransport,
    now: &dyn Fn() -> Instant,
) -> Result<Completion> {
    execute_with_clock_and_deadline(anchor_utc, base, request, transport, now, None)
}

#[cfg(test)]
fn execute_with_clock_and_deadline(
    anchor_utc: DateTime<Utc>,
    base: &Path,
    request: PoolExecRequest,
    transport: &dyn PoolTransport,
    now: &dyn Fn() -> Instant,
    caller_deadline: Option<Instant>,
) -> Result<Completion> {
    let anchor = now();
    let utc = move || {
        let elapsed = now().saturating_duration_since(anchor);
        anchor_utc
            + chrono::Duration::from_std(elapsed).unwrap_or_else(|_| chrono::Duration::zero())
    };
    execute_inner(
        base,
        request,
        transport,
        &PoolClock::new(now, &utc),
        caller_deadline,
    )
}

fn execute_inner(
    base: &Path,
    request: PoolExecRequest,
    transport: &dyn PoolTransport,
    clock: &PoolClock<'_>,
    caller_deadline: Option<Instant>,
) -> Result<Completion> {
    let now = clock.monotonic();
    let started = now();
    validate(&request)?;
    let local_deadline = started
        .checked_add(Duration::from_secs(request.timeout_secs))
        .ok_or_else(invalid)?;
    let deadline = caller_deadline.map_or(local_deadline, |caller| caller.min(local_deadline));
    remaining(deadline, now())?;
    // One validated snapshot owns both the hard hold and every later settlement.
    let manifest = ModelManifest::load(base).map_err(|_| unsupported())?;
    if manifest
        .models
        .iter()
        .find(|model| model.id == request.model)
        .is_some_and(|model| {
            model
                .context_window
                .is_some_and(|bound| request.max_tokens > bound)
                || model
                    .output_limit
                    .is_some_and(|bound| request.max_tokens > bound)
        })
    {
        return Err(invalid());
    }
    // Map the single absolute monotonic deadline onto one UTC pricing interval.
    // Preparation proves continuous coverage before touching pool custody.
    let observed = now();
    let admission_utc = clock.utc();
    let interval =
        chrono::Duration::from_std(remaining(deadline, observed)?).map_err(|_| unsupported())?;
    let deadline_utc = admission_utc
        .checked_add_signed(interval)
        .ok_or_else(unsupported)?;
    // The durable ledger has second precision. Round outward so a live attempt
    // never becomes stale merely because its deadline's subsecond part was lost.
    let reservation_deadline = deadline_utc
        .timestamp()
        .checked_add(i64::from(deadline_utc.timestamp_subsec_nanos() != 0))
        .ok_or_else(unsupported)?;
    let pricing: Pricing =
        prepare(&manifest, &request, admission_utc, deadline_utc).ok_or_else(unsupported)?;
    let pool = Pool::new(base);
    let mut candidates = pool
        .execution_candidates_bound_with_clock(&request.provider, deadline, clock)
        .map_err(custody_error)?;
    remaining(deadline, now())?;
    if candidates.len() > 1024 {
        return Err(unavailable());
    }
    candidates.sort_by(|left, right| left.entry.name.as_str().cmp(right.entry.name.as_str()));
    if candidates.is_empty() {
        return Err(exhausted(&Ineligible::default()));
    }
    let mut attempted = HashSet::new();
    let mut refreshed = HashSet::new();
    let mut candidates = VecDeque::from(candidates);
    let mut ineligible = Ineligible::default();
    while let Some(candidate) = candidates.pop_front() {
        remaining(deadline, now())?;
        if !attempted.insert(candidate.generation.clone()) {
            continue;
        }
        ineligible.attempted += 1;
        trace_candidate_admission("candidate_attempt", "none");
        // Custody is the outer lock. The fresh key and public metadata/generation are
        // bound before the ledger transaction; no custody guard reaches the transport.
        let admission = pool.with_execution_key_bound_with_clock(
            &candidate,
            deadline,
            clock,
            |secret, anchor, salt_id| -> Result<_> {
                remaining(deadline, now())?;
                let reservation = BudgetLedger::with_bound(base, anchor, salt_id, |ledger| {
                    #[cfg(test)]
                    tests::before_reservation_probe(reservation_deadline);
                    ledger.reserve(
                        &candidate,
                        pricing.hold_nanos,
                        clock.utc().timestamp(),
                        reservation_deadline,
                    )
                });
                Ok((secret, reservation))
            },
        );
        let ExecutionAdmission {
            value,
            can_dispatch,
        } = match admission {
            Err(PoolError::MutationRefused) => {
                trace_candidate_admission("candidate_unreadable", "pool_mutation_refused");
                ineligible.unreadable += 1;
                if candidate.entry.source == KeySource::EnvFile
                    && refreshed.insert(candidate.entry.name.as_str().to_owned())
                {
                    remaining(deadline, now())?;
                    let fresh = pool
                        .execution_candidates_bound_with_clock(&request.provider, deadline, clock)
                        .map_err(custody_error)?
                        .into_iter()
                        .find(|fresh| fresh.entry.name == candidate.entry.name);
                    if let Some(fresh) = fresh {
                        // Retry only a newly minted rotation of this same public
                        // row, never a replacement key or a metadata edit.
                        if fresh.entry == candidate.entry
                            && fresh.generation != candidate.generation
                            && fresh.fingerprint() != candidate.fingerprint()
                        {
                            candidates.push_front(fresh);
                        }
                    }
                }
                continue;
            }
            Err(
                error @ (PoolError::KeyMissing
                | PoolError::ItemReadUnavailable
                | PoolError::EnvFileInvalid
                | PoolError::EnvFileUnavailable),
            ) => {
                let kind = match error {
                    PoolError::KeyMissing => "pool_key_missing",
                    PoolError::ItemReadUnavailable => "pool_item_read_unavailable",
                    PoolError::EnvFileInvalid => "pool_env_file_invalid",
                    _ => "pool_env_file_unavailable",
                };
                trace_candidate_admission("candidate_unreadable", kind);
                ineligible.unreadable += 1;
                continue;
            }
            Err(error) => return Err(custody_error(error)),
            Ok(result) => result,
        };
        let (secret, reservation) = value?;
        let reservation = match reservation {
            Ok(reservation) => reservation,
            Err(BudgetError::CandidateUnavailable) => {
                trace_candidate_admission("ledger_error", "pool_candidate_unavailable");
                // The ledger validates the rounded UTC deadline against the
                // execution clock's UTC reading. An admission that outlives its
                // budget on that one clock is a request timeout, not evidence
                // that the selected candidate is unreadable.
                if now() >= deadline || clock.utc().timestamp() >= reservation_deadline {
                    trace_candidate_admission("deadline_expired", "pool_deadline_exceeded");
                    return Err(fixed(SdkErrorCode::Timeout, "pool_deadline_exceeded"));
                }
                ineligible.unreadable += 1;
                continue;
            }
            Err(error) => {
                let kind = match error {
                    BudgetError::Unavailable => "pool_budget_unavailable",
                    BudgetError::Undetermined => "pool_budget_undetermined",
                    BudgetError::IdentityMismatch => "pool_ledger_identity_mismatch",
                    BudgetError::ClockRegressed => "pool_clock_regressed",
                    BudgetError::ResolveInvariantViolation => "pool_resolve_invariant_violation",
                    BudgetError::DefiniteDispositionAlreadyRecorded => {
                        "pool_definite_disposition_already_recorded"
                    }
                    BudgetError::CandidateUnavailable => "pool_candidate_unavailable",
                };
                trace_candidate_admission("ledger_error", kind);
                return Err(budget_error(error));
            }
        };
        let reservation = match reservation {
            ReserveResult::Held(reservation) => reservation,
            ReserveResult::CapBlocked => {
                ineligible.capped = true;
                continue;
            }
            ReserveResult::InFlightBlocked => {
                ineligible.held = true;
                continue;
            }
            ReserveResult::Unresolved => {
                ineligible.unresolved = true;
                continue;
            }
            ReserveResult::NoCap => {
                ineligible.no_cap = true;
                continue;
            }
            ReserveResult::BelowHold => {
                ineligible.below_hold = true;
                continue;
            }
            ReserveResult::Cooling => continue,
        };
        if !can_dispatch {
            release_unsent_hold(&pool, base, &reservation, deadline, clock)?;
            return Err(fixed(
                SdkErrorCode::PoolUnavailable,
                "pool_ledger_finalization_pending",
            ));
        }
        let budget = match remaining(deadline, now()) {
            Ok(budget) => budget,
            Err(error) => {
                // This request definitely never dispatched, so cleanup releases it.
                release_unsent_hold(&pool, base, &reservation, deadline, clock)?;
                return Err(error);
            }
        };
        let outcome = transport.complete(&request, secret, budget);
        match outcome {
            Ok(completion) => {
                if now() >= deadline {
                    return Err(retain_unknown(&pool, base, &reservation, deadline, clock));
                }
                let Some(actual) = pricing.price_completion(&completion) else {
                    return Err(retain_unknown(&pool, base, &reservation, deadline, clock));
                };
                // A failed settlement cannot certify accounting even when HTTP succeeded.
                cleanup_ledger(&pool, base, deadline, clock, |ledger| {
                    ledger.settle(&reservation, actual)
                })
                .map_err(|_| uncertain())?;
                return Ok(completion);
            }
            Err(TransportError::Quota { retry_after_secs }) => {
                let cooldown = clock
                    .utc()
                    .timestamp()
                    .saturating_add(i64::try_from(retry_after_secs).unwrap_or(i64::MAX));
                cleanup_ledger(&pool, base, deadline, clock, |ledger| {
                    definite_disposition(ledger.reject_quota(&reservation, cooldown))
                })?;
                remaining(deadline, now())?;
            }
            Err(TransportError::Unknown) => {
                return Err(retain_unknown(&pool, base, &reservation, deadline, clock))
            }
            Err(error) => {
                // Only the transport's definite, nonbillable refusals enter this arm.
                cleanup_ledger(&pool, base, deadline, clock, |ledger| {
                    definite_disposition(ledger.release(&reservation))
                })?;
                return Err(match error {
                    TransportError::Authentication => {
                        fixed(SdkErrorCode::ProviderError, "pool_authentication_failed")
                    }
                    TransportError::Rejected => {
                        fixed(SdkErrorCode::ProviderError, "pool_request_rejected")
                    }
                    TransportError::Unsupported => unsupported(),
                    TransportError::LocalFailure => {
                        fixed(SdkErrorCode::Internal, "pool_local_pre_dispatch_failed")
                    }
                    // Quota and Unknown have already been handled without replay.
                    _ => uncertain(),
                });
            }
        }
    }
    remaining(deadline, now())?;
    Err(exhausted(&ineligible))
}

fn validate(request: &PoolExecRequest) -> Result<()> {
    if !matches!(request.provider.as_str(), "anthropic" | "openai") {
        return Err(fixed(
            SdkErrorCode::ProviderNotFound,
            "pool_provider_not_found",
        ));
    }
    let bytes = request
        .prompt
        .len()
        .checked_add(request.system.as_ref().map_or(0, String::len));
    if request.model.trim().is_empty()
        || request.prompt.trim().is_empty()
        || request.max_tokens == 0
        || request.max_input_bytes == 0
        || request.timeout_secs == 0
        || bytes.is_none_or(|bytes| bytes > request.max_input_bytes)
    {
        return Err(invalid());
    }
    Ok(())
}

fn trace_candidate_admission(branch: &'static str, error_kind: &'static str) {
    // Fixed vocabulary only: no candidate identity, fingerprint or request data.
    tracing::debug!(admission_branch = branch, error_kind = error_kind);
}

fn remaining(deadline: Instant, now: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| fixed(SdkErrorCode::Timeout, "pool_deadline_exceeded"))
}
fn accounting_deadline(clock: &PoolClock<'_>) -> Instant {
    let now = clock.now();
    // Accounting must finish after a timed-out HTTP attempt too. This bounded
    // cleanup window grants no further admission or transport work.
    // If the checked addition cannot be represented, fail closed at acquisition.
    now.checked_add(Duration::from_secs(5)).unwrap_or(now)
}
fn with_ledger<T>(
    pool: &Pool,
    base: &Path,
    clock: &PoolClock<'_>,
    operation: impl FnOnce(&mut BudgetLedger) -> std::result::Result<T, BudgetError>,
) -> Result<T> {
    pool.with_ledger_identity_with_clock(accounting_deadline(clock), clock, |anchor, salt_id| {
        BudgetLedger::with_bound(base, anchor, salt_id, operation)
    })
    .map_err(custody_error)?
    .map_err(budget_error)
}
fn cleanup_ledger<T>(
    pool: &Pool,
    base: &Path,
    deadline: Instant,
    clock: &PoolClock<'_>,
    operation: impl FnOnce(&mut BudgetLedger) -> std::result::Result<T, BudgetError>,
) -> Result<T> {
    let result = with_ledger(pool, base, clock, operation);
    if result.is_err() && clock.now() >= deadline {
        tracing::warn!(error_kind = "pool_settle_after_deadline_failed");
    }
    result
}
fn definite_disposition(
    result: std::result::Result<(), BudgetError>,
) -> std::result::Result<(), BudgetError> {
    match result {
        Err(BudgetError::DefiniteDispositionAlreadyRecorded) => Ok(()),
        other => other,
    }
}
fn release_unsent_hold(
    pool: &Pool,
    base: &Path,
    reservation: &Reservation,
    deadline: Instant,
    clock: &PoolClock<'_>,
) -> Result<()> {
    cleanup_ledger(pool, base, deadline, clock, |ledger| {
        definite_disposition(ledger.release(reservation))
    })
    .inspect_err(|_| {
        // The durable hold remains conservative and is charged at resolution.
        tracing::warn!(error_kind = "pool_unsent_hold_release_failed");
    })
}
fn retain_unknown(
    pool: &Pool,
    base: &Path,
    reservation: &Reservation,
    deadline: Instant,
    clock: &PoolClock<'_>,
) -> SdkError {
    // The original durable reservation remains protected even if this annotation fails.
    if cleanup_ledger(pool, base, deadline, clock, |ledger| {
        ledger.retain_unknown(reservation)
    })
    .is_err()
    {
        tracing::warn!(error_kind = "pool_retain_unknown_failed");
    }
    uncertain()
}
fn budget_error(error: BudgetError) -> SdkError {
    match error {
        BudgetError::Unavailable => unavailable(),
        BudgetError::Undetermined => unavailable(),
        BudgetError::IdentityMismatch => fixed(
            SdkErrorCode::PoolUnavailable,
            "pool_ledger_identity_mismatch",
        ),
        BudgetError::ClockRegressed => fixed(SdkErrorCode::PoolUnavailable, "pool_clock_regressed"),
        BudgetError::ResolveInvariantViolation => fixed(
            SdkErrorCode::PoolUnavailable,
            "pool_resolve_invariant_violation",
        ),
        BudgetError::CandidateUnavailable => {
            fixed(SdkErrorCode::PoolUnavailable, "pool_candidate_unavailable")
        }
        BudgetError::DefiniteDispositionAlreadyRecorded => fixed(
            SdkErrorCode::PoolUnavailable,
            "pool_definite_disposition_already_recorded",
        ),
    }
}
fn custody_error(error: PoolError) -> SdkError {
    match error {
        PoolError::ManifestUnavailable => {
            fixed(SdkErrorCode::PoolUnavailable, "no_pool_configured")
        }
        PoolError::LedgerIdentityMismatch => fixed(
            SdkErrorCode::PoolUnavailable,
            "pool_ledger_identity_mismatch",
        ),
        PoolError::Busy => fixed(SdkErrorCode::Timeout, "pool_custody_busy"),
        PoolError::LedgerMirrorUnavailable => fixed(
            SdkErrorCode::PoolUnavailable,
            "pool_ledger_mirror_unavailable",
        ),
        PoolError::UnrelatedKeyUnavailable => fixed(
            SdkErrorCode::PoolUnavailable,
            "pool_unrelated_key_unavailable",
        ),
        PoolError::ManifestWriteUnavailable => {
            fixed(SdkErrorCode::PoolUnavailable, "pool_custody_unavailable")
        }
        _ => fixed(SdkErrorCode::PoolUnavailable, "pool_custody_unavailable"),
    }
}
fn exhausted(ineligible: &Ineligible) -> SdkError {
    if ineligible.attempted != 0 && ineligible.unreadable == ineligible.attempted {
        return fixed(SdkErrorCode::PoolUnavailable, "pool_candidate_unavailable");
    }
    fixed(
        SdkErrorCode::PoolExhausted,
        if ineligible.unresolved {
            "pool_generation_outcome_unresolved"
        } else if ineligible.held {
            "pool_budget_held_for_in_flight_worst_case"
        } else if ineligible.below_hold {
            "pool_cap_below_worst_case_hold"
        } else if ineligible.no_cap {
            "pool_key_has_no_cap"
        } else if ineligible.capped {
            "pool_budget_cap_reached"
        } else {
            "pool_no_eligible_key"
        },
    )
}
fn fixed(code: SdkErrorCode, message: &'static str) -> SdkError {
    SdkError::trusted(code, message)
}
fn invalid() -> SdkError {
    fixed(SdkErrorCode::InvalidInput, "pool_invalid_request")
}
fn unsupported() -> SdkError {
    fixed(SdkErrorCode::Unsupported, "pool_model_or_price_unsupported")
}
fn unavailable() -> SdkError {
    fixed(SdkErrorCode::PoolUnavailable, "pool_ledger_unavailable")
}
fn uncertain() -> SdkError {
    fixed(SdkErrorCode::Undetermined, "pool_accounting_undetermined")
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
