//! Bounded retry policy outside message-store authority; no new key or identity.
use crate::sdk::SdkErrorCode;
use crate::sessions::directives::DirectiveError;
use std::time::{Duration, Instant};

const DELAYS: [Duration; 3] = [
    Duration::from_millis(150),
    Duration::from_millis(300),
    Duration::from_millis(600),
];
const WAIT_BUDGET: Duration = Duration::from_millis(1_100);

/// Retry only protected UND outcomes with the originally admitted key.
/// Recovery must be readonly and fail closed on missing/corrupt authority.
pub fn run<T>(
    protected: bool,
    key: &str,
    recover: impl FnMut(&str) -> Result<Option<T>, DirectiveError>,
    attempt: impl FnMut(&str) -> Result<T, DirectiveError>,
) -> Result<T, DirectiveError> {
    run_with_wait(protected, key, recover, attempt, std::thread::sleep)
}

/// Retain admitted UTC continuity across the existing bounded retry policy.
/// Recovery remains independent so a verified positive receipt can end ambiguity
/// after publication even when further admitted clock reads are forbidden.
/// Attempts must use `capture` for their existing successful preflight reads
/// before constructing admitted contexts; captures raise the floor without
/// latching lower raw reads. The original epoch and elapsed deadline stay local.
pub fn run_with_admission_clock<T>(
    protected: bool,
    key: &str,
    wall: &dyn Fn() -> Result<u64, DirectiveError>,
    recover: impl FnMut(&str) -> Result<Option<T>, DirectiveError>,
    mut attempt: impl FnMut(
        &str,
        &dyn Fn() -> Result<u64, DirectiveError>,
        &dyn Fn() -> Result<u64, DirectiveError>,
    ) -> Result<T, DirectiveError>,
) -> Result<T, DirectiveError> {
    let provider = super::request::AdmissionProvider::new(wall);
    let admitted = || provider.observe();
    let capture = || provider.capture();
    run(protected, key, recover, |key| {
        attempt(key, &admitted, &capture)
    })
}

fn counted(mut error: DirectiveError, attempts: u8) -> DirectiveError {
    if error.code == SdkErrorCode::Undetermined {
        error.attempts = Some(attempts);
    }
    error
}

fn run_with_wait<T>(
    protected: bool,
    key: &str,
    mut recover: impl FnMut(&str) -> Result<Option<T>, DirectiveError>,
    mut attempt: impl FnMut(&str) -> Result<T, DirectiveError>,
    mut wait: impl FnMut(Duration),
) -> Result<T, DirectiveError> {
    if !protected {
        return attempt(key);
    }
    let mut attempts = 1;
    let mut result = attempt(key);
    let mut remaining = WAIT_BUDGET;
    for delay in DELAYS {
        let error = match result {
            Ok(value) => return Ok(value),
            Err(error) if error.code != SdkErrorCode::Undetermined => return Err(error),
            Err(error) => error,
        };
        match recover(key) {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(error) => return Err(counted(error, attempts)),
        }
        let start = Instant::now();
        let Some(deadline) = start.checked_add(remaining) else {
            return Err(counted(error, attempts));
        };
        if delay > remaining {
            return Err(counted(error, attempts));
        }
        wait(delay);
        let finished = Instant::now();
        // Charge scheduled time even when a test waiter returns immediately.
        remaining = remaining.saturating_sub(delay.max(finished.duration_since(start)));
        // Sleep scheduling may overrun; never admit a further attempt afterward.
        if finished >= deadline {
            return Err(counted(error, attempts));
        }
        attempts += 1;
        result = attempt(key);
    }
    result.map_err(|error| counted(error, attempts))
}

#[cfg(all(test, unix))]
#[path = "request_retry_tests.rs"]
mod tests;
