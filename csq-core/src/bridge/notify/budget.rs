//! Persisted rate limit for outbound owner pings.
//!
//! Two fixed windows (10 per 60 s, 60 per 3600 s) are stored in a 0600 JSON
//! file beside the bridge config. The whole read-check-commit runs under an
//! exclusive lock, so two processes cannot both spend the same slot — the
//! threat is a runaway session loop, and a lock-free read-modify-write would
//! let two loops double the burst.
//!
//! Failure posture (`guard-reader-writer-parity.md` MUST-2): ONLY a missing
//! file is a fresh window. A corrupt, empty, oversized, non-regular, symlinked,
//! foreign-owned or unreadable file is a refusal — never a silent reset to
//! zero, which would erase the limit the file exists to enforce.

use crate::platform::fs;
use crate::platform::lock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Budget file name inside `<base_dir>`.
pub(crate) const BUDGET_FILE: &str = "owner-ping-budget.json";

/// Lock file name beside it. The lock is a separate file so the budget file
/// itself is only ever replaced atomically.
pub(crate) const BUDGET_LOCK_FILE: &str = "owner-ping-budget.lock";

/// Largest budget file we are willing to parse.
const BUDGET_MAX_BYTES: u64 = 512;

/// Schema version this build writes and accepts.
const BUDGET_VERSION: u32 = 1;

/// Minute window length, seconds.
const MINUTE_SECS: i64 = 60;

/// Hour window length, seconds.
const HOUR_SECS: i64 = 3_600;

/// Sends permitted per minute window.
const MINUTE_LIMIT: u32 = 10;

/// Sends permitted per hour window.
const HOUR_LIMIT: u32 = 60;

/// Pre-commit lock budget: 50 attempts × 10 ms = 500 ms.
///
/// A refusal is free here (nothing has been sent), so a wedged holder fails
/// closed instead of blocking the CLI.
const LOCK_ATTEMPTS: u32 = 50;
const LOCK_DELAY: Duration = Duration::from_millis(10);

/// The persisted window state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BudgetState {
    /// Schema version; an unknown value is a refusal, not a reset.
    pub version: u32,
    /// Start (unix seconds) of the current minute window.
    pub minute_start: i64,
    /// Sends counted in the current minute window.
    pub minute_count: u32,
    /// Start (unix seconds) of the current hour window.
    pub hour_start: i64,
    /// Sends counted in the current hour window.
    pub hour_count: u32,
}

/// Why a reservation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BudgetError {
    /// The lock was held past its budget.
    Locked,
    /// The state file exists but cannot be trusted.
    Unreadable,
    /// The state file could not be written.
    Unwritable,
    /// The clock is zero, negative, or earlier than a stored window start.
    ClockInvalid,
    /// A window's limit is already spent.
    RateLimited,
}

/// Reserves one send slot, or refuses.
///
/// The increment IS the spend: a caller that later refuses (audit unavailable,
/// kill switch, transport failure) does not refund it, so a broken send path
/// cannot become an unbounded retry loop.
pub(crate) fn reserve(base_dir: &Path, now: i64) -> Result<(), BudgetError> {
    if now <= 0 {
        return Err(BudgetError::ClockInvalid);
    }
    std::fs::create_dir_all(base_dir).map_err(|_| BudgetError::Unwritable)?;

    let lock_path = base_dir.join(BUDGET_LOCK_FILE);
    let _guard = lock::try_lock_file_bounded_nofollow(&lock_path, LOCK_ATTEMPTS, LOCK_DELAY)
        .map_err(|_| BudgetError::Locked)?
        .ok_or(BudgetError::Locked)?;

    let path = base_dir.join(BUDGET_FILE);
    let bytes = fs::read_private_regular_nofollow_bounded(&path, BUDGET_MAX_BYTES)
        .map_err(|_| BudgetError::Unreadable)?;

    let mut state = match bytes {
        None => BudgetState {
            version: BUDGET_VERSION,
            minute_start: now,
            minute_count: 0,
            hour_start: now,
            hour_count: 0,
        },
        Some(bytes) => {
            if bytes.is_empty() {
                return Err(BudgetError::Unreadable);
            }
            let state: BudgetState =
                serde_json::from_slice(&bytes).map_err(|_| BudgetError::Unreadable)?;
            if state.version != BUDGET_VERSION {
                return Err(BudgetError::Unreadable);
            }
            state
        }
    };

    // A backwards or pre-epoch clock must not reset a window: that would hand
    // the caller a fresh budget. Refuse instead.
    if now < state.minute_start || now < state.hour_start {
        return Err(BudgetError::ClockInvalid);
    }
    if now >= state.minute_start.saturating_add(MINUTE_SECS) {
        state.minute_start = now;
        state.minute_count = 0;
    }
    if now >= state.hour_start.saturating_add(HOUR_SECS) {
        state.hour_start = now;
        state.hour_count = 0;
    }
    if state.minute_count >= MINUTE_LIMIT || state.hour_count >= HOUR_LIMIT {
        return Err(BudgetError::RateLimited);
    }
    state.minute_count += 1;
    state.hour_count += 1;

    let bytes = serde_json::to_vec(&state).map_err(|_| BudgetError::Unwritable)?;
    let writer = fs::write_private_tmp_synced_retained(&path, &bytes)
        .map_err(|_| BudgetError::Unwritable)?;
    writer.replace(&path).map_err(|_| BudgetError::Unwritable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_000_000;

    fn state(dir: &Path) -> BudgetState {
        let bytes = fs::read_private_regular_nofollow_bounded(&dir.join(BUDGET_FILE), 512)
            .expect("read")
            .expect("present");
        serde_json::from_slice(&bytes).expect("parse")
    }

    /// Writes a 0600 file so a content/shape refusal cannot be satisfied by
    /// the permission check instead.
    fn write_private(dir: &Path, bytes: &[u8]) {
        let path = dir.join(BUDGET_FILE);
        let writer = fs::write_private_tmp_synced_retained(&path, bytes).expect("writer");
        writer.replace(&path).expect("replace");
    }

    #[test]
    fn first_send_creates_the_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        reserve(dir.path(), T0).expect("first");
        let s = state(dir.path());
        assert_eq!(s.minute_count, 1);
        assert_eq!(s.hour_count, 1);
        assert_eq!(s.minute_start, T0);
    }

    #[test]
    fn the_eleventh_minute_send_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        for _ in 0..MINUTE_LIMIT {
            reserve(dir.path(), T0).expect("within limit");
        }
        assert_eq!(reserve(dir.path(), T0), Err(BudgetError::RateLimited));
        // The count did not advance on the refusal.
        assert_eq!(state(dir.path()).minute_count, MINUTE_LIMIT);
    }

    #[test]
    fn the_next_minute_admits_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        for _ in 0..MINUTE_LIMIT {
            reserve(dir.path(), T0).expect("within limit");
        }
        reserve(dir.path(), T0 + MINUTE_SECS).expect("new window");
        let s = state(dir.path());
        assert_eq!(s.minute_count, 1);
        assert_eq!(s.hour_count, MINUTE_LIMIT + 1);
    }

    #[test]
    fn the_sixty_first_hour_send_is_refused_even_across_minutes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut now = T0;
        for i in 0..HOUR_LIMIT {
            if i > 0 && i % MINUTE_LIMIT == 0 {
                now += MINUTE_SECS;
            }
            reserve(dir.path(), now).expect("within hour");
        }
        // A later minute still inside the hour cannot admit.
        assert_eq!(reserve(dir.path(), now), Err(BudgetError::RateLimited));
        // The next hour can.
        reserve(dir.path(), T0 + HOUR_SECS).expect("new hour");
    }

    #[test]
    fn a_corrupt_file_refuses_and_is_not_reset() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_private(dir.path(), b"{not json");
        assert_eq!(reserve(dir.path(), T0), Err(BudgetError::Unreadable));
        let raw = std::fs::read(dir.path().join(BUDGET_FILE)).expect("read");
        assert_eq!(raw, b"{not json");
    }

    #[test]
    fn an_empty_file_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_private(dir.path(), b"");
        assert_eq!(reserve(dir.path(), T0), Err(BudgetError::Unreadable));
    }

    #[test]
    fn an_unknown_version_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = BudgetState {
            version: 2,
            minute_start: T0,
            minute_count: 0,
            hour_start: T0,
            hour_count: 0,
        };
        write_private(dir.path(), &serde_json::to_vec(&s).unwrap());
        assert_eq!(reserve(dir.path(), T0), Err(BudgetError::Unreadable));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("elsewhere.json");
        std::fs::write(&target, b"{}").expect("write");
        std::os::unix::fs::symlink(&target, dir.path().join(BUDGET_FILE)).expect("symlink");
        assert_eq!(reserve(dir.path(), T0), Err(BudgetError::Unreadable));
    }

    #[test]
    fn a_backwards_clock_refuses_without_resetting() {
        let dir = tempfile::tempdir().expect("tempdir");
        reserve(dir.path(), T0).expect("first");
        assert_eq!(reserve(dir.path(), T0 - 1), Err(BudgetError::ClockInvalid));
        assert_eq!(state(dir.path()).minute_count, 1);
    }

    #[test]
    fn a_zero_or_negative_clock_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(reserve(dir.path(), 0), Err(BudgetError::ClockInvalid));
        assert_eq!(reserve(dir.path(), -1), Err(BudgetError::ClockInvalid));
    }

    #[cfg(unix)]
    #[test]
    fn a_held_lock_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join(BUDGET_LOCK_FILE);
        let _held = lock::lock_file(&lock_path).expect("hold");
        assert_eq!(reserve(dir.path(), T0), Err(BudgetError::Locked));
    }
}
