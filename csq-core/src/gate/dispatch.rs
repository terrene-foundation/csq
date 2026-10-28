//! Ordered, cooperative dispatch. A RowRunner must enforce its supplied deadline;
//! this layer rejects late results but cannot preempt a blocking implementation.
use super::matcher::{MatchError, Matcher};
use super::output::Fold;
use super::pin::{VerifiedBytes, VerifiedRegistry};
use super::registry::{self, CwdScope, Event, FailurePolicy, HookRow, Surface};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_ROW_OUTPUT_BYTES: usize = 1024 * 1024;

/// One centralized ceiling, shared with registration. SessionEnd has a separate
/// native 1.5s ceiling; keep 100ms to deliver its result. These are cooperative.
pub fn event_budget(event: Event) -> Duration {
    if event == Event::SessionEnd {
        Duration::from_millis(1400)
    } else {
        Duration::from_secs(9)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    Limit,
    Malformed,
    EventMismatch,
    InvalidCwd,
}

pub struct ParsedPayload {
    pub event: Event,
    pub surface: Surface,
    pub value: Value,
    pub original_bytes: Vec<u8>,
    pub payload_cwd: PathBuf,
    pub process_cwd: PathBuf,
}
impl ParsedPayload {
    /// JSON is decoded once, with duplicate keys rejected. Subsequent rows share
    /// the same original input; an accepted rewrite applies after all decisions.
    pub fn parse(
        event: Event,
        surface: Surface,
        bytes: Vec<u8>,
        process_cwd: PathBuf,
    ) -> Result<Self, InputError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(InputError::Limit);
        }
        let value = registry::strict_json(&bytes).map_err(|_| InputError::Malformed)?;
        if value.get("hook_event_name").and_then(Value::as_str) != Some(event.as_str()) {
            return Err(InputError::EventMismatch);
        }
        let cwd = value
            .get("cwd")
            .and_then(Value::as_str)
            .ok_or(InputError::InvalidCwd)?;
        let payload_cwd = PathBuf::from(cwd);
        if !payload_cwd.is_absolute() || !process_cwd.is_absolute() {
            return Err(InputError::InvalidCwd);
        }
        Ok(Self {
            event,
            surface,
            value,
            original_bytes: bytes,
            payload_cwd,
            process_cwd,
        })
    }
}

pub struct RowRequest<'a> {
    pub row: &'a HookRow,
    pub source: &'a VerifiedBytes,
    pub payload: &'a Value,
    pub cwd: &'a Path,
    pub deadline: Instant,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowFailure {
    Incomplete,
    Crash,
    Timeout,
    /// The runner could not durably record a security-relevant demotion.
    ///
    /// This is deliberately separate from the row's declared failure policy:
    /// losing the demotion event must deny, even for an otherwise continue-on-
    /// crash row.
    DemotionLedger,
}

#[derive(Debug, Default)]
pub struct RowOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait RowRunner {
    /// Execute admitted bytes, never reopen source_path as execution authority.
    fn run(&mut self, request: RowRequest<'_>) -> Result<RowOutput, RowFailure>;
}

/// This capability comes from compiled application code. Registry metadata can
/// never select it by claiming a special id/file/form. Messaging is best effort.
pub trait NativeHook {
    /// Upper bound for a valid native output, established before any durable
    /// claim. The callback must admit its output within this bound before claim.
    fn output_bound(&self) -> usize;
    fn run(&mut self, input: &ParsedPayload, deadline: Instant) -> Result<RowOutput, RowFailure>;
}

#[derive(Debug)]
pub struct DispatchResult {
    pub denied: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// A pin/input admission failure consults no untrusted manifest defaults.
pub fn unavailable(event: Event) -> DispatchResult {
    unavailable_with_policy(event, FailurePolicy::Deny)
}

/// Only use a fallback policy recovered from an authenticated private pin. An
/// unreadable pin supplies Deny; repository metadata supplies no authority.
pub fn unavailable_with_policy(event: Event, policy: FailurePolicy) -> DispatchResult {
    let mut fold = Fold::default();
    if policy == FailurePolicy::Deny {
        fold.failure("hook_admission_incomplete");
    }
    fold.finish(event)
}

pub fn dispatch(
    input: &ParsedPayload,
    registry: &VerifiedRegistry,
    runner: &mut dyn RowRunner,
    matcher: &mut dyn Matcher,
    native: Option<&mut dyn NativeHook>,
    deadline: Instant,
) -> DispatchResult {
    let deadline = deadline.min(Instant::now() + event_budget(input.event));
    dispatch_with_clock(
        input,
        registry,
        runner,
        matcher,
        native,
        (deadline, Instant::now),
    )
}

fn dispatch_with_clock(
    input: &ParsedPayload,
    registry: &VerifiedRegistry,
    runner: &mut dyn RowRunner,
    matcher: &mut dyn Matcher,
    native: Option<&mut dyn NativeHook>,
    timing: (Instant, impl FnMut() -> Instant),
) -> DispatchResult {
    let (deadline, mut now) = timing;
    let mut fold = Fold::default();
    let native = native.filter(|native| fold.reserve_native(native.output_bound()));
    let mut rows: Vec<_> = registry
        .rows
        .iter()
        .filter(|r| r.row.event == input.event && r.row.surfaces.contains(&input.surface))
        .collect();
    rows.sort_by_key(|r| r.row.order); // stable manifest order breaks ties.
    for verified in rows {
        let row = &verified.row;
        if now() >= deadline {
            fold.failed(row, RowFailure::Timeout);
            continue;
        }
        match matcher.matches(input.event, &row.matcher, &input.value, deadline) {
            Ok(false) => continue,
            Err(error) => {
                fold.failed(
                    row,
                    if error == MatchError::Timeout {
                        RowFailure::Timeout
                    } else {
                        RowFailure::Incomplete
                    },
                );
                continue;
            }
            Ok(true) => {}
        }
        let Ok(source) = &verified.admission else {
            fold.failed(row, RowFailure::Incomplete);
            continue;
        };
        let row_deadline = row
            .timeout
            .and_then(|seconds| now().checked_add(Duration::from_secs(seconds)))
            .map_or(deadline, |end| end.min(deadline));
        if now() >= row_deadline {
            fold.failed(row, RowFailure::Timeout);
            continue;
        }
        let cwd = match row.contract.cwd_scope {
            CwdScope::Payload => &input.payload_cwd,
            CwdScope::Process => &input.process_cwd,
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runner.run(RowRequest {
                row,
                source,
                payload: &input.value,
                cwd,
                deadline: row_deadline,
            })
        }))
        .unwrap_or(Err(RowFailure::Crash));
        // A completed refusal remains authoritative if the clock expires
        // between the runner's return and folding. Late permissive output,
        // context and rewrites still follow the row timeout policy below.
        if let Ok(output) = &outcome {
            fold.retain_exit_two(output.exit_code);
        }
        if now() >= row_deadline {
            fold.failed(row, RowFailure::Timeout);
            continue;
        }
        match outcome {
            Err(failure) => fold.failed(row, failure),
            Ok(output) => {
                if let Err(failure) = fold.accept(input.event, &output, Some(row)) {
                    fold.failed(row, failure);
                }
            }
        }
    }
    // Native messaging runs last, preserving all earlier decisions. It has the
    // same remaining deadline but cannot turn a missed notice into a denial.
    if let Some(native) = native {
        if now() < deadline {
            fold.release_native();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                native.run(input, deadline)
            }));
            if let Ok(Ok(output)) = outcome {
                // A successful durable claim is already committed. Delivery may
                // cross the cooperative deadline; discarding it loses the notice.
                if fold.accept(input.event, &output, None).is_err() {
                    fold.failure("native_output_contract_incomplete");
                }
            }
        }
    }
    fold.finish(input.event)
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;
