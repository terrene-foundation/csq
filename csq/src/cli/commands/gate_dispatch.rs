//! Bounded native hook entry point: `csq gate dispatch <event>`.
//!
//! This command is deliberately a thin boundary.  It owns stdin admission and
//! fixed refusal output; the authenticated pin, package verifier and ordered
//! dispatcher remain in `csq-core`.  Hook registrations must invoke this
//! command directly, before any ordinary CLI startup work.

use super::gate_row_audit::AuditWriter;
use super::gate_row_observer::RowObserver;
use anyhow::Result;
use clap::Args;
use csq_core::gate::dispatch::{self, DispatchResult, ParsedPayload};
#[cfg(all(test, unix))]
use csq_core::gate::dispatch::{RowFailure, RowOutput, RowRequest, RowRunner};
#[cfg(all(test, unix))]
use csq_core::gate::legacy::{
    pool_name, ExecutionMode, NodePoolRunner, PoolCachedRunner, PoolRowContract, PoolRunError,
};
use csq_core::gate::legacy::{NodeEnvironment, NodeRowRunner, VerifiedPackage};
use csq_core::gate::matcher::Matcher;
use csq_core::gate::matcher::NativeMatcher;
use csq_core::gate::pin::Pin;
use csq_core::gate::process::{read_payload_until, PayloadReadError};
use csq_core::gate::registry::{self, Event, Surface};
#[cfg(all(test, unix))]
use csq_core::gate::runtime_mapping::prove_runtime_pools;
use serde_json::json;
#[cfg(test)]
use std::io::Read;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

/// The production ceiling on a dispatch: the caller's deadline clamped to the
/// per-event budget ([`dispatch::event_budget`], 9 s). Production callers
/// already pass a deadline at that ceiling, so the clamp is a no-op for them.
/// A FIXTURE that must exercise a larger budget opts in through
/// `with_event_budget_override` (plain code text, not an intra-doc link: the
/// seam is `cfg(all(test, unix))` and absent from the docs build): without
/// it, the 9 s ceiling — not the fixture's budget — decides any deliberately
/// slow child, and the row reds on a saturated host for a wall-clock
/// artifact.
///
/// SCOPE: the override reaches POOL execution only (this entry point passes
/// the lifted deadline straight to the row runner). `csq_core::gate::
/// dispatch::dispatch` re-clamps every deadline to `event_budget` itself, so
/// process-mode and row-mode dispatch stay under 9 s regardless.
fn effective_deadline(stdin_deadline: Instant, event: Event) -> Instant {
    let ceiling = match test_event_budget_override() {
        Some(budget) => Instant::now() + budget,
        None => Instant::now() + dispatch::event_budget(event),
    };
    stdin_deadline.min(ceiling)
}

#[cfg(test)]
thread_local! {
    /// Fixture-scoped event-budget override. Thread-local so a test's larger
    /// budget cannot leak into a sibling test running in parallel.
    static EVENT_BUDGET_OVERRIDE: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn test_event_budget_override() -> Option<Duration> {
    EVENT_BUDGET_OVERRIDE.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn test_event_budget_override() -> Option<std::time::Duration> {
    None
}

/// Runs `f` with the fixture event budget overridden, restoring the previous
/// value on return AND on panic (the guard drops during unwind), so a failing
/// fixture cannot leave the override in place for the rest of the thread.
///
/// Unix-only with its callers: the pool fixtures are `cfg(unix)` tests, and a
/// Windows test build would otherwise carry a dead_code warning that
/// `test-windows.yml`'s `-D warnings` lint turns red.
#[cfg(all(test, unix))]
fn with_event_budget_override<T>(budget: Duration, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Duration>);
    impl Drop for Restore {
        fn drop(&mut self) {
            EVENT_BUDGET_OVERRIDE.with(|cell| cell.set(self.0));
        }
    }
    let previous = EVENT_BUDGET_OVERRIDE.with(|cell| cell.replace(Some(budget)));
    let _restore = Restore(previous);
    f()
}

#[derive(Debug, Args)]
pub struct GateDispatchArgs {
    /// Claude hook event name, for example `PreToolUse` or `Stop`.
    pub event: String,
    /// Exact repository authenticated by the private pin.
    #[arg(long)]
    pub repo: PathBuf,
    /// Existing private operator pin.  Dispatch never creates or replaces it.
    #[arg(long)]
    pub pin: PathBuf,
    /// Immutable Loom adapter package manifest.
    #[arg(long)]
    pub adapter_manifest: PathBuf,
    /// Independently reviewed SHA-256 of the adapter manifest bytes.
    #[arg(long)]
    pub expected_adapter_sha256: String,
    /// Optional private outside-repository row audit destination.
    #[arg(long)]
    pub row_audit: Option<PathBuf>,
    /// Pool qualification is unavailable until owner-authenticated Loom proof exists.
    #[arg(long)]
    pub pool_audit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    InvalidInput,
    Pin,
    Adapter,
    Deadline,
    PoolSafetyHold,
    #[cfg(all(test, unix))]
    PoolIncomplete,
}

fn refusal_json() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "decision": "block",
        "reason": "csq_gate_refused"
    }))
    .expect("fixed gate refusal is always serializable")
}

fn write_refusal(out: &mut impl Write) -> Result<()> {
    out.write_all(&refusal_json())?;
    out.write_all(b"\n")?;
    Ok(())
}

fn write_dispatch_refusal(out: &mut impl Write, refusal: Refusal) -> Result<()> {
    match refusal {
        Refusal::PoolSafetyHold => {
            out.write_all(b"{\"decision\":\"block\",\"reason\":\"csq_gate_pool_safety_hold\"}\n")?
        }
        #[cfg(all(test, unix))]
        Refusal::PoolIncomplete => {
            let response = json!({"decision":"block", "reason":"csq_gate_pool_incomplete",
                "message":"csq Gate pool execution incomplete — action denied"});
            serde_json::to_writer(&mut *out, &response)?;
            out.write_all(b"\n")?;
        }
        _ => return write_refusal(out),
    }
    Ok(())
}

/// Fixed, path-free refusal used by the early CLI parser route.  Malformed
/// dispatch arguments must not pass clap's echoed error text to hook stdout.
pub(crate) fn emit_parse_refusal() -> Result<i32> {
    write_refusal(&mut io::stdout().lock())?;
    Ok(2)
}

fn parse_surface() -> Surface {
    // The first native activation is Claude Code.  The registry remains
    // surface-aware, so adding another caller is an explicit command change.
    Surface::Claude
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Package verification is bounded at the command boundary.  The verifier
/// performs bounded regular-file reads but has no preemptive filesystem API;
/// a timed-out worker is detached and its result is discarded.
fn verify_package_until(
    manifest: &Path,
    repo: &Path,
    deadline: Instant,
) -> Result<VerifiedPackage, Refusal> {
    if Instant::now() >= deadline {
        return Err(Refusal::Deadline);
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let manifest = manifest.to_owned();
    let repo = repo.to_owned();
    thread::Builder::new()
        .name("csq-gate-package-admission".into())
        .spawn(move || {
            let _ = sender.send(VerifiedPackage::verify(&manifest, &repo));
        })
        .map_err(|_| Refusal::Adapter)?;
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(package)) => Ok(package),
        Ok(Err(_)) => Err(Refusal::Adapter),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(Refusal::Deadline),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(Refusal::Adapter),
    }
}

fn dispatch_bytes(
    args: &GateDispatchArgs,
    bytes: Vec<u8>,
    process_cwd: PathBuf,
    stdin_deadline: Instant,
) -> Result<DispatchResult, Refusal> {
    if args.pool_audit {
        return Err(Refusal::PoolSafetyHold);
    }
    let event = Event::from_str(&args.event).map_err(|_| Refusal::InvalidInput)?;
    let input = ParsedPayload::parse(event, parse_surface(), bytes, process_cwd)
        .map_err(|_| Refusal::InvalidInput)?;
    let repo = args.repo.canonicalize().map_err(|_| Refusal::Pin)?;
    let deadline = effective_deadline(stdin_deadline, event);
    let verified =
        Pin::load_verify_until(&args.pin, &repo, event, deadline).map_err(|_| Refusal::Pin)?;
    if !valid_digest(&args.expected_adapter_sha256) {
        return Err(Refusal::Adapter);
    }
    let package_deadline = deadline.saturating_duration_since(Instant::now());
    let package = verify_package_until(
        &args.adapter_manifest,
        &repo,
        Instant::now() + package_deadline,
    )?;
    if package.manifest_sha256() != args.expected_adapter_sha256 {
        return Err(Refusal::Adapter);
    }
    let environment = NodeEnvironment {
        claude_config_dir: std::env::var("CLAUDE_CONFIG_DIR").ok(),
        codex_home: std::env::var("CODEX_HOME").ok(),
        session_id: std::env::var("CSQ_SESSION_ID").ok(),
        handle_dir: std::env::var("CSQ_HANDLE_DIR").ok(),
        path: std::env::var("PATH").ok(),
        home: std::env::var("HOME").ok(),
        tmpdir: std::env::var("TMPDIR").ok(),
    };
    // Pool activation has no owner-authenticated immutable-loader proof yet.
    // No CLI flag, environment variable, or config value can bypass this hold.
    // Existing launches retain their admitted per-row execution path.
    let mut runner = NodeRowRunner::new(package.clone()).with_environment(environment.clone());
    if let Some(handle_dir) = environment.handle_dir.as_deref() {
        runner = runner.with_fault_ledger(Path::new(handle_dir).join("gate-demotions.jsonl"));
    }
    runner
        .preflight_ledger()
        .map_err(|_| Refusal::PoolSafetyHold)?;
    let mut matcher = NativeMatcher;
    let mut candidates: Vec<_> = verified
        .rows
        .iter()
        .filter(|row| row.row.event == event && row.row.surfaces.contains(&parse_surface()))
        .collect();
    candidates.sort_by_key(|row| row.row.order);
    let matched_row_ids = preflight_matched_rows(
        &candidates,
        &package,
        event,
        &input.value,
        &mut matcher,
        deadline,
    )?;
    let payload_sha256 = registry::sha256(&input.original_bytes);
    let audit = if let Some(path) = &args.row_audit {
        let header = json!({"type":"header","schema":"csq.gate-row-audit.v2","execution_mode":"row",
            "event":event.as_str(),"payload_sha256":payload_sha256,
            "repo_sha256":registry::sha256(repo.as_os_str().as_encoded_bytes()),
            "registry_sha256":verified.registry.content_sha256,"source_sha":verified.registry.source_sha,
            "adapter_sha256":package.manifest_sha256(),
            "max_bytes":super::gate_row_audit::MAX_AUDIT_BYTES,"max_records":super::gate_row_audit::MAX_AUDIT_RECORDS,
            "candidate_row_ids":candidates.iter().map(|row|row.row.id.clone()).collect::<Vec<_>>(),
            "matched_row_ids":matched_row_ids,
            "candidates":candidates.iter().map(|row|json!({"row_id":row.row.id,"source_sha256":row.row.file_sha256,
                "order":row.row.order,"pool":csq_core::gate::legacy::pool_name(row.row.pool),
                "cwd_scope":format!("{:?}",row.row.contract.cwd_scope)})).collect::<Vec<_>>()});
        Some(AuditWriter::open(path, &repo, &header).map_err(|_| Refusal::Adapter)?)
    } else {
        None
    };
    let mut runner = RowObserver::new(runner, audit, event, payload_sha256);
    let result = dispatch::dispatch(&input, &verified, &mut runner, &mut matcher, None, deadline);
    runner.finish().map_err(|_| Refusal::Adapter)?;
    Ok(result)
}

/// Preflight only successful matches. False/error matcher results must retain
/// the ordinary dispatcher's skip and declared failure-policy behavior.
fn preflight_matched_rows(
    candidates: &[&csq_core::gate::pin::VerifiedRow],
    package: &VerifiedPackage,
    event: Event,
    payload: &serde_json::Value,
    matcher: &mut dyn Matcher,
    deadline: Instant,
) -> Result<Vec<String>, Refusal> {
    let mut selected = Vec::new();
    for row in candidates {
        if matches!(
            matcher.matches(event, &row.row.matcher, payload, deadline),
            Ok(true)
        ) {
            package
                .bind_verified_bytes(row.admission.as_ref().map_err(|_| Refusal::Adapter)?)
                .map_err(|_| Refusal::Adapter)?;
            selected.push(row.row.id.clone());
        }
    }
    Ok(selected)
}

// Controlled fixtures may exercise the inactive implementation. This entry is
// absent from production, including from the ordinary dispatch command.
#[cfg(all(test, unix))]
fn dispatch_pool_fixture_bytes(
    args: &GateDispatchArgs,
    bytes: Vec<u8>,
    process_cwd: PathBuf,
    stdin_deadline: Instant,
) -> Result<DispatchResult, Refusal> {
    let event = Event::from_str(&args.event).map_err(|_| Refusal::InvalidInput)?;
    let input = ParsedPayload::parse(event, parse_surface(), bytes, process_cwd)
        .map_err(|_| Refusal::InvalidInput)?;
    let repo = args.repo.canonicalize().map_err(|_| Refusal::Pin)?;
    let deadline = effective_deadline(stdin_deadline, event);
    let verified =
        Pin::load_verify_until(&args.pin, &repo, event, deadline).map_err(|_| Refusal::Pin)?;
    if !valid_digest(&args.expected_adapter_sha256) {
        return Err(Refusal::Adapter);
    }
    let package_deadline = deadline.saturating_duration_since(Instant::now());
    let package = verify_package_until(
        &args.adapter_manifest,
        &repo,
        Instant::now() + package_deadline,
    )?;
    if package.manifest_sha256() != args.expected_adapter_sha256 {
        return Err(Refusal::Adapter);
    }
    let environment = NodeEnvironment {
        claude_config_dir: std::env::var("CLAUDE_CONFIG_DIR").ok(),
        codex_home: std::env::var("CODEX_HOME").ok(),
        session_id: std::env::var("CSQ_SESSION_ID").ok(),
        handle_dir: std::env::var("CSQ_HANDLE_DIR").ok(),
        path: std::env::var("PATH").ok(),
        home: std::env::var("HOME").ok(),
        tmpdir: std::env::var("TMPDIR").ok(),
    };
    // Match before spawning a pool child.  A matcher-skipped row must not be
    // executed merely because it shares an authenticated runtime.
    let mut pre_matcher = NativeMatcher;
    let mut matched = std::collections::BTreeSet::new();
    let mut candidates: Vec<_> = verified
        .rows
        .iter()
        .filter(|row| row.row.event == event && row.row.surfaces.contains(&parse_surface()))
        .collect();
    candidates.sort_by_key(|row| row.row.order);
    for row in &candidates {
        if pre_matcher
            .matches(event, &row.row.matcher, &input.value, deadline)
            .map_err(|_| Refusal::Adapter)?
        {
            matched.insert(row.row.id.clone());
        }
    }
    let bindings =
        prove_runtime_pools(&verified, event, parse_surface()).map_err(|_| Refusal::Adapter)?;
    // Preflight ALL pools before any child can have effects. A second pool's
    // valid-but-different package must not fail only after the first has run.
    for binding in &bindings {
        let runtime = verified
            .runtimes
            .get(binding.runtime_index)
            .ok_or(Refusal::Adapter)?;
        package
            .bind_verified_bytes(runtime)
            .map_err(|_| Refusal::Adapter)?;
        for row_id in &binding.row_ids {
            let row = verified
                .rows
                .iter()
                .find(|row| row.row.id == *row_id)
                .ok_or(Refusal::Adapter)?;
            package
                .bind_verified_bytes(row.admission.as_ref().map_err(|_| Refusal::Adapter)?)
                .map_err(|_| Refusal::Adapter)?;
        }
    }
    let mut row_contracts = std::collections::BTreeMap::new();
    for row in &verified.rows {
        if matched.contains(&row.row.id) {
            row_contracts.insert(
                row.row.id.clone(),
                PoolRowContract {
                    id: row.row.id.clone(),
                    source_path: row
                        .admission
                        .as_ref()
                        .map_err(|_| Refusal::Adapter)?
                        .source_path()
                        .strip_prefix(&repo)
                        .ok()
                        .and_then(|path| path.to_str())
                        .ok_or(Refusal::Adapter)?
                        .to_owned(),
                    source_sha256: row.row.file_sha256.clone(),
                    timeout_secs: row.row.timeout,
                },
            );
        }
    }
    let payload_sha256 = registry::sha256(&input.original_bytes);
    let mut audit = if let Some(path) = &args.row_audit {
        let candidate_row_ids: Vec<_> = candidates.iter().map(|row| row.row.id.clone()).collect();
        let matched_row_ids: Vec<_> = candidate_row_ids
            .iter()
            .filter(|id| matched.contains(*id))
            .cloned()
            .collect();
        let candidates: Vec<_> = candidates
            .iter()
            .map(|row| {
                json!({
                    "row_id": row.row.id,
                    "source_sha256": row.row.file_sha256,
                    "order": row.row.order,
                    "pool": pool_name(row.row.pool),
                    "cwd_scope": format!("{:?}", row.row.contract.cwd_scope),
                })
            })
            .collect();
        let header = json!({
            "type": "header",
            "schema": "csq.gate-row-audit.v1",
            "event": event.as_str(),
            "payload_sha256": payload_sha256,
            "repo_sha256": registry::sha256(repo.as_os_str().as_encoded_bytes()),
            "registry_sha256": verified.registry.content_sha256,
            "source_sha": verified.registry.source_sha,
            "adapter_sha256": package.manifest_sha256(),
            "max_bytes": super::gate_row_audit::MAX_AUDIT_BYTES,
            "max_records": super::gate_row_audit::MAX_AUDIT_RECORDS,
            "candidates": candidates,
            "candidate_row_ids": candidate_row_ids,
            "matched_row_ids": matched_row_ids,
        });
        Some(AuditWriter::open(path, &repo, &header).map_err(|_| Refusal::Adapter)?)
    } else {
        None
    };
    let mut outcomes = Vec::new();
    let mut process_rows = std::collections::BTreeSet::new();
    let mut process_runner =
        NodeRowRunner::new(package.clone()).with_environment(environment.clone());
    if let Some(handle_dir) = environment.handle_dir.as_deref() {
        process_runner =
            process_runner.with_fault_ledger(Path::new(handle_dir).join("gate-demotions.jsonl"));
    }
    process_runner
        .preflight_ledger()
        .map_err(|_| Refusal::PoolSafetyHold)?;
    let mut seen_rows = std::collections::BTreeSet::new();
    for binding in bindings {
        let mut binding = binding;
        binding.row_ids.retain(|id| matched.contains(id));
        if binding.row_ids.is_empty() {
            continue;
        }
        let runtime = verified
            .registry
            .runtimes
            .get(binding.runtime_index)
            .ok_or(Refusal::Adapter)?;
        let mut pool = NodePoolRunner::new(package.clone(), &runtime.entry)
            .map_err(|_| Refusal::Adapter)?
            .with_environment(environment.clone());
        if let Some(handle_dir) = environment.handle_dir.as_deref() {
            pool = pool.with_fault_ledger(Path::new(handle_dir).join("gate-demotions.jsonl"));
        }
        binding.row_ids.retain(|id| {
            if pool.execution_mode(id, binding.pool) == ExecutionMode::Process {
                process_rows.insert(id.clone());
                false
            } else {
                true
            }
        });
        if binding.row_ids.is_empty() {
            continue;
        }
        let cwd = verified
            .rows
            .iter()
            .find(|row| binding.row_ids.iter().any(|id| id == &row.row.id))
            .map(|row| match row.row.contract.cwd_scope {
                csq_core::gate::registry::CwdScope::Payload => &input.payload_cwd,
                csq_core::gate::registry::CwdScope::Process => &input.process_cwd,
            })
            .ok_or(Refusal::Adapter)?;
        let binding_contracts: Vec<_> = binding
            .row_ids
            .iter()
            .filter_map(|id| row_contracts.get(id).cloned())
            .collect();
        if binding_contracts.len() != binding.row_ids.len() {
            return Err(Refusal::Adapter);
        }
        let execution = match pool.run_event_rows(
            &binding,
            &binding_contracts,
            &payload_sha256,
            &input.original_bytes,
            cwd,
            deadline,
        ) {
            Ok(execution) => execution,
            Err(PoolRunError::Refusal(RowFailure::DemotionLedger)) => {
                return Err(Refusal::PoolSafetyHold)
            }
            Err(PoolRunError::Refusal(
                RowFailure::Incomplete | RowFailure::Crash | RowFailure::Timeout,
            )) => return Err(Refusal::PoolIncomplete),
        };
        if let Some(audit) = audit.as_mut() {
            let rows: Vec<_> = execution
                .rows
                .iter()
                .map(|row| {
                    json!({
                        "row_id": row.row_id,
                        "source_sha256": row.source_sha256,
                        "status": row.status,
                        "exit_code": row.exit_code,
                        "stdout_bytes": row.stdout.len(),
                        "stdout_sha256": registry::sha256(&row.stdout),
                        "stderr_bytes": row.stderr.len(),
                        "stderr_sha256": registry::sha256(&row.stderr),
                    })
                })
                .collect();
            let record = json!({
                "type": "pool",
                "event": event.as_str(),
                "pool": pool_name(binding.pool),
                "runtime_index": binding.runtime_index,
                "runtime_entry_sha256": runtime.entry_sha256,
                "matched_row_ids": binding.row_ids,
                "cwd_sha256": registry::sha256(cwd.as_os_str().as_encoded_bytes()),
                "child_started": execution.child_started,
                "rows": rows,
            });
            audit.record(&record).map_err(|_| Refusal::Adapter)?;
        }
        for row in execution.rows {
            if !seen_rows.insert(row.row_id.clone()) {
                return Err(Refusal::Adapter);
            }
            outcomes.push(row);
        }
    }
    if seen_rows.len() + process_rows.len() != row_contracts.len() {
        return Err(Refusal::Adapter);
    }
    let mut runner = ExecutionRunner {
        pool: PoolCachedRunner::new(outcomes).map_err(|_| Refusal::Adapter)?,
        process: process_runner,
        process_rows,
        process_audit: Vec::new(),
    };
    let mut matcher = NativeMatcher;
    let result = dispatch::dispatch(&input, &verified, &mut runner, &mut matcher, None, deadline);
    if let Some(mut audit) = audit {
        for record in runner.process_audit {
            audit.record(&record).map_err(|_| Refusal::Adapter)?;
        }
        audit.complete().map_err(|_| Refusal::Adapter)?;
    }
    Ok(result)
}

/// Actual demoted process execution remains distinct from pooled audit proof.
/// These observations never claim one pooled child or an inside-pool row return.
#[cfg(all(test, unix))]
struct ExecutionRunner {
    pool: PoolCachedRunner,
    process: NodeRowRunner,
    process_rows: std::collections::BTreeSet<String>,
    process_audit: Vec<serde_json::Value>,
}
#[cfg(all(test, unix))]
impl RowRunner for ExecutionRunner {
    fn run(&mut self, request: RowRequest<'_>) -> Result<RowOutput, RowFailure> {
        if !self.process_rows.contains(&request.row.id) {
            return self.pool.run(request);
        }
        let row_id = request.row.id.clone();
        let source_sha256 = request.row.file_sha256.clone();
        let result = self.process.run(request);
        let mut record =
            json!({"type":"process_fallback", "row_id":row_id, "source_sha256":source_sha256});
        if let Ok(output) = &result {
            record["status"] = "returned".into();
            record["exit_code"] = output.exit_code.into();
            record["stdout_bytes"] = output.stdout.len().into();
            record["stdout_sha256"] = registry::sha256(&output.stdout).into();
            record["stderr_bytes"] = output.stderr.len().into();
            record["stderr_sha256"] = registry::sha256(&output.stderr).into();
        } else {
            record["status"] = "failed".into();
        }
        self.process_audit.push(record);
        result
    }
}

fn emit_result(
    result: DispatchResult,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<i32> {
    if !result.stderr.is_empty() {
        stderr.write_all(&result.stderr)?;
    }
    if result.stdout.is_empty() && result.denied {
        write_refusal(stdout)?;
    } else if !result.stdout.is_empty() {
        stdout.write_all(&result.stdout)?;
    }
    Ok(result.exit_code)
}

/// Execute one native hook invocation.  All refusal classes share one bounded,
/// path-free JSON response so malformed input and unreadable trust state cannot
/// leak filesystem details into a vendor hook protocol.
pub fn handle(args: &GateDispatchArgs) -> Result<i32> {
    let event = match Event::from_str(&args.event) {
        Ok(event) => event,
        Err(_) => {
            let mut stdout = io::stdout().lock();
            write_refusal(&mut stdout)?;
            return Ok(2);
        }
    };
    let deadline = Instant::now() + dispatch::event_budget(event);
    let stdin = io::stdin();
    let bytes = match read_payload_until(stdin, deadline) {
        Ok(bytes) => bytes,
        Err(PayloadReadError::Limit | PayloadReadError::Io | PayloadReadError::Timeout) => {
            let mut stdout = io::stdout().lock();
            write_refusal(&mut stdout)?;
            return Ok(2);
        }
    };
    let mut stdout = io::stdout().lock();
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) => {
            write_refusal(&mut stdout)?;
            return Ok(2);
        }
    };
    let mut stderr = io::stderr().lock();
    match dispatch_bytes(args, bytes, cwd, deadline) {
        Ok(result) => emit_result(result, &mut stdout, &mut stderr),
        Err(refusal) => {
            write_dispatch_refusal(&mut stdout, refusal)?;
            Ok(2)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    #[cfg(unix)]
    struct PrivateEnvironment {
        _guard: csq_core::platform::test_env::EnvTestGuard,
        _home: tempfile::TempDir,
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    #[cfg(unix)]
    impl PrivateEnvironment {
        fn new() -> Self {
            Self::with_guard(csq_core::platform::test_env::lock())
        }
        fn with_guard(guard: csq_core::platform::test_env::EnvTestGuard) -> Self {
            let home = tempfile::tempdir().unwrap();
            let previous = [
                "HOME",
                "CSQ_BASE_DIR",
                "CLAUDE_CONFIG_DIR",
                "CODEX_HOME",
                "CSQ_SESSION_ID",
                "CSQ_HANDLE_DIR",
            ]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
            for key in ["HOME", "CSQ_BASE_DIR"] {
                std::env::set_var(key, home.path());
            }
            for key in [
                "CLAUDE_CONFIG_DIR",
                "CODEX_HOME",
                "CSQ_SESSION_ID",
                "CSQ_HANDLE_DIR",
            ] {
                std::env::remove_var(key);
            }
            Self {
                _guard: guard,
                _home: home,
                previous,
            }
        }
    }
    #[cfg(unix)]
    impl Drop for PrivateEnvironment {
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_environment_preserves_parent_tmpdir_and_native_child_uses_owned_temp() {
        let guard = csq_core::platform::test_env::lock();
        let previous = std::env::var_os("TMPDIR");
        let environment = PrivateEnvironment::with_guard(guard);
        assert_eq!(std::env::var_os("TMPDIR"), previous);
        let (_temp, mut args, payload) = node_decision_fixture(false);
        let runtime = args.repo.join(".claude/hooks/runtime.js");
        let original = std::fs::read_to_string(&runtime).unwrap();
        std::fs::write(&runtime, format!("require('fs').writeFileSync(require('path').join(process.env.TMPDIR,'child-tmp-marker'),'owned');{original}")).unwrap();
        reseal_fixture(&mut args, |_| {});
        let package = VerifiedPackage::verify(&args.adapter_manifest, &args.repo).unwrap();
        let mut runner = NodePoolRunner::new(package, ".claude/hooks/runtime.js")
            .unwrap()
            .with_environment(NodeEnvironment {
                path: std::env::var("PATH").ok(),
                home: Some(environment._home.path().to_string_lossy().into_owned()),
                tmpdir: Some(environment._home.path().to_string_lossy().into_owned()),
                ..Default::default()
            });
        let result = runner
            .run_event(
                registry::Pool::Repo,
                Event::PreToolUse,
                &payload,
                &args.repo,
                Instant::now() + FIXTURE_DISPATCH_BUDGET,
            )
            .unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(
            std::fs::read(environment._home.path().join("child-tmp-marker")).unwrap(),
            b"owned"
        );
        assert_eq!(std::env::var_os("TMPDIR"), previous);
        drop(environment);
        let _guard = csq_core::platform::test_env::lock();
        assert_eq!(std::env::var_os("TMPDIR"), previous);
    }

    #[test]
    fn fixed_refusal_never_echoes_paths_or_error_text() {
        let bytes = refusal_json();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text, r#"{"decision":"block","reason":"csq_gate_refused"}"#);
        assert!(!text.contains("/"));
    }

    #[test]
    fn event_and_digest_admission_are_closed() {
        assert!(Event::from_str("PreToolUse").is_ok());
        assert!(Event::from_str("/tmp/secret").is_err());
        assert!(valid_digest(&"a".repeat(64)));
        assert!(!valid_digest(&"A".repeat(64)));
        assert!(!valid_digest("not-a-digest"));
    }

    #[test]
    fn invalid_payload_is_a_compiled_deny_fixture() {
        let args = GateDispatchArgs {
            event: "Stop".into(),
            repo: PathBuf::from("/private/repo-canary"),
            pin: PathBuf::from("/private/pin-canary"),
            adapter_manifest: PathBuf::from("/private/manifest-canary"),
            expected_adapter_sha256: "a".repeat(64),
            row_audit: None,
            pool_audit: false,
        };
        let result = dispatch_bytes(
            &args,
            br#"{"hook_event_name":"PreToolUse","cwd":"/tmp"}"#.to_vec(),
            PathBuf::from("/tmp"),
            Instant::now() + Duration::from_secs(1),
        );
        assert!(matches!(result, Err(Refusal::InvalidInput)));
    }

    #[test]
    fn blocked_reader_returns_refusal_budget_without_joining() {
        let (release, wait) = mpsc::channel();
        let start = Instant::now();
        let result = read_payload_until(Blocked(wait), start + Duration::from_millis(20));
        assert_eq!(result, Err(PayloadReadError::Timeout));
        let _ = release.send(());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn tampered_adapter_bytes_refuse_before_any_runner_is_constructed() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let runtime = repo.join(".claude/hook-runtime/1.0.0");
        std::fs::create_dir_all(&runtime).unwrap();
        let runtime_path = runtime.join("runtime.js");
        std::fs::write(&runtime_path, b"tampered").unwrap();
        let manifest = serde_json::json!({
            "package": "loom-hook-runtime",
            "version": "1.0.0",
            "proposed_path": ".claude/hook-runtime/1.0.0/",
            "invocation": "node runtime.js",
            "commit_sha": "a".repeat(40),
            "commit_sha_convention": "pinned",
            "head_at_generation": "b".repeat(40),
            "runtime_clean_at_generation": true,
            "file_count": 1,
            "files": [{
                "path": ".claude/hook-runtime/1.0.0/runtime.js",
                "sha256": "9b71639a65b38ff87410ae3c7e1284cd94dd2abf930d40bb00ab22eb7c432de3",
                "bytes": 15
            }],
            "verification": {
                "pins": [{
                    "path": ".claude/hook-runtime/1.0.0/runtime.js",
                    "sha256": "9b71639a65b38ff87410ae3c7e1284cd94dd2abf930d40bb00ab22eb7c432de3",
                    "source": "runtime_closure"
                }],
                "runtime_closure": {
                    "entry_points": [".claude/hook-runtime/1.0.0/runtime.js"],
                    "reached_files": 1,
                    "gaps": [],
                    "method": "lexical walk"
                }
            }
        });
        let manifest_path = runtime.join("PACKAGE-MANIFEST.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let result = verify_package_until(
            &manifest_path,
            &repo,
            Instant::now() + Duration::from_secs(1),
        );
        assert!(matches!(result, Err(Refusal::Adapter)));
    }

    /// The induced delay `a_pool_child_slower_than_the_old_five_second_budget_
    /// still_completes` busy-waits in the decision child. Named so every
    /// fixture budget below DERIVES from it instead of restating a literal.
    #[cfg(unix)]
    pub(crate) const FIXTURE_INDUCED_CHILD_DELAY_SECS: u64 = 6;

    /// Scheduling margin applied to the induced delay. 10x is a CHOSEN,
    /// generous budget for a saturated shared host; the ~7x slowdown observed
    /// on a stalled darwin lib-bins leg is the typical case it covers — an
    /// observation, never a bound.
    #[cfg(unix)]
    pub(crate) const FIXTURE_SCHEDULING_FACTOR: u64 = 10;

    /// Startup allowance for the child process itself — interpreter boot and
    /// module load — which the induced delay does not cover.
    #[cfg(unix)]
    pub(crate) const FIXTURE_CHILD_START_ALLOWANCE_SECS: u64 = 30;

    /// Enclosing dispatch budget for POSITIVE fixture rows — the clock the
    /// whole dispatch runs under. DERIVED as the induced delay times the
    /// scheduling margin, plus the child startup allowance. Every
    /// positive-path row passes this budget; a bare literal anywhere on that
    /// path is what train #12 and this train's first sign-off both red on.
    /// Fault rows that deliberately test a deadline keep their own short
    /// budgets (the 250 ms/1 s/3 s literals).
    #[cfg(unix)]
    pub(crate) const FIXTURE_DISPATCH_BUDGET: Duration = Duration::from_secs(
        FIXTURE_INDUCED_CHILD_DELAY_SECS * FIXTURE_SCHEDULING_FACTOR
            + FIXTURE_CHILD_START_ALLOWANCE_SECS,
    );

    /// Row deadline for the shared decision fixture: the dispatch budget plus
    /// the startup allowance again, so it sits strictly ABOVE the dispatch
    /// budget.
    ///
    /// `dispatch.rs` derives each row's deadline as `min(row.timeout,
    /// dispatch deadline)`, computed per row start. Row mode enforces that
    /// deadline; the fixture's pool runtime echoes `timeout_secs` but is
    /// governed by the dispatch clock alone. A row timeout BELOW the dispatch
    /// budget therefore hands the ROW mode its own clock — a Node child alive
    /// but unscheduled for that long reports `on_timeout: "deny"` in row mode
    /// while the same work completes in pool mode, a wall-clock artifact that
    /// reds the equivalence rows. Only a row timeout above the dispatch
    /// budget makes the dispatch deadline the single decider in BOTH modes.
    ///
    /// The timeout path is covered deliberately by
    /// `whole_pool_execution_failures_are_named_denials_even_with_continue_policies`
    /// (250 ms budget, forever-looping child), not by these equivalence rows.
    #[cfg(unix)]
    pub(crate) const FIXTURE_ROW_TIMEOUT_SECS: u64 =
        FIXTURE_DISPATCH_BUDGET.as_secs() + FIXTURE_CHILD_START_ALLOWANCE_SECS;

    /// Compile-time pin of the single-clock invariant: `min(row.timeout,
    /// dispatch deadline)` may resolve to the DISPATCH deadline only, in row
    /// mode and pool mode alike. A row timeout at or below the dispatch
    /// budget hands row mode its own clock while pool mode completes — a
    /// wall-clock artifact in the equivalence rows. A const assertion (not a
    /// runtime test) keeps it out of clippy's `assertions_on_constants` and
    /// turns an invert into a BUILD failure.
    #[cfg(unix)]
    const _: () = assert!(
        FIXTURE_ROW_TIMEOUT_SECS > FIXTURE_DISPATCH_BUDGET.as_secs(),
        "row timeout must exceed the dispatch budget"
    );

    #[cfg(unix)]
    pub(crate) fn node_decision_fixture(
        block: bool,
    ) -> (tempfile::TempDir, GateDispatchArgs, Vec<u8>) {
        node_decision_fixture_with_pools(block, false)
    }

    #[cfg(unix)]
    fn node_decision_fixture_with_pools(
        block: bool,
        split: bool,
    ) -> (tempfile::TempDir, GateDispatchArgs, Vec<u8>) {
        let temp = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let repo = temp.path().join("repo");
        let hooks = repo.join(".claude/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let repo = repo.canonicalize().unwrap();
        let marker = serde_json::to_string(&repo.join("pool-row-markers")).unwrap();
        let child = serde_json::to_string(&repo.join("pool-child-count")).unwrap();
        let load = serde_json::to_string(&repo.join("unmatched-load")).unwrap();
        let effect = serde_json::to_string(&repo.join("unmatched-effect")).unwrap();
        let defaults: std::collections::BTreeMap<_, _> = Event::ALL
            .into_iter()
            .map(|event| (event.as_str(), event.default_policy()))
            .collect();
        let mut rows = Vec::new();
        let mut metadata = Vec::new();
        let mut files = Vec::new();
        for (index, (name, matcher, label)) in [
            ("decision", "*", "decision"),
            ("skipped", "Edit", "skipped"),
            ("unmatched", "Read", "unmatched"),
        ]
        .into_iter()
        .enumerate()
        {
            let file = format!(".claude/hooks/{name}.js");
            let id = registry::stable_row_id(Event::PreToolUse, matcher, &file);
            let deny = block && index == 0;
            let value = json!({"hookSpecificOutput":{"hookEventName":"PreToolUse",
                "permissionDecision":if deny {"deny"} else {"allow"}}});
            let top_level = if index == 2 {
                format!("fs.appendFileSync({load},'LOAD');")
            } else {
                String::new()
            };
            let body = if index == 2 {
                format!("fs.appendFileSync({effect},'EFFECT');")
            } else {
                format!("fs.appendFileSync({marker},{label:?});")
            };
            let source = r#"const fs=require('fs'); @LOAD@
module.exports=()=>{ @BODY@ return @VALUE@; };
if(require.main===module){let input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',()=>{
fs.appendFileSync(@CHILD@,'x');process.stdout.write(JSON.stringify(module.exports()));process.exitCode=@EXIT@;});}
"#.replace("@LOAD@", &top_level).replace("@BODY@", &body).replace("@VALUE@", &value.to_string())
                .replace("@CHILD@", &child).replace("@EXIT@", if deny {"2"} else {"0"});
            std::fs::write(repo.join(&file), source.as_bytes()).unwrap();
            let sha = registry::sha256(source.as_bytes());
            let pool = if split && index == 1 {
                "template"
            } else {
                "repo"
            };
            rows.push(json!({"id":id,"order":index+1,"event":"PreToolUse","matcher":matcher,
                "file":file,"file_sha256":sha,"on_incomplete":"deny","on_crash":"deny","on_timeout":"deny","timeout":FIXTURE_ROW_TIMEOUT_SECS,
                "source":if pool=="template" {"loom-template"} else {"repo-local"},"pool":pool,"deps":[],"surfaces":["claude"],
                "contract":{"payload_stdin":{"claude":"cc-hook-json"},
                    "protocol":{"kind":"permission-decision","exit_codes":[0,2],"exit_codes_computed":false,
                        "decision_fields":["permissionDecision"],"severity":"block"},
                    "form":"legacy","runtime":"node-subprocess","cwd_scope":"payload",
                    "side_effects":{"fs_writes":["pool-row-markers","pool-child-count","unmatched-load","unmatched-effect"],
                        "network":false,"spawns":[],"declared_by":"author"},"idempotent":false,"may_rewrite_input":false}}));
            metadata.push(
                json!({"id":id,"sha":sha,"source_path":file,"file":format!("./{name}.js"),"matcher":matcher,
                "code":if deny {2} else {0},"pool":pool}),
            );
            files.push(json!({"path":file,"sha256":sha,"bytes":source.len()}));
        }
        let mut runtimes = Vec::new();
        for (index, pool) in if split {
            vec![(0, "repo"), (1, "template")]
        } else {
            vec![(0, "repo")]
        } {
            let selected: Vec<_> = metadata
                .iter()
                .filter(|row| row["pool"] == pool)
                .cloned()
                .collect();
            let source = r#"const fs=require('fs'),crypto=require('crypto');const definitions=@ROWS@;
let input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',()=>{
fs.appendFileSync(@CHILD@,'x');const payload=JSON.parse(input);
const poolMode=!!process.argv[4];const contracts=poolMode?JSON.parse(process.argv[5]):definitions
.filter(row=>row.matcher==='*'||row.matcher===payload.tool_name).map(row=>({id:row.id,source_path:row.source_path,source_sha256:row.sha,timeout_secs:@TIMEOUT@}));
const replies=contracts.map(contract=>{const row=definitions.find(row=>row.id===contract.id);if(!row)throw Error('unknown row');
if(contract.source_path!==row.source_path||contract.source_sha256!==row.sha)throw Error('source binding');
const value=require(row.file)();return {id:row.id,source_sha256:row.sha,status:'executed',timeout_secs:contract.timeout_secs,
exit_code:row.code,stdout_b64:Buffer.from(JSON.stringify(value)).toString('base64'),stderr_b64:''};});
if(poolMode){process.stdout.write(JSON.stringify({schema:'csq.gate.pool.v1',pool:process.argv[3],event:process.argv[2],
payload_sha256:crypto.createHash('sha256').update(input).digest('hex'),status:'complete',rows:replies}));}
else{const denied=replies.some(row=>row.exit_code===2);process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:'PreToolUse',
permissionDecision:denied?'deny':'allow'}}));process.exitCode=denied?2:0;}});
"#.replace("@ROWS@", &serde_json::to_string(&selected).unwrap()).replace("@CHILD@", &child)
                .replace("@TIMEOUT@", &FIXTURE_ROW_TIMEOUT_SECS.to_string());
            let entry = format!(
                ".claude/hooks/runtime{}.js",
                if index == 0 {
                    String::new()
                } else {
                    index.to_string()
                }
            );
            std::fs::write(repo.join(&entry), source.as_bytes()).unwrap();
            let sha = registry::sha256(source.as_bytes());
            let deps: Vec<_> = rows
                .iter()
                .filter(|row| row["pool"] == pool)
                .map(|row| json!({"path":row["file"],"sha256":row["file_sha256"]}))
                .collect();
            runtimes.push(json!({"entry":entry,"entry_sha256":sha,"deps":deps}));
            files.push(json!({"path":entry,"sha256":sha,"bytes":source.len()}));
        }
        let mut registry = json!({"$id":"loom.hook-registry/v1","version":"1.0.0","content_sha256":"",
            "content_sha256_scheme":"RFC 8785 JCS","source_sha":"a".repeat(40),"generated_by":"test",
            "unknown_major_policy":"fail-closed","default_on_incomplete":defaults,"precedence":registry::PRECEDENCE,
            "runtimes":runtimes,"hooks":rows});
        registry["content_sha256"] =
            registry::sha256(&registry::canonical_content_bytes(&registry).unwrap()).into();
        let registry_bytes = serde_json::to_vec(&registry).unwrap();
        std::fs::write(repo.join(".claude/hook-registry.json"), &registry_bytes).unwrap();
        let pin = Pin::capture_operator_bound(
            &repo,
            &registry::sha256(&registry_bytes),
            csq_core::gate::pin::IntegrityPolicy::Hash,
        )
        .unwrap();
        let pin_path = temp.path().join("pin.json");
        pin.write_private(&pin_path).unwrap();
        let pins: Vec<_> = files.iter().map(|file| json!({"path":file["path"],"sha256":file["sha256"],"source":"runtime_closure"})).collect();
        let entries: Vec<_> = files.iter().map(|file| file["path"].clone()).collect();
        let adapter_dir = repo.join(".claude/hook-runtime/1.0.0");
        std::fs::create_dir_all(&adapter_dir).unwrap();
        let package = json!({"package":"loom-hook-runtime","version":"1.0.0","proposed_path":".claude/hook-runtime/1.0.0/",
            "invocation":"node runtime.js","commit_sha":"a".repeat(40),"commit_sha_convention":"pinned",
            "head_at_generation":"b".repeat(40),"runtime_clean_at_generation":true,"file_count":files.len(),"files":files,
            "verification":{"pins":pins,"runtime_closure":{"entry_points":entries,"reached_files":entries.len(),"gaps":[],"method":"lexical walk"}}});
        let adapter_path = adapter_dir.join("PACKAGE-MANIFEST.json");
        std::fs::write(&adapter_path, serde_json::to_vec(&package).unwrap()).unwrap();
        let adapter = VerifiedPackage::verify(&adapter_path, &repo).unwrap();
        let args = GateDispatchArgs {
            event: "PreToolUse".into(),
            repo: repo.clone(),
            pin: pin_path,
            adapter_manifest: adapter_path,
            expected_adapter_sha256: adapter.manifest_sha256().into(),
            row_audit: None,
            pool_audit: false,
        };
        let payload = serde_json::to_vec(
            &json!({"hook_event_name":"PreToolUse","cwd":repo,"tool_name":"Bash"}),
        )
        .unwrap();
        (temp, args, payload)
    }

    #[cfg(unix)]
    #[test]
    fn compiled_node_bridge_preserves_deny_and_allow_verdicts() {
        let _environment = PrivateEnvironment::new();
        let (_deny_temp, deny_args, deny_payload) = node_decision_fixture(true);
        let deny = dispatch_pool_fixture_bytes(
            &deny_args,
            deny_payload,
            deny_args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(deny.denied, "the real Node row must deny");
        assert_eq!(deny.exit_code, 2);
        assert_eq!(
            std::fs::read_to_string(deny_args.repo.join("pool-row-markers")).unwrap(),
            "decision"
        );

        let (_allow_temp, allow_args, allow_payload) = node_decision_fixture(false);
        let allow = dispatch_pool_fixture_bytes(
            &allow_args,
            allow_payload,
            allow_args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(
            !allow.denied,
            "a valid allow control prevents always-deny tests"
        );
        assert_eq!(allow.exit_code, 0);
        assert_eq!(
            std::fs::read_to_string(allow_args.repo.join("pool-row-markers")).unwrap(),
            "decision"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pool_executes_two_matched_rows_with_one_child_and_skips_unmatched_row() {
        let _environment = PrivateEnvironment::new();
        let (_temp, args, _payload) = node_decision_fixture(false);
        let payload = serde_json::to_vec(&json!({
            "hook_event_name": "PreToolUse",
            "cwd": args.repo,
            "tool_name": "Edit"
        }))
        .unwrap();
        let result = dispatch_pool_fixture_bytes(
            &args,
            payload,
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(!result.denied);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"x"
        );
        assert_eq!(
            std::fs::read_to_string(args.repo.join("pool-row-markers")).unwrap(),
            "decisionskipped"
        );
    }

    #[cfg(unix)]
    fn edit_payload(args: &GateDispatchArgs) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"hook_event_name":"PreToolUse", "cwd":args.repo, "tool_name":"Edit"}),
        )
        .unwrap()
    }
    #[cfg(unix)]
    fn assert_unmatched_never_loaded(repo: &Path) {
        assert!(
            !repo.join("unmatched-load").exists(),
            "unmatched module must not LOAD"
        );
        assert!(
            !repo.join("unmatched-effect").exists(),
            "unmatched function must not execute"
        );
    }
    #[cfg(unix)]
    fn audit_records(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    #[cfg(unix)]
    fn reseal_fixture(args: &mut GateDispatchArgs, modify: impl FnOnce(&mut serde_json::Value)) {
        let registry_path = args.repo.join(".claude/hook-registry.json");
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
        modify(&mut document);
        let mut package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&args.adapter_manifest).unwrap()).unwrap();
        for file in package["files"].as_array_mut().unwrap() {
            let bytes = std::fs::read(args.repo.join(file["path"].as_str().unwrap())).unwrap();
            file["sha256"] = registry::sha256(&bytes).into();
            file["bytes"] = bytes.len().into();
        }
        for row in document["hooks"].as_array_mut().unwrap() {
            row["file_sha256"] = registry::sha256(
                &std::fs::read(args.repo.join(row["file"].as_str().unwrap())).unwrap(),
            )
            .into();
        }
        for runtime in document["runtimes"].as_array_mut().unwrap() {
            runtime["entry_sha256"] = registry::sha256(
                &std::fs::read(args.repo.join(runtime["entry"].as_str().unwrap())).unwrap(),
            )
            .into();
            for dep in runtime["deps"].as_array_mut().unwrap() {
                dep["sha256"] = registry::sha256(
                    &std::fs::read(args.repo.join(dep["path"].as_str().unwrap())).unwrap(),
                )
                .into();
            }
        }
        for pin in package["verification"]["pins"].as_array_mut().unwrap() {
            pin["sha256"] = registry::sha256(
                &std::fs::read(args.repo.join(pin["path"].as_str().unwrap())).unwrap(),
            )
            .into();
        }
        document["content_sha256"] =
            registry::sha256(&registry::canonical_content_bytes(&document).unwrap()).into();
        let bytes = serde_json::to_vec(&document).unwrap();
        std::fs::write(&registry_path, &bytes).unwrap();
        Pin::capture_operator_bound(
            &args.repo,
            &registry::sha256(&bytes),
            csq_core::gate::pin::IntegrityPolicy::Hash,
        )
        .unwrap()
        .write_private(&args.pin)
        .unwrap();
        std::fs::write(
            &args.adapter_manifest,
            serde_json::to_vec(&package).unwrap(),
        )
        .unwrap();
        args.expected_adapter_sha256 = VerifiedPackage::verify(&args.adapter_manifest, &args.repo)
            .unwrap()
            .manifest_sha256()
            .into();
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_dispatch_stays_per_row_and_pool_activation_has_no_bypass() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(false);
        let result = dispatch_bytes(
            &args,
            edit_payload(&args),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(!result.denied);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"xx",
            "default command must remain two admitted row children, not pooled"
        );
        assert_unmatched_never_loaded(&args.repo);
        std::fs::remove_file(args.repo.join("pool-child-count")).unwrap();
        std::fs::remove_file(args.repo.join("pool-row-markers")).unwrap();
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("refused.ndjson"));
        args.pool_audit = true;
        assert!(matches!(
            dispatch_bytes(
                &args,
                edit_payload(&args),
                args.repo.clone(),
                Instant::now() + FIXTURE_DISPATCH_BUDGET
            ),
            Err(Refusal::PoolSafetyHold)
        ));
        assert!(!args.repo.join("pool-child-count").exists());
        assert!(
            !args.row_audit.unwrap().exists(),
            "unavailable proof must not create apparent pool evidence"
        );
    }

    #[cfg(unix)]
    #[test]
    fn actual_native_aggregate_matches_inactive_pool_and_counter_control_discriminates() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(false);
        let payload = edit_payload(&args);
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("rows.ndjson"));
        let pooled = dispatch_pool_fixture_bytes(
            &args,
            payload.clone(),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        let records = audit_records(args.row_audit.as_ref().unwrap());
        assert_eq!(records[0]["candidate_row_ids"].as_array().unwrap().len(), 3);
        assert_eq!(records[0]["matched_row_ids"].as_array().unwrap().len(), 2);
        assert_eq!(records[1]["rows"].as_array().unwrap().len(), 2);
        assert_eq!(records[2], json!({"type":"complete","records":1}));
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"x"
        );
        assert_unmatched_never_loaded(&args.repo);
        std::fs::remove_file(args.repo.join("pool-child-count")).unwrap();
        let package = VerifiedPackage::verify(&args.adapter_manifest, &args.repo).unwrap();
        let mut native = NodePoolRunner::new(package, ".claude/hooks/runtime.js")
            .unwrap()
            .with_environment(NodeEnvironment {
                path: std::env::var("PATH").ok(),
                home: std::env::var("HOME").ok(),
                tmpdir: Some(_environment._home.path().to_string_lossy().into_owned()),
                ..Default::default()
            });
        let native = native
            .run_event(
                registry::Pool::Repo,
                Event::PreToolUse,
                &payload,
                &args.repo,
                Instant::now() + FIXTURE_DISPATCH_BUDGET,
            )
            .unwrap();
        assert_eq!(native.stdout, pooled.stdout);
        assert_eq!(native.stderr, pooled.stderr);
        assert_eq!(native.exit_code, pooled.exit_code);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"x"
        );
        assert_unmatched_never_loaded(&args.repo);
        std::fs::remove_file(args.repo.join("pool-child-count")).unwrap();
        args.row_audit = None;
        let old_strategy = dispatch_bytes(
            &args,
            payload,
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert_eq!(old_strategy.stdout, pooled.stdout);
        assert_eq!(std::fs::read(args.repo.join("pool-child-count")).unwrap(),b"xx",
            "real old per-row strategy fails the same one-child denominator while preserving verdict");
    }

    #[cfg(unix)]
    #[test]
    fn unmatched_missing_registry_row_does_not_deny_edit_but_matched_missing_row_refuses_before_child(
    ) {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(false);
        let missing = ".claude/hooks/missing.js";
        // Authenticate this additional registry row while its source exists.
        // It is deliberately outside the complete, unchanged adapter package.
        std::fs::copy(
            args.repo.join(".claude/hooks/unmatched.js"),
            args.repo.join(missing),
        )
        .unwrap();
        reseal_fixture(&mut args, |registry| {
            let mut row = registry["hooks"][2].clone();
            row["order"] = 4.into();
            row["file"] = missing.into();
            row["id"] = registry::stable_row_id(Event::PreToolUse, "Read", missing).into();
            registry["hooks"].as_array_mut().unwrap().push(row);
        });
        std::fs::remove_file(args.repo.join(missing)).unwrap();
        let admitted = Pin::load_verify(&args.pin, &args.repo).unwrap();
        assert!(
            admitted.rows[3].admission.is_err(),
            "fixture really contains missing row admission"
        );
        VerifiedPackage::verify(&args.adapter_manifest, &args.repo).unwrap();
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("edit.ndjson"));
        let result = dispatch_bytes(
            &args,
            edit_payload(&args),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(
            !result.denied,
            "unmatched missing Read row cannot deny Edit"
        );
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"xx"
        );
        assert_unmatched_never_loaded(&args.repo);
        let records = audit_records(args.row_audit.as_ref().unwrap());
        assert_eq!(records[0]["candidate_row_ids"].as_array().unwrap().len(), 4);
        assert_eq!(records[0]["matched_row_ids"].as_array().unwrap().len(), 2);
        std::fs::remove_file(args.repo.join("pool-child-count")).unwrap();
        std::fs::remove_file(args.repo.join("pool-row-markers")).unwrap();
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("read.ndjson"));
        let payload = serde_json::to_vec(
            &json!({"hook_event_name":"PreToolUse","cwd":args.repo,"tool_name":"Read"}),
        )
        .unwrap();
        assert!(
            matches!(
                dispatch_bytes(
                    &args,
                    payload,
                    args.repo.clone(),
                    Instant::now() + FIXTURE_DISPATCH_BUDGET
                ),
                Err(Refusal::Adapter)
            ),
            "matched missing row remains refusal before every child"
        );
        assert!(!args.repo.join("pool-child-count").exists());
        assert!(!args.repo.join("pool-row-markers").exists());
        assert_unmatched_never_loaded(&args.repo);
        assert!(!args.row_audit.unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn production_preflight_admitted_matched_row_outside_package_refuses_before_every_child() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(false);
        let outside = ".claude/hooks/unpackaged.js";
        std::fs::copy(
            args.repo.join(".claude/hooks/skipped.js"),
            args.repo.join(outside),
        )
        .unwrap();
        reseal_fixture(&mut args, |registry| {
            let mut row = registry["hooks"][1].clone();
            row["order"] = 4.into();
            row["file"] = outside.into();
            row["id"] = registry::stable_row_id(Event::PreToolUse, "Edit", outside).into();
            row["on_incomplete"] = "continue".into();
            row["on_crash"] = "continue".into();
            row["on_timeout"] = "continue".into();
            row["contract"]["protocol"]["severity"] = "advise".into();
            registry["hooks"].as_array_mut().unwrap().push(row);
        });
        let admitted = Pin::load_verify(&args.pin, &args.repo).unwrap();
        let source = admitted.rows[3].admission.as_ref().unwrap();
        let package = VerifiedPackage::verify(&args.adapter_manifest, &args.repo).unwrap();
        assert!(
            package.bind_verified_bytes(source).is_err(),
            "coherent fixture isolates Pin/package byte authority mismatch"
        );
        assert!(args.repo.join(outside).is_file());
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("unbound.ndjson"));
        let result = dispatch_bytes(
            &args,
            edit_payload(&args),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        );
        assert!(
            matches!(result, Err(Refusal::Adapter)),
            "Pin-admitted matched source outside package must refuse regardless of Continue"
        );
        assert!(
            !args.repo.join("pool-child-count").exists(),
            "no earlier matched child may start"
        );
        assert!(!args.repo.join("pool-row-markers").exists());
        assert!(!args.row_audit.unwrap().exists());
        assert_unmatched_never_loaded(&args.repo);
    }

    #[cfg(unix)]
    #[test]
    fn production_preflight_unsupported_matcher_preserves_continue_without_child() {
        let _environment = PrivateEnvironment::new();
        let (_temp, mut args, _) = node_decision_fixture(false);
        reseal_fixture(&mut args, |registry| {
            for row in registry["hooks"].as_array_mut().unwrap() {
                let pattern = "(?=Edit)";
                row["matcher"] = pattern.into();
                row["id"] = registry::stable_row_id(
                    Event::PreToolUse,
                    pattern,
                    row["file"].as_str().unwrap(),
                )
                .into();
                row["on_incomplete"] = "continue".into();
                row["on_crash"] = "continue".into();
                row["on_timeout"] = "continue".into();
                row["contract"]["protocol"]["severity"] = "advise".into();
            }
        });
        let result = dispatch_bytes(
            &args,
            edit_payload(&args),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(
            !result.denied,
            "UnsupportedPattern must retain per-row Continue fold"
        );
        assert!(!args.repo.join("pool-child-count").exists());
        assert!(!args.repo.join("pool-row-markers").exists());
        assert_unmatched_never_loaded(&args.repo);
    }

    #[cfg(unix)]
    #[test]
    fn production_preflight_matcher_timeout_retains_continue_fold_without_child() {
        let _environment = PrivateEnvironment::new();
        let (_temp, mut args, _) = node_decision_fixture(false);
        reseal_fixture(&mut args, |registry| {
            for row in registry["hooks"].as_array_mut().unwrap() {
                row["on_incomplete"] = "continue".into();
                row["on_crash"] = "continue".into();
                row["on_timeout"] = "continue".into();
                row["contract"]["protocol"]["severity"] = "advise".into();
            }
        });
        struct TimeoutMatcher;
        impl Matcher for TimeoutMatcher {
            fn matches(
                &mut self,
                _: Event,
                _: &str,
                _: &serde_json::Value,
                _: Instant,
            ) -> Result<bool, csq_core::gate::matcher::MatchError> {
                Err(csq_core::gate::matcher::MatchError::Timeout)
            }
        }
        let verified = Pin::load_verify(&args.pin, &args.repo).unwrap();
        let package = VerifiedPackage::verify(&args.adapter_manifest, &args.repo).unwrap();
        let input = ParsedPayload::parse(
            Event::PreToolUse,
            Surface::Claude,
            edit_payload(&args),
            args.repo.clone(),
        )
        .unwrap();
        let candidates = verified.rows.iter().collect::<Vec<_>>();
        let deadline = Instant::now() + FIXTURE_DISPATCH_BUDGET;
        assert!(preflight_matched_rows(
            &candidates,
            &package,
            Event::PreToolUse,
            &input.value,
            &mut TimeoutMatcher,
            deadline
        )
        .unwrap()
        .is_empty());
        let mut runner = NodeRowRunner::new(package);
        let result = dispatch::dispatch(
            &input,
            &verified,
            &mut runner,
            &mut TimeoutMatcher,
            None,
            deadline,
        );
        assert!(
            !result.denied,
            "Timeout matcher remains per-row Continue, never a global preflight refusal"
        );
        assert!(!args.repo.join("pool-child-count").exists());
        assert_unmatched_never_loaded(&args.repo);
    }

    #[cfg(unix)]
    #[test]
    fn production_row_audit_matches_actual_pool_rows_without_claiming_pooled_children() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(false);
        let payload = edit_payload(&args);
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("pool.ndjson"));
        let pooled = dispatch_pool_fixture_bytes(
            &args,
            payload.clone(),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        let pool_records = audit_records(args.row_audit.as_ref().unwrap());
        std::fs::remove_file(args.repo.join("pool-child-count")).unwrap();
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("row.ndjson"));
        let per_row = dispatch_bytes(
            &args,
            payload,
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert_eq!(per_row.stdout, pooled.stdout);
        assert_eq!(per_row.stderr, pooled.stderr);
        assert_eq!(per_row.exit_code, pooled.exit_code);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"xx"
        );
        let row_records = audit_records(args.row_audit.as_ref().unwrap());
        assert_eq!(row_records[0]["execution_mode"], "row");
        assert_eq!(row_records[0]["schema"], "csq.gate-row-audit.v2");
        assert_eq!(row_records[3], json!({"type":"complete","records":2}));
        for (actual, pooled) in row_records[1..3]
            .iter()
            .zip(pool_records[1]["rows"].as_array().unwrap())
        {
            assert_eq!(actual["type"], "row");
            assert!(actual.get("child_started").is_none());
            for field in [
                "row_id",
                "source_sha256",
                "status",
                "exit_code",
                "stdout_bytes",
                "stdout_sha256",
                "stderr_bytes",
                "stderr_sha256",
            ] {
                assert_eq!(
                    actual[field], pooled[field],
                    "actual standalone vs actual inside-pool {field}"
                );
            }
        }
        assert_unmatched_never_loaded(&args.repo);
    }

    /// The audit-vs-pool equivalence must not be decided by the row clock.
    /// Induced delay: the shared decision row busy-waits 3 s, longer than the
    /// old 2 s fixture budget. With the derived fixture budget the row deadline
    /// is the enclosing dispatch deadline in BOTH modes, so a live but slowly
    /// scheduled child cannot turn into `on_timeout: "deny"` in one mode only.
    #[cfg(unix)]
    #[test]
    fn audit_equivalence_survives_a_row_child_slower_than_the_old_two_second_budget() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(false);
        let decision = args.repo.join(".claude/hooks/decision.js");
        let source = std::fs::read_to_string(&decision).unwrap();
        let slow = source.replacen(
            "module.exports=()=>{",
            "module.exports=()=>{const end=Date.now()+3000;while(Date.now()<end){}",
            1,
        );
        assert_ne!(
            slow, source,
            "the induced delay must reach the decision row"
        );
        let old_sha = registry::sha256(source.as_bytes());
        let new_sha = registry::sha256(slow.as_bytes());
        std::fs::write(&decision, slow.as_bytes()).unwrap();
        // The pool runtime embeds each row's admission sha at fixture creation
        // and refuses a contract whose source binding no longer matches. Re-bind
        // the edited row before resealing, or the pool child exits immediately
        // and the delay never executes.
        let runtime = args.repo.join(".claude/hooks/runtime.js");
        let runtime_source = std::fs::read_to_string(&runtime).unwrap();
        assert!(
            runtime_source.contains(&old_sha),
            "the pool runtime must embed the decision row's admission sha"
        );
        std::fs::write(&runtime, runtime_source.replace(&old_sha, &new_sha)).unwrap();
        reseal_fixture(&mut args, |_| {});
        let payload = edit_payload(&args);
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("pool.ndjson"));
        let budget = FIXTURE_DISPATCH_BUDGET;
        let pooled = dispatch_pool_fixture_bytes(
            &args,
            payload.clone(),
            args.repo.clone(),
            Instant::now() + budget,
        )
        .unwrap();
        std::fs::remove_file(args.repo.join("pool-child-count")).unwrap();
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("row.ndjson"));
        let per_row =
            dispatch_bytes(&args, payload, args.repo.clone(), Instant::now() + budget).unwrap();
        assert_eq!(per_row.stdout, pooled.stdout);
        assert_eq!(per_row.stderr, pooled.stderr);
        assert_eq!(per_row.exit_code, pooled.exit_code);
    }

    #[cfg(unix)]
    #[test]
    fn two_actual_pools_start_exactly_two_children_and_unmatched_module_is_absent() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture_with_pools(false, true);
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("rows.ndjson"));
        let result = dispatch_pool_fixture_bytes(
            &args,
            edit_payload(&args),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(!result.denied);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"xx"
        );
        assert_eq!(
            std::fs::read(args.repo.join("pool-row-markers")).unwrap(),
            b"decisionskipped"
        );
        assert_unmatched_never_loaded(&args.repo);
        let records = audit_records(args.row_audit.as_ref().unwrap());
        assert_eq!(records.len(), 4);
        assert_eq!(records[1]["pool"], "repo");
        assert_eq!(records[2]["pool"], "template");
        assert_eq!(records[3], json!({"type":"complete","records":2}));
    }

    /// The pool fixture's POSITIVE path must not be decided by the old 5 s
    /// enclosing budget: a pool child that is alive but scheduled slowly must
    /// not turn the whole dispatch into `PoolIncomplete`. Induced delay: the
    /// shared decision row busy-waits 6 s, longer than the former 5 s budget;
    /// the derived [`FIXTURE_DISPATCH_BUDGET`] keeps the dispatch clock out of
    /// the child's way.
    #[cfg(unix)]
    #[test]
    fn a_pool_child_slower_than_the_old_five_second_budget_still_completes() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture_with_pools(false, true);
        let decision = args.repo.join(".claude/hooks/decision.js");
        let source = std::fs::read_to_string(&decision).unwrap();
        // The delay is the named constant in milliseconds, so the budget
        // derivation above and the induced fault cannot drift apart.
        let delay_ms = FIXTURE_INDUCED_CHILD_DELAY_SECS * 1000;
        let slow = source.replacen(
            "module.exports=()=>{",
            &format!(
                "module.exports=()=>{{const end=Date.now()+{delay_ms};while(Date.now()<end){{}}"
            ),
            1,
        );
        assert_ne!(
            slow, source,
            "the induced delay must reach the decision row"
        );
        let old_sha = registry::sha256(source.as_bytes());
        let new_sha = registry::sha256(slow.as_bytes());
        std::fs::write(&decision, slow.as_bytes()).unwrap();
        // Each pool runtime embeds the admission sha of its own rows; rebind the
        // edited row wherever it is embedded before resealing.
        for runtime_name in [".claude/hooks/runtime.js", ".claude/hooks/runtime1.js"] {
            let runtime = args.repo.join(runtime_name);
            let runtime_source = std::fs::read_to_string(&runtime).unwrap();
            if runtime_source.contains(&old_sha) {
                std::fs::write(&runtime, runtime_source.replace(&old_sha, &new_sha)).unwrap();
            }
        }
        reseal_fixture(&mut args, |_| {});
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("rows.ndjson"));
        // The production 9 s ceiling would otherwise clamp the fixture budget
        // and decide this deliberately slow child on a saturated host; the
        // override makes the FIXTURE budget the governing clock.
        let result = with_event_budget_override(FIXTURE_DISPATCH_BUDGET, || {
            dispatch_pool_fixture_bytes(
                &args,
                edit_payload(&args),
                args.repo.clone(),
                Instant::now() + FIXTURE_DISPATCH_BUDGET,
            )
        })
        .unwrap();
        assert!(!result.denied);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"xx"
        );
    }

    /// The fixture seam: WITHOUT the override the production 9 s ceiling
    /// clamps any larger fixture budget; WITH it the fixture budget governs.
    /// This is what lets a deliberately slow child complete on a saturated
    /// host instead of being decided by the production ceiling.
    ///
    /// RED mutation: make `effective_deadline` ignore the override -> the
    /// overridden arm falls back to ~9 s and the second assertion fails.
    #[cfg(unix)]
    #[test]
    fn event_budget_override_lifts_the_production_ceiling_for_a_fixture() {
        let start = Instant::now();
        let ceiling = effective_deadline(start + FIXTURE_DISPATCH_BUDGET, Event::PreToolUse);
        assert!(
            ceiling.saturating_duration_since(start) < Duration::from_secs(15),
            "the production ceiling clamps the fixture budget to ~9 s"
        );
        let overridden = with_event_budget_override(FIXTURE_DISPATCH_BUDGET, || {
            effective_deadline(start + FIXTURE_DISPATCH_BUDGET, Event::PreToolUse)
        });
        assert!(
            overridden.saturating_duration_since(start) > Duration::from_secs(60),
            "the override must let the fixture budget (not the 9 s ceiling) govern"
        );
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_ledger_holds_all_pools_before_any_child() {
        let _environment = PrivateEnvironment::new();
        let (temp, args, _) = node_decision_fixture_with_pools(false, true);
        let handle = temp.path().canonicalize().unwrap().join("handle");
        std::fs::create_dir(&handle).unwrap();
        std::fs::write(handle.join("gate-demotions.jsonl"), b"not durable state").unwrap();
        std::env::set_var("CSQ_HANDLE_DIR", &handle);
        assert!(matches!(
            dispatch_pool_fixture_bytes(
                &args,
                edit_payload(&args),
                args.repo.clone(),
                Instant::now() + FIXTURE_DISPATCH_BUDGET
            ),
            Err(Refusal::PoolSafetyHold)
        ));
        assert!(!args.repo.join("pool-child-count").exists());
        assert!(!args.repo.join("pool-row-markers").exists());
    }

    #[cfg(unix)]
    #[test]
    fn demoted_repo_row_really_runs_standalone_and_cannot_claim_pooled_audit() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(false);
        let handle = temp.path().canonicalize().unwrap().join("handle");
        std::fs::create_dir(&handle).unwrap();
        let id = registry::stable_row_id(Event::PreToolUse, "*", ".claude/hooks/decision.js");
        let event = json!({"row_id":id,"crashes":3,"demoted_at_ms":1});
        std::fs::write(handle.join("gate-demotions.jsonl"), format!("{event}\n")).unwrap();
        std::env::set_var("CSQ_HANDLE_DIR", &handle);
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("rows.ndjson"));
        let payload = serde_json::to_vec(
            &json!({"hook_event_name":"PreToolUse","cwd":args.repo,"tool_name":"Bash"}),
        )
        .unwrap();
        let result = dispatch_pool_fixture_bytes(
            &args,
            payload,
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(!result.denied);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"x"
        );
        assert_eq!(
            std::fs::read(args.repo.join("pool-row-markers")).unwrap(),
            b"decision"
        );
        let records = audit_records(args.row_audit.as_ref().unwrap());
        assert_eq!(records[1]["type"], "process_fallback");
        assert_eq!(records[1]["status"], "returned");
        assert_eq!(records[2], json!({"type":"complete","records":1}));
        assert_unmatched_never_loaded(&args.repo);
    }

    #[cfg(unix)]
    #[test]
    fn whole_pool_execution_failures_are_named_denials_even_with_continue_policies() {
        let _environment = PrivateEnvironment::new();
        for (fault, source) in [("crash", "process.kill(process.pid,'SIGKILL');"),
            ("incomplete", "process.stdin.resume();process.stdin.on('end',()=>process.stdout.write('not-json'));"),
            ("timeout", "setInterval(()=>{},1000);")] {
            let (temp,mut args,_)=node_decision_fixture(false);
            std::fs::write(args.repo.join(".claude/hooks/runtime.js"),source).unwrap();
            reseal_fixture(&mut args, |registry| for row in registry["hooks"].as_array_mut().unwrap() {
                row["on_incomplete"]="continue".into();row["on_crash"]="continue".into();row["on_timeout"]="continue".into();
                row["contract"]["protocol"]["severity"]="advise".into();
            });
            args.row_audit=Some(temp.path().canonicalize().unwrap().join("fault.ndjson"));
            let budget=if fault=="timeout" {Duration::from_millis(250)} else {FIXTURE_DISPATCH_BUDGET};
            let start=Instant::now();
            // The fault rows use the fixture budget here (the timeout row
            // still passes its own 250 ms deadline) so the elapsed assertion
            // below compares against the SAME clock the dispatch runs under.
            let refusal=with_event_budget_override(FIXTURE_DISPATCH_BUDGET, || {
                dispatch_pool_fixture_bytes(&args,edit_payload(&args),args.repo.clone(),Instant::now()+budget)
            }).unwrap_err();
            // The refusal must be named from the FAULT, not from the enclosing
            // clock: a broken fault detector that lets the row run to the
            // deadline still denies (PoolIncomplete) and would otherwise pass.
            // Half the dispatch budget is a CHOSEN margin — above the startup
            // allowance by construction, far below the deadline — so a
            // detected fault cannot be confused with a deadline expiry.
            if fault!="timeout" {
                assert!(start.elapsed()<FIXTURE_DISPATCH_BUDGET/2,
                    "the {fault} fault must be DETECTED, not caught by the deadline: elapsed {:?}",start.elapsed());
            }
            let mut out=Vec::new();write_dispatch_refusal(&mut out,refusal).unwrap();
            let value:serde_json::Value=serde_json::from_slice(&out).unwrap();
            assert_eq!(value["decision"],"block","actual {fault} must deny");
            assert_eq!(value["reason"],"csq_gate_pool_incomplete","actual {fault} must be named");
            assert_eq!(value["message"],"csq Gate pool execution incomplete — action denied");
            assert_eq!(audit_records(args.row_audit.as_ref().unwrap()).len(),1,"no fabricated row return or completion");
        }
    }

    #[cfg(unix)]
    #[test]
    fn actual_denying_sibling_then_held_pipe_refuses_three_times_before_fourth_row_fallback() {
        let _environment = PrivateEnvironment::new();
        let (temp, mut args, _) = node_decision_fixture(true);
        let handle = temp.path().canonicalize().unwrap().join("handle");
        std::fs::create_dir(&handle).unwrap();
        std::env::set_var("CSQ_HANDLE_DIR", &handle);
        let counter = serde_json::to_string(&args.repo.join("pool-child-count")).unwrap();
        // Both actual modules execute, including the deny sibling. Exit 1 with
        // an inherited pipe cannot yield a complete authenticated pool envelope.
        let source=format!("const fs=require('fs');let input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',()=>{{fs.appendFileSync({counter},'x');require('./decision.js')();require('./skipped.js')();require('child_process').spawn(process.execPath,['-e','setInterval(()=>{{}},1000)'],{{stdio:['ignore','inherit','inherit']}});process.exit(1);}});");
        std::fs::write(args.repo.join(".claude/hooks/runtime.js"), source).unwrap();
        reseal_fixture(&mut args, |registry| {
            for row in registry["hooks"].as_array_mut().unwrap() {
                row["on_incomplete"] = "continue".into();
                row["on_crash"] = "continue".into();
                row["on_timeout"] = "continue".into();
                row["contract"]["protocol"]["severity"] = "advise".into();
            }
        });
        for attempt in 1..=3 {
            let refusal = dispatch_pool_fixture_bytes(
                &args,
                edit_payload(&args),
                args.repo.clone(),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap_err();
            let mut out = Vec::new();
            write_dispatch_refusal(&mut out, refusal).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(
                value["reason"], "csq_gate_pool_incomplete",
                "failed call {attempt} must deny without sibling replay"
            );
            assert_eq!(
                value["message"],
                "csq Gate pool execution incomplete — action denied"
            );
            assert_eq!(
                std::fs::read(args.repo.join("pool-child-count")).unwrap(),
                vec![b'x'; attempt]
            );
            assert_eq!(
                std::fs::read(args.repo.join("pool-row-markers")).unwrap(),
                b"decisionskipped".repeat(attempt)
            );
            assert_unmatched_never_loaded(&args.repo);
        }
        args.row_audit = Some(temp.path().canonicalize().unwrap().join("fallback.ndjson"));
        let result = dispatch_pool_fixture_bytes(
            &args,
            edit_payload(&args),
            args.repo.clone(),
            Instant::now() + FIXTURE_DISPATCH_BUDGET,
        )
        .unwrap();
        assert!(
            result.denied,
            "actual standalone deny remains authoritative"
        );
        assert_eq!(result.exit_code, 2);
        assert_eq!(
            std::fs::read(args.repo.join("pool-child-count")).unwrap(),
            b"xxxxx"
        );
        assert_eq!(
            std::fs::read(args.repo.join("pool-row-markers")).unwrap(),
            b"decisionskipped".repeat(4)
        );
        let records = audit_records(args.row_audit.as_ref().unwrap());
        assert_eq!(records[1]["type"], "process_fallback");
        assert_eq!(records[1]["exit_code"], 2);
        assert_eq!(records[2]["type"], "process_fallback");
        assert_eq!(records[3], json!({"type":"complete","records":2}));
        assert_unmatched_never_loaded(&args.repo);
    }

    #[cfg(unix)]
    #[test]
    fn malformed_context_and_outer_exit_two_refuse_even_when_all_row_policies_continue() {
        let _environment = PrivateEnvironment::new();
        for fault in ["payload", "source", "outer2"] {
            let (_temp, mut args, _) = node_decision_fixture(false);
            let runtime = args.repo.join(".claude/hooks/runtime.js");
            let source = std::fs::read_to_string(&runtime).unwrap();
            let changed = match fault {
                "payload" => source.replace(
                    "crypto.createHash('sha256').update(input).digest('hex')",
                    "'bad'",
                ),
                "source" => source.replace("source_sha256:row.sha", "source_sha256:'bad'"),
                _ => source.replace("if(poolMode){", "if(poolMode){process.exitCode=2;"),
            };
            // Context mutation remains valid JSON; refusal must come from exact binding.
            std::fs::write(&runtime, changed).unwrap();
            reseal_fixture(&mut args, |registry| {
                for row in registry["hooks"].as_array_mut().unwrap() {
                    row["on_incomplete"] = "continue".into();
                    row["on_crash"] = "continue".into();
                    row["on_timeout"] = "continue".into();
                    row["contract"]["protocol"]["severity"] = "advise".into();
                }
            });
            assert!(
                matches!(
                    dispatch_pool_fixture_bytes(
                        &args,
                        edit_payload(&args),
                        args.repo.clone(),
                        Instant::now() + FIXTURE_DISPATCH_BUDGET
                    ),
                    Err(Refusal::PoolIncomplete)
                ),
                "{fault} cannot become Continue"
            );
        }
    }

    #[test]
    fn pool_diagnostic_does_not_change_other_refusal_responses() {
        for refusal in [
            Refusal::InvalidInput,
            Refusal::Pin,
            Refusal::Adapter,
            Refusal::Deadline,
        ] {
            let mut out = Vec::new();
            write_dispatch_refusal(&mut out, refusal).unwrap();
            assert_eq!(
                out,
                b"{\"decision\":\"block\",\"reason\":\"csq_gate_refused\"}\n"
            );
        }
        let mut out = Vec::new();
        write_dispatch_refusal(&mut out, Refusal::PoolSafetyHold).unwrap();
        assert_eq!(
            out,
            b"{\"decision\":\"block\",\"reason\":\"csq_gate_pool_safety_hold\"}\n"
        );
    }

    struct Blocked(mpsc::Receiver<()>);
    impl Read for Blocked {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0
                .recv()
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            Ok(0)
        }
    }

    #[test]
    fn refusal_writer_is_independent_of_stdin_fixture() {
        let mut out = Vec::new();
        write_refusal(&mut out).unwrap();
        assert_eq!(
            out,
            b"{\"decision\":\"block\",\"reason\":\"csq_gate_refused\"}\n"
        );
        let mut input = Cursor::new(Vec::<u8>::new());
        assert_eq!(input.read_to_end(&mut Vec::new()).unwrap(), 0);
    }
}
