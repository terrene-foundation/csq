//! `csq exec --json` (`csq.exec.v1`) — a single non-interactive completion, and
//! `csq sdk capabilities --json` (`csq.capabilities.v1`) — op discovery.
//!
//! `csq exec` is a **spawn-capture** executor (SDK-plan corrected ground truth #1): it
//! spawns `claude --print --output-format json`, captures the child's stdout, parses it
//! through the pure [`csq_core::sdk::parse_claude_json`] adapter, and re-emits the
//! result as a single [`csq_core::sdk`] envelope line. It is emphatically NOT the
//! `csq run` path — `run` ends in `exec_or_spawn` → `Command::exec`, which REPLACES the
//! csq process image so csq never sees the child's stdout. `exec` shares `run`'s
//! credential / handle-dir / keychain / env resolution but never calls `exec_or_spawn`.
//!
//! Invariants honored (SDK-plan cross-shard rules):
//! - **R3** — the ONLY stdout writer is [`csq_core::sdk::emit`]; every code path here,
//!   success or failure, routes through it. Diagnostics from reused helpers go to
//!   stderr (tracing). There are no `println!`s in this module's call graph.
//! - **R2** — every failure is an enveloped [`SdkError`] with a closed `code` and a
//!   `RedactedString` message; provider/slot and prompt/stdin mutual-exclusion are
//!   validated in code (emitting `invalid_input`) rather than via clap `conflicts_with`
//!   so the consumer always receives a JSON envelope, never a bare clap error.
//! - **H3** — the child is spawned with the parent env stripped
//!   ([`super::run::strip_sensitive_env`]), the binary resolved via
//!   [`find_claude_binary`] (never a bare `Command::new("claude")` — memory
//!   `feedback_find_claude_binary_at_all_spawn_sites`), the prompt passed as an argv
//!   value (no shell), and tools left default-closed (no `--dangerously-skip-permissions`).
//! - **HIGH-3** — the child is killed on `--timeout` expiry; on Linux it is also killed
//!   on parent death via `PR_SET_PDEATHSIG`.
//!
//! ## Ground-truth deviation from the plan (spec-accuracy)
//! The plan listed `--max-tokens?` as an exec input. Claude Code's `--print` mode
//! exposes no output-token cap, so S1's Claude adapter does NOT surface `--max-tokens`
//! — exposing a flag that silently does nothing would violate `rules/spec-accuracy.md`.
//! It returns when an adapter that supports it lands (native/direct-API).

use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Serialize;

use csq_core::accounts::login::find_claude_binary;
use csq_core::cli_deps::sanitize::redact_home_prefix;
use csq_core::sdk::{
    self, Completion, Envelope, SdkError, SdkErrorCode, SCHEMA_CAPABILITIES_V1, SCHEMA_EXEC_V1,
};
use csq_core::types::AccountNum;

/// The one provider `csq.exec.v1` grounds today (S1 Claude adapter).
const CLAUDE_PROVIDER: &str = "claude";

/// Parsed `csq exec` arguments (clap-populated in `cli::mod`).
pub struct ExecArgs {
    /// Positional prompt. Mutually exclusive with `stdin`.
    pub prompt: Option<String>,
    /// Read the prompt from stdin instead of the positional argument.
    pub stdin: bool,
    /// Target a provider by name; resolves to a healthy slot. XOR `slot`.
    pub provider: Option<String>,
    /// Target a specific slot (1-999). XOR `provider`.
    pub slot: Option<u16>,
    /// Model alias/id to request (`opus`, `sonnet`, or a full id). Optional.
    pub model: Option<String>,
    /// System prompt to append (maps to `--append-system-prompt`).
    pub system: Option<String>,
    /// Correlation id echoed back verbatim on the envelope.
    pub id: Option<String>,
    /// Seconds to wait before killing the child.
    pub timeout_secs: u64,
}

/// The `csq.exec.v1` success payload (completion-core embedded per S0).
#[derive(Debug, Serialize)]
struct ExecPayload {
    completion: Completion,
}

/// `csq exec` entry point. Emits exactly one `csq.exec.v1` envelope line and exits with
/// `0` on success, non-zero on any failure. Never returns normally (always `exit`s
/// through [`sdk::emit`]).
pub fn handle(base_dir: &Path, claude_home: &Path, args: ExecArgs) -> Result<()> {
    let id = args.id.clone();
    let result = run_exec(base_dir, claude_home, &args);
    let code = match result {
        Ok(completion) => sdk::emit(&Envelope::success(
            SCHEMA_EXEC_V1,
            id,
            ExecPayload { completion },
        ))?,
        Err(err) => sdk::emit(&Envelope::<ExecPayload>::failure(SCHEMA_EXEC_V1, id, err))?,
    };
    std::process::exit(code);
}

/// `csq sdk capabilities` entry point — emits the `csq.capabilities.v1` envelope.
pub fn handle_capabilities() -> Result<()> {
    let env = csq_core::sdk::capabilities::build();
    debug_assert_eq!(env.schema, SCHEMA_CAPABILITIES_V1);
    let code = sdk::emit(&env)?;
    std::process::exit(code);
}

/// The fallible core: resolve inputs → resolve slot → spawn-capture → parse. Every
/// error is an [`SdkError`] so the caller can wrap it in a failure envelope.
fn run_exec(base_dir: &Path, claude_home: &Path, args: &ExecArgs) -> Result<Completion, SdkError> {
    let prompt = resolve_prompt(args)?;
    let slot = resolve_slot(base_dir, args)?;

    let bin = find_claude_binary().ok_or_else(|| {
        SdkError::trusted(
            SdkErrorCode::SpawnFailed,
            "claude binary not found on PATH — install Claude Code first",
        )
    })?;

    // Ephemeral handle dir (term-<pid>): credential symlinks + keychain mirror, exactly
    // as `csq run` sets up, so the spawned claude authenticates as this slot. Reconciler
    // reaps it by liveness if we crash; we best-effort remove it on the happy path.
    let pid = std::process::id();
    let handle_dir = csq_core::session::create_handle_dir(base_dir, claude_home, slot, pid)
        .map_err(|e| {
            SdkError::new(
                SdkErrorCode::Internal,
                format!(
                    "failed to create handle dir: {}",
                    redact_home_prefix(&e.to_string())
                ),
            )
        })?;
    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    // CC reads OAuth keychain-first (memory discovery_cc_keychain_first_credential_read);
    // mirror the fresh token into the keychain item keyed by CLAUDE_CONFIG_DIR.
    // Best-effort — a keychain miss falls back to the symlinked file (SSH/non-macOS).
    let _ = csq_core::credentials::keychain::sync_handle_dir(&handle_dir_abs);

    let outcome = spawn_capture(
        &bin,
        &handle_dir_abs,
        &prompt,
        args,
        Duration::from_secs(args.timeout_secs),
    );

    // Best-effort cleanup of the ephemeral handle dir (reconciler is the backstop).
    let _ = std::fs::remove_dir_all(&handle_dir);

    let outcome = outcome?;
    parse_outcome(outcome, args.timeout_secs)
}

/// Positional prompt XOR stdin. Both-or-neither → `invalid_input`. Empty → `invalid_input`.
fn resolve_prompt(args: &ExecArgs) -> Result<String, SdkError> {
    let prompt = match (args.prompt.as_deref(), args.stdin) {
        (Some(_), true) => {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "provide the prompt as a positional argument OR --stdin, not both",
            ))
        }
        (None, false) => {
            return Err(SdkError::trusted(
                SdkErrorCode::InvalidInput,
                "no prompt: pass a positional prompt or --stdin",
            ))
        }
        (Some(p), false) => p.to_string(),
        (None, true) => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).map_err(|e| {
                SdkError::new(
                    SdkErrorCode::InvalidInput,
                    format!("failed to read stdin: {e}"),
                )
            })?;
            buf
        }
    };
    if prompt.trim().is_empty() {
        return Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "prompt must not be empty",
        ));
    }
    Ok(prompt)
}

/// `--provider` XOR `--slot`. Both-or-neither → `invalid_input`. A slot/provider that
/// does not resolve to a Claude surface → `unsupported` / `no_healthy_slot`.
fn resolve_slot(base_dir: &Path, args: &ExecArgs) -> Result<AccountNum, SdkError> {
    match (args.slot, args.provider.as_deref()) {
        (Some(_), Some(_)) => Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "specify --slot OR --provider, not both",
        )),
        (None, None) => Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "specify a target: --slot N or --provider claude",
        )),
        (Some(n), None) => {
            let slot = AccountNum::try_from(n).map_err(|e| {
                SdkError::new(SdkErrorCode::InvalidInput, format!("invalid slot {n}: {e}"))
            })?;
            if !slot_serves_claude(base_dir, slot) {
                return Err(SdkError::trusted(
                    SdkErrorCode::Unsupported,
                    "csq.exec.v1 supports Claude slots only; this slot is codex/gemini/3P",
                ));
            }
            Ok(slot)
        }
        (None, Some(provider)) => {
            if !provider.eq_ignore_ascii_case(CLAUDE_PROVIDER) {
                return Err(SdkError::trusted(
                    SdkErrorCode::ProviderNotFound,
                    "csq.exec.v1 supports only --provider claude",
                ));
            }
            resolve_healthy_claude_slot(base_dir)
        }
    }
}

/// True iff `slot` resolves to the Claude surface (not codex/gemini/3P). Mirrors
/// `run::surface_cli_for_slot`'s classification without exposing that private helper.
fn slot_serves_claude(base_dir: &Path, slot: AccountNum) -> bool {
    use csq_core::providers::catalog::Surface;
    let codex = csq_core::credentials::file::canonical_path_for(base_dir, slot, Surface::Codex);
    if std::fs::symlink_metadata(&codex).is_ok() {
        return false;
    }
    if let Some(uuid) = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        let uuid_codex =
            csq_core::accounts::identity_store::credentials_codex_path_for(base_dir, uuid);
        if std::fs::symlink_metadata(&uuid_codex).is_ok() {
            return false;
        }
    }
    let gemini = csq_core::credentials::file::canonical_path_for(base_dir, slot, Surface::Gemini);
    if std::fs::symlink_metadata(&gemini).is_ok() {
        return false;
    }
    true
}

/// Pick the first healthy Anthropic slot: authenticated, not broker-failed.
fn resolve_healthy_claude_slot(base_dir: &Path) -> Result<AccountNum, SdkError> {
    for acc in csq_core::accounts::discovery::discover_anthropic(base_dir) {
        let Ok(slot) = AccountNum::try_from(acc.id) else {
            continue;
        };
        if csq_core::refresh::sentinel::is_broker_failed(base_dir, slot) {
            continue;
        }
        return Ok(slot);
    }
    Err(SdkError::trusted(
        SdkErrorCode::NoHealthySlot,
        "no healthy Claude slot available (all are logged out or broker-failed)",
    ))
}

/// The result of a spawn-capture: either the child completed (status + captured bytes),
/// or it exceeded the timeout and was killed.
enum Captured {
    Completed {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    TimedOut,
}

/// Spawn `claude --print --output-format json` capturing stdout+stderr, killing the
/// child on `timeout` expiry. Reader threads drain the pipes concurrently so a large
/// completion cannot deadlock on a full pipe buffer.
fn spawn_capture(
    bin: &Path,
    handle_dir_abs: &Path,
    prompt: &str,
    args: &ExecArgs,
    timeout: Duration,
) -> Result<Captured, SdkError> {
    let mut cmd = Command::new(bin);
    cmd.env("CLAUDE_CONFIG_DIR", handle_dir_abs);
    super::run::strip_sensitive_env(&mut cmd);
    cmd.arg("--print")
        .arg(prompt)
        .arg("--output-format")
        .arg("json");
    if let Some(model) = args.model.as_deref() {
        cmd.arg("--model").arg(model);
    }
    if let Some(system) = args.system.as_deref() {
        cmd.arg("--append-system-prompt").arg(system);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Parent-death guard (Linux): if csq dies, the kernel SIGKILLs the child. macOS has
    // no PDEATHSIG; the child shares csq's process group (terminal signals propagate)
    // and the --timeout bounds any orphan.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `pre_exec` runs the closure in the forked child before `exec`.
        // `prctl(PR_SET_PDEATHSIG, …)` is async-signal-safe and only arms a
        // parent-death signal for this child; it touches no shared state. The
        // outer `unsafe` also covers the `prctl` call inside the closure.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        SdkError::new(
            SdkErrorCode::SpawnFailed,
            format!(
                "failed to spawn claude: {}",
                redact_home_prefix(&e.to_string())
            ),
        )
    })?;

    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");
    let out_reader = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let err_reader = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_reader.join();
                    let _ = err_reader.join();
                    return Ok(Captured::TimedOut);
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                // Join the drain threads for symmetry with the timeout/complete paths;
                // they EOF once the killed child's pipes close.
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(SdkError::new(
                    SdkErrorCode::Internal,
                    format!(
                        "wait on claude failed: {}",
                        redact_home_prefix(&e.to_string())
                    ),
                ));
            }
        }
    };
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    Ok(Captured::Completed {
        status,
        stdout,
        stderr,
    })
}

/// Turn a spawn outcome into a [`Completion`] or an [`SdkError`].
fn parse_outcome(outcome: Captured, timeout_secs: u64) -> Result<Completion, SdkError> {
    let (status, stdout, stderr) = match outcome {
        Captured::TimedOut => {
            return Err(SdkError::trusted(
                SdkErrorCode::Timeout,
                format!("claude exceeded the {timeout_secs}s timeout and was killed"),
            ))
        }
        Captured::Completed {
            status,
            stdout,
            stderr,
        } => (status, stdout, stderr),
    };

    // The adapter is the source of truth for a well-formed result (it maps is_error →
    // ProviderError). Only when it can't parse do we fall back to the exit-status/stderr.
    match sdk::parse_claude_json(&stdout) {
        Ok(completion) => Ok(completion),
        Err(parse_err) => {
            if !status.success() {
                let code = status.code().unwrap_or(-1);
                Err(SdkError::new(
                    SdkErrorCode::ProviderError,
                    format!(
                        "claude exited with status {code}: {}",
                        redact_home_prefix(&String::from_utf8_lossy(&stderr))
                    ),
                ))
            } else {
                Err(parse_err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(
        prompt: Option<&str>,
        stdin: bool,
        slot: Option<u16>,
        provider: Option<&str>,
    ) -> ExecArgs {
        ExecArgs {
            prompt: prompt.map(str::to_string),
            stdin,
            provider: provider.map(str::to_string),
            slot,
            model: None,
            system: None,
            id: None,
            timeout_secs: 120,
        }
    }

    #[test]
    fn prompt_and_stdin_both_is_invalid_input() {
        let err = resolve_prompt(&args(Some("hi"), true, None, None)).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
    }

    #[test]
    fn prompt_neither_is_invalid_input() {
        let err = resolve_prompt(&args(None, false, None, None)).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
    }

    #[test]
    fn empty_prompt_is_invalid_input() {
        let err = resolve_prompt(&args(Some("   "), false, None, None)).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
    }

    #[test]
    fn positional_prompt_resolves() {
        assert_eq!(
            resolve_prompt(&args(Some("hello"), false, None, None)).unwrap(),
            "hello"
        );
    }

    #[test]
    fn slot_and_provider_both_is_invalid_input() {
        let base = std::path::Path::new("/nonexistent");
        let err = resolve_slot(base, &args(Some("p"), false, Some(3), Some("claude"))).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
    }

    #[test]
    fn slot_and_provider_neither_is_invalid_input() {
        let base = std::path::Path::new("/nonexistent");
        let err = resolve_slot(base, &args(Some("p"), false, None, None)).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::InvalidInput);
    }

    #[test]
    fn non_claude_provider_is_provider_not_found() {
        let base = std::path::Path::new("/nonexistent");
        let err = resolve_slot(base, &args(Some("p"), false, None, Some("gemini"))).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::ProviderNotFound);
    }

    #[test]
    fn timed_out_outcome_maps_to_timeout_error() {
        let err = parse_outcome(Captured::TimedOut, 30).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::Timeout);
        assert!(err.message.as_str().contains("30s"));
    }

    #[test]
    fn healthy_slot_none_when_no_anthropic_slots() {
        // A base dir with no accounts yields no healthy Claude slot.
        let tmp = std::env::temp_dir().join(format!("csq-exec-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let err = resolve_healthy_claude_slot(&tmp).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::NoHealthySlot);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
