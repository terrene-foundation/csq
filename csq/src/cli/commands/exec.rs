//! `csq exec --json` (`csq.exec.v1`) — a single non-interactive completion, and
//! `csq sdk capabilities --json` (`csq.capabilities.v1`) — op discovery.
//!
//! `csq exec` is a **spawn-capture** executor (SDK-plan corrected ground truth #1): it
//! spawns the slot's provider CLI non-interactively — `claude --print
//! --output-format json` (Claude/3P), `gemini --prompt … --output-format json`
//! (Gemini), or `codex exec --json` (Codex, an internal ticket) — captures the child's stdout,
//! parses it through the matching adapter, and re-emits the result as a single
//! [`csq_core::sdk`] envelope line. It is emphatically NOT the
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

/// Maximum number of bytes captured from a single child pipe (stdout or stderr).
///
/// 8 MiB is large enough to hold any realistic CLI JSON completion (Claude's
/// maximum output is on the order of tens of kilobytes). The cap protects csq
/// against a hostile or runaway child that streams multi-GB before the
/// `--timeout` fires, which would otherwise grow csq's heap unbounded.
///
/// The reader thread drains bytes past the cap into a sink so the child never
/// blocks on a full OS pipe buffer — only the retained bytes are bounded.
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

use anyhow::Result;
use serde::Serialize;

use csq_core::accounts::login::{find_claude_binary, find_cli_binary};
use csq_core::cli_deps::sanitize::redact_home_prefix;
use csq_core::sdk::{
    self, Completion, Envelope, FinishReason, SdkError, SdkErrorCode, Usage,
    SCHEMA_CAPABILITIES_V1, SCHEMA_EXEC_V1,
};
use csq_core::types::AccountNum;

/// The provider tag for Gemini surface completions.
const GEMINI_PROVIDER: &str = "gemini";
/// The gemini-cli binary name. Mirrors the const in `csq_core::providers::gemini`
/// without taking a dependency on that internal module from the community exec path.
const GEMINI_CLI_BINARY: &str = "gemini";
/// The provider tag for Codex surface completions.
const CODEX_PROVIDER: &str = "codex";

/// Build the non-interactive argv for a `codex exec` spawn.
///
/// `exec` is codex-cli's headless subcommand; `--json` emits a JSONL event
/// stream (parsed by [`parse_codex_json`]); `--skip-git-repo-check` suppresses
/// the interactive "not a git repo" guard. The prompt is a positional arg. No
/// tools flag — plain completion only. Mirrors the proven enterprise invocation
/// in `subscription_client.rs::build_codex_invocation`.
fn codex_argv(prompt: &str) -> Vec<String> {
    vec![
        "exec".to_string(),
        "--json".to_string(),
        "--skip-git-repo-check".to_string(),
        prompt.to_string(),
    ]
}

/// Build the non-interactive argv for a gemini-cli spawn.
///
/// Uses the long-form `--output-format json` (not the unverified `-o` short flag)
/// and `--skip-trust` to suppress the folder-trust interactive gate on a fresh
/// `GEMINI_CLI_HOME`. Both flags are proven from `subscription_client.rs:684-690`.
fn gemini_argv(prompt: &str) -> Vec<String> {
    vec![
        "--prompt".to_string(),
        prompt.to_string(),
        "--output-format".to_string(),
        "json".to_string(),
        "--skip-trust".to_string(),
    ]
}

/// Which CLI surface will handle a resolved slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecSurface {
    Claude,
    Gemini,
    Codex,
}

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

/// Successful outcome of [`run_exec`]: the parsed completion plus per-stream
/// truncation flags that must be surfaced in the envelope.
///
/// `Debug` is test-only-in-practice (needed by `Result::unwrap_err` in
/// `run_exec`-level test assertions) but is not `#[cfg(test)]`-gated because
/// deriving it unconditionally is zero-cost and avoids a cfg-gated derive
/// drifting out of sync with non-test callers that may want it later.
#[derive(Debug)]
struct ExecResult {
    completion: Completion,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

/// The `csq.exec.v1` success payload (completion-core embedded per S0).
#[derive(Debug, Serialize)]
struct ExecPayload {
    completion: Completion,
    /// `true` iff the child's stdout was cut off at [`MAX_CAPTURE_BYTES`].
    /// The `completion.text` may therefore be an incomplete/unparseable JSON
    /// fragment.  Integrators MUST inspect this field before trusting the
    /// completion — a truncated capture almost certainly means parse failed
    /// and the envelope carries an error instead, but the flag lets consumers
    /// distinguish "normal parse failure" from "output was too large".
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stdout_truncated: bool,
    /// `true` iff the child's stderr was cut off at [`MAX_CAPTURE_BYTES`].
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stderr_truncated: bool,
}

/// `csq exec` entry point. Emits exactly one `csq.exec.v1` envelope line and exits with
/// `0` on success, non-zero on any failure. Never returns normally (always `exit`s
/// through [`sdk::emit`]).
pub fn handle(base_dir: &Path, claude_home: &Path, args: ExecArgs) -> Result<()> {
    let id = args.id.clone();
    let result = run_exec(base_dir, claude_home, &args);
    let code = match result {
        Ok(ExecResult {
            completion,
            stdout_truncated,
            stderr_truncated,
        }) => sdk::emit(&Envelope::success(
            SCHEMA_EXEC_V1,
            id,
            ExecPayload {
                completion,
                stdout_truncated,
                stderr_truncated,
            },
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

/// Enterprise license gate for `csq exec`, returning an enveloped [`SdkError`] (exec's R2
/// invariant) rather than the `anyhow` form the CLI-layer `enforce_enterprise_license` uses.
/// Reads the wall clock fail-CLOSED (a pre-epoch clock cannot validate a time-bounded
/// license, so it denies — mirroring `cli::license_now_fail_closed`). Delegates the actual
/// signature / expiry / revocation / liveness logic to
/// [`csq_core::license::enforce_returning_advisory`], and surfaces the approaching-expiry
/// soft-enforcement nudge (an internal ticket) to STDERR — never stdout, so the exec JSON envelope
/// (invariant R3) stays clean.
#[cfg(feature = "enterprise")]
fn enforce_license(base_dir: &Path) -> Result<(), SdkError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| {
            SdkError::trusted(
                SdkErrorCode::LicenseRequired,
                "system clock is invalid (before the UNIX epoch) — cannot validate the enterprise license",
            )
        })?;
    if let Some(a) = csq_core::license::enforce_returning_advisory(base_dir, now)? {
        eprintln!("csq: license notice — {}", a.message);
    }
    Ok(())
}

/// The fallible core: resolve inputs → resolve slot → spawn-capture → parse. Every
/// error is an [`SdkError`] so the caller can wrap it in a failure envelope.
fn run_exec(base_dir: &Path, claude_home: &Path, args: &ExecArgs) -> Result<ExecResult, SdkError> {
    // Enterprise license gate (task #77 gate-coverage remediation). `csq exec` provides the
    // same LLM-execution value as the gated `csq run` — it spawns `claude` against a slot's
    // credentials and returns completions — so the enterprise binary MUST gate it too, or a
    // keyless use-only binary gets completions for free, defeating the "useless without a
    // key" contract (see `csq_core::license` module docs). Emitted as an enveloped
    // `LicenseRequired` `SdkError` (exec invariant R2 — every failure is a JSON envelope,
    // never an anyhow bail). Community builds carry no gate. Inert while the placeholder key
    // is baked.
    #[cfg(feature = "enterprise")]
    enforce_license(base_dir)?;

    let prompt = resolve_prompt(args)?;
    let (slot, surface) = resolve_slot(base_dir, args)?;

    match surface {
        ExecSurface::Claude => {
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
            // Security review 1386 M4: `canonicalize_for_keychain_sync` returns
            // the usual non-canonical fallback for `handle_dir_abs` (still the
            // right `CLAUDE_CONFIG_DIR` to spawn against), paired with whether
            // canonicalize actually succeeded — the keychain write below MUST
            // be skipped when it did not (see that function's doc for why).
            let (handle_dir_abs, handle_dir_is_canonical) =
                csq_core::credentials::keychain::canonicalize_for_keychain_sync(&handle_dir);

            // Security review 1386 F10: `csq exec` has no daemon requirement,
            // so an exec-only install (no `csq run`, no daemon) would never
            // drain the keychain pending-clear queue (H1) otherwise. Same
            // opportunistic sweep `run.rs` performs, same small dedicated
            // budget (`sweep_pending_clears_opportunistic`, bounded ~37.5s
            // worst case, NOT the daemon's ~187.5s one) — cheap when the queue
            // is empty (one file read, no subprocess calls), bounded but not
            // free when it isn't.
            let _ = csq_core::credentials::keychain::sweep_pending_clears_opportunistic(base_dir);

            // CC reads OAuth keychain-first (memory discovery_cc_keychain_first_credential_read);
            // mirror the fresh token into the keychain item keyed by CLAUDE_CONFIG_DIR.
            // Best-effort — a keychain miss falls back to the symlinked file (SSH/non-macOS).
            //
            // `_account_changed` variant, not the plain sweep one — this is a FRESH
            // handle dir, and its canonicalized path can collide with a stale item
            // left by a since-removed account (PID reuse, or an unconfirmed
            // `csq logout` keychain clear — security review 1386 H2). The plain
            // `sync_handle_dir` newer-than-keychain guard could otherwise PRESERVE
            // that wrong-account item; `_account_changed` always overwrites/clears.
            if handle_dir_is_canonical {
                let _ = csq_core::credentials::keychain::sync_handle_dir_account_changed(
                    &handle_dir_abs,
                );
            } else {
                tracing::warn!(
                    error_kind = "keychain_sync_canonicalize_failed",
                    "csq exec: could not canonicalize this handle dir's path — \
                     the keychain mirror was NOT written (non-fatal — exec \
                     continues; CC falls back to the symlinked .credentials.json)"
                );
            }

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
            parse_outcome(outcome, args.timeout_secs).map(
                |(completion, stdout_truncated, stderr_truncated)| ExecResult {
                    completion,
                    stdout_truncated,
                    stderr_truncated,
                },
            )
        }
        ExecSurface::Gemini => {
            let bin = find_cli_binary(GEMINI_CLI_BINARY).ok_or_else(|| {
                SdkError::trusted(
                    SdkErrorCode::SpawnFailed,
                    "gemini binary not found on PATH — install gemini-cli first",
                )
            })?;

            // Minimal ephemeral handle dir for gemini: <accounts-root>/gemini-exec-<pid>/ with a
            // .csq-account marker and a .gemini/ subdir. gemini-cli reads OAuth creds from
            // ~/.gemini/oauth_creds.json (HOME-relative), not from the handle dir, so no
            // credential symlinks are needed here.
            let pid = std::process::id();
            let handle_dir = create_gemini_handle_dir(
                base_dir,
                slot,
                pid,
                args.model.as_deref(),
                args.system.as_deref(),
            )
            .map_err(|e| {
                SdkError::new(
                    SdkErrorCode::Internal,
                    format!(
                        "failed to create gemini handle dir: {}",
                        redact_home_prefix(&e.to_string())
                    ),
                )
            })?;

            let outcome = spawn_capture_gemini(
                &bin,
                &handle_dir,
                &prompt,
                Duration::from_secs(args.timeout_secs),
            );

            let _ = std::fs::remove_dir_all(&handle_dir);

            let outcome = outcome?;
            parse_gemini_outcome(outcome, args.timeout_secs).map(
                |(completion, stdout_truncated, stderr_truncated)| ExecResult {
                    completion,
                    stdout_truncated,
                    stderr_truncated,
                },
            )
        }
        ExecSurface::Codex => {
            // Fail-loud on --model / --system for Codex (issue: judge-calibration
            // silent-drop). codex-cli's ONLY verified model-selection mechanism in
            // this codebase is the slot's PERSISTENT `config.toml` `model` key
            // (`providers::codex::surface::render_config_toml[_with_global]`),
            // written once at provisioning time — there is no verified per-request
            // override flag (`codex exec` takes no `-c`/`--model`/system-prompt
            // argument anywhere in this codebase, including the proven enterprise
            // `subscription_client.rs::build_codex_invocation`, which the argv here
            // mirrors). Silently ignoring a caller-supplied `--model`/`--system` was
            // the defect: `csq exec` returned `ok: true` with a completion from
            // whatever model the slot's config.toml happened to pin, and the caller
            // had no way to detect the mismatch. Reject explicitly instead.
            if args.model.is_some() || args.system.is_some() {
                return Err(SdkError::trusted(
                    SdkErrorCode::Unsupported,
                    "csq.exec.v1 does not support --model or --system on the Codex surface — \
                     codex-cli has no verified per-request override; only the slot's \
                     persistent config.toml model applies (run `csq login <N> --provider \
                     codex` after changing the model, or omit --model/--system)",
                ));
            }
            // Pre-flight (redteam R2 MED-1): a partially-provisioned slot can pass
            // `slot_serves_codex` (has a codex credential) yet lack
            // `config-<N>/config.toml`, so codex-cli would launch against its own
            // default config (keychain auth) and fail with an opaque non-zero exit.
            // Mirror run.rs::verify_codex_config_toml with an actionable error.
            if !csq_core::providers::codex::surface::config_toml_path(base_dir, slot).exists() {
                // NoHealthySlot (not Internal): a codex slot lacking its config.toml
                // is a user-resolvable provisioning gap (re-login), the same signal
                // resolve_healthy_codex_slot emits — not an internal csq invariant
                // failure (redteam R4 LOW).
                return Err(SdkError::trusted(
                    SdkErrorCode::NoHealthySlot,
                    "codex slot is not fully provisioned (missing config.toml) — run `csq login <N> --provider codex` first",
                ));
            }

            let bin = find_cli_binary(csq_core::providers::codex::surface::CLI_BINARY).ok_or_else(
                || {
                    SdkError::trusted(
                        SdkErrorCode::SpawnFailed,
                        "codex binary not found on PATH — install codex-cli first",
                    )
                },
            )?;

            // create_handle_dir_codex_named materializes an ephemeral codex handle
            // dir with the slot's config.toml + credential symlinks (legacy or
            // per-identity), so the spawned codex authenticates as this slot. The
            // reconciler reaps it by liveness if we crash; best-effort remove on the
            // happy path.
            let pid = std::process::id();
            let handle_dir = csq_core::session::create_handle_dir_codex_named(
                base_dir,
                slot,
                pid,
                &format!("codex-exec-{pid}"),
            )
            .map_err(|e| {
                SdkError::new(
                    SdkErrorCode::Internal,
                    format!(
                        "failed to create codex handle dir: {}",
                        redact_home_prefix(&e.to_string())
                    ),
                )
            })?;

            let outcome = spawn_capture_codex(
                &bin,
                &handle_dir,
                claude_home,
                &prompt,
                Duration::from_secs(args.timeout_secs),
            );

            let _ = std::fs::remove_dir_all(&handle_dir);

            let outcome = outcome?;
            parse_codex_outcome(outcome, args.timeout_secs).map(
                |(completion, stdout_truncated, stderr_truncated)| ExecResult {
                    completion,
                    stdout_truncated,
                    stderr_truncated,
                },
            )
        }
    }
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
/// does not resolve to a Claude or Gemini surface → `unsupported` / `no_healthy_slot`.
fn resolve_slot(base_dir: &Path, args: &ExecArgs) -> Result<(AccountNum, ExecSurface), SdkError> {
    match (args.slot, args.provider.as_deref()) {
        (Some(_), Some(_)) => Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "specify --slot OR --provider, not both",
        )),
        (None, None) => Err(SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "specify a target: --slot N or --provider <claude|gemini|codex>",
        )),
        (Some(n), None) => {
            let slot = AccountNum::try_from(n).map_err(|e| {
                SdkError::new(SdkErrorCode::InvalidInput, format!("invalid slot {n}: {e}"))
            })?;
            if slot_serves_gemini(base_dir, slot) {
                return Ok((slot, ExecSurface::Gemini));
            }
            if slot_serves_codex(base_dir, slot) {
                return Ok((slot, ExecSurface::Codex));
            }
            // Native Kimi/Grok CLI sessions are checked BEFORE the slot_serves_claude
            // fallthrough. slot_serves_claude excludes them (it returns false for a
            // native-bound slot), so without this branch a native-bound slot would fall
            // all the way through to the generic Unsupported error below with no
            // indication of WHICH surface it is actually bound to — silently
            // indistinguishable from a genuinely unbound slot. Naming the bound surface
            // here is exactly the harness-unreachable / model-refused / parse-failed
            // triage a judge runner depends on to not misattribute an availability gap
            // as a calibration verdict.
            if let Some(native_surface) =
                csq_core::providers::native::native_surface_for_slot(base_dir, slot)
            {
                return Err(SdkError::trusted(
                    SdkErrorCode::Unsupported,
                    format!(
                        "csq.exec.v1 does not support the native {native_surface} CLI surface \
                         yet — slot {n} is bound to it (use `csq run {n}` for an interactive \
                         session)"
                    ),
                ));
            }
            // slot_serves_claude ALSO covers env-transport 3P slots (DeepSeek/Kimi-bearer/
            // Z.AI/MiniMax/Ollama, ANTHROPIC_BASE_URL pinned via config-N/settings.json) and
            // cloud-Claude (Vertex/Bedrock) slots — see its doc comment. Both spawn `claude`,
            // which reads the pinned env from CLAUDE_CONFIG_DIR/settings.json at its own
            // startup, so no extra plumbing is needed here.
            if slot_serves_claude(base_dir, slot) {
                return Ok((slot, ExecSurface::Claude));
            }
            // Provably reachable only for a pathological dual-bound slot (both a Gemini
            // AND a ClaudeCode credential file present on the same slot) — every
            // well-formed slot resolves in one of the branches above.
            Err(SdkError::trusted(
                SdkErrorCode::Unsupported,
                format!(
                    "csq.exec.v1 could not determine a supported CLI surface for slot {n} — no \
                     Claude, Gemini, Codex, Kimi, or Grok binding was detected"
                ),
            ))
        }
        (None, Some(provider)) => {
            // THE single source of the exec-routing decision — `csq-core`'s
            // `registry::exec_route_for_provider_id`. This mirrors nothing by
            // hand: `registry::exec_routable_provider_ids` (in turn `csq sdk
            // capabilities --json`'s `features.exec.providers_routable`) is
            // derived from the SAME function, so this match and that
            // advertisement cannot disagree about which ids are routable
            // without a change to `exec_route_for_provider_id` itself.
            match csq_core::providers::registry::exec_route_for_provider_id(provider) {
                Some(csq_core::providers::registry::ExecRoute::Gemini) => {
                    resolve_healthy_gemini_slot(base_dir).map(|slot| (slot, ExecSurface::Gemini))
                }
                Some(csq_core::providers::registry::ExecRoute::Codex) => {
                    resolve_healthy_codex_slot(base_dir).map(|slot| (slot, ExecSurface::Codex))
                }
                Some(csq_core::providers::registry::ExecRoute::Claude) => {
                    resolve_healthy_claude_slot(base_dir).map(|slot| (slot, ExecSurface::Claude))
                }
                // 3P env-transport catalog ids (DeepSeek/Kimi-bearer/Z.AI/MiniMax/Ollama) —
                // the SAME model-on-Claude-Code-harness contrast the coc-bench study runs
                // on per-slot ANTHROPIC_BASE_URL pinning. `azure`/`vertex` (enterprise
                // Phase-2b direct-API providers with NO `claude`-spawn passthrough) are
                // excluded by `exec_route_for_provider_id` itself, not here.
                Some(csq_core::providers::registry::ExecRoute::ThirdParty(id)) => {
                    resolve_healthy_third_party_slot(base_dir, id)
                        .map(|slot| (slot, ExecSurface::Claude))
                }
                None => Err(SdkError::trusted(
                    SdkErrorCode::ProviderNotFound,
                    "csq.exec.v1 supports --provider claude, gemini, codex, or a 3P catalog id \
                     (deepseek, kimi, zai, mm, ollama)",
                )),
            }
        }
    }
}

/// True iff `slot` resolves to the Claude surface — NOT codex/gemini, and NOT a
/// native Kimi/Grok CLI session (Surface::Kimi/Surface::Grok, credential-less
/// binding marker `credentials/{kimi,grok}-<N>.json`). Env-transport 3P slots
/// (DeepSeek/Kimi-bearer/Z.AI/MiniMax/Ollama, `ANTHROPIC_BASE_URL` pinned via
/// `config-<N>/settings.json`) and cloud-Claude (Vertex/Bedrock) slots are NOT
/// excluded here — both spawn `claude`, which reads its pinned env from
/// `CLAUDE_CONFIG_DIR/settings.json` at its own startup (see module docs
/// "Claude/3P"), so they correctly fall through to `true`. Mirrors
/// `run::surface_cli_for_slot`'s classification without exposing that private
/// helper.
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
    // Native Kimi/Grok CLI sessions are a THIRD exclusion. Without this check a
    // slot bound to `csq login N --provider kimi-cli` (or `grok`) has neither a
    // codex nor a gemini credential file, so the two checks above would fall
    // through and this function would (incorrectly) report it as Claude-served —
    // exec.rs would then spawn `claude` against a slot that has no Claude
    // credentials at all. `resolve_slot` adds a specific, distinguishable
    // Unsupported error for this case (checked before this function is called);
    // this function only needs to say "not Claude."
    if csq_core::providers::native::native_surface_for_slot(base_dir, slot).is_some() {
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

/// Pick the first healthy 3P (env-transport) slot bound to catalog id `provider_id`
/// (e.g. `"deepseek"`, `"kimi"`, `"zai"`, `"mm"`, `"ollama"`) — not broker-failed.
///
/// Reuses [`csq_core::accounts::discovery::discover_per_slot_third_party`], the SAME
/// per-slot 3P enumeration `csq run`'s host-isolation warning and `csq doctor`'s
/// bearer-slot detector are built on, and
/// [`csq_core::providers::catalog::id_from_display_name`] to map the discovered
/// slot's display-name provider label (e.g. `"Kimi"`, `"DeepSeek"`) back to a
/// catalog id — no duplicated classification logic
/// (`account-terminal-separation.md` MUST Rule 4: diagnostic / dispatch surfaces
/// read the same channel as production paths).
fn resolve_healthy_third_party_slot(
    base_dir: &Path,
    provider_id: &str,
) -> Result<AccountNum, SdkError> {
    use csq_core::accounts::AccountSource;
    for acc in csq_core::accounts::discovery::discover_per_slot_third_party(base_dir) {
        let AccountSource::ThirdParty { provider } = &acc.source else {
            continue;
        };
        if csq_core::providers::catalog::id_from_display_name(provider) != Some(provider_id) {
            continue;
        }
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
        format!(
            "no healthy {provider_id} slot available (none are bound, or all are broker-failed)"
        ),
    ))
}

/// True iff `slot` resolves to the Gemini surface (has gemini credentials but not ClaudeCode).
///
/// Tie-break contract (redteam R1 M2): `resolve_slot` checks gemini → codex →
/// claude, so a slot bound to BOTH gemini and codex resolves to Gemini. This is
/// intentional and matches the check order; the login flow does not produce such
/// dual-provider slots in practice.
fn slot_serves_gemini(base_dir: &Path, slot: AccountNum) -> bool {
    use csq_core::providers::catalog::Surface;
    let gemini = csq_core::credentials::file::canonical_path_for(base_dir, slot, Surface::Gemini);
    if std::fs::symlink_metadata(&gemini).is_err() {
        return false;
    }
    // Must NOT also serve ClaudeCode (that would be a dual-credential slot; route as Claude).
    let cc = csq_core::credentials::file::canonical_path_for(base_dir, slot, Surface::ClaudeCode);
    std::fs::symlink_metadata(&cc).is_err()
}

/// Pick the first Gemini slot that has credential files present.
fn resolve_healthy_gemini_slot(base_dir: &Path) -> Result<AccountNum, SdkError> {
    use csq_core::types::MAX_ACCOUNTS;
    for n in 1..=MAX_ACCOUNTS {
        let Ok(slot) = AccountNum::try_from(n) else {
            continue;
        };
        if slot_serves_gemini(base_dir, slot) {
            return Ok(slot);
        }
    }
    Err(SdkError::trusted(
        SdkErrorCode::NoHealthySlot,
        "no Gemini slot available (none are logged in to gemini)",
    ))
}

/// True iff `slot` resolves to the Codex surface — it has a codex canonical
/// binding (legacy `credentials/codex-N.json`) or a per-identity
/// `identities/<UUID>/credentials-codex.json` (post-A++). Mirrors the codex
/// checks that `slot_serves_claude` uses to EXCLUDE codex slots.
fn slot_serves_codex(base_dir: &Path, slot: AccountNum) -> bool {
    use csq_core::providers::catalog::Surface;
    let codex = csq_core::credentials::file::canonical_path_for(base_dir, slot, Surface::Codex);
    if std::fs::symlink_metadata(&codex).is_ok() {
        return true;
    }
    if let Some(uuid) = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        let uuid_codex =
            csq_core::accounts::identity_store::credentials_codex_path_for(base_dir, uuid);
        if std::fs::symlink_metadata(&uuid_codex).is_ok() {
            return true;
        }
    }
    false
}

/// Pick the first HEALTHY Codex slot — has codex credentials AND is not
/// broker-failed. Mirrors `resolve_healthy_claude_slot`'s broker-failed skip
/// (redteam R1 HIGH-1): a broker-failed codex slot's JWT is expired/revoked, so
/// dispatching to it yields a `ProviderError` from a doomed spawn instead of the
/// correct `NoHealthySlot` (re-login) signal.
fn resolve_healthy_codex_slot(base_dir: &Path) -> Result<AccountNum, SdkError> {
    use csq_core::types::MAX_ACCOUNTS;
    for n in 1..=MAX_ACCOUNTS {
        let Ok(slot) = AccountNum::try_from(n) else {
            continue;
        };
        if slot_serves_codex(base_dir, slot)
            && !csq_core::refresh::sentinel::is_broker_failed(base_dir, slot)
        {
            return Ok(slot);
        }
    }
    Err(SdkError::trusted(
        SdkErrorCode::NoHealthySlot,
        "no Codex slot available (none are logged in to codex, or all are broker-failed)",
    ))
}

/// Read up to `cap` bytes from `r` into a `Vec`, then drain the remainder to
/// `/dev/null`-equivalent (a sink) so the writer side never blocks on a full
/// OS pipe buffer.
///
/// Returns `(bytes, truncated)` where `truncated` is `true` iff the stream
/// produced more than `cap` bytes.  The returned `Vec` contains exactly the
/// first `cap` bytes in that case.
///
/// This is a pure helper so it can be unit-tested independently of a real
/// child process.
fn capture_bounded<R: Read>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    let mut taken = r.by_ref().take(cap as u64);
    // Fill up to `cap` bytes.
    let _ = taken.read_to_end(&mut buf);
    // Drain any remaining bytes so the child's pipe does not block.
    // `Interrupted` (EINTR) is a spurious signal interruption — NOT EOF;
    // treat it as a retryable condition, not a termination signal.
    let mut discard = [0u8; 4096];
    let mut extra = false;
    loop {
        match r.read(&mut discard) {
            Ok(0) => break,
            Ok(_) => {
                extra = true;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let truncated = extra;
    (buf, truncated)
}

/// The result of a spawn-capture: either the child completed (status + captured bytes),
/// or it exceeded the timeout and was killed.
enum Captured {
    Completed {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        /// True iff the child's stdout stream exceeded [`MAX_CAPTURE_BYTES`].
        stdout_truncated: bool,
        /// True iff the child's stderr stream exceeded [`MAX_CAPTURE_BYTES`].
        stderr_truncated: bool,
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
    let out_reader = thread::spawn(move || capture_bounded(&mut out, MAX_CAPTURE_BYTES));
    let err_reader = thread::spawn(move || capture_bounded(&mut err, MAX_CAPTURE_BYTES));

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // LOAD-BEARING ORDERING: kill() MUST precede the join() calls.
                    // The drain loop in `capture_bounded` only self-terminates when the
                    // child's pipe reaches EOF.  A forever-streaming hostile child keeps the
                    // pipe open indefinitely — memory is bounded by the 4 KiB discard
                    // buffer, but TERMINATION depends on `child.kill()` closing the pipe.
                    // Do NOT reorder or remove kill-before-join without replacing this
                    // termination guarantee.
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
    let (stdout, stdout_truncated) = out_reader.join().unwrap_or_default();
    let (stderr, stderr_truncated) = err_reader.join().unwrap_or_default();
    Ok(Captured::Completed {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

/// Turn a spawn outcome into a `(Completion, stdout_truncated, stderr_truncated)`
/// triple, or an [`SdkError`].
fn parse_outcome(
    outcome: Captured,
    timeout_secs: u64,
) -> Result<(Completion, bool, bool), SdkError> {
    let (status, stdout, stderr, stdout_truncated, stderr_truncated) = match outcome {
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
            stdout_truncated,
            stderr_truncated,
        } => (status, stdout, stderr, stdout_truncated, stderr_truncated),
    };

    // The adapter is the source of truth for a well-formed result (it maps is_error →
    // ProviderError). Only when it can't parse do we fall back to the exit-status/stderr.
    match sdk::parse_claude_json(&stdout) {
        Ok(completion) => Ok((completion, stdout_truncated, stderr_truncated)),
        Err(parse_err) => {
            // When truncation caused the parse failure the signal MUST surface in the
            // error — otherwise it is silent on the only path that matters (failure).
            let truncation_note = if stdout_truncated || stderr_truncated {
                format!(
                    " [output truncated at {} MiB — the captured stream exceeded the capture cap; the partial output could not be parsed]",
                    MAX_CAPTURE_BYTES / (1024 * 1024)
                )
            } else {
                String::new()
            };
            if !status.success() {
                let code = status.code().unwrap_or(-1);
                Err(SdkError::new(
                    SdkErrorCode::ProviderError,
                    format!(
                        "claude exited with status {code}: {}{}",
                        redact_home_prefix(&String::from_utf8_lossy(&stderr)),
                        truncation_note,
                    ),
                ))
            } else {
                Err(SdkError::new(
                    parse_err.code,
                    format!("{}{}", parse_err.message.as_str(), truncation_note),
                ))
            }
        }
    }
}

/// Create a minimal Gemini handle dir:
///   `<base_dir>/accounts/gemini-exec-<pid>/`  (contains `.csq-account` + `.gemini/`)
/// gemini-cli reads OAuth creds from `~/.gemini/oauth_creds.json` (HOME-relative), so
/// credential symlinks are not needed — only the GEMINI_CLI_HOME isolation boundary.
///
/// `model` / `system` (from `--model` / `--system`) flow into `settings.json`'s
/// `model.name` / `system_instruction` fields via [`csq_core::providers::gemini::
/// settings::render`] — the SAME mechanism the capability-layer spawn path
/// (`providers::gemini::probe::reassert_settings_drift_with_system_instruction`,
/// used by `csq run`'s with-layer arm) uses to inject a system prompt for
/// gemini-cli. gemini-cli reads its config from `GEMINI_CLI_HOME/settings.json` at
/// its own startup — there is no `--model`/`--system` argv flag; this settings-file
/// injection point is gemini-cli's real mechanism (mirrors how a Claude 3P slot's
/// `ANTHROPIC_BASE_URL` flows through `config-N/settings.json`, module docs
/// "Claude/3P"). `model.unwrap_or("")` — `render` treats an empty model name as
/// "omit the field" (gemini-cli's own default applies).
fn create_gemini_handle_dir(
    base_dir: &Path,
    slot: AccountNum,
    pid: u32,
    model: Option<&str>,
    system: Option<&str>,
) -> Result<std::path::PathBuf, std::io::Error> {
    let handle_dir = base_dir.join("accounts").join(format!("gemini-exec-{pid}"));
    std::fs::create_dir_all(&handle_dir)?;
    // `.csq-account` marker so downstream tools can identify the owning slot.
    let marker = handle_dir.join(".csq-account");
    std::fs::write(&marker, format!("{}\n", slot.get()))?;
    // `.gemini/` subdir expected by gemini-cli when reading GEMINI_CLI_HOME.
    std::fs::create_dir_all(handle_dir.join(".gemini"))?;
    // Seed settings.json with selectedType=oauth-personal so gemini-cli does not
    // show the interactive auth picker on a fresh GEMINI_CLI_HOME.
    // Mirrors spawn.rs step-3 behavior. Reuses the community helper (no enterprise gate).
    let settings_json = csq_core::providers::gemini::settings::render(
        model.unwrap_or(""),
        system,
        Some(csq_core::providers::gemini::settings::SELECTED_TYPE_OAUTH_PERSONAL),
    );
    std::fs::write(
        handle_dir.join(".gemini").join("settings.json"),
        settings_json,
    )?;
    Ok(handle_dir)
}

/// Spawn `gemini -o json <prompt>`, capturing stdout+stderr, killing the child on
/// `timeout` expiry. No `--tools` flag: gemini-cli plain-text mode only.
/// GEMINI_CLI_HOME is set to the ephemeral handle dir; env is otherwise cleared.
/// `--model` / `--system` are NOT argv here — gemini-cli has no such flags; they are
/// injected via `create_gemini_handle_dir`'s settings.json write (see its docs).
fn spawn_capture_gemini(
    bin: &Path,
    handle_dir: &Path,
    prompt: &str,
    timeout: Duration,
) -> Result<Captured, SdkError> {
    // AC1 — argv must include `-o json` and must NOT include `--tools`.
    let mut cmd = Command::new(bin);
    cmd.env_clear();
    // Gemini CLI needs HOME so it can find ~/.gemini/oauth_creds.json.
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        cmd.env("XDG_RUNTIME_DIR", xdg);
    }
    cmd.env("GEMINI_CLI_HOME", handle_dir);
    for arg in gemini_argv(prompt) {
        cmd.arg(arg);
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `pre_exec` runs the closure in the forked child before `exec`.
        // `prctl(PR_SET_PDEATHSIG, …)` is async-signal-safe and only arms a
        // parent-death signal for this child; it touches no shared state.
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
                "failed to spawn gemini: {}",
                redact_home_prefix(&e.to_string())
            ),
        )
    })?;

    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");
    let out_reader = thread::spawn(move || capture_bounded(&mut out, MAX_CAPTURE_BYTES));
    let err_reader = thread::spawn(move || capture_bounded(&mut err, MAX_CAPTURE_BYTES));

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // LOAD-BEARING ORDERING: kill() MUST precede the join() calls.
                    // The drain loop in `capture_bounded` only self-terminates when the
                    // child's pipe reaches EOF.  A forever-streaming hostile child keeps the
                    // pipe open indefinitely — memory is bounded by the 4 KiB discard
                    // buffer, but TERMINATION depends on `child.kill()` closing the pipe.
                    // Do NOT reorder or remove kill-before-join without replacing this
                    // termination guarantee.
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
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(SdkError::new(
                    SdkErrorCode::Internal,
                    format!(
                        "wait on gemini failed: {}",
                        redact_home_prefix(&e.to_string())
                    ),
                ));
            }
        }
    };
    let (stdout, stdout_truncated) = out_reader.join().unwrap_or_default();
    let (stderr, stderr_truncated) = err_reader.join().unwrap_or_default();
    Ok(Captured::Completed {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

/// Parse gemini-cli's `-o json` envelope into a normalised [`Completion`].
///
/// Gemini JSON shape (community-side inline parser — NO phase2b dependency):
/// ```json
/// { "session_id"?: "...", "response"?: "...", "stats"?: {...}, "error"?: {...} }
/// ```
/// AC2 — success path: `response` → `text`, recursive token search in `stats`.
/// AC3 — error path: `error.type` + `error.message` → `ok:false`.
fn parse_gemini_json(stdout: &[u8]) -> Result<Completion, SdkError> {
    let text = String::from_utf8_lossy(stdout);
    let v: serde_json::Value = serde_json::from_str(text.trim()).map_err(|e| {
        SdkError::new(
            SdkErrorCode::OutputParseFailed,
            format!("gemini output is not valid JSON: {e}"),
        )
    })?;

    // Error path first: gemini signals failures via an `error` object.
    if let Some(err_obj) = v.get("error") {
        let kind = err_obj
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("UnknownError");
        let msg = err_obj
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("gemini returned an error");
        return Err(SdkError::new(
            SdkErrorCode::ProviderError,
            format!("{kind}: {msg}"),
        ));
    }

    // Success path: `response` field carries the completion text.
    let response_text = v
        .get("response")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            SdkError::trusted(
                SdkErrorCode::OutputParseFailed,
                "gemini response field is missing or empty",
            )
        })?;

    // Extract token counts from stats via deep recursive search (the nested structure
    // varies across gemini-cli versions; we search rather than hard-code the path).
    let usage = v.get("stats").map(|stats| {
        let input = find_u64_by_key(stats, "promptTokenCount");
        let output = find_u64_by_key(stats, "candidatesTokenCount");
        let cache = find_u64_by_key(stats, "cachedContentTokenCount");
        Usage::default()
            .with_input_tokens(input)
            .with_output_tokens(output)
            .with_cache_read_input_tokens(cache)
    });

    Ok(Completion::new(
        response_text.to_owned(),
        // intentional gap: gemini-cli --output-format json does not expose the served model name
        String::new(),
        GEMINI_PROVIDER.to_owned(),
        FinishReason::Stop,
    )
    .with_usage(usage))
}

/// Recursively search a JSON value for the first field named `key` whose value is a
/// non-negative integer. Used to extract token counts from gemini's nested stats object.
fn find_u64_by_key(v: &serde_json::Value, key: &str) -> Option<u64> {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(val) = map.get(key) {
                if let Some(n) = val.as_u64() {
                    return Some(n);
                }
            }
            for child in map.values() {
                if let Some(n) = find_u64_by_key(child, key) {
                    return Some(n);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                if let Some(n) = find_u64_by_key(child, key) {
                    return Some(n);
                }
            }
            None
        }
        _ => None,
    }
}

/// Turn a Gemini spawn outcome into a `(Completion, stdout_truncated,
/// stderr_truncated)` triple, or an [`SdkError`].
fn parse_gemini_outcome(
    outcome: Captured,
    timeout_secs: u64,
) -> Result<(Completion, bool, bool), SdkError> {
    let (status, stdout, stderr, stdout_truncated, stderr_truncated) = match outcome {
        Captured::TimedOut => {
            return Err(SdkError::trusted(
                SdkErrorCode::Timeout,
                format!("gemini exceeded the {timeout_secs}s timeout and was killed"),
            ))
        }
        Captured::Completed {
            status,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        } => (status, stdout, stderr, stdout_truncated, stderr_truncated),
    };

    match parse_gemini_json(&stdout) {
        Ok(completion) => Ok((completion, stdout_truncated, stderr_truncated)),
        Err(parse_err) => {
            // When truncation caused the parse failure the signal MUST surface in the
            // error — otherwise it is silent on the only path that matters (failure).
            let truncation_note = if stdout_truncated || stderr_truncated {
                format!(
                    " [output truncated at {} MiB — the captured stream exceeded the capture cap; the partial output could not be parsed]",
                    MAX_CAPTURE_BYTES / (1024 * 1024)
                )
            } else {
                String::new()
            };
            if !status.success() {
                let code = status.code().unwrap_or(-1);
                Err(SdkError::new(
                    SdkErrorCode::ProviderError,
                    format!(
                        "gemini exited with status {code}: {}{}",
                        redact_home_prefix(&String::from_utf8_lossy(&stderr)),
                        truncation_note,
                    ),
                ))
            } else {
                Err(SdkError::new(
                    parse_err.code,
                    format!("{}{}", parse_err.message.as_str(), truncation_note),
                ))
            }
        }
    }
}

/// Spawn `codex exec --json --skip-git-repo-check <prompt>`, capturing
/// stdout+stderr, killing the child on `timeout` expiry.
///
/// Env handling mirrors the proven enterprise `build_codex_invocation`
/// (`subscription_client.rs`): the parent env is inherited (codex-cli needs
/// PATH/HOME/locale and more than gemini's minimal set), CLAUDE state-dir vars
/// are scrubbed so a codex-cli cannot resolve a Claude config dir, and
/// `CODEX_HOME` points at the ephemeral handle dir so codex authenticates as
/// this slot. `cwd` is the accounts home (not the caller's project dir), so
/// codex does not load the invoking project's context.
fn spawn_capture_codex(
    bin: &Path,
    handle_dir: &Path,
    claude_home: &Path,
    prompt: &str,
    timeout: Duration,
) -> Result<Captured, SdkError> {
    let mut cmd = Command::new(bin);
    // H3 invariant (module header): strip credential-bearing parent env before
    // spawning. `strip_sensitive_env` removes ANTHROPIC_*/OPENAI_*/AWS_* /
    // CLAUDE_API_KEY / CODEX_HOME — matching what run.rs::launch_codex does for
    // the same child, so e.g. an `OPENAI_BASE_URL` in the caller's shell cannot
    // redirect codex's JWT to an unintended endpoint (redteam R1 MED-1).
    super::run::strip_sensitive_env(&mut cmd);
    // Also scrub the Claude state-dir vars (not covered by strip_sensitive_env)
    // so codex cannot resolve a Claude config dir.
    cmd.env_remove("CLAUDE_CONFIG_DIR");
    cmd.env_remove("CLAUDE_HOME");
    // Re-pin CODEX_HOME (stripped above) to the ephemeral handle dir.
    cmd.env(
        csq_core::providers::codex::surface::HOME_ENV_VAR,
        handle_dir,
    );
    cmd.current_dir(claude_home);
    for arg in codex_argv(prompt) {
        cmd.arg(arg);
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `pre_exec` runs the closure in the forked child before `exec`.
        // `prctl(PR_SET_PDEATHSIG, …)` is async-signal-safe and only arms a
        // parent-death signal for this child; it touches no shared state.
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
                "failed to spawn codex: {}",
                redact_home_prefix(&e.to_string())
            ),
        )
    })?;

    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");
    let out_reader = thread::spawn(move || capture_bounded(&mut out, MAX_CAPTURE_BYTES));
    let err_reader = thread::spawn(move || capture_bounded(&mut err, MAX_CAPTURE_BYTES));

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // LOAD-BEARING ORDERING: kill() MUST precede join() — the drain
                    // loop in capture_bounded self-terminates only on child EOF, so a
                    // forever-streaming child's pipe is closed by kill().
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
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(SdkError::new(
                    SdkErrorCode::Internal,
                    format!(
                        "wait on codex failed: {}",
                        redact_home_prefix(&e.to_string())
                    ),
                ));
            }
        }
    };

    let (stdout, stdout_truncated) = out_reader.join().unwrap_or_default();
    let (stderr, stderr_truncated) = err_reader.join().unwrap_or_default();
    Ok(Captured::Completed {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

/// Parse codex-cli's `--json` JSONL event stream into a [`Completion`].
///
/// Mirrors the enterprise `parse_codex` (`subscription_client.rs`): the final
/// `agent_message` item carries the response text; the `turn.completed` event
/// carries usage. Non-JSON tracing lines are skipped. codex follows OpenAI's
/// token convention — `input_tokens` is the TOTAL prompt (cached + uncached)
/// and `cached_input_tokens` is the read-from-cache subset (mapped to
/// `cache_read_input_tokens`); consumers MUST NOT add them.
fn parse_codex_json(stdout: &[u8]) -> Result<Completion, SdkError> {
    let text = String::from_utf8_lossy(stdout);
    let mut content_text: Option<String> = None;
    let mut usage: Option<Usage> = None;
    let mut error_text: Option<String> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
            continue; // tracing / non-JSON noise
        };
        match ev.get("type").and_then(serde_json::Value::as_str) {
            Some("item.completed") => {
                if let Some(item) = ev.get("item") {
                    if item.get("type").and_then(serde_json::Value::as_str) == Some("agent_message")
                    {
                        if let Some(t) = item.get("text").and_then(serde_json::Value::as_str) {
                            content_text = Some(t.to_string());
                        }
                    }
                }
            }
            Some("turn.completed") => {
                if let Some(u) = ev.get("usage") {
                    usage = Some(
                        Usage::default()
                            .with_input_tokens(
                                u.get("input_tokens").and_then(serde_json::Value::as_u64),
                            )
                            .with_output_tokens(
                                u.get("output_tokens").and_then(serde_json::Value::as_u64),
                            )
                            .with_cache_read_input_tokens(
                                u.get("cached_input_tokens")
                                    .and_then(serde_json::Value::as_u64),
                            ),
                    );
                }
            }
            Some("error") => {
                // Redteam R2 MED-2: codex signals auth/rate-limit failures via a
                // `type:"error"` event (mirrors gemini's error envelope). Capture
                // the last one so a turn that errors without an agent_message
                // surfaces the real reason, not a generic parse failure.
                if let Some(msg) = ev.get("message").and_then(serde_json::Value::as_str) {
                    error_text = Some(msg.to_string());
                }
            }
            _ => {}
        }
    }

    let response_text = content_text.filter(|t| !t.is_empty()).ok_or_else(|| {
        // Prefer the codex-reported error over a generic "no output" message.
        match error_text {
            Some(msg) => SdkError::new(
                SdkErrorCode::ProviderError,
                format!("codex error: {}", redact_home_prefix(&msg)),
            ),
            None => SdkError::trusted(
                SdkErrorCode::OutputParseFailed,
                "codex produced no agent_message in its --json output",
            ),
        }
    })?;

    Ok(Completion::new(
        response_text,
        // Intentional v1 gap (mirrors gemini): codex's --json stream does not
        // surface the served model name in the parsed events.
        String::new(),
        CODEX_PROVIDER.to_owned(),
        FinishReason::Stop,
    )
    .with_usage(usage))
}

/// Turn a Codex spawn outcome into a `(Completion, stdout_truncated,
/// stderr_truncated)` triple, or an [`SdkError`]. Mirrors [`parse_gemini_outcome`].
fn parse_codex_outcome(
    outcome: Captured,
    timeout_secs: u64,
) -> Result<(Completion, bool, bool), SdkError> {
    let (status, stdout, stderr, stdout_truncated, stderr_truncated) = match outcome {
        Captured::TimedOut => {
            return Err(SdkError::trusted(
                SdkErrorCode::Timeout,
                format!("codex exceeded the {timeout_secs}s timeout and was killed"),
            ))
        }
        Captured::Completed {
            status,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        } => (status, stdout, stderr, stdout_truncated, stderr_truncated),
    };

    match parse_codex_json(&stdout) {
        Ok(completion) => Ok((completion, stdout_truncated, stderr_truncated)),
        Err(parse_err) => {
            let truncation_note = if stdout_truncated || stderr_truncated {
                format!(
                    " [output truncated at {} MiB — the captured stream exceeded the capture cap; the partial output could not be parsed]",
                    MAX_CAPTURE_BYTES / (1024 * 1024)
                )
            } else {
                String::new()
            };
            if !status.success() {
                let code = status.code().unwrap_or(-1);
                Err(SdkError::new(
                    SdkErrorCode::ProviderError,
                    format!(
                        "codex exited with status {code}: {}{}",
                        redact_home_prefix(&String::from_utf8_lossy(&stderr)),
                        truncation_note,
                    ),
                ))
            } else {
                Err(SdkError::new(
                    parse_err.code,
                    format!("{}{}", parse_err.message.as_str(), truncation_note),
                ))
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

    /// Gate-coverage wiring (task #77): the `csq exec` license gate delegates to the shared
    /// `csq_core::license::enforce`, which is INERT while the placeholder key is baked — so it
    /// MUST NOT block the happy path today (an over-eager gate would break `csq exec` for
    /// every user immediately). The deny path (invalid/expired/revoked/stale) is exercised by
    /// the `csq_core::license::enforce_with` tests with an injected non-inert key.
    #[cfg(feature = "enterprise")]
    #[test]
    fn exec_license_gate_is_inert_under_placeholder_key() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            enforce_license(tmp.path()).is_ok(),
            "the exec gate must be inert (Ok) while the placeholder key is baked"
        );
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

    /// AC1 (argv builder) — `--provider gemini` against an empty base routes to Gemini surface
    /// and produces `NoHealthySlot` (no gemini creds in /nonexistent), NOT `ProviderNotFound`.
    /// This verifies that gemini is a recognised provider and the argv builder would be called.
    #[test]
    fn gemini_provider_routes_to_no_healthy_slot_not_provider_not_found() {
        let base = std::path::Path::new("/nonexistent");
        let err = resolve_slot(base, &args(Some("p"), false, None, Some("gemini"))).unwrap_err();
        assert_eq!(
            err.code,
            SdkErrorCode::NoHealthySlot,
            "gemini is a known provider — should reach slot resolution, not ProviderNotFound"
        );
    }

    /// an internal ticket — `--provider codex` is a KNOWN provider: it reaches slot resolution
    /// (NoHealthySlot when no codex slot exists), NOT ProviderNotFound. Guards
    /// against `registry::exec_route_for_provider_id`'s `"codex" => Codex` arm
    /// being dropped.
    #[test]
    fn codex_provider_routes_to_no_healthy_slot_not_provider_not_found() {
        let base = std::path::Path::new("/nonexistent");
        let err = resolve_slot(base, &args(Some("p"), false, None, Some("codex"))).unwrap_err();
        assert_eq!(
            err.code,
            SdkErrorCode::NoHealthySlot,
            "codex is a known provider — should reach slot resolution, not ProviderNotFound"
        );
    }

    // ── --model / --system fail-loud on Codex (judge-calibration silent-drop) ──
    //
    // Before this fix, `spawn_capture_codex` took no `ExecArgs` parameter at all —
    // `--model` and `--system` were silently discarded and `csq exec` returned
    // `ok: true` with a completion from whatever model the slot's config.toml
    // happened to pin. A judge-calibration run measured this directly: 0/75
    // usable Codex results, because the judge's rubric (delivered via `--system`)
    // never reached the model, which then invented its own label vocabulary. Both
    // tests below run `run_exec` directly (not just `resolve_slot`) so they
    // exercise the SAME code path `csq exec`'s `handle()` calls — no live spawn:
    // the check fires before any `Command::new(...)` for Codex.

    /// `--model` on a Codex slot MUST fail loud, not silently drop the flag. Uses
    /// a bare `credentials/codex-<N>.json` marker (existence-only check in
    /// `slot_serves_codex`) — no config.toml, no real codex binary — because the
    /// rejection fires BEFORE the config.toml pre-flight and before any spawn.
    #[test]
    fn codex_rejects_model_before_any_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("credentials")).unwrap();
        std::fs::write(tmp.path().join("credentials").join("codex-5.json"), "{}").unwrap();
        let mut a = args(Some("hi"), false, Some(5), None);
        a.model = Some("gpt-5.6-sol".to_string());
        let err = run_exec(tmp.path(), tmp.path(), &a).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::Unsupported);
        assert!(
            err.message.as_str().contains("--model") || err.message.as_str().contains("Codex"),
            "error must name the rejected flag or surface; got: {}",
            err.message.as_str()
        );
    }

    /// `--system` on a Codex slot MUST fail loud, not silently drop the flag.
    #[test]
    fn codex_rejects_system_before_any_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("credentials")).unwrap();
        std::fs::write(tmp.path().join("credentials").join("codex-6.json"), "{}").unwrap();
        let mut a = args(Some("hi"), false, Some(6), None);
        a.system = Some("You are a terse reviewer.".to_string());
        let err = run_exec(tmp.path(), tmp.path(), &a).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::Unsupported);
    }

    /// Negative control: a Codex slot with NEITHER `--model` NOR `--system` set
    /// must NOT hit the new rejection branch — it should proceed past it to the
    /// config.toml pre-flight (which fails NoHealthySlot-style here because no
    /// config.toml exists in this fixture — proving the rejection is scoped to
    /// the two flags, not to Codex slots in general).
    #[test]
    fn codex_without_model_or_system_reaches_config_toml_preflight() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("credentials")).unwrap();
        std::fs::write(tmp.path().join("credentials").join("codex-9.json"), "{}").unwrap();
        let a = args(Some("hi"), false, Some(9), None);
        let err = run_exec(tmp.path(), tmp.path(), &a).unwrap_err();
        // NOT Unsupported (the model/system rejection) — this is the config.toml
        // pre-flight's NoHealthySlot, proving the code advanced past the new check.
        assert_eq!(err.code, SdkErrorCode::NoHealthySlot);
        assert!(err.message.as_str().contains("config.toml"));
    }

    // ── --model / --system wiring on Gemini (via settings.json, not argv) ──

    /// Non-vacuity target: `create_gemini_handle_dir` writes `--model` /
    /// `--system` into `.gemini/settings.json`'s `model.name` /
    /// `system_instruction` fields — the same mechanism the capability-layer
    /// spawn path uses to inject a system prompt for gemini-cli.
    #[test]
    fn gemini_handle_dir_writes_model_and_system_into_settings_json() {
        let tmp = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let handle_dir = create_gemini_handle_dir(
            tmp.path(),
            slot,
            999_999,
            Some("gemini-3-pro"),
            Some("You are terse."),
        )
        .unwrap();
        let settings =
            std::fs::read_to_string(handle_dir.join(".gemini").join("settings.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&settings).unwrap();
        assert_eq!(v["model"]["name"], "gemini-3-pro");
        assert_eq!(v["system_instruction"], "You are terse.");
    }

    /// Regression guard: when `--model`/`--system` are NOT supplied, the fields
    /// stay absent (no spurious empty-string model, no phantom system prompt) —
    /// the plain no-flags path is unchanged.
    #[test]
    fn gemini_handle_dir_omits_model_and_system_when_not_supplied() {
        let tmp = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(4u16).unwrap();
        let handle_dir = create_gemini_handle_dir(tmp.path(), slot, 999_998, None, None).unwrap();
        let settings =
            std::fs::read_to_string(handle_dir.join(".gemini").join("settings.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&settings).unwrap();
        assert!(v.get("model").is_none(), "settings.json: {settings}");
        assert!(
            v.get("system_instruction").is_none(),
            "settings.json: {settings}"
        );
    }

    /// AC1 (argv builder) — verify gemini spawn uses `--output-format json` + `--skip-trust`,
    /// not the unverified `-o` short flag, and never includes `--tools`.
    #[test]
    fn gemini_argv_uses_output_json_flag_not_tools() {
        let argv = gemini_argv("ping");
        assert!(
            argv.contains(&"--output-format".to_string()),
            "--output-format must be present (not the unverified -o short flag); got: {argv:?}"
        );
        assert!(
            argv.contains(&"json".to_string()),
            "json must be present as format value; got: {argv:?}"
        );
        assert!(
            argv.contains(&"--skip-trust".to_string()),
            "--skip-trust must be present to suppress folder-trust interactive gate; got: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--tools"),
            "--tools must be absent (plain-text mode only); got: {argv:?}"
        );
        // prompt must be present
        assert!(
            argv.contains(&"ping".to_string()),
            "prompt must be present in argv; got: {argv:?}"
        );
    }

    /// AC2 — gemini success fixture parses into the normalised `csq.exec.v1` envelope shape.
    #[test]
    fn gemini_parse_json_success_fixture() {
        let fixture = br#"{"session_id":"s1","response":"pong","stats":{"models":{"x":{"tokens":{"promptTokenCount":9,"candidatesTokenCount":2}}}}}"#;
        let completion = parse_gemini_json(fixture).unwrap();
        assert_eq!(completion.text, "pong");
        assert_eq!(completion.provider, GEMINI_PROVIDER);
        assert_eq!(completion.finish_reason, FinishReason::Stop);
        let usage = completion.usage.expect("usage present");
        assert_eq!(usage.input_tokens, Some(9));
        assert_eq!(usage.output_tokens, Some(2));
    }

    /// AC2 — empty response field yields OutputParseFailed.
    #[test]
    fn gemini_parse_json_empty_response_is_malformed() {
        let fixture = br#"{"response":""}"#;
        let err = parse_gemini_json(fixture).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::OutputParseFailed);
    }

    /// AC3 — gemini error envelope maps to `ok:false` with ProviderError code.
    #[test]
    fn gemini_parse_json_error_envelope_is_provider_error() {
        let fixture =
            br#"{"error":{"type":"IneligibleTierError","message":"free tier not supported"}}"#;
        let err = parse_gemini_json(fixture).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::ProviderError);
        assert!(
            err.message.as_str().contains("IneligibleTierError"),
            "error type must appear in message"
        );
    }

    // ── an internal ticket codex-exec ────────────────────────────────────────────────
    #[test]
    fn codex_argv_uses_exec_json_no_tools() {
        let argv = codex_argv("ping");
        assert_eq!(
            argv.first().map(String::as_str),
            Some("exec"),
            "first arg must be the exec subcommand; got: {argv:?}"
        );
        assert!(
            argv.contains(&"--json".to_string()),
            "--json must be present; got: {argv:?}"
        );
        assert!(
            argv.contains(&"--skip-git-repo-check".to_string()),
            "--skip-git-repo-check must be present; got: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--tools"),
            "--tools must be absent; got: {argv:?}"
        );
        assert!(
            argv.contains(&"ping".to_string()),
            "prompt must be a positional arg; got: {argv:?}"
        );
    }

    #[test]
    fn codex_parse_json_success_fixture() {
        // codex `--json` JSONL: an agent_message item + a turn.completed usage line.
        let fixture = b"{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"pong\"}}\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":9,\"output_tokens\":2,\"cached_input_tokens\":3}}\n";
        let completion = parse_codex_json(fixture).unwrap();
        assert_eq!(completion.text, "pong");
        assert_eq!(completion.provider, CODEX_PROVIDER);
        assert_eq!(completion.finish_reason, FinishReason::Stop);
        let usage = completion.usage.expect("usage present");
        assert_eq!(usage.input_tokens, Some(9));
        assert_eq!(usage.output_tokens, Some(2));
        // OpenAI convention: cached_input_tokens → cache_read; NOT added to input.
        assert_eq!(usage.cache_read_input_tokens, Some(3));
        assert_eq!(usage.cache_creation_input_tokens, None);
    }

    #[test]
    fn codex_parse_json_no_agent_message_is_parse_failed() {
        // Only a turn.completed line, no agent_message → no text → parse failed.
        let fixture =
            b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}\n";
        let err = parse_codex_json(fixture).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::OutputParseFailed);
    }

    #[test]
    fn codex_parse_json_skips_non_json_noise_lines() {
        // Tracing/noise lines before the JSON events must be skipped, not fail.
        let fixture = b"[codex] booting...\n{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"ok\"}}\n";
        let completion = parse_codex_json(fixture).unwrap();
        assert_eq!(completion.text, "ok");
        // No turn.completed line → usage must be None.
        assert!(completion.usage.is_none());
    }

    #[test]
    fn codex_parse_json_error_event_becomes_provider_error() {
        // an internal ticket R2: a codex `type:"error"` event with no agent_message surfaces
        // the real reason as ProviderError, not a generic OutputParseFailed.
        let fixture = b"{\"type\":\"error\",\"message\":\"unauthorized: token expired\"}\n";
        let err = parse_codex_json(fixture).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::ProviderError);
        assert!(
            err.message.as_str().contains("unauthorized"),
            "codex error message must surface; got: {}",
            err.message.as_str()
        );
    }

    /// AC4 — Claude surface timeout still maps to SdkErrorCode::Timeout (no regression).
    #[test]
    fn timed_out_outcome_maps_to_timeout_error() {
        let err = parse_outcome(Captured::TimedOut, 30).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::Timeout);
        assert!(err.message.as_str().contains("30s"));
    }

    /// AC4 — Gemini surface timeout maps to SdkErrorCode::Timeout.
    #[test]
    fn gemini_timed_out_outcome_maps_to_timeout_error() {
        let err = parse_gemini_outcome(Captured::TimedOut, 45).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::Timeout);
        assert!(err.message.as_str().contains("45s"));
    }

    // ── capture_bounded helper unit tests (an internal ticket) ──────────────────────

    /// Under-cap: all bytes returned, truncated == false.
    #[test]
    fn capture_bounded_under_cap_returns_all_bytes_not_truncated() {
        let data = b"hello world";
        let (captured, truncated) = capture_bounded(data.as_slice(), 64);
        assert_eq!(captured, data);
        assert!(
            !truncated,
            "under-cap output must not be flagged as truncated"
        );
    }

    /// Exactly at the cap: bytes == cap len, truncated == false (no extra bytes).
    #[test]
    fn capture_bounded_exactly_at_cap_not_truncated() {
        let data: Vec<u8> = (0u8..=9).collect(); // 10 bytes
        let (captured, truncated) = capture_bounded(data.as_slice(), 10);
        assert_eq!(captured, data);
        assert!(
            !truncated,
            "stream of exactly cap bytes has no remainder; must not be truncated"
        );
    }

    /// Over-cap: only the first `cap` bytes are returned, truncated == true.
    #[test]
    fn capture_bounded_over_cap_truncates_and_sets_flag() {
        let cap = 16;
        let data: Vec<u8> = (0..100u8).collect(); // 100 bytes, cap at 16
        let (captured, truncated) = capture_bounded(data.as_slice(), cap);
        assert_eq!(captured.len(), cap, "captured length must equal cap");
        assert_eq!(
            &captured,
            &data[..cap],
            "captured bytes must be the first cap bytes"
        );
        assert!(truncated, "over-cap output must set truncated = true");
    }

    /// Empty stream: no bytes, not truncated.
    #[test]
    fn capture_bounded_empty_stream_is_not_truncated() {
        let (captured, truncated) = capture_bounded(std::io::empty(), 1024);
        assert!(captured.is_empty());
        assert!(!truncated);
    }

    /// Single-byte stream, cap = 1: not truncated (exactly at cap).
    #[test]
    fn capture_bounded_single_byte_equals_cap_not_truncated() {
        let (captured, truncated) = capture_bounded([42u8].as_slice(), 1);
        assert_eq!(captured, [42u8]);
        assert!(!truncated);
    }

    /// Single-byte stream, cap = 0: nothing captured, but there IS extra data.
    #[test]
    fn capture_bounded_cap_zero_captures_nothing_but_detects_extra() {
        let (captured, truncated) = capture_bounded([42u8].as_slice(), 0);
        assert!(captured.is_empty());
        assert!(truncated, "data beyond cap=0 must be detected");
    }

    /// Live integration (an internal ticket): a REAL child process emitting more than
    /// [`MAX_CAPTURE_BYTES`] through a REAL OS pipe is bounded at the cap, flagged
    /// truncated, AND the child still exits — the drain-past-cap consumes the
    /// remainder so the writer never blocks on a full pipe. The other tests
    /// exercise the pure helper against in-memory readers; this is the only one
    /// that exercises a genuine child + pipe end-to-end (the "live" leg an internal ticket's
    /// unit coverage otherwise lacks). Unix-only (spawns `sh`).
    #[cfg(unix)]
    #[test]
    fn capture_bounded_bounds_real_child_pipe_and_child_exits() {
        use std::process::{Command, Stdio};
        // Emit 9 MiB (> the 8 MiB cap) then close. `yes` SIGPIPEs when `head`
        // has taken its bytes; the pipeline (sh) exit status is head's (0).
        let over_cap: usize = MAX_CAPTURE_BYTES + 1024 * 1024; // 9 MiB
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(format!("yes | head -c {over_cap}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn test child");
        let stdout = child.stdout.take().expect("child stdout is piped");

        let (captured, truncated) = capture_bounded(stdout, MAX_CAPTURE_BYTES);

        assert_eq!(
            captured.len(),
            MAX_CAPTURE_BYTES,
            "retained bytes from a >cap child must be bounded at the 8 MiB cap"
        );
        assert!(
            truncated,
            "a child emitting more than the cap must be flagged truncated"
        );
        // The drain consumed the remaining ~1 MiB, so the child could finish and
        // close its pipe rather than block on a full one — `wait()` returns.
        let status = child.wait().expect("child wait");
        assert!(
            status.success() || status.code().is_none(),
            "child must have exited (not hung on a full pipe); status = {status:?}"
        );
    }

    /// A `Read` impl that emits `Err(Interrupted)` on the first drain call, then
    /// returns real bytes.  Used to verify that `capture_bounded` does NOT treat
    /// EINTR as EOF (MED-1 regression test).
    struct InterruptedThenData {
        interrupted_once: bool,
        data: std::io::Cursor<Vec<u8>>,
    }

    impl InterruptedThenData {
        fn new(data: Vec<u8>) -> Self {
            Self {
                interrupted_once: false,
                data: std::io::Cursor::new(data),
            }
        }
    }

    impl Read for InterruptedThenData {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted_once {
                self.interrupted_once = true;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "spurious EINTR",
                ));
            }
            self.data.read(buf)
        }
    }

    /// MED-1 regression: a spurious EINTR mid-drain MUST be retried, not treated
    /// as EOF.  The reader emits one Interrupted error then real data beyond the
    /// cap; `capture_bounded` must continue past the EINTR and set `truncated=true`.
    #[test]
    fn capture_bounded_continues_past_interrupted_error() {
        let cap = 4;
        // 4 bytes that fill the cap, then 3 extra bytes that require the drain loop.
        let cap_bytes: Vec<u8> = vec![1, 2, 3, 4];
        let extra_bytes: Vec<u8> = vec![5, 6, 7];
        let all_bytes: Vec<u8> = cap_bytes
            .iter()
            .chain(extra_bytes.iter())
            .copied()
            .collect();

        // First, read up to `cap` bytes via `take(cap)` — that uses a plain `.read_to_end`
        // call, which may retry EINTR itself.  Then the drain loop fires with our
        // InterruptedThenData reader for the remainder.
        //
        // We build the reader from `all_bytes` so `take(cap)` fills the buffer first,
        // then the drain loop sees the Interrupted-then-data tail.  To exercise the drain
        // path we need the EINTR to appear AFTER the take() phase.  We wrap in a reader
        // that passes the first `cap` bytes normally, then injects the EINTR before the
        // extra bytes.
        struct TakeNormalThenInterrupt {
            normal_remaining: usize,
            inner: InterruptedThenData,
        }
        impl Read for TakeNormalThenInterrupt {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.normal_remaining > 0 {
                    let want = buf.len().min(self.normal_remaining);
                    let n = self.inner.data.read(&mut buf[..want])?;
                    self.normal_remaining -= n;
                    Ok(n)
                } else {
                    // Hand off to the interrupted-then-data path (drain phase).
                    self.inner.read(buf)
                }
            }
        }

        let reader = TakeNormalThenInterrupt {
            normal_remaining: cap,
            inner: InterruptedThenData::new(all_bytes),
        };
        let (captured, truncated) = capture_bounded(reader, cap);
        assert_eq!(captured, cap_bytes, "first cap bytes must be retained");
        assert!(
            truncated,
            "EINTR followed by real data must not prematurely stop the drain; \
             truncated must be true because extra bytes were seen"
        );
    }

    /// Parse-failure with `stdout_truncated=true` → Err whose message contains "truncated".
    ///
    /// Truncation is the most common cause of a parse failure (8 MiB of output gets cut
    /// mid-JSON).  The AC for an internal ticket requires the signal be non-silent in the error
    /// when it can't reach the success-path envelope.  This test uses a success ExitStatus
    /// so it hits the `else { Err(parse_err) }` sub-branch of `parse_outcome`.
    #[test]
    #[cfg(unix)]
    fn parse_outcome_truncated_unparseable_surfaces_truncation_in_error() {
        use std::os::unix::process::ExitStatusExt;
        let outcome = Captured::Completed {
            status: ExitStatus::from_raw(0), // exit code 0 (success)
            stdout: b"not valid json at all".to_vec(),
            stderr: vec![],
            stdout_truncated: true,
            stderr_truncated: false,
        };
        let err = parse_outcome(outcome, 30).unwrap_err();
        assert!(
            err.message.as_str().contains("truncated"),
            "error message must contain 'truncated' when stdout_truncated=true; got: {:?}",
            err.message.as_str()
        );
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

    /// AC1 — no healthy gemini slot in an empty base dir.
    #[test]
    fn healthy_gemini_slot_none_when_no_gemini_slots() {
        let tmp = std::env::temp_dir().join(format!("csq-gemini-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let err = resolve_healthy_gemini_slot(&tmp).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::NoHealthySlot);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── 3P slot reachability + native Kimi/Grok misrouting fix (coc-bench H-contrast) ──
    //
    // The coc-bench study's identifying contrast is "same model, different harness" —
    // e.g. the Kimi model on the Claude Code harness (a 3P slot, ANTHROPIC_BASE_URL
    // pinned) versus the Kimi model on Kimi's own native harness (a native-CLI slot).
    // These tests establish and lock down exactly how `csq exec --slot N` classifies
    // each of those two slot shapes today.

    /// A slot with NO codex/gemini/native binding marker resolves to
    /// ExecSurface::Claude — this is the mechanism that lets a 3P
    /// (ANTHROPIC_BASE_URL-pinned) slot reach `csq exec --slot N` today: the
    /// classification is negative (absence of codex/gemini/native markers), not
    /// positive (presence of Claude credentials), so a slot whose settings.json pins
    /// a 3P endpoint reaches the SAME `claude` spawn path as a real Anthropic OAuth
    /// slot. `claude` itself reads the pinned env from
    /// CLAUDE_CONFIG_DIR/settings.json at its own startup (module docs "Claude/3P").
    #[test]
    fn three_p_slot_via_slot_number_resolves_to_claude_surface() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("config-13");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.kimi.com/coding","ANTHROPIC_AUTH_TOKEN":"sk-kimi-x"}}"#,
        )
        .unwrap();
        let (slot, surface) =
            resolve_slot(tmp.path(), &args(Some("p"), false, Some(13), None)).unwrap();
        assert_eq!(slot.get(), 13);
        assert_eq!(surface, ExecSurface::Claude);
    }

    /// Non-vacuity companion to the above: a COMPLETELY EMPTY slot (no config-N dir
    /// at all, no credentials of any kind) ALSO resolves to Claude — proving the
    /// classification is exclusion-based (absence of codex/gemini/native markers),
    /// not a positive check for Claude/3P credentials. Documents the actual
    /// mechanism precisely rather than the (incorrect) "3P is Unsupported" framing
    /// the removed error message implied.
    #[test]
    fn completely_unbound_slot_via_slot_number_also_resolves_to_claude_surface() {
        let tmp = tempfile::tempdir().unwrap();
        // Deliberately: no config-N dir, no credentials/ dir, nothing at all.
        let (slot, surface) =
            resolve_slot(tmp.path(), &args(Some("p"), false, Some(41), None)).unwrap();
        assert_eq!(slot.get(), 41);
        assert_eq!(surface, ExecSurface::Claude);
    }

    /// A slot bound to the native Kimi CLI (credential-less binding marker,
    /// `credentials/kimi-<N>.json`) MUST NOT be misrouted to ExecSurface::Claude —
    /// exec.rs would otherwise spawn `claude` against a slot that has no Claude
    /// credentials at all, and (before this fix) the caller could not distinguish
    /// that from a genuinely unsupported/unbound slot.
    #[test]
    fn native_kimi_bound_slot_is_not_misrouted_to_claude_surface() {
        use csq_core::providers::catalog::Surface;
        let tmp = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(7u16).unwrap();
        csq_core::providers::native::write_binding(tmp.path(), slot, Surface::Kimi).unwrap();
        let err = resolve_slot(tmp.path(), &args(Some("p"), false, Some(7), None)).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::Unsupported);
        assert!(
            err.message.as_str().contains("kimi"),
            "error must name the bound native surface; got: {}",
            err.message.as_str()
        );
    }

    /// Same fix, Grok surface — guards the sibling native CLI.
    #[test]
    fn native_grok_bound_slot_is_not_misrouted_to_claude_surface() {
        use csq_core::providers::catalog::Surface;
        let tmp = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(8u16).unwrap();
        csq_core::providers::native::write_binding(tmp.path(), slot, Surface::Grok).unwrap();
        let err = resolve_slot(tmp.path(), &args(Some("p"), false, Some(8), None)).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::Unsupported);
        assert!(
            err.message.as_str().contains("grok"),
            "error must name the bound native surface; got: {}",
            err.message.as_str()
        );
    }

    /// Direct unit test on the exclusion predicate itself (not just its caller) — a
    /// native-bound slot must not read as Claude-served.
    #[test]
    fn slot_serves_claude_is_false_for_native_bound_slot() {
        use csq_core::providers::catalog::Surface;
        let tmp = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();
        csq_core::providers::native::write_binding(tmp.path(), slot, Surface::Grok).unwrap();
        assert!(!slot_serves_claude(tmp.path(), slot));
    }

    /// `--provider deepseek` (a 3P catalog id) resolves to the slot whose
    /// settings.json pins the DeepSeek endpoint, surfaced as ExecSurface::Claude.
    #[test]
    fn provider_deepseek_resolves_via_third_party_catalog_id() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("config-21");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_AUTH_TOKEN":"sk-x"}}"#,
        )
        .unwrap();
        let (slot, surface) =
            resolve_slot(tmp.path(), &args(Some("p"), false, None, Some("deepseek"))).unwrap();
        assert_eq!(slot.get(), 21);
        assert_eq!(surface, ExecSurface::Claude);
    }

    /// `--provider kimi` is the Bearer 3P catalog id (ClaudeCode surface,
    /// ANTHROPIC_BASE_URL=api.kimi.com/coding) — must resolve distinctly from the
    /// native `kimi-cli` surface, which `get_provider` does not recognise at all
    /// (catalog id space and native-CLI id space are disjoint by design — see
    /// `providers::native::descriptor_by_id`'s `"kimi-cli"` vs catalog `"kimi"`).
    #[test]
    fn provider_kimi_bearer_resolves_distinct_from_native_kimi_cli() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("config-22");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.kimi.com/coding","ANTHROPIC_AUTH_TOKEN":"sk-kimi-x"}}"#,
        )
        .unwrap();
        let (slot, surface) =
            resolve_slot(tmp.path(), &args(Some("p"), false, None, Some("kimi"))).unwrap();
        assert_eq!(slot.get(), 22);
        assert_eq!(surface, ExecSurface::Claude);
    }

    /// `--provider azure` (an enterprise Phase-2b direct-API provider with NO
    /// `ANTHROPIC_BASE_URL` passthrough) MUST NOT resolve through the 3P branch — it
    /// has no `claude`-spawn compatible endpoint, so routing it through
    /// ExecSurface::Claude would silently spawn `claude` against a URL it cannot
    /// talk to. Regression guard for the `base_url_env_var` filter.
    #[test]
    fn provider_azure_does_not_resolve_via_third_party_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let err =
            resolve_slot(tmp.path(), &args(Some("p"), false, None, Some("azure"))).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::ProviderNotFound);
    }

    /// `--provider deepseek` with no bound slot yields NoHealthySlot, not a panic or
    /// a silent fallback to another surface.
    #[test]
    fn provider_deepseek_no_healthy_slot_when_unbound() {
        let tmp = tempfile::tempdir().unwrap();
        let err =
            resolve_slot(tmp.path(), &args(Some("p"), false, None, Some("deepseek"))).unwrap_err();
        assert_eq!(err.code, SdkErrorCode::NoHealthySlot);
    }
}
