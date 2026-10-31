//! `csq login <N>` — OAuth login flow for a new account.
//!
//! # Path selection
//!
//! The CLI shells out to `claude auth login` (via [`handle_direct`])
//! for the `claude` provider. CC is the reference OAuth client; its
//! seamless flow uses IPv6 loopback `[::1]:<random>/callback` plus a
//! hosted-page JS bridge that csq does not — and intentionally does
//! not — re-implement (per the "delegate to reference client" rule).
//!
//! The previous default — an in-process parallel-race flow that
//! bound an IPv4 loopback listener AND prompted for a paste code in
//! parallel — diverged from CC: Anthropic's authorize endpoint
//! rejects `http://127.0.0.1:<port>/callback` for the Claude Code
//! client_id, so the race's auto-URL surfaces a "redirect URI fail"
//! page in the browser before the user can ever paste. The race
//! infrastructure remains in `csq-core` for the desktop shim
//! (`start_claude_login_race`); its CLI entry is gone.
//!
//! `--legacy-shell` is now a no-op alias for the default and is kept
//! only so scripts that hard-coded it keep parsing.
//!
//! All paths end by writing the `.csq-account` marker, updating
//! `profiles.json` with the email label, and clearing any
//! `broker_failed` sentinel via [`csq_core::accounts::login::finalize_verified_login`].

use anyhow::{anyhow, Context, Result};
#[cfg(all(test, unix))]
use csq_core::accounts::anthropic_identity::LoginPrior;
use csq_core::accounts::anthropic_identity::{
    capture_login_prior, commit_anthropic_login, read_native_expectation, CommittedAnthropicLogin,
};
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::cli_deps::SurfaceCli;
use csq_core::credentials;
use csq_core::oauth::{self, RaceResult};
use csq_core::providers::catalog::Surface;
use csq_core::types::AccountNum;
use std::io::Write;
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
#[cfg(all(test, unix))]
use std::time::Instant;

#[cfg(unix)]
use csq_core::daemon::{self, DaemonClientError, DetectResult};
use csq_core::providers::codex::desktop_login::extract_device_auth_url;
#[cfg(unix)]
use std::io::BufRead;

/// Entry point invoked from `main.rs`. Dispatches on `provider`:
///
/// * `"claude"` (default) — Anthropic OAuth by shell-out to
///   `claude auth login`. `legacy_shell` is accepted and ignored —
///   it once selected this path; now it IS the only path.
/// * `"codex"` — Codex device-auth flow per spec 07 §7.3.3 (PR-C3b).
///   `legacy_shell` is ignored for Codex.
#[allow(clippy::too_many_arguments)]
pub fn handle(
    base_dir: &Path,
    account: AccountNum,
    provider: &str,
    legacy_shell: bool,
    reset_handle_dir: bool,
    non_interactive: bool,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    track_latest: bool,
    json: bool,
) -> Result<()> {
    // R2/B80: `--reset-handle-dir` is handled first, before any OAuth
    // flow. It re-creates provider-specific artifacts without re-running
    // authentication. With `--non-interactive`, exits 64 if tokens are
    // expired (caller must re-login interactively first).
    if reset_handle_dir {
        return handle_reset_handle_dir(base_dir, account, provider, non_interactive);
    }

    // GH an internal ticket: this dispatcher previously refused `csq login N
    // --provider {codex,gemini,claude}` up-front when `N` was bound to a
    // native (Kimi/Grok) marker (redteam R1 MED's reverse conflict guard).
    // That refusal is RETIRED — it is now handled by silent cleanup deeper
    // in the OAuth-login flow, mirroring the shipped 3P-unbind precedent:
    //   * `claude`/`` (Anthropic) and `codex` REPLACE the slot's identity,
    //     so a stale Gemini or native marker is now detected pre-mint
    //     (`binding_guard::detect_stale_marker_binding`) and cleared on the
    //     login's SUCCESS path (`binding_guard::clear_detected_marker_binding`)
    //     — called from `accounts::login::finalize_login` and
    //     `providers::codex::login::perform_with` respectively — rather than
    //     refused here. Login "just works" and replaces cleanly instead of
    //     forcing an explicit `csq logout` first. A login that fails
    //     partway through leaves the prior binding untouched.
    //   * `gemini` never needed this pre-check — `handle_gemini_oauth`'s own
    //     `oauth_login::perform` already refuses ANY cross-surface binding
    //     (not just native) via `binding_guard::conflicting_bound_surface`,
    //     so this dispatch-level check was redundant for that arm.
    // native→native and native→other-native are still guarded (refused, not
    // cleaned — a login would orphan the vendor home) inside `handle_native`.

    // NOTE: the an internal ticket drivability guard is NOT called here. It runs inside each
    // provider handler, immediately AFTER that handler's
    // `cli_deps_gate::enforce` — see those call sites for why the order is
    // load-bearing.

    match provider {
        "codex" => {
            return handle_codex(
                base_dir,
                account,
                ignore_cli_version,
                no_auto_update_cli,
                track_latest,
                json,
            )
        }
        // Stage 2 of an internal journal entry: Gemini has THREE auth paths today.
        // OAuth (Code Assist subscription) is the `csq login` entry;
        // AI Studio API keys and Vertex SA still go through `csq
        // setkey gemini` because those are non-OAuth credential paste
        // flows.
        "gemini" => {
            return handle_gemini_oauth(
                base_dir,
                account,
                ignore_cli_version,
                no_auto_update_cli,
                track_latest,
                json,
            )
        }
        // Wave 3 (an internal journal entry): native, self-authenticating vendor CLIs.
        // csq stores no credentials — only a credential-less binding marker
        // (exactly the Gemini pattern). See `handle_native`.
        "kimi-cli" => {
            return handle_native(
                base_dir,
                account,
                Surface::Kimi,
                ignore_cli_version,
                no_auto_update_cli,
                track_latest,
                json,
            )
        }
        "grok" => {
            return handle_native(
                base_dir,
                account,
                Surface::Grok,
                ignore_cli_version,
                no_auto_update_cli,
                track_latest,
                json,
            )
        }
        "claude" | "" => {
            // Claude OAuth shells out to `claude auth login` (CC is the
            // reference OAuth client; csq delegates per the rule that
            // diverging from CC's current behavior is a bug). The race
            // flow's `redirect_uri=http://127.0.0.1:<port>/callback`
            // is rejected by Anthropic for this client_id — CC itself
            // uses IPv6 `[::1]:<random>` plus a hosted-page JS bridge,
            // and matching that in-process re-implements an upstream
            // surface that already exists.
        }
        other => {
            return Err(anyhow!(
                "unknown --provider {other:?} — supported: claude, codex, gemini, kimi-cli, grok"
            ));
        }
    }

    // `--legacy-shell` is now a no-op alias for the default — kept so
    // scripts that hard-coded it keep parsing. The in-process race
    // flow is no longer reachable from the CLI (see issue tracker for
    // its removal); desktop still wires it through `start_claude_login_race`.
    let _ = legacy_shell;
    handle_direct(base_dir, account, json)
}

/// Single call site for the an internal ticket fail-fast guard (see the doc at its call
/// site in [`handle`]). Resolves `provider` (defaulting the empty string to
/// `"claude"`, matching `handle`'s own dispatch) against the registry, derives
/// its [`csq_core::sdk::LoginFlow`], and refuses immediately when that flow
/// needs an attended session absent one. An id `handle`'s own `match provider`
/// arm will later reject as unknown (unreachable in practice — clap's
/// `value_parser` on `--provider` already closes the set) is a no-op here,
/// deferring to that existing error rather than duplicating it.
fn guard_login_drivability(provider: &str, json: bool) -> Result<()> {
    use csq_core::providers::{guard_attended_session, login_flow_for, registry};
    use csq_core::sdk::{Envelope, SCHEMA_LOGIN_V1};
    use std::io::IsTerminal;

    let resolved_id = if provider.is_empty() {
        "claude"
    } else {
        provider
    };
    let Some(descriptor) = registry::lookup(resolved_id) else {
        return Ok(());
    };
    let flow = login_flow_for(&descriptor);
    // Honour the repo's ESTABLISHED non-TTY bypass rather than reading the
    // terminal raw. `cli::check_test_bypass` is compiled in ONLY under the
    // `test-utils` feature (production builds use
    // `--no-default-features --features cli`, where it is a `const false`), so
    // the env var cannot weaken this guard for a real user.
    //
    // Reading `is_terminal()` alone made this guard fire in every integration
    // test that drives `csq login` as a subprocess — 12 tests in
    // `cli_deps_login_integration` refused before reaching the codex
    // version-gate logic they exist to pin (26 passed on main, 14 passed here).
    // Reusing the helper rather than re-deriving the bypass keeps ONE
    // definition of "may this build skip the TTY requirement".
    let has_tty = std::io::stdin().is_terminal() || super::cli::check_test_bypass();
    if let Err(sdk_err) = guard_attended_session(flow, descriptor.id, has_tty) {
        if json {
            let code =
                csq_core::sdk::emit(&Envelope::<()>::failure(SCHEMA_LOGIN_V1, None, sdk_err))?;
            std::process::exit(code);
        }
        return Err(anyhow!("{}", sdk_err.message.as_str()));
    }
    Ok(())
}

/// Returns true if the credentials file at `path` is missing OR
/// `claudeAiOauth.expiresAt` (camelCase, Unix milliseconds — per the
/// serde rename on `csq_core::credentials::OAuthPayload`) is in the
/// past.
///
/// The previous implementation read a top-level `expires_at` field
/// in Unix seconds — neither key nor unit matches any real CC
/// credentials file, so the function returned `true` for every
/// healthy slot, making `csq login N --reset-handle-dir
/// --non-interactive` unusable as a T22a pre-flight gate.
/// Whether slot `account`'s Anthropic OAuth tokens are expired, for the
/// `--reset-handle-dir --non-interactive` recording pre-flight.
///
/// Reads the DAEMON'S CANONICAL credential channel —
/// `identities/<UUID>/credentials.json` resolved via
/// [`resolve_slot_to_uuid`](csq_core::accounts::profiles::resolve_slot_to_uuid)
/// (`account-terminal-separation.md` MUST Rule 4: a diagnostic surface MUST read
/// the same channel the daemon's production paths write) — NOT the retired legacy
/// `config-<N>/.credentials.json` mirror. Spec 02 INV-05: the daemon stopped
/// writing that mirror in the M3-7 identity-store migration, so a post-migration
/// install has NO legacy file; the prior check (`Err(_) => true`) therefore
/// reported EVERY slot expired — including the active one — and made the §10.5
/// recording bench structurally unrunnable. The legacy mirror is consulted ONLY as
/// a pre-A++ fallback (when no identity mapping exists, `by_slot` empty).
fn credentials_expired_for_recording(base_dir: &Path, account: AccountNum) -> bool {
    // Canonical channel first (what the daemon actually refreshes).
    let canonical = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get())
        .map(|uuid| csq_core::accounts::identity_store::credentials_path_for(base_dir, uuid));
    let legacy = base_dir
        .join(format!("config-{}", account))
        .join(".credentials.json");
    let path = match canonical {
        Some(p) if p.exists() => p,
        // No identity mapping (pre-A++), or the identity file is absent → fall back
        // to the legacy mirror (which itself may be absent → treated as expired).
        _ => legacy,
    };
    credential_file_expired(&path)
}

/// Pure token-expiry check over one Anthropic `.credentials.json`-shaped file.
/// Missing / unparseable / `claudeAiOauth.expiresAt` absent or `<= now` → expired.
fn credential_file_expired(path: &Path) -> bool {
    let body = match std::fs::read_to_string(path) {
        Err(_) => return true, // missing → treat as expired
        Ok(b) => b,
    };
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let expires_at_ms = v
        .get("claudeAiOauth")
        .and_then(|o| o.get("expiresAt"))
        .and_then(|e| e.as_u64())
        .unwrap_or(0);
    expires_at_ms == 0 || expires_at_ms <= now_ms
}

/// `--reset-handle-dir` implementation (R2/B80).
///
/// Per-provider behavior:
/// - **Codex**: Re-symlink `term-<pid>/config.toml` →
///   `config-<N>/config.toml`. Recovers from handle-dir drift without
///   a full re-login.
/// - **Gemini**: Strip `system_instruction` from
///   `config-<N>/.gemini/settings.json` (removes stale scaffold content
///   that does not belong in the canonical slot config).
/// - **Claude (CC)**: No-op — CC handle dirs are reconstructed lazily
///   by `session::create_handle_dir` on every `csq run`.
///
/// With `--non-interactive`: after reset, check token expiry. If the
/// stored credentials are expired, exits 64 with a clear message so CI
/// and harness callers can distinguish "reset succeeded, tokens valid"
/// from "reset succeeded, tokens expired — re-login required".
fn handle_reset_handle_dir(
    base_dir: &Path,
    account: AccountNum,
    provider: &str,
    non_interactive: bool,
) -> Result<()> {
    let surface = match provider {
        "codex" => Surface::Codex,
        "gemini" => Surface::Gemini,
        "kimi-cli" => Surface::Kimi,
        "grok" => Surface::Grok,
        "claude" | "" => Surface::ClaudeCode,
        other => {
            return Err(anyhow!(
                "unknown --provider {other:?} — supported: claude, codex, gemini, kimi-cli, grok"
            ));
        }
    };

    match surface {
        Surface::Codex => reset_handle_dir_codex(base_dir, account)?,
        Surface::Gemini => reset_handle_dir_gemini(base_dir, account)?,
        Surface::ClaudeCode => {
            // CC: no-op — handle dirs are reconstructed on every `csq run`.
            eprintln!("info: --reset-handle-dir for claude is a no-op; handle dirs are created fresh on each `csq run`");
        }
        Surface::Kimi | Surface::Grok => {
            // Native-CLI handle dirs are recreated fresh on each `csq run`
            // (like Gemini/CC) — nothing persistent to reset.
            eprintln!("info: --reset-handle-dir for native-CLI slots is a no-op; handle dirs are created fresh on each `csq run`");
        }
    }

    if non_interactive {
        // Check the daemon's canonical identity-store credential (not the retired
        // legacy `config-<N>/.credentials.json` mirror — account-terminal-separation
        // MUST Rule 4 / spec 02 INV-05).
        if credentials_expired_for_recording(base_dir, account) {
            eprintln!(
                "error: slot {account} has expired tokens; \
                 refresh interactively before recording"
            );
            std::process::exit(64);
        }
    }

    Ok(())
}

/// Codex reset: re-symlink `term-<current-pid>/config.toml` →
/// `config-<N>/config.toml` in the currently active handle dir
/// (identified via the running process's `CLAUDE_CONFIG_DIR` env var).
///
/// If `CLAUDE_CONFIG_DIR` is not set (no active session), only the
/// canonical `config-<N>/config.toml` is verified to exist. Nothing is
/// written if there's no active handle dir to reset.
fn reset_handle_dir_codex(base_dir: &Path, account: AccountNum) -> Result<()> {
    let canonical = base_dir
        .join(format!("config-{}", account))
        .join("config.toml");

    if !canonical.exists() {
        return Err(anyhow!(
            "no Codex credentials for slot {account}: {} not found; \
             run `csq login {account} --provider codex` first",
            redact_path(&canonical)
        ));
    }

    // If there's an active handle dir for this process, re-symlink.
    if let Ok(handle_dir) = std::env::var("CLAUDE_CONFIG_DIR") {
        let handle_dir = std::path::Path::new(&handle_dir);
        if handle_dir.is_dir() {
            let link_path = handle_dir.join("config.toml");
            // Remove existing entry (symlink, regular file, or nothing).
            let _ = std::fs::remove_file(&link_path);
            #[cfg(unix)]
            std::os::unix::fs::symlink(&canonical, &link_path).with_context(|| {
                format!(
                    "symlink {} -> {}",
                    redact_path(&link_path),
                    redact_path(&canonical)
                )
            })?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&canonical, &link_path).with_context(|| {
                format!(
                    "symlink {} -> {}",
                    redact_path(&link_path),
                    redact_path(&canonical)
                )
            })?;
            eprintln!(
                "info: reset Codex handle dir: {} -> {}",
                redact_path(&link_path),
                redact_path(&canonical)
            );
        }
    }

    Ok(())
}

/// Gemini reset: strip `system_instruction` from
/// `config-<N>/.gemini/settings.json`.
///
/// The system_instruction key is injected by `csq run` from scaffold
/// output on each invocation. When drift occurs (stale content, manual
/// edits), `--reset-handle-dir` removes it so the next `csq run` can
/// re-inject a fresh value.
///
/// Uses atomic_replace + write_new_private (§5a cleanup) to ensure the file
/// is never left in a half-written state.
fn reset_handle_dir_gemini(base_dir: &Path, account: AccountNum) -> Result<()> {
    use csq_core::platform::fs::{unique_tmp_path, write_new_private_retained};

    let gemini_dir = base_dir.join(format!("config-{}", account)).join(".gemini");
    let settings_path = gemini_dir.join("settings.json");

    if !settings_path.exists() {
        // Nothing to reset; not an error (Gemini slot may be unconfigured).
        eprintln!(
            "info: {} not found; nothing to reset",
            redact_path(&settings_path)
        );
        return Ok(());
    }

    let body = std::fs::read_to_string(&settings_path)
        .with_context(|| format!("read {}", redact_path(&settings_path)))?;

    let mut v: serde_json::Value =
        serde_json::from_str(&body).context("parse Gemini settings.json")?;

    // Remove system_instruction at the top level.
    if let Some(obj) = v.as_object_mut() {
        let removed = obj.remove("system_instruction").is_some();
        if !removed {
            eprintln!(
                "info: system_instruction not present in {}; no change needed",
                redact_path(&settings_path)
            );
            return Ok(());
        }
    } else {
        return Err(anyhow!(
            "{} is not a JSON object",
            redact_path(&settings_path)
        ));
    }

    let updated =
        serde_json::to_string_pretty(&v).context("serialize updated Gemini settings.json")?;

    // §5a: `write_new_private` creates the tmp file at 0o600 at creation,
    // closing the window a separate std::fs::write + secure_file pair
    // would leave open.
    let tmp = unique_tmp_path(&settings_path);
    let writer = match write_new_private_retained(&tmp, updated.as_bytes()) {
        Ok(writer) => writer,
        // The private writer cleans up only files it created; collisions stay untouched.
        Err(e) => {
            return Err(anyhow!(
                "write Gemini settings tmp {}: {e}",
                redact_path(&tmp)
            ));
        }
    };
    if let Err(e) = writer.replace(&settings_path) {
        return Err(anyhow!(
            "atomic_replace {} -> {}: {e}",
            redact_path(&tmp),
            redact_path(&settings_path)
        ));
    }

    eprintln!(
        "info: removed system_instruction from {}",
        redact_path(&settings_path)
    );
    Ok(())
}

/// Acquires the per-account login lock or returns a clear error
/// pointing at the holder PID.
///
/// UX-R1-H3 regression: two concurrent `csq login N` processes
/// could both run an OAuth race and stomp `credentials/N.json`.
/// Holding an exclusive flock around the entire login flow
/// serializes them. The lock is per-ACCOUNT, not per-provider — it
/// also serializes a `csq login N --provider gemini` (or `codex`)
/// against a concurrent Anthropic `csq login N` (or a desktop login
/// for the same slot), which is exactly the shape that matters since
/// every provider's login writes into the same `config-<N>/` +
/// `profiles.json`.
///
/// `bypass_hint` names the flag (if any) that lets the caller route
/// around the contention instead of waiting/killing the holder.
/// `Some("--legacy-shell")` for the Claude paths (the in-process race
/// flow ignores this lock entirely); `None` for providers with no
/// such escape hatch — codex and gemini have no analogous flag, and
/// suggesting `--legacy-shell` there would send the user down a dead
/// end — neither `handle_codex` nor `handle_gemini_oauth` takes a
/// `legacy_shell` parameter, so `handle()` never threads it into
/// either dispatch branch.
///
/// UX-R2-01: error messages include the platform-specific kill
/// command for the holder PID so non-technical users have a concrete
/// next action ("run `kill 12345`") instead of a bare PID number.
/// SEC-R2-08: a stale-PID file (crashed prior holder) renders a
/// distinct "stale lock" message rather than misdirecting the user
/// at a dead PID.
fn acquire_login_lock(
    base_dir: &Path,
    account: AccountNum,
    bypass_hint: Option<&str>,
) -> Result<AccountLoginLock> {
    let bypass_suffix = match bypass_hint {
        Some(flag) => format!(", or use {flag} to bypass"),
        None => String::new(),
    };
    match AccountLoginLock::acquire(base_dir, account)
        .with_context(|| format!("create login lock file for account {account}"))?
    {
        AcquireOutcome::Acquired(guard) => Ok(guard),
        AcquireOutcome::Held {
            pid: Some(pid),
            pid_alive: Some(false),
        } if cfg!(windows) => Err(anyhow!(
            "another csq login {account} holds the operating-system lock (recorded PID {pid}) — wait for the owning login to finish; nothing was reclaimed"
        )),
        AcquireOutcome::Held { pid: Some(pid), pid_alive: Some(false) } => Err(anyhow!(
            "stale lock file for csq login {account} (prior holder PID {pid} \
             is no longer running) — the lock has been reclaimed; re-run the \
             command to proceed"
        )),
        AcquireOutcome::Held {
            pid: Some(pid),
            pid_alive: _,
        } if cfg!(windows) => Err(anyhow!(
            "another csq login {account} is in progress (PID {pid}) — {}",
            kill_hint(pid)
        )),
        AcquireOutcome::Held { pid: Some(pid), pid_alive: _ } => Err(anyhow!(
            "another csq login {account} is in progress (PID {pid}) — \
             wait for it to finish, or run `{}` to terminate it{}",
            kill_hint(pid),
            bypass_suffix
        )),
        AcquireOutcome::Held {
            pid: None,
            pid_alive: _,
        } if cfg!(windows) => Err(anyhow!(
            "another csq login {account} holds the operating-system lock (holder unknown) — wait for the owning login to finish"
        )),
        AcquireOutcome::Held { pid: None, pid_alive: _ } => Err(anyhow!(
            "another csq login {account} is in progress — wait{}",
            bypass_suffix
        )),
    }
}

/// Returns platform recovery guidance. Windows waits for the owning login;
/// Unix retains its existing signal command.
///
/// UX-R2-01: rendered into the lock-held error message so a
/// non-technical user knows exactly what to run instead of having to
/// look up platform recovery syntax.
fn kill_hint(pid: u32) -> String {
    if cfg!(target_os = "windows") {
        format!(
            "wait for the owning login (PID {pid}) to finish; unlock cannot stop a running process"
        )
    } else {
        format!("kill {pid}")
    }
}

/// `capture_login_prior` for the CLI login paths. A bare `?` printed the
/// profiles-lock contention tag (`anthropic_identity_profiles_busy`) with no
/// remedy; contention now goes through the shared retry wording, and every
/// other identity error is returned unchanged (same text, same error type).
fn capture_prior_for_cli(
    base_dir: &Path,
    account: AccountNum,
) -> Result<csq_core::accounts::anthropic_identity::LoginPrior> {
    capture_login_prior(base_dir, account).map_err(prior_capture_error_for_cli)
}

fn prior_capture_error_for_cli(
    error: csq_core::accounts::anthropic_identity::IdentityError,
) -> anyhow::Error {
    if error == csq_core::accounts::anthropic_identity::IdentityError::BindingBusy {
        anyhow!(csq_core::accounts::login::LoginCommitOutcome::describe_prior_capture_error(&error))
    } else {
        anyhow::Error::from(error)
    }
}

/// In-process parallel-race flow. **No longer reachable from the CLI**:
/// Anthropic's authorize endpoint rejects the IPv4 loopback
/// `redirect_uri=http://127.0.0.1:<port>/callback` for this
/// client_id (CC uses `[::1]:<random>` + a hosted-page JS bridge),
/// so the auto half of the race surfaces a "redirect URI fail" page
/// in the browser. Retained behind `#[allow(dead_code)]` while the
/// follow-up workspace removes the race infrastructure entirely —
/// the helper symbols below are still exercised by unit tests.
#[allow(dead_code)]
fn handle_race(base_dir: &Path, account: AccountNum) -> Result<()> {
    // UX-R1-H3: serialise concurrent `csq login N` invocations.
    // The guard is bound to a local so it lives until the function
    // returns (or panics) — at which point the kernel releases the
    // flock automatically.
    let _lock = acquire_login_lock(base_dir, account, Some("--legacy-shell"))?;
    let prior = capture_prior_for_cli(base_dir, account)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("csq-login-race")
        .build()
        .context("failed to build tokio runtime for login race")?;

    let outcome = rt.block_on(async move { run_race_with_browser(account).await })?;

    let result: RaceResult = match outcome {
        RaceOutcome::Resolved(r) => r,
        RaceOutcome::UserCancelled => {
            // M2 (UX-R1-M2): exit code 130 is the conventional
            // Bash-style "killed by SIGINT" code (128 + signal 2).
            // The lock guard above releases when this function
            // returns; the orchestrator's drop already closed the
            // loopback port.
            eprintln!();
            eprintln!("cancelled — re-run with --legacy-shell to use the shell-out path");
            std::process::exit(130);
        }
    };

    // PKCE binds the issued code to the original redirect_uri, so
    // the exchange MUST use the same redirect_uri the authorize URL
    // carried. The race winner exposes that for us.
    let redirect_uri = result.winner.redirect_uri().to_string();
    let code = result.winner.code().to_string();
    let verifier = result.verifier;

    let credential = oauth::exchange_code(
        &code,
        &verifier,
        &redirect_uri,
        csq_core::http::post_json_node,
    )
    .map_err(|e| anyhow!("token exchange failed: {e}"))?;

    let committed =
        commit_anthropic_login(base_dir, account, &credential, None, prior).map_err(|e| {
            report_undurable_rescue_refusal();
            anyhow!(
                "verify login for account {account}: {}",
                csq_core::accounts::login::LoginCommitOutcome::describe_error_for_account(
                    &e, account
                )
            )
        })?;
    println!("Login successful.");

    finalize_verified(base_dir, account, committed)
}

/// Outcome of [`run_race_with_browser`]. Distinguishes a successful
/// race from an explicit Ctrl-C cancel so `handle_race` can exit
/// 130 (the standard SIGINT exit code) rather than render an error
/// noisily.
enum RaceOutcome {
    Resolved(RaceResult),
    /// User pressed Ctrl-C before either path resolved. Caller
    /// should print the rollback hint and exit 130.
    UserCancelled,
}

/// Async core of the race flow. Separated so unit tests can drive
/// it with a mock paste resolver. **Currently only reachable from
/// [`handle_race`]** (itself dead per the comment there).
#[allow(dead_code)]
async fn run_race_with_browser(account: AccountNum) -> Result<RaceOutcome> {
    let store = Arc::new(oauth::OAuthStateStore::new());
    let prep = oauth::prepare_race(&store, account)
        .await
        .map_err(|e| anyhow!("OAuth race preparation failed: {e}"))?;

    println!("Starting login for account {account}...");
    println!("Opening browser...");

    let browser_opened = open_in_browser(&prep.auto_url).is_ok();
    if !browser_opened {
        // Browser failed — show paste prompt immediately. The
        // loopback listener still runs in case the user copies
        // the URL into a working browser elsewhere.
        //
        // L5 (UX-R1-L1) decision: we accept that the auto URL
        // (which contains the per-race state token AND path secret)
        // surfaces on stderr in this fallback. Both are single-use
        // — the state token is consumed atomically by the store on
        // first use, and the path secret is meaningless without the
        // accompanying loopback port and the in-process verifier.
        // The alternative — refusing to render a manual fallback
        // URL — would leave users on broken browsers with no
        // recovery path. The trade-off is documented; do not
        // silently widen this.
        eprintln!("warning: could not open browser automatically.");
        eprintln!("Open this URL manually to continue:");
        eprintln!("  {}", prep.auto_url);
        eprintln!();
        print_paste_prompt(&prep.manual_url);
    } else {
        // Browser opened — give it 3 seconds to render before
        // surfacing the paste fallback. The race itself is
        // already running underneath, so the loopback path can
        // win during this delay.
        let manual_url = prep.manual_url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            print_paste_prompt(&manual_url);
        });
    }

    let paste_resolver = stdin_paste_resolver();

    // M2 (UX-R1-M2): make Ctrl-C a clean cancel rather than a
    // process kill. Race the orchestrator against `signal::ctrl_c`;
    // on Ctrl-C, drop the orchestrator (which closes the loopback
    // port and aborts the stdin read) and return UserCancelled.
    let race_fut = oauth::drive_race(prep, &store, paste_resolver, oauth::DEFAULT_OVERALL_TIMEOUT);
    let ctrl_c_fut = async {
        tokio::signal::ctrl_c()
            .await
            .context("failed to install Ctrl-C handler")
    };
    race_or_cancel(race_fut, ctrl_c_fut).await
}

/// Races the orchestrator against an arbitrary "cancel" future.
/// Production wires the cancel arm to `tokio::signal::ctrl_c()`;
/// tests inject a future that resolves immediately to exercise the
/// cancellation path deterministically.
async fn race_or_cancel<R, C>(race_fut: R, cancel_fut: C) -> Result<RaceOutcome>
where
    R: std::future::Future<
        Output = std::result::Result<csq_core::oauth::RaceResult, csq_core::error::OAuthError>,
    >,
    C: std::future::Future<Output = Result<()>>,
{
    tokio::select! {
        race_res = race_fut => {
            let result = race_res.map_err(|e| anyhow!("OAuth race failed: {e}"))?;
            Ok(RaceOutcome::Resolved(result))
        }
        ctrl_c_res = cancel_fut => {
            // Propagate signal-installation failure as a hard error
            // rather than a fake cancel.
            ctrl_c_res?;
            Ok(RaceOutcome::UserCancelled)
        }
    }
}

/// Prints the paste prompt to stdout. Called either after a 3s
/// delay (browser opened) or immediately (browser open failed).
fn print_paste_prompt(manual_url: &str) {
    println!();
    println!("Browser didn't open? Open this URL manually:");
    println!("  {manual_url}");
    println!("After authorizing, paste the code shown by Anthropic:");
    let _ = std::io::stdout().flush();
}

/// Builds the production paste resolver: reads one line from
/// stdin asynchronously so it can be raced against the loopback
/// listener via `tokio::select!`.
///
/// `tokio::io::stdin` is line-buffered on TTYs; reading one line
/// blocks until the user hits enter. If the loopback listener
/// resolves first, the race orchestrator drops this future and
/// the in-flight `read_line` is aborted. The next time stdin is
/// read by the process (which won't happen in this command path)
/// it would resume from the next character.
fn stdin_paste_resolver() -> oauth::PasteResolver {
    Box::new(|| {
        Box::pin(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let stdin = tokio::io::stdin();
            let mut reader = BufReader::new(stdin);
            let mut line = String::new();
            // Read one line, propagate read errors as Exchange
            // errors with a sanitised message (no token material
            // is in scope at this point).
            match reader.read_line(&mut line).await {
                Ok(0) => Err(csq_core::error::OAuthError::Exchange(
                    "stdin closed before paste".to_string(),
                )),
                Ok(_) => Ok(line.trim().to_string()),
                Err(e) => Err(csq_core::error::OAuthError::Exchange(format!(
                    "stdin read failed: {e}"
                ))),
            }
        }) as Pin<Box<dyn std::future::Future<Output = _> + Send>>
    })
}

/// `--provider codex` dispatch. Round-7 (this session) UX rewrite:
///
/// 0. Refuse a non-interactive stdin (`guard_login_drivability`), right after the
///    login lock and before ANY output or read: step 3's Enter read would otherwise block
///    forever on an open non-TTY stdin.
/// 1. Print the device-auth prerequisite banner.
/// 2. Auto-open the ChatGPT Security Settings URL in the user's
///    default browser so they can flip "Device code authorization" on
///    without navigating manually.
/// 3. Block on stdin Enter — forces an explicit acknowledgement that
///    the toggle is enabled before any device code is generated. The
///    pre-Round-7 banner alone was just text users scanned past.
/// 4. **Pre-flight probe** (PR-MCD2, spec/13 §3): inserted IMMEDIATELY
///    before `Command::new("codex")` to close the TOCTOU window (R1-C2).
///    `Outdated` / `UnrecognizedVersion` bail by default; `--ignore-cli-version`
///    downgrades to WARN. `Missing` and `WrongBinary` are unconditional bails.
/// 5. Spawn `codex login --device-auth` with stdout piped, tee each
///    line to the operator's terminal, AND parse for the verification
///    URL — when seen, auto-open it in the browser. Pre-Round-7
///    behavior left the user to copy/paste the URL manually.
///
/// Keychain probe + config.toml pre-seed + canonical relocation still
/// happen inside `csq_core::providers::codex::login::perform_with`.
fn handle_codex(
    base_dir: &Path,
    account: AccountNum,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    track_latest: bool,
    json: bool,
) -> Result<()> {
    crate::login_cancel_guard::with_cli_login_session(account, |cancellation| {
        use csq_core::providers::codex::desktop_login::parse_device_code_line;
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        // UX-R1-H3 (lock symmetry, cross-provider): serialise this
        // invocation against any other `csq login N` for the SAME
        // account — CLI or desktop, any provider. `codex login
        // --device-auth` shares `CODEX_HOME=config-<N>/` with a
        // concurrent invocation for the same slot; without this lock two
        // processes race the subprocess's own `auth.json` write (before
        // either reaches `providers::codex::login::perform_with`'s
        // `ProfilesFileLock`, which only serialises the identity-mint +
        // canonical-save step, not the codex-cli subprocess itself).
        // Acquired FIRST, before the interactive ToS-prerequisite prompt,
        // so contention is reported immediately rather than after the
        // user has already read the prerequisite and pressed Enter.
        let login_lock = std::sync::Arc::new(acquire_login_lock(base_dir, account, None)?);

        // Fail-FAST drivability guard (an internal ticket), FIRST: refuse a non-interactive stdin before the
        // prerequisite banner, the browser open and the Enter read below. That read blocks until the
        // operator presses Enter; on an OPEN non-TTY stdin (unattended runner, `trestle`,
        // `echo | csq login`) it never returns, and the EOF check after it only catches a CLOSED
        // stdin. ORDER IS LOAD-BEARING: this guard must stay ahead of the read. It also runs ahead of
        // `cli_deps_gate::enforce` (step 4 below), so an unattended host is told to find a TTY before
        // it is told about the vendor-CLI state; the Enter read already preceded that gate, so no
        // earlier behaviour regressed. With a TTY (or the test-utils bypass) it passes and the
        // interactive path is unchanged.
        guard_login_drivability("codex", json)?;

        const SETTINGS_URL: &str = "https://chatgpt.com/#settings/Security";

        eprintln!(
            "==> Codex device-auth prerequisite\n\
         \n\
         Codex requires \"Device code authorization\" to be ENABLED in your\n\
         ChatGPT Security Settings BEFORE the device code can be redeemed.\n\
         Without this toggle, OpenAI's browser flow rejects the code with\n\
         \"Enable device code authorization for Codex in ChatGPT Security\n\
         Settings, then run 'codex login --device-auth' again\".\n\
         \n\
         I'll open the Settings page for you in a moment. Look for\n\
         \"Device code authorization\" under Security and turn it ON, then\n\
         press Enter here to continue.\n"
        );
        let _ = std::io::stderr().flush();

        // Auto-open the Settings page (best-effort — failure is logged and
        // the user can navigate manually).
        if let Err(e) = open_in_browser(SETTINGS_URL) {
            let e_redacted = csq_core::error::redact_tokens(&e.to_string());
            eprintln!(
                "(could not auto-open browser to {SETTINGS_URL}: {e_redacted}; open it manually)"
            );
        }

        // Block until the operator confirms the toggle is enabled.
        eprint!("Press Enter when 'Device code authorization' is enabled (or Ctrl-C to abort)... ");
        let _ = std::io::stderr().flush();
        let mut buf = String::new();
        let n = std::io::stdin()
            .read_line(&mut buf)
            .context("waiting for Enter to confirm device-auth prerequisite")?;
        // Detect stdin-at-EOF (no TTY allocated, or stdin redirected from
        // /dev/null) so we don't silently skip the operator-confirmation
        // gate and immediately spawn `codex login --device-auth`. Without
        // this check, an ssh-without-`-t` shell observes a "press Enter"
        // prompt that flashes past instantly.
        if n == 0 {
            return Err(anyhow!(
                "stdin reached EOF before the device-auth prerequisite was confirmed — \
             this terminal has no TTY (re-connect with `ssh -t ...`, run inside tmux/screen, \
             or invoke `csq login` from an interactive shell)"
            ));
        }
        eprintln!();

        // ── Pre-flight probe (PR-MCD2, spec/13 §3, R1-C2) ────────────────────
        // Probe is spawn-adjacent: placed AFTER the user's interactive Enter
        // and IMMEDIATELY before Command::new("codex") to close the TOCTOU
        // window. Probe-disabled WARN is emitted by probe() itself per R2-N4;
        // login handler does NOT duplicate it.
        super::cli_deps_gate::enforce(
            SurfaceCli::Codex,
            ignore_cli_version,
            no_auto_update_cli,
            track_latest,
            base_dir,
            &format!("csq login {account} --provider codex"),
        )?;

        // ─────────────────────────────────────────────────────────────────────

        // Custom spawn function: pipe codex-cli's stdout, tee to terminal,
        // auto-launch the verification URL when seen.
        let already_opened = Arc::new(AtomicBool::new(false));
        let already_opened_clone = already_opened.clone();
        let grant = Arc::new(std::sync::Mutex::new(
            csq_core::accounts::credential_transaction::VendorLoginGrant::new(base_dir)?,
        ));
        let vendor_grant = Arc::clone(&grant);
        let vendor_lock = std::sync::Arc::clone(&login_lock);
        let spawn = move |config_dir: &Path| -> Result<std::process::ExitStatus> {
            let mut command = Command::new("codex");
            command
                .args(["login", "--device-auth"])
                .env("CODEX_HOME", config_dir)
                .env_remove("CLAUDE_CONFIG_DIR")
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            // perform_with holds StdoutLock: this callback must stay on its caller.
            let on_line = |line: String| {
                // Tee to the operator's terminal so they still see codex-cli's UI.
                println!("{line}");
                let _ = std::io::stdout().flush();

                // codex-cli v0.128.0 splits URL and code across separate
                // lines (URL on one paragraph, code on the next). The
                // older same-line `parse_device_code_line` parser misses
                // this shape — try both. Browser launch fires on the URL
                // alone, since that's the action the user needs to take.
                if !already_opened_clone.load(Ordering::SeqCst) {
                    let url = parse_device_code_line(&line)
                        .map(|info| info.verification_url)
                        .or_else(|| extract_device_auth_url(&line));
                    if let Some(url) = url {
                        if !already_opened_clone.swap(true, Ordering::SeqCst) {
                            eprintln!("==> Auto-opening verification URL in your browser: {url}");
                            if let Err(e) = open_in_browser(&url) {
                                let e_redacted = csq_core::error::redact_tokens(&e.to_string());
                                eprintln!(
                                "(could not auto-open browser: {e_redacted}; copy the URL above manually)"
                            );
                            }
                            let _ = std::io::stderr().flush();
                        }
                    }
                }
            };
            let result = crate::login_cancel_guard::spawn_cli_piped_login_scoped(
                &mut command,
                login_subprocess_timeout(),
                (vendor_lock, Arc::clone(&vendor_grant)),
                "Codex",
                on_line,
                |notice| crate::login_cancel_guard::print_cli_notice(notice, account),
                cancellation,
            );
            crate::login_cancel_guard::complete_vendor_grant(&vendor_grant, result)
        };

        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        let outcome = csq_core::providers::codex::login::perform_with_seal_and_grant(
            base_dir,
            account,
            (&mut reader, &mut writer),
            csq_core::providers::codex::keychain::probe_residue,
            csq_core::providers::codex::keychain::purge_residue,
            spawn,
            (|| cancellation.seal_publication(), Arc::clone(&grant)),
        )
        .with_context(|| format!("codex device-auth login for account {account}"));
        // Preserve committed truth even if a later private grant cleanup refuses.
        if outcome.is_ok() {
            cancellation.mark_publication_committed();
        }
        crate::login_cancel_guard::cleanup_vendor_grant(&grant, outcome)?;

        // Task 7: notify the daemon so its discovery_cache + refresh-status cache
        // are invalidated. Without this, the daemon would not know about the newly
        // provisioned Codex slot's identity-keyed credentials until the next
        // restart or periodic reconciliation tick.
        notify_daemon_cache_invalidation(base_dir);

        // login-followup LOW-8 (same class as `finalize_verified`): the codex
        // binding just COMMITTED, so wake the usage poller too. `codex::tick`
        // rides the same 5-minute Anthropic cadence, so without this the freshly
        // bound slot shows no quota for up to `POLL_INTERVAL`.
        wake_usage_poller(base_dir, account);

        // Ledger #5: join the new slot to the cross-slot session store. Placed on
        // the SUCCESS path only, after the identity is minted, and advisory by
        // construction — `share_after_login` returns a report, never a `Result`,
        // so a migration problem cannot cost the operator the login they just
        // completed. See `sessions::share_after_login` for the guard semantics.
        eprintln!(
            "{}",
            super::sessions::share_after_login(base_dir, account, Surface::Codex)
        );

        Ok(())
    })
}

/// `csq login N --provider gemini` — Code Assist OAuth binding
/// (an internal journal entry design — gemini-cli v0.41.2+ has no non-interactive
/// auth surface). Delegates to
/// `csq_core::providers::gemini::oauth_login::perform` which:
///
/// 1. **Pre-flight probe** (PR-MCD2, spec/13 §3, R1-C2): inserted
///    IMMEDIATELY before the gemini oauth-check spawn to close the
///    TOCTOU window. `Outdated` / `UnrecognizedVersion` bail by default;
///    `--ignore-cli-version` downgrades to WARN.
/// 2. Verifies `~/.gemini/oauth_creds.json` exists, parses, and
///    carries a non-expired `access_token`.
/// 3. Writes the binding marker `auth = CodeAssistOAuth`.
///
/// The user MUST have already run `gemini` once interactively
/// (gemini-cli's first-run UI: select "Sign in with Google" → browser
/// flow → quit). csq does not drive OAuth itself — gemini-cli is the
/// reference client per `feedback_delegate_to_reference_client`.
/// Subsequent `csq run <slot>` invocations pin
/// `selectedType=oauth-personal` in the per-slot settings.json so
/// gemini-cli skips the first-run picker (an internal journal entry).
///
/// Stage 2 of an internal journal entry
fn handle_gemini_oauth(
    base_dir: &Path,
    account: AccountNum,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    track_latest: bool,
    json: bool,
) -> Result<()> {
    // UX-R1-H3 (lock symmetry, cross-provider): serialise this
    // invocation against any other `csq login N` for the SAME
    // account — CLI or desktop, any provider. Two concurrent
    // `csq login N --provider gemini` processes both race
    // `oauth_login::perform`'s OAuth-flow-then-verify sequence
    // against the SAME shared `~/.gemini/oauth_creds.json` (gemini-cli
    // has no per-slot credential store — see the `oauth_login` module
    // doc for the design), and both write the same per-slot
    // `profiles.json` + identity marker on completion. Without this
    // lock the last writer wins silently. Acquired FIRST, before the
    // pre-flight CLI-version probe (which itself spawns
    // `gemini --version`), so contention is reported before any
    // subprocess or the interactive browser-OAuth wait inside
    // `perform`.
    let _lock = acquire_login_lock(base_dir, account, None)?;

    // ── Pre-flight probe (PR-MCD2, spec/13 §3, R1-C2) ────────────────────
    // Probe is spawn-adjacent: placed IMMEDIATELY before the gemini
    // credential-check invocation to close the TOCTOU window. Probe-disabled
    // WARN is emitted by probe() itself per R2-N4; login handler does NOT
    // duplicate it.
    super::cli_deps_gate::enforce(
        SurfaceCli::Gemini,
        ignore_cli_version,
        no_auto_update_cli,
        track_latest,
        base_dir,
        &format!("csq login {account} --provider gemini"),
    )?;

    // Fail-FAST drivability guard (an internal ticket) — a provider whose login flow needs an
    // attended session (a TTY to block a confirmation read on, or a local browser
    // its subprocess drives) refuses IMMEDIATELY rather than proceeding into a
    // wait an unattended host can never satisfy.
    //
    // ORDER IS LOAD-BEARING: this runs AFTER `cli_deps_gate::enforce` above, not
    // before the dispatch. Placing it earlier pre-empted the version gate, so a
    // headless operator whose vendor CLI was outdated/missing was told to find a
    // TTY instead of being told their CLI is unusable — they would fix the wrong
    // thing first, then hit the real problem. The vendor-CLI state is the more
    // fundamental and more actionable failure, and it must be reported first.
    // (Caught by `cli_deps_login_integration`: 26 pass on main, 14 with the guard
    // hoisted ahead of the gate.) The gate is itself timeout-bounded, so running
    // it first preserves an internal ticket's no-hang property.
    guard_login_drivability("gemini", json)?;
    // ─────────────────────────────────────────────────────────────────────

    // Redact at the IPC / process boundary: defense-in-depth in
    // case a downstream `ProvisionError` carries a token-bearing
    // path or reason in its Display chain (round-2 redteam MED).
    csq_core::providers::gemini::oauth_login::perform(base_dir, account).map_err(|e| {
        let redacted = csq_core::error::redact_tokens(&e.to_string());
        anyhow!("Code Assist OAuth login for slot {account}: {redacted}")
    })?;
    // Symmetric with handle_codex (Task 7) and finalize() — invalidate
    // daemon discovery_cache + refresh-status cache on every successful
    // login surface.
    notify_daemon_cache_invalidation(base_dir);

    // login-followup LOW-8 (same class as `finalize_verified`): the Code
    // Assist binding just COMMITTED, so wake the usage poller. `gemini_oauth::
    // tick` rides the Anthropic cadence, so without this a fresh OAuth
    // binding shows no quota for up to `POLL_INTERVAL`.
    wake_usage_poller(base_dir, account);
    eprintln!(
        "info: slot {account} bound in Code Assist OAuth mode. \
         Run `csq run {account}` to start a Gemini session."
    );
    Ok(())
}

// pre_flight_check moved to super::cli_deps_gate::enforce (H4 extraction, R1 redteam).
// Both handle_codex and handle_gemini_oauth now delegate to that shared function.

/// `csq login N --provider kimi-cli|grok` (Wave B, an internal journal entry) — binds a
/// slot to a native, self-authenticating vendor CLI via a **per-slot vendor
/// home** (`native::native_home_path`), the `CODEX_HOME` isolation pattern
/// without codex's UUID/symlink/relocation machinery (native surfaces
/// self-refresh in place; csq never centrally rotates their tokens). Two
/// slots on the same provider get distinct homes, so a provider supports
/// multiple independent accounts. csq still writes NO credentials of its
/// own — only the credential-less binding marker
/// ([`csq_core::providers::native::write_binding`]) — but the marker is now
/// written **only after** a real vendor login succeeds and its credential
/// file is confirmed present ([`csq_core::providers::native::has_credentials`]),
/// superseding the 0133 marker-only design (a marker used to mean "slot
/// wants this surface"; it now means "slot has a working native login").
///
/// Steps:
/// 1. **Pre-flight probe** ([`super::cli_deps_gate::enforce`]) — the same
///    binary-presence + version-floor gate every other surface's login uses.
///    `Missing` bails unconditionally (spec/13 §3); `Outdated` /
///    `UnrecognizedVersion` downgrade to WARN under `--ignore-cli-version`.
/// 2. **Run the vendor's own device-auth login**
///    ([`csq_core::providers::native_login::login_native_cli_with`]) — spawns
///    `kimi login` / `grok login --device-auth` with stdio inherited (the
///    user sees the vendor's own device-code prompt directly) and
///    `<HOME_ENV>` set to this slot's isolated vendor home. On exit 0,
///    verifies the vendor's credential file landed under that home before
///    writing the binding marker; on spawn failure, non-zero exit, or a
///    missing credential file, returns `Err` with NO marker written.
/// 3. **Record `by_slot_identity[N]`** = `"kimi-<N>"` / `"grok-<N>"`
///    (mirrors [`csq_core::providers::gemini::provisioning::gemini_identity_label`]).
///    Non-fatal on failure — unlike Gemini's daemon backfill, native surfaces
///    have no backfill pass yet (tracked: an internal journal entry W3-6); the binding
///    marker written in step 2 remains the sole authority for "is this slot
///    bound", so a failed identity write leaves the slot fully usable.
/// 4. **Invalidate the daemon's discovery cache** (symmetric with every other
///    login surface).
fn handle_native(
    base_dir: &Path,
    account: AccountNum,
    surface: Surface,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    track_latest: bool,
    json: bool,
) -> Result<()> {
    crate::login_cancel_guard::with_cli_login_session(account, |cancellation| {
        let login_lock = std::sync::Arc::new(acquire_login_lock(base_dir, account, None)?);

        use csq_core::providers::native;
        use csq_core::providers::native_login;

        let descriptor = native::descriptor(surface).ok_or_else(|| {
            anyhow!(
                "internal error: {surface} is not a native-CLI surface (handle_native misrouted)"
            )
        })?;

        // Cross-surface conflict guard — parity with the desktop provision twin
        // (`provision_native_cli`) and `csq setkey` (redteam HIGH-2). Refuse if the
        // slot is already bound to another surface (Codex / Claude / Gemini / 3P /
        // the other native) so `csq login N --provider kimi-cli|grok` cannot
        // silently write a second binding marker that `csq run N` then mis-dispatches
        // (native is the lowest dispatch precedence) or the collision guard rejects.
        // Use the `BoundSurface`-returning guard directly (not the `Option<Surface>`
        // delegate) so a 3P-bearer conflict is labeled "a third-party provider", not
        // mislabeled "Claude (Anthropic OAuth)" via the `ThirdPartyBearer→ClaudeCode`
        // wire collapse (redteam R1 MEDIUM-1).
        if let Some(existing) =
            csq_core::accounts::binding_guard::conflicting_bound_surface(base_dir, account, surface)
        {
            return Err(anyhow!(
                "slot {account} is bound to {} — run `csq logout {account}` to rebind",
                existing.label()
            ));
        }

        // ── Pre-flight probe — same gate every surface's login uses ─────────────
        super::cli_deps_gate::enforce(
            descriptor.surface_cli,
            ignore_cli_version,
            no_auto_update_cli,
            track_latest,
            base_dir,
            &format!("csq login {account} --provider {}", descriptor.id),
        )?;

        // Fail-FAST drivability guard (an internal ticket) — a provider whose login flow needs an
        // attended session (a TTY to block a confirmation read on, or a local browser
        // its subprocess drives) refuses IMMEDIATELY rather than proceeding into a
        // wait an unattended host can never satisfy.
        //
        // ORDER IS LOAD-BEARING: this runs AFTER `cli_deps_gate::enforce` above, not
        // before the dispatch. Placing it earlier pre-empted the version gate, so a
        // headless operator whose vendor CLI was outdated/missing was told to find a
        // TTY instead of being told their CLI is unusable — they would fix the wrong
        // thing first, then hit the real problem. The vendor-CLI state is the more
        // fundamental and more actionable failure, and it must be reported first.
        // (Caught by `cli_deps_login_integration`: 26 pass on main, 14 with the guard
        // hoisted ahead of the gate.) The gate is itself timeout-bounded, so running
        // it first preserves an internal ticket's no-hang property.
        guard_login_drivability(descriptor.id, json)?;
        // ─────────────────────────────────────────────────────────────────────

        eprintln!(
            "Starting {} device-auth login for slot {account}...",
            descriptor.display_name
        );
        eprintln!(
            "{} will display a device code and verification URL below — this account \
         is isolated to slot {account}; other slots on the same provider are unaffected.",
            descriptor.binary
        );

        // Wave B (0135): runs the vendor's own device-auth login into this
        // slot's isolated vendor home, then verifies + writes the marker.
        // `login_native_cli_with` owns the marker write — no separate
        // `native::write_binding` call here (unlike the retired 0133 flow).
        native_login::login_native_cli_with_seal(
            base_dir,
            account,
            surface,
            |mut command| {
                crate::login_cancel_guard::spawn_cli_inherited_login_scoped(
                    &mut command,
                    login_subprocess_timeout(),
                    std::sync::Arc::clone(&login_lock),
                    descriptor.display_name,
                    |notice| crate::login_cancel_guard::print_cli_notice(notice, account),
                    cancellation,
                )
            },
            || cancellation.seal_publication(),
        )
        .map_err(|error| {
            if crate::login_cancel_guard::cli_error_exit_code(&error) == 130 {
                error.context(format!(
                "Login cancelled; no binding marker was published. Vendor files already written \
                 remain in this slot. Retry csq login {account} --provider {} to finish.",
                descriptor.id,
            ))
            } else {
                error
            }
        })?;

        // by_slot_identity[N] = "kimi-<N>" / "grok-<N>" — mirrors
        // `gemini::provisioning::write_gemini_identity`'s type-witnessed lock
        // acquisition. Non-fatal (see docstring above): the binding marker
        // already committed above is the sole authority for slot binding.
        let label = format!("{}-{account}", surface.as_str());
        match csq_core::accounts::profiles_lock::ProfilesFileLock::acquire(base_dir) {
            Ok(lock) => {
                if let Err(e) = csq_core::accounts::profiles::set_slot_identity(
                    &lock,
                    base_dir,
                    account.get(),
                    &label,
                ) {
                    tracing::warn!(
                        error_kind = "native_identity_write_failed",
                        surface = surface.as_str(),
                        account = account.get(),
                        "by_slot_identity[{account}] write failed (slot usable; \
                     no backfill pass exists yet for native surfaces): {e}"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error_kind = "native_identity_lock_failed",
                    surface = surface.as_str(),
                    account = account.get(),
                    "profiles lock unavailable while writing by_slot_identity[{account}] \
                 (slot usable): {e}"
                );
            }
        }

        // Symmetric with handle_codex / handle_gemini_oauth — invalidate daemon
        // discovery_cache + refresh-status cache on every successful login surface.
        notify_daemon_cache_invalidation(base_dir);

        // Ledger #5 — same success-path join as handle_codex. Today the kimi/grok
        // live-writer guard cannot determine liveness, so this reports a SKIP and
        // migrates nothing; that refusal is correct, and printing it is what stops
        // it reading as a successful share.
        eprintln!(
            "{}",
            super::sessions::share_after_login(base_dir, account, surface)
        );

        eprintln!(
            "info: slot {account} bound to {} ({}). Run `csq run {account}` to start a session.",
            descriptor.display_name, descriptor.binary
        );
        Ok(())
    })
}

// `which_claude` was inlined and replaced by
// `csq_core::accounts::login::find_claude_binary`, which also walks
// well-known install paths so Finder-launched apps (the desktop
// bundle) can find `claude` even when their `$PATH` is the minimal
// Finder default.

/// Pure diagnostic only: does not open a vault, acquire login locks, or probe.
#[cfg(unix)]
fn daemon_login_not_running_reason() -> String {
    format!(
        "csq daemon is not running — {}",
        daemon::recovery::recovery_guidance()
    )
}

/// Daemon-delegated paste-code login path (deprecated for CLI).
///
/// **Status**: kept for backward compatibility with the desktop
/// shim during the parallel-race transition. The CLI default is
/// now [`handle_race`] (in-process, no daemon dependency, no
/// `claude` binary on PATH). Once the desktop migrates to the
/// in-process orchestrator this function and its helpers are slated
/// for removal.
///
/// Steps:
///
/// 1. Detect the healthy daemon; require `DetectResult::Healthy`.
/// 2. `GET /api/login/{N}` — daemon mints a PKCE state and returns
///    the Anthropic authorize URL + state token.
/// 3. Open the URL in the user's browser.
/// 4. Prompt on stdin for the authorization code shown on
///    Anthropic's hosted callback page.
/// 5. `POST /api/oauth/exchange` with `{state, code}` — daemon
///    runs the token exchange and writes `credentials/{N}.json`.
/// 6. Finalize (profile update, marker, broker-failed clear).
#[cfg(unix)]
#[allow(dead_code)]
fn handle_paste_code(base_dir: &Path, account: AccountNum) -> Result<()> {
    // UX-R1-H3: same lock as handle_race for symmetry. The
    // daemon-delegated path also stomps credentials/N.json on the
    // last writer, so it benefits from the same serialisation.
    let _lock = acquire_login_lock(base_dir, account, Some("--legacy-shell"))?;

    // Step 1: detect the daemon.
    let socket_path = match daemon::detect_daemon(base_dir) {
        DetectResult::Healthy {
            socket_path,
            daemon_version,
            ..
        } => {
            // A daemon predating the OAuth exchange wire-shape we expect
            // can return a parseable but stale `/api/login/N` body. Refuse
            // rather than route the user through an exchange against the
            // wrong PKCE/state shape.
            if let Some(reason) = daemon::version_drift_reason(&daemon_version) {
                return Err(anyhow!("daemon is stale: {reason}"));
            }
            socket_path
        }
        DetectResult::NotRunning => {
            return Err(anyhow!("{}", daemon_login_not_running_reason()));
        }
        DetectResult::Stale { reason } => {
            return Err(anyhow!("csq daemon is stale: {reason}"));
        }
        DetectResult::Unhealthy { reason } => {
            return Err(anyhow!("csq daemon is unhealthy: {reason}"));
        }
    };

    // Step 2: ask the daemon to start an OAuth login.
    let path_and_query = format!("/api/login/{}", account.get());
    let resp = daemon::http_get_unix(&socket_path, &path_and_query)
        .map_err(|e: DaemonClientError| anyhow!("daemon login call failed: {e}"))?;

    match resp.status {
        200 => {}
        400 => {
            return Err(anyhow!(
                "daemon rejected account {}: {}",
                account,
                resp.body.trim()
            ));
        }
        503 => {
            return Err(anyhow!(
                "daemon was started without OAuth support — login unavailable"
            ));
        }
        other => {
            return Err(anyhow!(
                "daemon returned HTTP {other} on /api/login/{}: {}",
                account,
                resp.body.trim()
            ));
        }
    }

    let login = parse_login_response(&resp.body)
        .with_context(|| "could not parse daemon /api/login response")?;

    // Step 3: open the authorize URL.
    println!(
        "Starting OAuth login for account {} (paste-code flow)...",
        account
    );
    println!("Opening your browser to:");
    println!("  {}", login.auth_url);
    println!();

    if let Err(e) = open_in_browser(&login.auth_url) {
        let e_redacted = csq_core::error::redact_tokens(&e.to_string());
        eprintln!("warning: could not spawn browser opener: {e_redacted}");
        eprintln!("         open the URL above by hand to continue.");
    }

    // Step 4: prompt for the authorization code.
    println!("After authorizing, Anthropic's page will display a code.");
    print!("Paste the authorization code here: ");
    std::io::stdout()
        .flush()
        .context("failed to flush stdout before paste-code prompt")?;

    let mut line = String::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle
        .read_line(&mut line)
        .context("failed to read authorization code from stdin")?;
    let code = line.trim().trim_end_matches('\r').trim().to_string();
    if code.is_empty() {
        return Err(anyhow!("paste was empty; login cancelled"));
    }

    // Step 5: POST /api/oauth/exchange with {state, code}.
    let exchange_body = serde_json::json!({
        "state": login.state,
        "code": code,
    });
    let exchange_body_str = serde_json::to_string(&exchange_body)
        .context("failed to serialize /api/oauth/exchange request body")?;

    let exchange_resp =
        daemon::http_post_unix_json(&socket_path, "/api/oauth/exchange", &exchange_body_str)
            .map_err(|e: DaemonClientError| anyhow!("daemon exchange call failed: {e}"))?;

    match exchange_resp.status {
        200 => {}
        400 => {
            return Err(anyhow!(
                "daemon rejected exchange: {}",
                exchange_resp.body.trim()
            ));
        }
        502 => {
            return Err(anyhow!(
                "Anthropic rejected the authorization code: {}",
                exchange_resp.body.trim()
            ));
        }
        503 => {
            return Err(anyhow!(
                "daemon was started without OAuth support — exchange unavailable"
            ));
        }
        other => {
            return Err(anyhow!(
                "daemon returned HTTP {other} on /api/oauth/exchange: {}",
                exchange_resp.body.trim()
            ));
        }
    }

    // Step 6: finalize.
    println!("Credentials written for account {}.", account);
    // The daemon already verified and finalized this exact exchanged grant.
    // Re-reading ambient native metadata here could undo its organization binding.
    notify_daemon_cache_invalidation(base_dir);
    Ok(())
}

// `extract_device_auth_url` and the supporting `strip_ansi_escapes` /
// `CODEX_DEVICE_AUTH_HOST_ALLOWLIST` live in
// `csq_core::providers::codex::desktop_login` so the desktop and CLI
// device-auth paths share a single canonical extractor with the same
// trust-boundary defenses.

/// Subset of the daemon's `LoginRequest` JSON we need.
///
/// Defined locally so the CLI is not coupled to the full struct's
/// layout — `auth_url` + `state` are the load-bearing fields.
///
/// Used only by [`handle_paste_code`], which is kept around for
/// the desktop shim transition. Marked `dead_code`-allowed
/// because the CLI default no longer reaches this path.
#[cfg(unix)]
#[derive(Debug)]
#[allow(dead_code)]
struct DaemonLoginRequest {
    auth_url: String,
    state: String,
}

#[cfg(unix)]
#[allow(dead_code)]
fn parse_login_response(body: &str) -> Result<DaemonLoginRequest> {
    let json: serde_json::Value = serde_json::from_str(body)
        .with_context(|| format!("response is not valid JSON: {body}"))?;
    let auth_url = json
        .get("auth_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("response is missing 'auth_url' field"))?
        .to_string();
    if auth_url.is_empty() {
        return Err(anyhow!("response 'auth_url' is empty"));
    }
    let state = json
        .get("state")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("response is missing 'state' field"))?
        .to_string();
    if state.is_empty() {
        return Err(anyhow!("response 'state' is empty"));
    }
    Ok(DaemonLoginRequest { auth_url, state })
}

/// Spawns the platform-appropriate "open a URL in the default
/// browser" command. Best-effort — failures are reported but do not
/// abort the login (the user can paste the URL by hand).
///
/// Security: the URL comes from the daemon's `start_login`, which
/// composes it from trusted constants + validated PKCE + state
/// tokens. It never contains shell metacharacters that could escape
/// an argv. Even so, we pass the URL as a single `arg()` entry, not
/// via a shell string, so no shell parsing is involved.
fn open_in_browser(url: &str) -> Result<()> {
    // NON-INTERACTIVE GUARD (all platforms). Hijacking the operator's browser
    // is only defensible when there is a human at this terminal to act on the
    // page. A `csq login --provider codex` run from a script, a CI step, or an
    // agent session still printed its "press Enter to continue" prompt AND
    // opened `https://chatgpt.com/#settings/Security` in whatever browser
    // happened to be frontmost — a prompt nobody can answer plus a stolen
    // window, repeating on every invocation. Reported by the maintainer
    // 2026-09-12: "why do you keep triggering [the ChatGPT security settings
    // page] to pop on my browser?"
    //
    // Same predicate as the ToS prompt above (`stdin().is_terminal()` plus the
    // integration-test bypass), so the two cannot disagree about whether a
    // session is interactive. The caller's "open it manually" fallback already
    // prints the URL, so a skipped open loses nothing.
    //
    // The Linux block below stays: it answers a DIFFERENT question — whether a
    // GUI exists at all — and an interactive SSH session has a TTY and no
    // display.
    {
        use std::io::IsTerminal;
        if !(std::io::stdin().is_terminal() || super::cli::check_test_bypass()) {
            return Err(anyhow!(
                "not an interactive terminal — not opening a browser; \
                 open this URL yourself: {url}"
            ));
        }
    }

    // Headless Linux guard: if neither $DISPLAY (X11) nor $WAYLAND_DISPLAY
    // is set, there is no GUI session to deliver a URL to. Skipping the
    // spawn lets the caller's "open this URL manually" fallback fire
    // cleanly and prevents xdg-open from launching a Chromium
    // subprocess that spews `ozone_platform_x11` / `aura/env` errors
    // into csq's stderr stream. Fixes the head-on-server flow where
    // csq login prints chromium noise between its prompt lines.
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none_or(|v| v.is_empty())
        && std::env::var_os("WAYLAND_DISPLAY").is_none_or(|v| v.is_empty())
    {
        let _ = url;
        return Err(anyhow!(
            "no GUI display detected (DISPLAY/WAYLAND_DISPLAY unset) — \
             open the URL manually in a browser on a GUI machine"
        ));
    }

    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };

    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        // Suppress the spawned browser's stderr/stdout so chromium's
        // ozone-platform noise (when xdg-open's chosen browser is
        // misconfigured) does not interleave with csq's prompts. The
        // browser's stdio is inherited from xdg-open, which we
        // redirect to /dev/null here.
        c.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        c
    };

    #[cfg(target_os = "windows")]
    let mut cmd = {
        // `cmd /c start "" <url>` — the empty "" is the window
        // title, which `start` treats as the first quoted arg.
        let mut c = Command::new("cmd");
        c.args(["/c", "start", "", url]);
        c
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let mut cmd = {
        let _ = url;
        return Err(anyhow!("no browser-open helper for this platform"));
    };

    let status = cmd.status().context("failed to spawn browser opener")?;
    if !status.success() {
        return Err(anyhow!("browser opener exited with non-zero status"));
    }
    Ok(())
}

/// Direct login path — fallback when the daemon is not available.
///
/// Spawns `claude auth login` with an isolated `CLAUDE_CONFIG_DIR`
/// and captures credentials from the keychain or the
/// `.credentials.json` file.
fn handle_direct(base_dir: &Path, account: AccountNum, json: bool) -> Result<()> {
    // an internal ticket drivability guard. Claude is the ONE provider with no
    // `cli_deps_gate::enforce` of its own (it shells out to `claude auth
    // login`, whose availability is not version-gated here), so there is no
    // earlier gate to order behind — the guard runs first thing instead.
    guard_login_drivability("claude", json)?;

    crate::login_cancel_guard::with_cli_login_session(account, |cancellation| {
        let login_lock = std::sync::Arc::new(acquire_login_lock(
            base_dir,
            account,
            Some("--legacy-shell"),
        )?);
        let prior = capture_prior_for_cli(base_dir, account)?;
        csq_core::platform::fs::ensure_private_dir_root(base_dir)
            .map_err(|error| anyhow!("accounts_root_refused: {error}"))?;
        let grant = std::sync::Arc::new(std::sync::Mutex::new(
            csq_core::accounts::credential_transaction::VendorLoginGrant::new(base_dir)?,
        ));
        let config_dir = grant
            .lock()
            .map_err(|_| anyhow!("vendor grant lock poisoned"))?
            .config_dir()
            .to_path_buf();
        println!("Starting OAuth login for account {account}...");
        println!("Your browser will open for authorization.");
        let result = (|| -> Result<()> {
            let mut command = claude_login_command(&config_dir)?;
            grant
                .lock()
                .map_err(|_| anyhow!("vendor grant lock poisoned"))?
                .begin_launch()?;
            let login_timeout = login_subprocess_timeout();
            // Keyed on the stop having ACTUALLY SUCCEEDED, carried out of the
            // wait loop — never on the refusal cause, so a setup refusal that
            // came first still prints the paragraph.
            let mut deadline_stopped = false;
            let vendor_result = crate::login_cancel_guard::spawn_cli_login_scoped(
                &mut command,
                login_timeout,
                (
                    std::sync::Arc::clone(&login_lock),
                    std::sync::Arc::clone(&grant),
                ),
                |notice| crate::login_cancel_guard::print_cli_notice(notice, account),
                cancellation,
                &mut deadline_stopped,
            );
            // S1's operator message, restored verbatim and printed only AFTER
            // the vendor's actual reap (spawn_cli_login_scoped returns after
            // it): the deadline refusal must stay actionable.
            if deadline_stopped {
                eprintln!(
                    "`claude auth login` did not complete within {}s and was \
                     terminated — the browser OAuth callback never returned \
                     (this happens when the redirect lands on a page that 404s). \
                     Re-run `csq login {account}`, or use the desktop app's \
                     Add Account flow, which uses a different callback path. \
                     Set CSQ_LOGIN_TIMEOUT_SECS to change the timeout.",
                    login_timeout.as_secs()
                );
            }
            let exit = crate::login_cancel_guard::complete_vendor_grant(&grant, vendor_result)?;
            if !exit.success() {
                return Err(anyhow!("claude auth login {exit}"));
            }
            // The vendor, native expectation and fresh credential capture all
            // use the SAME unique grant home, never the prior canonical slot.
            let expected = read_native_expectation(&config_dir)?;
            let creds = credentials::read_fresh_after_login(&config_dir)
                .map_err(|error| anyhow!("{error}"))?;
            let committed = csq_core::accounts::anthropic_identity::commit_anthropic_login_sealed(
                base_dir,
                account,
                &creds,
                Some(&expected),
                prior,
                || cancellation.seal_publication(),
            )?;
            finalize_verified(base_dir, account, committed)?;
            cancellation.mark_publication_committed();
            Ok(())
        })();
        // Created grants may be cleaned without a launch; Spawning grants
        // refuse cleanup unless a positive actual completion receipt fenced it.
        crate::login_cancel_guard::cleanup_vendor_grant(&grant, result)
    })
}

/// The wiring of [`handle_direct`] with the subprocess and the verified
/// commit injected: lock, prior capture, handle-dir creation, subprocess,
/// post-subprocess commit, then `finalize_verified`. Production passes the
/// real `claude auth login` runner and commit; tests pass stubs so the
/// wiring itself (notably the finalize call) is observable without a
/// browser, network or keychain.
#[cfg(all(test, unix))]
fn handle_direct_flow(
    base_dir: &Path,
    account: AccountNum,
    run_login: impl FnOnce(&Path) -> Result<bool>,
    post: impl FnOnce(&Path, bool, LoginPrior) -> Result<CommittedAnthropicLogin>,
) -> Result<()> {
    // UX-R1-H3 (lock symmetry): serialise concurrent invocations.
    let _lock = acquire_login_lock(base_dir, account, Some("--legacy-shell"))?;
    let prior = capture_prior_for_cli(base_dir, account)?;

    // SEC-2.15 (unified, R1 M1): secure the accounts root (config-N's
    // parent) fail-closed before creating the handle dir.
    csq_core::platform::fs::ensure_private_dir_root(base_dir)
        .map_err(|e| anyhow::anyhow!("accounts_root_refused: {e}"))?;
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)?;

    println!("Starting OAuth login for account {}...", account);
    println!("Your browser will open for authorization.");

    let subprocess_succeeded = run_login(&config_dir)?;
    let committed = post(&config_dir, subprocess_succeeded, prior)?;
    finalize_verified(base_dir, account, committed)
}

/// Run `claude auth login` against `config_dir` and report whether it exited
/// successfully. Enforces the watchdog timeout.
fn claude_login_command(config_dir: &Path) -> Result<Command> {
    let claude_bin = csq_core::accounts::login::find_claude_binary().ok_or_else(|| {
        anyhow!(
            "claude binary not found on PATH or well-known locations \
             (~/.local/bin, ~/.npm-global/bin, ~/.bun/bin, ~/.cargo/bin, \
             /opt/homebrew/bin, /usr/local/bin) — install Claude Code first \
             (https://claude.com/code)"
        )
    })?;

    let mut command = Command::new(&claude_bin);
    command
        .args(["auth", "login"])
        .env("CLAUDE_CONFIG_DIR", config_dir);
    Ok(command)
}

/// Watchdog timeout for the interactive `claude auth login` subprocess.
///
/// Default 300s (5 min) — comfortably longer than a normal human OAuth flow
/// (open browser → authorize → redirect), but finite so a hung callback cannot
/// hide the named refusal indefinitely. Custody still lasts until actual reap.
/// Overridable via
/// `CSQ_LOGIN_TIMEOUT_SECS`; a non-numeric or zero value falls back to the
/// default (zero would refuse every login immediately).
fn login_subprocess_timeout() -> Duration {
    parse_login_timeout(std::env::var("CSQ_LOGIN_TIMEOUT_SECS").ok().as_deref())
}

/// Pure parse of the `CSQ_LOGIN_TIMEOUT_SECS` value (split out for hermetic
/// testing — no env mutation). A non-numeric, empty, or zero value falls back
/// to the 300s default (zero would refuse every login immediately).
fn parse_login_timeout(raw: Option<&str>) -> Duration {
    crate::login_child_custody::parse_timeout(raw)
}

/// Post-subprocess work for [`handle_direct`]: capture credentials and verify
/// their complete provider context before canonical publication. Return the
/// receipt whose consuming finalizer writes the authoritative UUID marker.
///
/// Extracted so REV-R1-02 / M8 can be regression-tested without
/// spawning the real `claude` binary.
#[cfg(all(test, unix))]
fn handle_direct_post_subprocess(
    base_dir: &Path,
    account: AccountNum,
    config_dir: &Path,
    subprocess_succeeded: bool,
    prior: LoginPrior,
) -> Result<CommittedAnthropicLogin> {
    handle_direct_post_subprocess_using(
        base_dir,
        account,
        config_dir,
        subprocess_succeeded,
        prior,
        || credentials::read_fresh_after_login(config_dir).map_err(|e| anyhow!("{e}")),
        |credential, expected, prior| {
            let committed =
                commit_anthropic_login(base_dir, account, credential, Some(expected), prior);
            if committed.is_err() {
                report_undurable_rescue_refusal();
            }
            committed
        },
    )
}

/// Prints ONE fixed operator line when a refused login grant's rescue
/// record could not be discarded at all (tombstone and unlink both failed).
/// No payload, path or token is printed.
fn report_undurable_rescue_refusal() {
    if let Some(notice) = csq_core::credentials::rescue::take_refusal_not_durable_notice() {
        eprintln!("{notice}");
    }
}

// Only the Unix-gated test module calls this.
#[cfg(all(test, unix))]
fn handle_direct_post_subprocess_with(
    base_dir: &Path,
    account: AccountNum,
    config_dir: &Path,
    subprocess_succeeded: bool,
    prior: LoginPrior,
    profile: &csq_core::daemon::usage_poller::HttpGetFn,
    capture: impl FnOnce() -> Result<credentials::CredentialFile>,
) -> Result<CommittedAnthropicLogin> {
    handle_direct_post_subprocess_using(
        base_dir,
        account,
        config_dir,
        subprocess_succeeded,
        prior,
        capture,
        |credential, expected, prior| {
            csq_core::accounts::anthropic_identity::commit_anthropic_login_with(
                base_dir,
                account,
                credential,
                profile,
                Some(expected),
                prior,
            )
        },
    )
}

#[cfg(all(test, unix))]
fn handle_direct_post_subprocess_using(
    _base_dir: &Path,
    account: AccountNum,
    config_dir: &Path,
    subprocess_succeeded: bool,
    prior: LoginPrior,
    capture: impl FnOnce() -> Result<credentials::CredentialFile>,
    commit: impl FnOnce(
        &credentials::CredentialFile,
        &csq_core::accounts::anthropic_identity::NativeContextExpectation,
        LoginPrior,
    ) -> std::result::Result<
        CommittedAnthropicLogin,
        csq_core::accounts::anthropic_identity::IdentityError,
    >,
) -> Result<CommittedAnthropicLogin> {
    if !subprocess_succeeded {
        // REV-R1-02 (M8): do NOT write the .csq-account marker
        // when the subprocess failed. The marker is the "this dir
        // holds credentials for account N" sentinel; writing it
        // before confirming the subprocess succeeded leaves an
        // orphan marker that the daemon's discovery path treats
        // as a legitimate (but credential-less) account.
        return Err(anyhow!("claude auth login exited with non-zero status"));
    }

    // CC's modern `claude auth login` writes the freshly minted token to ONE
    // of two places, depending on platform / version:
    //   * macOS: the system keychain at the hashed service name
    //     (`Claude Code-credentials-{hash}`) — the commit can land a beat
    //     AFTER the subprocess exits, racing an immediate read.
    //   * Linux/Windows: always `.credentials.json`.
    //
    // `read_fresh_after_login` absorbs that race: it reads both sources,
    // keeps whichever has the later `expiresAt` (a stale `.credentials.json`
    // can never shadow a fresh keychain token), retries to let CC commit, and
    // errors rather than persisting an already-expired token. See
    // `csq_core::credentials::post_login` for the full rationale.
    // Native metadata is only an expectation. The selected captured token must
    // independently prove the complete account/organization context before save.
    let expected = read_native_expectation(config_dir)?;
    let creds = capture()?;
    let committed = commit(&creds, &expected, prior).map_err(|e| {
        anyhow!(
            "identity verification failed: {}",
            csq_core::accounts::login::LoginCommitOutcome::describe_error_for_account(&e, account)
        )
    })?;
    println!("Credentials saved for account {account}.");

    // The receipt-consuming finalizer owns the marker under binding authority.
    Ok(committed)
}

fn finalize_verified(
    base_dir: &Path,
    account: AccountNum,
    committed: CommittedAnthropicLogin,
) -> Result<()> {
    let email = csq_core::accounts::login::finalize_verified_login(base_dir, account, committed)
        .with_context(|| format!("finalize verified login for account {account}"))?;
    notify_daemon_cache_invalidation(base_dir);
    // login-followup: the login just COMMITTED (finalize above succeeded),
    // so wake the daemon's usage poller for an immediate quota tick —
    // otherwise the new slot shows no quota for up to 5 minutes.
    wake_usage_poller(base_dir, account);
    println!("Logged in as {} (account {}).", email, account);
    Ok(())
}

/// Best-effort cache invalidation: notify the daemon (Unix socket or
/// Windows named pipe) that on-disk account state changed. Routes through
/// the single cross-platform chokepoint — see `csq_core::daemon::notify`
/// (an internal ticket), which already logs a `tracing::warn!` on a reachable-
/// but-failing daemon.
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    csq_core::daemon::notify::cache_invalidation(base_dir);
}

/// Wake the daemon's usage poller for an IMMEDIATE quota tick after a
/// slot's identity has just been bound (login-followup LOW-8).
///
/// Called on the SUCCESS path of every login surface whose slot the daemon
/// polls on the fast (5-minute) cadence, AFTER the credential/profile write
/// has committed: Anthropic (`finalize_verified`), codex (`handle_codex`)
/// and Gemini Code Assist OAuth (`handle_gemini_oauth`). Without it a
/// freshly bound slot shows "no quota" for up to `POLL_INTERVAL`.
///
/// Best-effort by construction — see `csq_core::daemon::notify::slot_rebind`
/// (an internal ticket semantics): no daemon is the common case, the binding is already
/// durable when this runs, and a failed wake must never turn a completed
/// login into a failed one. The native kimi/grok surfaces deliberately do
/// NOT wake: their ticks ride the 3P cadence and a wake does not run the
/// 3P tick, so the call would be inert there.
fn wake_usage_poller(base_dir: &Path, account: AccountNum) {
    csq_core::daemon::notify::slot_rebind(base_dir, account.get());
}

// `get_email_from_cc` and `update_profile` were extracted to
// `csq_core::accounts::login::finalize_login` so the desktop's
// Add Account flow can call the same code. The legacy
// `claude auth status --json` fallback was dropped along the way
// because the `.claude.json` source is reliable on every CC version
// we've shipped against and `auth status` was only used to recover
// from a race that the file-source path (added in alpha.5) doesn't
// have.

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn cli_prior_capture_contention_prints_the_retry_remedy_not_the_bare_tag() {
        use csq_core::accounts::anthropic_identity::IdentityError as E;
        let busy = prior_capture_error_for_cli(E::BindingBusy).to_string();
        assert!(busy.contains("retry the login"), "{busy}");
        assert_ne!(busy, "anthropic_identity_profiles_busy");
        // Every other identity error keeps its exact text and type.
        let other = prior_capture_error_for_cli(E::MissingBinding);
        assert_eq!(other.to_string(), E::MissingBinding.to_string());
        assert_eq!(other.downcast_ref::<E>(), Some(&E::MissingBinding));
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn native_same_slot_concurrent_login_refuses_before_probe() {
        use std::ffi::OsString;
        use std::os::unix::fs::PermissionsExt;
        let _env_guard = csq_core::platform::test_env::lock();
        let private = tempfile::tempdir().unwrap();
        let home = private.path().join("home");
        let bin = private.path().join("bin");
        let base = private.path().join("base");
        for path in [&home, &bin, &base] {
            std::fs::create_dir_all(path).unwrap();
        }
        // OLD lockless handler may reach only this inert probe, never a real
        // known-install vendor. GREEN refuses at actual login-lock admission.
        let probe = bin.join("kimi");
        let probe_marker = private.path().join("unexpected-native-probe");
        std::fs::write(
            &probe,
            b"#!/bin/sh\n: > \"$CSQ_PRIVATE_NATIVE_PROBE_MARKER\"\nexit 64\n",
        )
        .unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o700)).unwrap();
        struct Restore(Vec<(&'static str, Option<OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, prior) in self.0.drain(..).rev() {
                    match prior {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
        let variables = [
            ("HOME", home.as_os_str()),
            ("PATH", bin.as_os_str()),
            ("CSQ_BASE_DIR", base.as_os_str()),
            ("CSQ_SECRET_BACKEND", std::ffi::OsStr::new("in-memory")),
            ("CSQ_PRIVATE_NATIVE_PROBE_MARKER", probe_marker.as_os_str()),
        ];
        let _restore = Restore(
            variables
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect(),
        );
        for (key, value) in variables {
            std::env::set_var(key, value);
        }
        let account = AccountNum::try_from(1_u16).unwrap();
        let _first_login = match AccountLoginLock::acquire(&base, account).unwrap() {
            AcquireOutcome::Acquired(lock) => lock,
            _ => panic!("private first login lock unexpectedly held"),
        };
        let error = handle_native(&base, account, Surface::Kimi, false, true, false, true)
            .expect_err("same-slot native admission must refuse");
        assert!(
            error
                .to_string()
                .contains("another csq login 1 is in progress")
                && !probe_marker.exists(),
            "LOGIN_NATIVE_CTRLC_CONCURRENT_LOCK_REFUSED"
        );
    }

    #[cfg(unix)]
    #[test]
    fn daemon_recovery_login_absent_daemon_requires_owner_verification() {
        let text = daemon_login_not_running_reason();
        assert!(text.contains("supervisor is unverified"));
        assert!(text.contains("Only for a confirmed standalone foreground"));
        assert!(text.contains("restarting the same old binary does not fix"));
        assert!(!text.contains("daemon stop && csq daemon start"));
        assert!(!text.contains("or install the desktop app"));
    }

    // ── Daemon paste-code parser regression tests (deprecated path) ──

    #[test]
    fn parse_login_response_extracts_auth_url() {
        let body = r#"{
            "auth_url": "https://claude.ai/oauth/authorize?client_id=abc&state=xyz",
            "state": "xyz",
            "account": 3,
            "expires_in_secs": 300
        }"#;
        let parsed = parse_login_response(body).unwrap();
        assert!(parsed
            .auth_url
            .starts_with("https://claude.ai/oauth/authorize"));
        assert!(parsed.auth_url.contains("state=xyz"));
    }

    #[test]
    fn parse_login_response_rejects_missing_auth_url() {
        let body = r#"{"state":"xyz","account":3}"#;
        let err = parse_login_response(body).unwrap_err();
        assert!(err.to_string().contains("auth_url"));
    }

    #[test]
    fn parse_login_response_rejects_empty_auth_url() {
        let body = r#"{"auth_url":"","state":"xyz","account":3}"#;
        let err = parse_login_response(body).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn parse_login_response_rejects_invalid_json() {
        let body = "not json";
        let err = parse_login_response(body).unwrap_err();
        assert!(err.to_string().contains("valid JSON"));
    }

    // ── login subprocess watchdog timeout parsing (hermetic; no env) ──

    #[test]
    fn parse_login_timeout_defaults_to_300s() {
        assert_eq!(parse_login_timeout(None), Duration::from_secs(300));
    }

    #[test]
    fn parse_login_timeout_honors_valid_override() {
        assert_eq!(parse_login_timeout(Some("600")), Duration::from_secs(600));
        assert_eq!(parse_login_timeout(Some(" 120 ")), Duration::from_secs(120));
    }

    #[test]
    fn parse_login_timeout_rejects_zero_and_garbage_falling_back_to_default() {
        // Zero would kill every login instantly; garbage/empty are user error.
        assert_eq!(parse_login_timeout(Some("0")), Duration::from_secs(300));
        assert_eq!(parse_login_timeout(Some("abc")), Duration::from_secs(300));
        assert_eq!(parse_login_timeout(Some("")), Duration::from_secs(300));
        assert_eq!(parse_login_timeout(Some("-5")), Duration::from_secs(300));
    }

    // ── Race-flow regression tests ─────────────────────────────────

    #[test]
    fn print_paste_prompt_includes_manual_url() {
        // Smoke test: the function should not panic and should
        // render the URL into stdout. We can't capture stdout in
        // a unit test without ceremony, but the function has no
        // branches — calling it once exercises the body.
        print_paste_prompt("https://example.invalid/manual");
    }

    #[test]
    fn stdin_paste_resolver_returns_a_paste_resolver() {
        // Type-shape assertion: stdin_paste_resolver must produce
        // an oauth::PasteResolver. The race orchestrator's
        // signature pins this; if the type drifts we want the
        // failure here, not in a downstream race test.
        let _r: oauth::PasteResolver = stdin_paste_resolver();
    }

    // GH an internal ticket retired the dispatch-level reverse conflict guard that
    // used to live here (`login_non_native_provider_refuses_native_bound_slot`
    // — redteam R1 MED): `csq login N --provider codex` onto a native-bound
    // slot no longer refuses in `handle()`'s dispatch; it now proceeds and
    // `providers::codex::login::perform_with` detects the stale native
    // marker pre-mint and clears it on the login's success path. That
    // behavior is covered where it now lives:
    // `perform_with_clears_stale_native_marker_after_login` (codex/login.rs)
    // and `finalize_login_clears_stale_native_marker` (accounts/login.rs) for
    // the Anthropic side, plus `detect_stale_marker_binding` /
    // `clear_detected_marker_binding`'s own unit tests
    // (accounts/binding_guard.rs) — including
    // `finalize_login_failure_preserves_prior_gemini_binding`, the
    // failed-login-must-not-destroy-the-prior-binding regression.

    // ── Forward guard (redteam R3 H1/M2): handle_native onto a bound slot ──

    #[test]
    fn handle_native_refuses_and_labels_3p_bearer_slot() {
        // redteam R3 H1/M2: `csq login N --provider kimi-cli` onto a slot bound
        // to a 3P-bearer provider must refuse in `handle_native`'s forward guard
        // (the R1 mislabel-fix site) and label it "a third-party provider" — NOT
        // the pre-fix "Claude (Anthropic OAuth)" that the ThirdPartyBearer→
        // ClaudeCode wire collapse would have produced.
        //
        // `handle_native` installs the process-global scoped login
        // cancellation guard before this refusal, so this test serializes on
        // the shared test lock with every other installer in the binary
        // (`login_cancel_guard::INSTALLATION`'s test contract).
        let _env_guard = csq_core::platform::test_env::lock();
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(9u16).unwrap();
        csq_core::accounts::third_party::bind_provider_to_slot(
            dir.path(),
            "deepseek",
            account,
            Some("sk-deepseek-xxxxxxxx"),
            None,
        )
        .unwrap();

        let err = handle(
            dir.path(),
            account,
            "kimi-cli",
            false,
            false,
            false,
            false,
            false,
            false,
            false, // json
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("a third-party provider"),
            "3P slot must be labeled accurately, got: {msg}"
        );
        assert!(
            !msg.contains("Claude (Anthropic OAuth)"),
            "must NOT mislabel a 3P slot as Anthropic, got: {msg}"
        );
    }

    // ── an internal ticket: fail-fast login-drivability guard ────────────────────

    /// Clears `CSQ_TEST_BYPASS_TTY` and restores its previous value on drop
    /// (also on a failed assertion). Callers hold the test-env lock.
    struct BypassTtyOff(Option<std::ffi::OsString>);

    impl BypassTtyOff {
        fn new() -> Self {
            let prev = std::env::var_os("CSQ_TEST_BYPASS_TTY");
            // SAFETY: callers hold `csq_core::platform::test_env::lock()`, the
            // process-wide lock every env-mutating test in this crate takes.
            unsafe { std::env::remove_var("CSQ_TEST_BYPASS_TTY") };
            Self(prev)
        }
    }

    impl Drop for BypassTtyOff {
        fn drop(&mut self) {
            if let Some(v) = self.0.take() {
                // SAFETY: still under the caller's test-env lock (dropped after).
                unsafe { std::env::set_var("CSQ_TEST_BYPASS_TTY", v) };
            }
        }
    }

    /// True (after printing why) when the harness stdin IS a terminal: the TTY-guard tests
    /// assume it never is, and at a terminal the guard passes and `handle` would open a
    /// browser, block on Enter and spawn the real vendor login.
    fn skip_at_terminal(test: &str) -> bool {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            eprintln!("SKIP {test}: stdin is a terminal, so the TTY guard would not fire");
            return true;
        }
        false
    }

    /// `cargo test`'s harness stdin is never a TTY, so `handle(..., "codex", ...)` on a
    /// clean slot (past the reverse-conflict guard, which these two tests already prove fires
    /// independently) must refuse with the drivability guard's own "attended session" message.
    /// The assertions check that message (and, for codex, that it is NOT the later
    /// "stdin reached EOF" error); they do not capture stderr, so "no banner / no browser" is
    /// established by the guard being the first statement after the lock, not by this test.
    /// A regression that moves the read ahead of the guard hangs this test on an open stdin.
    /// At a real terminal the guard would pass and `handle` would run a real login, so the
    /// test skips there with a printed reason ([`skip_at_terminal`]).
    #[test]
    fn handle_codex_refuses_fast_without_a_tty() {
        if skip_at_terminal("handle_codex_refuses_fast_without_a_tty") {
            return;
        }
        // The TTY guard also passes when the test-only `CSQ_TEST_BYPASS_TTY`
        // is set, and `check_test_bypass_honours_env_var` sets it process-wide
        // under the shared test-env lock. Hold that same lock and clear the var
        // for this test's duration; otherwise a concurrent run makes the guard
        // pass and `handle` blocks on the Enter read forever (observed hanging
        // the csq bins suite under trestle, where stdin never reaches EOF).
        let _env_guard = csq_core::platform::test_env::lock();
        let _bypass_off = BypassTtyOff::new();
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(9u16).unwrap();

        let err = handle(
            dir.path(),
            account,
            "codex",
            false, // legacy_shell
            false, // reset_handle_dir
            false, // non_interactive
            false, // ignore_cli_version
            false, // no_auto_update_cli
            false, // track_latest
            false, // json
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("attended session") && !msg.contains("stdin reached EOF"),
            "expected an interaction-required refusal, got: {msg}"
        );
    }

    /// Same property for the default (`claude`) provider — `handle_direct`
    /// spawns `claude auth login`, which manages its own browser + loopback
    /// callback; the guard must refuse before that spawn, not after a
    /// `CSQ_LOGIN_TIMEOUT_SECS` wait.
    #[test]
    fn handle_claude_default_refuses_fast_without_a_tty() {
        if skip_at_terminal("handle_claude_default_refuses_fast_without_a_tty") {
            return;
        }
        // The TTY guard also passes when the test-only `CSQ_TEST_BYPASS_TTY`
        // is set, and `check_test_bypass_honours_env_var` sets it process-wide
        // under the shared test-env lock. Hold that same lock and clear the var
        // for this test's duration; otherwise a concurrent run makes the guard
        // pass and `handle` blocks on the Enter read forever (observed hanging
        // the csq bins suite under trestle, where stdin never reaches EOF).
        let _env_guard = csq_core::platform::test_env::lock();
        let _bypass_off = BypassTtyOff::new();
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(9u16).unwrap();

        let err = handle(
            dir.path(),
            account,
            "", // default provider, mirrors real CLI default_value = "claude"
            false,
            false,
            false,
            false,
            false,
            false,
            false, // json
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("attended session") || msg.contains("TTY"),
            "expected an interaction-required refusal, got: {msg}"
        );
    }

    /// Repoints the process-wide fd 0 at a fresh pty slave and restores the
    /// saved stdin on drop (including on panic).
    ///
    /// SAFETY: fd 0 is process-global. Callers MUST hold
    /// `csq_core::platform::test_env::lock()` — the same shared mutex the
    /// other fd-0 swapper (`codex_supervise::tests::flush_typed_ahead_stdin_
    /// discards_queued_pty_input`) and these refusal tests take — so a swap
    /// can never overlap a test that samples `stdin().is_terminal()`.
    #[cfg(unix)]
    struct Fd0Pty {
        master: std::os::fd::RawFd,
        slave: std::os::fd::RawFd,
        saved_stdin: std::os::fd::RawFd,
    }

    #[cfg(unix)]
    impl Fd0Pty {
        fn new() -> Self {
            // SAFETY: every call operates on fds this constructor owns; the
            // pty helpers are POSIX and used identically by
            // `codex_supervise`'s typed-ahead test.
            unsafe {
                let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
                assert!(
                    master >= 0,
                    "posix_openpt failed: {:?}",
                    std::io::Error::last_os_error()
                );
                assert_eq!(libc::grantpt(master), 0, "grantpt failed");
                assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
                let ptr = libc::ptsname(master);
                assert!(!ptr.is_null(), "ptsname returned null");
                let slave_path = std::ffi::CStr::from_ptr(ptr).to_owned();
                let slave = libc::open(slave_path.as_ptr(), libc::O_RDWR);
                assert!(
                    slave >= 0,
                    "open(slave) failed: {:?}",
                    std::io::Error::last_os_error()
                );
                let saved_stdin = libc::dup(0);
                assert!(saved_stdin >= 0, "dup(0) failed");
                assert_eq!(libc::dup2(slave, 0), 0, "dup2(slave, 0) failed");
                Self {
                    master,
                    slave,
                    saved_stdin,
                }
            }
        }
    }

    #[cfg(unix)]
    impl Drop for Fd0Pty {
        fn drop(&mut self) {
            // SAFETY: restores the descriptor saved in `new` and closes the
            // three fds this guard owns, each exactly once.
            unsafe {
                libc::dup2(self.saved_stdin, 0);
                libc::close(self.saved_stdin);
                libc::close(self.slave);
                libc::close(self.master);
            }
        }
    }

    /// Pins the MECHANISM behind the darwin preflight flake: the drivability
    /// guard samples the process-wide fd 0, so any concurrent test that
    /// repoints fd 0 at a pty flips its verdict. `codex_supervise::tests::
    /// flush_typed_ahead_stdin_discards_queued_pty_input` is the only
    /// in-process fd-0 swapper in this binary; it now holds the same shared
    /// env-test lock these tests hold. This test proves both halves with no
    /// host or timing dependence:
    ///   - with the harness's non-tty fd 0 the guard refuses;
    ///   - with fd 0 repointed at a pty it passes with NO test bypass set.
    ///
    /// If the swap ever stops taking the shared lock, these refusal tests
    /// become timing-dependent again — exactly the flake recorded in the dev
    /// preflight's darwin `lib-bins` leg.
    #[cfg(unix)]
    #[test]
    fn drivability_guard_reads_fd0_so_fd0_swaps_share_the_env_lock() {
        let _env_guard = csq_core::platform::test_env::lock();
        let _bypass_off = BypassTtyOff::new();

        assert!(
            guard_login_drivability("claude", false).is_err(),
            "precondition: with a non-tty fd 0 (and no bypass) the guard must refuse"
        );

        let _tty = Fd0Pty::new();
        assert_eq!(
            unsafe { libc::isatty(0) },
            1,
            "fd 0 must be a tty for this test to exercise the mechanism"
        );
        assert!(
            guard_login_drivability("claude", false).is_ok(),
            "with fd 0 a tty the guard passes WITHOUT any test bypass — a \
             concurrent fd-0 swap is what makes a refusal test fall through"
        );
    }

    // Non-headless-guard exemption for gemini (`ExternalPrerequisite`) and the
    // native device-code providers is covered at the unit level in
    // `csq_core::providers::login_capability::tests` (`guard_never_gates_
    // device_code_or_external_prerequisite`) rather than here: `handle_gemini_
    // oauth`/`handle_native` go on to read REAL `~/.gemini/oauth_creds.json` /
    // spawn a real vendor binary once past the guard, which would make an
    // end-to-end `handle()` test here environment-dependent.

    fn native_identity_fixture(config: &Path, organization: &str) -> credentials::CredentialFile {
        std::fs::create_dir_all(config).unwrap();
        std::fs::write(
            config.join(".claude.json"),
            serde_json::json!({
                "oauthAccount": {
                    "emailAddress": "native-ingress@test.invalid",
                    "accountUuid": "11111111-1111-4111-8111-111111111111",
                    "organizationUuid": organization,
                }
            })
            .to_string(),
        )
        .unwrap();
        csq_core::platform::fs::secure_file(&config.join(".claude.json")).unwrap();
        // Both candidate grants share a year-2100 TTL. TTL cannot prove org identity.
        serde_json::from_value(serde_json::json!({"claudeAiOauth": {
            "accessToken": "fixture-native-selected-token",
            "refreshToken": "fixture-native-selected-refresh",
            "expiresAt": 4102444800000_u64,
            "scopes": ["user:profile", "user:inference"],
        }}))
        .unwrap()
    }

    fn native_profile_fixture(
        organization: &'static str,
    ) -> csq_core::daemon::usage_poller::HttpGetFn {
        Arc::new(move |url, token, _| {
            assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
            assert_eq!(
                token, "fixture-native-selected-token",
                "profile must verify the captured candidate"
            );
            Ok((200, serde_json::json!({
                "account": {"uuid": "11111111-1111-4111-8111-111111111111", "email": "native-ingress@test.invalid"},
                "organization": {"uuid": organization},
            }).to_string().into_bytes()))
        })
    }

    #[test]
    fn native_login_equal_ttl_wrong_organization_candidate_does_not_publish() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::TempDir::new().unwrap();
            let account = AccountNum::try_from(7).unwrap();
            let config = dir.path().join("config-7");
            let captured = native_identity_fixture(&config, "22222222-2222-4222-8222-222222222222");
            let prior = capture_login_prior(dir.path(), account).unwrap();
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed_calls = Arc::clone(&calls);
            let response = native_profile_fixture("33333333-3333-4333-8333-333333333333");
            let profile: csq_core::daemon::usage_poller::HttpGetFn =
                Arc::new(move |url, token, headers| {
                    observed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    response(url, token, headers)
                });
            let result = handle_direct_post_subprocess_with(
                dir.path(),
                account,
                &config,
                true,
                prior,
                &profile,
                || Ok(captured),
            );
            assert!(
                result.is_err(),
                "equal TTL does not authorize a different organization"
            );
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the refusal must follow exact-token profile verification"
            );
            assert!(
                csq_core::accounts::profiles::resolve_slot_to_uuid(dir.path(), account.get())
                    .is_none()
            );
            assert!(
                !config.join(".csq-account").exists(),
                "refused candidate must not publish a marker"
            );
        });
    }

    #[test]
    fn native_login_profile_transport_error_does_not_leak_token_or_body() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::TempDir::new().unwrap();
            let account = AccountNum::try_from(7).unwrap();
            let config = dir.path().join("config-7");
            let captured = native_identity_fixture(&config, "22222222-2222-4222-8222-222222222222");
            let profile: csq_core::daemon::usage_poller::HttpGetFn =
                Arc::new(|_, token, _| Err(format!("{token}: fixture-private-profile-body")));
            let err = handle_direct_post_subprocess_with(
                dir.path(),
                account,
                &config,
                true,
                capture_login_prior(dir.path(), account).unwrap(),
                &profile,
                || Ok(captured),
            )
            .unwrap_err()
            .to_string();
            assert!(!err.contains("fixture-native-selected-token"));
            assert!(!err.contains("fixture-private-profile-body"));
            assert!(
                csq_core::accounts::profiles::resolve_slot_to_uuid(dir.path(), account.get())
                    .is_none()
            );
        });
    }

    #[test]
    fn native_login_unknown_full_context_refuses_before_capture_or_profile() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::TempDir::new().unwrap();
            let account = AccountNum::try_from(7).unwrap();
            let config = dir.path().join("config-7");
            std::fs::create_dir_all(&config).unwrap();
            std::fs::write(
                config.join(".claude.json"),
                r#"{"oauthAccount":{"emailAddress":"native-ingress@test.invalid"}}"#,
            )
            .unwrap();
            csq_core::platform::fs::secure_file(&config.join(".claude.json")).unwrap();
            let profile: csq_core::daemon::usage_poller::HttpGetFn =
                Arc::new(|_, _, _| panic!("unknown context must refuse before HTTP"));
            let result = handle_direct_post_subprocess_with(
                dir.path(),
                account,
                &config,
                true,
                capture_login_prior(dir.path(), account).unwrap(),
                &profile,
                || panic!("unknown context must refuse before credential capture"),
            );
            assert!(result.is_err());
            assert!(
                csq_core::accounts::profiles::resolve_slot_to_uuid(dir.path(), account.get())
                    .is_none()
            );
            assert!(!config.join(".csq-account").exists());
        });
    }

    #[test]
    fn native_login_exact_captured_context_publishes_and_reuses_same_identity() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::TempDir::new().unwrap();
            let account = AccountNum::try_from(7).unwrap();
            let config = dir.path().join("config-7");
            let credential =
                native_identity_fixture(&config, "22222222-2222-4222-8222-222222222222");
            let profile = native_profile_fixture("22222222-2222-4222-8222-222222222222");
            let first = handle_direct_post_subprocess_with(
                dir.path(),
                account,
                &config,
                true,
                capture_login_prior(dir.path(), account).unwrap(),
                &profile,
                || Ok(credential.clone()),
            )
            .unwrap();
            let first_id = first.identity();
            assert_eq!(
                csq_core::accounts::profiles::resolve_slot_to_uuid(dir.path(), account.get()),
                Some(first_id)
            );
            assert!(
                csq_core::accounts::identity_store::credentials_path_for(dir.path(), first_id)
                    .is_file()
            );
            let again = handle_direct_post_subprocess_with(
                dir.path(),
                account,
                &config,
                true,
                capture_login_prior(dir.path(), account).unwrap(),
                &profile,
                || Ok(credential),
            )
            .unwrap();
            assert_eq!(
                again.identity(),
                first_id,
                "same complete verified context reuses identity"
            );
        });
    }

    /// an internal ticket regression (moved from `cli_deps_login_integration`): on a FRESH
    /// install (empty base, no `profiles.json`, no `by_slot` mapping) the first
    /// Anthropic login must publish credentials. Pre-an internal ticket `save_canonical_for`
    /// failed closed on the absent UUID because the mint ran only after the save.
    ///
    /// The subprocess form of this test cannot be hermetic since the org-identity
    /// change: the commit now verifies the captured token against
    /// `api.anthropic.com/api/oauth/profile` and requires `accountUuid` and
    /// `organizationUuid` in `.claude.json`. This drives the same chain
    /// (real `.claude.json`/`.credentials.json` reads through
    /// `read_fresh_after_login` -> verified commit -> finalize) with the profile
    /// transport injected, and asserts the original an internal ticket outcomes.
    #[test]
    fn fresh_install_login_mints_uuid_and_persists_creds() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::TempDir::new().unwrap();
            let account = AccountNum::try_from(1).unwrap();
            let config = dir.path().join("config-1");
            let credential =
                native_identity_fixture(&config, "22222222-2222-4222-8222-222222222222");
            // What `claude auth login` leaves behind on Linux/Windows.
            credentials::save(&config.join(".credentials.json"), &credential).unwrap();
            assert!(
                !dir.path().join("profiles.json").exists(),
                "fixture must be a fresh install"
            );
            let profile = native_profile_fixture("22222222-2222-4222-8222-222222222222");
            let committed = handle_direct_post_subprocess_with(
                dir.path(),
                account,
                &config,
                true,
                capture_login_prior(dir.path(), account).unwrap(),
                &profile,
                || credentials::read_fresh_after_login(&config).map_err(|e| anyhow!("{e}")),
            )
            .expect("fresh-install login must succeed");
            let email =
                csq_core::accounts::login::finalize_verified_login(dir.path(), account, committed)
                    .expect("fresh-install login must finalize");
            assert_eq!(email, "native-ingress@test.invalid");

            let profiles: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(dir.path().join("profiles.json"))
                    .expect("fresh-install login: profiles.json must exist after login"),
            )
            .unwrap();
            let uuid = profiles
                .get("by_slot")
                .and_then(|m| m.get("1"))
                .and_then(|v| v.as_str())
                .expect(
                    "fresh-install login: by_slot[\"1\"] must hold a minted UUID after fresh login",
                );
            assert!(
                dir.path()
                    .join("identities")
                    .join(uuid)
                    .join("credentials.json")
                    .is_file(),
                "fresh-install login: identities/{uuid}/credentials.json must exist after login"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(
                    dir.path()
                        .join("identities")
                        .join(uuid)
                        .join("credentials.json"),
                )
                .unwrap()
                .permissions()
                .mode()
                    & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "fresh-install login: the canonical credential must be private"
                );
            }
            // finalize owns the UUID marker; a finalize that returns Ok without
            // publishing it leaves the slot credential-less to every marker reader.
            assert_eq!(
                csq_core::accounts::markers::read_csq_account_uuid(&config)
                    .map(|id| id.to_string())
                    .as_deref(),
                Some(uuid),
                "fresh-install login: finalize must write the UUID .csq-account marker"
            );
        });
    }

    /// an internal ticket, fail-closed pole: on a fresh install, a captured token whose profile does not
    /// confirm the recorded organization is refused, and nothing is minted or written.
    /// (The retired subprocess test's per-slot `CLAUDE_CONFIG_DIR` coverage is pinned by
    /// `login_subprocess_timeout_integration`; this test pins the refusal outcome.)
    #[test]
    fn fresh_install_login_with_an_unconfirmed_profile_mints_nothing() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            let dir = tempfile::TempDir::new().unwrap();
            let account = AccountNum::try_from(1).unwrap();
            let config = dir.path().join("config-1");
            let credential =
                native_identity_fixture(&config, "22222222-2222-4222-8222-222222222222");
            credentials::save(&config.join(".credentials.json"), &credential).unwrap();
            // The profile reports a different organization than the captured context.
            let response = native_profile_fixture("33333333-3333-4333-8333-333333333333");
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed_calls = Arc::clone(&calls);
            let profile: csq_core::daemon::usage_poller::HttpGetFn =
                Arc::new(move |url, token, headers| {
                    observed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    response(url, token, headers)
                });
            // Every file under the base, with its bytes, before the attempt: the refusal must
            // leave the whole tree (by_slot / profiles.json contexts, identities/*, the
            // credential files, the config-1 handle and its marker) untouched.
            fn snapshot(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
                fn walk(
                    root: &Path,
                    dir: &Path,
                    out: &mut std::collections::BTreeMap<String, Vec<u8>>,
                ) {
                    for entry in std::fs::read_dir(dir).unwrap().flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            out.insert(
                                format!("{}/", path.strip_prefix(root).unwrap().display()),
                                Vec::new(),
                            );
                            walk(root, &path, out);
                        } else {
                            out.insert(
                                path.strip_prefix(root).unwrap().display().to_string(),
                                std::fs::read(&path).unwrap(),
                            );
                        }
                    }
                }
                let mut out = std::collections::BTreeMap::new();
                walk(root, root, &mut out);
                out
            }
            let prior = capture_login_prior(dir.path(), account).unwrap();
            let before = snapshot(dir.path());
            let result = handle_direct_post_subprocess_with(
                dir.path(),
                account,
                &config,
                true,
                prior,
                &profile,
                || credentials::read_fresh_after_login(&config).map_err(|e| anyhow!("{e}")),
            );
            let err = result.expect_err("an unconfirmed organization must be refused");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("organization identity could not be confirmed")
                    && msg.contains("oauth_identity_refused"),
                "the refusal must be the unconfirmed-organization one, got: {msg}"
            );
            // The product words a transport failure and an organization mismatch the same, so
            // the text alone cannot tell them apart; the call count does: the refusal must
            // FOLLOW exactly one exact-token profile verification, not precede it.
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the refusal must follow the profile verification, not a pre-check"
            );
            assert_eq!(
                snapshot(dir.path()),
                before,
                "a refused login must not create, change or remove any file under the base"
            );
            let by_slot_minted = std::fs::read_to_string(dir.path().join("profiles.json"))
                .ok()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                .and_then(|v| v.get("by_slot").and_then(|m| m.get("1")).cloned())
                .is_some();
            assert!(!by_slot_minted, "nothing may be minted for a refused login");
            let identities = dir.path().join("identities");
            let written = identities.is_dir()
                && std::fs::read_dir(&identities)
                    .unwrap()
                    .flatten()
                    .any(|e| e.path().join("credentials.json").exists());
            assert!(
                !written,
                "no canonical credential may be written for a refused login"
            );
        });
    }

    /// M-2: `handle_direct`'s own wiring must reach `finalize_verified`.
    /// Drives `handle_direct_flow` with a stub subprocess and the injected
    /// profile transport; the UUID marker exists only if finalize ran.
    #[test]
    fn handle_direct_flow_finalizes_the_verified_login() {
        csq_core::platform::test_env::with_in_memory_secret_backend(|| {
            // The recording daemon's socket derives from `dir` on macOS; a
            // deep runner TMPDIR would push its pathname past `sun_path`.
            let dir = csq_core::testing::socket_fixture::short_root("csq-login-").unwrap();
            let account = AccountNum::try_from(1).unwrap();
            let config = dir.path().join("config-1");
            let credential =
                native_identity_fixture(&config, "22222222-2222-4222-8222-222222222222");
            credentials::save(&config.join(".credentials.json"), &credential).unwrap();
            let profile = native_profile_fixture("22222222-2222-4222-8222-222222222222");
            // The recorder registers `dir` with `daemon::paths::test_socket` so finalize's
            // daemon POSTs hit it, never a real daemon. The surrounding
            // `with_in_memory_secret_backend` already holds the env lock; the recorder takes none.
            let daemon = RecordingDaemon::spawn(dir.path());
            handle_direct_flow(
                dir.path(),
                account,
                |_| Ok(true),
                |config_dir, ok, prior| {
                    handle_direct_post_subprocess_with(
                        dir.path(),
                        account,
                        config_dir,
                        ok,
                        prior,
                        &profile,
                        || {
                            credentials::read_fresh_after_login(config_dir)
                                .map_err(|e| anyhow!("{e}"))
                        },
                    )
                },
            )
            .expect("handle_direct_flow must succeed");
            let got = daemon.wait_for_requests(2, Duration::from_secs(5));
            assert!(
                got.iter()
                    .any(|r| r.starts_with("POST /api/invalidate-cache ")),
                "finalize must invalidate the daemon cache: {got:?}"
            );
            assert!(
                got.iter().any(|r| r.starts_with("POST /api/slot-rebind ")),
                "finalize must wake the usage poller: {got:?}"
            );
            let marker = std::fs::read_to_string(config.join(".csq-account"))
                .expect("finalize must publish the account marker");
            assert!(
                !marker.trim().is_empty(),
                "marker must carry the minted identity"
            );
        });
    }

    // ── REV-R1-02 / M8: marker-write ordering regression ───────────

    #[test]
    fn handle_direct_does_not_write_marker_on_subprocess_failure() {
        // Simulates the failure path of `handle_direct` without
        // spawning the real `claude` binary. If the subprocess fails,
        // the .csq-account marker MUST NOT be written — otherwise the
        // daemon's discovery sees an orphan account with no creds.
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(7u16).unwrap();
        let config_dir = dir.path().join("config-7");
        std::fs::create_dir_all(&config_dir).unwrap();

        // Pretend the subprocess returned non-zero.
        let result = handle_direct_post_subprocess(
            dir.path(),
            account,
            &config_dir,
            false,
            capture_login_prior(dir.path(), account).unwrap(),
        );
        assert!(result.is_err(), "subprocess failure must propagate as Err");

        // No marker written.
        let marker = config_dir.join(".csq-account");
        assert!(
            !marker.exists(),
            ".csq-account marker MUST NOT exist after subprocess failure: {:?}",
            marker
        );
    }

    // ── M2 / UX-R1-M2: Ctrl-C cancellation regression ─────────────

    #[tokio::test]
    async fn race_or_cancel_returns_user_cancelled_when_signal_resolves_first() {
        // Build a race future that never resolves and a cancel
        // future that resolves immediately. The select! must pick
        // cancel.
        let never_race = async {
            std::future::pending::<csq_core::oauth::RaceResult>().await;
            // Unreachable, but produce a typed Result so the
            // closure has a concrete return type for select!.
            Err::<csq_core::oauth::RaceResult, _>(csq_core::error::OAuthError::StateMismatch)
        };
        let immediate_cancel = async { Ok::<(), anyhow::Error>(()) };

        let outcome = race_or_cancel(never_race, immediate_cancel).await.unwrap();
        match outcome {
            RaceOutcome::UserCancelled => {}
            RaceOutcome::Resolved(_) => panic!("cancel arm should have won"),
        }
    }

    #[tokio::test]
    async fn race_or_cancel_returns_resolved_when_race_wins() {
        // Race future resolves immediately with a synthesised
        // RaceResult; cancel hangs forever. select! must pick race.
        use csq_core::oauth::pkce::{generate_verifier, CodeVerifier};
        let synth = csq_core::oauth::RaceResult {
            winner: csq_core::oauth::RaceWinner::Paste {
                code: "c".into(),
                redirect_uri: "https://platform.claude.com/oauth/code/callback".into(),
            },
            auto_url: "auto".into(),
            manual_url: "manual".into(),
            state: "s".into(),
            verifier: {
                let _: CodeVerifier = generate_verifier();
                generate_verifier()
            },
        };
        let immediate_race = async move { Ok::<_, csq_core::error::OAuthError>(synth) };
        let never_cancel = async {
            std::future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };

        let outcome = race_or_cancel(immediate_race, never_cancel).await.unwrap();
        match outcome {
            RaceOutcome::Resolved(r) => {
                assert!(matches!(
                    r.winner,
                    csq_core::oauth::RaceWinner::Paste { .. }
                ));
            }
            RaceOutcome::UserCancelled => panic!("race arm should have won"),
        }
    }

    #[tokio::test]
    async fn race_or_cancel_propagates_race_error() {
        // Race future returns Err — race_or_cancel propagates as
        // anyhow::Error, NOT as UserCancelled.
        let failing_race = async {
            Err::<csq_core::oauth::RaceResult, _>(csq_core::error::OAuthError::StateMismatch)
        };
        let never_cancel = async {
            std::future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };

        let res = race_or_cancel(failing_race, never_cancel).await;
        assert!(res.is_err(), "race error must propagate as Err");
    }

    // ── UX-R2-01: kill_hint platform branching ────────────────────

    #[test]
    fn kill_hint_uses_kill_on_unix() {
        // Pure-function test, gated on target_os via cfg!. Runs on
        // every platform — only the assertion changes.
        let hint = kill_hint(12345);
        if cfg!(target_os = "windows") {
            assert!(
                hint.contains("wait for the owning login"),
                "Windows hint must wait for the owner: {hint}"
            );
            assert!(!hint.contains("/F"));
            assert!(hint.contains("12345"));
        } else {
            assert!(
                hint.starts_with("kill "),
                "unix kill_hint must start with `kill `: {hint}"
            );
            assert!(hint.contains("12345"));
        }
    }

    #[test]
    fn lock_held_error_message_includes_kill_command_unix() {
        // Emulate the lock-held error path the user sees. The error
        // message MUST include the platform's kill command so a
        // non-technical user knows exactly what to type.
        //
        // Pure string composition — we don't need to acquire a real
        // lock for this assertion. The failure mode being guarded is
        // a future refactor that loses the kill-hint splice from the
        // anyhow! call.
        let pid: u32 = 12345;
        let hint = kill_hint(pid);
        let rendered = format!(
            "another csq login 5 is in progress (PID {pid}) — \
             wait for it to finish, or run `{hint}` to terminate it, or \
             use --legacy-shell to bypass"
        );
        if !cfg!(target_os = "windows") {
            assert!(
                rendered.contains("`kill 12345`"),
                "unix lock-held message must include the literal `kill {pid}` \
                 command guidance: {rendered}"
            );
            assert!(rendered.contains("--legacy-shell"));
        }
    }

    #[test]
    fn lock_held_error_message_waits_for_owner_windows() {
        // Sibling of the unix test: gate the assertion on target_os.
        // The compile-time branch ensures the message body always
        // names the right command on the target build.
        let pid: u32 = 12345;
        let hint = kill_hint(pid);
        let rendered = format!("PID {pid} … `{hint}` …");
        if cfg!(target_os = "windows") {
            assert!(
                rendered.contains("wait for the owning login (PID 12345)"),
                "Windows lock-held message must name the owning login: {rendered}"
            );
        } else {
            // On non-Windows the test is a no-op — the assertion
            // here just keeps the test name discoverable in
            // `cargo test` output.
            assert!(rendered.contains("kill 12345"));
        }
    }

    // ── acquire_login_lock: real acquisition, bypass_hint wiring ──
    //
    // The tests above assert on hand-composed strings, never calling
    // the real function. These call it, proving the bypass_hint
    // parameter (added when the codex path was wired onto the same
    // lock, and reused unchanged by gemini) actually changes the
    // rendered message rather than being a dead parameter. The lock
    // itself is per-account, not per-provider (see the docstring
    // above), so these tests exercise `acquire_login_lock` directly
    // rather than through any one provider's `handle_*` entry point.

    #[test]
    fn acquire_login_lock_with_bypass_hint_mentions_it_when_held() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(21u16).unwrap();

        // Hold the lock ourselves first (same process, second `open()`
        // — flock is scoped to the open file description, not the
        // process, so this genuinely reproduces contention; see
        // `login_lock.rs`'s own same-process tests for the same
        // pattern).
        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        let msg = match acquire_login_lock(dir.path(), account, Some("--legacy-shell")) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("second acquire must fail while the first guard is alive"),
        };
        assert!(
            msg.contains("--legacy-shell"),
            "Some(bypass_hint) must be rendered into the held-lock message: {msg}"
        );
        assert!(msg.contains("in progress"), "message: {msg}");
    }

    #[test]
    fn acquire_login_lock_without_bypass_hint_omits_it_when_held() {
        // Both the codex and gemini call sites pass `None` — neither
        // provider has a `--legacy-shell`-style escape hatch, so
        // suggesting it would send the user down a dead end.
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(22u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        let msg = match acquire_login_lock(dir.path(), account, None) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("second acquire must fail while the first guard is alive"),
        };
        assert!(
            !msg.contains("--legacy-shell"),
            "None bypass_hint must NOT mention --legacy-shell (neither codex nor \
             gemini has such an escape hatch): {msg}"
        );
        assert!(msg.contains("in progress"), "message: {msg}");
    }

    #[test]
    fn acquire_login_lock_succeeds_once_prior_guard_drops() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(23u16).unwrap();

        let held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };
        drop(held);

        acquire_login_lock(dir.path(), account, None)
            .expect("acquire must succeed once the holder drops");
    }

    // ── handle_codex: cross-process lock is the FIRST thing it does ──
    //
    // `handle_codex` acquires the login lock before touching stdin,
    // opening a browser, or spawning `codex login --device-auth` — so
    // a held-lock test never reaches any of the interactive/subprocess
    // parts and is safe (and fast) to run unattended.

    #[test]
    fn handle_codex_refuses_when_login_lock_held_by_another_process() {
        // `handle_codex` installs the process-global scoped login
        // cancellation guard before taking the login lock, so this test
        // serializes on the shared test lock with every other installer in
        // the binary (`login_cancel_guard::INSTALLATION`'s test contract).
        let _env_guard = csq_core::platform::test_env::lock();
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(24u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        // false x4 (ignore_cli_version, no_auto_update_cli, track_latest, json):
        // no version-ignore or output-format flags are relevant here —
        // the lock check runs before the cli_deps_gate probe too.
        let result = handle_codex(dir.path(), account, false, false, false, false);
        let err = result.expect_err(
            "handle_codex must refuse when the account's login lock is held, \
             not fall through to the interactive ToS prompt / stdin read",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("in progress"),
            "handle_codex's Err must be the lock-contention message, not e.g. \
             a stdin-EOF or cli_deps_gate error: {msg}"
        );
        assert!(
            !msg.contains("--legacy-shell"),
            "codex has no --legacy-shell escape hatch: {msg}"
        );
    }

    #[test]
    fn handle_codex_lock_is_per_account_not_global() {
        // A held lock on account 25 must NOT block account 26 — the
        // lock file is `.login-<N>.lock`, keyed by account number.
        let dir = tempfile::TempDir::new().unwrap();
        let held_account = AccountNum::try_from(25u16).unwrap();
        let other_account = AccountNum::try_from(26u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), held_account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        // acquire_login_lock alone (not the full handle_codex, which
        // would go on to prompt stdin / spawn codex-cli for the
        // "free" case — out of scope for this lock-scoping check).
        acquire_login_lock(dir.path(), other_account, None)
            .expect("a different account's slot must not be blocked");
    }

    #[test]
    fn handle_direct_does_not_write_marker_when_credentials_missing() {
        // Subprocess succeeded but no credentials were captured
        // (keychain empty AND .credentials.json missing). Marker
        // must NOT be written — same rationale as the failure path.
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(8u16).unwrap();
        let config_dir = dir.path().join("config-8");
        std::fs::create_dir_all(&config_dir).unwrap();

        let _ = native_identity_fixture(&config_dir, "22222222-2222-4222-8222-222222222222");
        let profile: csq_core::daemon::usage_poller::HttpGetFn =
            Arc::new(|_, _, _| panic!("missing credentials must not query a real profile"));
        let result = handle_direct_post_subprocess_with(
            dir.path(),
            account,
            &config_dir,
            true,
            capture_login_prior(dir.path(), account).unwrap(),
            &profile,
            || Err(anyhow!("fixture has no credentials")),
        );
        assert!(result.is_err(), "missing credentials must propagate as Err");

        let marker = config_dir.join(".csq-account");
        assert!(
            !marker.exists(),
            ".csq-account marker MUST NOT exist when credential capture fails: {:?}",
            marker
        );
    }

    // ── credentials_expired_for_recording (T22a pre-flight) ──

    #[test]
    fn credentials_expired_for_recording_returns_true_when_file_missing() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(credential_file_expired(&path));
    }

    #[test]
    fn credentials_expired_for_recording_returns_false_for_valid_camel_case_creds() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".credentials.json");
        let future_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 86_400_000) as u64;
        let body = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "tok",
                "refreshToken": "ref",
                "expiresAt": future_ms,
                "scopes": ["user:profile"],
            }
        });
        std::fs::write(&path, body.to_string()).unwrap();
        assert!(!credential_file_expired(&path));
    }

    #[test]
    fn credentials_expired_for_recording_returns_true_for_past_expiry() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".credentials.json");
        let body = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "tok",
                "refreshToken": "ref",
                "expiresAt": 1_000u64, // long past
            }
        });
        std::fs::write(&path, body.to_string()).unwrap();
        assert!(credential_file_expired(&path));
    }

    #[test]
    fn credentials_expired_for_recording_returns_true_when_field_missing() {
        // The pre-fix bug shape: snake_case top-level expires_at.
        // Now treated as expired because the camelCase nested key is
        // missing.
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".credentials.json");
        let body = serde_json::json!({
            "expires_at": 9_999_999_999u64,
        });
        std::fs::write(&path, body.to_string()).unwrap();
        assert!(credential_file_expired(&path));
    }

    #[test]
    fn credentials_expired_for_recording_returns_true_for_invalid_json() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".credentials.json");
        std::fs::write(&path, b"not valid json {{{").unwrap();
        assert!(credential_file_expired(&path));
    }

    /// Regression for the §10.5-bench-blocker: with NO identity mapping (pre-A++
    /// fallback) the slot-based check reads the legacy `config-<N>/.credentials.json`
    /// mirror. A FRESH legacy mirror → NOT expired. Proves the new slot-based
    /// signature falls back correctly.
    #[test]
    fn credentials_expired_for_recording_slot_uses_fresh_legacy_mirror_when_no_identity() {
        use tempfile::TempDir;
        let base = TempDir::new().unwrap();
        let acct = AccountNum::try_from(3u16).unwrap();
        let cfg = base.path().join("config-3");
        std::fs::create_dir_all(&cfg).unwrap();
        let future_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 86_400_000) as u64;
        std::fs::write(
            cfg.join(".credentials.json"),
            serde_json::json!({ "claudeAiOauth": { "expiresAt": future_ms } }).to_string(),
        )
        .unwrap();
        assert!(!credentials_expired_for_recording(base.path(), acct));
    }

    /// With neither an identity mapping NOR a legacy mirror (a post-M3-7 install —
    /// the exact on-disk state that made the bench report every slot expired) the
    /// check returns expired. The FIX is that a real install DOES have the canonical
    /// `identities/<UUID>/credentials.json`, which this slot-based signature now
    /// reads first (verified end-to-end by the live bench pre-flight).
    #[test]
    fn credentials_expired_for_recording_slot_expired_when_nothing_on_disk() {
        use tempfile::TempDir;
        let base = TempDir::new().unwrap();
        let acct = AccountNum::try_from(3u16).unwrap();
        assert!(credentials_expired_for_recording(base.path(), acct));
    }

    // Tests for `extract_device_auth_url` + `strip_ansi_escapes` live with
    // their canonical implementation in
    // `csq-core/src/providers/codex/desktop_login.rs`.

    // ── handle_gemini_oauth: cross-process lock is the FIRST thing it does ──
    //
    // `handle_gemini_oauth` acquires the login lock before the
    // pre-flight CLI-version probe (which spawns `gemini --version`)
    // or `oauth_login::perform`'s browser-OAuth wait — so a held-lock
    // test never reaches any subprocess or interactive part, and is
    // safe (and fast) to run unattended, even without `gemini-cli`
    // installed in the test environment.

    #[test]
    fn handle_gemini_oauth_refuses_when_login_lock_held_by_another_process() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(44u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        let result = handle_gemini_oauth(dir.path(), account, false, false, false, false);
        let err = result.expect_err(
            "handle_gemini_oauth must refuse when the account's login lock is \
             held, not fall through to the CLI-version probe / OAuth flow",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("in progress"),
            "handle_gemini_oauth's Err must be the lock-contention message, \
             not e.g. a gemini-cli-not-installed error from the version probe: {msg}"
        );
        assert!(
            !msg.contains("--legacy-shell"),
            "gemini has no --legacy-shell escape hatch: {msg}"
        );
        assert!(
            !msg.contains("not installed"),
            "must not have fallen through to the cli_deps_gate probe, which \
             would spawn `gemini --version`: {msg}"
        );
    }

    #[test]
    fn handle_gemini_oauth_lock_is_per_account_not_global() {
        // A held lock on account 45 must NOT block account 46 — the
        // lock file is `.login-<N>.lock`, keyed by account number.
        let dir = tempfile::TempDir::new().unwrap();
        let held_account = AccountNum::try_from(45u16).unwrap();
        let other_account = AccountNum::try_from(46u16).unwrap();

        let _held = match AccountLoginLock::acquire(dir.path(), held_account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("first acquire must succeed"),
        };

        // acquire_login_lock alone (not the full handle_gemini_oauth,
        // which would go on to the CLI-version probe / OAuth flow for
        // the "free" case — out of scope for this lock-scoping check).
        acquire_login_lock(dir.path(), other_account, None)
            .expect("a different account's slot must not be blocked");
    }

    // ── login-followup LOW-8: the login surfaces' usage-poller wake ──────

    /// A Unix-socket listener standing in for the daemon's IPC socket: it
    /// records every request it receives and answers 200. Mirrors the
    /// per-base socket injection (`daemon::paths::test_socket`): only calls
    /// passing this fixture's `base` resolve to its socket, so it never binds
    /// (and the wake never POSTs into) the ambient runtime dir, a real daemon
    /// included, and no process-global env is touched.
    struct RecordingDaemon {
        socket: std::path::PathBuf,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        _thread: std::thread::JoinHandle<()>,
        // Per-base socket injection (an internal ticket): no process-env mutation.
        _registration: csq_core::daemon::paths::test_socket::Registration,
        #[cfg(target_os = "linux")]
        _runtime_dir: tempfile::TempDir,
    }

    impl RecordingDaemon {
        fn spawn(base: &std::path::Path) -> Self {
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering;

            #[cfg(target_os = "linux")]
            // The shared short-root fixture pins this private (0700) runtime
            // directory at creation, not by a later chmod.
            let runtime_dir = csq_core::testing::socket_fixture::short_root("csq-r2b-")
                .expect("private runtime dir for the recording daemon");

            #[cfg(target_os = "linux")]
            let (registration, _) =
                csq_core::daemon::paths::test_socket::register_in(base, runtime_dir.path());
            #[cfg(not(target_os = "linux"))]
            let (registration, _) = csq_core::daemon::paths::test_socket::register(base);

            let socket = csq_core::daemon::socket_path(base);
            if let Some(parent) = socket.parent() {
                std::fs::create_dir_all(parent).expect("socket parent dir");
            }
            let _ = std::fs::remove_file(&socket);
            let listener = std::os::unix::net::UnixListener::bind(&socket)
                .expect("bind recording daemon socket");
            listener
                .set_nonblocking(true)
                .expect("nonblocking recording listener");

            let requests: Arc<std::sync::Mutex<Vec<String>>> =
                Arc::new(std::sync::Mutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let requests_for_thread = Arc::clone(&requests);
            let stop_for_thread = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                while !stop_for_thread.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let mut buf = [0u8; 4096];
                            let n = stream.read(&mut buf).unwrap_or(0);
                            requests_for_thread
                                .lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                            let body = r#"{"ok":true}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes());
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });

            RecordingDaemon {
                socket,
                requests,
                stop,
                _thread: thread,
                _registration: registration,
                #[cfg(target_os = "linux")]
                _runtime_dir: runtime_dir,
            }
        }

        /// Bounded wait for `n` recorded requests; the panic names how many
        /// actually arrived.
        fn wait_for_requests(&self, n: usize, bound: Duration) -> Vec<String> {
            let deadline = Instant::now() + bound;
            loop {
                let seen = self.requests.lock().unwrap().clone();
                if seen.len() >= n {
                    return seen;
                }
                assert!(
                    Instant::now() < deadline,
                    "recording daemon saw {} of {n} requests within {bound:?}",
                    seen.len()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for RecordingDaemon {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = std::fs::remove_file(&self.socket);
        }
    }

    /// `wake_usage_poller` — the single call the Anthropic finalize, codex
    /// and gemini-oauth completion sites share — must POST the daemon's
    /// rebind route carrying THAT slot. Removing the notify call inside the
    /// helper reds this test (no request is recorded); a wrong route or a
    /// dropped slot number reds the two content assertions.
    #[test]
    fn wake_usage_poller_posts_the_rebind_route_with_the_bound_slot() {
        // The recording daemon's socket derives from `dir` on macOS.
        let dir = csq_core::testing::socket_fixture::short_root("csq-login-").unwrap();
        // The recorder takes no env lock; this test holds its own.
        let _env = csq_core::platform::test_env::lock();
        let daemon = RecordingDaemon::spawn(dir.path());

        let account = AccountNum::try_from(7u16).unwrap();
        wake_usage_poller(dir.path(), account);

        let got = daemon.wait_for_requests(1, Duration::from_secs(5));
        assert_eq!(
            got.len(),
            1,
            "one wake must issue exactly one request, got {got:?}"
        );
        assert!(
            got[0].starts_with("POST /api/slot-rebind "),
            "the wake must POST the rebind route, got {:?}",
            got[0]
        );
        assert!(
            got[0].contains(r#"{"slot":7}"#),
            "the wake must carry the bound slot, got {:?}",
            got[0]
        );
    }
}
