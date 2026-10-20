//! Subprocess-based Claude OAuth login command.
//!
//! Phase 1 of an internal ticket — adds `start_claude_login_subprocess` Tauri command
//! alongside the existing parallel-race flow in [`super::race`]. CC is
//! the reference OAuth client; this command shells out to
//! `claude auth login` with `CLAUDE_CONFIG_DIR=<base>/config-<N>` and
//! lets CC's own seamless flow (IPv6 `[::1]:<random>` + hosted JS
//! bridge) handle the redirect end-to-end. Once the subprocess exits
//! successfully, we capture the credentials CC wrote, persist them
//! canonically, write the `.csq-account` marker, and run
//! [`csq_core::accounts::login::finalize_verified_login`] for the email +
//! profiles.json update — identical to the CLI's `handle_direct` path
//! that landed in an internal ticket.
//!
//! # Why not race the loopback in-process
//!
//! The parallel-race flow built an IPv4 loopback `redirect_uri`
//! (`http://127.0.0.1:<port>/callback`) which Anthropic rejects for
//! the Claude Code client_id, surfacing a "redirect URI fail" page
//! before the user could ever paste. CC itself uses IPv6 `[::1]` plus
//! a hosted-page JS bridge; re-implementing that surface violates the
//! delegate-to-reference rule (see `feedback_delegate_to_reference_client`).
//!
//! # Phase 2 (shipped)
//!
//! The Svelte modal in `csq/ui/src/lib/components/AddAccountModal.svelte`
//! now invokes this command directly; the `claude-login-*` event
//! stream is no longer subscribed. The legacy `start_claude_login_race`
//! / `submit_paste_code` / `cancel_race_login` commands are unregistered
//! from `invoke_handler!` in the Phase 2 PR (renderer cannot reach
//! them), while their source stays compiled under `#![allow(dead_code)]`
//! for one release. Phase 3 deletes the source files outright:
//! `csq-core/src/oauth/{race,loopback}.rs` and
//! `csq/src/desktop/commands/race.rs`.

use csq_core::accounts::login::{finalize_verified_login, find_claude_binary};
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::error::redact_tokens;
use csq_core::types::AccountNum;
use serde::Serialize;
use tauri::Window;

/// Frontend-visible shape returned on a successful subprocess login.
/// Mirrors the trailing `claude-login-success` event payload from the
/// race flow so a future frontend swap can reuse the same wrapper.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct SubprocessLoginResponse {
    pub account: u16,
    pub email: String,
}

/// Tauri command — runs `claude auth login` for slot `account` and
/// captures the credentials CC writes. Synchronous from the frontend's
/// view: the returned Promise resolves only when the subprocess exits
/// AND credentials are persisted, so no separate event subscription is
/// required.
///
/// Returns an error string. Round-1 (Phase 2 redteam — security M1 +
/// deep-analyst M2) introduces stable error-code prefixes so the
/// renderer can branch on a tag rather than substring-match prose:
///
/// * `"INVALID_INPUT:..."` — `AccountNum::try_from` failed
/// * `"BASE_DIR_MISSING:..."` — wrong CWD
/// * `"LOCK_HELD:..."` — flock held by another login (CLI or desktop)
/// * `"LOCK_FAILED:..."` — flock open / lock syscall failed
/// * `"CLAUDE_BIN_MISSING:..."` — CC is not installed
/// * `"SPAWN_FAILED:..."` — exec error from `tokio::process::Command`
/// * `"CC_EXITED_NONZERO:..."` — user cancelled in the browser, or CC failed
/// * `"NO_CREDENTIALS:..."` — CC exited 0 but wrote no credentials
/// * `"STALE_CREDENTIALS:..."` — CC exited 0 but only an expired credential
///   was readable after retry (keychain commit raced / access denied)
/// * `"CRED_WRITE_FAILED:..."` / `"MARKER_WRITE_FAILED:..."` /
///   `"FINALIZE_FAILED:..."` — post-subprocess persistence faults
///
/// The suffix after the colon is a human-readable message; the
/// renderer uses the prefix for branching and renders the full
/// string verbatim in the error banner. Every suffix passes through
/// `redact_tokens` per `rules/security.md` MUST Rule 2 (defense in
/// depth — the frontend mirrors this in a small `redactTokens`
/// helper).
#[tauri::command]
pub async fn start_claude_login_subprocess(
    window: Window,
    base_dir: String,
    account: u16,
) -> Result<SubprocessLoginResponse, String> {
    let account_num = AccountNum::try_from(account)
        .map_err(|e| format!("INVALID_INPUT: invalid account number {account}: {e}"))?;

    // R3-fix-check LOW 4: containment via the shared resolver (the sweep
    // only covered mod.rs).
    let base = super::resolve_csq_base_dir(&base_dir)?;
    if !base.is_dir() {
        return Err(format!(
            "BASE_DIR_MISSING: base directory does not exist: {}",
            redact_tokens(&base_dir)
        ));
    }

    // `window` is unused today but kept on the signature so Phase 2
    // can attach progress events without breaking the frontend's
    // invoke shape.
    let _ = window;

    // GH an internal ticket: the reverse conflict guard that used to run here
    // (redteam R3) is retired — a stale Gemini/native marker is now detected
    // pre-mint and cleared on the SUCCESS path by `finalize_login`
    // (`binding_guard::detect_stale_marker_binding` +
    // `clear_detected_marker_binding`) rather than refused up-front. See
    // those functions' doc comments.

    let _lock = match AccountLoginLock::acquire(&base, account_num) {
        Ok(AcquireOutcome::Acquired(g)) => g,
        Ok(AcquireOutcome::Held { pid, .. }) => {
            return Err(match pid {
                Some(p) => format!(
                    "LOCK_HELD: another login is in progress for account {account} (PID {p}) — \
                     cancel it first or wait for it to finish"
                ),
                None => format!(
                    "LOCK_HELD: another login is in progress for account {account} — \
                     cancel it first or wait for it to finish"
                ),
            });
        }
        Err(e) => {
            return Err(format!("LOCK_FAILED: {}", redact_tokens(&e.to_string())));
        }
    };

    // Capture before launching the vendor process. An initially unbound slot
    // must remain unbound until this exact login publishes its verified grant.
    let prior_base = base.clone();
    let prior = tokio::task::spawn_blocking(move || {
        csq_core::accounts::anthropic_identity::capture_login_prior(&prior_base, account_num)
    })
    .await
    .map_err(|_| "INTERNAL: identity capture task failed".to_string())?
    .map_err(|e| prior_capture_failure(&e))?;

    // SEC-2.15 (unified, R1 M1): secure the accounts root (config-N's
    // parent) fail-closed before creating the handle dir.
    csq_core::platform::fs::ensure_private_dir_root(&base).map_err(|e| {
        format!(
            "CRED_WRITE_FAILED: secure accounts root: {}",
            redact_tokens(&e.to_string())
        )
    })?;
    let config_dir = base.join(format!("config-{}", account_num.get()));
    tokio::fs::create_dir_all(&config_dir).await.map_err(|e| {
        format!(
            "CRED_WRITE_FAILED: create config dir: {}",
            redact_tokens(&e.to_string())
        )
    })?;

    let claude_bin = find_claude_binary().ok_or_else(|| {
        "CLAUDE_BIN_MISSING: claude binary not found on PATH or well-known locations — \
         install Claude Code first (https://claude.com/code)"
            .to_string()
    })?;

    let status = tokio::process::Command::new(&claude_bin)
        .args(["auth", "login"])
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .kill_on_drop(true)
        .status()
        .await
        .map_err(|e| {
            format!(
                "SPAWN_FAILED: failed to spawn `claude auth login`: {}",
                redact_tokens(&e.to_string())
            )
        })?;

    if !status.success() {
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "killed by signal".to_string());
        return Err(format!(
            "CC_EXITED_NONZERO: `claude auth login` exited with non-zero status ({code})"
        ));
    }

    // CC commits the freshly minted token to the macOS Keychain, and that
    // write can land a beat AFTER `claude auth login` exits — racing an
    // immediate read. `read_fresh_after_login` reads both keychain and file,
    // keeps whichever has the later `expiresAt`, retries to let CC commit, and
    // errors rather than persisting a stale token (the twin of the CLI fix —
    // `csq_core::credentials::post_login`). Without it the desktop Re-auth flow
    // silently saved the 35-day-old `.credentials.json` and the card stayed
    // Expired forever.
    //
    // The helper is SYNCHRONOUS: each attempt spawns a blocking `security`
    // subprocess (macOS keychain read) and, on a lost race, `thread::sleep`s
    // up to ~2.2 s. Run it on a blocking pool so the Tauri runtime worker stays
    // responsive — same convention as the gemini login twin
    // (`gemini_provision_oauth`) and `start_claude_login`. `tauri-commands.md`
    // MUST-NOT-3 (no blocking the async runtime thread).
    let config_dir_for_read = config_dir.clone();
    let base_for_commit = base.clone();
    let committed = tokio::task::spawn_blocking(move || {
        let expected =
            csq_core::accounts::anthropic_identity::read_native_expectation(&config_dir_for_read)
                .map_err(|e| format!("IDENTITY_FAILED: {e}"))?;
        let creds =
            csq_core::credentials::read_fresh_after_login(&config_dir_for_read).map_err(|e| {
                let tag = match e {
                    csq_core::credentials::FreshLoginError::NoCredentials => "NO_CREDENTIALS",
                    csq_core::credentials::FreshLoginError::OnlyStale => "STALE_CREDENTIALS",
                };
                format!("{tag}: {e}")
            })?;
        csq_core::accounts::anthropic_identity::commit_anthropic_login(
            &base_for_commit,
            account_num,
            &creds,
            Some(&expected),
            prior,
        )
        .map_err(|e| {
            format!(
                "IDENTITY_FAILED: {}",
                csq_core::accounts::login::LoginCommitOutcome::describe_commit_failure_for_account(
                    &e,
                    account_num
                )
            )
        })
    })
    .await
    .map_err(|_| "INTERNAL: verified login task failed".to_string())??;

    // Finalization rechecks the committed receipt, writes its UUID marker under
    // the profiles lock, then queues the nonblocking keychain mirror.
    let base_for_finalize = base.clone();
    let email = tokio::task::spawn_blocking(move || {
        finalize_verified_login(&base_for_finalize, account_num, committed)
    })
    .await
    .map_err(|e| format!("INTERNAL: finalize task join failed: {e}"))?
    .map_err(|e| format!("FINALIZE_FAILED: {}", redact_tokens(&e.to_string())))?;

    // login-followup HIGH-1: the commit + finalize above SUCCEEDED, so the
    // daemon gets both best-effort notifications — the account-discovery
    // cache is stale, and the usage poller should tick immediately.
    //
    // They are BLOCKING (a Unix socket round-trip bounded by the client's 2 s
    // DEFAULT_TIMEOUT; on Windows a short-lived runtime) and MUST NOT run on
    // this async worker: pre-fix the Windows arm's `rt.block_on` panicked
    // here ("Cannot start a runtime from within a runtime") AFTER the login
    // had committed, on every successful Add Account on Windows. The call
    // now runs on the blocking pool, and `notify::windows_post` is runtime-
    // safe on its own as well. Best-effort: an absent daemon is the common
    // case, and a failed notify must never fail a committed login — hence
    // the join result is discarded, not propagated (folding these calls into
    // the finalize closure above would instead turn any notify panic into
    // "finalize task join failed" for a login that DID succeed).
    notify_daemon_after_login_off_runtime(base.clone(), account_num).await;

    Ok(SubprocessLoginResponse {
        account: account_num.get(),
        email,
    })
}

/// Best-effort daemon notifications after a SUCCESSFUL commit + finalize.
///
/// * the account-discovery cache is stale, so the dashboard's next poll sees
///   the new slot immediately rather than after its 5 s TTL. This replaces
///   the previous Unix-only inline `POST /api/invalidate-cache`, which never
///   fired on Windows (the `notify` chokepoint covers both transports);
/// * the just-bound slot should be picked up by the usage poller on an
///   IMMEDIATE tick instead of up to `POLL_INTERVAL` (5 min) later.
///
/// BLOCKING, by construction: Unix socket connect + read/write, or a
/// short-lived current-thread runtime on Windows. Call ONLY from a blocking
/// context — the command above runs it via
/// [`notify_daemon_after_login_off_runtime`].
fn notify_daemon_after_login(base: &std::path::Path, account: AccountNum) {
    csq_core::daemon::notify::cache_invalidation(base);
    csq_core::daemon::notify::slot_rebind(base, account.get());
}

/// Runs [`notify_daemon_after_login`] on the tokio blocking pool.
///
/// Kept as its own function rather than inlined at the call site so the
/// placement is TESTABLE: `tests::notify_step_never_blocks_the_async_worker`
/// drives this function and reds if the blocking body is ever called inline
/// on the runtime thread. (The finalize closure cannot serve as that seam —
/// driving it needs a real `CommittedAnthropicLogin`.)
async fn notify_daemon_after_login_off_runtime(base: std::path::PathBuf, account: AccountNum) {
    super::notify_daemon_blocking(move || notify_daemon_after_login(&base, account)).await;
}

/// Error text for a failure of the pre-login identity snapshot. Nothing was
/// published at that point, so this deliberately does NOT go through the
/// commit-time `describe_error` ("credential publication failed"); it matches
/// the CLI twin, which shows the raw identity message.
fn prior_capture_failure(error: &csq_core::accounts::anthropic_identity::IdentityError) -> String {
    format!(
        "IDENTITY_FAILED: {}",
        csq_core::accounts::login::LoginCommitOutcome::describe_prior_capture_error(error)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N-3: an Io error while capturing the pre-login snapshot must not read
    /// as a publication failure.
    #[test]
    fn prior_capture_failure_is_not_reported_as_publication_failure() {
        use csq_core::accounts::anthropic_identity::IdentityError;
        let line = prior_capture_failure(&IdentityError::Io);
        assert_eq!(line, format!("IDENTITY_FAILED: {}", IdentityError::Io));
        assert!(
            !line.contains("credential publication failed"),
            "got: {line}"
        );
    }

    /// Type-shape regression: the response derives `Serialize` so it
    /// can cross the Tauri IPC boundary, and the field shape matches
    /// the trailing `claude-login-success` event payload from the
    /// race flow (`{ account, email }`).
    #[test]
    fn subprocess_login_response_serializes_to_expected_json() {
        let r = SubprocessLoginResponse {
            account: 5,
            email: "user@example.com".to_string(),
        };
        let json = serde_json::to_string(&r).expect("serialize");
        assert_eq!(json, r#"{"account":5,"email":"user@example.com"}"#);
    }

    /// Phase 2 / an internal ticket follow-up: drive the full command with a stub
    /// `claude` binary on PATH. Requires the `stub-claude` bin and a
    /// `clean_command`-style env reset (rules/testing.md MUST Rule 4a)
    /// that the existing `cli_deps_login_integration` harness already
    /// builds for the CLI side; mirroring it here is non-trivial
    /// because the desktop command needs `tauri::Window` which is
    /// hard to fake outside of `tauri::test::mock_app()`. Tracked on
    /// an internal ticket as the desktop-side end-to-end gap.
    #[allow(dead_code)]
    fn _phase2_end_to_end_test_placeholder() {}

    #[cfg(unix)]
    use crate::desktop::commands::test_recording_daemon as recording_daemon;

    /// login-followup R1 LOW-7(a): the shipped post-finalize notify step
    /// fires BOTH daemon notifications against a real socket — the wake
    /// (`POST /api/slot-rebind`) with the validated slot in its body, and
    /// the discovery-cache invalidation. Deleting either call in
    /// `notify_daemon_after_login` reds this test.
    #[cfg(unix)]
    #[test]
    fn post_finalize_notify_reaches_the_daemon_with_rebind_and_invalidation() {
        let daemon = recording_daemon::RecordingDaemon::new(std::time::Duration::ZERO);
        let account = AccountNum::try_from(2u16).unwrap();

        notify_daemon_after_login(daemon.base_dir(), account);

        let a = daemon.recv("the cache-invalidation POST");
        let b = daemon.recv("the slot-rebind POST");
        let rebind = [&a, &b]
            .into_iter()
            .find(|r| r.starts_with("POST /api/slot-rebind HTTP/1.1"))
            .unwrap_or_else(|| {
                panic!("no POST /api/slot-rebind reached the daemon; got {a:?} and {b:?}")
            });
        assert!(
            rebind.contains(r#"{"slot":2}"#),
            "the rebind body must carry the validated slot: {rebind:?}"
        );
        assert!(
            [&a, &b]
                .into_iter()
                .any(|r| r.starts_with("POST /api/invalidate-cache HTTP/1.1")),
            "no POST /api/invalidate-cache reached the daemon; got {a:?} and {b:?}"
        );
    }

    /// login-followup R1 HIGH-1 / LOW-5 placement pin: the notify step MUST
    /// run OFF the async worker. Drives the shipped async wrapper on a
    /// current-thread runtime against a daemon that delays its answer, while
    /// a heartbeat task counts how often the runtime gets to poll it. Called
    /// INLINE — the pre-fix shape on the tauri worker — the runtime thread
    /// sits in the blocking socket read and the count stays 0 (this test
    /// reds; the probe was executed in review and is pinned here).
    #[cfg(unix)]
    #[tokio::test]
    async fn notify_step_never_blocks_the_async_worker() {
        let daemon = recording_daemon::RecordingDaemon::new(std::time::Duration::from_millis(300));
        let beats = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let heartbeat = {
            let beats = std::sync::Arc::clone(&beats);
            tokio::spawn(async move {
                loop {
                    beats.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
            })
        };

        let account = AccountNum::try_from(2u16).unwrap();
        notify_daemon_after_login_off_runtime(daemon.base_dir().to_path_buf(), account).await;
        heartbeat.abort();

        assert!(
            beats.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the notify step must not run on the async worker: the heartbeat \
             task was never polled while it ran"
        );
        // The step really did run (it is not a no-op that trivially "does
        // not block"): the daemon saw the invalidation request.
        let _ = daemon.recv("the cache-invalidation POST");
    }
}
