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

    start_claude_login_owned(base, account_num, ClaudeLoginIo::production()).await
}

// Command/transport injection changes no admission, cleanup, seal or finalization
// policy. The renderer can reach only the production constructor above.
type ClaudeCommandFactory =
    Box<dyn FnOnce(&std::path::Path) -> Result<std::process::Command, String> + Send>;
pub(crate) struct ClaudeLoginIo {
    command: ClaudeCommandFactory,
    timeout: std::time::Duration,
    #[cfg(all(test, feature = "test-utils"))]
    pub(crate) profile: Option<csq_core::daemon::usage_poller::HttpGetFn>,
    #[cfg(all(test, feature = "test-utils"))]
    pub(crate) seal_observer: Option<std::sync::Arc<dyn Fn(bool) + Send + Sync>>,
    notify: bool,
}
impl ClaudeLoginIo {
    fn production() -> Self {
        Self {
            command: Box::new(|config| {
                let binary = find_claude_binary()
                    .ok_or_else(|| "CLAUDE_BIN_MISSING: claude binary not found".to_string())?;
                let mut command = std::process::Command::new(binary);
                command
                    .args(["auth", "login"])
                    .env("CLAUDE_CONFIG_DIR", config);
                Ok(command)
            }),
            timeout: crate::login_child_custody::login_timeout(),
            #[cfg(all(test, feature = "test-utils"))]
            profile: None,
            #[cfg(all(test, feature = "test-utils"))]
            seal_observer: None,
            notify: true,
        }
    }
    #[cfg(all(test, unix, feature = "test-utils"))]
    pub(crate) fn fixture(
        command: std::process::Command,
        timeout: std::time::Duration,
        profile: csq_core::daemon::usage_poller::HttpGetFn,
        seal_observer: Option<std::sync::Arc<dyn Fn(bool) + Send + Sync>>,
    ) -> Self {
        Self {
            command: Box::new(move |config| {
                let mut command = command;
                command.env("CSQ_PRIVATE_GRANT", config);
                Ok(command)
            }),
            timeout,
            profile: Some(profile),
            seal_observer,
            notify: false,
        }
    }
}

/// Every error of the owned Claude login, as the renderer receives it.
///
/// Post-lease failures (`begin_launch`, `SPAWN_FAILED`, `mark_completed`,
/// "vendor custody not finalized", `LOGIN_GRANT_CLEANUP_FAILED`) carry the
/// quarantine message, which names the grant relative to the accounts base
/// (`VendorLoginGrant::quarantine_message`). `redact_tokens` does not strip
/// paths; this outer `redact_home_anywhere` is defense in depth for any
/// other home-bearing error in the chain, matching the Codex twin's wrapper
/// around its worker result in `commands/mod.rs` (an internal ticket).
pub(crate) async fn start_claude_login_owned(
    base: std::path::PathBuf,
    account_num: AccountNum,
    io: ClaudeLoginIo,
) -> Result<SubprocessLoginResponse, String> {
    start_claude_login_owned_unredacted(base, account_num, io)
        .await
        .map_err(|e| redact_tokens(&csq_core::cli_deps::sanitize::redact_home_anywhere(&e)))
}

async fn start_claude_login_owned_unredacted(
    base: std::path::PathBuf,
    account_num: AccountNum,
    io: ClaudeLoginIo,
) -> Result<SubprocessLoginResponse, String> {
    let account = account_num.get();
    // S1's sign-in marker: registered before admission and moved into the
    // owned worker below, so a dropped IPC reply can never strand the
    // registration while the login keeps running.
    let signin = crate::desktop::credential_writes::global().register_signin(
        crate::desktop::credential_writes::SigninProvider::Claude,
        account_num,
    )?;
    let key = crate::desktop::login_custody::ChildKey::new(
        crate::desktop::login_custody::LoginProvider::Claude,
        account_num,
    );
    let login =
        crate::desktop::login_custody::global().spawn_with_ticket(move |ticket| async move {
            let _signin = signin;
            let _lock = std::sync::Arc::new(match AccountLoginLock::acquire(&base, account_num) {
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
            });

            let watchdog = crate::login_child_custody::LoginWatchdog::new(
                io.timeout, crate::login_child_custody::DeliveryPhase::Unknown,
            );
            let operation = crate::desktop::login_custody::global().reserve_child(key, watchdog.clone())?;
            // Capture before launching the vendor process. An initially unbound slot
            // must remain unbound until this exact login publishes its verified grant.
            let prior_base = base.clone();
            let prior_lock = std::sync::Arc::clone(&_lock);
            let prior_ticket = std::sync::Arc::clone(&ticket);
            let prior = tokio::task::spawn_blocking(move || {
                let _lock = prior_lock;
                let _ticket = prior_ticket;
                csq_core::accounts::anthropic_identity::capture_login_prior(
                    &prior_base,
                    account_num,
                )
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
            let grant = std::sync::Arc::new(std::sync::Mutex::new(
                csq_core::accounts::credential_transaction::VendorLoginGrant::new(&base)
                    .map_err(|e| format!("LOGIN_GRANT_FAILED: {}", redact_tokens(&e.to_string())))?,
            ));
            { let bound_grant = grant.lock().map_err(|_|"vendor grant lock poisoned".to_string())?; operation.bind_quarantine(&bound_grant)?; }
            let config_dir = grant.lock().map_err(|_| "login_grant_state_poisoned")?.config_dir().to_path_buf();

            // Only an actual successful waiter result permits synchronous cleanup
            // here. A refused observer can return while the vendor still writes;
            // its retained owner performs cleanup after actual group completion.
            let mut vendor_completed_successfully = false;
            let result = async {
            let command = (io.command)(&config_dir)?;
            let grant_for_refusal = std::sync::Arc::clone(&grant);
            let status = desktop_vendor_status_with_grant(
                command,
                (
                    std::sync::Arc::clone(&_lock),
                    std::sync::Arc::clone(&ticket), std::sync::Arc::clone(&grant),
                ),
                watchdog.clone(), std::sync::Arc::clone(&operation), Some(std::sync::Arc::clone(&grant)),
                move || grant_for_refusal.lock().map_err(|_| "login_grant_state_poisoned".to_string())?
                    .cleanup().map_err(|e| format!("LOGIN_GRANT_CLEANUP_FAILED: {}", redact_tokens(&e.to_string()))),
            )
            .await?;
            vendor_completed_successfully = status.success();

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
            let lock_for_commit = std::sync::Arc::clone(&_lock);
            let ticket_for_commit = std::sync::Arc::clone(&ticket);
            let operation_for_commit = std::sync::Arc::clone(&operation);
            let grant_for_commit = std::sync::Arc::clone(&grant);
            let committed = tokio::task::spawn_blocking(move || {
                let _lock = lock_for_commit;
                let _ticket = ticket_for_commit;
                let _grant = grant_for_commit;
                let expected = csq_core::accounts::anthropic_identity::read_native_expectation(
                    &config_dir_for_read,
                )
                .map_err(|e| format!("IDENTITY_FAILED: {e}"))?;
                // Fixture transport is file-only: HOME and mirror suppression do
                // not prove that a native keychain read is safe on macOS.
                #[cfg(all(test, feature = "test-utils"))]
                let fixture_credentials = io.profile.is_some().then(||
                    csq_core::credentials::file::load(&config_dir_for_read.join(".credentials.json"))
                        .map_err(|_| "NO_CREDENTIALS: private fixture grant unreadable".to_string()));
                #[cfg(all(test, feature = "test-utils"))]
                let creds = match fixture_credentials {
                    Some(result) => result?,
                    None => read_fresh_vendor_credentials(&config_dir_for_read)?,
                };
                #[cfg(not(all(test, feature = "test-utils")))]
                let creds = read_fresh_vendor_credentials(&config_dir_for_read)?;
                let seal = || {
                    #[cfg(all(test, feature = "test-utils"))]
                    if let Some(observer)=&io.seal_observer {observer(false);}
                    operation_for_commit.seal_publication()?;
                    #[cfg(all(test, feature = "test-utils"))]
                    if let Some(observer)=&io.seal_observer {observer(true);}
                    Ok(())
                };
                #[cfg(all(test, feature = "test-utils"))]
                if let Some(profile)=&io.profile {
                    return csq_core::accounts::anthropic_identity::commit_anthropic_login_with_seal(
                        &base_for_commit, account_num, &creds, profile, Some(&expected), prior, seal)
                        .map_err(|e|format!("IDENTITY_FAILED: {}",redact_tokens(&format!("{e:#}"))));
                }
                csq_core::accounts::anthropic_identity::commit_anthropic_login_sealed(
                    &base_for_commit,
                    account_num,
                    &creds,
                    Some(&expected),
                    prior,
                    seal,
                )
                .map_err(|e| {
                    format!(
                        "IDENTITY_FAILED: {}",
                        redact_tokens(&format!("{e:#}"))
                    )
                })
            })
            .await
            .map_err(|_| "INTERNAL: verified login task failed".to_string())??;

            // Finalization rechecks the committed receipt, writes its UUID marker under
            // the profiles lock, then queues the nonblocking keychain mirror.
            let base_for_finalize = base.clone();
            let lock_for_finalize = std::sync::Arc::clone(&_lock);
            let ticket_for_finalize = std::sync::Arc::clone(&ticket);
            let operation_for_finalize = std::sync::Arc::clone(&operation);
            let grant_for_finalize = std::sync::Arc::clone(&grant);
            let email = tokio::task::spawn_blocking(move || {
                let _lock = lock_for_finalize;
                let _ticket = ticket_for_finalize;
                let _operation = operation_for_finalize;
                let _grant = grant_for_finalize;
                finalize_verified_login(&base_for_finalize, account_num, committed)
            })
            .await
            .map_err(|e| {
                format!(
                    "INTERNAL: finalize task join failed: {}",
                    csq_core::error::join_cause(&e)
                )
            })?
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
            if io.notify { notify_daemon_after_login_off_runtime(base.clone(), account_num).await; }

            operation.mark_committed()?;
            Ok(SubprocessLoginResponse {
                account: account_num.get(),
                email,
            })
            }.await;
            if vendor_completed_successfully {
                if let Err(error) = grant.lock().map_err(|_| "login_grant_state_poisoned")?.cleanup() {
                    if result.as_ref().err().is_some_and(|error| error.starts_with("login_committed_cancelled:")) {
                        return Err(format!("{}; private grant cleanup unconfirmed: {}", crate::desktop::login_custody::COMMITTED_CANCELLED, redact_tokens(&error.to_string())));
                    }
                    return Err(format!("LOGIN_GRANT_CLEANUP_FAILED: {}", redact_tokens(&error.to_string())));
                }
            }
            result
        })?;
    login
        .await
        .map_err(|_| "INTERNAL: owned desktop login failed".to_string())?
}

fn read_fresh_vendor_credentials(
    config: &std::path::Path,
) -> Result<csq_core::credentials::CredentialFile, String> {
    csq_core::credentials::read_fresh_after_login(config).map_err(|error| {
        let tag = match error {
            csq_core::credentials::FreshLoginError::NoCredentials => "NO_CREDENTIALS",
            csq_core::credentials::FreshLoginError::OnlyStale => "STALE_CREDENTIALS",
        };
        format!("{tag}: {error}")
    })
}

/// The UI observes this operation; the blocking owner retains the actual
/// child and keepalive guard after timeout or observer cancellation. Opaque
/// vendor browser authorization is UNKNOWN, so this adapter never requests a
/// graceful stop or kill and never infers PRE from output or elapsed time.
#[cfg(test)]
pub(crate) async fn desktop_vendor_status_registered_with_timeout<K: Send + Sync + 'static>(
    command: std::process::Command,
    keepalive: K,
    timeout: std::time::Duration,
    key: crate::desktop::login_custody::ChildKey,
) -> Result<std::process::ExitStatus, String> {
    let watchdog = crate::login_child_custody::LoginWatchdog::new(
        timeout,
        crate::login_child_custody::DeliveryPhase::Unknown,
    );
    let operation = crate::desktop::login_custody::global().reserve_child(key, watchdog.clone())?;
    desktop_vendor_status_impl(command, keepalive, watchdog, operation, || Ok(())).await
}
#[cfg(test)]
pub(crate) async fn desktop_vendor_status_impl<K: Send + Sync + 'static>(
    command: std::process::Command,
    keepalive: K,
    watchdog: crate::login_child_custody::LoginWatchdog,
    operation: std::sync::Arc<crate::desktop::login_custody::ChildRegistration>,
    cleanup_refused_grant: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<std::process::ExitStatus, String> {
    desktop_vendor_status_with_grant(
        command,
        keepalive,
        watchdog,
        operation,
        None,
        cleanup_refused_grant,
    )
    .await
}
async fn desktop_vendor_status_with_grant<K: Send + Sync + 'static>(
    mut command: std::process::Command,
    keepalive: K,
    watchdog: crate::login_child_custody::LoginWatchdog,
    operation: std::sync::Arc<crate::desktop::login_custody::ChildRegistration>,
    grant: Option<super::SharedVendorGrant>,
    cleanup_refused_grant: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<std::process::ExitStatus, String> {
    use crate::login_child_custody::OwnedLoginChild;
    watchdog.check_spawn_allowed().map_err(|e| e.to_string())?;
    let (notice_tx, mut notice_rx) = tokio::sync::oneshot::channel();
    let mut worker = tokio::task::spawn_blocking(move || {
        let registered = std::sync::Arc::new(crate::desktop::login_custody::ChildCustody::new(
            keepalive, operation,
        ));
        if let Some(grant) = &grant {
            grant
                .lock()
                .map_err(|_| "vendor grant lock poisoned".to_string())?
                .begin_launch()
                .map_err(|e| redact_tokens(&format!("{e:#}")))?;
        }
        let (child, group) =
            crate::login_child_custody::group::spawn(&mut command).map_err(|e| {
                let quarantine = grant
                    .as_ref()
                    .and_then(|grant| grant.lock().ok().map(|grant| grant.quarantine_message()))
                    .unwrap_or_else(|| "vendor login quarantine state unavailable".into());
                format!(
                    "SPAWN_FAILED: {}; {quarantine}",
                    redact_tokens(&e.to_string())
                )
            })?;
        // Adoption is infallible and immediately follows successful spawn.
        // This inherited-stdio flow owns no pipe readers or forwarder.
        let mut child = OwnedLoginChild::adopt_group(
            child,
            group,
            watchdog.clone(),
            std::sync::Arc::clone(&registered),
        );
        registered.attach(child.shared_child(), child.group_control());
        let mut notice_tx = Some(notice_tx);
        let result = child.wait_vendor(
            || Ok(true),
            move |notice| {
                if let Some(tx) = notice_tx.take() {
                    let _ = tx.send(format!("{}: sign-in program is still running; canonical login publication refused", notice.tag()));
                }
            },
            || Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "opaque desktop login has no authorized PRE stop",
            )),
        ).map_err(|e| e.to_string());
        if let Some(grant) = &grant {
            if child.custody_finalized() {
                grant
                    .lock()
                    .map_err(|_| "vendor grant lock poisoned".to_string())?
                    .mark_completed()
                    .map_err(|e| redact_tokens(&format!("{e:#}")))?;
            } else {
                let message = grant
                    .lock()
                    .map(|grant| grant.quarantine_message())
                    .unwrap_or_else(|_| "vendor login quarantine state unavailable".into());
                // Cleanup closure retains the same unique grant while actual
                // owner retains its K. No launch-unknown cleanup authority.
                std::mem::forget(cleanup_refused_grant);
                return Err(format!("{message}; vendor custody not finalized"));
            }
        }
        if watchdog.custody_unresolved() {
            // Keep cleanup/operation ownership with the retained actual process.
            std::mem::forget(cleanup_refused_grant);
            return result;
        }
        if !matches!(&result, Ok(status) if status.success()) {
            if let Err(error) = cleanup_refused_grant() {
                tracing::error!(error_kind="login_grant_cleanup_unconfirmed", reason=%redact_tokens(&error), "refused private vendor grant cleanup failed; quarantine retained");
                return Err(error);
            }
        }
        result
    });

    tokio::select! {
        // The helper atomically seals OnTimeComplete or Refused, including a
        // simultaneous completion/deadline. A late exit 0 remains Err.
        result = &mut worker => {
            result.map_err(|_| "INTERNAL: desktop vendor owner failed".to_string())?
        }
        notice = &mut notice_rx => {
            match notice {
                Ok(refusal) => Err(refusal),
                // Normal completion drops the unused notice sender. Await the
                // actual worker result; a closed channel is not completion.
                Err(_) => worker.await
                    .map_err(|_| "INTERNAL: desktop vendor owner failed".to_string())?,
            }
        }
    }
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

    /// Restores `HOME` on drop, so a failing assertion cannot leak the
    /// override into the next test that takes the env lock.
    #[cfg(all(unix, feature = "test-utils"))]
    struct HomeRestore(Option<std::ffi::OsString>);
    #[cfg(all(unix, feature = "test-utils"))]
    impl Drop for HomeRestore {
        fn drop(&mut self) {
            unsafe {
                match self.0.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    /// an internal ticket R1 M1: a failure AFTER the grant's lease is written carries
    /// the quarantine message, and the accounts base lives under `$HOME`
    /// (the OS user name). Drives the real owned flow to a
    /// post-lease failure — the vendor binary cannot be spawned, after
    /// `begin_launch` has persisted the lease — and asserts the String the
    /// renderer receives carries neither `$HOME` nor any absolute path,
    /// matching the Codex twin's `redact_home_anywhere` wrapper.
    #[cfg(all(unix, feature = "test-utils"))]
    #[tokio::test]
    async fn post_lease_failure_reaches_the_renderer_without_the_home_path() {
        let _env = csq_core::platform::test_env::lock();
        let home = tempfile::TempDir::new().unwrap();
        let base = home.path().join(".claude").join("accounts");
        std::fs::create_dir_all(&base).unwrap();
        let _restore = HomeRestore(std::env::var_os("HOME"));
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let profile: csq_core::daemon::usage_poller::HttpGetFn =
            std::sync::Arc::new(|_, _, _| panic!("a failed spawn must not reach the profile"));
        let command = std::process::Command::new(home.path().join("missing-claude-1729"));
        let error = start_claude_login_owned(
            base,
            AccountNum::try_from(47u16).unwrap(),
            ClaudeLoginIo::fixture(command, std::time::Duration::from_secs(30), profile, None),
        )
        .await
        .expect_err("an unspawnable vendor binary must fail the login");

        // The failure must be post-lease, or the assertions below prove nothing.
        assert!(
            error.contains("SPAWN_FAILED") && error.contains("vendor_login_quarantined"),
            "expected a post-lease spawn failure carrying the quarantine: {error}"
        );
        assert_renderer_safe(&error, &[home.path()]);
    }

    /// Asserts `error` names none of `roots` (literal or canonical) and
    /// carries no absolute path at all.
    #[cfg(all(unix, feature = "test-utils"))]
    fn assert_renderer_safe(error: &str, roots: &[&std::path::Path]) {
        for root in roots {
            let literal = root.display().to_string();
            let canonical = std::fs::canonicalize(root).unwrap().display().to_string();
            assert!(
                !error.contains(&literal) && !error.contains(&canonical),
                "{literal} reached the renderer: {error}"
            );
        }
        let mut previous = ' ';
        for c in error.chars() {
            assert!(
                !(c == '/' && (previous.is_whitespace() || "(:=\"'".contains(previous))),
                "an absolute path reached the renderer: {error}"
            );
            previous = c;
        }
    }

    /// an internal ticket R2-1: `~/.claude/accounts` symlinked to a tree OUTSIDE `$HOME`
    /// (a dotfile manager, another volume). The grant home canonicalizes
    /// outside home, so `redact_home_anywhere` cannot catch it; only a
    /// quarantine location rendered relative to the base keeps it out.
    #[cfg(all(unix, feature = "test-utils"))]
    #[tokio::test]
    async fn post_lease_failure_with_a_base_outside_home_reaches_the_renderer_path_free() {
        let _env = csq_core::platform::test_env::lock();
        let home = tempfile::TempDir::new().unwrap();
        let target = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        let base = home.path().join(".claude").join("accounts");
        std::os::unix::fs::symlink(target.path(), &base).unwrap();
        let _restore = HomeRestore(std::env::var_os("HOME"));
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let profile: csq_core::daemon::usage_poller::HttpGetFn =
            std::sync::Arc::new(|_, _, _| panic!("a failed spawn must not reach the profile"));
        let command = std::process::Command::new(home.path().join("missing-claude-1729"));
        let error = start_claude_login_owned(
            base,
            AccountNum::try_from(48u16).unwrap(),
            ClaudeLoginIo::fixture(command, std::time::Duration::from_secs(30), profile, None),
        )
        .await
        .expect_err("an unspawnable vendor binary must fail the login");
        assert!(
            error.contains("SPAWN_FAILED") && error.contains("vendor_login_quarantined"),
            "expected a post-lease spawn failure carrying the quarantine: {error}"
        );
        assert_renderer_safe(&error, &[home.path(), target.path()]);
    }

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
