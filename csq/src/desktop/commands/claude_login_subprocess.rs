//! Subprocess-based Claude OAuth login command.
//!
//! Phase 1 of #389 — adds `start_claude_login_subprocess` Tauri command
//! alongside the existing parallel-race flow in [`super::race`]. CC is
//! the reference OAuth client; this command shells out to
//! `claude auth login` with `CLAUDE_CONFIG_DIR=<base>/config-<N>` and
//! lets CC's own seamless flow (IPv6 `[::1]:<random>` + hosted JS
//! bridge) handle the redirect end-to-end. Once the subprocess exits
//! successfully, we capture the credentials CC wrote, persist them
//! canonically, write the `.csq-account` marker, and run
//! [`csq_core::accounts::login::finalize_login`] for the email +
//! profiles.json update — identical to the CLI's `handle_direct` path
//! that landed in #388.
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

use csq_core::accounts::login::{finalize_login, find_claude_binary};
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::accounts::{markers, profiles};
use csq_core::credentials::file as cred_file;
use csq_core::error::redact_tokens;
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::PathBuf;
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

    let base = PathBuf::from(&base_dir);
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
    let creds = tokio::task::spawn_blocking(move || {
        csq_core::credentials::read_fresh_after_login(&config_dir_for_read)
    })
    .await
    .map_err(|e| format!("INTERNAL: credential-read task join failed: {e}"))?
    .map_err(|e| {
        let tag = match e {
            csq_core::credentials::FreshLoginError::NoCredentials => "NO_CREDENTIALS",
            csq_core::credentials::FreshLoginError::OnlyStale => "STALE_CREDENTIALS",
        };
        format!("{tag}: {e}")
    })?;

    // an internal ticket (mirror of the CLI fix): mint the slot's identity UUID BEFORE
    // save — save_canonical_for is fail-closed on an absent UUID (M4-12), which
    // the fresh-install / macOS-keychain-only flow otherwise can't satisfy until
    // finalize_login (later). Idempotent + no-op when already minted / no email.
    csq_core::accounts::login::ensure_login_identity_minted(&base, account_num)
        .map_err(|e| format!("MINT_FAILED: {}", redact_tokens(&e)))?;

    cred_file::save_canonical_for(&base, account_num, &creds).map_err(|e| {
        format!(
            "CRED_WRITE_FAILED: credential write failed: {}",
            redact_tokens(&e.to_string())
        )
    })?;

    // M4-7 (an internal ticket Phase 4, spec 02 §INV-03 + §2.3.1): seed the
    // `.csq-account` marker now so the post-credential state can be
    // identified by readers even if `finalize_login` fails halfway
    // through. The marker content is the slot's identity UUID when a
    // `by_slot` mapping exists; otherwise the legacy decimal slot id.
    // `finalize_login` re-writes the marker AFTER `mint_for_login`
    // succeeds, so the final on-disk content reflects the freshly
    // minted UUID in the happy path.
    match profiles::resolve_slot_to_uuid(&base, account_num.get()) {
        Some(uuid) => markers::write_csq_account(&config_dir, uuid).map_err(|e| {
            format!(
                "MARKER_WRITE_FAILED: marker write failed: {}",
                redact_tokens(&e.to_string())
            )
        })?,
        None => markers::write_csq_account_legacy(&config_dir, account_num).map_err(|e| {
            format!(
                "MARKER_WRITE_FAILED: marker write failed: {}",
                redact_tokens(&e.to_string())
            )
        })?,
    }

    // `finalize_login` is SYNCHRONOUS and now mirrors the bound account's token
    // into the macOS keychain (`sync_all_handle_dirs` — one blocking `security`
    // subprocess per live handle dir, no timeout). Run it on the blocking pool so
    // the Tauri runtime worker stays responsive — same convention as the
    // `read_fresh_after_login` call above and `tauri-commands.md` MUST-NOT-3 (no
    // blocking the async runtime thread).
    let base_for_finalize = base.clone();
    let email =
        tokio::task::spawn_blocking(move || finalize_login(&base_for_finalize, account_num))
            .await
            .map_err(|e| format!("INTERNAL: finalize task join failed: {e}"))?
            .map_err(|e| format!("FINALIZE_FAILED: {}", redact_tokens(&e.to_string())))?;

    // Best-effort: nudge the daemon's account-discovery cache so the
    // dashboard's next poll sees the new slot immediately rather than
    // after its 5 s TTL. Failure is swallowed — the dashboard will
    // still pick up the slot on its own.
    #[cfg(unix)]
    {
        let sock = csq_core::daemon::socket_path(&base);
        if sock.exists() {
            let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
        }
    }

    Ok(SubprocessLoginResponse {
        account: account_num.get(),
        email,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Phase 2 / #389 follow-up: drive the full command with a stub
    /// `claude` binary on PATH. Requires the `stub-claude` bin and a
    /// `clean_command`-style env reset (rules/testing.md MUST Rule 4a)
    /// that the existing `cli_deps_login_integration` harness already
    /// builds for the CLI side; mirroring it here is non-trivial
    /// because the desktop command needs `tauri::Window` which is
    /// hard to fake outside of `tauri::test::mock_app()`. Tracked on
    /// #389 as the desktop-side end-to-end gap.
    #[allow(dead_code)]
    fn _phase2_end_to_end_test_placeholder() {}
}
