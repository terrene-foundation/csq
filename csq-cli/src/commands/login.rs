//! `csq login <N>` — OAuth login flow for a new account.
//!
//! # Path selection (revised in v2.0.0-alpha.5)
//!
//! Previous versions tried a daemon-delegated path first that
//! assumed the daemon would catch a loopback OAuth redirect. That
//! was true under the v1.x loopback design, but journal 0020
//! retired loopback and nothing replaced the "daemon completes the
//! exchange" step — the CLI would open the browser and then poll
//! `credentials/{N}.json` for five minutes while nothing ever
//! wrote it.
//!
//! The current priority is:
//!
//! 1. **Delegate to `claude auth login`** (preferred) — if the
//!    `claude` binary is on `PATH`, spawn it with an isolated
//!    `CLAUDE_CONFIG_DIR=config-{N}/`. CC has its own
//!    seamless flow (browser opens, hosted callback page bridges
//!    the code back to a local listener CC owns). csq imports the
//!    credentials from the isolated dir when CC exits. **This is
//!    the same UX as running `claude auth login` yourself.**
//!
//! 2. **Paste-code via the daemon** (fallback) — if `claude` is
//!    not on `PATH` or its process fails, and a healthy daemon is
//!    available, ask the daemon to `GET /api/login/{N}` for an
//!    authorize URL, open the browser, prompt on stdin for the
//!    authorization code from Anthropic's hosted callback page,
//!    and `POST /api/oauth/exchange` with the code. The daemon
//!    writes `credentials/{N}.json` on successful exchange.
//!
//! Both paths finish by updating `profiles.json` (email label),
//! writing the `.csq-account` marker, and clearing any
//! `broker_failed` sentinel.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::markers;
use csq_core::credentials::{self, file, keychain};
use csq_core::types::AccountNum;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::Command;

#[cfg(unix)]
use csq_core::daemon::{self, DaemonClientError, DetectResult};

/// Entry point invoked from `main.rs`. Prefers the shell-out to
/// `claude auth login` (same UX as running CC directly); falls back
/// to the daemon paste-code path when `claude` is unavailable.
pub fn handle(base_dir: &Path, account: AccountNum) -> Result<()> {
    if csq_core::accounts::login::find_claude_binary().is_some() {
        return handle_direct(base_dir, account);
    }

    #[cfg(unix)]
    {
        eprintln!(
            "note: `claude` binary not found on PATH — falling back to daemon paste-code flow"
        );
        handle_paste_code(base_dir, account)
    }

    #[cfg(not(unix))]
    {
        Err(anyhow!(
            "`claude` binary not found on PATH — install Claude Code and re-run `csq login {account}`"
        ))
    }
}

// `which_claude` was inlined and replaced by
// `csq_core::accounts::login::find_claude_binary`, which also walks
// well-known install paths so Finder-launched apps (the desktop
// bundle) can find `claude` even when their `$PATH` is the minimal
// Finder default.

/// Paste-code login path via the csq daemon.
///
/// Only used when `claude` is not on `PATH`. Steps:
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
fn handle_paste_code(base_dir: &Path, account: AccountNum) -> Result<()> {
    // Step 1: detect the daemon.
    let socket_path = match daemon::detect_daemon(base_dir) {
        DetectResult::Healthy { socket_path, .. } => socket_path,
        DetectResult::NotRunning => {
            return Err(anyhow!(
                "csq daemon is not running — start it with `csq daemon start` \
                 or install the desktop app so the daemon runs in the background"
            ));
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
        eprintln!("warning: could not spawn browser opener: {e}");
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
    finalize(base_dir, account).context("post-login finalization failed")
}

/// Subset of the daemon's `LoginRequest` JSON we need.
///
/// Defined locally so the CLI is not coupled to the full struct's
/// layout — `auth_url` + `state` are the load-bearing fields.
#[cfg(unix)]
#[derive(Debug)]
struct DaemonLoginRequest {
    auth_url: String,
    state: String,
}

#[cfg(unix)]
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
#[cfg(unix)]
fn open_in_browser(url: &str) -> Result<()> {
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
fn handle_direct(base_dir: &Path, account: AccountNum) -> Result<()> {
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)?;

    // Mark this dir with the account number early so recovery is possible
    markers::write_csq_account(&config_dir, account)?;

    println!("Starting OAuth login for account {}...", account);
    println!("Your browser will open for authorization.");

    // Invoke `claude auth login` with isolated config dir
    let status = Command::new("claude")
        .args(["auth", "login"])
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .status()
        .context("failed to spawn `claude auth login` — is Claude Code installed?")?;

    if !status.success() {
        return Err(anyhow!("claude auth login exited with non-zero status"));
    }

    // CC's modern `claude auth login` writes credentials to ONE of
    // two places, depending on platform / version:
    //   * macOS: the system keychain at the hashed service name
    //     (`Claude Code-credentials-{hash}`) — sometimes ALSO
    //     mirrored to `.credentials.json`, sometimes not.
    //   * Linux/Windows: always `.credentials.json`.
    //
    // We read keychain first, fall back to file. Either source is
    // authoritative — they hold the same payload — and at least one
    // is guaranteed to exist after a successful auth.
    let creds = keychain::read(&config_dir)
        .or_else(|| credentials::load(&config_dir.join(".credentials.json")).ok())
        .ok_or_else(|| {
            anyhow!("no credentials captured after login — keychain and file both empty")
        })?;

    // Save canonical + mirror
    file::save_canonical(base_dir, account, &creds)?;
    println!(
        "Credentials saved to {}",
        file::canonical_path(base_dir, account).display()
    );

    finalize(base_dir, account)
}

/// Post-login finalization shared by both paths.
///
/// 1. Writes the `.csq-account` marker if the config dir exists.
/// 2. Updates `profiles.json` with the email (best-effort — uses
///    `claude auth status --json` if the binary is available,
///    otherwise stores "unknown").
/// 3. Clears any `broker_failed` sentinel for this account.
fn finalize(base_dir: &Path, account: AccountNum) -> Result<()> {
    // Marker write + .claude.json email read + profiles update +
    // broker-failed clear all live in csq_core so the desktop
    // Add Account flow can call the same helper.
    let email = csq_core::accounts::login::finalize_login(base_dir, account)
        .with_context(|| format!("finalize for account {account}"))?;

    notify_daemon_cache_invalidation(base_dir);

    println!("Logged in as {} (account {}).", email, account);
    Ok(())
}

#[cfg(unix)]
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    let sock = csq_core::daemon::socket_path(base_dir);
    if !sock.exists() {
        return;
    }
    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
}

#[cfg(not(unix))]
fn notify_daemon_cache_invalidation(_base_dir: &Path) {
    // Windows named-pipe invalidation is not yet implemented (M8-03).
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
    use super::*;

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
}
