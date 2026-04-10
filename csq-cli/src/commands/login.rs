//! `csq login <N>` — OAuth login flow for a new account.
//!
//! # Two execution paths
//!
//! 1. **Daemon-delegated (preferred on Unix)** — when a healthy
//!    daemon is running, the CLI asks it to start a PKCE login via
//!    `GET /api/login/{N}`, opens the returned authorize URL in a
//!    browser, and polls `{base_dir}/credentials/{N}.json` until
//!    the daemon's `/oauth/callback` handler writes it. This path
//!    is the one Claude Code itself uses internally and produces
//!    byte-identical credentials — no shell-out, no `claude`
//!    binary dependency.
//!
//! 2. **Direct shell-out (fallback)** — if no daemon is running,
//!    the port 8420 callback listener is unavailable, or the user
//!    has not yet started the daemon, we fall back to the legacy
//!    path: spawn `claude auth login` with an isolated
//!    `CLAUDE_CONFIG_DIR`, then capture the credentials from the
//!    keychain or `.credentials.json` file.
//!
//! Both paths finish by updating `profiles.json` (email label),
//! writing the `.csq-account` marker, and clearing any
//! `broker_failed` sentinel. These finalization steps are owned by
//! the CLI, not the daemon, so the discovery cache picks up the
//! account on the next poll regardless of which path ran.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::{markers, profiles};
use csq_core::broker::fanout;
use csq_core::credentials::{self, file, keychain};
use csq_core::types::AccountNum;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(unix)]
use csq_core::daemon::{self, DaemonClientError, DetectResult};

/// How often the CLI polls the canonical credential file while
/// waiting for the daemon's callback handler to write it.
const POLL_INTERVAL: Duration = Duration::from_millis(750);

/// Cap on the total daemon-path wait time. The daemon's state store
/// has its own TTL ([`csq_core::oauth::STATE_TTL`], currently 5
/// minutes), but we also bound the CLI wait so a user who walked
/// away from their browser still gets a clear error instead of an
/// indefinite spinner. 5 minutes matches the state TTL.
const DAEMON_WAIT_CAP: Duration = Duration::from_secs(300);

/// Entry point invoked from `main.rs`. Tries the daemon-delegated
/// path first and falls back to the direct path on failure.
pub fn handle(base_dir: &Path, account: AccountNum) -> Result<()> {
    #[cfg(unix)]
    {
        match try_daemon_path(base_dir, account) {
            DaemonPathOutcome::Succeeded => return Ok(()),
            DaemonPathOutcome::Fallback(reason) => {
                eprintln!("note: {reason}");
                eprintln!("      falling back to direct `claude auth login`.");
            }
            DaemonPathOutcome::Failed(e) => return Err(e),
        }
    }

    handle_direct(base_dir, account)
}

/// Outcome of attempting the daemon-delegated login path.
#[cfg(unix)]
enum DaemonPathOutcome {
    /// Login completed via the daemon path; nothing more to do.
    Succeeded,
    /// Daemon is not available or returned 503; caller should fall
    /// back to the direct path. The string is a one-line reason
    /// for the fallback note printed to stderr.
    Fallback(String),
    /// The daemon path reached an unrecoverable failure; propagate
    /// the error to the user instead of silently falling back.
    /// Example: user denied consent, or the exchange failed.
    Failed(anyhow::Error),
}

/// Attempts the daemon-delegated login path.
///
/// Does NOT call `Command::new("claude")` — the daemon owns the
/// OAuth flow end-to-end. On success the CLI only performs the
/// finalization steps (profile update, marker, broker-failed
/// clear).
#[cfg(unix)]
fn try_daemon_path(base_dir: &Path, account: AccountNum) -> DaemonPathOutcome {
    // Step 1: detect the daemon. Any result other than Healthy
    // triggers a fallback with a descriptive reason.
    let socket_path = match daemon::detect_daemon(base_dir) {
        DetectResult::Healthy { socket_path, .. } => socket_path,
        DetectResult::NotRunning => {
            return DaemonPathOutcome::Fallback("csq daemon is not running".to_string());
        }
        DetectResult::Stale { reason } => {
            return DaemonPathOutcome::Fallback(format!("csq daemon is stale: {reason}"));
        }
        DetectResult::Unhealthy { reason } => {
            return DaemonPathOutcome::Fallback(format!("csq daemon is unhealthy: {reason}"));
        }
    };

    // Step 2: ask the daemon to start an OAuth login. The daemon
    // generates the PKCE pair, stores the state token, and returns
    // the Anthropic authorize URL. A 503 here means the OAuth
    // callback listener is down (port 8420 in use) — the daemon is
    // otherwise healthy, so we can cleanly fall back.
    let path_and_query = format!("/api/login/{}", account.get());
    let resp = match daemon::http_get_unix(&socket_path, &path_and_query) {
        Ok(r) => r,
        Err(DaemonClientError::Connect(_)) => {
            return DaemonPathOutcome::Fallback(
                "lost connection to daemon socket".to_string(),
            );
        }
        Err(e) => {
            return DaemonPathOutcome::Failed(anyhow!("daemon login call failed: {e}"));
        }
    };

    match resp.status {
        200 => {}
        400 => {
            return DaemonPathOutcome::Failed(anyhow!(
                "daemon rejected account {}: {}",
                account,
                resp.body.trim()
            ));
        }
        503 => {
            return DaemonPathOutcome::Fallback(
                "daemon OAuth callback listener is not available (port 8420 in use?)"
                    .to_string(),
            );
        }
        other => {
            return DaemonPathOutcome::Failed(anyhow!(
                "daemon returned HTTP {} on /api/login/{}: {}",
                other,
                account,
                resp.body.trim()
            ));
        }
    }

    // Step 3: parse the daemon's LoginRequest JSON. Only the
    // `auth_url` is strictly required; the other fields are
    // informational for the CLI.
    let login = match parse_login_response(&resp.body) {
        Ok(v) => v,
        Err(e) => {
            return DaemonPathOutcome::Failed(anyhow!(
                "could not parse daemon /api/login response: {e}"
            ));
        }
    };

    // Step 4: open the authorize URL in the user's browser.
    println!("Starting OAuth login for account {} via csq daemon...", account);
    println!("Opening your browser to complete authorization.");
    println!();
    println!("If the browser does not open, paste this URL manually:");
    println!("  {}", login.auth_url);
    println!();

    if let Err(e) = open_in_browser(&login.auth_url) {
        eprintln!("warning: could not spawn browser opener: {e}");
        eprintln!("         open the URL above by hand to continue.");
    }

    // Step 5: poll the canonical credential file until the daemon
    // writes it, or the wait cap elapses. Polling the filesystem
    // directly avoids the `/api/accounts` discovery cache (5s TTL)
    // and keeps the CLI responsive.
    let canonical = file::canonical_path(base_dir, account);
    let deadline = Instant::now() + DAEMON_WAIT_CAP;
    println!("Waiting for the daemon to complete the exchange...");

    loop {
        if canonical.exists() {
            // Verify the file is a well-formed credential file
            // before declaring victory — a half-written file is
            // unlikely given `atomic_replace`, but defensive.
            if credentials::load(&canonical).is_ok() {
                break;
            }
        }
        if Instant::now() >= deadline {
            return DaemonPathOutcome::Failed(anyhow!(
                "timed out waiting {} seconds for daemon to complete login — \
                 the browser flow may have been cancelled or the state token expired",
                DAEMON_WAIT_CAP.as_secs()
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // Step 6: finalize. The daemon wrote credentials/N.json and
    // config-N/.credentials.json but left profile/markers to the
    // CLI, because the daemon never runs `claude auth status` and
    // should not depend on the `claude` binary.
    if let Err(e) = finalize(base_dir, account) {
        return DaemonPathOutcome::Failed(e.context("post-login finalization failed"));
    }

    DaemonPathOutcome::Succeeded
}

/// Subset of the daemon's `LoginRequest` JSON we need.
///
/// Defined locally so the CLI is not coupled to the full struct's
/// layout — only `auth_url` is load-bearing.
#[cfg(unix)]
#[derive(Debug)]
struct DaemonLoginRequest {
    auth_url: String,
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
    Ok(DaemonLoginRequest { auth_url })
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

    // Capture credentials — try keychain first, then file
    let captured = keychain::read(&config_dir)
        .or_else(|| credentials::load(&config_dir.join(".credentials.json")).ok());

    let creds = captured.ok_or_else(|| {
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
    let config_dir = base_dir.join(format!("config-{}", account));
    if config_dir.exists() {
        // Best-effort: the daemon path also creates this dir (via
        // save_canonical's live_path mirror). The direct path
        // already created it at the top of handle_direct().
        markers::write_csq_account(&config_dir, account)?;
    }

    let email = get_email_from_cc(&config_dir).unwrap_or_else(|_| "unknown".to_string());
    update_profile(base_dir, account, &email)?;

    fanout::clear_broker_failed(base_dir, account);

    println!("Logged in as {} (account {}).", email, account);
    Ok(())
}

fn get_email_from_cc(config_dir: &Path) -> Result<String> {
    let output = Command::new("claude")
        .args(["auth", "status", "--json"])
        .env("CLAUDE_CONFIG_DIR", config_dir)
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("claude auth status failed"));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    json.get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no email in claude auth status output"))
}

fn update_profile(base_dir: &Path, account: AccountNum, email: &str) -> Result<()> {
    let path = profiles::profiles_path(base_dir);
    let mut profiles = profiles::load(&path).unwrap_or_else(|_| profiles::ProfilesFile::empty());

    profiles.set_profile(
        account.get(),
        profiles::AccountProfile {
            email: email.to_string(),
            method: "oauth".to_string(),
            extra: std::collections::HashMap::new(),
        },
    );

    profiles::save(&path, &profiles)?;
    Ok(())
}

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
        assert!(parsed.auth_url.starts_with("https://claude.ai/oauth/authorize"));
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
