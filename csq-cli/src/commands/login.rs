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
use csq_core::accounts::{markers, profiles};
use csq_core::broker::fanout;
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
    if which_claude().is_some() {
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

/// Returns `Some(path)` if `claude` is on `PATH`, `None` otherwise.
/// Stdlib-only PATH walk — no `which` crate dependency.
fn which_claude() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("claude");
        if let Ok(meta) = candidate.metadata() {
            if meta.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o111 != 0 {
                        return Some(candidate);
                    }
                }
                #[cfg(not(unix))]
                {
                    return Some(candidate);
                }
            }
        }
        // Windows: also try `claude.exe`
        #[cfg(windows)]
        {
            let candidate_exe = dir.join("claude.exe");
            if candidate_exe.is_file() {
                return Some(candidate_exe);
            }
        }
    }
    None
}

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

/// Reads the account email for a freshly-logged-in config dir.
///
/// Tries two sources, in order:
///
/// 1. **`config_dir/.claude.json`** → `oauthAccount.emailAddress`.
///    CC writes this field to the local `.claude.json` as part of
///    `claude auth login`, and it's the canonical on-disk copy of
///    the user identity bound to that slot. File-based, no
///    subprocess, no timing window — preferred.
///
/// 2. **`claude auth status --json`** fallback. Kept for cases
///    where `.claude.json` is missing (e.g. the user ran
///    `csq login` against a pre-existing config dir that CC had
///    populated via `.credentials.json` but not `.claude.json`).
///
/// The previous implementation shelled out to `claude auth status`
/// exclusively. That had a race window right after `claude auth login`
/// exited where CC's keychain/.claude.json writes hadn't fully landed,
/// causing the JSON output to lack `email` and the finalizer to
/// report `Logged in as unknown`.
fn get_email_from_cc(config_dir: &Path) -> Result<String> {
    // Source 1: .claude.json local state (preferred)
    let claude_json_path = config_dir.join(".claude.json");
    if let Ok(content) = std::fs::read_to_string(&claude_json_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(email) = json
                .get("oauthAccount")
                .and_then(|a| a.get("emailAddress"))
                .and_then(|v| v.as_str())
            {
                if !email.is_empty() {
                    return Ok(email.to_string());
                }
            }
        }
    }

    // Source 2: claude auth status --json (legacy fallback)
    let output = Command::new("claude")
        .args(["auth", "status", "--json"])
        .env("CLAUDE_CONFIG_DIR", config_dir)
        .output()
        .context("failed to spawn `claude auth status`")?;

    if !output.status.success() {
        return Err(anyhow!("claude auth status failed"));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("claude auth status produced non-JSON output")?;
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
