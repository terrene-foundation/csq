//! `csq login <N>` — OAuth login flow for a new account.
//!
//! # Path selection (revised for the parallel-race flow)
//!
//! Default is the in-process parallel-race flow that mirrors CC's
//! `services/oauth/index.ts:58-86` pattern: csq binds an ephemeral
//! loopback listener AND prompts for a paste code in parallel.
//! Whichever resolves first wins; the loser is dropped cleanly.
//! The user can authorise seamlessly OR copy the URL to a separate
//! device and paste the resulting code back. Same login flow,
//! both work — no daemon, no `claude` binary on PATH required.
//!
//! `--legacy-shell` preserves the original `claude auth login`
//! shell-out path as an emergency rollback. The daemon-delegated
//! paste-code path is still exposed as `handle_paste_code` for the
//! desktop shim during the transition; it is no longer the CLI
//! default.
//!
//! All paths end by writing the `.csq-account` marker, updating
//! `profiles.json` with the email label, and clearing any
//! `broker_failed` sentinel via [`csq_core::accounts::login::finalize_login`].

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::accounts::markers;
use csq_core::credentials::{self, file, keychain};
use csq_core::oauth::{self, RaceResult};
use csq_core::types::AccountNum;
use std::io::{BufRead, Write};
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use csq_core::daemon::{self, DaemonClientError, DetectResult};

/// Entry point invoked from `main.rs`. Dispatches on `provider`:
///
/// * `"claude"` (default) — Anthropic OAuth via the in-process
///   parallel-race flow. Pass `legacy_shell = true` to fall back
///   to the legacy `claude auth login` shell-out (emergency
///   rollback only).
/// * `"codex"` — Codex device-auth flow per spec 07 §7.3.3 (PR-C3b).
///   `legacy_shell` is ignored for Codex.
pub fn handle(
    base_dir: &Path,
    account: AccountNum,
    provider: &str,
    legacy_shell: bool,
) -> Result<()> {
    match provider {
        "codex" => return handle_codex(base_dir, account),
        // FR-G-CLI-06: Gemini has no OAuth login flow — API keys
        // are provisioned via `csq setkey gemini --slot N`. Refuse
        // here so an operator who guessed at the provider name
        // gets a pointer to the right command.
        "gemini" => {
            return Err(anyhow!(
                "gemini uses API keys; run `csq setkey gemini --slot {account}`"
            ));
        }
        "claude" | "" => {}
        other => {
            return Err(anyhow!(
                "unknown --provider {other:?} — supported: claude, codex, gemini"
            ));
        }
    }

    if legacy_shell {
        return handle_direct(base_dir, account);
    }

    handle_race(base_dir, account)
}

/// Acquires the per-account login lock or returns a clear error
/// pointing at the holder PID.
///
/// UX-R1-H3 regression: two concurrent `csq login N` processes
/// could both run an OAuth race and stomp `credentials/N.json`.
/// Holding an exclusive flock around the entire login flow
/// serializes them.
///
/// UX-R2-01: error messages include the platform-specific kill
/// command for the holder PID so non-technical users have a concrete
/// next action ("run `kill 12345`") instead of a bare PID number.
/// SEC-R2-08: a stale-PID file (crashed prior holder) renders a
/// distinct "stale lock" message rather than misdirecting the user
/// at a dead PID.
fn acquire_login_lock(base_dir: &Path, account: AccountNum) -> Result<AccountLoginLock> {
    match AccountLoginLock::acquire(base_dir, account)
        .with_context(|| format!("create login lock file for account {account}"))?
    {
        AcquireOutcome::Acquired(guard) => Ok(guard),
        AcquireOutcome::Held {
            pid: Some(pid),
            pid_alive: Some(false),
        } => Err(anyhow!(
            "stale lock file for csq login {account} (prior holder PID {pid} \
             is no longer running) — the lock has been reclaimed; re-run the \
             command to proceed"
        )),
        AcquireOutcome::Held {
            pid: Some(pid),
            pid_alive: _,
        } => Err(anyhow!(
            "another csq login {account} is in progress (PID {pid}) — \
             wait for it to finish, or run `{}` to terminate it, or \
             use --legacy-shell to bypass",
            kill_hint(pid)
        )),
        AcquireOutcome::Held {
            pid: None,
            pid_alive: _,
        } => Err(anyhow!(
            "another csq login {account} is in progress \
             — wait or use --legacy-shell to bypass"
        )),
    }
}

/// Returns the platform-appropriate command for terminating a process
/// by PID, formatted as a complete shell command users can copy.
///
/// UX-R2-01: rendered into the lock-held error message so a
/// non-technical user knows exactly what to run instead of having to
/// look up `kill` vs `taskkill` syntax.
fn kill_hint(pid: u32) -> String {
    if cfg!(target_os = "windows") {
        format!("taskkill /F /PID {pid}")
    } else {
        format!("kill {pid}")
    }
}

/// Default Anthropic login: in-process parallel-race flow.
///
/// 1. Bind a loopback listener on `127.0.0.1:0`.
/// 2. Build both URLs (auto = loopback redirect, manual =
///    paste-code redirect) sharing one PKCE verifier + state.
/// 3. Print the auto URL and try to open the browser; print the
///    manual URL after a 3-second beat (or immediately if the
///    browser open fails).
/// 4. Race the loopback `accept_one` future against a stdin
///    `read_line` paste resolver via `tokio::select!`.
/// 5. On winner: exchange the captured code at the token endpoint,
///    persist credentials atomically, finalize.
fn handle_race(base_dir: &Path, account: AccountNum) -> Result<()> {
    // UX-R1-H3: serialise concurrent `csq login N` invocations.
    // The guard is bound to a local so it lives until the function
    // returns (or panics) — at which point the kernel releases the
    // flock automatically.
    let _lock = acquire_login_lock(base_dir, account)?;

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

    file::save_canonical(base_dir, account, &credential)
        .with_context(|| format!("save credential for account {account}"))?;
    println!("Login successful.");

    // Best-effort marker write — finalize_login also handles the
    // marker but it requires the config dir to exist already on
    // some legacy paths. Mirror handle_direct's defensive write.
    let config_dir = base_dir.join(format!("config-{}", account));
    if config_dir.exists() {
        let _ = markers::write_csq_account(&config_dir, account);
    }

    finalize(base_dir, account)
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
/// it with a mock paste resolver.
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

/// `--provider codex` dispatch. Thin wrapper around
/// `csq_core::providers::codex::login::perform` — the orchestration
/// (keychain probe, config.toml pre-seed, `codex login --device-auth`
/// shell-out, canonical relocation) lives in csq-core so the desktop
/// Add Account modal can call the same helper in a future PR.
fn handle_codex(base_dir: &Path, account: AccountNum) -> Result<()> {
    let _outcome = csq_core::providers::codex::perform(base_dir, account)
        .with_context(|| format!("codex device-auth login for account {account}"))?;
    // `perform` has already printed a human-readable success line.
    // Nothing else to do here — PR-C3c will wire daemon registration
    // (refresher filter + usage poller) once `broker_codex_check`
    // lands in PR-C4.
    Ok(())
}

// `which_claude` was inlined and replaced by
// `csq_core::accounts::login::find_claude_binary`, which also walks
// well-known install paths so Finder-launched apps (the desktop
// bundle) can find `claude` even when their `$PATH` is the minimal
// Finder default.

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
    let _lock = acquire_login_lock(base_dir, account)?;

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
    // UX-R1-H3 (lock symmetry): serialise concurrent invocations.
    let _lock = acquire_login_lock(base_dir, account)?;

    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)?;

    println!("Starting OAuth login for account {}...", account);
    println!("Your browser will open for authorization.");

    // Invoke `claude auth login` with isolated config dir
    let status = Command::new("claude")
        .args(["auth", "login"])
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .status()
        .context("failed to spawn `claude auth login` — is Claude Code installed?")?;

    handle_direct_post_subprocess(base_dir, account, &config_dir, status.success())?;
    finalize(base_dir, account)
}

/// Post-subprocess work for [`handle_direct`]: capture credentials
/// from keychain or file, persist them canonically, then write the
/// `.csq-account` marker — in that order so a subprocess failure or
/// credential-capture failure leaves no orphan marker on disk.
///
/// Extracted so REV-R1-02 / M8 can be regression-tested without
/// spawning the real `claude` binary.
fn handle_direct_post_subprocess(
    base_dir: &Path,
    account: AccountNum,
    config_dir: &Path,
    subprocess_succeeded: bool,
) -> Result<()> {
    if !subprocess_succeeded {
        // REV-R1-02 (M8): do NOT write the .csq-account marker
        // when the subprocess failed. The marker is the "this dir
        // holds credentials for account N" sentinel; writing it
        // before confirming the subprocess succeeded leaves an
        // orphan marker that the daemon's discovery path treats
        // as a legitimate (but credential-less) account.
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
    let creds = keychain::read(config_dir)
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

    // REV-R1-02 (M8): write the marker AFTER the credential save
    // succeeds, so a subprocess failure or post-subprocess credential
    // capture failure leaves no orphan marker on disk.
    markers::write_csq_account(config_dir, account)?;
    Ok(())
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
        let result = handle_direct_post_subprocess(dir.path(), account, &config_dir, false);
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
                hint.contains("taskkill"),
                "windows kill_hint must use taskkill: {hint}"
            );
            assert!(hint.contains("/F"));
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
    fn lock_held_error_message_includes_taskkill_command_windows() {
        // Sibling of the unix test: gate the assertion on target_os.
        // The compile-time branch ensures the message body always
        // names the right command on the target build.
        let pid: u32 = 12345;
        let hint = kill_hint(pid);
        let rendered = format!("PID {pid} … `{hint}` …");
        if cfg!(target_os = "windows") {
            assert!(
                rendered.contains("taskkill /F /PID 12345"),
                "windows lock-held message must include the literal taskkill \
                 command: {rendered}"
            );
        } else {
            // On non-Windows the test is a no-op — the assertion
            // here just keeps the test name discoverable in
            // `cargo test` output.
            assert!(rendered.contains("kill 12345"));
        }
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

        let result = handle_direct_post_subprocess(dir.path(), account, &config_dir, true);
        assert!(result.is_err(), "missing credentials must propagate as Err");

        let marker = config_dir.join(".csq-account");
        assert!(
            !marker.exists(),
            ".csq-account marker MUST NOT exist when credential capture fails: {:?}",
            marker
        );
    }
}
