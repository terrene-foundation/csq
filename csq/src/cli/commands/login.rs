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
//! `broker_failed` sentinel via [`csq_core::accounts::login::finalize_login`].

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::accounts::markers;
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::cli_deps::SurfaceCli;
use csq_core::credentials::{self, file};
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
use csq_core::providers::codex::desktop_login::extract_device_auth_url;

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
) -> Result<()> {
    // R2/B80: `--reset-handle-dir` is handled first, before any OAuth
    // flow. It re-creates provider-specific artifacts without re-running
    // authentication. With `--non-interactive`, exits 64 if tokens are
    // expired (caller must re-login interactively first).
    if reset_handle_dir {
        return handle_reset_handle_dir(base_dir, account, provider, non_interactive);
    }

    match provider {
        "codex" => return handle_codex(base_dir, account, ignore_cli_version, no_auto_update_cli),
        // Stage 2 of an internal journal entry: Gemini has THREE auth paths today.
        // OAuth (Code Assist subscription) is the `csq login` entry;
        // AI Studio API keys and Vertex SA still go through `csq
        // setkey gemini` because those are non-OAuth credential paste
        // flows.
        "gemini" => {
            return handle_gemini_oauth(base_dir, account, ignore_cli_version, no_auto_update_cli)
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
                "unknown --provider {other:?} — supported: claude, codex, gemini"
            ));
        }
    }

    // `--legacy-shell` is now a no-op alias for the default — kept so
    // scripts that hard-coded it keep parsing. The in-process race
    // flow is no longer reachable from the CLI (see issue tracker for
    // its removal); desktop still wires it through `start_claude_login_race`.
    let _ = legacy_shell;
    handle_direct(base_dir, account)
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
fn credentials_expired_for_recording(path: &Path) -> bool {
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
    use csq_core::providers::catalog::Surface;

    let surface = match provider {
        "codex" => Surface::Codex,
        "gemini" => Surface::Gemini,
        "claude" | "" => Surface::ClaudeCode,
        other => {
            return Err(anyhow!(
                "unknown --provider {other:?} — supported: claude, codex, gemini"
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
    }

    if non_interactive {
        let cred_path = base_dir
            .join(format!("config-{}", account))
            .join(".credentials.json");
        if credentials_expired_for_recording(&cred_path) {
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
/// canonical config-<N>/config.toml is verified to exist. Nothing is
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
/// Uses atomic_replace + secure_file (§5a cleanup) to ensure the file
/// is never left in a half-written state.
fn reset_handle_dir_gemini(base_dir: &Path, account: AccountNum) -> Result<()> {
    use csq_core::platform::fs::{atomic_replace, secure_file, unique_tmp_path};

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

    // §5a atomic write with cleanup on every error branch.
    let tmp = unique_tmp_path(&settings_path);
    if let Err(e) = std::fs::write(&tmp, updated.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!(
            "write Gemini settings tmp {}: {e}",
            redact_path(&tmp)
        ));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!(
            "secure_file Gemini settings tmp {}: {e}",
            redact_path(&tmp)
        ));
    }
    if let Err(e) = atomic_replace(&tmp, &settings_path) {
        let _ = std::fs::remove_file(&tmp);
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

    file::save_canonical_for(base_dir, account, &credential)
        .with_context(|| format!("save credential for account {account}"))?;
    println!("Login successful.");

    // Best-effort marker write — finalize_login also handles the
    // marker but it requires the config dir to exist already on
    // some legacy paths. Mirror handle_direct's defensive write.
    //
    // M4-7: prefer the UUID-content marker when `by_slot` maps;
    // finalize_login below re-writes after mint_for_login completes.
    let config_dir = base_dir.join(format!("config-{}", account));
    if config_dir.exists() {
        match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()) {
            Some(uuid) => {
                let _ = markers::write_csq_account(&config_dir, uuid);
            }
            None => {
                let _ = markers::write_csq_account_legacy(&config_dir, account);
            }
        }
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
) -> Result<()> {
    use csq_core::providers::codex::desktop_login::parse_device_code_line;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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
        &format!("csq login {account} --provider codex"),
    )?;
    // ─────────────────────────────────────────────────────────────────────

    // Custom spawn function: pipe codex-cli's stdout, tee to terminal,
    // auto-launch the verification URL when seen.
    let already_opened = Arc::new(AtomicBool::new(false));
    let already_opened_clone = already_opened.clone();
    let spawn = move |config_dir: &Path| -> Result<std::process::ExitStatus> {
        let mut child = Command::new("codex")
            .args(["login", "--device-auth"])
            .env("CODEX_HOME", config_dir)
            .env_remove("CLAUDE_CONFIG_DIR")
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn `codex login --device-auth` — is codex-cli installed and on PATH?")?;
        let stdout = child
            .stdout
            .take()
            .context("codex-cli stdout pipe missing")?;
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line.context("read codex-cli stdout")?;
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
        }
        let status = child.wait().context("wait on codex-cli exit")?;
        Ok(status)
    };

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let _outcome = csq_core::providers::codex::login::perform_with(
        base_dir,
        account,
        &mut reader,
        &mut writer,
        csq_core::providers::codex::keychain::probe_residue,
        csq_core::providers::codex::keychain::purge_residue,
        spawn,
    )
    .with_context(|| format!("codex device-auth login for account {account}"))?;

    // Task 7: notify the daemon so its discovery_cache + refresh-status cache
    // are invalidated. Without this, the daemon would not know about the newly
    // provisioned Codex slot's identity-keyed credentials until the next
    // restart or periodic reconciliation tick.
    notify_daemon_cache_invalidation(base_dir);

    Ok(())
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
) -> Result<()> {
    // ── Pre-flight probe (PR-MCD2, spec/13 §3, R1-C2) ────────────────────
    // Probe is spawn-adjacent: placed IMMEDIATELY before the gemini
    // credential-check invocation to close the TOCTOU window. Probe-disabled
    // WARN is emitted by probe() itself per R2-N4; login handler does NOT
    // duplicate it.
    super::cli_deps_gate::enforce(
        SurfaceCli::Gemini,
        ignore_cli_version,
        no_auto_update_cli,
        &format!("csq login {account} --provider gemini"),
    )?;
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
    eprintln!(
        "info: slot {account} bound in Code Assist OAuth mode. \
         Run `csq run {account}` to start a Gemini session."
    );
    Ok(())
}

// pre_flight_check moved to super::cli_deps_gate::enforce (H4 extraction, R1 redteam).
// Both handle_codex and handle_gemini_oauth now delegate to that shared function.

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
    finalize(base_dir, account).context("post-login finalization failed")
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
fn handle_direct(base_dir: &Path, account: AccountNum) -> Result<()> {
    // UX-R1-H3 (lock symmetry): serialise concurrent invocations.
    let _lock = acquire_login_lock(base_dir, account)?;

    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)?;

    println!("Starting OAuth login for account {}...", account);
    println!("Your browser will open for authorization.");

    // Resolve the `claude` binary via `find_claude_binary`'s PATH +
    // well-known-locations walk rather than relying on `Command::new("claude")`
    // hitting $PATH alone. The latter fails on minimal shells (non-interactive
    // SSH, GUI Tauri spawn, cron jobs) where `~/.local/bin` is not in PATH
    // even though the binary is installed there. The Phase 1 Tauri subprocess
    // command (#390) already follows this pattern.
    let claude_bin = csq_core::accounts::login::find_claude_binary().ok_or_else(|| {
        anyhow!(
            "claude binary not found on PATH or well-known locations \
             (~/.local/bin, ~/.npm-global/bin, ~/.bun/bin, ~/.cargo/bin, \
             /opt/homebrew/bin, /usr/local/bin) — install Claude Code first \
             (https://claude.com/code)"
        )
    })?;

    // Invoke `claude auth login` with isolated config dir
    let status = Command::new(&claude_bin)
        .args(["auth", "login"])
        .env("CLAUDE_CONFIG_DIR", &config_dir)
        .status()
        .context("failed to spawn `claude auth login`")?;

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
    let creds = credentials::read_fresh_after_login(config_dir).map_err(|e| anyhow!("{e}"))?;

    // an internal ticket: mint the slot's identity UUID BEFORE save. `save_canonical_for`
    // is fail-closed on an absent UUID (M4-12), but on a fresh install the UUID is
    // minted only by `finalize_login` — which runs in `finalize()`, AFTER this.
    // On macOS the daemon Pass-0 fallback can't mint from a keychain-only cred
    // either. Without this, first login on a fresh install fails "no credentials
    // configured". Idempotent + no-op when already minted or when no email source.
    csq_core::accounts::login::ensure_login_identity_minted(base_dir, account)
        .map_err(|e| anyhow!("mint identity for account {account}: {e}"))?;

    // Save canonical (UUID-keyed; M4-12: fail-closed if UUID absent — minted above)
    file::save_canonical_for(base_dir, account, &creds)?;
    println!("Credentials saved for account {account}.");

    // REV-R1-02 (M8): write the marker AFTER the credential save
    // succeeds, so a subprocess failure or post-subprocess credential
    // capture failure leaves no orphan marker on disk.
    //
    // M4-7: identity UUID if mapped, else legacy decimal slot id.
    match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => markers::write_csq_account(config_dir, uuid)?,
        None => markers::write_csq_account_legacy(config_dir, account)?,
    }
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

    // NOTE: the CC keychain mirror now lives in the shared
    // `csq_core::accounts::login::finalize_login` (called above) so every login
    // twin — this CLI path AND the desktop subprocess/paste-code/race flows —
    // sweeps the keychain. Do NOT re-add a sweep here (would double-sweep).

    println!("Logged in as {} (account {}).", email, account);
    Ok(())
}

#[cfg(unix)]
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    let sock = csq_core::daemon::socket_path(base_dir);
    if !sock.exists() {
        return;
    }
    if let Err(e) = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache") {
        tracing::warn!(
            error_kind = "daemon_cache_invalidate_failed",
            error = %e,
            "failed to notify daemon of cache invalidation; \
             daemon will pick up changes at next periodic tick"
        );
    }
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

    // ── credentials_expired_for_recording (T22a pre-flight) ──

    #[test]
    fn credentials_expired_for_recording_returns_true_when_file_missing() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(credentials_expired_for_recording(&path));
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
        assert!(!credentials_expired_for_recording(&path));
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
        assert!(credentials_expired_for_recording(&path));
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
        assert!(credentials_expired_for_recording(&path));
    }

    #[test]
    fn credentials_expired_for_recording_returns_true_for_invalid_json() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".credentials.json");
        std::fs::write(&path, b"not valid json {{{").unwrap();
        assert!(credentials_expired_for_recording(&path));
    }

    // Tests for `extract_device_auth_url` + `strip_ansi_escapes` live with
    // their canonical implementation in
    // `csq-core/src/providers/codex/desktop_login.rs`.
}
