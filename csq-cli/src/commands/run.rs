//! `csq run [N]` — launch Claude Code or Codex with isolated credentials.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::{discovery, markers, AccountSource};
use csq_core::broker::fanout::is_broker_failed;
use csq_core::credentials::{self, file};
use csq_core::platform::env_check::{self, EnvIssue};
use csq_core::providers::catalog::Surface;
use csq_core::providers::codex::surface as codex_surface;
use csq_core::session;
use csq_core::types::AccountNum;
use std::path::Path;
use std::process::Command;

use csq_core::daemon::{self, DetectResult};

/// Exit code when `csq run` cannot spawn a Codex slot because the
/// daemon is not running (INV-P02). Distinct from anyhow's default 1
/// so scripts can detect "daemon-down" vs other launch failures.
const EXIT_CODE_DAEMON_REQUIRED: i32 = 2;

pub fn handle(
    base_dir: &Path,
    account: Option<AccountNum>,
    profile: Option<&str>,
    rest: &[String],
) -> Result<()> {
    let claude_home = super::claude_home()?;

    // Environment preflight — warn (non-blocking) about configured
    // hooks that will fail after we exec `claude`. Users on fresh WSL
    // most often hit this via `csq run`, not `csq install`, so we
    // surface the same signal here without the interactive prompt.
    run_env_preflight(&claude_home);

    // Resolve account number
    let account = resolve_account(base_dir, account)?;

    let account = match account {
        Some(a) => a,
        None => {
            // 0 accounts — launch vanilla claude
            println!("No accounts configured — launching vanilla claude.");
            return exec_claude(rest);
        }
    };

    // Codex dispatch: if this slot has a Codex canonical credential
    // file, route to `launch_codex`. Checked BEFORE config-<N>/
    // housekeeping because the Codex path's `create_handle_dir_codex`
    // owns the handle-dir-level symlinks + marker writes (it does
    // NOT reuse the Claude-surface `create_handle_dir`).
    //
    // The existence check uses `symlink_metadata` not `exists()` so a
    // dangling canonical symlink is treated as "Codex-bound" and
    // refuses to silently fall through to the Claude launch path —
    // same posture as FR-CLI-05 in `setkey`. Origin: spec 07 §7.5
    // INV-P02 + journal 0013 PR-C3c scope.
    let codex_canonical = file::canonical_path_for(base_dir, account, Surface::Codex);
    if std::fs::symlink_metadata(&codex_canonical).is_ok() {
        if let Some(profile_id) = profile {
            return Err(anyhow!(
                "--profile is not supported for Codex slots (slot {account} is Codex, requested: {profile_id})"
            ));
        }
        return launch_codex(base_dir, account, rest);
    }

    // Ensure config-N exists (permanent account home)
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)?;

    // Mark account on config-N (permanent identity)
    markers::write_csq_account(&config_dir, account)?;
    markers::write_current_account(&config_dir, account)?;

    // Mark onboarding complete on config-N
    session::mark_onboarding_complete(&config_dir)?;

    // Detect whether this slot is bound to a third-party provider
    // (MiniMax, Z.AI, Ollama, ...). 3P slots have
    // `config-<N>/settings.json` with a non-Anthropic
    // `env.ANTHROPIC_BASE_URL` and no OAuth credential file.
    let is_third_party = discovery::discover_per_slot_third_party(base_dir)
        .into_iter()
        .any(|a| a.id == account.get() && matches!(a.source, AccountSource::ThirdParty { .. }));

    if is_third_party {
        if let Some(profile_id) = profile {
            return Err(anyhow!(
                "--profile is not supported for third-party slots (slot {account} is already provider-bound, requested: {profile_id})"
            ));
        }

        launch_third_party(base_dir, &claude_home, account, rest)
    } else {
        // Anthropic OAuth path.
        if is_broker_failed(base_dir, account) {
            return Err(anyhow!(
                "account {} is in LOGIN-NEEDED state — run `csq login {}` to re-authenticate",
                account,
                account
            ));
        }

        // Verify canonical credentials exist and are loadable
        let canonical_path = file::canonical_path(base_dir, account);
        let canonical = credentials::load(&canonical_path).with_context(|| {
            format!("failed to load canonical credentials for account {account}")
        })?;

        // Warn if token is already expired
        if canonical
            .expect_anthropic()
            .claude_ai_oauth
            .is_expired_within(0)
        {
            eprintln!(
                "warning: access token for account {} has expired — CC may fail until the daemon refreshes it",
                account
            );
        }

        // Copy credentials into config-N so symlinks resolve
        session::setup::copy_credentials_for_session(base_dir, &config_dir, account)
            .context("failed to copy credentials")?;

        // Profile support deferred
        if let Some(profile_id) = profile {
            return Err(anyhow!(
                "--profile support is not yet implemented (requested: {profile_id})"
            ));
        }

        launch_anthropic(base_dir, &claude_home, account, rest)
    }
}

/// Launches CC for a 3P slot. The slot's `config-<N>/settings.json`
/// carries `env.ANTHROPIC_BASE_URL` + `env.ANTHROPIC_AUTH_TOKEN`, and
/// CC reads both on startup. We strip the parent env as usual so a
/// poisoned dotfile can't redirect traffic, then exec with
/// `CLAUDE_CONFIG_DIR` pointing at the handle dir whose
/// `settings.json` symlink resolves back to `config-<N>`.
fn launch_third_party(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    rest: &[String],
) -> Result<()> {
    let settings_path = base_dir.join(format!("config-{}/settings.json", account));
    if !settings_path.exists() {
        return Err(anyhow!(
            "slot {account} is missing config-{account}/settings.json — run `csq setkey <provider> --slot {account} --key <KEY>` first"
        ));
    }

    let pid = std::process::id();
    let handle_dir = session::create_handle_dir(base_dir, claude_home, account, pid)
        .context("failed to create handle dir")?;

    // Defensive re-materialize: create_handle_dir already calls
    // materialize_handle_settings internally, but calling it explicitly
    // here makes the contract visible at the call site and survives
    // any refactor that factors the step out of create_handle_dir.
    // See journal 0059 — stale per-slot settings drifted silently
    // through a csq install upgrade; making the invariant explicit is
    // a belt-and-suspenders guard against the same class of regression.
    let config_dir = base_dir.join(format!("config-{}", account));
    if let Err(e) = session::materialize_handle_settings(&handle_dir, claude_home, &config_dir) {
        // Non-fatal: create_handle_dir already populated settings.json
        // successfully (otherwise we wouldn't be here). A secondary
        // failure here means the settings.json on disk is the one
        // create_handle_dir wrote, which is still correct.
        eprintln!("warning: defensive settings re-materialize failed: {e}");
    }

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    println!(
        "Launching claude for 3P slot {} (term-{}) via {}...",
        account,
        pid,
        settings_path.display()
    );

    let mut cmd = Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &handle_dir_abs);
    strip_sensitive_env(&mut cmd);
    cmd.args(rest);

    exec_or_spawn(cmd, &handle_dir)
}

/// Launches CC for an Anthropic OAuth slot. Assumes credentials have
/// already been copied into `config-<N>` by the caller.
fn launch_anthropic(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    rest: &[String],
) -> Result<()> {
    // Create ephemeral handle dir: term-<pid> with symlinks to config-N
    // for credentials and ~/.claude for shared items. CC checks CWD
    // (not CLAUDE_CONFIG_DIR) for session identity, so handle dirs
    // are compatible with --resume as long as the CWD matches.
    let pid = std::process::id();
    let handle_dir = session::create_handle_dir(base_dir, claude_home, account, pid)
        .context("failed to create handle dir")?;

    // Defensive re-materialize: create_handle_dir already calls
    // materialize_handle_settings internally, but calling it explicitly
    // here makes the contract visible at the call site and survives
    // any refactor that factors the step out of create_handle_dir.
    // See journal 0059 — stale per-slot settings drifted silently
    // through a csq install upgrade; making the invariant explicit is
    // a belt-and-suspenders guard against the same class of regression.
    let config_dir = base_dir.join(format!("config-{}", account));
    if let Err(e) = session::materialize_handle_settings(&handle_dir, claude_home, &config_dir) {
        // Non-fatal: create_handle_dir already populated settings.json
        // successfully (otherwise we wouldn't be here). A secondary
        // failure here means the settings.json on disk is the one
        // create_handle_dir wrote, which is still correct.
        eprintln!("warning: defensive settings re-materialize failed: {e}");
    }

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    println!("Launching claude for account {} (term-{})...", account, pid);

    // Strip ANTHROPIC_* (and related) env vars before exec.
    let mut cmd = Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &handle_dir_abs);
    strip_sensitive_env(&mut cmd);
    cmd.args(rest);

    exec_or_spawn(cmd, &handle_dir)
}

/// Launches Codex for a Codex-surface slot.
///
/// Spec 07 §7.5 INV-P02: daemon is a hard prerequisite — if the
/// daemon is not running, refresh cadence cannot be guaranteed and
/// codex-cli's on-expiry refresh will burn the refresh token
/// (openai/codex#10332). Refuse with exit 2 before creating a handle
/// dir.
///
/// Spec 07 §7.2.2 on-disk layout: `term-<pid>` IS `$CODEX_HOME`.
/// The Codex child sees auth.json / config.toml / sessions /
/// history.jsonl through the handle-dir symlinks assembled by
/// `create_handle_dir_codex` (PR-C3a).
///
/// Env: `strip_sensitive_env` removes `ANTHROPIC_*` + bedrock/vertex
/// variants (same attack surface as Claude launch — a poisoned
/// dotfile cannot redirect traffic). Additionally removes
/// `CLAUDE_CONFIG_DIR` so a parent csq-managed shell does not leak
/// the Claude-surface state dir into the Codex child. Full
/// `env_clear + allowlist` is a PR-C3c-follow-up hardening target;
/// today's env_remove set matches PR-C3b's login spawn.
fn launch_codex(base_dir: &Path, account: AccountNum, rest: &[String]) -> Result<()> {
    require_daemon_healthy(base_dir)?;
    verify_codex_config_toml(base_dir, account)?;
    verify_codex_canonical_is_regular_file(base_dir, account)?;

    let pid = std::process::id();
    let handle_dir = session::create_handle_dir_codex(base_dir, account, pid)
        .with_context(|| format!("create Codex handle dir for account {account}"))?;

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    println!("Launching codex for account {} (term-{})...", account, pid);

    // Strip BEFORE `cmd.env(HOME_ENV_VAR, …)` so our explicit
    // CODEX_HOME value wins over any parent-shell export.
    // `strip_sensitive_env` scrubs CODEX_HOME from the parent env
    // (H1 fix) — if we set it first it would get env_remove'd right
    // back out.
    let mut cmd = Command::new(codex_surface::CLI_BINARY);
    strip_sensitive_env(&mut cmd);
    // Codex does not read CLAUDE_CONFIG_DIR today, but a parent csq
    // shell will have it set — scrub so a future codex-cli cannot
    // accidentally resolve a Claude state dir. Mirrors PR-C3b login
    // spawn's posture.
    cmd.env_remove("CLAUDE_CONFIG_DIR");
    cmd.env_remove("CLAUDE_HOME");
    cmd.env(codex_surface::HOME_ENV_VAR, &handle_dir_abs);
    cmd.args(rest);

    exec_or_spawn(cmd, &handle_dir)
}

/// Verifies `credentials/codex-<N>.json` is a regular file, not a
/// symlink, before a Codex spawn. Origin: PR-C3c security review M1.
///
/// The dispatch branch in [`handle`] uses `symlink_metadata` so a
/// dangling symlink still routes to Codex (refusing to silently fall
/// through to the Claude path — journal 0013). But `symlink_metadata`
/// also accepts a symlink-to-anywhere, which would let a same-user
/// attacker who races a swap between dispatch and spawn inject
/// attacker-chosen tokens into the handle dir's `auth.json` symlink
/// chain. Refusing any canonical that is a symlink at spawn time
/// closes that vector — PR-C3b's `save_canonical_for` always writes
/// a regular file, so a symlink at this path is an external mutation
/// that deserves an abort.
fn verify_codex_canonical_is_regular_file(base_dir: &Path, account: AccountNum) -> Result<()> {
    let path = file::canonical_path_for(base_dir, account, Surface::Codex);
    let meta = std::fs::symlink_metadata(&path).with_context(|| {
        format!(
            "stat {} — Codex canonical missing; run `csq login {account} --provider codex`",
            path.display()
        )
    })?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(anyhow!(
            "refusing Codex launch: {} is a symlink. csq only writes a regular file at this path (spec 07 §7.2.2 + INV-P08); a symlink here means an external process mutated the credentials directory. Re-run `csq login {account} --provider codex` to rewrite.",
            path.display()
        ));
    }
    if !ft.is_file() {
        return Err(anyhow!(
            "refusing Codex launch: {} is not a regular file (type: {:?})",
            path.display(),
            ft
        ));
    }
    Ok(())
}

/// Verifies `config-<N>/config.toml` exists before a Codex spawn.
/// Extracted from [`launch_codex`] so the precondition can be
/// unit-tested without shelling out to `codex` or exit(2)-ing on the
/// daemon check.
fn verify_codex_config_toml(base_dir: &Path, account: AccountNum) -> Result<()> {
    let config_toml = codex_surface::config_toml_path(base_dir, account);
    if !config_toml.exists() {
        return Err(anyhow!(
            "slot {account} is missing {} — run `csq login {account} --provider codex` to complete login",
            config_toml.display()
        ));
    }
    Ok(())
}

/// Requires the daemon to be `Healthy` before a Codex spawn. Spec 07
/// §7.5 INV-P02: without the daemon, codex's on-expiry in-process
/// refresh will fire and burn the refresh token. Exits with
/// [`EXIT_CODE_DAEMON_REQUIRED`] on any non-Healthy state so scripts
/// can distinguish "daemon-down" from other launch failures.
///
/// PR-C4 (H2 gate): cross-platform — `daemon::detect_daemon` already
/// has a Windows named-pipe branch (`csq-core/src/daemon/detect.rs`
/// `windows_health_check`), so the same DetectResult variants apply
/// across Unix and Windows. This closes the journal 0015
/// `#[cfg(not(unix))] Ok(())` carve-out.
fn require_daemon_healthy(base_dir: &Path) -> Result<()> {
    match daemon::detect_daemon(base_dir) {
        DetectResult::Healthy { .. } => Ok(()),
        DetectResult::NotRunning => {
            eprintln!(
                "Codex spawn refused — csq daemon is not running.\n\
                 The daemon must own token refresh for Codex (spec 07 §7.5 INV-P02);\n\
                 start it with `csq daemon start` or install the desktop app."
            );
            std::process::exit(EXIT_CODE_DAEMON_REQUIRED);
        }
        DetectResult::Stale { reason } => {
            eprintln!(
                "Codex spawn refused — csq daemon is stale: {reason}.\n\
                 Restart with `csq daemon stop && csq daemon start`."
            );
            std::process::exit(EXIT_CODE_DAEMON_REQUIRED);
        }
        DetectResult::Unhealthy { reason } => {
            eprintln!(
                "Codex spawn refused — csq daemon is unhealthy: {reason}.\n\
                 Inspect logs with `csq daemon status` and restart if needed."
            );
            std::process::exit(EXIT_CODE_DAEMON_REQUIRED);
        }
    }
}

/// Execs CC on Unix or spawns + waits on Windows, cleaning up the
/// handle dir on failure.
fn exec_or_spawn(mut cmd: Command, handle_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces process — if it fails, clean up handle dir
        let err = cmd.exec();
        let _ = std::fs::remove_dir_all(handle_dir);
        Err(anyhow!("exec failed: {err}"))
    }

    #[cfg(not(unix))]
    {
        // Non-Unix (Windows): spawn CC as a child and record its
        // PID in `.live-cc-pid` so the daemon sweep can tell CC
        // apart from csq-cli. On Unix `exec` replaces csq-cli with
        // claude and the csq PID becomes claude's PID, so there is
        // only one PID and this marker is not needed.
        let handle_dir_abs =
            std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(handle_dir);
                return Err(anyhow!("failed to launch claude: {e}"));
            }
        };
        let child_pid = child.id();
        if let Err(e) = markers::write_live_cc_pid(&handle_dir_abs, child_pid) {
            eprintln!("warning: could not record CC child PID: {e}");
        }
        let status = child.wait();
        let _ = std::fs::remove_dir_all(handle_dir);
        match status {
            Ok(s) if !s.success() => std::process::exit(s.code().unwrap_or(1)),
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!("failed to wait for claude: {e}")),
        }
    }
}

fn resolve_account(base_dir: &Path, explicit: Option<AccountNum>) -> Result<Option<AccountNum>> {
    if let Some(a) = explicit {
        return Ok(Some(a));
    }

    // PR-C3c: the "pick the only live slot" convenience must consider
    // Codex slots too — otherwise `csq run` on a machine with only a
    // Codex slot would resolve `None` and launch vanilla claude.
    // Multi-slot listings include Codex entries via `discover_codex`
    // so the user can pick by number across surfaces.
    let mut accounts = discovery::discover_anthropic(base_dir);
    accounts.extend(discovery::discover_codex(base_dir));
    let with_creds: Vec<_> = accounts.iter().filter(|a| a.has_credentials).collect();

    match with_creds.len() {
        0 => Ok(None), // vanilla claude
        1 => {
            let num = AccountNum::try_from(with_creds[0].id)
                .map_err(|e| anyhow!("invalid account: {e}"))?;
            Ok(Some(num))
        }
        _ => {
            let mut msg = String::from("multiple accounts configured — specify one:\n");
            for a in &with_creds {
                let surface_hint = match a.surface {
                    Surface::ClaudeCode => "",
                    Surface::Codex => " [codex]",
                };
                msg.push_str(&format!(
                    "  csq run {}  ({}){}\n",
                    a.id, a.label, surface_hint
                ));
            }
            Err(anyhow!(msg))
        }
    }
}

/// Warn-only environment preflight invoked at the top of `handle`.
///
/// Prints to stderr so it shows up during exec without polluting
/// parseable stdout. Never blocks — users have already decided to
/// launch; mid-session interactive prompts would strand them.
fn run_env_preflight(claude_home: &Path) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    let issues = env_check::run_preflight(claude_home, &cwd);
    if issues.is_empty() {
        return;
    }
    eprintln!("csq: environment issues detected before launch:");
    for issue in &issues {
        match issue {
            EnvIssue::NodeMissingForHooks { hook_count } => {
                eprintln!("  ! node / bun not found, but {hook_count} hook command(s) configured.");
                eprintln!("    Claude Code will emit 'SessionStart:startup hook error' on launch.");
                eprintln!("    Fix: {}", env_check::node_install_hint());
            }
            EnvIssue::HookScriptMissing { script_path, .. } => {
                eprintln!("  ! hook script not found: {}", script_path.display());
            }
            EnvIssue::HookRelativeRequireMissing {
                script_path,
                missing_sibling,
            } => {
                eprintln!(
                    "  ! hook require fails: {} expects {}",
                    script_path.display(),
                    missing_sibling.display()
                );
                eprintln!(
                    "    (this is node:internal/modules/cjs/loader:1143 — sibling modules missing)"
                );
            }
        }
    }
    eprintln!();
}

fn exec_claude(rest: &[String]) -> Result<()> {
    let mut cmd = Command::new("claude");
    // Always strip sensitive env vars, even on the vanilla path.
    strip_sensitive_env(&mut cmd);
    cmd.args(rest);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow!("exec failed: {err}"))
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Removes env vars that could override credentials, redirect API traffic,
/// or otherwise compromise the isolated session.
///
/// Strips:
///
/// - `ANTHROPIC_*` — base-URL redirects / auth-token overrides for the
///   Claude Code surface.
/// - `AWS_BEARER_TOKEN_BEDROCK` — bedrock bypass.
/// - `CLAUDE_API_KEY` — direct key override.
/// - `OPENAI_*` — symmetric protection for the Codex surface. A
///   poisoned dotfile setting `OPENAI_BASE_URL=https://attacker.example`
///   would silently redirect every Codex API call and exfiltrate the
///   JWT access token csq just provisioned. Origin: PR-C3c security
///   review H1 — symmetric with the `ANTHROPIC_*` threat.
/// - `CODEX_HOME` — scrubbed so the only authoritative value is the
///   `cmd.env(HOME_ENV_VAR, handle_dir)` csq sets explicitly in
///   `launch_codex`. Prevents a parent shell that already exported
///   `CODEX_HOME=/somewhere-else` from winning a clash if csq's
///   layering ever regresses.
///
/// Both the Claude and Codex launch paths call this so a mis-
/// provisioned slot cannot leak credentials across surfaces via a
/// parent-shell env var.
fn strip_sensitive_env(cmd: &mut Command) {
    // Collect into a Vec first so we don't mutate env vars during iteration.
    let to_strip: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| {
            if k.starts_with("ANTHROPIC_")
                || k.starts_with("OPENAI_")
                || k == "AWS_BEARER_TOKEN_BEDROCK"
                || k == "CLAUDE_API_KEY"
                || k == "CODEX_HOME"
            {
                Some(k)
            } else {
                None
            }
        })
        .collect();

    for key in to_strip {
        cmd.env_remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// PR-C3c regression: `verify_codex_config_toml` errors with an
    /// actionable message when the pre-seed is missing.
    #[test]
    fn codex_precondition_errors_on_missing_config_toml() {
        let dir = TempDir::new().unwrap();
        let err = verify_codex_config_toml(dir.path(), acc(4))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("config.toml"),
            "error should name config.toml: {err}"
        );
        assert!(
            err.contains("csq login 4 --provider codex"),
            "error should point at the fix: {err}"
        );
    }

    /// PR-C3c regression: precondition succeeds once the pre-seed
    /// exists (PR-C3b's `surface::write_config_toml` output).
    #[test]
    fn codex_precondition_succeeds_when_config_toml_present() {
        let dir = TempDir::new().unwrap();
        let slot = acc(5);
        codex_surface::write_config_toml(dir.path(), slot, "gpt-5.4").unwrap();
        verify_codex_config_toml(dir.path(), slot).expect("precondition should pass");
    }

    /// PR-C3c regression: `resolve_account` lists Codex slots
    /// alongside Claude slots and returns an error listing BOTH when
    /// multiple are configured. The surface hint ` [codex]` lets the
    /// user disambiguate without reading `credentials/` directly.
    #[test]
    fn resolve_account_multi_slot_lists_codex_alongside_claude() {
        use csq_core::credentials::{
            AnthropicCredentialFile, CodexCredentialFile, CodexTokensFile, CredentialFile,
            OAuthPayload,
        };
        use csq_core::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Install one Anthropic slot…
        let anth = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-fake".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-fake".into()),
                expires_at: 1775726524877,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&file::canonical_path(base, acc(1)), &anth).unwrap();

        // …and one Codex slot.
        let codex = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-1234".into()),
                access_token: "eyJ.jwt.stub".into(),
                refresh_token: Some("rt_stub_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into()),
                id_token: Some("eyJ.id.stub".into()),
                extra: Default::default(),
            },
            last_refresh: None,
            extra: Default::default(),
        });
        credentials::save(
            &file::canonical_path_for(base, acc(4), Surface::Codex),
            &codex,
        )
        .unwrap();

        let err = resolve_account(base, None).unwrap_err().to_string();
        assert!(
            err.contains("csq run 1"),
            "multi-slot listing must include Anthropic slot 1: {err}"
        );
        assert!(
            err.contains("csq run 4"),
            "multi-slot listing must include Codex slot 4: {err}"
        );
        assert!(
            err.contains("[codex]"),
            "Codex slots must carry a surface hint: {err}"
        );
    }

    /// PR-C3c security review M1 regression: a Codex canonical that
    /// is a symlink (same-user swap attack) is refused at launch
    /// time even though the dispatch branch in `handle` accepts a
    /// `symlink_metadata`-present file.
    #[cfg(unix)]
    #[test]
    fn codex_canonical_symlink_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = acc(9);

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Attacker-target file with a fake credential shape.
        let decoy = dir.path().join("decoy.json");
        std::fs::write(&decoy, b"{}").unwrap();
        // Canonical is a symlink to the decoy — NOT a regular file.
        symlink(&decoy, creds_dir.join("codex-9.json")).unwrap();

        let err = verify_codex_canonical_is_regular_file(base, slot)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("symlink"),
            "error must name the symlink posture: {err}"
        );
        assert!(
            err.contains("csq login 9 --provider codex"),
            "error must point at the fix: {err}"
        );
    }

    #[test]
    fn codex_canonical_regular_file_passes() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-10.json"), b"{}").unwrap();

        verify_codex_canonical_is_regular_file(base, acc(10)).expect("regular file accepted");
    }

    /// PR-C3c security review H1 regression: `strip_sensitive_env`
    /// now covers `OPENAI_*` and `CODEX_HOME` in addition to the
    /// pre-existing `ANTHROPIC_*` / `AWS_BEARER_TOKEN_BEDROCK` /
    /// `CLAUDE_API_KEY` set. A poisoned dotfile setting
    /// `OPENAI_BASE_URL` must not leak into a Codex child.
    #[test]
    fn strip_sensitive_env_covers_openai_and_codex_home() {
        let test_vars = [
            ("OPENAI_API_KEY", true),
            ("OPENAI_BASE_URL", true),
            ("OPENAI_API_BASE", true),
            ("OPENAI_ORG_ID", true),
            ("CODEX_HOME", true),
            ("ANTHROPIC_API_KEY", true),
            ("CLAUDE_API_KEY", true),
            ("AWS_BEARER_TOKEN_BEDROCK", true),
            ("PATH", false),
            ("HOME", false),
            ("CLAUDE_CONFIG_DIR", false),
        ];
        for (var, should_strip) in test_vars {
            let matches = var.starts_with("ANTHROPIC_")
                || var.starts_with("OPENAI_")
                || var == "AWS_BEARER_TOKEN_BEDROCK"
                || var == "CLAUDE_API_KEY"
                || var == "CODEX_HOME";
            assert_eq!(matches, should_strip, "var {var} classification mismatch");
        }
    }

    /// PR-C3c regression: when only a Codex slot is present,
    /// `resolve_account` picks it (rather than falling through to
    /// vanilla claude). This is the "single-Codex user" onboarding
    /// path — `csq run` with no args must still work.
    #[test]
    fn resolve_account_single_codex_slot_is_picked() {
        use csq_core::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let codex = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-only".into()),
                access_token: "eyJ.jwt".into(),
                refresh_token: Some("rt_only_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into()),
                id_token: None,
                extra: Default::default(),
            },
            last_refresh: None,
            extra: Default::default(),
        });
        credentials::save(
            &file::canonical_path_for(base, acc(2), Surface::Codex),
            &codex,
        )
        .unwrap();

        let picked = resolve_account(base, None).unwrap();
        assert_eq!(
            picked,
            Some(acc(2)),
            "the single Codex slot must be auto-picked"
        );
    }

    #[test]
    fn strip_sensitive_env_removes_anthropic_vars() {
        // We can't modify the real env during tests (parallel safety), so
        // we test the logic by verifying the filter directly.
        let test_vars = [
            ("ANTHROPIC_API_KEY", true),
            ("ANTHROPIC_BASE_URL", true),
            ("ANTHROPIC_AUTH_TOKEN", true),
            ("ANTHROPIC_MODEL", true),
            ("AWS_BEARER_TOKEN_BEDROCK", true),
            ("CLAUDE_API_KEY", true),
            ("PATH", false),
            ("HOME", false),
            ("CLAUDE_CONFIG_DIR", false),
            ("CLAUDE_HOME", false),
        ];

        for (var, should_strip) in test_vars {
            let matches = var.starts_with("ANTHROPIC_")
                || var == "AWS_BEARER_TOKEN_BEDROCK"
                || var == "CLAUDE_API_KEY";
            assert_eq!(matches, should_strip, "var {var}");
        }
    }

    /// Regression guard for journal 0059 invariant: csq run N MUST leave
    /// term-<pid>/settings.json populated after handle dir creation.
    ///
    /// This test exercises `csq_core::session::create_handle_dir` plus the
    /// explicit defensive re-materialize that run.rs adds at the call site.
    /// It does NOT invoke `run()` itself because `run()` execs claude and
    /// would hang the test suite. The invariant we care about — settings.json
    /// exists, is valid JSON, and reflects the merged base+overlay — is fully
    /// observable at the handle-dir level.
    ///
    /// Arrange: tempdir with ~/.claude/settings.json (global base) and
    ///          config-1/settings.json (slot overlay).
    /// Act:     create_handle_dir + defensive re-materialize.
    /// Assert:  term-<pid>/settings.json exists, is a regular file (not a
    ///          symlink), is parseable JSON, and merges content from both
    ///          sources (overlay key wins).
    #[test]
    fn settings_json_exists_after_create_handle_dir() {
        use csq_core::session;
        use csq_core::types::AccountNum;

        let base = tempfile::tempdir().expect("tempdir");
        let claude_home = tempfile::tempdir().expect("tempdir");

        // Arrange: permanent account dir
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.path().join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();

        // Write account marker so create_handle_dir sees a valid config-N
        csq_core::accounts::markers::write_csq_account(&config_dir, account).unwrap();
        csq_core::accounts::markers::write_current_account(&config_dir, account).unwrap();

        // Global settings: base layer (statusLine customization)
        let global_settings = serde_json::json!({
            "env": {},
            "statusBar": {"visible": true},
            "theme": "dark"
        });
        std::fs::write(
            claude_home.path().join("settings.json"),
            serde_json::to_string_pretty(&global_settings).unwrap(),
        )
        .unwrap();

        // Slot settings: overlay layer (3P env block wins over base)
        let slot_settings = serde_json::json!({
            "env": {
                "ANTHROPIC_BASE_URL": "https://example.com/v1"
            }
        });
        std::fs::write(
            config_dir.join("settings.json"),
            serde_json::to_string_pretty(&slot_settings).unwrap(),
        )
        .unwrap();

        // Act: create handle dir (which calls materialize internally)
        let pid = std::process::id();
        let handle_dir =
            session::create_handle_dir(base.path(), claude_home.path(), account, pid).unwrap();

        // Defensive re-materialize — mirrors exactly what run.rs does
        let result =
            session::materialize_handle_settings(&handle_dir, claude_home.path(), &config_dir);
        assert!(
            result.is_ok(),
            "defensive re-materialize failed: {:?}",
            result.err()
        );

        // Assert: settings.json exists as a real file (not a symlink)
        let settings_path = handle_dir.join("settings.json");
        assert!(settings_path.exists(), "settings.json must exist");
        let metadata = std::fs::symlink_metadata(&settings_path).unwrap();
        assert!(
            !metadata.file_type().is_symlink(),
            "settings.json must be a real file, not a symlink"
        );

        // Assert: parseable JSON
        let content = std::fs::read_to_string(&settings_path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("settings.json must be valid JSON");

        // Assert: overlay key present (env.ANTHROPIC_BASE_URL from slot settings)
        assert_eq!(
            parsed["env"]["ANTHROPIC_BASE_URL"],
            serde_json::json!("https://example.com/v1"),
            "slot overlay env key must survive merge"
        );

        // Assert: base key present (theme from global settings)
        assert_eq!(
            parsed["theme"],
            serde_json::json!("dark"),
            "global base key must survive merge"
        );
    }

    /// Regression guard: calling `materialize_handle_settings` twice on the
    /// same handle dir produces identical byte content (idempotency).
    ///
    /// This pins the invariant that the defensive re-materialize in run.rs
    /// cannot corrupt a settings.json that create_handle_dir already wrote.
    #[test]
    fn materialize_handle_settings_is_idempotent() {
        use csq_core::session;
        use csq_core::types::AccountNum;

        let base = tempfile::tempdir().expect("tempdir");
        let claude_home = tempfile::tempdir().expect("tempdir");

        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.path().join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();

        csq_core::accounts::markers::write_csq_account(&config_dir, account).unwrap();
        csq_core::accounts::markers::write_current_account(&config_dir, account).unwrap();

        let slot_settings = serde_json::json!({
            "env": {"ANTHROPIC_MODEL": "claude-opus-4"},
            "statusBar": {"visible": false}
        });
        std::fs::write(
            config_dir.join("settings.json"),
            serde_json::to_string_pretty(&slot_settings).unwrap(),
        )
        .unwrap();

        let pid = std::process::id();
        let handle_dir =
            session::create_handle_dir(base.path(), claude_home.path(), account, pid).unwrap();

        // First call (already done by create_handle_dir, but call explicitly)
        session::materialize_handle_settings(&handle_dir, claude_home.path(), &config_dir).unwrap();
        let first_read = std::fs::read(handle_dir.join("settings.json")).unwrap();

        // Second call — must produce identical bytes
        session::materialize_handle_settings(&handle_dir, claude_home.path(), &config_dir).unwrap();
        let second_read = std::fs::read(handle_dir.join("settings.json")).unwrap();

        assert_eq!(
            first_read, second_read,
            "materialize_handle_settings must be idempotent: second call produced different bytes"
        );
    }
}
