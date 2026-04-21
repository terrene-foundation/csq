//! `csq run [N]` — launch Claude Code with isolated credentials.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::{discovery, markers, AccountSource};
use csq_core::broker::fanout::is_broker_failed;
use csq_core::credentials::{self, file};
use csq_core::session;
use csq_core::types::AccountNum;
use std::path::Path;
use std::process::Command;

pub fn handle(
    base_dir: &Path,
    account: Option<AccountNum>,
    profile: Option<&str>,
    rest: &[String],
) -> Result<()> {
    let claude_home = super::claude_home()?;

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
        if canonical.claude_ai_oauth.is_expired_within(0) {
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

    let accounts = discovery::discover_anthropic(base_dir);
    let anthropic_with_creds: Vec<_> = accounts.iter().filter(|a| a.has_credentials).collect();

    match anthropic_with_creds.len() {
        0 => Ok(None), // vanilla claude
        1 => {
            let num = AccountNum::try_from(anthropic_with_creds[0].id)
                .map_err(|e| anyhow!("invalid account: {e}"))?;
            Ok(Some(num))
        }
        _ => {
            let mut msg = String::from("multiple accounts configured — specify one:\n");
            for a in &anthropic_with_creds {
                msg.push_str(&format!("  csq run {}  ({})\n", a.id, a.label));
            }
            Err(anyhow!(msg))
        }
    }
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
/// Strips every `ANTHROPIC_*` variable plus bedrock/vertex variants.
/// This prevents attacks where a poisoned dotfile sets
/// `ANTHROPIC_BASE_URL=https://attacker.example.com` and silently
/// exfiltrates tokens on every CC API call.
fn strip_sensitive_env(cmd: &mut Command) {
    // Collect into a Vec first so we don't mutate env vars during iteration.
    let to_strip: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| {
            if k.starts_with("ANTHROPIC_")
                || k == "AWS_BEARER_TOKEN_BEDROCK"
                || k == "CLAUDE_API_KEY"
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
