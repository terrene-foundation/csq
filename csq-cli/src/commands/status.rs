//! `csq status` — display all accounts with quota usage.
//!
//! # Execution paths
//!
//! 1. **Daemon-delegated (preferred on Unix)** — when a healthy
//!    daemon is running, the CLI fetches the account list via
//!    `GET /api/accounts` and composes it with the local quota
//!    file. The daemon's 5s discovery cache means a cold
//!    filesystem scan happens at most once per 5 seconds across
//!    every CLI invocation, rather than once per invocation.
//!
//! 2. **Direct (fallback)** — when no daemon is running or the
//!    daemon is unhealthy, the CLI runs `discover_anthropic`
//!    itself. Behaviour is byte-identical to pre-M8 versions.
//!
//! The quota file is a local read in both paths — the daemon does
//! not currently expose `/api/quota`, and adding one is M8.6 work
//! (the background poller). Composing daemon-discovered accounts
//! with locally-read quota produces identical output to the direct
//! path for the same `(accounts, quota)` pair.

use anyhow::Result;
use csq_core::accounts::{markers, AccountInfo};
use csq_core::quota::status::{compose_status, show_status, AccountStatus};
use csq_core::types::AccountNum;
use std::path::Path;

#[cfg(unix)]
use csq_core::daemon::{self, DetectResult};

pub fn handle(base_dir: &Path, json: bool) -> Result<()> {
    // Try to resolve active account from current config dir marker
    let active = super::current_config_dir()
        .as_deref()
        .and_then(markers::read_current_account);

    let accounts = resolve_accounts(base_dir, active);

    if json {
        println!("{}", serde_json::to_string(&accounts)?);
        return Ok(());
    }

    if accounts.is_empty() {
        println!("No accounts configured.");
        println!();
        println!("Run `csq login 1` to add your first account.");
        return Ok(());
    }

    println!();
    for account in &accounts {
        println!("{}", account.format_line());
    }
    println!();

    Ok(())
}

/// Returns the composed [`AccountStatus`] entries, trying the
/// daemon first and falling back to direct discovery on any
/// failure.
///
/// Silent fallback — a failed daemon round trip must not produce
/// user-visible noise on a successful status call. Tracing at the
/// debug level captures the detection reason for troubleshooting.
fn resolve_accounts(base_dir: &Path, active: Option<AccountNum>) -> Vec<AccountStatus> {
    #[cfg(unix)]
    {
        if let Some(accounts) = try_daemon_accounts(base_dir) {
            return compose_status(base_dir, accounts, active);
        }
    }

    show_status(base_dir, active)
}

/// Attempts to fetch accounts from the running daemon via
/// `GET /api/accounts`. Returns `None` on any failure
/// (daemon not running, unhealthy, parse error, non-200 status)
/// so the caller can fall back to direct discovery.
///
/// All non-200 outcomes are silent — the user runs `csq status`
/// expecting output, not a fallback warning. Debug-level tracing
/// captures the reason for troubleshooting.
#[cfg(unix)]
fn try_daemon_accounts(base_dir: &Path) -> Option<Vec<AccountInfo>> {
    let socket_path = match daemon::detect_daemon(base_dir) {
        DetectResult::Healthy { socket_path, .. } => socket_path,
        other => {
            tracing::debug!(result = ?other, "csq status: daemon not healthy, using direct path");
            return None;
        }
    };

    let resp = match daemon::http_get_unix(&socket_path, "/api/accounts") {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "csq status: daemon GET /api/accounts failed");
            return None;
        }
    };

    if resp.status != 200 {
        tracing::debug!(
            status = resp.status,
            "csq status: daemon returned non-200 for /api/accounts"
        );
        return None;
    }

    // AccountsResponse is `{ "accounts": [...] }`. `AccountInfo`
    // already derives Deserialize in csq-core, so we navigate to
    // the inner array via `serde_json::Value` rather than adding a
    // direct `serde` dependency to csq-cli just for an envelope.
    let value: serde_json::Value = match serde_json::from_str(&resp.body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "csq status: /api/accounts body is not valid JSON");
            return None;
        }
    };

    let arr = value.get("accounts")?.clone();
    match serde_json::from_value::<Vec<AccountInfo>>(arr) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::debug!(error = %e, "csq status: could not deserialize accounts array");
            None
        }
    }
}
