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
use csq_core::accounts::snapshot;
use csq_core::quota::status::{render_status_table, show_status, AccountStatus};
use csq_core::sdk::{self, Envelope, SCHEMA_STATUS_V1};
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::Path;

#[cfg(unix)]
use csq_core::accounts::AccountInfo;
#[cfg(unix)]
use csq_core::daemon::{self, DetectResult};
#[cfg(unix)]
use csq_core::quota::status::compose_status;

/// `csq.status.v1` payload (an internal ticket Track B). **R1** — hand-authored, explicit
/// field: `data` carries the pre-existing `Vec<AccountStatus>` rows UNCHANGED. Before
/// this schema existed `csq status --json` emitted a BARE top-level array, so a host
/// had nothing to feature-detect against. Migration for an existing consumer is a
/// one-line jq change: `.[0].id` -> `.data[0].id` (workspace `sdk-surface`
/// LAUNCH-LEDGER 2026-08-09-wave3 Track B).
#[derive(Debug, Serialize)]
struct StatusPayload {
    data: Vec<AccountStatus>,
}

pub fn handle(base_dir: &Path, json: bool) -> Result<()> {
    // Resolve active account authority-first (workspace
    // an internal workspace): snapshot_account reads `.csq-account`
    // (numeric direct / UUID via by_slot) and self-heals the cache, so the
    // "active" highlight cannot be pinned to a stale `.current-account`.
    let active = super::current_config_dir()
        .as_deref()
        .and_then(|cd| snapshot::snapshot_account(cd, base_dir));

    let accounts = resolve_accounts(base_dir, active);

    if json {
        // R3: emit() is the only stdout writer for the enveloped surface.
        sdk::emit(&Envelope::success(
            SCHEMA_STATUS_V1,
            None,
            StatusPayload { data: accounts },
        ))?;
        return Ok(());
    }

    if accounts.is_empty() {
        println!("No accounts configured.");
        println!();
        println!("Run `csq login 1` to add your first account.");
        return Ok(());
    }

    let clock = chrono::Local::now().format("%a %H:%M").to_string();
    print!("{}", render_status_table(&accounts, active, &clock));
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
        DetectResult::Healthy {
            socket_path,
            daemon_version,
            ..
        } => {
            // Stale-daemon defense: a long-running daemon spawned from
            // a pre-upgrade binary will silently serve stale
            // `/api/accounts` (e.g. missing Gemini slots from before
            // `discover_gemini` was wired in). Rather than consume the
            // stale view, fall back to the direct path AND tell the
            // user — they need to restart the daemon to refresh.
            if let Some(reason) = daemon::version_drift_reason(&daemon_version) {
                eprintln!("warning: {reason}");
                return None;
            }
            socket_path
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::accounts::{AccountSource, Backend};
    use csq_core::providers::catalog::Surface;

    fn sample_row() -> AccountStatus {
        AccountStatus {
            id: 1,
            label: "user@example.com".into(),
            is_active: true,
            five_hour_pct: Some(42.5),
            five_hour_resets_in: Some(3600),
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            balance: None,
            backend: Backend::Direct,
            stale_secs: None,
        }
    }

    /// Golden fixture (an internal ticket Track B): every pre-existing `AccountStatus`
    /// row field, unchanged, now lives at `data[N].<field>` under the
    /// `csq.status.v1` envelope. A rename or retype of ANY field asserted here
    /// REDS this test — that non-vacuity is the entire point of versioning the
    /// schema (verified by hand: renaming `StatusPayload.data` to `.rows` fails
    /// this test with "missing field `data`" / a null `data[0]` lookup).
    #[test]
    fn status_json_envelope_matches_golden_shape() {
        let payload = StatusPayload {
            data: vec![sample_row()],
        };
        let env = Envelope::success(SCHEMA_STATUS_V1, None, payload);
        let line = env.to_line().unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(v["schema"], "csq.status.v1");
        assert_eq!(v["ok"], true);
        assert!(
            v.get("error").is_none(),
            "success envelope carries no error"
        );

        let row = &v["data"][0];
        assert_eq!(row["id"], 1);
        assert_eq!(row["label"], "user@example.com");
        assert_eq!(row["is_active"], true);
        assert_eq!(row["five_hour_pct"], 42.5);
        assert_eq!(row["five_hour_resets_in"], 3600);
        assert!(row["seven_day_pct"].is_null());
        assert!(row["seven_day_resets_in"].is_null());
        assert_eq!(row["source"], "Anthropic");
        assert_eq!(row["surface"], "claude-code");
        assert_eq!(row["method"], "oauth");
        assert_eq!(row["backend"], "direct");
        // Optional, skip_serializing_if fields stay ABSENT (not null) when None —
        // the pre-existing `AccountStatus` wire behavior, unchanged by the envelope.
        assert!(row.get("balance").is_none());
        assert!(row.get("stale_secs").is_none());
    }

    #[test]
    fn status_json_envelope_is_a_single_line() {
        let env = Envelope::success(
            SCHEMA_STATUS_V1,
            None,
            StatusPayload {
                data: vec![sample_row()],
            },
        );
        let line = env.to_line().unwrap();
        assert_eq!(line.matches('\n').count(), 0);
    }
}
