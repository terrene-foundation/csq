use csq_core::accounts::discovery;
use csq_core::accounts::AccountSource;
use csq_core::broker::fanout;
use csq_core::credentials::{self, file as cred_file};
use csq_core::quota::state as quota_state;
use csq_core::quota::QuotaFile;
use csq_core::rotation;
use csq_core::rotation::config as rotation_config;
use csq_core::rotation::RotationConfig;
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::PathBuf;

/// Public view of a single account, safe to send over IPC.
///
/// Credentials, tokens, and keys are never included.
#[derive(Serialize)]
pub struct AccountView {
    pub id: u16,
    pub label: String,
    /// "anthropic" | "third_party" | "manual"
    pub source: String,
    pub has_credentials: bool,
    pub five_hour_pct: f64,
    pub seven_day_pct: f64,
    pub updated_at: f64,
    /// "healthy" | "expiring" | "expired" | "missing"
    pub token_status: String,
    /// Seconds until token expires. Negative = expired N seconds ago.
    pub expires_in_secs: Option<i64>,
}

/// Daemon status, safe to send over IPC.
#[derive(Serialize)]
pub struct DaemonStatusView {
    pub running: bool,
    pub pid: Option<u32>,
}

/// Returns all configured accounts with current quota data.
///
/// `base_dir` is the Claude accounts directory (e.g. `~/.claude/accounts`).
/// Returns a validation error if the directory does not exist.
#[tauri::command]
pub fn get_accounts(base_dir: String) -> Result<Vec<AccountView>, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    let accounts = discovery::discover_all(&base);
    let quota: QuotaFile = quota_state::load_state(&base).unwrap_or_else(|_| QuotaFile::empty());

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let views = accounts
        .into_iter()
        .map(|a| {
            let q = quota.get(a.id);

            // Token health: load credential file and check expiry
            let (token_status, expires_in_secs) = match AccountNum::try_from(a.id) {
                Ok(num) => {
                    let canonical = cred_file::canonical_path(&base, num);
                    match credentials::load(&canonical) {
                        Ok(creds) => {
                            let exp_ms = creds.claude_ai_oauth.expires_at;
                            let secs = (exp_ms as i64 - now_ms as i64) / 1000;
                            let status = if secs <= 0 {
                                "expired"
                            } else if creds.claude_ai_oauth.is_expired_within(7200) {
                                "expiring"
                            } else {
                                "healthy"
                            };
                            (status.to_string(), Some(secs))
                        }
                        Err(_) => ("missing".to_string(), None),
                    }
                }
                Err(_) => ("missing".to_string(), None),
            };

            AccountView {
                id: a.id,
                label: a.label,
                source: match a.source {
                    AccountSource::Anthropic => "anthropic".into(),
                    AccountSource::ThirdParty { .. } => "third_party".into(),
                    AccountSource::Manual => "manual".into(),
                },
                has_credentials: a.has_credentials,
                five_hour_pct: q.map(|q| q.five_hour_pct()).unwrap_or(0.0),
                seven_day_pct: q.map(|q| q.seven_day_pct()).unwrap_or(0.0),
                updated_at: q.map(|q| q.updated_at).unwrap_or(0.0),
                token_status,
                expires_in_secs,
            }
        })
        .collect();

    Ok(views)
}

/// Swaps the active account in the first config dir found for `target`.
///
/// `base_dir` is the Claude accounts directory. `target` must be 1–999.
/// Returns an error if no active session exists for the account.
#[tauri::command]
pub fn swap_account(base_dir: String, target: u16) -> Result<String, String> {
    let base = PathBuf::from(&base_dir);

    let account = AccountNum::try_from(target).map_err(|e| format!("invalid account: {e}"))?;

    let config_dirs = fanout::scan_config_dirs(&base, account);
    let config_dir = config_dirs
        .first()
        .ok_or_else(|| format!("no active session for account {target}"))?;

    rotation::swap_to(&base, config_dir, account)
        .map(|r| format!("Swapped to account {}", r.account))
        .map_err(|e| e.to_string())
}

/// Returns the current auto-rotation configuration.
///
/// Returns defaults if `rotation.json` does not exist.
#[tauri::command]
pub fn get_rotation_config(base_dir: String) -> Result<RotationConfig, String> {
    let base = PathBuf::from(&base_dir);
    rotation_config::load(&base).map_err(|e| e.to_string())
}

/// Enables or disables auto-rotation, writing the change to `rotation.json`.
#[tauri::command]
pub fn set_rotation_enabled(base_dir: String, enabled: bool) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    let mut config = rotation_config::load(&base).map_err(|e| e.to_string())?;
    config.enabled = enabled;
    rotation_config::save(&base, &config).map_err(|e| e.to_string())
}

/// Returns whether the csq daemon is running.
#[tauri::command]
pub fn get_daemon_status(base_dir: String) -> Result<DaemonStatusView, String> {
    let base = PathBuf::from(&base_dir);
    let pid_path = csq_core::daemon::pid_file_path(&base);
    let status = csq_core::daemon::status_of(&pid_path);
    Ok(match status {
        csq_core::daemon::DaemonStatus::Running { pid } => DaemonStatusView {
            running: true,
            pid: Some(pid),
        },
        _ => DaemonStatusView {
            running: false,
            pid: None,
        },
    })
}

/// Returns a login instruction for the given account.
///
/// Full OAuth from the desktop app requires the daemon's callback
/// listener. For alpha, we direct users to the CLI.
#[tauri::command]
pub fn start_login(account: u16) -> Result<String, String> {
    if !(1..=999).contains(&account) {
        return Err(format!("account must be 1-999, got {account}"));
    }
    Ok(format!(
        "Run `csq login {account}` in your terminal to authenticate this account."
    ))
}
