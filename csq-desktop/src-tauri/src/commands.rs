use crate::AppState;
use csq_core::accounts::discovery;
use csq_core::accounts::AccountSource;
use csq_core::broker::fanout;
use csq_core::credentials::{self, file as cred_file};
use csq_core::oauth::{
    exchange_code, start_login as oauth_start_login, LoginRequest, PASTE_CODE_REDIRECT_URI,
};
use csq_core::providers;
use csq_core::quota::state as quota_state;
use csq_core::quota::QuotaFile;
use csq_core::rotation;
use csq_core::rotation::config as rotation_config;
use csq_core::rotation::RotationConfig;
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::PathBuf;
use tauri::State;

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

/// Public view of a provider entry, safe to send over IPC.
///
/// Intentionally does not include any secret material — the
/// `key_env_var` and `base_url_env_var` fields name the env vars
/// whose *values* are secrets, not the values themselves.
#[derive(Serialize)]
pub struct ProviderView {
    /// Short identifier used on subsequent commands (e.g. "claude", "mm", "zai").
    pub id: String,
    /// Display name (e.g. "Claude", "MiniMax", "Z.AI").
    pub name: String,
    /// `"oauth"` | `"bearer"` | `"none"`.
    pub auth_type: String,
    /// Default base URL or null.
    pub default_base_url: Option<String>,
    /// Default model the provider ships with.
    pub default_model: String,
}

/// Returns the provider catalog, excluding `ollama` for now
/// (the desktop Add Account flow covers Claude/MiniMax/Z.AI).
#[tauri::command]
pub fn list_providers() -> Result<Vec<ProviderView>, String> {
    Ok(providers::PROVIDERS
        .iter()
        .filter(|p| p.id != "ollama")
        .map(|p| ProviderView {
            id: p.id.to_string(),
            name: p.name.to_string(),
            auth_type: match p.auth_type {
                providers::catalog::AuthType::OAuth => "oauth".into(),
                providers::catalog::AuthType::Bearer => "bearer".into(),
                providers::catalog::AuthType::None => "none".into(),
            },
            default_base_url: p.default_base_url.map(|s| s.to_string()),
            default_model: p.default_model.to_string(),
        })
        .collect())
}

/// Result of [`start_claude_login`]. Safe to send over IPC — contains
/// the authorize URL, the CSRF state token, and the target account,
/// but no tokens, verifier, or authorization code.
#[derive(Serialize)]
pub struct ClaudeLoginView {
    /// Full Anthropic authorize URL the frontend should open (either
    /// in a child WebviewWindow or as a fallback in the system
    /// browser).
    pub auth_url: String,
    /// CSRF state token. The frontend carries this so it can route
    /// the `oauth-login-complete` / `oauth-login-failed` event back
    /// to the correct waiting UI when multiple logins are in flight.
    pub state: String,
    /// Account slot being authorized, echoed back for correlation.
    pub account: u16,
    /// Seconds remaining on the pending state entry. The frontend
    /// uses this to cancel the spinner with a clear message if the
    /// user walks away.
    pub expires_in_secs: u64,
}

impl From<LoginRequest> for ClaudeLoginView {
    fn from(r: LoginRequest) -> Self {
        Self {
            auth_url: r.auth_url,
            state: r.state,
            account: r.account,
            expires_in_secs: r.expires_in_secs,
        }
    }
}

/// Initiates an Anthropic OAuth login for the given account slot.
///
/// Generates a fresh PKCE verifier + state token, records them in
/// the shared [`OAuthStateStore`], and returns a paste-code
/// authorize URL the frontend should open in the system browser.
///
/// After the user authorizes, Anthropic displays an authorization
/// code on its callback page. The frontend collects that code from
/// the user and submits it via [`submit_oauth_code`] to complete
/// the login.
///
/// # Errors
///
/// - `"invalid account: ..."` — account number is out of range
#[tauri::command]
pub fn start_claude_login(
    state: State<'_, AppState>,
    account: u16,
) -> Result<ClaudeLoginView, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    oauth_start_login(&state.oauth_store, account_num)
        .map(ClaudeLoginView::from)
        .map_err(|e| format!("failed to start login: {e}"))
}

/// Submits a paste-code from Anthropic's OAuth callback page and
/// exchanges it for a credential file.
///
/// The frontend calls this after the user completes the browser
/// authorization and pastes the displayed code. This command:
///
/// 1. Consumes the pending PKCE state entry keyed by `state_token`
///    (rejects missing, expired, or already-consumed entries)
/// 2. Calls [`csq_core::oauth::exchange_code`] with the code, the
///    recovered verifier, and the paste-code redirect URI (must be
///    byte-identical to what the authorize URL advertised)
/// 3. Writes the resulting credential file to
///    `credentials/N.json` with 0o600 permissions
/// 4. Returns the account number so the frontend can refresh the
///    account list and show a success toast
///
/// # Errors
///
/// - `"invalid code: ..."` — empty or whitespace-only paste input
/// - `"no matching login: ..."` — state token not recognized
///   (wrong paste window, already submitted, or TTL expired)
/// - `"exchange failed: ..."` — Anthropic rejected the code or
///   returned a malformed token response
/// - `"credential write failed: ..."` — disk error during save
///
/// All error messages are pre-redacted — the underlying
/// [`OAuthError`] types already run response bodies through
/// `redact_tokens`, so it is safe to surface the message to the
/// frontend and the log.
#[tauri::command]
pub fn submit_oauth_code(
    state: State<'_, AppState>,
    base_dir: String,
    state_token: String,
    code: String,
) -> Result<u16, String> {
    // Clean the pasted code: strip whitespace, CR (Windows paste),
    // and any `#state=...` fragment the user may have accidentally
    // included. Anthropic's paste-code page displays the code as a
    // single string in a copy box — normal paste gives us just the
    // code, but we defend against the user highlighting extra
    // characters on either side.
    let code = code.trim().trim_end_matches('\r').to_string();
    let code = code
        .split_once('#')
        .map(|(c, _)| c.to_string())
        .unwrap_or(code);
    if code.is_empty() {
        return Err("invalid code: paste was empty".into());
    }

    // Consume the pending PKCE state. `consume` is the authentication
    // boundary: only a caller holding the exact state token that was
    // issued at `start_claude_login` time can retrieve the verifier.
    let pending = state
        .oauth_store
        .consume(&state_token)
        .map_err(|e| format!("no matching login: {e}"))?;

    // Run the token exchange synchronously. Production uses
    // `csq_core::http::post_json` which is blocking reqwest under
    // the hood. Tauri commands run on the async runtime but this
    // particular call is short (one HTTP round-trip) and carries
    // no secret material in its error path (OAuthError is already
    // redacted), so we do not need spawn_blocking.
    let credential = exchange_code(
        &code,
        &pending.code_verifier,
        PASTE_CODE_REDIRECT_URI,
        csq_core::http::post_json,
    )
    .map_err(|e| format!("exchange failed: {e}"))?;

    // Persist to `credentials/N.json` via the canonical helper
    // which handles atomic replace + 0o600 permissions.
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    credentials::save_canonical(&base, pending.account, &credential)
        .map_err(|e| format!("credential write failed: {e}"))?;

    Ok(pending.account.get())
}

/// Cancels a pending login by consuming its state token from the
/// store. Used when the user closes the Add Account modal before
/// submitting a code.
///
/// Returns `Ok(())` even if the token was not found — a concurrent
/// callback may have already consumed it, which is not an error
/// from the user's perspective.
#[tauri::command]
pub fn cancel_login(state: State<'_, AppState>, state_token: String) -> Result<(), String> {
    // `consume` returns the pending entry on success, or a
    // StateMismatch / StateExpired error if the token was already
    // consumed or evicted. All three outcomes are "the token no
    // longer does anything" from the caller's perspective — exactly
    // what cancel means — so we classify explicitly rather than use
    // a blanket discard.
    match state.oauth_store.consume(&state_token) {
        Ok(_pending) => {
            // Token was still pending; now cancelled.
            Ok(())
        }
        Err(csq_core::error::OAuthError::StateMismatch) => {
            // Already consumed by a racing callback, or never valid.
            // Idempotent from the user's perspective.
            Ok(())
        }
        Err(csq_core::error::OAuthError::StateExpired { .. }) => {
            // TTL elapsed. Same effective outcome — the token is
            // gone from the store.
            Ok(())
        }
        Err(e) => Err(format!("cancel failed: {e}")),
    }
}

/// Sets the API key for a bearer-auth provider (MiniMax, Z.AI).
///
/// Wraps [`providers::settings::save_settings`] with validation
/// matching the CLI `csq setkey` command. The key is never echoed
/// back to the caller — only a masked fingerprint of the stored
/// key.
///
/// # Errors
///
/// - `"unknown provider: X"` — provider id not in catalog
/// - `"provider X uses OAuth, not API keys"` — wrong flow for Claude
/// - `"provider X does not use API keys"` — keyless provider
/// - `"key must not be empty"` — empty input
/// - `"key too long"` — input >4096 bytes
#[tauri::command]
pub fn set_provider_key(
    base_dir: String,
    provider_id: String,
    key: String,
) -> Result<String, String> {
    // 4096 matches MAX_KEY_LEN in csq-cli setkey.
    const MAX_KEY_LEN: usize = 4096;

    let provider = providers::get_provider(&provider_id)
        .ok_or_else(|| format!("unknown provider: {provider_id}"))?;

    match provider.auth_type {
        providers::catalog::AuthType::OAuth => {
            return Err(format!(
                "provider {provider_id} uses OAuth, not API keys — use start_claude_login instead"
            ));
        }
        providers::catalog::AuthType::None => {
            return Err(format!("provider {provider_id} does not use API keys"));
        }
        providers::catalog::AuthType::Bearer => {}
    }

    let key = key.trim().trim_end_matches('\r').to_string();
    if key.is_empty() {
        return Err("key must not be empty".into());
    }
    if key.len() > MAX_KEY_LEN {
        return Err(format!("key too long (limit {MAX_KEY_LEN} bytes)"));
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    let mut settings = providers::settings::load_settings(&base, &provider_id)
        .map_err(|e| format!("load settings: {e}"))?;
    settings
        .set_api_key(&key)
        .map_err(|e| format!("set key: {e}"))?;
    providers::settings::save_settings(&base, &settings)
        .map_err(|e| format!("save settings: {e}"))?;

    Ok(settings.key_fingerprint())
}
