use crate::{AppState, CachedUpdateInfo};
use csq_core::accounts::discovery;
use csq_core::accounts::AccountSource;
use csq_core::broker::fanout;
use csq_core::credentials::{self, file as cred_file};
use csq_core::oauth::{exchange_code, LoginRequest, PASTE_CODE_REDIRECT_URI};
use csq_core::providers;
use csq_core::quota::state as quota_state;
use csq_core::quota::QuotaFile;
use csq_core::rotation;
use csq_core::rotation::config as rotation_config;
use csq_core::rotation::RotationConfig;
use csq_core::sessions;
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::PathBuf;
use tauri::{AppHandle, State};
use tauri_plugin_autostart::ManagerExt;

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
    pub five_hour_resets_in: Option<i64>,
    pub seven_day_pct: f64,
    pub seven_day_resets_in: Option<i64>,
    pub updated_at: f64,
    /// "healthy" | "expiring" | "expired" | "missing"
    pub token_status: String,
    /// Seconds until token expires. Negative = expired N seconds ago.
    pub expires_in_secs: Option<i64>,
    /// Fixed-vocabulary tag for the most recent refresh failure,
    /// or null if the last refresh succeeded / there's no flag.
    /// Possible values: "broker_token_invalid" (needs re-login),
    /// "broker_refresh_failed" (refresh + sibling recovery both
    /// failed), "credential" / "config" / "platform" / "other".
    /// The dashboard joins this to the status to render e.g.
    /// "Expired — invalid token" so users know WHY a slot is
    /// stuck, not just that it is.
    pub last_refresh_error: Option<String>,
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

    // Sibling-quota fallback map: email → quota of the first slot
    // for that email that has any usage data. When a freshly-added
    // duplicate-email slot has no quota entry yet (the daemon
    // polls every 5 minutes), the dashboard borrows its sibling's
    // numbers so the user sees the correct total immediately
    // instead of "0%" for up to 5 minutes. Both slots share the
    // same Anthropic backend account, so the numbers are identical
    // by construction.
    let mut sibling_quota: std::collections::HashMap<String, &csq_core::quota::AccountQuota> =
        std::collections::HashMap::new();
    for a in &accounts {
        if matches!(a.source, AccountSource::Anthropic) && !a.label.is_empty() {
            if let Some(q) = quota.get(a.id) {
                if q.five_hour.is_some() || q.seven_day.is_some() {
                    sibling_quota.entry(a.label.clone()).or_insert(q);
                }
            }
        }
    }

    let views = accounts
        .into_iter()
        .map(|a| {
            let own = quota.get(a.id);
            let q = match own {
                Some(q) if q.five_hour.is_some() || q.seven_day.is_some() => Some(q),
                _ if matches!(a.source, AccountSource::Anthropic) && !a.label.is_empty() => {
                    sibling_quota.get(a.label.as_str()).copied().or(own)
                }
                _ => own,
            };

            // Token health depends on account type:
            // - Anthropic accounts: check OAuth credential expiry
            // - 3P accounts (MiniMax, Z.AI): API-key based, no expiry
            let is_third_party = matches!(a.source, AccountSource::ThirdParty { .. });
            let (token_status, expires_in_secs, last_refresh_error) = if is_third_party {
                // 3P accounts use API keys, not OAuth tokens.
                // They're "healthy" if they have a key configured.
                let status = if a.has_credentials {
                    "healthy"
                } else {
                    "missing"
                };
                (status.to_string(), None, None)
            } else {
                match AccountNum::try_from(a.id) {
                    Ok(num) => {
                        let canonical = cred_file::canonical_path(&base, num);
                        let reason =
                            csq_core::broker::fanout::read_broker_failed_reason(&base, num)
                                .filter(|s| !s.is_empty());
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
                                (status.to_string(), Some(secs), reason)
                            }
                            Err(_) => ("missing".to_string(), None, reason),
                        }
                    }
                    Err(_) => ("missing".to_string(), None, None),
                }
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
                five_hour_resets_in: q.and_then(|q| {
                    q.five_hour.as_ref().map(|w| {
                        let now = now_ms / 1000;
                        w.resets_at as i64 - now as i64
                    })
                }),
                seven_day_pct: q.map(|q| q.seven_day_pct()).unwrap_or(0.0),
                seven_day_resets_in: q.and_then(|q| {
                    q.seven_day.as_ref().map(|w| {
                        let now = now_ms / 1000;
                        w.resets_at as i64 - now as i64
                    })
                }),
                updated_at: q.map(|q| q.updated_at).unwrap_or(0.0),
                token_status,
                expires_in_secs,
                last_refresh_error,
            }
        })
        .collect();

    Ok(views)
}

/// Swaps the active account in the first config dir found for `target`.
///
/// `base_dir` is the Claude accounts directory. `target` must be 1–999.
///
/// Refuses to swap to a 3P provider slot (MiniMax, Z.AI, etc.). Those
/// slots have no `credentials/N.json` — they're API-key based and
/// require a *new* CC session pointed at the provider's base URL,
/// which is `csq run <provider>` not `csq swap N`. Returns a typed
/// THIRD_PARTY_NOT_SWAPPABLE error so the dashboard can phrase a
/// useful message instead of bubbling up "credential file not found".
#[tauri::command]
pub fn swap_account(base_dir: String, target: u16) -> Result<String, String> {
    let base = PathBuf::from(&base_dir);

    let account = AccountNum::try_from(target).map_err(|e| format!("invalid account: {e}"))?;

    // Reject 3P slots before touching the rotation path.
    let all_accounts = discovery::discover_all(&base);
    if let Some(matched) = all_accounts.iter().find(|a| a.id == target) {
        if let AccountSource::ThirdParty { provider } = &matched.source {
            return Err(format!(
                "THIRD_PARTY_NOT_SWAPPABLE: account {target} is a {provider} slot. Open a new terminal and run `csq run {provider}` to use this provider — desktop swap only works for Anthropic OAuth accounts."
            ));
        }
    }

    let config_dirs = fanout::scan_config_dirs(&base, account);
    let config_dir = config_dirs
        .first()
        .ok_or_else(|| format!("no active session for account {target}"))?;

    rotation::swap_to(&base, config_dir, account)
        .map(|r| format!("Swapped to account {}", r.account))
        .map_err(|e| e.to_string())
}

/// Renames an account's display label in profiles.json.
#[tauri::command]
pub fn rename_account(base_dir: String, account: u16, name: String) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    if name.trim().is_empty() {
        return Err("name must not be empty".into());
    }
    csq_core::accounts::profiles::update_email(&base, account_num, name.trim())
        .map_err(|e| format!("rename failed: {e}"))
}

/// Removes an account: deletes credentials, config dir, and profile entry.
///
/// Refuses if a live `claude` process is currently bound to the
/// account (returns the conflicting PIDs in the error message). Best-
/// effort daemon cache invalidation runs after a successful removal.
#[tauri::command]
pub fn remove_account(base_dir: String, account: u16) -> Result<RemoveAccountSummary, String> {
    use csq_core::accounts::logout::{logout_account, LogoutError};

    let base = PathBuf::from(&base_dir);
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    match logout_account(&base, account_num) {
        Ok(s) => {
            // Best-effort daemon cache invalidation. Mirrors `csq logout`.
            #[cfg(unix)]
            {
                let sock = csq_core::daemon::socket_path(&base);
                if sock.exists() {
                    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
                }
            }
            Ok(RemoveAccountSummary {
                account: s.account.get(),
                canonical_removed: s.canonical_removed,
                config_dir_removed: s.config_dir_removed,
                profiles_entry_removed: s.profiles_entry_removed,
            })
        }
        Err(LogoutError::InUse { account: a, pids }) => Err(format!(
            "ACCOUNT_IN_USE: account {} is bound to live process(es) {:?} — exit those terminals first",
            a, pids
        )),
        Err(LogoutError::NotConfigured { account: a }) => {
            Err(format!("NOT_CONFIGURED: account {a} has no state to remove"))
        }
        Err(e) => Err(format!("REMOVE_FAILED: {e}")),
    }
}

#[derive(Clone, serde::Serialize)]
pub struct RemoveAccountSummary {
    pub account: u16,
    pub canonical_removed: bool,
    pub config_dir_removed: bool,
    pub profiles_entry_removed: bool,
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

/// Public view of one live CC session, safe to send over IPC.
///
/// Includes the current account for the bound config dir plus its
/// 5-hour usage percentage so the dashboard can render a "terminal
/// #5 → account #3 at 87%" row without the frontend making a
/// second IPC call.
///
/// Also exposes terminal identity fields (tty, iTerm window/tab/pane,
/// profile, resolved tab title) so the user can match the dashboard
/// row to the terminal window they're looking at.
#[derive(Serialize)]
pub struct SessionView {
    /// OS process ID.
    pub pid: u32,
    /// Working directory at process creation.
    pub cwd: String,
    /// Path to the `config-N` dir this session is bound to.
    pub config_dir: String,
    /// Account number extracted from the config dir name, or null.
    pub account_id: Option<u16>,
    /// Account label for `account_id` at the moment of the query,
    /// or null if the account is unknown.
    pub account_label: Option<String>,
    /// Current 5-hour quota percentage for the bound account.
    pub five_hour_pct: f64,
    /// Current 7-day quota percentage for the bound account.
    pub seven_day_pct: f64,
    /// Unix seconds since the process started, or null if the
    /// platform could not report it.
    pub started_at: Option<u64>,
    /// Controlling TTY basename (e.g. `"ttys003"`). Users can run
    /// `tty` in their terminal to match a row.
    pub tty: Option<String>,
    /// iTerm2 window/tab/pane indices parsed from `TERM_SESSION_ID`.
    pub term_window: Option<u8>,
    pub term_tab: Option<u8>,
    pub term_pane: Option<u8>,
    /// iTerm2 profile name from `ITERM_PROFILE`.
    pub iterm_profile: Option<String>,
    /// Human-readable iTerm2 tab title resolved via osascript.
    /// Most specific identifier when available.
    pub terminal_title: Option<String>,
}

/// Returns the list of live Claude Code sessions under the current
/// user. Each entry is one terminal's `claude` process with the
/// current account and 5-hour quota for its bound config dir.
///
/// Unknown on Windows (returns an empty vector). See
/// `csq_core::sessions::windows` for the rationale.
#[tauri::command]
pub fn list_sessions(base_dir: String) -> Result<Vec<SessionView>, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    let sessions = sessions::list();
    if sessions.is_empty() {
        return Ok(Vec::new());
    }

    // One discovery + quota load reused across rows. Ties each
    // session row to the *current* active account for its config
    // dir, which may have rotated since the process launched.
    let accounts = discovery::discover_all(&base);
    let quota: QuotaFile = quota_state::load_state(&base).unwrap_or_else(|_| QuotaFile::empty());

    let mut out = Vec::with_capacity(sessions.len());
    for s in sessions {
        // Use the `.csq-account` marker for the live account, not
        // the config dir name. The marker reflects swaps and renames
        // (e.g. config-8 with marker=7 after a slot rename).
        let live_account = csq_core::accounts::markers::read_csq_account(&s.config_dir)
            .map(|n| n.get())
            .or(s.account_id);
        let account_info = live_account.and_then(|id| accounts.iter().find(|a| a.id == id));
        let account_label = account_info.map(|a| a.label.clone());
        let five_hour_pct = live_account
            .and_then(|id| quota.get(id).map(|q| q.five_hour_pct()))
            .unwrap_or(0.0);
        let seven_day_pct = live_account
            .and_then(|id| quota.get(id).map(|q| q.seven_day_pct()))
            .unwrap_or(0.0);

        out.push(SessionView {
            pid: s.pid,
            cwd: s.cwd.display().to_string(),
            config_dir: s.config_dir.display().to_string(),
            account_id: live_account,
            account_label,
            five_hour_pct,
            seven_day_pct,
            started_at: s.started_at,
            tty: s.tty,
            term_window: s.term_window,
            term_tab: s.term_tab,
            term_pane: s.term_pane,
            iterm_profile: s.iterm_profile,
            terminal_title: s.terminal_title,
        });
    }

    // Deterministic ordering by PID so the dashboard list doesn't
    // shuffle between polls. Ascending PID roughly maps to "order
    // the terminals were opened" which matches how the user thinks
    // about their workspace.
    out.sort_by_key(|s| s.pid);
    Ok(out)
}

/// Retargets a **specific** `config-N` dir to a new account,
/// bypassing the "most recently modified" heuristic that the tray
/// quick-swap uses.
///
/// This is the command the Sessions view calls when the user
/// clicks the Swap button on a specific terminal row — it knows
/// exactly which config dir belongs to that terminal from the
/// `list_sessions` output.
///
/// `base_dir` is the csq accounts root (`~/.claude/accounts`).
/// `config_dir` MUST be a path that lives underneath it (enforced
/// below to prevent path-traversal). `target` must be 1..=999.
#[tauri::command]
pub fn swap_session(base_dir: String, config_dir: String, target: u16) -> Result<String, String> {
    let base = PathBuf::from(&base_dir);
    let config = PathBuf::from(&config_dir);

    // Canonicalize both sides and refuse any config dir that isn't
    // a direct child of `base`. `fs::canonicalize` follows symlinks,
    // which is the correct behavior here — if the user symlinked
    // `config-5` to a directory outside `base`, we refuse the swap
    // instead of letting IPC writes escape the accounts root.
    let base_canon = std::fs::canonicalize(&base).map_err(|e| format!("invalid base_dir: {e}"))?;
    let config_canon =
        std::fs::canonicalize(&config).map_err(|e| format!("invalid config_dir: {e}"))?;
    if config_canon.parent() != Some(base_canon.as_path()) {
        return Err(format!(
            "config_dir must be a direct child of base_dir: {}",
            config.display()
        ));
    }
    // Second defense: the dir name must match `config-<1..=999>`.
    let name = config_canon
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "config_dir has no name".to_string())?;
    let num_str = name
        .strip_prefix("config-")
        .ok_or_else(|| format!("config_dir must be config-<N>: {name}"))?;
    let n: u16 = num_str
        .parse()
        .map_err(|_| format!("config_dir suffix is not numeric: {num_str}"))?;
    if !(1..=999).contains(&n) {
        return Err(format!("config_dir number out of range: {n}"));
    }

    // Reject 3P slots on either side of the swap.
    //
    // `rotation::swap_to` copies `credentials/{target}.json` into
    // `config_dir/.credentials.json`, which is only meaningful for
    // OAuth accounts. If `target` is a 3P slot (e.g. MiniMax) the
    // copy fails with NotFound. If the **source** config dir is
    // itself a 3P slot (e.g. config-9 with MiniMax settings.json)
    // then even a successful OAuth copy would corrupt the slot's
    // 3P binding by shoving an OAuth credential file alongside its
    // settings.json. Reject both cases up-front with a clear error
    // message that points the user at the right workflow.
    let all_accounts = discovery::discover_all(&base_canon);
    let target_is_third_party = all_accounts
        .iter()
        .any(|a| a.id == target && matches!(a.source, AccountSource::ThirdParty { .. }));
    if target_is_third_party {
        return Err(format!(
            "account {target} is a third-party provider slot; swap it from the Accounts tab instead"
        ));
    }
    // Use the `.csq-account` marker (not the config dir number) to
    // determine the source account. After a rename (e.g. config-8
    // with marker=7), the dir number no longer matches any account.
    let source_account = csq_core::accounts::markers::read_csq_account(&config_canon)
        .map(|a| a.get())
        .unwrap_or(n);
    let source_is_third_party = all_accounts
        .iter()
        .any(|a| a.id == source_account && matches!(a.source, AccountSource::ThirdParty { .. }));
    if source_is_third_party {
        return Err(format!(
            "{name} is bound to a third-party provider (account {source_account}); \
             unbind it from settings.json before rotating to an OAuth account"
        ));
    }

    let account = AccountNum::try_from(target).map_err(|e| format!("invalid account: {e}"))?;
    rotation::swap_to(&base_canon, &config_canon, account)
        .map(|r| format!("Swapped {} to account {}", name, r.account))
        .map_err(|e| e.to_string())
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

/// Returns the full provider catalog (Claude, MiniMax, Z.AI, Ollama).
///
/// The frontend branches on `auth_type`:
/// - `"oauth"` → Claude sign-in flow
/// - `"bearer"` → API-key entry (MiniMax, Z.AI)
/// - `"none"` → keyless slot binding (Ollama) via [`bind_keyless_provider`]
#[tauri::command]
pub fn list_providers() -> Result<Vec<ProviderView>, String> {
    Ok(providers::PROVIDERS
        .iter()
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

/// Result of [`begin_claude_login`]. Safe to send over IPC — contains
/// the authorize URL, the CSRF state token, and the target account,
/// but no tokens, verifier, or authorization code.
#[derive(Serialize)]
pub struct ClaudeLoginView {
    /// Full Anthropic authorize URL the frontend should open in the
    /// system browser via `tauri-plugin-opener`'s `openUrl`.
    pub auth_url: String,
    /// CSRF state token. The frontend carries this through the
    /// paste-code step so it can route the submission back to the
    /// correct pending PKCE state when multiple logins are in flight.
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

/// Begins an in-process PKCE OAuth login for the given account slot.
///
/// This is step 1 of the paste-code OAuth flow:
/// 1. Generates a fresh PKCE verifier + challenge
/// 2. Records them in the shared [`OAuthStateStore`] keyed by a
///    random state token (CSRF protection + single-use)
/// 3. Builds the Anthropic authorize URL and returns it to the
///    frontend as a [`ClaudeLoginView`]
///
/// After calling this command the frontend should:
/// - Open `auth_url` in the system browser (via `openUrl`)
/// - Show a code-paste input field to the user
/// - Call [`submit_oauth_code`] with the `state_token` returned here
///   and the code the user copies from Anthropic's callback page
///
/// To cancel an in-flight login (e.g. user closes the modal),
/// call [`cancel_login`] with the same `state_token`.
///
/// # Errors
///
/// - `"invalid account: ..."` — account out of range 1..=999
/// - `"login store full"` — MAX_PENDING simultaneous logins active
///   (unlikely in practice but possible under rapid re-opens)
#[tauri::command]
pub fn begin_claude_login(
    state: State<'_, AppState>,
    account: u16,
) -> Result<ClaudeLoginView, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    csq_core::oauth::login::start_login(&state.oauth_store, account_num)
        .map(ClaudeLoginView::from)
        .map_err(|e| e.to_string())
}

/// Runs `claude auth login` subprocess for the given account slot,
/// using an absolute path to the `claude` binary so the call works
/// in the Finder-launched desktop bundle (which doesn't inherit the
/// user's shell `PATH`).
///
/// Returns `CLAUDE_NOT_FOUND` if no `claude` install can be located
/// in `$PATH` or any of the well-known directories searched by
/// [`csq_core::accounts::login::find_claude_binary`]. The frontend
/// uses that tag to fall back to the in-process paste-code flow.
///
/// This is a BLOCKING command — runs on a Tokio blocking worker so
/// it doesn't freeze the Tauri event loop. The OAuth handshake is
/// owned entirely by the spawned `claude` process: it opens a
/// browser, captures the callback, writes `.credentials.json` into
/// the supplied `CLAUDE_CONFIG_DIR`. csq just reads the file after
/// the subprocess exits and mirrors it to `credentials/N.json`.
///
/// On 3P import, the daemon's account-discovery cache is invalidated
/// so the dashboard sees the new account on its next 5s poll.
#[tauri::command]
pub async fn start_claude_login(base_dir: String, account: u16) -> Result<u16, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = std::path::PathBuf::from(&base_dir);

    tokio::task::spawn_blocking(move || {
        // Resolve `claude` via the shared finder before we start
        // creating state — there's no point provisioning a new
        // config dir if the binary is missing.
        let claude_bin = csq_core::accounts::login::find_claude_binary().ok_or_else(|| {
            "CLAUDE_NOT_FOUND: could not locate the `claude` binary in $PATH or any standard install location".to_string()
        })?;

        let config_dir = base.join(format!("config-{}", account_num));
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| format!("failed to create config dir: {e}"))?;

        // Mark this dir with the account number
        csq_core::accounts::markers::write_csq_account(&config_dir, account_num)
            .map_err(|e| format!("failed to write marker: {e}"))?;

        // Run claude auth login with isolated config dir, calling
        // by absolute path so the Finder-default $PATH gap can't
        // bite us.
        let status = std::process::Command::new(&claude_bin)
            .args(["auth", "login"])
            .env("CLAUDE_CONFIG_DIR", &config_dir)
            .status()
            .map_err(|e| format!("failed to run `claude auth login`: {e}"))?;

        if !status.success() {
            return Err("claude auth login failed or was cancelled".to_string());
        }

        // CC's modern `claude auth login` writes credentials to the
        // macOS keychain at the hashed service name (sometimes also
        // mirrored to `.credentials.json`, sometimes not). Read
        // keychain first, fall back to file — at least one source
        // is populated after a successful auth.
        let creds = csq_core::credentials::keychain::read(&config_dir)
            .or_else(|| credentials::load(&config_dir.join(".credentials.json")).ok())
            .ok_or_else(|| {
                "no credentials captured after login — keychain and file both empty".to_string()
            })?;

        // Save canonical
        credentials::save_canonical(&base, account_num, &creds)
            .map_err(|e| format!("credential write failed: {e}"))?;

        // Marker, profiles.json email update, broker-failed clear —
        // shared with `csq login` so the dashboard sees the real
        // email instead of "unknown".
        csq_core::accounts::login::finalize_login(&base, account_num)
            .map_err(|e| format!("post-login bookkeeping failed: {e}"))?;

        // Tell the daemon its account-discovery cache is stale so
        // get_accounts picks up the new slot on the dashboard's
        // next 5s poll.
        #[cfg(unix)]
        {
            let sock = csq_core::daemon::socket_path(&base);
            if sock.exists() {
                let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
            }
        }

        Ok(account_num.get())
    })
    .await
    .map_err(|e| format!("login task failed: {e}"))?
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
pub async fn submit_oauth_code(
    state: State<'_, AppState>,
    base_dir: String,
    state_token: String,
    code: String,
) -> Result<u16, String> {
    // Clean the pasted code: strip whitespace and CR (Windows paste).
    // Anthropic authorization codes can contain `#` characters, so
    // we must NOT strip at `#` — doing so truncates the code and
    // causes the exchange to fail.
    let code = code.trim().trim_end_matches('\r').to_string();
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

    // Run the blocking token exchange on a worker thread so we
    // don't freeze the Tauri event loop during the HTTP call.
    let base_dir_clone = base_dir.clone();
    tokio::task::spawn_blocking(move || {
        let credential = exchange_code(
            &code,
            &pending.code_verifier,
            PASTE_CODE_REDIRECT_URI,
            csq_core::http::post_json_node,
        )
        .map_err(|e| format!("exchange failed: {e}"))?;

        // Persist to `credentials/N.json` via the canonical helper
        // which handles atomic replace + 0o600 permissions.
        let base = PathBuf::from(&base_dir_clone);
        if !base.is_dir() {
            return Err(format!("base directory does not exist: {base_dir_clone}"));
        }

        credentials::save_canonical(&base, pending.account, &credential)
            .map_err(|e| format!("credential write failed: {e}"))?;

        // Mirror the start_claude_login bookkeeping so the paste-code
        // path also populates profiles.json. In this branch CC did
        // NOT run, so `.claude.json` is unlikely to exist with an
        // emailAddress field — finalize_login falls back to "unknown"
        // gracefully and still writes the marker + clears the
        // broker-failed flag.
        let _ = csq_core::accounts::login::finalize_login(&base, pending.account);

        // Tell the daemon its account-discovery cache is stale.
        #[cfg(unix)]
        {
            let sock = csq_core::daemon::socket_path(&base);
            if sock.exists() {
                let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
            }
        }

        Ok(pending.account.get())
    })
    .await
    .map_err(|e| format!("exchange task failed: {e}"))?
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

/// Binds a keyless provider (Ollama) to an account slot, optionally
/// with a user-selected model.
///
/// The UI flow calls this when the user picks Ollama from the Add
/// Account modal — there is no key to enter, but the user MAY have
/// multiple models installed locally (`ollama list`). Passing `model`
/// overrides the catalog default (currently `gemma4`) and is written
/// verbatim to every `ANTHROPIC_*_MODEL` env key. Omit to accept the
/// default.
///
/// Thin wrapper around [`csq_core::accounts::third_party::bind_provider_to_slot`]
/// with `key = None`, plus input validation (bounds on slot, existence
/// of base dir, provider must be keyless, model non-empty when given).
///
/// # Errors
///
/// - `"unknown provider: X"` — provider id not in catalog
/// - `"provider X is not keyless"` — called on a keyed provider
/// - `"invalid slot: ..."` — slot out of range 1..=999
/// - `"model must not be empty"` — model override supplied but blank
/// - `"base directory does not exist: ..."` — base dir missing
/// - filesystem errors surfaced from the core bind path
#[tauri::command]
pub fn bind_keyless_provider(
    base_dir: String,
    provider_id: String,
    slot: u16,
    model: Option<String>,
) -> Result<(), String> {
    let provider = providers::get_provider(&provider_id)
        .ok_or_else(|| format!("unknown provider: {provider_id}"))?;

    if provider.auth_type != providers::catalog::AuthType::None {
        return Err(format!("provider {provider_id} is not keyless"));
    }

    let slot =
        csq_core::types::AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;

    let model = match model {
        Some(m) => {
            let trimmed = m.trim();
            if trimmed.is_empty() {
                return Err("model must not be empty".into());
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    csq_core::accounts::third_party::bind_provider_to_slot(
        &base,
        &provider_id,
        slot,
        None,
        model.as_deref(),
    )
    .map_err(|e| format!("bind provider: {e}"))
}

/// Returns the list of locally-installed Ollama models by running
/// `ollama list`. Returns an empty list if Ollama is not installed
/// or has no models pulled — the frontend treats empty as a prompt
/// to `ollama pull <model>` before retrying.
///
/// Wraps [`csq_core::providers::ollama::get_ollama_models`]; errors
/// from the subprocess (not-found, non-zero exit) collapse into an
/// empty list so a missing Ollama install surfaces as "no models
/// found" rather than a hang.
#[tauri::command]
pub fn list_ollama_models() -> Result<Vec<String>, String> {
    Ok(providers::ollama::get_ollama_models())
}

// ── Launch-on-login (tauri-plugin-autostart) ──────────────────

/// Returns whether the csq desktop app is registered to auto-start
/// at OS login.
///
/// Reads the platform-native registration state:
/// - **macOS**: `~/Library/LaunchAgents/<bundle-id>.plist`
/// - **Windows**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<bundle-id>`
/// - **Linux**: `~/.config/autostart/<bundle-id>.desktop`
///
/// All three paths are abstracted by `tauri-plugin-autostart`.
/// Returns `false` on any read error so the UI defaults to "off"
/// rather than displaying stale information.
#[tauri::command]
pub fn get_autostart_enabled(app: AppHandle) -> Result<bool, String> {
    app.autolaunch()
        .is_enabled()
        .map_err(|e| format!("failed to read autostart state: {e}"))
}

/// Enables or disables launch-on-login for the csq desktop app.
///
/// Writes the platform-native registration as described in
/// `get_autostart_enabled`. Takes effect on the next login (no
/// need to log out and back in now — the change persists).
///
/// Idempotent: enabling when already enabled, or disabling when
/// already disabled, is a no-op on all three platforms.
#[tauri::command]
pub fn set_autostart_enabled(app: AppHandle, enabled: bool) -> Result<(), String> {
    let autolaunch = app.autolaunch();
    if enabled {
        autolaunch
            .enable()
            .map_err(|e| format!("failed to enable autostart: {e}"))
    } else {
        autolaunch
            .disable()
            .map_err(|e| format!("failed to disable autostart: {e}"))
    }
}

// ── Update check ─────────────────────────────────────────────────
//
// These commands expose the CLI's update-check mechanism
// (`csq_core::update::check_for_update`) to the desktop frontend.
// They do NOT install updates — the signing key is a placeholder
// and `download_and_apply` rejects placeholder-signed releases.
// Instead, the frontend should notify the user and open the GitHub
// release page for manual install.

/// Current running csq version — read at compile time from the
/// workspace `Cargo.toml`. Shown in the "v{current} → v{latest}"
/// update banner so users can confirm the delta.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Triggers a synchronous GitHub Releases check.
///
/// Returns `Some(CachedUpdateInfo)` if a newer version is available,
/// `None` otherwise. Caches the result in `AppState` so the frontend
/// can re-read without re-polling. Network errors are surfaced as
/// `Err(String)` — the frontend decides whether to retry or hide the
/// banner.
#[tauri::command]
pub fn check_for_update(state: State<'_, AppState>) -> Result<Option<CachedUpdateInfo>, String> {
    let info = match csq_core::update::check_for_update() {
        Ok(v) => v,
        Err(e) => return Err(format!("update check failed: {e}")),
    };

    let cached = info.map(|u| CachedUpdateInfo {
        version: u.version,
        current_version: CURRENT_VERSION.to_string(),
        release_url: u.html_url,
    });

    // Store in cache so get_update_status can return it without a
    // fresh network call. Lock held briefly; no await in scope.
    if let Ok(mut guard) = state.update_cache.lock() {
        *guard = cached.clone();
    }

    Ok(cached)
}

/// Returns the cached result of the most recent update check without
/// re-polling GitHub. Intended for frontend callers that want to
/// render the banner without paying network latency on every mount.
///
/// Returns `None` if no check has run yet OR the app is up to date.
/// Callers distinguish the two by calling `check_for_update` once at
/// startup (the desktop app does this automatically 10s after launch).
#[tauri::command]
pub fn get_update_status(state: State<'_, AppState>) -> Result<Option<CachedUpdateInfo>, String> {
    match state.update_cache.lock() {
        Ok(guard) => Ok(guard.clone()),
        Err(_) => Err("update cache lock poisoned".into()),
    }
}

/// Opens the GitHub release page for the cached update in the user's
/// default browser. The frontend calls this from the update banner's
/// "download" button. Manual install is the only option until the
/// Foundation's Ed25519 signing key is provisioned.
///
/// Returns `Err` if no update is cached (the button should be hidden
/// in that case — this guard is defense-in-depth, not a UX path).
#[tauri::command]
pub fn open_release_page(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    let url = {
        let guard = state
            .update_cache
            .lock()
            .map_err(|_| "update cache lock poisoned")?;
        match guard.as_ref() {
            Some(u) => u.release_url.clone(),
            None => return Err("no cached update — call check_for_update first".into()),
        }
    };

    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(&url, None::<&str>)
        .map_err(|e| format!("failed to open release page: {e}"))
}

// ── Unit tests ──────────────────────────────────────────────────
//
// Tests the input-validation and mapping logic that runs before
// any filesystem or network I/O. The core logic (discovery, swap,
// quota) is tested exhaustively in csq-core; these tests verify
// the IPC boundary catches bad inputs before they reach core code.

#[cfg(test)]
mod tests {
    use super::*;

    // ── list_providers ─────────────────────────────────────────

    #[test]
    fn list_providers_includes_ollama() {
        let providers = list_providers().unwrap();
        let ollama = providers
            .iter()
            .find(|p| p.id == "ollama")
            .expect("ollama should appear in the desktop provider list");
        assert_eq!(ollama.auth_type, "none");
        assert!(ollama.default_base_url.is_some());
    }

    #[test]
    fn list_providers_includes_anthropic() {
        let providers = list_providers().unwrap();
        assert!(providers.iter().any(|p| p.id == "claude"));
    }

    #[test]
    fn list_providers_auth_types_are_valid() {
        let providers = list_providers().unwrap();
        for p in &providers {
            assert!(
                ["oauth", "bearer", "none"].contains(&p.auth_type.as_str()),
                "unexpected auth_type '{}' for provider '{}'",
                p.auth_type,
                p.id
            );
        }
    }

    // ── set_provider_key validation ────────────────────────────
    //
    // These tests exercise the validation that runs before any
    // filesystem access. Each case returns Err before touching disk.

    #[test]
    fn set_provider_key_rejects_unknown_provider() {
        let err = set_provider_key("/fake".into(), "nonexistent".into(), "key".into()).unwrap_err();
        assert!(err.contains("unknown provider"));
    }

    #[test]
    fn set_provider_key_rejects_oauth_provider() {
        let err = set_provider_key("/fake".into(), "claude".into(), "key".into()).unwrap_err();
        assert!(err.contains("uses OAuth"));
    }

    #[test]
    fn set_provider_key_rejects_empty_key() {
        let err = set_provider_key("/fake".into(), "mm".into(), "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn set_provider_key_rejects_oversized_key() {
        let long_key = "x".repeat(5000);
        let err = set_provider_key("/fake".into(), "mm".into(), long_key).unwrap_err();
        assert!(err.contains("too long"));
    }

    // ── bind_keyless_provider validation ───────────────────────

    #[test]
    fn bind_keyless_provider_rejects_unknown_provider() {
        let err = bind_keyless_provider("/fake".into(), "nonexistent".into(), 1, None).unwrap_err();
        assert!(err.contains("unknown provider"));
    }

    #[test]
    fn bind_keyless_provider_rejects_keyed_provider() {
        let err = bind_keyless_provider("/fake".into(), "mm".into(), 1, None).unwrap_err();
        assert!(err.contains("not keyless"), "got: {err}");
    }

    #[test]
    fn bind_keyless_provider_rejects_invalid_slot() {
        let err = bind_keyless_provider("/fake".into(), "ollama".into(), 0, None).unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn bind_keyless_provider_rejects_missing_base_dir() {
        let err = bind_keyless_provider("/nonexistent/base/dir".into(), "ollama".into(), 5, None)
            .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn bind_keyless_provider_rejects_empty_model_override() {
        // An all-whitespace model from the UI dropdown would silently
        // write `ANTHROPIC_MODEL=""` and make CC unusable. Reject
        // before the filesystem write.
        let err = bind_keyless_provider("/fake".into(), "ollama".into(), 1, Some("   ".into()))
            .unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn bind_keyless_provider_ollama_writes_settings() {
        // End-to-end: real temp dir, real ollama bind. Verifies the
        // command writes the slot's settings.json with the placeholder
        // auth token and base URL.
        let dir = tempfile::TempDir::new().unwrap();
        let result = bind_keyless_provider(
            dir.path().to_string_lossy().into_owned(),
            "ollama".into(),
            9,
            None,
        );
        assert!(result.is_ok(), "bind should succeed: {result:?}");

        let settings_path = dir.path().join("config-9/settings.json");
        assert!(settings_path.exists());
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert!(content.contains("\"ANTHROPIC_AUTH_TOKEN\": \"ollama\""));
        assert!(content.contains("localhost:11434"));
    }

    #[test]
    fn bind_keyless_provider_with_model_override_writes_chosen_model() {
        let dir = tempfile::TempDir::new().unwrap();
        bind_keyless_provider(
            dir.path().to_string_lossy().into_owned(),
            "ollama".into(),
            11,
            Some("qwen3:latest".into()),
        )
        .unwrap();

        let content = std::fs::read_to_string(dir.path().join("config-11/settings.json")).unwrap();
        assert!(
            content.contains("\"ANTHROPIC_MODEL\": \"qwen3:latest\""),
            "expected model override in settings, got: {content}"
        );
    }

    #[test]
    fn list_ollama_models_returns_vec() {
        // Can't assume Ollama is installed in CI — just assert the
        // command returns Ok (possibly empty). Exhaustive parsing
        // tests live in csq_core::providers::ollama.
        let result = list_ollama_models();
        assert!(result.is_ok());
    }

    // ── rename_account validation ──────────────────────────────

    #[test]
    fn rename_account_rejects_invalid_account_number() {
        let err = rename_account("/fake".into(), 0, "test".into()).unwrap_err();
        assert!(err.contains("invalid account"));
    }

    #[test]
    fn rename_account_rejects_empty_name() {
        let err = rename_account("/fake".into(), 1, "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    // ── swap_account validation ────────────────────────────────

    #[test]
    fn swap_account_rejects_account_zero() {
        let err = swap_account("/fake".into(), 0).unwrap_err();
        assert!(err.contains("invalid account"));
    }

    // ── ClaudeLoginView conversion ─────────────────────────────

    #[test]
    fn claude_login_view_from_login_request() {
        let req = LoginRequest {
            auth_url: "https://example.com/auth".into(),
            state: "state123".into(),
            account: 5,
            expires_in_secs: 600,
        };
        let view = ClaudeLoginView::from(req);
        assert_eq!(view.auth_url, "https://example.com/auth");
        assert_eq!(view.state, "state123");
        assert_eq!(view.account, 5);
        assert_eq!(view.expires_in_secs, 600);
    }
}
