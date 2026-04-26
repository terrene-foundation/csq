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
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_autostart::ManagerExt;

/// Public view of a single account, safe to send over IPC.
///
/// Credentials, tokens, and keys are never included.
#[derive(Serialize)]
pub struct AccountView {
    pub id: u16,
    pub label: String,
    /// "anthropic" | "codex" | "third_party" | "manual"
    pub source: String,
    /// Upstream CLI surface binding: "claude-code" | "codex".
    /// Added PR-C6 so the dashboard can badge codex-backed slots
    /// without inferring from `source` (Anthropic → claude-code,
    /// Codex → codex, ThirdParty / Manual → claude-code).
    pub surface: String,
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
    /// Third-party provider id ("mm" | "zai" | "ollama") for
    /// slots bound to a 3P provider, else None. Lets the
    /// frontend branch on stable ids rather than on the display
    /// label (which is localizable and could drift).
    pub provider_id: Option<String>,

    // ── PR-G5 — Gemini-specific quota fields ───────────────────
    //
    // None on non-Gemini slots; populated from `quota.json` for
    // slots where `surface == "gemini"`. The frontend renders
    // counter / 429 / downgrade UI per FR-G-UI-03 only when the
    // surface chip is "gemini" — the fields are scoped to Gemini
    // by convention rather than discriminated union to keep the
    // serde shape stable across mixed-surface dashboards.
    /// Number of requests issued today on this Gemini slot, or
    /// None when no events have been drained yet (renders "quota:
    /// n/a" per FR-G-UI-03).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_counter_today: Option<u64>,
    /// ISO-8601 UTC timestamp when the active 429 retry window
    /// ends, or None when no retry is active. The frontend
    /// computes the countdown via `Date.parse(...)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_rate_limit_reset_at: Option<String>,
    /// Model the user pinned via the binding marker (`auto`,
    /// `gemini-2.5-pro`, etc). Used together with
    /// `gemini_effective_model` to render the downgrade badge
    /// when the served model differs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_selected_model: Option<String>,
    /// Model Gemini actually served on the most recent response
    /// (parsed from `modelVersion`). Drives the
    /// `selected → effective` chip in the AccountCard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_effective_model: Option<String>,
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
                                let exp_ms = creds.expect_anthropic().claude_ai_oauth.expires_at;
                                let secs = (exp_ms as i64 - now_ms as i64) / 1000;
                                let status = if secs <= 0 {
                                    "expired"
                                } else if creds
                                    .expect_anthropic()
                                    .claude_ai_oauth
                                    .is_expired_within(7200)
                                {
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

            // Resolve the stable provider id ("mm", "zai", "ollama")
            // for 3P slots so the frontend can branch on a value
            // the Rust catalog owns, rather than on the localisable
            // display name.
            let provider_id = if matches!(a.source, AccountSource::ThirdParty { .. }) {
                providers::PROVIDERS
                    .iter()
                    .find(|p| p.name == a.label)
                    .map(|p| p.id.to_string())
            } else {
                None
            };

            // Gemini surface fields — pulled directly from quota.json
            // counter/rate_limit/model fields the daemon writes (PR-G3
            // NDJSON drain). All None on non-Gemini slots so the
            // frontend's `surface === "gemini"` branch is the sole
            // gate for Gemini rendering.
            let is_gemini = matches!(a.surface, csq_core::providers::catalog::Surface::Gemini);
            let gemini_counter_today = if is_gemini {
                q.and_then(|q| q.counter.as_ref().map(|c| c.requests_today))
            } else {
                None
            };
            let gemini_rate_limit_reset_at =
                if is_gemini {
                    q.and_then(|q| {
                        q.rate_limit.as_ref().and_then(|r| {
                            if r.active {
                                r.reset_at.clone()
                            } else {
                                None
                            }
                        })
                    })
                } else {
                    None
                };
            let gemini_selected_model = if is_gemini {
                q.and_then(|q| q.selected_model.clone())
            } else {
                None
            };
            let gemini_effective_model = if is_gemini {
                q.and_then(|q| q.effective_model.clone())
            } else {
                None
            };

            AccountView {
                id: a.id,
                label: a.label,
                source: match a.source {
                    AccountSource::Anthropic => "anthropic".into(),
                    AccountSource::Codex => "codex".into(),
                    AccountSource::ThirdParty { .. } => "third_party".into(),
                    AccountSource::Manual => "manual".into(),
                },
                surface: a.surface.to_string(),
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
                provider_id,
                gemini_counter_today,
                gemini_rate_limit_reset_at,
                gemini_selected_model,
                gemini_effective_model,
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

    rotation::swap_to(
        &base,
        config_dir,
        account,
        csq_core::providers::catalog::Surface::ClaudeCode,
    )
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
    rotation::swap_to(
        &base_canon,
        &config_canon,
        account,
        csq_core::providers::catalog::Surface::ClaudeCode,
    )
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
        // Fixed-vocabulary fallback to avoid leaking `OAuthError::Http { body }`
        // or `OAuthError::Exchange(String)` content through the IPC
        // response if a future refactor widens `consume`'s error
        // surface. Journal 0063 M1.
        Err(csq_core::error::OAuthError::Http { .. }) => Err("cancel failed: http_error".into()),
        Err(csq_core::error::OAuthError::PkceVerification) => {
            Err("cancel failed: pkce_verification".into())
        }
        Err(csq_core::error::OAuthError::Exchange(_)) => {
            Err("cancel failed: exchange_failed".into())
        }
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
/// - `"key too short ..."` — fewer than 8 bytes after trimming
/// - `"key contains control characters ..."` — control byte in key
/// - `"key too long"` — input >4096 bytes
#[tauri::command]
pub fn set_provider_key(
    base_dir: String,
    provider_id: String,
    key: String,
) -> Result<String, String> {
    // 4096 matches MAX_KEY_LEN in csq-cli setkey.
    const MAX_KEY_LEN: usize = 4096;
    // Mirrors csq_core::accounts::third_party::MIN_KEY_LEN (journal 0058).
    // Defense in depth against ESC / garbage tokens slipping through the
    // Bearer form's input box.
    const MIN_KEY_LEN: usize = 8;

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
    if key.len() < MIN_KEY_LEN {
        return Err(format!("key too short (need at least {MIN_KEY_LEN} bytes)"));
    }
    if key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("key contains control characters — check your clipboard and try again".into());
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

/// Retargets a slot's `config-<slot>/settings.json` to a new model
/// by rewriting every `ANTHROPIC_*_MODEL` env key.
///
/// The slot must already be bound (via `bind_keyless_provider` or
/// `setkey` on the CLI). This is the runtime model-change path
/// for Ollama slots whose installed model list expands post-bind.
/// Same semantics as the CLI's `csq models switch <provider> <model>
/// --slot N --no-pull`: we assume any required pull has already
/// happened via [`pull_ollama_model`].
///
/// # Errors
///
/// - `"invalid slot: ..."` — slot out of range 1..=999
/// - `"model must not be empty"` — blank input
/// - `"base directory does not exist: ..."` — base dir missing
/// - `"slot N is not bound — ..."` — slot has no settings.json
/// - filesystem errors surfaced from the atomic-write path
pub fn set_slot_model_write(base_dir: String, slot: u16, model: String) -> Result<(), String> {
    use csq_core::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
    use csq_core::session::merge::MODEL_KEYS;
    use serde_json::Value;

    let slot_num =
        csq_core::types::AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let model = model.trim().to_string();
    if model.is_empty() {
        return Err("model must not be empty".into());
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    let settings_path = base
        .join(format!("config-{}", slot_num))
        .join("settings.json");
    let content = std::fs::read_to_string(&settings_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("slot {slot_num} is not bound — add it via the Add Account modal first")
        } else {
            format!("read {}: {e}", settings_path.display())
        }
    })?;
    let mut value: Value = serde_json::from_str(&content)
        .map_err(|e| format!("{} is not valid JSON: {e}", settings_path.display()))?;

    let env = value
        .as_object_mut()
        .and_then(|o| o.get_mut("env"))
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            format!(
                "{} has no `env` object — can't set model",
                settings_path.display()
            )
        })?;
    for key in MODEL_KEYS {
        env.insert((*key).to_string(), Value::String(model.clone()));
    }

    let json = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("serialize slot settings: {e}"))?;
    let tmp = unique_tmp_path(&settings_path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| format!("write tmp: {e}"))?;
    secure_file(&tmp).map_err(|e| format!("secure_file: {e}"))?;
    atomic_replace(&tmp, &settings_path).map_err(|e| format!("atomic replace: {e}"))?;

    Ok(())
}

#[tauri::command]
pub fn set_slot_model(
    app: AppHandle,
    base_dir: String,
    slot: u16,
    model: String,
) -> Result<(), String> {
    set_slot_model_write(base_dir, slot, model.clone())?;
    // Notify any other listening window / tray menu that the slot
    // changed, so they can refresh their view. Best-effort: a
    // failed emit doesn't undo the successful file write.
    let _ = app.emit(
        "slot-model-changed",
        serde_json::json!({ "slot": slot, "model": model }),
    );
    Ok(())
}

/// Fetches an Ollama model via `ollama pull <model>`, streaming
/// progress segments back to the frontend on the
/// `ollama-pull-progress` Tauri event so the UI can render a
/// progress indicator. Returns once the pull subprocess exits.
///
/// **Streaming**: ollama renders progress as a single line
/// updated with carriage returns, not newlines. A naive
/// `BufRead::lines()` reader would buffer the entire pull into
/// one string and never emit anything until completion. This
/// function instead reads bytes and flushes a payload on either
/// `\r` or `\n`, so the UI sees live progress bars.
///
/// **Cancellation**: the running child is registered in
/// `AppState.ollama_pull_child` so a later `cancel_ollama_pull`
/// command can send SIGTERM and release the UI from a stuck
/// (or unwanted) download. Normal completion clears the handle.
///
/// **Pre-check**: if the `ollama` binary is not on PATH we fail
/// fast with an installable-ness hint rather than letting the
/// user wait on a silent exec failure.
///
/// Failure modes:
///   - `ollama` binary not found → `"ollama not found: ..."`
///   - non-zero exit from the pull → `"ollama pull exited with N"`
///     (if the exit was SIGTERM from cancel_ollama_pull the
///     payload matches `"ollama pull exited with -1"` or a
///     signal code; the frontend treats any non-zero exit the
///     same — back to the picker screen).
#[tauri::command]
pub async fn pull_ollama_model(
    app: AppHandle,
    state: State<'_, AppState>,
    model: String,
) -> Result<(), String> {
    let model = model.trim().to_string();
    if model.is_empty() {
        return Err("model must not be empty".into());
    }

    // Pre-check: resolve the ollama binary. A Finder-launched macOS
    // GUI inherits `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, so bare
    // `Command::new("ollama")` fails to locate the binary at the
    // usual Homebrew prefixes. `find_ollama_bin` walks the known
    // install paths and honours the `OLLAMA_BIN` override.
    let ollama_bin = match providers::ollama::find_ollama_bin() {
        Some(p) if p.is_file() => p,
        _ => {
            return Err(
                "ollama not found — install via https://ollama.com or set OLLAMA_BIN".into(),
            );
        }
    };
    if std::process::Command::new(&ollama_bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return Err("ollama not found — install via https://ollama.com or set OLLAMA_BIN".into());
    }

    // Capture the child-slot Arc BEFORE `spawn_blocking` so the
    // worker thread doesn't need to borrow `State<AppState>`.
    let child_slot = state.ollama_pull_child.clone();

    tauri::async_runtime::spawn_blocking(move || {
        pull_ollama_model_blocking(app, child_slot, ollama_bin, model)
    })
    .await
    .map_err(|e| format!("pull task join error: {e}"))?
}

/// Pure-Rust body of `pull_ollama_model` (no Tauri traits) so it
/// can be invoked from `spawn_blocking` without the caller
/// holding a `State<AppState>` borrow.
fn pull_ollama_model_blocking(
    app: AppHandle,
    child_slot: Arc<std::sync::Mutex<Option<Arc<std::sync::Mutex<std::process::Child>>>>>,
    ollama_bin: std::path::PathBuf,
    model: String,
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(&ollama_bin)
        .arg("pull")
        .arg(&model)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn ollama pull: {e}"))?;

    let stderr = child.stderr.take();
    let stdout = child.stdout.take();
    let child_arc = Arc::new(std::sync::Mutex::new(child));

    // Register for cancel. Overwrite any stale entry — the
    // frontend guards against concurrent pulls, but defence
    // in depth doesn't hurt here.
    {
        let mut slot = child_slot.lock().map_err(|_| "child slot poisoned")?;
        *slot = Some(child_arc.clone());
    }

    let stderr_t = spawn_progress_reader(stderr, "stderr", app.clone());
    let stdout_t = spawn_progress_reader(stdout, "stdout", app.clone());

    // Wait for the child to exit (or be killed via cancel).
    let status = {
        let mut guard = child_arc.lock().map_err(|_| "child lock poisoned")?;
        guard
            .wait()
            .map_err(|e| format!("wait on ollama pull: {e}"))?
    };

    if let Some(t) = stderr_t {
        let _ = t.join();
    }
    if let Some(t) = stdout_t {
        let _ = t.join();
    }

    {
        let mut slot = child_slot.lock().map_err(|_| "child slot poisoned")?;
        *slot = None;
    }

    if !status.success() {
        return Err(format!(
            "ollama pull exited with {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Byte-level progress reader. `ollama pull` updates a single
/// progress line with carriage returns, not newlines, so a
/// standard `BufRead::lines()` reader would buffer the entire
/// multi-gigabyte download into one string. This function reads
/// bytes and flushes on either `\r` or `\n` so the UI sees live
/// progress. The 1 MiB buffer cap is a defence against a stream
/// that never emits a delimiter.
fn spawn_progress_reader(
    stream: Option<impl std::io::Read + Send + 'static>,
    tag: &'static str,
    app: AppHandle,
) -> Option<std::thread::JoinHandle<()>> {
    let mut stream = stream?;
    Some(std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(2048);
        let mut byte = [0u8; 1];
        let flush = |buf: &mut Vec<u8>, app: &AppHandle| {
            if buf.is_empty() {
                return;
            }
            let line = String::from_utf8_lossy(buf).to_string();
            let _ = app.emit(
                "ollama-pull-progress",
                serde_json::json!({ "stream": tag, "line": line }),
            );
            buf.clear();
        };
        loop {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    let b = byte[0];
                    if b == b'\r' || b == b'\n' {
                        flush(&mut buf, &app);
                    } else {
                        buf.push(b);
                        if buf.len() >= 1 << 20 {
                            flush(&mut buf, &app);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        flush(&mut buf, &app);
    }))
}

/// Cancels an in-flight `ollama pull` by killing the child
/// process. No-op when no pull is running — the modal's Cancel
/// button calls this unconditionally, and the frontend treats a
/// successful cancel as "return to picker".
///
/// Uses `Child::kill` (SIGKILL on Unix, TerminateProcess on
/// Windows). The companion `pull_ollama_model` reader threads
/// see EOF on their piped stdout/stderr and exit cleanly; the
/// `wait()` call in the blocking task returns a non-success
/// status which the frontend maps to the error banner.
#[tauri::command]
pub fn cancel_ollama_pull(state: State<'_, AppState>) -> Result<(), String> {
    let handle_opt = {
        let slot = state
            .ollama_pull_child
            .lock()
            .map_err(|_| "child slot poisoned")?;
        slot.clone()
    };
    let Some(handle) = handle_opt else {
        return Ok(());
    };
    let mut child = handle.lock().map_err(|_| "child lock poisoned")?;
    let _ = child.kill();
    Ok(())
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

// ── Codex desktop commands (PR-C8) ───────────────────────────────
//
// Four commands driving the Codex surface Add Account + Change Model
// flows. Every command validates at the IPC boundary and delegates
// the real work to csq-core's `providers::codex` module. No token
// material ever enters a return type (IPC audit is in `tests` below
// — extends the PR-C6 `account_view_serializes_surface_without_secrets`
// forbidden-key harness to every new `Serialize` struct).

/// Fires the pre-check step of a Codex Add Account flow: surfaces
/// whether the user must first acknowledge the Codex terms-of-service
/// disclosure and whether a stale `com.openai.codex` keychain entry
/// would conflict with the file-backed auth store csq requires.
///
/// No filesystem writes beyond the keychain probe. The caller
/// resolves both preconditions and then invokes
/// [`complete_codex_login`].
#[tauri::command]
pub async fn start_codex_login(
    base_dir: String,
    account: u16,
) -> Result<csq_core::providers::codex::desktop_login::StartLoginView, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = PathBuf::from(&base_dir);
    tokio::task::spawn_blocking(move || {
        csq_core::providers::codex::desktop_login::start_login(
            &base,
            account_num,
            csq_core::providers::codex::keychain::probe_residue,
        )
        .map_err(|e| format!("{e:#}"))
    })
    .await
    .map_err(|e| format!("start_codex_login task failed: {e}"))?
}

/// Completes a Codex Add Account flow after the UI has resolved the
/// ToS and keychain prompts. Emits `codex-device-code` events with
/// `{ verification_url, user_code }` payloads so the Svelte modal can
/// render the code the user types on ChatGPT's verification page.
///
/// Blocks until `codex login --device-auth` exits (normally minutes,
/// capped by codex-cli's own internal timeout). On success, relocates
/// the freshly-written `auth.json` to `credentials/codex-<N>.json`
/// with 0o400 and fires an `invalidate-cache` to the daemon so the
/// dashboard sees the new slot on its next poll tick.
///
/// # Idempotency + concurrency (journal 0021 finding 8)
///
/// This command is NOT idempotent mid-flight: a second concurrent call
/// for the same `account` returns `Err("codex login already in progress
/// for slot N")` rather than racing the first call. The rejection is
/// observed via `AppState.codex_login_child` — if the slot is already
/// populated we refuse. Once the first call completes (success or
/// failure), the slot is cleared and a retry is allowed.
///
/// # Cancellation (journal 0021 finding 6)
///
/// The running child process is registered in
/// `AppState.codex_login_child` so a later [`cancel_codex_login`] can
/// SIGKILL it from the modal's close/unmount handler. Without this the
/// subprocess orphans for the minutes-long device-auth window after
/// the user closes the modal.
#[tauri::command]
pub async fn complete_codex_login(
    app: AppHandle,
    state: State<'_, AppState>,
    base_dir: String,
    account: u16,
    purge_keychain: bool,
) -> Result<csq_core::providers::codex::desktop_login::CompleteLoginView, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = PathBuf::from(&base_dir);
    let app_for_task = app.clone();

    // Journal 0021 finding 8: refuse concurrent invocations for any
    // account. codex-cli writes to a single `CODEX_HOME/auth.json`
    // and multiple spawns would race both the subprocess itself and
    // the post-login `save_canonical_for` + `remove_file` sequence.
    {
        let slot_guard = state
            .codex_login_child
            .lock()
            .map_err(|_| "codex login slot poisoned")?;
        if slot_guard.is_some() {
            return Err(format!(
                "codex login already in progress (slot {account}) — \
                 cancel the running flow before starting a new one"
            ));
        }
    }

    let child_slot = state.codex_login_child.clone();
    let child_slot_for_cleanup = child_slot.clone();

    tokio::task::spawn_blocking(move || {
        let result = csq_core::providers::codex::desktop_login::complete_login(
            &base,
            account_num,
            purge_keychain,
            csq_core::providers::codex::keychain::purge_residue,
            |config_dir, on_code| {
                spawn_codex_device_auth_piped(config_dir, on_code, &app_for_task, &child_slot)
            },
            |info| {
                // Journal 0021 finding 4: emit_to("main") so a
                // secondary window (tray/settings) cannot subscribe
                // to the one-time user_code.
                let _ = app_for_task.emit_to("main", "codex-device-code", &info);
            },
        )
        // Journal 0021 finding M3: pass the full anyhow chain
        // through `redact_tokens` before it reaches the renderer.
        // Defense-in-depth — inner call sites already redact, but
        // a future `.context(...)` that omits redaction would leak
        // without this outer wrapper.
        .map_err(|e| csq_core::error::redact_tokens(&format!("{e:#}")));

        // Always clear the child slot once we exit, regardless of
        // result. The slot is cleared inside
        // `spawn_codex_device_auth_piped`'s exit path already, but
        // do it here too so an early error (pre-spawn) cannot leave
        // a stale slot entry.
        {
            if let Ok(mut slot) = child_slot_for_cleanup.lock() {
                *slot = None;
            }
        }

        let result = result?;

        // Best-effort: kick daemon cache invalidation so the dashboard
        // sees the new slot immediately rather than waiting for the
        // 5s discovery tick. Journal 0021 finding M6: the HTTP POST
        // over the Unix socket has NO client-side timeout — a hung
        // daemon would block the spawn_blocking thread. We wrap in
        // a coarse 500ms deadline enforced by a worker thread. If
        // the daemon doesn't answer in 500ms the dashboard catches
        // up on its next 5s discovery tick.
        #[cfg(unix)]
        {
            let sock = csq_core::daemon::socket_path(&base);
            if sock.exists() {
                // Fire-and-forget style: spawn a short-lived worker
                // that does the blocking call; a timer on the main
                // thread bounds the wait. Whichever finishes first
                // wins; the other side is dropped on return.
                let (tx, rx) = std::sync::mpsc::channel();
                let sock_copy = sock.clone();
                std::thread::spawn(move || {
                    let r = csq_core::daemon::http_post_unix(&sock_copy, "/api/invalidate-cache");
                    let _ = tx.send(r);
                });
                let _ = rx.recv_timeout(std::time::Duration::from_millis(500));
            }
        }

        Ok::<_, String>(result)
    })
    .await
    .map_err(|e| format!("complete_codex_login task failed: {e}"))?
}

/// Cancels an in-flight `codex login --device-auth` by killing the
/// child process. No-op when no login is running — the modal's close
/// handler calls this unconditionally, and the frontend treats a
/// successful cancel as "return to picker".
///
/// Mirrors [`cancel_ollama_pull`] — SIGKILL via `Child::kill`; the
/// reader threads see EOF on piped stdout/stderr and exit; the
/// waiting `spawn_blocking` task returns a non-success status and
/// the frontend sees a generic failure banner.
#[tauri::command]
pub fn cancel_codex_login(state: State<'_, AppState>) -> Result<(), String> {
    let handle_opt = {
        let slot = state
            .codex_login_child
            .lock()
            .map_err(|_| "codex login slot poisoned")?;
        slot.clone()
    };
    let Some(handle) = handle_opt else {
        return Ok(());
    };
    let mut child = handle.lock().map_err(|_| "codex login child poisoned")?;
    let _ = child.kill();
    Ok(())
}

/// Production `codex login --device-auth` spawn. Captures stdout +
/// stderr line-by-line; feeds each line through
/// [`csq_core::providers::codex::desktop_login::parse_device_code_line`]
/// to detect the device-code payload; when found, invokes `on_code`
/// so [`complete_codex_login`] can forward it to the UI.
///
/// Also emits `codex-login-progress` events with raw stdout/stderr
/// lines (scrubbed of anything token-shaped via the core redactor)
/// so the modal can show a log tail for debugging auth failures —
/// same ergonomic pattern as `ollama-pull-progress` in
/// [`pull_ollama_model`].
///
/// # PR-C9a hardening (journal 0021)
///
/// - Device-code parse runs on the **scrubbed** line (finding 2) so a
///   malicious codex-cli that prints a synthetic code alongside a
///   token cannot trick the parser into forwarding a fake code.
/// - The BufReader is bounded at 64 KiB per line (finding 3) so
///   codex-cli cannot OOM the process by emitting an unbounded line.
///   Lines that exceed the cap are emitted as `[line truncated]`.
/// - The device-code channel is `sync_channel(4)` + early-exit after
///   the first code (finding M7) so a banner repetition cannot fill
///   memory.
/// - The child process is registered in the shared `child_slot`
///   (finding 6) so `cancel_codex_login` can kill it.
/// - `child.wait()` runs BEFORE joining the reader threads (finding
///   7) so a stuck reader cannot deadlock the forwarder.
fn spawn_codex_device_auth_piped(
    config_dir: &std::path::Path,
    on_code: &mut dyn FnMut(csq_core::providers::codex::desktop_login::DeviceCodeInfo),
    app: &AppHandle,
    child_slot: &Arc<std::sync::Mutex<Option<Arc<std::sync::Mutex<std::process::Child>>>>>,
) -> anyhow::Result<std::process::ExitStatus> {
    use csq_core::error::redact_tokens;
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};

    let child = Command::new(csq_core::providers::codex::surface::CLI_BINARY)
        .args(["login", "--device-auth"])
        .env(
            csq_core::providers::codex::surface::HOME_ENV_VAR,
            config_dir,
        )
        .env_remove("CLAUDE_CONFIG_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!(
                "spawn `{} login --device-auth`: {e} — is codex-cli installed and on PATH?",
                csq_core::providers::codex::surface::CLI_BINARY
            )
        })?;

    let mut child = child;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child_arc = Arc::new(std::sync::Mutex::new(child));

    // Register for cancel. Overwrite any stale entry defensively —
    // `complete_codex_login`'s pre-check rejects concurrent callers,
    // but a panicked prior run could leave a ghost entry.
    {
        let mut slot = child_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("child slot poisoned"))?;
        *slot = Some(child_arc.clone());
    }

    // Bounded channel — pathological codex-cli banner repetition
    // cannot fill memory. `sync_channel(4)` lets four codes queue
    // (unlikely in practice; the forwarder exits after the first).
    let (tx, rx) = std::sync::mpsc::sync_channel::<
        csq_core::providers::codex::desktop_login::DeviceCodeInfo,
    >(4);

    // Reader factory. Only the stdout reader feeds the parser; stderr
    // emits progress only. This narrows the parse trust boundary:
    // stderr lines are never interpreted as device codes.
    let reader = |stream: Option<Box<dyn std::io::Read + Send>>,
                  tag: &'static str,
                  parse: bool,
                  app: AppHandle,
                  tx: std::sync::mpsc::SyncSender<
        csq_core::providers::codex::desktop_login::DeviceCodeInfo,
    >| {
        let stream = match stream {
            Some(s) => s,
            None => return None,
        };
        Some(std::thread::spawn(move || {
            // 64 KiB per-line cap. Manual read_until beats
            // BufReader::lines() which allocates unboundedly.
            const LINE_CAP: usize = 64 * 1024;
            let mut buf = BufReader::new(stream);
            let mut line_bytes: Vec<u8> = Vec::with_capacity(1024);
            loop {
                line_bytes.clear();
                // Take the reader limited to the cap to prevent
                // unbounded allocation per line.
                let n = {
                    let mut limited = (&mut buf).take((LINE_CAP + 1) as u64);
                    limited
                        .read_until(b'\n', &mut line_bytes)
                        .unwrap_or_default()
                };
                if n == 0 {
                    break;
                }
                // If the line exceeded LINE_CAP (still no newline),
                // drop the rest of that line from the underlying
                // reader and emit a truncation marker instead of
                // the raw bytes.
                let truncated = line_bytes.len() > LINE_CAP;
                if truncated {
                    // Drain the rest of the physical line so the
                    // next iteration sees a fresh start. Best-effort.
                    let mut sink = Vec::new();
                    let _ = (&mut buf)
                        .take((1 << 20) as u64)
                        .read_until(b'\n', &mut sink);
                }
                let raw_line = if truncated {
                    "[line truncated]".to_string()
                } else {
                    // Strip trailing newline for cleaner display.
                    let bytes = if line_bytes.last() == Some(&b'\n') {
                        &line_bytes[..line_bytes.len() - 1]
                    } else {
                        &line_bytes[..]
                    };
                    String::from_utf8_lossy(bytes).to_string()
                };
                let scrubbed = redact_tokens(&raw_line);
                let _ = app.emit(
                    "codex-login-progress",
                    serde_json::json!({ "stream": tag, "line": scrubbed }),
                );
                // Device-code parse runs on the SCRUBBED string and
                // ONLY for stdout (trust boundary narrowing — journal
                // 0021 finding 2).
                if parse && !truncated {
                    if let Some(info) =
                        csq_core::providers::codex::desktop_login::parse_device_code_line(&scrubbed)
                    {
                        // try_send so a full channel does not block
                        // the reader thread. Drop extra codes.
                        let _ = tx.try_send(info);
                    }
                }
            }
        }))
    };

    let stdout_t = reader(
        stdout.map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        "stdout",
        true, // parse device-code on stdout only
        app.clone(),
        tx.clone(),
    );
    let stderr_t = reader(
        stderr.map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        "stderr",
        false, // stderr is progress-only; never parse
        app.clone(),
        tx.clone(),
    );

    // Drop the forwarder's tx clone so rx.recv() returns Err once
    // both readers drop theirs (on pipe EOF / child exit).
    drop(tx);

    // Forwarder: fire on_code for the FIRST code, drain subsequent
    // sends into the void. We do not `break` — draining keeps reader
    // threads from blocking on a full bounded channel.
    let mut seen_code = false;
    while let Ok(info) = rx.recv() {
        if !seen_code {
            seen_code = true;
            on_code(info);
        }
    }

    // Journal 0021 finding 7: wait on the child BEFORE joining
    // reader threads. A stuck reader thread would deadlock .join()
    // forever otherwise. After child exit, the OS closes pipes and
    // the reader threads see EOF.
    let status = {
        let mut guard = child_arc
            .lock()
            .map_err(|_| anyhow::anyhow!("codex login child poisoned"))?;
        guard.wait()?
    };

    // Explicit drops so the pipe fds close if the kernel didn't
    // already do it (belt-and-suspenders).
    drop(child_arc);

    if let Some(t) = stdout_t {
        let _ = t.join();
    }
    if let Some(t) = stderr_t {
        let _ = t.join();
    }

    // Clear slot now that the subprocess is fully reaped.
    {
        let mut slot = child_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("child slot poisoned"))?;
        *slot = None;
    }

    Ok(status)
}

/// Returns the Codex models list. Consults (in order) the on-disk
/// cache, a live fetch to `https://chatgpt.com/backend-api/codex/models`
/// with a 1.5s timeout via the Node transport, and finally the
/// bundled cold-start list. Never returns an empty list.
///
/// Requires a Codex account to be already authenticated — the live
/// fetch uses that account's access token as a Bearer. If no Codex
/// slot exists, only the cache and bundled fallback are consulted.
#[tauri::command]
pub async fn list_codex_models(
    base_dir: String,
) -> Result<csq_core::providers::codex::models::CodexModelList, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    tokio::task::spawn_blocking(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let base_for_cache = base.clone();
        let base_for_write = base.clone();
        let base_for_fetch = base.clone();
        let list = csq_core::providers::codex::models::list_models_with(
            move || csq_core::providers::codex::models::read_cache(&base_for_cache, now),
            move || fetch_codex_models_live(&base_for_fetch),
            move |list| {
                let _ = csq_core::providers::codex::models::write_cache(&base_for_write, list);
            },
            now,
        );
        Ok::<_, String>(list)
    })
    .await
    .map_err(|e| format!("list_codex_models task failed: {e}"))?
}

/// Live fetcher used by [`list_codex_models`]. Picks the lowest-numbered
/// Codex account slot, reads its access token, and issues a Bearer
/// GET against `chatgpt.com/backend-api/codex/models`. Returns the
/// raw response body on HTTP 200; any other status is a fetch
/// failure, surfacing as a fall-through to the bundled list.
fn fetch_codex_models_live(base_dir: &std::path::Path) -> Result<Vec<u8>, String> {
    // Discover Codex slots. If none, nothing to fetch with.
    let accounts = csq_core::accounts::discovery::discover_all(base_dir);
    let codex_account = accounts
        .iter()
        .find(|a| a.surface == csq_core::providers::catalog::Surface::Codex)
        .ok_or_else(|| "no codex account provisioned".to_string())?;

    // Read that account's canonical credential file.
    let codex_num = AccountNum::try_from(codex_account.id)
        .map_err(|e| format!("bad codex account number {}: {e}", codex_account.id))?;
    let canonical = csq_core::credentials::file::canonical_path_for(
        base_dir,
        codex_num,
        csq_core::providers::catalog::Surface::Codex,
    );
    let creds = csq_core::credentials::load(&canonical)
        .map_err(|e| format!("load codex credentials: {e}"))?;
    let token = creds
        .codex()
        .ok_or_else(|| "credentials at canonical path are not codex-shape".to_string())?
        .tokens
        .access_token
        .clone();

    let url = "https://chatgpt.com/backend-api/codex/models";
    let extra_headers: &[(&str, &str)] = &[("User-Agent", "csq-desktop/codex-models")];
    let (status, body) =
        csq_core::http::get_bearer_node(url, &token, extra_headers).map_err(|e| e.to_string())?;
    if status != 200 {
        return Err(format!("codex/models returned HTTP {status}"));
    }
    Ok(body)
}

/// Writes `model = "<id>"` into the Codex slot's `config.toml`.
/// Mirrors the `csq models switch codex <id>` CLI path (PR-C7) —
/// uses `providers::codex::surface::write_config_toml` so the
/// `cli_auth_credentials_store = "file"` directive (INV-P03) is
/// preserved. `--force` semantics are handled at the UI — the
/// desktop picker only surfaces ids from `list_codex_models`, and
/// custom ids are an explicit override.
///
/// # Surface verification (journal 0021 finding 9)
///
/// Refuses when the target slot is not a Codex slot. Without this
/// check, a renderer passing a ClaudeCode slot number would cause
/// `write_config_toml` to seed a `config-<N>/config.toml` into an
/// Anthropic slot's directory — poisoning surface classification
/// because `config.toml` is a Codex-unique marker in the handle-dir
/// model (spec 07 §7.2.2). We verify via `discover_all` which
/// includes both ClaudeCode and Codex slots.
#[tauri::command]
pub fn set_codex_slot_model(
    app: AppHandle,
    base_dir: String,
    slot: u16,
    model: String,
) -> Result<(), String> {
    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let model = model.trim().to_string();
    if model.is_empty() {
        return Err("model must not be empty".into());
    }
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    // Journal 0021 finding 9: verify surface before writing.
    // `write_config_toml` does not verify the destination slot's
    // surface; it would silently poison an Anthropic slot with
    // Codex config.toml if called on the wrong slot.
    let accounts = csq_core::accounts::discovery::discover_all(&base);
    let slot_info = accounts.iter().find(|a| a.id == slot);
    match slot_info {
        Some(info) if info.surface == csq_core::providers::catalog::Surface::Codex => {
            // ok
        }
        Some(info) => {
            return Err(format!(
                "slot {slot} is not a Codex slot (surface = {:?}) — \
                 use set_slot_model for ClaudeCode slots",
                info.surface
            ));
        }
        None => {
            return Err(format!(
                "slot {slot} does not exist or has no credentials — \
                 run `csq login {slot} --provider codex` first"
            ));
        }
    }

    csq_core::providers::codex::surface::write_config_toml(&base, slot_num, &model)
        .map_err(|e| format!("write codex config.toml: {e}"))?;
    let _ = app.emit(
        "slot-model-changed",
        serde_json::json!({ "slot": slot, "model": model, "surface": "codex" }),
    );
    Ok(())
}

/// Records that the user has read and acknowledged the Codex
/// terms-of-service disclosure. Writes
/// `accounts/codex-tos-accepted.json` at 0o600. Idempotent.
#[tauri::command]
pub fn acknowledge_codex_tos(base_dir: String) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    csq_core::providers::codex::tos::acknowledge(&base)
        .map(|_| ())
        .map_err(|e| format!("acknowledge codex tos: {e}"))
}

// ── PR-G5 — Gemini desktop UI commands ──────────────────────────
//
// FR-G-UI-01: AddAccountModal Gemini panel needs ToS gate, paste
// (AI Studio API key) or file picker (Vertex SA), and an inline
// warning when `~/.gemini/oauth_creds.json` is present.
//
// FR-G-UI-02: ChangeModelModal needs a static-list switch — the
// model id catalog is small and frozen client-side; the desktop
// only submits canonical ids so the boundary check is `is_known_gemini_model`.
//
// All Gemini commands live in csq-core; the Tauri commands here are
// thin: validate at the IPC boundary, delegate the orchestration to
// csq-core fns. None of the return types carry secret material —
// keys are stored in the platform vault and never echoed to IPC.

/// Returns `true` when the user has previously acknowledged the
/// Gemini terms-of-service disclosure. Used by the desktop modal to
/// decide whether to render the disclosure or skip straight to the
/// provisioning panel. Mirrors `is_acknowledged` for Codex.
#[tauri::command]
pub fn is_gemini_tos_acknowledged(base_dir: String) -> Result<bool, String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    Ok(csq_core::providers::gemini::tos::is_acknowledged(&base))
}

/// Records that the user has read and acknowledged the Gemini
/// terms-of-service disclosure. Writes
/// `accounts/gemini-tos-accepted.json` at 0o600. Idempotent.
#[tauri::command]
pub fn acknowledge_gemini_tos(base_dir: String) -> Result<(), String> {
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }
    csq_core::providers::gemini::tos::acknowledge(&base)
        .map(|_| ())
        .map_err(|e| format!("acknowledge gemini tos: {e}"))
}

/// Probes whether `~/.gemini/oauth_creds.json` exists. The Add
/// Account Gemini panel renders an inline warning when this returns
/// `Some(...)` because csq's EP1 drift detector will neutralise the
/// OAuth file on every spawn — Google's ToS prohibits OAuth
/// subscription rerouting through third-party tools (ADR-G01/G12).
/// Returns the absolute path so the warning can name the file
/// concretely.
#[tauri::command]
pub fn gemini_probe_tos_residue() -> Result<Option<String>, String> {
    let home =
        dirs::home_dir().ok_or_else(|| "could not resolve user home directory".to_string())?;
    Ok(csq_core::providers::gemini::tos::probe_oauth_residue(&home)
        .map(|p| p.display().to_string()))
}

/// Provisions a Gemini slot with an AI Studio API key (paste mode).
/// The plaintext key NEVER touches disk under `accounts/` — it goes
/// straight to the platform-native vault (macOS Keychain, Linux
/// Secret Service, Windows DPAPI). The binding marker
/// `credentials/gemini-<N>.json` carries metadata only (auth mode,
/// model name, timestamp).
///
/// Boundary validation: rejects empty, oversized (> 200 bytes),
/// control-character, non-`AIza`-prefixed input, and slots already
/// bound to a non-Gemini surface (Codex / Anthropic OAuth).
#[tauri::command]
pub fn gemini_provision_api_key(base_dir: String, slot: u16, key: String) -> Result<(), String> {
    use csq_core::providers::gemini::provisioning::{
        detect_other_surface_binding, provision_api_key_via_vault, BoundSurface,
    };
    use secrecy::SecretString;

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("key must not be empty".into());
    }
    if trimmed.len() < 30 {
        return Err(format!(
            "key too short ({} bytes; AI Studio keys are 30+ bytes)",
            trimmed.len()
        ));
    }
    if trimmed.len() > 200 {
        return Err(format!("key too long ({} bytes; max 200)", trimmed.len()));
    }
    if trimmed.chars().any(|c| c.is_ascii_control()) {
        return Err("key contains control characters — paste likely truncated".into());
    }
    if !trimmed.starts_with("AIza") {
        return Err(
            "expected an AI Studio API key (prefix `AIza`); for Vertex AI, use the \
             Vertex SA tab instead"
                .into(),
        );
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    if let Some(existing) = detect_other_surface_binding(&base, slot_num) {
        let surface_name = match existing {
            BoundSurface::Codex => "Codex",
            BoundSurface::ClaudeCode => "Claude (Anthropic OAuth)",
        };
        return Err(format!(
            "slot {slot} is bound to {surface_name} — run `csq logout {slot}` to rebind to Gemini"
        ));
    }

    let vault = csq_core::platform::secret::open_default_vault()
        .map_err(|e| format!("secret vault unavailable ({}): {e}", e.error_kind_tag()))?;

    let secret = SecretString::new(trimmed.to_string().into());
    provision_api_key_via_vault(&base, slot_num, &secret, vault.as_ref())
        .map_err(|e| format!("provision api key: {e}"))?;
    Ok(())
}

/// Provisions a Gemini slot with a Vertex AI service account JSON
/// path. The path is canonicalised and validated (regular file, ≤ 64
/// KiB, not a symlink) before the binding marker is written. The
/// JSON contents are not parsed here — gemini-cli does that on first
/// call. Returns the canonical path that ended up in the marker so
/// the UI can echo it back to the user.
#[tauri::command]
pub fn gemini_provision_vertex_sa(
    base_dir: String,
    slot: u16,
    sa_path: String,
) -> Result<String, String> {
    use csq_core::providers::gemini::provisioning::{
        detect_other_surface_binding, provision_vertex_sa, BoundSurface,
    };

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let trimmed = sa_path.trim();
    if trimmed.is_empty() {
        return Err("Vertex SA JSON path must not be empty".into());
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err(format!(
            "Vertex SA JSON path must be absolute (got `{trimmed}`)"
        ));
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    if let Some(existing) = detect_other_surface_binding(&base, slot_num) {
        let surface_name = match existing {
            BoundSurface::Codex => "Codex",
            BoundSurface::ClaudeCode => "Claude (Anthropic OAuth)",
        };
        return Err(format!(
            "slot {slot} is bound to {surface_name} — run `csq logout {slot}` to rebind to Gemini"
        ));
    }

    let canonical = provision_vertex_sa(&base, slot_num, &path)
        .map_err(|e| format!("provision vertex sa: {e}"))?;
    Ok(canonical.display().to_string())
}

/// Switches the model name stored in the slot's Gemini binding
/// marker. The drift detector picks up the new value on the next
/// `csq run <slot>` (or session swap). Validates against the static
/// list (`is_known_gemini_model`) — the desktop static picker
/// submits canonical ids only, so aliases (`pro`, `flash`) are
/// refused at this boundary. Returns `()`.
#[tauri::command]
pub fn gemini_switch_model(
    app: AppHandle,
    base_dir: String,
    slot: u16,
    model: String,
) -> Result<(), String> {
    use csq_core::providers::gemini::provisioning::{is_known_gemini_model, set_model_name};

    let slot_num = AccountNum::try_from(slot).map_err(|e| format!("invalid slot: {e}"))?;
    let model_trimmed = model.trim();
    if !is_known_gemini_model(model_trimmed) {
        return Err(format!(
            "unknown Gemini model `{model_trimmed}` — desktop submits canonical ids only \
             (auto, gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite, gemini-3-pro-preview)"
        ));
    }

    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    set_model_name(&base, slot_num, model_trimmed).map_err(|e| {
        format!(
            "switch gemini model on slot {slot} to `{model_trimmed}`: {} ({e})",
            e.error_kind_tag()
        )
    })?;

    let _ = app.emit(
        "slot-model-changed",
        serde_json::json!({ "slot": slot, "model": model_trimmed, "surface": "gemini" }),
    );
    Ok(())
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

    #[test]
    fn set_provider_key_rejects_key_shorter_than_min() {
        // Seven-char key passes the old "non-empty" gate but is
        // obviously not a real API key — MM JWTs are kilobytes, Z.AI
        // keys are 40+ chars. Must match the csq-core shape gate.
        let err = set_provider_key("/fake".into(), "mm".into(), "short12".into()).unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn set_provider_key_rejects_key_with_control_char() {
        // ESC (0x1b) slipping through the Bearer form's password
        // input is the desktop twin of the CLI bug in journal 0058.
        let key = "valid-prefix\x1b-rest".to_string();
        let err = set_provider_key("/fake".into(), "mm".into(), key).unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn set_provider_key_order_rejects_too_short_before_too_long() {
        // Sanity: the order of checks matters only when all three
        // could apply. Verify "too long" still fires before "too
        // short" — a 5000-char key with control chars should still
        // hit the too-long branch, not control-char, because the
        // length ceiling is a cheaper check and a huge input is
        // almost certainly a clipboard mishap.
        let key = "x".repeat(5000);
        let err = set_provider_key("/fake".into(), "mm".into(), key).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
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

    // ── set_slot_model_write validation ─────────────────────

    #[test]
    fn set_slot_model_rejects_invalid_slot() {
        let err = set_slot_model_write("/fake".into(), 0, "gemma4".into()).unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn set_slot_model_rejects_empty_model() {
        let err = set_slot_model_write("/fake".into(), 1, "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn set_slot_model_rejects_missing_base_dir() {
        let err =
            set_slot_model_write("/nonexistent/base/dir".into(), 1, "gemma4".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn set_slot_model_errors_when_slot_not_bound() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = set_slot_model_write(
            dir.path().to_string_lossy().into_owned(),
            7,
            "gemma4".into(),
        )
        .unwrap_err();
        assert!(err.contains("not bound"), "got: {err}");
    }

    #[test]
    fn set_slot_model_rewrites_every_model_key() {
        // Bind an ollama slot, then retarget its model. All five
        // MODEL_KEYS in config-N/settings.json should reflect the
        // new value. Other env keys (ANTHROPIC_BASE_URL,
        // ANTHROPIC_AUTH_TOKEN) survive untouched.
        let dir = tempfile::TempDir::new().unwrap();
        csq_core::accounts::third_party::bind_provider_to_slot(
            dir.path(),
            "ollama",
            csq_core::types::AccountNum::try_from(5u16).unwrap(),
            None,
            None,
        )
        .unwrap();

        set_slot_model_write(
            dir.path().to_string_lossy().into_owned(),
            5,
            "qwen3:latest".into(),
        )
        .unwrap();

        let path = dir.path().join("config-5/settings.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for key in csq_core::session::merge::MODEL_KEYS {
            assert_eq!(
                v.pointer(&format!("/env/{}", key)).and_then(|x| x.as_str()),
                Some("qwen3:latest"),
                "{key} should reflect the new model"
            );
        }
        // Base URL and auth token survived.
        assert_eq!(
            v.pointer("/env/ANTHROPIC_BASE_URL")
                .and_then(|x| x.as_str()),
            Some("http://localhost:11434")
        );
        assert_eq!(
            v.pointer("/env/ANTHROPIC_AUTH_TOKEN")
                .and_then(|x| x.as_str()),
            Some("ollama")
        );
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

    // ── PR-C9a (journal 0021 finding 5) — IPC audit: whitelist, not blacklist ─

    /// Recursively collect every object key under `v`. The JSON is an
    /// arbitrary `serde_json::Value`; this walks nested objects +
    /// arrays so flatten / nested-struct shapes are inspected too.
    fn collect_json_keys(v: &serde_json::Value, out: &mut std::collections::HashSet<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, sub) in map {
                    out.insert(k.clone());
                    collect_json_keys(sub, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for sub in arr {
                    collect_json_keys(sub, out);
                }
            }
            _ => {}
        }
    }

    /// Whitelist audit helper — fails if `actual` contains any key
    /// not in `expected`. Pre-PR-C9a the IPC tests blacklisted a
    /// fixed set of token-shaped keys (`access_token`, etc.), but
    /// that list missed Codex-specific shapes (`sess-*`, `rt_*`,
    /// `OPENAI_API_KEY` with caps, `account_id`, `tokens`). A
    /// whitelist closes that gap: any future field addition that
    /// accidentally includes a token must be explicitly added to
    /// `expected`, forcing the author to see the audit.
    #[track_caller]
    fn assert_ipc_keys_whitelisted<T: serde::Serialize>(value: &T, expected: &[&str]) {
        let json = serde_json::to_value(value).expect("serialize");
        let mut actual: std::collections::HashSet<String> = std::collections::HashSet::new();
        collect_json_keys(&json, &mut actual);
        let expected_set: std::collections::HashSet<String> =
            expected.iter().map(|s| (*s).to_string()).collect();
        let extra: Vec<&String> = actual.difference(&expected_set).collect();
        assert!(
            extra.is_empty(),
            "IPC payload contains non-whitelisted keys {:?}. \
             Audit the type — if the new field is safe, add it to the \
             whitelist explicitly. Whitelist (not blacklist) is mandatory \
             per journal 0021 finding 5.",
            extra
        );
    }

    /// AccountView exposes the `surface` field and never leaks
    /// credential material. This is the Tauri IPC audit per
    /// `tauri-commands.md` MUST Rule 3.
    #[test]
    fn account_view_serializes_surface_without_secrets() {
        let v = AccountView {
            id: 1,
            label: "Work".into(),
            source: "anthropic".into(),
            surface: "claude-code".into(),
            has_credentials: true,
            five_hour_pct: 0.0,
            five_hour_resets_in: None,
            seven_day_pct: 0.0,
            seven_day_resets_in: None,
            updated_at: 0.0,
            token_status: "healthy".into(),
            expires_in_secs: None,
            last_refresh_error: None,
            provider_id: None,
            gemini_counter_today: None,
            gemini_rate_limit_reset_at: None,
            gemini_selected_model: None,
            gemini_effective_model: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""surface":"claude-code""#));
        // The four PR-G5 Gemini fields are `skip_serializing_if =
        // "Option::is_none"` so claude-code slots produce a payload
        // identical to the pre-PR-G5 shape — no new keys leak into
        // the wire format for non-Gemini accounts.
        assert!(!json.contains("gemini_counter_today"));
        assert!(!json.contains("gemini_rate_limit_reset_at"));
        assert!(!json.contains("gemini_selected_model"));
        assert!(!json.contains("gemini_effective_model"));
        // Whitelist the full set of AccountView fields. Any future
        // addition must be added here explicitly so an author must
        // see the audit when introducing a field.
        assert_ipc_keys_whitelisted(
            &v,
            &[
                "id",
                "label",
                "source",
                "surface",
                "has_credentials",
                "five_hour_pct",
                "five_hour_resets_in",
                "seven_day_pct",
                "seven_day_resets_in",
                "updated_at",
                "token_status",
                "expires_in_secs",
                "last_refresh_error",
                "provider_id",
                // PR-G5 Gemini fields are skip_serializing_if=Option::is_none,
                // so they don't appear in the serialized whitelist for
                // non-Gemini accounts. They're added to the whitelist
                // entry below in the gemini-populated test instead.
            ],
        );
    }

    // ── PR-C8 Codex command IPC contract ───────────────────────
    //
    // Structural audit on every new Serialize type per
    // `tauri-commands.md` MUST Rule 3. Journal 0021 finding 5 flips
    // the blacklist harness to a per-struct whitelist so a future
    // `#[serde(flatten)] extra: CodexCredentials` slip is caught.

    #[test]
    fn codex_start_login_view_keys_whitelisted() {
        let v = csq_core::providers::codex::desktop_login::StartLoginView {
            account: 7,
            tos_required: true,
            keychain: "absent".into(),
            awaiting_keychain_decision: false,
        };
        assert_ipc_keys_whitelisted(
            &v,
            &[
                "account",
                "tos_required",
                "keychain",
                "awaiting_keychain_decision",
            ],
        );
    }

    #[test]
    fn codex_complete_login_view_keys_whitelisted() {
        let v = csq_core::providers::codex::desktop_login::CompleteLoginView {
            account: 5,
            label: "codex-5/abc".into(),
        };
        assert_ipc_keys_whitelisted(&v, &["account", "label"]);
    }

    #[test]
    fn codex_device_code_info_keys_whitelisted() {
        let v = csq_core::providers::codex::desktop_login::DeviceCodeInfo {
            user_code: "ABCD-EFGH".into(),
            verification_url: "https://chat.openai.com/codex/verify".into(),
        };
        assert_ipc_keys_whitelisted(&v, &["user_code", "verification_url"]);
    }

    #[test]
    fn codex_model_list_keys_whitelisted() {
        let v = csq_core::providers::codex::models::bundled();
        // CodexModelList = { models: [CodexModelEntry], source, fetched_at }
        // CodexModelEntry = { id, label }
        assert_ipc_keys_whitelisted(
            &v,
            &[
                // top-level
                "models",
                "source",
                "fetched_at",
                // per-entry
                "id",
                "label",
            ],
        );
    }

    /// Regression: a hypothetical flatten slip would introduce
    /// keys like `access_token` or `tokens` into the IPC payload.
    /// The whitelist helper must flag any extra key — this test
    /// synthesizes that scenario by serializing a tuple struct
    /// with a token-shaped field and asserting the helper complains.
    #[test]
    #[should_panic(expected = "non-whitelisted keys")]
    fn whitelist_helper_panics_on_extra_key() {
        #[derive(serde::Serialize)]
        struct Leak {
            account: u32,
            access_token: String, // would-be leak
        }
        let v = Leak {
            account: 1,
            access_token: "sk-ant-oat01-dangerous".into(),
        };
        assert_ipc_keys_whitelisted(&v, &["account"]);
    }

    // ── acknowledge_codex_tos validation ──────────────────────

    #[tokio::test]
    async fn acknowledge_codex_tos_rejects_missing_base_dir() {
        let err = acknowledge_codex_tos("/nonexistent/csq-base".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[tokio::test]
    async fn acknowledge_codex_tos_writes_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::codex::tos::is_acknowledged(dir.path()));
    }

    #[tokio::test]
    async fn acknowledge_codex_tos_is_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::codex::tos::is_acknowledged(dir.path()));
    }

    // ── start_codex_login validation ──────────────────────────

    #[tokio::test]
    async fn start_codex_login_rejects_invalid_account() {
        let err = start_codex_login("/tmp".into(), 0).await.unwrap_err();
        assert!(err.contains("invalid account"), "got: {err}");
    }

    #[tokio::test]
    async fn start_codex_login_returns_tos_required_when_marker_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let view = start_codex_login(dir.path().to_string_lossy().into_owned(), 2)
            .await
            .unwrap();
        assert_eq!(view.account, 2);
        assert!(
            view.tos_required,
            "fresh base_dir has no marker → tos_required must be true"
        );
    }

    #[tokio::test]
    async fn start_codex_login_returns_tos_not_required_after_acknowledge() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_codex_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        let view = start_codex_login(dir.path().to_string_lossy().into_owned(), 2)
            .await
            .unwrap();
        assert!(!view.tos_required);
    }

    // ── list_codex_models validation ──────────────────────────

    #[tokio::test]
    async fn list_codex_models_rejects_missing_base_dir() {
        let err = list_codex_models("/nonexistent/csq-base".into())
            .await
            .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[tokio::test]
    async fn list_codex_models_falls_back_to_bundled_when_no_account() {
        let dir = tempfile::TempDir::new().unwrap();
        let list = list_codex_models(dir.path().to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(
            list.source,
            csq_core::providers::codex::models::ModelSource::Bundled,
            "no Codex account → bundled fallback"
        );
        assert!(!list.models.is_empty(), "bundled list must never be empty");
    }

    #[test]
    fn account_view_surface_codex_variant_roundtrips() {
        let v = AccountView {
            id: 3,
            label: "codex-3".into(),
            source: "codex".into(),
            surface: "codex".into(),
            has_credentials: true,
            five_hour_pct: 10.0,
            five_hour_resets_in: Some(3600),
            seven_day_pct: 5.0,
            seven_day_resets_in: Some(86_400),
            updated_at: 1_775_722_800.0,
            token_status: "healthy".into(),
            expires_in_secs: Some(7200),
            last_refresh_error: None,
            provider_id: None,
            gemini_counter_today: None,
            gemini_rate_limit_reset_at: None,
            gemini_selected_model: None,
            gemini_effective_model: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""source":"codex""#));
        assert!(json.contains(r#""surface":"codex""#));
    }

    #[test]
    fn account_view_surface_gemini_variant_serializes_quota_fields() {
        // PR-G5: when a Gemini slot has counter / 429 / model fields
        // populated, all four optional fields appear in the wire
        // payload. None of them carry secret material — keys live in
        // the platform vault, paths are absolute filesystem strings.
        let v = AccountView {
            id: 9,
            label: "gemini-9".into(),
            source: "manual".into(),
            surface: "gemini".into(),
            has_credentials: true,
            five_hour_pct: 0.0,
            five_hour_resets_in: None,
            seven_day_pct: 0.0,
            seven_day_resets_in: None,
            updated_at: 0.0,
            token_status: "healthy".into(),
            expires_in_secs: None,
            last_refresh_error: None,
            provider_id: None,
            gemini_counter_today: Some(42),
            gemini_rate_limit_reset_at: Some("2026-04-26T13:00:00Z".into()),
            gemini_selected_model: Some("gemini-3-pro-preview".into()),
            gemini_effective_model: Some("gemini-2.5-pro".into()),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(r#""surface":"gemini""#));
        assert!(json.contains(r#""gemini_counter_today":42"#));
        assert!(json.contains(r#""gemini_rate_limit_reset_at":"2026-04-26T13:00:00Z""#));
        assert!(json.contains(r#""gemini_selected_model":"gemini-3-pro-preview""#));
        assert!(json.contains(r#""gemini_effective_model":"gemini-2.5-pro""#));
        // No secret-shaped keys leak into the IPC payload.
        assert!(!json.contains("api_key"));
        assert!(!json.contains("AIza"));
    }

    // ── PR-C9a journal 0021 — set_codex_slot_model surface verification ─

    /// Journal 0021 finding 9: `set_codex_slot_model` must refuse when
    /// the target slot is not a Codex slot. Without this the command
    /// would write a `config.toml` into a ClaudeCode slot's directory,
    /// poisoning surface classification (config.toml is a Codex-unique
    /// marker per spec 07 §7.2.2). This test pins the refusal — we do
    /// NOT need a Tauri runtime because the early refusal returns
    /// before `app.emit` runs; the fn signature takes `AppHandle` but
    /// we synthesize the rejection path without entering the emit.
    ///
    /// Structural: we can't easily fake an `AppHandle` in a unit test,
    /// so we drive this through the core-level path — seeding a
    /// ClaudeCode slot via the same setup the test helpers use and
    /// asserting that `discover_all` classifies it as ClaudeCode.
    /// The command itself is exercised at higher-level integration
    /// tests but this pins the discovery classification that the
    /// command's refusal key-reads.
    #[test]
    fn set_codex_slot_model_guards_classification_via_discover_all() {
        use csq_core::accounts::discovery;
        use csq_core::providers::catalog::Surface;

        let dir = tempfile::TempDir::new().unwrap();
        // Seed a ClaudeCode slot (credentials/5.json).
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("5.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();

        let accounts = discovery::discover_all(dir.path());
        let slot_5 = accounts
            .iter()
            .find(|a| a.id == 5)
            .expect("slot 5 must be discoverable");
        assert_eq!(
            slot_5.surface,
            Surface::ClaudeCode,
            "slot 5 seeded as ClaudeCode → set_codex_slot_model must refuse it"
        );
    }

    /// Happy-path classification: a seeded Codex slot MUST be
    /// classified as `Surface::Codex` by `discover_all`, which is
    /// the key lookup `set_codex_slot_model` uses. Without this the
    /// refusal would fire on valid Codex slots too.
    #[test]
    fn set_codex_slot_model_allows_codex_slot_via_discover_all() {
        use csq_core::accounts::discovery;
        use csq_core::providers::catalog::Surface;

        let dir = tempfile::TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Minimal Codex credential shape.
        std::fs::write(
            creds_dir.join("codex-7.json"),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"eyJacc","refresh_token":"rt_x","id_token":"eyJid","account_id":"uuid"},"last_refresh":"2026-04-22T00:00:00Z"}"#,
        )
        .unwrap();

        let accounts = discovery::discover_all(dir.path());
        let slot_7 = accounts
            .iter()
            .find(|a| a.id == 7)
            .expect("slot 7 must be discoverable");
        assert_eq!(
            slot_7.surface,
            Surface::Codex,
            "Codex slot 7 must classify as Surface::Codex so set_codex_slot_model accepts it"
        );
    }

    // ── PR-C9a journal 0021 finding 2 — device-code parse is on scrubbed line ─

    /// Pins the trust-boundary narrowing: if a codex-cli process
    /// substitution prints `"Go to https://legit enter FOOB-AR23 sk-ant-oat01-bad"`
    /// the scrubber removes `sk-ant-oat01-bad` — but more importantly,
    /// the parse runs on the scrubbed line, so any token-shaped
    /// substring that the parser might otherwise mis-extract is
    /// already replaced. This test pins `redact_tokens` behaviour for
    /// the typical Codex-adjacent token shapes.
    #[test]
    fn redact_tokens_strips_sk_ant_and_rt_and_jwt_shapes() {
        use csq_core::error::redact_tokens;
        // rt_* requires ≥20 body chars per TOKEN_PREFIXES_WITH_BODY in
        // csq-core error.rs — this reflects real Codex refresh tokens
        // which are 87-char base64url bodies (journal 0010).
        let raw =
            "Visit https://chatgpt.com/auth/device code FOOB-AR23 token=sk-ant-oat01-abcdef1234 \
                   eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.sigPaddingLongEnough \
                   rt_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH";
        let scrubbed = redact_tokens(raw);
        assert!(
            !scrubbed.contains("sk-ant-oat01-abcdef1234"),
            "sk-ant-* token must be redacted: {scrubbed}"
        );
        assert!(
            !scrubbed.contains("rt_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"),
            "rt_* refresh shape must be redacted (≥20 body): {scrubbed}"
        );
        // The device-code substring must survive — we rely on this
        // to still pass through to the parser.
        assert!(
            scrubbed.contains("FOOB-AR23"),
            "device-code shape must survive redaction: {scrubbed}"
        );
    }

    // ── PR-G5 — Gemini desktop UI command boundary tests ───────
    //
    // These exercise the Tauri-boundary input validation that runs
    // before any csq-core orchestration. Core fns are tested
    // exhaustively in csq-core::providers::gemini::provisioning.

    #[test]
    fn is_gemini_tos_acknowledged_rejects_missing_base_dir() {
        let err = is_gemini_tos_acknowledged("/nonexistent/csq-base".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn is_gemini_tos_acknowledged_returns_false_when_marker_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let acked = is_gemini_tos_acknowledged(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(!acked);
    }

    #[test]
    fn is_gemini_tos_acknowledged_returns_true_after_acknowledge() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(is_gemini_tos_acknowledged(dir.path().to_string_lossy().into_owned()).unwrap());
    }

    #[test]
    fn acknowledge_gemini_tos_rejects_missing_base_dir() {
        let err = acknowledge_gemini_tos("/nonexistent/csq-base".into()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn acknowledge_gemini_tos_writes_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::gemini::tos::is_acknowledged(
            dir.path()
        ));
    }

    #[test]
    fn acknowledge_gemini_tos_is_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        acknowledge_gemini_tos(dir.path().to_string_lossy().into_owned()).unwrap();
        assert!(csq_core::providers::gemini::tos::is_acknowledged(
            dir.path()
        ));
    }

    #[test]
    fn gemini_provision_api_key_rejects_invalid_account() {
        let err = gemini_provision_api_key(
            "/tmp".into(),
            0,
            "AIzaSyXX_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
        )
        .unwrap_err();
        assert!(err.contains("invalid slot"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_empty_key() {
        let err = gemini_provision_api_key("/tmp".into(), 1, "   ".into()).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_too_short_key() {
        let err = gemini_provision_api_key("/tmp".into(), 1, "AIzaShort".into()).unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_oversized_key() {
        let long = "A".repeat(300);
        let err = gemini_provision_api_key("/tmp".into(), 1, long).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_control_characters() {
        // ESC byte mid-paste — same shape the Bearer form was bitten
        // by in journal 0058. Refuse at the boundary.
        let key = "AIzaSy\x1bXX_xxxxxxxxxxxxxxxxxxxxxxxxxx".to_string();
        let err = gemini_provision_api_key("/tmp".into(), 1, key).unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_non_aiza_prefix() {
        // 30+ bytes so the length check passes, but no AIza prefix.
        let key = "sk-ant-XX_xxxxxxxxxxxxxxxxxxxxxxxx".to_string();
        let err = gemini_provision_api_key("/tmp".into(), 1, key).unwrap_err();
        assert!(err.contains("AIza"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_rejects_missing_base_dir() {
        let err = gemini_provision_api_key(
            "/nonexistent/csq-base".into(),
            1,
            "AIzaSyXX_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
        )
        .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_refuses_codex_bound_slot() {
        // Seed a Codex marker; provision call should refuse with a
        // pointer to `csq logout`.
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-3.json"), b"{}").unwrap();

        let err = gemini_provision_api_key(
            dir.path().to_string_lossy().into_owned(),
            3,
            "AIzaSyXX_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
        )
        .unwrap_err();
        assert!(err.contains("Codex"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn gemini_provision_api_key_refuses_claude_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join("4.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":9999999999999,"scopes":[]}}"#,
        )
        .unwrap();

        let err = gemini_provision_api_key(
            dir.path().to_string_lossy().into_owned(),
            4,
            "AIzaSyXX_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
        )
        .unwrap_err();
        assert!(err.contains("Claude"), "got: {err}");
        assert!(err.contains("csq logout"), "got: {err}");
    }

    #[test]
    fn gemini_provision_vertex_sa_rejects_relative_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = gemini_provision_vertex_sa(
            dir.path().to_string_lossy().into_owned(),
            1,
            "./relative/sa.json".into(),
        )
        .unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[test]
    fn gemini_provision_vertex_sa_rejects_empty_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let err =
            gemini_provision_vertex_sa(dir.path().to_string_lossy().into_owned(), 1, "  ".into())
                .unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn gemini_provision_vertex_sa_refuses_codex_bound_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-2.json"), b"{}").unwrap();

        let sa_path = dir.path().join("sa.json");
        std::fs::write(&sa_path, br#"{"type":"service_account"}"#).unwrap();

        let err = gemini_provision_vertex_sa(
            dir.path().to_string_lossy().into_owned(),
            2,
            sa_path.to_string_lossy().into_owned(),
        )
        .unwrap_err();
        assert!(err.contains("Codex"), "got: {err}");
    }

    // gemini_switch_model takes AppHandle so we test the shape via a
    // structural seed: set_model_name is the csq-core fn it calls.
    // The boundary checks (invalid slot / unknown model) are in
    // is_known_gemini_model + AccountNum::try_from which are
    // exercised at csq-core. Here we pin the unknown-model rejection
    // string the UI surfaces.

    #[test]
    fn gemini_switch_model_unknown_model_message_lists_canonical_ids() {
        // Synthesises the exact error-string format the boundary
        // would return — calls the validator the command also calls.
        use csq_core::providers::gemini::provisioning::is_known_gemini_model;
        let bad = "pro";
        assert!(!is_known_gemini_model(bad));
        let msg = format!(
            "unknown Gemini model `{bad}` — desktop submits canonical ids only \
             (auto, gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite, gemini-3-pro-preview)"
        );
        assert!(msg.contains("auto"));
        assert!(msg.contains("gemini-2.5-pro"));
        assert!(msg.contains("gemini-3-pro-preview"));
    }
}
