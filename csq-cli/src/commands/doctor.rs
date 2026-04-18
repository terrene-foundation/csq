//! `csq doctor` — diagnostic report for troubleshooting.
//!
//! Checks binary version, daemon status, account health, Claude Code
//! installation, settings.json configuration, platform info, and
//! legacy terminal detection (CC sessions using old `config-N` dirs
//! instead of `term-<pid>` handle dirs).
//! Outputs color-coded text by default, or structured JSON with `--json`.

use anyhow::Result;
use csq_core::accounts::{discovery, AccountSource};
use csq_core::broker::fanout;
use csq_core::credentials::file as cred_file;
use csq_core::platform::process::is_pid_alive;
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct DoctorReport {
    version: String,
    platform: PlatformInfo,
    claude_code: ClaudeCodeInfo,
    js_runtime: JsRuntimeInfo,
    settings: SettingsInfo,
    daemon: DaemonInfo,
    accounts: AccountsInfo,
    broker_failed: BrokerFailedInfo,
    mixed_state_slots: MixedStateInfo,
    terminals: TerminalInfo,
    resurrections: ResurrectionInfo,
}

/// Whether a JS runtime (`node` or `bun`) is available for the
/// Anthropic HTTP subprocess path. `reqwest/rustls` is blocked by
/// Cloudflare's JA3/JA4 fingerprint (journal 0056), so the token
/// refresher and usage poller shell out via Node — without one the
/// daemon cannot refresh OAuth tokens or pull quota.
#[derive(Serialize)]
struct JsRuntimeInfo {
    found: bool,
    path: Option<String>,
}

/// One slot that has BOTH a 3P `config-N/settings.json` env block
/// AND a valid OAuth `credentials/N.json`. This is an inconsistent
/// state usually caused by partial recovery: e.g. `csq login N` ran
/// but the pre-existing 3P env block was not stripped, so CC still
/// routes to the 3P endpoint despite having OAuth creds. Resolve by
/// running `csq login N` on a build that includes the automatic
/// unbind (PR #130) or manually removing the env block.
#[derive(Serialize)]
struct MixedStateSlot {
    account: u16,
    provider: String,
}

#[derive(Serialize)]
struct MixedStateInfo {
    count: usize,
    entries: Vec<MixedStateSlot>,
}

/// Counts of canonical-credentials resurrection events the daemon
/// has recorded in `.resurrection-log.jsonl`. Non-zero means the
/// refresher found at least one account whose `credentials/N.json`
/// was missing and had to rebuild it from `config-N/.credentials.json`
/// — evidence that something in the write path is orphaning live
/// files without mirroring to canonical. Operators should investigate
/// recent write paths (login, Add Account, imports) when this is > 0.
#[derive(Serialize)]
struct ResurrectionInfo {
    /// Total breadcrumb records found.
    total: usize,
    /// Number of distinct accounts that have been resurrected.
    distinct_accounts: usize,
    /// Unix seconds of the most recent resurrection event, if any.
    last_timestamp_secs: Option<u64>,
    /// Sample of the most recent account IDs (up to 5) for the
    /// operator to start their investigation. Intentionally not
    /// the whole list — if there are hundreds the doctor output
    /// would become unreadable.
    recent_accounts: Vec<u16>,
}

/// Information about running CC terminals (legacy vs modern handle-dir).
#[derive(Serialize)]
struct TerminalInfo {
    /// Number of `term-<pid>` handle dirs with a living PID.
    modern_count: usize,
    /// Number of `config-N` directories that appear to have an active legacy
    /// CC session (credentials file is NOT a symlink, meaning it is a real
    /// file from the pre-handle-dir era).
    legacy_count: usize,
    /// Whether process enumeration was available on this platform.
    /// On Windows this is always false; on Unix it depends on fs access.
    check_available: bool,
}

#[derive(Serialize)]
struct PlatformInfo {
    os: String,
    arch: String,
}

#[derive(Serialize)]
struct ClaudeCodeInfo {
    found: bool,
    path: Option<String>,
    version: Option<String>,
}

#[derive(Serialize)]
struct SettingsInfo {
    exists: bool,
    statusline_configured: bool,
    statusline_command: Option<String>,
}

#[derive(Serialize)]
struct DaemonInfo {
    /// One of: "healthy", "pid_alive_no_socket", "stale", "unhealthy", "not running",
    /// "not supported".
    status: String,
    pid: Option<u32>,
    /// Whether the daemon socket responded to the health check. `None` when
    /// the daemon is not running or the platform does not support detection.
    socket_healthy: Option<bool>,
}

/// One account whose broker has set the LOGIN-NEEDED sentinel.
#[derive(Serialize)]
struct BrokerFailedEntry {
    account: u16,
    reason: String,
}

/// Summary of broker-failed sentinel files found under
/// `credentials/N.broker-failed`.
#[derive(Serialize)]
struct BrokerFailedInfo {
    /// Number of accounts with a broker-failed sentinel.
    count: usize,
    /// Per-account details (account number + reason tag).
    entries: Vec<BrokerFailedEntry>,
}

#[derive(Serialize)]
struct AccountsInfo {
    total: usize,
    with_credentials: usize,
    expired: usize,
}

pub fn handle(base_dir: &Path, json: bool) -> Result<()> {
    let report = build_report(base_dir);

    if json {
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }

    print_report(&report);
    Ok(())
}

fn build_report(base_dir: &Path) -> DoctorReport {
    DoctorReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: check_platform(),
        claude_code: check_claude_code(),
        js_runtime: check_js_runtime(),
        settings: check_settings(),
        daemon: check_daemon(base_dir),
        accounts: check_accounts(base_dir),
        broker_failed: check_broker_failed(base_dir),
        mixed_state_slots: check_mixed_state_slots(base_dir),
        terminals: check_terminals(base_dir),
        resurrections: check_resurrections(base_dir),
    }
}

/// Probes for a `node` or `bun` binary using the same two-stage
/// resolver as the HTTP client (PATH + known install locations).
/// The daemon cannot refresh tokens or poll quota without one, so
/// `not found` is reported as a WARN.
fn check_js_runtime() -> JsRuntimeInfo {
    match csq_core::http::js_runtime_path() {
        Some(p) => JsRuntimeInfo {
            found: true,
            path: Some(p),
        },
        None => JsRuntimeInfo {
            found: false,
            path: None,
        },
    }
}

/// Finds slots whose `config-N/settings.json` carries a 3P env block
/// AND whose `credentials/N.json` is a valid OAuth credential.
///
/// This is a mixed-state slot — on `csq run N` CC will route to the
/// 3P endpoint because `env.ANTHROPIC_BASE_URL` wins over OAuth, so
/// the OAuth credential sits unused. `csq login N` on a post-PR-#130
/// build auto-strips the 3P env block; older installs leave the slot
/// stuck.
fn check_mixed_state_slots(base_dir: &Path) -> MixedStateInfo {
    let third_party = discovery::discover_per_slot_third_party(base_dir);
    let mut entries: Vec<MixedStateSlot> = Vec::new();

    for slot in third_party {
        let Ok(num) = AccountNum::try_from(slot.id) else {
            continue;
        };
        let canonical = cred_file::canonical_path(base_dir, num);
        // Only flag when the OAuth file is parseable. A corrupt or
        // empty `credentials/N.json` isn't "mixed state" — it's a
        // separate kind of broken that other doctor checks surface
        // (`expired`, `broker_failed`).
        if csq_core::credentials::load(&canonical).is_ok() {
            let provider = match &slot.source {
                AccountSource::ThirdParty { provider } => provider.clone(),
                _ => "third-party".to_string(),
            };
            entries.push(MixedStateSlot {
                account: slot.id,
                provider,
            });
        }
    }

    entries.sort_by_key(|e| e.account);
    MixedStateInfo {
        count: entries.len(),
        entries,
    }
}

/// Reads `{base_dir}/.resurrection-log.jsonl` and summarizes it.
///
/// Each line is an object emitted by the refresher when it had to
/// rebuild a canonical credential file from its live sibling. Any
/// non-zero count means at least one OAuth slot's canonical went
/// missing — a symptom of a broken write path. The operator should
/// investigate login / Add Account / import flows that touched the
/// affected accounts.
fn check_resurrections(base_dir: &Path) -> ResurrectionInfo {
    let path = base_dir.join(".resurrection-log.jsonl");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            return ResurrectionInfo {
                total: 0,
                distinct_accounts: 0,
                last_timestamp_secs: None,
                recent_accounts: Vec::new(),
            };
        }
    };

    let mut total = 0usize;
    let mut last_ts: Option<u64> = None;
    let mut distinct: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    // Keep the last 5 account IDs in insertion order for the recent
    // sample. We don't guarantee chronological order of the file
    // beyond "appended" — appender is single-threaded inside the
    // daemon refresher so this is safe in practice.
    let mut recent: std::collections::VecDeque<u16> = std::collections::VecDeque::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        total += 1;
        if let Some(ts) = val.get("timestamp_secs").and_then(|v| v.as_u64()) {
            last_ts = Some(last_ts.map_or(ts, |prev| prev.max(ts)));
        }
        if let Some(acct) = val
            .get("account")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
        {
            distinct.insert(acct);
            recent.push_back(acct);
            while recent.len() > 5 {
                recent.pop_front();
            }
        }
    }

    ResurrectionInfo {
        total,
        distinct_accounts: distinct.len(),
        last_timestamp_secs: last_ts,
        recent_accounts: recent.into_iter().collect(),
    }
}

fn check_platform() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

fn check_claude_code() -> ClaudeCodeInfo {
    // Find claude binary (which on Unix, where.exe on Windows)
    #[cfg(unix)]
    let output = std::process::Command::new("which").arg("claude").output();
    #[cfg(windows)]
    let output = std::process::Command::new("where.exe")
        .arg("claude")
        .output();

    let (found, path) = match output {
        Ok(o) if o.status.success() => {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
            (true, Some(p))
        }
        _ => (false, None),
    };

    let version = if found {
        std::process::Command::new("claude")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        None
    };

    ClaudeCodeInfo {
        found,
        path,
        version,
    }
}

fn check_settings() -> SettingsInfo {
    let claude_home = super::claude_home().ok();

    let settings_path = claude_home.as_ref().map(|h| h.join("settings.json"));

    let (exists, statusline_configured, statusline_command) = match settings_path {
        Some(ref path) if path.exists() => match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(val) => {
                    let cmd = val
                        .get("statusLine")
                        .and_then(|sl| sl.get("command"))
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string());
                    // Any non-empty command is "configured" — doctor should
                    // not second-guess what script is used, only that one
                    // exists. The old `c.contains("csq")` check rejected
                    // valid wrapper scripts.
                    let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());
                    (true, configured, cmd)
                }
                Err(_) => (true, false, None),
            },
            Err(_) => (true, false, None),
        },
        _ => (false, false, None),
    };

    SettingsInfo {
        exists,
        statusline_configured,
        statusline_command,
    }
}

fn check_daemon(base_dir: &Path) -> DaemonInfo {
    use csq_core::daemon::{detect_daemon, DetectResult};
    match detect_daemon(base_dir) {
        DetectResult::Healthy { pid, .. } => DaemonInfo {
            status: "healthy".into(),
            pid: Some(pid),
            socket_healthy: Some(true),
        },
        DetectResult::Stale { .. } => DaemonInfo {
            status: "stale".into(),
            pid: None,
            socket_healthy: Some(false),
        },
        DetectResult::Unhealthy { reason } => {
            // PID is alive but the socket did not respond — daemon is up
            // but not serving. The reason string distinguishes "PID alive
            // but socket missing" from other unhealthy cases.
            let pid_alive_no_socket = reason.contains("socket") && reason.contains("missing");
            DaemonInfo {
                status: if pid_alive_no_socket {
                    "pid_alive_no_socket".into()
                } else {
                    "unhealthy".into()
                },
                pid: None,
                socket_healthy: Some(false),
            }
        }
        DetectResult::NotRunning => DaemonInfo {
            status: "not running".into(),
            pid: None,
            socket_healthy: None,
        },
    }
}

fn check_accounts(base_dir: &Path) -> AccountsInfo {
    let accounts = discovery::discover_anthropic(base_dir);
    let total = accounts.len();
    let with_credentials = accounts.iter().filter(|a| a.has_credentials).count();

    // Check for expired tokens
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut expired = 0usize;
    for a in &accounts {
        if !a.has_credentials {
            continue;
        }
        let Ok(num) = AccountNum::try_from(a.id) else {
            continue;
        };
        let cred_path = cred_file::canonical_path(base_dir, num);
        if let Ok(content) = std::fs::read_to_string(&cred_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(exp) = val
                    .get("claude_ai_oauth")
                    .and_then(|o| o.get("expires_at"))
                    .and_then(|e| e.as_u64())
                {
                    if exp < now_ms {
                        expired += 1;
                    }
                }
            }
        }
    }

    AccountsInfo {
        total,
        with_credentials,
        expired,
    }
}

/// Scans `credentials/N.broker-failed` sentinel files and returns the list of
/// accounts that require re-login.
///
/// The scan uses two approaches combined:
/// 1. Check every account discovered by `discovery::discover_anthropic` —
///    covers accounts whose credential slot exists.
/// 2. Glob `credentials/*.broker-failed` directly — catches sentinel files for
///    accounts whose `credentials/N.json` is missing (total loss case).
///
/// Both sets are unioned and de-duplicated before building the report.
fn check_broker_failed(base_dir: &Path) -> BrokerFailedInfo {
    let mut failed_ids: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();

    // Pass 1: discovered accounts.
    let accounts = discovery::discover_anthropic(base_dir);
    for a in &accounts {
        let Ok(num) = AccountNum::try_from(a.id) else {
            continue;
        };
        if fanout::is_broker_failed(base_dir, num) {
            failed_ids.insert(a.id);
        }
    }

    // Pass 2: filesystem scan of credentials/*.broker-failed to catch
    // accounts not in the discovery list.
    let creds_dir = base_dir.join("credentials");
    if let Ok(entries) = std::fs::read_dir(&creds_dir) {
        for entry in entries.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let stem = match name.strip_suffix(".broker-failed") {
                Some(s) => s,
                None => continue,
            };
            if let Ok(id) = stem.parse::<u16>() {
                failed_ids.insert(id);
            }
        }
    }

    let entries: Vec<BrokerFailedEntry> = failed_ids
        .iter()
        .filter_map(|&id| {
            let Ok(num) = AccountNum::try_from(id) else {
                return None;
            };
            let reason = fanout::read_broker_failed_reason(base_dir, num).unwrap_or_default();
            let display_reason = if reason.is_empty() {
                "unknown".to_string()
            } else {
                reason
            };
            Some(BrokerFailedEntry {
                account: id,
                reason: display_reason,
            })
        })
        .collect();

    let count = entries.len();
    BrokerFailedInfo { count, entries }
}

/// Detects legacy and modern CC terminals by examining the `base_dir` layout.
///
/// Strategy:
///
/// **Modern terminals** — scan for `term-<pid>` directories. Extract the PID
/// from the name and call `is_pid_alive`. Count those whose PID is still alive.
///
/// **Legacy terminals** — scan for `config-<N>` directories. In the modern
/// handle-dir model the `.credentials.json` inside each `config-N` is always a
/// plain file (the canonical OAuth token store). But the distinguishing
/// characteristic of a *still-active legacy terminal* is that the CC process
/// has `CLAUDE_CONFIG_DIR` pointing directly at a `config-N` path, bypassing
/// the `term-<pid>` layer. We cannot read every running process's environment
/// portably, so we use a best-effort proxy: count `config-N` dirs whose
/// `.credentials.json` is a **real file** (not a symlink). In the handle-dir
/// model this is still the expected layout — `config-N/.credentials.json` is
/// always a real file. To improve signal we also count how many live `term-<pid>`
/// dirs have a symlink pointing into each `config-N`; if no `term-<pid>` has
/// adopted a `config-N`, and the `config-N` has credentials, that `config-N`
/// might be hosting a legacy terminal.
///
/// Because perfect detection would require reading `/proc/*/environ` (Linux) or
/// `proc_pidinfo` (macOS) for every process — which is expensive and may be
/// blocked by SIP — we settle for the simplest reliable proxy:
///
/// - `modern_count` = number of `term-<pid>` dirs with a living PID
/// - `legacy_count` = number of `config-N` dirs that have credentials but are
///   NOT referenced by any living `term-<pid>` symlink
/// - `check_available` = true on Unix (where we can at least check PIDs)
///
/// On Windows the check is skipped entirely.
fn check_terminals(base_dir: &Path) -> TerminalInfo {
    #[cfg(not(unix))]
    {
        let _ = base_dir;
        return TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: false,
        };
    }

    #[cfg(unix)]
    {
        check_terminals_unix(base_dir)
    }
}

#[cfg(unix)]
fn check_terminals_unix(base_dir: &Path) -> TerminalInfo {
    use std::collections::HashSet;

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => {
            return TerminalInfo {
                modern_count: 0,
                legacy_count: 0,
                check_available: false,
            };
        }
    };

    // Collect all entries once so we can iterate twice.
    let all_entries: Vec<_> = entries.flatten().collect();

    // Pass 1: count living term-<pid> dirs and collect which config-N each references.
    let mut modern_count = 0usize;
    // Set of config-N dir names (e.g. "config-1") that have at least one live
    // term-<pid> pointing at them.
    let mut adopted_configs: HashSet<String> = HashSet::new();

    for entry in &all_entries {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if !name.starts_with("term-") {
            continue;
        }

        let pid: u32 = match name.strip_prefix("term-").and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        if !is_pid_alive(pid) {
            continue; // orphaned, not a live modern terminal
        }

        modern_count += 1;

        // Find which config-N this handle dir currently points at by reading
        // the .credentials.json symlink target and extracting the config-N component.
        let handle_path = entry.path();
        let cred_link = handle_path.join(".credentials.json");
        if let Ok(target) = std::fs::read_link(&cred_link) {
            // target is something like "../config-2/.credentials.json" or an absolute path.
            // We want the parent component that matches "config-N".
            if let Some(config_name) = target
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .find(|c| c.starts_with("config-"))
            {
                adopted_configs.insert(config_name.to_string());
            }
        }
    }

    // Pass 2: count config-N dirs that have credentials but no living handle dir.
    let mut legacy_count = 0usize;

    for entry in &all_entries {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if !name.starts_with("config-") {
            continue;
        }

        // Only count config dirs that have real credentials (not empty stubs).
        let cred_path = entry.path().join(".credentials.json");
        if !cred_path.exists() {
            continue;
        }

        // If this config-N has been adopted by at least one living term-<pid>,
        // then terminals on it are modern and already counted above.
        if adopted_configs.contains(&name) {
            continue;
        }

        // config-N has credentials but no living term-<pid> references it.
        // This is the legacy case: either there's a legacy CC session running
        // directly against this config dir, or simply no terminal is open on it.
        // We count it as "potentially legacy" — the warning is advisory.
        legacy_count += 1;
    }

    TerminalInfo {
        modern_count,
        legacy_count,
        check_available: true,
    }
}

fn print_report(r: &DoctorReport) {
    println!();
    println!("csq doctor — v{}", r.version);
    println!();

    // Platform
    println!("  Platform:    {} / {}", r.platform.os, r.platform.arch);

    // Claude Code
    let cc_icon = if r.claude_code.found { ok() } else { fail() };
    let cc_detail = match (&r.claude_code.version, &r.claude_code.path) {
        (Some(v), Some(p)) => format!("{v} ({p})"),
        (None, Some(p)) => format!("found at {p}"),
        _ => "not found".into(),
    };
    println!("  Claude Code: {cc_icon} {cc_detail}");

    // JS runtime (node/bun) — required for the Cloudflare-bypass
    // HTTP path. Missing runtime = broken token refresh + quota poll.
    let js_icon = if r.js_runtime.found { ok() } else { warn() };
    let js_detail = match &r.js_runtime.path {
        Some(p) => format!("found at {p}"),
        None => "not found — daemon can't refresh tokens or poll quota; install node or bun".into(),
    };
    println!("  JS runtime:  {js_icon} {js_detail}");

    // Settings
    let settings_icon = if r.settings.statusline_configured {
        ok()
    } else if r.settings.exists {
        warn()
    } else {
        fail()
    };
    let settings_detail = if r.settings.statusline_configured {
        format!(
            "statusline configured ({})",
            r.settings.statusline_command.as_deref().unwrap_or("?")
        )
    } else if r.settings.exists {
        "settings.json exists but statusline not configured".into()
    } else {
        "settings.json not found — run `csq install`".into()
    };
    println!("  Settings:    {settings_icon} {settings_detail}");

    // Daemon
    let (daemon_icon, daemon_detail) = match r.daemon.status.as_str() {
        "healthy" => {
            let pid_str = r
                .daemon
                .pid
                .map(|p| format!(" (PID {p})"))
                .unwrap_or_default();
            (ok(), format!("running and healthy{pid_str}"))
        }
        "pid_alive_no_socket" => (
            warn(),
            "PID alive but socket unreachable — daemon may be starting up".into(),
        ),
        "stale" => (fail(), "stale PID/socket — run `csq daemon start`".into()),
        "unhealthy" => (
            warn(),
            "daemon unhealthy — socket connect or health check failed".into(),
        ),
        "not running" => (warn(), "not running — run `csq daemon start`".into()),
        _ => (warn(), r.daemon.status.clone()),
    };
    println!("  Daemon:      {daemon_icon} {daemon_detail}");

    // Accounts
    let acct_icon = if r.accounts.with_credentials > 0 && r.accounts.expired == 0 {
        ok()
    } else if r.accounts.expired > 0 {
        warn()
    } else {
        fail()
    };
    let mut acct_detail = format!(
        "{} account(s), {} with credentials",
        r.accounts.total, r.accounts.with_credentials
    );
    if r.accounts.expired > 0 {
        acct_detail.push_str(&format!(", {} expired", r.accounts.expired));
    }
    println!("  Accounts:    {acct_icon} {acct_detail}");

    // Mixed-state slots (3P env block + OAuth creds)
    if r.mixed_state_slots.count > 0 {
        for entry in &r.mixed_state_slots.entries {
            println!(
                "  Mixed:       {} Slot {} has both {} env and OAuth creds — CC will route via {}. Run `csq login {}` to unbind.",
                warn(),
                entry.account,
                entry.provider,
                entry.provider,
                entry.account,
            );
        }
    }

    // Broker-failed sentinels
    if r.broker_failed.count > 0 {
        for entry in &r.broker_failed.entries {
            println!(
                "  Broker:      {} Account {}: LOGIN-NEEDED ({}) — run `csq login {}`",
                fail(),
                entry.account,
                entry.reason,
                entry.account,
            );
        }
    }

    // Terminals
    let t = &r.terminals;
    if !t.check_available {
        println!("  Terminals:   - check not available on this platform");
    } else if t.legacy_count > 0 {
        let term_icon = warn();
        println!(
            "  Terminals:   {term_icon} {} legacy, {} modern — relaunch legacy terminals with `csq run`",
            t.legacy_count, t.modern_count
        );
    } else if t.modern_count > 0 {
        let term_icon = ok();
        println!(
            "  Terminals:   {term_icon} {} terminal(s) using handle dirs",
            t.modern_count
        );
    } else {
        println!("  Terminals:   - no active terminals detected");
    }

    // Resurrection forensics — only printed when the daemon has had
    // to rebuild a canonical credential file at least once. Non-zero
    // is always a WARN because it implies a broken write path that
    // the daemon is auto-healing.
    let res = &r.resurrections;
    if res.total > 0 {
        let ts_str = res
            .last_timestamp_secs
            .map(format_utc_date)
            .unwrap_or_else(|| "unknown".into());
        let sample: Vec<String> = res.recent_accounts.iter().map(|a| a.to_string()).collect();
        println!(
            "  Resurrections: {} {} canonical rebuilds across {} account(s) — last at {} — \
             investigate write path (recent: {}). Breadcrumbs: ~/.claude/accounts/.resurrection-log.jsonl",
            warn(),
            res.total,
            res.distinct_accounts,
            ts_str,
            sample.join(", ")
        );
    }

    println!();
}

/// Formats a Unix epoch second count as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// Hand-rolled because bringing in `chrono` or `time` for a single
/// print statement is excess baggage. The daemon stamps timestamps
/// with `SystemTime::now().duration_since(UNIX_EPOCH)` so valid
/// values are always non-negative and within the i64 range.
fn format_utc_date(secs: u64) -> String {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Civil from days algorithm (Howard Hinnant, "date algorithms",
    // public domain). Converts days-since-1970-01-01 into Y/M/D.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn ok() -> &'static str {
    "\x1b[32m✓\x1b[0m"
}

fn warn() -> &'static str {
    "\x1b[33m⚠\x1b[0m"
}

fn fail() -> &'static str {
    "\x1b[31m✗\x1b[0m"
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── helpers ───────────────────────────────────────────────────────────

    /// Create a minimal `config-<N>` directory with a real `.credentials.json`.
    fn make_config(base: &std::path::Path, n: u16) -> std::path::PathBuf {
        let dir = base.join(format!("config-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".credentials.json"), "{}").unwrap();
        dir
    }

    /// Create a `term-<pid>` handle directory with a symlink to config-N's
    /// .credentials.json. Uses an absolute target path so the component
    /// extraction in check_terminals_unix works reliably.
    #[cfg(unix)]
    fn make_handle_dir_with_symlink(base: &std::path::Path, pid: u32, config_name: &str) {
        let handle = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), pid.to_string()).unwrap();
        // Absolute path target so component scan finds "config-N"
        let target = base.join(config_name).join(".credentials.json");
        std::os::unix::fs::symlink(&target, handle.join(".credentials.json")).unwrap();
    }

    // ── check_terminals tests (Unix only) ─────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn no_dirs_reports_zero() {
        // Arrange
        let tmp = TempDir::new().unwrap();

        // Act
        let info = check_terminals(tmp.path());

        // Assert
        assert!(info.check_available);
        assert_eq!(info.modern_count, 0);
        assert_eq!(info.legacy_count, 0);
    }

    #[test]
    #[cfg(unix)]
    fn config_dir_without_credentials_not_counted_as_legacy() {
        // Arrange: config dir exists but has no .credentials.json
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("config-1")).unwrap();

        // Act
        let info = check_terminals(tmp.path());

        // Assert: no credentials means not a legacy terminal
        assert_eq!(info.legacy_count, 0);
    }

    #[test]
    #[cfg(unix)]
    fn config_dir_with_credentials_but_no_handle_counted_as_legacy() {
        // Arrange: config-1 has credentials, no term-<pid> adopts it
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);

        // Act
        let info = check_terminals(tmp.path());

        // Assert: one legacy, zero modern
        assert_eq!(info.legacy_count, 1);
        assert_eq!(info.modern_count, 0);
    }

    #[test]
    #[cfg(unix)]
    fn living_handle_dir_counts_as_modern_and_suppresses_legacy() {
        // Arrange: config-1 with credentials, adopted by a term-1
        // (PID 1 = init/launchd — always alive on Unix)
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        make_handle_dir_with_symlink(tmp.path(), 1, "config-1");

        // Act
        let info = check_terminals(tmp.path());

        // Assert: PID 1 is alive → one modern terminal; config-1 is adopted
        // so not counted as legacy.
        assert_eq!(info.modern_count, 1);
        assert_eq!(info.legacy_count, 0);
    }

    #[test]
    #[cfg(unix)]
    fn dead_handle_dir_not_counted_as_modern() {
        // Arrange: config-1 with credentials, term-999999999 pointing at it
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        make_handle_dir_with_symlink(tmp.path(), 999_999_999, "config-1");

        // Act
        let info = check_terminals(tmp.path());

        // Assert: dead PID → zero modern; config-1 not adopted → one legacy.
        assert_eq!(info.modern_count, 0);
        assert_eq!(info.legacy_count, 1);
    }

    #[test]
    #[cfg(unix)]
    fn mixed_layout_detected_correctly() {
        // Arrange:
        //   config-1 — adopted by living term-1 (PID 1 = init/launchd)
        //   config-2 — no living handle dir → legacy
        //   term-999999999 — dead PID (orphan, adopts config-1 but is dead)
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        make_config(tmp.path(), 2);
        // Living handle for config-1
        make_handle_dir_with_symlink(tmp.path(), 1, "config-1");
        // Dead orphaned handle for config-1
        make_handle_dir_with_symlink(tmp.path(), 999_999_999, "config-1");

        // Act
        let info = check_terminals(tmp.path());

        // Assert
        assert_eq!(info.modern_count, 1); // only PID 1 is alive
        assert_eq!(info.legacy_count, 1); // config-2 has no living adopter
    }

    // ── TerminalInfo JSON serialization ───────────────────────────────────

    /// Helper: build a minimal DoctorReport with specific terminal info.
    fn make_report(terminals: TerminalInfo) -> DoctorReport {
        DoctorReport {
            version: "0.0.0".into(),
            platform: PlatformInfo {
                os: "test".into(),
                arch: "x86_64".into(),
            },
            claude_code: ClaudeCodeInfo {
                found: false,
                path: None,
                version: None,
            },
            js_runtime: JsRuntimeInfo {
                found: false,
                path: None,
            },
            settings: SettingsInfo {
                exists: false,
                statusline_configured: false,
                statusline_command: None,
            },
            daemon: DaemonInfo {
                status: "not running".into(),
                pid: None,
                socket_healthy: None,
            },
            accounts: AccountsInfo {
                total: 0,
                with_credentials: 0,
                expired: 0,
            },
            broker_failed: BrokerFailedInfo {
                count: 0,
                entries: Vec::new(),
            },
            mixed_state_slots: MixedStateInfo {
                count: 0,
                entries: Vec::new(),
            },
            terminals,
            resurrections: ResurrectionInfo {
                total: 0,
                distinct_accounts: 0,
                last_timestamp_secs: None,
                recent_accounts: Vec::new(),
            },
        }
    }

    #[test]
    fn check_resurrections_absent_file_reports_zero() {
        let tmp = TempDir::new().unwrap();
        let info = check_resurrections(tmp.path());
        assert_eq!(info.total, 0);
        assert_eq!(info.distinct_accounts, 0);
        assert!(info.last_timestamp_secs.is_none());
        assert!(info.recent_accounts.is_empty());
    }

    #[test]
    fn check_resurrections_counts_unique_accounts() {
        // Three breadcrumbs across two distinct accounts — distinct
        // count should be 2, total count should be 3, and the recent
        // sample should contain the most recent entries in insertion
        // order.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(".resurrection-log.jsonl");
        std::fs::write(
            &path,
            concat!(
                r#"{"timestamp_secs":1000,"account":3,"event":"canonical_resurrected","live_mtime_secs":950,"live_path":"/a"}"#, "\n",
                r#"{"timestamp_secs":2000,"account":5,"event":"canonical_resurrected","live_mtime_secs":1950,"live_path":"/b"}"#, "\n",
                r#"{"timestamp_secs":3000,"account":3,"event":"canonical_resurrected","live_mtime_secs":2950,"live_path":"/c"}"#, "\n",
            ),
        )
        .unwrap();

        let info = check_resurrections(tmp.path());

        assert_eq!(info.total, 3);
        assert_eq!(info.distinct_accounts, 2, "accounts 3 and 5 are distinct");
        assert_eq!(info.last_timestamp_secs, Some(3000));
        assert_eq!(info.recent_accounts, vec![3, 5, 3]);
    }

    #[test]
    fn check_resurrections_ignores_malformed_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(".resurrection-log.jsonl");
        std::fs::write(
            &path,
            concat!(
                "not json\n",
                r#"{"timestamp_secs":1000,"account":7,"event":"canonical_resurrected","live_mtime_secs":950,"live_path":"/a"}"#, "\n",
                "\n",
                "{ broken\n",
            ),
        )
        .unwrap();

        let info = check_resurrections(tmp.path());
        assert_eq!(info.total, 1, "only the valid line counts");
        assert_eq!(info.recent_accounts, vec![7]);
    }

    #[test]
    fn format_utc_date_round_trips_known_timestamps() {
        // 2026-04-14 02:00:00 UTC
        let s = format_utc_date(1_776_132_000);
        assert_eq!(s, "2026-04-14 02:00:00 UTC");
        // 1970-01-01 00:00:00 UTC
        let epoch = format_utc_date(0);
        assert_eq!(epoch, "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn report_fields_no_active_terminals() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: true,
        });

        // Assert: the report struct carries the expected values that drive
        // the "no active terminals" display branch.
        assert_eq!(r.terminals.modern_count, 0);
        assert_eq!(r.terminals.legacy_count, 0);
        assert!(r.terminals.check_available);
    }

    #[test]
    fn report_fields_modern_terminals_only() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 3,
            legacy_count: 0,
            check_available: true,
        });

        // Assert
        assert_eq!(r.terminals.modern_count, 3);
        assert_eq!(r.terminals.legacy_count, 0);
    }

    #[test]
    fn report_fields_legacy_terminals_present() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 2,
            legacy_count: 1,
            check_available: true,
        });

        // Assert: legacy_count > 0 is the condition that drives the warning branch
        assert!(r.terminals.legacy_count > 0);
        assert_eq!(r.terminals.modern_count, 2);
    }

    #[test]
    fn report_fields_check_not_available() {
        // Arrange: simulate Windows (check_available = false)
        let r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: false,
        });

        // Assert
        assert!(!r.terminals.check_available);
    }

    #[test]
    fn json_output_includes_terminals_field() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 5,
            legacy_count: 2,
            check_available: true,
        });

        // Act
        let json = serde_json::to_string(&r).unwrap();

        // Assert
        assert!(
            json.contains("\"terminals\""),
            "JSON must include terminals key"
        );
        assert!(
            json.contains("\"modern_count\":5"),
            "JSON must include modern_count"
        );
        assert!(
            json.contains("\"legacy_count\":2"),
            "JSON must include legacy_count"
        );
        assert!(
            json.contains("\"check_available\":true"),
            "JSON must include check_available"
        );
    }

    // ── Fix 2: statusline check tests ─────────────────────────────────────

    #[test]
    fn statusline_any_non_empty_command_is_configured() {
        // Arrange: a wrapper script that doesn't contain "csq"
        let cmd = Some("statusline-quota.sh".to_string());

        // Act: replicate the check logic
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert: non-empty → configured
        assert!(
            configured,
            "any non-empty command should be considered configured"
        );
    }

    #[test]
    fn statusline_empty_command_is_not_configured() {
        // Arrange
        let cmd = Some("   ".to_string());

        // Act
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert
        assert!(
            !configured,
            "whitespace-only command should not be configured"
        );
    }

    #[test]
    fn statusline_none_command_is_not_configured() {
        // Arrange
        let cmd: Option<String> = None;

        // Act
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert
        assert!(!configured, "None command should not be configured");
    }

    #[test]
    fn statusline_csq_command_still_configured_after_relaxation() {
        // Arrange: original csq command still works under the relaxed check
        let cmd = Some("csq statusline".to_string());

        // Act
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert
        assert!(configured);
    }

    // ── Fix 3: broker_failed scanning tests ───────────────────────────────

    #[test]
    fn check_broker_failed_no_sentinels_reports_empty() {
        // Arrange
        let tmp = TempDir::new().unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 0);
        assert!(info.entries.is_empty());
    }

    #[test]
    fn check_broker_failed_detects_sentinel_files() {
        // Arrange: write two broker-failed sentinel files directly
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("2.broker-failed"), "invalid_grant").unwrap();
        std::fs::write(creds_dir.join("5.broker-failed"), "network").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 2, "two sentinels should be detected");
        let ids: Vec<u16> = info.entries.iter().map(|e| e.account).collect();
        assert!(ids.contains(&2), "account 2 should be in entries");
        assert!(ids.contains(&5), "account 5 should be in entries");
    }

    #[test]
    fn check_broker_failed_reads_reason_from_file() {
        // Arrange
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("3.broker-failed"), "rate_limit").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 1);
        assert_eq!(info.entries[0].account, 3);
        assert_eq!(info.entries[0].reason, "rate_limit");
    }

    #[test]
    fn check_broker_failed_empty_sentinel_shows_unknown_reason() {
        // Arrange: pre-v2.1 zero-byte sentinel file
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.broker-failed"), b"").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 1);
        assert_eq!(
            info.entries[0].reason, "unknown",
            "empty file should show 'unknown'"
        );
    }

    #[test]
    fn check_broker_failed_ignores_non_sentinel_files() {
        // Arrange: a .json and a random file in credentials/
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), "{}").unwrap();
        std::fs::write(creds_dir.join("random.txt"), "data").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 0, "non-sentinel files should not be counted");
    }

    #[test]
    fn check_broker_failed_entries_sorted_by_account_number() {
        // Arrange: write sentinels in reverse order
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("7.broker-failed"), "network").unwrap();
        std::fs::write(creds_dir.join("2.broker-failed"), "invalid_grant").unwrap();
        std::fs::write(creds_dir.join("4.broker-failed"), "rate_limit").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert: entries should be sorted ascending by account number
        assert_eq!(info.count, 3);
        assert_eq!(info.entries[0].account, 2);
        assert_eq!(info.entries[1].account, 4);
        assert_eq!(info.entries[2].account, 7);
    }

    // ── mixed-state slot tests ─────────────────────────────────

    #[test]
    fn check_mixed_state_slots_reports_empty_when_no_slots_mixed() {
        let tmp = TempDir::new().unwrap();
        let info = check_mixed_state_slots(tmp.path());
        assert_eq!(info.count, 0);
        assert!(info.entries.is_empty());
    }

    #[test]
    fn check_mixed_state_slots_flags_oauth_plus_3p_slot() {
        // Arrange: write a 3P env block AND a valid-shape OAuth
        // credential for slot 3. This is the exact state the PR
        // #130 login flow now prevents; older installs can still
        // produce it via manual filesystem edits.
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().join("config-3");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io/anthropic","ANTHROPIC_AUTH_TOKEN":"sk-fake-minimax-12345"}}"#,
        ).unwrap();

        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Minimum-viable OAuth credential — must parse, concrete values don't matter.
        std::fs::write(
            creds_dir.join("3.json"),
            r#"{"claudeAiOauth":{"accessToken":"oat-stub","refreshToken":"rt-stub","expiresAt":9999999999999,"scopes":["user:profile"],"subscriptionType":"max"}}"#,
        ).unwrap();

        // Act
        let info = check_mixed_state_slots(tmp.path());

        // Assert
        assert_eq!(info.count, 1, "slot 3 should be flagged");
        assert_eq!(info.entries[0].account, 3);
        assert_eq!(info.entries[0].provider, "MiniMax");
    }

    #[test]
    fn check_mixed_state_slots_ignores_3p_only_slot() {
        // 3P env block without any OAuth credential is the normal
        // MM/Z.AI/Ollama state — must not be flagged.
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().join("config-3");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://localhost:11434","ANTHROPIC_AUTH_TOKEN":"ollama"}}"#,
        ).unwrap();

        let info = check_mixed_state_slots(tmp.path());
        assert_eq!(info.count, 0);
    }

    #[test]
    fn check_mixed_state_slots_ignores_oauth_only_slot() {
        // Pure OAuth slot (no 3P settings) is the normal Anthropic
        // path — must not be flagged.
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("1.json"),
            r#"{"claudeAiOauth":{"accessToken":"oat-stub","refreshToken":"rt-stub","expiresAt":9999999999999,"scopes":["user:profile"],"subscriptionType":"max"}}"#,
        ).unwrap();

        let info = check_mixed_state_slots(tmp.path());
        assert_eq!(info.count, 0);
    }

    // ── js_runtime test ────────────────────────────────────────

    #[test]
    fn check_js_runtime_returns_consistent_structure() {
        // Can't assume the CI has node/bun installed — just assert
        // the invariant: `found == path.is_some()`. Exhaustive probe
        // logic lives in csq_core::http tests.
        let info = check_js_runtime();
        assert_eq!(info.found, info.path.is_some());
    }

    #[test]
    fn json_output_includes_broker_failed_field() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: true,
        });

        // Act
        let json = serde_json::to_string(&r).unwrap();

        // Assert
        assert!(
            json.contains("\"broker_failed\""),
            "JSON must include broker_failed key"
        );
        assert!(
            json.contains("\"count\":0"),
            "JSON must include count field"
        );
    }
}
