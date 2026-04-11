//! `csq doctor` — diagnostic report for troubleshooting.
//!
//! Checks binary version, daemon status, account health, Claude Code
//! installation, settings.json configuration, and platform info.
//! Outputs color-coded text by default, or structured JSON with `--json`.

use anyhow::Result;
use csq_core::accounts::discovery;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct DoctorReport {
    version: String,
    platform: PlatformInfo,
    claude_code: ClaudeCodeInfo,
    settings: SettingsInfo,
    daemon: DaemonInfo,
    accounts: AccountsInfo,
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
    status: String,
    pid: Option<u32>,
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
        settings: check_settings(),
        daemon: check_daemon(base_dir),
        accounts: check_accounts(base_dir),
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
    let output = std::process::Command::new("which")
        .arg("claude")
        .output();
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
        Some(ref path) if path.exists() => {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(val) => {
                            let cmd = val
                                .get("statusLine")
                                .and_then(|sl| sl.get("command"))
                                .and_then(|c| c.as_str())
                                .map(|s| s.to_string());
                            let configured = cmd.as_ref().is_some_and(|c| c.contains("csq"));
                            (true, configured, cmd)
                        }
                        Err(_) => (true, false, None),
                    }
                }
                Err(_) => (true, false, None),
            }
        }
        _ => (false, false, None),
    };

    SettingsInfo {
        exists,
        statusline_configured,
        statusline_command,
    }
}

fn check_daemon(base_dir: &Path) -> DaemonInfo {
    #[cfg(unix)]
    {
        use csq_core::daemon::{self, DaemonStatus};
        let pid_path = daemon::pid_file_path(base_dir);
        match daemon::status_of(&pid_path) {
            DaemonStatus::Running { pid } => DaemonInfo {
                status: "running".into(),
                pid: Some(pid),
            },
            DaemonStatus::Stale { pid } => DaemonInfo {
                status: "stale".into(),
                pid: Some(pid),
            },
            DaemonStatus::NotRunning => DaemonInfo {
                status: "not running".into(),
                pid: None,
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = base_dir;
        DaemonInfo {
            status: "not supported".into(),
            pid: None,
        }
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
        let cred_path = base_dir
            .join("credentials")
            .join(format!("{}.json", a.id));
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
    let daemon_icon = match r.daemon.status.as_str() {
        "running" => ok(),
        "stale" => fail(),
        _ => warn(),
    };
    let daemon_detail = match (r.daemon.status.as_str(), r.daemon.pid) {
        ("running", Some(pid)) => format!("running (PID {pid})"),
        ("stale", Some(pid)) => format!("stale PID file (PID {pid}) — run `csq daemon start`"),
        _ => "not running".into(),
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

    println!();
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
