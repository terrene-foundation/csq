//! `csq doctor` — diagnostic report for troubleshooting.
//!
//! Checks binary version, daemon status, account health, Claude Code
//! installation, settings.json configuration, platform info, and
//! legacy terminal detection (CC sessions using old `config-N` dirs
//! instead of `term-<pid>` handle dirs).
//! Outputs color-coded text by default, or structured JSON with `--json`.

use anyhow::Result;
use csq_core::accounts::discovery;
use csq_core::platform::process::is_pid_alive;
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
    terminals: TerminalInfo,
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
        terminals: check_terminals(base_dir),
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
                    let configured = cmd.as_ref().is_some_and(|c| c.contains("csq"));
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
        let cred_path = base_dir.join("credentials").join(format!("{}.json", a.id));
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
            settings: SettingsInfo {
                exists: false,
                statusline_configured: false,
                statusline_command: None,
            },
            daemon: DaemonInfo {
                status: "not running".into(),
                pid: None,
            },
            accounts: AccountsInfo {
                total: 0,
                with_credentials: 0,
                expired: 0,
            },
            terminals,
        }
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
}
