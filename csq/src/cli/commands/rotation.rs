//! `csq rotation` — view and change the daemon's auto-rotation settings.
//!
//! The daemon's auto-rotator (spec 02 §2.7) swaps a terminal onto a
//! lower-usage account when its account's five-hour usage reaches the
//! threshold. Its only configuration is `<base>/rotation.json`; this command
//! is the terminal-side twin of the desktop toggle, and BOTH write through
//! [`csq_core::rotation::config::set_enabled`] / [`update`] so the file is
//! read-modified-written the same way from either surface.
//!
//! The command never talks to the daemon and never touches credentials or
//! quota: the daemon re-reads `rotation.json` on every tick, so a change takes
//! effect within one tick without a restart. `status` only *observes* whether
//! the daemon is up, so an "on" setting with no daemon is not mistaken for
//! working rotation.
//!
//! # Per-session override
//!
//! `csq rotation session on|off|default [--session <TERM-PID>]` writes a small
//! owner-only file inside ONE terminal's `term-<pid>/` handle dir
//! ([`csq_core::rotation::session_override`]). `on`/`off` beat the machine
//! setting for that terminal; `default` removes the file so the terminal follows
//! the machine setting again. The terminal is the one the command runs in
//! (`CLAUDE_CONFIG_DIR`, admitted only when it is `term-<pid>` directly under
//! the base) unless `--session` names another.
//!
//! [`update`]: csq_core::rotation::config::update

use anyhow::{anyhow, Result};
use clap::Subcommand;
use csq_core::daemon::{detect_daemon, DetectResult};
use csq_core::rotation::config::{self, RotationConfig, RotationUpdateError};
use csq_core::rotation::session_override::{
    self, SessionEntry, SessionRotationError, SessionRotationMode, SessionRotationState,
};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

/// Fixed text for an unreadable `rotation.json` (no path, no parse detail).
const UNREADABLE_MESSAGE: &str = "rotation.json is unreadable; fix or remove it";

/// Fixed refusal text for a terminal the daemon rotator never moves. Shared by
/// `csq rotation session`; the desktop and `csq run --auto-swap` refuse on the
/// same predicate ([`csq_core::rotation::eligibility`]).
const INELIGIBLE_MESSAGE: &str =
    "auto-rotate applies to Claude Code sign-in sessions only; the daemon would never move this terminal";

/// `on` / `off` / `default` for [`RotationCommand::Session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SessionModeArg {
    /// Move this terminal when it is over the threshold, even if auto-rotate is off machine-wide
    On,
    /// Never move this terminal, even if auto-rotate is on machine-wide
    Off,
    /// Follow the machine-wide setting again
    Default,
}

impl SessionModeArg {
    fn mode(self) -> SessionRotationMode {
        match self {
            SessionModeArg::On => SessionRotationMode::On,
            SessionModeArg::Off => SessionRotationMode::Off,
            SessionModeArg::Default => SessionRotationMode::Default,
        }
    }
}

/// `--auto-swap on|off` for `csq run`: the launch-time form of
/// `csq rotation session on|off` (there is nothing to reset on a fresh handle dir).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AutoSwapArg {
    /// Move this terminal when it is over the threshold, even if auto-rotate is off machine-wide
    On,
    /// Never move this terminal, even if auto-rotate is on machine-wide
    Off,
}

impl AutoSwapArg {
    pub(crate) fn mode(self) -> SessionRotationMode {
        match self {
            AutoSwapArg::On => SessionRotationMode::On,
            AutoSwapArg::Off => SessionRotationMode::Off,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum RotationCommand {
    /// Show whether auto-rotate is on, its settings, and whether the daemon is running
    Status,
    /// Turn auto-rotate on
    On,
    /// Turn auto-rotate off
    Off,
    /// Turn auto-rotate on or off for ONE terminal, overriding the machine-wide setting
    /// (applies to Claude Code sign-in sessions; `default` follows the machine setting)
    Session {
        /// `on`, `off`, or `default`
        #[arg(value_enum)]
        mode: SessionModeArg,
        /// The terminal to change, as its number (`12345` or `term-12345`).
        /// Default: the terminal this command is run in
        #[arg(long, value_name = "TERM-PID")]
        session: Option<String>,
    },
    /// Change the threshold and/or cooldown (leaves on/off unchanged)
    Set {
        /// Five-hour usage percentage (1-100) at which a terminal is moved
        /// to a lower-usage account
        #[arg(long, value_name = "PERCENT", allow_negative_numbers = true)]
        threshold: Option<f64>,
        /// Seconds (1-86400) a terminal waits before it can be moved again
        #[arg(long, value_name = "SECS", allow_negative_numbers = true)]
        cooldown: Option<i64>,
    },
}

/// What the daemon-liveness probe saw, reduced to the four states a user can
/// act on. Never carries a path or socket detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonView {
    Running {
        pid: u32,
    },
    /// A process holds the PID file but the daemon did not answer its
    /// health check (starting up or wedged).
    Unresponsive,
    /// A PID file exists but names a dead or foreign process.
    Stale,
    NotRunning,
}

impl DaemonView {
    fn probe(base_dir: &Path) -> Self {
        Self::from_detection(&detect_daemon(base_dir))
    }

    pub(crate) fn from_detection(result: &DetectResult) -> Self {
        match result {
            DetectResult::Healthy { pid, .. } => DaemonView::Running { pid: *pid },
            DetectResult::Unhealthy { .. } => DaemonView::Unresponsive,
            DetectResult::Stale { .. } => DaemonView::Stale,
            DetectResult::NotRunning => DaemonView::NotRunning,
        }
    }

    fn key(self) -> &'static str {
        match self {
            DaemonView::Running { .. } => "running",
            DaemonView::Unresponsive => "unresponsive",
            DaemonView::Stale => "stale",
            DaemonView::NotRunning => "not_running",
        }
    }

    fn text(self) -> String {
        match self {
            DaemonView::Running { pid } => format!("running (PID {pid})"),
            DaemonView::Unresponsive => "not responding (it may still be starting up)".to_string(),
            DaemonView::Stale => "not running (stale PID file)".to_string(),
            DaemonView::NotRunning => "not running".to_string(),
        }
    }

    fn is_running(self) -> bool {
        matches!(self, DaemonView::Running { .. })
    }
}

/// Machine-readable `csq rotation` output (not an enveloped SDK surface).
#[derive(Debug, Serialize)]
struct RotationJson<'a> {
    enabled: bool,
    threshold_percent: f64,
    cooldown_secs: u64,
    exclude_accounts: &'a [u16],
    /// `running` | `unresponsive` | `stale` | `not_running`.
    daemon: &'static str,
    /// True only when the daemon is running AND will move at least one terminal:
    /// the machine setting is on, or a live terminal the rotator can move is set
    /// to `on` (a per-terminal `on` beats an off machine setting).
    rotating: bool,
    /// Live, rotator-eligible terminals set to `on`.
    sessions_on: usize,
    /// Live terminals with their own `on`/`off` setting (see
    /// `csq rotation session`); empty when none, or when they could not be
    /// listed (`sessions_listed` is then `false`).
    sessions: &'a [SessionEntry],
    sessions_listed: bool,
}

fn json_of(
    base_dir: &Path,
    cfg: &RotationConfig,
    daemon: DaemonView,
    sessions: &Result<Vec<SessionEntry>, SessionRotationError>,
) -> Result<String> {
    // `sessions_listed` below tells a reader when this 0 means "unknown".
    let sessions_on = live_on_count(base_dir, sessions).unwrap_or(0);
    Ok(serde_json::to_string(&RotationJson {
        enabled: cfg.enabled,
        threshold_percent: cfg.threshold_percent,
        cooldown_secs: cfg.cooldown_secs,
        exclude_accounts: &cfg.exclude_accounts,
        daemon: daemon.key(),
        rotating: (cfg.enabled || sessions_on > 0) && daemon.is_running(),
        sessions_on,
        sessions: sessions.as_deref().unwrap_or(&[]),
        sessions_listed: sessions.is_ok(),
    })?)
}

/// How many live terminals the daemon will move because their OWN setting is
/// `on`: the per-session override read by the rotator (`read_override` through
/// [`session_override::list_overrides`]) AND the rotator's eligibility
/// ([`csq_core::rotation::eligibility`]), so a terminal the rotator skips (3P,
/// native, unbound) is not counted. `None` = the per-terminal settings could
/// not be listed: unknown, which a caller MUST NOT present as "none" (a live
/// `on` terminal may still be moved).
pub(crate) fn live_on_count(
    base_dir: &Path,
    sessions: &Result<Vec<SessionEntry>, SessionRotationError>,
) -> Option<usize> {
    let Ok(list) = sessions else {
        return None;
    };
    let on: Vec<u32> = list
        .iter()
        .filter(|e| e.mode == SessionRotationState::On)
        .map(|e| e.pid)
        .collect();
    if on.is_empty() {
        return Some(0);
    }
    let accounts = csq_core::accounts::discovery::discover_all(base_dir);
    let count = on
        .into_iter()
        .filter(|pid| {
            session_override::resolve_session_dir(base_dir, *pid).is_ok_and(|dir| {
                csq_core::rotation::eligibility::session_rotation_eligible(
                    base_dir, &accounts, &dir,
                )
            })
        })
        .count();
    Some(count)
}

/// `csq status`'s one-line auto-rotate summary: the shared machine line
/// ([`config::summary_line`]) plus, when the machine setting is off but live
/// terminals are set to `on`, the fact that the daemon still moves them.
pub(crate) fn summary_line_with_sessions(base_dir: &Path) -> String {
    summary_line_from(config::summary_line(base_dir), live_on_count_for(base_dir))
}

/// [`summary_line_with_sessions`] over an already-computed machine line and count.
fn summary_line_from(line: String, live_on: Option<usize>) -> String {
    if !line.starts_with("Auto-rotate: off") {
        return line;
    }
    match live_on {
        Some(0) => line,
        Some(n) => {
            format!("Auto-rotate: off machine-wide, but {n} terminal(s) set to on are still moved")
        }
        None => "Auto-rotate: off machine-wide; per-terminal settings could not be listed, so a terminal set to on may still be moved".to_string(),
    }
}

/// [`live_on_count`] straight from disk, for `csq status` and `csq doctor`.
pub(crate) fn live_on_count_for(base_dir: &Path) -> Option<usize> {
    live_on_count(base_dir, &session_override::list_overrides(base_dir))
}

/// The per-session block of `csq rotation status`: one line per live terminal
/// that carries its own setting. Empty when there are none.
fn sessions_text(sessions: &Result<Vec<SessionEntry>, SessionRotationError>) -> String {
    match sessions {
        Err(_) => "  Sessions:  could not be listed\n".to_string(),
        Ok(list) if list.is_empty() => String::new(),
        Ok(list) => {
            let mut out = String::from("  Sessions with their own setting:\n");
            for entry in list {
                let meaning = match entry.mode {
                    SessionRotationState::On => {
                        "on (moved even if auto-rotate is off machine-wide)"
                    }
                    SessionRotationState::Off => "off (never moved)",
                    SessionRotationState::Unreadable => {
                        "unreadable (treated as off; reset with `csq rotation session default`)"
                    }
                    SessionRotationState::Default => "default",
                };
                out.push_str(&format!("    term-{}: {meaning}\n", entry.pid));
            }
            out
        }
    }
}

/// The plain-words block `csq rotation status` prints.
fn status_text(
    base_dir: &Path,
    cfg: &RotationConfig,
    daemon: DaemonView,
    sessions: &Result<Vec<SessionEntry>, SessionRotationError>,
) -> String {
    let live_on = live_on_count(base_dir, sessions);
    let mut out = String::new();
    out.push_str(if cfg.enabled {
        "Auto-rotate: on\n"
    } else {
        "Auto-rotate: off\n"
    });
    out.push_str(&format!(
        "  Threshold: {}% (a terminal moves to a lower-usage account when its account's 5-hour usage reaches this)\n",
        config::format_percent(cfg.threshold_percent)
    ));
    out.push_str(&format!(
        "  Cooldown:  {}s (minimum wait before the same terminal is moved again)\n",
        cfg.cooldown_secs
    ));
    if !cfg.exclude_accounts.is_empty() {
        let list: Vec<String> = cfg.exclude_accounts.iter().map(u16::to_string).collect();
        out.push_str(&format!(
            "  Excluded:  accounts {} (never moved onto)\n",
            list.join(", ")
        ));
    }
    out.push_str(&format!("  Daemon:    {}\n", daemon.text()));
    out.push_str(&sessions_text(sessions));
    if let Some(note) = advice(cfg, daemon, live_on) {
        out.push_str(&format!("  {note}\n"));
    }
    out
}

/// One follow-up line when the setting and the daemon disagree, or the
/// feature is off. `None` when rotation is on and working. `live_on` is the
/// number of live terminals set to `on` ([`live_on_count`]): the daemon moves
/// those even when the machine setting is off, so they count as rotation.
fn advice(cfg: &RotationConfig, daemon: DaemonView, live_on: Option<usize>) -> Option<String> {
    let Some(live_on) = live_on else {
        // Unknown per-terminal state: never claim "nothing will move".
        return if cfg.enabled && daemon.is_running() {
            None
        } else if cfg.enabled {
            Some("Auto-rotate is on but the daemon is not running, so no terminal will be moved. Start it with `csq daemon start`.".to_string())
        } else {
            Some("Auto-rotate is off machine-wide, but per-terminal settings could not be listed, so a terminal set to on may still be moved.".to_string())
        };
    };
    if !cfg.enabled && live_on == 0 {
        Some("Turn it on with `csq rotation on`.".to_string())
    } else if !cfg.enabled && !daemon.is_running() {
        Some(format!(
            "Auto-rotate is off machine-wide, but {live_on} terminal(s) are set to on and the daemon is not running, so no terminal will be moved. Start it with `csq daemon start`."
        ))
    } else if !cfg.enabled {
        Some(format!(
            "Auto-rotate is off machine-wide, but {live_on} terminal(s) are set to on and will still be moved."
        ))
    } else if !daemon.is_running() {
        Some("Auto-rotate is on but the daemon is not running, so no terminal will be moved. Start it with `csq daemon start`.".to_string())
    } else {
        None
    }
}

fn update_error(error: RotationUpdateError) -> anyhow::Error {
    anyhow!("{}", error.redacted_message())
}

/// `csq rotation on|off`: one write through the shared core, then a report.
fn toggle(
    base_dir: &Path,
    enable: bool,
    json: bool,
    daemon: impl FnOnce() -> DaemonView,
    out: &mut impl Write,
) -> Result<()> {
    let cfg =
        config::set_enabled(base_dir, enable).map_err(|e| anyhow!("{}", e.redacted_message()))?;
    let daemon = daemon();
    if json {
        let sessions = session_override::list_overrides(base_dir);
        writeln!(out, "{}", json_of(base_dir, &cfg, daemon, &sessions)?)?;
    } else if enable {
        writeln!(
            out,
            "Auto-rotate is on (threshold {}%, cooldown {}s).",
            config::format_percent(cfg.threshold_percent),
            cfg.cooldown_secs
        )?;
        if let Some(note) = advice(&cfg, daemon, live_on_count_for(base_dir)) {
            writeln!(out, "{note}")?;
        }
    } else {
        writeln!(out, "Auto-rotate is off.")?;
        match live_on_count_for(base_dir) {
            Some(0) => {}
            Some(live_on) => writeln!(
                out,
                "{live_on} terminal(s) are set to on and will still be moved; reset them with `csq rotation session default`."
            )?,
            None => writeln!(
                out,
                "Per-terminal settings could not be listed, so a terminal set to on may still be moved."
            )?,
        }
    }
    Ok(())
}

/// Machine-readable result of `csq rotation session`.
#[derive(Debug, Serialize)]
struct SessionJson {
    /// The terminal number (`term-<pid>`).
    session: u32,
    /// `on` | `off` | `default` — what is now stored for this terminal.
    auto_swap: &'static str,
    /// The machine-wide setting the terminal falls back to under `default`.
    machine_enabled: bool,
    /// Whether the daemon may move this terminal now.
    effective: bool,
    /// `running` | `unresponsive` | `stale` | `not_running`.
    daemon: &'static str,
}

/// `csq rotation session on|off|default [--session <TERM-PID>]`.
///
/// Resolves the target FIRST (the named terminal, else the one in
/// `current_config_dir`), admits its handle dir strictly under the canonical base,
/// then writes the override. A refusal prints fixed text and writes nothing.
/// `current_config_dir` is injected (the caller passes `CLAUDE_CONFIG_DIR`) so
/// tests never touch the process environment.
pub(crate) fn session_action(
    base_dir: &Path,
    mode: SessionRotationMode,
    session: Option<&str>,
    current_config_dir: Option<&Path>,
    json: bool,
    daemon: impl FnOnce() -> DaemonView,
    out: &mut impl Write,
) -> Result<()> {
    let pid = match session {
        // `set` below admits the handle dir; nothing is written before it does.
        Some(name) => session_override::parse_session_id(name).map_err(session_error)?,
        None => {
            session_override::resolve_current_session(base_dir, current_config_dir)
                .map_err(session_error)?
                .0
        }
    };
    // An unreadable rotation.json refuses `on`/`off`, as the desktop commands do:
    // the daemon skips every terminal while it is broken, so reporting a defaulted
    // machine setting would misstate what the daemon will do. Nothing is written.
    // `default` only CLEARS a setting, so it skips the machine-config read: while
    // the file is unreadable the daemon rotates nothing, so clearing is safe and
    // must stay possible; the reported machine setting is then `false` (nothing
    // rotates), not a read of the file.
    let machine_enabled = if mode == SessionRotationMode::Default {
        config::load(base_dir)
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
    } else {
        config::load(base_dir)
            .map_err(|_| anyhow!(UNREADABLE_MESSAGE))?
            .enabled
    };
    // `on`/`off` only mean something where the rotator can move the terminal;
    // `default` stays allowed so a stale setting can always be cleared.
    if mode != SessionRotationMode::Default {
        let dir = session_override::resolve_session_dir(base_dir, pid).map_err(session_error)?;
        let accounts = csq_core::accounts::discovery::discover_all(base_dir);
        if !csq_core::rotation::eligibility::session_rotation_eligible(base_dir, &accounts, &dir) {
            return Err(anyhow!(INELIGIBLE_MESSAGE));
        }
    }
    let state = session_override::set(base_dir, pid, mode).map_err(session_error)?;
    // `Unreadable` right after our own write means the file we just published is not
    // readable back; say so rather than reporting success.
    if state == SessionRotationState::Unreadable {
        return Err(session_error(SessionRotationError::Write));
    }
    let effective = session_override::rotates(machine_enabled, state);
    let daemon = daemon();
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string(&SessionJson {
                session: pid,
                auto_swap: state.as_str(),
                machine_enabled,
                effective,
                daemon: daemon.key(),
            })?
        )?;
        return Ok(());
    }
    match state {
        SessionRotationState::On => writeln!(
            out,
            "Auto-rotate for term-{pid}: on (this terminal only; it can be moved to a lower-usage account{}).",
            if machine_enabled {
                ""
            } else {
                " even though auto-rotate is off machine-wide"
            }
        )?,
        SessionRotationState::Off => writeln!(
            out,
            "Auto-rotate for term-{pid}: off (this terminal is never moved{}).",
            if machine_enabled {
                " even though auto-rotate is on machine-wide"
            } else {
                ""
            }
        )?,
        SessionRotationState::Default | SessionRotationState::Unreadable => writeln!(
            out,
            "Auto-rotate for term-{pid}: follows the machine setting (currently {}).",
            if machine_enabled { "on" } else { "off" }
        )?,
    }
    if effective && !daemon.is_running() {
        writeln!(
            out,
            "The daemon is not running, so this terminal will not be moved. Start it with `csq daemon start`."
        )?;
    }
    Ok(())
}

fn session_error(error: SessionRotationError) -> anyhow::Error {
    anyhow!("{error}")
}

/// Runs one `csq rotation` action, writing user output to `out`. The daemon
/// probe is injected so tests never touch a real daemon.
pub(crate) fn run(
    base_dir: &Path,
    action: RotationCommand,
    json: bool,
    daemon: impl FnOnce() -> DaemonView,
    out: &mut impl Write,
) -> Result<()> {
    match action {
        RotationCommand::Status => {
            let cfg = config::load(base_dir).map_err(|_| anyhow!(UNREADABLE_MESSAGE))?;
            let daemon = daemon();
            let sessions = session_override::list_overrides(base_dir);
            if json {
                writeln!(out, "{}", json_of(base_dir, &cfg, daemon, &sessions)?)?;
            } else {
                write!(out, "{}", status_text(base_dir, &cfg, daemon, &sessions))?;
            }
        }
        RotationCommand::Session { mode, session } => {
            let current = std::env::var_os("CLAUDE_CONFIG_DIR").map(std::path::PathBuf::from);
            session_action(
                base_dir,
                mode.mode(),
                session.as_deref(),
                current.as_deref(),
                json,
                daemon,
                out,
            )?;
        }
        RotationCommand::On => toggle(base_dir, true, json, daemon, out)?,
        RotationCommand::Off => toggle(base_dir, false, json, daemon, out)?,
        RotationCommand::Set {
            threshold,
            cooldown,
        } => {
            // A negative cooldown can never be in range; refuse it with the
            // same fixed text as any other out-of-range value.
            let cooldown = match cooldown {
                Some(c) => {
                    Some(u64::try_from(c).map_err(|_| anyhow!(config::COOLDOWN_RANGE_MESSAGE))?)
                }
                None => None,
            };
            let cfg = config::update(base_dir, threshold, cooldown).map_err(update_error)?;
            let daemon = daemon();
            if json {
                let sessions = session_override::list_overrides(base_dir);
                writeln!(out, "{}", json_of(base_dir, &cfg, daemon, &sessions)?)?;
            } else {
                writeln!(
                    out,
                    "Auto-rotate settings saved: threshold {}%, cooldown {}s.",
                    config::format_percent(cfg.threshold_percent),
                    cfg.cooldown_secs
                )?;
                if !cfg.enabled {
                    writeln!(
                        out,
                        "Auto-rotate is currently off; turn it on with `csq rotation on`."
                    )?;
                }
            }
        }
    }
    Ok(())
}

pub fn handle(base_dir: &Path, action: RotationCommand, json: bool) -> Result<()> {
    run(
        base_dir,
        action,
        json,
        || DaemonView::probe(base_dir),
        &mut std::io::stdout().lock(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn run_capture(
        base: &Path,
        action: RotationCommand,
        json: bool,
        daemon: DaemonView,
    ) -> Result<String> {
        let mut buf = Vec::new();
        run(base, action, json, || daemon, &mut buf)?;
        Ok(String::from_utf8(buf).unwrap())
    }

    const UP: DaemonView = DaemonView::Running { pid: 4242 };

    #[test]
    fn rotation_on_then_off_writes_the_file_and_status_reads_it_back() {
        let dir = TempDir::new().unwrap();

        let out = run_capture(dir.path(), RotationCommand::On, false, UP).unwrap();
        assert!(out.starts_with("Auto-rotate is on"), "{out}");
        assert!(config::load(dir.path()).unwrap().enabled);
        let status = run_capture(dir.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(status.starts_with("Auto-rotate: on\n"), "{status}");

        let out = run_capture(dir.path(), RotationCommand::Off, false, UP).unwrap();
        assert_eq!(out, "Auto-rotate is off.\n");
        assert!(!config::load(dir.path()).unwrap().enabled);
        let status = run_capture(dir.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(status.starts_with("Auto-rotate: off\n"), "{status}");
    }

    #[test]
    fn rotation_status_reports_the_files_values() {
        let dir = TempDir::new().unwrap();
        config::save(
            dir.path(),
            &RotationConfig {
                enabled: true,
                threshold_percent: 80.5,
                cooldown_secs: 120,
                exclude_accounts: vec![3, 7],
            },
        )
        .unwrap();

        let out = run_capture(dir.path(), RotationCommand::Status, false, UP).unwrap();

        assert!(out.contains("Auto-rotate: on"), "{out}");
        assert!(out.contains("Threshold: 80.5%"), "{out}");
        assert!(out.contains("Cooldown:  120s"), "{out}");
        assert!(out.contains("accounts 3, 7"), "{out}");
        assert!(out.contains("running (PID 4242)"), "{out}");
    }

    #[test]
    fn rotation_status_reports_defaults_when_the_file_is_absent() {
        let dir = TempDir::new().unwrap();
        assert!(!config::config_path(dir.path()).exists());

        let out = run_capture(
            dir.path(),
            RotationCommand::Status,
            false,
            DaemonView::NotRunning,
        )
        .unwrap();

        assert!(out.starts_with("Auto-rotate: off\n"), "{out}");
        assert!(out.contains("Threshold: 95%"), "{out}");
        assert!(out.contains("Cooldown:  300s"), "{out}");
        assert!(out.contains("Daemon:    not running"), "{out}");
        assert!(out.contains("csq rotation on"), "{out}");
        assert!(
            !config::config_path(dir.path()).exists(),
            "status must be read-only"
        );
    }

    #[test]
    fn rotation_status_says_nothing_will_move_when_on_without_a_daemon() {
        let dir = TempDir::new().unwrap();
        config::set_enabled(dir.path(), true).unwrap();

        for down in [
            DaemonView::NotRunning,
            DaemonView::Stale,
            DaemonView::Unresponsive,
        ] {
            let out = run_capture(dir.path(), RotationCommand::Status, false, down).unwrap();
            assert!(out.contains("no terminal will be moved"), "{down:?}: {out}");
            assert!(out.contains("csq daemon start"), "{down:?}: {out}");
        }
        let out = run_capture(dir.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(!out.contains("no terminal will be moved"), "{out}");
    }

    #[test]
    fn rotation_status_json_carries_the_values_and_daemon_state() {
        let dir = TempDir::new().unwrap();
        config::save(
            dir.path(),
            &RotationConfig {
                enabled: true,
                threshold_percent: 90.0,
                cooldown_secs: 60,
                exclude_accounts: vec![2],
            },
        )
        .unwrap();

        let up: serde_json::Value = serde_json::from_str(
            &run_capture(dir.path(), RotationCommand::Status, true, UP).unwrap(),
        )
        .unwrap();
        assert_eq!(up["enabled"], true);
        assert_eq!(up["threshold_percent"], 90.0);
        assert_eq!(up["cooldown_secs"], 60);
        assert_eq!(up["exclude_accounts"], serde_json::json!([2]));
        assert_eq!(up["daemon"], "running");
        assert_eq!(up["rotating"], true);

        let down: serde_json::Value = serde_json::from_str(
            &run_capture(
                dir.path(),
                RotationCommand::Status,
                true,
                DaemonView::NotRunning,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(down["daemon"], "not_running");
        assert_eq!(down["rotating"], false);
    }

    #[test]
    fn rotation_status_on_an_unreadable_file_fails_with_fixed_text() {
        let dir = TempDir::new().unwrap();
        std::fs::write(config::config_path(dir.path()), b"{not valid json").unwrap();

        let err = run_capture(dir.path(), RotationCommand::Status, false, UP).unwrap_err();

        assert_eq!(err.to_string(), UNREADABLE_MESSAGE);
        assert!(!err.to_string().contains(dir.path().to_str().unwrap()));
    }

    #[test]
    fn rotation_set_changes_the_values_and_keeps_on_off() {
        let dir = TempDir::new().unwrap();
        config::set_enabled(dir.path(), true).unwrap();

        let out = run_capture(
            dir.path(),
            RotationCommand::Set {
                threshold: Some(70.0),
                cooldown: Some(30),
            },
            false,
            UP,
        )
        .unwrap();

        assert_eq!(
            out,
            "Auto-rotate settings saved: threshold 70%, cooldown 30s.\n"
        );
        let cfg = config::load(dir.path()).unwrap();
        assert_eq!((cfg.threshold_percent, cfg.cooldown_secs), (70.0, 30));
        assert!(cfg.enabled, "set must not change on/off");
    }

    #[test]
    fn rotation_set_refuses_out_of_range_with_fixed_text_and_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let cases: [(Option<f64>, Option<i64>, &str); 6] = [
            (Some(0.0), None, config::THRESHOLD_RANGE_MESSAGE),
            (Some(101.0), None, config::THRESHOLD_RANGE_MESSAGE),
            (Some(-5.0), None, config::THRESHOLD_RANGE_MESSAGE),
            (None, Some(0), config::COOLDOWN_RANGE_MESSAGE),
            (None, Some(-1), config::COOLDOWN_RANGE_MESSAGE),
            (None, Some(86_401), config::COOLDOWN_RANGE_MESSAGE),
        ];
        for (threshold, cooldown, expected) in cases {
            let err = run_capture(
                dir.path(),
                RotationCommand::Set {
                    threshold,
                    cooldown,
                },
                false,
                UP,
            )
            .unwrap_err();
            assert_eq!(err.to_string(), expected, "{threshold:?} {cooldown:?}");
        }
        let err = run_capture(
            dir.path(),
            RotationCommand::Set {
                threshold: None,
                cooldown: None,
            },
            false,
            UP,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), config::NOTHING_TO_UPDATE_MESSAGE);
        assert!(
            !config::config_path(dir.path()).exists(),
            "refused input must not create rotation.json"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rotation_on_leaves_an_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        run_capture(dir.path(), RotationCommand::On, false, UP).unwrap();
        let mode = std::fs::metadata(config::config_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rotation_daemon_view_maps_every_detection_result() {
        assert_eq!(
            DaemonView::from_detection(&DetectResult::Healthy {
                pid: 7,
                socket_path: "/x".into(),
                daemon_version: "1".into(),
            }),
            DaemonView::Running { pid: 7 }
        );
        assert_eq!(
            DaemonView::from_detection(&DetectResult::Unhealthy { reason: "r".into() }),
            DaemonView::Unresponsive
        );
        assert_eq!(
            DaemonView::from_detection(&DetectResult::Stale { reason: "r".into() }),
            DaemonView::Stale
        );
        assert_eq!(
            DaemonView::from_detection(&DetectResult::NotRunning),
            DaemonView::NotRunning
        );
    }
    // ── per-session override ─────────────────────────────────────────────

    /// A `term-<own pid>` dir bound to Claude Code slot 1: the owning process
    /// (this test binary) is alive, so `status` lists it, and the rotator's
    /// eligibility predicate admits it.
    fn live_handle(base: &Path) -> (u32, std::path::PathBuf) {
        let (pid, dir) = live_unbound_handle(base);
        csq_core::accounts::markers::write_csq_account_legacy(
            &dir,
            csq_core::types::AccountNum::try_from(1u16).unwrap(),
        )
        .unwrap();
        (pid, dir)
    }

    /// Like [`live_handle`] but bound to slot `slot`, which pins a third-party
    /// `ANTHROPIC_BASE_URL` (the rotator skips it).
    fn live_third_party_handle(base: &Path, slot: u16) -> (u32, std::path::PathBuf) {
        let (pid, dir) = live_unbound_handle(base);
        let cfg = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.z.ai/api/anthropic"}}"#,
        )
        .unwrap();
        csq_core::accounts::markers::write_csq_account_legacy(
            &dir,
            csq_core::types::AccountNum::try_from(slot).unwrap(),
        )
        .unwrap();
        (pid, dir)
    }

    fn live_unbound_handle(base: &Path) -> (u32, std::path::PathBuf) {
        let pid = std::process::id();
        let dir = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&dir).unwrap();
        (pid, dir)
    }

    fn session_capture(
        base: &Path,
        mode: SessionRotationMode,
        session: Option<&str>,
        current: Option<&Path>,
        json: bool,
        daemon: DaemonView,
    ) -> Result<String> {
        let mut buf = Vec::new();
        session_action(base, mode, session, current, json, || daemon, &mut buf)?;
        Ok(String::from_utf8(buf).unwrap())
    }

    #[test]
    fn session_command_targets_the_current_terminals_handle_dir() {
        let base = TempDir::new().unwrap();
        let (pid, handle) = live_handle(base.path());
        let out = session_capture(
            base.path(),
            SessionRotationMode::On,
            None,
            Some(&handle),
            false,
            UP,
        )
        .unwrap();
        assert!(
            out.starts_with(&format!("Auto-rotate for term-{pid}: on")),
            "{out}"
        );
        assert!(
            out.contains("even though auto-rotate is off machine-wide"),
            "{out}"
        );
        assert_eq!(
            session_override::read_override(&handle),
            SessionRotationState::On
        );
        // The machine-wide file is not touched by a session change.
        assert!(!config::config_path(base.path()).exists());

        let out = session_capture(
            base.path(),
            SessionRotationMode::Default,
            None,
            Some(&handle),
            false,
            UP,
        )
        .unwrap();
        assert!(
            out.contains("follows the machine setting (currently off)"),
            "{out}"
        );
        assert!(!handle.join(session_override::OVERRIDE_FILE).exists());
    }

    #[test]
    fn session_command_with_a_named_terminal_accepts_bare_and_prefixed_numbers() {
        let base = TempDir::new().unwrap();
        let (pid, handle) = live_handle(base.path());
        for name in [pid.to_string(), format!("term-{pid}")] {
            session_capture(
                base.path(),
                SessionRotationMode::Off,
                Some(&name),
                None,
                false,
                UP,
            )
            .unwrap();
            assert_eq!(
                session_override::read_override(&handle),
                SessionRotationState::Off,
                "{name}"
            );
            session_capture(
                base.path(),
                SessionRotationMode::Default,
                Some(&name),
                None,
                false,
                UP,
            )
            .unwrap();
        }
    }

    #[test]
    fn session_command_refuses_outside_the_base_and_writes_nothing() {
        let base = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let (pid, handle) = live_handle(base.path());
        // This terminal's CLAUDE_CONFIG_DIR is a term dir under ANOTHER base.
        let foreign = other.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&foreign).unwrap();
        for current in [Some(foreign.as_path()), Some(other.path()), None] {
            let err = session_capture(
                base.path(),
                SessionRotationMode::On,
                None,
                current,
                false,
                UP,
            )
            .unwrap_err()
            .to_string();
            assert!(!err.contains(other.path().to_str().unwrap()), "{err}");
            assert!(!err.contains(base.path().to_str().unwrap()), "{err}");
        }
        // A config dir is not a session either.
        let config_dir = base.path().join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        assert!(session_capture(
            base.path(),
            SessionRotationMode::On,
            None,
            Some(&config_dir),
            false,
            UP
        )
        .is_err());
        // Named forms that are not a terminal number, or that name no session.
        for bad in ["../x", "0", "term-", "12 34", "nope", "99999999999"] {
            assert!(
                session_capture(
                    base.path(),
                    SessionRotationMode::On,
                    Some(bad),
                    None,
                    false,
                    UP
                )
                .is_err(),
                "{bad:?}"
            );
        }
        assert!(session_capture(
            base.path(),
            SessionRotationMode::On,
            Some("4194001"),
            None,
            false,
            UP
        )
        .is_err());
        for dir in [
            foreign.as_path(),
            handle.as_path(),
            config_dir.as_path(),
            other.path(),
            base.path(),
        ] {
            assert!(
                !dir.join(session_override::OVERRIDE_FILE).exists(),
                "a refused request wrote into {dir:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn session_command_refuses_a_symlinked_terminal_dir() {
        let base = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let pid = std::process::id();
        let link = base.path().join(format!("term-{pid}"));
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        for (session, current) in [(Some(pid.to_string()), None), (None, Some(link.clone()))] {
            assert!(session_capture(
                base.path(),
                SessionRotationMode::On,
                session.as_deref(),
                current.as_deref(),
                false,
                UP
            )
            .is_err());
        }
        assert!(!outside
            .path()
            .join(session_override::OVERRIDE_FILE)
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn session_command_leaves_an_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let base = TempDir::new().unwrap();
        let (_, handle) = live_handle(base.path());
        session_capture(
            base.path(),
            SessionRotationMode::On,
            None,
            Some(&handle),
            false,
            UP,
        )
        .unwrap();
        let mode = std::fs::metadata(handle.join(session_override::OVERRIDE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn session_command_json_reports_the_effective_decision() {
        let base = TempDir::new().unwrap();
        let (pid, handle) = live_handle(base.path());
        let json: serde_json::Value = serde_json::from_str(
            &session_capture(
                base.path(),
                SessionRotationMode::On,
                None,
                Some(&handle),
                true,
                UP,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["session"], pid);
        assert_eq!(json["auto_swap"], "on");
        assert_eq!(json["machine_enabled"], false);
        assert_eq!(json["effective"], true);
        assert_eq!(json["daemon"], "running");

        config::set_enabled(base.path(), true).unwrap();
        let json: serde_json::Value = serde_json::from_str(
            &session_capture(
                base.path(),
                SessionRotationMode::Off,
                None,
                Some(&handle),
                true,
                UP,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["auto_swap"], "off");
        assert_eq!(json["machine_enabled"], true);
        assert_eq!(json["effective"], false);
    }

    #[test]
    fn session_command_says_nothing_will_move_when_the_daemon_is_down() {
        let base = TempDir::new().unwrap();
        let (_, handle) = live_handle(base.path());
        let out = session_capture(
            base.path(),
            SessionRotationMode::On,
            None,
            Some(&handle),
            false,
            DaemonView::NotRunning,
        )
        .unwrap();
        assert!(out.contains("csq daemon start"), "{out}");
        let out = session_capture(
            base.path(),
            SessionRotationMode::Off,
            None,
            Some(&handle),
            false,
            DaemonView::NotRunning,
        )
        .unwrap();
        assert!(!out.contains("csq daemon start"), "{out}");
    }

    #[test]
    fn status_lists_live_sessions_with_their_own_setting_and_nothing_else() {
        let base = TempDir::new().unwrap();
        let (pid, handle) = live_handle(base.path());
        // No override yet: no sessions block, no sessions in JSON.
        let out = run_capture(base.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(!out.contains("Sessions"), "{out}");

        session_override::write_override(&handle, SessionRotationMode::On).unwrap();
        let out = run_capture(base.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(out.contains("Sessions with their own setting:"), "{out}");
        assert!(out.contains(&format!("term-{pid}: on")), "{out}");
        let json: serde_json::Value = serde_json::from_str(
            &run_capture(base.path(), RotationCommand::Status, true, UP).unwrap(),
        )
        .unwrap();
        assert_eq!(json["sessions_listed"], true);
        assert_eq!(json["sessions"][0]["pid"], pid);
        assert_eq!(json["sessions"][0]["mode"], "on");

        // A corrupt file is reported, not hidden and not repaired.
        std::fs::write(handle.join(session_override::OVERRIDE_FILE), b"{bad").unwrap();
        let out = run_capture(base.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(out.contains(&format!("term-{pid}: unreadable")), "{out}");
        assert_eq!(
            std::fs::read(handle.join(session_override::OVERRIDE_FILE)).unwrap(),
            b"{bad"
        );
    }

    /// C12: an unreadable rotation.json refuses, with fixed text, and writes
    /// nothing — it does not report a defaulted `machine_enabled:false`.
    #[test]
    fn session_command_refuses_when_the_machine_file_is_unreadable() {
        let base = TempDir::new().unwrap();
        let (_, handle) = live_handle(base.path());
        std::fs::write(config::config_path(base.path()), b"{not valid json").unwrap();
        for json in [false, true] {
            let err = session_capture(
                base.path(),
                SessionRotationMode::On,
                None,
                Some(&handle),
                json,
                UP,
            )
            .unwrap_err()
            .to_string();
            assert_eq!(err, UNREADABLE_MESSAGE);
        }
        assert!(!handle.join(session_override::OVERRIDE_FILE).exists());
    }

    /// C2: `csq rotation session on|off` refuses a terminal the rotator never
    /// moves; `default` still clears a stale setting.
    #[test]
    fn session_command_refuses_a_terminal_the_rotator_never_moves() {
        for bind in [live_third_party_handle, live_unbound_handle_for_test] {
            let base = TempDir::new().unwrap();
            let (_, handle) = bind(base.path(), 9);
            for mode in [SessionRotationMode::On, SessionRotationMode::Off] {
                let err = session_capture(base.path(), mode, None, Some(&handle), false, UP)
                    .unwrap_err()
                    .to_string();
                assert_eq!(err, INELIGIBLE_MESSAGE);
                assert!(!handle.join(session_override::OVERRIDE_FILE).exists());
            }
            session_override::write_override(&handle, SessionRotationMode::On).unwrap();
            session_capture(
                base.path(),
                SessionRotationMode::Default,
                None,
                Some(&handle),
                false,
                UP,
            )
            .unwrap();
            assert!(!handle.join(session_override::OVERRIDE_FILE).exists());
        }
    }

    fn live_unbound_handle_for_test(base: &Path, _slot: u16) -> (u32, std::path::PathBuf) {
        live_unbound_handle(base)
    }

    /// C3: machine off, one live terminal `on`: status, JSON and the follow-up
    /// advice say the daemon WILL move it, and warn when no daemon is running.
    #[test]
    fn status_reports_a_live_on_override_when_the_machine_setting_is_off() {
        let base = TempDir::new().unwrap();
        let (_, handle) = live_handle(base.path());
        session_override::write_override(&handle, SessionRotationMode::On).unwrap();

        let out = run_capture(base.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(out.starts_with("Auto-rotate: off\n"), "{out}");
        assert!(
            out.contains("1 terminal(s) are set to on and will still be moved"),
            "{out}"
        );
        assert!(!out.contains("Turn it on with"), "{out}");
        let json: serde_json::Value = serde_json::from_str(
            &run_capture(base.path(), RotationCommand::Status, true, UP).unwrap(),
        )
        .unwrap();
        assert_eq!(json["enabled"], false);
        assert_eq!(json["rotating"], true);
        assert_eq!(json["sessions_on"], 1);

        let down = run_capture(
            base.path(),
            RotationCommand::Status,
            false,
            DaemonView::NotRunning,
        )
        .unwrap();
        assert!(
            down.contains("daemon is not running, so no terminal will be moved"),
            "{down}"
        );
        let json: serde_json::Value = serde_json::from_str(
            &run_capture(
                base.path(),
                RotationCommand::Status,
                true,
                DaemonView::NotRunning,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["rotating"], false);

        // `off` machine-wide says so for the terminal that is still on.
        let out = run_capture(base.path(), RotationCommand::Off, false, UP).unwrap();
        assert!(
            out.contains("1 terminal(s) are set to on and will still be moved"),
            "{out}"
        );
    }

    /// An `on` override on a terminal the rotator skips (3P) is not rotation.
    #[test]
    fn summary_line_reports_live_on_overrides_only_when_the_machine_is_off() {
        let base = TempDir::new().unwrap();
        let (_, handle) = live_handle(base.path());
        assert!(summary_line_with_sessions(base.path()).starts_with("Auto-rotate: off ("));
        session_override::write_override(&handle, SessionRotationMode::On).unwrap();
        assert_eq!(
            summary_line_with_sessions(base.path()),
            "Auto-rotate: off machine-wide, but 1 terminal(s) set to on are still moved"
        );
        config::set_enabled(base.path(), true).unwrap();
        assert!(summary_line_with_sessions(base.path()).starts_with("Auto-rotate: on"));
    }

    /// N5: an unlistable per-terminal state is unknown, never "none".
    #[test]
    fn unlisted_terminals_are_unknown_not_zero() {
        let base = TempDir::new().unwrap();
        assert_eq!(
            live_on_count(base.path(), &Err(SessionRotationError::List)),
            None
        );
        assert_eq!(live_on_count(base.path(), &Ok(Vec::new())), Some(0));
        let line = summary_line_from("Auto-rotate: off (turn it on)".to_string(), None);
        assert!(line.contains("could not be listed"), "{line}");
        let on = RotationConfig {
            enabled: true,
            ..RotationConfig::default()
        };
        let note = advice(&on, DaemonView::NotRunning, None).unwrap();
        assert!(note.contains("daemon is not running"), "{note}");
        let off = RotationConfig::default();
        let note = advice(&off, UP, None).unwrap();
        assert!(note.contains("could not be listed"), "{note}");
    }

    /// N4 (corr): `default` clears a stale setting even while rotation.json is
    /// unreadable; `on` still refuses and writes nothing.
    #[test]
    fn session_default_clears_while_the_machine_config_is_unreadable() {
        let base = TempDir::new().unwrap();
        let (pid, handle) = live_handle(base.path());
        session_override::write_override(&handle, SessionRotationMode::On).unwrap();
        std::fs::write(config::config_path(base.path()), b"{not valid json").unwrap();
        let err = session_capture(
            base.path(),
            SessionRotationMode::On,
            Some(&pid.to_string()),
            None,
            false,
            UP,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), UNREADABLE_MESSAGE);
        session_capture(
            base.path(),
            SessionRotationMode::Default,
            Some(&pid.to_string()),
            None,
            false,
            UP,
        )
        .unwrap();
        assert_eq!(
            session_override::read_override(&handle),
            SessionRotationState::Default
        );
    }

    /// Cloud-Claude (Vertex/Bedrock) slots carry no base URL but are not Claude
    /// sign-in sessions: refused by `csq rotation session`, never counted.
    #[test]
    fn cloud_claude_slot_is_refused_and_not_counted() {
        for flag in ["CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_BEDROCK"] {
            let base = TempDir::new().unwrap();
            let (pid, dir) = live_unbound_handle(base.path());
            let cfg = base.path().join("config-6");
            std::fs::create_dir_all(&cfg).unwrap();
            std::fs::write(
                cfg.join("settings.json"),
                format!(r#"{{"env":{{"{flag}":"1"}}}}"#),
            )
            .unwrap();
            csq_core::accounts::markers::write_csq_account_legacy(
                &dir,
                csq_core::types::AccountNum::try_from(6u16).unwrap(),
            )
            .unwrap();
            for mode in [SessionRotationMode::On, SessionRotationMode::Off] {
                let err =
                    session_capture(base.path(), mode, Some(&pid.to_string()), None, false, UP)
                        .unwrap_err();
                assert_eq!(err.to_string(), INELIGIBLE_MESSAGE, "{flag}");
            }
            // An `on` that predates the guard is not counted either.
            session_override::write_override(&dir, SessionRotationMode::On).unwrap();
            assert_eq!(
                live_on_count(base.path(), &session_override::list_overrides(base.path())),
                Some(0),
                "{flag}"
            );
        }
    }

    #[test]
    fn status_does_not_count_an_on_override_the_rotator_would_skip() {
        let base = TempDir::new().unwrap();
        let (_, handle) = live_third_party_handle(base.path(), 9);
        session_override::write_override(&handle, SessionRotationMode::On).unwrap();
        let json: serde_json::Value = serde_json::from_str(
            &run_capture(base.path(), RotationCommand::Status, true, UP).unwrap(),
        )
        .unwrap();
        assert_eq!(json["sessions_on"], 0);
        assert_eq!(json["rotating"], false);
        let out = run_capture(base.path(), RotationCommand::Status, false, UP).unwrap();
        assert!(out.contains("Turn it on with"), "{out}");
    }
}
