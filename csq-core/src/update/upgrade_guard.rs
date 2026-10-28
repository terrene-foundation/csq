//! Stop an explicitly selected installation before its replacement can run.
//!
//! This controller initializes no daemon, account state or application, and
//! takes no csq lock. Its only success condition is a complete final scan with
//! no verified live target and signaled exit of every retained target handle.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

pub mod drain;
#[cfg(windows)]
pub mod quit_event;
#[cfg(windows)]
pub mod windows;

/// A snapshot entry supplies only a negative filter, never stop authority.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub pid: u32,
    pub basename: Option<OsString>,
}

/// Desktop processes can host the refresher even without daemon PID ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Daemon,
    Desktop,
    Cli,
}

pub struct Inspected<H> {
    pub handle: H,
    pub installed: bool,
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitChannel {
    Bound,
    Legacy,
    Unavailable,
}

/// Native providers must bind full-image verification and every destructive
/// request to an owned process handle. A missing identity is an error, not a
/// foreign-process verdict. `None` requires a verified non-target image or exit.
/// Installed images refuse on every foreign, SYSTEM, or unreadable owner fact.
pub trait Backend {
    type Handle;
    fn scan(&mut self) -> Result<Vec<Candidate>>;
    fn legacy_event_present(&mut self) -> Result<bool> {
        Ok(false)
    }
    fn inspect(
        &mut self,
        candidate: &Candidate,
        installed: &[PathBuf],
    ) -> Result<Option<Inspected<Self::Handle>>>;
    fn pid(handle: &Self::Handle) -> u32;
    fn birth(handle: &Self::Handle) -> u64;
    fn quit_channel(&mut self, handle: &Self::Handle) -> Result<QuitChannel>;
    fn request_quit(&mut self, handle: &Self::Handle, channel: QuitChannel) -> Result<()>;
    fn exited(&mut self, handle: &Self::Handle) -> Result<bool>;
    fn elapsed(&self) -> Duration;
    fn pause(&mut self, duration: Duration);
}

/// Operator wait budgets, NEVER an upper bound on a refresh or credential write.
/// Each role gets `total` from its first request; expiry refuses, never terminates.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub total: Duration,
    pub poll: Duration,
}

/// Shared scheduling/exit-observation margin for guard and ordinary stop.
pub const SHUTDOWN_OBSERVATION_MARGIN: Duration = Duration::from_secs(5);

pub fn shutdown_observer_budget() -> Result<Duration> {
    drain::derived_shutdown_budget()?
        .checked_add(SHUTDOWN_OBSERVATION_MARGIN)
        .context("upgrade_shutdown_observer_budget_overflow")
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            total: shutdown_observer_budget().unwrap_or(Duration::MAX),
            poll: Duration::from_millis(25),
        }
    }
}

#[derive(Debug, Default)]
pub struct StopReport {
    pub selected: usize,
    pub verified_exits: usize,
}

/// Known differing basenames cannot equal an installed image path. Unknown or
/// non-Unicode names proceed to full native identity verification, fail closed.
pub fn basename_may_match(candidate: &Candidate, installed: &[PathBuf]) -> bool {
    let Some(name) = candidate.basename.as_ref().and_then(|name| name.to_str()) else {
        return true;
    };
    if name.is_empty() {
        return true;
    }
    // Other installed editions may listen on the same legacy user event.
    // Family names widen inspection; they never authorize a stop.
    let folded = name.to_ascii_lowercase();
    if folded == "csq"
        || folded == "csq.exe"
        || folded.starts_with("csq-")
        || folded.starts_with("csq_")
    {
        return true;
    }
    installed.iter().any(|image| {
        image
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|installed| {
                #[cfg(windows)]
                {
                    windows::basename_equal(name, installed).unwrap_or(true)
                }
                #[cfg(not(windows))]
                {
                    !installed.is_ascii()
                        || !name.is_ascii()
                        || name.eq_ignore_ascii_case(installed)
                }
            })
    })
}

struct Retained<H> {
    handle: H,
    role: Role,
    channel: Option<QuitChannel>,
    quit_requested: bool,
    exit_counted: bool,
}

fn manual_step(role: Role) -> &'static str {
    match role {
        Role::Daemon | Role::Desktop => "token-safe shutdown is unverified; leave this host running; S2/S3 migration is required before retrying the installer",
        Role::Cli => "close the csq terminal sessions listed below, then re-run the installer",
    }
}

/// Drains only exact installed images, preserving PID/birth-bound handles until
/// the final proof. New arrivals receive a graceful request where available,
/// within the role's original observer budget. No replacement/launch callback
/// exists here: callers may proceed only after this function returns `Ok`.
pub fn stop_installed<B: Backend>(
    backend: &mut B,
    installed: &[PathBuf],
    limits: Limits,
) -> Result<StopReport> {
    let mut progress = StopProgress::default();
    stop_installed_inner(backend, installed, limits, &mut progress).map_err(|error| {
        let recovery = if progress.daemon_exit_verified {
            Some("daemon already stopped — run csq daemon start after any remaining drain finishes, before resuming sessions")
        } else if progress.daemon_quit_requested {
            Some("daemon shutdown already requested and may still be draining — run csq daemon start after the drain finishes, before resuming sessions")
        } else { None };
        if let Some(recovery) = recovery {
            // Display only the controller's policy surface, never a source
            // chain, argv, credential response or panic payload. Keep the
            // original error intact underneath this added recovery context.
            let policy = error.to_string();
            let policy = if policy.starts_with("upgrade refused:") {
                crate::error::redact_tokens(&policy)
            } else {
                "upgrade refused: shutdown verification unavailable".to_owned()
            };
            error.context(format!("{recovery}; {policy}"))
        } else {
            error
        }
    })
}

#[derive(Default)]
struct StopProgress {
    daemon_quit_requested: bool,
    daemon_exit_verified: bool,
}

fn stop_installed_inner<B: Backend>(
    backend: &mut B,
    installed: &[PathBuf],
    limits: Limits,
    progress: &mut StopProgress,
) -> Result<StopReport> {
    if installed.is_empty() || installed.len() > 16 || installed.iter().any(|p| !p.is_absolute()) {
        bail!("upgrade refused: provide 1..16 absolute installed image paths");
    }
    if limits.total.is_zero()
        || limits.total > Duration::from_secs(300)
        || limits.poll.is_zero()
        || limits.poll > limits.total
    {
        bail!("upgrade refused: invalid bounded shutdown deadlines");
    }
    let mut phase_start = backend.elapsed();
    let mut role_starts = [None; 3];
    let mut retained: Vec<Retained<B::Handle>> = Vec::new();
    let mut identities = HashSet::new();
    let mut report = StopReport::default();
    let mut full_census = false;
    'census: loop {
        if backend.elapsed().saturating_sub(phase_start) >= limits.total {
            let mut pids = Vec::new();
            for target in &retained {
                if !backend.exited(&target.handle)? {
                    pids.push(format!(
                        "PID {} role={:?} start_filetime={}: {}",
                        B::pid(&target.handle),
                        target.role,
                        B::birth(&target.handle),
                        if target.channel == Some(QuitChannel::Legacy) {
                            "legacy daemon retained handle did not exit before deadline; leave admitted work running"
                        } else { manual_step(target.role) }
                    ));
                }
            }
            bail!("upgrade refused: shutdown deadline reached; surviving target PIDs {pids:?}");
        }
        full_census |= backend
            .legacy_event_present()
            .context("upgrade refused: legacy event presence cannot be determined")?;
        // Success requires a snapshot taken after all retained exits were counted.
        let exits_before_snapshot = report.verified_exits;
        let snapshot = backend
            .scan()
            .context("upgrade refused: incomplete process scan")?;
        if snapshot.len() > 32768 {
            bail!("upgrade refused: process snapshot exceeds verification bound");
        }
        for candidate in snapshot {
            // PID 0 is the Windows idle pseudo-process, never a user image.
            if candidate.pid == 0 {
                continue;
            }
            if backend.elapsed().saturating_sub(phase_start) >= limits.total {
                bail!("upgrade refused: deadline verifying PID {}", candidate.pid);
            }
            // Enumeration stays complete. A known different
            // basename is still a negative filter in legacy mode: the legacy
            // target is PID-file/image verified, and protected SYSTEM images
            // cannot add csq identity evidence. Renamed images require S2's
            // explicit installed-image list; unknown names still verify.
            if !basename_may_match(&candidate, installed) {
                continue;
            }
            let Some(inspected) = backend
                .inspect(&candidate, installed)
                .with_context(|| format!("upgrade refused: cannot verify PID {}", candidate.pid))?
            else {
                continue;
            };
            if !inspected.installed {
                if inspected.role != Role::Cli {
                    bail!(
                        "upgrade refused: non-installed daemon-capable PID {} ({:?}); {}",
                        B::pid(&inspected.handle),
                        inspected.role,
                        manual_step(inspected.role)
                    );
                }
                continue;
            }
            let handle = inspected.handle;
            let identity = (B::pid(&handle), B::birth(&handle));
            if identities.insert(identity) {
                if retained.len() >= 32768 {
                    bail!("upgrade refused: too many process identities during drain");
                }
                retained.push(Retained {
                    handle,
                    role: inspected.role,
                    channel: None,
                    quit_requested: false,
                    exit_counted: false,
                });
                report.selected += 1;
            }
        }
        // If a legacy event appeared during discovery, repeat the complete
        // census before any request. Known-different basenames remain a
        // negative filter; only verified daemon targets may use legacy quit.
        if backend.legacy_event_present()? && !full_census {
            full_census = true;
            continue;
        }
        // Complete discovery and all bound-endpoint checks before any signal.
        let mut active_role = None;
        for target in &mut retained {
            let pid = B::pid(&target.handle);
            if backend
                .exited(&target.handle)
                .with_context(|| format!("upgrade refused: cannot confirm exit of PID {pid}"))?
            {
                if !target.exit_counted {
                    report.verified_exits += 1;
                }
                target.exit_counted = true;
                if target.role == Role::Daemon && target.quit_requested {
                    progress.daemon_exit_verified = true;
                }
                continue;
            }
            active_role = Some(active_role.map_or(target.role, |role: Role| role.min(target.role)));
            if target.channel.is_none() {
                let channel = backend.quit_channel(&target.handle).with_context(|| {
                    format!("upgrade refused: cannot inspect quit endpoint for PID {pid}")
                })?;
                if channel == QuitChannel::Unavailable {
                    bail!(
                        "upgrade refused: PID {pid} role={:?} start_filetime={} has no bound quit endpoint; {}",
                        target.role,
                        B::birth(&target.handle),
                        manual_step(target.role)
                    );
                }
                if channel == QuitChannel::Legacy && target.role != Role::Daemon {
                    bail!("upgrade refused: legacy quit cannot prove token-safe completion for PID {pid}; leave it running; S2/S3 migration is required before retrying the installer");
                }
                target.channel = Some(channel);
            }
        }
        let Some(active_role) = active_role else {
            if exits_before_snapshot != retained.len() {
                continue;
            }
            if backend.elapsed().saturating_sub(phase_start) >= limits.total {
                bail!("upgrade refused: final verification exceeded shutdown deadline");
            }
            return Ok(report);
        };
        // A role's deadline starts at its first request, and is never reset by
        // a later arrival in that role. Sequential drains each get their policy.
        if let Some(started) = role_starts[active_role as usize] {
            phase_start = started;
            if backend.elapsed().saturating_sub(phase_start) >= limits.total {
                bail!("upgrade refused: role shutdown deadline reached before request");
            }
        }
        for target in &mut retained {
            if target.exit_counted || target.role != active_role {
                continue;
            }
            let pid = B::pid(&target.handle);
            // Request once, retaining the same process identity throughout.
            // No role can be force-stopped: a CLI may also rotate credentials.
            if !target.quit_requested {
                if backend.legacy_event_present()? && !full_census {
                    full_census = true;
                    continue 'census;
                }
                let channel = target
                    .channel
                    .context("upgrade refused: live endpoint not checked")?;
                if channel != QuitChannel::Unavailable {
                    phase_start =
                        *role_starts[active_role as usize].get_or_insert_with(|| backend.elapsed());
                    backend
                        .request_quit(&target.handle, channel)
                        .with_context(|| {
                            format!("upgrade refused: quit request failed for PID {pid}")
                        })?;
                }
                target.quit_requested = true;
                if target.role == Role::Daemon {
                    progress.daemon_quit_requested = true;
                }
            }
            let now = backend.elapsed();
            if now.saturating_sub(phase_start) >= limits.total {
                bail!(
                    "upgrade refused: PID {pid} role={:?} start_filetime={}; {}",
                    target.role,
                    B::birth(&target.handle),
                    manual_step(target.role)
                );
            }
        }
        let remaining = limits
            .total
            .saturating_sub(backend.elapsed().saturating_sub(phase_start));
        backend.pause(limits.poll.min(remaining));
    }
}

/// Ordinary daemon stop cannot signal a shared legacy event under upgrade
/// authority. Enumerate and retain all daemon candidates before any SetEvent.
#[cfg(any(windows, test))]
pub(crate) fn require_sole_daemon<B: Backend>(
    backend: &mut B,
    target: (u32, u64),
    own_pid: u32,
    installed: &[PathBuf],
) -> Result<()> {
    let rows = backend.scan().context("legacy stop census unavailable")?;
    if rows.len() > 32768 {
        bail!("legacy stop census exceeds verification bound");
    }
    let mut found = false;
    for row in rows {
        if row.pid == 0 || row.pid == own_pid || !basename_may_match(&row, installed) {
            continue;
        }
        let Some(process) = backend.inspect(&row, installed)? else {
            continue;
        };
        if process.role != Role::Daemon || backend.exited(&process.handle)? {
            continue;
        }
        if (B::pid(&process.handle), B::birth(&process.handle)) != target {
            bail!("legacy stop refused: another live same-user daemon may receive the shared event; zero signals sent");
        }
        found = true;
    }
    if !found {
        bail!("legacy stop target is absent from the verified daemon census");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
