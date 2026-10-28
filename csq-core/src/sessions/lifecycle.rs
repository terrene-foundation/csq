//! Trusted managed-Claude launch and lifecycle observation; never a scratch reaper.
#[cfg(unix)]
use super::lifecycle_records::{self as private, *};
#[cfg(unix)]
use serde::Serialize;
#[cfg(unix)]
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessProbe {
    Present(u64),
    Gone,
    Unknown,
}

pub fn probe_process(pid: u32) -> ProcessProbe {
    #[cfg(unix)]
    {
        let Ok(pid_i) = i32::try_from(pid) else {
            return ProcessProbe::Unknown;
        };
        if pid_i <= 0 {
            return ProcessProbe::Unknown;
        }
        let before = super::ancestor_start(pid);
        // Signal zero does not send a signal. Only kernel ESRCH proves Gone.
        let rc = unsafe { libc::kill(pid_i, 0) };
        if rc != 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                ProcessProbe::Gone
            } else {
                ProcessProbe::Unknown
            };
        }
        match (before, super::ancestor_start(pid)) {
            (Some(a), Some(b)) if a != 0 && a == b => ProcessProbe::Present(a),
            _ => ProcessProbe::Unknown,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        ProcessProbe::Unknown
    }
}

pub struct LaunchTicket {
    base: PathBuf,
    #[cfg(unix)]
    generation: String,
}

pub fn prepare_exec(handle: &Path) -> Option<LaunchTicket> {
    capture(handle, std::process::id())
}

pub fn capture_child(handle: &Path, child: &std::process::Child) -> Option<LaunchTicket> {
    capture(handle, child.id()).inspect(observe_ticket)
}

pub fn cancel_exec(ticket: Option<&LaunchTicket>) {
    mark(ticket, "exec_failed", "cancelled");
}
pub fn waited(ticket: Option<&LaunchTicket>, _status: &std::process::ExitStatus) {
    mark(ticket, "direct_wait", "ended");
}
fn mark(ticket: Option<&LaunchTicket>, reason: &str, name: &str) {
    #[cfg(unix)]
    if let Some(t) = ticket {
        if write_event(
            t,
            name,
            &End {
                observed: now().unwrap_or(0),
                reason: reason.into(),
            },
        )
        .is_err()
        {
            tracing::warn!(
                error_kind = "lifecycle_event_write_failed",
                "managed lifecycle event unavailable"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (ticket, reason, name);
}

#[cfg(unix)]
pub(crate) fn scratch_path(l: &Launch, id: &str, tmp: &Path) -> PathBuf {
    let slug = l
        .cwd
        .to_string_lossy()
        .chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect::<String>();
    tmp.join(format!("claude-{}", l.uid)).join(slug).join(id)
}

fn capture(handle: &Path, pid: u32) -> Option<LaunchTicket> {
    #[cfg(unix)]
    {
        let result = (|| -> io::Result<LaunchTicket> {
            let initial_identity = private::identity(handle)?;
            let handle = fs::canonicalize(handle)?;
            let base = handle.parent().ok_or_else(invalid)?.to_path_buf();
            let (handle_dev, handle_ino) = private::identity(&handle)?;
            if initial_identity != (handle_dev, handle_ino) {
                return Err(invalid());
            }
            let ProcessProbe::Present(exact) = probe_process(pid) else {
                return Err(invalid());
            };
            let store = private::store(&base, true)?;
            private::lock(&store)?;
            if store.names()?.len() >= MAX_RECORDS {
                return Err(invalid());
            }
            let generation = uuid::Uuid::new_v4().to_string();
            let launch = Launch {
                schema: 1,
                generation: generation.clone(),
                boot: boot().ok_or_else(invalid)?,
                uid: unsafe { libc::geteuid() },
                pid,
                exact,
                units: start_units().into(),
                handle,
                cwd: std::env::current_dir()?,
                handle_dev,
                handle_ino,
                created: now().ok_or_else(invalid)?,
            };
            if probe_process(pid) != ProcessProbe::Present(exact)
                || private::identity(&launch.handle)? != (handle_dev, handle_ino)
            {
                return Err(invalid());
            }
            let d = store.child(&generation, true)?;
            d.write("launch", &launch)?;
            Ok(LaunchTicket { base, generation })
        })();
        if result.is_err() {
            tracing::warn!(
                error_kind = "lifecycle_capture_unknown",
                "managed launch receipt unavailable"
            );
        }
        result.ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, pid);
        None
    }
}

#[cfg(unix)]
const EVENT_LOCK_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(unix)]
const EVENT_LOCK_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);
#[cfg(unix)]
const EVENT_LOCK_MAX_ATTEMPTS: usize = 101;

#[cfg(unix)]
/// Exit/cancellation can wait up to `EVENT_LOCK_BUDGET` (2 seconds) when the
/// daemon's `reconcile_owned` holds the store lock, plus OS scheduling delay.
fn write_event<T: Serialize>(t: &LaunchTicket, name: &str, event: &T) -> io::Result<()> {
    write_event_with_lock(t, name, event, private::lock)
}

#[cfg(unix)]
fn write_event_with_lock<T: Serialize>(
    t: &LaunchTicket,
    name: &str,
    event: &T,
    mut lock: impl FnMut(&private::Dir) -> io::Result<()>,
) -> io::Result<()> {
    // Retain this descriptor across contention; do not resolve a replacement store.
    let store = private::store(&t.base, false)?;
    let started = std::time::Instant::now();
    let mut attempts = 0;
    loop {
        attempts += 1;
        match lock(&store) {
            Ok(()) => return store.child(&t.generation, false)?.write(name, event),
            Err(error) => {
                // Only contention is transient. Namespace, generation and write
                // failures keep their existing refusal and immutable-file semantics.
                if error.kind() != io::ErrorKind::WouldBlock
                    && error.raw_os_error() != Some(libc::EAGAIN)
                {
                    return Err(error);
                }
                let remaining = EVENT_LOCK_BUDGET.saturating_sub(started.elapsed());
                if attempts >= EVENT_LOCK_MAX_ATTEMPTS || remaining.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(EVENT_LOCK_BACKOFF.min(remaining));
                // A delayed wake-up must not initiate another lock attempt past
                // the monotonic deadline, even if the attempt cap is not reached.
                if started.elapsed() >= EVENT_LOCK_BUDGET {
                    return Err(error);
                }
            }
        }
    }
}

pub fn registry_home(claude_home: &Path) -> Option<&Path> {
    claude_home
        .ends_with(".claude")
        .then_some(claude_home.parent())
        .flatten()
}
fn observe_ticket(t: &LaunchTicket) {
    let home = t.base.parent().and_then(registry_home);
    let _ = reconcile_owned(&t.base, home);
}

#[cfg(any(unix, test))]
fn ended_by(probe: ProcessProbe, exact: u64) -> Option<&'static str> {
    match probe {
        ProcessProbe::Gone => Some("raw_esrch"),
        ProcessProbe::Present(s) if s != exact => Some("incarnation_replaced"),
        _ => None,
    }
}

#[cfg(unix)]
fn reconcile_end(d: &private::Dir, l: &Launch, probe: ProcessProbe) -> io::Result<bool> {
    let Some(reason) = ended_by(probe, l.exact) else {
        return Ok(false);
    };
    d.write(
        "ended",
        &End {
            observed: now().ok_or_else(invalid)?,
            reason: reason.into(),
        },
    )?;
    Ok(true)
}

pub fn reconcile_owned(base: &Path, home: Option<&Path>) -> io::Result<usize> {
    #[cfg(unix)]
    {
        let store = match private::store(base, false) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        private::lock(&store)?;
        let mut changed = 0;
        let mut unknown = false;
        for name in store.names()? {
            let outcome = (|| -> io::Result<usize> {
                let mut changed = 0;
                let d = store.child(&name, false)?;
                let l: Launch = d.read("launch")?.ok_or_else(invalid)?;
                validate_launch(&l, &name)?;
                if d.read::<End>("cancelled")?.is_some() || d.read::<End>("ended")?.is_some() {
                    return Ok(changed);
                }
                let probe = probe_process(l.pid);
                if reconcile_end(&d, &l, probe)? {
                    changed += 1;
                    return Ok(changed);
                }
                if probe != ProcessProbe::Present(l.exact) {
                    return Ok(changed);
                }
                if let Some(home) = home {
                    if let Some(binding) = bind(&l, base, home)? {
                        match d.read::<Binding>("binding")? {
                            None => {
                                d.write("binding", &binding)?;
                                changed += 1;
                            }
                            Some(old)
                                if (old.uuid != binding.uuid
                                    || old.dev != binding.dev
                                    || old.ino != binding.ino)
                                    && d.read::<End>("invalidated")?.is_none() =>
                            {
                                d.write(
                                    "invalidated",
                                    &End {
                                        observed: now().ok_or_else(invalid)?,
                                        reason: "binding_changed".into(),
                                    },
                                )?;
                                changed += 1;
                            }
                            _ => (),
                        }
                    }
                }
                Ok(changed)
            })();
            match outcome {
                Ok(n) => changed += n,
                Err(_) => unknown = true,
            }
        }
        if unknown {
            Err(invalid())
        } else {
            Ok(changed)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (base, home);
        Err(invalid())
    }
}

#[cfg(unix)]
fn bind(l: &Launch, base: &Path, home: &Path) -> io::Result<Option<Binding>> {
    let Ok(Some((info, exact))) =
        super::session_info_exact_for_pid_kind(super::CliKind::Claude, l.pid)
    else {
        return Ok(None);
    };
    if exact != l.exact
        || info.config_dir != l.handle
        || info.cwd != l.cwd
        || private::identity(&l.handle)? != (l.handle_dev, l.handle_ino)
    {
        return Ok(None);
    }
    let tmp = scratch_tmp();
    let ctx = super::rows::RowContext {
        base_dir: base.to_owned(),
        home: home.to_owned(),
        tmp_root: tmp.clone(),
        uid: Some(l.uid),
        now_secs: now().ok_or_else(invalid)?,
    };
    let row = super::rows::enrich_kind(super::CliKind::Claude, vec![info], &ctx)
        .into_iter()
        .next();
    let Some(row) = row else {
        return Ok(None);
    };
    checked_binding(l, &row, &tmp, &probe_process)
}

#[cfg(unix)]
fn checked_binding(
    l: &Launch,
    row: &super::rows::SessionRowData,
    tmp: &Path,
    probe: &dyn Fn(u32) -> ProcessProbe,
) -> io::Result<Option<Binding>> {
    let Some(id) = row.session_id.clone().filter(|x| valid_uuid(x)) else {
        return Ok(None);
    };
    let scratch = scratch_path(l, &id, tmp);
    let slug = scratch
        .parent()
        .and_then(Path::file_name)
        .and_then(|x| x.to_str())
        .ok_or_else(invalid)?;
    let root = tmp.join(format!("claude-{}", l.uid));
    let rootfd = private::Dir::open(&root)?;
    let project = rootfd.child(slug, false)?;
    let leaf = project.child(&id, false)?;
    let m = leaf.0.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if row.scratch_dir.as_ref() != Some(&scratch)
        || probe(l.pid) != ProcessProbe::Present(l.exact)
        || private::identity(&scratch)? != (m.dev(), m.ino())
        || private::identity(&l.handle)? != (l.handle_dev, l.handle_ino)
    {
        return Ok(None);
    }
    Ok(Some(Binding {
        uuid: id,
        scratch,
        dev: m.dev(),
        ino: m.ino(),
        observed: now().ok_or_else(invalid)?,
    }))
}

#[cfg(not(unix))]
fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::Unsupported)
}
#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "lifecycle_diagnostics_tests.rs"]
mod diagnostics_tests;

#[cfg(all(test, unix))]
#[path = "lifecycle_retry_tests.rs"]
mod retry_tests;
