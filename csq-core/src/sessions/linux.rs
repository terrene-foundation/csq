//! Linux backend for live CC session discovery.
//!
//! Walks `/proc/*` for processes owned by the current UID and reads:
//!
//! - `/proc/<pid>/comm` for the executable name (must be `claude`).
//! - `/proc/<pid>/environ` for the NUL-separated env (must contain
//!   `CLAUDE_CONFIG_DIR`).
//! - `/proc/<pid>/cwd` via `readlink` for the working directory.
//! - `/proc/<pid>/stat` field 22 (`starttime`) for the start-time
//!   in clock ticks since boot, converted to Unix seconds via
//!   `/proc/stat` btime + clk_tck (we approximate with a simpler
//!   elapsed-seconds-via-`/proc/uptime` calculation).
//!
//! All file reads are best-effort — a process that exits between
//! enumeration and inspection is silently skipped.

use super::{
    parse_term_session_id, CliKind, HopProbe, IncompleteCause, Listing, PidLookup, SessionInfo,
    Undetermined,
};
use std::fs;
use std::path::PathBuf;

/// Returns the list of live CC sessions for the current user.
pub fn list() -> Vec<SessionInfo> {
    try_list().unwrap_or_default()
}

/// [`list`], but `None` when `/proc` itself could not be read, so a caller
/// can tell "no live sessions" from "could not look".
pub fn try_list() -> Option<Vec<SessionInfo>> {
    try_list_detailed().map(|l| l.sessions)
}

/// [`try_list`] plus the count of same-uid `claude` processes that could not be read, and
/// `incomplete`: whether the `/proc` view may hide processes (see `listing_incomplete_via`).
pub fn try_list_detailed() -> Option<Listing> {
    try_list_detailed_kind(CliKind::Claude)
}

/// [`try_list_detailed`] for the processes of `kind` (named `kind.comm()`, carrying
/// `kind.env_key()`).
pub fn try_list_detailed_kind(kind: CliKind) -> Option<Listing> {
    let entries = fs::read_dir("/proc").ok()?;
    let pids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok()?.parse::<u32>().ok())
        .collect();
    try_list_detailed_kind_via(kind, &RealProc, &pids)
}

/// The walk behind [`try_list_detailed`], over an injected `/proc` and pid list. A `/proc`
/// whose mounts may hide processes from this caller (see [`listing_incomplete_via`]) sets
/// `incomplete`: the walk cannot be whole, our own non-dumpable `claude` included.
#[cfg(test)]
pub(crate) fn try_list_detailed_via(src: &dyn ProcSource, pids: &[u32]) -> Option<Listing> {
    try_list_detailed_kind_via(CliKind::Claude, src, pids)
}

/// [`try_list_detailed_via`] for `kind`.
pub(crate) fn try_list_detailed_kind_via(
    kind: CliKind,
    src: &dyn ProcSource,
    pids: &[u32],
) -> Option<Listing> {
    let mut out = Vec::new();
    let mut unreadable_pids: Vec<u32> = Vec::new();
    let incomplete_cause = listing_incomplete_cause_via(src);
    // A known cause (hidepid=1 also refuses /proc/1/stat with EPERM) names the real next step,
    // so it takes precedence over the sandbox verdict.
    // Only hidepid legitimately refuses pid 1's `stat` to a caller that can otherwise read
    // `/proc`; any OTHER known cause (unreadable /proc/self, mountinfo, fs type) is what a
    // sandbox denying /proc produces too, so it must not cancel the restricted verdict.
    let restricted =
        !matches!(incomplete_cause, Some(IncompleteCause::Hidepid)) && caller_restricted_via(src);
    for &pid in pids {
        match listing_entry_kind_via(kind, pid, src) {
            ListEntry::Session(info) => out.push(info),
            ListEntry::UnreadableClaude => unreadable_pids.push(pid),
            ListEntry::NotSession => {}
        }
    }
    Some(Listing {
        sessions: out,
        unreadable_claude: unreadable_pids.len(),
        unreadable_pids,
        incomplete: incomplete_cause.is_some(),
        incomplete_cause,
        restricted,
    })
}

/// One pid's contribution to a listing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListEntry {
    Session(SessionInfo),
    /// Not a session, positively: gone, another uid, a zombie, or not named `claude`.
    NotSession,
    /// Same uid (or owner unreadable), and named `claude` (or the name unreadable), but the
    /// process could not be read into a session. It may be one, so it is counted rather than
    /// skipped (INV-31-02).
    UnreadableClaude,
}

/// [`read_process_via`] for the listing: a read failure is classified by what is still
/// knowable about the process, so an unreadable `claude` is counted and an unreadable
/// stranger, a zombie, or an exited process is not.
#[cfg(test)]
pub(crate) fn listing_entry_via(pid: u32, src: &dyn ProcSource) -> ListEntry {
    listing_entry_kind_via(CliKind::Claude, pid, src)
}

/// [`listing_entry_via`] for `kind`: the name that makes an unreadable process countable is
/// `kind.comm()`, so an unreadable `codex` is never mistaken for "not a session".
pub(crate) fn listing_entry_kind_via(kind: CliKind, pid: u32, src: &dyn ProcSource) -> ListEntry {
    if let Ok(found) = read_process_kind_via(kind, pid, src) {
        return found.map_or(ListEntry::NotSession, ListEntry::Session);
    }
    match proc_read(src, pid, "status") {
        // Confirmed gone (`kill(pid, 0)` ESRCH).
        Ok(None) => return ListEntry::NotSession,
        Ok(Some(st)) => {
            let st = String::from_utf8_lossy(&st);
            // A zombie has no environment or arguments to read and is not a live session.
            let zombie = st
                .lines()
                .find_map(|l| l.strip_prefix("State:"))
                .is_some_and(|v| v.trim_start().starts_with('Z'));
            let other_uid = parse_euid(&st).is_some_and(|e| e != src.euid());
            if zombie || other_uid {
                return ListEntry::NotSession;
            }
        }
        // Owner unreadable (or NotFound without proof the pid is gone): fall through to
        // the name, which is itself probed.
        Err(_) => {}
    }
    match proc_read(src, pid, "comm") {
        Ok(None) => ListEntry::NotSession,
        Ok(Some(c)) if String::from_utf8_lossy(&c).trim() == kind.comm() => {
            ListEntry::UnreadableClaude
        }
        Ok(Some(_)) => ListEntry::NotSession,
        // The name itself is unreadable: it may be a claude.
        Err(_) => ListEntry::UnreadableClaude,
    }
}

/// The session for one pid (same filter and fields as [`try_list`]), without walking
/// `/proc`. Three outcomes (spec 31 §3, see [`super::session_info_for_pid`]).
pub(crate) fn session_info_for_pid(pid: u32) -> PidLookup {
    read_process_via(pid, &RealProc)
}

/// [`session_info_for_pid`] for `kind`.
pub(crate) fn session_info_for_pid_kind(kind: CliKind, pid: u32) -> PidLookup {
    read_process_kind_via(kind, pid, &RealProc)
}

/// [`hop_probe_via`] over the real `/proc`.
pub(crate) fn hop_probe(pid: u32) -> HopProbe {
    hop_probe_via(pid, &RealProc)
}

/// One process between a caller and a claimed owner, read for its IMAGE only (no terminal,
/// no environment), whatever its uid. The signals are `comm`, `cmdline` and the
/// `/proc/<pid>/exe` link (which the process cannot rename; `EACCES` on another uid's
/// process), classified by [`crate::sessions::image_verdict`]: any positive signal is a
/// session image, a not-a-session verdict needs at least two successful reads, and
/// otherwise the hop is `Unreadable` (fail closed). A zombie has no image and is
/// `Unreadable`; a confirmed-gone process is `Gone`.
pub(crate) fn hop_probe_via(pid: u32, src: &dyn ProcSource) -> HopProbe {
    let status = match proc_read(src, pid, "status") {
        Ok(Some(b)) => String::from_utf8_lossy(&b).into_owned(),
        Ok(None) => return HopProbe::Gone,
        Err(_) => return HopProbe::Unreadable,
    };
    let zombie = status
        .lines()
        .find_map(|l| l.strip_prefix("State:"))
        .is_some_and(|v| v.trim_start().starts_with('Z'));
    if zombie {
        return HopProbe::Unreadable;
    }
    let comm = match proc_read(src, pid, "comm") {
        Ok(Some(c)) => Some(String::from_utf8_lossy(&c).trim().to_string()),
        Ok(None) => return HopProbe::Gone,
        Err(_) => None,
    };
    let argv = match proc_read(src, pid, "cmdline") {
        Ok(Some(raw)) => Some(split_cmdline(&raw)),
        Ok(None) => return HopProbe::Gone,
        Err(_) => None,
    };
    let exe = src.link(pid, "exe");
    let reads = crate::sessions::ImageReads { comm, argv, exe };
    let codex_wrapper = crate::sessions::is_codex_node_wrapper(&reads);
    match crate::sessions::image_verdict(&reads, &crate::sessions::exe_is_resolved_cli) {
        Some(session_image) => HopProbe::Process {
            session_image,
            codex_wrapper: session_image && codex_wrapper,
        },
        None => HopProbe::Unreadable,
    }
}

/// `/proc/<pid>/cmdline` split on NUL: the launch argv. `None` when unreadable.
pub(crate) fn launch_argv_for_pid(pid: u32) -> Option<Vec<String>> {
    let raw = RealProc.read(pid, "cmdline").ok()?;
    Some(split_cmdline(&raw))
}

/// Splits a `cmdline` blob into arguments (lossy UTF-8; a trailing NUL ends the last one).
pub(crate) fn split_cmdline(raw: &[u8]) -> Vec<String> {
    let body = raw.strip_suffix(&[0]).unwrap_or(raw);
    if body.is_empty() {
        return Vec::new();
    }
    body.split(|b| *b == 0)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// The `/proc` reads behind [`read_process_via`], injectable so each outcome is testable
/// without a process.
pub(crate) trait ProcSource {
    /// The effective uid this process runs as (the caller's).
    fn euid(&self) -> u32;
    /// The contents of `/proc/<pid>/<name>`.
    fn read(&self, pid: u32, name: &str) -> std::io::Result<Vec<u8>>;
    /// The target of the symlink `/proc/<pid>/<name>`.
    fn link(&self, pid: u32, name: &str) -> Option<PathBuf>;
    /// `kill(pid, 0)`: does the pid exist, independent of `/proc` visibility.
    fn signal_probe(&self, pid: u32) -> SignalProbe;
    /// The contents of `/proc/self/mountinfo`.
    fn mountinfo(&self) -> std::io::Result<String>;
    /// The target of the symlink `/proc/self`: the caller's pid as THIS `/proc` names it.
    /// `None` when unreadable or dangling.
    fn self_link(&self) -> Option<PathBuf>;
    /// `statfs("/proc").f_type`; `None` when the call fails.
    fn proc_fs_type(&self) -> Option<i64>;
}

/// `PROC_SUPER_MAGIC`: `statfs.f_type` of a real procfs.
pub(crate) const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// The outcome of a `kill(pid, 0)` existence probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalProbe {
    /// Success: the process exists and we may signal it (so it may be ours).
    Exists,
    /// ESRCH: no such process. The ONLY probe result that proves a pid is gone.
    NoSuchProcess,
    /// EPERM: it exists, but a sandbox (e.g. Landlock signal scoping) can return this for
    /// our own same-uid `claude`, so it is NOT evidence the process is gone or not ours.
    NotPermitted,
    /// Any other failure: unknown.
    Failed,
}

struct RealProc;

impl ProcSource for RealProc {
    fn euid(&self) -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }
    fn read(&self, pid: u32, name: &str) -> std::io::Result<Vec<u8>> {
        fs::read(format!("/proc/{pid}/{name}"))
    }
    fn link(&self, pid: u32, name: &str) -> Option<PathBuf> {
        fs::read_link(format!("/proc/{pid}/{name}")).ok()
    }
    fn mountinfo(&self) -> std::io::Result<String> {
        fs::read_to_string("/proc/self/mountinfo")
    }
    fn self_link(&self) -> Option<PathBuf> {
        fs::read_link("/proc/self").ok()
    }
    fn proc_fs_type(&self) -> Option<i64> {
        let path = std::ffi::CString::new("/proc").ok()?;
        // SAFETY: statfs is plain-old-data (all-zero is valid); `path` is a live
        // NUL-terminated string and `st` a live, exclusively borrowed out-buffer.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(path.as_ptr(), &mut st) };
        // `f_type`'s width and signedness differ by target libc; widen explicitly.
        #[allow(clippy::unnecessary_cast)]
        let f_type = st.f_type as i64;
        (rc == 0).then_some(f_type)
    }
    fn signal_probe(&self, pid: u32) -> SignalProbe {
        let Ok(raw) = libc::pid_t::try_from(pid) else {
            return SignalProbe::Failed;
        };
        // A pid <= 0 would signal a process group; never probe one.
        if raw <= 0 {
            return SignalProbe::Failed;
        }
        // SAFETY: signal 0 only checks existence and permission; nothing is delivered.
        if unsafe { libc::kill(raw, 0) } == 0 {
            return SignalProbe::Exists;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => SignalProbe::NoSuchProcess,
            Some(libc::EPERM) => SignalProbe::NotPermitted,
            _ => SignalProbe::Failed,
        }
    }
}

/// Is a pid positively gone? Only on `kill(pid, 0)` ESRCH. Under `hidepid=2` a process we
/// cannot ptrace-read (our own non-dumpable `claude`) is NotFound in `/proc`, and a
/// sandbox can make the probe fail with EPERM for our own `claude`; neither is proof, so
/// success, EPERM and any other failure all leave the pid undetermined.
fn confirmed_gone(src: &dyn ProcSource, pid: u32) -> bool {
    matches!(src.signal_probe(pid), SignalProbe::NoSuchProcess)
}

/// One read of a `/proc` file as a three-way answer: `Ok(None)` is the process being
/// POSITIVELY gone (NotFound AND [`confirmed_gone`]); a NotFound the probe does not
/// confirm, and any other error, is a failed read (`Err`).
fn proc_read(src: &dyn ProcSource, pid: u32, name: &str) -> Result<Option<Vec<u8>>, Undetermined> {
    match src.read(pid, name) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if confirmed_gone(src, pid) {
                Ok(None)
            } else {
                Err(Undetermined)
            }
        }
        Err(_) => Err(Undetermined),
    }
}

/// Can a `/proc` walk by this caller NOT be complete? No exemption applies: not root (the
/// visibility needs `CAP_SYS_PTRACE`, absent for root in a default container or user
/// namespace) and not a `gid=` group (`hidepid=ptraceable` never consults it). Incomplete
/// when ANY of: `mountinfo` is unreadable or has no `/proc` mount; any `/proc` line (whatever
/// its fstype) carries a `hidepid=` token, in its per-mount options or anywhere after the
/// ` - ` separator, with a value other than `0`/`off` (unknown values count); the LAST `/proc`
/// line is not fstype `proc`; a `/proc` line has no separator or no fstype; the LAST `/proc`
/// line's root field is not exactly `/` (a bind of a subtree); any mount point is
/// `/proc/<digits>` or below one (a mount over a per-pid directory); or `/proc/self` is
/// unreadable, dangling, or not the decimal number `std::process::id()` (a pid-namespace
/// mismatch: this `/proc` describes another namespace's pids).
#[cfg(test)]
pub(crate) fn listing_incomplete_via(src: &dyn ProcSource) -> bool {
    listing_incomplete_cause_via(src).is_some()
}

/// [`listing_incomplete_via`] naming the first cause found, so the operator gets a next step.
pub(crate) fn listing_incomplete_cause_via(src: &dyn ProcSource) -> Option<IncompleteCause> {
    let self_matches = src
        .self_link()
        .and_then(|l| l.to_str().map(str::to_owned))
        .is_some_and(|l| {
            !l.is_empty()
                && l.bytes().all(|b| b.is_ascii_digit())
                && l.parse::<u32>().ok() == Some(std::process::id())
        });
    if !self_matches {
        return Some(IncompleteCause::PidNamespaceMismatch);
    }
    // A mount that merely LOOKS like procfs in mountinfo (a FUSE or tmpfs fake) is not one:
    // the filesystem type of `/proc` itself must be procfs, and an unreadable one fails closed.
    if src.proc_fs_type() != Some(PROC_SUPER_MAGIC) {
        return Some(IncompleteCause::NotProcfs);
    }
    let Ok(info) = src.mountinfo() else {
        return Some(IncompleteCause::MountinfoUnreadable);
    };
    let mut last_fstype: Option<&str> = None;
    let mut last_root_is_slash = false;
    for line in info.lines() {
        let (pre, post) = match line.split_once(" - ") {
            Some((pre, post)) => (pre, Some(post)),
            None => (line, None),
        };
        let pre: Vec<&str> = pre.split_whitespace().collect();
        // id parent major:minor root mountpoint mount-options [optional...]
        if let Some(mp) = pre.get(4) {
            let under_pid_dir = mp
                .strip_prefix("/proc/")
                .and_then(|r| r.split('/').next())
                .is_some_and(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()));
            if under_pid_dir {
                return Some(IncompleteCause::PidDirMount);
            }
        }
        if pre.get(4) != Some(&"/proc") {
            continue;
        }
        last_root_is_slash = pre[3] == "/";
        let Some(post) = post else {
            return Some(IncompleteCause::NotProcfs);
        };
        let post: Vec<&str> = post.split_whitespace().collect();
        // post: fstype source super-options, but an empty source shifts the columns, so
        // every field after the fstype is searched rather than indexed.
        let Some((fstype, rest)) = post.split_first() else {
            return Some(IncompleteCause::NotProcfs);
        };
        last_fstype = Some(fstype);
        let tokens = pre[5..].iter().chain(rest.iter());
        for tok in tokens.flat_map(|f| f.split(',')) {
            if let Some(v) = tok.strip_prefix("hidepid=") {
                if !matches!(v, "0" | "off") {
                    return Some(IncompleteCause::Hidepid);
                }
            }
        }
    }
    if last_fstype != Some("proc") {
        Some(IncompleteCause::NotProcfs)
    } else if !last_root_is_slash {
        Some(IncompleteCause::SubtreeBind)
    } else {
        None
    }
}

/// Is the caller refused process information outright? `/proc/1/stat` exists on every host
/// whose `/proc` the caller can see into, so a refusal that is not "no such file" (a
/// sandbox's EPERM/EACCES) means the caller reads nothing, and every unreadable pid in the
/// listing is a symptom of that. Both `hidepid` modes hide pid 1 from a non-root caller
/// (`hidepid=2` as NotFound, `hidepid=1` as EPERM on `stat`); `incomplete` reports them, so
/// the walk only calls the caller restricted when no cause is known.
pub(crate) fn caller_restricted_via(src: &dyn ProcSource) -> bool {
    matches!(src.read(1, "stat"), Err(e) if e.kind() != std::io::ErrorKind::NotFound)
}

/// Field 2 of `Uid:` (the effective uid) in a `/proc/<pid>/status` body.
pub(crate) fn parse_euid(status: &str) -> Option<u32> {
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// `(tty_nr, starttime_ticks)` from a `/proc/<pid>/stat` body, parsed after the LAST `)`.
pub(crate) fn parse_tty_and_start(stat: &str) -> Option<(i64, u64)> {
    let close = stat.rfind(')')?;
    let f: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // After the comm: index 0 is field 3 (state), so tty_nr (7) is 4 and starttime (22) 19.
    Some((f.get(4)?.parse().ok()?, f.get(19)?.parse().ok()?))
}

/// The first `key=` value in an environ blob, three-way: `Ok(None)` the key is absent;
/// `Err` its value is not UTF-8 (present but unparseable). Entries of other keys that are
/// not UTF-8 are skipped, never mistaken for "absent".
fn environ_lookup(blob: &[u8], key: &str) -> Result<Option<String>, Undetermined> {
    let needle = format!("{key}=");
    for entry in blob.split(|&b| b == 0) {
        if let Some(v) = entry.strip_prefix(needle.as_bytes()) {
            return std::str::from_utf8(v)
                .map(|v| Some(v.to_string()))
                .map_err(|_| Undetermined);
        }
    }
    Ok(None)
}

/// Reads one `/proc/<pid>/` entry, three-outcome.
fn read_process_via(pid: u32, src: &dyn ProcSource) -> PidLookup {
    read_process_kind_via(CliKind::Claude, pid, src)
}

/// [`read_process_via`] for `kind`.
fn read_process_kind_via(kind: CliKind, pid: u32, src: &dyn ProcSource) -> PidLookup {
    // Owner: only a same-uid process is ours to read (`environ` EACCES does not prove it:
    // it also fires for a same-uid process that is not dumpable).
    let status = match proc_read(src, pid, "status") {
        Ok(Some(status)) => status,
        // `proc_read` returns `Ok(None)` only when `kill(pid, 0)` agreed it is gone.
        Ok(None) => return Ok(None),
        // An unreadable status (e.g. `/proc` mounted `hidepid=1`) cannot tell our own
        // process from a stranger's: undetermined.
        Err(Undetermined) => return Err(Undetermined),
    };
    let euid = parse_euid(&String::from_utf8_lossy(&status)).ok_or(Undetermined)?;
    if euid != src.euid() {
        return Ok(None);
    }

    // Start identity from one `stat` read. Linux has NO controlling-terminal rule: the
    // pre-native Linux listing filtered only on `comm` and `CLAUDE_CONFIG_DIR` (it never
    // used `ps`), so a `claude` with `tty_nr == 0` (a detached or service-run session) is
    // still a session; only macOS requires a terminal (spec 31 §2).
    let Some(stat) = proc_read(src, pid, "stat")? else {
        return Ok(None);
    };
    let stat = String::from_utf8_lossy(&stat).into_owned();
    let (_tty_nr, ticks) = parse_tty_and_start(&stat).ok_or(Undetermined)?;

    let Some(comm) = proc_read(src, pid, "comm")? else {
        return Ok(None);
    };
    if String::from_utf8_lossy(&comm).trim() != kind.comm() {
        return Ok(None);
    }

    // Same uid but the environment cannot be read (EACCES on a non-dumpable process):
    // undetermined, not "no CLAUDE_CONFIG_DIR".
    let Some(environ) = proc_read(src, pid, "environ")? else {
        return Ok(None);
    };
    let Some(config_dir) = environ_lookup(&environ, kind.env_key())?.filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    let config_dir = PathBuf::from(config_dir);
    let account_id = SessionInfo::extract_account_id(&config_dir);

    // csq's own wake child (`codex -c k=v queue ...`, run with the TARGET's CODEX_HOME) has no
    // terminal rule to drop it on Linux, so it is dropped by its subcommand: it is a client of
    // the session it wakes, not a second owner of that home (spec 32 §5.1). An unreadable
    // `cmdline` excludes nothing: a real session is never hidden by a failed read.
    if kind == CliKind::Codex {
        if let Ok(Some(raw)) = proc_read(src, pid, "cmdline") {
            if crate::sessions::is_queue_invocation(&split_cmdline(&raw)) {
                return Ok(None);
            }
        }
    }

    let cwd = src.link(pid, "cwd").unwrap_or_default();

    // pid reuse between the reads: the same pid must still carry the same start ticks.
    let Some(again) = proc_read(src, pid, "stat")? else {
        return Ok(None);
    };
    let (_, ticks_again) =
        parse_tty_and_start(&String::from_utf8_lossy(&again)).ok_or(Undetermined)?;
    if ticks_again != ticks {
        return Ok(None);
    }

    let started_at = start_from_ticks(ticks);

    // Terminal identity env vars — populated by iTerm2 clones like
    // WezTerm, by iTerm2 itself when run on Linux (rare but real),
    // or empty for plain `xterm`. Linux users with tmux get
    // TMUX instead — not parsed here.
    let term_session_id = parse_environ(&environ, "TERM_SESSION_ID");
    let (term_window, term_tab, term_pane) = term_session_id
        .as_deref()
        .map(parse_term_session_id)
        .unwrap_or((None, None, None));
    let iterm_profile = parse_environ(&environ, "ITERM_PROFILE");

    // The controlling terminal's device path, from the fd/0 symlink when it is one.
    let tty = src
        .link(pid, "fd/0")
        .and_then(|p| {
            p.to_str()
                .map(|s| s.trim_start_matches("/dev/").to_string())
        })
        .filter(|s| !s.is_empty() && !s.contains("null") && !s.contains("socket"));

    Ok(Some(SessionInfo {
        pid,
        cwd,
        config_dir,
        account_id,
        started_at,
        tty,
        term_window,
        term_tab,
        term_pane,
        iterm_profile,
        terminal_title: None, // osascript is macOS-only; no Linux equivalent yet
    }))
}

/// Unix seconds of a start expressed in clock ticks since boot (`/proc/stat` `btime`).
fn start_from_ticks(ticks: u64) -> Option<u64> {
    let system_stat = fs::read_to_string("/proc/stat").ok()?;
    let btime: u64 = system_stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    Some(btime + ticks / clock_ticks_per_sec())
}

/// Parses a NUL-separated `KEY=VALUE\0KEY=VALUE\0...` blob for a
/// specific key and returns the value as an owned `String`.
fn parse_environ(blob: &[u8], key: &str) -> Option<String> {
    let needle = format!("{key}=");
    for entry in blob.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(entry).ok()?;
        if let Some(v) = s.strip_prefix(&needle) {
            return Some(v.to_string());
        }
    }
    None
}

/// Clock ticks per second, from `sysconf(_SC_CLK_TCK)`; 100 only when sysconf reports a
/// non-positive value (it cannot fail on a conforming kernel, but 0 would divide by zero).
fn clock_ticks_per_sec() -> u64 {
    // SAFETY: sysconf takes a plain integer name, reads no memory, and returns -1 on error.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ticks_or_default(v)
}

/// `v` when positive, else the conventional 100.
fn ticks_or_default(v: libc::c_long) -> u64 {
    u64::try_from(v).ok().filter(|t| *t > 0).unwrap_or(100)
}

/// Field 4 (`ppid`) of a `/proc/<pid>/stat` body, parsed after the LAST `)` because the
/// command name in field 2 may itself contain spaces and parentheses.
pub(crate) fn parse_ppid(stat: &str) -> Option<u32> {
    let close = stat.rfind(')')?;
    // After the comm: field 3 (state) is index 0, field 4 (ppid) is index 1.
    stat[close + 1..].split_whitespace().nth(1)?.parse().ok()
}

/// The parent pid of `pid` from `/proc/<pid>/stat`, or `None` when unreadable.
pub(crate) fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_ppid(&stat)
}

/// Reads the Unix-seconds start time of a process from its
/// `/proc/<pid>/stat` file, cross-referenced with `/proc/stat`
/// `btime` and `sysconf(_SC_CLK_TCK)`.
///
/// Returns `None` on any parse failure — the session row still
/// renders without a start time if this fails.
pub(crate) fn read_start_time(proc_dir: &std::path::Path) -> Option<u64> {
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    // Field 22 is starttime in clock ticks since boot.
    // But there's a gotcha: field 2 (comm) is in parens and may
    // contain spaces or close-parens. Find the LAST `)` and split
    // from there.
    let close = stat.rfind(')')?;
    let after_comm = stat[close + 1..].trim();
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After field 2, fields are 1-indexed in this slice: index 0 is
    // field 3, ..., index 19 is field 22 (starttime).
    let starttime_ticks: u64 = fields.get(19)?.parse().ok()?;

    let starttime_secs = starttime_ticks / clock_ticks_per_sec();

    // /proc/stat has a line `btime <unix_seconds>` giving system
    // boot time.
    let system_stat = fs::read_to_string("/proc/stat").ok()?;
    let mut btime: Option<u64> = None;
    for line in system_stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            btime = rest.trim().parse().ok();
            break;
        }
    }
    let btime = btime?;
    Some(btime + starttime_secs)
}

/// The raw `starttime` (`/proc/<pid>/stat` field 22, clock ticks since boot) of the process
/// at `proc_dir`: full precision, no `btime` involved, so two reads of one process are
/// exactly equal and two processes started in the same second still differ.
pub(crate) fn read_start_ticks(proc_dir: &std::path::Path) -> Option<u64> {
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    parse_stat_start_ticks(&stat)
}

fn parse_stat_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)? // index 0 is field 3, so field 22 is index 19
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn stat_start_ticks_parses_field_22_after_a_hostile_comm() {
        // comm contains spaces and ')'; fields 3..21 are 19 values, field 22 = 987654
        let stat = "42 (a ) b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 0";
        assert_eq!(super::parse_stat_start_ticks(stat), Some(987_654));
        assert_eq!(super::parse_stat_start_ticks("42 (x) S 1"), None);
    }

    use super::*;

    // ── three-outcome classification over an injected /proc (no process) ──

    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::{Error, ErrorKind};

    type Replies = Vec<Result<Vec<u8>, ErrorKind>>;

    /// An injected `/proc`: per file name, a queue of replies (the last one repeats).
    struct Fake {
        euid: u32,
        probe: SignalProbe,
        mountinfo: std::io::Result<String>,
        self_link: Option<PathBuf>,
        files: RefCell<HashMap<String, Replies>>,
        fs_type: Option<i64>,
    }

    impl ProcSource for Fake {
        fn proc_fs_type(&self) -> Option<i64> {
            self.fs_type
        }
        fn euid(&self) -> u32 {
            self.euid
        }
        fn read(&self, _pid: u32, name: &str) -> std::io::Result<Vec<u8>> {
            let mut files = self.files.borrow_mut();
            let q = files
                .get_mut(name)
                .unwrap_or_else(|| panic!("no fixture for {name}"));
            let r = if q.len() > 1 {
                q.remove(0)
            } else {
                q[0].clone()
            };
            r.map_err(Error::from)
        }
        fn link(&self, _pid: u32, name: &str) -> Option<PathBuf> {
            match name {
                "cwd" => Some(PathBuf::from("/w")),
                "exe" => self.files.borrow().get("exe-link").and_then(|q| {
                    q[0].clone()
                        .ok()
                        .map(|b| PathBuf::from(String::from_utf8_lossy(&b).into_owned()))
                }),
                _ => None,
            }
        }
        fn signal_probe(&self, _pid: u32) -> SignalProbe {
            self.probe
        }
        fn self_link(&self) -> Option<PathBuf> {
            self.self_link.clone()
        }
        fn mountinfo(&self) -> std::io::Result<String> {
            match &self.mountinfo {
                Ok(s) => Ok(s.clone()),
                Err(e) => Err(Error::from(e.kind())),
            }
        }
    }

    fn stat_body(tty_nr: i64, ticks: u64) -> Vec<u8> {
        // pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt
        // cmajflt utime stime cutime cstime priority nice threads itrealvalue starttime
        format!("77 (claude) S 1 77 77 {tty_nr} 77 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0")
            .into_bytes()
    }

    fn fake() -> Fake {
        let ok = |b: &[u8]| vec![Ok(b.to_vec())];
        let mut m: HashMap<String, Replies> = HashMap::new();
        m.insert(
            "status".into(),
            ok(b"Name:\tclaude\nUid:\t501\t501\t501\t501\n"),
        );
        m.insert("stat".into(), vec![Ok(stat_body(34816, 4000))]);
        m.insert("comm".into(), ok(b"claude\n"));
        m.insert(
            "environ".into(),
            ok(b"HOME=/h\0CLAUDE_CONFIG_DIR=/x/accounts/config-7\0"),
        );
        Fake {
            euid: 501,
            probe: SignalProbe::NoSuchProcess,
            mountinfo: Ok(mountinfo_line("rw,relatime")),
            self_link: Some(PathBuf::from(std::process::id().to_string())),
            files: RefCell::new(m),
            fs_type: Some(PROC_SUPER_MAGIC),
        }
    }

    fn mountinfo_line(super_opts: &str) -> String {
        format!(
            "22 1 0:21 / /sys rw - sysfs sysfs rw\n23 1 0:22 / /proc rw,nosuid - proc proc {super_opts}\n"
        )
    }

    fn set(f: &Fake, name: &str, replies: Replies) {
        f.files.borrow_mut().insert(name.to_string(), replies);
    }

    #[test]
    fn a_readable_same_uid_claude_with_a_terminal_is_a_session() {
        let info = read_process_via(77, &fake()).unwrap().expect("a session");
        assert_eq!(info.account_id, Some(7));
        assert_eq!(info.cwd, PathBuf::from("/w"));
    }

    #[test]
    fn an_unreadable_environ_of_a_same_uid_claude_is_undetermined_not_absent() {
        let f = fake();
        set(&f, "environ", vec![Err(ErrorKind::PermissionDenied)]);
        assert_eq!(read_process_via(77, &f), Err(Undetermined));
        // present but not UTF-8: also unparseable, not "no CLAUDE_CONFIG_DIR"
        set(
            &f,
            "environ",
            vec![Ok(b"CLAUDE_CONFIG_DIR=/x/\xff\0".to_vec())],
        );
        assert_eq!(read_process_via(77, &f), Err(Undetermined));
        // a failed uid read is not "another user" either
        let f = fake();
        set(&f, "status", vec![Ok(b"garbage".to_vec())]);
        assert_eq!(read_process_via(77, &f), Err(Undetermined));
        let f = fake();
        set(&f, "stat", vec![Err(ErrorKind::PermissionDenied)]);
        assert_eq!(read_process_via(77, &f), Err(Undetermined));
    }

    #[test]
    fn positively_not_a_session_is_ok_none() {
        let f = fake();
        set(&f, "status", vec![Err(ErrorKind::NotFound)]);
        assert_eq!(read_process_via(77, &f), Ok(None), "gone");
        let f = fake();
        set(
            &f,
            "status",
            vec![Ok(b"Uid:\t502\t502\t502\t502\n".to_vec())],
        );
        assert_eq!(read_process_via(77, &f), Ok(None), "other uid");
        let f = fake();
        set(&f, "comm", vec![Ok(b"node\n".to_vec())]);
        assert_eq!(read_process_via(77, &f), Ok(None), "not claude");
        let f = fake();
        set(&f, "environ", vec![Ok(b"HOME=/h\0".to_vec())]);
        assert_eq!(read_process_via(77, &f), Ok(None), "no config dir");
        // another key's non-UTF-8 value does not hide the absence of ours
        set(&f, "environ", vec![Ok(b"X=\xff\0HOME=/h\0".to_vec())]);
        assert_eq!(read_process_via(77, &f), Ok(None));
    }

    /// Linux has no terminal rule (the old Linux listing never used `ps` and never
    /// filtered on a tty): a `claude` with `tty_nr == 0` IS a session.
    #[test]
    fn a_claude_without_a_controlling_terminal_is_a_session_on_linux() {
        let f = fake();
        set(&f, "stat", vec![Ok(stat_body(0, 4000))]);
        let info = read_process_via(77, &f).unwrap().expect("a session");
        assert_eq!(info.account_id, Some(7));
    }

    #[test]
    fn an_unreadable_claude_is_counted_and_a_stranger_zombie_or_gone_is_not() {
        let unreadable_env = |f: &Fake| set(f, "environ", vec![Err(ErrorKind::PermissionDenied)]);
        let f = fake();
        unreadable_env(&f);
        assert_eq!(listing_entry_via(77, &f), ListEntry::UnreadableClaude);
        // same failure, but the process is `node`
        let f = fake();
        unreadable_env(&f);
        set(&f, "comm", vec![Ok(b"node\n".to_vec())]);
        assert_eq!(listing_entry_via(77, &f), ListEntry::NotSession);
        // a zombie claude cannot be read and must not count
        let f = fake();
        unreadable_env(&f);
        set(
            &f,
            "status",
            vec![Ok(
                b"Name:\tclaude\nState:\tZ (zombie)\nUid:\t501\t501\t501\t501\n".to_vec(),
            )],
        );
        assert_eq!(listing_entry_via(77, &f), ListEntry::NotSession);
        // exited between reads
        let f = fake();
        set(&f, "status", vec![Err(ErrorKind::NotFound)]);
        assert_eq!(listing_entry_via(77, &f), ListEntry::NotSession);
        // another uid never counts
        let f = fake();
        set(
            &f,
            "status",
            vec![Ok(b"Uid:\t502\t502\t502\t502\n".to_vec())],
        );
        assert_eq!(listing_entry_via(77, &f), ListEntry::NotSession);
        // a readable claude is a session, not "unreadable"
        assert!(matches!(
            listing_entry_via(77, &fake()),
            ListEntry::Session(_)
        ));
        // an unreadable status AND comm: the name is unknown, so it may be a claude
        let f = fake();
        set(&f, "status", vec![Err(ErrorKind::PermissionDenied)]);
        set(&f, "comm", vec![Err(ErrorKind::PermissionDenied)]);
        assert_eq!(listing_entry_via(77, &f), ListEntry::UnreadableClaude);
    }

    /// `hidepid=1`: an unreadable `status` cannot tell a stranger from our own process, so
    /// it is undetermined in the by-pid lookup and counted in the listing (when the name
    /// is unreadable too).
    #[test]
    fn an_unreadable_status_is_undetermined() {
        let f = fake();
        set(&f, "status", vec![Err(ErrorKind::PermissionDenied)]);
        set(&f, "comm", vec![Err(ErrorKind::PermissionDenied)]);
        assert_eq!(listing_entry_via(77, &f), ListEntry::UnreadableClaude);
        assert_eq!(read_process_via(77, &f), Err(Undetermined));
    }

    /// `hidepid=2`: a process we cannot ptrace-read has no visible `status`; only
    /// `kill(pid, 0)` says whether it is gone, not ours, or possibly ours.
    #[test]
    fn a_not_found_status_is_confirmed_with_a_signal_probe() {
        let cases = [
            (SignalProbe::NoSuchProcess, Ok(None), ListEntry::NotSession),
            // EPERM can be a sandbox refusing a probe of our own claude: not proof.
            (
                SignalProbe::NotPermitted,
                Err(Undetermined),
                ListEntry::UnreadableClaude,
            ),
            (
                SignalProbe::Exists,
                Err(Undetermined),
                ListEntry::UnreadableClaude,
            ),
            (
                SignalProbe::Failed,
                Err(Undetermined),
                ListEntry::UnreadableClaude,
            ),
        ];
        for (probe, lookup, entry) in cases {
            let mut f = fake();
            set(&f, "status", vec![Err(ErrorKind::NotFound)]);
            set(&f, "comm", vec![Err(ErrorKind::NotFound)]);
            f.probe = probe;
            assert_eq!(read_process_via(77, &f), lookup, "{probe:?} lookup");
            assert_eq!(listing_entry_via(77, &f), entry, "{probe:?} listing");
        }
    }

    /// Every NotFound read after `status` succeeded goes through the probe too.
    #[test]
    fn a_later_not_found_read_is_gone_only_on_a_confirming_probe() {
        for name in ["stat", "comm", "environ"] {
            for (probe, want) in [
                (SignalProbe::NoSuchProcess, Ok(None)),
                (SignalProbe::Exists, Err(Undetermined)),
                (SignalProbe::NotPermitted, Err(Undetermined)),
            ] {
                let mut f = fake();
                set(&f, name, vec![Err(ErrorKind::NotFound)]);
                f.probe = probe;
                assert_eq!(read_process_via(77, &f), want, "{name} {probe:?}");
            }
        }
        // the second `stat` read (pid-reuse check)
        for (probe, want) in [
            (SignalProbe::NoSuchProcess, Ok(None)),
            (SignalProbe::Exists, Err(Undetermined)),
        ] {
            let mut f = fake();
            set(
                &f,
                "stat",
                vec![Ok(stat_body(34816, 4000)), Err(ErrorKind::NotFound)],
            );
            f.probe = probe;
            assert_eq!(read_process_via(77, &f), want, "stat2 {probe:?}");
        }
    }

    /// The listing's own `status` re-read is NotFound after the first read was fine.
    #[test]
    fn a_listing_status_that_vanishes_after_a_same_uid_read_follows_the_probe() {
        for (probe, want) in [
            (SignalProbe::NoSuchProcess, ListEntry::NotSession),
            (SignalProbe::Exists, ListEntry::UnreadableClaude),
        ] {
            let mut f = fake();
            set(
                &f,
                "status",
                vec![
                    Ok(b"Name:\tclaude\nUid:\t501\t501\t501\t501\n".to_vec()),
                    Err(ErrorKind::NotFound),
                ],
            );
            set(&f, "environ", vec![Err(ErrorKind::PermissionDenied)]);
            f.probe = probe;
            assert_eq!(listing_entry_via(77, &f), want, "{probe:?}");
        }
    }

    #[test]
    fn a_proc_that_is_not_procfs_or_whose_statfs_fails_makes_the_listing_incomplete() {
        let mut f = fake();
        assert!(!listing_incomplete_via(&f), "control: real procfs magic");
        f.fs_type = Some(0x0102_1994); // tmpfs
        assert!(
            listing_incomplete_via(&f),
            "tmpfs wearing a procfs mountinfo line"
        );
        f.fs_type = None;
        assert!(listing_incomplete_via(&f), "failed statfs fails closed");
    }

    #[test]
    fn any_hidepid_on_any_proc_mount_makes_the_listing_incomplete() {
        let with = |mi: std::io::Result<String>, euid: u32| {
            let mut f = fake();
            f.mountinfo = mi;
            f.euid = euid;
            listing_incomplete_via(&f)
        };
        let mi = |o: &str| Ok(mountinfo_line(o));
        let lines = |s: &str| Ok(s.to_string());
        assert!(!with(mi("rw"), 501), "no hidepid");
        assert!(!with(mi("rw,hidepid=0"), 501), "hidepid=0");
        assert!(!with(mi("rw,hidepid=off"), 501), "hidepid=off");
        assert!(with(mi("rw,hidepid=2"), 501), "hidepid=2");
        assert!(with(mi("rw,hidepid=invisible"), 501), "invisible");
        assert!(with(mi("rw,hidepid=nonsense"), 501), "unknown value");
        assert!(with(mi("rw,hidepid=1,gid=900"), 501), "gid is no exemption");
        assert!(with(mi("rw,hidepid=ptraceable,gid=900"), 501), "ptraceable");
        assert!(with(mi("rw,hidepid=2"), 0), "root is no exemption");
        assert!(with(mi("rw,hidepid=2,gid=900"), 0), "root in gid");
        // per-mount options carry it too
        assert!(with(
            lines("23 1 0:22 / /proc rw,hidepid=2 - proc proc rw\n"),
            501
        ));
        // an empty source shifts the columns
        assert!(with(
            lines("23 1 0:22 / /proc rw - proc  rw,hidepid=2\n"),
            501
        ));
        // two /proc lines, only the FIRST hides
        assert!(with(
            lines(
                "23 1 0:22 / /proc rw - proc proc rw,hidepid=2\n\
                 24 1 0:23 / /proc rw - proc proc rw\n"
            ),
            501
        ));
        // the last /proc line is not procfs
        assert!(with(
            lines(
                "23 1 0:22 / /proc rw - proc proc rw\n\
                 24 1 0:23 / /proc rw - tmpfs tmpfs rw\n"
            ),
            501
        ));
        // fail closed
        assert!(with(Err(ErrorKind::PermissionDenied.into()), 501));
        assert!(with(Ok("garbage\n".into()), 501), "no /proc mount");
        assert!(
            with(lines("23 1 0:22 / /proc rw proc proc rw\n"), 501),
            "no separator"
        );
        assert!(with(lines("23 1 0:22 / /proc rw - \n"), 501), "no fstype");
    }

    #[test]
    fn a_pid_namespace_mismatch_makes_the_listing_incomplete() {
        let with = |l: Option<PathBuf>| {
            let mut f = fake();
            f.self_link = l;
            listing_incomplete_via(&f)
        };
        let me = std::process::id();
        assert!(!with(Some(PathBuf::from(me.to_string()))), "control");
        assert!(with(Some(PathBuf::from((me + 1).to_string()))), "differs");
        assert!(with(None), "unreadable or dangling");
        assert!(with(Some(PathBuf::from("thread-self"))), "non-numeric");
        assert!(with(Some(PathBuf::from(format!("+{me}")))), "not decimal");
    }

    #[test]
    fn a_proc_subtree_bind_or_a_pid_dir_mount_makes_the_listing_incomplete() {
        let with = |s: &str| {
            let mut f = fake();
            f.mountinfo = Ok(s.to_string());
            listing_incomplete_via(&f)
        };
        assert!(
            with("23 1 0:22 /1 /proc rw - proc proc rw\n"),
            "subtree bind"
        );
        assert!(!with("23 1 0:22 / /proc rw - proc proc rw\n"), "control");
        let base = "23 1 0:22 / /proc rw - proc proc rw\n";
        for mp in ["/proc/1234", "/proc/1234/ns", "/proc/1"] {
            let l = format!("{base}30 23 0:40 / {mp} rw - tmpfs tmpfs rw\n");
            assert!(with(&l), "{mp}");
        }
        for mp in ["/proc/sys", "/proc/kcore", "/proc/bus", "/proc/12a"] {
            let l = format!("{base}30 23 0:40 / {mp} ro - tmpfs tmpfs ro\n");
            assert!(!with(&l), "{mp} unaffected");
        }
    }

    #[test]
    fn realistic_mountinfo_lines_with_optional_fields() {
        let with = |s: &str| {
            let mut f = fake();
            f.mountinfo = Ok(s.to_string());
            listing_incomplete_via(&f)
        };
        assert!(!with(
            "25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
        ));
        assert!(with(
            "25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw,gid=0,hidepid=invisible,subset=pid\n"
        ));
    }

    /// The walk itself carries the verdict in `Listing::incomplete`, and not in
    /// `unreadable_claude`.
    #[test]
    fn the_walk_sets_incomplete_from_the_mounts() {
        let mut f = fake();
        let ok = try_list_detailed_via(&f, &[77]).unwrap();
        assert!(!ok.incomplete, "control: complete /proc");
        assert_eq!(ok.sessions.len(), 1);
        f.mountinfo = Ok(mountinfo_line("rw,hidepid=2"));
        let hidden = try_list_detailed_via(&f, &[77]).unwrap();
        assert!(hidden.incomplete);
        assert_eq!(hidden.unreadable_claude, 0);
    }

    /// Each mount shape reports its own cause, so the operator gets the right next step;
    /// control: a clean procfs has none.
    #[test]
    fn each_incompleteness_has_its_own_cause() {
        let cause = |f: &Fake| listing_incomplete_cause_via(f);
        assert_eq!(cause(&fake()), None, "control");
        let mut f = fake();
        f.mountinfo = Ok(mountinfo_line("rw,hidepid=2"));
        assert_eq!(cause(&f), Some(IncompleteCause::Hidepid));
        let mut f = fake();
        f.self_link = Some(PathBuf::from((std::process::id() + 1).to_string()));
        assert_eq!(cause(&f), Some(IncompleteCause::PidNamespaceMismatch));
        let mut f = fake();
        f.fs_type = Some(0x0102_1994);
        assert_eq!(cause(&f), Some(IncompleteCause::NotProcfs));
        let mut f = fake();
        f.mountinfo = Ok("23 1 0:22 /1 /proc rw - proc proc rw\n".into());
        assert_eq!(cause(&f), Some(IncompleteCause::SubtreeBind));
        let mut f = fake();
        f.mountinfo = Ok(format!(
            "{}30 23 0:40 / /proc/1234 rw - tmpfs tmpfs rw\n",
            "23 1 0:22 / /proc rw - proc proc rw\n"
        ));
        assert_eq!(cause(&f), Some(IncompleteCause::PidDirMount));
        let mut f = fake();
        f.mountinfo = Err(ErrorKind::PermissionDenied.into());
        assert_eq!(cause(&f), Some(IncompleteCause::MountinfoUnreadable));
        // the walk carries the cause, and it agrees with `incomplete`
        let mut f = fake();
        f.mountinfo = Ok(mountinfo_line("rw,hidepid=2"));
        let l = try_list_detailed_via(&f, &[77]).unwrap();
        assert!(l.incomplete && l.incomplete_cause == Some(IncompleteCause::Hidepid));
    }

    /// A refusal to read pid 1's `stat` (EPERM) marks the caller restricted; NotFound
    /// (hidepid) does not, a readable one does not, and under `hidepid=1` (EPERM too) the
    /// known cause wins: not restricted, cause `Hidepid`.
    #[test]
    fn a_refused_pid_one_stat_marks_the_caller_restricted() {
        let walk = |r: Replies| {
            let f = fake();
            set(&f, "stat", r);
            try_list_detailed_via(&f, &[77]).unwrap().restricted
        };
        assert!(!walk(vec![Ok(stat_body(34816, 4000))]), "control");
        assert!(walk(vec![Err(ErrorKind::PermissionDenied)]));
        assert!(
            !walk(vec![Err(ErrorKind::NotFound)]),
            "hidepid is incomplete, not restricted"
        );
        let mut f = fake();
        f.mountinfo = Ok(mountinfo_line("rw,hidepid=1"));
        set(&f, "stat", vec![Err(ErrorKind::PermissionDenied)]);
        let l = try_list_detailed_via(&f, &[77]).unwrap();
        assert!(!l.restricted, "hidepid=1 is not a sandbox");
        assert_eq!(l.incomplete_cause, Some(IncompleteCause::Hidepid));
        // a sandbox denying /proc: /proc/self unreadable AND pid 1 refused ⇒ still
        // restricted, whatever incompleteness cause is also reported
        let mut f = fake();
        f.self_link = None;
        set(&f, "stat", vec![Err(ErrorKind::PermissionDenied)]);
        let l = try_list_detailed_via(&f, &[77]).unwrap();
        assert!(
            l.restricted,
            "a sandbox stays restricted: {:?}",
            l.incomplete_cause
        );
        let mut f = fake();
        f.mountinfo = Err(std::io::Error::from(ErrorKind::PermissionDenied));
        set(&f, "stat", vec![Err(ErrorKind::PermissionDenied)]);
        assert!(
            try_list_detailed_via(&f, &[77]).unwrap().restricted,
            "mountinfo denied"
        );
    }

    /// pid reuse between the two `stat` reads: different start ticks, different process.
    #[test]
    fn a_pid_reused_between_the_reads_is_not_a_session() {
        let f = fake();
        set(
            &f,
            "stat",
            vec![Ok(stat_body(34816, 4000)), Ok(stat_body(34816, 9000))],
        );
        assert_eq!(read_process_via(77, &f), Ok(None));
        let f = fake();
        set(
            &f,
            "stat",
            vec![Ok(stat_body(34816, 4000)), Err(ErrorKind::NotFound)],
        );
        assert_eq!(
            read_process_via(77, &f),
            Ok(None),
            "exited between the reads"
        );
    }

    #[test]
    fn parse_euid_reads_the_effective_uid() {
        assert_eq!(parse_euid("Name:\tx\nUid:\t1\t2\t3\t4\n"), Some(2));
        assert_eq!(parse_euid("Name:\tx\n"), None);
        assert_eq!(parse_euid("Uid:\t1\n"), None);
    }

    #[test]
    fn parse_ppid_reads_field_four_after_the_last_paren() {
        assert_eq!(
            parse_ppid("123 (claude) S 77 123 123 0 -1 4194304"),
            Some(77)
        );
        // comm containing spaces and parens must not shift the fields
        assert_eq!(parse_ppid("123 (a) b) (c) S 88 123 123 0 -1"), Some(88));
        assert_eq!(parse_ppid("123 (claude) S"), None);
        assert_eq!(parse_ppid("garbage"), None);
        assert_eq!(parse_ppid("123 (claude) S notanumber 1"), None);
    }

    #[test]
    fn clock_ticks_default_only_when_non_positive() {
        assert_eq!(ticks_or_default(250), 250);
        assert_eq!(ticks_or_default(0), 100);
        assert_eq!(ticks_or_default(-1), 100);
        assert!(clock_ticks_per_sec() > 0);
    }

    #[test]
    fn parent_pid_of_this_process_is_readable() {
        assert!(parent_pid(std::process::id()).is_some());
    }

    #[test]
    fn parse_environ_finds_key() {
        let blob = b"PATH=/bin\0USER=alice\0CLAUDE_CONFIG_DIR=/x/config-3\0HOME=/h\0";
        assert_eq!(
            parse_environ(blob, "CLAUDE_CONFIG_DIR"),
            Some("/x/config-3".to_string())
        );
    }

    #[test]
    fn parse_environ_handles_missing_key() {
        let blob = b"PATH=/bin\0USER=alice\0";
        assert_eq!(parse_environ(blob, "CLAUDE_CONFIG_DIR"), None);
    }

    #[test]
    fn parse_environ_avoids_substring_match() {
        let blob = b"FAKE_CLAUDE_CONFIG_DIR=wrong\0CLAUDE_CONFIG_DIR=/right\0";
        assert_eq!(
            parse_environ(blob, "CLAUDE_CONFIG_DIR"),
            Some("/right".to_string())
        );
    }

    #[test]
    fn parse_environ_tolerates_trailing_nul() {
        let blob = b"USER=alice\0";
        assert_eq!(parse_environ(blob, "USER"), Some("alice".to_string()));
    }

    #[test]
    fn parse_environ_tolerates_empty_entries() {
        // Some kernels leave extra NULs at the end of /proc/environ.
        let blob = b"\0\0USER=alice\0\0CLAUDE_CONFIG_DIR=/x/config-1\0\0";
        assert_eq!(
            parse_environ(blob, "CLAUDE_CONFIG_DIR"),
            Some("/x/config-1".to_string())
        );
    }

    fn codex_fake() -> Fake {
        let f = fake();
        set(&f, "comm", vec![Ok(b"codex\n".to_vec())]);
        set(
            &f,
            "environ",
            vec![Ok(b"HOME=/h\0CODEX_HOME=/x/accounts/term-9\0".to_vec())],
        );
        set(&f, "cmdline", vec![Ok(b"/v/bin/codex\0".to_vec())]);
        f
    }

    /// S3: on Linux the wake child (`codex -c k=v queue ...`, the target's CODEX_HOME) is NOT
    /// listed as a second owner of the home, while the real session and an unreadable-argv
    /// codex still are. Falsifier: without the subcommand check the queue child is listed.
    #[test]
    fn the_wake_child_is_not_a_second_owner_of_the_targets_home() {
        let f = codex_fake();
        set(
            &f,
            "cmdline",
            vec![Ok(
                b"codex\0-c\0sqlite_home=/h/config-3\0queue\0--thread\0t\0--message\0m\0".to_vec(),
            )],
        );
        assert_eq!(read_process_kind_via(CliKind::Codex, 77, &f), Ok(None));
        assert_eq!(
            listing_entry_kind_via(CliKind::Codex, 77, &f),
            ListEntry::NotSession
        );
        // the interactive session (no subcommand) and `resume` stay listed
        for argv in [&b"codex\0"[..], b"codex\0resume\0queue\0"] {
            let g = codex_fake();
            set(&g, "cmdline", vec![Ok(argv.to_vec())]);
            assert!(read_process_kind_via(CliKind::Codex, 77, &g)
                .unwrap()
                .is_some());
        }
        // an unreadable cmdline hides nothing
        let g = codex_fake();
        set(&g, "cmdline", vec![Err(ErrorKind::PermissionDenied)]);
        assert!(read_process_kind_via(CliKind::Codex, 77, &g)
            .unwrap()
            .is_some());
        // hop logic is unchanged: as a caller's ancestor image the queue process is still a
        // session image (the wake child is a sibling of an MCP caller, never its ancestor)
        let hop = hop_fake(Some(b"codex\n"), Some(b"codex\0-c\0k=v\0queue\0"), 501);
        assert_eq!(hop_probe_via(77, &hop), YES);
    }

    #[test]
    fn a_codex_native_process_is_a_codex_session_and_never_a_claude_one() {
        let info = read_process_kind_via(CliKind::Codex, 77, &codex_fake())
            .unwrap()
            .expect("a codex session");
        assert_eq!(info.config_dir, PathBuf::from("/x/accounts/term-9"));
        assert_eq!(
            read_process_kind_via(CliKind::Claude, 77, &codex_fake()),
            Ok(None)
        );
        // a claude fixture is not a codex session either
        assert_eq!(read_process_kind_via(CliKind::Codex, 77, &fake()), Ok(None));
    }

    #[test]
    fn the_node_wrapper_in_front_of_codex_is_not_a_second_session() {
        // comm `node`, same CODEX_HOME inherited: positively not named `codex`.
        let f = codex_fake();
        set(&f, "comm", vec![Ok(b"node\n".to_vec())]);
        assert_eq!(read_process_kind_via(CliKind::Codex, 77, &f), Ok(None));
        assert_eq!(
            listing_entry_kind_via(CliKind::Codex, 77, &f),
            ListEntry::NotSession
        );
    }

    #[test]
    fn an_unreadable_codex_is_counted_for_codex_and_not_for_claude() {
        let f = codex_fake();
        set(&f, "environ", vec![Err(ErrorKind::PermissionDenied)]);
        assert_eq!(
            listing_entry_kind_via(CliKind::Codex, 77, &f),
            ListEntry::UnreadableClaude
        );
        assert_eq!(
            listing_entry_kind_via(CliKind::Claude, 77, &f),
            ListEntry::NotSession
        );
    }

    #[test]
    fn cmdline_is_split_on_nul_and_empty_is_no_arguments() {
        assert_eq!(
            split_cmdline(b"codex\0-c\0sqlite_home=\"/a\"\0resume\0t\0"),
            vec!["codex", "-c", "sqlite_home=\"/a\"", "resume", "t"]
        );
        assert!(split_cmdline(b"").is_empty());
    }

    // ---- between-hop image probe (F1): no terminal, no environment required ----

    fn hop_fake(comm: Option<&[u8]>, cmdline: Option<&[u8]>, uid: u32) -> Fake {
        let f = fake();
        {
            let mut m = f.files.borrow_mut();
            m.insert(
                "status".into(),
                vec![Ok(format!(
                    "Name:\tx\nState:\tS (sleeping)\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                )
                .into_bytes())],
            );
            m.insert(
                "comm".into(),
                vec![comm.map_or(Err(ErrorKind::PermissionDenied), |c| Ok(c.to_vec()))],
            );
            m.insert(
                "cmdline".into(),
                vec![cmdline.map_or(Err(ErrorKind::PermissionDenied), |c| Ok(c.to_vec()))],
            );
        }
        f
    }

    const YES: HopProbe = HopProbe::Process {
        session_image: true,
        codex_wrapper: false,
    };
    const NO: HopProbe = HopProbe::Process {
        session_image: false,
        codex_wrapper: false,
    };

    fn with_exe(f: Fake, exe: &str) -> Fake {
        set(&f, "exe-link", vec![Ok(exe.as_bytes().to_vec())]);
        f
    }

    #[test]
    fn a_codex_or_claude_hop_without_terminal_or_env_is_a_session_image() {
        // the fake carries no `environ` or tty at all: only the image is read
        let codex = hop_fake(Some(b"codex\n"), Some(b"/v/bin/codex\0exec\0"), 501);
        assert_eq!(hop_probe_via(77, &codex), YES);
        let claude = hop_fake(Some(b"claude\n"), Some(b"claude\0"), 501);
        assert_eq!(hop_probe_via(77, &claude), YES);
        let sh = hop_fake(Some(b"bash\n"), Some(b"bash\0-c\0x\0"), 501);
        assert_eq!(hop_probe_via(77, &sh), NO);
        // one name unreadable and no positive hit: undetermined, not "no"
        let half = hop_fake(Some(b"bash\n"), None, 501);
        assert_eq!(hop_probe_via(77, &half), HopProbe::Unreadable);
        // one name unreadable but the other says codex: a session
        let named = hop_fake(Some(b"codex\n"), None, 501);
        assert_eq!(hop_probe_via(77, &named), YES);
    }

    /// N1: a 15-character truncated `comm` of the native asset, a renamed process whose
    /// `exe` link says what it is, and npm Claude's `/claude/versions/` binary.
    #[test]
    fn truncated_renamed_and_versioned_images_are_session_images() {
        let trunc = hop_fake(Some(b"codex-aarch64-a\n"), Some(b"x\0"), 501);
        assert_eq!(hop_probe_via(77, &trunc), YES);
        let renamed = with_exe(
            hop_fake(Some(b"cx\n"), Some(b"cx\0"), 501),
            "/v/codex-x86_64-unknown-linux-musl",
        );
        assert_eq!(hop_probe_via(77, &renamed), YES);
        let ver = with_exe(
            hop_fake(Some(b"2.1.289\n"), Some(b"2.1.289\0"), 501),
            "/h/.local/share/claude/versions/2.1.289",
        );
        assert_eq!(hop_probe_via(77, &ver), YES);
        let node = hop_fake(
            Some(b"node\n"),
            Some(b"node\0--x\0/o/@google/gemini-cli/bundle/gemini.js\0"),
            501,
        );
        assert_eq!(hop_probe_via(77, &node), YES);
        let other = hop_fake(Some(b"node\n"), Some(b"node\0/r/trestle.mjs\0"), 501);
        assert_eq!(hop_probe_via(77, &other), NO);
    }

    /// N5: another uid's CLI image is a session; its readable non-CLI image is not; an
    /// unreadable exe link never overrides two read names.
    #[test]
    fn another_uids_cli_image_is_a_session() {
        let other = hop_fake(Some(b"codex\n"), Some(b"codex\0"), 999);
        assert_eq!(hop_probe_via(77, &other), YES);
        let sh = hop_fake(Some(b"bash\n"), Some(b"bash\0"), 999);
        assert_eq!(hop_probe_via(77, &sh), NO);
    }
}
