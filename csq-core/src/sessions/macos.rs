//! macOS backend for live CC session discovery.
//!
//! No process is spawned to enumerate sessions. Everything comes from kernel
//! interfaces, in the shape `ps`/`lsof` themselves use, so one pass over a loaded
//! host costs milliseconds instead of minutes (a `ps` + per-session `lsof` + `ps`
//! pass was measured at ~3 min with a load average near 38 and 20 sessions):
//!
//! - candidates: `proc_listallpids`, then `proc_pidinfo(PROC_PIDTBSDINFO)` per pid
//!   for the owner uid (same-UID only), the start time and the controlling tty;
//! - argv and environment (`CLAUDE_CONFIG_DIR`, `TERM_SESSION_ID`, `ITERM_PROFILE`):
//!   `sysctl(KERN_PROCARGS2)`, parsed by [`parse_procargs`], which is exact (NUL
//!   separated), unlike the old whitespace heuristic over `ps -E`;
//! - cwd: `proc_pidinfo(PROC_PIDVNODEPATHINFO)` → `pvi_cdir.vip_path`;
//! - tty name: `devname_r` over the BSD info's `e_tdev`.
//!
//! `ps` is NOT kept as a fallback: every syscall above has existed since macOS 10.5,
//! and a fallback that spawns would reintroduce the cost it exists to remove.
//!
//! Terminal titles are the one remaining subprocess (`osascript`). They are a
//! decoration, so they are opt-in ([`try_list_opts`]), cached for 10 s, and bounded by
//! a hard timeout ([`OSASCRIPT_TIMEOUT`]); the machine paths never ask for them.

use super::{
    parse_term_session_id, CliKind, HopProbe, Listing, PidLookup, SessionInfo, Undetermined,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
#[cfg(test)]
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub(crate) mod holders;

/// Upper bound on the `KERN_PROCARGS2` buffer. `kern.argmax` is 1 MiB on macOS and the
/// argv + environment of a process cannot exceed it, so 2 MiB holds any real process;
/// a larger one makes the sysctl fail (`ENOMEM`) and the process is omitted rather than
/// read truncated.
const PROCARGS_CAP: usize = 2 << 20;
/// Largest `argc` accepted from a `KERN_PROCARGS2` buffer (a corrupt count must not drive
/// an unbounded walk).
const MAX_ARGC: usize = 65_536;
/// Upper bound on the pid table (`proc_listallpids`) — 256 Ki pids is far beyond the
/// kernel's `maxproc`.
const MAX_PIDS: usize = 262_144;

/// Returns the list of live CC sessions for the current user, with iTerm titles (the
/// desktop display path).
pub fn list() -> Vec<SessionInfo> {
    try_list_opts(true).unwrap_or_default()
}

/// [`list`] without titles, but `None` when the process table itself could not be read,
/// so a caller can tell "no live sessions" from "could not look".
pub fn try_list() -> Option<Vec<SessionInfo>> {
    try_list_opts(false)
}

/// [`try_list`], optionally resolving iTerm titles (bounded, cached `osascript`).
pub fn try_list_opts(titles: bool) -> Option<Vec<SessionInfo>> {
    try_list_detailed_opts(titles).map(|l| l.sessions)
}

/// [`try_list`] plus the count of same-uid `claude`-named processes that could not be read.
pub fn try_list_detailed() -> Option<Listing> {
    try_list_detailed_opts(false)
}

/// [`try_list_detailed`], optionally resolving iTerm titles.
pub fn try_list_detailed_opts(titles: bool) -> Option<Listing> {
    try_list_detailed_kind_opts(CliKind::Claude, titles)
}

/// [`try_list_detailed_opts`] for the processes of `kind`. Terminal titles are resolved for
/// Claude sessions only (the iTerm lookup is the desktop's Claude display path).
pub fn try_list_detailed_kind_opts(kind: CliKind, titles: bool) -> Option<Listing> {
    let pids = list_pids()?;
    let total = pids.len();
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let mut buf = vec![0u8; procargs_capacity()];
    let mut out: Vec<SessionInfo> = Vec::new();
    let mut unreadable_pids: Vec<u32> = Vec::new();
    for pid in pids {
        let mut args = |p: u32| match read_procargs(p, &mut buf) {
            Probe::Got(len) => Probe::Got(buf[..len].to_vec()),
            Probe::Gone => Probe::Gone,
            Probe::Failed => Probe::Failed,
        };
        // A pid that cannot be read cannot become a row, but it is COUNTED when it is a
        // same-uid `claude`-named process: it may be a session, so a caller that needs
        // uniqueness must not read the listing as whole (INV-31-02).
        match listing_entry_kind_via(
            kind,
            pid,
            uid,
            Reads {
                bsd: &probe_bsd_info,
                args: &mut args,
                cwd: &read_cwd,
            },
        ) {
            ListEntry::Session(info) => out.push(info),
            ListEntry::UnreadableClaude => unreadable_pids.push(pid),
            ListEntry::NotSession => {}
        }
    }
    if titles && kind == CliKind::Claude {
        let titles = read_iterm_titles_by_tty();
        for info in &mut out {
            if let Some(ref tty) = info.tty {
                if let Some((window_name, session_name)) = titles.get(tty) {
                    info.terminal_title = Some(format_terminal_title(window_name, session_name));
                }
            }
        }
    }
    let restricted = caller_restricted(total, unreadable_pids.len(), &probe_bsd_info(1));
    Some(Listing {
        sessions: out,
        unreadable_claude: unreadable_pids.len(),
        unreadable_pids,
        incomplete: false,
        incomplete_cause: None,
        restricted,
    })
}

/// Is the caller refused process information outright (a sandbox)? Pid 1 is always alive and
/// foreign to a non-root caller, so its short read succeeds on a normal host (measured: 358
/// foreign pids resolve through it, 0 same-uid pids fail); when even that read fails, or every
/// listed pid is unreadable, the unreadable pids are a symptom of the restriction rather than
/// findings about `claude`. A root caller reads pid 1 in full, so it is never restricted.
pub(crate) fn caller_restricted(total: usize, unreadable: usize, pid1: &Probe<BsdFacts>) -> bool {
    matches!(pid1, Probe::Failed) || (total > 0 && unreadable == total)
}

/// One pid's contribution to a listing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListEntry {
    Session(SessionInfo),
    /// Positively not a session: gone, another uid, a zombie, no terminal, or named
    /// something other than `claude`.
    NotSession,
    /// A same-uid process that may be a `claude` (named `claude`, or its name could not be
    /// read) and could not be read into a session.
    UnreadableClaude,
}

/// [`read_session_via`] for the listing. A read failure is classified by what the cheap
/// `PROC_PIDTBSDINFO` read still says without the arguments: `pbi_comm`/`pbi_name`,
/// the owner, and the zombie status.
#[cfg(test)]
pub(crate) fn listing_entry_via(pid: u32, uid: u32, reads: Reads<'_>) -> ListEntry {
    listing_entry_kind_via(CliKind::Claude, pid, uid, reads)
}

/// [`listing_entry_via`] for `kind`.
pub(crate) fn listing_entry_kind_via(
    kind: CliKind,
    pid: u32,
    uid: u32,
    reads: Reads<'_>,
) -> ListEntry {
    let bsd = reads.bsd;
    match read_session_kind_via(kind, pid, uid, reads) {
        Ok(Some(info)) => ListEntry::Session(info),
        Ok(None) => ListEntry::NotSession,
        Err(Undetermined) => match bsd(pid) {
            Probe::Gone => ListEntry::NotSession,
            // Not even the name could be read: it may be a claude.
            Probe::Failed => ListEntry::UnreadableClaude,
            Probe::Got(f) if f.uid != uid || f.zombie => ListEntry::NotSession,
            Probe::Got(f) if f.named(kind) => ListEntry::UnreadableClaude,
            Probe::Got(_) => ListEntry::NotSession,
        },
    }
}

/// The session for one pid, read the same way the listing reads it, without touching any
/// other process. Three outcomes (spec 31 §3): `Ok(Some)` a live session; `Ok(None)` the
/// pid is positively not one (gone, other uid, not `claude`, no `CLAUDE_CONFIG_DIR`, no
/// controlling terminal); `Err` it could not be read, which is NOT "not a session".
pub fn session_info_for_pid(pid: u32) -> PidLookup {
    session_info_for_pid_kind(CliKind::Claude, pid)
}

/// [`session_info_for_pid`] for `kind`.
pub fn session_info_for_pid_kind(kind: CliKind, pid: u32) -> PidLookup {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let mut buf = vec![0u8; procargs_capacity()];
    read_session(kind, pid, uid, &mut buf)
}

/// [`hop_probe_via`] over the real kernel reads.
pub(crate) fn hop_probe(pid: u32) -> HopProbe {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let mut buf = vec![0u8; procargs_capacity()];
    let mut args = |p: u32| match read_procargs(p, &mut buf) {
        Probe::Got(len) => Probe::Got(buf[..len].to_vec()),
        Probe::Gone => Probe::Gone,
        Probe::Failed => Probe::Failed,
    };
    hop_probe_via(
        pid,
        uid,
        &probe_bsd_info,
        &mut args,
        &read_exe_path,
        &crate::sessions::exe_is_resolved_cli,
    )
}

/// The executable path of `pid` (`proc_pidpath`). Unlike `argv[0]` and the kernel name the
/// process cannot change it. `ESRCH` is [`Probe::Gone`]; any other failure (`EPERM` on
/// another uid's process) is [`Probe::Failed`].
fn read_exe_path(pid: u32) -> Probe<PathBuf> {
    let Ok(cpid) = libc::c_int::try_from(pid) else {
        return Probe::Gone;
    };
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is a live, exclusively borrowed buffer of exactly `buf.len()` bytes;
    // proc_pidpath writes at most that many and returns the byte count, or <= 0 on failure.
    let n = unsafe {
        libc::proc_pidpath(
            cpid,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        )
    };
    if n > 0 {
        buf.truncate(usize::try_from(n).unwrap_or(0));
        Probe::Got(PathBuf::from(OsStr::from_bytes(&buf)))
    } else if last_errno() == Some(libc::ESRCH) {
        Probe::Gone
    } else {
        Probe::Failed
    }
}

/// One process between a caller and a claimed owner, read for its IMAGE only: no terminal
/// and no environment are required (a `codex exec` from a tool has neither). The image is
/// classified from every signal that was readable (kernel `claude`/`codex` name, argv, the
/// `proc_pidpath` executable) by [`crate::sessions::image_verdict`], whatever the owner uid:
/// a CLI image of another uid between the caller and the owner is still a nearer session.
/// When the arguments and the path are both unreadable (`EPERM` on another uid's process)
/// and the kernel name is not a CLI, the hop is `Unreadable` (fail closed). A zombie has no
/// image. The kernel name is only trusted as a read for a same-uid process: the short
/// fallback read used for other uids carries no names.
pub(crate) fn hop_probe_via(
    pid: u32,
    uid: u32,
    bsd: &dyn Fn(u32) -> Probe<BsdFacts>,
    args: &mut dyn FnMut(u32) -> Probe<Vec<u8>>,
    exe: &dyn Fn(u32) -> Probe<PathBuf>,
    resolved: &dyn Fn(&std::path::Path) -> bool,
) -> HopProbe {
    let facts = match bsd(pid) {
        Probe::Gone => return HopProbe::Gone,
        Probe::Failed => return HopProbe::Unreadable,
        Probe::Got(f) => f,
    };
    if facts.pid != pid || facts.zombie {
        return HopProbe::Unreadable;
    }
    let comm = if facts.claude_named {
        Some("claude".to_string())
    } else if facts.codex_named {
        Some("codex".to_string())
    } else if facts.uid == uid {
        Some(String::new()) // read, and not a CLI the kernel name check knows
    } else {
        None
    };
    let argv = match args(pid) {
        Probe::Gone => return HopProbe::Gone,
        Probe::Failed => None,
        Probe::Got(raw) => parse_procargs(&raw).map(|p| {
            p.argv
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()
        }),
    };
    let exe = match exe(pid) {
        Probe::Gone => return HopProbe::Gone,
        Probe::Failed => None,
        Probe::Got(p) => Some(p),
    };
    let reads = crate::sessions::ImageReads { comm, argv, exe };
    let codex_wrapper = crate::sessions::is_codex_node_wrapper(&reads);
    match crate::sessions::image_verdict(&reads, resolved) {
        Some(session_image) => HopProbe::Process {
            session_image,
            codex_wrapper: session_image && codex_wrapper,
        },
        None => HopProbe::Unreadable,
    }
}

/// The launch argv of one process (`KERN_PROCARGS2`, lossy UTF-8); `None` when unreadable.
/// The environment region is parsed past and never returned.
pub(crate) fn launch_argv_for_pid(pid: u32) -> Option<Vec<String>> {
    let mut buf = vec![0u8; procargs_capacity()];
    let Probe::Got(len) = read_procargs(pid, &mut buf) else {
        return None;
    };
    let parsed = parse_procargs(&buf[..len])?;
    Some(
        parsed
            .argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect(),
    )
}

/// Every pid in the kernel process table. `None` when the table cannot be read, so the
/// caller reports "undetermined" rather than an empty success (INV-31-02).
fn list_pids() -> Option<Vec<u32>> {
    // SAFETY: a null buffer with size 0 only asks for the number of pids.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return None;
    }
    let mut cap = usize::try_from(n).ok()?.saturating_add(256).min(MAX_PIDS);
    for _ in 0..4 {
        let mut pids: Vec<libc::pid_t> = vec![0; cap];
        let bytes = libc::c_int::try_from(cap * std::mem::size_of::<libc::pid_t>()).ok()?;
        // SAFETY: `pids` is a live, exclusively borrowed buffer of exactly `bytes`
        // bytes; proc_listallpids writes at most that many and returns the pid count
        // written, or <= 0 on failure.
        let got =
            unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<libc::c_void>(), bytes) };
        if got <= 0 {
            return None;
        }
        let got = usize::try_from(got).ok()?;
        if got < cap {
            pids.truncate(got);
            return Some(
                pids.into_iter()
                    .filter_map(|p| u32::try_from(p).ok().filter(|p| *p > 0))
                    .collect(),
            );
        }
        // The table filled the buffer: it may have grown between the two calls.
        if cap >= MAX_PIDS {
            return None;
        }
        cap = (cap * 2).min(MAX_PIDS);
    }
    None
}

/// The kernel facts of one process that session classification uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BsdFacts {
    pub pid: u32,
    pub uid: u32,
    /// `pbi_start_tvsec`; zero means the kernel did not populate it.
    pub start: u64,
    /// `e_tdev`; [`NODEV`] when the process has no controlling terminal.
    pub tdev: u32,
    /// `pbi_comm` or `pbi_name` is `claude`: readable without the process arguments, so it
    /// still classifies a process whose arguments cannot be read.
    pub claude_named: bool,
    /// `pbi_comm` or `pbi_name` is `codex`: the same, for a Codex session.
    pub codex_named: bool,
    /// `pbi_status == SZOMB`: exited, awaiting its parent's wait; it has no arguments to read.
    pub zombie: bool,
    /// `pbi_pgid`: the process group. A group outlives its leader and survives reparenting,
    /// and reading it needs no environment, so the orphan sweep's holder scan uses it as a
    /// witness for a terminal whose launcher (the group leader) has died.
    pub pgid: u32,
}

impl BsdFacts {
    /// Whether the process is named after `kind` (readable without its arguments).
    pub(crate) fn named(&self, kind: CliKind) -> bool {
        match kind {
            CliKind::Claude => self.claude_named,
            CliKind::Codex => self.codex_named,
        }
    }
}

/// Whether a NUL-terminated `c_char` field (`pbi_comm`, `pbi_name`) is exactly `claude`.
pub(crate) fn c_field_is_claude(field: &[libc::c_char]) -> bool {
    c_field_is(field, b"claude")
}

/// Whether a NUL-terminated `c_char` field is exactly `name`.
pub(crate) fn c_field_is(field: &[libc::c_char], name: &[u8]) -> bool {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    bytes == name
}

/// `pbi_status` of a zombie (`SZOMB` in `<sys/proc.h>`).
const SZOMB: u32 = 5;

/// `e_tdev` of a process with no controlling terminal.
pub(crate) const NODEV: u32 = u32::MAX;

/// One kernel read: the process is gone, the read failed for any other reason, or a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Probe<T> {
    /// `ESRCH`: the process no longer exists.
    Gone,
    /// Any other failure: the process may well exist, this read says nothing about it.
    Failed,
    Got(T),
}

/// The injected kernel reads behind [`read_session_via`].
pub(crate) struct Reads<'a> {
    pub bsd: &'a dyn Fn(u32) -> Probe<BsdFacts>,
    pub args: &'a mut dyn FnMut(u32) -> Probe<Vec<u8>>,
    pub cwd: &'a dyn Fn(u32) -> Option<PathBuf>,
}

/// One candidate pid into a session, three-outcome (see [`session_info_for_pid`]). `buf` is
/// the reused `KERN_PROCARGS2` buffer. The environment is never logged.
fn read_session(kind: CliKind, pid: u32, uid: u32, buf: &mut Vec<u8>) -> PidLookup {
    let mut args = |p: u32| match read_procargs(p, buf) {
        Probe::Got(len) => Probe::Got(buf[..len].to_vec()),
        Probe::Gone => Probe::Gone,
        Probe::Failed => Probe::Failed,
    };
    read_session_kind_via(
        kind,
        pid,
        uid,
        Reads {
            bsd: &probe_bsd_info,
            args: &mut args,
            cwd: &read_cwd,
        },
    )
}

/// The classification, over injected reads so every outcome is testable without a process.
#[cfg(test)]
pub(crate) fn read_session_via(pid: u32, uid: u32, reads: Reads<'_>) -> PidLookup {
    read_session_kind_via(CliKind::Claude, pid, uid, reads)
}

/// [`read_session_via`] for `kind`: argv\[0\] must be `kind.comm()` and the handle dir is
/// `kind.env_key()`. For Codex that is the NATIVE binary (`…/vendor/…/bin/codex`); the
/// `node …/bin/codex` wrapper has argv\[0\] `node`, so it is positively not a session and
/// the pair never counts twice (spec 32 §2.1).
pub(crate) fn read_session_kind_via(
    kind: CliKind,
    pid: u32,
    uid: u32,
    reads: Reads<'_>,
) -> PidLookup {
    let Reads { bsd, args, cwd } = reads;
    let first = match bsd(pid) {
        Probe::Gone => return Ok(None),
        Probe::Failed => return Err(Undetermined),
        Probe::Got(f) => f,
    };
    // The kernel answered for a different pid: that read is not about this process.
    if first.pid != pid {
        return Err(Undetermined);
    }
    if first.uid != uid {
        return Ok(None);
    }
    // A session has a controlling terminal, as under the old `ps` listing (no `-x`).
    if first.tdev == NODEV {
        return Ok(None);
    }
    let raw = match args(pid) {
        Probe::Gone => return Ok(None),
        Probe::Failed => return Err(Undetermined),
        Probe::Got(b) => b,
    };
    // Same uid, readable, but the arguments could not be read or parsed: undetermined.
    let Some(parsed) = parse_procargs(&raw) else {
        return Err(Undetermined);
    };
    // argv[0] basename is `claude`. Child processes that merely inherit CLAUDE_CONFIG_DIR
    // (node MCP servers, language servers) are positively not sessions.
    let Some(argv0) = parsed.argv.first() else {
        return Ok(None);
    };
    if std::path::Path::new(OsStr::from_bytes(argv0)).file_name() != Some(OsStr::new(kind.comm())) {
        return Ok(None);
    }
    // csq's wake child (`codex -c k=v queue ...`, the TARGET's CODEX_HOME) is a client of the
    // session it wakes, not a second owner of that home. `setsid` already drops it here via
    // the terminal rule above; the subcommand check makes the exclusion the same on every
    // platform and independent of how the child was spawned (spec 32 §5.1).
    if kind == CliKind::Codex {
        let argv: Vec<String> = parsed
            .argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        if crate::sessions::is_queue_invocation(&argv) {
            return Ok(None);
        }
    }
    // A `claude` whose environment came back empty was not read: its CLAUDE_CONFIG_DIR is
    // unknown, so it is undetermined, never "not a session".
    if parsed.env_is_empty() {
        return Err(Undetermined);
    }
    let Some(config_dir) = parsed.env_get(kind.env_key()).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let config_dir = PathBuf::from(OsStr::from_bytes(config_dir));
    let account_id = SessionInfo::extract_account_id(&config_dir);

    let term_session_id = parsed
        .env_get("TERM_SESSION_ID")
        .map(|v| String::from_utf8_lossy(v).into_owned());
    let (term_window, term_tab, term_pane) = term_session_id
        .as_deref()
        .map(parse_term_session_id)
        .unwrap_or((None, None, None));
    let iterm_profile = parsed
        .env_get("ITERM_PROFILE")
        .map(|v| String::from_utf8_lossy(v).into_owned());
    let cwd = cwd(pid).unwrap_or_default();

    // The pid may have been reused between the first read and the argv read: the same
    // pid must still carry the same start time and owner, or what was read is another
    // process's.
    match bsd(pid) {
        Probe::Gone => return Ok(None),
        Probe::Failed => return Err(Undetermined),
        Probe::Got(again) => {
            if again.pid != pid || again.start != first.start || again.uid != first.uid {
                return Ok(None);
            }
        }
    }

    Ok(Some(SessionInfo {
        pid,
        cwd,
        config_dir,
        account_id,
        // Zero means the kernel did not populate it: unread, so the row is omitted
        // downstream (INV-31-01), never emitted with a made-up time.
        started_at: (first.start != 0).then_some(first.start),
        tty: tty_name(first.tdev),
        term_window,
        term_tab,
        term_pane,
        iterm_profile,
        terminal_title: None, // filled in by the caller when titles are requested
    }))
}

/// A parsed `KERN_PROCARGS2` buffer. Borrows the buffer; nothing is copied.
#[derive(Debug)]
pub(crate) struct ProcArgs<'a> {
    /// `argv[0..argc]`.
    pub argv: Vec<&'a [u8]>,
    /// The NUL-separated `KEY=VALUE` environment region (everything after argv).
    env: &'a [u8],
}

impl<'a> ProcArgs<'a> {
    /// No environment entry at all (the first entry is empty or absent).
    pub(crate) fn env_is_empty(&self) -> bool {
        self.env
            .split(|&b| b == 0)
            .next()
            .is_none_or(|e| e.is_empty())
    }

    /// The value of EVERY `KEY=` entry, in order (a duplicated key is legal in a raw
    /// environment block, and which entry a runtime honours is not ours to guess). The
    /// environment region ends at the first empty entry.
    pub(crate) fn env_get_all(&self, key: &str) -> Vec<&'a [u8]> {
        let key = key.as_bytes();
        let mut values = Vec::new();
        for entry in self.env.split(|&b| b == 0) {
            if entry.is_empty() {
                break;
            }
            if let Some(value) = entry.strip_prefix(key).and_then(|r| r.strip_prefix(b"=")) {
                values.push(value);
            }
        }
        values
    }

    /// The value of the first `KEY=` entry. The environment region ends at the first
    /// empty entry (the kernel pads the tail with NULs).
    pub(crate) fn env_get(&self, key: &str) -> Option<&'a [u8]> {
        let key = key.as_bytes();
        for entry in self.env.split(|&b| b == 0) {
            if entry.is_empty() {
                return None;
            }
            if let Some(rest) = entry.strip_prefix(key) {
                if let Some(value) = rest.strip_prefix(b"=") {
                    return Some(value);
                }
            }
        }
        None
    }
}

/// Parses a `KERN_PROCARGS2` buffer: a native-endian `int argc`, the exec path (skipped:
/// argv[0] is what identifies the session) and its NUL padding, `argc` NUL-terminated argv strings, then the environment. Defensive: any
/// short, unterminated or implausible buffer is `None`; no index is trusted.
pub(crate) fn parse_procargs(buf: &[u8]) -> Option<ProcArgs<'_>> {
    let argc = u32::from_ne_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    if argc > MAX_ARGC {
        return None;
    }
    let rest = &buf[4..];
    let end = rest.iter().position(|&b| b == 0)?;
    let mut rest = &rest[end..];
    let pad = rest.iter().position(|&b| b != 0).unwrap_or(rest.len());
    rest = &rest[pad..];
    let mut argv = Vec::with_capacity(argc.min(64));
    for _ in 0..argc {
        let end = rest.iter().position(|&b| b == 0)?;
        argv.push(&rest[..end]);
        rest = &rest[end + 1..];
    }
    Some(ProcArgs { argv, env: rest })
}

/// `sysctl(CTL_KERN, KERN_PROCARGS2, pid)` into `buf` (resized once to
/// [`PROCARGS_CAP`]); the byte count written. `ESRCH` is [`Probe::Gone`]; every other
/// failure is [`Probe::Failed`].
fn read_procargs(pid: u32, buf: &mut Vec<u8>) -> Probe<usize> {
    let Ok(pid) = libc::c_int::try_from(pid) else {
        return Probe::Gone; // outside c_int: no such pid can exist
    };
    if buf.len() < procargs_capacity() {
        buf.resize(procargs_capacity(), 0);
    }
    let cap = procargs_capacity();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut len: libc::size_t = cap;
    // SAFETY: `mib` is three c_ints and namelen is 3; `buf` holds at least PROCARGS_CAP
    // >= `cap` bytes and `len` states exactly `cap`, so the kernel writes at most `len`
    // bytes and stores the written count back into it; newp is null with newlen 0.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 && len <= cap {
        return Probe::Got(len);
    }
    if rc != 0 && last_errno() == Some(libc::ESRCH) {
        Probe::Gone
    } else {
        Probe::Failed
    }
}

/// `errno` of the failed call just made.
fn last_errno() -> Option<i32> {
    std::io::Error::last_os_error().raw_os_error()
}

/// The buffer size to hand `KERN_PROCARGS2`: the kernel's own `kern.argmax`. The kernel
/// refuses a request larger than `argmax` (measured: a 2 MiB request failed for every
/// pid, this process included), so the size is read once rather than assumed, clamped
/// to [`PROCARGS_CAP`], and defaults to the documented 1 MiB if the read fails.
fn procargs_capacity() -> usize {
    static CAP: OnceLock<usize> = OnceLock::new();
    *CAP.get_or_init(|| {
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        let mut argmax: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: `mib` is two c_ints and namelen is 2; oldp points at a live c_int and
        // `len` is its exact size; newp is null with newlen 0.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                (&mut argmax as *mut libc::c_int).cast::<libc::c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        let argmax = if rc == 0 {
            usize::try_from(argmax).unwrap_or(0)
        } else {
            0
        };
        if argmax == 0 {
            1 << 20
        } else {
            argmax.clamp(64 << 10, PROCARGS_CAP)
        }
    })
}

/// The current directory of `pid` via `proc_pidinfo(PROC_PIDVNODEPATHINFO)`.
fn read_cwd(pid: u32) -> Option<PathBuf> {
    let pid = libc::c_int::try_from(pid).ok()?;
    // SAFETY: proc_vnodepathinfo is plain-old-data (integers and char arrays), for which
    // the all-zero bit pattern is valid.
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
    // SAFETY: `info` is a live, exclusively borrowed buffer of exactly `size` bytes;
    // proc_pidinfo writes at most `size` bytes and returns the byte count, or <= 0.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut info as *mut libc::proc_vnodepathinfo as *mut libc::c_void,
            size,
        )
    };
    if written != size {
        return None;
    }
    // The path is `[[c_char; 32]; 32]` in the libc binding: 1024 contiguous bytes.
    let bytes: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .iter()
        .flatten()
        .map(|&c| c as u8)
        .collect();
    parse_vnode_path(&bytes)
}

/// The NUL-terminated path in a `vip_path` buffer. `None` when it is empty or has no
/// terminator (a truncated path is not a path).
pub(crate) fn parse_vnode_path(bytes: &[u8]) -> Option<PathBuf> {
    let end = bytes.iter().position(|&b| b == 0)?;
    (end > 0).then(|| PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}

extern "C" {
    /// `devname_r(3)`: the device name for a `dev_t`, written into `buf`.
    fn devname_r(
        dev: libc::dev_t,
        mode: libc::mode_t,
        buf: *mut libc::c_char,
        len: libc::c_int,
    ) -> *mut libc::c_char;
}

/// The controlling tty (`ttys003`) for a BSD-info `e_tdev`, `None` when detached.
fn tty_name(e_tdev: u32) -> Option<String> {
    if e_tdev == u32::MAX {
        return None; // NODEV
    }
    let mut buf = [0 as libc::c_char; 64];
    // SAFETY: `buf` is a live 64-byte buffer and the length passed is 64; devname_r
    // writes a NUL-terminated name of at most that length, or returns NULL.
    let p = unsafe {
        devname_r(
            e_tdev as libc::dev_t,
            libc::S_IFCHR,
            buf.as_mut_ptr(),
            buf.len() as libc::c_int,
        )
    };
    if p.is_null() {
        return None;
    }
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    normalize_tty(&String::from_utf8_lossy(&bytes))
}

/// Normalizes a device name to the basename (`ttys003`) so it joins iTerm's `tty of
/// session` (`/dev/ttys003`); `""`, `??` and devname's `#C…` "no such device" form are
/// no tty.
pub(crate) fn normalize_tty(raw: &str) -> Option<String> {
    let t = raw
        .trim()
        .trim_start_matches("/dev/")
        .trim_start_matches('/');
    (!t.is_empty() && t != "??" && !t.starts_with('#')).then(|| t.to_string())
}

/// Combines iTerm's window name and session name into a single
/// display string. Examples:
///
/// - `("✳ terrene", "✳ arbor (claude)")` → `"terrene · arbor"`
/// - `("✳ Claude Code", "✳ Claude Code (claude)")` → `"Claude Code"`
///   (collapsed — when window and session are the same, show once)
/// - `("", "✳ arbor (claude)")` → `"arbor"`
/// - `("✳ terrene", "")` → `"terrene"`
///
/// iTerm prefixes titles with status icons like `✳` (active) or
/// `⠂` (idle) and appends the current command in parens like
/// `(claude)`. Both are stripped so the display stays clean.
pub(crate) fn format_terminal_title(window_name: &str, session_name: &str) -> String {
    let w = strip_iterm_decorations(window_name);
    let s = strip_iterm_decorations(session_name);
    match (w.is_empty(), s.is_empty()) {
        (true, true) => String::new(),
        (false, true) => w,
        (true, false) => s,
        (false, false) if w == s => w,
        (false, false) => format!("{w} · {s}"),
    }
}

/// Strips iTerm2's status-icon prefix (`✳ `, `⠂ `, similar) and the
/// trailing `(command)` annotation from a title string. Returns
/// the whitespace-trimmed core.
fn strip_iterm_decorations(raw: &str) -> String {
    // Leading status icon: a non-ASCII char followed by a space.
    // iTerm uses `✳` (U+2733) for active and `⠂` (U+2802 braille)
    // for idle. We match by "not ASCII letter/digit" as the first
    // char, then one space.
    let mut s = raw.trim();
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        if !first.is_ascii_alphanumeric() {
            // Check that the next char is a space.
            if chars.next() == Some(' ') {
                s = &s[first.len_utf8() + 1..];
            }
        }
    }
    // Trailing `(foo)` annotation — drop it entirely.
    if let Some(paren_idx) = s.rfind(" (") {
        if s.ends_with(')') {
            s = &s[..paren_idx];
        }
    }
    s.trim().to_string()
}

/// How long a cached osascript result stays fresh.
///
/// `list_sessions` polls every 5s from the desktop app, so a 10s
/// TTL means osascript runs at most every other poll — one
/// subprocess call per ~10s instead of every 5s. Tab titles and
/// window names update within that window on the next poll; that's
/// fast enough for a UX where the user changes tabs and glances
/// at the dashboard.
///
/// Design question 2 from an internal journal entry: decided to cache instead
/// of calling per-poll because `osascript` is ~120ms and doing it
/// at every list tick burns CPU for stale data.
const ITERM_CACHE_TTL: Duration = Duration::from_secs(10);

/// A resolved `{tty → (window_name, session_name)}` tuple from
/// the last osascript walk. The outer Option is None on first
/// call, Some afterwards.
type IntermediateCache = (HashMap<String, (String, String)>, Instant);
static ITERM_CACHE: OnceLock<Mutex<Option<IntermediateCache>>> = OnceLock::new();

fn iterm_cache() -> &'static Mutex<Option<IntermediateCache>> {
    ITERM_CACHE.get_or_init(|| Mutex::new(None))
}

/// Queries iTerm2 via AppleScript for `{TTY → (window_name,
/// tab_title)}` tuples.
///
/// Returns the window title (stable per iTerm window) **and** the
/// user-set tab title (falling back to the session name when unavailable).
/// The caller combines them as `"window · session"` for
/// display so users see e.g. `"terrene · arbor"`.
///
/// This is a best-effort lookup. If iTerm2 isn't running, the
/// user denied automation permission, or AppleScript fails, we
/// return an empty map and the sessions view falls through to the
/// env-based tags (`Window N • Tab M`, TTY, etc.).
///
/// ### iTerm2 AppleScript gotchas
///
/// - `tabs` do NOT have a `name` property directly — querying it
///   returns `Can't get name of item 1 of every tab (-1728)`. You
///   must walk into `sessions of tab`; `tab.title` is read in that session's
///   tell context, with `name of session` only as its fallback.
/// - `windows` DO have a `name` property — that's the title you
///   set in iTerm preferences (or iTerm derives from the active
///   tab). That's what the user means by "window name".
///
/// ### Cache
///
/// Each call returns a clone of the cached result if it's under
/// [`ITERM_CACHE_TTL`] old, otherwise re-runs the osascript and
/// refreshes the cache. Concurrent callers coalesce on one `osascript`: a
/// second mutex ([`iterm_refresh`]) is held for the whole walk, and a caller that
/// waited on it re-checks the cache before walking, so it finds the result the first
/// caller stored. The cache mutex itself is never held across the subprocess.
fn read_iterm_titles_by_tty() -> HashMap<String, (String, String)> {
    titles_single_flight(iterm_cache(), iterm_refresh(), ITERM_CACHE_TTL, &|| {
        walk_iterm_titles()
    })
}

fn iterm_refresh() -> &'static Mutex<()> {
    static REFRESH: Mutex<()> = Mutex::new(());
    &REFRESH
}

/// The cache-and-coalesce core of [`read_iterm_titles_by_tty`], over an injected cache,
/// refresh lock, ttl and walker.
fn titles_single_flight(
    cache: &Mutex<Option<IntermediateCache>>,
    refresh: &Mutex<()>,
    ttl: Duration,
    walk: &dyn Fn() -> Option<HashMap<String, (String, String)>>,
) -> HashMap<String, (String, String)> {
    let fresh = || {
        let guard = cache.lock().expect("iterm cache lock poisoned");
        guard
            .as_ref()
            .filter(|(_, when)| when.elapsed() < ttl)
            .map(|(map, _)| map.clone())
    };
    if let Some(map) = fresh() {
        return map;
    }
    // One walker at a time; a waiter re-checks, because the walker ahead of it has
    // normally just filled the cache.
    let _flight = refresh.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(map) = fresh() {
        return map;
    }
    // A failed walk is cached as empty so a missing or slow iTerm is not re-asked every poll.
    let map = walk().unwrap_or_default();
    let mut guard = cache.lock().expect("iterm cache lock poisoned");
    *guard = Some((map.clone(), Instant::now()));
    map
}

/// One `osascript` walk of iTerm: `None` when the script did not run to completion.
fn walk_iterm_titles() -> Option<HashMap<String, (String, String)>> {
    walk_iterm_titles_with(&run_bounded)
}

type BoundedTitleRunner<'a> = dyn Fn(&str, &[&str], Duration) -> Option<Vec<u8>> + 'a;

/// The same script and TTY parser over an injected bounded runner; fixtures never query
/// or alter the operator's iTerm sessions.
fn walk_iterm_titles_with(
    run: &BoundedTitleRunner<'_>,
) -> Option<HashMap<String, (String, String)>> {
    // Cache miss — query iTerm2. Note: NO `pgrep` short-circuit
    // because iTerm2 doesn't run as a process literally named
    // `iTerm2` (the actual binary name varies by install path),
    // so `pgrep -x iTerm2` finds nothing even when iTerm is
    // running. We rely on osascript failing fast (~70ms) when
    // iTerm isn't running.
    //
    // Tabs don't have a `name` property in iTerm's AppleScript
    // dictionary — querying it errors with `-1728`. We read
    // The user-set tab title is `tab.title`, read in the session's tell context;
    // `variable named "tab.title" of s` fails with -1723. `name of session` can
    // instead reflect the running command, so keep it only as a missing-title fallback.
    const SCRIPT: &str = r#"
        set out to ""
        try
            tell application "iTerm2"
                repeat with w in windows
                    set winName to name of w
                    repeat with t in tabs of w
                        repeat with s in sessions of t
                            set tt to ""
                            try
                                tell s to set tt to (variable named "tab.title")
                            end try
                            if tt is missing value then set tt to ""
                            if tt is "" then set tt to name of s
                            set out to out & (tty of s) & "|" & winName & "|" & tt & linefeed
                        end repeat
                    end repeat
                end repeat
            end tell
        on error
            return ""
        end try
        return out
    "#;

    let bytes = run("osascript", &["-e", SCRIPT], OSASCRIPT_TIMEOUT)?;
    let stdout = String::from_utf8_lossy(&bytes).into_owned();

    let mut map = HashMap::new();
    for line in stdout.lines() {
        // Each line is `<tty>|<window_name>|<session_name>`.
        // iTerm returns `/dev/ttys003` for the TTY; strip the
        // `/dev/` prefix to match `ps -o tty=` output.
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() != 3 {
            continue;
        }
        let tty = parts[0].trim().trim_start_matches("/dev/").to_string();
        let window_name = parts[1].trim().to_string();
        let session_name = parts[2].trim().to_string();
        if !tty.is_empty() {
            map.insert(tty, (window_name, session_name));
        }
    }

    Some(map)
}

/// Hard ceiling on one `osascript` walk. On a loaded host the script can take minutes;
/// titles are a decoration, so a slow one is abandoned (and cached as empty for
/// [`ITERM_CACHE_TTL`]) rather than allowed to dominate the listing.
const OSASCRIPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs `program args` and returns its stdout when it exits 0 within `timeout`. On a
/// timeout the owned process group is killed and the child reaped. Output readers
/// share the deadline, so a descendant holding stdout cannot strand the listing.
/// The title table retains its 1 MiB output ceiling; failed probes return `None`.
fn run_bounded(program: &str, args: &[&str], timeout: Duration) -> Option<Vec<u8>> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    match crate::cli_deps::cli_shim::probe_command_with_limits(cmd, timeout, 1 << 20) {
        crate::cli_deps::cli_shim::ProbeOutcome::Ok(stdout) => Some(stdout),
        _ => None,
    }
}

/// Reads the kernel-absolute start time (unix seconds) of a process via
/// `proc_pidinfo(PROC_PIDTBSDINFO)` → `pbi_start_tvsec`. Returns `None` on
/// any failure (no such process, not permitted, short read).
///
/// The value is the process's recorded start timestamp, so two reads of the
/// same live process are always equal and a wall-clock step cannot move it
/// (INV-31-01: `started_at` is an exact-equality identity key). An earlier
/// version derived it as `now − ps etime`, which is neither stable across
/// calls (the two operands truncate independently, giving a one-second
/// wobble) nor step-proof. No process is spawned.
///
/// `pub(crate)` (`keychain-fix-r11.md` S-LOW-1/D-4b): also the
/// identity-aware liveness confirmation
/// `credentials::keychain::live_handle_dir_maps_to_service` uses — a PID
/// can pass bare `kill(pid, 0)` yet belong to a process this call cannot
/// otherwise positively confirm; requiring the kernel to independently
/// resolve a start time is a second, differently-sourced signal before
/// treating a PID as a genuine live collision.
pub(crate) fn read_start_time(pid: u32) -> Option<u64> {
    let info = read_bsd_info(pid)?;
    // A kernel process always has a non-zero start time; zero means the
    // struct was not populated, so treat it as unread.
    (info.pbi_start_tvsec != 0).then_some(info.pbi_start_tvsec)
}

/// The start time of `pid`, three-outcome: [`Probe::Gone`] only on `ESRCH`;
/// [`Probe::Failed`] for any other failure AND for a populated-but-zero start (the kernel
/// did not fill it in), neither of which says the process is dead; [`Probe::Got`] a
/// non-zero start. [`read_start_time`] folds the last two into `None`, which is wrong for
/// a caller that must not read "could not read" as "dead".
pub(crate) fn probe_start_time(pid: u32) -> Probe<u64> {
    match probe_bsd_raw(pid) {
        Probe::Got(i) if i.pbi_start_tvsec != 0 => Probe::Got(i.pbi_start_tvsec),
        Probe::Got(_) | Probe::Failed => Probe::Failed,
        Probe::Gone => Probe::Gone,
    }
}

/// The parent pid of `pid` (`pbi_ppid`), or `None` when the process cannot be read.
///
/// A process the full read refuses (setuid-root `/usr/bin/login` as a non-root caller) still
/// answers the short-info read, whose `pbsi_ppid` is taken when the full read fails for any
/// reason but `ESRCH` and the answer is about this pid.
pub(crate) fn parent_pid(pid: u32) -> Option<u32> {
    parent_pid_via(pid, probe_bsd_raw, probe_bsd_short)
}

fn parent_pid_via(
    pid: u32,
    full: impl Fn(u32) -> Probe<libc::proc_bsdinfo>,
    short: impl Fn(u32) -> Probe<ProcBsdShortInfo>,
) -> Option<u32> {
    match full(pid) {
        Probe::Got(i) => Some(i.pbi_ppid),
        Probe::Gone => None,
        Probe::Failed => match short(pid) {
            Probe::Got(s) if s.pbsi_pid == pid => Some(s.pbsi_ppid),
            _ => None,
        },
    }
}

fn ancestor_start_via(
    pid: u32,
    full: impl Fn(u32) -> Option<u64>,
    sysctl: impl Fn(u32) -> Option<u64>,
) -> Option<u64> {
    full(pid).or_else(|| sysctl(pid))
}

/// Full-precision start of an ancestry-walk hop in microseconds since the epoch
/// (`pbi_start_tvsec * 1_000_000 + pbi_start_tvusec`), with the `sysctl` `p_starttime`
/// timeval (sec + usec) as the fallback. Both are the same kernel clock.
pub(crate) fn ancestor_start_micros(pid: u32) -> Option<u64> {
    ancestor_start_via(pid, read_start_micros, sysctl_start_micros)
}

fn micros(sec: u64, usec: u64) -> Option<u64> {
    (sec != 0).then(|| sec.saturating_mul(1_000_000).saturating_add(usec))
}

fn read_start_micros(pid: u32) -> Option<u64> {
    let i = read_bsd_info(pid)?;
    micros(i.pbi_start_tvsec, i.pbi_start_tvusec)
}

fn sysctl_start_micros(pid: u32) -> Option<u64> {
    let tv = sysctl_start_timeval(pid)?;
    micros(
        u64::try_from(tv.tv_sec).ok()?,
        u64::try_from(tv.tv_usec).ok()?,
    )
}

/// `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid)` → `kinfo_proc.kp_proc.p_un.__p_starttime`
/// (a `struct timeval`, the first member of `kinfo_proc`, so `tv_sec` is the first 8 bytes).
/// Measured: succeeds for root-owned pids as a non-root user. A short result is `None`; a
/// zero timeval is returned as-is and refused by [`micros`] in `sysctl_start_micros`.
fn sysctl_start_timeval(pid: u32) -> Option<libc::timeval> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // kinfo_proc is 648 bytes on this ABI; the buffer is larger so a bigger struct still fits.
    let mut buf = [0u8; 2048];
    let mut len: libc::size_t = buf.len();
    // SAFETY: `mib` is 4 valid ints; `buf` is a live exclusively borrowed buffer of `len`
    // bytes that sysctl writes at most `len` bytes into and updates `len` with the count.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len < std::mem::size_of::<libc::timeval>() {
        return None;
    }
    // SAFETY: at least size_of::<timeval>() bytes were written; read_unaligned has no
    // alignment requirement and timeval is plain-old-data.
    let tv: libc::timeval =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::timeval) };
    Some(tv)
}

/// `proc_pidinfo(PROC_PIDTBSDINFO)` for `pid`; `None` on any failure or short read.
fn read_bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
    match probe_bsd_raw(pid) {
        Probe::Got(i) => Some(i),
        _ => None,
    }
}

/// `struct proc_bsdshortinfo` from `<sys/proc_info.h>` (`PROC_PIDT_SHORTBSDINFO`, flavor
/// 13), defined here because the pinned `libc` does not export it on every version.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdShortInfo {
    pbsi_pid: u32,
    pbsi_ppid: u32,
    pbsi_pgid: u32,
    pbsi_status: u32,
    pbsi_comm: [libc::c_char; 16],
    pbsi_flags: u32,
    pbsi_uid: u32,
    pbsi_gid: u32,
    pbsi_ruid: u32,
    pbsi_rgid: u32,
    pbsi_svuid: u32,
    pbsi_svgid: u32,
    pbsi_rfu: u32,
}

/// `PROC_PIDT_SHORTBSDINFO`.
const PROC_PIDT_SHORTBSDINFO: libc::c_int = 13;

/// `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)`: unlike `PROC_PIDTBSDINFO` it succeeds for
/// processes owned by another user (measured: pid 1 as a non-root user). `ESRCH` is
/// [`Probe::Gone`]; a short read or any other errno is [`Probe::Failed`].
fn probe_bsd_short(pid: u32) -> Probe<ProcBsdShortInfo> {
    let Ok(pid) = libc::c_int::try_from(pid) else {
        return Probe::Gone;
    };
    // SAFETY: ProcBsdShortInfo is plain-old-data; all-zero is a valid bit pattern.
    let mut info: ProcBsdShortInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcBsdShortInfo>() as libc::c_int;
    // SAFETY: `info` is a live, exclusively borrowed buffer of exactly `size` bytes;
    // proc_pidinfo writes at most `size` bytes and returns the count, or <= 0 on failure.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDT_SHORTBSDINFO,
            0,
            &mut info as *mut ProcBsdShortInfo as *mut libc::c_void,
            size,
        )
    };
    if written == size {
        Probe::Got(info)
    } else if written <= 0 && last_errno() == Some(libc::ESRCH) {
        Probe::Gone
    } else {
        Probe::Failed
    }
}

/// What a short-info read can still positively say when the full read failed: only that
/// the process belongs to ANOTHER user (or is gone). A same-uid short read says nothing the
/// full read did not, so it stays [`Probe::Failed`].
fn short_probe_as_facts(short: Probe<ProcBsdShortInfo>, pid: u32, euid: u32) -> Probe<BsdFacts> {
    match short {
        Probe::Gone => Probe::Gone,
        Probe::Got(s) if s.pbsi_pid == pid && s.pbsi_uid != euid => Probe::Got(BsdFacts {
            pid,
            uid: s.pbsi_uid,
            start: 0,
            tdev: NODEV,
            claude_named: false,
            codex_named: false,
            zombie: s.pbsi_status == SZOMB,
            pgid: s.pbsi_pgid,
        }),
        Probe::Got(_) | Probe::Failed => Probe::Failed,
    }
}

/// [`probe_bsd_raw`] reduced to the facts classification uses. When the full read fails for
/// any reason but `ESRCH` (root-owned processes, as a non-root user), the short-info read
/// is consulted to learn whether the process is foreign.
fn probe_bsd_info(pid: u32) -> Probe<BsdFacts> {
    probe_bsd_info_with(pid, probe_bsd_raw, probe_bsd_short)
}

fn probe_bsd_info_with(
    pid: u32,
    full: impl Fn(u32) -> Probe<libc::proc_bsdinfo>,
    short: impl Fn(u32) -> Probe<ProcBsdShortInfo>,
) -> Probe<BsdFacts> {
    match full(pid) {
        Probe::Failed => {
            // SAFETY: geteuid has no preconditions and cannot fail.
            let euid = unsafe { libc::geteuid() };
            short_probe_as_facts(short(pid), pid, euid)
        }
        Probe::Got(i) => Probe::Got(BsdFacts {
            pid: i.pbi_pid,
            uid: i.pbi_uid,
            start: i.pbi_start_tvsec,
            tdev: i.e_tdev,
            claude_named: c_field_is_claude(&i.pbi_comm) || c_field_is_claude(&i.pbi_name),
            codex_named: c_field_is(&i.pbi_comm, b"codex") || c_field_is(&i.pbi_name, b"codex"),
            zombie: i.pbi_status == SZOMB,
            pgid: i.pbi_pgid,
        }),
        Probe::Gone => Probe::Gone,
    }
}

/// `proc_pidinfo(PROC_PIDTBSDINFO)` for `pid`. `ESRCH` is [`Probe::Gone`]; a short read or
/// any other errno is [`Probe::Failed`].
fn probe_bsd_raw(pid: u32) -> Probe<libc::proc_bsdinfo> {
    let Ok(pid) = libc::c_int::try_from(pid) else {
        return Probe::Gone; // outside c_int: no such pid can exist
    };
    // SAFETY: proc_bsdinfo is plain-old-data (integers and char arrays), for
    // which the all-zero bit pattern is valid.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is a live, exclusively borrowed buffer of exactly `size`
    // bytes; proc_pidinfo writes at most `size` bytes into it and returns the
    // byte count written, or <= 0 on failure.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
            size,
        )
    };
    if written == size {
        Probe::Got(info)
    } else if written <= 0 && last_errno() == Some(libc::ESRCH) {
        Probe::Gone
    } else {
        Probe::Failed
    }
}

/// A process's kernel-assigned unique id and the unique id of the process that created it
/// (`proc_uniqidentifierinfo`). The unique id is never reused for another process while the
/// machine is up, and `p_puniqueid` is fixed when the process is forked: unlike `pbi_ppid`
/// it survives the creator's death and the reparenting that follows. The orphan sweep walks
/// this CREATION lineage, because the current parent of a process whose creator died is
/// launchd, which is also the parent of every launchd-spawned service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Uniq {
    pub uniqueid: u64,
    pub puniqueid: u64,
}

/// `struct proc_uniqidentifierinfo` from `<sys/proc_info.h>` (56 bytes), defined here
/// because the pinned `libc` does not export it.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcUniqIdentifierInfo {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    /// `p_idversion` and `p_reserve2` (two `i32`), then two reserved `u64`.
    p_reserved: [u64; 3],
}

/// `PROC_PIDUNIQIDENTIFIERINFO`.
const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

/// `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)`. Unlike the full BSD-info flavor it answers
/// for processes owned by another user (measured: pid 1 and root's `login` as a non-root
/// user), which the lineage walk needs to step through them. `ESRCH` is [`Probe::Gone`]; a
/// short read, any other errno, or an unpopulated (zero) unique id is [`Probe::Failed`].
pub(crate) fn probe_uniq(pid: u32) -> Probe<Uniq> {
    let Ok(pid) = libc::c_int::try_from(pid) else {
        return Probe::Gone; // outside c_int: no such pid can exist
    };
    // SAFETY: ProcUniqIdentifierInfo is plain-old-data; all-zero is a valid bit pattern.
    let mut info: ProcUniqIdentifierInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcUniqIdentifierInfo>() as libc::c_int;
    // SAFETY: `info` is a live, exclusively borrowed buffer of exactly `size` bytes;
    // proc_pidinfo writes at most `size` bytes and returns the count, or <= 0 on failure.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            &mut info as *mut ProcUniqIdentifierInfo as *mut libc::c_void,
            size,
        )
    };
    if written == size && info.p_uniqueid != 0 {
        Probe::Got(Uniq {
            uniqueid: info.p_uniqueid,
            puniqueid: info.p_puniqueid,
        })
    } else if written <= 0 && last_errno() == Some(libc::ESRCH) {
        Probe::Gone
    } else {
        Probe::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── restricted caller, and the parent walk past an unreadable ancestor ──

    fn bsd_with(pid: u32, ppid: u32, uid: u32) -> libc::proc_bsdinfo {
        // SAFETY: proc_bsdinfo is plain-old-data; all-zero is a valid bit pattern.
        let mut i: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        i.pbi_pid = pid;
        i.pbi_ppid = ppid;
        i.pbi_uid = uid;
        i
    }

    fn short_with(pid: u32, ppid: u32, uid: u32) -> ProcBsdShortInfo {
        // SAFETY: ProcBsdShortInfo is plain-old-data; all-zero is a valid bit pattern.
        let mut i: ProcBsdShortInfo = unsafe { std::mem::zeroed() };
        i.pbsi_pid = pid;
        i.pbsi_ppid = ppid;
        i.pbsi_uid = uid;
        i
    }

    fn foreign_facts() -> Probe<BsdFacts> {
        Probe::Got(BsdFacts {
            pid: 1,
            uid: 0,
            start: 0,
            tdev: NODEV,
            claude_named: false,
            codex_named: false,
            zombie: false,
            pgid: 0,
        })
    }

    /// Restricted when pid 1 cannot be read at all, or every listed pid is unreadable;
    /// control: a readable pid 1 and some readable pids is not.
    #[test]
    fn a_caller_that_reads_nothing_is_restricted() {
        assert!(!caller_restricted(1489, 0, &foreign_facts()), "control");
        assert!(caller_restricted(1489, 0, &Probe::Failed), "pid 1 refused");
        assert!(
            caller_restricted(40, 40, &foreign_facts()),
            "every pid unreadable"
        );
        assert!(!caller_restricted(40, 39, &foreign_facts()), "one readable");
        assert!(
            !caller_restricted(0, 0, &foreign_facts()),
            "empty table is not proof"
        );
        assert!(!caller_restricted(5, 0, &Probe::Gone));
    }

    /// The full read refusing (setuid-root login) falls back to the short read's ppid, for
    /// the same pid only; ESRCH stays None.
    #[test]
    fn parent_pid_uses_the_short_read_when_the_full_read_is_refused() {
        let refused = |_: u32| Probe::Failed;
        let short = |p: u32| Probe::Got(short_with(p, 321, 0));
        assert_eq!(parent_pid_via(77, refused, short), Some(321));
        let full = |p: u32| Probe::Got(bsd_with(p, 55, 501));
        assert_eq!(parent_pid_via(77, full, short), Some(55), "full read wins");
        let other = |_: u32| Probe::Got(short_with(999, 321, 0));
        assert_eq!(
            parent_pid_via(77, refused, other),
            None,
            "answer about another pid"
        );
        assert_eq!(parent_pid_via(77, |_| Probe::Gone, short), None, "ESRCH");
        assert_eq!(parent_pid_via(77, refused, |_| Probe::Failed), None);
    }

    #[test]
    fn ancestor_start_micros_agrees_with_the_second_reader_and_both_sources() {
        let me = std::process::id();
        let us = ancestor_start_micros(me).expect("own micros readable");
        assert_eq!(
            us / 1_000_000,
            read_start_time(me).unwrap(),
            "same clock, seconds"
        );
        assert_eq!(
            read_start_micros(me),
            sysctl_start_micros(me),
            "full read == sysctl"
        );
        assert_eq!(ancestor_start_micros(me), Some(us), "stable across reads");
        assert!(sysctl_start_micros(1).is_some());
        assert_eq!(ancestor_start_micros(4_000_000), None);
    }

    #[test]
    fn ancestor_start_falls_back_to_sysctl_only_when_the_full_read_fails() {
        assert_eq!(ancestor_start_via(7, |_| Some(10), |_| Some(99)), Some(10));
        assert_eq!(ancestor_start_via(7, |_| None, |_| Some(99)), Some(99));
        assert_eq!(ancestor_start_via(7, |_| None, |_| None), None);
    }

    /// The sysctl reader agrees with the full read on a readable process (so the two sources
    /// are the same clock), and an absent pid is `None`.
    #[test]
    fn sysctl_start_time_matches_the_full_read() {
        let me = std::process::id();
        assert_eq!(
            sysctl_start_micros(me).map(|u| u / 1_000_000),
            read_start_time(me)
        );
        assert!(sysctl_start_micros(me).is_some());
        assert_eq!(sysctl_start_micros(4_000_000), None);
        // the case the fallback exists for: launchd (pid 1) is always root-owned, so a
        // non-root caller's full read of it is refused while sysctl still answers
        assert!(
            sysctl_start_micros(1).is_some(),
            "sysctl must read a root-owned start"
        );
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(read_start_time(1), None, "why the fallback is needed");
        }
    }

    /// The live ancestry walk from this test process reaches a verdict (it ends at launchd,
    /// start-checking every ancestor (setuid-root ones via sysctl)); `Some(false)` for a pid that is not an
    /// ancestor. `None` here would be the F6 defect: an unreadable ancestor read as undetermined.
    #[test]
    fn live_ancestry_walk_reaches_a_verdict() {
        let r = super::super::is_ancestor_of_current(4_000_000);
        assert_eq!(r, Some(false), "a pid that cannot be an ancestor");
        assert_eq!(
            super::super::is_ancestor_of_current(parent_pid(std::process::id()).unwrap()),
            Some(true)
        );
    }

    // ── read_start_time (INV-31-01: absolute, stable start time) ──

    /// Parses `ps -o lstart=` (local time, second resolution) to unix seconds
    /// through absolute-path `/bin/date`, an independent source from the
    /// kernel call under test.
    fn lstart_unix(pid: u32) -> u64 {
        let ps = Command::new("/bin/ps")
            .env("LC_ALL", "C")
            .args(["-p", &pid.to_string(), "-o", "lstart="])
            .output()
            .unwrap();
        let ls = String::from_utf8(ps.stdout).unwrap().trim().to_string();
        let d = Command::new("/bin/date")
            .env("LC_ALL", "C")
            .args(["-j", "-f", "%a %b %e %H:%M:%S %Y", &ls, "+%s"])
            .output()
            .unwrap();
        String::from_utf8(d.stdout).unwrap().trim().parse().unwrap()
    }

    /// Every read equals the independently parsed absolute `lstart`. The old
    /// `now − etime` derivation straddled a second boundary between its two
    /// clock samples and could be off by one (probabilistic; the
    /// deterministic RED is `read_start_time_spawns_no_process`).
    #[test]
    fn read_start_time_is_absolute_and_stable() {
        let pid = std::process::id();
        let expected = lstart_unix(pid);
        for i in 0..300 {
            assert_eq!(
                read_start_time(pid),
                Some(expected),
                "read {i} differs from the absolute start time"
            );
        }
    }

    /// Deterministic RED under the old derivation: it spawned `ps` through
    /// PATH, so an empty PATH made it return `None`. The kernel call spawns
    /// nothing and still answers (INV-31-01, "no more processes than today").
    #[test]
    fn read_start_time_spawns_no_process() {
        struct RestorePath(Option<std::ffi::OsString>);
        impl Drop for RestorePath {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("PATH", v),
                    None => std::env::remove_var("PATH"),
                }
            }
        }
        let pid = std::process::id();
        let expected = lstart_unix(pid); // absolute-path spawns, before PATH is emptied
        let _g = crate::platform::test_env::lock();
        let empty = tempfile::tempdir().unwrap();
        let _restore = RestorePath(std::env::var_os("PATH"));
        std::env::set_var("PATH", empty.path());
        assert_eq!(read_start_time(pid), Some(expected));
    }

    #[test]
    fn read_start_time_of_absent_pid_is_none() {
        // pid_max on macOS is 99_999; this pid cannot exist.
        assert_eq!(read_start_time(4_000_000), None);
        // Out of c_int range must not wrap into a different process.
        assert_eq!(read_start_time(u32::MAX), None);
    }

    // ── native enumeration (parsers on fixture bytes) ───────────

    /// A `KERN_PROCARGS2` buffer: argc, exec path, NUL padding, argv, env.
    fn procargs_fixture(argc: u32, exec: &str, argv: &[&str], env: &[&str]) -> Vec<u8> {
        let mut b = argc.to_ne_bytes().to_vec();
        b.extend_from_slice(exec.as_bytes());
        b.extend_from_slice(&[0, 0, 0]); // terminator + alignment padding
        for a in argv {
            b.extend_from_slice(a.as_bytes());
            b.push(0);
        }
        for e in env {
            b.extend_from_slice(e.as_bytes());
            b.push(0);
        }
        b.extend_from_slice(&[0, 0]); // trailing pad the kernel leaves
        b
    }

    #[test]
    fn parse_procargs_splits_exec_argv_and_env_exactly() {
        let buf = procargs_fixture(
            2,
            "/opt/homebrew/bin/claude",
            &["claude", "--resume"],
            &[
                "PATH=/a /b",
                "CLAUDE_CONFIG_DIR=/x/accounts/term-9",
                "TERM_SESSION_ID=w3t2p0:ABC",
            ],
        );
        let p = parse_procargs(&buf).unwrap();
        assert_eq!(p.argv, vec![&b"claude"[..], &b"--resume"[..]]);
        // A value containing a space is not split (the old `ps -E` heuristic could).
        assert_eq!(p.env_get("PATH"), Some(&b"/a /b"[..]));
        assert_eq!(
            p.env_get("CLAUDE_CONFIG_DIR"),
            Some(&b"/x/accounts/term-9"[..])
        );
        assert_eq!(p.env_get("TERM_SESSION_ID"), Some(&b"w3t2p0:ABC"[..]));
        assert_eq!(p.env_get("ITERM_PROFILE"), None);
    }

    #[test]
    fn parse_procargs_env_key_is_exact_not_a_suffix_or_prefix() {
        let buf = procargs_fixture(1, "/c", &["claude"], &["FAKE_PATH=x", "PATH=/a", "PATHX=y"]);
        let p = parse_procargs(&buf).unwrap();
        assert_eq!(p.env_get("PATH"), Some(&b"/a"[..]));
        assert_eq!(p.env_get("FAKE"), None);
    }

    #[test]
    fn env_get_all_returns_every_entry_of_a_duplicated_key_in_order() {
        let buf = procargs_fixture(1, "/c", &["node"], &["K=a", "PATH=/p", "K=", "KK=z", "K=b"]);
        let p = parse_procargs(&buf).unwrap();
        assert_eq!(p.env_get_all("K"), vec![&b"a"[..], &b""[..], &b"b"[..]]);
        assert_eq!(p.env_get("K"), Some(&b"a"[..]));
        assert!(p.env_get_all("MISSING").is_empty());
    }

    #[test]
    fn parse_procargs_rejects_malformed_buffers() {
        assert!(parse_procargs(&[]).is_none());
        assert!(parse_procargs(&[1, 0, 0]).is_none()); // short argc
                                                       // argc claims 9 argv but only one is present (the fixture's 2 trailing pad NULs
                                                       // cannot make up the difference)
        assert!(parse_procargs(&procargs_fixture(9, "/c", &["claude"], &[])).is_none());
        // unterminated exec path
        let mut b = 1u32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/no/terminator");
        assert!(parse_procargs(&b).is_none());
        // unterminated last argv
        let mut b = 1u32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/c\0\0claude");
        assert!(parse_procargs(&b).is_none());
        // implausible argc
        let mut b = u32::MAX.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/c\0\0claude\0");
        assert!(parse_procargs(&b).is_none());
    }

    #[test]
    fn parse_procargs_env_ends_at_first_empty_entry() {
        // Whatever follows the empty entry is not environment.
        let buf = procargs_fixture(
            1,
            "/c",
            &["claude"],
            &["A=1", "", "CLAUDE_CONFIG_DIR=/leak"],
        );
        let p = parse_procargs(&buf).unwrap();
        assert_eq!(p.env_get("A"), Some(&b"1"[..]));
        assert_eq!(p.env_get("CLAUDE_CONFIG_DIR"), None);
    }

    #[test]
    fn parse_vnode_path_reads_to_the_first_nul_and_refuses_the_rest() {
        let mut b = vec![0u8; 1024];
        b[..8].copy_from_slice(b"/Users/e");
        assert_eq!(parse_vnode_path(&b), Some(PathBuf::from("/Users/e")));
        assert_eq!(parse_vnode_path(&[0u8; 1024]), None); // empty
        assert_eq!(parse_vnode_path(&[b'a'; 1024]), None); // truncated: no terminator
        assert_eq!(parse_vnode_path(&[]), None);
    }

    #[test]
    fn normalize_tty_yields_the_basename_and_no_tty_forms() {
        assert_eq!(normalize_tty("ttys003"), Some("ttys003".into()));
        assert_eq!(normalize_tty("/dev/ttys003"), Some("ttys003".into()));
        assert_eq!(normalize_tty("??"), None);
        assert_eq!(normalize_tty(""), None);
        assert_eq!(normalize_tty("#C1,2"), None);
        assert_eq!(tty_name(u32::MAX), None);
    }

    // ── native enumeration (live) ───────────────────────────────

    #[test]
    fn this_process_is_readable_natively_env_argv_cwd() {
        let _g = crate::platform::test_env::lock();
        let pid = std::process::id();
        let mut buf = vec![0u8; procargs_capacity()];
        let Probe::Got(len) = read_procargs(pid, &mut buf) else {
            panic!("own procargs readable");
        };
        let p = parse_procargs(&buf[..len]).expect("own procargs parse");
        // The kernel keeps the environment the process was STARTED with, so assert on a
        // variable every test run starts with rather than one set after launch.
        assert!(
            p.env_get("PATH").is_some_and(|v| !v.is_empty()),
            "PATH present in the started environment"
        );
        let argv0 = std::env::args_os().next().unwrap();
        assert_eq!(p.argv[0], argv0.as_bytes());
        let want = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let got = read_cwd(pid).expect("own cwd readable");
        assert_eq!(std::fs::canonicalize(got).unwrap(), want);
        assert!(list_pids().unwrap().contains(&pid), "own pid in the table");
    }

    /// Body of the sleeper child spawned by [`spawn_fake`]: returns at once in a normal
    /// run, sleeps only when the parent test asks for it.
    #[test]
    fn fake_claude_sleeper() {
        if std::env::var_os("CSQ_FAKE_CLAUDE_SLEEP").is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    /// A child whose argv[0] is `argv0`, with `CLAUDE_CONFIG_DIR` etc. set. It re-runs
    /// THIS test binary rather than `/bin/sleep`: macOS withholds the environment of
    /// platform (SIP-protected) binaries from `KERN_PROCARGS2` (measured: `/bin/sleep`
    /// yields argv only), while a real `claude` is an ordinary signed binary like this one.
    fn spawn_fake(argv0: &str, config_dir: Option<&str>) -> std::process::Child {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.arg0(argv0)
            .args(["--exact", "sessions::macos::tests::fake_claude_sleeper"])
            .env("CSQ_FAKE_CLAUDE_SLEEP", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("CLAUDE_CONFIG_DIR");
        if let Some(d) = config_dir {
            c.env("CLAUDE_CONFIG_DIR", d)
                .env("TERM_SESSION_ID", "w3t2p0:ABC")
                .env("ITERM_PROFILE", "Work");
        }
        c.spawn().unwrap()
    }

    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_claude_child_is_listed_and_read_by_pid_with_no_process_spawned() {
        let kid = Reap(spawn_fake("claude", Some("/x/accounts/config-7")));
        let pid = kid.0.id();
        // Spawns after this point would fail: PATH is empty, so a `ps`/`lsof` shell-out
        // (the old implementation) cannot work, while the syscalls still do.
        let _g = crate::platform::test_env::lock();
        struct RestorePath(Option<std::ffi::OsString>);
        impl Drop for RestorePath {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("PATH", v),
                    None => std::env::remove_var("PATH"),
                }
            }
        }
        let _restore = RestorePath(std::env::var_os("PATH"));
        let empty = tempfile::tempdir().unwrap();
        std::env::set_var("PATH", empty.path());

        // The child inherits this test's controlling terminal. Under a runner with none (an
        // offload host, CI) it is positively not a session; that is the terminal rule, so
        // assert it rather than skip.
        let own_tty = matches!(probe_bsd_info(std::process::id()),
            Probe::Got(f) if f.tdev != NODEV);
        if !own_tty {
            assert_eq!(
                session_info_for_pid(pid),
                Ok(None),
                "no terminal, no session"
            );
            return;
        }
        let one = session_info_for_pid(pid)
            .expect("claude child readable by pid")
            .expect("claude child is a session");
        assert_eq!(one.pid, pid);
        assert_eq!(one.config_dir, PathBuf::from("/x/accounts/config-7"));
        assert_eq!(one.account_id, Some(7));
        assert_eq!(one.term_window, Some(3));
        assert_eq!(one.term_tab, Some(2));
        assert_eq!(one.iterm_profile.as_deref(), Some("Work"));
        assert_eq!(one.started_at, read_start_time(pid));
        let want = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(std::fs::canonicalize(&one.cwd).unwrap(), want);

        let all = try_list().expect("process table readable");
        let listed: Vec<_> = all.iter().filter(|s| s.pid == pid).collect();
        assert_eq!(listed.len(), 1, "the child appears exactly once");
        assert_eq!(*listed[0], one, "listing and by-pid reader agree");
    }

    #[test]
    fn non_sessions_are_excluded_by_pid_and_by_listing() {
        // Right env, wrong argv[0] (an MCP server inheriting the variable).
        let inherit = Reap(spawn_fake("node", Some("/x/config-1")));
        // Right argv[0], no CLAUDE_CONFIG_DIR.
        let bare = Reap(spawn_fake("claude", None));
        for k in [&inherit, &bare] {
            assert_eq!(session_info_for_pid(k.0.id()), Ok(None));
        }
        let all = try_list().unwrap();
        assert!(!all
            .iter()
            .any(|s| s.pid == inherit.0.id() || s.pid == bare.0.id()));
        // An absent pid and one outside c_int are not sessions and do not wrap.
        assert_eq!(session_info_for_pid(4_000_000), Ok(None));
        assert_eq!(session_info_for_pid(u32::MAX), Ok(None));
    }

    // ── three-outcome classification over injected reads (no process) ──

    const UID: u32 = 501;
    const START_SECS: u64 = 1_790_000_000;

    fn facts(uid: u32, start: u64, tdev: u32) -> BsdFacts {
        BsdFacts {
            pid: 77,
            uid,
            start,
            tdev,
            claude_named: true,
            codex_named: false,
            zombie: false,
            pgid: 0,
        }
    }

    fn claude_args() -> Vec<u8> {
        procargs_fixture(
            1,
            "/opt/homebrew/bin/claude",
            &["claude"],
            &["CLAUDE_CONFIG_DIR=/x/accounts/config-7"],
        )
    }

    /// Classify pid 77 with the given reads. `bsd` is consulted per call, in order.
    fn classify(
        bsd: Vec<Probe<BsdFacts>>,
        args: Probe<Vec<u8>>,
    ) -> Result<Option<SessionInfo>, Undetermined> {
        let calls = std::cell::Cell::new(0usize);
        let bsd_fn = |_: u32| {
            let i = calls.get();
            calls.set(i + 1);
            bsd.get(i).or(bsd.last()).cloned().expect("a bsd reply")
        };
        let mut args_fn = |_: u32| args.clone();
        read_session_via(
            77,
            UID,
            Reads {
                bsd: &bsd_fn,
                args: &mut args_fn,
                cwd: &|_| Some(PathBuf::from("/w")),
            },
        )
    }

    #[test]
    fn a_readable_same_uid_claude_with_a_terminal_is_a_session() {
        let f = facts(UID, START_SECS, 0x1000003);
        let got = classify(vec![Probe::Got(f)], Probe::Got(claude_args()));
        let info = got.unwrap().expect("a session");
        assert_eq!(info.pid, 77);
        assert_eq!(info.started_at, Some(START_SECS));
        assert_eq!(info.account_id, Some(7));
    }

    #[test]
    fn unreadable_args_of_a_same_uid_process_are_undetermined_not_absent() {
        let f = facts(UID, START_SECS, 0x1000003);
        assert_eq!(
            classify(vec![Probe::Got(f)], Probe::Failed),
            Err(Undetermined)
        );
        // present but unparseable: argc claims more argv than the buffer holds
        let torn = 3u32.to_ne_bytes().to_vec();
        assert_eq!(
            classify(vec![Probe::Got(f)], Probe::Got(torn)),
            Err(Undetermined)
        );
        // a failed process-info read (not ESRCH) is not "gone" either
        assert_eq!(
            classify(vec![Probe::Failed], Probe::Got(claude_args())),
            Err(Undetermined)
        );
    }

    #[test]
    fn positively_not_a_session_is_ok_none() {
        let f = facts(UID, START_SECS, 0x1000003);
        let args = Probe::Got(claude_args());
        assert_eq!(classify(vec![Probe::Gone], args.clone()), Ok(None), "gone");
        assert_eq!(
            classify(
                vec![Probe::Got(facts(UID + 1, START_SECS, 0x1000003))],
                args.clone()
            ),
            Ok(None),
            "other uid"
        );
        // ESRCH on the args read. DEFENSIVE branch: XNU's KERN_PROCARGS2 reports a vanished
        // pid as EINVAL, not ESRCH (see `procargs_of_an_absent_pid_is_not_got`), so on a
        // real kernel a process that exits after the first read arrives as `Failed`
        // (undetermined, the safe direction) and is then settled by the bsd re-probe.
        assert_eq!(
            classify(vec![Probe::Got(f)], Probe::Gone),
            Ok(None),
            "args ESRCH (defensive)"
        );
        let node = procargs_fixture(
            1,
            "/usr/bin/node",
            &["node"],
            &["CLAUDE_CONFIG_DIR=/x/config-1"],
        );
        assert_eq!(classify(vec![Probe::Got(f)], Probe::Got(node)), Ok(None));
        let bare = procargs_fixture(1, "/bin/claude", &["claude"], &["HOME=/h"]);
        assert_eq!(classify(vec![Probe::Got(f)], Probe::Got(bare)), Ok(None));
    }

    fn listing_entry(bsd: Vec<Probe<BsdFacts>>, args: Probe<Vec<u8>>) -> ListEntry {
        let calls = std::cell::Cell::new(0usize);
        let bsd_fn = |_: u32| {
            let i = calls.get();
            calls.set(i + 1);
            bsd.get(i).or(bsd.last()).cloned().expect("a bsd reply")
        };
        let mut args_fn = |_: u32| args.clone();
        listing_entry_via(
            77,
            UID,
            Reads {
                bsd: &bsd_fn,
                args: &mut args_fn,
                cwd: &|_| Some(PathBuf::from("/w")),
            },
        )
    }

    /// An unreadable `claude`-named process is COUNTED (so caller resolution cannot call
    /// the listing whole); an unreadable stranger, zombie, other-uid or exited process is not.
    #[test]
    fn an_unreadable_claude_is_counted_and_other_unreadables_are_not() {
        let f = facts(UID, START_SECS, 0x1000003);
        let stranger = BsdFacts {
            claude_named: false,
            ..f
        };
        let zombie = BsdFacts { zombie: true, ..f };
        let other = BsdFacts { uid: UID + 1, ..f };
        assert_eq!(
            listing_entry(vec![Probe::Got(f)], Probe::Failed),
            ListEntry::UnreadableClaude
        );
        assert_eq!(
            listing_entry(vec![Probe::Got(stranger)], Probe::Failed),
            ListEntry::NotSession,
            "unreadable non-claude"
        );
        assert_eq!(
            listing_entry(vec![Probe::Got(zombie)], Probe::Failed),
            ListEntry::NotSession,
            "zombie"
        );
        assert_eq!(
            listing_entry(vec![Probe::Got(other)], Probe::Failed),
            ListEntry::NotSession,
            "other uid"
        );
        // exited after the first read: args fail, the re-probe says ESRCH
        assert_eq!(
            listing_entry(vec![Probe::Got(f), Probe::Gone], Probe::Failed),
            ListEntry::NotSession,
            "exited"
        );
        // not even the process info is readable: the name is unknown, so it may be a claude
        assert_eq!(
            listing_entry(vec![Probe::Failed], Probe::Failed),
            ListEntry::UnreadableClaude
        );
        assert!(matches!(
            listing_entry(vec![Probe::Got(f)], Probe::Got(claude_args())),
            ListEntry::Session(_)
        ));
    }

    #[test]
    fn c_field_is_claude_is_exact_and_nul_terminated() {
        let mut a = [0 as libc::c_char; 16];
        for (i, b) in b"claude".iter().enumerate() {
            a[i] = *b as libc::c_char;
        }
        assert!(c_field_is_claude(&a));
        a[6] = b'x' as libc::c_char;
        assert!(!c_field_is_claude(&a), "claudex");
        a[6] = 0;
        a[3] = 0;
        assert!(!c_field_is_claude(&a), "cla");
    }

    /// The real kernel's answer for a pid that cannot exist: neither read yields a value.
    /// Records which probe variant `KERN_PROCARGS2` gives (EINVAL expected -> `Failed`,
    /// not `Gone`): the args-read `Gone` arm is defensive, `Failed` is the live path.
    #[test]
    fn procargs_of_an_absent_pid_is_not_got() {
        let absent = 2_000_000_000u32;
        assert_eq!(probe_bsd_info(absent), Probe::Gone);
        let mut buf = vec![0u8; 1 << 16];
        assert_eq!(read_procargs(absent, &mut buf), Probe::Failed);
    }

    /// A session requires a controlling terminal on macOS (the old `ps` listing had no `-x`).
    #[test]
    fn a_claude_without_a_controlling_terminal_is_not_a_session() {
        let detached = facts(UID, START_SECS, NODEV);
        assert_eq!(
            classify(vec![Probe::Got(detached)], Probe::Got(claude_args())),
            Ok(None)
        );
    }

    /// pid reuse between the two kernel reads: a different start time or owner on the
    /// re-read means what the argv read described is another process.
    #[test]
    fn a_pid_reused_between_the_reads_is_not_a_session() {
        let first = facts(UID, START_SECS, 0x1000003);
        let args = Probe::Got(claude_args());
        let moved = facts(UID, START_SECS + 5, 0x1000003);
        assert_eq!(
            classify(vec![Probe::Got(first), Probe::Got(moved)], args.clone()),
            Ok(None),
            "start time changed"
        );
        let other = facts(UID + 1, START_SECS, 0x1000003);
        assert_eq!(
            classify(vec![Probe::Got(first), Probe::Got(other)], args.clone()),
            Ok(None),
            "owner changed"
        );
        assert_eq!(
            classify(vec![Probe::Got(first), Probe::Gone], args.clone()),
            Ok(None),
            "exited"
        );
        assert!(classify(vec![Probe::Got(first), Probe::Got(first)], args)
            .unwrap()
            .is_some());
    }

    // ── iTerm title single-flight ──

    /// Concurrent callers on a cold cache run ONE walk, not one each.
    #[test]
    fn concurrent_title_readers_coalesce_on_one_walk() {
        let cache = Mutex::new(None);
        let refresh = Mutex::new(());
        let walks = std::sync::atomic::AtomicUsize::new(0);
        let walk = || {
            walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(150));
            let mut m = HashMap::new();
            m.insert("ttys001".to_string(), ("w".to_string(), "s".to_string()));
            Some(m)
        };
        std::thread::scope(|sc| {
            let hs: Vec<_> = (0..6)
                .map(|_| {
                    sc.spawn(|| {
                        titles_single_flight(&cache, &refresh, Duration::from_secs(60), &walk)
                    })
                })
                .collect();
            for h in hs {
                assert_eq!(h.join().unwrap().len(), 1, "every caller gets the titles");
            }
        });
        assert_eq!(walks.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_title_walk_is_cached_as_empty() {
        let cache = Mutex::new(None);
        let refresh = Mutex::new(());
        let walks = std::sync::atomic::AtomicUsize::new(0);
        let walk = || {
            walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            None
        };
        for _ in 0..3 {
            assert!(
                titles_single_flight(&cache, &refresh, Duration::from_secs(60), &walk).is_empty()
            );
        }
        assert_eq!(walks.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn run_bounded_abandons_a_slow_child_and_keeps_a_fast_one() {
        let _env_guard = crate::platform::test_env::lock();
        let t = Instant::now();
        assert!(run_bounded("/bin/sleep", &["30"], Duration::from_millis(200)).is_none());
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "bounded: {:?}",
            t.elapsed()
        );
        assert_eq!(
            run_bounded("/bin/echo", &["hi"], Duration::from_secs(5)),
            Some(b"hi\n".to_vec())
        );
        assert!(run_bounded("/usr/bin/false", &[], Duration::from_secs(5)).is_none());
        assert_eq!(
            run_bounded(
                "/usr/bin/head",
                &["-c", "32768", "/dev/zero"],
                Duration::from_secs(5)
            )
            .unwrap()
            .len(),
            32768,
            "title output keeps its larger ceiling than CLI probes"
        );
    }

    #[test]
    fn title_probe_abandons_inherited_stdout_before_descendant_releases_it() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _env_guard = crate::platform::test_env::lock();
        let dir = tempfile::TempDir::new().unwrap();
        let fifo = dir.path().join("release");
        let ready = dir.path().join("ready");
        let ready_for_assertion = ready.clone();
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a valid NUL-terminated path within this test's TempDir.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        // Keeping both ends open lets cleanup release the fixture even after the
        // production runner has killed its process group; cleanup cannot block.
        let mut release = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = run_bounded(
                "/bin/sh",
                &[
                    "-c",
                    "(printf ready > \"$2\"; read line < \"$1\") & exit 0",
                    "title-fixture",
                    fifo.to_str().unwrap(),
                    ready.to_str().unwrap(),
                ],
                OSASCRIPT_TIMEOUT,
            );
            tx.send(result).unwrap();
        });
        // A generous hang guard, not a scheduler-sensitive elapsed assertion.
        // Release the inherited pipe before joining, so the old implementation
        // fails behaviorally (Some(empty)) instead of hanging the test process.
        //
        // Env custody is done before this wait: `run_bounded` reads no process
        // env (the child's argv carries every path it needs) and it captured
        // its environment at fork/exec inside the worker, not here. Release
        // the shared lock rather than hold it across the 15s bound.
        drop(_env_guard);
        let bounded_result = rx.recv_timeout(Duration::from_secs(15));
        release.write_all(b"release\n").unwrap();
        worker.join().unwrap();
        assert_eq!(
            std::fs::read(&ready_for_assertion).unwrap(),
            b"ready",
            "the descendant must have started and inherited stdout"
        );
        assert_eq!(
            bounded_result,
            Ok(None),
            "title probe must return without waiting for inherited stdout EOF"
        );
    }

    // ── format_terminal_title + decorations ────────────────

    #[test]
    fn session_tab_title_uses_session_variable_and_keeps_tty_identity() {
        let titles = walk_iterm_titles_with(&|program, args, timeout| {
            assert_eq!(program, "osascript");
            assert_eq!(args.len(), 2);
            assert_eq!(args[0], "-e");
            assert_eq!(timeout, OSASCRIPT_TIMEOUT);
            let script = args[1];
            assert!(
                script.contains("tell s to set tt to (variable named \"tab.title\")"),
                "user tab title must be read in the matching session context"
            );
            assert!(
                script.contains("& tt & linefeed"),
                "the queried tab title must feed the emitted TTY row"
            );
            assert!(script.contains("if tt is missing value then set tt to \"\""));
            assert!(script.contains("if tt is \"\" then set tt to name of s"));
            assert!(!script.contains("(variable named \"tab.title\") of s"));
            // Private protocol output: labels must follow their TTY, not traversal
            // position or a shared window name. This is not live AppleScript execution.
            Some(
                b"/dev/ttys007|work|user tab seven\n/dev/ttys003|work|fallback session three\n"
                    .to_vec(),
            )
        })
        .unwrap();
        assert_eq!(
            titles.get("ttys007"),
            Some(&("work".to_string(), "user tab seven".to_string()))
        );
        assert_eq!(
            titles.get("ttys003"),
            Some(&("work".to_string(), "fallback session three".to_string()))
        );
        assert_eq!(titles.len(), 2);
        assert_eq!(
            format_terminal_title(&titles["ttys007"].0, &titles["ttys007"].1),
            "work · user tab seven"
        );
    }

    #[test]
    fn session_tab_title_failed_walk_keeps_best_effort_fallback_available() {
        assert!(walk_iterm_titles_with(&|_, _, _| None).is_none());
        assert!(walk_iterm_titles_with(&|_, _, _| Some(Vec::new()))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn strip_iterm_decorations_removes_status_icon() {
        assert_eq!(strip_iterm_decorations("✳ terrene"), "terrene");
        assert_eq!(strip_iterm_decorations("⠂ Claude Code"), "Claude Code");
    }

    #[test]
    fn strip_iterm_decorations_removes_trailing_command() {
        assert_eq!(strip_iterm_decorations("✳ arbor (claude)"), "arbor");
        assert_eq!(
            strip_iterm_decorations("✳ Claude Code (node)"),
            "Claude Code"
        );
    }

    #[test]
    fn strip_iterm_decorations_leaves_plain_titles_intact() {
        assert_eq!(strip_iterm_decorations("Plain title"), "Plain title");
    }

    #[test]
    fn strip_iterm_decorations_handles_empty() {
        assert_eq!(strip_iterm_decorations(""), "");
        assert_eq!(strip_iterm_decorations("   "), "");
    }

    #[test]
    fn format_terminal_title_window_and_session() {
        // User's canonical case: window "terrene", session "arbor".
        let out = format_terminal_title("✳ terrene", "✳ arbor (claude)");
        assert_eq!(out, "terrene · arbor");
    }

    #[test]
    fn format_terminal_title_collapses_when_identical() {
        // iTerm often propagates the tab title up to the window
        // title. When both are the same we show once, not twice.
        let out = format_terminal_title("✳ Claude Code", "✳ Claude Code (claude)");
        assert_eq!(out, "Claude Code");
    }

    #[test]
    fn format_terminal_title_window_only() {
        assert_eq!(format_terminal_title("✳ terrene", ""), "terrene");
    }

    #[test]
    fn format_terminal_title_session_only() {
        assert_eq!(format_terminal_title("", "✳ arbor (claude)"), "arbor");
    }

    #[test]
    fn format_terminal_title_both_empty() {
        assert_eq!(format_terminal_title("", ""), "");
    }

    // ── foreign-process fallback (PROC_PIDT_SHORTBSDINFO) ──

    #[test]
    fn short_info_struct_matches_the_sdk_header_size() {
        // <sys/proc_info.h> struct proc_bsdshortinfo: 4*u32 + char[16] + 8*u32 = 64.
        assert_eq!(std::mem::size_of::<ProcBsdShortInfo>(), 64);
    }

    fn short(pid: u32, uid: u32, status: u32) -> ProcBsdShortInfo {
        // SAFETY: plain-old-data, all-zero valid.
        let mut s: ProcBsdShortInfo = unsafe { std::mem::zeroed() };
        s.pbsi_pid = pid;
        s.pbsi_uid = uid;
        s.pbsi_status = status;
        s
    }

    fn full_failed(_: u32) -> Probe<libc::proc_bsdinfo> {
        Probe::Failed
    }

    #[test]
    fn a_failed_full_read_with_a_foreign_short_read_is_positively_foreign() {
        // SAFETY: geteuid cannot fail.
        let euid = unsafe { libc::geteuid() };
        let foreign = euid.wrapping_add(1);
        let got = probe_bsd_info_with(77, full_failed, |_| Probe::Got(short(77, foreign, 2)));
        let Probe::Got(f) = got else {
            panic!("{got:?}")
        };
        assert_eq!(f.uid, foreign);
        // And the listing / by-pid classification drop it as not ours.
        let reads = |bsd: &dyn Fn(u32) -> Probe<BsdFacts>| {
            let mut args = |_: u32| Probe::Failed;
            let cwd = |_: u32| None;
            let r = Reads {
                bsd,
                args: &mut args,
                cwd: &cwd,
            };
            listing_entry_via(77, euid, r)
        };
        assert_eq!(
            reads(&|p| probe_bsd_info_with(p, full_failed, |_| Probe::Got(short(77, foreign, 2)))),
            ListEntry::NotSession
        );
        let mut args = |_: u32| Probe::Failed;
        let r = Reads {
            bsd: &|p| probe_bsd_info_with(p, full_failed, |_| Probe::Got(short(77, foreign, 2))),
            args: &mut args,
            cwd: &|_| None,
        };
        assert_eq!(read_session_via(77, euid, r), Ok(None));
    }

    #[test]
    fn a_failed_full_read_stays_failed_for_same_uid_or_failed_short_reads() {
        // SAFETY: geteuid cannot fail.
        let euid = unsafe { libc::geteuid() };
        let same = probe_bsd_info_with(77, full_failed, |_| Probe::Got(short(77, euid, 2)));
        assert_eq!(same, Probe::Failed, "same uid: nothing new learned");
        let bad = probe_bsd_info_with(77, full_failed, |_| Probe::Failed);
        assert_eq!(bad, Probe::Failed);
        let other_pid = probe_bsd_info_with(77, full_failed, |_| {
            Probe::Got(short(78, euid.wrapping_add(1), 2))
        });
        assert_eq!(other_pid, Probe::Failed, "answer about a different pid");
        let gone = probe_bsd_info_with(77, full_failed, |_| Probe::Gone);
        assert_eq!(gone, Probe::Gone);
    }

    /// LIVE: pid 1 (launchd, root) is unreadable by `PROC_PIDTBSDINFO` for a non-root
    /// caller; through the real probe it must classify as not a session.
    #[test]
    fn live_root_pid_one_is_not_a_session_and_not_unreadable_claude() {
        // SAFETY: geteuid cannot fail.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return; // root can read pid 1 in full; the fallback is not exercised
        }
        let mut args = |_: u32| Probe::Failed;
        let r = Reads {
            bsd: &probe_bsd_info,
            args: &mut args,
            cwd: &read_cwd,
        };
        assert_eq!(listing_entry_via(1, euid, r), ListEntry::NotSession);
        let mut args = |_: u32| Probe::Failed;
        let r = Reads {
            bsd: &probe_bsd_info,
            args: &mut args,
            cwd: &read_cwd,
        };
        assert_eq!(read_session_via(1, euid, r), Ok(None));
        let l = try_list_detailed().expect("process table readable");
        assert!(!l.unreadable_pids.contains(&1), "{:?}", l.unreadable_pids);
        assert_eq!(l.unreadable_claude, l.unreadable_pids.len());
    }

    #[test]
    fn a_claude_with_an_empty_environment_is_undetermined_not_not_a_session() {
        let args = procargs_fixture(1, "/opt/homebrew/bin/claude", &["claude"], &[]);
        let f = facts(UID, START_SECS, 0x1000);
        assert_eq!(
            classify(vec![Probe::Got(f)], Probe::Got(args)),
            Err(Undetermined)
        );
        // Control: a non-claude with an empty environment is still positively not a session.
        let node = procargs_fixture(1, "/usr/bin/node", &["node"], &[]);
        assert_eq!(classify(vec![Probe::Got(f)], Probe::Got(node)), Ok(None));
    }

    fn classify_kind(
        kind: CliKind,
        f: BsdFacts,
        args: Vec<u8>,
    ) -> Result<Option<SessionInfo>, Undetermined> {
        let bsd_fn = move |_: u32| Probe::Got(f);
        let mut args_fn = move |_: u32| Probe::Got(args.clone());
        read_session_kind_via(
            kind,
            77,
            UID,
            Reads {
                bsd: &bsd_fn,
                args: &mut args_fn,
                cwd: &|_| None,
            },
        )
    }

    fn codex_args(argv0: &str, exe: &str) -> Vec<u8> {
        procargs_fixture(1, exe, &[argv0], &["CODEX_HOME=/x/accounts/term-9"])
    }

    #[test]
    fn a_native_codex_is_a_codex_session_and_the_node_wrapper_is_not() {
        let f = facts(UID, START_SECS, 0x1000003);
        let native = codex_args("codex", "/n/vendor/x/bin/codex");
        let s = classify_kind(CliKind::Codex, f, native.clone())
            .unwrap()
            .expect("session");
        assert_eq!(s.config_dir, PathBuf::from("/x/accounts/term-9"));
        assert_eq!(classify_kind(CliKind::Claude, f, native), Ok(None));
        let wrapper = codex_args("node", "/usr/bin/node");
        assert_eq!(classify_kind(CliKind::Codex, f, wrapper), Ok(None));
    }

    /// S3: a `codex -c k=v queue ...` process is not listed, even WITH a controlling terminal
    /// (so the exclusion does not rest on `setsid` having dropped it), while a bare `codex` and
    /// `codex resume` stay listed. Falsifier: without the subcommand check the queue process
    /// with a terminal is a Codex session owning the target's home.
    #[test]
    fn a_codex_queue_child_is_not_a_session_with_or_without_a_terminal() {
        let f = facts(UID, START_SECS, 0x1000003);
        let env = ["CODEX_HOME=/x/accounts/term-9"];
        let queue = procargs_fixture(
            6,
            "/n/bin/codex",
            &["codex", "-c", "sqlite_home=/h", "queue", "--thread", "t"],
            &env,
        );
        assert_eq!(classify_kind(CliKind::Codex, f, queue), Ok(None));
        let resume = procargs_fixture(3, "/n/bin/codex", &["codex", "resume", "queue"], &env);
        assert!(classify_kind(CliKind::Codex, f, resume).unwrap().is_some());
        let bare = procargs_fixture(1, "/n/bin/codex", &["codex"], &env);
        assert!(classify_kind(CliKind::Codex, f, bare).unwrap().is_some());
    }

    #[test]
    fn an_unreadable_codex_is_counted_by_its_name_only_for_codex() {
        let f = BsdFacts {
            claude_named: false,
            codex_named: true,
            ..facts(UID, START_SECS, 0x1000003)
        };
        let bsd_fn = move |_: u32| Probe::Got(f);
        let r = |kind| {
            listing_entry_kind_via(
                kind,
                77,
                UID,
                Reads {
                    bsd: &bsd_fn,
                    args: &mut |_| Probe::Failed,
                    cwd: &|_| None,
                },
            )
        };
        assert_eq!(r(CliKind::Codex), ListEntry::UnreadableClaude);
        assert_eq!(r(CliKind::Claude), ListEntry::NotSession);
    }

    // ---- between-hop image probe (F1): no terminal, no environment required ----

    const YES: HopProbe = HopProbe::Process {
        session_image: true,
        codex_wrapper: false,
    };
    const NO: HopProbe = HopProbe::Process {
        session_image: false,
        codex_wrapper: false,
    };

    fn hop_full(
        uid: u32,
        facts_in: BsdFacts,
        args: Probe<Vec<u8>>,
        exe: Probe<PathBuf>,
        resolved: bool,
    ) -> HopProbe {
        let mut a = |_: u32| args.clone();
        hop_probe_via(
            77,
            uid,
            &|_| Probe::Got(facts_in),
            &mut a,
            &|_| exe.clone(),
            &|_| resolved,
        )
    }

    fn hop(uid: u32, facts_in: BsdFacts, args: Probe<Vec<u8>>) -> HopProbe {
        hop_full(uid, facts_in, args, Probe::Failed, false)
    }

    fn plain(uid: u32) -> BsdFacts {
        let mut f = facts(uid, START_SECS, NODEV);
        f.claude_named = false;
        f.codex_named = false;
        f
    }

    #[test]
    fn a_codex_hop_with_no_terminal_and_no_codex_home_is_a_session_image() {
        let mut f = facts(UID, START_SECS, NODEV);
        f.claude_named = false;
        f.codex_named = true;
        let args = procargs_fixture(
            1,
            "/vendor/bin/codex",
            &["codex"],
            &["CLAUDE_CONFIG_DIR=/x/accounts/term-1"],
        );
        assert_eq!(hop(UID, f, Probe::Got(args)), YES);
    }

    #[test]
    fn a_claude_hop_with_no_terminal_and_no_env_is_a_session_image_and_a_shell_is_not() {
        let f = facts(UID, START_SECS, NODEV);
        let claude = procargs_fixture(1, "/bin/claude", &["claude"], &[]);
        assert_eq!(hop(UID, f, Probe::Got(claude)), YES);
        let zsh = procargs_fixture(1, "/bin/zsh", &["zsh"], &["PATH=/a"]);
        assert_eq!(hop(UID, plain(UID), Probe::Got(zsh)), NO);
    }

    /// N1, measured on this host: Claude Code's binary is
    /// `~/.local/share/claude/versions/2.1.289` (basename `2.1.289`), so a renamed argv\[0\]
    /// and a kernel name that says nothing still leave the executable PATH.
    #[test]
    fn a_renamed_claude_is_caught_by_its_executable_path() {
        let args = procargs_fixture(1, "/x/cx", &["cx"], &[]);
        let exe = Probe::Got(PathBuf::from(
            "/Users/u/.local/share/claude/versions/2.1.289",
        ));
        assert_eq!(hop_full(UID, plain(UID), Probe::Got(args), exe, false), YES);
    }

    /// N1: the native release asset names, and an alias that only the resolved-binary inode
    /// compare can see. Control: an unrelated `codex-helper` is not a session.
    #[test]
    fn native_asset_names_and_aliases_are_session_images() {
        let args = || Probe::Got(procargs_fixture(1, "/x/y", &["y"], &[]));
        let triple = Probe::Got(PathBuf::from("/v/codex-aarch64-apple-darwin"));
        assert_eq!(hop_full(UID, plain(UID), args(), triple, false), YES);
        let alias = Probe::Got(PathBuf::from("/v/cx"));
        assert_eq!(hop_full(UID, plain(UID), args(), alias.clone(), true), YES);
        assert_eq!(hop_full(UID, plain(UID), args(), alias, false), NO);
        let helper = Probe::Got(PathBuf::from("/v/codex-helper"));
        assert_eq!(hop_full(UID, plain(UID), args(), helper, false), NO);
    }

    /// INVEST-NOW: gemini (measured: `#!/usr/bin/env node` script `gemini.js`) shows `node`
    /// as image; only argv\[1\] names it. A node running some other script is not a session.
    #[test]
    fn a_node_hosted_cli_is_classified_by_its_script_only() {
        let node = Probe::Got(PathBuf::from("/opt/homebrew/Cellar/node/25.9.0_2/bin/node"));
        let gem = procargs_fixture(
            3,
            "/opt/homebrew/bin/node",
            &[
                "node",
                "--disable-sigusr1",
                "/o/@google/gemini-cli/bundle/gemini.js",
            ],
            &[],
        );
        assert_eq!(
            hop_full(UID, plain(UID), Probe::Got(gem), node.clone(), false),
            YES
        );
        let other = procargs_fixture(
            2,
            "/opt/homebrew/bin/node",
            &["node", "/r/trestle.mjs"],
            &[],
        );
        assert_eq!(
            hop_full(UID, plain(UID), Probe::Got(other), node, false),
            NO
        );
    }

    /// N5: another uid's CLI image between the caller and the owner is a session; another
    /// uid whose image cannot be read is undetermined, never "not a session".
    #[test]
    fn another_uids_cli_image_is_a_session_and_an_unreadable_one_is_undetermined() {
        let codex = procargs_fixture(1, "/v/codex", &["codex"], &[]);
        // the caller is UID; the hop's process belongs to UID + 1
        assert_eq!(hop(UID, plain(UID + 1), Probe::Got(codex)), YES);
        assert_eq!(
            hop(UID, plain(UID + 1), Probe::Failed),
            HopProbe::Unreadable
        );
        let zsh = procargs_fixture(1, "/bin/zsh", &["zsh"], &[]);
        assert_eq!(
            hop(UID, plain(UID + 1), Probe::Got(zsh)),
            HopProbe::Unreadable
        );
    }

    /// An unreadable executable path never overrides two successfully read names.
    #[test]
    fn an_unreadable_exe_does_not_override_two_read_names() {
        let sh = procargs_fixture(1, "/bin/zsh", &["zsh"], &[]);
        assert_eq!(
            hop_full(UID, plain(UID), Probe::Got(sh), Probe::Failed, false),
            NO
        );
    }

    #[test]
    fn a_hop_that_cannot_be_read_or_has_exited_is_not_a_session_image() {
        // unreadable arguments and no kernel name: undetermined, never "not a session"
        assert_eq!(hop(UID, plain(UID), Probe::Failed), HopProbe::Unreadable);
        // unreadable arguments but the kernel names it claude: a session
        let named = facts(UID, START_SECS, NODEV);
        assert_eq!(hop(UID, named, Probe::Failed), YES);
        let mut a = |_: u32| Probe::Failed;
        let gone = |_: u32| Probe::Failed;
        assert_eq!(
            hop_probe_via(77, UID, &|_| Probe::Gone, &mut a, &gone, &|_| false),
            HopProbe::Gone
        );
        assert_eq!(
            hop_probe_via(77, UID, &|_| Probe::Failed, &mut a, &gone, &|_| false),
            HopProbe::Unreadable
        );
    }

    // ── creation lineage ───────────────────────────────────────────────────

    #[test]
    fn the_unique_id_struct_matches_the_kernels_56_bytes() {
        assert_eq!(std::mem::size_of::<ProcUniqIdentifierInfo>(), 56);
    }

    /// The kernel's answer for this very process: a non-zero unique id, and a creator id
    /// that is the unique id of the process whose pid is our current parent. Pid 1 is
    /// launchd, which has no creator.
    #[test]
    fn a_process_reports_its_unique_id_and_its_creators() {
        let Probe::Got(me) = probe_uniq(std::process::id()) else {
            panic!("own unique id readable");
        };
        assert_ne!(me.uniqueid, 0);
        // SAFETY: getppid has no preconditions and cannot fail.
        let parent = unsafe { libc::getppid() };
        let Probe::Got(creator) = probe_uniq(u32::try_from(parent).unwrap()) else {
            panic!("parent unique id readable");
        };
        assert_eq!(
            me.puniqueid, creator.uniqueid,
            "p_puniqueid is the creator's p_uniqueid"
        );
        assert_ne!(me.uniqueid, creator.uniqueid);
        let Probe::Got(launchd) = probe_uniq(1) else {
            panic!("launchd's unique id is readable by an ordinary user");
        };
        assert_eq!(launchd.puniqueid, 0, "launchd has no creator");
        assert_eq!(probe_uniq(2_000_000_000), Probe::Gone);
    }

    /// The unique id is kept across `exec`: the launcher csq records is a `csq` process that
    /// may `exec` the CLI it launches (`csq swap` replaces its own image), and descent compares
    /// the id it recorded with the creator ids of the processes that follow. `sh` reports its
    /// pid, waits on its stdin, then `exec`s `sleep`; the id is read before and after. The test
    /// proves the exec happened (the image changed from `sh` to `sleep`) before it reads the
    /// second id, so a kernel that gave an exec'd process a new id would fail it, and a test
    /// whose exec never ran would too.
    #[test]
    fn a_unique_id_is_kept_across_exec() {
        use std::io::{BufRead, Write};
        use std::process::{Child, Command, Stdio};

        /// Kills and reaps the child when the test ends, however it ends.
        struct Reap(Child);
        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let mut child = Reap(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("echo ready; read _; exec /bin/sleep 600")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("sh starts"),
        );
        let pid = child.0.id();
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut line)
            .expect("sh says it is ready");
        let image = || {
            let out = Command::new("/bin/ps")
                .args(["-o", "comm=", "-p", &pid.to_string()])
                .output()
                .expect("ps runs");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert!(image().ends_with("sh"), "before: running sh");
        let Probe::Got(before) = probe_uniq(pid) else {
            panic!("the child's unique id is readable");
        };
        writeln!(child.0.stdin.as_mut().expect("piped stdin")).expect("release sh");
        // Wait (bounded) for the image to become `sleep`: the exec has happened.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !image().ends_with("sleep") {
            assert!(
                std::time::Instant::now() < deadline,
                "sh never exec'd sleep"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let Probe::Got(after) = probe_uniq(pid) else {
            panic!("the exec'd process's unique id is readable");
        };
        assert_eq!(after.uniqueid, before.uniqueid, "kept across exec");
        assert_eq!(after.puniqueid, before.puniqueid, "its creator is the same");
    }

    /// S2: what every descent verdict must survive. When a process's creator exits and it is
    /// reparented to launchd, the kernel SOMETIMES rewrites `p_puniqueid` to launchd's (1) and
    /// sometimes keeps the creator's id; which one happens is not guaranteed and varies with
    /// host load, so this test asserts neither. It asserts the PRODUCT property: a live
    /// orphan of a (dead) launcher is never read as "no descendant of it" by BOTH witnesses.
    /// Either its environment (here: names a test config dir) is found by the scan, or the
    /// lineage says `Descendant` or `Unknown`; `Not` with no environment hit would let the
    /// sweep delete a keychain item the orphan still uses.
    ///
    /// `sh` forks a background `sleep` (the grandchild) that carries the config dir, prints
    /// its pid and waits on its stdin; closing the stdin ends it. The creator is reaped, then
    /// a whole scan of the real table is asked about a launcher that was that creator.
    #[test]
    fn a_live_orphan_of_the_launcher_is_never_ruled_out_by_both_witnesses() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};

        /// Kills the grandchild by pid when the test ends, however it ends.
        struct Reap(libc::pid_t);
        impl Drop for Reap {
            fn drop(&mut self) {
                // SAFETY: kill takes two integers and touches no memory; the pid is the
                // `sleep` this test started.
                unsafe { libc::kill(self.0, libc::SIGKILL) };
            }
        }

        let orphan_dir = format!("/csq-reparent-test/accounts/term-{}", std::process::id());
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("/bin/sleep 600 & echo $!; read _")
            .env("CLAUDE_CONFIG_DIR", &orphan_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("sh starts");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut line)
            .expect("sh prints the grandchild's pid");
        let grandchild: libc::pid_t = line.trim().parse().expect("a pid");
        let _reap = Reap(grandchild);
        let grandchild = u32::try_from(grandchild).unwrap();

        let Probe::Got(creator) = probe_uniq(child.id()) else {
            panic!("the creator's unique id is readable while it lives");
        };
        let Probe::Got(before) = probe_uniq(grandchild) else {
            panic!("the grandchild's unique id is readable");
        };
        assert_eq!(before.puniqueid, creator.uniqueid, "control: creator alive");

        // End the creator and reap it: it is gone, and the grandchild lives on, reparented.
        drop(child.stdin.take());
        child.wait().expect("sh exits once its stdin closes");
        assert_eq!(probe_uniq(child.id()), Probe::Gone, "the creator is gone");

        let Probe::Got(after) = probe_uniq(grandchild) else {
            panic!("the grandchild outlives its creator");
        };
        assert_eq!(after.uniqueid, before.uniqueid, "the same process");
        // Either outcome of the kernel is legal; observe which one this run got.
        eprintln!(
            "reparent: creator id kept={}",
            after.puniqueid == creator.uniqueid
        );

        // End to end: a whole scan of the live table must keep the orphan placed by at least
        // one witness. Its environment names `orphan_dir` unless macOS withholds it, and the
        // lineage says Descendant (id kept) or Unknown (id rewritten, environment hidden).
        let scan = holders::scan_process_env(std::time::Duration::from_secs(30))
            .expect("process table readable");
        let by_env = scan
            .config_dirs
            .contains(&std::path::PathBuf::from(&orphan_dir));
        let by_lineage = scan.descent(creator.uniqueid) != holders::Descent::Not;
        // The grandchild's own lineage entry, so the old code (which read a rewritten id
        // as "forked by launchd" and said Not) cannot pass on the env witness alone: the
        // entry is the creator's id, or launchd's with the process recorded as opaque (or, when macOS shows its environment, found by it).
        let g = scan.lineage.get(&after.uniqueid).copied();
        assert!(
            g == Some(creator.uniqueid)
                || (g == Some(1) && (scan.opaque.contains(&after.uniqueid) || by_env)),
            "grandchild lineage entry {g:?}: neither its creator's id nor an opaque launchd-born one"
        );
        assert!(
            by_env || by_lineage,
            "the orphan is ruled out by both witnesses (env found: {by_env})"
        );
    }
}
