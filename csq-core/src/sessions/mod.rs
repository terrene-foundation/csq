//! Live Claude Code session discovery.
//!
//! Enumerates running `claude` processes under the current UID and
//! extracts, per process:
//!
//! 1. `CLAUDE_CONFIG_DIR` from the environment — this tells us
//!    which `~/.claude/accounts/config-N/` the session is bound to.
//! 2. The process `cwd` — which working directory the user started
//!    the session in (how they recognize "terminal #5").
//! 3. Start time — how long ago the session launched.
//!
//! From `CLAUDE_CONFIG_DIR` the caller can cross-reference the
//! dir's current active account, quota state, and credentials.
//!
//! ### Why this exists
//!
//! The tray quick-swap heuristic targets "the most recently modified
//! config-N", which works most of the time but is invisible: users
//! can't see which terminal is bound to which `config-N` until they
//! run `lsof` by hand. When a user has 8 accounts across 15 terminal
//! windows and terminal #5 hits a rate limit, they need:
//!
//! - to know *that it was terminal #5*, and
//! - to swap **only that terminal's** config dir to a fresh account
//!   without disturbing the other 14.
//!
//! This module provides the data. The desktop sessions view renders
//! it; the Tauri `swap_to_dir` command does the targeted swap.
//!
//! ### Platform strategy
//!
//! - **macOS** — native kernel calls, no per-session process spawn:
//!   `proc_listallpids` + `proc_pidinfo(PROC_PIDTBSDINFO)` find same-UID
//!   candidates, `sysctl(KERN_PROCARGS2)` gives argv and the environment,
//!   `proc_pidinfo(PROC_PIDVNODEPATHINFO)` gives the cwd. Only the optional iTerm
//!   title lookup still spawns (`osascript`, bounded, desktop path only).
//! - **Linux** — `/proc/<pid>/environ` is NUL-separated and readable
//!   by the process owner without root. `readlink /proc/<pid>/cwd`
//!   gives the cwd. `/proc/<pid>/stat` gives the start time.
//! - **Windows** — Toolhelp snapshot for `claude.exe`, then a PEB walk
//!   (`NtQueryInformationProcess` + `ReadProcessMemory`) for the environment and cwd.
//!   Compile-checked on `x86_64-pc-windows-gnu`; same-user filter by process-token SID (spec 31 §2).
//!
//! ### Privacy
//!
//! We filter to processes owned by the **current UID**: macOS compares `pbi_uid`, Linux
//! the effective uid in `/proc/<pid>/status`, each with `geteuid()`.
//!
//! ### Filtering
//!
//! A process is a "CC session" iff:
//! 1. Its command's first token (argv\[0\] basename) is `claude`.
//! 2. Its environment contains `CLAUDE_CONFIG_DIR`.
//! 3. On macOS only, it has a controlling terminal (`e_tdev`), as the old `ps` listing
//!    without `-x` did. Linux and Windows do not require one (spec 31 §2).
//!
//! The command filter drops child processes that inherit
//! `CLAUDE_CONFIG_DIR` from their parent (pyright-langserver,
//! node MCP servers, etc.) — we only want one row per top-level
//! `claude` process.

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

/// A single discovered live Claude Code session.
///
/// All fields are derived from OS process state; none are read
/// from the csq credential store or quota file. Callers that want
/// quota/account data should cross-reference `config_dir` via
/// `accounts::discovery` + `quota::state`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    /// OS process ID.
    pub pid: u32,
    /// Working directory at process creation (read once; not live).
    pub cwd: PathBuf,
    /// Value of `CLAUDE_CONFIG_DIR` in the process's environment.
    pub config_dir: PathBuf,
    /// Account number extracted from `config_dir` (`config-<N>`).
    /// `None` if the dir doesn't match the expected shape.
    pub account_id: Option<u16>,
    /// Unix seconds since epoch when the process started. `None`
    /// if the platform couldn't report it.
    pub started_at: Option<u64>,
    /// Controlling TTY device, e.g. `"ttys003"`. `None` if the
    /// process is not attached to a terminal (unlikely for a
    /// top-level `claude` invocation but defended for safety).
    pub tty: Option<String>,
    /// Parsed iTerm2 window index from `TERM_SESSION_ID`.
    /// `TERM_SESSION_ID=w3t2p0:UUID` yields `term_window=3`,
    /// `term_tab=2`, `term_pane=0`. `None` outside iTerm2.
    pub term_window: Option<u8>,
    /// Parsed iTerm2 tab index. See `term_window`.
    pub term_tab: Option<u8>,
    /// Parsed iTerm2 pane index. See `term_window`.
    pub term_pane: Option<u8>,
    /// iTerm2 profile name from `ITERM_PROFILE` env var.
    /// Useful when the user has multiple named profiles
    /// (e.g. "Work", "Personal", "Terrene").
    pub iterm_profile: Option<String>,
    /// Human-readable terminal tab title resolved via
    /// `osascript` against iTerm2 (macOS only, best-effort).
    /// `None` outside iTerm2 or when the osascript query fails.
    pub terminal_title: Option<String>,
}

impl SessionInfo {
    /// Derives the account number from a `config-N` directory name.
    /// Returns `None` for any other shape.
    pub(crate) fn extract_account_id(config_dir: &std::path::Path) -> Option<u16> {
        let name = config_dir.file_name()?.to_str()?;
        let num_str = name.strip_prefix("config-")?;
        let num: u16 = num_str.parse().ok()?;
        if (1..=999).contains(&num) {
            Some(num)
        } else {
            None
        }
    }
}

/// Parses `TERM_SESSION_ID` (iTerm2 format) into `(window, tab, pane)`.
///
/// The format is `w<N>t<M>p<K>:<uuid>` where each of N, M, K is a
/// 1-3 digit integer. Anything else returns `None, None, None`.
///
/// Example: `"w3t2p0:3B8385EC-9D2C-4E26-A416-2E04BCA60DA3"` →
/// `(Some(3), Some(2), Some(0))`.
pub(crate) fn parse_term_session_id(raw: &str) -> (Option<u8>, Option<u8>, Option<u8>) {
    let prefix = match raw.split(':').next() {
        Some(p) => p,
        None => return (None, None, None),
    };
    // Walk the prefix character by character: `w` then digits, `t`
    // then digits, `p` then digits. Anything unexpected bails out.
    let mut chars = prefix.chars().peekable();
    let take_num = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>| -> Option<u8> {
        let mut digits = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                digits.push(c);
                chars.next();
            } else {
                break;
            }
        }
        digits.parse().ok()
    };

    if chars.next() != Some('w') {
        return (None, None, None);
    }
    let window = take_num(&mut chars);
    if chars.next() != Some('t') {
        return (window, None, None);
    }
    let tab = take_num(&mut chars);
    if chars.next() != Some('p') {
        return (window, tab, None);
    }
    let pane = take_num(&mut chars);
    (window, tab, pane)
}

pub mod directives;
pub mod lifecycle;
#[cfg(unix)]
pub mod lifecycle_records;
pub mod lifecycle_report;
mod rows;
pub use rows::{
    enrich, enrich_kind, list_rows, list_rows_detailed, list_rows_for_names, list_rows_titled,
    retry_if_only_unreadable, RowContext, RowsListing, SessionRowData, SURFACE_CLAUDE_CODE,
    SURFACE_CODEX,
};

pub(crate) use rows::{registry_start_in_window, MAX_REGISTRY_BYTES};

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use macos::list as list_impl;
#[cfg(target_os = "macos")]
pub use macos::try_list as try_list_impl;
#[cfg(target_os = "macos")]
pub use macos::try_list_detailed as try_list_detailed_impl;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::list as list_impl;
#[cfg(target_os = "linux")]
pub use linux::try_list as try_list_impl;
#[cfg(target_os = "linux")]
pub use linux::try_list_detailed as try_list_detailed_impl;

// The pure Windows env-block parser compiles everywhere so its
// unit tests run on macOS/Linux CI. The `windows.rs` syscall
// wrapper that feeds this parser is Windows-only because it
// depends on `windows-sys` FFI types.
//
// `#[allow(dead_code)]` on non-Windows targets because the
// functions are only called from the syscall wrapper, which is
// cfg-gated out. Their tests still exercise them on every
// platform, which is the whole point of splitting them out.
#[cfg(target_os = "windows")]
mod windows;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod windows_parse;
#[cfg(target_os = "windows")]
pub use windows::list as list_impl;
#[cfg(target_os = "windows")]
pub use windows::try_list as try_list_impl;
#[cfg(target_os = "windows")]
pub use windows::try_list_detailed as try_list_detailed_impl;

/// Discover live CC sessions for the current user.
///
/// Silently skips processes whose env or cwd cannot be read — most
/// such failures mean the process has exited between enumeration
/// and per-process inspection. A completely broken platform
/// backend returns an empty vector, never panics.
pub fn list() -> Vec<SessionInfo> {
    list_impl()
}

/// [`list`], but `None` when the platform backend could not enumerate
/// processes at all (the process table, `/proc`, or the Windows snapshot was
/// unreadable). An empty `Some` means "enumerated, none live"; callers that
/// must not mistake one for the other (the `csq.sessions.v1` listing and
/// directive delivery) use this.
pub fn try_list() -> Option<Vec<SessionInfo>> {
    try_list_impl()
}

/// A process listing with the facts [`try_list`] drops: how many same-uid processes that may
/// be a `claude` session were found but could not be read into one, whether the process
/// table itself is `incomplete`, and whether the caller is `restricted` from reading process
/// information at all.
///
/// A caller that needs UNIQUENESS (the directive inbox/ack caller resolution) cannot treat
/// an unreadable candidate as absent: it may own the same handle dir as the one it found.
/// Zombies, positively-gone processes, processes positively owned by another user and
/// processes positively named something other than `claude` are not counted. The name is
/// `comm` on Linux and macOS (`pbi_comm`/`pbi_name`) and the image name on Windows; where the
/// name itself could not be read the process IS counted, because it may be a `claude`. A Linux
/// `/proc` whose mounts may hide processes from the caller is reported separately, in
/// `incomplete`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The readable live sessions, exactly as [`try_list`] returns them.
    pub sessions: Vec<SessionInfo>,
    /// Same-uid processes that may be a `claude` session (named `claude`, or whose name could
    /// not be read) and could not be read into one.
    pub unreadable_claude: usize,
    /// The pids behind `unreadable_claude`, in listing order (so `unreadable_claude ==
    /// unreadable_pids.len()`), for an operator-facing message. Pids only.
    pub unreadable_pids: Vec<u32>,
    /// The process table itself may hide processes from this caller (Linux: any `hidepid`
    /// on a `/proc` mount; `mountinfo` unreadable or without a procfs `/proc`; a `/proc` that
    /// is a subtree bind, has a mount over a per-pid directory, or whose `/proc/self` is not
    /// this process's pid).
    /// The listing is then not whole even when `unreadable_claude` is 0. Always false on
    /// macOS and Windows.
    pub incomplete: bool,
    /// Why the table is `incomplete`; `Some` exactly when `incomplete` is (Linux only).
    pub incomplete_cause: Option<IncompleteCause>,
    /// The caller cannot read process information at all (a sandbox): on macOS the kernel
    /// refuses even the short read of pid 1, or every listed pid is unreadable; on Linux
    /// `/proc/1/stat` is refused. The unreadable pids are then a symptom, not a finding.
    pub restricted: bool,
}

impl Listing {
    /// The facts a caller needs to decide whether the listing can be trusted as whole.
    #[must_use]
    pub fn visibility(&self) -> Visibility {
        Visibility {
            restricted: self.restricted,
            incomplete: self.incomplete,
            cause: self.incomplete_cause,
        }
    }
}

/// Why a Linux `/proc` view may hide processes from the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncompleteCause {
    /// A `/proc` mount carries `hidepid=` other than `0`/`off`.
    Hidepid,
    /// `/proc/self` is not this process's pid: `/proc` describes another pid namespace.
    PidNamespaceMismatch,
    /// `/proc` is not procfs (or its filesystem type could not be read).
    NotProcfs,
    /// `/proc` is a bind of a subtree of procfs.
    SubtreeBind,
    /// A mount sits over a per-pid directory under `/proc`.
    PidDirMount,
    /// `mountinfo` could not be read.
    MountinfoUnreadable,
}

impl IncompleteCause {
    /// One line naming the cause and the next step for the operator.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Hidepid => "/proc is mounted with hidepid, which hides other processes; remount /proc without hidepid, or run csq where /proc is fully visible",
            Self::PidNamespaceMismatch => "/proc describes a different pid namespace than this process (a container?); run csq on the host, outside the container",
            Self::NotProcfs => "/proc is not a real procfs here; run csq where /proc is the kernel's procfs",
            Self::SubtreeBind => "/proc is a bind mount of a subtree of procfs; run csq where /proc is mounted whole",
            Self::PidDirMount => "a mount sits over a per-pid directory under /proc; unmount it or run csq where /proc is untouched",
            Self::MountinfoUnreadable => "/proc/self/mountinfo could not be read, so /proc cannot be vouched for; run csq outside the sandbox or container",
        }
    }
}

/// What a caller may rely on about a [`Listing`]: see [`Listing::visibility`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Visibility {
    /// See [`Listing::restricted`].
    pub restricted: bool,
    /// See [`Listing::incomplete`].
    pub incomplete: bool,
    /// See [`Listing::incomplete_cause`].
    pub cause: Option<IncompleteCause>,
}

impl Visibility {
    /// Nothing hidden from the caller.
    pub const WHOLE: Visibility = Visibility {
        restricted: false,
        incomplete: false,
        cause: None,
    };
}

/// [`try_list`] with the unreadable count, the `incomplete` verdict and `restricted`. `None` as for [`try_list`].
pub fn try_list_detailed() -> Option<Listing> {
    try_list_detailed_impl()
}

/// [`try_list_detailed`] plus terminal titles where the platform can resolve them (see
/// [`try_list_titled`]); for the human table.
pub fn try_list_detailed_titled() -> Option<Listing> {
    #[cfg(target_os = "macos")]
    {
        macos::try_list_detailed_opts(true)
    }
    #[cfg(not(target_os = "macos"))]
    {
        try_list_detailed_impl()
    }
}

/// [`try_list`] plus terminal titles where the platform can resolve them (macOS iTerm,
/// via a bounded, cached `osascript`). Display surfaces use this; machine surfaces use
/// [`try_list`], which never pays for titles.
pub fn try_list_titled() -> Option<Vec<SessionInfo>> {
    #[cfg(target_os = "macos")]
    {
        macos::try_list_opts(true)
    }
    #[cfg(not(target_os = "macos"))]
    {
        try_list_impl()
    }
}

/// A single-pid read that could not decide. Not "not a session": the process may be a live
/// session whose arguments, environment or owner could not be read (INV-31-01/02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Undetermined;

impl std::fmt::Display for Undetermined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the process could not be read")
    }
}

/// Outcome of [`session_info_for_pid`].
pub type PidLookup = Result<Option<SessionInfo>, Undetermined>;

/// The live session for ONE pid, read the same way [`try_list`] reads it, without
/// enumerating any other process. Three outcomes, on every platform:
///
/// - `Ok(Some(info))`: a live same-UID `claude` session with a `CLAUDE_CONFIG_DIR` (and,
///   on macOS only, a controlling terminal).
/// - `Ok(None)`: the pid is positively not one: it is gone, has another uid, is not
///   `claude`, has no `CLAUDE_CONFIG_DIR`, or (macOS only) has no controlling terminal.
/// - `Err(Undetermined)`: the process was found with a matching owner but reading or
///   parsing it failed, or the kernel call failed for a reason other than "no such
///   process". Callers MUST NOT treat this as `Ok(None)` (spec 31 §3).
pub fn session_info_for_pid(pid: u32) -> PidLookup {
    #[cfg(target_os = "macos")]
    {
        macos::session_info_for_pid(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::session_info_for_pid(pid)
    }
    #[cfg(target_os = "windows")]
    {
        windows::session_info_for_pid(pid)
    }
}

/// How far two readings of one process's `started_at` may differ and still name the same
/// process. macOS reads the kernel's absolute start time and is exact; Linux derives it
/// from `/proc/stat` `btime`, which the kernel recomputes from the wall clock on every
/// read and can move by one second (spec 31, INV-31-01).
pub const START_TOLERANCE_SECS: u64 = 1;

/// Whether two `started_at` readings name the same process start, within
/// [`START_TOLERANCE_SECS`].
#[must_use]
pub fn same_start(a: u64, b: u64) -> bool {
    a.abs_diff(b) <= START_TOLERANCE_SECS
}

/// The start time (unix seconds) of one process, read the same way [`try_list`] reads it,
/// without enumerating the process table. `None` when the process does not exist or its
/// start time cannot be read.
#[must_use]
pub fn process_start_time(pid: u32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        macos::read_start_time(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::read_start_time(&std::path::Path::new("/proc").join(pid.to_string()))
    }
    #[cfg(target_os = "windows")]
    {
        windows::start_time_of(pid)
    }
}

/// The parent pid of `pid`, or `None` when it cannot be read (the process is gone or the
/// platform call failed).
#[must_use]
pub fn parent_pid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        macos::parent_pid(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::parent_pid(pid)
    }
    #[cfg(target_os = "windows")]
    {
        windows::parent_pid_of(pid)
    }
}

/// Most parent hops [`is_ancestor_of_current`] follows.
pub const MAX_ANCESTRY_HOPS: usize = 64;

/// Whether `pid` is an ancestor of this process, reading parents with `parent_of` and
/// start times with `start_of`.
/// Walks from this process's parent, at most [`MAX_ANCESTRY_HOPS`] hops:
/// `Some(true)` on reaching `pid`; `Some(false)` on reaching pid 0 or 1 or on a cycle;
/// `None` when a read fails (or the hop cap is hit) first — never a silent `false`.
///
/// `start_of` MUST return a FULL-PRECISION start from one kernel clock (macOS microseconds,
/// Linux raw `starttime` ticks, Windows creation FILETIME; see [`ancestor_start`]) and the
/// walk compares it with NO tolerance. The one-second `started_at` used elsewhere cannot
/// tell a pid reused within the same second from the original.
///
/// Every hop is validated: a parent must not have started after its child
/// (`start(parent) <= start(child)`, strict). A parent pid that was reused
/// while it was being read (and, on Windows, an orphan whose recorded parent pid now names
/// an unrelated process) always started AFTER the child, so such a hop is `None`
/// (undetermined). A hop's OWN pid can also be reused between reading its start and
/// reading its parent (the new process's parent may be any older process), so each
/// hop's start is read again AFTER its parent is read and must be unchanged; a changed
/// or unreadable re-read is `None`. Together these give: never a `Some(true)` for a
/// process that is not an ancestor, provided start stamps are monotonic. Linux field 22 is
/// on the kernel's boot-time clock (forward-only), so this holds unconditionally there;
/// macOS and Windows stamp creation with the wall clock, so a backward clock step between
/// a parent's and a child's creation can make a REAL chain read as `None` (fail-closed,
/// never a false `Some(true)` without also winning a pid-reuse race).
pub fn is_ancestor_with<T: Ord + Copy>(
    pid: u32,
    me: u32,
    parent_of: &dyn Fn(u32) -> Option<u32>,
    start_of: &dyn Fn(u32) -> Option<T>,
) -> Option<bool> {
    ancestor_path_with(pid, me, parent_of, start_of).map(|p| p.is_some())
}

/// The processes strictly between a caller and its claimed owner, nearest first, each as
/// `(pid, full-precision start)` (see [`ancestor_path_with`]).
pub type AncestorHops = Vec<(u32, u64)>;

/// [`is_ancestor_with`], additionally returning the processes STRICTLY BETWEEN `me` and
/// `pid` (nearest first) as `(pid, full-precision start)`: `Some(Some(between))` on reaching
/// `pid`, `Some(None)` when `pid` is not an ancestor, `None` undetermined. Every hop keeps
/// the full-precision start checks, so each returned pair was validated as a genuine link
/// of the chain, not a recycled pid; the start is carried out so a later classification of
/// the hop can prove it is still the SAME incarnation (`between_hop_is_session`).
pub fn ancestor_path_with<T: Ord + Copy>(
    pid: u32,
    me: u32,
    parent_of: &dyn Fn(u32) -> Option<u32>,
    start_of: &dyn Fn(u32) -> Option<T>,
) -> Option<Option<Vec<(u32, T)>>> {
    let mut between: Vec<(u32, T)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(me);
    let mut child_start = start_of(me)?;
    let mut cur = parent_of(me)?;
    for hop in 0..MAX_ANCESTRY_HOPS {
        // pid 0 and 1 are the chain's roots; they have no meaningful start to compare.
        if cur > 1 {
            let parent_start = start_of(cur)?;
            if parent_start > child_start {
                return None;
            }
            child_start = parent_start;
        }
        if cur == pid {
            return Some(Some(between));
        }
        if cur <= 1 {
            return Some(None);
        }
        if !seen.insert(cur) {
            return Some(None);
        }
        between.push((cur, child_start));
        if hop + 1 == MAX_ANCESTRY_HOPS {
            break;
        }
        let next = parent_of(cur)?;
        // `cur` must still be the process whose start was checked: re-read it after its
        // parent. (`cur > 1` here: 0 and 1 returned above.)
        if start_of(cur)? != child_start {
            return None;
        }
        cur = next;
    }
    None
}

/// Full-precision process start for the ancestry walk only (NOT an identity key; do not
/// compare with [`same_start`]): macOS microseconds since the epoch, Linux raw
/// `/proc/<pid>/stat` `starttime` clock ticks, Windows creation FILETIME (100 ns). Units
/// differ per platform but are consistent within one, which is all the walk needs.
#[must_use]
pub fn ancestor_start(pid: u32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        macos::ancestor_start_micros(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::read_start_ticks(&std::path::Path::new("/proc").join(pid.to_string()))
    }
    #[cfg(target_os = "windows")]
    {
        windows::creation_filetime_of(pid)
    }
}

/// [`is_ancestor_with`] over this process and the real parent chain, at full precision.
#[must_use]
pub fn is_ancestor_of_current(pid: u32) -> Option<bool> {
    is_ancestor_with(pid, std::process::id(), &parent_pid, &ancestor_start)
}

/// [`ancestor_path_with`] over this process and the real parent chain, at full precision.
#[must_use]
pub fn ancestor_path_of_current(pid: u32) -> Option<Option<AncestorHops>> {
    ancestor_path_with(pid, std::process::id(), &parent_pid, &ancestor_start)
}

/// Whether `pid` is a live Claude OR Codex session: `Some(true)` / `Some(false)`, and `None`
/// when either lookup could not be read (never read as "not a session").
#[must_use]
pub fn is_session_pid(pid: u32) -> Option<bool> {
    let mut any = false;
    for kind in [CliKind::Claude, CliKind::Codex] {
        match session_info_for_pid_kind(kind, pid) {
            Ok(Some(_)) => any = true,
            Ok(None) => {}
            Err(Undetermined) => return None,
        }
    }
    Some(any)
}

/// One raw read of a process that sits between a caller and a claimed owner (F1/F3). The
/// platform readers produce it; [`classify_hop`] turns it into a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HopProbe {
    /// The process no longer exists (positively; e.g. `ESRCH`).
    Gone,
    /// The process could not be read well enough to classify its image.
    Unreadable,
    /// Read, and [`image_verdict`] reached a verdict: whether its IMAGE is a CLI session
    /// csq launches. The owner uid is deliberately absent: a session image between the caller
    /// and the owner is a nearer session whoever runs it (`sudo -u other codex`).
    ///
    /// `codex_wrapper` is `true` only for a `node` image running Codex's own launcher script
    /// (the npm wrapper that sits directly above the native `codex`); it implies
    /// `session_image`. Windows never sets it (its snapshot carries the image name only).
    Process {
        session_image: bool,
        codex_wrapper: bool,
    },
}

/// The between-hop verdict of one [`HopProbe`]. A `claude`/`codex`/`gemini`/`kimi`/`grok`
/// image is a session whatever its uid, terminal or environment (a `codex exec` from a tool
/// has neither a terminal nor its own `CODEX_HOME`). `Gone` and `Unreadable` are `None`: a
/// hop that cannot be classified is never "not a session".
#[must_use]
pub(crate) fn classify_hop(probe: HopProbe) -> Option<bool> {
    match probe {
        HopProbe::Gone | HopProbe::Unreadable => None,
        HopProbe::Process { session_image, .. } => Some(session_image),
    }
}

/// What one process between the listed Codex and its supervisor is, for the wake chain
/// check (spec 32 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainHop {
    /// A `node` image running Codex's launcher script: Codex's own npm wrapper.
    CodexWrapper,
    /// Any other CLI image (`claude`, `codex`, `gemini`, `kimi`, `grok`).
    Cli,
    /// Read, and not a CLI image.
    Plain,
}

/// The [`ChainHop`] of one [`HopProbe`]; `Gone` and `Unreadable` are `None` (undetermined).
pub(crate) fn classify_chain_hop(probe: HopProbe) -> Option<ChainHop> {
    match probe {
        HopProbe::Gone | HopProbe::Unreadable => None,
        HopProbe::Process {
            session_image: false,
            ..
        } => Some(ChainHop::Plain),
        HopProbe::Process {
            codex_wrapper: true,
            ..
        } => Some(ChainHop::CodexWrapper),
        HopProbe::Process { .. } => Some(ChainHop::Cli),
    }
}

/// Whether a `codex` argv is the wake invocation `codex [-c key=value]... queue ...`: the
/// subcommand, the first argument after the `-c`/`--config` pairs, is `queue`. That process is
/// csq's own short-lived wake child (`messaging::wake`), launched with the TARGET's
/// `CODEX_HOME`; it is a client of the session it wakes, not a second session owning the home,
/// so the listings leave it out. Nothing else is excluded: any other subcommand, and a bare
/// `codex` (no subcommand), stay listed.
#[cfg(unix)]
pub(crate) fn is_queue_invocation<S: AsRef<str>>(argv: &[S]) -> bool {
    let mut i = 1; // argv[0] is the program
    while let Some(a) = argv.get(i).map(AsRef::as_ref) {
        if a == "-c" || a == "--config" {
            i += 2;
        } else if a.starts_with("-c=") || a.starts_with("--config=") {
            i += 1;
        } else {
            return a == "queue";
        }
    }
    false
}

/// The CLIs csq launches; a process whose image is one of these is a session.
const CLI_IMAGE_NAMES: [&str; 5] = ["claude", "codex", "gemini", "kimi", "grok"];

/// First token after `<cli>-` of a release-asset name (`codex-aarch64-apple-darwin`,
/// `grok-macos-aarch64`) that marks it as a CLI binary rather than an unrelated tool whose
/// name merely starts with the CLI's (`codex-helper`, `claude-mem`).
const ASSET_SUFFIX_STARTS: [&str; 10] = [
    "aarch64", "x86_64", "arm64", "amd64", "i686", "armv7", "macos", "darwin", "linux", "windows",
];

/// Whether a process image BASENAME (argv\[0\]'s, the kernel comm, or the executable's) is a
/// CLI csq launches: the bare name, with or without `.exe`, or the native release asset
/// `<cli>-<arch-or-os…>` / `<cli>-<version>…`. The Linux `comm` is cut to 15 characters, so
/// `codex-aarch64-apple-darwin` arrives as `codex-aarch64-a`; the check is on the prefix
/// after `<cli>-`, which that cut leaves intact.
#[must_use]
pub(crate) fn is_cli_image_name(base: &str) -> bool {
    let lower = base.to_ascii_lowercase();
    let b = lower.strip_suffix(".exe").unwrap_or(&lower);
    CLI_IMAGE_NAMES.iter().any(|n| {
        b == *n
            || b.strip_prefix(n)
                .and_then(|r| r.strip_prefix('-'))
                .is_some_and(|rest| {
                    rest.starts_with(|c: char| c.is_ascii_digit())
                        || ASSET_SUFFIX_STARTS.iter().any(|t| rest.starts_with(t))
                })
    })
}

#[cfg(unix)]
fn is_node_image_name(base: &str) -> bool {
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower) == "node"
}

#[cfg(unix)]
fn base_of(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

#[cfg(unix)]
/// Whether an executable PATH is a CLI image by where it lives: Claude Code's installer
/// puts the binary at `…/claude/versions/<version>` (basename `2.1.289`, measured on this
/// host), so the basename says nothing and the directory does.
fn exe_path_is_cli_image(exe: &std::path::Path) -> bool {
    let s = exe.to_string_lossy().replace('\\', "/");
    s.contains("/claude/versions/") || is_cli_image_name(base_of(&s))
}

#[cfg(unix)]
/// For a `node` image: whether the SCRIPT it runs is a CLI. The script is the first argument
/// after argv\[0\] that is not a node option (or an option's value). Matches the script's
/// stem (`gemini.js`) or an npm package directory (`@google/gemini-cli/`).
fn node_script_is_cli(argv: &[String]) -> bool {
    node_script_cli(argv).is_some()
}

#[cfg(unix)]
/// The CLI a `node` image's script belongs to ([`node_script_is_cli`]'s rule), by name.
fn node_script_cli(argv: &[String]) -> Option<&'static str> {
    const TAKES_VALUE: [&str; 8] = [
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "-e",
        "-p",
        "--eval",
    ];
    let mut it = argv.iter().skip(1);
    while let Some(a) = it.next() {
        if TAKES_VALUE.contains(&a.as_str()) {
            it.next();
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        let norm = a.replace('\\', "/");
        for (pkg, cli) in [
            ("/@anthropic-ai/claude-code/", "claude"),
            ("/@openai/codex/", "codex"),
            ("/@google/gemini-cli/", "gemini"),
        ] {
            if norm.contains(pkg) {
                return Some(cli);
            }
        }
        let base = base_of(&norm);
        let stem = [".js", ".mjs", ".cjs"]
            .iter()
            .find_map(|e| base.strip_suffix(e))
            .unwrap_or(base);
        return CLI_IMAGE_NAMES.iter().copied().find(|n| *n == stem);
    }
    None
}

#[cfg(unix)]
/// What the platform readers could read about one process's image. `None` is "could not
/// read", never "empty".
pub(crate) struct ImageReads {
    /// The kernel name (`comm` / `pbi_comm`), basename only.
    pub comm: Option<String>,
    /// The launch argv.
    pub argv: Option<Vec<String>>,
    /// The executable path (`/proc/<pid>/exe`, `proc_pidpath`, the Windows image name).
    /// Unlike the first two it cannot be changed by the process (`exec -a`, `prctl`).
    pub exe: Option<std::path::PathBuf>,
}

#[cfg(unix)]
/// The image verdict from [`ImageReads`]: `Some(true)` when ANY signal names a CLI (the
/// kernel name, argv\[0\], the executable's basename or `/claude/versions/` directory,
/// the executable being the same file as a CLI binary `exe_is_resolved_cli` resolves, or a
/// `node` image running a CLI's script), `Some(false)` only when at least TWO signals were
/// read and none matched, `None` otherwise. An unreadable signal therefore never overrides
/// a positive one and never turns a lone reading into "not a session".
pub(crate) fn image_verdict(
    r: &ImageReads,
    exe_is_resolved_cli: &dyn Fn(&std::path::Path) -> bool,
) -> Option<bool> {
    let argv0_base = r
        .argv
        .as_ref()
        .and_then(|a| a.first())
        .map(|a0| base_of(a0).to_string());
    let exe_base = r
        .exe
        .as_ref()
        .map(|e| base_of(&e.to_string_lossy()).to_string());
    let names = [
        r.comm.as_deref(),
        argv0_base.as_deref(),
        exe_base.as_deref(),
    ];
    if names.iter().flatten().any(|n| is_cli_image_name(n)) {
        return Some(true);
    }
    if let Some(exe) = &r.exe {
        if exe_path_is_cli_image(exe) || exe_is_resolved_cli(exe) {
            return Some(true);
        }
    }
    if let Some(argv) = &r.argv {
        if names.iter().flatten().any(|n| is_node_image_name(n)) && node_script_is_cli(argv) {
            return Some(true);
        }
    }
    let read = usize::from(r.comm.is_some())
        + usize::from(r.argv.as_ref().is_some_and(|a| !a.is_empty()))
        + usize::from(r.exe.is_some());
    (read >= 2).then_some(false)
}

#[cfg(unix)]
/// Whether the image is Codex's own npm launcher: a `node` image (by kernel name, argv\[0\]
/// basename or executable basename) whose script is Codex's (`/@openai/codex/…` or a
/// `codex.js` stem). A `node` running Claude's or Gemini's script is NOT one.
pub(crate) fn is_codex_node_wrapper(r: &ImageReads) -> bool {
    let argv0_base = r
        .argv
        .as_ref()
        .and_then(|a| a.first())
        .map(|a0| base_of(a0).to_string());
    let exe_base = r
        .exe
        .as_ref()
        .map(|e| base_of(&e.to_string_lossy()).to_string());
    let names = [
        r.comm.as_deref(),
        argv0_base.as_deref(),
        exe_base.as_deref(),
    ];
    names.iter().flatten().any(|n| is_node_image_name(n))
        && r.argv
            .as_ref()
            .is_some_and(|a| node_script_cli(a) == Some("codex"))
}

/// Whether `exe` is the same file (device + inode) as a CLI binary csq resolves
/// ([`crate::accounts::login::find_cli_binary`]); closes the case where the image is
/// renamed or aliased (`ln -s codex cx`) and every name read says something else.
#[cfg(unix)]
pub(crate) fn exe_is_resolved_cli(exe: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(me) = std::fs::metadata(exe) else {
        return false;
    };
    CLI_IMAGE_NAMES.iter().any(|n| {
        crate::accounts::login::find_cli_binary(n)
            .and_then(|p| std::fs::metadata(p).ok())
            .is_some_and(|m| m.dev() == me.dev() && m.ino() == me.ino())
    })
}

/// Whether the process between caller and owner, identified as `(pid, start)` from the
/// ancestry walk, is a session, for the nearest-session check (spec 32 §2.2). The start is
/// re-read BEFORE and AFTER the classification read and must equal the walked `start`
/// exactly (full precision): a hop that exited after the walk, or whose pid was reused,
/// changes or loses its start and is `None` (undetermined), so the classification is always
/// about the incarnation the walk saw. This is NOT the listing predicate
/// ([`is_session_pid`]), which requires a terminal and an own handle-dir variable.
pub(crate) fn between_hop_is_session(
    pid: u32,
    start: u64,
    start_of: &dyn Fn(u32) -> Option<u64>,
    probe: &dyn Fn(u32) -> HopProbe,
) -> Option<bool> {
    if start_of(pid)? != start {
        return None;
    }
    let verdict = classify_hop(probe(pid))?;
    (start_of(pid)? == start).then_some(verdict)
}

/// `between_hop_is_session` for the wake chain: the [`ChainHop`] of the hop `(pid, start)`,
/// with the same start bracket (an unreadable, vanished or re-used hop is `None`).
pub(crate) fn between_hop_chain(
    pid: u32,
    start: u64,
    start_of: &dyn Fn(u32) -> Option<u64>,
    probe: &dyn Fn(u32) -> HopProbe,
) -> Option<ChainHop> {
    if start_of(pid)? != start {
        return None;
    }
    let class = classify_chain_hop(probe(pid))?;
    (start_of(pid)? == start).then_some(class)
}

/// `between_hop_is_session` over the real process table at full precision.
#[must_use]
pub fn is_session_hop(pid: u32, start: u64) -> Option<bool> {
    between_hop_is_session(pid, start, &ancestor_start, &hop_probe)
}

fn hop_probe(pid: u32) -> HopProbe {
    #[cfg(target_os = "macos")]
    {
        macos::hop_probe(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::hop_probe(pid)
    }
    #[cfg(target_os = "windows")]
    {
        windows::hop_probe(pid)
    }
}

/// Which CLI a listing or caller resolution is for (spec 32 §2.1).
///
/// The process name is `comm()` (argv\[0\] basename on macOS, `/proc/<pid>/comm` on Linux)
/// and the handle dir is the process's `env_key()` variable. For Codex the session is the
/// NATIVE `codex` binary, not the `node …/bin/codex` wrapper in front of it: the wrapper's
/// name is `node`, so only one process per session is named `codex` and uniqueness holds;
/// the native process is also the one whose argv carries the launch flags
/// ([`parse_codex_launch`]) and the parent of every tool process the caller runs from, so
/// the caller descends from it exactly as it does from `claude`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliKind {
    /// Claude Code (`claude`, `CLAUDE_CONFIG_DIR`).
    Claude,
    /// Codex (`codex`, `CODEX_HOME`).
    Codex,
}

impl CliKind {
    /// The process name that identifies this CLI.
    #[must_use]
    pub const fn comm(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    /// The environment variable naming the session's handle dir.
    #[must_use]
    pub const fn env_key(self) -> &'static str {
        match self {
            Self::Claude => "CLAUDE_CONFIG_DIR",
            Self::Codex => "CODEX_HOME",
        }
    }

    /// The `surface` value on the wire.
    #[must_use]
    pub const fn surface(self) -> &'static str {
        match self {
            Self::Claude => SURFACE_CLAUDE_CODE,
            Self::Codex => SURFACE_CODEX,
        }
    }
}

/// [`try_list_detailed`] for the processes of `kind`. `None` as there; on Windows a Codex
/// listing is not implemented and is `None` (undetermined), never an empty "none live".
pub fn try_list_detailed_kind(kind: CliKind) -> Option<Listing> {
    #[cfg(target_os = "macos")]
    {
        macos::try_list_detailed_kind_opts(kind, false)
    }
    #[cfg(target_os = "linux")]
    {
        linux::try_list_detailed_kind(kind)
    }
    #[cfg(target_os = "windows")]
    {
        match kind {
            CliKind::Claude => windows::try_list_detailed(),
            CliKind::Codex => None,
        }
    }
}

/// [`session_info_for_pid`] for `kind` (Windows Codex: `Err(Undetermined)`).
pub fn session_info_for_pid_kind(kind: CliKind, pid: u32) -> PidLookup {
    #[cfg(target_os = "macos")]
    {
        macos::session_info_for_pid_kind(kind, pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::session_info_for_pid_kind(kind, pid)
    }
    #[cfg(target_os = "windows")]
    {
        match kind {
            CliKind::Claude => windows::session_info_for_pid(pid),
            CliKind::Codex => Err(Undetermined),
        }
    }
}

/// [`session_info_for_pid_kind`] plus the session's FULL-PRECISION start ([`ancestor_start`]),
/// read before and after the lookup and required to be equal: the pair is one incarnation.
/// `Ok(None)` is as for the lookup; an unreadable or changed exact start is `Undetermined`.
/// The exact start stays in csq-core (it is not a `SessionInfo` field, so it cannot reach the
/// `csq.sessions.v1` wire); it is what [`codex_launch_checked`] binds the argv read to.
pub fn session_info_exact_for_pid_kind(
    kind: CliKind,
    pid: u32,
) -> Result<Option<(SessionInfo, u64)>, Undetermined> {
    session_info_exact_with(&|| session_info_for_pid_kind(kind, pid), &|| {
        ancestor_start(pid)
    })
}

pub(crate) fn session_info_exact_with(
    lookup: &dyn Fn() -> PidLookup,
    exact_start_of: &dyn Fn() -> Option<u64>,
) -> Result<Option<(SessionInfo, u64)>, Undetermined> {
    let before = exact_start_of();
    let info = lookup()?;
    let after = exact_start_of();
    match (info, before, after) {
        (None, _, _) => Ok(None),
        (Some(i), Some(b), Some(a)) if a == b => Ok(Some((i, b))),
        _ => Err(Undetermined),
    }
}

/// What a Codex process was launched with, read from its argv. csq-core callers only: it
/// is never serialised and never reaches a wire (spec 32 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodexLaunch {
    /// The thread id from `resume <thread-uuid>`, lowercase; `None` for a fresh launch or
    /// when the token after `resume` is not a UUID (`--last`, a name).
    pub thread_id: Option<String>,
    /// The value of `-c sqlite_home=<value>` with its TOML quotes removed; the last one wins.
    pub sqlite_home: Option<PathBuf>,
}

fn is_uuid_shape(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Parse `codex -c sqlite_home="<dir>" … resume <thread-uuid>` launch argv. Pure.
///
/// Config flags are read only BEFORE the `resume` token (or a bare `--`), so prompt text that
/// follows cannot inject a `sqlite_home`. The thread id is the token right after `resume`,
/// accepted only when UUID-shaped.
#[must_use]
pub fn parse_codex_launch(argv: &[String]) -> CodexLaunch {
    let mut out = CodexLaunch::default();
    let mut i = 1; // argv[0] is the program
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            break;
        }
        if a == "resume" {
            out.thread_id = argv
                .get(i + 1)
                .filter(|t| is_uuid_shape(t))
                .map(|t| t.to_ascii_lowercase());
            break;
        }
        let value = if a == "-c" || a == "--config" {
            i += 1;
            argv.get(i).map(String::as_str)
        } else {
            a.strip_prefix("-c=")
                .or_else(|| a.strip_prefix("--config="))
        };
        if let Some(v) = value.and_then(|v| v.strip_prefix("sqlite_home=")) {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                .unwrap_or(v);
            // Only an absolute, plainly-quoted path counts: a relative value would resolve
            // against whatever cwd the reader has, and a leftover quote or backslash means
            // the unquote did not recognise the value's shape.
            if !v.is_empty()
                && !v
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '"' | '\'' | '\\'))
                && std::path::Path::new(v).is_absolute()
            {
                out.sqlite_home = Some(PathBuf::from(v));
            }
        }
        i += 1;
    }
    out
}

/// The launch info of one Codex process; `None` when its argv could not be read (never
/// "no launch flags"). Windows: always `None`.
#[must_use]
pub fn codex_launch_for_pid(pid: u32) -> Option<CodexLaunch> {
    #[cfg(target_os = "macos")]
    let argv = macos::launch_argv_for_pid(pid);
    #[cfg(target_os = "linux")]
    let argv = linux::launch_argv_for_pid(pid);
    #[cfg(target_os = "windows")]
    let argv: Option<Vec<String>> = {
        let _ = pid;
        None
    };
    argv.map(|a| parse_codex_launch(&a))
}

/// [`codex_launch_for_pid`] bound to ONE session incarnation: reads the start, the process
/// name, the argv, then the start again through the injected readers. `None` when any read
/// fails, the start is not the session's (`started_at`, [`same_start`]), the name is not a
/// Codex session, or the full-precision start (`exact_start_of`, [`ancestor_start`]) differs
/// between the read before the name and the read after the argv. The bracket compares with
/// exact equality at full precision, so a pid reused within the same second (or a Linux
/// `btime` jitter of one second) cannot pass as the same incarnation; `start_of` (seconds)
/// is used only for the comparison against the listed `started_at`.
///
/// BOUND, stated exactly: the full-precision bracket proves that the name check and the argv
/// read were about ONE incarnation. Binding that incarnation to the LISTED session is
/// seconds-precision only (`same_start`), because the listing's `SessionInfo` carries no
/// full-precision start (it is a wire struct built by literal in several crates, so a field
/// cannot be added without touching all of them). A different `codex` that took the pid
/// within the same second as the listed one (or inside Linux's one-second `btime` jitter)
/// would therefore pass; [`WakeTarget::still_live`] closes the window that follows the
/// wake-target check, not the one between listing and this call.
pub fn codex_launch_checked(
    started_at: u64,
    listed_exact: u64,
    start_of: &dyn Fn() -> Option<u64>,
    exact_start_of: &dyn Fn() -> Option<u64>,
    is_codex: &dyn Fn() -> bool,
    argv_of: &dyn Fn() -> Option<Vec<String>>,
) -> Option<CodexLaunch> {
    if !same_start(start_of()?, started_at) {
        return None;
    }
    let first = exact_start_of()?;
    if first != listed_exact {
        return None;
    }
    if !is_codex() {
        return None;
    }
    let argv = argv_of()?;
    let second = exact_start_of()?;
    (second == first).then(|| parse_codex_launch(&argv))
}

/// The launch info of the Codex session `(pid, started_at)`; `None` unless that exact
/// incarnation is a live `codex` whose argv could be read ([`codex_launch_checked`]).
#[must_use]
pub fn codex_launch_for_session(
    pid: u32,
    started_at: u64,
    listed_exact: u64,
) -> Option<CodexLaunch> {
    codex_launch_checked(
        started_at,
        listed_exact,
        &|| process_start_time(pid),
        &|| ancestor_start(pid),
        &|| matches!(session_info_for_pid_kind(CliKind::Codex, pid), Ok(Some(_))),
        &|| {
            #[cfg(target_os = "macos")]
            let a = macos::launch_argv_for_pid(pid);
            #[cfg(target_os = "linux")]
            let a = linux::launch_argv_for_pid(pid);
            #[cfg(target_os = "windows")]
            let a: Option<Vec<String>> = None;
            a
        },
    )
}

/// A Codex wake target that passed [`wake_target_ok`]. Fields are private: the only way to
/// hold one is to have passed every check, so a spawn can take its paths from here and
/// nowhere else. The checks describe the filesystem and process table AT CHECK TIME; the
/// caller MUST call [`WakeTarget::still_live`] immediately before spawning, which re-reads
/// the target's exact start (the recorded incarnation, so a reused pid fails) and
/// re-validates the handle dir and its `.live-pid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeTarget {
    pid: u32,
    /// Full-precision start of `pid` ([`ancestor_start`]) when the checks ran.
    start: u64,
    /// The `<N>` of `term-<N>`: the csq supervisor pid, or `pid` itself on the swap-exec path.
    supervisor: u32,
    /// Full-precision start of `supervisor` when the checks ran.
    supervisor_start: u64,
    codex_home: PathBuf,
    sqlite_home: PathBuf,
}

impl WakeTarget {
    /// The canonical `<accounts>/term-<supervisor>` to pass as `CODEX_HOME`.
    #[must_use]
    pub fn codex_home(&self) -> &std::path::Path {
        &self.codex_home
    }

    /// The canonical `<accounts>/config-<N>` to pass as `-c sqlite_home=`.
    #[must_use]
    pub fn sqlite_home(&self) -> &std::path::Path {
        &self.sqlite_home
    }

    /// Whether a csq supervisor OTHER than the Codex process itself exists to retry a deferred
    /// wake: false on the swap-exec path, where the supervisor IS the Codex pid.
    #[must_use]
    pub fn has_retrier(&self) -> bool {
        self.supervisor != self.pid
    }

    /// The listed Codex process id this target was validated for.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Exact start captured during validation, for private messaging evidence.
    pub fn exact_start(&self) -> u64 {
        self.start
    }

    /// Whether the target is still the incarnation that was validated: the Codex pid and its
    /// supervisor each still have EXACTLY the recorded full-precision start (a reused pid
    /// has a different one), the handle dir is still a real directory (not a symlink), and
    /// its `.live-pid` still names the supervisor. Any unreadable input is `false`.
    #[must_use]
    pub fn still_live(&self) -> bool {
        self.still_live_with(&ancestor_start)
    }

    pub(crate) fn still_live_with(&self, start_of: &dyn Fn(u32) -> Option<u64>) -> bool {
        start_of(self.pid) == Some(self.start)
            && start_of(self.supervisor) == Some(self.supervisor_start)
            && handle_dir_names_supervisor(&self.codex_home, self.supervisor)
    }
}

/// The processes between the listed Codex and its supervisor (`between`, nearest first, each
/// with the start the walk validated) are exactly Codex's own launch chain, and the chain's
/// top is the supervisor's recorded child. Mechanisms: (1) the hop directly below the
/// supervisor (the last of `between`, or `pid` itself when there is none) must be the pid
/// `term-<sup>/.live-cc-pid` names: the supervisor writes it right after it spawns Codex
/// (`codex_supervise.rs`), so an absent, unreadable or different record refuses; (2) each hop
/// is classified by IMAGE under the start bracket ([`between_hop_chain`]): only the FIRST hop
/// (the listed pid's parent) may be a CLI image, and only when it is Codex's npm wrapper
/// (a `node` image running Codex's script); any other CLI image, a second wrapper, or a hop
/// that cannot be read refuses. A Codex started by a tool inside the session inherits
/// `CODEX_HOME` and descends from the supervisor, but a `claude`, a `codex` or its wrapper
/// stands above it, so (2) refuses it; the record in (1) alone could not, because the nested
/// Codex still sits under the supervised child.
fn chain_is_own_launch(
    home: &std::path::Path,
    pid: u32,
    between: &[(u32, u64)],
    start_of: &dyn Fn(u32) -> Option<u64>,
    probe: &dyn Fn(u32) -> HopProbe,
) -> Option<()> {
    let top = between.last().map_or(pid, |h| h.0);
    match crate::accounts::markers::read_live_cc_pid_checked(home) {
        Ok(Some(child)) if child == top => {}
        _ => return None,
    }
    for (i, (hop, hop_start)) in between.iter().enumerate() {
        match between_hop_chain(*hop, *hop_start, start_of, probe)? {
            ChainHop::Plain => {}
            ChainHop::CodexWrapper if i == 0 => {}
            ChainHop::CodexWrapper | ChainHop::Cli => return None,
        }
    }
    Some(())
}

/// The swap-exec shape of an npm Codex: `exec_codex_after_binding` exec-replaces csq, so the
/// `node` launcher becomes the handle dir's supervisor (`term-<its pid>/.live-pid` names it,
/// checked by the caller) and the native `codex` is its DIRECT child. Nothing on that path
/// writes `.live-cc-pid`, so [`chain_is_own_launch`] can never hold; this accepts the shape
/// only when ALL of: nothing sits between the listed pid and the supervisor (`between` is
/// empty, i.e. the parent is the supervisor, start-monotonic per [`ancestor_path_with`]) and
/// the supervisor itself probes as Codex's npm wrapper under the start bracket. A supervisor
/// that is csq, a shell or another CLI is refused, and any intervening hop (a nested Codex
/// behind a shell or its own wrapper) refuses, so only the wrapper's own native child passes.
fn exec_wrapper_launch(
    between: &[(u32, u64)],
    supervisor: u32,
    supervisor_start: u64,
    start_of: &dyn Fn(u32) -> Option<u64>,
    probe: &dyn Fn(u32) -> HopProbe,
) -> Option<()> {
    if !between.is_empty() {
        return None;
    }
    match between_hop_chain(supervisor, supervisor_start, start_of, probe)? {
        ChainHop::CodexWrapper => Some(()),
        ChainHop::Cli | ChainHop::Plain => None,
    }
}

/// `dir` is a real directory (`symlink_metadata`, so a symlink is refused) whose `.live-pid`
/// reads as exactly `supervisor`. An unreadable or malformed marker is `false`.
fn handle_dir_names_supervisor(dir: &std::path::Path, supervisor: u32) -> bool {
    std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir())
        && matches!(
            crate::accounts::markers::read_live_pid_checked(dir),
            Ok(Some(p)) if p == supervisor
        )
}

/// Whether a Codex session may be woken (spec 32 §5.1); `Some` only when EVERY check holds.
/// `pid` is the listed Codex process (the native `codex`); `codex_home` is its `CODEX_HOME`.
///
/// Mechanisms: (1) `codex_home` must canonicalise to `canonical(accounts)/term-<sup>` with
/// `<sup>` a canonical decimal pid, and that path must be a real directory
/// (`symlink_metadata`), so a symlink named `term-<sup>` is refused; (2) `csq run` names the
/// handle dir after the csq SUPERVISOR's pid, not Codex's (`run.rs::launch_codex`), so the
/// listed pid is bound to `<sup>` instead of being compared with it: `term-<sup>/.live-pid`
/// must read `<sup>`, `<sup>` must have a readable start (live), and `pid` must descend from
/// `<sup>` through a full-precision, start-monotonic parent walk ([`ancestor_path_with`]; an
/// npm node wrapper between them is just a hop), or `<sup> == pid` (the swap-exec path, where
/// Codex itself holds `term-<own pid>`). `<sup>` is taken from `CODEX_HOME` alone and every
/// claim it makes is verified against the process table and the `.live-pid` the supervisor
/// wrote, so a forged `CODEX_HOME` naming another live session's dir fails the descent;
/// (3) the launch's `sqlite_home` must be absolute, equal to its own canonical form (no
/// symlink or `..` component anywhere), a real directory, and be exactly
/// `canonical(accounts).join("config-<N>")` with `<N>` a valid account number in canonical
/// decimal: the one location `csq run` passes at codex launch (`codex_command` canonicalises
/// the slot's `config-<N>` dir). Anything else, including an unreadable path or a missing
/// `sqlite_home`, is a refusal. The returned paths are the canonical ones the check saw.
#[must_use]
pub fn wake_target_ok(
    accounts: &std::path::Path,
    pid: u32,
    codex_home: &std::path::Path,
    launch: &CodexLaunch,
) -> Option<WakeTarget> {
    wake_target_with(
        accounts,
        pid,
        codex_home,
        launch,
        &parent_pid,
        &ancestor_start,
        &hop_probe,
    )
}

pub(crate) fn wake_target_with(
    accounts: &std::path::Path,
    pid: u32,
    codex_home: &std::path::Path,
    launch: &CodexLaunch,
    parent_of: &dyn Fn(u32) -> Option<u32>,
    start_of: &dyn Fn(u32) -> Option<u64>,
    probe: &dyn Fn(u32) -> HopProbe,
) -> Option<WakeTarget> {
    let root = std::fs::canonicalize(accounts).ok()?;
    let home = std::fs::canonicalize(codex_home).ok()?;
    if home.parent() != Some(root.as_path()) {
        return None;
    }
    let name = home.file_name()?.to_str()?;
    let supervisor: u32 = name.strip_prefix("term-")?.parse().ok()?;
    if name != format!("term-{supervisor}") || supervisor <= 1 {
        return None;
    }
    let start = start_of(pid)?;
    let supervisor_start = start_of(supervisor)?;
    if !handle_dir_names_supervisor(&home, supervisor) {
        return None;
    }
    if supervisor != pid {
        // `Some(Some(_))`: reached `supervisor` from `pid`; `Some(None)` not an ancestor;
        // `None` unreadable. Only the first passes.
        let between = ancestor_path_with(supervisor, pid, parent_of, start_of)??;
        if chain_is_own_launch(&home, pid, &between, start_of, probe).is_none() {
            exec_wrapper_launch(&between, supervisor, supervisor_start, start_of, probe)?;
        }
    }
    if start_of(pid)? != start {
        return None;
    }
    let raw = launch.sqlite_home.as_deref().filter(|p| p.is_absolute())?;
    let sqlite = std::fs::canonicalize(raw).ok()?;
    if raw != sqlite || sqlite.parent() != Some(root.as_path()) {
        return None;
    }
    let name = sqlite.file_name()?.to_str()?;
    let n: u16 = name.strip_prefix("config-")?.parse().ok()?;
    let slot = crate::types::AccountNum::try_from(n).ok()?;
    if name != format!("config-{slot}") {
        return None;
    }
    if !std::fs::symlink_metadata(&sqlite)
        .ok()?
        .file_type()
        .is_dir()
    {
        return None;
    }
    Some(WakeTarget {
        pid,
        start,
        supervisor,
        supervisor_start,
        codex_home: home,
        sqlite_home: sqlite,
    })
}

/// Why a caller could not be resolved (spec 32 §2.2). Fixed, csq-authored text; no paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerError {
    /// Could not decide: never read as "not a session" (INV-31-02).
    Undetermined(String),
    /// Positively not the calling session: not an ancestor, or its pid was recycled.
    TargetMismatch,
}

/// The session a caller was proved to be running inside. Only [`resolve_caller`] builds one,
/// and its fields are private: nothing can alter the identity between proof and mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCaller {
    kind: CliKind,
    pid: u32,
    started_at: u64,
    handle_dir: PathBuf,
    /// The handle dir canonicalised DURING resolution; `None` when that failed.
    canonical: Option<PathBuf>,
    /// Full-precision start ([`ancestor_start`]) of `pid`, read right after the proof and
    /// kept only if the listed start still agrees. Set by [`resolve_caller_from_env`]; the
    /// pure resolver leaves it `None`, so a caller proved any other way binds no exact start.
    started_exact: Option<u64>,
}

impl ResolvedCaller {
    /// Which CLI.
    #[must_use]
    pub fn kind(&self) -> CliKind {
        self.kind
    }

    /// The CLI process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Its start time as listed (INV-31-01).
    #[must_use]
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Its handle dir as the process reported it.
    #[must_use]
    pub fn handle_dir(&self) -> &std::path::Path {
        &self.handle_dir
    }

    /// The messaging identity for this caller. The handle-dir hash is SHA-256 of the
    /// canonical handle dir computed at resolution; no name (a name never feeds an identity
    /// or a limit key). A handle dir that could not be canonicalised is `Undetermined`: a
    /// different path is never hashed in its place.
    pub fn verified(&self) -> Result<crate::messaging::VerifiedSession, CallerError> {
        use crate::messaging::{Sender, Surface, VerifiedSession};
        use sha2::{Digest, Sha256};
        let canon = self.canonical.as_ref().ok_or_else(|| {
            CallerError::Undetermined("the session's handle dir could not be resolved".into())
        })?;
        let dir = canon.to_string_lossy().into_owned();
        let hash = format!("{:x}", Sha256::digest(dir.as_bytes()));
        Ok(VerifiedSession::from_resolved(Sender {
            pid: self.pid,
            started_at: self.started_at,
            surface: match self.kind {
                CliKind::Claude => Surface::ClaudeCode,
                CliKind::Codex => Surface::Codex,
            },
            handle_dir_hash: hash,
            handle_dir: dir,
            name: None,
            started_exact: self.started_exact,
        }))
    }
}

/// The caller's own surface from its two handle-dir variables. Exactly one set (non-empty)
/// names it; neither or both is `Undetermined`: with both set (a Codex run from inside a
/// Claude session inherits `CLAUDE_CONFIG_DIR`) the environment cannot say which process
/// the caller is inside, and guessing would let a spoofed variable pick the identity.
pub fn caller_kind<'a>(
    claude_config_dir: Option<&'a str>,
    codex_home: Option<&'a str>,
) -> Result<(CliKind, &'a str), CallerError> {
    let c = claude_config_dir.filter(|d| !d.is_empty());
    let x = codex_home.filter(|d| !d.is_empty());
    match (c, x) {
        (Some(d), None) => Ok((CliKind::Claude, d)),
        (None, Some(d)) => Ok((CliKind::Codex, d)),
        (None, None) => Err(CallerError::Undetermined(
            "neither CLAUDE_CONFIG_DIR nor CODEX_HOME is set".into(),
        )),
        (Some(_), Some(_)) => Err(CallerError::Undetermined(
            "both CLAUDE_CONFIG_DIR and CODEX_HOME are set, so the calling surface is ambiguous"
                .into(),
        )),
    }
}

/// Resolve the calling session of `kind` (spec 32 §2.2, generalising spec 31 §5).
///
/// The caller is the UNIQUE live process of `kind` whose handle dir canonicalizes to `dir`.
/// Every owner is counted BEFORE any is dropped for lacking a start time. A restricted or
/// `incomplete` table, or any same-uid process that may be of `kind` but could not be read
/// (`unreadable`), is `Undetermined`: it may own the same dir. `dir` alone is spoofable by
/// any same-user process, so the owner must also be an ancestor of this process
/// (`ancestry`: `Some(None)` is `TargetMismatch`, `None` `Undetermined`), be the NEAREST
/// session on the way up (any `is_session` hop between is `TargetMismatch`; unreadable, gone
/// or re-used since the walk is `Undetermined`; each hop is passed as `(pid, walked start)`,
/// see `between_hop_is_session`) and its start
/// time re-read through `start_of` must still match within `START_TOLERANCE_SECS` (the pid
/// may have been recycled between listing and walk, INV-31-01).
#[allow(clippy::too_many_arguments)] // one proof per input: table, visibility, dir, three probes
pub fn resolve_caller(
    kind: CliKind,
    sessions: &[SessionInfo],
    unreadable: &[u32],
    view: Visibility,
    dir: Option<&str>,
    ancestry: &dyn Fn(u32) -> Option<Option<AncestorHops>>,
    is_session: &dyn Fn(u32, u64) -> Option<bool>,
    start_of: &dyn Fn(u32) -> Option<u64>,
) -> Result<ResolvedCaller, CallerError> {
    let undetermined = |m: &str| CallerError::Undetermined(m.to_string());
    let comm = kind.comm();
    let Some(dir) = dir.filter(|d| !d.is_empty()) else {
        return Err(undetermined(&format!("{} is not set", kind.env_key())));
    };
    if view.restricted {
        return Err(undetermined(
            "process information is restricted for this caller (a sandbox?); run csq sessions inbox/ack outside the sandbox",
        ));
    }
    if view.incomplete {
        return Err(undetermined(&format!(
            "inbox/ack cannot confirm this session here: {}",
            view.cause.map_or(
                "the process table hides processes from this caller",
                IncompleteCause::describe
            )
        )));
    }
    if !unreadable.is_empty() {
        let shown: Vec<String> = unreadable.iter().take(5).map(u32::to_string).collect();
        let more = if unreadable.len() > 5 { ", …" } else { "" };
        return Err(undetermined(&format!(
            "{} process(es) that may be a {comm} session could not be read (pid {}{more}), so the owner of this handle dir is not unique; retry, and if it persists check that process",
            unreadable.len(),
            shown.join(", ")
        )));
    }
    let canon = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let want = canon(std::path::Path::new(dir));
    let owners: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| canon(&s.config_dir) == want)
        .collect();
    let one = match owners.as_slice() {
        [] => {
            return Err(undetermined(&format!(
                "no live {comm} session owns this handle dir"
            )))
        }
        [one] => *one,
        _ => {
            return Err(undetermined(&format!(
                "more than one {comm} session owns this handle dir"
            )))
        }
    };
    let listed = one
        .started_at
        .ok_or_else(|| undetermined(&format!("the owning {comm} session has no start time")))?;
    match ancestry(one.pid) {
        Some(Some(between)) => {
            // The owner must be the NEAREST session: a session strictly between the caller
            // and the owner is where the caller really runs, and the env var naming the
            // outer one is a claim (a Codex launched from Claude A, calling as A).
            for (hop, hop_start) in between {
                match is_session(hop, hop_start) {
                    Some(false) => {}
                    Some(true) => {
                        tracing::warn!(
                            pid = one.pid,
                            reason = "nested_session",
                            "calling session refused: a nearer session sits between"
                        );
                        return Err(CallerError::TargetMismatch);
                    }
                    None => {
                        return Err(undetermined(
                            "a process between the caller and the session could not be classified",
                        ));
                    }
                }
            }
        }
        Some(None) => {
            tracing::warn!(
                pid = one.pid,
                reason = "caller_not_descendant",
                "calling session refused: not an ancestor of this process"
            );
            return Err(CallerError::TargetMismatch);
        }
        None => {
            tracing::warn!(
                pid = one.pid,
                reason = "ancestry_unreadable",
                "calling session undetermined: parent chain unreadable"
            );
            return Err(undetermined(
                "the caller's process ancestry could not be read",
            ));
        }
    }
    match start_of(one.pid) {
        Some(now_start) if same_start(now_start, listed) => Ok(ResolvedCaller {
            kind,
            pid: one.pid,
            started_at: listed,
            handle_dir: one.config_dir.clone(),
            canonical: std::fs::canonicalize(&one.config_dir).ok(),
            started_exact: None,
        }),
        Some(_) => {
            tracing::warn!(
                pid = one.pid,
                reason = "start_time_changed",
                "calling session refused: pid was recycled"
            );
            Err(CallerError::TargetMismatch)
        }
        None => Err(undetermined(&format!(
            "the owning {comm} session's start time could not be re-read"
        ))),
    }
}

/// Resolve the caller from the real environment and process table: the surface from
/// [`caller_kind`], the table from [`try_list_detailed_kind`] (`None` is `Undetermined`).
pub fn resolve_caller_from_env() -> Result<ResolvedCaller, CallerError> {
    let claude = std::env::var("CLAUDE_CONFIG_DIR").ok();
    let codex = std::env::var("CODEX_HOME").ok();
    let (kind, dir) = caller_kind(claude.as_deref(), codex.as_deref())?;
    let listing = try_list_detailed_kind(kind)
        .ok_or_else(|| CallerError::Undetermined("live sessions could not be enumerated".into()))?;
    #[cfg(unix)]
    if kind == CliKind::Codex
        && crate::providers::codex::managed_backend::is_configured(Path::new(dir))
    {
        if listing.restricted || listing.incomplete || !listing.unreadable_pids.is_empty() {
            return Err(CallerError::Undetermined(
                "managed caller process visibility is incomplete".into(),
            ));
        }
        let mapped = crate::providers::codex::managed_backend::resolve_managed_caller(
            Path::new(dir),
            std::time::Duration::from_secs(2),
        )
        .map_err(|_| {
            CallerError::Undetermined(
                "managed caller binding or ancestry could not be verified".into(),
            )
        })?;
        if let Some(mapped) = mapped {
            return mapped_caller_from_listing(&mapped, &listing.sessions);
        }
    }
    let mut caller = resolve_caller(
        kind,
        &listing.sessions,
        &listing.unreadable_pids,
        listing.visibility(),
        Some(dir),
        &ancestor_path_of_current,
        &is_session_hop,
        &process_start_time,
    )?;
    caller.started_exact = exact_start_if_unchanged(caller.pid, caller.started_at);
    Ok(caller)
}

/// The authenticated backend is an implementation role, not a second terminal.
/// Every other owner still counts before missing starts are discarded.
#[cfg(unix)]
pub(crate) fn mapped_caller_from_listing(
    mapped: &crate::providers::codex::managed_backend::ManagedCaller,
    sessions: &[SessionInfo],
) -> Result<ResolvedCaller, CallerError> {
    let mut recipient_seen = false;
    for session in sessions {
        let home = session.config_dir.canonicalize().map_err(|_| {
            CallerError::Undetermined("listed handle identity could not be resolved".into())
        })?;
        let same_handle = home == mapped.handle_dir();
        if !same_handle {
            continue;
        }
        if session.pid == mapped.native().pid {
            if ancestor_start(session.pid) != Some(mapped.native().started_exact) {
                return Err(CallerError::Undetermined(
                    "managed backend listing changed".into(),
                ));
            }
            continue;
        }
        if session.pid != mapped.recipient().pid
            || recipient_seen
            || session
                .started_at
                .is_none_or(|start| !same_start(start, mapped.started_at()))
        {
            return Err(CallerError::Undetermined(
                "managed recipient owner is not unique".into(),
            ));
        }
        recipient_seen = true;
    }
    if !recipient_seen || mapped.recipient().verify().is_err() || mapped.native().verify().is_err()
    {
        return Err(CallerError::Undetermined(
            "managed recipient listing or incarnation unavailable".into(),
        ));
    }
    Ok(ResolvedCaller {
        kind: CliKind::Codex,
        pid: mapped.recipient().pid,
        started_at: mapped.started_at(),
        handle_dir: mapped.handle_dir().to_path_buf(),
        canonical: Some(mapped.handle_dir().to_path_buf()),
        started_exact: Some(mapped.recipient().started_exact),
    })
}

/// [`ancestor_start`] of `pid`, bracketed by the listed-seconds reading: kept only when
/// `process_start_time` agrees with `listed` (within `START_TOLERANCE_SECS`) both before and
/// after the exact read, so the value belongs to the incarnation `listed` names. Any
/// unreadable or disagreeing reading is `None`, which downstream means "no exact binding".
fn exact_start_if_unchanged(pid: u32, listed: u64) -> Option<u64> {
    exact_start_bracketed(&process_start_time, &ancestor_start, pid, listed)
}

fn exact_start_bracketed(
    secs_of: &dyn Fn(u32) -> Option<u64>,
    exact_of: &dyn Fn(u32) -> Option<u64>,
    pid: u32,
    listed: u64,
) -> Option<u64> {
    let agrees = || secs_of(pid).is_some_and(|s| same_start(s, listed));
    if !agrees() {
        return None;
    }
    let exact = exact_of(pid)?;
    agrees().then_some(exact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// A root ancestor whose start comes from a fallback reader (macOS sysctl) is still
    /// start-checked: an earlier start continues the walk to a verdict, a LATER start than its
    /// child is a reused pid and undetermined, and an unreadable start is undetermined.
    #[test]
    fn a_foreign_ancestor_keeps_its_start_check() {
        // me=10 -> 20 -> 30 (root login) -> 40 -> 1
        let parents = chain(&[(10, 20), (20, 30), (30, 40), (40, 1)]);
        let starts = |p: u32| match p {
            10 => Some(1000),
            20 => Some(990),
            30 => Some(950),
            40 => Some(900),
            _ => None,
        };
        assert_eq!(is_ancestor_with(99, 10, &parents, &starts), Some(false));
        assert_eq!(is_ancestor_with(40, 10, &parents, &starts), Some(true));
        let later = |p: u32| if p == 30 { Some(5000) } else { starts(p) };
        assert_eq!(is_ancestor_with(99, 10, &parents, &later), None);
        assert_eq!(is_ancestor_with(40, 10, &parents, &later), None);
        let unreadable = |p: u32| if p == 30 { None } else { starts(p) };
        assert_eq!(is_ancestor_with(99, 10, &parents, &unreadable), None);
    }

    /// A hop's pid reused between reading its start and reading its parent: the second
    /// read of that hop's start differs, so the walk is undetermined instead of following
    /// the new process's parent to a target that is not an ancestor. Control: a stable
    /// start reaches the target.
    #[test]
    fn a_hop_reused_between_its_start_and_parent_reads_is_undetermined() {
        use std::cell::Cell;
        // me=10 -> 20 -> (20 dies, pid reused by a child of 40) -> 40 (the target)
        let parents = chain(&[(10, 20), (20, 40), (40, 1)]);
        let reads = Cell::new(0u32);
        let reused = |p: u32| match p {
            10 => Some(1000),
            20 => {
                reads.set(reads.get() + 1);
                // first read: the real ancestor; later reads: the reusing process
                Some(if reads.get() == 1 { 990 } else { 1005 })
            }
            40 => Some(900),
            _ => None,
        };
        assert_eq!(is_ancestor_with(40, 10, &parents, &reused), None);
        let stable = |p: u32| match p {
            10 => Some(1000),
            20 => Some(990),
            40 => Some(900),
            _ => None,
        };
        assert_eq!(
            is_ancestor_with(40, 10, &parents, &stable),
            Some(true),
            "control"
        );
    }

    fn chain(pairs: &[(u32, u32)]) -> impl Fn(u32) -> Option<u32> {
        let m: HashMap<u32, u32> = pairs.iter().copied().collect();
        move |p| m.get(&p).copied()
    }

    /// Every pid started at t=1000 unless listed: parents never start after children.
    fn starts(pairs: &[(u32, u64)]) -> impl Fn(u32) -> Option<u64> {
        let m: HashMap<u32, u64> = pairs.iter().copied().collect();
        move |p| Some(m.get(&p).copied().unwrap_or(1000))
    }

    #[test]
    fn ancestry_chain_reaches_the_pid() {
        let f = chain(&[(100, 90), (90, 80), (80, 1)]);
        let st = starts(&[(100, 3000), (90, 2000), (80, 1000)]);
        assert_eq!(is_ancestor_with(80, 100, &f, &st), Some(true));
        assert_eq!(is_ancestor_with(90, 100, &f, &st), Some(true));
    }

    #[test]
    fn ancestry_chain_ends_at_init_without_reaching_the_pid() {
        let f = chain(&[(100, 90), (90, 80), (80, 1)]);
        let st = starts(&[]);
        assert_eq!(is_ancestor_with(55, 100, &f, &st), Some(false));
        let g = chain(&[(100, 0)]);
        assert_eq!(is_ancestor_with(55, 100, &g, &st), Some(false));
    }

    #[test]
    fn ancestry_cycle_is_false_not_a_hang() {
        let f = chain(&[(100, 90), (90, 80), (80, 90)]);
        assert_eq!(is_ancestor_with(55, 100, &f, &starts(&[])), Some(false));
    }

    #[test]
    fn ancestry_read_failure_is_none() {
        let st = starts(&[]);
        // 90's parent is unreadable before the pid is reached
        let f = chain(&[(100, 90)]);
        assert_eq!(is_ancestor_with(55, 100, &f, &st), None);
        // our own parent is unreadable
        assert_eq!(is_ancestor_with(55, 100, &chain(&[]), &st), None);
        // a start time is unreadable (Windows: dead parent) -> undetermined, not a verdict
        let no_start = |p: u32| if p == 90 { None } else { Some(1000) };
        let f = chain(&[(100, 90), (90, 80)]);
        assert_eq!(is_ancestor_with(80, 100, &f, &no_start), None);
    }

    #[test]
    fn ancestry_reused_parent_pid_with_later_start_is_none_never_true() {
        // 90 is named as 100's parent but started AFTER 100: the pid was reused.
        let f = chain(&[(100, 90), (90, 1)]);
        let st = starts(&[(100, 1000), (90, 5000)]);
        assert_eq!(is_ancestor_with(90, 100, &f, &st), None);
        assert_eq!(is_ancestor_with(55, 100, &f, &st), None);
        // no tolerance: equal starts are the same instant (parent may equal child)...
        let st = starts(&[(100, 1000), (90, 1000)]);
        assert_eq!(is_ancestor_with(90, 100, &f, &st), Some(true));
        // ...but ONE unit later is a reused pid
        let st = starts(&[(100, 1000), (90, 1001)]);
        assert_eq!(is_ancestor_with(90, 100, &f, &st), None);
    }

    /// Sub-second precision: units are microseconds here. A parent pid reused within the
    /// SAME second as the child (equal whole seconds, later microseconds) is `None` for the
    /// order check; a hop reused within the same second between its start read and its
    /// re-read (equal seconds, different microseconds) is `None` for the re-read.
    #[test]
    fn a_reuse_within_the_same_second_is_undetermined() {
        use std::cell::Cell;
        let secs = 1_700_000_000u64 * 1_000_000;
        let f = chain(&[(100, 90), (90, 1)]);
        let late = |p: u32| Some(if p == 100 { secs + 100 } else { secs + 900_000 });
        assert_eq!(is_ancestor_with(90, 100, &f, &late), None, "order check");
        assert_eq!(is_ancestor_with(55, 100, &f, &late), None, "order check");
        let ok = |p: u32| Some(if p == 100 { secs + 900_000 } else { secs + 100 });
        assert_eq!(is_ancestor_with(90, 100, &f, &ok), Some(true), "control");

        let g = chain(&[(100, 90), (90, 80), (80, 1)]);
        let reads = Cell::new(0u32);
        let reread = |p: u32| match p {
            100 => Some(secs + 900_000),
            90 => {
                reads.set(reads.get() + 1);
                Some(secs + if reads.get() == 1 { 100 } else { 200 })
            }
            _ => Some(secs),
        };
        assert_eq!(is_ancestor_with(80, 100, &g, &reread), None, "re-read");
    }

    #[test]
    fn ancestry_hop_cap_is_none_and_reads_no_parent_past_it() {
        // a long non-cyclic chain that never reaches the pid nor init
        let reads = std::cell::Cell::new(0usize);
        let f = |p: u32| {
            reads.set(reads.get() + 1);
            Some(p + 1)
        };
        let st = |_p: u32| Some(1000u64);
        assert_eq!(is_ancestor_with(1_000_000, 100, &f, &st), None);
        // one read for me's parent, then one per hop except the last
        assert_eq!(reads.get(), MAX_ANCESTRY_HOPS);
    }

    #[test]
    fn this_processs_own_parent_chain_is_readable() {
        let me = std::process::id();
        assert!(parent_pid(me).is_some(), "own parent readable");
        let own = is_ancestor_of_current(me);
        let parent = parent_pid(me).unwrap();
        let par = is_ancestor_of_current(parent);
        if cfg!(windows) {
            // Windows does not reparent orphans: the chain may legitimately end in an
            // unreadable (dead) parent, which is undetermined, never a false verdict.
            assert!(matches!(own, Some(false) | None), "own: {own:?}");
            assert!(matches!(par, Some(true) | None), "parent: {par:?}");
        } else {
            // Our own pid is never our ancestor. The walk to init may still stop at an
            // ancestor whose start time this user cannot read (a root-owned sshd when the
            // tests run over a remote session), which is undetermined (`None`), never a
            // false verdict; what must never happen is `Some(true)`.
            assert!(matches!(own, Some(false) | None), "own: {own:?}");
            // our direct parent is reached on the first hop
            assert_eq!(par, Some(true));
        }
    }

    /// The exact start is kept only when the seconds reading agrees before AND after the
    /// exact read. Falsifier: returning `exact_of(pid)` unconditionally fails the middle
    /// three cases.
    #[test]
    fn exact_start_is_bound_only_to_the_incarnation_the_listed_start_names() {
        use std::cell::Cell;
        let exact = |_: u32| Some(123_456_789);
        assert_eq!(
            exact_start_bracketed(&|_| Some(1_000), &exact, 7, 1_000),
            Some(123_456_789)
        );
        assert_eq!(
            exact_start_bracketed(&|_| Some(1_005), &exact, 7, 1_000),
            None
        );
        assert_eq!(exact_start_bracketed(&|_| None, &exact, 7, 1_000), None);
        assert_eq!(
            exact_start_bracketed(&|_| Some(1_000), &|_| None, 7, 1_000),
            None
        );
        // Recycled between the first and the second seconds reading.
        let n = Cell::new(0);
        let flip = |_: u32| {
            n.set(n.get() + 1);
            Some(if n.get() == 1 { 1_000 } else { 2_000 })
        };
        assert_eq!(exact_start_bracketed(&flip, &exact, 7, 1_000), None);
    }

    #[test]
    fn same_start_tolerates_one_second_and_no_more() {
        assert!(same_start(100, 100));
        assert!(same_start(100, 101));
        assert!(same_start(101, 100));
        assert!(!same_start(100, 102));
        assert!(!same_start(102, 100));
    }

    #[test]
    fn process_start_time_of_this_process_matches_the_listing_reader() {
        let me = std::process::id();
        let t = process_start_time(me).expect("own start time is readable");
        assert!(t > 1_600_000_000, "unix seconds, got {t}");
        let again = process_start_time(me).expect("own start time is readable");
        assert!(
            same_start(t, again),
            "same process across reads: {t} vs {again}"
        );
    }

    #[test]
    fn extract_account_id_valid() {
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("/a/b/config-5")),
            Some(5)
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-999")),
            Some(999)
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-1")),
            Some(1)
        );
    }

    #[test]
    fn extract_account_id_rejects_out_of_range() {
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-0")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-1000")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-99999")),
            None
        );
    }

    #[test]
    fn extract_account_id_rejects_bad_shape() {
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-abc")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("config-")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("other-5")),
            None
        );
        assert_eq!(
            SessionInfo::extract_account_id(&PathBuf::from("/a/b/")),
            None
        );
    }

    #[test]
    fn session_info_for_pid_is_none_for_a_non_claude_process() {
        // This test binary is not `claude`, whatever env it carries.
        assert_eq!(session_info_for_pid(std::process::id()), Ok(None));
        assert_eq!(session_info_for_pid(4_000_000), Ok(None));
    }

    #[test]
    fn list_does_not_panic() {
        // Smoke test — the important invariant is that `list()`
        // never panics on a live system, even when the platform
        // backend encounters unexpected state (permission errors,
        // short-lived child processes, missing /proc entries).
        let _ = list();
    }

    // ── parse_term_session_id ──────────────────────────────

    #[test]
    fn parse_term_session_id_full_iterm_format() {
        let (w, t, p) = parse_term_session_id("w3t2p0:3B8385EC-9D2C-4E26-A416-2E04BCA60DA3");
        assert_eq!(w, Some(3));
        assert_eq!(t, Some(2));
        assert_eq!(p, Some(0));
    }

    #[test]
    fn parse_term_session_id_multi_digit_indices() {
        // Users with 10+ tabs are a thing.
        let (w, t, p) = parse_term_session_id("w12t45p3:abc");
        assert_eq!(w, Some(12));
        assert_eq!(t, Some(45));
        assert_eq!(p, Some(3));
    }

    #[test]
    fn parse_term_session_id_missing_prefix_returns_none() {
        assert_eq!(
            parse_term_session_id("not-iterm-format"),
            (None, None, None)
        );
        assert_eq!(parse_term_session_id(""), (None, None, None));
    }

    #[test]
    fn parse_term_session_id_partial_prefix() {
        // Window only — still useful, return what we have.
        let (w, t, p) = parse_term_session_id("w3:abc");
        assert_eq!(w, Some(3));
        assert_eq!(t, None);
        assert_eq!(p, None);
    }

    #[test]
    fn parse_term_session_id_no_uuid_part() {
        // Valid prefix but no colon/uuid — still parses the prefix.
        let (w, t, p) = parse_term_session_id("w1t1p0");
        assert_eq!(w, Some(1));
        assert_eq!(t, Some(1));
        assert_eq!(p, Some(0));
    }

    #[test]
    fn parse_term_session_id_rejects_huge_numbers() {
        // u8 overflow — takes what fits and stops.
        let (w, _, _) = parse_term_session_id("w99999t1p1:abc");
        assert_eq!(w, None); // 99999 > u8::MAX
    }

    // ---- spec 32 §2.2: surface-generalised caller resolution, launch parsing ----

    fn cli_session(pid: u32, dir: &str, started_at: Option<u64>) -> SessionInfo {
        SessionInfo {
            pid,
            cwd: PathBuf::from("/"),
            config_dir: PathBuf::from(dir),
            account_id: None,
            started_at,
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        }
    }

    fn resolve(
        kind: CliKind,
        sessions: &[SessionInfo],
        unreadable: &[u32],
        view: Visibility,
        anc: Option<bool>,
        start: Option<u64>,
    ) -> Result<ResolvedCaller, CallerError> {
        resolve_caller(
            kind,
            sessions,
            unreadable,
            view,
            Some("/nonexistent-csq-test/term-9"),
            &move |_| anc.map(|b| b.then(Vec::new)),
            &|_, _| Some(false),
            &move |_| start,
        )
    }

    const D: &str = "/nonexistent-csq-test/term-9";

    fn is_undetermined<T: std::fmt::Debug>(r: Result<T, CallerError>) -> bool {
        matches!(r, Err(CallerError::Undetermined(_)))
    }

    #[test]
    fn codex_caller_resolves_to_the_unique_native_process_and_a_verified_codex_session() {
        let tmp = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(tmp.path()).unwrap();
        let real_s = real.to_string_lossy().into_owned();
        let s = [
            cli_session(50, &real_s, Some(100)),
            cli_session(51, "/other", Some(100)),
        ];
        let go = |kind| {
            resolve_caller(
                kind,
                &s,
                &[],
                Visibility::WHOLE,
                Some(&real_s),
                &|_| Some(Some(Vec::new())),
                &|_, _| Some(false),
                &|_| Some(100),
            )
        };
        let r = go(CliKind::Codex).expect("resolved");
        assert_eq!(
            (r.kind(), r.pid(), r.started_at()),
            (CliKind::Codex, 50, 100)
        );
        let v = r.verified().unwrap();
        let sender = v.sender();
        assert_eq!(sender.surface, crate::messaging::Surface::Codex);
        assert_eq!(sender.pid, 50);
        assert_eq!(sender.handle_dir, real_s);
        assert_eq!(sender.handle_dir_hash.len(), 64);
        assert!(sender
            .handle_dir_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sender.name, None);
        let c = go(CliKind::Claude).unwrap().verified().unwrap();
        assert_eq!(c.sender().surface, crate::messaging::Surface::ClaudeCode);
    }

    #[test]
    fn no_match_two_matches_unreadable_peer_and_blind_tables_are_undetermined() {
        let ok = |s: &[SessionInfo], un: &[u32], v: Visibility| {
            resolve(CliKind::Codex, s, un, v, Some(true), Some(100))
        };
        assert!(is_undetermined(ok(&[], &[], Visibility::WHOLE)), "no match");
        let two = [cli_session(1, D, Some(100)), cli_session(2, D, Some(100))];
        assert!(is_undetermined(ok(&two, &[], Visibility::WHOLE)), "two");
        // two owners are ambiguous even when only one has a start time
        let two_one_untimed = [cli_session(1, D, Some(100)), cli_session(2, D, None)];
        assert!(is_undetermined(ok(
            &two_one_untimed,
            &[],
            Visibility::WHOLE
        )));
        let one = [cli_session(1, D, Some(100))];
        assert!(
            is_undetermined(ok(&one, &[777], Visibility::WHOLE)),
            "unreadable"
        );
        let blind = Visibility {
            restricted: false,
            incomplete: true,
            cause: None,
        };
        assert!(is_undetermined(ok(&one, &[], blind)), "incomplete table");
        let sandbox = Visibility {
            restricted: true,
            incomplete: false,
            cause: None,
        };
        assert!(is_undetermined(ok(&one, &[], sandbox)), "restricted");
        assert!(is_undetermined(ok(
            &[cli_session(1, D, None)],
            &[],
            Visibility::WHOLE
        )));
        assert!(is_undetermined(resolve_caller(
            CliKind::Codex,
            &one,
            &[],
            Visibility::WHOLE,
            None,
            &|_| Some(Some(Vec::new())),
            &|_, _| Some(false),
            &|_| Some(100)
        )));
    }

    #[test]
    fn a_caller_not_descended_or_recycled_is_target_mismatch_and_unreadable_is_undetermined() {
        let one = [cli_session(1, D, Some(100))];
        let go = |anc, start| resolve(CliKind::Codex, &one, &[], Visibility::WHOLE, anc, start);
        assert_eq!(go(Some(false), Some(100)), Err(CallerError::TargetMismatch));
        assert_eq!(
            go(Some(true), Some(5000)),
            Err(CallerError::TargetMismatch),
            "recycled"
        );
        assert!(is_undetermined(go(None, Some(100))), "ancestry unreadable");
        assert!(is_undetermined(go(Some(true), None)), "start unreadable");
        assert!(
            go(Some(true), Some(101)).is_ok(),
            "within START_TOLERANCE_SECS"
        );
    }

    #[test]
    fn the_calling_surface_is_the_one_variable_set_and_both_or_neither_is_undetermined() {
        assert_eq!(caller_kind(Some("/c"), None), Ok((CliKind::Claude, "/c")));
        assert_eq!(caller_kind(None, Some("/x")), Ok((CliKind::Codex, "/x")));
        assert_eq!(
            caller_kind(Some(""), Some("/x")),
            Ok((CliKind::Codex, "/x"))
        );
        assert!(is_undetermined(caller_kind(None, None)));
        assert!(is_undetermined(caller_kind(Some("/c"), Some("/x"))));
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    fn absolute_sqlite_home_fixture(path: &str) -> String {
        // Windows requires a drive as well as a root; argv accepts forward slashes.
        let path = if cfg!(windows) {
            format!("C:{path}")
        } else {
            path.to_owned()
        };
        assert!(std::path::Path::new(&path).is_absolute(), "{path}");
        assert!(!path.contains('\\'), "fixture must be unescaped: {path}");
        path
    }

    #[cfg(unix)]
    #[test]
    fn queue_is_the_subcommand_after_the_config_pairs_and_nothing_else() {
        assert!(is_queue_invocation(&argv(&[
            "codex", "queue", "--thread", "x"
        ])));
        assert!(is_queue_invocation(&argv(&[
            "codex",
            "-c",
            "sqlite_home=/h",
            "queue",
            "--message",
            "m"
        ])));
        assert!(is_queue_invocation(&argv(&[
            "codex",
            "--config=a=b",
            "-c",
            "c=d",
            "queue"
        ])));
        assert!(!is_queue_invocation(&argv(&["codex"])));
        assert!(!is_queue_invocation(&argv(&["codex", "resume", "queue"])));
        assert!(!is_queue_invocation(&argv(&["codex", "exec", "queue"])));
        assert!(!is_queue_invocation(&argv(&["codex", "-c", "queue"])));
        assert!(!is_queue_invocation(&argv(&["codex", "--model", "queue"])));
    }

    #[test]
    fn codex_launch_is_read_from_the_measured_argv_shape() {
        let t = "0199d3a2-7b1c-7c3e-8a55-0f2d9c4e1b77";
        let config_3 = absolute_sqlite_home_fixture("/a/config-3");
        let l = parse_codex_launch(&argv(&[
            "codex",
            "-c",
            &format!("sqlite_home=\"{config_3}\""),
            "--dangerously-bypass-approvals-and-sandbox",
            "resume",
            t,
        ]));
        assert_eq!(l.thread_id.as_deref(), Some(t));
        assert_eq!(l.sqlite_home, Some(PathBuf::from(config_3)));
        // uppercase UUID is normalised; `--config=` form; last sqlite_home wins
        let first = absolute_sqlite_home_fixture("/b");
        let last = absolute_sqlite_home_fixture("/c");
        let l = parse_codex_launch(&argv(&[
            "codex",
            &format!("--config=sqlite_home='{first}'"),
            "-c",
            &format!("sqlite_home={last}"),
            "resume",
            &t.to_uppercase(),
        ]));
        assert_eq!(l.thread_id.as_deref(), Some(t));
        assert_eq!(l.sqlite_home, Some(PathBuf::from(last)));
        // not a thread: `--last`, a non-UUID, nothing after resume, a fresh launch
        for a in [
            argv(&["codex", "resume", "--last"]),
            argv(&["codex", "resume", "not-a-uuid"]),
            argv(&["codex", "resume"]),
            argv(&["codex"]),
        ] {
            assert_eq!(parse_codex_launch(&a).thread_id, None, "{a:?}");
        }
    }

    #[test]
    fn prompt_text_after_resume_or_a_double_dash_cannot_inject_a_sqlite_home() {
        let t = "0199d3a2-7b1c-7c3e-8a55-0f2d9c4e1b77";
        let l = parse_codex_launch(&argv(&["codex", "resume", t, "-c", "sqlite_home=/evil"]));
        assert_eq!(l.sqlite_home, None);
        let l = parse_codex_launch(&argv(&["codex", "--", "-c", "sqlite_home=/evil"]));
        assert_eq!(l.sqlite_home, None);
        // a bare value with no `-c` before it is not a config flag
        assert_eq!(
            parse_codex_launch(&argv(&["codex", "sqlite_home=/x"])).sqlite_home,
            None
        );
        // an empty or control-character value is dropped, not stored
        assert_eq!(
            parse_codex_launch(&argv(&["codex", "-c", "sqlite_home="])).sqlite_home,
            None
        );
        assert_eq!(
            parse_codex_launch(&argv(&["codex", "-c", "sqlite_home=/a\nb"])).sqlite_home,
            None
        );
    }

    // ---- S2b: nearest-session ancestry, identity mint, launch binding ----

    /// caller(10) -> B(20, codex) -> A(30, claude): the walk returns what lies strictly
    /// between the caller and the claimed owner.
    #[test]
    fn the_ancestor_path_names_every_process_between_caller_and_owner() {
        let parents = chain(&[(10, 15), (15, 20), (20, 25), (25, 30), (30, 1)]);
        let starts = |p: u32| match p {
            10 => Some(1000u64),
            15 => Some(900),
            20 => Some(800),
            25 => Some(700),
            30 => Some(600),
            _ => None,
        };
        assert_eq!(
            ancestor_path_with(30, 10, &parents, &starts),
            Some(Some(vec![(15, 900), (20, 800), (25, 700)]))
        );
        assert_eq!(
            ancestor_path_with(15, 10, &parents, &starts),
            Some(Some(vec![]))
        );
        assert_eq!(ancestor_path_with(99, 10, &parents, &starts), Some(None));
    }

    /// Resolve `claimed` as the owner with `between` the processes the walk found between
    /// the caller and it, of which `sessions` are themselves sessions.
    fn nested(between: Vec<u32>, sessions: &'static [u32]) -> Result<ResolvedCaller, CallerError> {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_string_lossy().into_owned();
        let owners = [cli_session(30, &dir, Some(100))];
        resolve_caller(
            CliKind::Claude,
            &owners,
            &[],
            Visibility::WHOLE,
            Some(&dir),
            &move |_| Some(Some(between.iter().map(|h| (*h, 1)).collect())),
            &move |h, _| Some(sessions.contains(&h)),
            &|_| Some(100),
        )
    }

    #[test]
    fn a_nested_session_cannot_claim_its_parent_session() {
        // caller -> shell 15 -> codex B 20 -> shell 25 -> claude A 30; caller claims A
        assert_eq!(
            nested(vec![15, 20, 25], &[20]),
            Err(CallerError::TargetMismatch)
        );
        // control: claiming B (only a shell between) resolves
        assert!(nested(vec![15], &[20]).is_ok(), "control: nearest session");
        // control: nothing but shells between resolves
        assert!(nested(vec![15, 20, 25], &[]).is_ok());
    }

    #[test]
    fn an_unclassifiable_hop_between_is_undetermined_not_a_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_string_lossy().into_owned();
        let owners = [cli_session(30, &dir, Some(100))];
        let r = resolve_caller(
            CliKind::Claude,
            &owners,
            &[],
            Visibility::WHOLE,
            Some(&dir),
            &|_| Some(Some(vec![(15, 1)])),
            &|_, _| None,
            &|_| Some(100),
        );
        assert!(is_undetermined(r));
    }

    #[test]
    fn verified_hashes_the_path_canonicalised_at_resolution_and_never_a_fallback() {
        // an unresolvable handle dir resolves (directives need only pid/start) but cannot mint
        let r = resolve(
            CliKind::Codex,
            &[cli_session(50, D, Some(100))],
            &[],
            Visibility::WHOLE,
            Some(true),
            Some(100),
        )
        .unwrap();
        assert!(is_undetermined(r.verified()));
        // a symlinked handle dir hashes its TARGET
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        #[cfg(unix)]
        {
            let link = tmp.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let l = link.to_string_lossy().into_owned();
            let r = resolve_caller(
                CliKind::Codex,
                &[cli_session(50, &l, Some(100))],
                &[],
                Visibility::WHOLE,
                Some(&l),
                &|_| Some(Some(Vec::new())),
                &|_, _| Some(false),
                &|_| Some(100),
            )
            .unwrap();
            let v = r.verified().unwrap();
            assert_eq!(
                v.sender().handle_dir,
                std::fs::canonicalize(&real).unwrap().to_string_lossy()
            );
        }
    }

    #[test]
    fn codex_launch_is_read_only_for_the_exact_incarnation() {
        use std::cell::Cell;
        let home = absolute_sqlite_home_fixture("/a");
        let argv = || Some(argv(&["codex", "-c", &format!("sqlite_home={home}")]));
        let same = || Some(7_000_000u64);
        const X: u64 = 7_000_000;
        let ok = codex_launch_checked(100, X, &|| Some(100), &same, &|| true, &argv);
        assert_eq!(ok.unwrap().sqlite_home, Some(PathBuf::from(&home)));
        // listed start is not the session's (recycled pid)
        assert!(codex_launch_checked(100, X, &|| Some(5000), &same, &|| true, &argv).is_none());
        // not a codex
        assert!(codex_launch_checked(100, X, &|| Some(100), &same, &|| false, &argv).is_none());
        // argv unreadable / starts unreadable
        assert!(codex_launch_checked(100, X, &|| Some(100), &same, &|| true, &|| None).is_none());
        assert!(codex_launch_checked(100, X, &|| None, &same, &|| true, &argv).is_none());
        assert!(codex_launch_checked(100, X, &|| Some(100), &|| None, &|| true, &argv).is_none());
        // the exact start changes across the argv read (recycled mid-read)
        let n = Cell::new(0);
        let flip = || {
            n.set(n.get() + 1);
            Some(if n.get() == 1 { 7_000_000 } else { 7_000_001 })
        };
        assert!(
            codex_launch_checked(100, 7_000_000, &|| Some(100), &flip, &|| true, &argv).is_none()
        );
    }

    /// N4: the argv read is bound to the LISTED incarnation at full precision. A different
    /// `codex` that took the pid inside the same whole second passes `same_start` and is
    /// stable across the bracket, yet its exact start is not the listed one: refused.
    #[test]
    fn a_pid_reused_within_the_same_second_as_the_listed_session_is_refused() {
        let argv = || Some(argv(&["codex", "-c", "sqlite_home=/a"]));
        let secs = 1_700_000_000u64;
        let listed_exact = 1_700_000_000_000_100u64;
        let impostor = || Some(1_700_000_000_000_500u64); // same second, stable, different
        let live = || Some(secs);
        assert!(same_start(secs, secs), "the seconds check cannot see it");
        assert!(
            codex_launch_checked(secs, listed_exact, &live, &impostor, &|| true, &argv).is_none(),
            "reused within the same second"
        );
        let genuine = || Some(listed_exact);
        assert!(
            codex_launch_checked(secs, listed_exact, &live, &genuine, &|| true, &argv).is_some(),
            "control: the listed incarnation"
        );
    }

    /// N4: the lookup and its exact start are one incarnation, or `Undetermined`.
    #[test]
    fn the_exact_start_lookup_is_one_incarnation_or_undetermined() {
        use std::cell::Cell;
        let found = || Ok(Some(cli_session(5, "/h", Some(100))));
        let stable = || Some(42u64);
        let got = session_info_exact_with(&found, &stable).unwrap().unwrap();
        assert_eq!((got.0.pid, got.1), (5, 42));
        assert_eq!(session_info_exact_with(&|| Ok(None), &|| None), Ok(None));
        assert!(
            session_info_exact_with(&found, &|| None).is_err(),
            "unreadable"
        );
        let n = Cell::new(0u64);
        let moving = || {
            n.set(n.get() + 1);
            Some(n.get())
        };
        assert!(session_info_exact_with(&found, &moving).is_err(), "changed");
        assert!(session_info_exact_with(&|| Err(Undetermined), &stable).is_err());
    }

    /// The bracket is exact: a reuse inside the SAME whole second (what the second-resolution
    /// `start_of` and `same_start`'s one-second tolerance cannot see) is refused.
    #[test]
    fn a_pid_reused_within_the_same_second_is_refused_by_the_launch_bracket() {
        use std::cell::Cell;
        let argv = || Some(argv(&["codex", "-c", "sqlite_home=/a"]));
        let n = Cell::new(0);
        // micros: 1_700_000_000.100000 then 1_700_000_000.900000 — the same second
        let exact = || {
            n.set(n.get() + 1);
            Some(1_700_000_000_000_000 + if n.get() == 1 { 100_000 } else { 900_000 })
        };
        assert!(codex_launch_checked(
            1_700_000_000,
            1_700_000_000_000_100,
            &|| Some(1_700_000_000),
            &exact,
            &|| true,
            &argv
        )
        .is_none());
    }

    fn wake_launch(p: Option<&std::path::Path>) -> CodexLaunch {
        CodexLaunch {
            thread_id: None,
            sqlite_home: p.map(PathBuf::from),
        }
    }

    /// accounts/{term-7,term-8,config-3} under a CANONICAL temp root.
    fn wake_fixture() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let acc = root.join("accounts");
        for d in ["term-7", "term-8", "config-3"] {
            std::fs::create_dir_all(acc.join(d)).unwrap();
        }
        // `csq run` writes `.live-pid` = the supervisor pid it names the dir after.
        std::fs::write(acc.join("term-7").join(".live-pid"), "7").unwrap();
        std::fs::write(acc.join("term-8").join(".live-pid"), "8").unwrap();
        // The supervisor records its spawned child; the default is the direct native codex 70.
        set_child(&acc, 70);
        (tmp, acc)
    }

    fn set_child(acc: &std::path::Path, pid: u32) {
        std::fs::write(acc.join("term-7").join(".live-cc-pid"), pid.to_string()).unwrap();
    }

    /// Process table for the wake tests (pid, parent, start): 7 and 8 are two live csq
    /// supervisors; 70 is the native codex under supervisor 7; 71 is an npm node wrapper
    /// under 7 with native codex 72 under it; 80 is the native codex under supervisor 8.
    /// Pid 7 is also the swap-exec shape: Codex itself holding `term-7`.
    ///
    /// Nested shapes, all under supervisor 7 (see [`wake_probe`] for the images): 73 is a
    /// `claude`, 74 a shell and 75 a Codex a tool started inside it; 76/77 a shell and a
    /// Codex started under the native codex 70; 78 a shell and 79 a node wrapper with Codex
    /// 90 under it, started under the native codex 72; 83 is an unreadable hop directly under
    /// the supervisor with Codex 84 under it.
    const WAKE_TABLE: [(u32, u32, u64); 18] = [
        (7, 1, 100),
        (8, 1, 100),
        (70, 7, 200),
        (71, 7, 200),
        (72, 71, 210),
        (80, 8, 200),
        (99, 1, 300),
        (73, 7, 200),
        (74, 73, 210),
        (75, 74, 220),
        (76, 70, 210),
        (77, 76, 220),
        (78, 72, 220),
        (79, 78, 230),
        (90, 79, 240),
        (83, 7, 200),
        (84, 83, 220),
        (85, 71, 210),
    ];

    /// The image of each hop in [`WAKE_TABLE`]: 71 and 79 are npm node wrappers running
    /// Codex's script; 70, 72 and 73 are CLI images (native codex, native codex, claude);
    /// 85 is a node running CLAUDE's script; 83 cannot be read; the rest are plain.
    fn wake_probe(pid: u32) -> HopProbe {
        let p = |session_image, codex_wrapper| HopProbe::Process {
            session_image,
            codex_wrapper,
        };
        match pid {
            71 | 79 => p(true, true),
            70 | 72 | 73 | 85 => p(true, false),
            83 => HopProbe::Unreadable,
            _ => p(false, false),
        }
    }

    fn wt_with(
        table: &[(u32, u32, u64)],
        acc: &std::path::Path,
        pid: u32,
        home: &std::path::Path,
        l: &CodexLaunch,
    ) -> Option<WakeTarget> {
        let t = table.to_vec();
        let t2 = table.to_vec();
        wake_target_with(
            acc,
            pid,
            home,
            l,
            &move |p| t.iter().find(|r| r.0 == p).map(|r| r.1),
            &move |p| t2.iter().find(|r| r.0 == p).map(|r| r.2),
            &wake_probe,
        )
    }

    fn wt(
        acc: &std::path::Path,
        pid: u32,
        home: &std::path::Path,
        l: &CodexLaunch,
    ) -> Option<WakeTarget> {
        wt_with(&WAKE_TABLE, acc, pid, home, l)
    }

    /// N2: `csq run` names the handle dir after the SUPERVISOR's pid, so the listed Codex
    /// pid (70, or 72 behind an npm node wrapper) is bound to `term-7` by descent.
    #[test]
    fn a_supervised_codex_is_bound_to_its_supervisors_handle_dir() {
        let (_tmp, acc) = wake_fixture();
        let (home, cfg) = (acc.join("term-7"), acc.join("config-3"));
        let l = wake_launch(Some(&cfg));
        let direct = wt(&acc, 70, &home, &l).expect("direct child of the supervisor");
        assert_eq!((direct.pid(), direct.codex_home()), (70, home.as_path()));
        // behind an npm node wrapper: the supervisor's recorded child is the wrapper 71
        set_child(&acc, 71);
        let wrapped = wt(&acc, 72, &home, &l).expect("behind an npm node wrapper");
        assert_eq!(wrapped.pid(), 72);
        // the swap-exec shape: codex is itself term-<own pid>
        assert!(wt(&acc, 7, &home, &l).is_some(), "swap-exec");
    }

    /// T2: a Codex started by a tool inside the session inherits `CODEX_HOME=term-7` and
    /// descends from supervisor 7, but it is not the session's own Codex. Every shape is
    /// refused, each with its control passing under the same fixture.
    #[test]
    fn a_nested_codex_under_the_supervisor_is_refused() {
        let (_tmp, acc) = wake_fixture();
        let (home, cfg) = (acc.join("term-7"), acc.join("config-3"));
        let l = wake_launch(Some(&cfg));
        // controls: the supervised direct codex, and the codex behind its own wrapper
        assert!(wt(&acc, 70, &home, &l).is_some(), "control: direct");
        set_child(&acc, 71);
        assert!(wt(&acc, 72, &home, &l).is_some(), "control: wrapper");
        // 75: codex under a shell under a CLAUDE that is the supervised child
        set_child(&acc, 73);
        assert!(wt(&acc, 75, &home, &l).is_none(), "under a claude hop");
        // 77: codex under a shell under the supervised native codex 70
        set_child(&acc, 70);
        assert!(wt(&acc, 77, &home, &l).is_none(), "under another codex");
        // 90: codex behind ITS OWN wrapper 79, under codex 72 under wrapper 71
        set_child(&acc, 71);
        assert!(wt(&acc, 90, &home, &l).is_none(), "nested wrapper chain");
        // 84: codex under an UNREADABLE hop 83 (the supervisor's recorded child)
        set_child(&acc, 83);
        assert!(wt(&acc, 84, &home, &l).is_none(), "unreadable hop");
        // 85 runs Claude's node script directly above the listed pid: a CLI, not Codex's wrapper
        let mut table = WAKE_TABLE.to_vec();
        table.push((86, 85, 220));
        assert!(
            wt_with(&table, &acc, 86, &home, &l).is_none(),
            "claude node wrapper"
        );
    }

    /// F2: an npm Codex started through `csq swap` exec-replaces csq: the `node` wrapper (60)
    /// IS the handle dir's supervisor, the native codex (61) its direct child, and no
    /// `.live-cc-pid` exists. It is woken; a non-wrapper supervisor, an intervening hop and a
    /// stale `.live-pid` still refuse. Falsifier: without `exec_wrapper_launch` the first
    /// assertion fails (`chain_is_own_launch` needs `.live-cc-pid`).
    #[test]
    fn an_npm_swap_exec_codex_under_its_own_wrapper_is_woken() {
        let (_tmp, acc) = wake_fixture();
        let cfg = acc.join("config-3");
        let l = wake_launch(Some(&cfg));
        for d in ["term-60", "term-62"] {
            std::fs::create_dir_all(acc.join(d)).unwrap();
        }
        std::fs::write(acc.join("term-60/.live-pid"), "60").unwrap();
        std::fs::write(acc.join("term-62/.live-pid"), "62").unwrap();
        let mut table = WAKE_TABLE.to_vec();
        // 60: node wrapper = supervisor; 61: native codex child; 64/65: shell + nested codex
        // under 61; 62: a PLAIN process = supervisor with child codex 63.
        table.extend([
            (60, 1, 100),
            (61, 60, 200),
            (64, 61, 210),
            (65, 64, 220),
            (62, 1, 100),
            (63, 62, 200),
        ]);
        let probe = |p: u32| {
            if p == 60 {
                HopProbe::Process {
                    session_image: true,
                    codex_wrapper: true,
                }
            } else {
                wake_probe(p)
            }
        };
        let go = |pid: u32, term: &str| {
            let t = table.clone();
            let t2 = table.clone();
            wake_target_with(
                &acc,
                pid,
                &acc.join(term),
                &l,
                &move |p| t.iter().find(|r| r.0 == p).map(|r| r.1),
                &move |p| t2.iter().find(|r| r.0 == p).map(|r| r.2),
                &probe,
            )
        };
        assert!(
            !acc.join("term-60/.live-cc-pid").exists(),
            "no record, by construction"
        );
        assert_eq!(
            go(61, "term-60").map(|t| t.pid()),
            Some(61),
            "npm swap-exec"
        );
        assert!(go(65, "term-60").is_none(), "nested codex behind a shell");
        assert!(go(63, "term-62").is_none(), "non-wrapper supervisor");
    }

    /// T2: the supervisor's recorded child must be the chain's top: absent, unreadable or a
    /// different pid refuses, even for the otherwise valid direct codex.
    #[test]
    fn the_wake_chain_must_top_out_at_the_supervisors_recorded_child() {
        let (_tmp, acc) = wake_fixture();
        let (home, cfg) = (acc.join("term-7"), acc.join("config-3"));
        let l = wake_launch(Some(&cfg));
        assert!(wt(&acc, 70, &home, &l).is_some(), "control");
        set_child(&acc, 73);
        assert!(wt(&acc, 70, &home, &l).is_none(), "records another child");
        std::fs::write(home.join(".live-cc-pid"), "garbage").unwrap();
        assert!(wt(&acc, 70, &home, &l).is_none(), "unreadable record");
        std::fs::remove_file(home.join(".live-cc-pid")).unwrap();
        assert!(wt(&acc, 70, &home, &l).is_none(), "no record");
    }

    /// T2: a hop re-classified under a changed start is undetermined (refuse).
    #[test]
    fn a_chain_hop_whose_start_moves_is_undetermined() {
        let flip = std::cell::Cell::new(0u32);
        let start = |_p: u32| {
            flip.set(flip.get() + 1);
            Some(if flip.get() == 1 { 500 } else { 501 })
        };
        assert_eq!(between_hop_chain(15, 500, &start, &|_| wake_probe(1)), None);
        assert_eq!(
            between_hop_chain(15, 500, &|_| Some(500), &|_| wake_probe(71)),
            Some(ChainHop::CodexWrapper)
        );
        assert_eq!(
            between_hop_chain(15, 500, &|_| Some(500), &|_| wake_probe(73)),
            Some(ChainHop::Cli)
        );
    }

    /// N2: a CODEX_HOME naming ANOTHER live session's `term-<sup>` with no descent is refused,
    /// and so is a `.live-pid` that does not name the supervisor.
    #[test]
    fn a_forged_supervisor_dir_or_a_mismatched_live_pid_is_refused() {
        let (_tmp, acc) = wake_fixture();
        let cfg = acc.join("config-3");
        let l = wake_launch(Some(&cfg));
        // 80 runs under supervisor 8 but claims supervisor 7's home
        assert!(
            wt(&acc, 80, &acc.join("term-7"), &l).is_none(),
            "no descent"
        );
        // 99 is a stranger (parent 1) claiming supervisor 7's home
        assert!(wt(&acc, 99, &acc.join("term-7"), &l).is_none(), "stranger");
        assert!(wt(&acc, 70, &acc.join("term-7"), &l).is_some(), "control");
        std::fs::write(acc.join("term-7").join(".live-pid"), "8").unwrap();
        assert!(
            wt(&acc, 70, &acc.join("term-7"), &l).is_none(),
            "live-pid names 8"
        );
        std::fs::write(acc.join("term-7").join(".live-pid"), "garbage").unwrap();
        assert!(
            wt(&acc, 70, &acc.join("term-7"), &l).is_none(),
            "unreadable"
        );
        std::fs::remove_file(acc.join("term-7").join(".live-pid")).unwrap();
        assert!(wt(&acc, 70, &acc.join("term-7"), &l).is_none(), "absent");
    }

    /// N2: a supervisor that is not a live process is refused, and a supervisor that started
    /// AFTER the codex (a recycled pid) fails the start-monotonic walk.
    #[test]
    fn a_dead_or_recycled_supervisor_is_refused() {
        let (_tmp, acc) = wake_fixture();
        let home = acc.join("term-7");
        let l = wake_launch(Some(&acc.join("config-3")));
        let no7: Vec<_> = WAKE_TABLE.iter().copied().filter(|r| r.0 != 7).collect();
        assert!(wt_with(&no7, &acc, 70, &home, &l).is_none(), "7 not live");
        let recycled: Vec<_> = WAKE_TABLE
            .iter()
            .map(|r| if r.0 == 7 { (7, 1, 900) } else { *r })
            .collect();
        assert!(
            wt_with(&recycled, &acc, 70, &home, &l).is_none(),
            "7 younger than 70"
        );
    }

    /// N3: `still_live` re-reads the exact starts and the handle dir, and is false on any
    /// change or unreadable input.
    #[test]
    fn still_live_rechecks_the_incarnation_and_the_handle_dir() {
        let (_tmp, acc) = wake_fixture();
        let home = acc.join("term-7");
        let l = wake_launch(Some(&acc.join("config-3")));
        let t = wt(&acc, 70, &home, &l).unwrap();
        let same = |p: u32| WAKE_TABLE.iter().find(|r| r.0 == p).map(|r| r.2);
        assert!(t.still_live_with(&same), "control");
        let reused = |p: u32| if p == 70 { Some(201) } else { same(p) };
        assert!(!t.still_live_with(&reused), "codex pid reused");
        let sup_reused = |p: u32| if p == 7 { Some(101) } else { same(p) };
        assert!(!t.still_live_with(&sup_reused), "supervisor pid reused");
        let gone = |p: u32| if p == 70 { None } else { same(p) };
        assert!(!t.still_live_with(&gone), "unreadable start");
        std::fs::write(home.join(".live-pid"), "8").unwrap();
        assert!(!t.still_live_with(&same), ".live-pid changed");
        std::fs::write(home.join(".live-pid"), "7").unwrap();
        assert!(t.still_live_with(&same));
        std::fs::remove_dir_all(&home).unwrap();
        assert!(!t.still_live_with(&same), "handle dir gone");
    }

    #[test]
    fn a_wake_target_must_be_its_own_handle_dir_with_the_slot_sqlite_home() {
        let (tmp, acc) = wake_fixture();
        let (own, other, cfg) = (acc.join("term-7"), acc.join("term-8"), acc.join("config-3"));
        let outside = std::fs::canonicalize(tmp.path()).unwrap().join("elsewhere");
        std::fs::create_dir(&outside).unwrap();
        let l = wake_launch;
        let ok = wt(&acc, 7, &own, &l(Some(&cfg))).expect("control");
        assert_eq!(
            (ok.codex_home(), ok.sqlite_home()),
            (own.as_path(), cfg.as_path())
        );
        assert!(
            wt(&acc, 7, &other, &l(Some(&cfg))).is_none(),
            "sibling home"
        );
        assert!(
            wt(&acc, 7, &outside, &l(Some(&cfg))).is_none(),
            "home outside"
        );
        assert!(
            wt(&acc, 7, &own, &l(Some(&outside))).is_none(),
            "sqlite outside"
        );
        assert!(wt(&acc, 7, &own, &l(None)).is_none(), "no sqlite_home");
        assert!(
            wt(&acc, 7, &own, &l(Some(std::path::Path::new("config-3")))).is_none(),
            "relative sqlite_home"
        );
        assert!(
            wt(&acc, 9, &own, &l(Some(&cfg))).is_none(),
            "pid has no term dir"
        );
    }

    /// F4: `sqlite_home` is exactly `<accounts>/config-<N>`, not anywhere under accounts.
    #[test]
    fn sqlite_home_is_exactly_the_slot_config_dir_csq_passes_at_launch() {
        let (_tmp, acc) = wake_fixture();
        let own = acc.join("term-7");
        let l = wake_launch;
        // another term dir, a nested dir, a name that is not config-<N>: all under accounts
        let nested = acc.join("config-3").join("sub");
        std::fs::create_dir(&nested).unwrap();
        for d in ["config-007", "config-0", "configs", "config-x"] {
            std::fs::create_dir(acc.join(d)).unwrap();
        }
        for bad in [
            acc.join("term-8"),
            nested,
            acc.join("config-007"),
            acc.join("config-0"),
            acc.join("configs"),
            acc.join("config-x"),
            acc.clone(),
        ] {
            assert!(
                wt(&acc, 7, &own, &l(Some(&bad))).is_none(),
                "{}",
                bad.display()
            );
        }
        #[cfg(unix)]
        {
            // a symlink named like the slot dir that points at another one is not it
            let link = acc.join("config-5");
            std::os::unix::fs::symlink(acc.join("config-3"), &link).unwrap();
            assert!(
                wt(&acc, 7, &own, &l(Some(&link))).is_none(),
                "symlink config"
            );
            let esc = acc.join("escape");
            std::os::unix::fs::symlink(acc.join("term-8"), &esc).unwrap();
            assert!(
                wt(&acc, 7, &own, &l(Some(&esc))).is_none(),
                "symlink escape"
            );
        }
    }

    /// F4: `term-<pid>` as a symlink is refused even when it resolves to the codex home.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_term_dir_is_not_a_wake_target() {
        let (tmp, acc) = wake_fixture();
        let real = std::fs::canonicalize(tmp.path()).unwrap().join("real-home");
        std::fs::create_dir(&real).unwrap();
        let link = acc.join("term-9");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let cfg = acc.join("config-3");
        // the symlink canonicalises to `real`, which a canonicalising check calls "the home"
        assert!(wt(&acc, 9, &real, &wake_launch(Some(&cfg))).is_none());
        assert!(wt(&acc, 9, &link, &wake_launch(Some(&cfg))).is_none());
    }

    // ---- F1/F2/F3: the between-hop predicate ----

    fn proc_of(session_image: bool) -> HopProbe {
        HopProbe::Process {
            session_image,
            codex_wrapper: false,
        }
    }

    /// F1: a codex (or claude) hop with no terminal and no own handle-dir variable still
    /// refuses: the predicate looks at the image, not at what the listing needs.
    #[test]
    fn a_session_image_hop_refuses_even_without_terminal_or_handle_dir_variable() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_string_lossy().into_owned();
        let owners = [cli_session(30, &dir, Some(100))];
        for (what, image) in [("codex", true), ("claude", true)] {
            let r = resolve_caller(
                CliKind::Claude,
                &owners,
                &[],
                Visibility::WHOLE,
                Some(&dir),
                &|_| Some(Some(vec![(15, 500)])),
                // the REAL between predicate over injected readers: start stable, image read
                &|pid, start| {
                    between_hop_is_session(pid, start, &|_| Some(500), &|_| proc_of(image))
                },
                &|_| Some(100),
            );
            assert_eq!(r, Err(CallerError::TargetMismatch), "{what} hop");
        }
        // control: a shell hop resolves
        let ok = resolve_caller(
            CliKind::Claude,
            &owners,
            &[],
            Visibility::WHOLE,
            Some(&dir),
            &|_| Some(Some(vec![(15, 500)])),
            &|pid, start| between_hop_is_session(pid, start, &|_| Some(500), &|_| proc_of(false)),
            &|_| Some(100),
        );
        assert!(ok.is_ok(), "control: a non-session hop");
    }

    /// F2: a hop that exited after the walk, or whose pid was reused, is undetermined.
    #[test]
    fn a_hop_gone_or_reused_since_the_walk_is_undetermined_never_not_a_session() {
        use std::cell::Cell;
        let img = |_: u32| proc_of(false);
        // control: stable start, readable image
        assert_eq!(
            between_hop_is_session(15, 500, &|_| Some(500), &img),
            Some(false)
        );
        // gone: the start can no longer be read
        assert_eq!(between_hop_is_session(15, 500, &|_| None, &img), None);
        // gone: the classification read says so
        assert_eq!(
            between_hop_is_session(15, 500, &|_| Some(500), &|_| HopProbe::Gone),
            None
        );
        // reused before the classification read
        assert_eq!(between_hop_is_session(15, 500, &|_| Some(501), &img), None);
        // reused DURING the classification read: start 500 first, 501 after
        let n = Cell::new(0);
        let flip = |_: u32| {
            n.set(n.get() + 1);
            Some(if n.get() == 1 { 500 } else { 501 })
        };
        assert_eq!(
            between_hop_is_session(15, 500, &flip, &|_| proc_of(true)),
            None
        );
        // unreadable image
        assert_eq!(
            between_hop_is_session(15, 500, &|_| Some(500), &|_| HopProbe::Unreadable),
            None
        );
    }

    #[cfg(unix)]
    fn no_exe(_: &std::path::Path) -> bool {
        false
    }

    #[cfg(unix)]
    fn reads(comm: Option<&str>, argv: Option<&[&str]>, exe: Option<&str>) -> ImageReads {
        ImageReads {
            comm: comm.map(str::to_string),
            argv: argv.map(|a| a.iter().map(|x| (*x).to_string()).collect()),
            exe: exe.map(PathBuf::from),
        }
    }

    /// N1/INVEST-NOW: the image names csq's five CLIs go by, including release-asset names;
    /// lookalikes are not CLIs.
    #[test]
    fn cli_image_names_cover_the_five_clis_and_not_lookalikes() {
        for yes in [
            "claude",
            "codex",
            "gemini",
            "kimi",
            "grok",
            "codex.exe",
            "CODEX.EXE",
            "codex-aarch64-apple-darwin",
            "codex-x86_64-pc-windows-msvc.exe",
            "codex-aarch64-a",
            "grok-0.2.118-macos-aarch64",
            "grok-macos-aarch64",
        ] {
            assert!(is_cli_image_name(yes), "{yes}");
        }
        for no in [
            "node",
            "codex-helper",
            "claude-mem",
            "xcodex",
            "2.1.289",
            "codex.cmd",
            "",
        ] {
            assert!(!is_cli_image_name(no), "{no}");
        }
    }

    /// N1: every signal is OR'd, an unreadable one never overrides, and "not a session" needs
    /// two successful reads.
    #[cfg(unix)]
    #[test]
    fn image_verdict_ors_signals_and_needs_two_reads_to_say_no() {
        let v = |r: ImageReads| image_verdict(&r, &no_exe);
        assert_eq!(
            v(reads(Some("cx"), Some(&["cx"]), Some("/v/codex"))),
            Some(true),
            "exe only"
        );
        assert_eq!(
            v(reads(
                Some("2.1.289"),
                Some(&["2.1.289"]),
                Some("/h/claude/versions/2.1.289")
            )),
            Some(true),
            "versions dir"
        );
        assert_eq!(
            v(reads(None, Some(&["codex"]), None)),
            Some(true),
            "one positive read"
        );
        assert_eq!(v(reads(Some("zsh"), None, None)), None, "one negative read");
        assert_eq!(v(reads(None, None, None)), None);
        assert_eq!(v(reads(Some("zsh"), Some(&["zsh"]), None)), Some(false));
        assert_eq!(v(reads(Some("zsh"), None, Some("/bin/zsh"))), Some(false));
        assert_eq!(
            image_verdict(&reads(Some("cx"), Some(&["cx"]), Some("/v/cx")), &|_| true),
            Some(true),
            "same file as a resolved CLI binary"
        );
    }

    /// INVEST-NOW: a node image is a CLI only through its script; node options and their
    /// values are skipped, and a bare argument is not a script path of a CLI by name alone.
    #[cfg(unix)]
    #[test]
    fn a_node_image_is_a_cli_only_through_its_script() {
        let v = |argv: &[&str]| {
            image_verdict(
                &reads(Some("node"), Some(argv), Some("/o/bin/node")),
                &no_exe,
            )
        };
        assert_eq!(
            v(&["node", "/o/@google/gemini-cli/bundle/gemini.js"]),
            Some(true)
        );
        assert_eq!(v(&["node", "--disable-sigusr1", "/x/kimi.mjs"]), Some(true));
        assert_eq!(v(&["node", "-r", "/p/pre.js", "/x/grok.js"]), Some(true));
        assert_eq!(
            v(&["node", "/x/@openai/codex/bin/codex.js", "exec"]),
            Some(true)
        );
        assert_eq!(
            v(&["node", "/r/trestle.mjs", "run", "--", "gemini"]),
            Some(false)
        );
        assert_eq!(v(&["node", "-r", "/p/grok.js", "/r/other.js"]), Some(false));
    }

    #[test]
    fn classify_hop_has_three_outcomes() {
        assert_eq!(classify_hop(proc_of(true)), Some(true));
        assert_eq!(classify_hop(proc_of(false)), Some(false));
        assert_eq!(classify_hop(HopProbe::Gone), None);
        assert_eq!(classify_hop(HopProbe::Unreadable), None);
    }

    #[test]
    fn a_relative_or_escaped_sqlite_home_is_dropped() {
        let home = absolute_sqlite_home_fixture("/a");
        for v in [
            "sqlite_home=rel/dir".to_owned(),
            "sqlite_home=./x".to_owned(),
            format!("sqlite_home=\"{home}/b\"c\""),
            format!("sqlite_home={home}\\b"),
            format!("sqlite_home=\"{home}\\\"b\""),
            format!("sqlite_home={home}'b"),
        ] {
            assert_eq!(
                parse_codex_launch(&argv(&["codex", "-c", &v])).sqlite_home,
                None,
                "{v}"
            );
        }
        let valid = absolute_sqlite_home_fixture("/ok/dir");
        assert_eq!(
            parse_codex_launch(&argv(&["codex", "-c", &format!("sqlite_home=\"{valid}\"")]))
                .sqlite_home,
            Some(PathBuf::from(valid))
        );
    }
}
