//! Session rows for `csq sessions list --json` (`csq.sessions.v1`).
//!
//! Takes the OS-derived [`SessionInfo`] records and joins each with the
//! identity facts csq can establish without guessing:
//!
//! - `account_slot` from the handle dir's `.csq-account` marker, read through
//!   [`resolve_marker_to_slot`] (recognises decimal AND UUID content —
//!   `guard-reader-writer-parity.md` MUST-1). A directory name is never parsed
//!   (`account-terminal-separation.md` MUST NOT 3).
//! - `session_id` / `name` from Claude Code's own registry
//!   `<home>/.claude/sessions/<pid>.json`, accepted only when the file's `pid`
//!   equals the row's pid AND whose `startedAt` (ms) is no earlier than the row's
//!   `started_at` minus `START_TOLERANCE_SECS` (csq exec-replaces itself with
//!   `claude`, so `started_at` is csq's launch and the registry is written later,
//!   by an unbounded delay) and no later than `now` plus `REGISTRY_CLOCK_SKEW_SECS`.
//!   The previous holder of a pid always started EARLIER, so the lower bound is
//!   what rejects a stale file. Never inferred from argv.
//! - `scratch_dir`, reported only when the directory exists on disk, is a real
//!   directory (never a symlink) owned by the current euid, under a
//!   `claude-<uid>` root that is a real, owner-only (no group/other bits)
//!   directory owned by the same euid.
//!
//! INV-31-01: identity is `(pid, started_at)`. A session whose start time is
//! unknown cannot be targeted safely and is OMITTED (with a logged reason).
//!
//! The home and tmp roots are parameters so tests never touch the real `$HOME`
//! or `/private/tmp`. This module reads no credential files.

use super::{CliKind, Listing, SessionInfo};
use crate::accounts::markers::resolve_marker_to_slot;
use std::path::{Path, PathBuf};

/// Largest registry file we will read. Real files are a few hundred bytes.
pub(crate) const MAX_REGISTRY_BYTES: u64 = 64 * 1024;

/// Clock skew tolerated on the registry's upper bound: `startedAt` may be at most
/// this far past the injected `now`.
const REGISTRY_CLOCK_SKEW_SECS: u64 = 60;

/// The surface of a Claude Code row.
pub const SURFACE_CLAUDE_CODE: &str = "claude-code";

/// The surface of a Codex row (spec 31 §2 v1.4.0, spec 32 §2.1).
pub const SURFACE_CODEX: &str = "codex";

/// Filesystem roots used for enrichment. All injectable.
#[derive(Debug, Clone)]
pub struct RowContext {
    /// csq base dir (`~/.claude/accounts`), where `profiles.json` lives.
    pub base_dir: PathBuf,
    /// Home dir holding Claude Code's registry at `.claude/sessions/`.
    pub home: PathBuf,
    /// Root of Claude Code's per-user scratch trees (`/private/tmp` on macOS).
    pub tmp_root: PathBuf,
    /// Numeric uid used in `claude-<uid>`; `None` where there is no uid.
    pub uid: Option<u32>,
    /// The current unix time, injected so the registry window is deterministic.
    pub now_secs: u64,
}

/// One enriched live session. `started_at` is always known (INV-31-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRowData {
    /// OS process id.
    pub pid: u32,
    /// OS process start time, unix seconds.
    pub started_at: u64,
    /// [`SURFACE_CLAUDE_CODE`] or [`SURFACE_CODEX`].
    pub surface: &'static str,
    /// Claude Code session id, when the registry vouches for it.
    pub session_id: Option<String>,
    /// Claude Code session name, when the registry vouches for it.
    pub name: Option<String>,
    /// Working directory at process creation.
    pub cwd: PathBuf,
    /// The session's `CLAUDE_CONFIG_DIR`.
    pub handle_dir: PathBuf,
    /// Slot from the handle dir's `.csq-account` marker.
    pub account_slot: Option<u16>,
    /// Controlling TTY basename.
    pub tty: Option<String>,
    /// Terminal tab title, best effort.
    pub terminal_title: Option<String>,
    /// Existing scratch directory whose last segment is `session_id`.
    pub scratch_dir: Option<PathBuf>,
}

/// Discover live sessions on this host and enrich them against the real
/// `$HOME`-derived roots. `None` when the process table could not be read
/// at all (never folded into an empty list: an empty `Some` means
/// "enumerated, none live").
pub fn list_rows(base_dir: &Path, home: &Path) -> Option<Vec<SessionRowData>> {
    list_rows_from(base_dir, home, &super::try_list)
}

/// [`list_rows`] with terminal titles resolved where the platform can (a bounded,
/// cached `osascript` on macOS). For the human table; the `--json` machine path uses
/// [`list_rows`] and never pays for titles (spec 31 §2).
pub fn list_rows_titled(base_dir: &Path, home: &Path) -> Option<Vec<SessionRowData>> {
    list_rows_from(base_dir, home, &super::try_list_titled)
}

fn list_rows_from(
    base_dir: &Path,
    home: &Path,
    list: &dyn Fn() -> Option<Vec<SessionInfo>>,
) -> Option<Vec<SessionRowData>> {
    let ctx = row_context(base_dir, home)?;
    Some(enrich(list()?, &ctx))
}

fn row_context(base_dir: &Path, home: &Path) -> Option<RowContext> {
    let now_secs = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => {
            tracing::warn!(
                reason = "clock_unreadable",
                "system clock is before the epoch; listing undetermined"
            );
            return None;
        }
    };
    Some(RowContext {
        base_dir: base_dir.to_path_buf(),
        home: home.to_path_buf(),
        tmp_root: PathBuf::from("/private/tmp"),
        uid: current_uid(),
        now_secs,
    })
}

/// Rows plus what the listing could not see (spec 31 §2: `incomplete`, `unreadable_pids`,
/// `restricted`), so a machine surface never reads a partial listing as whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowsListing {
    /// The enriched rows, as [`list_rows`] returns them.
    pub rows: Vec<SessionRowData>,
    /// Pids that may be a session and could not be read (see [`super::Listing`]).
    pub unreadable_pids: Vec<u32>,
    /// The process table may hide processes from this caller.
    pub incomplete: bool,
    /// The caller cannot read process information at all.
    pub restricted: bool,
    /// Why the table is `incomplete` (Linux).
    pub incomplete_cause: Option<super::IncompleteCause>,
}

impl RowsListing {
    /// Whether the listing saw every process: not `incomplete`, not `restricted`, and no
    /// unreadable pid. Name resolution needs this: an unreadable process may carry the name.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.incomplete && !self.restricted && self.unreadable_pids.is_empty()
    }
}

impl RowsListing {
    /// Incomplete ONLY because some pids could not be read: not `incomplete`, not
    /// `restricted`. Such a gap is often transient (a process exiting mid-read).
    #[must_use]
    pub fn only_unreadable(&self) -> bool {
        !self.incomplete && !self.restricted && !self.unreadable_pids.is_empty()
    }
}

/// Retry a listing ONCE when [`RowsListing::only_unreadable`], keeping the retry when it
/// could be read (else the first). Bounded to one retry: a persistent gap stays a gap and
/// name resolution then answers `undetermined`.
#[must_use]
pub fn retry_if_only_unreadable(
    first: RowsListing,
    relist: impl FnOnce() -> Option<RowsListing>,
) -> RowsListing {
    if !first.only_unreadable() {
        return first;
    }
    relist().unwrap_or(first)
}

/// [`list_rows_detailed`] for name resolution: one internal retry when the only blind spot is
/// unreadable pids ([`retry_if_only_unreadable`]).
pub fn list_rows_for_names(base_dir: &Path, home: &Path) -> Option<RowsListing> {
    let first = list_rows_detailed(base_dir, home, false)?;
    Some(retry_if_only_unreadable(first, || {
        list_rows_detailed(base_dir, home, false)
    }))
}

/// [`list_rows`] / [`list_rows_titled`] with the listing's blind spots attached.
pub fn list_rows_detailed(base_dir: &Path, home: &Path, titles: bool) -> Option<RowsListing> {
    let ctx = row_context(base_dir, home)?;
    let claude = if titles {
        super::try_list_detailed_titled()?
    } else {
        super::try_list_detailed()?
    };
    // A Codex table that cannot be read makes the whole listing undetermined, except on
    // Windows where Codex is not enumerated at all (a documented gap, not an empty table).
    let codex = match super::try_list_detailed_kind(CliKind::Codex) {
        Some(l) => Some(l),
        None if cfg!(target_os = "windows") => None,
        None => return None,
    };
    Some(rows_from_listings(claude, codex, &ctx))
}

/// Claude rows first (so their order and bytes are what the Claude-only listing gave), then
/// Codex rows; a blind spot in either table is a blind spot of the whole listing.
pub(crate) fn rows_from_listings(
    claude: Listing,
    codex: Option<Listing>,
    ctx: &RowContext,
) -> RowsListing {
    let mut rows = enrich_kind(CliKind::Claude, claude.sessions, ctx);
    let mut unreadable_pids = claude.unreadable_pids;
    let (mut incomplete, mut restricted) = (claude.incomplete, claude.restricted);
    let mut incomplete_cause = claude.incomplete_cause;
    if let Some(codex) = codex {
        rows.extend(enrich_kind(CliKind::Codex, codex.sessions, ctx));
        unreadable_pids.extend(codex.unreadable_pids);
        incomplete |= codex.incomplete;
        restricted |= codex.restricted;
        incomplete_cause = incomplete_cause.or(codex.incomplete_cause);
    }
    RowsListing {
        rows,
        unreadable_pids,
        incomplete,
        restricted,
        incomplete_cause,
    }
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    Some(unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// Enrich discovered sessions; omit any whose start time is unknown.
pub fn enrich(infos: Vec<SessionInfo>, ctx: &RowContext) -> Vec<SessionRowData> {
    enrich_kind(CliKind::Claude, infos, ctx)
}

/// [`enrich`] for `kind`. A Codex row has no Claude registry file and no Claude scratch
/// tree, so `session_id`, `name` and `scratch_dir` stay `None`; its `account_slot` is read
/// from the handle dir's marker exactly as a Claude row's is.
pub fn enrich_kind(
    kind: CliKind,
    infos: Vec<SessionInfo>,
    ctx: &RowContext,
) -> Vec<SessionRowData> {
    let mut out = Vec::with_capacity(infos.len());
    for info in infos {
        let Some(started_at) = info.started_at else {
            tracing::warn!(
                pid = info.pid,
                reason = "start_time_unknown",
                "session omitted from listing (INV-31-01)"
            );
            continue;
        };
        let account_slot = resolve_marker_to_slot(&ctx.base_dir, &info.config_dir).map(|n| n.get());
        let registry = match kind {
            CliKind::Claude => read_registry(&ctx.home, info.pid, started_at, ctx.now_secs),
            CliKind::Codex => None,
        };
        let (session_id, name) = match registry {
            Some((id, name)) => (Some(id), name),
            None => (None, None),
        };
        let scratch_dir = session_id
            .as_deref()
            .and_then(|id| find_scratch_dir(ctx, &info.cwd, id));
        out.push(SessionRowData {
            pid: info.pid,
            started_at,
            surface: kind.surface(),
            session_id,
            name,
            cwd: info.cwd,
            handle_dir: info.config_dir,
            account_slot,
            tty: info.tty,
            terminal_title: info.terminal_title,
            scratch_dir,
        });
    }
    out
}

/// Whether a registry `startedAt` (whole seconds) is a plausible record of the process that
/// started at `started_at`: no earlier than it less `START_TOLERANCE_SECS`, no later than `now`
/// plus `REGISTRY_CLOCK_SKEW_SECS`. Shared with the Claude wake (`messaging::wake`), so both
/// readers of the registry bind a record to a process by the same rule.
pub(crate) fn registry_start_in_window(reg_secs: u64, started_at: u64, now_secs: u64) -> bool {
    reg_secs.saturating_add(super::START_TOLERANCE_SECS) >= started_at
        && reg_secs <= now_secs.saturating_add(REGISTRY_CLOCK_SKEW_SECS)
}

/// A session id becomes a path segment, so only a plain token is accepted.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Reads `<home>/.claude/sessions/<pid>.json`. Returns `(sessionId, name)` only
/// when the file's own `pid` equals `pid`, its `startedAt` (ms) / 1000 lies in
/// `[started_at - START_TOLERANCE_SECS, now_secs + REGISTRY_CLOCK_SKEW_SECS]` (see the module
/// doc for why there is no upper bound relative to `started_at`), and `sessionId` is a
/// safe token. Anything else is treated as absent (INV-31-01: identity is
/// `(pid, started_at)`, never the pid alone).
fn read_registry(
    home: &Path,
    pid: u32,
    started_at: u64,
    now_secs: u64,
) -> Option<(String, Option<String>)> {
    let path = home
        .join(".claude")
        .join("sessions")
        .join(format!("{pid}.json"));
    // One bounded read of the OPEN handle: no symlink follow, no block on a FIFO, size cap
    // enforced on the bytes actually read (not a stat that can go stale).
    let bytes = match crate::platform::fs::read_regular_nofollow_bounded(&path, MAX_REGISTRY_BYTES)
    {
        Ok(Some(b)) => b,
        Ok(None) => return None,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            tracing::warn!(
                pid,
                reason = "registry_not_regular_or_too_large",
                "session registry ignored"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(pid, error_kind = ?e.kind(), "session registry unreadable; fields absent");
            return None;
        }
    };
    let raw = match String::from_utf8(bytes) {
        Ok(r) => r,
        Err(_) => {
            tracing::warn!(
                pid,
                reason = "registry_not_utf8",
                "session registry ignored"
            );
            return None;
        }
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(
                pid,
                reason = "registry_not_json",
                "session registry ignored"
            );
            return None;
        }
    };
    if v.get("pid").and_then(serde_json::Value::as_u64) != Some(u64::from(pid)) {
        tracing::warn!(
            pid,
            reason = "registry_pid_mismatch",
            "session registry ignored"
        );
        return None;
    }
    let reg_start_secs = v
        .get("startedAt")
        .and_then(serde_json::Value::as_u64)
        .map(|ms| ms / 1000);
    match reg_start_secs {
        Some(t) if registry_start_in_window(t, started_at, now_secs) => {}
        Some(_) => {
            tracing::warn!(
                pid,
                reason = "registry_started_at_outside_window",
                "stale session registry ignored"
            );
            return None;
        }
        None => {
            tracing::warn!(
                pid,
                reason = "registry_started_at_missing",
                "session registry ignored"
            );
            return None;
        }
    }
    let id = v.get("sessionId").and_then(serde_json::Value::as_str)?;
    if !is_safe_segment(id) {
        tracing::warn!(
            pid,
            reason = "session_id_unsafe",
            "session registry ignored"
        );
        return None;
    }
    let name = v
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|n| !n.is_empty() && n.len() <= 256 && !n.chars().any(char::is_control))
        .map(str::to_string);
    Some((id.to_string(), name))
}

#[cfg(unix)]
/// Claude Code's project slug: the cwd with `/` and `.` replaced by `-`.
fn project_slug(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

/// Outcome of vetting one scratch-tree path without following symlinks.
#[cfg(unix)]
enum DirCheck {
    /// Does not exist (normal; nothing to report).
    Missing,
    /// A real directory owned by the expected uid (and, for the root, 0700).
    Ok,
    /// A plain file, socket or similar: not a directory and not a symlink.
    /// Ordinary clutter in the tmp root, never a security signal.
    NotADirectory,
    /// Exists but failed a security check; the fixed tag names which.
    Rejected(&'static str),
}

/// `symlink_metadata`-based vetting: the path must be a real directory (a
/// symlink is rejected, never followed) owned by `uid`; with `owner_only`
/// it must additionally carry no group/other permission bits.
#[cfg(unix)]
fn check_dir(path: &Path, uid: u32, owner_only: bool) -> DirCheck {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DirCheck::Missing,
        Err(_) => return DirCheck::Rejected("scratch_unreadable"),
    };
    if meta.file_type().is_symlink() {
        return DirCheck::Rejected("scratch_is_symlink");
    }
    if !meta.is_dir() {
        return DirCheck::NotADirectory;
    }
    if meta.uid() != uid {
        return DirCheck::Rejected("scratch_wrong_owner");
    }
    if owner_only && meta.permissions().mode() & 0o077 != 0 {
        return DirCheck::Rejected("scratch_root_not_private");
    }
    DirCheck::Ok
}

/// The fixed WARN tag a vetting outcome warrants, or `None` when silent.
/// `quiet_plain` marks scan entries and `<dir>/<session_id>` candidates,
/// where a plain file is ordinary clutter rather than an anomaly (a plain
/// file at either position is treated the same way); symlink, owner,
/// permission and unreadable outcomes always warn.
#[cfg(unix)]
fn warn_tag(check: &DirCheck, quiet_plain: bool) -> Option<&'static str> {
    match check {
        DirCheck::Ok | DirCheck::Missing => None,
        DirCheck::NotADirectory if quiet_plain => None,
        DirCheck::NotADirectory => Some("scratch_not_a_directory"),
        DirCheck::Rejected(reason) => Some(reason),
    }
}

#[cfg(unix)]
/// `Some(())` iff `path` is vetted; a rejection is logged with a fixed tag.
fn vetted_with(path: &Path, uid: u32, owner_only: bool, quiet_plain: bool) -> Option<()> {
    let check = check_dir(path, uid, owner_only);
    if let Some(reason) = warn_tag(&check, quiet_plain) {
        tracing::warn!(reason, "scratch_dir omitted from listing");
    }
    matches!(check, DirCheck::Ok).then_some(())
}

#[cfg(unix)]
fn vetted(path: &Path, uid: u32, owner_only: bool) -> Option<()> {
    vetted_with(path, uid, owner_only, false)
}

#[cfg(unix)]
fn vetted_scan(path: &Path, uid: u32) -> Option<()> {
    vetted_with(path, uid, false, true)
}

/// Scratch dir for a session: the derived path when it exists, else a scan of
/// `<tmp_root>/claude-<uid>/*/` for a directory named exactly `session_id`.
/// Every path is vetted with `symlink_metadata` (see [`check_dir`]); the root
/// must be owner-only. Any failed check omits the field.
#[cfg(unix)]
fn find_scratch_dir(ctx: &RowContext, cwd: &Path, session_id: &str) -> Option<PathBuf> {
    let uid = ctx.uid?;
    let root = ctx.tmp_root.join(format!("claude-{uid}"));
    vetted(&root, uid, true)?;
    let slug_dir = root.join(project_slug(cwd));
    let derived = slug_dir.join(session_id);
    if vetted(&slug_dir, uid, false).is_some() && vetted(&derived, uid, false).is_some() {
        return Some(derived);
    }
    let entries = std::fs::read_dir(&root).ok()?;
    for entry in entries.flatten() {
        // `DirEntry::file_type` does not follow symlinks: a symlink entry
        // still reaches `vetted` and is logged; plain files are skipped.
        if matches!(entry.file_type(), Ok(t) if !t.is_dir() && !t.is_symlink()) {
            continue;
        }
        let dir = entry.path();
        if vetted_scan(&dir, uid).is_none() {
            continue;
        }
        let candidate = dir.join(session_id);
        if vetted_scan(&candidate, uid).is_some() {
            return Some(candidate);
        }
    }
    None
}

/// No uid, no scratch tree (`RowContext::uid` is `None` off unix).
#[cfg(not(unix))]
fn find_scratch_dir(_ctx: &RowContext, _cwd: &Path, _session_id: &str) -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::identity_store::IdentityId;
    use crate::accounts::profiles::{profiles_path, save, ProfilesFile};
    use std::fs;

    const UUID_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SID: &str = "c5c006d3-4fc9-4da3-b8c1-0713f103c735";

    #[cfg(unix)]
    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[cfg(not(unix))]
    fn euid() -> u32 {
        0
    }

    #[cfg(unix)]
    fn set_mode(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_mode(_p: &Path, _mode: u32) {}

    #[cfg(unix)]
    fn croot(f: &Fx) -> PathBuf {
        f.ctx.tmp_root.join(format!("claude-{}", euid()))
    }

    /// Injected clock for every registry-window test.
    const NOW: u64 = 1_000_000;

    struct Fx {
        _td: tempfile::TempDir,
        ctx: RowContext,
        handle: PathBuf,
    }

    fn fx() -> Fx {
        let td = tempfile::tempdir().unwrap();
        let root = td.path().to_path_buf();
        let base = root.join("accounts");
        let handle = base.join("term-4242");
        fs::create_dir_all(&handle).unwrap();
        fs::create_dir_all(root.join("home/.claude/sessions")).unwrap();
        fs::create_dir_all(root.join("tmp")).unwrap();
        let ctx = RowContext {
            base_dir: base,
            home: root.join("home"),
            tmp_root: root.join("tmp"),
            uid: Some(euid()),
            now_secs: NOW,
        };
        // The root must be owner-only for scratch dirs to be reported.
        let root = ctx.tmp_root.join(format!("claude-{}", euid()));
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o700);
        Fx {
            _td: td,
            ctx,
            handle,
        }
    }

    fn info(fx: &Fx, started_at: Option<u64>) -> SessionInfo {
        SessionInfo {
            pid: 4242,
            cwd: PathBuf::from("/Users/x/repos/dev/csq"),
            config_dir: fx.handle.clone(),
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

    fn write_registry(fx: &Fx, body: &str) {
        fs::write(fx.ctx.home.join(".claude/sessions/4242.json"), body).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn registry_fifo_returns_promptly_with_fields_absent() {
        use std::os::unix::ffi::OsStrExt;
        let f = fx();
        let path = f.ctx.home.join(".claude/sessions/4242.json");
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = f.ctx.clone();
        let i = info(&f, Some(100));
        std::thread::spawn(move || {
            let _ = tx.send(enrich(vec![i], &ctx));
        });
        let rows = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("a FIFO at the registry path must not hang the listing");
        assert_eq!(rows[0].session_id, None);
    }

    #[test]
    fn oversized_registry_is_rejected() {
        let f = fx();
        let pad = "x".repeat((MAX_REGISTRY_BYTES as usize) + 1);
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100500,"sessionId":"{SID}","x":"{pad}"}}"#),
        );
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].session_id, None);
    }

    #[test]
    fn registry_pid_mismatch_gives_no_session_id() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":9999,"startedAt":100000,"sessionId":"{SID}","name":"n"}}"#),
        );
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, None);
        assert_eq!(rows[0].name, None);
    }

    #[test]
    fn matching_registry_supplies_session_id_and_name() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100500,"sessionId":"{SID}","name":"csq-04"}}"#),
        );
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].session_id.as_deref(), Some(SID));
        assert_eq!(rows[0].name.as_deref(), Some("csq-04"));
    }

    #[test]
    fn missing_registry_gives_fields_absent() {
        let f = fx();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, None);
        assert_eq!(rows[0].name, None);
        assert_eq!(rows[0].scratch_dir, None);
    }

    #[test]
    #[cfg(unix)]
    fn scratch_dir_reported_only_when_it_exists() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir, None, "dir not created yet");

        let derived = croot(&f).join("-Users-x-repos-dev-csq").join(SID);
        fs::create_dir_all(&derived).unwrap();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir.as_deref(), Some(derived.as_path()));
    }

    #[test]
    #[cfg(unix)]
    fn scratch_dir_falls_back_to_exact_name_scan() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        let other = croot(&f).join("-some-other-slug").join(SID);
        fs::create_dir_all(&other).unwrap();
        // A near-miss name must not match.
        fs::create_dir_all(croot(&f).join("-x").join(format!("{SID}-2"))).unwrap();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir.as_deref(), Some(other.as_path()));
    }

    #[test]
    fn unsafe_session_id_is_rejected() {
        let f = fx();
        write_registry(
            &f,
            r#"{"pid":4242,"startedAt":100000,"sessionId":"../../etc"}"#,
        );
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].session_id, None);
    }

    #[test]
    fn stale_registry_from_an_earlier_pid_holder_is_absent() {
        let f = fx();
        // startedAt one hour BEFORE this process started.
        write_registry(
            &f,
            &format!(
                r#"{{"pid":4242,"startedAt":{},"sessionId":"{SID}","name":"old"}}"#,
                (10_000u64 - 3600) * 1000
            ),
        );
        let rows = enrich(vec![info(&f, Some(10_000))], &f.ctx);
        assert_eq!(rows[0].session_id, None);
        assert_eq!(rows[0].name, None);
        assert_eq!(rows[0].scratch_dir, None);
    }

    #[test]
    fn registry_window_edges() {
        let f = fx();
        // started_at = 10_000 s; NOW = 1_000_000 s
        for (ms, accepted) in [
            (10_000_000u64, true),  // exactly started_at
            (10_600_000, true),     // written 10 minutes after started_at (slow start)
            (9_999_000, true),      // started_at - 1 s: inside the tolerance
            (9_998_999, false),     // just before started_at - 1 s
            (1_000_060_000, true),  // now + 60 s: the clock-skew edge
            (1_000_061_000, false), // now + 61 s
        ] {
            write_registry(
                &f,
                &format!(r#"{{"pid":4242,"startedAt":{ms},"sessionId":"{SID}"}}"#),
            );
            let rows = enrich(vec![info(&f, Some(10_000))], &f.ctx);
            assert_eq!(rows[0].session_id.is_some(), accepted, "startedAt={ms}");
        }
    }

    #[test]
    fn registry_without_started_at_is_absent() {
        let f = fx();
        write_registry(&f, &format!(r#"{{"pid":4242,"sessionId":"{SID}"}}"#));
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].session_id, None);
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_scratch_candidate_is_omitted() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        let victim = f.ctx.tmp_root.join("victim");
        fs::create_dir_all(&victim).unwrap();
        let slug = croot(&f).join("-Users-x-repos-dev-csq");
        fs::create_dir_all(&slug).unwrap();
        std::os::unix::fs::symlink(&victim, slug.join(SID)).unwrap();
        // The scan fallback must not follow a symlinked candidate either.
        let other = croot(&f).join("-elsewhere");
        fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink(&victim, other.join(SID)).unwrap();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir, None);
    }

    #[test]
    #[cfg(unix)]
    fn plain_files_in_the_tmp_root_scan_are_silent_and_skipped() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        let r = croot(&f);
        fs::write(r.join("daemon.log"), b"x").unwrap();
        fs::create_dir_all(r.join("-aaa")).unwrap();
        fs::write(r.join("-aaa").join(SID), b"x").unwrap();
        fs::create_dir_all(r.join("-elsewhere").join(SID)).unwrap();
        let uid = euid();
        for p in [r.join("daemon.log"), r.join("-aaa").join(SID)] {
            let c = check_dir(&p, uid, false);
            assert!(matches!(c, DirCheck::NotADirectory));
            assert_eq!(warn_tag(&c, true), None, "plain file must not WARN");
        }
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir, Some(r.join("-elsewhere").join(SID)));
    }

    #[test]
    #[cfg(unix)]
    fn security_rejections_always_warn_with_fixed_tags() {
        let f = fx();
        let r = croot(&f);
        let real = f.ctx.tmp_root.join("real-slug");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, r.join("-linked")).unwrap();
        let c = check_dir(&r.join("-linked"), euid(), false);
        assert_eq!(warn_tag(&c, true), Some("scratch_is_symlink"));
        let c = check_dir(&r, euid().wrapping_add(1), false);
        assert_eq!(warn_tag(&c, true), Some("scratch_wrong_owner"));
        set_mode(&r, 0o755);
        let c = check_dir(&r, euid(), true);
        assert_eq!(warn_tag(&c, true), Some("scratch_root_not_private"));
        // A non-directory at a DERIVED path (quiet_plain = false) still warns.
        fs::write(f.ctx.tmp_root.join("file"), b"x").unwrap();
        let c = check_dir(&f.ctx.tmp_root.join("file"), euid(), false);
        assert_eq!(warn_tag(&c, false), Some("scratch_not_a_directory"));
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_scan_directory_is_not_followed() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        let real = f.ctx.tmp_root.join("real-slug");
        fs::create_dir_all(real.join(SID)).unwrap();
        std::os::unix::fs::symlink(&real, croot(&f).join("-linked")).unwrap();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir, None);
    }

    #[test]
    #[cfg(unix)]
    fn scratch_root_with_group_or_other_bits_is_omitted() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        fs::create_dir_all(croot(&f).join("-Users-x-repos-dev-csq").join(SID)).unwrap();
        for mode in [0o750, 0o705, 0o755] {
            set_mode(&croot(&f), mode);
            let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
            assert_eq!(rows[0].scratch_dir, None, "mode {mode:o}");
        }
        set_mode(&croot(&f), 0o700);
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert!(rows[0].scratch_dir.is_some(), "0700 root is accepted");
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_scratch_root_is_omitted() {
        let f = fx();
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        let real = f.ctx.tmp_root.join("real-root");
        fs::create_dir_all(real.join("-Users-x-repos-dev-csq").join(SID)).unwrap();
        set_mode(&real, 0o700);
        let link = croot(&f);
        fs::remove_dir(&link).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir, None);
    }

    #[test]
    #[cfg(unix)]
    fn scratch_owned_by_another_uid_is_omitted() {
        let mut f = fx();
        // The tree is owned by the real euid; expect a different uid.
        let other = euid().wrapping_add(1);
        f.ctx.uid = Some(other);
        let root = f.ctx.tmp_root.join(format!("claude-{other}"));
        fs::create_dir_all(root.join("-Users-x-repos-dev-csq").join(SID)).unwrap();
        set_mode(&root, 0o700);
        write_registry(
            &f,
            &format!(r#"{{"pid":4242,"startedAt":100000,"sessionId":"{SID}"}}"#),
        );
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].scratch_dir, None);
    }

    #[test]
    fn decimal_marker_resolves_to_its_slot() {
        let f = fx();
        fs::write(f.handle.join(".csq-account"), "7").unwrap();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].account_slot, Some(7));
    }

    #[test]
    fn uuid_marker_resolves_to_its_slot() {
        let f = fx();
        let mut p = ProfilesFile::empty();
        p.by_slot
            .insert("9".into(), UUID_A.parse::<IdentityId>().unwrap());
        save(&profiles_path(&f.ctx.base_dir), &p).unwrap();
        fs::write(f.handle.join(".csq-account"), UUID_A).unwrap();
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].account_slot, Some(9));
    }

    #[test]
    fn missing_marker_gives_no_slot_and_never_parses_dir_name() {
        let f = fx();
        // Handle dir name `term-4242` must not yield 4242 or any slot.
        let rows = enrich(vec![info(&f, Some(100))], &f.ctx);
        assert_eq!(rows[0].account_slot, None);
    }

    #[test]
    fn missing_start_time_omits_the_row() {
        let f = fx();
        let rows = enrich(vec![info(&f, None), info(&f, Some(55))], &f.ctx);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].started_at, 55);
    }

    #[test]
    #[cfg(unix)]
    fn project_slug_replaces_slash_and_dot() {
        assert_eq!(
            project_slug(Path::new("/Users/alice/repos/dev/csq")),
            "-Users-alice-repos-dev-csq"
        );
        assert_eq!(project_slug(Path::new("/a/.b/c.d")), "-a--b-c-d");
    }

    fn listing(sessions: Vec<SessionInfo>, unreadable: Vec<u32>) -> Listing {
        Listing {
            sessions,
            unreadable_claude: unreadable.len(),
            unreadable_pids: unreadable,
            incomplete: false,
            incomplete_cause: None,
            restricted: false,
        }
    }

    #[test]
    fn codex_rows_follow_claude_rows_and_claude_rows_are_unchanged() {
        let f = fx();
        let claude_only = enrich(vec![info(&f, Some(100))], &f.ctx);
        let mut codex = info(&f, Some(200));
        codex.pid = 5000;
        let both = rows_from_listings(
            listing(vec![info(&f, Some(100))], vec![]),
            Some(listing(vec![codex], vec![])),
            &f.ctx,
        );
        assert_eq!(both.rows.len(), 2);
        assert_eq!(
            both.rows[0], claude_only[0],
            "claude row identical to the Claude-only listing"
        );
        let c = &both.rows[1];
        assert_eq!((c.surface, c.pid, c.started_at), (SURFACE_CODEX, 5000, 200));
        assert_eq!(c.handle_dir, f.handle);
        assert_eq!(
            (c.session_id.clone(), c.name.clone(), c.scratch_dir.clone()),
            (None, None, None)
        );
    }

    #[test]
    fn a_blind_spot_in_either_table_is_a_blind_spot_of_the_listing() {
        let f = fx();
        let mut codex = listing(vec![], vec![91]);
        codex.incomplete = true;
        codex.restricted = true;
        let l = rows_from_listings(listing(vec![], vec![7]), Some(codex), &f.ctx);
        assert_eq!(l.unreadable_pids, vec![7, 91]);
        assert!(l.incomplete && l.restricted);
    }

    /// B2: the registry resolves names only over a listing that saw every process. An
    /// unreadable pid alone (not `incomplete`, not `restricted`) must make it incomplete.
    #[test]
    fn a_listing_with_an_unreadable_pid_is_not_complete() {
        let whole = RowsListing {
            rows: vec![],
            unreadable_pids: vec![],
            incomplete: false,
            restricted: false,
            incomplete_cause: None,
        };
        assert!(whole.is_complete());
        let mut l = whole.clone();
        l.unreadable_pids = vec![41];
        assert!(!l.is_complete(), "an unreadable pid may carry the name");
        let mut l = whole.clone();
        l.incomplete = true;
        assert!(!l.is_complete());
        let mut l = whole;
        l.restricted = true;
        assert!(!l.is_complete());
    }

    fn gap(unreadable: Vec<u32>) -> RowsListing {
        RowsListing {
            rows: vec![],
            unreadable_pids: unreadable,
            incomplete: false,
            restricted: false,
            incomplete_cause: None,
        }
    }

    /// An unreadable-only gap is retried exactly once; a clean second read replaces it, a
    /// persistent gap stays (and name resolution then says `undetermined`).
    #[test]
    fn an_unreadable_only_gap_is_retried_once_and_no_more() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let healed = retry_if_only_unreadable(gap(vec![5]), || {
            calls.set(calls.get() + 1);
            Some(gap(vec![]))
        });
        assert!(healed.is_complete());
        assert_eq!(calls.get(), 1);
        let still = retry_if_only_unreadable(gap(vec![5]), || {
            calls.set(calls.get() + 1);
            Some(gap(vec![5]))
        });
        assert!(!still.is_complete());
        assert_eq!(calls.get(), 2, "one retry per listing, not a loop");
        let failed = retry_if_only_unreadable(gap(vec![5]), || None);
        assert_eq!(
            failed.unreadable_pids,
            vec![5],
            "an unreadable retry keeps the first"
        );
    }

    /// A gap that is NOT only unreadable pids is never retried: `incomplete` / `restricted`
    /// are not transient.
    #[test]
    fn incomplete_or_restricted_or_whole_listings_are_not_retried() {
        let mut inc = gap(vec![5]);
        inc.incomplete = true;
        let mut res = gap(vec![]);
        res.restricted = true;
        for l in [inc, res, gap(vec![])] {
            let out = retry_if_only_unreadable(l.clone(), || panic!("must not retry"));
            assert_eq!(out, l);
        }
    }
}
