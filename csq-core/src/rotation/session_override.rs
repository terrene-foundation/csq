//! Per-session auto-swap override — one terminal opts in or out of the daemon
//! rotator regardless of the machine-wide `rotation.json` `enabled` flag.
//!
//! # Where it lives
//!
//! `<base>/term-<pid>/.csq-auto-swap.json`, INSIDE the session's handle dir
//! (spec 02 §2.7 "Per-session override"). It is not an `ACCOUNT_BOUND_ITEMS`
//! entry: `csq swap` and the rotator's own repoint rewrite only those links, so
//! the file stays put when the session moves to another account, and it is
//! removed with the handle dir (`remove_dir_all` in every reaper). Nothing ever
//! copies it into `config-N/`.
//!
//! # States
//!
//! The stored value is `on` or `off`; an absent file means "follow the machine
//! setting" (`default`). The rotator rotates a handle dir iff the override is
//! `on`, or the override is absent AND the machine setting is enabled
//! ([`rotates`]). Threshold, cooldown and exclusions stay machine-level.
//!
//! # Fail direction
//!
//! A file that cannot be read as a bounded private regular file, or does not
//! parse to exactly `{"auto_swap":"on"|"off"}`, is [`SessionRotationState::Unreadable`]
//! and counts as `off` for that session only: ambiguity must never move a live
//! session between accounts (`guard-reader-writer-parity.md` MUST-2). The writer
//! only ever produces `on`/`off` (or deletes the file for `default`), so the
//! reader accepts every form the writer can produce.
//!
//! # Errors
//!
//! [`SessionRotationError`] carries fixed text only — no path, no OS error — so
//! it is safe to print and to send across the desktop IPC boundary.

use crate::platform::fs::{
    read_private_regular_nofollow_bounded, write_private_tmp_synced_retained,
};
use crate::platform::process::is_pid_alive;
use crate::session::handle_dir::{is_term_handle_dir_name, term_handle_dir_name};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Name of the override file inside a `term-<pid>/` handle dir.
pub const OVERRIDE_FILE: &str = ".csq-auto-swap.json";

/// The file is `{"auto_swap":"off"}` plus a newline; anything longer is not ours.
const OVERRIDE_MAX_BYTES: u64 = 256;

/// What an operator asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRotationMode {
    /// This session is moved when over threshold, even if the machine setting is off.
    On,
    /// This session is never moved by the rotator, even if the machine setting is on.
    Off,
    /// Remove the override: follow the machine setting.
    Default,
}

impl SessionRotationMode {
    /// Parses the wire spelling (`on` / `off` / `default`), exactly.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            "default" => Some(Self::Default),
            _ => None,
        }
    }
}

/// What the rotator finds in a handle dir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionRotationState {
    /// No override file: follow the machine setting.
    Default,
    /// Override `on`.
    On,
    /// Override `off`.
    Off,
    /// A file is present but is not a readable, well-formed override. Treated as `off`.
    Unreadable,
}

impl SessionRotationState {
    /// The fixed wire spelling (`default` / `on` / `off` / `unreadable`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::On => "on",
            Self::Off => "off",
            Self::Unreadable => "unreadable",
        }
    }
}

/// Whether the rotator may move a session: override `on`, or no override and the
/// machine setting enabled. `Off` and `Unreadable` never rotate.
pub fn rotates(machine_enabled: bool, state: SessionRotationState) -> bool {
    match state {
        SessionRotationState::On => true,
        SessionRotationState::Off | SessionRotationState::Unreadable => false,
        SessionRotationState::Default => machine_enabled,
    }
}

/// Why a per-session operation was refused or failed. Fixed text; never a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionRotationError {
    /// The terminal number is not a positive integer (optionally `term-` prefixed).
    #[error("session must be a terminal number such as 12345 or term-12345")]
    InvalidSession,
    /// The csq base directory cannot be resolved.
    #[error("the csq base directory is unavailable")]
    BaseUnavailable,
    /// No `term-<pid>` handle dir exists for that terminal.
    #[error("no such terminal session")]
    NotFound,
    /// The handle dir is a link, not a directory, or does not sit directly under the base.
    #[error("that is not a csq terminal session under this base directory")]
    OutsideBase,
    /// The current terminal is not a csq `term-<pid>` handle-dir session.
    #[error(
        "this terminal is not a csq session; run it inside `csq run`, or pass --session <TERM-PID>"
    )]
    NotInSession,
    /// The override could not be written or removed.
    #[error("could not update the per-session auto-swap setting")]
    Write,
    /// The sessions under the base directory could not be listed.
    #[error("could not list terminal sessions")]
    List,
}

/// Parses the one body the writer produces: a JSON object with exactly the key
/// `auto_swap` whose string value is `on` or `off`. A struct derive is NOT used:
/// serde would also accept a one-element ARRAY for a struct, a form no writer emits.
fn parse_override(bytes: &[u8]) -> Option<SessionRotationState> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    match object.get("auto_swap")?.as_str()? {
        "on" => Some(SessionRotationState::On),
        "off" => Some(SessionRotationState::Off),
        _ => None,
    }
}

/// Reads the override of `handle_dir` with the bounded, no-follow, owner-checked
/// reader. Absent = `Default`; any read or parse failure = `Unreadable` (counts
/// as `off`). Never writes and never follows a symlink at the file.
pub fn read_override(handle_dir: &Path) -> SessionRotationState {
    let path = handle_dir.join(OVERRIDE_FILE);
    match read_private_regular_nofollow_bounded(&path, OVERRIDE_MAX_BYTES) {
        Ok(None) => SessionRotationState::Default,
        Ok(Some(bytes)) => parse_override(&bytes).unwrap_or(SessionRotationState::Unreadable),
        Err(_) => SessionRotationState::Unreadable,
    }
}

/// Writes (`on` / `off`) or removes (`default`) the override in `handle_dir`.
///
/// The change is made under TWO bounded locks, taken in the daemon rotator's own
/// order: first the per-handle-dir swap lock
/// ([`crate::credentials::keychain::lock_handle_dir_for_swap_bounded`], a real
/// lock on macOS, `NotNeeded` elsewhere), then the repoint lock
/// (`crate::session::handle_dir::lock_repoint_bounded`, the `.swap.lock` the
/// rotator takes in `lock_repoint_custody`), on EVERY platform. The rotator
/// re-reads this file only AFTER it holds both, so a writer that returns has
/// published before the rotator's re-read, and a writer still waiting cannot
/// publish between that re-read and the repoint (the rotator holds the lock it
/// needs): an `off` is never followed by a rotation it could have stopped (S2).
/// Both sides acquire swap lock then repoint lock, and every acquisition here is
/// bounded (about 20 s and 10 s), so no wait cycle is possible and a stuck holder
/// costs a refusal, never a hang. A lock that cannot be taken within its bound is
/// [`SessionRotationError::Write`] and nothing is changed.
///
/// The file is staged through [`write_private_tmp_synced_retained`] (owner-only,
/// fsynced, creator-owned cleanup) and published by rename, so a crash never
/// leaves a torn file (`rules/security.md` MUST 4, 5, 5a). `handle_dir` MUST
/// already be admitted ([`resolve_session_dir`], or a dir `csq run` just created).
pub fn write_override(
    handle_dir: &Path,
    mode: SessionRotationMode,
) -> Result<(), SessionRotationError> {
    use crate::session::handle_dir::lock_repoint_bounded;
    write_override_locked(handle_dir, mode, || lock_repoint_bounded(handle_dir))
}

/// [`write_override`] with the repoint-lock acquisition injected, so a test can
/// give it a short bound.
fn write_override_locked(
    handle_dir: &Path,
    mode: SessionRotationMode,
    repoint_lock: impl FnOnce() -> Result<
        Option<crate::platform::lock::FileLockGuard>,
        crate::error::PlatformError,
    >,
) -> Result<(), SessionRotationError> {
    use crate::credentials::keychain::{lock_handle_dir_for_swap_bounded, BoundedLockOutcome};
    let _swap_guard = match lock_handle_dir_for_swap_bounded(handle_dir) {
        BoundedLockOutcome::Acquired(guard) => Some(guard),
        BoundedLockOutcome::NotNeeded => None,
        BoundedLockOutcome::TimedOut | BoundedLockOutcome::Failed => {
            return Err(SessionRotationError::Write)
        }
    };
    let _repoint_guard = match repoint_lock() {
        Ok(Some(guard)) => guard,
        Ok(None) | Err(_) => return Err(SessionRotationError::Write),
    };
    let path = handle_dir.join(OVERRIDE_FILE);
    let value = match mode {
        SessionRotationMode::On => "on",
        SessionRotationMode::Off => "off",
        SessionRotationMode::Default => {
            return match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(SessionRotationError::Write),
            };
        }
    };
    let body = format!("{{\"auto_swap\":\"{value}\"}}\n");
    let writer = write_private_tmp_synced_retained(&path, body.as_bytes())
        .map_err(|_| SessionRotationError::Write)?;
    writer
        .replace(&path)
        .map_err(|_| SessionRotationError::Write)
}

/// Parses `12345` or `term-12345` into a positive terminal number.
pub fn parse_session_id(value: &str) -> Result<u32, SessionRotationError> {
    let digits = value.strip_prefix("term-").unwrap_or(value);
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SessionRotationError::InvalidSession);
    }
    match digits.parse::<u32>() {
        Ok(pid) if pid > 0 => Ok(pid),
        _ => Err(SessionRotationError::InvalidSession),
    }
}

/// Admits the handle dir of terminal `pid`: `<canonical base>/term-<pid>` must be a
/// real directory (not a symlink) whose canonical form is exactly that name
/// directly under the canonical base. The returned path is canonical.
pub fn resolve_session_dir(base_dir: &Path, pid: u32) -> Result<PathBuf, SessionRotationError> {
    if pid == 0 {
        return Err(SessionRotationError::InvalidSession);
    }
    let canonical_base = base_dir
        .canonicalize()
        .map_err(|_| SessionRotationError::BaseUnavailable)?;
    let name = term_handle_dir_name(pid);
    let candidate = canonical_base.join(&name);
    let meta = match std::fs::symlink_metadata(&candidate) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SessionRotationError::NotFound)
        }
        Err(_) => return Err(SessionRotationError::OutsideBase),
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(SessionRotationError::OutsideBase);
    }
    let resolved = candidate
        .canonicalize()
        .map_err(|_| SessionRotationError::OutsideBase)?;
    let direct_child = resolved.parent() == Some(canonical_base.as_path())
        && resolved.file_name().and_then(|n| n.to_str()) == Some(name.as_str());
    if !direct_child {
        return Err(SessionRotationError::OutsideBase);
    }
    Ok(resolved)
}

/// Resolves the terminal the caller is running in from its `CLAUDE_CONFIG_DIR`
/// value: it must be named `term-<pid>` and canonicalize to exactly the admitted
/// `<canonical base>/term-<pid>` ([`resolve_session_dir`]). Anything else — unset,
/// a `config-N` dir, a `term-` dir under another base, a path with `..` that
/// lands elsewhere — is refused.
pub fn resolve_current_session(
    base_dir: &Path,
    config_dir: Option<&Path>,
) -> Result<(u32, PathBuf), SessionRotationError> {
    let raw = config_dir.ok_or(SessionRotationError::NotInSession)?;
    let name = raw
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(SessionRotationError::NotInSession)?;
    if !is_term_handle_dir_name(name) {
        return Err(SessionRotationError::NotInSession);
    }
    let pid = parse_session_id(name).map_err(|_| SessionRotationError::NotInSession)?;
    let resolved = resolve_session_dir(base_dir, pid).map_err(|e| match e {
        SessionRotationError::NotFound => SessionRotationError::OutsideBase,
        other => other,
    })?;
    let env_canonical = raw
        .canonicalize()
        .map_err(|_| SessionRotationError::OutsideBase)?;
    if env_canonical != resolved {
        return Err(SessionRotationError::OutsideBase);
    }
    Ok((pid, resolved))
}

/// Reads the override of terminal `pid` after admitting its handle dir.
pub fn get(base_dir: &Path, pid: u32) -> Result<SessionRotationState, SessionRotationError> {
    let dir = resolve_session_dir(base_dir, pid)?;
    Ok(read_override(&dir))
}

/// Sets the override of terminal `pid` after admitting its handle dir, and returns
/// the state now on disk (read back, so an unwritable result is not reported as set).
pub fn set(
    base_dir: &Path,
    pid: u32,
    mode: SessionRotationMode,
) -> Result<SessionRotationState, SessionRotationError> {
    let dir = resolve_session_dir(base_dir, pid)?;
    write_override(&dir, mode)?;
    Ok(read_override(&dir))
}

/// One live session that carries an explicit override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SessionEntry {
    /// The terminal number (`term-<pid>`).
    pub pid: u32,
    /// `on`, `off` or `unreadable` (never `default`: those are not listed).
    pub mode: SessionRotationState,
}

/// Lists the live terminals under `base_dir` that carry an explicit override
/// (`on`, `off` or `unreadable`), ordered by terminal number. A terminal whose
/// owning process is gone is not listed. A base directory that does not exist has
/// no sessions; any other listing failure is an error, not an empty list.
pub fn list_overrides(base_dir: &Path) -> Result<Vec<SessionEntry>, SessionRotationError> {
    let canonical_base = match base_dir.canonicalize() {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(SessionRotationError::BaseUnavailable),
    };
    let entries = std::fs::read_dir(&canonical_base).map_err(|_| SessionRotationError::List)?;
    let mut found = Vec::new();
    for entry in entries {
        // A per-entry error is a listing failure, never a silently shorter list.
        let entry = entry.map_err(|_| SessionRotationError::List)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_term_handle_dir_name(&name) {
            continue;
        }
        let Ok(pid) = parse_session_id(&name) else {
            continue;
        };
        if !is_pid_alive(pid) {
            continue;
        }
        // An entry that fails admission (a symlink, a file) is not a session.
        let Ok(dir) = resolve_session_dir(&canonical_base, pid) else {
            continue;
        };
        let mode = read_override(&dir);
        if mode != SessionRotationState::Default {
            found.push(SessionEntry { pid, mode });
        }
    }
    found.sort_by_key(|e| e.pid);
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn session_dir(base: &Path, pid: u32) -> PathBuf {
        let dir = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// S2 (every platform): the writer takes the rotator's repoint lock, bounded.
    /// While another holder has it the write is refused and changes nothing; once
    /// released the same write succeeds and releases the lock again.
    #[test]
    fn write_override_takes_the_bounded_repoint_lock_on_every_platform() {
        let base = TempDir::new().unwrap();
        let dir = session_dir(base.path(), 7001);
        let lock = crate::session::handle_dir::repoint_lock_path(&dir);
        let held = crate::platform::lock::HeldOnOtherThread::hold(&lock);
        let short = || {
            crate::session::handle_dir::lock_repoint_bounded_with(
                &dir,
                2,
                std::time::Duration::from_millis(1),
            )
        };
        assert_eq!(
            write_override_locked(&dir, SessionRotationMode::Off, short),
            Err(SessionRotationError::Write)
        );
        assert!(
            !dir.join(OVERRIDE_FILE).exists(),
            "a refused write changes nothing"
        );
        drop(held);
        write_override_locked(&dir, SessionRotationMode::Off, short).unwrap();
        assert_eq!(read_override(&dir), SessionRotationState::Off);
        // The writer released the repoint lock: the rotator can take it.
        let free = crate::session::handle_dir::lock_repoint_bounded_with(
            &dir,
            2,
            std::time::Duration::from_millis(1),
        )
        .unwrap();
        assert!(free.is_some());
    }

    // ── precedence ───────────────────────────────────────────────────────

    #[test]
    fn precedence_table_machine_by_session() {
        use SessionRotationState::*;
        // (machine enabled, session state, rotates)
        let table = [
            (true, Default, true),
            (false, Default, false),
            (true, On, true),
            (false, On, true),
            (true, Off, false),
            (false, Off, false),
            // Ambiguity moves nothing, whichever way the machine is set.
            (true, Unreadable, false),
            (false, Unreadable, false),
        ];
        for (machine, state, expected) in table {
            assert_eq!(
                rotates(machine, state),
                expected,
                "machine={machine} session={state:?}"
            );
        }
    }

    // ── reader / writer parity ───────────────────────────────────────────

    #[test]
    fn writer_forms_round_trip_through_the_reader() {
        let dir = TempDir::new().unwrap();
        let handle = session_dir(dir.path(), 4242);
        assert_eq!(read_override(&handle), SessionRotationState::Default);
        for (mode, state) in [
            (SessionRotationMode::On, SessionRotationState::On),
            (SessionRotationMode::Off, SessionRotationState::Off),
        ] {
            write_override(&handle, mode).unwrap();
            assert_eq!(read_override(&handle), state);
        }
        write_override(&handle, SessionRotationMode::Default).unwrap();
        assert_eq!(read_override(&handle), SessionRotationState::Default);
        assert!(!handle.join(OVERRIDE_FILE).exists());
        // Removing an absent override is not an error.
        write_override(&handle, SessionRotationMode::Default).unwrap();
    }

    #[test]
    fn corrupt_or_foreign_forms_read_as_unreadable() {
        let dir = TempDir::new().unwrap();
        let handle = session_dir(dir.path(), 4242);
        let path = handle.join(OVERRIDE_FILE);
        let cases: [&[u8]; 8] = [
            b"",
            b"{not json",
            b"{\"auto_swap\":\"maybe\"}",
            b"{\"auto_swap\":\"default\"}",
            b"{\"auto_swap\":true}",
            b"{\"auto_swap\":\"on\",\"extra\":1}",
            b"{}",
            b"[\"on\"]",
        ];
        for bytes in cases {
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(
                read_override(&handle),
                SessionRotationState::Unreadable,
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        // Over the byte bound: not ours, not read.
        std::fs::write(&path, vec![b' '; 4096]).unwrap();
        assert_eq!(read_override(&handle), SessionRotationState::Unreadable);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_override_is_unreadable_not_followed() {
        let dir = TempDir::new().unwrap();
        let handle = session_dir(dir.path(), 4242);
        let elsewhere = dir.path().join("elsewhere.json");
        std::fs::write(&elsewhere, b"{\"auto_swap\":\"on\"}").unwrap();
        std::os::unix::fs::symlink(&elsewhere, handle.join(OVERRIDE_FILE)).unwrap();
        assert_eq!(read_override(&handle), SessionRotationState::Unreadable);
    }

    #[cfg(unix)]
    #[test]
    fn override_is_owner_only_and_a_looser_file_is_replaced_privately() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let handle = session_dir(dir.path(), 4242);
        let path = handle.join(OVERRIDE_FILE);
        // A pre-existing world-readable file is replaced, not edited in place.
        std::fs::write(&path, b"{\"auto_swap\":\"off\"}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_override(&handle, SessionRotationMode::On).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(read_override(&handle), SessionRotationState::On);
        // No staging file is left behind (`.swap-lock` and `.swap.lock` are the
        // persistent locks `write_override` takes, not stages).
        let leftovers: Vec<_> = std::fs::read_dir(&handle)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != OVERRIDE_FILE && n != ".swap-lock" && n != ".swap.lock")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_override_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let handle = session_dir(dir.path(), 4242);
        let path = handle.join(OVERRIDE_FILE);
        std::fs::write(&path, b"{\"auto_swap\":\"on\"}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(read_override(&handle), SessionRotationState::Unreadable);
    }

    // ── admission ────────────────────────────────────────────────────────

    #[test]
    fn parse_session_id_accepts_bare_and_prefixed_positive_numbers_only() {
        assert_eq!(parse_session_id("123"), Ok(123));
        assert_eq!(parse_session_id("term-123"), Ok(123));
        for bad in [
            "",
            "0",
            "term-",
            "term-0",
            "-1",
            "1.5",
            "12a",
            "term-term-1",
            "../1",
            "term-1/..",
            " 1",
            "99999999999",
            "4294967296",
        ] {
            assert_eq!(
                parse_session_id(bad),
                Err(SessionRotationError::InvalidSession),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn resolve_session_dir_requires_an_existing_real_term_dir() {
        let dir = TempDir::new().unwrap();
        assert_eq!(
            resolve_session_dir(dir.path(), 77),
            Err(SessionRotationError::NotFound)
        );
        assert_eq!(
            resolve_session_dir(dir.path(), 0),
            Err(SessionRotationError::InvalidSession)
        );
        let handle = session_dir(dir.path(), 77);
        assert_eq!(
            resolve_session_dir(dir.path(), 77).unwrap(),
            handle.canonicalize().unwrap()
        );
        // A regular file named like a handle dir is not a session.
        std::fs::write(dir.path().join("term-88"), b"x").unwrap();
        assert_eq!(
            resolve_session_dir(dir.path(), 88),
            Err(SessionRotationError::OutsideBase)
        );
        // A missing base is refused, not created.
        assert_eq!(
            resolve_session_dir(&dir.path().join("nope"), 77),
            Err(SessionRotationError::BaseUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_session_dir_refuses_a_symlinked_term_dir() {
        let base = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("term-5")).unwrap();
        assert_eq!(
            resolve_session_dir(base.path(), 5),
            Err(SessionRotationError::OutsideBase)
        );
        // A link to ANOTHER term dir inside the base is refused too.
        session_dir(base.path(), 6);
        std::os::unix::fs::symlink(base.path().join("term-6"), base.path().join("term-7")).unwrap();
        assert_eq!(
            resolve_session_dir(base.path(), 7),
            Err(SessionRotationError::OutsideBase)
        );
        assert!(
            !outside.path().join(OVERRIDE_FILE).exists(),
            "nothing may be written through a refused link"
        );
    }

    #[test]
    fn resolve_current_session_accepts_only_this_bases_term_dir() {
        let base = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let handle = session_dir(base.path(), 4242);
        let (pid, resolved) = resolve_current_session(base.path(), Some(&handle)).unwrap();
        assert_eq!(pid, 4242);
        assert_eq!(resolved, handle.canonicalize().unwrap());

        // Unset, a config dir, a non-term name.
        assert_eq!(
            resolve_current_session(base.path(), None),
            Err(SessionRotationError::NotInSession)
        );
        let config = base.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();
        assert_eq!(
            resolve_current_session(base.path(), Some(&config)),
            Err(SessionRotationError::NotInSession)
        );
        // A term dir under a DIFFERENT base, even with the same name.
        let foreign = session_dir(other.path(), 4242);
        assert_eq!(
            resolve_current_session(base.path(), Some(&foreign)),
            Err(SessionRotationError::OutsideBase)
        );
        // A term dir nested one level below the base.
        let nested = session_dir(&base.path().join("sub"), 4242);
        assert_eq!(
            resolve_current_session(base.path(), Some(&nested)),
            Err(SessionRotationError::OutsideBase)
        );
        // `..` that escapes and comes back is judged on the canonical form.
        let dotted = base.path().join("sub").join("..").join("term-4242");
        assert_eq!(
            resolve_current_session(base.path(), Some(&dotted))
                .unwrap()
                .1,
            handle.canonicalize().unwrap()
        );
        let escaping = other
            .path()
            .join("..")
            .join(other.path().file_name().unwrap());
        let escaping = escaping.join("term-4242");
        assert_eq!(
            resolve_current_session(base.path(), Some(&escaping)),
            Err(SessionRotationError::OutsideBase)
        );
    }

    #[test]
    fn set_and_get_round_trip_and_default_removes_the_file() {
        let base = TempDir::new().unwrap();
        let handle = session_dir(base.path(), 31337);
        assert_eq!(get(base.path(), 31337), Ok(SessionRotationState::Default));
        assert_eq!(
            set(base.path(), 31337, SessionRotationMode::On),
            Ok(SessionRotationState::On)
        );
        assert_eq!(get(base.path(), 31337), Ok(SessionRotationState::On));
        assert_eq!(
            set(base.path(), 31337, SessionRotationMode::Off),
            Ok(SessionRotationState::Off)
        );
        assert_eq!(
            set(base.path(), 31337, SessionRotationMode::Default),
            Ok(SessionRotationState::Default)
        );
        assert!(!handle.join(OVERRIDE_FILE).exists());
        assert_eq!(
            set(base.path(), 99, SessionRotationMode::On),
            Err(SessionRotationError::NotFound)
        );
    }

    #[test]
    fn errors_carry_fixed_text_without_paths() {
        let base = TempDir::new().unwrap();
        let shown = [
            SessionRotationError::InvalidSession,
            SessionRotationError::BaseUnavailable,
            SessionRotationError::NotFound,
            SessionRotationError::OutsideBase,
            SessionRotationError::NotInSession,
            SessionRotationError::Write,
            SessionRotationError::List,
        ]
        .map(|e| e.to_string());
        for text in shown {
            assert!(!text.contains(base.path().to_str().unwrap()), "{text}");
            assert!(!text.contains('/'), "{text}");
        }
    }

    // ── listing ──────────────────────────────────────────────────────────

    #[test]
    fn list_overrides_reports_only_live_sessions_with_an_explicit_override() {
        let base = TempDir::new().unwrap();
        let own = std::process::id();
        // Live, explicit `on`.
        let live = session_dir(base.path(), own);
        write_override(&live, SessionRotationMode::On).unwrap();
        // A dead owner with an override: not listed. The pid is PROBED dead, not assumed.
        let dead_pid = (4_000_000u32..4_000_500)
            .find(|pid| !is_pid_alive(*pid))
            .expect("a dead pid in a 500-wide probe window");
        let dead = session_dir(base.path(), dead_pid);
        write_override(&dead, SessionRotationMode::Off).unwrap();
        // A live process's term dir WITHOUT an override (the process-1 init pid is
        // alive on unix): following the machine, so not listed.
        session_dir(base.path(), 1);
        // Not a term dir: ignored.
        std::fs::create_dir_all(base.path().join("config-1")).unwrap();

        let listed = list_overrides(base.path()).unwrap();
        assert_eq!(
            listed,
            vec![SessionEntry {
                pid: own,
                mode: SessionRotationState::On
            }]
        );
        // An unreadable override is surfaced as such, not hidden.
        std::fs::write(live.join(OVERRIDE_FILE), b"{bad").unwrap();
        assert_eq!(
            list_overrides(base.path()).unwrap(),
            vec![SessionEntry {
                pid: own,
                mode: SessionRotationState::Unreadable
            }]
        );
        // A base that does not exist has no sessions.
        assert_eq!(list_overrides(&base.path().join("absent")), Ok(Vec::new()));
    }

    /// S2: `write_override` is ordered against the rotator through the per-handle-dir
    /// swap lock. While another holder has it, the write waits; after release it lands.
    #[cfg(target_os = "macos")]
    #[test]
    fn write_override_waits_for_the_per_handle_dir_swap_lock() {
        let base = TempDir::new().unwrap();
        let handle = session_dir(base.path(), 31338);
        let held = crate::platform::lock::try_lock_file(
            &crate::credentials::keychain::swap_lock_path(&handle),
        )
        .unwrap()
        .expect("test takes the free swap lock");

        let writer_dir = handle.clone();
        let writer =
            std::thread::spawn(move || write_override(&writer_dir, SessionRotationMode::Off));
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(
            !handle.join(OVERRIDE_FILE).exists(),
            "the override must not be written while the swap lock is held elsewhere"
        );

        drop(held);
        assert_eq!(writer.join().unwrap(), Ok(()));
        assert_eq!(read_override(&handle), SessionRotationState::Off);
    }
}
