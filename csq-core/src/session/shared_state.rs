//! Cross-slot session sharing — conversation history survives `csq swap`.
//!
//! # The problem
//!
//! csq isolates each account slot's vendor CLI state by redirecting that
//! CLI's home env var at spawn time (`CODEX_HOME` -> `config-<N>/`,
//! `KIMI_CODE_HOME` -> `native-homes/kimi-<N>/`, `GROK_HOME` ->
//! `native-homes/grok-<N>/`). That correctly isolates IDENTITY — but it also
//! isolates CONVERSATION state, so swapping to a different slot loses
//! `resume`. Measured on a maintainer host: 6,820 codex rollout files
//! stranded in `config-11`, 451 in `config-12`, invisible to every other
//! slot's `codex resume`.
//!
//! Claude Code does not have this problem: `config-N/` owns only identity
//! (`.credentials.json`, `.claude.json`, markers) and symlinks `projects`,
//! `sessions`, `history.jsonl`, etc. out to a single shared `~/.claude/`
//! (see [`super::isolation::SHARED_ITEMS`]). This module gives the other
//! surfaces (Codex, Kimi, Grok) the same split: a declared subset of each
//! slot's vendor home is relocated to `<base>/shared-state/<surface>/` and
//! replaced with a symlink, so every slot bound to that surface reads and
//! writes the SAME conversation store.
//!
//! # Scope discipline
//!
//! [`SharedStateSpec::shared`] is a POSITIVE allowlist, derived from a live
//! install, not a guess. Identity (`codex-auth.json`, `auth.json`,
//! `credentials/`, `oauth/`, `device_id`, `agent_id`), entitlement-sensitive
//! caches (`codex-models_cache.json`, `models_cache.json` — a shared cache
//! could offer a model the CURRENT account cannot use), and per-slot
//! config/telemetry (`codex-installation_id`, `region`, `config.toml`,
//! `trusted_folders.toml`) are deliberately NOT on any list here — sharing
//! them would cross-contaminate accounts. Grok's `active_sessions.json` +
//! `.lock` are a LIVE session registry, not history, and are conservatively
//! kept per-slot to avoid cross-slot corruption of an in-flight lock.
//!
//! # Safety model
//!
//! Migration is MERGE, never CLOBBER, and FAIL-CLOSED:
//!
//! - Directory entries are relocated via same-filesystem [`std::fs::rename`]
//!   of each child, which is atomic and never destroys data: a failure
//!   midway leaves the unmoved children exactly where they were, and the
//!   slot dir is converted to a symlink ONLY once it is fully drained. No
//!   separate backup copy is needed for this path — nothing is ever
//!   deleted except a byte-for-byte-verified duplicate (see
//!   `files_identical`).
//! - File entries (`*.jsonl`) are read, merged in memory with the existing
//!   shared content, and written back via a tmp-file + atomic rename. The
//!   pre-migration slot file's content survives inside the merged shared
//!   file (that IS the backup — every line either lands in the shared file
//!   or was a proven duplicate of a line already there).
//! - Running the migration twice is a no-op the second time: an entry
//!   already symlinked to the correct shared target is left untouched.
//! - An entry whose on-disk shape disagrees with its declared kind, or
//!   whose slot path is a symlink to something OTHER than the expected
//!   shared target, is refused rather than guessed at.

use crate::providers::catalog::Surface;
use crate::session::isolation;
use crate::types::AccountNum;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Whether a shared entry is a single file or a directory tree.
///
/// DECLARED, never inferred from the name — see `session::handle_dir`'s
/// `SharedKind` for the defect class this avoids (a directory pre-created
/// where codex-cli needed a file, `failed to start embedded app server`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
}

/// One relpath, under a slot's vendor home, that is conversation state
/// shared account-wide rather than slot-owned.
#[derive(Debug, Clone, Copy)]
pub struct SharedEntry {
    pub relpath: &'static str,
    pub kind: EntryKind,
}

/// The declared shared-state partition for one [`Surface`].
#[derive(Debug)]
pub struct SharedStateSpec {
    pub surface: Surface,
    pub shared: &'static [SharedEntry],
}

/// Codex: rollout transcripts, the resume index, the command-history log,
/// and the per-thread write locks a resumed session needs to contend on
/// from whichever slot resumes it. `codex-skills`, `codex-plugins`,
/// `codex-models_cache.json`, `codex-version.json`, `codex-installation_id`,
/// and any `*.sqlite` state are deliberately NOT here — see the module doc.
pub const CODEX_SHARED: SharedStateSpec = SharedStateSpec {
    surface: Surface::Codex,
    shared: &[
        SharedEntry {
            relpath: "codex-sessions",
            kind: EntryKind::Dir,
        },
        SharedEntry {
            relpath: "codex-session_index.jsonl",
            kind: EntryKind::File,
        },
        SharedEntry {
            relpath: "codex-history.jsonl",
            kind: EntryKind::File,
        },
        SharedEntry {
            relpath: "codex-thread-writer-locks",
            kind: EntryKind::Dir,
        },
    ],
};

/// Kimi: transcripts, the resume index, and the search index built over
/// them. `credentials/`, `oauth/`, `device_id`, `config.toml`,
/// `migrations-effort.json`, `region`, `tui.toml`, `workspace-trust`,
/// `workspaces.json` stay per-slot — see the module doc.
pub const KIMI_SHARED: SharedStateSpec = SharedStateSpec {
    surface: Surface::Kimi,
    shared: &[
        SharedEntry {
            relpath: "sessions",
            kind: EntryKind::Dir,
        },
        SharedEntry {
            relpath: "session_index.jsonl",
            kind: EntryKind::File,
        },
        SharedEntry {
            relpath: "search-index",
            kind: EntryKind::Dir,
        },
    ],
};

/// Grok: transcripts only. `active_sessions.json` + `.lock` are a LIVE
/// session registry (not history) and are conservatively kept per-slot —
/// sharing a live lock registry risks cross-slot corruption. `auth.json`,
/// `agent_id`, `config.toml`, `models_cache.json`, `trusted_folders.toml`
/// stay per-slot — see the module doc.
pub const GROK_SHARED: SharedStateSpec = SharedStateSpec {
    surface: Surface::Grok,
    shared: &[SharedEntry {
        relpath: "sessions",
        kind: EntryKind::Dir,
    }],
};

/// Every declared spec. Exactly the three surfaces named in the design —
/// `ClaudeCode` already shares via [`isolation::SHARED_ITEMS`]; `Gemini` is
/// out of scope until evidence of the same split is gathered on a live
/// install (module doc's evidence discipline).
pub const ALL_SHARED_SPECS: &[&SharedStateSpec] = &[&CODEX_SHARED, &KIMI_SHARED, &GROK_SHARED];

/// The declared spec for `surface`, if this module covers it.
#[must_use]
pub fn spec_for(surface: Surface) -> Option<&'static SharedStateSpec> {
    ALL_SHARED_SPECS
        .iter()
        .copied()
        .find(|s| s.surface == surface)
}

#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("{0} has no declared cross-slot shared-state spec")]
    UnsupportedSurface(Surface),
    #[error("io error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error(
        "{relpath} at {path} is not shaped as declared, or is a symlink to an \
         unexpected target — refusing to guess"
    )]
    UnexpectedShape {
        relpath: &'static str,
        path: PathBuf,
    },
    #[error(
        "refusing to migrate {surface}: {count} live writer(s) detected (pid(s): {pids}). \
         Stop the running {surface} session(s) first, or pass --force --surface {surface} \
         to override (not recommended while a session is active)."
    )]
    LiveWriters {
        surface: Surface,
        count: usize,
        pids: String,
    },
    #[error(
        "refusing to migrate {0}: could not determine whether a live writer is running. \
         Pass --force --surface {0} to override (not recommended)."
    )]
    LiveWritersUndeterminable(Surface),
    #[error(
        "cannot create a real symlink at {path}: this host produced a \
         {produced} instead, which stops resolving to the shared store the \
         first time it is rewritten. On Windows, enable Developer Mode (or \
         grant SeCreateSymbolicLinkPrivilege) and re-run. The content is \
         already in the shared store, so re-running is safe."
    )]
    LinkNotSupported { path: PathBuf, produced: String },
    // S-LOW-3: `path` is pre-redacted (`sanitize::redact_path`) at every
    // construction site, not a raw `PathBuf` — this variant's message is
    // reachable from `csq sessions share`'s own stderr, so an un-redacted
    // `$HOME`-rooted path here would leak the operator's username exactly
    // like the credential-path cases `security.md` MUST-2 already covers.
    #[error(
        "{relpath} at {path} is not shaped as declared, or is a symlink to an \
         unexpected target — refusing to guess"
    )]
    UnexpectedShapeDynamic { relpath: String, path: String },
    #[error(
        "cannot merge codex's cross-slot sqlite state: no `sqlite3` binary found. \
         Checked ${env_var} and PATH. Install sqlite3, or set ${env_var} to an \
         absolute path to one."
    )]
    Sqlite3NotFound { env_var: &'static str },
    #[error("`sqlite3` at {binary} exited with an error against {path}: {detail}")]
    SqliteCommandFailed {
        binary: PathBuf,
        path: PathBuf,
        detail: String,
    },
    #[error("refusing to merge {basename}: PRAGMA integrity_check failed on {path}: {detail}")]
    SqliteIntegrityCheckFailed {
        basename: String,
        path: PathBuf,
        detail: String,
    },
    #[error(
        "refusing to merge {basename}: `_sqlx_migrations` differs between {a_path} and \
         {b_path} — schemas are not reconciled by this migration. Upgrade codex-cli on \
         the lagging slot so every slot's migration set matches, then re-run."
    )]
    SqliteMigrationsMismatch {
        basename: String,
        a_path: PathBuf,
        b_path: PathBuf,
    },
    #[error(
        "refusing to merge {basename}: `threads` has a column named {column:?}, which \
         fails the identifier allowlist (^[A-Za-z_][A-Za-z0-9_]*$) — refusing to \
         interpolate it into SQL"
    )]
    SqliteUnsafeColumnName { basename: String, column: String },
    #[error(
        "refusing to attach {path} for a sqlite merge: the path contains a newline or \
         NUL byte"
    )]
    SqliteUnsafeAttachPath { path: PathBuf },
    #[error(
        "refusing to merge {basename}: {path} changed after the pre-merge snapshot was taken \
         (a codex-cli session appears to have started writing to it mid-merge). This \
         basename's merge has been rolled back; every original for it is intact. Re-run once \
         no codex session is active."
    )]
    SqliteChangedDuringMerge { basename: String, path: PathBuf },
    #[error(
        "a codex cross-slot sqlite migration is in progress; wait for `csq sessions share` \
         to finish and retry the launch"
    )]
    CodexShareLockContended,
    #[error(
        "refusing to merge {basename}: {path} has a `{object_type}` named {object_name:?} in \
         `sqlite_master` — an ordinary codex-cli database never carries a view or trigger, so \
         this indicates a hand-modified or malicious file; refusing to trust it rather than \
         attach and copy its schema in"
    )]
    SqliteUntrustedSchemaObject {
        basename: String,
        path: PathBuf,
        object_type: String,
        object_name: String,
    },
    #[error(
        "cannot acquire the codex cross-slot share lock: timed out after ~{bound_secs}s \
         waiting for it to be released. Live codex session(s) observed just before waiting \
         (pid(s)): {pids}. This is NOT overridden by --force — the lock protects the on-disk \
         session store from being retargeted while it is in use. Wait for the running \
         session(s) to exit, then re-run `csq sessions share`."
    )]
    CodexShareLockTimedOut { bound_secs: u64, pids: String },
}

impl ShareError {
    fn io(path: &Path, source: io::Error) -> Self {
        ShareError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// `<base>/shared-state/<surface>/` — the single cross-slot store.
///
/// Deliberately OUTSIDE every `config-N` / `native-homes/<surface>-N`, so a
/// [`crate::accounts::move_slot`] rename of a slot never has to touch it.
#[must_use]
pub fn shared_root(base: &Path, surface: Surface) -> PathBuf {
    base.join("shared-state").join(surface.as_str())
}

// ─────────────────────────────────────────────────────────────────────────
// F8: codex cross-slot share lock — reader/writer, not mutual-exclusion
// ─────────────────────────────────────────────────────────────────────────
//
// `codex_sqlite::share_codex_sqlite`'s live-writer guard (`ps`/`tasklist`,
// plus handle-dir bookkeeping) is a SNAPSHOT taken once at the top of the
// migration. Nothing stops a `csq run` codex launch from starting in the
// window between that snapshot and the migration's first mutation — the
// exact race this module's FM-10 fingerprint checks exist to catch, but
// only after the fact. This lock closes the window structurally instead of
// detecting it after the write has already landed: a launch acquires the
// lock SHARED (any number of launches may hold it at once — they are not
// each other's problem), and a migration acquires it EXCLUSIVE (excluding
// every launch AND every other migration) for its entire run.
//
// One POSIX `flock` (Unix) / byte-range `LockFileEx` (Windows) underlies
// both — the same primitive `platform::lock` uses for cross-process
// exclusion elsewhere in csq, extended here with the SHARED mode neither
// `platform::lock` nor any existing caller needed before now.

/// Guard for the codex cross-slot share lock, released on `Drop`. Whether
/// it was acquired SHARED or EXCLUSIVE is not tracked on the guard itself —
/// callers ask for the mode they need via [`acquire_codex_share_lock_shared`]
/// or the crate-internal exclusive acquire, and the guard is opaque either
/// way.
pub struct CodexShareLockGuard {
    _file: fs::File,
}

impl std::fmt::Debug for CodexShareLockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexShareLockGuard")
            .finish_non_exhaustive()
    }
}

/// `<base>/shared-state/codex/.share.lock` — created (never unlinked) the
/// first time either side acquires it, matching `platform::lock`'s
/// persistent-lock-file posture (an unlink/re-open race can otherwise let
/// two callers each believe they hold the only lock).
fn codex_share_lock_path(base: &Path) -> PathBuf {
    shared_root(base, Surface::Codex).join(".share.lock")
}

/// S-LOW-5: refuses a symlink planted at ANY path component from `base`
/// down to (and including) `dir`, not just `dir` itself. A single
/// `symlink_metadata` on the leaf component (the original S-L7 check) does
/// not see a symlink planted at an INTERMEDIATE component — e.g.
/// `base/shared-state` itself — because the OS silently follows it while
/// resolving the leaf path for `symlink_metadata`'s own lookup, so
/// `create_dir_all`/`set_permissions` would still land inside whatever that
/// intermediate symlink points at. This walks every component of `dir`
/// relative to `base` (never `base` itself, which the caller already
/// trusts — it is `csq`'s own base dir, not attacker-controlled), `lstat`-
/// ing each one individually via `symlink_metadata` so a symlink anywhere
/// in the chain is caught before any component below it is ever resolved
/// through it.
fn assert_no_symlink_in_chain(base: &Path, dir: &Path) -> Result<(), ShareError> {
    let relative = dir.strip_prefix(base).unwrap_or(dir);
    let mut probe = base.to_path_buf();
    for component in relative.components() {
        probe.push(component);
        if let Ok(meta) = fs::symlink_metadata(&probe) {
            if meta.file_type().is_symlink() {
                let relpath = probe
                    .strip_prefix(base)
                    .unwrap_or(&probe)
                    .to_string_lossy()
                    .into_owned();
                return Err(ShareError::UnexpectedShapeDynamic {
                    relpath,
                    path: crate::cli_deps::sanitize::redact_path(&probe),
                });
            }
        }
    }
    Ok(())
}

/// Opens (creating if absent) the share-lock file, 0600, under a 0700
/// `shared-state/codex/` directory.
///
/// S-L7: refuses BOTH the directory and the lock file itself if either is a
/// symlink. `assert_no_symlink_in_chain` (S-LOW-5) checks every component
/// from `base` down to `shared-state/codex`, not just the leaf — a planted
/// `shared-state/codex -> /somewhere/else`, OR a planted
/// `shared-state -> /somewhere/else` with a real `codex/` dir underneath,
/// is caught before `create_dir_all`/`set_permissions` ever follow it. On
/// the file, `O_NOFOLLOW` makes the OPEN ITSELF refuse a symlinked
/// `.share.lock` (`ELOOP`) rather than merely inspecting it first — closing
/// the TOCTOU window a separate lstat-then-open pair would leave open
/// between the check and the open call.
fn open_codex_share_lock_file(base: &Path) -> Result<fs::File, ShareError> {
    let dir = shared_root(base, Surface::Codex);
    assert_no_symlink_in_chain(base, &dir)?;
    fs::create_dir_all(&dir).map_err(|e| ShareError::io(&dir, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| ShareError::io(&dir, e))?;
    }
    let path = codex_share_lock_path(base);
    let mut open_options = fs::OpenOptions::new();
    open_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = open_options.open(&path).map_err(|e| {
        #[cfg(unix)]
        {
            if e.raw_os_error() == Some(libc::ELOOP) {
                return ShareError::UnexpectedShapeDynamic {
                    relpath: ".share.lock".to_string(),
                    path: crate::cli_deps::sanitize::redact_path(&path),
                };
            }
        }
        ShareError::io(&path, e)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| ShareError::io(&path, e))?;
    }
    Ok(file)
}

#[cfg(unix)]
fn share_lock_try(file: &fs::File, exclusive: bool) -> io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    let op = (if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    }) | libc::LOCK_NB;
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    if rc == 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

#[cfg(windows)]
fn share_lock_try(file: &fs::File, exclusive: bool) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let mut flags = LOCKFILE_FAIL_IMMEDIATELY;
    if exclusive {
        flags |= LOCKFILE_EXCLUSIVE_LOCK;
    }
    let ok = unsafe { LockFileEx(handle, flags, 0, u32::MAX, u32::MAX, &mut overlapped) };
    if ok != 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        if code == ERROR_LOCK_VIOLATION || code == ERROR_IO_PENDING {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

fn acquire_share_lock_bounded(
    base: &Path,
    exclusive: bool,
    attempts: u32,
    delay: std::time::Duration,
) -> Result<Option<CodexShareLockGuard>, ShareError> {
    let file = open_codex_share_lock_file(base)?;
    for attempt in 0..attempts.max(1) {
        let acquired = share_lock_try(&file, exclusive)
            .map_err(|e| ShareError::io(&codex_share_lock_path(base), e))?;
        if acquired {
            return Ok(Some(CodexShareLockGuard { _file: file }));
        }
        if attempt + 1 < attempts.max(1) {
            std::thread::sleep(delay);
        }
    }
    Ok(None)
}

/// Acquire the codex share lock SHARED.
///
/// Non-blocking-with-bound, NOT indefinite: up to 20 attempts, 100ms apart
/// (~2s total), then [`ShareError::CodexShareLockContended`] rather than
/// hanging a `csq run` launch behind a long-running migration. Multiple
/// callers may hold this simultaneously — it excludes only the EXCLUSIVE
/// (migration) side, never a sibling SHARED holder.
///
/// Called by `launch_codex` (held across the codex spawn) so a migration
/// cannot retarget the session store out from under an in-flight launch;
/// see [`codex_sqlite::share_codex_sqlite`] for the EXCLUSIVE side.
pub fn acquire_codex_share_lock_shared(base: &Path) -> Result<CodexShareLockGuard, ShareError> {
    acquire_share_lock_bounded(base, false, 20, std::time::Duration::from_millis(100))?
        .ok_or(ShareError::CodexShareLockContended)
}

/// EXCLUSIVE-side bound (S-M1). `launch_codex` holds the SHARED side for
/// the ENTIRE supervised codex run — "spawn through however long this
/// codex child lives" (`csq/src/cli/commands/run.rs`) — which can be hours,
/// so an unbounded blocking `flock(LOCK_EX)` (the prior behaviour) could
/// hang `csq sessions share` indefinitely with no signal to the operator at
/// all. The two outcomes this bound has to separate: another migration or
/// admin invocation briefly finishing (at most a few seconds for a
/// many-slot sqlite merge) vs. a live codex session holding SHARED for the
/// remainder of its run (effectively indefinite from this command's
/// perspective). 30 attempts * 100ms = ~3s — a little more patient than the
/// SHARED side's own ~2s bound (`acquire_codex_share_lock_shared`), since
/// this side is an operator-invoked one-shot command rather than a launch
/// hot path — sits with wide margin above the first outcome and returns
/// control to the operator long before the second would ever end on its
/// own.
const EXCLUSIVE_LOCK_ATTEMPTS: u32 = 30;
const EXCLUSIVE_LOCK_DELAY_MS: u64 = 100;

/// Acquire the codex share lock EXCLUSIVE — BOUNDED, never blocking
/// indefinitely (S-M1). Held for the whole
/// [`codex_sqlite::share_codex_sqlite`] run (every basename's plan AND
/// apply phase), so no launch can slip a SHARED acquire in between this
/// call returning and the migration's first mutation.
///
/// On timeout, reports the codex session(s) actually observed — scanned
/// via [`detect_live_writers`] BEFORE attempting the lock (no lock is
/// needed to read a handle dir's `.live-pid`), so the message names real
/// evidence rather than inferring "someone" from the lock's contended
/// state alone. The scan and the lock attempt are not synchronized, so the
/// named pid(s) may not be the exact final holder by the time the bound
/// expires — but they are genuine evidence observed just before waiting,
/// which is truthful and actionable, unlike a bare "timed out". `--force`
/// does NOT shorten or skip this wait: it only skips the separate
/// live-writer refusal ([`ensure_no_live_writers`]) once the lock is
/// actually held — see this function's callers.
fn acquire_codex_share_lock_exclusive_bounded_reporting(
    base: &Path,
) -> Result<CodexShareLockGuard, ShareError> {
    acquire_codex_share_lock_exclusive_bounded_reporting_with(
        base,
        EXCLUSIVE_LOCK_ATTEMPTS,
        std::time::Duration::from_millis(EXCLUSIVE_LOCK_DELAY_MS),
    )
}

/// [`acquire_codex_share_lock_exclusive_bounded_reporting`] with the
/// attempts/delay INJECTED, so a test can prove the timeout report's
/// content (pids named, bound stated) without paying the production bound's
/// full wall-clock cost. Production always routes through the fixed-bound
/// wrapper above; only tests call this directly.
fn acquire_codex_share_lock_exclusive_bounded_reporting_with(
    base: &Path,
    attempts: u32,
    delay: std::time::Duration,
) -> Result<CodexShareLockGuard, ShareError> {
    let live = detect_live_writers(base, Surface::Codex).unwrap_or_default();
    match acquire_share_lock_bounded(base, true, attempts, delay)? {
        Some(guard) => Ok(guard),
        None => {
            let bound_secs = (u64::from(attempts) * delay.as_millis() as u64) / 1000;
            Err(ShareError::CodexShareLockTimedOut {
                bound_secs,
                pids: format_live_writer_pids(&live),
            })
        }
    }
}

/// Test-only bounded (never indefinitely blocking) variants of both modes,
/// so a test can prove exclusivity without risking a hung suite.
#[cfg(test)]
fn acquire_codex_share_lock_exclusive_bounded(
    base: &Path,
    attempts: u32,
    delay: std::time::Duration,
) -> Result<Option<CodexShareLockGuard>, ShareError> {
    acquire_share_lock_bounded(base, true, attempts, delay)
}

#[cfg(test)]
fn acquire_codex_share_lock_shared_bounded(
    base: &Path,
    attempts: u32,
    delay: std::time::Duration,
) -> Result<Option<CodexShareLockGuard>, ShareError> {
    acquire_share_lock_bounded(base, false, attempts, delay)
}

/// The per-slot vendor home a surface's declared relpaths resolve against.
pub fn slot_home(base: &Path, surface: Surface, slot: AccountNum) -> Result<PathBuf, ShareError> {
    match surface {
        Surface::Codex => Ok(base.join(format!("config-{slot}"))),
        Surface::Kimi | Surface::Grok => Ok(crate::providers::native::native_home_path(
            base, slot, surface,
        )),
        Surface::ClaudeCode | Surface::Gemini => Err(ShareError::UnsupportedSurface(surface)),
    }
}

/// Every slot with an on-disk vendor home for `surface` — filesystem
/// enumeration, not credential/identity resolution, so a slot mid-migration
/// or with an ambiguous binding is still found. Migration only ever touches
/// the declared relpaths, so a false-positive slot (a home dir with no
/// vendor data in it) is simply a no-op.
#[must_use]
pub fn discover_slots(base: &Path, surface: Surface) -> Vec<AccountNum> {
    let (scan_dir, prefix): (PathBuf, String) = match surface {
        Surface::Codex => (base.to_path_buf(), "config-".to_string()),
        Surface::Kimi | Surface::Grok => {
            (base.join("native-homes"), format!("{}-", surface.as_str()))
        }
        Surface::ClaudeCode | Surface::Gemini => return Vec::new(),
    };
    let Ok(entries) = fs::read_dir(&scan_dir) else {
        return Vec::new();
    };
    let mut slots: Vec<AccountNum> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter_map(|name| name.strip_prefix(prefix.as_str()).map(str::to_string))
        .filter_map(|numstr| numstr.parse::<u16>().ok())
        .filter_map(|n| AccountNum::try_from(n).ok())
        .collect();
    slots.sort_by_key(|a| a.get());
    slots.dedup_by_key(|a| a.get());
    slots
}

/// Per-entry outcome of a (real or dry-run) migration attempt.
#[derive(Debug, Clone, Default)]
pub struct EntryReport {
    pub relpath: &'static str,
    /// The slot path was already a symlink to the correct shared target —
    /// nothing to do.
    pub already_shared: bool,
    /// Files relocated (directory entries) or 1 for a merged file entry.
    pub files_moved: u64,
    pub bytes_moved: u64,
    /// Directory-merge only: children removed because they were
    /// byte-for-byte identical to what the shared store already held.
    pub duplicates_removed: u64,
    /// Directory-merge only: children kept under a `.slot<N>`-suffixed name
    /// because they collided by name with DIFFERENT content.
    pub conflicts_kept_both: u64,
    /// File-merge only (JSONL): new lines appended to the shared file.
    pub lines_added: u64,
    /// File-merge only (JSONL): incoming lines that were duplicates of a
    /// line already in the shared file (by `(id, updated_at)` when both
    /// parse, else exact line text).
    pub lines_deduped: u64,
    /// Directory-merge only: `true` when some content could not be
    /// relocated (a rename failed) — the slot dir is left as a REAL
    /// directory, not converted to a symlink, so the next run retries the
    /// remainder. Never set alongside data loss: unmoved content stays in
    /// place.
    pub partial: bool,
}

/// Per-slot report: one [`EntryReport`] per declared shared entry.
#[derive(Debug, Clone)]
pub struct SlotReport {
    pub surface: Surface,
    pub slot: AccountNum,
    pub entries: Vec<EntryReport>,
}

/// Migrate (or, when `dry_run`, plan) every declared entry for one slot.
///
/// Idempotent: an entry already symlinked to its shared target reports
/// `already_shared: true` and is left untouched.
pub fn share_slot(
    base: &Path,
    surface: Surface,
    slot: AccountNum,
    dry_run: bool,
) -> Result<SlotReport, ShareError> {
    let spec = spec_for(surface).ok_or(ShareError::UnsupportedSurface(surface))?;
    let mut entries = Vec::with_capacity(spec.shared.len());
    for entry in spec.shared {
        entries.push(share_entry(base, surface, slot, entry, dry_run)?);
    }
    Ok(SlotReport {
        surface,
        slot,
        entries,
    })
}

/// Attach only this slot to an already initialized shared store, without migration.
///
/// `None` means not eligible: a target is missing/wrong-shaped, the slot home
/// is not a real directory, or any local entry is not absent/already linked.
/// All entries are inspected before publication. Only native, no-replacement
/// symlink creation is permitted; shared targets are never written or seeded.
/// An I/O error (including after some links were installed) returns `Err` and
/// MUST NOT trigger migration fallback. A retry can reuse the installed links.
///
/// Each link publication is atomic, not the whole set. This does not lock out
/// unrelated external namespace changes or claim crash durability. In
/// particular, no emptiness check authorizes deleting an ordinary local entry.
pub fn attach_slot_to_existing_shared(
    base: &Path,
    surface: Surface,
    slot: AccountNum,
    dry_run: bool,
) -> Result<Option<SlotReport>, ShareError> {
    attach_slot_with(base, surface, slot, dry_run, create_shared_symlink)
}

fn attach_slot_with(
    base: &Path,
    surface: Surface,
    slot: AccountNum,
    dry_run: bool,
    mut create: impl FnMut(&Path, &Path, EntryKind) -> io::Result<()>,
) -> Result<Option<SlotReport>, ShareError> {
    let spec = spec_for(surface).ok_or(ShareError::UnsupportedSurface(surface))?;
    // Relative symlink targets would resolve relative to the slot home.
    if !base.is_absolute() {
        return Err(ShareError::io(
            base,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared-state attach requires an absolute base",
            ),
        ));
    }
    let home = slot_home(base, surface, slot)?;
    match home.symlink_metadata() {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ShareError::io(&home, e)),
    }
    let root = shared_root(base, surface);
    let mut entries = Vec::with_capacity(spec.shared.len());
    for entry in spec.shared {
        let target = root.join(entry.relpath);
        match target.symlink_metadata() {
            Ok(meta)
                if match entry.kind {
                    EntryKind::Dir => meta.is_dir(),
                    EntryKind::File => meta.is_file(),
                } => {}
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ShareError::io(&target, e)),
        }
        let link = home.join(entry.relpath);
        let already_shared = match link.symlink_metadata() {
            Ok(meta) if meta.file_type().is_symlink() => {
                if fs::read_link(&link).map_err(|e| ShareError::io(&link, e))? != target {
                    return Ok(None);
                }
                true
            }
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(ShareError::io(&link, e)),
        };
        entries.push(EntryReport {
            relpath: entry.relpath,
            already_shared,
            ..Default::default()
        });
    }
    for (entry, report) in spec.shared.iter().zip(&mut entries) {
        if dry_run || report.already_shared {
            continue;
        }
        let link = home.join(entry.relpath);
        let target = root.join(entry.relpath);
        if let Err(e) = create(&target, &link, entry.kind) {
            // A concurrent attach may have installed exactly the same link.
            // Never unlink, replace, copy over, or clean up an existing entry.
            if e.kind() != io::ErrorKind::AlreadyExists
                || !link
                    .symlink_metadata()
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                || fs::read_link(&link).map_err(|e| ShareError::io(&link, e))? != target
            {
                return Err(ShareError::io(&link, e));
            }
            report.already_shared = true;
        }
    }
    Ok(Some(SlotReport {
        surface,
        slot,
        entries,
    }))
}

fn create_shared_symlink(target: &Path, link: &Path, kind: EntryKind) -> io::Result<()> {
    #[cfg(unix)]
    {
        let _ = kind;
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        match kind {
            EntryKind::Dir => std::os::windows::fs::symlink_dir(target, link),
            EntryKind::File => std::os::windows::fs::symlink_file(target, link),
        }
    }
}

/// A live process that may be writing into the session store a migration is
/// about to relocate. `handle_dir` names the csq handle dir the pid was
/// found bound to, or a `<process scan: ...>` placeholder when the evidence
/// is a raw OS process match with no handle-dir bookkeeping behind it (see
/// [`detect_live_writers`] Signal 1 vs Signal 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveWriter {
    pub pid: u32,
    pub handle_dir: PathBuf,
}

/// Vendor CLI process names (`ps`/`tasklist` comm) that are independent,
/// process-level evidence of a live writer for `surface`. `codex-code-mode-host`
/// is codex's MCP-adjacent helper process, observed alive alongside `codex`
/// itself on a live host. Empty for a surface this module has no reliable
/// binary name for yet (kimi/grok — conservatively always
/// [`ShareError::LiveWritersUndeterminable`] until their detection is built).
fn vendor_process_names(surface: Surface) -> &'static [&'static str] {
    match surface {
        Surface::Codex => &["codex", "codex-code-mode-host"],
        Surface::Kimi | Surface::Grok | Surface::ClaudeCode | Surface::Gemini => &[],
    }
}

/// PIDs among `procs` (pid, basename) whose basename exactly matches one of
/// `names`. Pure and unit-testable without spawning a real process list —
/// [`list_running_processes`] is the only untestable I/O boundary.
fn matching_pids(procs: &[(u32, String)], names: &[&str]) -> Vec<u32> {
    procs
        .iter()
        .filter(|(_, comm)| names.contains(&comm.as_str()))
        .map(|(pid, _)| *pid)
        .collect()
}

/// Every running process as `(pid, basename)`, basename stripped of any
/// directory prefix (macOS `ps -o comm=` reports codex's helper process by
/// full path, e.g. `/Users/x/.codex/.../bin/codex-code-mode-host`) and, on
/// Windows, the `.exe` suffix. `Err` means the OS could not even be asked —
/// callers MUST treat that as "cannot determine", never as "found nothing".
#[cfg(unix)]
fn list_running_processes() -> Result<Vec<(u32, String)>, String> {
    // S-F6: resolved to an absolute path rather than "ps" on `PATH` — the
    // same posture `codex_sqlite`'s own process/binary resolution takes
    // (`session::codex_supervisor` and `providers::codex::ancestry` already
    // invoke `/bin/ps` for the identical reason), so a live-writer check
    // this module's own destructive rename path depends on cannot be
    // satisfied by an attacker-controlled `ps` earlier on `PATH`.
    // S-L4: env_clear + a minimal fixed env, mirroring
    // `session::codex_supervisor::process_start_time` and
    // `providers::codex::ancestry`'s identical `/bin/ps` invocations — an
    // inherited `LC_ALL`/locale or a `TZ` cannot change `ps`'s output
    // format out from under this parser, and PATH cannot be used to
    // smuggle a different `ps` in despite the absolute path already
    // ruling that out for THIS argv[0].
    let output = std::process::Command::new("/bin/ps")
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("PATH", "/usr/bin:/bin")
        .args(["-A", "-o", "pid=,comm="])
        .output()
        .map_err(|e| format!("could not run `ps`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`ps` exited with status {:?}",
            output.status.code()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (pid_str, comm) = line.split_once(' ')?;
            let pid = pid_str.trim().parse::<u32>().ok()?;
            let base = comm.trim().rsplit('/').next().unwrap_or(comm.trim());
            Some((pid, base.to_string()))
        })
        .collect())
}

#[cfg(windows)]
fn list_running_processes() -> Result<Vec<(u32, String)>, String> {
    // S-L4: env_clear so an inherited env var cannot alter `tasklist`'s
    // output format or locale out from under this parser. `tasklist.exe`
    // lives in `%SystemRoot%\System32`, which Windows searches before
    // consulting `PATH` for process creation, so clearing `PATH` here does
    // not risk failing to resolve it.
    let output = std::process::Command::new("tasklist")
        .env_clear()
        .args(["/FO", "CSV", "/NH"])
        .output()
        .map_err(|e| format!("could not run `tasklist`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`tasklist` exited with status {:?}",
            output.status.code()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(|line| {
            // CSV: "Image Name","PID","Session Name","Session#","Mem Usage"
            let fields: Vec<&str> = line.split(',').map(|f| f.trim_matches('"')).collect();
            if fields.len() < 2 {
                return None;
            }
            let name = fields[0].trim_end_matches(".exe");
            let pid = fields[1].trim().parse::<u32>().ok()?;
            Some((pid, name.to_string()))
        })
        .collect())
}

// Test-only injection seam for [`list_running_processes`]'s OS-wide
// process snapshot. `detect_live_writers` (the REAL, non-`_with` entry
// point every production caller uses — `ensure_no_live_writers`,
// `acquire_codex_share_lock_exclusive_bounded_reporting_with`, and the
// mid-loop recheck in `codex_sqlite::apply_basename_plan_with`) reads a
// HOST-WIDE `ps`/`tasklist` scan (Signal 1), so a test that expects "no
// live writer" or asserts the EXACT pid list is not hermetic when the test
// binary itself happens to be running as a descendant of a live
// `claude`/`codex` process — the case on every developer machine, and the
// case in CI whenever this suite is invoked from inside an agentic coding
// session. Same idiom as `csq/src/cli/commands/swap.rs`'s
// `COUNT_CODEX_ANCESTORS_OVERRIDE`: thread-local, defaults to "no
// override" (the real OS scan), RAII-reset on drop (including on test
// panic/unwind) so a reused test-harness thread never leaks an override
// into an unrelated test.
#[cfg(test)]
thread_local! {
    static LIST_RUNNING_PROCESSES_OVERRIDE: std::cell::RefCell<Option<Vec<(u32, String)>>> =
        const { std::cell::RefCell::new(None) };
}

/// RAII guard returned by [`force_list_running_processes`]; clears the
/// override on drop so a later test reusing the same harness thread always
/// starts from "no override" (the real process scan).
#[cfg(test)]
struct ListRunningProcessesOverrideGuard;

#[cfg(test)]
impl Drop for ListRunningProcessesOverrideGuard {
    fn drop(&mut self) {
        LIST_RUNNING_PROCESSES_OVERRIDE.with(|c| *c.borrow_mut() = None);
    }
}

/// Forces every live-writer check's OS-wide process snapshot on THIS
/// THREAD until the returned guard drops — the process-table injection
/// seam the governing task requires: no test may read the real process
/// table. Every caller reachable from `detect_live_writers` (directly or
/// through `ensure_no_live_writers`, the exclusive-lock timeout reporter,
/// or the sqlite merge's mid-loop recheck) is deterministic under this
/// override, regardless of what `claude`/`codex` processes happen to be
/// live on the host running the test.
#[cfg(test)]
fn force_list_running_processes(procs: Vec<(u32, String)>) -> ListRunningProcessesOverrideGuard {
    LIST_RUNNING_PROCESSES_OVERRIDE.with(|c| *c.borrow_mut() = Some(procs));
    ListRunningProcessesOverrideGuard
}

/// [`list_running_processes`] with the test override (if any) consulted
/// first. Production (`not(test)`) builds route straight to the real scan
/// — see the sibling definition below.
#[cfg(test)]
fn list_running_processes_checked() -> Result<Vec<(u32, String)>, String> {
    if let Some(forced) = LIST_RUNNING_PROCESSES_OVERRIDE.with(|c| c.borrow().clone()) {
        return Ok(forced);
    }
    list_running_processes()
}

/// Production build: no override exists, so this is a direct pass-through.
/// Kept as a separate `cfg` arm (rather than an `if cfg!(test)` inside one
/// function) so the override machinery above — including its
/// `thread_local!` — is compiled out of every non-test build entirely.
#[cfg(not(test))]
fn list_running_processes_checked() -> Result<Vec<(u32, String)>, String> {
    list_running_processes()
}

/// Detect live vendor sessions for `surface`.
///
/// WHY THIS EXISTS. The migration relocates a slot's session store with
/// per-file `rename`, which is atomic per file — but atomicity does not
/// help against a CONCURRENT WRITER. A live `codex` that writes a rollout
/// file into the old directory after that directory has been drained lands
/// its write in a path about to be replaced by a symlink, and the write
/// becomes invisible. On the maintainer's install that is 6,820 transcripts
/// of exposure, so the guard is a precondition, not a nicety.
///
/// FAIL-CLOSED, in four places, because the failure this prevents is silent
/// data loss and the failure it causes is a retry:
///   * the OS process list being unreadable is an `Err`, never "found nothing";
///   * an unreadable base dir is an `Err`, never "found nothing";
///   * a handle dir whose liveness cannot be read counts as live;
///   * a surface with no reliable detector at all is `LiveWritersUndeterminable`
///     rather than an empty list.
///
/// Two INDEPENDENT signals, combined by union (either one finding evidence
/// is enough to refuse):
///
/// 1. **Process-name scan** (`ps`/`tasklist`, `vendor_process_names`) — a
///    genuine running `codex` or `codex-code-mode-host` process, found
///    regardless of csq's own bookkeeping. Catches a bare `codex` invocation
///    or a handle dir whose `.live-pid` was removed by a cleanup sweep
///    while the process was still alive.
/// 2. **Handle-dir bookkeeping** (codex only) — csq launches every session
///    through a `term-<pid>` handle dir and records `.live-pid` there; a
///    codex handle dir is identified by the same dual-symlink shape codex's
///    handle-dir provisioning uses (`auth.json` AND `config.toml` both
///    present and both symlinks). Defense-in-depth alongside signal 1, not
///    a replacement for it.
pub fn detect_live_writers(base: &Path, surface: Surface) -> Result<Vec<LiveWriter>, ShareError> {
    let procs = list_running_processes_checked()
        .map_err(|_| ShareError::LiveWritersUndeterminable(surface))?;
    detect_live_writers_with(&procs, base, surface)
}

/// [`detect_live_writers`]'s core, with the OS process snapshot INJECTED
/// rather than read live. `detect_live_writers` is the real caller; tests
/// call this directly with a controlled `procs` list so the test's verdict
/// does not depend on what happens to be running on the machine `cargo
/// test` executes on — Signal 1 is host-wide by construction (it queries
/// every process, not just ones under `base`), so an un-injectable version
/// of this function would pass or fail depending on whether a real vendor
/// CLI happened to be running at test time (`test-hermeticity.md`).
fn detect_live_writers_with(
    procs: &[(u32, String)],
    base: &Path,
    surface: Surface,
) -> Result<Vec<LiveWriter>, ShareError> {
    let names = vendor_process_names(surface);
    if names.is_empty() {
        // No reliable detector for this surface yet — report that we
        // cannot tell rather than returning an empty list a caller would
        // read as "safe".
        return Err(ShareError::LiveWritersUndeterminable(surface));
    }

    let mut live: Vec<LiveWriter> = matching_pids(procs, names)
        .into_iter()
        .map(|pid| LiveWriter {
            pid,
            handle_dir: PathBuf::from(format!("<process scan: pid {pid}>")),
        })
        .collect();

    if !matches!(surface, Surface::Codex) {
        return Ok(live);
    }

    let entries = fs::read_dir(base).map_err(|e| ShareError::io(base, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| ShareError::io(base, e))?;
        let path = entry.path();
        let is_term_dir = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("term-"));
        if !is_term_dir {
            continue;
        }

        // Codex shape: `auth.json` AND `config.toml` both PRESENT. Those two
        // names together are codex-specific — a Claude Code handle dir has
        // neither — so presence alone identifies the surface.
        //
        // Deliberately NOT "both are symlinks". Handle-dir provisioning
        // creates them through `isolation::create_symlink_pub`, which
        // degrades to a hard link or a copy on a Windows host without
        // symlink privilege. Keying the guard on `is_symlink` made it read
        // those dirs as "not codex" and fail OPEN on exactly the platform
        // where the degradation happens — a guard blind to what the writer
        // actually produces (`guard-reader-writer-parity.md` MUST-1). The
        // widened test can only ever cause an extra REFUSAL, which is the
        // safe direction for a guard over an irreplaceable session store
        // (MUST-2).
        let codex_shaped = ["auth.json", "config.toml"]
            .iter()
            .all(|item| path.join(item).symlink_metadata().is_ok());
        if !codex_shaped {
            continue;
        }

        let pid_path = path.join(".live-pid");
        let raw = match fs::read_to_string(&pid_path) {
            Ok(r) => r,
            // No recorded pid: the dir is not an active session.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            // Present but unreadable — cannot prove it is idle, so treat as live.
            Err(_) => {
                live.push(LiveWriter {
                    pid: 0,
                    handle_dir: path.clone(),
                });
                continue;
            }
        };
        let Ok(pid) = raw.trim().parse::<u32>() else {
            // Malformed marker: cannot prove idle.
            live.push(LiveWriter {
                pid: 0,
                handle_dir: path.clone(),
            });
            continue;
        };
        if crate::platform::process::is_pid_alive(pid) {
            live.push(LiveWriter {
                pid,
                handle_dir: path.clone(),
            });
        }
    }
    Ok(live)
}

/// [`detect_live_writers`], reduced to the go/no-go a migration needs.
///
/// `force` skips the check entirely; every other path refuses on any doubt.
pub fn ensure_no_live_writers(
    base: &Path,
    surface: Surface,
    force: bool,
) -> Result<(), ShareError> {
    if force {
        return Ok(());
    }
    // Routes through the real `detect_live_writers`, NOT the injectable
    // `_with` variant — a `ps`/`tasklist` failure there is a hard `Err`
    // (`LiveWritersUndeterminable`), and that fail-closed behaviour must
    // reach this caller unchanged. Only tests bypass the real OS call, via
    // `ensure_no_live_writers_with` below.
    let live = detect_live_writers(base, surface)?;
    refuse_if_any_live(live, surface)
}

/// [`ensure_no_live_writers`]'s core with the process snapshot INJECTED —
/// see [`detect_live_writers_with`] for why. Test-only entry point.
#[cfg(test)]
fn ensure_no_live_writers_with(
    procs: &[(u32, String)],
    base: &Path,
    surface: Surface,
) -> Result<(), ShareError> {
    let live = detect_live_writers_with(procs, base, surface)?;
    refuse_if_any_live(live, surface)
}

/// Shared verdict-formatting tail for [`ensure_no_live_writers`] and
/// [`ensure_no_live_writers_with`] — one source for the operator-facing pid
/// list, so the two entry points cannot report it differently.
fn refuse_if_any_live(live: Vec<LiveWriter>, surface: Surface) -> Result<(), ShareError> {
    if live.is_empty() {
        return Ok(());
    }
    let count = live.len();
    let pids = format_live_writer_pids(&live);
    Err(ShareError::LiveWriters {
        surface,
        count,
        pids,
    })
}

/// Shared pid-list formatter for [`refuse_if_any_live`] and the EXCLUSIVE
/// share-lock timeout report (S-M1) — one source, so the two callers cannot
/// describe the same evidence differently. An empty `live` here (only
/// reachable from the lock-timeout path; [`refuse_if_any_live`] returns
/// `Ok` before formatting anything for an empty list) means the pre-lock
/// scan found no evidence even though the lock itself is still contended —
/// worth saying plainly, since it means the holder is not a session this
/// scan can see (a stale lock, or another `csq sessions share` run).
fn format_live_writer_pids(live: &[LiveWriter]) -> String {
    if live.is_empty() {
        return "none identified by the pre-lock scan (the holder may be a process without \
                 handle-dir bookkeeping, or another `csq sessions share` invocation)"
            .to_string();
    }
    live.iter()
        .map(|w| {
            if w.pid == 0 {
                // S-LOW-3: this string reaches the operator via
                // `ShareError::LiveWriters`/`CodexShareLockTimedOut`'s
                // `{pids}` interpolation — redact before it does, same as
                // every other operator-facing path field in this module.
                format!(
                    "<unreadable at {}>",
                    crate::cli_deps::sanitize::redact_path(&w.handle_dir)
                )
            } else {
                w.pid.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// [`share_slot`] over every slot [`discover_slots`] finds for `surface`.
///
/// `--dry-run` is read-only and is NEVER gated by the live-writer guard — it
/// is exactly the safe way to inspect a surface while a session is up.
/// `force` skips the guard for a REAL run (see [`ensure_no_live_writers`]).
pub fn share_surface(
    base: &Path,
    surface: Surface,
    dry_run: bool,
    force: bool,
) -> Result<Vec<SlotReport>, ShareError> {
    if !dry_run {
        ensure_no_live_writers(base, surface, force)?;
    }
    discover_slots(base, surface)
        .into_iter()
        .map(|slot| share_slot(base, surface, slot, dry_run))
        .collect()
}

/// Both halves of Codex's cross-slot share — [`share_surface`]'s
/// symlink-based entries AND [`codex_sqlite::share_codex_sqlite`]'s
/// separate sqlite-state merge — under ONE acquire of the codex share lock
/// and ONE live-writer scan (S-M2).
///
/// Before this, only the sqlite half took the EXCLUSIVE lock at all: a
/// `launch_codex` SHARED holder was excluded for the sqlite merge, but the
/// symlink-entry migration ran with no lock whatsoever, so it could still
/// repoint a slot's `codex-sessions`/etc. directories out from under a live
/// session in the window between the two halves running as two separate,
/// unlocked-then-locked calls.
///
/// `csq sessions share [--surface codex]` is the only caller: kimi and grok
/// have no codex-style lock or sqlite half, so they keep calling
/// [`share_surface`] directly.
pub fn share_codex_surface_and_sqlite(
    base: &Path,
    dry_run: bool,
    force: bool,
) -> Result<(Vec<SlotReport>, codex_sqlite::CodexSqliteReport), ShareError> {
    let _share_lock = if dry_run {
        None
    } else {
        Some(acquire_codex_share_lock_exclusive_bounded_reporting(base)?)
    };
    if !dry_run {
        ensure_no_live_writers(base, Surface::Codex, force)?;
    }
    let slot_reports = discover_slots(base, Surface::Codex)
        .into_iter()
        .map(|slot| share_slot(base, Surface::Codex, slot, dry_run))
        .collect::<Result<Vec<_>, _>>()?;
    let sqlite_report = codex_sqlite::share_codex_sqlite_locked(base, dry_run, force)?;
    Ok((slot_reports, sqlite_report))
}

fn share_entry(
    base: &Path,
    surface: Surface,
    slot: AccountNum,
    entry: &SharedEntry,
    dry_run: bool,
) -> Result<EntryReport, ShareError> {
    let home = slot_home(base, surface, slot)?;
    let slot_path = home.join(entry.relpath);
    let shared_dir_root = shared_root(base, surface);
    let shared_path = shared_dir_root.join(entry.relpath);

    // S-LOW-D: refuse a symlink planted at ANY component of `shared_path`
    // (which subsumes `shared_dir_root`, its prefix) BEFORE any
    // `create_dir_all` / `merge_dir` / `merge_jsonl` call below can follow
    // it. `open_codex_share_lock_file` already runs this check for the
    // codex share-lock dir; `share_entry` is the generic per-surface,
    // per-entry merge path (kimi, grok, and codex's own entries all route
    // through here) and had no equivalent guard — a symlink planted at
    // `shared-state/<surface>/<relpath>` (or any ancestor) would silently
    // redirect every subsequent write into wherever it points.
    assert_no_symlink_in_chain(base, &shared_path)?;

    let mut report = EntryReport {
        relpath: entry.relpath,
        ..Default::default()
    };

    let slot_meta = slot_path.symlink_metadata();

    // Already migrated: a symlink to exactly the shared target is a no-op.
    // A symlink to anything ELSE is refused, never silently repointed.
    if let Ok(meta) = &slot_meta {
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&slot_path).map_err(|e| ShareError::io(&slot_path, e))?;
            if target == shared_path {
                report.already_shared = true;
                return Ok(report);
            }
            return Err(ShareError::UnexpectedShape {
                relpath: entry.relpath,
                path: slot_path,
            });
        }
    }

    if !dry_run {
        fs::create_dir_all(&shared_dir_root).map_err(|e| ShareError::io(&shared_dir_root, e))?;
    }

    match slot_meta {
        Err(_) => {
            // No local data: nothing to merge. Seed an empty shared target
            // (so the symlink resolves) and link.
            if !dry_run {
                match entry.kind {
                    EntryKind::Dir => fs::create_dir_all(&shared_path)
                        .map_err(|e| ShareError::io(&shared_path, e))?,
                    EntryKind::File => {
                        if !shared_path.exists() {
                            fs::write(&shared_path, b"")
                                .map_err(|e| ShareError::io(&shared_path, e))?;
                        }
                    }
                }
                link_slot_to_shared(&slot_path, &shared_path)?;
            }
        }
        Ok(meta) => match entry.kind {
            EntryKind::Dir => {
                if !meta.is_dir() {
                    return Err(ShareError::UnexpectedShape {
                        relpath: entry.relpath,
                        path: slot_path,
                    });
                }
                if !dry_run {
                    // The shared target dir must exist before `merge_dir`
                    // can rename anything INTO it — the top-level create
                    // for the surface's shared root (above) does not reach
                    // this per-entry subdirectory.
                    fs::create_dir_all(&shared_path)
                        .map_err(|e| ShareError::io(&shared_path, e))?;
                }
                let slot_tag = format!("slot{slot}");
                let mut stats = DirMergeStats::default();
                let drained = merge_dir(&shared_path, &slot_path, &slot_tag, dry_run, &mut stats)?;
                report.files_moved = stats.files_moved;
                report.bytes_moved = stats.bytes_moved;
                report.duplicates_removed = stats.duplicates_removed;
                report.conflicts_kept_both = stats.conflicts_kept_both;
                report.partial = !drained;
                if !dry_run && drained {
                    fs::remove_dir(&slot_path).map_err(|e| ShareError::io(&slot_path, e))?;
                    link_slot_to_shared(&slot_path, &shared_path)?;
                }
            }
            EntryKind::File => {
                if !meta.is_file() {
                    return Err(ShareError::UnexpectedShape {
                        relpath: entry.relpath,
                        path: slot_path,
                    });
                }
                let stats = merge_jsonl(&shared_path, &slot_path, dry_run)?;
                report.lines_added = stats.lines_added;
                report.lines_deduped = stats.lines_deduped;
                report.files_moved = 1;
                report.bytes_moved = meta.len();
                if !dry_run {
                    fs::remove_file(&slot_path).map_err(|e| ShareError::io(&slot_path, e))?;
                    link_slot_to_shared(&slot_path, &shared_path)?;
                }
            }
        },
    }

    Ok(report)
}

/// Links `slot_path` to `shared_path` and PROVES the result is a symlink.
///
/// The underlying primitive ([`isolation::create_symlink_pub`]) degrades on
/// a Windows host that cannot create symlinks: a hard link, or a copy, for
/// files. Neither delivers the sharing contract here, because
/// [`merge_jsonl`] rewrites the shared file through
/// [`crate::platform::fs::atomic_replace`] — a tmp-file + rename, which
/// gives the shared path a NEW file and leaves a hard link resolving to the
/// orphaned old one. A copy was never connected at all. Both diverge
/// silently, which is exactly the shape this whole migration exists to
/// remove, so a degraded result is refused rather than reported as shared.
///
/// On refusal the slot path is left absent, not half-linked. The content is
/// already in the shared store by then, so the next run takes the
/// "no local data" branch and re-links — the operation is retryable and
/// loses nothing.
fn link_slot_to_shared(slot_path: &Path, shared_path: &Path) -> Result<(), ShareError> {
    isolation::create_symlink_pub(shared_path, slot_path)
        .map_err(|e| ShareError::io(slot_path, e))?;
    verify_is_symlink(slot_path)
}

/// Fail-closed post-condition for [`link_slot_to_shared`]: the path MUST be
/// a symlink. Anything else — a hard link, a copy, a missing entry — is
/// removed and reported, never accepted as "shared".
///
/// Split out from its caller so the refusal is provable on every platform:
/// on Unix the degraded shapes cannot arise naturally, so a test that only
/// exercised `link_slot_to_shared` would pass whether or not this check
/// existed (`instrument-discipline.md` MUST-2).
fn verify_is_symlink(path: &Path) -> Result<(), ShareError> {
    let meta = path
        .symlink_metadata()
        .map_err(|e| ShareError::io(path, e))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    let produced = if meta.is_dir() {
        "directory".to_string()
    } else {
        "regular file (hard link or copy)".to_string()
    };
    // Leave no half-shared artifact behind: the content is in the shared
    // store already, so removing the degraded entry makes the next run
    // re-link cleanly instead of merging the same bytes a second time.
    let _ = if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    Err(ShareError::LinkNotSupported {
        path: path.to_path_buf(),
        produced,
    })
}

#[derive(Debug, Clone, Copy, Default)]
struct DirMergeStats {
    files_moved: u64,
    bytes_moved: u64,
    duplicates_removed: u64,
    conflicts_kept_both: u64,
}

/// Relocate every child of `slot_dir` into `shared_dir`, merging rather
/// than clobbering on a name collision, then report whether `slot_dir` was
/// fully drained (safe to remove + symlink).
///
/// `dry_run` gates ONLY the mutating calls (`rename`/`remove_file`/
/// `remove_dir`/`create_dir_all`) — every read (directory listing,
/// existence check, hash comparison) always runs for real, so a dry-run's
/// counts are the SAME decision the real run would make, not a separate
/// guess (`instrument-discipline.md`: the two paths must be able to
/// disagree, or a dry-run bug can hide behind a real run that happens to
/// still work).
fn merge_dir(
    shared_dir: &Path,
    slot_dir: &Path,
    slot_tag: &str,
    dry_run: bool,
    stats: &mut DirMergeStats,
) -> Result<bool, ShareError> {
    let entries = fs::read_dir(slot_dir).map_err(|e| ShareError::io(slot_dir, e))?;
    let mut drained = true;

    for entry in entries {
        let entry = entry.map_err(|e| ShareError::io(slot_dir, e))?;
        let name = entry.file_name();
        let slot_child = entry.path();
        let shared_child = shared_dir.join(&name);
        let slot_type = entry
            .file_type()
            .map_err(|e| ShareError::io(&slot_child, e))?;

        if slot_type.is_symlink() {
            // Not an expected shape inside a shared-state source dir —
            // refuse to guess what it should become. Leave it; report partial.
            drained = false;
            continue;
        }

        let shared_exists = shared_child.symlink_metadata().is_ok();
        if !shared_exists {
            // No collision: relocate the whole subtree in one rename (real
            // run) or count it recursively (dry run — there is no
            // single-syscall count).
            if dry_run {
                let (files, bytes) = count_recursive(&slot_child);
                stats.files_moved += files;
                stats.bytes_moved += bytes;
            } else if let Err(e) = fs::rename(&slot_child, &shared_child) {
                tracing::warn!(
                    path = %slot_child.display(),
                    error = %e,
                    "shared-state: rename failed, leaving in place for retry"
                );
                drained = false;
            } else {
                let (files, bytes) = count_recursive(&shared_child);
                stats.files_moved += files;
                stats.bytes_moved += bytes;
            }
            continue;
        }

        // Collision: both dest and source have this name.
        let shared_meta =
            fs::symlink_metadata(&shared_child).map_err(|e| ShareError::io(&shared_child, e))?;

        if slot_type.is_dir() && shared_meta.is_dir() {
            let child_drained = merge_dir(&shared_child, &slot_child, slot_tag, dry_run, stats)?;
            if child_drained {
                if !dry_run {
                    fs::remove_dir(&slot_child).map_err(|e| ShareError::io(&slot_child, e))?;
                }
            } else {
                drained = false;
            }
        } else if slot_type.is_file() && shared_meta.is_file() {
            let identical = files_identical(&slot_child, &shared_child)?;
            if identical {
                stats.duplicates_removed += 1;
                if !dry_run {
                    fs::remove_file(&slot_child).map_err(|e| ShareError::io(&slot_child, e))?;
                }
            } else {
                let dest = unique_conflict_name(shared_dir, &name.to_string_lossy(), slot_tag);
                stats.conflicts_kept_both += 1;
                stats.files_moved += 1;
                stats.bytes_moved += fs::metadata(&slot_child).map(|m| m.len()).unwrap_or(0);
                if !dry_run {
                    fs::rename(&slot_child, &dest).map_err(|e| ShareError::io(&slot_child, e))?;
                }
            }
        } else {
            // Type mismatch (file vs dir) at the same name — never guess;
            // keep both under a suffixed name.
            let dest = unique_conflict_name(shared_dir, &name.to_string_lossy(), slot_tag);
            stats.conflicts_kept_both += 1;
            if !dry_run {
                fs::rename(&slot_child, &dest).map_err(|e| ShareError::io(&slot_child, e))?;
            }
        }
    }

    Ok(drained)
}

/// A name under `dir` derived from `name`, guaranteed not to already exist —
/// `<name>.slotN`, then `<name>.slotN.1`, `.2`, … on further collision.
fn unique_conflict_name(dir: &Path, name: &str, slot_tag: &str) -> PathBuf {
    let base = format!("{name}.{slot_tag}");
    let mut candidate = dir.join(&base);
    let mut i = 1u32;
    while candidate.symlink_metadata().is_ok() {
        candidate = dir.join(format!("{base}.{i}"));
        i += 1;
    }
    candidate
}

/// `true` iff both files have identical content, compared by streaming
/// SHA-256 rather than loading either fully into memory (rollout files can
/// be large).
fn files_identical(a: &Path, b: &Path) -> Result<bool, ShareError> {
    let ha = hash_file(a).map_err(|e| ShareError::io(a, e))?;
    let hb = hash_file(b).map_err(|e| ShareError::io(b, e))?;
    Ok(ha == hb)
}

fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize().into())
}

/// Recursive `(file count, total bytes)` under `p` — used ONLY for dry-run
/// counting of a subtree that would move as a single `rename` in a real
/// run. Best-effort: an unreadable entry contributes nothing rather than
/// failing the plan.
fn count_recursive(p: &Path) -> (u64, u64) {
    let Ok(meta) = fs::symlink_metadata(p) else {
        return (0, 0);
    };
    if meta.is_file() {
        return (1, meta.len());
    }
    if !meta.is_dir() {
        return (0, 0);
    }
    let Ok(entries) = fs::read_dir(p) else {
        return (0, 0);
    };
    entries.flatten().fold((0, 0), |(f, b), e| {
        let (cf, cb) = count_recursive(&e.path());
        (f + cf, b + cb)
    })
}

#[derive(Debug, Clone, Copy, Default)]
struct FileMergeStats {
    lines_added: u64,
    lines_deduped: u64,
}

/// The dedupe key for one JSONL line: `(id, updated_at)` when both parse as
/// JSON object fields (codex's `codex-session_index.jsonl` shape), else the
/// exact line text (codex's `codex-history.jsonl` uses `session_id`/`ts`
/// instead, so it falls back here — still correctly dedupes an exact
/// repeat, never merges two lines that merely share a field).
fn jsonl_dedupe_key(line: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(line) {
        if let (Some(id), Some(updated_at)) = (v.get("id"), v.get("updated_at")) {
            return format!("id={id}\u{0}updated_at={updated_at}");
        }
    }
    line.trim_end().to_string()
}

/// Merge `slot_file`'s lines into `shared_file`, deduping by
/// [`jsonl_dedupe_key`], preserving first-seen order (shared file's
/// existing lines first, then any genuinely new incoming lines).
///
/// `dry_run` gates only the final write — the read + dedupe logic always
/// runs against the real files, so the reported counts are exact.
fn merge_jsonl(
    shared_file: &Path,
    slot_file: &Path,
    dry_run: bool,
) -> Result<FileMergeStats, ShareError> {
    // FAIL CLOSED on the side this function is about to OVERWRITE.
    //
    // `unwrap_or_default()` here was the defect: a shared file that is not valid
    // UTF-8 read as `""`, and the `atomic_replace` below then wrote only the
    // SLOT's lines over it — total, silent loss of the shared side. The
    // asymmetry was the tell: the side about to be destroyed failed OPEN while
    // the side that survives (`slot_file`, below) failed CLOSED.
    // `guard-reader-writer-parity.md` MUST-2 — on a destructive path, "cannot
    // read" refuses.
    //
    // ENOENT stays benign and is the only tolerated error: a shared target that
    // does not exist yet is the normal first-migration case, and the seed path
    // in `share_entry` relies on it.
    let existing = match fs::read_to_string(shared_file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(ShareError::io(shared_file, e)),
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut out_lines: Vec<String> = Vec::new();
    for line in existing.lines() {
        if line.trim().is_empty() {
            continue;
        }
        seen.insert(jsonl_dedupe_key(line));
        out_lines.push(line.to_string());
    }

    let incoming = fs::read_to_string(slot_file).map_err(|e| ShareError::io(slot_file, e))?;
    let mut stats = FileMergeStats::default();
    for line in incoming.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let key = jsonl_dedupe_key(line);
        if seen.insert(key) {
            out_lines.push(line.to_string());
            stats.lines_added += 1;
        } else {
            stats.lines_deduped += 1;
        }
    }

    if !dry_run {
        let mut content = out_lines.join("\n");
        if !content.is_empty() {
            content.push('\n');
        }
        // §5a: treated as secret-bearing — this is shared conversation
        // history (rollout files / history.jsonl equivalents), which may
        // embed anything the user pasted into a session, including secrets.
        // `write_new_private` creates the tmp file at 0o600 at creation.
        let tmp = crate::platform::fs::unique_tmp_path(shared_file);
        if let Err(e) = crate::platform::fs::write_new_private(&tmp, content.as_bytes()) {
            let _ = fs::remove_file(&tmp);
            return Err(ShareError::io(&tmp, io::Error::other(e.to_string())));
        }
        if let Err(e) = crate::platform::fs::atomic_replace(&tmp, shared_file) {
            let _ = fs::remove_file(&tmp);
            return Err(ShareError::io(shared_file, io::Error::other(e.to_string())));
        }
    }

    Ok(stats)
}

// ─────────────────────────────────────────────────────────────────────────
// Codex cross-slot SQLite state sharing
// ─────────────────────────────────────────────────────────────────────────
//
// codex-cli keeps a "state" database (observed as `state_5.sqlite`) in
// schema-versioned SQLite files under `config-N/` (matched by
// [`CODEX_SHARED_SQLITE_SUFFIX`] in `session::handle_dir`, which shares
// them PER-TERMINAL within one slot). Its `threads` table carries the
// `/rename` a user gives a conversation. `merge_jsonl` cannot carry it — it
// is a real SQLite file, not line-oriented text — so a rename made in one
// account slot was invisible from every OTHER slot (the owner symptom this
// module exists to fix).
//
// Every OTHER `*.sqlite` this module encounters — including
// `thread_history_1.sqlite` (`thread_items` / `thread_history_projection_state`,
// a cache replayed from the shared rollout `.jsonl`) and `goals_1`,
// `memories_1`, `queue_1`, `logs_2` (audited on a live host) — is treated
// as [`SqliteDbRole::KeptPerSlot`]: left exactly where codex-cli put it.
//
// `thread_history_1.sqlite` was DELIBERATELY considered and rejected for a
// "drop the rows, let codex-cli rebuild it" merge: nothing here has
// verified against real codex-cli that it lazily rebuilds an EMPTIED
// projection for a thread that already has projection-state history — a
// slot that has never opened a given thread builds its OWN projection fine
// (measured: slot 11 had 0 projection rows for a thread slot 14 had
// opened), but that is a different case from a slot whose projection
// EXISTS and is then truncated out from under it. If codex-cli treats an
// existing-but-emptied projection as "up to date, nothing to replay"
// rather than "absent, rebuild from scratch", every resumed conversation
// on the merged slots opens blank. The pre-share backup would make that
// recoverable, but it is still a user-visible regression for a cache that
// already works fine per slot today, and the owner's actual symptom
// (`resume` by name across slots) needs only `threads.name` shared — so
// the risk buys nothing this fix needs. Per-account goal/memory/queue data
// merged on a guess is separately the kind of splice
// `guard-reader-writer-parity.md` exists to forbid; logs additionally have
// no cross-slot value even if they were merged.
//
// # Why the system `sqlite3` binary, not the `rusqlite` crate
//
// `rusqlite` appears in `Cargo.lock` only as a TRANSITIVE dependency of the
// enterprise-only `the enterprise seam crate` crate (via the enterprise edition) — it is not a
// direct dependency of `csq-core` in any `Cargo.toml`, and `csq-core` cannot
// depend on `the enterprise seam crate` (that edge is a cycle — see
// `discovery_kailash_seam_cycle_and_form_vs_mapping`). Adding a NEW
// C-backed dependency to `csq-core` to reach a crate it cannot use anyway
// needs its own review, so this module shells out to the system `sqlite3`
// CLI instead, resolved to an absolute path and invoked with a cleared,
// minimal environment — mirroring the precedent in
// `audit::export::tests::python` for exactly the same reason (a bare
// `Command::new("sqlite3")` would resolve via `PATH` at exec time, which is
// not the same guarantee as resolving it once, up front, and refusing
// loudly when it is absent).
//
// # Safety model
//
// Merge is FAIL-CLOSED on: any live codex writer; `PRAGMA integrity_check`
// failing on any input; and `_sqlx_migrations` differing between slots
// (schemas are reported, never reconciled). Every real per-slot database
// that participates is preserved byte-for-byte under a dated
// `.pre-share-<epoch-seconds>` suffix before its slot path becomes a
// symlink — reversal is: remove the symlink, rename the `.pre-share-*`
// file (and its `-wal`/`-shm` siblings, if present) back to the original
// name, and delete `shared-state/codex/<basename>`.
pub mod codex_sqlite {
    use super::{discover_slots, ensure_no_live_writers, shared_root, slot_home, ShareError};
    use crate::providers::catalog::Surface;
    use crate::types::AccountNum;
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Suffix identifying a codex schema-versioned sqlite database, matched
    /// the same way `session::handle_dir`'s intra-slot sharing matches it.
    const SQLITE_SUFFIX: &str = ".sqlite";

    /// Operator override: an absolute path to the `sqlite3` binary to use.
    pub const SQLITE3_ENV_VAR: &str = "CSQ_SQLITE3";

    /// The host surface [`resolve_sqlite3`] depends on, injected so its unit
    /// tests never depend on what is installed on the machine running them
    /// (`test-hermeticity.md`) — mirrors `audit::export::tests::python::Probe`.
    pub trait Probe {
        fn env_override(&self) -> Option<OsString>;
        fn is_executable(&self, path: &Path) -> bool;
        fn find_in_path(&self, name: &str) -> Option<PathBuf>;
    }

    struct RealProbe;

    impl Probe for RealProbe {
        fn env_override(&self) -> Option<OsString> {
            std::env::var_os(SQLITE3_ENV_VAR)
        }

        fn is_executable(&self, path: &Path) -> bool {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(path)
                    .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
            }
            #[cfg(windows)]
            {
                path.is_file()
            }
        }

        fn find_in_path(&self, name: &str) -> Option<PathBuf> {
            let path_var = std::env::var_os("PATH")?;
            find_executable_in_dirs(std::env::split_paths(&path_var), name, |p| {
                self.is_executable(p)
            })
        }
    }

    /// S-F10: `PATH` may legitimately contain an empty entry (historically
    /// meaning "the current directory" on some shells) or a relative entry
    /// (meaningful only relative to whatever the current working directory
    /// happens to be at spawn time) — either would let an untrusted or
    /// unintended binary satisfy the lookup. Both are skipped; `is_executable`
    /// is injected so this is testable without touching the real `PATH`.
    pub(super) fn find_executable_in_dirs(
        dirs: impl Iterator<Item = PathBuf>,
        name: &str,
        is_executable: impl Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        dirs.filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute())
            .find_map(|dir| {
                let candidate = dir.join(name);
                is_executable(&candidate).then_some(candidate)
            })
    }

    /// Resolve the `sqlite3` binary: `$CSQ_SQLITE3` (an explicit, loud error
    /// if set but not executable OR not absolute — a quiet fallback would
    /// hide the operator's mistake behind a passing run), else the system
    /// copy at `/usr/bin/sqlite3` when present, else `sqlite3` on `PATH`.
    ///
    /// S-F10: the override MUST be an absolute path to an existing regular
    /// (executable) file — this error message already said "absolute", but
    /// nothing had enforced it, so a relative override that happened to
    /// resolve executable from the process's current directory was
    /// silently accepted.
    ///
    /// S-L4: the system copy is preferred over a bare `PATH` search — the
    /// same posture `super::list_running_processes`'s `/bin/ps` already
    /// takes — so a same-user-writable directory placed earlier on `PATH` cannot
    /// substitute a different `sqlite3` when the trustworthy system one is
    /// right there. Unix only: there is no equivalent well-known absolute
    /// path on Windows, so that platform keeps the plain `PATH` search.
    pub fn resolve_with(probe: &dyn Probe) -> Result<PathBuf, ShareError> {
        if let Some(raw) = probe.env_override() {
            let path = PathBuf::from(&raw);
            if path.is_absolute() && probe.is_executable(&path) {
                return Ok(path);
            }
            return Err(ShareError::Sqlite3NotFound {
                env_var: SQLITE3_ENV_VAR,
            });
        }
        #[cfg(unix)]
        {
            let system_default = PathBuf::from("/usr/bin/sqlite3");
            if probe.is_executable(&system_default) {
                return Ok(system_default);
            }
        }
        probe
            .find_in_path("sqlite3")
            .ok_or(ShareError::Sqlite3NotFound {
                env_var: SQLITE3_ENV_VAR,
            })
    }

    pub fn resolve_sqlite3() -> Result<PathBuf, ShareError> {
        resolve_with(&RealProbe)
    }

    /// Run `script` against `db_path` via the resolved `sqlite3` binary,
    /// hermetically: cleared environment (minus a minimal `PATH`, in case
    /// the vendored `sqlite3` itself needs to resolve a shared library
    /// helper), no shell, argv only. Returns stdout as-is; a non-zero exit
    /// is a hard error naming the binary, the db path, and stderr.
    fn run_sqlite3(binary: &Path, db_path: &Path, script: &str) -> Result<String, ShareError> {
        run_sqlite3_with(binary, db_path, script, false)
    }

    /// [`run_sqlite3`], opened `-readonly` — the ONLY way to inspect a
    /// database that may have a pending, un-checkpointed `-wal` without
    /// mutating it: a normal (writable) connection that happens to be the
    /// LAST one open on a WAL-mode database checkpoints (and can truncate)
    /// the WAL as a side effect of closing, even for a connection that only
    /// ever ran `SELECT`s. Every verification read this module performs
    /// against a slot's ORIGINAL file — never against a disposable working
    /// copy, where a checkpoint is harmless — MUST go through this, or a
    /// dry run (or even the pre-mutation verification phase of a real run)
    /// can silently fold a slot's own pending WAL into its main file before
    /// this module has taken its backup.
    fn run_sqlite3_readonly(
        binary: &Path,
        db_path: &Path,
        script: &str,
    ) -> Result<String, ShareError> {
        run_sqlite3_with(binary, db_path, script, true)
    }

    fn run_sqlite3_with(
        binary: &Path,
        db_path: &Path,
        script: &str,
        readonly: bool,
    ) -> Result<String, ShareError> {
        let mut command = Command::new(binary);
        // `-bail` (C-F6): without it, sqlite3 keeps executing a script's
        // remaining statements after one fails, so a failed `INSERT ...
        // SELECT *` can be followed by a `COMMIT` that lands a HALF-merged
        // transaction (the sibling `UPDATE`, but not the `INSERT`) while csq
        // reports an error. `-bail` stops the shell at the first error,
        // before that `COMMIT` line is ever reached; the transaction's
        // BEGIN never lands a commit record, so closing the connection with
        // it still open lets SQLite's own crash-recovery / uncommitted-
        // transaction discard drop it entirely.
        command.args(["-batch", "-noheader", "-list", "-bail"]);
        if readonly {
            command.arg("-readonly");
            // S-F8 (defense in depth): `-safe` disables dangerous shell
            // features. Only added to READ-ONLY invocations — every one of
            // THESE is a plain SELECT/PRAGMA, so `-safe` can only narrow
            // what they can do, never break them. The WRITE path
            // (`merge_threads`, via the non-readonly `run_sqlite3`)
            // legitimately needs `ATTACH DATABASE`, which some `-safe`
            // builds restrict — applying `-safe` there could break the
            // merge itself rather than just harden it, so it is
            // deliberately NOT added to that path.
            if binary_supports_safe_flag(binary) {
                command.arg("-safe");
            }
        }
        // S-L3: prepended to EVERY sqlite3 invocation this module makes —
        // read-only or not. `trusted_schema=OFF` disables loading of
        // triggers/views (and other schema-driven mechanisms SQLite
        // otherwise trusts by default) from ANY attached database,
        // including one that later fails `forbid_untrusted_schema_objects`'
        // own explicit check — a second, independent gate against the same
        // hand-modified-database class, applied even to the read-only
        // inspection queries that check runs before.
        let mut sent = String::with_capacity(script.len() + 32);
        sent.push_str("PRAGMA trusted_schema=OFF;\n");
        sent.push_str(script);
        let script = sent;
        // S-L4 / operator-surface-verification.md Rule 1: neither the
        // path nor the binary this error names may leak the operator's
        // full `$HOME`-rooted host path, and sqlite3's own stderr is
        // attacker- or corruption-influenced content that must not reach
        // an operator surface un-redacted.
        let redacted_binary = || PathBuf::from(crate::cli_deps::sanitize::redact_path(binary));
        let redacted_path = || PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path));
        let mut child = command
            .arg(db_path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ShareError::SqliteCommandFailed {
                binary: redacted_binary(),
                path: redacted_path(),
                detail: format!("spawn: {e}"),
            })?;
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(script.as_bytes())
            .map_err(|e| ShareError::SqliteCommandFailed {
                binary: redacted_binary(),
                path: redacted_path(),
                detail: format!("write script: {e}"),
            })?;
        let output = child
            .wait_with_output()
            .map_err(|e| ShareError::SqliteCommandFailed {
                binary: redacted_binary(),
                path: redacted_path(),
                detail: format!("wait: {e}"),
            })?;
        if !output.status.success() {
            let stderr =
                crate::error::redact_tokens(String::from_utf8_lossy(&output.stderr).trim());
            return Err(ShareError::SqliteCommandFailed {
                binary: redacted_binary(),
                path: redacted_path(),
                detail: format!("exit {:?}: {stderr}", output.status.code()),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Single-quote-escape a path for interpolation into an `ATTACH DATABASE`
    /// statement. Our own generated tempdir/config-dir paths never legitimately
    /// contain a `'`, but the escape costs nothing and removes the question.
    fn sql_quote_path(path: &Path) -> String {
        path.display().to_string().replace('\'', "''")
    }

    /// S-F8: an `ATTACH DATABASE` path is single-quote-escaped (above), but
    /// a newline or embedded NUL byte inside the quoted literal can still
    /// desynchronize a naive script reader or a later shell wrapper. Our own
    /// generated paths never legitimately contain either — refuse rather
    /// than interpolate one that does.
    pub(super) fn ensure_safe_attach_path(path: &Path) -> Result<(), ShareError> {
        let display = path.display().to_string();
        if display.contains('\n') || display.contains('\r') || display.contains('\0') {
            return Err(ShareError::SqliteUnsafeAttachPath {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    /// S-F8: identifier allowlist for interpolating a column name (from
    /// `PRAGMA table_info`, plain text with no parameter-binding option)
    /// into SQL. Anything outside this shape is refused rather than quoted
    /// and hoped: ASCII letters, digits, underscore; first character not a
    /// digit.
    fn is_safe_sql_identifier(name: &str) -> bool {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Double-quote a VALIDATED SQL identifier, escaping an embedded `"` by
    /// doubling. Defense in depth: [`is_safe_sql_identifier`] already
    /// excludes `"`, so this can never actually need to escape anything —
    /// but the escape is free and removes the question, matching
    /// [`sql_quote_path`]'s posture on `'`.
    fn quote_ident(name: &str) -> String {
        format!("\"{}\"", name.replace('"', "\"\""))
    }

    /// Whether the resolved `sqlite3` binary's `-help` output advertises
    /// `-safe`. Probed once per process (the binary is resolved once and
    /// reused for the whole migration run) rather than on every invocation,
    /// so the merge's normal path is not a second spawn per SQL call.
    static SAFE_FLAG_SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    fn binary_supports_safe_flag(binary: &Path) -> bool {
        *SAFE_FLAG_SUPPORTED.get_or_init(|| {
            // S-L4: env_clear so an inherited env var cannot change
            // `-help`'s wording (or, in principle, substitute a shared
            // library the resolved binary depends on) out from under the
            // `.contains("-safe")` check below.
            let Ok(output) = Command::new(binary)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .arg("-help")
                .output()
            else {
                return false;
            };
            // `-help`'s flag list may land on stdout or stderr depending on
            // the build; check both rather than assume one.
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .contains("-safe")
        })
    }

    /// Role a codex sqlite database plays in cross-slot sharing, determined
    /// by which tables it actually contains — never by its schema-versioned
    /// filename, which changes across codex-cli releases.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SqliteDbRole {
        /// Has a `threads` table — the `/rename` target. Merged by
        /// coalescing rows (non-empty `name` wins, tie-broken by the larger
        /// `updated_at_ms`).
        State,
        /// Anything else, INCLUDING `thread_history_1.sqlite`'s
        /// `thread_items` / `thread_history_projection_state` projection —
        /// see the module doc for why that one is deliberately NOT merged
        /// or truncated. Left exactly where codex-cli put it, per-slot,
        /// undisturbed.
        KeptPerSlot,
    }

    /// What happened (or would happen, in a dry run) to one basename.
    #[derive(Debug, Clone)]
    pub enum SqliteDbOutcome {
        /// Every slot holding this basename was already a symlink to the
        /// shared target — nothing to do.
        AlreadyShared,
        /// [`SqliteDbRole::State`]: `slots_merged` real per-slot copies were
        /// coalesced into the shared database.
        Merged { slots_merged: usize },
        /// [`SqliteDbRole::KeptPerSlot`]: left untouched in `slots` slots.
        KeptPerSlot { slots: usize },
    }

    #[derive(Debug, Clone)]
    pub struct SqliteDbReport {
        pub basename: String,
        pub role: SqliteDbRole,
        pub outcome: SqliteDbOutcome,
    }

    #[derive(Debug, Clone, Default)]
    pub struct CodexSqliteReport {
        pub databases: Vec<SqliteDbReport>,
    }

    /// Non-recursive `*.sqlite` basenames directly under `dir` — file OR
    /// symlink (an already-shared slot's copy is a symlink, and it must
    /// still be enumerated so a re-run can report `AlreadyShared` for it
    /// rather than silently seeing nothing to do). `-wal`/`-shm` sidecars
    /// never carry this bare suffix, so they are excluded by construction.
    fn scan_basenames_in(dir: &Path) -> Vec<String> {
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| {
                e.file_type()
                    .map(|t| t.is_file() || t.is_symlink())
                    .unwrap_or(false)
            })
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|name| name.ends_with(SQLITE_SUFFIX))
            // S-F9: a `.merge-src` / `.pre-share-<epoch>` scratch artifact
            // left over from an earlier failed run never carries the bare
            // `SQLITE_SUFFIX` ending (it is `state_5.sqlite.merge-src`, not
            // `....sqlite`), so the filter above already excludes it — this
            // second check is defense in depth against a future basename
            // that happens to end in one of these scratch suffixes.
            .filter(|name| !name.contains(".merge-src") && !name.contains(".pre-share-"))
            .collect()
    }

    /// Recovers the basename a `.pre-share-<epoch>` file backs up, or
    /// `None` if `name` does not have exactly that shape. Requires the
    /// suffix after `.pre-share-` to be non-empty and all-ASCII-digits (so
    /// a `-wal`/`-shm` sidecar, whose suffix is `<epoch>-wal` /
    /// `<epoch>-shm`, is excluded) and the recovered base to itself end in
    /// [`SQLITE_SUFFIX`] (so a name that merely CONTAINS the literal
    /// substring `.pre-share-` elsewhere, like a `.sqlite`-suffixed
    /// adversarial test fixture, is not mistaken for a real backup).
    fn basename_from_pre_share(name: &str) -> Option<String> {
        let idx = name.find(".pre-share-")?;
        let (base, rest) = name.split_at(idx);
        let epoch_str = rest.strip_prefix(".pre-share-")?;
        if !epoch_str.is_empty()
            && epoch_str.chars().all(|c| c.is_ascii_digit())
            && base.ends_with(SQLITE_SUFFIX)
        {
            Some(base.to_string())
        } else {
            None
        }
    }

    /// Every `*.sqlite` basename [`plan_one_basename`] should consider for
    /// one slot home: `scan_basenames_in`'s ordinary real-file-or-symlink
    /// scan, PLUS (C-R4-14) any basename recoverable from a stranded
    /// `.pre-share-<epoch>` backup that `scan_basenames_in` cannot see (it
    /// does not end in the bare `SQLITE_SUFFIX`).
    ///
    /// FM-12(A) already restores such a backup once its basename reaches
    /// `plan_one_basename` — but only for a basename discovery already
    /// found. Without this recovery pass, a basename whose ONLY surviving
    /// evidence anywhere is a lone `.pre-share-<epoch>` file (no other
    /// slot holds a real copy, symlink, or the shared DB) never enters
    /// `basenames` at all: the stranded slot stays permanently invisible
    /// to every future migration run, and a resumed codex-cli session
    /// against it creates a fresh, diverging database instead of picking
    /// up its own prior state.
    pub(super) fn list_sqlite_basenames(home: &Path) -> Vec<String> {
        let mut names = scan_basenames_in(home);

        if let Ok(entries) = fs::read_dir(home) {
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if !file_type.is_file() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if let Some(base) = basename_from_pre_share(&name) {
                    names.push(base);
                }
            }
        }

        names.sort();
        names.dedup();
        names
    }

    fn table_set(binary: &Path, db_path: &Path) -> Result<HashSet<String>, ShareError> {
        let out = run_sqlite3_readonly(
            binary,
            db_path,
            "SELECT name FROM sqlite_master WHERE type='table';",
        )?;
        Ok(out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn detect_role(binary: &Path, db_path: &Path) -> Result<SqliteDbRole, ShareError> {
        let tables = table_set(binary, db_path)?;
        if tables.contains("threads") {
            Ok(SqliteDbRole::State)
        } else {
            Ok(SqliteDbRole::KeptPerSlot)
        }
    }

    fn integrity_check(binary: &Path, basename: &str, db_path: &Path) -> Result<(), ShareError> {
        let out = run_sqlite3_readonly(binary, db_path, "PRAGMA integrity_check;")?;
        let trimmed = out.trim();
        if trimmed == "ok" {
            Ok(())
        } else {
            Err(ShareError::SqliteIntegrityCheckFailed {
                basename: basename.to_string(),
                path: db_path.to_path_buf(),
                detail: trimmed.to_string(),
            })
        }
    }

    /// S-L3: refuses a database that carries a `view` or `trigger` in its
    /// `sqlite_master` — an ordinary codex-cli sqlite file never has
    /// either, so one is evidence of a hand-modified or malicious file.
    ///
    /// This is the module's chosen answer to "seed the shared DB from
    /// schema-plus-`threads`-rows only, OR refuse any input whose
    /// `sqlite_master` contains a trigger or view": REFUSE, rather than
    /// reimplement a schema-only seed. `copy_db_with_sidecars` (the
    /// existing seed path for a brand-new shared DB) copies the WHOLE
    /// file, including any view/trigger — the `PRAGMA
    /// trusted_schema=OFF;` prepended to every invocation ([`run_sqlite3_with`])
    /// already stops a trigger from FIRING, but does nothing about a view
    /// or trigger silently riding into the canonical shared store as
    /// inert-but-present schema. Refusing here is fail-closed and costs
    /// nothing on the path that matters — a genuine codex-cli `threads`
    /// database has no legitimate reason to carry either.
    fn forbid_untrusted_schema_objects(
        binary: &Path,
        basename: &str,
        db_path: &Path,
    ) -> Result<(), ShareError> {
        let out = run_sqlite3_readonly(
            binary,
            db_path,
            "SELECT type, name FROM sqlite_master WHERE type IN ('trigger','view');",
        )?;
        if let Some(line) = out.lines().map(str::trim).find(|l| !l.is_empty()) {
            let mut fields = line.splitn(2, '|');
            // S-L6 / operator-surface-verification.md Rule 1: the path must
            // not leak the operator's full `$HOME`-rooted host path, exactly
            // like every other error this module raises from sqlite3
            // output. `object_type`/`object_name` come from `sqlite_master`
            // in a file this branch has just determined is hand-modified or
            // malicious, so they are attacker-influenced content too —
            // `redact_tokens` on principle, same as `run_sqlite3_with`'s
            // stderr handling.
            let object_type = crate::error::redact_tokens(fields.next().unwrap_or("object"));
            let object_name = crate::error::redact_tokens(fields.next().unwrap_or("?"));
            return Err(ShareError::SqliteUntrustedSchemaObject {
                basename: basename.to_string(),
                path: PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path)),
                object_type,
                object_name,
            });
        }
        Ok(())
    }

    /// `None` when the database has no `_sqlx_migrations` table (older
    /// codex-cli); `Some(rows)` otherwise, one row's columns per line,
    /// ordered so two databases with the identical migration set produce
    /// identical strings.
    fn migrations_signature(binary: &Path, db_path: &Path) -> Result<Option<String>, ShareError> {
        let has = run_sqlite3_readonly(
            binary,
            db_path,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations';",
        )?;
        if has.trim().is_empty() {
            return Ok(None);
        }
        let rows = run_sqlite3_readonly(
            binary,
            db_path,
            "SELECT * FROM _sqlx_migrations ORDER BY 1;",
        )?;
        Ok(Some(rows))
    }

    fn checkpoint_truncate(binary: &Path, db_path: &Path) -> Result<(), ShareError> {
        run_sqlite3(binary, db_path, "PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Informational: every merged DB / working copy / backup this module
    /// creates gets 0600 explicitly, rather than whatever `fs::copy` /
    /// `fs::rename` happened to preserve or the process umask produced —
    /// matching `security.md` MUST-5's posture for credential files,
    /// applied here to the cross-slot session store. No-op on Windows.
    #[cfg(unix)]
    fn secure_sqlite_paths(main: &Path) {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", main.display()));
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(windows)]
    fn secure_sqlite_paths(_main: &Path) {}

    /// Copy `src` (and its `-wal`/`-shm` sidecars, if present) to `dst` with
    /// the same suffix scheme. Used both for the disposable merge-working
    /// copy and for the durable, reversible `.pre-share-<epoch>` backup.
    fn copy_db_with_sidecars(src: &Path, dst: &Path) -> Result<(), ShareError> {
        fs::copy(src, dst).map_err(|e| ShareError::io(src, e))?;
        for suffix in ["-wal", "-shm"] {
            let src_side = PathBuf::from(format!("{}{suffix}", src.display()));
            if src_side.exists() {
                let dst_side = PathBuf::from(format!("{}{suffix}", dst.display()));
                fs::copy(&src_side, &dst_side).map_err(|e| ShareError::io(&src_side, e))?;
            }
        }
        secure_sqlite_paths(dst);
        Ok(())
    }

    /// Rename `src` (and its `-wal`/`-shm` sidecars, if present) to `dst`
    /// with the same suffix scheme — the durable backup step. Each
    /// individual `fs::rename` is atomic, but the three (main + two
    /// sidecars) are not atomic AS A GROUP.
    ///
    /// FM-12(B): if a sidecar rename fails after the main file (or an
    /// earlier sidecar) has already moved, every rename already performed
    /// by THIS call is undone, in reverse order, before the error is
    /// returned — so a partial sidecar failure never leaves `dst` holding
    /// the main file while `src` still holds a stranded sidecar, or
    /// vice versa.
    pub(super) fn rename_db_with_sidecars(src: &Path, dst: &Path) -> Result<(), ShareError> {
        fs::rename(src, dst).map_err(|e| ShareError::io(src, e))?;
        let mut done_sidecars: Vec<&str> = Vec::with_capacity(2);
        for suffix in ["-wal", "-shm"] {
            let src_side = PathBuf::from(format!("{}{suffix}", src.display()));
            if src_side.exists() {
                let dst_side = PathBuf::from(format!("{}{suffix}", dst.display()));
                if let Err(e) = fs::rename(&src_side, &dst_side) {
                    for done_suffix in done_sidecars.iter().rev() {
                        let s = PathBuf::from(format!("{}{done_suffix}", src.display()));
                        let d = PathBuf::from(format!("{}{done_suffix}", dst.display()));
                        let _ = fs::rename(&d, &s);
                    }
                    let _ = fs::rename(dst, src);
                    return Err(ShareError::io(&src_side, e));
                }
                done_sidecars.push(suffix);
            }
        }
        secure_sqlite_paths(dst);
        Ok(())
    }

    /// C-R4-12 / S-F6: the single rollback routine every error exit from
    /// the per-entry rename loop in `apply_basename_plan_with` MUST go
    /// through, so a SIBLING entry already renamed+linked earlier in the
    /// same loop is undone regardless of which check tripped. Best-effort
    /// (`let _ =`) on each undo, matching the fingerprint-mismatch arm's
    /// pre-existing behaviour: a failure here means the ORIGINAL rename
    /// this call is reversing already succeeded once, so the failure mode
    /// is "still linked", never "silently lost".
    fn rollback_renamed(renamed_so_far: &[(PathBuf, PathBuf)]) {
        for (original, backup) in renamed_so_far.iter().rev() {
            let _ = rename_db_with_sidecars(backup, original);
        }
    }

    fn remove_db_with_sidecars(path: &Path) {
        let _ = fs::remove_file(path);
        for suffix in ["-wal", "-shm"] {
            let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", path.display())));
        }
    }

    /// `threads` column names, in schema order, excluding `id` — dynamically
    /// discovered so the merge does not need to hardcode every column
    /// codex-cli's schema happens to carry today.
    ///
    /// S-F8: `PRAGMA table_info` returns column names as plain text with no
    /// parameter-binding option, and they are interpolated directly into
    /// generated SQL by [`merge_threads`] — so every name is validated
    /// against [`is_safe_sql_identifier`] here, up front, and refused rather
    /// than passed through if it fails.
    /// S-L3: the ONLY `threads` columns a merge's UPDATE (cross-slot
    /// overwrite of a colliding `id`) may touch — conversation IDENTITY
    /// (`name`, the `/rename` target this whole sharing feature exists
    /// for) and RECENCY (`updated_at_ms`, `created_at_ms`, needed to
    /// arbitrate which slot's `name` is newer). Every other column codex-cli
    /// may add to `threads` — `cwd`, `sandbox_policy`, `approval_policy`,
    /// `model`, or anything else describing HOW or WHERE a thread runs — is
    /// per-account/per-environment and MUST NOT be overwritten by a merge
    /// sourced from a different slot's copy; a shared conversation must not
    /// silently adopt another account's working directory or model. A
    /// brand-new row (an `id` with no `dest` counterpart) is unaffected by
    /// this allowlist: it is inserted whole via `INSERT ... SELECT *`,
    /// which is safe because there is no existing per-account row for it
    /// to clobber.
    const THREADS_MERGE_ALLOWLIST: &[&str] = &["name", "updated_at_ms", "created_at_ms"];

    /// `threads` column names, in schema order, excluding `id` — dynamically
    /// discovered so the merge does not need to hardcode every column
    /// codex-cli's schema happens to carry today.
    ///
    /// S-F8: `PRAGMA table_info` returns column names as plain text with no
    /// parameter-binding option, and they are interpolated directly into
    /// generated SQL by [`merge_threads`] — so every name is validated
    /// against [`is_safe_sql_identifier`] here, up front, and refused rather
    /// than passed through if it fails, REGARDLESS of whether it survives
    /// the [`THREADS_MERGE_ALLOWLIST`] filter below: an unsafe identifier is
    /// evidence of a hand-modified schema (the same class
    /// `forbid_untrusted_schema_objects` exists to catch), not something to
    /// silently drop.
    ///
    /// The returned list is already restricted to `THREADS_MERGE_ALLOWLIST`
    /// — this is the ONLY production caller, and callers needing the full
    /// validated column set for another purpose should not assume this
    /// returns it.
    fn threads_non_id_columns(
        binary: &Path,
        basename: &str,
        db_path: &Path,
    ) -> Result<Vec<String>, ShareError> {
        let out = run_sqlite3_readonly(binary, db_path, "PRAGMA table_info(threads);")?;
        let mut columns = Vec::new();
        for line in out.lines() {
            let mut fields = line.split('|');
            let Some(_cid) = fields.next() else { continue };
            let Some(name) = fields.next() else { continue };
            if name == "id" {
                continue;
            }
            if !is_safe_sql_identifier(name) {
                return Err(ShareError::SqliteUnsafeColumnName {
                    basename: basename.to_string(),
                    column: name.to_string(),
                });
            }
            if THREADS_MERGE_ALLOWLIST.contains(&name) {
                columns.push(name.to_string());
            }
        }
        Ok(columns)
    }

    /// Coalesce `source`'s `threads` rows into `dest` (both real sqlite
    /// files, `dest` writable): insert rows whose `id` is new; for a
    /// colliding `id`, `name` and every OTHER column are decided
    /// SEPARATELY (C-F7):
    ///
    /// - `name` takes `source`'s value only when `source.name` is
    ///   non-empty AND (`dest.name` is empty/NULL OR
    ///   `source.updated_at_ms` is strictly greater) — an empty-but-newer
    ///   `source` name must never erase a real `dest` name.
    /// - every other column takes `source`'s value only when
    ///   `source.updated_at_ms` is strictly greater than `dest`'s — so an
    ///   OLDER `source` never rolls back a newer `dest`'s `updated_at` or
    ///   any other field, regardless of what `source.name` happens to be.
    ///
    /// `updated_at_ms` ties keep `dest` (arbitrary but deterministic; only
    /// one side can have written since the shared timestamp last matched).
    ///
    /// `columns` MUST already be validated (S-F8) AND restricted to
    /// [`THREADS_MERGE_ALLOWLIST`] — via [`threads_non_id_columns`], which
    /// is the only production caller of this function. A NEW row (an `id`
    /// with no `dest` counterpart) is inserted via `INSERT ... SELECT *`
    /// UNCONDITIONALLY — every column, allowlisted or not — because a
    /// fresh row has no existing per-account data to protect. `columns`
    /// governs ONLY the UPDATE path (a colliding `id`): an empty list
    /// (every discovered column filtered out by the allowlist — an
    /// unexpected schema, not the ordinary case) skips the UPDATE clause
    /// entirely rather than emitting an empty `SET`, but new rows are
    /// still inserted.
    fn merge_threads(
        binary: &Path,
        dest: &Path,
        source: &Path,
        columns: &[String],
    ) -> Result<(), ShareError> {
        ensure_safe_attach_path(source)?;
        let quoted_source = sql_quote_path(source);
        let id_q = quote_ident("id");
        let mut script = format!(
            "ATTACH DATABASE '{quoted_source}' AS srcdb;\n\
             BEGIN IMMEDIATE;\n\
             INSERT INTO threads SELECT * FROM srcdb.threads WHERE {id_q} NOT IN (SELECT {id_q} FROM threads);\n"
        );
        if !columns.is_empty() {
            let updated_q = quote_ident("updated_at_ms");
            let name_q = quote_ident("name");
            let set_clause = columns
                .iter()
                .map(|c| {
                    let cq = quote_ident(c);
                    if c == "name" {
                        format!(
                            "{name_q} = CASE \
                             WHEN s.{name_q} IS NOT NULL AND s.{name_q} <> '' \
                                  AND (threads.{name_q} IS NULL OR threads.{name_q} = '' \
                                       OR s.{updated_q} > threads.{updated_q}) \
                             THEN s.{name_q} \
                             ELSE threads.{name_q} END"
                        )
                    } else {
                        format!(
                            "{cq} = CASE \
                             WHEN s.{updated_q} > threads.{updated_q} THEN s.{cq} \
                             ELSE threads.{cq} END"
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join(",\n  ");
            script.push_str(&format!(
                "UPDATE threads SET\n  {set_clause}\n\
                 FROM (SELECT * FROM srcdb.threads) AS s\n\
                 WHERE threads.{id_q} = s.{id_q};\n"
            ));
        }
        script.push_str("COMMIT;\nDETACH DATABASE srcdb;\n");
        run_sqlite3(binary, dest, &script)?;
        Ok(())
    }

    /// Delete every row from every table in `db_path` except sqlite's own
    /// bookkeeping tables and `_sqlx_migrations` — the "adopt schema, drop
    /// content" strategy for a rebuildable projection database.
    fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// One real per-slot sqlite file participating in a merge.
    struct RealEntry {
        path: PathBuf,
        work_copy: PathBuf,
        /// FM-10: `path`'s (main, wal) fingerprint at the moment `work_copy`
        /// was taken from it — re-compared immediately before `path` is
        /// renamed away, below.
        snapshot: DbFingerprint,
    }

    /// (inode, size, mtime) for one file — `None` when the file does not
    /// exist. Deliberately infallible: a stat error (permission, race) is
    /// folded into `None` rather than propagated, because on the
    /// destructive rename path this fingerprint guards, "cannot prove this
    /// file is unchanged" MUST read as CHANGED, never as an error to
    /// surface separately (`guard-reader-writer-parity.md` MUST-2).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileStamp {
        #[cfg(unix)]
        ino: u64,
        size: u64,
        mtime_ns: i128,
    }

    impl FileStamp {
        fn of(meta: &fs::Metadata) -> Self {
            let mtime_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i128)
                .unwrap_or(-1);
            #[cfg(unix)]
            let ino = {
                use std::os::unix::fs::MetadataExt;
                meta.ino()
            };
            FileStamp {
                #[cfg(unix)]
                ino,
                size: meta.len(),
                mtime_ns,
            }
        }
    }

    /// FM-10: the fingerprint compared immediately before each per-basename
    /// rename — the main db file plus its `-wal` sidecar (a live writer's
    /// most recent transaction lands there before a checkpoint, so the main
    /// file's stamp alone can lag behind an active writer).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DbFingerprint {
        main: Option<FileStamp>,
        wal: Option<FileStamp>,
    }

    fn fingerprint_db(path: &Path) -> DbFingerprint {
        let main = fs::metadata(path).ok().as_ref().map(FileStamp::of);
        let wal_path = PathBuf::from(format!("{}-wal", path.display()));
        let wal = fs::metadata(&wal_path).ok().as_ref().map(FileStamp::of);
        DbFingerprint { main, wal }
    }

    // C-R4-11: a genuine filesystem race (a write landing INSIDE the
    // syscall duration of `copy_db_with_sidecars`) cannot be reproduced
    // deterministically in a test without either a flaky true race or an
    // injectable seam — so this thread-local hook gives tests exactly one
    // deterministic place to land a mutation between the pre- and
    // post-copy fingerprint samples `apply_basename_plan_with` takes.
    // Production code NEVER populates it; `run_test_after_copy_hook` is a
    // no-op outside `#[cfg(test)]` builds (the `thread_local!` itself does
    // not exist there), so this has zero footprint in a release binary.
    #[cfg(test)]
    type TestAfterCopyHook = std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>>;

    #[cfg(test)]
    thread_local! {
        static TEST_AFTER_COPY_HOOK: TestAfterCopyHook = const { std::cell::RefCell::new(None) };
    }

    fn run_test_after_copy_hook(_path: &Path) {
        #[cfg(test)]
        TEST_AFTER_COPY_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_path);
            }
        });
    }

    #[cfg(test)]
    pub(super) fn set_test_after_copy_hook(hook: impl FnMut(&Path) + 'static) {
        TEST_AFTER_COPY_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn clear_test_after_copy_hook() {
        TEST_AFTER_COPY_HOOK.with(|cell| *cell.borrow_mut() = None);
    }

    // F8: the sibling seam for the NEW post-rename re-fingerprint check —
    // a genuine "an already-open fd keeps writing after `rename` retargets
    // the path" race is exactly as undeterministic to reproduce as
    // C-R4-11's copy-phase race above, so this hook gives a test one
    // deterministic place to mutate a BACKUP file's bytes between its
    // rename-to-backup and the post-loop re-fingerprint compare. Same
    // zero-footprint-outside-`#[cfg(test)]` posture as its sibling.
    #[cfg(test)]
    type TestAfterRenameHook = std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>>;

    #[cfg(test)]
    thread_local! {
        static TEST_AFTER_RENAME_HOOK: TestAfterRenameHook = const { std::cell::RefCell::new(None) };
    }

    fn run_test_after_rename_hook(_path: &Path) {
        #[cfg(test)]
        TEST_AFTER_RENAME_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_path);
            }
        });
    }

    #[cfg(test)]
    pub(super) fn set_test_after_rename_hook(hook: impl FnMut(&Path) + 'static) {
        TEST_AFTER_RENAME_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn clear_test_after_rename_hook() {
        TEST_AFTER_RENAME_HOOK.with(|cell| *cell.borrow_mut() = None);
    }

    /// S-F9: removes every registered `.merge-src` scratch copy (and its
    /// `-wal`/`-shm` sidecars) on drop — success, a mid-merge error, or a
    /// symlink-step failure alike — so a scratch copy is never left behind
    /// on ANY exit path out of the block that creates them. Idempotent:
    /// removing a path already cleaned up by the success path (or never
    /// fully written) is a harmless no-op via [`remove_db_with_sidecars`].
    #[derive(Default)]
    struct WorkCopyGuard(Vec<PathBuf>);

    impl WorkCopyGuard {
        fn push(&mut self, path: PathBuf) {
            self.0.push(path);
        }
    }

    impl Drop for WorkCopyGuard {
        fn drop(&mut self) {
            for path in &self.0 {
                remove_db_with_sidecars(path);
            }
        }
    }

    /// What [`plan_one_basename`] found for one basename — a decision made
    /// entirely from READS, with no mutation performed yet.
    #[derive(Debug)]
    pub(super) enum BasenamePlan {
        /// Every slot holding this basename is already correctly linked (or
        /// no slot has a real copy left — a concurrent second run).
        AlreadyShared,
        /// [`SqliteDbRole::KeptPerSlot`]: left untouched in `slots` slots.
        KeptPerSlot { slots: usize },
        /// [`SqliteDbRole::State`]: ready to merge. `real_paths` is every
        /// slot's real (non-symlink) copy; already verified for integrity
        /// and migration-set agreement against every OTHER real copy AND
        /// the existing shared DB, if any (C-F6). `columns` is `threads`'
        /// non-`id` column set, already validated against the identifier
        /// allowlist (S-F8).
        ToMerge {
            real_paths: Vec<PathBuf>,
            columns: Vec<String>,
        },
    }

    /// Merge (or, in a dry run, plan) every codex cross-slot sqlite database
    /// found across every codex slot under `base`.
    ///
    /// `--dry-run` never mutates: every READ this function performs (role
    /// detection, integrity check, migrations comparison) runs for real, so
    /// the reported plan is the same decision a real run would make, not a
    /// separate guess (`instrument-discipline.md`). `force` skips the
    /// live-writer guard for a real run, exactly as `share_surface` does.
    ///
    /// C-F6b: every basename is fully VERIFIED — via `plan_one_basename`,
    /// across every slot AND against the existing shared DB — before ANY
    /// basename is mutated. Basenames used to verify-then-mutate ONE AT A
    /// TIME, so a mismatch discovered on the Nth basename left the first
    /// N-1 already merged, backed up, and linked. Splitting into a
    /// verify-all phase followed by an apply-all phase means a failure on
    /// any basename aborts before any basename's on-disk state changes.
    pub fn share_codex_sqlite(
        base: &Path,
        dry_run: bool,
        force: bool,
    ) -> Result<CodexSqliteReport, ShareError> {
        // F8: EXCLUSIVE for the whole run, held across the live-writer
        // check AND every basename's plan+apply below — so a `csq run`
        // launch cannot acquire the SHARED side (see
        // `super::acquire_codex_share_lock_shared`) in the window between
        // this guard passing and this migration's first mutation. Dry runs
        // mutate nothing and are exempt, matching the live-writer guard's
        // own dry-run exemption immediately below. Dropped at function
        // exit (every return path, including `?`), releasing it for the
        // next launch or migration. S-M1: bounded, not blocking — see
        // `super::acquire_codex_share_lock_exclusive_bounded_reporting`.
        let _share_lock = if dry_run {
            None
        } else {
            Some(super::acquire_codex_share_lock_exclusive_bounded_reporting(
                base,
            )?)
        };
        if !dry_run {
            ensure_no_live_writers(base, Surface::Codex, force)?;
        }
        share_codex_sqlite_locked(base, dry_run, force)
    }

    /// [`share_codex_sqlite`]'s body with the EXCLUSIVE lock acquire and the
    /// live-writer check ALREADY DONE by the caller (S-M2). Used by
    /// [`super::share_codex_surface_and_sqlite`] to run both halves of the
    /// codex share under ONE lock acquire and ONE live-writer scan — calling
    /// [`share_codex_sqlite`] itself there would try to acquire the
    /// EXCLUSIVE lock a second time on a different file descriptor while
    /// this same process already holds it, and `flock` is not reentrant
    /// across descriptions, so the second acquire would simply time out
    /// against itself.
    pub(super) fn share_codex_sqlite_locked(
        base: &Path,
        dry_run: bool,
        force: bool,
    ) -> Result<CodexSqliteReport, ShareError> {
        let binary = resolve_sqlite3()?;
        let slots = discover_slots(base, Surface::Codex);
        let shared_dir = shared_root(base, Surface::Codex);
        if !dry_run {
            fs::create_dir_all(&shared_dir).map_err(|e| ShareError::io(&shared_dir, e))?;
        }

        let mut basenames: Vec<String> = Vec::new();
        let mut slot_homes: Vec<(AccountNum, PathBuf)> = Vec::with_capacity(slots.len());
        for slot in slots {
            let home = slot_home(base, Surface::Codex, slot)?;
            for name in list_sqlite_basenames(&home) {
                if !basenames.contains(&name) {
                    basenames.push(name);
                }
            }
            slot_homes.push((slot, home));
        }
        // C-R4-14: also derive basenames already present in the shared
        // store — covers a basename whose only per-slot evidence has since
        // been fully migrated (every slot symlinked) or removed (an
        // account deleted after migrating), so it would otherwise never
        // enter the verify/apply phases below even though the shared DB
        // for it still exists.
        for name in scan_basenames_in(&shared_dir) {
            if !basenames.contains(&name) {
                basenames.push(name);
            }
        }
        basenames.sort();

        // Phase 1: verify EVERY basename (read-only, except FM-12(A)'s
        // stranded-backup repair on a real run — see `plan_one_basename`).
        // A mismatch anywhere in this loop aborts before any basename
        // reaches phase 2.
        let mut plans: Vec<(String, BasenamePlan)> = Vec::with_capacity(basenames.len());
        for basename in &basenames {
            let plan = plan_one_basename(&binary, &shared_dir, &slot_homes, basename, dry_run)?;
            plans.push((basename.clone(), plan));
        }

        // Phase 2: apply every plan. Only reached once every basename in
        // this run has independently passed phase 1.
        let mut databases = Vec::with_capacity(plans.len());
        for (basename, plan) in plans {
            let report =
                apply_basename_plan(base, &binary, &shared_dir, &basename, plan, dry_run, force)?;
            databases.push(report);
        }
        Ok(CodexSqliteReport { databases })
    }

    /// The newest (largest-epoch) `<basename>.pre-share-<epoch>` backup
    /// directly under `home`, if any — excludes its own `-wal`/`-shm`
    /// sidecars, which never parse as a bare epoch suffix.
    ///
    /// FM-12(A): a crash between the backup rename and the symlink step
    /// leaves exactly this shape — a `.pre-share-*` backup with nothing
    /// left at the basename path.
    fn newest_pre_share_backup(home: &Path, basename: &str) -> Option<PathBuf> {
        let prefix = format!("{basename}.pre-share-");
        let entries = fs::read_dir(home).ok()?;
        entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_string();
                let suffix = name.strip_prefix(&prefix)?;
                if suffix.ends_with("-wal") || suffix.ends_with("-shm") {
                    return None;
                }
                let epoch: u64 = suffix.parse().ok()?;
                Some((epoch, home.join(name)))
            })
            .max_by_key(|(epoch, _)| *epoch)
            .map(|(_, path)| path)
    }

    /// S-F2: refuses a `.pre-share-<epoch>` name whose target is anything
    /// other than a genuine regular file — a symlink (planted to point
    /// somewhere the caller does not intend to restore from) or a
    /// directory. `symlink_metadata` is used deliberately: `metadata`
    /// follows a symlink and would report on whatever it points AT, which
    /// is exactly the shape this check exists to refuse rather than trust.
    fn verify_backup_is_regular_file(basename: &str, backup: &Path) -> Result<(), ShareError> {
        match backup.symlink_metadata() {
            Ok(meta) if meta.is_file() => Ok(()),
            _ => Err(ShareError::UnexpectedShapeDynamic {
                relpath: basename.to_string(),
                path: crate::cli_deps::sanitize::redact_path(backup),
            }),
        }
    }

    /// Verification phase for one basename — every read [`detect_role`],
    /// [`integrity_check`], [`migrations_signature`] performs runs for
    /// real, so the returned plan is the same decision a real (or dry) run
    /// makes.
    ///
    /// FM-12(A) is the one exception to "nothing here mutates" — and ONLY
    /// on a real (`dry_run == false`) run (C-R4-13 / S-F2): when a slot's
    /// basename path holds neither a real file nor a symlink but a
    /// `.pre-share-*` backup for it exists, this is a crash between the
    /// backup rename and the symlink step in a PRIOR run — the backup is
    /// renamed back to the basename path so it re-enters the merge as an
    /// ordinary real copy. This is a repair of a prior run's already-
    /// stranded state, not a forward mutation into the shared store: every
    /// downstream merge is idempotent on already-merged content
    /// (S-F7's newer-wins comparison), so re-verifying and re-linking it is
    /// safe even if this slot's data had already reached `shared_path`
    /// before the crash. Restoring it here — rather than silently
    /// `continue`-ing past it — is what stops a re-run from reporting
    /// `AlreadyShared` for a slot that in fact holds unshared, unlinked
    /// data with no other path back to it. Under `dry_run`, the same
    /// backup is instead read in place (never renamed) so planning still
    /// reports `ToMerge` rather than a false `AlreadyShared` — see
    /// `verify_backup_is_regular_file` for the S-F2 shape check applied to
    /// it in both cases.
    pub(super) fn plan_one_basename(
        binary: &Path,
        shared_dir: &Path,
        slot_homes: &[(AccountNum, PathBuf)],
        basename: &str,
        dry_run: bool,
    ) -> Result<BasenamePlan, ShareError> {
        let shared_path = shared_dir.join(basename);

        let mut real_paths: Vec<PathBuf> = Vec::new();
        for (_, home) in slot_homes {
            let p = home.join(basename);
            match p.symlink_metadata() {
                Err(_) => {
                    if let Some(backup) = newest_pre_share_backup(home, basename) {
                        // S-F2: a `.pre-share-<epoch>` name is trusted only
                        // when the entry it names is a REGULAR file —
                        // `symlink_metadata` (not `metadata`, which would
                        // follow a planted symlink and report on whatever
                        // it points at) so a symlink masquerading under
                        // this name is refused rather than restored.
                        verify_backup_is_regular_file(basename, &backup)?;
                        if dry_run {
                            // C-R4-13 / S-F2: `--dry-run` MUST NEVER
                            // mutate. Report what a real run would repair
                            // without performing the rename, and verify
                            // against the backup's own bytes (below, via
                            // `real_paths`) rather than the still-absent
                            // basename path.
                            tracing::info!(
                                backup = %crate::cli_deps::sanitize::redact_path(&backup),
                                restore_to = %crate::cli_deps::sanitize::redact_path(&p),
                                "shared-state (dry-run): would restore stranded pre-share backup"
                            );
                            real_paths.push(backup);
                        } else {
                            rename_db_with_sidecars(&backup, &p)?;
                            real_paths.push(p);
                        }
                    }
                    continue;
                }
                Ok(meta) if meta.file_type().is_symlink() => {
                    let target = fs::read_link(&p).map_err(|e| ShareError::io(&p, e))?;
                    if target != shared_path {
                        return Err(ShareError::UnexpectedShapeDynamic {
                            relpath: basename.to_string(),
                            path: crate::cli_deps::sanitize::redact_path(&p),
                        });
                    }
                    // Already correctly linked — nothing to do for this slot.
                }
                Ok(meta) if meta.is_file() => real_paths.push(p),
                Ok(_) => {
                    return Err(ShareError::UnexpectedShapeDynamic {
                        relpath: basename.to_string(),
                        path: crate::cli_deps::sanitize::redact_path(&p),
                    })
                }
            }
        }

        if real_paths.is_empty() {
            // Every slot holding this basename is already correctly linked,
            // or discovery found the name in a slot that no longer has a
            // real copy of it (a concurrent second run). Either way there
            // is nothing left to merge.
            return Ok(BasenamePlan::AlreadyShared);
        }

        // Role is determined from the FIRST real copy — every real copy is
        // required (below) to carry an identical `_sqlx_migrations` set,
        // which is the schema-identity guarantee that makes "first" as good
        // a representative as any other.
        let role = detect_role(binary, &real_paths[0])?;

        if role == SqliteDbRole::KeptPerSlot {
            return Ok(BasenamePlan::KeptPerSlot {
                slots: real_paths.len(),
            });
        }

        // ── verification: every real copy, before any mutation ──────────
        //
        // C-F6: the comparison must also cover the EXISTING shared DB, not
        // just the per-slot copies against each other. Two per-slot copies
        // can agree with each other and still disagree with an
        // already-established shared store (e.g. a slot lagging behind a
        // migration every OTHER slot, including the shared DB itself,
        // already has) — that must refuse exactly like a mismatched
        // sibling slot would, not merge silently into a schema the shared
        // DB does not have.
        let mut signatures: Vec<(PathBuf, Option<String>)> =
            Vec::with_capacity(real_paths.len() + 1);
        if shared_path.exists() {
            integrity_check(binary, basename, &shared_path)?;
            forbid_untrusted_schema_objects(binary, basename, &shared_path)?;
            let shared_sig = migrations_signature(binary, &shared_path)?;
            signatures.push((shared_path.clone(), shared_sig));
        }
        for path in &real_paths {
            integrity_check(binary, basename, path)?;
            forbid_untrusted_schema_objects(binary, basename, path)?;
            let sig = migrations_signature(binary, path)?;
            signatures.push((path.clone(), sig));
        }
        let (first_path, first_sig) = &signatures[0];
        for (path, sig) in &signatures[1..] {
            if sig != first_sig {
                return Err(ShareError::SqliteMigrationsMismatch {
                    basename: basename.to_string(),
                    a_path: first_path.clone(),
                    b_path: path.clone(),
                });
            }
        }

        // Only `SqliteDbRole::State` reaches here: `KeptPerSlot` already
        // returned above, and `detect_role` has no third variant.
        debug_assert_eq!(role, SqliteDbRole::State);

        // S-F8: validate + collect the `threads` columns up front, from
        // whichever database ends up canonical, so an unsafe identifier
        // refuses here — before any mutation — rather than mid-merge.
        let repr_path = if shared_path.exists() {
            &shared_path
        } else {
            &real_paths[0]
        };
        let columns = threads_non_id_columns(binary, basename, repr_path)?;

        Ok(BasenamePlan::ToMerge {
            real_paths,
            columns,
        })
    }

    /// Apply (or, in a dry run, report) a [`BasenamePlan`] already verified
    /// by [`plan_one_basename`]. Only the `ToMerge` arm, on a real run,
    /// performs any mutation.
    fn apply_basename_plan(
        base: &Path,
        binary: &Path,
        shared_dir: &Path,
        basename: &str,
        plan: BasenamePlan,
        dry_run: bool,
        force: bool,
    ) -> Result<SqliteDbReport, ShareError> {
        apply_basename_plan_with(
            base,
            binary,
            shared_dir,
            basename,
            plan,
            dry_run,
            force,
            super::isolation::create_symlink_pub,
        )
    }

    /// [`apply_basename_plan`]'s core, with the raw symlink-creation
    /// primitive INJECTED — mirrors [`attach_slot_with`]'s injection of
    /// [`create_shared_symlink`], for the same reason: a genuine link
    /// failure between the backup rename and the verify step (S-F9's
    /// rollback) cannot be produced by ordinary filesystem permissions,
    /// since both the rename and the symlink creation need write access to
    /// the SAME parent directory. Production always routes through
    /// [`apply_basename_plan`]; only tests call this directly with a
    /// failing `create`.
    // The eighth parameter is the injected symlink primitive (the test seam
    // documented above); folding it into a struct would obscure that seam.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_basename_plan_with(
        base: &Path,
        binary: &Path,
        shared_dir: &Path,
        basename: &str,
        plan: BasenamePlan,
        dry_run: bool,
        force: bool,
        mut create: impl FnMut(&Path, &Path) -> io::Result<()>,
    ) -> Result<SqliteDbReport, ShareError> {
        match plan {
            BasenamePlan::AlreadyShared => Ok(SqliteDbReport {
                basename: basename.to_string(),
                role: SqliteDbRole::KeptPerSlot,
                outcome: SqliteDbOutcome::AlreadyShared,
            }),
            BasenamePlan::KeptPerSlot { slots } => Ok(SqliteDbReport {
                basename: basename.to_string(),
                role: SqliteDbRole::KeptPerSlot,
                outcome: SqliteDbOutcome::KeptPerSlot { slots },
            }),
            BasenamePlan::ToMerge {
                real_paths,
                columns,
            } => {
                if dry_run {
                    return Ok(SqliteDbReport {
                        basename: basename.to_string(),
                        role: SqliteDbRole::State,
                        outcome: SqliteDbOutcome::Merged {
                            slots_merged: real_paths.len(),
                        },
                    });
                }
                let shared_path = shared_dir.join(basename);

                // S-F9: every `.merge-src` scratch copy created below is
                // removed on ANY exit from this block — success, a
                // verification failure, a merge failure, or a symlink
                // failure — via this drop guard, rather than only on the
                // success path.
                let mut work_copy_cleanup = WorkCopyGuard::default();

                // ── working copies: checkpoint + re-verify on the COPY,
                //    never the original, so the original's bytes stay
                //    pristine for the backup rename below. FM-10: snapshot
                //    each original's fingerprint HERE, at the moment its
                //    working copy is taken — re-compared immediately before
                //    that same original is renamed away, below ───────────
                let mut entries: Vec<RealEntry> = Vec::with_capacity(real_paths.len());
                for path in &real_paths {
                    let work_copy = PathBuf::from(format!("{}.merge-src", path.display()));
                    remove_db_with_sidecars(&work_copy);
                    work_copy_cleanup.push(work_copy.clone());
                    // C-R4-11 (FM-10): fingerprint BEFORE copying, not only
                    // after. A write that lands DURING
                    // `copy_db_with_sidecars` can be reflected in `path`'s
                    // stat once the copy returns while being ABSENT from
                    // `work_copy`'s bytes (the copy may already have read
                    // past that region) — fingerprinting only afterward
                    // cannot see the two have diverged, so the later
                    // pre-rename recheck (which compares a fresh stat
                    // against THIS snapshot) finds no difference and the
                    // write is silently missing from the merged DB.
                    // Re-fingerprinting immediately after the copy and
                    // refusing on any difference is what actually proves
                    // `work_copy` reflects `path` at a single instant.
                    let pre_copy = fingerprint_db(path);
                    copy_db_with_sidecars(path, &work_copy)?;
                    run_test_after_copy_hook(path);
                    let post_copy = fingerprint_db(path);
                    if pre_copy != post_copy {
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: path.clone(),
                        });
                    }
                    checkpoint_truncate(binary, &work_copy)?;
                    integrity_check(binary, basename, &work_copy)?;
                    entries.push(RealEntry {
                        path: path.clone(),
                        work_copy,
                        snapshot: post_copy,
                    });
                }

                let shared_already_exists = shared_path.exists();
                if !shared_already_exists {
                    // FM-11: never write the FIRST creation of the shared
                    // DB directly to `shared_path` — a write failure
                    // partway through (disk full, killed process) would
                    // leave a truncated file AT the canonical path, and
                    // every future run refuses forever on
                    // `PRAGMA integrity_check` against it, with no way to
                    // distinguish "born truncated" from "genuinely
                    // corrupt". Build it at a scratch name instead, merge
                    // every entry into THAT, verify its integrity, and
                    // only then atomically rename it into place. The
                    // scratch name is removed on ANY exit via
                    // `work_copy_cleanup` — a no-op once the rename below
                    // has moved it away.
                    let tmp_shared = PathBuf::from(format!("{}.new-share", shared_path.display()));
                    remove_db_with_sidecars(&tmp_shared);
                    work_copy_cleanup.push(tmp_shared.clone());
                    copy_db_with_sidecars(&entries[0].work_copy, &tmp_shared)?;
                    for entry in &entries[1..] {
                        merge_threads(binary, &tmp_shared, &entry.work_copy, &columns)?;
                    }
                    checkpoint_truncate(binary, &tmp_shared)?;
                    integrity_check(binary, basename, &tmp_shared)?;
                    rename_db_with_sidecars(&tmp_shared, &shared_path)?;
                } else {
                    for entry in &entries {
                        merge_threads(binary, &shared_path, &entry.work_copy, &columns)?;
                    }
                }

                // ── back up every original, then link. S-F9: if creating
                //    or verifying the link fails, the original is restored
                //    from the backup we just made — the slot must never be
                //    left with neither a real file nor a working symlink.
                //
                //    FM-10: the live-writer guard at the top of
                //    `share_codex_sqlite` runs ONCE, before this entire
                //    merge — a codex-cli session launched mid-merge (after
                //    that check, before this rename) would hold handles on
                //    THIS slot's soon-to-be-`.pre-share-*` files with
                //    nothing left to catch it. So immediately before EACH
                //    rename: re-run the live-writer guard, and re-compare
                //    this original's fingerprint against the snapshot
                //    taken when its working copy was made. Either check
                //    tripping aborts just THIS basename, leaves every
                //    original untouched, and rolls back any entry already
                //    renamed+linked for it earlier in this same loop ─────
                let mut renamed_so_far: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(entries.len());
                let epoch = now_epoch_secs();
                for entry in &entries {
                    // C-R4-12 / S-F6: every error exit from this loop body
                    // routes through `rollback_renamed`, not just the
                    // fingerprint-mismatch arm. `ensure_no_live_writers`
                    // returning `Err`, or the rename-to-backup itself
                    // failing, used to propagate via a bare `?` — skipping
                    // the rollback of any SIBLING entry already
                    // renamed+linked earlier in this same loop, leaving the
                    // slot set half-migrated. The doc comment above this
                    // loop already asserted "rolls back any entry already
                    // renamed+linked" as a blanket property
                    // (`doc-property-claims.md` MUST-1); it is now true for
                    // every branch, not only the one it happened to hold for.
                    if let Err(e) = ensure_no_live_writers(base, Surface::Codex, force) {
                        rollback_renamed(&renamed_so_far);
                        return Err(e);
                    }
                    if fingerprint_db(&entry.path) != entry.snapshot {
                        rollback_renamed(&renamed_so_far);
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: entry.path.clone(),
                        });
                    }
                    let backup =
                        PathBuf::from(format!("{}.pre-share-{epoch}", entry.path.display()));
                    if let Err(e) = rename_db_with_sidecars(&entry.path, &backup) {
                        rollback_renamed(&renamed_so_far);
                        return Err(e);
                    }
                    run_test_after_rename_hook(&backup);
                    let linked = create(&shared_path, &entry.path)
                        .map_err(|e| ShareError::io(&entry.path, e))
                        .and_then(|()| super::verify_is_symlink(&entry.path));
                    if let Err(e) = linked {
                        let _ = rename_db_with_sidecars(&backup, &entry.path);
                        rollback_renamed(&renamed_so_far);
                        return Err(e);
                    }
                    renamed_so_far.push((entry.path.clone(), backup));
                }

                // F8: one more fingerprint compare, now against each
                // freshly-created BACKUP file's own path, after every
                // entry in this basename has been renamed and linked.
                //
                // The per-entry check just above (immediately before ITS
                // rename) proves the original was unchanged up to the
                // instant of that rename — but `rename_db_with_sidecars`
                // retargets the PATH, not any file descriptor a writer
                // already has open on the underlying inode. A live writer
                // this process's `ps`/handle-dir scan failed to detect
                // (the exact residual risk the codex share lock narrows
                // but a stale `.live-pid`, or a process outside csq's own
                // launch path entirely, can still produce) keeps writing
                // through that fd, and the write now lands on the BACKUP
                // file rather than the path anyone else can reach — so the
                // pre-rename check alone cannot see it. Comparing again
                // here, against the same snapshot, catches exactly that:
                // any difference means the backup is not the pristine copy
                // this migration believed it moved, and every entry
                // renamed for THIS basename is rolled back rather than
                // left half-migrated on unverified content.
                for (entry, (_original, backup)) in entries.iter().zip(&renamed_so_far) {
                    if fingerprint_db(backup) != entry.snapshot {
                        rollback_renamed(&renamed_so_far);
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: entry.path.clone(),
                        });
                    }
                }

                Ok(SqliteDbReport {
                    basename: basename.to_string(),
                    role: SqliteDbRole::State,
                    outcome: SqliteDbOutcome::Merged {
                        slots_merged: entries.len(),
                    },
                })
            }
        }
    }
}

// HERMETICITY NOTE: any test that calls `detect_live_writers`,
// `ensure_no_live_writers`, `acquire_codex_share_lock_exclusive_bounded_reporting[_with]`,
// `share_surface`, `share_codex_surface_and_sqlite`, `share_codex_sqlite[_locked]`,
// or `apply_basename_plan[_with]` with `force=false` and asserts a
// DETERMINISTIC outcome (an exact pid list, an empty live-writer set, an
// uncontended success) MUST wrap it in
// `let _guard = force_list_running_processes(vec![]);` (or a populated
// list to simulate a live vendor process). Without it the test reads the
// REAL host-wide process table (Signal 1 of `detect_live_writers`), which
// includes real `codex`/`claude` processes on every developer machine and
// every agentic-coding-session CI run (`test-hermeticity.md`) — see
// `exclusive_bounded_reporting_times_out_and_names_the_scanned_pids` for
// the pattern. Tests that already guarantee a live writer via their OWN
// handle-dir fixture (a `term-*` dir with `.live-pid` == this process) do
// not need the guard for THAT signal, but still need it if they also
// assert on the EXACT pid list or an uncontended/empty result.
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn slot_num(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn write(p: &Path, content: &[u8]) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    // ── F8: codex share lock (shared/exclusive) ──────────────────────────
    //
    // Evidence-rule note: the property under test is discriminating —
    // `acquire_codex_share_lock_shared_bounded` returning `Some` vs `None`
    // is a DIFFERENT observable result depending on whether an exclusive
    // holder is alive, so these tests satisfy `instrument-discipline.md`
    // MUST-1/2 directly (both branches of the hypothesis are exercised and
    // produce different, asserted outcomes) without needing a source
    // mutation.

    /// Two SHARED acquires on the same path, from two independent opens
    /// (never reentrant same-fd calls — see `platform/lock.rs`'s own test
    /// comment on why that would not discriminate), must both succeed —
    /// readers never exclude each other.
    #[test]
    fn codex_share_lock_shared_permits_concurrent_readers() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        let g1 =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap();
        assert!(g1.is_some(), "first shared acquire must succeed");

        let g2 =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap();
        assert!(
            g2.is_some(),
            "a second SHARED acquire must succeed while the first is held \
             (readers do not exclude each other)"
        );
    }

    /// An EXCLUSIVE holder (the migration side) must exclude a concurrent
    /// SHARED attempt (a launch) for as long as it is held, and release it
    /// on drop — the RED/GREEN pair this test proves in one run.
    #[test]
    fn codex_share_lock_exclusive_excludes_a_concurrent_shared_attempt() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        let exclusive = acquire_codex_share_lock_exclusive_bounded(
            base,
            5,
            std::time::Duration::from_millis(20),
        )
        .unwrap()
        .expect("uncontended exclusive acquire must succeed");

        // RED (were exclusivity NOT enforced, this would also be `Some`):
        // a SHARED attempt while the migration holds EXCLUSIVE must be
        // contended.
        let contended =
            acquire_codex_share_lock_shared_bounded(base, 3, std::time::Duration::from_millis(20))
                .unwrap();
        assert!(
            contended.is_none(),
            "a SHARED acquire must be contended while EXCLUSIVE is held"
        );

        drop(exclusive);

        // GREEN: once released, the same request now succeeds.
        let after_release =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap();
        assert!(
            after_release.is_some(),
            "SHARED must succeed once the EXCLUSIVE holder is dropped"
        );
    }

    /// The converse: a live SHARED holder (a launch) must exclude a
    /// concurrent EXCLUSIVE attempt (a migration) until it is dropped.
    #[test]
    fn codex_share_lock_shared_excludes_a_concurrent_exclusive_attempt() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        let shared =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap()
                .expect("uncontended shared acquire must succeed");

        let contended = acquire_codex_share_lock_exclusive_bounded(
            base,
            3,
            std::time::Duration::from_millis(20),
        )
        .unwrap();
        assert!(
            contended.is_none(),
            "an EXCLUSIVE acquire must be contended while a SHARED holder is alive"
        );

        drop(shared);

        let after_release = acquire_codex_share_lock_exclusive_bounded(
            base,
            5,
            std::time::Duration::from_millis(20),
        )
        .unwrap();
        assert!(
            after_release.is_some(),
            "EXCLUSIVE must succeed once every SHARED holder is dropped"
        );
    }

    /// [`acquire_codex_share_lock_shared`] (the real, non-test, 20x100ms
    /// entry point `launch_codex` will call) reports the fixed-vocabulary
    /// contention error rather than hanging when the exclusive side is
    /// held — proving the PUBLIC function, not just the bounded test seam,
    /// actually surfaces [`ShareError::CodexShareLockContended`].
    #[test]
    fn public_shared_acquire_reports_contention_rather_than_hanging() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let _exclusive = acquire_codex_share_lock_exclusive_bounded(
            base,
            5,
            std::time::Duration::from_millis(20),
        )
        .unwrap()
        .expect("uncontended exclusive acquire must succeed");

        // NOTE: this exercises the PUBLIC function's full 20x100ms bound
        // (~2s) — acceptable for one test in this suite.
        let err = acquire_codex_share_lock_shared(base).unwrap_err();
        assert!(
            matches!(err, ShareError::CodexShareLockContended),
            "{err:?}"
        );
    }

    /// The lock DIRECTORY (0700) and the lock FILE (0600) carry the
    /// declared permissions this feature's brief requires.
    #[test]
    #[cfg(unix)]
    fn codex_share_lock_file_and_dir_are_secured() {
        use std::os::unix::fs::PermissionsExt;

        let t = TempDir::new().unwrap();
        let base = t.path();
        let _guard =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap()
                .unwrap();

        let dir = shared_root(base, Surface::Codex);
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "shared-state/codex/ must be 0700");

        let lock_path = codex_share_lock_path(base);
        let file_mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, ".share.lock must be 0600");
    }

    // ── S-M1: the EXCLUSIVE acquire is BOUNDED and REPORTS, never hangs ──

    /// A live SHARED holder must make the EXCLUSIVE side time out — never
    /// hang — and the timeout error must name the live session(s) the
    /// pre-lock scan observed. Uses the injectable `_with` seam (small
    /// attempts/delay) so this test pays only its own bound, not the
    /// production constant.
    #[test]
    fn exclusive_bounded_reporting_times_out_and_names_the_scanned_pids() {
        // Hermetic: the pre-lock scan reads the real host-wide process
        // table (Signal 1) unless overridden — force it empty so this
        // assertion is not at the mercy of whether a real `codex`/`claude`
        // process happens to be alive on the host running this test
        // (`test-hermeticity.md`).
        let _procs_guard = force_list_running_processes(vec![]);
        let t = TempDir::new().unwrap();
        let base = t.path();
        let shared =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap()
                .expect("uncontended shared acquire must succeed");

        let err = acquire_codex_share_lock_exclusive_bounded_reporting_with(
            base,
            3,
            std::time::Duration::from_millis(20),
        )
        .unwrap_err();
        match &err {
            ShareError::CodexShareLockTimedOut { pids, .. } => {
                // No handle-dir bookkeeping was set up by this fixture, so
                // the pre-lock scan legitimately finds nothing — the
                // message must say so plainly rather than fabricating a
                // pid, and must NOT be confused with the unrelated
                // `CodexShareLockContended` variant the SHARED side raises.
                assert!(
                    pids.contains("none identified"),
                    "expected the no-evidence wording, got: {pids}"
                );
            }
            other => panic!("expected CodexShareLockTimedOut, got {other:?}"),
        }
        assert!(!matches!(err, ShareError::CodexShareLockContended));

        drop(shared);
        let after_release = acquire_codex_share_lock_exclusive_bounded_reporting_with(
            base,
            5,
            std::time::Duration::from_millis(20),
        );
        assert!(
            after_release.is_ok(),
            "EXCLUSIVE must succeed once the SHARED holder releases: {after_release:?}"
        );
    }

    /// [`acquire_codex_share_lock_exclusive_bounded_reporting`] (the real,
    /// non-test, `EXCLUSIVE_LOCK_ATTEMPTS`x`EXCLUSIVE_LOCK_DELAY_MS` entry
    /// point [`codex_sqlite::share_codex_sqlite`] calls) reports the timeout
    /// error rather than hanging when a SHARED holder is alive — proving
    /// the PRODUCTION function, not just the bounded test seam. Also proves
    /// `--force` does NOT shorten or skip this wait: both calls below hit
    /// the SAME lock-timeout path, before `force` is ever consulted.
    ///
    /// NOTE: exercises the PUBLIC function's full ~3s bound, twice —
    /// acceptable for this suite, matching this file's existing
    /// `public_shared_acquire_reports_contention_rather_than_hanging`.
    #[test]
    fn public_exclusive_acquire_reports_timeout_rather_than_hanging_with_and_without_force() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let _shared =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap()
                .expect("uncontended shared acquire must succeed");

        for force in [false, true] {
            let err = codex_sqlite::share_codex_sqlite(base, false, force).unwrap_err();
            assert!(
                matches!(err, ShareError::CodexShareLockTimedOut { .. }),
                "force={force}: {err:?}"
            );
        }
    }

    // ── S-M2: the exclusive lock covers BOTH halves of the codex share ───

    /// Before S-M2, only the sqlite half took the exclusive lock — the
    /// symlink half (`share_surface`) ran completely unlocked, so a live
    /// `launch_codex` SHARED holder excluded the sqlite merge but NOT the
    /// symlink-entry migration. This proves the combined entry point
    /// excludes BOTH: while a SHARED holder is alive, neither half may run
    /// — in particular the symlink half must not have touched a single
    /// slot's on-disk shape.
    #[test]
    fn shared_holder_blocks_the_symlink_half_of_the_codex_share_too() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Codex, slot_num(9)).unwrap();
        fs::create_dir_all(home.join("codex-sessions")).unwrap();
        write(
            &home.join("codex-sessions/rollout.jsonl"),
            b"TEST INPUT rollout",
        );

        let shared =
            acquire_codex_share_lock_shared_bounded(base, 5, std::time::Duration::from_millis(20))
                .unwrap()
                .expect("uncontended shared acquire must succeed");

        // NOTE: exercises the PUBLIC combined entry point's real ~3s bound
        // — acceptable for one test in this suite (see the exclusive-side
        // note above).
        let err = share_codex_surface_and_sqlite(base, false, false).unwrap_err();
        assert!(
            matches!(err, ShareError::CodexShareLockTimedOut { .. }),
            "{err:?}"
        );

        drop(shared);

        // The property S-M2 exists to guarantee: the symlink half did NOT
        // run while the lock was contended, even though (pre-fix) it had no
        // lock of its own to be excluded by.
        assert!(
            !home
                .join("codex-sessions")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink half must not have run while the share lock was contended"
        );
    }

    /// Both halves DO run, in order, once the lock is uncontended — the
    /// positive case alongside the refusal above. Needs a real `sqlite3`
    /// binary (the sqlite half resolves one even when nothing is planted to
    /// merge) — same skip posture as `codex_sqlite_tests::require_sqlite3`.
    #[test]
    fn share_codex_surface_and_sqlite_runs_both_halves_when_uncontended() {
        // Hermetic: this call runs the REAL live-writer guard (force=false,
        // uncontended expected) — force the host-wide process scan empty
        // so a real `codex` process on the host running this test cannot
        // turn "uncontended" into an unexpected refusal
        // (`test-hermeticity.md`).
        let _procs_guard = force_list_running_processes(vec![]);
        match codex_sqlite::resolve_sqlite3() {
            Ok(_) => {}
            Err(_) if cfg!(target_os = "macos") => panic!(
                "this test requires a `sqlite3` binary (macOS ships /usr/bin/sqlite3) — see CSQ_SQLITE3"
            ),
            Err(_) => {
                eprintln!("SKIPPED: no `sqlite3` binary on this host (set CSQ_SQLITE3 to run)");
                return;
            }
        }
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Codex, slot_num(9)).unwrap();
        fs::create_dir_all(home.join("codex-sessions")).unwrap();
        write(
            &home.join("codex-sessions/rollout.jsonl"),
            b"TEST INPUT rollout",
        );

        let (slot_reports, sqlite_report) =
            share_codex_surface_and_sqlite(base, false, false).unwrap();
        assert_eq!(slot_reports.len(), 1, "{slot_reports:?}");
        assert!(
            home.join("codex-sessions")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink half must have run"
        );
        // No sqlite state was planted, so the sqlite half legitimately
        // reports nothing — its report existing at all (rather than an
        // Err) is what this test is proving.
        assert!(sqlite_report.databases.is_empty());
    }

    // ── S-L7: the lock dir and the lock file itself refuse a symlink ─────

    /// A `shared-state/codex` planted as a symlink (rather than a real
    /// directory) must be refused, not silently followed into whatever it
    /// points at.
    ///
    /// Unix-only: `std::os::unix::fs::symlink` does not exist on Windows
    /// (`std::os::windows::fs::symlink_dir` is the platform equivalent, and
    /// this test's own subject — a directory planted as a symlink — is not
    /// exercised on that platform here). Pre-existing gap found compiling
    /// this file for `x86_64-pc-windows-gnu` (`E0433: could not find "unix"
    /// in "os"`); the fix is the missing `#[cfg(unix)]`, not a rewrite.
    #[cfg(unix)]
    #[test]
    fn share_lock_refuses_a_symlinked_shared_state_dir() {
        use std::os::unix::fs::symlink;

        let t = TempDir::new().unwrap();
        let base = t.path();
        let elsewhere = t.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(base.join("shared-state")).unwrap();
        symlink(&elsewhere, base.join("shared-state/codex")).unwrap();

        let err =
            acquire_codex_share_lock_shared_bounded(base, 3, std::time::Duration::from_millis(20))
                .unwrap_err();
        assert!(
            matches!(err, ShareError::UnexpectedShapeDynamic { .. }),
            "{err:?}"
        );
        assert!(
            !elsewhere.join(".share.lock").exists(),
            "the lock file must not have been created through the planted symlink"
        );
    }

    /// A `.share.lock` planted as a symlink (rather than a real file) must
    /// be refused by the OPEN itself (`O_NOFOLLOW`), not merely inspected
    /// and then followed.
    ///
    /// Unix-only — see `share_lock_refuses_a_symlinked_shared_state_dir`'s
    /// doc for why (same `std::os::unix::fs::symlink` gap).
    #[cfg(unix)]
    #[test]
    fn share_lock_refuses_a_symlinked_lock_file() {
        use std::os::unix::fs::symlink;

        let t = TempDir::new().unwrap();
        let base = t.path();
        let dir = shared_root(base, Surface::Codex);
        fs::create_dir_all(&dir).unwrap();
        let decoy = t.path().join("decoy-lock-target");
        fs::write(&decoy, b"").unwrap();
        symlink(&decoy, dir.join(".share.lock")).unwrap();

        let err =
            acquire_codex_share_lock_shared_bounded(base, 3, std::time::Duration::from_millis(20))
                .unwrap_err();
        assert!(
            matches!(err, ShareError::UnexpectedShapeDynamic { .. }),
            "{err:?}"
        );
    }

    /// S-LOW-5: a symlink planted at the INTERMEDIATE `base/shared-state`
    /// component (with a genuine `codex/` directory underneath it, on the
    /// OTHER side of the symlink) must be refused just as surely as one
    /// planted at the leaf `shared-state/codex`. The pre-S-LOW-5 check
    /// (`symlink_metadata` on `shared-state/codex` alone) would NOT catch
    /// this: resolving that path's intermediate `shared-state` component
    /// follows the symlink transparently, so the leaf lstat would see an
    /// ordinary directory and never notice anything was planted upstream.
    #[cfg(unix)]
    #[test]
    fn share_lock_refuses_a_symlinked_intermediate_shared_state_component() {
        use std::os::unix::fs::symlink;

        let t = TempDir::new().unwrap();
        let base = t.path();
        let elsewhere = t.path().join("elsewhere");
        fs::create_dir_all(elsewhere.join("codex")).unwrap();
        // `base/shared-state` itself is the symlink — no real `shared-state`
        // dir exists under `base` at all.
        symlink(&elsewhere, base.join("shared-state")).unwrap();

        let err =
            acquire_codex_share_lock_shared_bounded(base, 3, std::time::Duration::from_millis(20))
                .unwrap_err();
        assert!(
            matches!(err, ShareError::UnexpectedShapeDynamic { .. }),
            "{err:?}"
        );
        assert!(
            !elsewhere.join("codex/.share.lock").exists(),
            "the lock file must not have been created through the planted \
             intermediate symlink"
        );
    }

    /// S-LOW-D: `share_entry` — the generic per-surface, per-entry merge
    /// path shared by kimi, grok, and codex's own entries — must refuse a
    /// symlink planted at `shared-state/<surface>/<relpath>` just as surely
    /// as the codex share-lock dir (S-LOW-5, covered above). Grok is the
    /// smallest declared spec (one entry, `sessions`), used here so the test
    /// exercises a DIFFERENT surface than the codex-only tests above.
    ///
    /// Non-vacuity: this is a genuine RED without the `assert_no_symlink_in_
    /// chain` call added to `share_entry` — `fs::create_dir_all(&shared_path)`
    /// would instead create `elsewhere/anything` through the planted
    /// symlink (or, for a real merge, write cross-slot session data into it),
    /// and the call would return `Ok`, never surfacing `UnexpectedShapeDynamic`.
    #[cfg(unix)]
    #[test]
    fn share_entry_refuses_a_symlinked_shared_state_target() {
        use std::os::unix::fs::symlink;

        let t = TempDir::new().unwrap();
        let base = t.path();
        let elsewhere = t.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(base.join("shared-state/grok")).unwrap();
        symlink(&elsewhere, base.join("shared-state/grok/sessions")).unwrap();

        let entry = GROK_SHARED.shared[0];
        let slot = AccountNum::try_from(4u16).unwrap();
        let err = share_entry(base, Surface::Grok, slot, &entry, false).unwrap_err();
        assert!(
            matches!(err, ShareError::UnexpectedShapeDynamic { .. }),
            "{err:?}"
        );
        assert!(
            fs::read_dir(&elsewhere).unwrap().next().is_none(),
            "nothing must have been written into the planted symlink's target"
        );
    }

    /// Restores `HOME` on drop (including on an unwinding panic), matching
    /// `codex_sqlite_tests::HomeRestore` — kept local to this module rather
    /// than shared across the `mod tests` / `mod codex_sqlite_tests`
    /// boundary.
    struct HomeRestoreForSymlinkTests(Option<std::ffi::OsString>);
    impl Drop for HomeRestoreForSymlinkTests {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    /// S-LOW-3: `UnexpectedShapeDynamic`'s `path` field must not leak the
    /// operator's `$HOME`-rooted host path — `HOME` is pinned to the
    /// tempdir root so the fixture's own paths are genuinely `$HOME`-rooted,
    /// which `redact_path` requires to have anything to strip.
    #[cfg(unix)]
    #[test]
    fn symlinked_shared_state_error_redacts_the_home_path() {
        use std::os::unix::fs::symlink;

        let _env_guard = crate::platform::test_env::lock();
        let t = TempDir::new().unwrap();
        let _restore = HomeRestoreForSymlinkTests(std::env::var_os("HOME"));
        std::env::set_var("HOME", t.path());
        let base = t.path();
        let elsewhere = t.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(base.join("shared-state")).unwrap();
        symlink(&elsewhere, base.join("shared-state/codex")).unwrap();

        let err =
            acquire_codex_share_lock_shared_bounded(base, 3, std::time::Duration::from_millis(20))
                .unwrap_err();
        let rendered = err.to_string();
        assert!(
            !rendered.contains(&t.path().display().to_string()),
            "error must not contain the raw $HOME-rooted path: {rendered}"
        );
    }

    /// S-LOW-3: the `<unreadable at {path}>` branch of
    /// `format_live_writer_pids` — reachable from both
    /// `ShareError::LiveWriters` and `CodexShareLockTimedOut`'s `{pids}`
    /// interpolation — must not leak the operator's `$HOME`-rooted
    /// handle-dir path either.
    #[test]
    fn format_live_writer_pids_redacts_unreadable_handle_dir() {
        let _env_guard = crate::platform::test_env::lock();
        let t = TempDir::new().unwrap();
        let _restore = HomeRestoreForSymlinkTests(std::env::var_os("HOME"));
        std::env::set_var("HOME", t.path());
        let handle_dir = t.path().join("term-999");

        let rendered = format_live_writer_pids(&[LiveWriter {
            pid: 0,
            handle_dir: handle_dir.clone(),
        }]);

        assert!(
            !rendered.contains(&t.path().display().to_string()),
            "must not contain the raw $HOME-rooted path: {rendered}"
        );
    }

    // Synthetic private filesystem only: no detector, CLI, identity resolver,
    // process listing, credentials, or keychain is called by these fixtures.
    fn attach_fixture() -> (TempDir, PathBuf, PathBuf) {
        let t = TempDir::new().unwrap();
        let home = slot_home(t.path(), Surface::Codex, slot_num(21)).unwrap();
        let root = shared_root(t.path(), Surface::Codex);
        fs::create_dir_all(&home).unwrap();
        for entry in CODEX_SHARED.shared {
            match entry.kind {
                EntryKind::Dir => fs::create_dir_all(root.join(entry.relpath)).unwrap(),
                EntryKind::File => write(&root.join(entry.relpath), b"TEST INPUT shared history\n"),
            }
        }
        write(
            &root.join("codex-sessions/rollout.jsonl"),
            b"TEST INPUT rollout",
        );
        write(
            &home.join("codex-auth.json"),
            b"TEST INPUT identity, not credentials",
        );
        (t, home, root)
    }

    #[test]
    fn attach_only_preflight_dry_run_preserves_namespace_and_bytes() {
        let (t, home, root) = attach_fixture();
        let report = attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), true)
            .unwrap()
            .unwrap();
        assert_eq!(report.entries.len(), 4);
        for entry in &report.entries {
            assert!(!entry.already_shared);
            assert!(home.join(entry.relpath).symlink_metadata().is_err());
        }
        assert_eq!(fs::read_dir(&home).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 4);
        assert_eq!(
            fs::read(root.join("codex-history.jsonl")).unwrap(),
            b"TEST INPUT shared history\n"
        );
    }

    #[test]
    #[cfg(unix)]
    fn attach_only_links_fresh_slot_preserving_shared_history_and_identity() {
        let (t, home, root) = attach_fixture();
        // A private live-writer-shaped handle must not cause process discovery
        // or migration. No test resolves or signals this PID.
        write(&t.path().join("term-123/.live-pid"), b"123");
        write(&t.path().join("term-123/auth.json"), b"TEST INPUT");
        write(&t.path().join("term-123/config.toml"), b"TEST INPUT");
        let first = attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false)
            .unwrap()
            .unwrap();
        assert_eq!(first.entries.len(), 4);
        for entry in &first.entries {
            assert_eq!(
                fs::read_link(home.join(entry.relpath)).unwrap(),
                root.join(entry.relpath)
            );
            assert_eq!(entry.files_moved + entry.bytes_moved + entry.lines_added, 0);
        }
        assert_eq!(
            fs::read(home.join("codex-auth.json")).unwrap(),
            b"TEST INPUT identity, not credentials"
        );
        assert!(!home
            .join("codex-auth.json")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(root.join("codex-history.jsonl")).unwrap(),
            b"TEST INPUT shared history\n"
        );
        assert_eq!(
            fs::read(root.join("codex-sessions/rollout.jsonl")).unwrap(),
            b"TEST INPUT rollout"
        );
        let second = attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false)
            .unwrap()
            .unwrap();
        assert!(second.entries.iter().all(|entry| entry.already_shared));
    }

    #[test]
    fn attach_only_late_local_entry_ineligible_before_any_publication() {
        for content in [b"".as_slice(), b"TEST INPUT local"] {
            let (t, home, root) = attach_fixture();
            write(&home.join("codex-thread-writer-locks"), content);
            assert!(
                attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false)
                    .unwrap()
                    .is_none()
            );
            assert!(home.join("codex-sessions").symlink_metadata().is_err());
            assert_eq!(
                fs::read(home.join("codex-thread-writer-locks")).unwrap(),
                content
            );
            assert_eq!(
                fs::read(root.join("codex-history.jsonl")).unwrap(),
                b"TEST INPUT shared history\n"
            );
        }
        let (t, home, _) = attach_fixture();
        fs::create_dir(home.join("codex-thread-writer-locks")).unwrap();
        assert!(
            attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false)
                .unwrap()
                .is_none()
        );
        assert!(home.join("codex-sessions").symlink_metadata().is_err());
    }

    #[test]
    fn attach_only_missing_or_wrong_target_never_seeds_or_links() {
        for wrong_shape in [false, true] {
            let (t, home, root) = attach_fixture();
            fs::remove_dir(root.join("codex-thread-writer-locks")).unwrap();
            if wrong_shape {
                write(&root.join("codex-thread-writer-locks"), b"TEST INPUT");
            }
            assert!(
                attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false)
                    .unwrap()
                    .is_none()
            );
            assert!(home.join("codex-sessions").symlink_metadata().is_err());
            assert_eq!(root.join("codex-thread-writer-locks").exists(), wrong_shape);
        }
    }

    #[test]
    #[cfg(unix)]
    fn attach_only_conflicting_or_dangling_link_is_not_repointed() {
        let (t, home, _) = attach_fixture();
        let foreign = t.path().join("missing-foreign");
        std::os::unix::fs::symlink(&foreign, home.join("codex-thread-writer-locks")).unwrap();
        assert!(
            attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read_link(home.join("codex-thread-writer-locks")).unwrap(),
            foreign
        );
        assert!(home.join("codex-sessions").symlink_metadata().is_err());
    }

    #[test]
    #[cfg(unix)]
    fn attach_only_metadata_error_is_not_absence() {
        let (t, home, root) = attach_fixture();
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir(root.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("shared-state", root.parent().unwrap()).unwrap();
        assert!(matches!(
            attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false),
            Err(ShareError::Io { .. })
        ));
        assert!(home.join("codex-sessions").symlink_metadata().is_err());
    }

    #[test]
    #[cfg(unix)]
    fn attach_only_concurrent_identical_attach_is_idempotent() {
        let (t, home, root) = attach_fixture();
        let report = attach_slot_with(
            t.path(),
            Surface::Codex,
            slot_num(21),
            false,
            |target, link, kind| {
                create_shared_symlink(target, link, kind)?;
                create_shared_symlink(target, link, kind)
            },
        )
        .unwrap()
        .unwrap();
        assert!(report.entries.iter().all(|e| e.already_shared));
        assert_eq!(
            fs::read_link(home.join("codex-history.jsonl")).unwrap(),
            root.join("codex-history.jsonl")
        );
    }

    #[test]
    #[cfg(unix)]
    fn attach_only_publication_race_never_overwrites_and_partial_error_is_retryable() {
        let (t, home, root) = attach_fixture();
        let mut calls = 0;
        let result = attach_slot_with(
            t.path(),
            Surface::Codex,
            slot_num(21),
            false,
            |target, link, kind| {
                calls += 1;
                if calls == 2 {
                    write(link, b"TEST INPUT competing writer");
                }
                create_shared_symlink(target, link, kind)
            },
        );
        assert!(matches!(result, Err(ShareError::Io { .. })));
        assert_eq!(calls, 2);
        assert_eq!(
            fs::read_link(home.join("codex-sessions")).unwrap(),
            root.join("codex-sessions")
        );
        assert_eq!(
            fs::read(home.join("codex-session_index.jsonl")).unwrap(),
            b"TEST INPUT competing writer"
        );
        assert!(home.join("codex-history.jsonl").symlink_metadata().is_err());
        assert_eq!(
            fs::read(root.join("codex-session_index.jsonl")).unwrap(),
            b"TEST INPUT shared history\n"
        );
        // Fixture removes its own competitor; the API never performs cleanup.
        fs::remove_file(home.join("codex-session_index.jsonl")).unwrap();
        assert!(
            attach_slot_to_existing_shared(t.path(), Surface::Codex, slot_num(21), false)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn attach_only_permission_failure_is_error_without_cleanup_or_fallback() {
        let (t, home, _) = attach_fixture();
        let result = attach_slot_with(t.path(), Surface::Codex, slot_num(21), false, |_, _, _| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TEST INPUT denied",
            ))
        });
        assert!(matches!(result, Err(ShareError::Io { .. })));
        assert_eq!(fs::read_dir(home).unwrap().count(), 1);
    }

    // ── merge does not lose data ─────────────────────────────────────────

    #[test]
    fn merge_does_not_lose_data_across_two_slots() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        let home1 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
        let home2 = slot_home(base, Surface::Codex, slot_num(12)).unwrap();
        write(
            &home1.join("codex-sessions/2026/08/23/rollout-a.jsonl"),
            b"slot11-content",
        );
        write(
            &home2.join("codex-sessions/2026/09/01/rollout-b.jsonl"),
            b"slot12-content",
        );

        share_slot(base, Surface::Codex, slot_num(11), false).unwrap();
        share_slot(base, Surface::Codex, slot_num(12), false).unwrap();

        let shared = shared_root(base, Surface::Codex).join("codex-sessions");
        let a = fs::read(shared.join("2026/08/23/rollout-a.jsonl")).unwrap();
        let b = fs::read(shared.join("2026/09/01/rollout-b.jsonl")).unwrap();
        assert_eq!(a, b"slot11-content");
        assert_eq!(b, b"slot12-content");

        // Both slot homes now resolve to the SAME shared store.
        assert_eq!(
            fs::read(home1.join("codex-sessions/2026/09/01/rollout-b.jsonl")).unwrap(),
            b"slot12-content"
        );
        assert_eq!(
            fs::read(home2.join("codex-sessions/2026/08/23/rollout-a.jsonl")).unwrap(),
            b"slot11-content"
        );
    }

    // ── idempotence ───────────────────────────────────────────────────────

    #[test]
    fn running_share_slot_twice_is_a_noop_the_second_time() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Codex, slot_num(3)).unwrap();
        write(&home.join("codex-sessions/rollout-x.jsonl"), b"content");
        write(
            &home.join("codex-history.jsonl"),
            b"{\"session_id\":\"a\"}\n",
        );

        let first = share_slot(base, Surface::Codex, slot_num(3), false).unwrap();
        assert!(first.entries.iter().all(|e| !e.already_shared));

        let second = share_slot(base, Surface::Codex, slot_num(3), false).unwrap();
        assert!(
            second.entries.iter().all(|e| e.already_shared),
            "second run must be a no-op: {second:?}"
        );
        for e in &second.entries {
            assert_eq!(e.files_moved, 0);
            assert_eq!(e.lines_added, 0);
        }

        // The rollout file is still there, exactly once, via the shared store.
        assert_eq!(
            fs::read(home.join("codex-sessions/rollout-x.jsonl")).unwrap(),
            b"content"
        );
    }

    // ── identity is never touched ────────────────────────────────────────

    #[test]
    fn identity_file_stays_a_real_per_slot_file_after_migration() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Codex, slot_num(5)).unwrap();
        write(&home.join("codex-auth.json"), b"{\"tokens\":\"secret\"}");
        write(&home.join("codex-sessions/rollout.jsonl"), b"x");

        share_slot(base, Surface::Codex, slot_num(5), false).unwrap();

        let meta = fs::symlink_metadata(home.join("codex-auth.json")).unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "codex-auth.json must remain a REAL per-slot file, never shared"
        );
        assert_eq!(
            fs::read(home.join("codex-auth.json")).unwrap(),
            b"{\"tokens\":\"secret\"}"
        );
    }

    // ── merge_jsonl fails CLOSED on the side it overwrites ───────────────

    /// A non-UTF-8 SHARED file must REFUSE the merge, not silently become "".
    ///
    /// The defect this pins: `merge_jsonl` read the shared side with
    /// `unwrap_or_default()`, so a shared file that is not valid UTF-8 read as
    /// the empty string and the `atomic_replace` below wrote ONLY the slot's
    /// lines over it — total, silent loss of the shared side. The asymmetry was
    /// the tell: the side about to be DESTROYED failed open while the side that
    /// SURVIVES failed closed (`guard-reader-writer-parity.md` MUST-2).
    ///
    /// Falsifying result, named up front: with `unwrap_or_default()` restored,
    /// `share_slot` returns Ok and the shared file afterwards contains only the
    /// slot's line — the original bytes gone. That is the assertion below.
    ///
    /// Reachability: today every declared `EntryKind::File` is JSONL, so this
    /// needs a hand-planted binary shared file. It arms for real the moment any
    /// binary entry is declared as `File` — which is precisely what "just share
    /// the sqlite too" would do.
    #[test]
    fn merge_jsonl_refuses_a_non_utf8_shared_file_instead_of_erasing_it() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Codex, slot_num(1)).unwrap();

        // A shared target that is not valid UTF-8 — e.g. a SQLite header.
        let shared = shared_root(base, Surface::Codex).join("codex-session_index.jsonl");
        fs::create_dir_all(shared.parent().unwrap()).unwrap();
        let binary: &[u8] = b"SQLite format 3\x00\xff\xfe\x00binary-payload";
        fs::write(&shared, binary).unwrap();

        write(
            &home.join("codex-session_index.jsonl"),
            b"{\"id\":\"only-slot-line\"}\n",
        );

        let err = share_slot(base, Surface::Codex, slot_num(1), false)
            .expect_err("a non-UTF-8 shared file must refuse the merge");

        // The bytes are still there, untouched.
        assert_eq!(
            fs::read(&shared).unwrap(),
            binary,
            "the shared file must be byte-identical after the refusal: {err:?}"
        );
    }

    /// The benign case must stay benign: an ABSENT shared file is the normal
    /// first-migration path and must NOT be turned into an error by the
    /// fail-closed change. Without this, the fix above would break every
    /// first-ever share.
    #[test]
    fn merge_jsonl_treats_an_absent_shared_file_as_empty_not_an_error() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Codex, slot_num(1)).unwrap();
        write(
            &home.join("codex-session_index.jsonl"),
            b"{\"id\":\"first\"}\n",
        );

        let report = share_slot(base, Surface::Codex, slot_num(1), false)
            .expect("a first migration with no shared file yet must succeed");
        let e = report
            .entries
            .iter()
            .find(|e| e.relpath == "codex-session_index.jsonl")
            .unwrap();
        assert_eq!(e.lines_added, 1, "the slot's one line lands: {e:?}");
    }

    // ── JSONL dedupe ─────────────────────────────────────────────────────

    #[test]
    fn jsonl_dedupe_collapses_duplicate_id_updated_at_keeps_distinct_ids() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home1 = slot_home(base, Surface::Codex, slot_num(1)).unwrap();
        let home2 = slot_home(base, Surface::Codex, slot_num(2)).unwrap();

        let dup_line = r#"{"id":"aaa","thread_name":"x","updated_at":"2026-01-01T00:00:00Z"}"#;
        let distinct_line = r#"{"id":"bbb","thread_name":"y","updated_at":"2026-01-02T00:00:00Z"}"#;

        write(
            &home1.join("codex-session_index.jsonl"),
            format!("{dup_line}\n").as_bytes(),
        );
        write(
            &home2.join("codex-session_index.jsonl"),
            format!("{dup_line}\n{distinct_line}\n").as_bytes(),
        );

        share_slot(base, Surface::Codex, slot_num(1), false).unwrap();
        let report2 = share_slot(base, Surface::Codex, slot_num(2), false).unwrap();

        let index_report = report2
            .entries
            .iter()
            .find(|e| e.relpath == "codex-session_index.jsonl")
            .unwrap();
        assert_eq!(
            index_report.lines_added, 1,
            "only bbb is new: {index_report:?}"
        );
        assert_eq!(
            index_report.lines_deduped, 1,
            "aaa is a duplicate: {index_report:?}"
        );

        let shared_content =
            fs::read_to_string(shared_root(base, Surface::Codex).join("codex-session_index.jsonl"))
                .unwrap();
        let lines: Vec<&str> = shared_content.lines().collect();
        assert_eq!(lines.len(), 2, "exactly one aaa + one bbb: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("\"aaa\"")));
        assert!(lines.iter().any(|l| l.contains("\"bbb\"")));
    }

    // ── dry-run makes no changes ─────────────────────────────────────────

    #[test]
    fn dry_run_reports_counts_but_touches_nothing() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Codex, slot_num(7)).unwrap();
        write(&home.join("codex-sessions/rollout.jsonl"), b"hello world");
        write(
            &home.join("codex-history.jsonl"),
            b"{\"session_id\":\"z\"}\n",
        );

        let report = share_slot(base, Surface::Codex, slot_num(7), true).unwrap();
        let sessions = report
            .entries
            .iter()
            .find(|e| e.relpath == "codex-sessions")
            .unwrap();
        assert_eq!(sessions.files_moved, 1);
        assert_eq!(sessions.bytes_moved, "hello world".len() as u64);

        // Nothing on disk changed: the slot dir is still real, not a symlink.
        let meta = fs::symlink_metadata(home.join("codex-sessions")).unwrap();
        assert!(!meta.file_type().is_symlink());
        assert!(!shared_root(base, Surface::Codex).exists());
    }

    // ── directory collision: identical content dedupes, different content kept-both ──

    #[test]
    fn directory_collision_hash_identical_dedupes_different_kept_both() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home1 = slot_home(base, Surface::Codex, slot_num(21)).unwrap();
        let home2 = slot_home(base, Surface::Codex, slot_num(22)).unwrap();

        write(
            &home1.join("codex-sessions/same-name.jsonl"),
            b"identical bytes",
        );
        share_slot(base, Surface::Codex, slot_num(21), false).unwrap();

        // slot 22 has a DIFFERENT file at the SAME relative name.
        write(
            &home2.join("codex-sessions/same-name.jsonl"),
            b"different bytes",
        );
        let report = share_slot(base, Surface::Codex, slot_num(22), false).unwrap();
        let sessions = report
            .entries
            .iter()
            .find(|e| e.relpath == "codex-sessions")
            .unwrap();
        assert_eq!(sessions.conflicts_kept_both, 1, "{sessions:?}");

        let shared = shared_root(base, Surface::Codex).join("codex-sessions");
        assert_eq!(
            fs::read(shared.join("same-name.jsonl")).unwrap(),
            b"identical bytes"
        );
        let kept_both = shared.join("same-name.jsonl.slot22");
        assert_eq!(fs::read(&kept_both).unwrap(), b"different bytes");

        // Re-run with a truly IDENTICAL duplicate: dedupes, no new kept-both file.
        let home3 = slot_home(base, Surface::Codex, slot_num(23)).unwrap();
        write(
            &home3.join("codex-sessions/same-name.jsonl"),
            b"identical bytes",
        );
        let report3 = share_slot(base, Surface::Codex, slot_num(23), false).unwrap();
        let sessions3 = report3
            .entries
            .iter()
            .find(|e| e.relpath == "codex-sessions")
            .unwrap();
        assert_eq!(sessions3.duplicates_removed, 1, "{sessions3:?}");
        assert_eq!(sessions3.conflicts_kept_both, 0, "{sessions3:?}");
    }

    // ── discover_slots ───────────────────────────────────────────────────

    #[test]
    fn discover_slots_finds_codex_and_kimi_homes() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        fs::create_dir_all(base.join("config-1")).unwrap();
        fs::create_dir_all(base.join("config-9")).unwrap();
        fs::create_dir_all(base.join("native-homes/kimi-4")).unwrap();
        fs::create_dir_all(base.join("native-homes/grok-4")).unwrap();

        let codex = discover_slots(base, Surface::Codex);
        assert_eq!(codex, vec![slot_num(1), slot_num(9)]);

        let kimi = discover_slots(base, Surface::Kimi);
        assert_eq!(kimi, vec![slot_num(4)]);

        let grok = discover_slots(base, Surface::Grok);
        assert_eq!(grok, vec![slot_num(4)]);
    }

    // ── spawn/cleanup path correctness ──────────────────────────────────
    //
    // `csq logout` removes a slot's home via `std::fs::remove_dir_all`
    // (`accounts::logout.rs`). Rust's `remove_dir_all` does NOT follow
    // symlinks — a symlinked entry is unlinked, never descended into — so
    // logging out of one slot must NOT touch the shared store another slot
    // still reads from. This pins that safety property directly rather
    // than relying on documented std behaviour.

    #[test]
    fn removing_a_slot_home_does_not_touch_the_shared_store() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home1 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
        let home2 = slot_home(base, Surface::Codex, slot_num(12)).unwrap();
        write(&home1.join("codex-sessions/rollout.jsonl"), b"slot11-data");
        write(&home2.join("codex-auth.json"), b"slot12-identity");

        share_slot(base, Surface::Codex, slot_num(11), false).unwrap();
        share_slot(base, Surface::Codex, slot_num(12), false).unwrap();

        // Simulate `csq logout 11`'s config-dir removal.
        fs::remove_dir_all(&home1).unwrap();

        // The shared store — and slot 12's view of it — must survive.
        let shared = shared_root(base, Surface::Codex).join("codex-sessions");
        assert_eq!(
            fs::read(shared.join("rollout.jsonl")).unwrap(),
            b"slot11-data"
        );
        assert_eq!(
            fs::read(home2.join("codex-sessions/rollout.jsonl")).unwrap(),
            b"slot11-data",
            "slot 12 must still resolve the shared history after slot 11 is logged out of"
        );
    }

    // ── live-writer guard ────────────────────────────────────────────────
    //
    // Protects the 15GB relocation from a concurrent writer: a per-file
    // `rename` is atomic per file, but a codex process that writes a
    // rollout into the OLD directory after that directory drains lands its
    // write in a path about to become a symlink — invisible. Proven on
    // BOTH independent signals, the `--force` override, and the
    // `--dry-run` exemption.

    #[test]
    fn live_writer_guard_refuses_on_either_signal_and_force_overrides() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        // Clean base, no injected processes: nothing to refuse.
        assert!(ensure_no_live_writers_with(&[], base, Surface::Codex).is_ok());

        // Signal 1 (process scan): a synthetic "codex" entry with NO
        // handle-dir bookkeeping behind it at all.
        let err = ensure_no_live_writers_with(&[(9999, "codex".to_string())], base, Surface::Codex)
            .expect_err("a matching process name alone must refuse");
        match err {
            ShareError::LiveWriters {
                count, ref pids, ..
            } => {
                assert_eq!(count, 1, "{err:?}");
                assert!(
                    pids.contains("9999"),
                    "operator must see the pid; got {pids}"
                );
            }
            other => panic!("expected LiveWriters, got {other:?}"),
        }

        // Signal 2 (handle-dir bookkeeping): a codex-shaped term-<pid> dir
        // with OUR OWN pid recorded — unambiguously alive, no sleeping, no
        // racing. Injected process list stays EMPTY, isolating this
        // assertion to signal 2 alone.
        let term = base.join("term-424242");
        fs::create_dir_all(&term).unwrap();
        let real = base.join("real-target");
        fs::write(&real, b"x").unwrap();
        for item in ["auth.json", "config.toml"] {
            isolation::create_symlink_pub(&real, &term.join(item)).unwrap();
        }
        let me = std::process::id();
        fs::write(term.join(".live-pid"), me.to_string()).unwrap();

        let err = ensure_no_live_writers_with(&[], base, Surface::Codex)
            .expect_err("a live codex handle dir must refuse even with an empty process scan");
        match err {
            ShareError::LiveWriters {
                count, ref pids, ..
            } => {
                assert_eq!(count, 1, "exactly the one live handle dir: {err:?}");
                assert!(
                    pids.contains(&me.to_string()),
                    "operator must see the pid; got {pids}"
                );
            }
            other => panic!("expected LiveWriters, got {other:?}"),
        }

        // `--dry-run` is NEVER gated by the guard — share_surface succeeds
        // even with the live writer still present.
        assert!(
            share_surface(base, Surface::Codex, true, false).is_ok(),
            "--dry-run must never be blocked by the live-writer guard"
        );

        // A REAL run without --force is refused.
        assert!(
            share_surface(base, Surface::Codex, false, false).is_err(),
            "a real run must be refused while a writer is live"
        );

        // `--force` bypasses the guard for a real run.
        assert!(
            share_surface(base, Surface::Codex, false, true).is_ok(),
            "--force must override the guard"
        );
    }

    /// The guard must see a codex handle dir whose `auth.json` /
    /// `config.toml` are REAL FILES, not symlinks — the shape Windows
    /// handle-dir provisioning produces when it cannot create a symlink and
    /// degrades to a hard link or a copy.
    ///
    /// This reds on every platform against an `is_symlink`-keyed detector,
    /// so it is not a Windows-only assertion smuggled into a Unix suite: the
    /// fixture constructs the degraded shape directly rather than waiting
    /// for a host that produces it (`guard-reader-writer-parity.md` MUST-4).
    #[test]
    fn live_writer_guard_sees_a_codex_handle_dir_whose_items_are_not_symlinks() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        let term = base.join("term-515151");
        fs::create_dir_all(&term).unwrap();
        // Real files — the degraded (hard-link / copy) shape.
        for item in ["auth.json", "config.toml"] {
            fs::write(term.join(item), b"{}").unwrap();
            assert!(
                !fs::symlink_metadata(term.join(item))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "fixture must NOT be a symlink, or the test proves nothing"
            );
        }
        let me = std::process::id();
        fs::write(term.join(".live-pid"), me.to_string()).unwrap();

        let err = ensure_no_live_writers_with(&[], base, Surface::Codex)
            .expect_err("a live codex handle dir must refuse whatever shape its items have");
        match err {
            ShareError::LiveWriters {
                count, ref pids, ..
            } => {
                assert_eq!(count, 1, "exactly the one live handle dir: {err:?}");
                assert!(pids.contains(&me.to_string()), "got {pids}");
            }
            other => panic!("expected LiveWriters, got {other:?}"),
        }
    }

    /// A non-codex handle dir is still ignored — widening the shape test to
    /// presence must not turn every `term-*` dir into a refusal.
    #[test]
    fn live_writer_guard_ignores_a_handle_dir_without_the_codex_pair() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        let term = base.join("term-626262");
        fs::create_dir_all(&term).unwrap();
        // Claude Code's shape: neither codex name present.
        fs::write(term.join(".credentials.json"), b"{}").unwrap();
        fs::write(term.join(".claude.json"), b"{}").unwrap();
        fs::write(term.join(".live-pid"), std::process::id().to_string()).unwrap();

        assert!(
            ensure_no_live_writers_with(&[], base, Surface::Codex).is_ok(),
            "a non-codex handle dir must not trip the codex guard"
        );
    }

    /// `verify_is_symlink` is the fail-closed post-condition that stops a
    /// degraded Windows link being reported as shared. Three outcomes, each
    /// pinned: a symlink passes, a real file is REFUSED and removed, an
    /// absent path is an io error — never a silent pass.
    #[test]
    fn verify_is_symlink_refuses_a_real_file_and_removes_it() {
        let t = TempDir::new().unwrap();
        let base = t.path();

        // (a) a real symlink -> Ok
        let target = base.join("shared-target");
        fs::write(&target, b"x").unwrap();
        let good = base.join("good-link");
        isolation::create_symlink_pub(&target, &good).unwrap();
        assert!(verify_is_symlink(&good).is_ok(), "a symlink must pass");

        // (b) a real file (the hard-link / copy degradation) -> refused
        let degraded = base.join("degraded");
        fs::write(&degraded, b"x").unwrap();
        match verify_is_symlink(&degraded) {
            Err(ShareError::LinkNotSupported { ref path, .. }) => {
                assert_eq!(path, &degraded);
            }
            other => panic!("expected LinkNotSupported, got {other:?}"),
        }
        assert!(
            fs::symlink_metadata(&degraded).is_err(),
            "the degraded entry must be removed so the next run re-links cleanly"
        );

        // (c) nothing there at all -> an io error, not a pass
        assert!(matches!(
            verify_is_symlink(&base.join("absent")),
            Err(ShareError::Io { .. })
        ));
    }

    /// Fail-closed: a surface with no positive detector must report that it
    /// cannot tell, never an empty list a caller would read as "safe".
    #[test]
    fn live_writer_guard_is_undeterminable_for_surfaces_with_no_detector() {
        let tmp = TempDir::new().unwrap();
        for surface in [Surface::Kimi, Surface::Grok] {
            let err = ensure_no_live_writers_with(&[], tmp.path(), surface)
                .expect_err("must refuse rather than claim safety it cannot prove");
            assert!(
                matches!(err, ShareError::LiveWritersUndeterminable(_)),
                "expected LiveWritersUndeterminable for {surface}, got {err:?}"
            );
        }
    }

    // ── unsupported surface ──────────────────────────────────────────────

    #[test]
    fn unsupported_surface_errors_rather_than_guessing() {
        let t = TempDir::new().unwrap();
        let err = share_slot(t.path(), Surface::ClaudeCode, slot_num(1), true).unwrap_err();
        assert!(matches!(
            err,
            ShareError::UnsupportedSurface(Surface::ClaudeCode)
        ));
    }

    // ── kimi + grok specs resolve to native-homes ───────────────────────

    #[test]
    fn kimi_and_grok_specs_resolve_under_native_homes() {
        let t = TempDir::new().unwrap();
        let base = t.path();
        let home = slot_home(base, Surface::Kimi, slot_num(4)).unwrap();
        assert_eq!(home, base.join("native-homes/kimi-4"));
        write(&home.join("sessions/thread.json"), b"kimi-transcript");
        write(&home.join("session_index.jsonl"), b"{\"id\":1}\n");
        write(&home.join("search-index/idx.bin"), b"index-bytes");

        let report = share_slot(base, Surface::Kimi, slot_num(4), false).unwrap();
        assert!(report.entries.iter().all(|e| !e.partial), "{report:?}");

        let grok_home = slot_home(base, Surface::Grok, slot_num(4)).unwrap();
        assert_eq!(grok_home, base.join("native-homes/grok-4"));
        write(&grok_home.join("active_sessions.json"), b"{}");
        write(&grok_home.join("sessions/t.json"), b"grok-transcript");
        share_slot(base, Surface::Grok, slot_num(4), false).unwrap();

        // active_sessions.json is NOT in GROK_SHARED — stays a real file.
        let meta = fs::symlink_metadata(grok_home.join("active_sessions.json")).unwrap();
        assert!(!meta.file_type().is_symlink());
    }

    // ── codex cross-slot sqlite sharing ─────────────────────────────────

    mod codex_sqlite_tests {
        use super::super::codex_sqlite::{
            self, resolve_with, CodexSqliteReport, Probe, SqliteDbOutcome, SqliteDbRole,
        };
        use super::*;
        use std::ffi::OsString;
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        /// Test-only sqlite3 invocation, independent of the production
        /// `run_sqlite3` (which is private to `codex_sqlite`) — this is the
        /// FIXTURE builder, not the code under test.
        fn sh(bin: &Path, db: &Path, script: &str) {
            let mut child = Command::new(bin)
                .args(["-batch"])
                .arg(db)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn sqlite3");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "sqlite3 fixture script failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        fn sh_query(bin: &Path, db: &Path, script: &str) -> String {
            let mut child = Command::new(bin)
                .args(["-batch", "-noheader", "-list"])
                .arg(db)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn sqlite3");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "sqlite3 fixture query failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        /// The `sqlite3` binary these tests drive, or `None` to skip the test.
        ///
        /// macOS always ships `/usr/bin/sqlite3`, so on macOS a missing binary is a
        /// broken environment and the test FAILS rather than skipping: the macOS CI
        /// leg is where this suite's coverage is guaranteed. Elsewhere (e.g. a Linux
        /// build host or CI runner without the sqlite3 CLI) the test is skipped with
        /// a line on stderr; `csq sessions share` itself refuses there with a clear
        /// error, so there is no product behaviour to exercise.
        fn require_sqlite3() -> Option<PathBuf> {
            match codex_sqlite::resolve_sqlite3() {
                Ok(bin) => Some(bin),
                Err(_) if cfg!(target_os = "macos") => panic!(
                    "this suite requires a `sqlite3` binary (macOS ships /usr/bin/sqlite3) — see CSQ_SQLITE3"
                ),
                Err(_) => {
                    eprintln!("SKIPPED: no `sqlite3` binary on this host (set CSQ_SQLITE3 to run)");
                    None
                }
            }
        }

        /// A `threads` row: (id, name, updated_at_ms).
        struct ThreadRow<'a> {
            id: &'a str,
            name: &'a str,
            updated_at_ms: i64,
        }

        fn create_state_db(bin: &Path, path: &Path, rows: &[ThreadRow], with_migrations: bool) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let _ = fs::remove_file(path);
            sh(
                bin,
                path,
                "CREATE TABLE threads (\
                   id TEXT PRIMARY KEY, title TEXT NOT NULL, name TEXT, \
                   updated_at TEXT, updated_at_ms INTEGER, cwd TEXT, model_provider TEXT\
                 );",
            );
            for row in rows {
                let insert = format!(
                    "INSERT INTO threads VALUES ('{}', 'untitled', '{}', 'ts', {}, '/work', 'anthropic');",
                    row.id, row.name, row.updated_at_ms
                );
                sh(bin, path, &insert);
            }
            if with_migrations {
                sh(
                    bin,
                    path,
                    "CREATE TABLE _sqlx_migrations (version INTEGER PRIMARY KEY, description TEXT); \
                     INSERT INTO _sqlx_migrations VALUES (1, 'init');",
                );
            }
        }

        fn create_other_db(bin: &Path, path: &Path) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let _ = fs::remove_file(path);
            sh(
                bin,
                path,
                "CREATE TABLE logs (id INTEGER PRIMARY KEY, message TEXT); \
                 INSERT INTO logs VALUES (1, 'hello');",
            );
        }

        fn thread_name(bin: &Path, path: &Path, id: &str) -> String {
            sh_query(
                bin,
                path,
                &format!("SELECT name FROM threads WHERE id = '{id}';"),
            )
            .trim()
            .to_string()
        }

        fn row_count(bin: &Path, path: &Path, table: &str) -> i64 {
            sh_query(bin, path, &format!("SELECT COUNT(*) FROM {table};"))
                .trim()
                .parse()
                .unwrap()
        }

        /// Any single `threads` column's value for `id`, as text — used by
        /// the C-F7 tests to inspect a column OTHER than `name`.
        fn thread_field(bin: &Path, path: &Path, id: &str, column: &str) -> String {
            sh_query(
                bin,
                path,
                &format!("SELECT {column} FROM threads WHERE id = '{id}';"),
            )
            .trim()
            .to_string()
        }

        // ── Probe-injected resolver tests (no real binary needed) ────────

        struct FakeProbe {
            env: Option<OsString>,
            executables: Vec<PathBuf>,
            path_hits: Vec<(String, PathBuf)>,
        }

        impl Probe for FakeProbe {
            fn env_override(&self) -> Option<OsString> {
                self.env.clone()
            }
            fn is_executable(&self, path: &Path) -> bool {
                self.executables.iter().any(|p| p == path)
            }
            fn find_in_path(&self, name: &str) -> Option<PathBuf> {
                self.path_hits
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, p)| p.clone())
            }
        }

        #[test]
        fn resolver_prefers_env_override_when_executable() {
            // An override must be ABSOLUTE; `/opt/...` is not on Windows, so
            // build one that is absolute on every platform.
            let custom = std::env::temp_dir().join("custom").join("sqlite3");
            let probe = FakeProbe {
                env: Some(custom.clone().into_os_string()),
                executables: vec![custom.clone()],
                path_hits: vec![("sqlite3".into(), PathBuf::from("/usr/bin/sqlite3"))],
            };
            assert_eq!(resolve_with(&probe).unwrap(), custom);
        }

        #[test]
        fn resolver_errors_loudly_on_non_executable_env_override_rather_than_falling_back() {
            let probe = FakeProbe {
                env: Some(OsString::from("/opt/custom/sqlite3")),
                executables: vec![], // the override is NOT executable
                path_hits: vec![("sqlite3".into(), PathBuf::from("/usr/bin/sqlite3"))],
            };
            let err = resolve_with(&probe).unwrap_err();
            assert!(matches!(err, ShareError::Sqlite3NotFound { .. }), "{err:?}");
        }

        #[test]
        fn resolver_falls_back_to_path_when_no_override_set() {
            let probe = FakeProbe {
                env: None,
                executables: vec![],
                path_hits: vec![("sqlite3".into(), PathBuf::from("/usr/bin/sqlite3"))],
            };
            assert_eq!(
                resolve_with(&probe).unwrap(),
                PathBuf::from("/usr/bin/sqlite3")
            );
        }

        /// S-L4 (unix only): the system copy at `/usr/bin/sqlite3` is
        /// preferred over ANY `PATH` hit, even one for a different name —
        /// so a same-user-writable directory placed earlier on `PATH`
        /// cannot substitute a different `sqlite3`. Genuinely
        /// discriminating: `path_hits` here points `find_in_path` at a
        /// DIFFERENT location, so the two candidates disagree and the test
        /// pins which one wins.
        #[test]
        #[cfg(unix)]
        fn resolver_prefers_system_sqlite3_over_a_path_hit() {
            let probe = FakeProbe {
                env: None,
                executables: vec![PathBuf::from("/usr/bin/sqlite3")],
                path_hits: vec![("sqlite3".into(), PathBuf::from("/opt/attacker/sqlite3"))],
            };
            assert_eq!(
                resolve_with(&probe).unwrap(),
                PathBuf::from("/usr/bin/sqlite3"),
                "the system copy must win even though a PATH hit exists"
            );
        }

        #[test]
        fn resolver_errors_when_nothing_found_anywhere() {
            let probe = FakeProbe {
                env: None,
                executables: vec![],
                path_hits: vec![],
            };
            let err = resolve_with(&probe).unwrap_err();
            assert!(matches!(err, ShareError::Sqlite3NotFound { .. }), "{err:?}");
        }

        /// S-F10: a RELATIVE `$CSQ_SQLITE3` override must be refused even
        /// when it happens to resolve executable — the error message
        /// already said "absolute path", but nothing enforced it.
        #[test]
        fn resolver_rejects_a_relative_env_override_even_if_executable() {
            let probe = FakeProbe {
                env: Some(OsString::from("relative/sqlite3")),
                executables: vec![PathBuf::from("relative/sqlite3")],
                path_hits: vec![("sqlite3".into(), PathBuf::from("/usr/bin/sqlite3"))],
            };
            let err = resolve_with(&probe).unwrap_err();
            assert!(matches!(err, ShareError::Sqlite3NotFound { .. }), "{err:?}");
        }

        /// S-F10: `PATH` lookup must skip empty and relative entries — every
        /// candidate under them "exists" per the injected `is_executable`,
        /// so only the absolute, non-empty entry may ever be returned.
        #[test]
        fn path_lookup_skips_empty_and_relative_entries() {
            // `/usr/bin` is not absolute on Windows; use a platform-absolute dir.
            let abs_dir = std::env::temp_dir();
            let dirs = vec![
                PathBuf::from(""),
                PathBuf::from("relative/bin"),
                abs_dir.clone(),
            ];
            let found =
                codex_sqlite::find_executable_in_dirs(dirs.into_iter(), "sqlite3", |_| true);
            assert_eq!(found, Some(abs_dir.join("sqlite3")));
        }

        /// S-F10: with ONLY empty/relative entries present, nothing may be
        /// returned, even though `is_executable` would say yes for every one.
        #[test]
        fn path_lookup_finds_nothing_when_only_empty_or_relative_entries_present() {
            let dirs = vec![PathBuf::from(""), PathBuf::from("relative/bin")];
            let found =
                codex_sqlite::find_executable_in_dirs(dirs.into_iter(), "sqlite3", |_| true);
            assert_eq!(found, None);
        }

        // ── real-binary merge behaviour ───────────────────────────────────

        #[test]
        fn rename_in_one_slot_is_visible_from_another_after_share() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            fs::create_dir_all(&home11).unwrap();
            fs::create_dir_all(&home14).unwrap();

            // Owner symptom: `/rename py` happened in slot 14; slot 11 never
            // saw it and still has an empty name for the SAME thread id.
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "01a0d8a0-thread",
                    name: "",
                    updated_at_ms: 100,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "01a0d8a0-thread",
                    name: "py",
                    updated_at_ms: 200,
                }],
                true,
            );

            let report = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert_eq!(report.databases.len(), 1, "{report:?}");
            let db = &report.databases[0];
            assert_eq!(db.basename, "state_5.sqlite");
            assert_eq!(db.role, SqliteDbRole::State);
            assert!(
                matches!(db.outcome, SqliteDbOutcome::Merged { slots_merged: 2 }),
                "{:?}",
                db.outcome
            );

            for home in [&home11, &home14] {
                let p = home.join("state_5.sqlite");
                assert!(
                    p.symlink_metadata().unwrap().file_type().is_symlink(),
                    "{p:?} was not linked"
                );
                assert_eq!(
                    fs::read_link(&p).unwrap(),
                    shared_root(base, Surface::Codex).join("state_5.sqlite")
                );
            }

            // The rename made in slot 14 is now visible by resolving THROUGH
            // slot 11's (now-symlinked) path — the owner symptom is fixed.
            assert_eq!(
                thread_name(&bin, &home11.join("state_5.sqlite"), "01a0d8a0-thread"),
                "py"
            );
        }

        #[test]
        fn name_conflict_tie_break_prefers_newer_updated_at_ms_over_either_non_empty_name() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            // BOTH sides have a non-empty name; the newer timestamp must win
            // regardless of which side has it.
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "py",
                    updated_at_ms: 300,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "rust",
                    updated_at_ms: 100,
                }],
                true,
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            assert_eq!(
                thread_name(&bin, &home11.join("state_5.sqlite"), "t1"),
                "py",
                "the newer (updated_at_ms=300) row must win even though the \
                 older row also has a non-empty name"
            );
        }

        /// C-F7 (i): `name` gets its own CASE — an empty-but-newer source
        /// must never erase a destination's real name, even though every
        /// OTHER column still follows `updated_at_ms` and DOES take the
        /// newer source's value.
        #[test]
        fn empty_but_newer_source_name_never_erases_a_destination_name() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 100,
                }],
                true,
            );
            // Newer, but its name is EMPTY.
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 999,
                }],
                true,
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                thread_name(&bin, &merged, "t1"),
                "orig",
                "an empty-but-newer source name must never erase a real destination name"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "updated_at_ms"),
                "999",
                "every OTHER column still follows updated_at_ms and takes the newer value"
            );
        }

        /// C-F7 (ii): dest's `name` is EMPTY and source's is non-empty and
        /// OLDER — so `name` itself is correctly adopted from source (an
        /// empty destination name always yields, per its own rule), but
        /// every OTHER column (here: `updated_at_ms` and `cwd`, standing in
        /// for a rollout path) must NOT follow along — an older source must
        /// never roll back a newer destination's other fields just because
        /// its name got adopted. The old (pre-C-F7) uniform CASE rolled ALL
        /// columns back together whenever the dest-empty branch fired.
        #[test]
        fn older_source_never_rolls_back_a_newer_destinations_other_columns() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 500,
                }],
                true,
            );
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "UPDATE threads SET cwd='/newer/work' WHERE id='t1';",
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "srcname",
                    updated_at_ms: 100,
                }],
                true,
            );
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "UPDATE threads SET cwd='/older/work' WHERE id='t1';",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                thread_name(&bin, &merged, "t1"),
                "srcname",
                "an empty destination name is correctly adopted from source"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "updated_at_ms"),
                "500",
                "an older source must not roll back the destination's updated_at_ms"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "cwd"),
                "/newer/work",
                "an older source must not roll back the destination's cwd (rollout path)"
            );
        }

        /// S-L3: `cwd` (standing in for any per-account/per-environment
        /// column — `sandbox_policy`, `approval_policy`, `model`) must
        /// NEVER be overwritten by a merge, even when the SOURCE is the
        /// row a timestamp comparison would otherwise prefer. This is the
        /// genuinely discriminating case the two tests above are not: here
        /// source is NEWER, so a timestamp-only rule (the pre-allowlist
        /// behaviour) WOULD adopt source's cwd — the allowlist must refuse
        /// that regardless.
        #[test]
        fn a_newer_sources_cwd_never_overwrites_the_destinations_cwd() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 100,
                }],
                true,
            );
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "UPDATE threads SET cwd='/account-11/work' WHERE id='t1';",
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "renamed-elsewhere",
                    updated_at_ms: 999,
                }],
                true,
            );
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "UPDATE threads SET cwd='/account-14/work' WHERE id='t1';",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                thread_name(&bin, &merged, "t1"),
                "renamed-elsewhere",
                "name IS allowlisted and DOES follow the newer source, as before"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "updated_at_ms"),
                "999",
                "updated_at_ms IS allowlisted and DOES follow the newer source"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "cwd"),
                "/account-11/work",
                "cwd is NOT allowlisted -- it must stay the destination's own value \
                 even though the source row is newer"
            );
        }

        /// Holds a read transaction open on `db` so a concurrent writer's
        /// connection close does NOT trigger sqlite3's automatic
        /// checkpoint-on-last-connection-close — the only way to leave
        /// real, un-checkpointed content in `-wal` on disk with no process
        /// still attached to it. `BEGIN` alone does not acquire the read
        /// snapshot; the `SELECT` after it does.
        ///
        /// Killed (never gracefully closed) by the caller once the WAL
        /// content it protected has been captured, so ending the hold never
        /// itself triggers the checkpoint it was suppressing.
        struct WalHolder(std::process::Child);

        impl WalHolder {
            fn open(bin: &Path, db: &Path) -> Self {
                let mut child = Command::new(bin)
                    .args(["-batch"])
                    .arg(db)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn wal-holder sqlite3");
                child
                    .stdin
                    .as_mut()
                    .expect("stdin was piped")
                    .write_all(b"BEGIN;\nSELECT count(*) FROM threads;\n")
                    .expect("write to wal-holder stdin");
                // Give the holder time to actually execute those statements
                // (and thus acquire its read snapshot) before the caller
                // proceeds to write.
                std::thread::sleep(std::time::Duration::from_millis(200));
                Self(child)
            }
        }

        impl Drop for WalHolder {
            fn drop(&mut self) {
                // SIGKILL, not a graceful close: closing gracefully would
                // itself be the checkpoint-on-close this fixture exists to
                // avoid triggering ahead of the assertions.
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        /// A rename codex-cli has committed but not yet checkpointed lives
        /// ONLY in the `-wal` sidecar — the main `.sqlite` file still shows
        /// the pre-rename value. The merge must include it: every real
        /// per-slot copy is read either after a checkpoint on a COPY (what
        /// this module does), or by opening the original read-only with its
        /// WAL present — never by reading just the main file.
        #[test]
        fn merge_includes_a_rename_still_only_in_the_wal_not_yet_checkpointed() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 1,
                }],
                true,
            );

            let path11 = home11.join("state_5.sqlite");
            sh(&bin, &path11, "PRAGMA journal_mode=WAL;");

            // Hold a read transaction open so the WRITE below lands in the
            // WAL and neither this writer's own close nor the holder's
            // eventual (killed, not closed) end checkpoints it away.
            let holder = WalHolder::open(&bin, &path11);
            sh(
                &bin,
                &path11,
                "UPDATE threads SET name='py', updated_at_ms=200 WHERE id='t1';",
            );

            let wal_path = PathBuf::from(format!("{}-wal", path11.display()));
            assert!(
                wal_path.exists() && fs::metadata(&wal_path).unwrap().len() > 0,
                "fixture must leave real content in the WAL, or this test proves nothing"
            );

            // Fixture sanity: the MAIN FILE'S BYTES ALONE (copied without
            // the `-wal` sidecar) must NOT show the rename — otherwise the
            // write was already checkpointed and this test is vacuous.
            let main_file_only = base.join("main-file-only-sanity-check.sqlite");
            fs::copy(&path11, &main_file_only).unwrap();
            assert_eq!(
                thread_name(&bin, &main_file_only, "t1"),
                "",
                "fixture sanity: the rename must be invisible from the main \
                 file alone, or it was already checkpointed"
            );

            // The WAL's bytes are now on disk; the holder's own end (killed
            // below, in Drop) can no longer erase them by checkpointing —
            // capture is what mattered, not the holder staying alive.
            drop(holder);

            let report = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert!(
                matches!(
                    report.databases[0].outcome,
                    SqliteDbOutcome::Merged { slots_merged: 2 }
                ),
                "{:?}",
                report.databases[0].outcome
            );

            assert_eq!(
                thread_name(&bin, &home11.join("state_5.sqlite"), "t1"),
                "py",
                "a rename still sitting only in the WAL must survive the merge"
            );
        }

        /// `thread_history_1.sqlite` (a projection replayed from the shared
        /// rollout) is deliberately NOT merged or truncated — see the
        /// module doc. It must classify as `KeptPerSlot`, exactly like
        /// goals/memories/queue/logs, and its rows must survive completely
        /// untouched, including on a slot whose projection is already
        /// populated (the case a truncate-and-rebuild strategy would have
        /// put at risk).
        #[test]
        fn thread_history_projection_is_kept_per_slot_never_merged_or_truncated() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_other_db(&bin, &home11.join("thread_history_1.sqlite"));
            // A second slot's copy too, to prove this stays per-slot even
            // in the presence of a sibling that could otherwise be merged.
            create_other_db(&bin, &home14.join("thread_history_1.sqlite"));

            let report = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            let db = report
                .databases
                .iter()
                .find(|d| d.basename == "thread_history_1.sqlite")
                .unwrap();
            assert_eq!(db.role, SqliteDbRole::KeptPerSlot);
            assert!(
                matches!(db.outcome, SqliteDbOutcome::KeptPerSlot { slots: 2 }),
                "{:?}",
                db.outcome
            );

            for home in [&home11, &home14] {
                let p = home.join("thread_history_1.sqlite");
                assert!(
                    !p.symlink_metadata().unwrap().file_type().is_symlink(),
                    "a kept-per-slot database must not be linked"
                );
                assert_eq!(
                    row_count(&bin, &p, "logs"),
                    1,
                    "content must be completely untouched"
                );
            }
            assert!(!shared_root(base, Surface::Codex)
                .join("thread_history_1.sqlite")
                .exists());
        }

        #[test]
        fn live_writer_refuses_and_leaves_originals_untouched() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 1,
                }],
                true,
            );

            // A codex-shaped handle dir with a `.live-pid` naming THIS
            // process (guaranteed alive for the duration of the test).
            let term = base.join("term-999");
            fs::create_dir_all(&term).unwrap();
            fs::write(term.join("auth.json"), b"x").unwrap();
            fs::write(term.join("config.toml"), b"x").unwrap();
            fs::write(term.join(".live-pid"), std::process::id().to_string()).unwrap();

            let err = codex_sqlite::share_codex_sqlite(base, false, false).unwrap_err();
            assert!(matches!(err, ShareError::LiveWriters { .. }), "{err:?}");
            assert!(
                !home
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the guard must refuse BEFORE any mutation"
            );
        }

        #[test]
        fn migrations_mismatch_refuses_and_leaves_originals_untouched() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "b",
                    updated_at_ms: 2,
                }],
                false, // no _sqlx_migrations table at all — a differing schema state
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteMigrationsMismatch { .. }),
                "{err:?}"
            );
            assert!(
                !home11
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "verification must run before any mutation"
            );
            assert!(!shared_root(base, Surface::Codex)
                .join("state_5.sqlite")
                .exists());
        }

        /// C-F6b: `share_codex_sqlite` verifies EVERY basename before
        /// mutating ANY of them. `state_5.sqlite` (a perfectly valid,
        /// mergeable pair) sorts before `state_9.sqlite` (a migrations
        /// mismatch); the mismatch on the LATER basename must abort before
        /// the earlier, individually-valid basename is merged, backed up,
        /// or linked.
        #[test]
        fn a_later_basename_mismatch_leaves_an_earlier_valid_basename_unmutated() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "py",
                    updated_at_ms: 2,
                }],
                true,
            );

            create_state_db(
                &bin,
                &home11.join("state_9.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_9.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "b",
                    updated_at_ms: 2,
                }],
                false, // no _sqlx_migrations table — a differing schema state
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteMigrationsMismatch { .. }),
                "{err:?}"
            );

            for home in [&home11, &home14] {
                for basename in ["state_5.sqlite", "state_9.sqlite"] {
                    assert!(
                        !home
                            .join(basename)
                            .symlink_metadata()
                            .unwrap()
                            .file_type()
                            .is_symlink(),
                        "an earlier, individually-valid basename must not be \
                         mutated when a LATER basename fails verification: {basename}"
                    );
                }
            }
            assert!(!shared_root(base, Surface::Codex)
                .join("state_5.sqlite")
                .exists());
            assert!(!shared_root(base, Surface::Codex)
                .join("state_9.sqlite")
                .exists());
        }

        /// C-F6: a re-run against an ESTABLISHED shared DB must compare its
        /// migration set too, not just the incoming slot copies against
        /// each other. A new slot whose schema differs from the shared DB
        /// (here: no `_sqlx_migrations` table at all) must refuse, and the
        /// shared DB's bytes must be provably untouched — compared by hash,
        /// not merely "still present".
        #[test]
        fn new_slot_schema_mismatch_against_existing_shared_db_refuses_and_leaves_shared_db_unchanged(
        ) {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();

            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );
            // First run establishes the shared DB from slot 11 alone.
            let first = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert!(matches!(
                first.databases[0].outcome,
                SqliteDbOutcome::Merged { slots_merged: 1 }
            ));

            let shared_path = shared_root(base, Surface::Codex).join("state_5.sqlite");
            let shared_before = fs::read(&shared_path).unwrap();

            // A brand-new slot, never before seen, with a schema that
            // disagrees with the shared DB (no `_sqlx_migrations` table).
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 5,
                }],
                false,
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteMigrationsMismatch { .. }),
                "{err:?}"
            );
            assert_eq!(
                fs::read(&shared_path).unwrap(),
                shared_before,
                "the shared DB must be byte-for-byte unchanged after a refusal"
            );
            assert!(
                !home14
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the new slot must not be mutated on a refusal"
            );
        }

        #[test]
        fn corrupt_database_refuses_and_leaves_everything_untouched() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            let many_rows: Vec<ThreadRow> = (0..500)
                .map(|i| ThreadRow {
                    id: Box::leak(format!("t{i}").into_boxed_str()),
                    name: "",
                    updated_at_ms: i,
                })
                .collect();
            create_state_db(&bin, &home11.join("state_5.sqlite"), &many_rows, true);
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "clean",
                    updated_at_ms: 1,
                }],
                true,
            );

            // Corrupt slot 11's copy by chopping it in half: page 1 (schema)
            // stays intact, later b-tree pages go missing.
            let corrupt_path = home11.join("state_5.sqlite");
            let bytes = fs::read(&corrupt_path).unwrap();
            assert!(bytes.len() > 4096, "fixture must span multiple pages");
            fs::write(&corrupt_path, &bytes[..bytes.len() / 2]).unwrap();

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(
                    err,
                    ShareError::SqliteIntegrityCheckFailed { .. }
                        | ShareError::SqliteCommandFailed { .. }
                ),
                "expected a refusal naming the corrupt database, got {err:?}"
            );
            assert!(
                !home14
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the clean slot must not be mutated when a SIBLING slot fails verification"
            );
            assert!(!shared_root(base, Surface::Codex)
                .join("state_5.sqlite")
                .exists());
        }

        #[test]
        fn backups_are_present_with_original_content_after_a_real_merge() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "original",
                    updated_at_ms: 1,
                }],
                true,
            );
            let original_bytes = fs::read(home11.join("state_5.sqlite")).unwrap();

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let backups: Vec<_> = fs::read_dir(&home11)
                .unwrap()
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("state_5.sqlite.pre-share-")
                })
                .collect();
            assert_eq!(backups.len(), 1, "{backups:?}");
            assert_eq!(fs::read(backups[0].path()).unwrap(), original_bytes);
        }

        #[test]
        fn idempotent_rerun_does_not_re_merge_or_duplicate_backups() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "py",
                    updated_at_ms: 2,
                }],
                true,
            );

            let first = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert!(matches!(
                first.databases[0].outcome,
                SqliteDbOutcome::Merged { slots_merged: 2 }
            ));

            let second = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert_eq!(second.databases.len(), 1);
            assert!(
                matches!(second.databases[0].outcome, SqliteDbOutcome::AlreadyShared),
                "{:?}",
                second.databases[0].outcome
            );

            let backups: Vec<_> = fs::read_dir(&home11)
                .unwrap()
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("state_5.sqlite.pre-share-")
                })
                .collect();
            assert_eq!(
                backups.len(),
                1,
                "a second run must not create a second backup: {backups:?}"
            );
            assert_eq!(
                thread_name(&bin, &home11.join("state_5.sqlite"), "t1"),
                "py",
                "second run must not disturb the already-merged content"
            );
        }

        #[test]
        fn a_database_with_no_recognised_role_stays_per_slot_untouched() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_other_db(&bin, &home11.join("logs_2.sqlite"));

            let report = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert_eq!(report.databases.len(), 1);
            let db = &report.databases[0];
            assert_eq!(db.role, SqliteDbRole::KeptPerSlot);
            assert!(matches!(
                db.outcome,
                SqliteDbOutcome::KeptPerSlot { slots: 1 }
            ));

            let p = home11.join("logs_2.sqlite");
            assert!(
                !p.symlink_metadata().unwrap().file_type().is_symlink(),
                "a per-slot database must not be linked"
            );
            assert_eq!(row_count(&bin, &p, "logs"), 1, "content must be untouched");
        }

        #[test]
        fn dry_run_reads_but_never_mutates() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "py",
                    updated_at_ms: 2,
                }],
                true,
            );

            let report: CodexSqliteReport =
                codex_sqlite::share_codex_sqlite(base, true, false).unwrap();
            assert!(matches!(
                report.databases[0].outcome,
                SqliteDbOutcome::Merged { slots_merged: 2 }
            ));

            for home in [&home11, &home14] {
                assert!(
                    !home
                        .join("state_5.sqlite")
                        .symlink_metadata()
                        .unwrap()
                        .file_type()
                        .is_symlink(),
                    "dry-run must never mutate"
                );
            }
            assert!(!shared_root(base, Surface::Codex)
                .join("state_5.sqlite")
                .exists());
        }

        // ── S-F8: identifier + ATTACH-path safety ─────────────────────────

        /// A `threads` column name outside the identifier allowlist (here:
        /// containing a `;`) must refuse the merge rather than interpolate
        /// it into SQL — before any mutation.
        #[test]
        fn threads_column_name_outside_the_identifier_allowlist_refuses_the_merge() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            fs::create_dir_all(&home11).unwrap();
            fs::create_dir_all(&home14).unwrap();

            for home in [&home11, &home14] {
                let path = home.join("state_5.sqlite");
                sh(
                    &bin,
                    &path,
                    "CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT, name TEXT, \
                     updated_at TEXT, updated_at_ms INTEGER, \"bad;name\" TEXT); \
                     CREATE TABLE _sqlx_migrations (version INTEGER PRIMARY KEY); \
                     INSERT INTO _sqlx_migrations VALUES (1);",
                );
                sh(
                    &bin,
                    &path,
                    "INSERT INTO threads VALUES ('t1', 'x', 'n', 'ts', 1, 'ok');",
                );
            }

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteUnsafeColumnName { .. }),
                "{err:?}"
            );
            assert!(
                !home11
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "verification must refuse before any mutation"
            );
        }

        /// S-L3: a `threads`-role database carrying a `view` or `trigger`
        /// in `sqlite_master` must refuse the merge, before any mutation —
        /// an ordinary codex-cli database never has either, so one is
        /// evidence of a hand-modified or malicious file.
        #[test]
        fn a_view_in_sqlite_master_refuses_the_merge_before_any_mutation() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            for home in [&home11, &home14] {
                create_state_db(
                    &bin,
                    &home.join("state_5.sqlite"),
                    &[ThreadRow {
                        id: "t1",
                        name: "orig",
                        updated_at_ms: 1,
                    }],
                    true,
                );
            }
            // Only slot 11's copy carries the planted view -- either real
            // copy reaching the check must be enough to refuse.
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "CREATE VIEW evil_view AS SELECT * FROM threads;",
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteUntrustedSchemaObject { .. }),
                "{err:?}"
            );
            assert!(
                !home11
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "verification must refuse before any mutation"
            );
            assert!(
                !home14
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the OTHER slot must be untouched too"
            );
        }

        /// Restores `HOME` on drop (including on an unwinding panic), so a
        /// failing assertion cannot leak the override into the rest of the
        /// suite — the same unwind-safety guarantee
        /// `platform::test_env::with_secret_backend` gives `CSQ_SECRET_BACKEND`.
        struct HomeRestore(Option<std::ffi::OsString>);
        impl Drop for HomeRestore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }

        /// S-L6: `SqliteUntrustedSchemaObject`'s `path` must not leak the
        /// operator's full `$HOME`-rooted host path — same posture as every
        /// other error this module raises from sqlite3 output
        /// (`run_sqlite3_with`'s `SqliteCommandFailed`). `HOME` is pinned to
        /// the tempdir root so the fixture's own paths are genuinely
        /// `$HOME`-rooted, which `redact_path` requires to have anything to
        /// strip.
        #[test]
        fn untrusted_schema_object_error_redacts_the_path() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let _env_guard = crate::platform::test_env::lock();
            let t = TempDir::new().unwrap();
            let _restore = HomeRestore(std::env::var_os("HOME"));
            std::env::set_var("HOME", t.path());
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            for home in [&home11, &home14] {
                create_state_db(
                    &bin,
                    &home.join("state_5.sqlite"),
                    &[ThreadRow {
                        id: "t1",
                        name: "orig",
                        updated_at_ms: 1,
                    }],
                    true,
                );
            }
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "CREATE VIEW evil_view AS SELECT * FROM threads;",
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteUntrustedSchemaObject { .. }),
                "{err:?}"
            );
            let msg = err.to_string();
            let raw_path = home11.join("state_5.sqlite").display().to_string();
            assert!(
                !msg.contains(&raw_path),
                "raw $HOME-rooted path leaked into the error: {msg}"
            );
            assert!(
                msg.contains('~'),
                "path should have been redacted to a `~`-relative form: {msg}"
            );
        }

        /// A path containing a newline must be refused before it is
        /// interpolated into an `ATTACH DATABASE` statement.
        #[test]
        fn attach_path_with_newline_is_refused() {
            let path = PathBuf::from("/tmp/evil\nrm -rf /.sqlite");
            let err = codex_sqlite::ensure_safe_attach_path(&path).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteUnsafeAttachPath { .. }),
                "{err:?}"
            );
        }

        /// A clean path (no newline/CR/NUL) passes the ATTACH-path check.
        #[test]
        fn attach_path_without_control_bytes_is_accepted() {
            let path = PathBuf::from("/tmp/state_5.sqlite.merge-src");
            assert!(codex_sqlite::ensure_safe_attach_path(&path).is_ok());
        }

        /// Smoke test: whether or not this host's `sqlite3` supports
        /// `-safe` (added conditionally to every read-only invocation), a
        /// plain dry-run — which exercises `integrity_check` and
        /// `migrations_signature`, both read-only — must still succeed
        /// cleanly.
        #[test]
        fn safe_flag_probe_does_not_break_a_plain_readonly_query() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "x",
                    updated_at_ms: 1,
                }],
                true,
            );

            codex_sqlite::share_codex_sqlite(base, true, true).unwrap();
        }

        // ── S-F9: rollback + leftover-scratch-file safety ─────────────────

        /// A `.merge-src` or `.pre-share-<epoch>` scratch artifact left over
        /// from an earlier failed run — even one contrived to end in the
        /// bare `.sqlite` suffix — must never be picked up as a basename.
        #[test]
        fn a_basename_containing_the_scratch_pattern_is_excluded() {
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            fs::create_dir_all(&home11).unwrap();
            fs::write(home11.join("weird.merge-src.sqlite"), b"not a real db").unwrap();
            fs::write(home11.join("weird.pre-share-123.sqlite"), b"not a real db").unwrap();
            fs::write(home11.join("state_5.sqlite"), b"also not a real db").unwrap();

            let names = codex_sqlite::list_sqlite_basenames(&home11);
            assert_eq!(
                names,
                vec!["state_5.sqlite".to_string()],
                "the scratch-pattern basenames must be excluded"
            );
        }

        /// If creating or verifying the symlink fails AFTER the original
        /// has already been renamed to its `.pre-share-<epoch>` backup, the
        /// original must be restored — the slot must never be left with
        /// neither a real file nor a working symlink — and its `.merge-src`
        /// scratch copy must not remain.
        #[test]
        fn symlink_failure_restores_the_original_and_leaves_no_merge_src() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );
            let original_bytes = fs::read(home11.join("state_5.sqlite")).unwrap();

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![(slot_num(11), home11.clone())];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap();

            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                |_target, _link| {
                    Err(std::io::Error::other(
                        "TEST INPUT: injected symlink failure",
                    ))
                },
            )
            .unwrap_err();
            assert!(matches!(err, ShareError::Io { .. }), "{err:?}");

            let p = home11.join("state_5.sqlite");
            assert!(
                !p.symlink_metadata().unwrap().file_type().is_symlink(),
                "the original must be restored, not left as a broken link"
            );
            assert_eq!(
                fs::read(&p).unwrap(),
                original_bytes,
                "restored content must match the pre-share original"
            );

            let leftovers: Vec<_> = fs::read_dir(&home11)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".merge-src"))
                .collect();
            assert!(
                leftovers.is_empty(),
                "no .merge-src scratch copy may remain: {leftovers:?}"
            );
        }

        // ── FM-10: re-check live writers + fingerprint before EACH rename ──

        /// A db that changes (a codex-cli session starts writing to it)
        /// between its work-copy snapshot and its rename must refuse — and
        /// leave every original (including a SIBLING slot already
        /// renamed+linked earlier in the same basename's loop) exactly as
        /// it was.
        #[test]
        fn a_db_that_changes_between_snapshot_and_rename_refuses_and_rolls_back() {
            // Hermetic: `apply_basename_plan_with`'s mid-loop recheck calls
            // the REAL live-writer guard (force=false) for BOTH slot 11
            // and slot 14 before this test's own fingerprint-mismatch
            // check is ever reached — force the host-wide process scan
            // empty so a real `codex` process on the host cannot pre-empt
            // the expected `SqliteChangedDuringMerge` with `LiveWriters`
            // (`test-hermeticity.md`).
            let _procs_guard = force_list_running_processes(vec![]);
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 1,
                }],
                true,
            );
            let original_11 = fs::read(home11.join("state_5.sqlite")).unwrap();

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![
                (slot_num(11), home11.clone()),
                (slot_num(14), home14.clone()),
            ];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap();

            let home11_path = home11.join("state_5.sqlite");
            let home14_path = home14.join("state_5.sqlite");
            let home14_path_for_closure = home14_path.clone();
            // Slot 11 is processed first (sorted). The instant its own
            // symlink is created, simulate a codex-cli session opening
            // slot 14's db for writing — BEFORE slot 14's own pre-rename
            // recheck runs.
            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                false,
                move |target, link| {
                    let r = crate::session::isolation::create_symlink_pub(target, link);
                    if link == home11_path.as_path() {
                        fs::write(&home14_path_for_closure, b"TEST INPUT: mutated mid-merge")
                            .unwrap();
                    }
                    r
                },
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );

            // Slot 11 was rolled back: no symlink, original bytes restored.
            assert!(
                !home11
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "slot 11 must be rolled back when a SIBLING slot changes mid-merge"
            );
            assert_eq!(
                fs::read(home11.join("state_5.sqlite")).unwrap(),
                original_11
            );

            // Slot 14 was never renamed; it still holds the injected
            // mid-merge write, not the merge's output.
            assert!(!home14_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(
                fs::read(&home14_path).unwrap(),
                b"TEST INPUT: mutated mid-merge"
            );
        }

        // ── FM-11: first-creation of the shared DB never writes in place ──

        /// A write failure while building the FIRST shared DB for a
        /// basename (simulated here by poisoning the exact scratch path
        /// FM-11 builds it at, the same shape a disk-full error takes)
        /// must never leave a truncated file at `shared_path`, and a later
        /// re-run — once the failure clears — must succeed cleanly.
        #[test]
        fn failed_first_shared_creation_leaves_no_shared_path_and_reruns_clean() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let shared_path = shared_dir.join("state_5.sqlite");
            let tmp_shared = PathBuf::from(format!("{}.new-share", shared_path.display()));
            // Poison the exact scratch path: a directory where FM-11
            // expects to write a file makes the first `fs::copy` into it
            // fail, the same shape a disk-full error takes.
            fs::create_dir_all(&tmp_shared).unwrap();

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(matches!(err, ShareError::Io { .. }), "{err:?}");
            assert!(
                !shared_path.exists(),
                "a failed first-creation must never leave a truncated shared_path"
            );

            fs::remove_dir_all(&tmp_shared).unwrap();
            let report = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert!(matches!(
                report.databases[0].outcome,
                SqliteDbOutcome::Merged { slots_merged: 1 }
            ));
            assert_eq!(thread_name(&bin, &shared_path, "t1"), "orig");
        }

        // ── FM-12(A): a stranded .pre-share backup is recovered on replan ──

        /// A crash between the backup rename and the symlink step leaves
        /// NEITHER a real file NOR a symlink at the basename path — only
        /// the `.pre-share-<epoch>` backup. A fresh plan must restore it
        /// and re-enter the merge, not report `AlreadyShared`.
        #[test]
        fn crash_between_backup_and_symlink_is_recovered_by_a_fresh_plan() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );
            let original_bytes = fs::read(home11.join("state_5.sqlite")).unwrap();

            let p = home11.join("state_5.sqlite");
            let backup = home11.join("state_5.sqlite.pre-share-1000");
            fs::rename(&p, &backup).unwrap();
            assert!(p.symlink_metadata().is_err());

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![(slot_num(11), home11.clone())];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap();
            assert!(
                matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }),
                "a stranded .pre-share backup must be restored into the merge, not treated as AlreadyShared"
            );
            assert!(
                p.exists(),
                "the backup must be restored to the basename path by planning"
            );
            assert_eq!(fs::read(&p).unwrap(), original_bytes);

            let report = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap();
            assert!(matches!(
                report.outcome,
                SqliteDbOutcome::Merged { slots_merged: 1 }
            ));
            assert!(p.symlink_metadata().unwrap().file_type().is_symlink());
        }

        // ── C-R4-13 / S-F2: dry-run never mutates the pre-share repair ────

        /// `--dry-run` must NEVER rename a stranded `.pre-share-<epoch>`
        /// backup into place — only report what a real run would repair.
        #[test]
        fn dry_run_never_restores_a_stranded_pre_share_backup() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );

            let p = home11.join("state_5.sqlite");
            let backup = home11.join("state_5.sqlite.pre-share-1000");
            fs::rename(&p, &backup).unwrap();
            assert!(p.symlink_metadata().is_err());

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![(slot_num(11), home11.clone())];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                true, // dry_run
            )
            .unwrap();
            assert!(
                matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }),
                "dry-run must still PLAN the repair as a merge, not report AlreadyShared"
            );
            assert!(
                p.symlink_metadata().is_err(),
                "dry-run must never rename the backup into place"
            );
            assert!(
                backup.exists(),
                "the backup itself must be left exactly where it was"
            );

            // The full-report entry point must agree.
            let report = codex_sqlite::share_codex_sqlite(base, true, true).unwrap();
            assert!(matches!(
                report.databases[0].outcome,
                SqliteDbOutcome::Merged { slots_merged: 1 }
            ));
            assert!(
                p.symlink_metadata().is_err(),
                "dry-run via share_codex_sqlite must also never mutate"
            );
        }

        /// A `.pre-share-<epoch>`-named entry that is actually a SYMLINK
        /// (planted, pointing outside the slot's home) must be refused
        /// rather than restored — `verify_backup_is_regular_file` uses
        /// `symlink_metadata`, never `metadata`, so it does not follow the
        /// link to judge what it points at.
        #[test]
        #[cfg(unix)]
        fn a_symlinked_backup_masquerade_is_refused_not_restored() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            fs::create_dir_all(&home11).unwrap();

            // Something OUTSIDE the slot's home the symlink points at —
            // must never be read as if it were a real backup.
            let elsewhere = base.join("elsewhere.sqlite");
            create_state_db(
                &bin,
                &elsewhere,
                &[ThreadRow {
                    id: "t1",
                    name: "planted",
                    updated_at_ms: 1,
                }],
                true,
            );
            let backup = home11.join("state_5.sqlite.pre-share-1000");
            std::os::unix::fs::symlink(&elsewhere, &backup).unwrap();

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![(slot_num(11), home11.clone())];
            let err = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::UnexpectedShapeDynamic { .. }),
                "{err:?}"
            );
            assert!(
                home11.join("state_5.sqlite").symlink_metadata().is_err(),
                "a symlinked backup masquerade must not be restored into the basename path"
            );
        }

        // ── C-R4-14: discovery also finds a stranded/orphaned backup ──────

        /// A basename whose ONLY surviving evidence anywhere is a lone
        /// `.pre-share-<epoch>` backup (no real file, no symlink, no OTHER
        /// slot, no shared DB) must still be discovered and repaired by a
        /// full `share_codex_sqlite` run — not silently invisible to
        /// discovery forever, leaving codex-cli to create a fresh,
        /// diverging database against it.
        #[test]
        fn a_lone_stranded_backup_with_no_other_evidence_is_discovered_and_repaired() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );
            let original_bytes = fs::read(home11.join("state_5.sqlite")).unwrap();

            let p = home11.join("state_5.sqlite");
            let backup = home11.join("state_5.sqlite.pre-share-1000");
            fs::rename(&p, &backup).unwrap();
            assert!(p.symlink_metadata().is_err());

            let names = codex_sqlite::list_sqlite_basenames(&home11);
            assert_eq!(
                names,
                vec!["state_5.sqlite".to_string()],
                "a lone stranded backup must still be discovered as its basename"
            );

            let report = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert_eq!(report.databases.len(), 1, "{:?}", report.databases);
            assert!(matches!(
                report.databases[0].outcome,
                SqliteDbOutcome::Merged { slots_merged: 1 }
            ));
            assert!(p.symlink_metadata().unwrap().file_type().is_symlink());
            assert_eq!(fs::read(&p).unwrap(), original_bytes);
        }

        /// A basename present ONLY in the shared store (every slot that
        /// once held it has since been removed, e.g. an account deletion
        /// after migrating) must still surface in `share_codex_sqlite`'s
        /// report — the shared store itself is scanned for basenames, not
        /// only each slot's home directory.
        #[test]
        fn a_basename_only_in_the_shared_dir_is_still_discovered() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let shared_dir = shared_root(base, Surface::Codex);
            create_state_db(
                &bin,
                &shared_dir.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orphaned-shared",
                    updated_at_ms: 1,
                }],
                true,
            );

            let report = codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            assert_eq!(report.databases.len(), 1, "{:?}", report.databases);
            assert_eq!(report.databases[0].basename, "state_5.sqlite");
            assert!(matches!(
                report.databases[0].outcome,
                SqliteDbOutcome::AlreadyShared
            ));
        }

        // ── C-R4-11: a write during the copy phase refuses before any rename ──

        /// A write that lands on `path` strictly between the pre-copy and
        /// post-copy fingerprint samples — `work_copy` was already
        /// produced from the OLD bytes by then — must refuse before any
        /// rename, not only at the LATER pre-rename recheck (which, before
        /// this fix, was the only place such a change was ever compared
        /// against: too late, since the stale `work_copy` had already been
        /// folded into the merge by then).
        #[test]
        fn a_write_landing_during_the_copy_phase_refuses_before_any_rename() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![(slot_num(11), home11.clone())];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap();

            let target = home11.join("state_5.sqlite");
            codex_sqlite::set_test_after_copy_hook(move |p: &Path| {
                if p == target {
                    fs::write(p, b"TEST INPUT: mutated during the copy window").unwrap();
                }
            });
            let result = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            );
            codex_sqlite::clear_test_after_copy_hook();

            let err = result.unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );

            let p = home11.join("state_5.sqlite");
            assert!(
                !p.symlink_metadata().unwrap().file_type().is_symlink(),
                "no rename must have happened — the refusal fires before the rename phase"
            );
            assert_eq!(
                fs::read(&p).unwrap(),
                b"TEST INPUT: mutated during the copy window",
                "the file itself must be left exactly as the injected write left it"
            );
        }

        // ── C-R4-12 / S-F6: every early-return in the rename loop rolls back ──

        /// A live writer appearing AFTER slot 11's own rename+link — but
        /// before slot 14's iteration re-checks — must roll back slot 11,
        /// not merely propagate the `LiveWriters` error. Before this fix,
        /// `ensure_no_live_writers(..)?` inside the loop returned via a
        /// bare `?`, skipping the rollback of any sibling entry already
        /// renamed+linked earlier in the same loop.
        #[test]
        fn live_writer_detected_mid_loop_rolls_back_already_renamed_entries() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 1,
                }],
                true,
            );
            let original_11 = fs::read(home11.join("state_5.sqlite")).unwrap();

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![
                (slot_num(11), home11.clone()),
                (slot_num(14), home14.clone()),
            ];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap();

            let home11_path = home11.join("state_5.sqlite");
            let base_for_closure = base.to_path_buf();
            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                false,
                move |target, link| {
                    let r = crate::session::isolation::create_symlink_pub(target, link);
                    if link == home11_path.as_path() {
                        // Simulate a codex-cli session starting right
                        // after slot 11's own symlink lands, before slot
                        // 14's iteration re-checks live writers.
                        let term = base_for_closure.join("term-999");
                        fs::create_dir_all(&term).unwrap();
                        fs::write(term.join("auth.json"), b"x").unwrap();
                        fs::write(term.join("config.toml"), b"x").unwrap();
                        fs::write(term.join(".live-pid"), std::process::id().to_string()).unwrap();
                    }
                    r
                },
            )
            .unwrap_err();
            assert!(matches!(err, ShareError::LiveWriters { .. }), "{err:?}");

            assert!(
                !home11
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "slot 11 must be rolled back when live-writer detection trips for a LATER slot"
            );
            assert_eq!(
                fs::read(home11.join("state_5.sqlite")).unwrap(),
                original_11
            );
            assert!(!home14
                .join("state_5.sqlite")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
        }

        /// A rename-to-backup FAILURE for a LATER slot (simulated: its
        /// home directory is made read-only right after the FIRST slot's
        /// own rename+link succeeds) must roll back the earlier slot, not
        /// merely propagate the `Io` error. Before this fix,
        /// `rename_db_with_sidecars(&entry.path, &backup)?` inside the loop
        /// returned via a bare `?`, skipping the rollback entirely.
        #[test]
        #[cfg(unix)]
        fn rename_to_backup_failure_for_a_later_slot_rolls_back_earlier_slots() {
            use std::os::unix::fs::PermissionsExt;

            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                true,
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 1,
                }],
                true,
            );
            let original_11 = fs::read(home11.join("state_5.sqlite")).unwrap();

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![
                (slot_num(11), home11.clone()),
                (slot_num(14), home14.clone()),
            ];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap();

            let home11_path = home11.join("state_5.sqlite");
            let home11_path_for_closure = home11_path.clone();
            let home14_for_closure = home14.clone();
            // force=true: this test exercises the RENAME failing, not the
            // live-writer guard.
            let result = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                move |target, link| {
                    let r = crate::session::isolation::create_symlink_pub(target, link);
                    if link == home11_path_for_closure.as_path() {
                        let mut perms = fs::metadata(&home14_for_closure).unwrap().permissions();
                        perms.set_mode(0o555);
                        fs::set_permissions(&home14_for_closure, perms).unwrap();
                    }
                    r
                },
            );

            // Restore permissions unconditionally before asserting, so a
            // failed assertion below still leaves the TempDir removable.
            let mut perms = fs::metadata(&home14).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&home14, perms).unwrap();

            let err = result.unwrap_err();
            assert!(matches!(err, ShareError::Io { .. }), "{err:?}");

            assert!(
                !home11_path
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "slot 11 must be rolled back when a LATER slot's rename-to-backup fails"
            );
            assert_eq!(fs::read(&home11_path).unwrap(), original_11);
        }

        /// [`rename_db_with_sidecars`]'s FM-12(B) rollback: a sidecar
        /// rename failure must undo the main rename (and any sidecar
        /// already moved before it) so `src` and `dst` end up exactly as
        /// they started.
        #[test]
        fn sidecar_rename_failure_undoes_the_main_rename() {
            let t = TempDir::new().unwrap();
            let base = t.path();
            let src = base.join("state_5.sqlite");
            let dst = base.join("state_5.sqlite.pre-share-1000");
            fs::write(&src, b"TEST INPUT: main db").unwrap();
            fs::write(format!("{}-wal", src.display()), b"TEST INPUT: wal").unwrap();
            // Poison dst's -wal as a DIRECTORY, so renaming src's real
            // -wal sidecar onto it fails — the main file has already
            // moved to dst by the time this sidecar rename runs.
            fs::create_dir_all(format!("{}-wal", dst.display())).unwrap();

            let err = codex_sqlite::rename_db_with_sidecars(&src, &dst).unwrap_err();
            assert!(matches!(err, ShareError::Io { .. }), "{err:?}");

            assert!(src.exists(), "the main file must be restored to src");
            assert_eq!(fs::read(&src).unwrap(), b"TEST INPUT: main db");
            assert!(!dst.exists(), "dst must not retain the main file");
            assert!(
                fs::metadata(format!("{}-wal", src.display()))
                    .unwrap()
                    .is_file(),
                "src's -wal sidecar must be restored, not left stranded at dst"
            );
        }

        // ── F8: post-rename re-fingerprint (a write reaching the BACKUP
        //    inode via an already-open fd, after the path has moved) ────

        /// A write landing on the BACKUP file's inode — simulating a live
        /// writer whose already-open file descriptor keeps writing after
        /// `rename_db_with_sidecars` retargets the path out from under it
        /// — must be caught by the post-loop re-fingerprint check and
        /// rolled back, exactly like the pre-rename (copy-phase) case
        /// above. The pre-rename check alone (compared immediately before
        /// THIS rename) cannot see this: the mutation happens AFTER that
        /// compare, once the file is already at `backup`.
        #[test]
        fn a_write_landing_on_the_backup_after_rename_refuses_and_rolls_back() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                true,
            );

            let shared_dir = shared_root(base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let slot_homes = vec![(slot_num(11), home11.clone())];
            let plan = codex_sqlite::plan_one_basename(
                &bin,
                &shared_dir,
                &slot_homes,
                "state_5.sqlite",
                false,
            )
            .unwrap();

            codex_sqlite::set_test_after_rename_hook(move |backup: &Path| {
                // Append rather than overwrite: still a genuine, detectable
                // change to the file's (size, mtime) fingerprint, without
                // relying on the exact byte layout sqlite3 produced.
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(backup)
                    .unwrap();
                f.write_all(b"MUTATED AFTER RENAME").unwrap();
            });
            let result = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            );
            codex_sqlite::clear_test_after_rename_hook();

            let err = result.unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );

            // The rollback moves the BACKUP (whatever it currently holds)
            // back onto the original path — that is what makes it safe for
            // a live writer whose already-open fd kept writing through the
            // rename: its bytes, including the post-rename append, are
            // preserved rather than discarded. There is no clean
            // "pre-mutation" content to restore TO here (unlike a sibling
            // slot's mid-merge mutation, which lands on a path never
            // renamed at all) — what matters is that nothing is lost and
            // nothing is left half-migrated.
            let p = home11.join("state_5.sqlite");
            assert!(
                !p.symlink_metadata().unwrap().file_type().is_symlink(),
                "rollback must restore the original as a real file, not leave it linked"
            );
            let restored = fs::read(&p).unwrap();
            assert!(
                restored.ends_with(b"MUTATED AFTER RENAME"),
                "rollback must preserve the live writer's post-rename append, not discard it"
            );
            let leftover: Vec<_> = fs::read_dir(&home11)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".pre-share-"))
                .collect();
            assert!(
                leftover.is_empty(),
                "no stranded backup must remain after rollback: {leftover:?}"
            );
        }
    }
}
