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
//! `codex-plugins` is an entitlement-sensitive cache too: measured on a
//! maintainer host 2026-09-29, one slot's tree carried an `openai-bundled`
//! plugin group (`sites`, `browser`, `visualize`) that another slot's did not,
//! and the curated plugins carry per-account connector install ids. Sharing it
//! would offer every slot the union of every account's plugins. `codex-skills`
//! holds only codex's own `.system/` bundle (same version marker on every
//! slot, no user skills), which codex rewrites itself — sharing it buys
//! nothing and lets two codex versions overwrite each other's copy.
//! Codex's `*.sqlite` state is shared separately, not through this list — see
//! the `codex_sqlite` module.
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
    #[error("CSQ_CODEX_RESUME_TARGET: {reason}; recover the target transcript before retrying the same csq resume command") ]
    CodexResumeTarget { reason: &'static str },
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
    // L2: the explanatory half of this message is composed by the caller
    // (`migrations_mismatch_note`), which has the context — which side is
    // `None` vs empty vs populated, whether the counts differ or only the
    // checksums do, and whether either side IS the canonical shared
    // database — to say something more specific than "different versions".
    #[error("refusing to merge {basename}: {a_path} and {b_path} have incompatible codex schemas. {note}")]
    SqliteMigrationsMismatch {
        basename: String,
        a_path: PathBuf,
        b_path: PathBuf,
        note: String,
    },
    #[error(
        "refusing to merge {basename}: `threads` has a column named {column:?}, which \
         fails the identifier allowlist (^[A-Za-z_][A-Za-z0-9_]*$) — refusing to \
         interpolate it into SQL"
    )]
    SqliteUnsafeColumnName { basename: String, column: String },
    #[error(
        "refusing to merge {basename}: {path} has a table named {table:?}, which fails the \
         identifier allowlist (^[A-Za-z_][A-Za-z0-9_]*$) — refusing to interpolate it into SQL"
    )]
    SqliteUnsafeTableName {
        basename: String,
        path: PathBuf,
        table: String,
    },
    // M2: the migrations-signature match already required across every
    // side (`plan_one_basename`) establishes that `threads`'s schema is
    // identical everywhere it is compared — but it says nothing about any
    // OTHER carried table's schema, which this module never compares
    // directly. Without this check, a source whose carried table gained or
    // dropped a column relative to the destination would still pass a
    // `SELECT *` blind — this variant is what a NAMED column-set mismatch
    // now refuses with instead.
    #[error(
        "refusing to merge {basename}: table `{table}` in {path} has a different SET of \
         columns than the destination's copy of the same table — refusing to carry its rows \
         across a schema mismatch this module has not verified is safe. csq does not upgrade \
         codex's database for it: start codex once on the side that is behind (`csq run \
         <slot>` on that slot, or on any slot already linked to the shared index, then \
         quit) so codex migrates its own database, then re-run."
    )]
    SqliteCarriedTableColumnMismatch {
        basename: String,
        table: String,
        path: PathBuf,
    },
    #[error(
        "refusing to merge {basename}: {path} failed `PRAGMA foreign_key_check` in a way this \
         module does not know how to repair ({detail}). B1: the whole merge into {path} ran as \
         ONE transaction, so this refusal rolled it back entirely — {path}'s content is \
         unchanged (SQLite does not guarantee the underlying bytes are identical after a \
         rollback, only the data), and every per-slot original is still intact (never renamed)."
    )]
    SqliteForeignKeyViolation {
        basename: String,
        path: PathBuf,
        detail: String,
    },
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
        "refusing to merge {basename}: the schema values verified for {path} contain a \
         character this module will not embed in the guard script that re-checks them \
         inside the merge transaction. Nothing was written."
    )]
    SqliteGuardValueUnsafe { basename: String, path: PathBuf },
    #[error(
        "refusing to move a database to {path}: a stray `{stray}` already exists there without \
         its main file (a leftover write-ahead file). Move it aside once codex is closed, \
         then re-run. Nothing was moved."
    )]
    SqliteStraySidecar { path: PathBuf, stray: PathBuf },
    #[error("cannot recover a stranded backup automatically: {listing}")]
    SqliteStrandedBackupNeedsManualRecovery { listing: String, commands: String },
    #[error(
        "merging into the shared index for {basename} failed in a way that cannot prove \
         nothing was committed ({cause}); the pre-merge backup is kept at {backup}. Check \
         the shared index, and restore from that backup if it is wrong."
    )]
    SqliteMergeOutcomeUnknown {
        basename: String,
        backup: PathBuf,
        /// Typed copy of the failure already described in the message.
        cause: Box<ShareError>,
    },
    #[error(
        "cannot take a pre-merge backup at {path}: this filesystem does not support hard \
         links, which the backup uses so it can refuse (never overwrite) an existing \
         backup. Move the codex state to a filesystem with hard-link support and re-run. \
         Nothing was merged."
    )]
    SqliteBackupHardLinkUnsupported { path: PathBuf },
    // H1: `SqliteChangedDuringMerge`'s "rolled back; every original for it
    // is intact" is TRUE only for a refusal that happens BEFORE
    // `merge_sources_into` commits (the plan/apply TOCTOU re-verify). A
    // refusal in the RENAME LOOP — reached only AFTER that commit, or after
    // the first-creation `tmp_shared` rename into place — is a different
    // situation entirely: the shared index has ALREADY been durably
    // updated, and it is the per-slot LINKING that failed, not the merge.
    // `rollback_renamed` restores each per-slot original it touched on a
    // BEST-EFFORT basis (R3) — `note` names any it could NOT restore, not a
    // blanket "every original is intact" claim. `source` (R3) carries the
    // underlying failure TYPED, so a caller can match on it directly
    // instead of parsing `note`'s prose.
    #[error(
        "the shared index for {basename} was merged into (its content may be unchanged); {note}"
    )]
    SqliteSharedCommittedSlotsUnlinked {
        basename: String,
        note: String,
        /// Typed copy of the failure already described in `note`. Not a
        /// `#[source]`: the `note` text carries it, and a source chain would
        /// print it a second time.
        cause: Box<ShareError>,
    },
    // Fixed vocabulary: the lock's contended state alone cannot name its
    // holder, so the message lists every holder class that can exclude a
    // SHARED acquire and says how to look for one — it never asserts which.
    #[error(
        "the codex cross-slot share lock is held exclusively, either by a running \
         `csq sessions share` or by a sqlite3 writer left behind by an interrupted one \
         (that writer exits once its script ends). Retry the launch once the lock is \
         released; to identify the holder, look for a `csq` or `sqlite3` process (e.g. \
         with `ps`) whose arguments name the csq accounts directory"
    )]
    CodexShareLockContended,
    #[error(
        "refusing to merge {basename}: {path} has a `{object_type}` named {object_name:?} in \
         `sqlite_master` that is not one of codex-cli's own (codex creates no views, and only \
         the five `threads_*` triggers csq recognises). A newer codex-cli may have changed \
         one — update csq; otherwise this is a hand-modified file and csq will not copy its \
         schema into the shared store"
    )]
    SqliteUntrustedSchemaObject {
        basename: String,
        path: PathBuf,
        object_type: String,
        object_name: String,
    },
    // Fixed vocabulary, as for `CodexShareLockContended`: `{pids}` is the
    // pre-lock scan's evidence, never a claim about which process holds it.
    #[error(
        "cannot acquire the codex cross-slot share lock: timed out after ~{bound_secs}s \
         waiting for it to be released. It is held by a running codex session, another \
         running `csq sessions share`, or a sqlite3 writer left behind by an interrupted \
         `csq sessions share` or csq run (that writer exits once its script ends). Live codex session(s) observed \
         just before waiting (pid(s)): {pids}. This is NOT overridden by --force — the lock \
         protects the on-disk session store from being retargeted while it is in use. To \
         identify the holder, look for a `codex`, `csq` or `sqlite3` process (e.g. with \
         `ps`) whose arguments name the csq accounts directory; once it has exited, re-run \
         `csq sessions share`."
    )]
    CodexShareLockTimedOut { bound_secs: u64, pids: String },
}

impl ShareError {
    // L1: every path this module names to an operator MUST be redacted —
    // this is the single construction site for `ShareError::Io`, used
    // throughout the file, so redacting here covers every call site at
    // once rather than requiring each one to remember it individually.
    fn io(path: &Path, source: io::Error) -> Self {
        ShareError::Io {
            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
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

impl Drop for CodexShareLockGuard {
    fn drop(&mut self) {
        // G2b item 2: release EXPLICITLY. POSIX flock is bound to the open
        // file description and is released only by LOCK_UN on any duplicate
        // or by closing EVERY descriptor to it (`flock(2)`). A fork from
        // any thread of the holding process keeps the description — and
        // the lock — alive past this guard's own close, until the child
        // execs (`FD_CLOEXEC`) or exits. LOCK_UN on any duplicate releases
        // the whole description, making this drop the release point.
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: `_file` is still open here (field drop runs after this
            // body); flock(LOCK_UN) touches no memory and only releases an
            // advisory lock this description holds.
            if unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) } != 0 {
                tracing::warn!(
                    error_kind = "codex_share_lock_unlock_failed",
                    errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                    "codex share lock could not be released"
                );
            }
        }
        // Windows: LockFileEx is released by CloseHandle, std handles are
        // non-inheritable, and there is no fork() — no duplicate can
        // outlive the close.
    }
}

/// What a writer `sqlite3` child inherits from the migration lock on Unix: the
/// locked descriptor, plus the `(st_dev, st_ino)` identity of the file it
/// named when the scope was opened (`None` when `fstat` failed then, which
/// makes every writer spawn under this token refuse). The child re-checks the
/// identity before duplicating the descriptor, so a descriptor number that was
/// closed and reused for another file is never handed to a writer as the lock.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ChildLockToken {
    pub(crate) fd: std::os::fd::RawFd,
    pub(crate) identity: Option<(libc::dev_t, libc::ino_t)>,
}

/// `(st_dev, st_ino)` of the open file `fd` names, or `None` when `fstat`
/// fails.
#[cfg(unix)]
pub(crate) fn fd_identity(fd: std::os::fd::RawFd) -> Option<(libc::dev_t, libc::ino_t)> {
    // SAFETY: a zeroed `stat` is a valid out-parameter; fstat only reads the
    // descriptor's metadata and changes nothing.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::fstat(fd, &mut st) == 0).then_some((st.st_dev, st.st_ino))
    }
}

/// What a writer `sqlite3` child inherits from the migration lock: the locked
/// descriptor on Unix; on Windows only the fact that a lock is held.
#[cfg(not(unix))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ChildLockToken;

thread_local! {
    /// The migration lock writer children spawned on THIS thread inherit; set
    /// only by a live [`ChildLockScope`], which borrows the guard that owns it.
    static CHILD_LOCK: std::cell::Cell<Option<ChildLockToken>> =
        const { std::cell::Cell::new(None) };
}

/// Makes a held [`CodexShareLockGuard`] the lock every writer repair/merge
/// `sqlite3` child spawned on this thread inherits, until the scope drops.
///
/// The scope BORROWS the guard, so the locked descriptor cannot be closed
/// while the scope exists, and it is `!Send`, so it is set and cleared on the
/// same thread. On drop the previous value is restored only while the slot
/// still holds THIS scope's own token (properly nested scopes); a scope
/// dropped out of order clears the slot instead, so the slot never names a
/// descriptor that a still-live scope did not install.
pub(crate) struct ChildLockScope<'a> {
    _lock: &'a CodexShareLockGuard,
    token: ChildLockToken,
    previous: Option<ChildLockToken>,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl CodexShareLockGuard {
    /// Hold this lock for writer children spawned on this thread (see
    /// [`ChildLockScope`]).
    pub(crate) fn hold_for_children(&self) -> ChildLockScope<'_> {
        #[cfg(unix)]
        let token = {
            let fd = std::os::fd::AsRawFd::as_raw_fd(&self._file);
            ChildLockToken {
                fd,
                identity: fd_identity(fd),
            }
        };
        #[cfg(not(unix))]
        let token = ChildLockToken;
        ChildLockScope {
            _lock: self,
            token,
            previous: CHILD_LOCK.with(|held| held.replace(Some(token))),
            _not_send: std::marker::PhantomData,
        }
    }
}

impl Drop for ChildLockScope<'_> {
    fn drop(&mut self) {
        CHILD_LOCK.with(|held| {
            if held.get() == Some(self.token) {
                held.set(self.previous);
            } else {
                held.set(None);
            }
        });
    }
}

/// Test seam: run `f` with `token` installed as this thread's child lock,
/// restoring the previous value afterwards (lets a test hand
/// `RepairChild::spawn` a descriptor or identity no real guard produces).
#[cfg(all(test, unix))]
pub(crate) fn with_child_lock_token_for_test<T>(token: ChildLockToken, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<ChildLockToken>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CHILD_LOCK.with(|held| held.set(self.0));
        }
    }
    let _restore = Restore(CHILD_LOCK.with(|held| held.replace(Some(token))));
    f()
}

/// The lock a writer child spawned on this thread must inherit, if any.
pub(crate) fn held_child_lock() -> Option<ChildLockToken> {
    CHILD_LOCK.with(std::cell::Cell::get)
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

/// The Windows system directory from `GetSystemDirectoryW`, or `None` when
/// the call fails, returns empty, or yields a non-absolute path.
#[cfg(windows)]
fn windows_system_directory() -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 520];
    // SAFETY: `buf` is a live, writable buffer of `buf.len()` u16 units and
    // the length passed is exactly that.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    // 0 = failure; n >= len = buffer too small (the value is the needed size).
    if n == 0 || n >= buf.len() {
        return None;
    }
    let dir = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]));
    dir.is_absolute().then_some(dir)
}

/// The Windows directory from `GetSystemWindowsDirectoryW`, or `None` when
/// the call fails, returns empty, or yields a non-absolute path.
#[cfg(windows)]
fn windows_directory() -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 520];
    // SAFETY: `buf` is a live, writable buffer of `buf.len()` u16 units and
    // the length passed is exactly that.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return None;
    }
    let dir = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]));
    dir.is_absolute().then_some(dir)
}

#[cfg(windows)]
fn list_running_processes() -> Result<Vec<(u32, String)>, String> {
    // S-L4: env_clear so an inherited env var cannot alter `tasklist`'s
    // output format or locale out from under this parser — but `SystemRoot`
    // and `WINDIR` are put back: `tasklist` enumerates through WMI/COM, which
    // cannot initialise in a process with no `SystemRoot` (Windows CI run
    // 38993121327, `live_writer_refuses_and_leaves_originals_untouched`).
    // The binary is resolved from `GetSystemDirectoryW`, NOT from an
    // environment variable: the process environment is attacker-influenced
    // input to a guard this module's destructive rename path depends on
    // (S-F6, as `/bin/ps` is on unix). A failed call, or a result that is
    // empty or not absolute, is an `Err` — fail closed, never a bare-name
    // lookup. The error text is fixed wording and carries no path.
    let system_dir = windows_system_directory().ok_or_else(|| {
        "could not resolve the Windows system directory; cannot locate `tasklist`".to_string()
    })?;
    let tasklist = system_dir.join("tasklist.exe");
    let mut command = std::process::Command::new(&tasklist);
    command.env_clear();
    // WMI needs SystemRoot; WINDIR is the same value on a stock host. Both
    // come from `GetSystemWindowsDirectoryW`, never from the environment
    // (attacker-influenced input to a guard on a destructive path). A failed,
    // empty or non-absolute result is an `Err`; the text carries no path.
    let windows_dir = windows_directory().ok_or_else(|| {
        "could not resolve the Windows directory; cannot run `tasklist`".to_string()
    })?;
    command.env("SystemRoot", &windows_dir);
    command.env("WINDIR", &windows_dir);
    let output = command
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
/// scan can see (another `csq sessions share` run, or a sqlite3 writer left
/// behind by an interrupted csq run).
fn format_live_writer_pids(live: &[LiveWriter]) -> String {
    if live.is_empty() {
        return "none identified by the pre-lock scan (the holder may be a process without \
                 handle-dir bookkeeping, another `csq sessions share` invocation, or a \
                 sqlite3 writer left behind by an interrupted `csq sessions share` or csq run)"
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
    let share_lock = if dry_run {
        None
    } else {
        Some(acquire_codex_share_lock_exclusive_bounded_reporting(base)?)
    };
    // Every writer sqlite3 child below inherits the lock (see `RepairChild`).
    let _children = share_lock
        .as_ref()
        .map(CodexShareLockGuard::hold_for_children);
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
        let writer = match crate::platform::fs::write_new_private_retained(&tmp, content.as_bytes())
        {
            Ok(writer) => writer,
            Err(e) => {
                return Err(ShareError::io(&tmp, io::Error::other(e.to_string())));
            }
        };
        if let Err(e) = writer.replace(shared_file) {
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
    use sha2::{Digest, Sha256};
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
        find_executable_in_dirs_for_platform(dirs, name, is_executable, cfg!(windows))
    }

    pub(super) fn find_executable_in_dirs_for_platform(
        dirs: impl Iterator<Item = PathBuf>,
        name: &str,
        is_executable: impl Fn(&Path) -> bool,
        windows: bool,
    ) -> Option<PathBuf> {
        dirs.filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute())
            .find_map(|dir| {
                let candidate = dir.join(if windows && name == "sqlite3" {
                    "sqlite3.exe"
                } else {
                    name
                });
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

    /// Read-only admission. The embedding process must keep SIGCHLD policy
    /// stable and must not reap this runner's children while repair is in flight.
    /// Admission cannot prevent another component changing policy later.
    #[cfg(unix)]
    fn repair_child_wait_policy_safe() -> bool {
        // SAFETY: null input only queries SIGCHLD; initialized output is owned.
        // This never changes host signal policy or reaps a child.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) == 0
                && action.sa_sigaction != libc::SIG_IGN
                && action.sa_flags & libc::SA_NOCLDWAIT == 0
        }
    }

    const REPAIR_IO_CAP: usize = 1024 * 1024;

    /// A fresh end-of-script marker for one writer run: `csq-end-` plus 16 hex
    /// digits from a per-call randomly keyed hash, so database content cannot
    /// predict (and so cannot print) it.
    pub(super) fn writer_end_marker() -> String {
        use std::hash::{BuildHasher, Hasher};
        static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        hasher.write_u32(std::process::id());
        format!("csq-end-{:016x}", hasher.finish())
    }

    /// The statement a writer script ends with: it prints `marker` only once
    /// every earlier statement ran (the shell stops at the first error).
    fn writer_end_statement(marker: &str) -> String {
        format!("SELECT '{marker}';")
    }

    /// `stdout` with its final line removed, when that final line is exactly
    /// `marker`; `None` otherwise. A writer whose stdout lacks the marker did
    /// not execute its whole script, whatever its exit status: a pipe write
    /// proves only that the bytes were buffered, never that they were read.
    pub(super) fn strip_writer_end_marker(stdout: &str, marker: &str) -> Option<String> {
        let body = stdout.strip_suffix('\n').unwrap_or(stdout);
        let body = body.strip_suffix('\r').unwrap_or(body);
        let (rest, last) = match body.rfind('\n') {
            Some(at) => (&body[..=at], &body[at + 1..]),
            None => ("", body),
        };
        (last == marker).then(|| rest.to_owned())
    }

    /// The fixed detail for a writer spawn refused by `RepairChild::spawn`'s
    /// own lock checks, or `None` for any other spawn failure.
    pub(super) fn writer_spawn_refusal_detail(error: &io::Error) -> Option<&'static str> {
        let text = error.to_string();
        if text == repair_child::UNLOCKED_WRITER_DETAIL {
            return Some(repair_child::UNLOCKED_WRITER_DETAIL);
        }
        #[cfg(unix)]
        {
            if text == repair_child::UNUSABLE_LOCK_DETAIL {
                return Some(repair_child::UNUSABLE_LOCK_DETAIL);
            }
            // Only `RepairChild::spawn`'s own classification produces this
            // text (an ESTALE confirmed against the descriptor); a bare
            // ESTALE from any other spawn or execve failure is not mapped.
            if text == repair_child::LOCK_IDENTITY_MISMATCH_DETAIL {
                return Some(repair_child::LOCK_IDENTITY_MISMATCH_DETAIL);
            }
        }
        None
    }

    /// The launch runner's largest accepted script, in bytes (the generators
    /// batch at `PAGED_BATCH_BYTES`, a sixth of this).
    const REPAIR_SCRIPT_CAP: usize = 60_000;

    /// The bounded runner's own deadline detail — the pre-spawn refusal and the
    /// wait-loop kill both carry exactly this. Named once because
    /// [`is_bounded_deadline_refusal`] matches it EXACTLY: the runner's other
    /// details embed the child's stderr, which quotes database content (a
    /// `rollout_path` may contain the word "deadline"), and a substring match
    /// would let that content steer which refusal class an operator is told to
    /// act on.
    pub(super) const ROLLOUT_REPAIR_DEADLINE_DETAIL: &str = "rollout repair deadline";

    /// Both runners' detail for a writer that exited 0 without printing its
    /// end marker: it did not execute its whole script.
    pub(super) const WRITER_NOT_FULLY_EXECUTED_DETAIL: &str =
        "sqlite3 writer exited without running its whole script";

    /// Both runners deliver statements one per stdin line, never in argv; the
    /// bail probe mirrors that shape.
    type BailKey = (PathBuf, u64, Option<std::time::SystemTime>);

    fn bail_cache() -> &'static std::sync::Mutex<std::collections::HashSet<BailKey>> {
        static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<BailKey>>> =
            std::sync::OnceLock::new();
        CACHE.get_or_init(Default::default)
    }

    fn bail_key(binary: &Path) -> Option<BailKey> {
        let meta = std::fs::metadata(binary).ok()?;
        Some((binary.to_path_buf(), meta.len(), meta.modified().ok()))
    }

    /// Run a script of three statements on a scratch `:memory:` database under
    /// `-bail`: a table with a named CHECK, an INSERT that violates it, then a
    /// SELECT that prints a marker. True only when the shell exits non-zero AND
    /// never printed the marker, i.e. it really stopped at the first error. A
    /// probe that cannot run is a failed probe.
    pub(super) fn probe_stops_at_first_error(binary: &Path) -> bool {
        use std::time::{Duration, Instant};
        // The probe observes its child with `waitid(WNOWAIT)` like the runner:
        // an auto-reaping SIGCHLD policy fails the probe (closed), never runs it.
        #[cfg(unix)]
        if !repair_child_wait_policy_safe() {
            return false;
        }
        let statements = [
            "CREATE TABLE csq_probe(ok INTEGER CONSTRAINT csq_probe_guard CHECK (ok IS 1));",
            "INSERT INTO csq_probe VALUES (0);",
            "SELECT 'csq_probe_reached';",
        ];
        let null_rc = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut command = Command::new(binary);
        command
            .args([
                "-init",
                null_rc,
                "-batch",
                "-noheader",
                "-list",
                "-bail",
                ":memory:",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Own process group: a probe shell that forks a descendant holding
        // stdout is killed with that descendant (see `RepairChild::spawn`).
        // A `:memory:` probe writes no database, so it inherits no lock.
        let Ok(mut child) = RepairChild::spawn(&mut command, ChildRole::Reader) else {
            return false;
        };
        {
            // The three statements are far below any pipe buffer, so this
            // write cannot block; dropping the pipe ends the shell's input.
            let Some(mut stdin) = child.take_stdin() else {
                return false;
            };
            if stdin.write_all(statements.join("\n").as_bytes()).is_err() {
                return false;
            }
        }
        let Some(mut stdout) = child.take_stdout() else {
            return false;
        };
        if set_repair_pipe_nonblocking(&stdout).is_err() {
            return false;
        }
        // ONE enforced 5s deadline covers the exit AND the drain of stdout: a
        // descendant that inherited stdout and outlives the shell can no longer
        // hold this read open. On expiry (or any failure) `RepairChild`'s drop
        // kills the process group and reaps within REPAIR_CHILD_CLEANUP_GRACE.
        let deadline = Instant::now() + PROBE_BUDGET;
        let mut out = Vec::new();
        let mut eof = false;
        loop {
            if drain_repair_pipe(&mut stdout, &mut out, &mut eof, REPAIR_IO_CAP).is_err() {
                return false;
            }
            match child.exited() {
                Ok(true) if eof => break,
                Ok(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                _ => return false,
            }
        }
        let Ok(status) = child.wait() else {
            return false;
        };
        !status.success() && !String::from_utf8_lossy(&out).contains("csq_probe_reached")
    }

    /// The bail probe's enforced bound: exit plus stdout drain, one window.
    const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

    /// How long a dropped, still-unreaped repair or probe child is given to be
    /// reaped after its process group is killed.
    const REPAIR_CHILD_CLEANUP_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

    #[cfg(test)]
    pub(super) use repair_child::resumed_writer_may_run;
    #[cfg(all(test, unix))]
    pub(super) use repair_child::{
        drop_signal_paths, lock_identity_refusal, LOCK_IDENTITY_MISMATCH_DETAIL,
        LOCK_IDENTITY_MISMATCH_ERRNO, UNLOCKED_WRITER_DETAIL, UNUSABLE_LOCK_DETAIL,
    };
    #[cfg(all(test, windows))]
    pub(super) use repair_child::{resume_threads, spawn_suspended_in_job};
    pub(super) use repair_child::{ChildRole, RepairChild};

    /// The ONLY constructor of a repair/probe/merge `sqlite3` child lives here,
    /// so no call site can spawn one outside its own process group or, for a
    /// writer, without inheriting the migration lock (the struct's fields are
    /// private to this module).
    mod repair_child {
        use super::REPAIR_CHILD_CLEANUP_GRACE;
        use std::io;
        use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};

        /// The fixed detail a writer spawn refuses with when this thread holds
        /// no migration lock (`super::super::ChildLockScope`).
        pub(in super::super) const UNLOCKED_WRITER_DETAIL: &str =
            "repair writer refused: migration lock not held";

        /// The fixed detail a writer spawn refuses with when the held lock
        /// token is not a descriptor a child can inherit as the lock: a
        /// standard-stream number (0-2, which the child's own stdio setup
        /// overwrites before `exec`) or an identity `fstat` could not read.
        #[cfg(unix)]
        pub(in super::super) const UNUSABLE_LOCK_DETAIL: &str =
            "repair writer refused: migration lock descriptor unusable";

        /// The errno a writer child exits its `pre_exec` with when the lock
        /// descriptor no longer names the file the scope recorded (closed and
        /// reused), BEFORE it is duplicated. Distinct from every errno the
        /// other `pre_exec` steps can return, so the refusal is identifiable.
        #[cfg(unix)]
        pub(in super::super) const LOCK_IDENTITY_MISMATCH_ERRNO: i32 = libc::ESTALE;

        /// The error text `RepairChild::spawn` returns (and a runner reports)
        /// for a writer whose lock descriptor failed the in-child identity
        /// check: a [`LOCK_IDENTITY_MISMATCH_ERRNO`] spawn failure that the
        /// parent confirms by re-reading the descriptor's identity
        /// ([`lock_identity_refusal`]).
        #[cfg(unix)]
        pub(in super::super) const LOCK_IDENTITY_MISMATCH_DETAIL: &str =
            "repair writer refused: migration lock descriptor no longer names the lock file";

        /// Whether a writer spawn failure is the in-child lock-identity
        /// refusal: its errno is [`LOCK_IDENTITY_MISMATCH_ERRNO`] AND the
        /// descriptor's identity read again in the parent (`now`) no longer
        /// equals the recorded one. ESTALE with the descriptor still naming
        /// the lock file came from somewhere else (e.g. `execve` on a stale
        /// NFS handle) and is NOT this refusal.
        /// A Unix spawn failure, with a confirmed lock-identity refusal
        /// ([`lock_identity_refusal`]) replaced by
        /// [`LOCK_IDENTITY_MISMATCH_DETAIL`]; any other error is unchanged.
        #[cfg(unix)]
        fn writer_spawn_error(
            error: io::Error,
            role: ChildRole,
            lock: Option<super::super::ChildLockToken>,
        ) -> io::Error {
            match (role, lock) {
                (ChildRole::Writer, Some(token)) => {
                    let now = super::super::fd_identity(token.fd);
                    if lock_identity_refusal(error.raw_os_error(), token.identity, now) {
                        io::Error::other(LOCK_IDENTITY_MISMATCH_DETAIL)
                    } else {
                        error
                    }
                }
                _ => error,
            }
        }

        #[cfg(unix)]
        pub(in super::super) fn lock_identity_refusal(
            errno: Option<i32>,
            recorded: Option<(libc::dev_t, libc::ino_t)>,
            now: Option<(libc::dev_t, libc::ino_t)>,
        ) -> bool {
            errno == Some(LOCK_IDENTITY_MISMATCH_ERRNO) && recorded.is_some() && now != recorded
        }

        /// Whether a child may write a database.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(in super::super) enum ChildRole {
            /// May write the Codex database: inherits the migration lock and
            /// refuses to spawn without one.
            Writer,
            /// `-readonly` inspection or a `:memory:` probe: inherits nothing.
            Reader,
        }

        /// A spawned repair/probe/merge `sqlite3` child that, when dropped
        /// unreaped, is killed and reaped within [`REPAIR_CHILD_CLEANUP_GRACE`].
        /// On Unix the child is the leader of its own process group
        /// (`process_group(0)`) and the WHOLE group is `SIGKILL`ed, so a shell
        /// that forked a descendant holding a pipe does not leave it running. The
        /// exit is observed with `waitid(WNOWAIT)` ([`RepairChild::exited`]) so
        /// the leader is never reaped before the group is signalled: an unreaped
        /// leader keeps its pid reserved as the group id, and once
        /// [`RepairChild::wait`] reaps it no signal or wait is ever issued for
        /// that pid again (`reaped`).
        ///
        /// On Unix a [`ChildRole::Writer`] child inherits a descriptor of the
        /// migration lock's open file description. `flock` ownership belongs to
        /// that description, so the lock stays held until the LAST holder closes
        /// it: csq releasing its own guard, or dying by any signal including
        /// `SIGKILL`, does not release the lock while this child or any
        /// descendant that inherited the descriptor is still running. Another
        /// csq therefore cannot take the exclusive lock while an orphaned writer
        /// is still writing. Because the child is in its own process group a
        /// terminal interrupt is not forwarded to it, and each write batch is
        /// one transaction that commits or rolls back whole.
        ///
        /// The runner's deadline is enforced only WHILE CSQ LIVES: it is the
        /// runner's own loop plus this type's drop, both in csq. What bounds a
        /// writer after csq dies is, per platform:
        /// - Linux: `PR_SET_PDEATHSIG(SIGKILL)`, armed in the writer's
        ///   `pre_exec` (with a `getppid` check for a parent that died before
        ///   it was armed). The kernel kills the writer when the THREAD that
        ///   forked it dies; every runner spawns, waits and drops its child on
        ///   one thread, so that thread outlives the child's useful life. The
        ///   killed writer's open transaction is rolled back by SQLite on the
        ///   next open, and the lock is released with the writer.
        /// - macOS and other Unix: no death signal exists. Every writer reads
        ///   its script on stdin (never argv). A launch batch normally fits one
        ///   pipe buffer and is delivered WHOLE at spawn, so an orphan runs its
        ///   whole batch to its end, bounded only by its own work and each lock
        ///   wait's `PRAGMA busy_timeout` ([`super::SQLITE_BUSY_TIMEOUT_MS`]),
        ///   with the lock held throughout so no other migration can start
        ///   (fail-closed); every batch is one transaction csq itself would
        ///   have run. Only a script larger than the pipe buffer is cut short
        ///   by csq's death: its undelivered remainder ends at EOF and the open
        ///   transaction rolls back.
        /// - Windows: `LockFileEx` locks belong to the handle, not an
        ///   inheritable description, so a writer only refuses to spawn without
        ///   a held lock. Each writer is created suspended (`CREATE_SUSPENDED`),
        ///   assigned to a Job Object created with
        ///   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` whose only handle csq owns,
        ///   and only then resumed, so it executes nothing outside the job:
        ///   csq's termination closes the job and the system kills the writer,
        ///   and csq dying before the assignment leaves a process that never
        ///   runs. A writer that cannot be assigned or resumed is terminated,
        ///   reaped and refused.
        pub(in super::super) struct RepairChild {
            child: Child,
            reaped: bool,
            /// Windows writers only: the Job Object the child is assigned to.
            /// Declared after `child`, so `Drop` kills and reaps the child
            /// before this closes the job's last handle.
            #[cfg(windows)]
            _job: Option<WriterJob>,
        }

        /// The fixed detail a Windows writer spawn refuses with when its Job
        /// Object cannot be created, configured or assigned.
        #[cfg(windows)]
        pub(in super::super) const WRITER_JOB_DETAIL: &str =
            "repair writer refused: could not confine the writer to a kill-on-close job";

        /// A Job Object created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Its
        /// handle is never inherited or duplicated, so it is csq's only handle:
        /// closing it, by this drop or by the system when csq terminates for
        /// any reason, kills every process still assigned to the job.
        #[cfg(windows)]
        pub(in super::super) struct WriterJob(windows_sys::Win32::Foundation::HANDLE);

        #[cfg(windows)]
        impl WriterJob {
            /// Create and configure the job, or refuse (never a job without the
            /// kill-on-close limit).
            fn create() -> io::Result<Self> {
                use windows_sys::Win32::System::JobObjects::{
                    CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                };
                // SAFETY: null attributes (a non-inheritable handle) and a null
                // name (an unnamed job no other process can open by name).
                let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
                if handle == 0 {
                    return Err(io::Error::other(WRITER_JOB_DETAIL));
                }
                let job = Self(handle);
                // SAFETY: a zeroed limit struct is valid; only the flag is set,
                // and the pointer/length describe exactly that struct.
                let configured = unsafe {
                    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                    SetInformationJobObject(
                        job.0,
                        JobObjectExtendedLimitInformation,
                        std::ptr::addr_of!(limits).cast(),
                        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    )
                };
                if configured == 0 {
                    return Err(io::Error::other(WRITER_JOB_DETAIL));
                }
                Ok(job)
            }

            /// Whether `child` is a member of this job (`IsProcessInJob`).
            #[cfg(test)]
            pub(in super::super) fn contains(&self, child: &Child) -> io::Result<bool> {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::System::JobObjects::IsProcessInJob;
                let mut member = 0;
                // SAFETY: both handles are open for this call; `member` is a
                // valid out-parameter.
                let ok = unsafe {
                    IsProcessInJob(
                        child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                        self.0,
                        &mut member,
                    )
                };
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(member != 0)
            }

            /// Assign `child` to this job.
            fn assign(&self, child: &Child) -> io::Result<()> {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
                // SAFETY: both handles are open: the job is owned by `self`, the
                // process handle by `child`, which outlives this call.
                let assigned = unsafe {
                    AssignProcessToJobObject(
                        self.0,
                        child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                    )
                };
                if assigned == 0 {
                    return Err(io::Error::other(WRITER_JOB_DETAIL));
                }
                Ok(())
            }
        }

        /// Spawn `command` SUSPENDED (`CREATE_SUSPENDED`) and assign it to a
        /// fresh kill-on-close [`WriterJob`] created before the spawn. The
        /// child has executed nothing when this returns; a failed assignment
        /// terminates and reaps it and refuses.
        #[cfg(windows)]
        pub(in super::super) fn spawn_suspended_in_job(
            command: &mut std::process::Command,
        ) -> io::Result<(Child, WriterJob)> {
            std::os::windows::process::CommandExt::creation_flags(
                command,
                windows_sys::Win32::System::Threading::CREATE_SUSPENDED,
            );
            let job = WriterJob::create()?;
            let mut child = command.spawn()?;
            if let Err(error) = job.assign(&child) {
                // Fail closed: an unconfined writer is terminated
                // (`Child::kill` is `TerminateProcess`) and reaped, never run.
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            Ok((child, job))
        }

        /// Whether a suspended writer may run: every thread csq found for it
        /// was resumed from a suspend count of exactly 1 (`ResumeThread`
        /// returns the PREVIOUS count). No thread found, a failed resume
        /// (`u32::MAX`), a thread that was not suspended (0) or one still
        /// suspended after the resume (> 1) all refuse.
        #[cfg(any(windows, test))]
        pub(in super::super) fn resumed_writer_may_run(previous_counts: &[u32]) -> bool {
            !previous_counts.is_empty() && previous_counts.iter().all(|&count| count == 1)
        }

        /// Resume every thread of the suspended `child` (enumerated with a
        /// Toolhelp thread snapshot filtered by its pid), or refuse with
        /// [`WRITER_JOB_DETAIL`] per [`resumed_writer_may_run`].
        #[cfg(windows)]
        pub(in super::super) fn resume_threads(child: &Child) -> io::Result<()> {
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            };
            use windows_sys::Win32::System::Threading::{
                OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
            };
            let pid = child.id();
            let refuse = || io::Error::other(WRITER_JOB_DETAIL);
            // SAFETY: a thread snapshot of the system; the handle is checked
            // and closed below on every path.
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == INVALID_HANDLE_VALUE || snapshot == 0 {
                return Err(refuse());
            }
            let mut previous_counts = Vec::new();
            // SAFETY: a zeroed THREADENTRY32 with `dwSize` set is the
            // documented input; the snapshot handle is open.
            let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
            while more {
                if entry.th32OwnerProcessID == pid {
                    // SAFETY: OpenThread on a thread id from the snapshot; a
                    // null handle (failure) is recorded as a failed resume.
                    let thread =
                        unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                    if thread == 0 {
                        previous_counts.push(u32::MAX);
                    } else {
                        // SAFETY: `thread` is an open handle with
                        // THREAD_SUSPEND_RESUME, closed right after.
                        previous_counts.push(unsafe { ResumeThread(thread) });
                        unsafe { CloseHandle(thread) };
                    }
                }
                // SAFETY: as for Thread32First.
                more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
            }
            // SAFETY: the snapshot handle is owned here and closed once.
            unsafe { CloseHandle(snapshot) };
            if resumed_writer_may_run(&previous_counts) {
                Ok(())
            } else {
                Err(refuse())
            }
        }

        #[cfg(windows)]
        impl Drop for WriterJob {
            fn drop(&mut self) {
                // SAFETY: the handle is owned by this value and closed once.
                // A failed close leaves nothing this drop could do instead.
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }

        #[cfg(all(test, unix))]
        thread_local! {
            /// Drops of this thread's children that reached the signal path.
            static DROP_SIGNAL_PATHS: std::cell::Cell<usize> =
                const { std::cell::Cell::new(0) };
        }

        /// Number of this thread's `RepairChild` drops that reached the
        /// waitid/kill path (test inspection).
        #[cfg(all(test, unix))]
        pub(in super::super) fn drop_signal_paths() -> usize {
            DROP_SIGNAL_PATHS.with(std::cell::Cell::get)
        }

        impl RepairChild {
            /// Spawn `command` as its own process-group leader (Unix). A
            /// [`ChildRole::Writer`] fails closed with
            /// [`UNLOCKED_WRITER_DETAIL`] when this thread holds no migration
            /// lock, and on Unix inherits a non-`CLOEXEC` duplicate of the
            /// locked descriptor: a token naming fd 0-2 or with no recorded
            /// identity refuses before fork (`UNUSABLE_LOCK_DETAIL`), and
            /// the child `fstat`s the descriptor before duplicating it,
            /// failing with `LOCK_IDENTITY_MISMATCH_ERRNO` when it no longer
            /// names the recorded file; the parent reports that as
            /// `LOCK_IDENTITY_MISMATCH_DETAIL` only after re-reading the
            /// descriptor's identity (`lock_identity_refusal`). On Linux the writer also
            /// arms `PR_SET_PDEATHSIG` (see the type's docs).
            pub(in super::super) fn spawn(
                command: &mut Command,
                role: ChildRole,
            ) -> io::Result<Self> {
                let lock = super::super::held_child_lock();
                if role == ChildRole::Writer && lock.is_none() {
                    return Err(io::Error::other(UNLOCKED_WRITER_DETAIL));
                }
                #[cfg(unix)]
                {
                    std::os::unix::process::CommandExt::process_group(command, 0);
                    if let (ChildRole::Writer, Some(token)) = (role, lock) {
                        let fd = token.fd;
                        let Some(identity) = token.identity else {
                            return Err(io::Error::other(UNUSABLE_LOCK_DETAIL));
                        };
                        if fd <= 2 {
                            return Err(io::Error::other(UNUSABLE_LOCK_DETAIL));
                        }
                        // Captured before fork: the child compares its parent
                        // with it after arming the death signal.
                        #[cfg(any(target_os = "linux", target_os = "android"))]
                        // SAFETY: getpid only queries.
                        let parent = unsafe { libc::getpid() };
                        // SAFETY: the closure runs between fork and exec and
                        // calls only `prctl`, `getppid`, `_exit`, `fcntl` and
                        // `fstat`, which are async-signal-safe; it allocates
                        // nothing (the errors are raw OS codes). `fd` stays open in the
                        // parent for the whole spawn: the `ChildLockScope`
                        // that published it borrows the guard owning it, on
                        // this thread.
                        unsafe {
                            std::os::unix::process::CommandExt::pre_exec(command, move || {
                                // Linux: the kernel SIGKILLs this writer when
                                // the thread that forked it dies, so an orphan
                                // stops holding the inherited lock with csq.
                                // A parent that died before `prctl` armed it
                                // is caught by the `getppid` comparison: the
                                // child exits instead of running orphaned.
                                #[cfg(any(target_os = "linux", target_os = "android"))]
                                {
                                    if libc::prctl(
                                        libc::PR_SET_PDEATHSIG,
                                        libc::SIGKILL as libc::c_ulong,
                                        0,
                                        0,
                                        0,
                                    ) == -1
                                    {
                                        return Err(io::Error::last_os_error());
                                    }
                                    if libc::getppid() != parent {
                                        libc::_exit(127);
                                    }
                                }
                                if libc::fcntl(fd, libc::F_GETFD) == -1 {
                                    return Err(io::Error::last_os_error());
                                }
                                // The descriptor must still name the file the
                                // scope recorded, checked BEFORE it is
                                // duplicated into the writer.
                                let mut st: libc::stat = std::mem::zeroed();
                                if libc::fstat(fd, &mut st) == -1 {
                                    return Err(io::Error::last_os_error());
                                }
                                if (st.st_dev, st.st_ino) != identity {
                                    return Err(io::Error::from_raw_os_error(
                                        LOCK_IDENTITY_MISMATCH_ERRNO,
                                    ));
                                }
                                // F_DUPFD (never F_DUPFD_CLOEXEC): the duplicate
                                // survives exec and shares the locked description.
                                if libc::fcntl(fd, libc::F_DUPFD, 3) == -1 {
                                    return Err(io::Error::last_os_error());
                                }
                                Ok(())
                            });
                        }
                    }
                }
                // Windows: the writer's job exists, kill-on-close, BEFORE the
                // spawn, and the writer is created SUSPENDED: it executes no
                // instruction until it is in the job, and only then are its
                // threads resumed. csq dying before the assignment leaves a
                // process that never runs; after it, the job's close kills it.
                #[cfg(windows)]
                let (child, job) = if role == ChildRole::Writer {
                    let (mut child, job) = spawn_suspended_in_job(command)?;
                    if let Err(error) = resume_threads(&child) {
                        // Fail closed: an unresumable writer is terminated
                        // (`Child::kill` is `TerminateProcess`) and reaped.
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error);
                    }
                    (child, Some(job))
                } else {
                    (command.spawn()?, None)
                };
                #[cfg(unix)]
                let child = command
                    .spawn()
                    .map_err(|e| writer_spawn_error(e, role, lock))?;
                #[cfg(not(any(unix, windows)))]
                let child = command.spawn()?;
                Ok(Self {
                    child,
                    reaped: false,
                    #[cfg(windows)]
                    _job: job,
                })
            }

            /// Whether this Windows writer is a member of its job (test
            /// inspection; `false` for a child with no job).
            #[cfg(all(test, windows))]
            pub(in super::super) fn in_writer_job(&self) -> io::Result<bool> {
                match &self._job {
                    Some(job) => job.contains(&self.child),
                    None => Ok(false),
                }
            }

            /// The child's pid (test inspection), as the PARENT observed it at
            /// spawn. The one race-free source for a test that needs it: a pid
            /// the child writes to a file cannot exist when a deadline kills
            /// the child before its first scheduling.
            #[cfg(all(test, unix))]
            pub(in super::super) fn id(&self) -> u32 {
                self.child.id()
            }

            pub(in super::super) fn take_stdin(&mut self) -> Option<ChildStdin> {
                self.child.stdin.take()
            }

            pub(in super::super) fn take_stdout(&mut self) -> Option<ChildStdout> {
                self.child.stdout.take()
            }

            pub(in super::super) fn take_stderr(&mut self) -> Option<ChildStderr> {
                self.child.stderr.take()
            }

            /// True once the child has exited. On Unix the exit is observed
            /// WITHOUT reaping, keeping the pid reserved for the group kill.
            pub(in super::super) fn exited(&mut self) -> io::Result<bool> {
                if self.reaped {
                    return Ok(true);
                }
                #[cfg(unix)]
                {
                    // SAFETY: a zeroed siginfo_t is valid; waitid with
                    // WNOHANG|WNOWAIT neither blocks nor consumes the exit
                    // status of this exclusively owned, unreaped child.
                    unsafe {
                        let mut info: libc::siginfo_t = std::mem::zeroed();
                        if libc::waitid(
                            libc::P_PID,
                            self.child.id() as libc::id_t,
                            &mut info,
                            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                        ) == -1
                        {
                            let error = io::Error::last_os_error();
                            return if error.kind() == io::ErrorKind::Interrupted {
                                Ok(false)
                            } else {
                                Err(error)
                            };
                        }
                        Ok(info.si_pid() != 0)
                    }
                }
                #[cfg(not(unix))]
                {
                    Ok(self.child.try_wait()?.is_some())
                }
            }

            /// Reap an exited child. Refuses a running one, so no wait blocks
            /// past a runner's deadline. After this call (whatever it returns)
            /// the pid may be reused, so `reaped` is set and neither `exited`
            /// nor `Drop` issues a `waitid` or `kill` for it again.
            pub(in super::super) fn wait(&mut self) -> io::Result<ExitStatus> {
                if !self.exited()? {
                    return Err(io::Error::other("repair child still running"));
                }
                let status = self.child.wait();
                self.reaped = true;
                status
            }
        }

        impl Drop for RepairChild {
            fn drop(&mut self) {
                if self.reaped {
                    return;
                }
                #[cfg(all(test, unix))]
                DROP_SIGNAL_PATHS.with(|count| count.set(count.get() + 1));
                #[cfg(unix)]
                {
                    // Err (ECHILD): no longer this process's unreaped child, so
                    // the pid may be reused and no signal is authorized. Ok:
                    // running or an unreaped zombie, so the pid is still
                    // reserved as this group's id.
                    if self.exited().is_err() {
                        return;
                    }
                    let group = self.child.id() as libc::pid_t;
                    // A group id <= 1 (including a wrapped negative) can never
                    // be a child's own group: `-group` would name init, every
                    // process, or a single pid. Refuse rather than signal it.
                    if group <= 1 {
                        return;
                    }
                    // SAFETY: `process_group(0)` made the child its own group
                    // leader before exec and the leader is unreaped; the
                    // negative pid targets only that group, never the caller's.
                    let killed = unsafe { libc::kill(-group, libc::SIGKILL) };
                    if killed == -1 {
                        // ESRCH: the group is gone. EPERM: Darwin's answer for a
                        // group whose leader already exited. Neither leaves a
                        // member this call can still signal; any other error
                        // falls back to the leader alone.
                        let errno = io::Error::last_os_error().raw_os_error();
                        if !matches!(errno, Some(libc::ESRCH) | Some(libc::EPERM)) {
                            let _ = self.child.kill();
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    if !matches!(self.child.try_wait(), Ok(None)) {
                        return;
                    }
                    if self.child.kill().is_err() {
                        return;
                    }
                }
                let cleanup = std::time::Instant::now() + REPAIR_CHILD_CLEANUP_GRACE;
                while std::time::Instant::now() < cleanup {
                    if matches!(self.child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
    }

    /// Make an owned child pipe non-blocking so [`drain_repair_pipe`] never
    /// waits for EOF.
    #[cfg(unix)]
    fn set_repair_pipe_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
        let fd = pipe.as_raw_fd();
        // SAFETY: the descriptor belongs to an open, exclusively owned child
        // pipe; the flag change does not transfer its ownership.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags == -1 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Windows pipes are drained with a peek (`drain_repair_pipe`), which never
    /// blocks, so there is no mode to change.
    #[cfg(windows)]
    fn set_repair_pipe_nonblocking<T>(_pipe: &T) -> io::Result<()> {
        Ok(())
    }

    /// Refuse a WRITE through a sqlite3 that does not stop at the first error.
    /// Every statement-failure safety argument in this module (a failed guard
    /// aborts before the writes, a failed write aborts before COMMIT) assumes
    /// `-bail` stops the shell, which was measured only on Apple 3.54.0 and
    /// Linux 3.45.1. This measures it on the binary about to write, once per
    /// (path, size, mtime); a probe that fails or cannot run refuses, and
    /// nothing falls back.
    fn ensure_stops_at_first_error(binary: &Path, db_path: &Path) -> Result<(), ShareError> {
        #[cfg(test)]
        if continue_past_errors() {
            // The defense-in-depth tests run the gates on a deliberately
            // continuing shell, past this probe.
            return Ok(());
        }
        let refuse = |detail: &str| ShareError::SqliteCommandFailed {
            binary: PathBuf::from(crate::cli_deps::sanitize::redact_path(binary)),
            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path)),
            detail: detail.to_owned(),
        };
        let Some(key) = bail_key(binary) else {
            return Err(refuse("sqlite3 write refused: binary cannot be inspected"));
        };
        if bail_cache().lock().is_ok_and(|cache| cache.contains(&key)) {
            return Ok(());
        }
        if !probe_stops_at_first_error(binary) {
            return Err(refuse(
                "sqlite3 write refused: -bail probe failed, this sqlite3 does not stop at the first error",
            ));
        }
        if let Ok(mut cache) = bail_cache().lock() {
            cache.insert(key);
        }
        Ok(())
    }

    /// Test fixtures that are not sqlite3 (hung, flooding, committing children)
    /// are declared probed so the runner under test still spawns them.
    #[cfg(all(test, unix))]
    pub(super) fn trust_bail_for_test(binary: &Path) {
        if let Some(key) = bail_key(binary) {
            bail_cache().lock().unwrap().insert(key);
        }
    }

    /// Only the guards (which abort before any write) are positively pre-commit,
    /// and only when the guard is the ONLY error `raw` carries: a failed
    /// BEGIN IMMEDIATE or a write error before it can leave earlier statements
    /// committed on a shell that kept going. Any other failure of the script is
    /// not pre-commit.
    pub(super) fn merge_failure_is_pre_commit(
        raw_detail: &Option<String>,
        mapped: &ShareError,
    ) -> bool {
        raw_detail
            .as_deref()
            .is_some_and(|detail| only_named_guard_failure(detail, "csq_merge_", true))
            && matches!(
                mapped,
                ShareError::SqliteChangedDuringMerge { .. }
                    | ShareError::SqliteForeignKeyViolation { .. }
            )
    }

    /// True only when `stderr` shows NOTHING but failures of the named guard
    /// (`CHECK constraint failed: <prefix>...`), plus, when
    /// `allow_no_transaction`, the `COMMIT` that then finds the transaction
    /// already rolled back. Any other error line (a failed BEGIN, a UNIQUE
    /// violation, a locked database) means a write may have landed, so the run is
    /// NOT a known rollback.
    pub(super) fn only_named_guard_failure(
        stderr: &str,
        prefix: &str,
        allow_no_transaction: bool,
    ) -> bool {
        let named = format!("CHECK constraint failed: {prefix}");
        let mut seen = false;
        for line in stderr.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if line.contains(&named) {
                seen = true;
            } else if !(allow_no_transaction
                && line.contains("cannot commit - no transaction is active"))
            {
                return false;
            }
        }
        seen
    }

    /// `-bail`, which stops the sqlite3 shell at the first error.
    #[cfg(not(test))]
    fn bail_flag() -> Option<&'static str> {
        Some("-bail")
    }

    /// Test seam: emulate a sqlite3 build that keeps executing past an error
    /// (Windows and `CSQ_SQLITE3` builds are unmeasured) by dropping `-bail`.
    #[cfg(test)]
    fn bail_flag() -> Option<&'static str> {
        (!continue_past_errors()).then_some("-bail")
    }

    #[cfg(test)]
    fn continue_past_errors() -> bool {
        TEST_CONTINUE_PAST_ERRORS.with(|cell| cell.get())
    }

    #[cfg(test)]
    thread_local! {
        static TEST_CONTINUE_PAST_ERRORS: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    #[cfg(test)]
    thread_local! {
        static TEST_RECORDED_SCRIPTS: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    /// One call per sqlite3 child spawned by either runner (test builds only).
    #[cfg(test)]
    fn record_script(script: &str) {
        TEST_RECORDED_SCRIPTS.with(|cell| cell.borrow_mut().push(script.to_owned()));
    }

    /// Scripts this thread's runners spawned since the last call, in order.
    #[cfg(test)]
    pub(super) fn take_recorded_scripts() -> Vec<String> {
        TEST_RECORDED_SCRIPTS.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
    }

    #[cfg(all(test, unix))]
    thread_local! {
        static TEST_SPAWNED_PIDS: std::cell::RefCell<Vec<u32>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    /// One call per sqlite3 child the MERGE and REPAIR runners spawn (test
    /// builds only). This is the runner's own record of the child it created.
    /// A pid the CHILD writes to a file is a different source with a different
    /// failure mode: under load the deadline can kill a child before its first
    /// scheduling, so the file never exists (CI: `fixture leader pid:
    /// NotFound`, r9_merge_runner_stdin_write_is_bounded). The parent observed
    /// the pid at spawn, so it cannot race with the child's execution.
    #[cfg(all(test, unix))]
    fn record_spawned_pid(pid: u32) {
        TEST_SPAWNED_PIDS.with(|cell| cell.borrow_mut().push(pid));
    }

    /// The pid of the last child this thread's merge/repair runners spawned,
    /// or None when the call refused BEFORE spawning (an expired pre-spawn
    /// budget). Never fed by the read-only probe path.
    ///
    /// TAKES the whole record: the runner records at most one spawn per call,
    /// so an entry can never carry over into a later loop iteration or a later
    /// call on this thread. More than one entry is a broken invariant, not a
    /// value to pick from.
    #[cfg(all(test, unix))]
    pub(super) fn take_last_spawned_pid() -> Option<u32> {
        let pids = TEST_SPAWNED_PIDS.with(|cell| std::mem::take(&mut *cell.borrow_mut()));
        assert!(
            pids.len() <= 1,
            "the runner spawn record holds one pid per call; found {}",
            pids.len()
        );
        pids.into_iter().next()
    }

    /// Run `f` with `-bail` dropped from every runner on this thread.
    #[cfg(test)]
    pub(super) fn with_continue_past_errors<T>(f: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                TEST_CONTINUE_PAST_ERRORS.with(|cell| cell.set(false));
            }
        }
        TEST_CONTINUE_PAST_ERRORS.with(|cell| cell.set(true));
        let _reset = Reset;
        f()
    }

    /// Split a generated script into complete statements, one per element.
    /// A `;` terminates a statement only outside `'...'`, `"..."`, `` `...` ``
    /// and `[...]` quoting (a doubled quote stays inside its literal). Trailing
    /// text without a `;` is kept as a final statement; blank pieces are dropped.
    ///
    /// Refuses, so the caller never spawns: a `--` or `/*` comment outside
    /// quotes (a quote or `;` inside a comment would mis-split the script), a
    /// quote, bracket or backtick still open at the end, any piece whose
    /// first non-space character is `.` (sqlite3 would run it as a shell
    /// dot-command: `.shell`, `.system`, `.load`), a line that is only `go` or
    /// `/` (the shell reading stdin ends a statement there, and the next line
    /// could then be a dot-command), a line starting with `#` (the shell
    /// skips it), and a `CREATE [TEMP] TRIGGER` piece: a trigger body holds
    /// `;`, so it would split into fragments that are each complete SQL.
    pub(super) fn split_sql_statements(script: &str) -> Result<Vec<String>, String> {
        fn refuse_unsplittable(piece: &str) -> Result<(), String> {
            let piece = piece.trim_start();
            if piece.starts_with('.') {
                return Err("sql statement starts with a sqlite3 dot-command".to_owned());
            }
            let mut words = piece.split_whitespace().map(str::to_ascii_uppercase);
            let mut first = words.next();
            if first.as_deref() == Some("EXPLAIN") {
                first = words.next();
                if first.as_deref() == Some("QUERY") {
                    words.next(); // PLAN
                    first = words.next();
                }
            }
            if first.as_deref() == Some("CREATE") {
                let mut next = words.next();
                if matches!(next.as_deref(), Some("TEMP" | "TEMPORARY")) {
                    next = words.next();
                }
                if next.as_deref() == Some("TRIGGER") {
                    return Err("a trigger body cannot be split into statements".to_owned());
                }
            }
            Ok(())
        }
        fn refuse_shell_line(line: &str) -> Result<(), String> {
            let line = line.trim();
            if line == "/" || line.eq_ignore_ascii_case("go") || line.starts_with('#') {
                return Err("sql line is a sqlite3 shell terminator or comment".to_owned());
            }
            Ok(())
        }
        let mut out = Vec::new();
        let mut current = String::new();
        let mut line = String::new();
        // A line that begins inside a quoted literal is data, not shell input.
        let mut line_is_sql = true;
        let mut closer: Option<char> = None;
        let mut chars = script.chars().peekable();
        while let Some(c) = chars.next() {
            current.push(c);
            if c == '\n' {
                if line_is_sql && closer.is_none() {
                    refuse_shell_line(&line)?;
                }
                line.clear();
                line_is_sql = closer.is_none();
            } else {
                line.push(c);
            }
            match closer {
                Some(end) if c == end => closer = None,
                Some(_) => {}
                None => match c {
                    '\'' | '"' | '`' => closer = Some(c),
                    '[' => closer = Some(']'),
                    '-' if chars.peek() == Some(&'-') => {
                        return Err("sql comment is not allowed in a split script".to_owned());
                    }
                    '/' if chars.peek() == Some(&'*') => {
                        return Err("sql comment is not allowed in a split script".to_owned());
                    }
                    ';' => {
                        if current.trim() != ";" {
                            refuse_unsplittable(&current)?;
                            out.push(std::mem::take(&mut current));
                        }
                        current.clear();
                        // The runners join pieces with a newline, so text that
                        // followed this `;` on the same line starts a new line.
                        line.clear();
                        line_is_sql = true;
                    }
                    _ => {}
                },
            }
        }
        if closer.is_some() {
            return Err("sql script ends inside an open quote or bracket".to_owned());
        }
        if line_is_sql {
            refuse_shell_line(&line)?;
        }
        if !current.trim().is_empty() {
            refuse_unsplittable(&current)?;
            out.push(current);
        }
        Ok(out)
    }

    /// The `PRAGMA busy_timeout` every generated write script sets, in
    /// milliseconds — the ONE wait a spawned child is ENFORCED to perform on
    /// the shared database's lock. Named once so the SQL and the budget
    /// derivation below cannot drift apart: a budget smaller than this kills a
    /// contended-but-healthy step while it is still waiting inside SQLite's own
    /// enforced bound.
    pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

    /// Tolerance for one spawned `sqlite3` child's own work — process start,
    /// argv transport, the bounded reads, and a small write's COMMIT — plus the
    /// caller's filesystem allowance before the first child. A TOLERANCE, not a
    /// bound: no enforced limit bounds scheduler or disk latency, which is why
    /// it carries `csq-artifact-evidence.md`'s "typical case, never a worst
    /// case" posture. The measured slow-host case (a slow host's stage disk:
    /// a bare `sqlite3 x.db "create table t(a)"` in ~1-2s under load) sits well
    /// inside it.
    pub const CODEX_REPAIR_READ_TOLERANCE_MS: u64 = 4_000;

    /// Per-step allowance for the launch repair, DERIVED from the two terms
    /// above — no measured term:
    ///
    /// ```text
    /// CODEX_REPAIR_STEP_BUDGET = SQLITE_BUSY_TIMEOUT_MS   (5_000: enforced by
    ///                                                      every generated
    ///                                                      write script's
    ///                                                      PRAGMA busy_timeout)
    ///                          + CODEX_REPAIR_READ_TOLERANCE_MS (4_000: the
    ///                                                      child's own work and
    ///                                                      the caller's pre-step
    ///                                                      allowance)
    ///                          = 9_000 ms
    /// ```
    ///
    /// Every spawned STEP (one `sqlite3` child) runs under a window of at least
    /// this much from the moment it starts, so it can always wait out the busy
    /// timeout its own script enforces and still finish its work: a
    /// slow-but-progressing host completes the repair, while a hung child is
    /// killed at its step bound and its database's repair refuses instead of
    /// extending any wait. The caller's allowance bounds admission, discovery
    /// and walks; the launch bound is this repair's own arithmetic, never a
    /// fixed wall-clock cap. The runner's direct API keeps its strict
    /// expired-deadline refusal; a caller's budget is only re-armed around
    /// children the repair is about to spawn.
    pub const CODEX_REPAIR_STEP_BUDGET_MS: u64 =
        SQLITE_BUSY_TIMEOUT_MS + CODEX_REPAIR_READ_TOLERANCE_MS;

    /// [`CODEX_REPAIR_STEP_BUDGET_MS`] as a `Duration`.
    pub const CODEX_REPAIR_STEP_BUDGET: std::time::Duration =
        std::time::Duration::from_millis(CODEX_REPAIR_STEP_BUDGET_MS);

    /// The budget one about-to-spawn step runs under: the caller's budget, or a
    /// fresh [`CODEX_REPAIR_STEP_BUDGET`] window from now when that is closer.
    fn step_budget(deadline: std::time::Instant) -> std::time::Instant {
        deadline.max(std::time::Instant::now() + CODEX_REPAIR_STEP_BUDGET)
    }

    /// [`CODEX_REPAIR_READ_TOLERANCE_MS`] as a `Duration`.
    const CODEX_REPAIR_READ_TOLERANCE: std::time::Duration =
        std::time::Duration::from_millis(CODEX_REPAIR_READ_TOLERANCE_MS);

    /// The budget the caller-side work over ONE returned page runs under: the
    /// current budget, or a fresh [`CODEX_REPAIR_READ_TOLERANCE`] window from
    /// the moment the page read returned when that is later. Without it, the
    /// in-process walk of a page is charged to the window of the child that
    /// produced it, so a child that finished late inside its own enforced step
    /// window would leave its page no time to be walked. The paged walk also
    /// re-arms it after every acknowledged write batch, and the exact route
    /// arms it for its row walk and transcript filename search.
    fn page_budget(deadline: std::time::Instant) -> std::time::Instant {
        deadline.max(std::time::Instant::now() + CODEX_REPAIR_READ_TOLERANCE)
    }

    /// Launch-only runner. SQL is fed on stdin, one statement per line, and
    /// never appears in argv (so `ps` never shows it, and a dead csq means
    /// EOF on the script). The script is written non-blocking from the runner's
    /// own loop ([`StdinFeeder`]), so no blocked stdin writer can hold the call
    /// past the caller's budget; on Windows the feeder's writer thread ends
    /// when the deadline kill closes the pipe. Each owned output pipe has
    /// exactly one reader; finite reads never wait for EOF.
    /// Unix embedding requires stable SIGCHLD disposition and sole ownership of
    /// waits for these children. Unsafe auto-reap policies refuse before spawn.
    pub(super) fn run_repair_sqlite_bounded(
        binary: &Path,
        db_path: &Path,
        script: &str,
        readonly: bool,
        deadline: std::time::Instant,
    ) -> Result<String, ShareError> {
        run_repair_sqlite_bounded_tracking(binary, db_path, script, readonly, deadline, &mut false)
    }

    // Track whether a write might have committed. Pre-spawn refusals remain
    // known-not-committed; a named paged guard aborts before the final COMMIT.
    pub(super) fn run_repair_sqlite_bounded_tracking(
        binary: &Path,
        db_path: &Path,
        script: &str,
        readonly: bool,
        deadline: std::time::Instant,
        commit_unknown: &mut bool,
    ) -> Result<String, ShareError> {
        *commit_unknown = false;
        use std::time::{Duration, Instant};
        let error = |detail: &str| ShareError::SqliteCommandFailed {
            binary: PathBuf::from(crate::cli_deps::sanitize::redact_path(binary)),
            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path)),
            detail: detail.to_owned(),
        };
        if Instant::now() >= deadline {
            return Err(error(ROLLOUT_REPAIR_DEADLINE_DETAIL));
        }
        // A writer's script ends with a per-run marker it must print (M1).
        let marker = (!readonly).then(writer_end_marker);
        let mut sent = format!("PRAGMA trusted_schema=OFF;\n{script}");
        if let Some(marker) = &marker {
            sent.push('\n');
            sent.push_str(&writer_end_statement(marker));
        }
        // One launch-time step stays small: the generators batch at
        // `PAGED_BATCH_BYTES`, and anything far above that is refused before
        // spawn rather than handed to a child under the launch budget.
        if sent.len() > REPAIR_SCRIPT_CAP {
            return Err(error("rollout repair SQL size limit"));
        }
        let db_arg = if readonly {
            readonly_db_arg(db_path)?
        } else {
            db_path.as_os_str().to_owned()
        };
        let stdin_script = split_sql_statements(&sent)
            .map_err(|detail| error(&format!("rollout repair {detail}")))?
            .join("\n");
        #[cfg(unix)]
        if !repair_child_wait_policy_safe() {
            return Err(error("rollout repair unsafe SIGCHLD disposition"));
        }
        if !readonly {
            ensure_stops_at_first_error(binary, db_path)?;
        }
        let null_rc = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut command = Command::new(binary);
        command.args(["-init", null_rc, "-batch", "-noheader", "-list"]);
        command.args(bail_flag());
        if readonly {
            command.arg("-readonly");
        }
        // Do not use binary_supports_safe_flag: its generic probe is unbounded.
        command.arg(db_arg);
        // One statement PER LINE on stdin. Measured: Apple's sqlite3 3.54.0
        // reports a statement that fails at run time (a CHECK) and keeps
        // executing the rest of the SAME line (or argv argument), so a failed
        // named guard was followed by the UPDATEs and the COMMIT; `-bail` does
        // stop between lines on that build and on Linux sqlite3 3.45.1, and
        // `ensure_stops_at_first_error` measured exactly this shape on this
        // binary above. Windows sqlite3 was not measured. Every
        // generated UPDATE/INSERT is additionally predicated on ALL of its
        // transaction's guards (`gate_exists`; the paged batch and the merge emit
        // every guard before the first write), so a failed guard voids the
        // writes even on a shell that keeps going. The merge FK guard necessarily
        // follows its writes and is `INSERT OR ROLLBACK`, which makes the final
        // `COMMIT` fail instead.
        #[cfg(test)]
        record_script(script);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Own process group, so a timed-out step is killed with every
        // descendant it forked; a writer also inherits the migration lock and
        // refuses to spawn without it (see `RepairChild::spawn`).
        let role = if readonly {
            ChildRole::Reader
        } else {
            ChildRole::Writer
        };
        let mut child = RepairChild::spawn(&mut command, role).map_err(|e| {
            error(writer_spawn_refusal_detail(&e).unwrap_or("rollout repair spawn failed"))
        })?;
        #[cfg(all(test, unix))]
        record_spawned_pid(child.id());
        *commit_unknown = !readonly;
        let stdin = child.take_stdin().ok_or_else(|| error("missing stdin"))?;
        let mut output = child.take_stdout().ok_or_else(|| error("missing stdout"))?;
        let mut errors = child.take_stderr().ok_or_else(|| error("missing stderr"))?;
        if set_repair_pipe_nonblocking(&output).is_err()
            || set_repair_pipe_nonblocking(&errors).is_err()
        {
            return Err(error("rollout repair pipe setup failed"));
        }
        let mut feeder = StdinFeeder::start(stdin, stdin_script.into_bytes())
            .map_err(|_| error("rollout repair script delivery failed"))?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out_eof = false;
        let mut err_eof = false;
        loop {
            if Instant::now() >= deadline {
                return Err(error(ROLLOUT_REPAIR_DEADLINE_DETAIL));
            }
            feeder
                .pump()
                .map_err(|_| error("rollout repair script delivery failed"))?;
            drain_repair_pipe(&mut output, &mut stdout, &mut out_eof, REPAIR_IO_CAP)
                .map_err(|_| error("rollout repair stdout limit or read failure"))?;
            drain_repair_pipe(&mut errors, &mut stderr, &mut err_eof, REPAIR_IO_CAP)
                .map_err(|_| error("rollout repair stderr limit or read failure"))?;
            // Observe the exit without reaping (`RepairChild::exited`): until
            // both pipes reach EOF a descendant may still hold one, and the
            // drop's group kill needs the leader's pid still reserved.
            if out_eof
                && err_eof
                && child
                    .exited()
                    .map_err(|_| error("rollout repair wait failed"))?
            {
                let status = child
                    .wait()
                    .map_err(|_| error("rollout repair wait failed"))?;
                if !status.success() {
                    // -bail stops at this generated guard before COMMIT
                    // (measured on Apple 3.54.0 and Linux 3.45.1 only; every
                    // write is also gated) and closing SQLite rolls back the
                    // still-open transaction.
                    // Other child failures retain the conservative unknown.
                    let guard_failure = String::from_utf8_lossy(&stderr);
                    if status.code().is_some()
                        && only_named_guard_failure(&guard_failure, "csq_paged_", false)
                    {
                        *commit_unknown = false;
                    }
                    let detail = crate::cli_deps::sanitize::redact_home_anywhere(
                        &crate::error::redact_tokens(String::from_utf8_lossy(&stderr).trim()),
                    );
                    return Err(error(&format!(
                        "rollout repair exit {:?}: {detail}",
                        status.code()
                    )));
                }
                // A shell that exited 0 without taking the whole script did
                // not run it: fail closed, and the commit stays unknown.
                // `finish` proves only that the bytes were written to the
                // pipe (a launch script fits one pipe buffer), so a writer
                // must ALSO have printed its end marker, which only the
                // script's last statement prints.
                if !feeder.finish() {
                    return Err(error("rollout repair script not fully delivered"));
                }
                let stdout = String::from_utf8(stdout)
                    .map_err(|_| error("rollout repair output is not UTF-8"))?;
                let stdout = match &marker {
                    Some(marker) => strip_writer_end_marker(&stdout, marker)
                        .ok_or_else(|| error(WRITER_NOT_FULLY_EXECUTED_DETAIL))?,
                    None => stdout,
                };
                *commit_unknown = false;
                return Ok(stdout);
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(2)),
            );
        }
    }

    #[cfg(unix)]
    fn drain_repair_pipe(
        reader: &mut impl std::io::Read,
        bytes: &mut Vec<u8>,
        eof: &mut bool,
        cap: usize,
    ) -> io::Result<()> {
        let mut buf = [0; 4096];
        for _ in 0..8 {
            match reader.read(&mut buf) {
                Ok(0) => {
                    *eof = true;
                    break;
                }
                Ok(n) => {
                    if bytes.len() + n > cap {
                        return Err(io::Error::other("output cap"));
                    }
                    bytes.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn drain_repair_pipe(
        reader: &mut (impl std::io::Read + std::os::windows::io::AsRawHandle),
        bytes: &mut Vec<u8>,
        eof: &mut bool,
        cap: usize,
    ) -> io::Result<()> {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let mut buf = [0; 4096];
        for _ in 0..8 {
            let mut available = 0;
            // SAFETY: the handle is an open, exclusively owned read end of an
            // anonymous child pipe. No other thread reads or operates on it.
            // Peek and the following bounded read execute on the same thread.
            let ok = unsafe {
                PeekNamedPipe(
                    reader.as_raw_handle() as _,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::BrokenPipe {
                    *eof = true;
                    break;
                }
                return Err(e);
            }
            if available == 0 {
                break;
            }
            let count = (available as usize).min(buf.len());
            let n = reader.read(&mut buf[..count])?;
            if n == 0 {
                *eof = true;
                break;
            }
            if bytes.len() + n > cap {
                return Err(io::Error::other("output cap"));
            }
            bytes.extend_from_slice(&buf[..n]);
        }
        Ok(())
    }

    /// Run `script` against `db_path` via the resolved `sqlite3` binary,
    /// hermetically: cleared environment (minus a minimal `PATH`, in case
    /// the vendored `sqlite3` itself needs to resolve a shared library
    /// helper), no shell, argv only. Returns stdout as-is; a non-zero exit
    /// is a hard error naming the binary, the db path, and stderr.
    pub(super) fn run_sqlite3(
        binary: &Path,
        db_path: &Path,
        script: &str,
    ) -> Result<String, ShareError> {
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

    /// Percent-encodes a path for an SQLite `file:` URI: every byte outside
    /// the RFC 3986 unreserved set and `/` is escaped, so `?`, `#`, `%` and
    /// spaces in a path can never be read as URI syntax.
    fn sqlite_uri_path(path: &Path) -> String {
        let mut out = String::new();
        for b in path.as_os_str().as_encoded_bytes() {
            match *b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                    out.push(*b as char)
                }
                other => out.push_str(&format!("%{other:02X}")),
            }
        }
        out
    }

    /// How a READ-ONLY inspection names the database to `sqlite3`.
    ///
    /// codex keeps its databases in WAL mode, and SQLite deletes the
    /// `-wal`/`-shm` pair when the last connection closes. A `-readonly`
    /// connection cannot create `-shm`, so it fails with "unable to open
    /// database file" on exactly the database state `csq sessions share`
    /// runs against — every codex session closed. Measured 2026-09-30: a
    /// real codex `state_5.sqlite` copy with no sidecars → `SQLITE_CANTOPEN`
    /// under `-readonly`, 425 rows read without it.
    ///
    /// - `-shm` present: the plain path (normal read-only WAL reader).
    /// - no `-wal` and no `-journal`: every committed page is in the main
    ///   file, so `immutable=1` reads it exactly and never writes a sidecar.
    /// - `-wal` without `-shm`, or a leftover `-journal`: only a crash leaves
    ///   either; reading past them could miss or half-read a transaction, so
    ///   refuse and say how to recover.
    fn readonly_db_arg(db_path: &Path) -> Result<OsString, ShareError> {
        let sidecar = |suffix: &str| {
            let mut p = db_path.as_os_str().to_os_string();
            p.push(suffix);
            PathBuf::from(p)
        };
        if sidecar("-shm").exists() {
            return Ok(db_path.as_os_str().to_os_string());
        }
        if !sidecar("-wal").exists() && !sidecar("-journal").exists() {
            return Ok(OsString::from(format!(
                "file:{}?immutable=1",
                sqlite_uri_path(db_path)
            )));
        }
        Err(ShareError::SqliteCommandFailed {
            binary: PathBuf::from("sqlite3"),
            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path)),
            detail: "an unfinished write was left behind (a -wal without its -shm, or a \
                     -journal) — codex did not shut down cleanly. Start codex on this slot \
                     once and quit so SQLite recovers it, then re-run"
                .to_string(),
        })
    }

    fn run_sqlite3_with(
        binary: &Path,
        db_path: &Path,
        script: &str,
        readonly: bool,
    ) -> Result<String, ShareError> {
        let deadline = std::time::Instant::now() + MERGE_SQLITE_BUDGET;
        run_sqlite3_with_deadline(binary, db_path, script, readonly, deadline)
    }

    /// The merge runner's enforced per-invocation bound (an enforced cap, not
    /// a measurement): script delivery, exit and output drain share this one
    /// window, after which the child's process group is killed. Generous on
    /// purpose, so it ends a wedged child rather than a slow merge.
    const MERGE_SQLITE_BUDGET: std::time::Duration = std::time::Duration::from_secs(300);

    /// The merge runner's deadline detail.
    pub(super) const MERGE_SQLITE_DEADLINE_DETAIL: &str = "sqlite3 deadline";

    /// The merge runner's retained-output cap per pipe. Larger than the launch
    /// runner's [`REPAIR_IO_CAP`]: merge-side reads list whole tables.
    const MERGE_IO_CAP: usize = 256 * 1024 * 1024;

    /// [`run_sqlite3_with`] under an explicit `deadline`.
    pub(super) fn run_sqlite3_with_deadline(
        binary: &Path,
        db_path: &Path,
        script: &str,
        readonly: bool,
        deadline: std::time::Instant,
    ) -> Result<String, ShareError> {
        use std::time::{Duration, Instant};
        if !readonly {
            ensure_stops_at_first_error(binary, db_path)?;
        }
        let db_arg = if readonly {
            readonly_db_arg(db_path)?
        } else {
            db_path.as_os_str().to_os_string()
        };
        let mut command = Command::new(binary);
        // `-bail` (C-F6): without it, sqlite3 keeps executing a script's
        // remaining statements after one fails, so a failed `INSERT ...
        // SELECT *` can be followed by a `COMMIT` that lands a HALF-merged
        // transaction (the sibling `UPDATE`, but not the `INSERT`) while csq
        // reports an error. `-bail` stops the shell at the first error
        // (measured: Apple 3.54.0 only when the next statement is on its own
        // line, which the script splitter below guarantees), before that
        // `COMMIT` line is ever reached; the transaction's
        // BEGIN never lands a commit record, so closing the connection with
        // it still open lets SQLite's own crash-recovery / uncommitted-
        // transaction discard drop it entirely.
        // `-init /dev/null`: with the environment cleared, sqlite3 still finds
        // the user's home via getpwuid and loads `~/.sqliterc`, whose
        // `.separator` / `.mode` would change the `-list` output every caller
        // here parses. No rc file is ever read.
        let empty_rc = if cfg!(windows) { "NUL" } else { "/dev/null" };
        command.args(["-init", empty_rc, "-batch", "-noheader", "-list"]);
        command.args(bail_flag());
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
        // S-L3 / M3: prepended to EVERY sqlite3 invocation this module makes
        // — read-only or not. `PRAGMA trusted_schema=OFF` does NOT stop a
        // trigger from firing or a view from being read (doc-property-claims.md
        // MUST-1: name the mechanism, and this is not it) — the allowlisted
        // `threads_*` triggers DO fire during a merge, by design. The precise
        // mechanism: it blocks any SQL function or virtual table NOT flagged
        // `SQLITE_INNOCUOUS` (SQLite's own "safe to invoke from an untrusted
        // context" marker) from being INVOKED from inside a schema-defined
        // object — a trigger body, a view, a `CHECK` or `DEFAULT` expression,
        // a generated column — refusing anything else at the engine level.
        // That is a narrower, independent defense alongside
        // `forbid_untrusted_schema_objects`'s explicit name+checksum
        // allowlist, not a substitute for it: this pragma is applied to
        // every invocation, including the read-only inspection queries that
        // run BEFORE `forbid_untrusted_schema_objects` itself gets to look.
        let mut sent = String::with_capacity(script.len() + 32);
        sent.push_str("PRAGMA trusted_schema=OFF;\n");
        sent.push_str(script);
        // One statement per line: measured on Apple's sqlite3 3.54.0, `-bail`
        // does not stop at a run-time failure (a CHECK guard) when the next
        // statement is on the SAME line, and the rest of that line still runs.
        let redacted_binary = || PathBuf::from(crate::cli_deps::sanitize::redact_path(binary));
        let redacted_path = || PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path));
        let script = split_sql_statements(&sent)
            .map_err(|detail| ShareError::SqliteCommandFailed {
                binary: redacted_binary(),
                path: redacted_path(),
                detail,
            })?
            .join("\n");
        #[cfg(test)]
        record_script(&script);
        // A writer's script ends with a per-run marker it must print (M1);
        // appended after recording, so recorded scripts stay the generated SQL.
        let marker = (!readonly).then(writer_end_marker);
        let script = match &marker {
            Some(marker) => format!("{script}\n{}", writer_end_statement(marker)),
            None => script,
        };
        // S-L4 / operator-surface-verification.md Rule 1: neither the
        // path nor the binary this error names may leak the operator's
        // full `$HOME`-rooted host path, and sqlite3's own stderr is
        // attacker- or corruption-influenced content that must not reach
        // an operator surface un-redacted.
        let fail = |detail: String| ShareError::SqliteCommandFailed {
            binary: redacted_binary(),
            path: redacted_path(),
            detail,
        };
        // The child is observed with `waitid(WNOWAIT)` (`RepairChild`): an
        // auto-reaping SIGCHLD policy refuses before spawn.
        #[cfg(unix)]
        if !repair_child_wait_policy_safe() {
            return Err(fail("unsafe SIGCHLD disposition".to_string()));
        }
        if Instant::now() >= deadline {
            return Err(fail(MERGE_SQLITE_DEADLINE_DETAIL.to_string()));
        }
        command
            .arg(&db_arg)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Own process group: a deadline kills the shell together with its
        // descendants. A writer inherits the migration lock and refuses to
        // spawn without it (see `RepairChild::spawn`).
        let role = if readonly {
            ChildRole::Reader
        } else {
            ChildRole::Writer
        };
        let mut child =
            RepairChild::spawn(&mut command, role).map_err(
                |e| match writer_spawn_refusal_detail(&e) {
                    Some(detail) => fail(detail.to_string()),
                    None => fail(format!("spawn: {e}")),
                },
            )?;
        #[cfg(all(test, unix))]
        record_spawned_pid(child.id());
        let stdin = child
            .take_stdin()
            .ok_or_else(|| fail("missing stdin".to_string()))?;
        let mut output = child
            .take_stdout()
            .ok_or_else(|| fail("missing stdout".to_string()))?;
        let mut errors = child
            .take_stderr()
            .ok_or_else(|| fail("missing stderr".to_string()))?;
        if set_repair_pipe_nonblocking(&output).is_err()
            || set_repair_pipe_nonblocking(&errors).is_err()
        {
            return Err(fail("pipe setup failed".to_string()));
        }
        // The script is fed without ever blocking past `deadline`: a child
        // that stops reading stdin can no longer wedge this call on a full
        // pipe buffer.
        let mut feeder = StdinFeeder::start(stdin, script.into_bytes())
            .map_err(|e| fail(format!("write script: {e}")))?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out_eof = false;
        let mut err_eof = false;
        let status = loop {
            if Instant::now() >= deadline {
                return Err(fail(MERGE_SQLITE_DEADLINE_DETAIL.to_string()));
            }
            feeder
                .pump()
                .map_err(|e| fail(format!("write script: {e}")))?;
            drain_repair_pipe(&mut output, &mut stdout, &mut out_eof, MERGE_IO_CAP)
                .map_err(|_| fail("stdout limit or read failure".to_string()))?;
            drain_repair_pipe(&mut errors, &mut stderr, &mut err_eof, MERGE_IO_CAP)
                .map_err(|_| fail("stderr limit or read failure".to_string()))?;
            if out_eof && err_eof && child.exited().map_err(|e| fail(format!("wait: {e}")))? {
                break child.wait().map_err(|e| fail(format!("wait: {e}")))?;
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(2)),
            );
        };
        if !status.success() {
            // M3: `redact_tokens` alone catches SECRET-shaped substrings
            // (an `sk-ant-*` prefix, long hex); it does not touch a home-
            // rooted PATH sqlite3's own stderr can legitimately embed (an
            // `ATTACH DATABASE` failure names the attach path verbatim,
            // e.g. "unable to open database file: /Users/<name>/..."). Both
            // passes are required; `redact_home_anywhere` is the one that
            // finds a path occurring anywhere mid-sentence, not only at the
            // start of the string.
            let stderr = crate::cli_deps::sanitize::redact_home_anywhere(
                &crate::error::redact_tokens(String::from_utf8_lossy(&stderr).trim()),
            );
            return Err(fail(format!("exit {:?}: {stderr}", status.code())));
        }
        // A shell that exited 0 without taking the whole script did not run
        // it: fail closed rather than report a partial script as applied.
        // `finish` proves only that the bytes reached the pipe, so a writer
        // must also have printed its end marker (its script's last statement).
        if !feeder.finish() {
            return Err(fail("script not fully delivered".to_string()));
        }
        let stdout = String::from_utf8_lossy(&stdout).into_owned();
        match &marker {
            Some(marker) => strip_writer_end_marker(&stdout, marker)
                .ok_or_else(|| fail(WRITER_NOT_FULLY_EXECUTED_DETAIL.to_string())),
            None => Ok(stdout),
        }
    }

    /// Delivers a script to a child's stdin without blocking the caller past
    /// its deadline: non-blocking writes, pumped from the runner's loop. The
    /// pipe is closed (EOF ends the shell's input) once the script is written;
    /// a closed read end (the shell stopped reading, e.g. under `-bail`) ends
    /// delivery, which [`StdinFeeder::finish`] then reports as incomplete.
    #[cfg(unix)]
    struct StdinFeeder {
        pipe: Option<std::process::ChildStdin>,
        script: Vec<u8>,
        written: usize,
    }

    #[cfg(unix)]
    impl StdinFeeder {
        fn start(pipe: std::process::ChildStdin, script: Vec<u8>) -> io::Result<Self> {
            set_repair_pipe_nonblocking(&pipe)?;
            let mut feeder = Self {
                pipe: Some(pipe),
                script,
                written: 0,
            };
            feeder.pump()?;
            Ok(feeder)
        }

        fn pump(&mut self) -> io::Result<()> {
            let Some(pipe) = self.pipe.as_mut() else {
                return Ok(());
            };
            while self.written < self.script.len() {
                match pipe.write(&self.script[self.written..]) {
                    Ok(0) => return Ok(()),
                    Ok(n) => self.written += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                        self.pipe = None;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }
            }
            self.pipe = None;
            Ok(())
        }

        /// True only when every script byte was written into the pipe. That
        /// proves delivery to the pipe buffer, NOT that the child read or ran
        /// it; writers prove execution with their end marker instead.
        fn finish(self) -> bool {
            self.written == self.script.len()
        }
    }

    /// Windows anonymous pipes have no non-blocking write mode: a dedicated
    /// writer thread feeds the script, and the runner never waits on it past
    /// its deadline. A deadline kill of the child closes the pipe's read end,
    /// which fails the thread's blocked write and ends it.
    #[cfg(windows)]
    struct StdinFeeder {
        done: std::sync::mpsc::Receiver<bool>,
        delivered: Option<bool>,
    }

    #[cfg(windows)]
    impl StdinFeeder {
        fn start(mut pipe: std::process::ChildStdin, script: Vec<u8>) -> io::Result<Self> {
            let (sender, done) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name("csq-sqlite3-stdin".to_string())
                .spawn(move || {
                    let delivered = pipe.write_all(&script).is_ok();
                    drop(pipe);
                    // A gone receiver means the runner already gave up.
                    let _ = sender.send(delivered);
                })?;
            Ok(Self {
                done,
                delivered: None,
            })
        }

        fn pump(&mut self) -> io::Result<()> {
            if self.delivered.is_none() {
                if let Ok(delivered) = self.done.try_recv() {
                    self.delivered = Some(delivered);
                }
            }
            Ok(())
        }

        /// True only when the writer thread wrote every script byte into the
        /// pipe. That proves delivery to the pipe, NOT that the child read or
        /// ran it; writers prove execution with their end marker instead.
        fn finish(mut self) -> bool {
            if self.delivered.is_none() {
                self.delivered = self.done.recv_timeout(REPAIR_CHILD_CLEANUP_GRACE).ok();
            }
            self.delivered == Some(true)
        }
    }

    /// Single-quote-escape a path for interpolation into an `ATTACH DATABASE`
    /// statement. Our own generated tempdir/config-dir paths never legitimately
    /// contain a `'`, but the escape costs nothing and removes the question.
    /// M3: `Path::display()` is LOSSY for a non-UTF-8 path — invalid bytes
    /// are silently replaced with U+FFFD, which means the SQL literal this
    /// produces can name a DIFFERENT path than the one the caller intended,
    /// with no error raised anywhere. Refuse rather than mangle: only a
    /// path that round-trips through `&str` is quoted.
    fn sql_quote_path(path: &Path) -> Result<String, ShareError> {
        let Some(s) = path.to_str() else {
            return Err(ShareError::SqliteUnsafeAttachPath {
                path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
            });
        };
        Ok(s.replace('\'', "''"))
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
                path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
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

    /// The outcome of this process's one `-safe` probe.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum SafeFlagProbe {
        /// The probe ran to completion: whether `-help` advertises `-safe`.
        Completed(bool),
        /// The probe timed out or could not run: unknown for this process.
        /// Never read as a completed "unsupported" answer.
        Unknown,
    }

    /// Whether the resolved `sqlite3` binary's `-help` output advertises
    /// `-safe`. Probed AT MOST ONCE per process (the binary is resolved once
    /// and reused for the whole migration run), so neither the merge's normal
    /// path nor a binary whose probe keeps timing out costs a probe spawn per
    /// SQL call.
    static SAFE_FLAG_SUPPORTED: std::sync::OnceLock<SafeFlagProbe> = std::sync::OnceLock::new();

    /// A probe that timed out or could not run is recorded as
    /// [`SafeFlagProbe::Unknown`]: this and every later call in the process
    /// run `-readonly` without `-safe` and never probe again.
    fn binary_supports_safe_flag(binary: &Path) -> bool {
        supports_safe_flag_cached(&SAFE_FLAG_SUPPORTED, || probe_safe_flag(binary))
    }

    pub(super) fn supports_safe_flag_cached(
        cache: &std::sync::OnceLock<SafeFlagProbe>,
        probe: impl FnOnce() -> Option<bool>,
    ) -> bool {
        let outcome = cache.get_or_init(|| match probe() {
            Some(supported) => SafeFlagProbe::Completed(supported),
            None => SafeFlagProbe::Unknown,
        });
        matches!(outcome, SafeFlagProbe::Completed(true))
    }

    /// `None` when the probe could not run to completion.
    fn probe_safe_flag(binary: &Path) -> Option<bool> {
        // S-L4: env_clear so an inherited env var cannot change
        // `-help`'s wording (or, in principle, substitute a shared
        // library the resolved binary depends on) out from under the
        // `.contains("-safe")` check below.
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("-help")
            .stdin(Stdio::null());
        // Bounded like every other sqlite3 child (`PROBE_BUDGET`); a probe
        // that cannot finish returns `None`, which is never cached.
        let (stdout, stderr) = run_probe_capture(&mut command)?;
        // `-help`'s flag list may land on stdout or stderr depending on
        // the build; check both rather than assume one.
        Some(
            format!(
                "{}{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            )
            .contains("-safe"),
        )
    }

    /// Run a short probe child to completion under [`PROBE_BUDGET`], returning
    /// its stdout and stderr; `None` when it cannot spawn, overruns, or fails
    /// to drain (its process group is then killed by `RepairChild`'s drop).
    fn run_probe_capture(command: &mut Command) -> Option<(Vec<u8>, Vec<u8>)> {
        use std::time::{Duration, Instant};
        #[cfg(unix)]
        if !repair_child_wait_policy_safe() {
            return None;
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = RepairChild::spawn(command, ChildRole::Reader).ok()?;
        let mut output = child.take_stdout()?;
        let mut errors = child.take_stderr()?;
        set_repair_pipe_nonblocking(&output).ok()?;
        set_repair_pipe_nonblocking(&errors).ok()?;
        let deadline = Instant::now() + PROBE_BUDGET;
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            drain_repair_pipe(&mut output, &mut stdout, &mut out_eof, REPAIR_IO_CAP).ok()?;
            drain_repair_pipe(&mut errors, &mut stderr, &mut err_eof, REPAIR_IO_CAP).ok()?;
            if out_eof && err_eof && child.exited().ok()? {
                child.wait().ok()?;
                return Some((stdout, stderr));
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
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
        /// M1: the `.pre-merge-<epoch>-<pid>` backup taken before merging
        /// into an EXISTING shared database, so an operator can locate and
        /// restore it without having to guess a filename. `None` for every
        /// outcome that does not merge into an already-established shared
        /// DB (a dry run, `AlreadyShared`, `KeptPerSlot`, or the FIRST
        /// creation of the shared store, which has nothing yet to back up).
        pub backup_path: Option<PathBuf>,
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
            // S-F9: a `.merge-src` / `.pre-share-<epoch>` / `.pre-merge-<epoch>`
            // / `.new-share` scratch artifact left over from an earlier
            // failed run never carries the bare `SQLITE_SUFFIX` ending (it
            // is `state_5.sqlite.merge-src`, not `....sqlite`), so the
            // filter above already excludes it — this second check is
            // defense in depth against a future basename that happens to
            // end in one of these scratch suffixes.
            .filter(|name| {
                !name.contains(".merge-src")
                    && !name.contains(".pre-share-")
                    && !name.contains(".pre-merge-")
                    && !name.contains(".new-share")
            })
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
            // L1/M1: `detail` is sqlite3's own output describing a corrupt
            // or hand-modified file — attacker- or corruption-influenced
            // content, same posture as `run_sqlite3_with`'s stderr handling.
            Err(ShareError::SqliteIntegrityCheckFailed {
                basename: basename.to_string(),
                path: PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path)),
                detail: crate::cli_deps::sanitize::redact_home_anywhere(
                    &crate::error::redact_tokens(trimmed),
                ),
            })
        }
    }

    /// codex-cli's OWN triggers, by name and SHA-256 of the exact `sql` text
    /// stored in `sqlite_master`. These keep derived timestamp columns of the
    /// same `threads` row in step on insert/update; every codex `state_5`
    /// database carries them (measured on codex-cli 0.159.2, four slots,
    /// byte-identical). A trigger with any other name, or one of these names
    /// with any other body, is still refused — so is every view.
    const CODEX_OWN_TRIGGERS: &[(&str, &str)] = &[
        (
            "threads_created_at_ms_after_insert",
            "a2d069cabb0396cf00fe2275fdbd19cb259231a1aea82ecc3edf4935fd8d7c5c",
        ),
        (
            "threads_created_at_ms_after_update",
            "4508e1771b42e6a9e4332fefdf16c1f8960f74d3d298f718b28ef928875e5e76",
        ),
        (
            "threads_recency_at_after_insert",
            "f8b489d82385b398c81354d7aeb0041164ea33e1f800be327708190ee83cf276",
        ),
        (
            "threads_updated_at_ms_after_insert",
            "46df6b8634993fad2bb6b9243c6eccb696eb659fb304039d5d9f5f95c2267fa1",
        ),
        (
            "threads_updated_at_ms_after_update",
            "4d54241e85f63e2c7db6ab7454238f367ebc89501ebfacad8bc790fdaf508595",
        ),
    ];

    /// S-L3: refuses a database that carries a `view`, or a `trigger` that
    /// is not one of codex-cli's own ([`CODEX_OWN_TRIGGERS`], matched by
    /// name AND the SHA-256 of its exact SQL), in `sqlite_master`. Anything
    /// else is evidence of a hand-modified or malicious file.
    ///
    /// The previous version refused EVERY trigger on the premise that
    /// codex-cli never creates one; codex-cli does, so the merge refused
    /// every real database while its fixtures (which had no triggers)
    /// passed.
    ///
    /// This is the module's chosen answer to "seed the shared DB from
    /// schema-plus-`threads`-rows only, OR refuse any input whose
    /// `sqlite_master` contains a trigger or view": REFUSE, rather than
    /// reimplement a schema-only seed. `copy_db_with_sidecars` (the
    /// existing seed path for a brand-new shared DB) copies the WHOLE
    /// file, including any view/trigger. `PRAGMA trusted_schema=OFF;`
    /// (prepended to every invocation, [`run_sqlite3_with`]) does NOT stop
    /// an untrusted trigger from firing or a view from being queried — it
    /// only narrows which SQL functions a schema object may call — so it is
    /// no defense at all against a trigger/view silently riding into the
    /// canonical shared store as present, ACTIVE schema. Refusing here is
    /// fail-closed and costs nothing on the path that matters — a genuine
    /// codex-cli `threads` database has no legitimate reason to carry
    /// anything beyond the five allowlisted triggers.
    fn forbid_untrusted_schema_objects(
        binary: &Path,
        basename: &str,
        db_path: &Path,
    ) -> Result<Vec<String>, ShareError> {
        let out = run_sqlite3_readonly(
            binary,
            db_path,
            // Every field hex-encoded: a trigger body spans lines (which
            // would split this line-oriented `-list` output) and a name may
            // contain `|`.
            &format!("SELECT {SCHEMA_OBJECT_ROW_EXPR} FROM sqlite_master WHERE type IN ('trigger','view');"),
        )?;
        validate_schema_objects(basename, db_path, &out)
    }

    fn validate_schema_objects(
        basename: &str,
        db_path: &Path,
        out: &str,
    ) -> Result<Vec<String>, ShareError> {
        let rows: Vec<String> = out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        let decode = |h: &str| hex::decode(h).ok().and_then(|b| String::from_utf8(b).ok());
        let untrusted = rows.iter().find(|line| {
            let mut f = line.splitn(3, '|');
            let (kind, name, sql_hex) = (
                f.next().unwrap_or(""),
                f.next().unwrap_or(""),
                f.next().unwrap_or(""),
            );
            let (Some(kind), Some(name), Ok(sql)) =
                (decode(kind), decode(name), hex::decode(sql_hex))
            else {
                return true;
            };
            if kind != "trigger" {
                return true;
            }
            let digest = hex::encode(Sha256::digest(&sql));
            !CODEX_OWN_TRIGGERS
                .iter()
                .any(|(n, h)| *n == name && *h == digest)
        });
        if let Some(line) = untrusted {
            let mut fields = line.splitn(3, '|');
            // S-L6 / operator-surface-verification.md Rule 1: the path must
            // not leak the operator's full `$HOME`-rooted host path, exactly
            // like every other error this module raises from sqlite3
            // output. `object_type`/`object_name` come from `sqlite_master`
            // in a file this branch has just determined is hand-modified or
            // malicious, so they are attacker-influenced content too —
            // `redact_tokens` on principle, same as `run_sqlite3_with`'s
            // stderr handling.
            let object_type = crate::error::redact_tokens(
                &fields
                    .next()
                    .and_then(decode)
                    .unwrap_or_else(|| "object".to_string()),
            );
            let object_name = crate::error::redact_tokens(
                &fields
                    .next()
                    .and_then(decode)
                    .unwrap_or_else(|| "?".to_string()),
            );
            return Err(ShareError::SqliteUntrustedSchemaObject {
                basename: basename.to_string(),
                path: PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path)),
                object_type,
                object_name,
            });
        }
        Ok(rows)
    }

    /// One `sqlite_master` trigger/view as text: type, name and sql all
    /// hex-encoded, joined by `|`. The merge transaction's guard rebuilds
    /// the same value to assert the destination's trigger/view set is
    /// exactly the one verified.
    const SCHEMA_OBJECT_ROW_EXPR: &str = "hex(type)||'|'||hex(name)||'|'||hex(sql)";

    /// `None` when the database has no `_sqlx_migrations` table (older
    /// codex-cli); `Some(rows)` otherwise, one row's columns per line,
    /// ordered so two databases with the identical migration set produce
    /// identical strings.
    /// Migrations applied, from a [`migrations_signature`] value: one row per
    /// line; no `_sqlx_migrations` table at all counts as zero.
    fn migration_count(sig: &Option<String>) -> usize {
        sig.as_deref()
            .map_or(0, |s| s.lines().filter(|l| !l.trim().is_empty()).count())
    }

    /// L2: composes the explanatory half of [`ShareError::SqliteMigrationsMismatch`],
    /// distinguishing three genuinely different situations a bare count
    /// comparison collapses into one sentence:
    ///
    /// - one side has NO `_sqlx_migrations` table at all (`None`) — a
    ///   codex-cli generation that predates the table entirely, not merely
    ///   "behind" the other side;
    /// - both sides have the table but a DIFFERENT NUMBER of migrations
    ///   applied — the ordinary "one slot hasn't been opened in a while"
    ///   case;
    /// - both sides have applied the SAME NUMBER of migrations, but with
    ///   different checksums — the two databases were created by different
    ///   codex-cli BUILDS at the same migration count, which `a_count` vs
    ///   `b_count` alone cannot even show as a difference.
    ///
    /// M2: `shared_path` used to justify "never opened directly by
    /// codex-cli" for the shared index — false once ANY slot is linked to
    /// it: codex opens the shared database THROUGH that slot's symlink and
    /// can migrate it there. The hint below is chosen by which SIDE is
    /// actually behind, not by treating "one side is shared" as its own
    /// case: if the BEHIND side is the shared index, point the operator at
    /// an already-shared slot (there is no per-slot path that names the
    /// shared index directly); if the behind side is a plain per-slot copy,
    /// name it directly.
    pub(super) fn migrations_mismatch_note(
        a_path: &Path,
        b_path: &Path,
        shared_path: &Path,
        a_sig: &Option<String>,
        b_sig: &Option<String>,
    ) -> String {
        let a_is_shared = a_path == shared_path;
        let b_is_shared = b_path == shared_path;
        let hint_for_behind_side = |behind_is_shared: bool| -> &'static str {
            if behind_is_shared {
                "start codex once on any slot already linked to the shared index (`csq run \
                 <slot>` on one of them, then quit) — that session opens the shared database \
                 THROUGH the symlink and migrates it in place"
            } else {
                "start codex once on that copy (`csq run <slot>`, then quit) so codex upgrades \
                 its own database"
            }
        };
        match (a_sig, b_sig) {
            (None, Some(s)) | (Some(s), None) => {
                let a_is_none = a_sig.is_none();
                let behind_is_shared = if a_is_none { a_is_shared } else { b_is_shared };
                let hint = hint_for_behind_side(behind_is_shared);
                let other = if s.trim().is_empty() {
                    "has a `_sqlx_migrations` table recording zero migrations"
                } else {
                    "has a `_sqlx_migrations` table"
                };
                format!(
                    "One database has no `_sqlx_migrations` table at all (a codex-cli \
                     generation that predates it), while the other {other} — these are not \
                     comparable schema generations. csq does not upgrade codex's database for \
                     it: {hint}, then re-run."
                )
            }
            (Some(_), Some(_)) if migration_count(a_sig) != migration_count(b_sig) => {
                let a_count = migration_count(a_sig);
                let b_count = migration_count(b_sig);
                let behind_is_shared = if a_count < b_count {
                    a_is_shared
                } else {
                    b_is_shared
                };
                let hint = hint_for_behind_side(behind_is_shared);
                format!(
                    "{a_count} vs {b_count} migrations applied. csq does not upgrade codex's \
                     database for it: {hint}, then re-run."
                )
            }
            _ => format!(
                "Both have applied the same NUMBER of migrations ({}) but with different \
                 checksums — they were created by different codex-cli BUILDS, not different \
                 migration states. Open codex once on each slot involved (so each is running \
                 the same codex-cli build) and quit, then re-run.",
                migration_count(a_sig),
            ),
        }
    }

    /// One `_sqlx_migrations` row as text, EVERY field hex-encoded and the
    /// fields joined by `|` (which hex digits cannot contain), so no value
    /// can collide with the separator. Used both to print the signature and
    /// to rebuild the same value inside the merge transaction's guard.
    /// A NULL field is `N`, a present one `V<hex>`, so NULL and an empty
    /// value (both `hex() = ''`) stay distinct.
    const MIGRATION_ROW_EXPR: &str =
        "CASE WHEN version IS NULL THEN 'N' ELSE 'V'||hex(version) END\
         ||'|'||CASE WHEN checksum IS NULL THEN 'N' ELSE 'V'||hex(checksum) END\
         ||'|'||CASE WHEN success IS NULL THEN 'N' ELSE 'V'||hex(success) END";

    pub(super) fn migrations_signature(
        binary: &Path,
        db_path: &Path,
    ) -> Result<Option<String>, ShareError> {
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
            // The migration's IDENTITY only. `SELECT *` also carried
            // `installed_on` and `execution_time`, which differ in every
            // database that applied the same migration, so any two real codex
            // databases compared unequal; and the raw `checksum` BLOB printed
            // across several lines. hex() keeps each migration on one line.
            &format!("SELECT {MIGRATION_ROW_EXPR} FROM _sqlx_migrations ORDER BY version;"),
        )?;
        Ok(Some(rows))
    }

    fn checkpoint_truncate(binary: &Path, db_path: &Path) -> Result<(), ShareError> {
        run_sqlite3(binary, db_path, "PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Every merged DB / working copy / backup this module creates gets
    /// 0600 explicitly, rather than whatever `fs::copy` / `fs::rename`
    /// happened to preserve or the process umask produced — matching
    /// `security.md` MUST-5's posture for credential files, applied here to
    /// the cross-slot session store. H3: a chmod FAILURE here is an ERROR,
    /// not a best-effort `let _ =` — a credential-bearing (this store holds
    /// codex session content) file left at a permissive mode is exactly the
    /// class `security.md` MUST-5 exists to prevent, so "the chmod call ran"
    /// is not good enough; "the file IS 0600" must be confirmed. No-op
    /// (`Ok(())`) on Windows, where POSIX modes do not apply.
    #[cfg(unix)]
    fn secure_sqlite_paths(main: &Path) -> Result<(), ShareError> {
        use std::os::unix::fs::PermissionsExt;
        if test_chmod_failure_forced() {
            return Err(ShareError::io(
                main,
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TEST INPUT: injected chmod failure",
                ),
            ));
        }
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", main.display()));
            if !p.exists() {
                continue;
            }
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600))
                .map_err(|e| ShareError::io(&p, e))?;
        }
        Ok(())
    }
    #[cfg(windows)]
    fn secure_sqlite_paths(_main: &Path) -> Result<(), ShareError> {
        Ok(())
    }

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
        secure_sqlite_paths(dst)?;
        Ok(())
    }

    /// FORWARD move of `src` (and its `-wal`/`-shm` sidecars, if present) to
    /// `dst` with the same suffix scheme: `original → .pre-share-*` and
    /// `tmp_shared → shared_path`. Each individual `rename_noreplace` is
    /// atomic, but the three (main + two sidecars) are not atomic AS A GROUP.
    /// The opposite direction (backup → original) is `restore_one`, driven by
    /// the [`MoveRecord`] this returns; it never undoes anything.
    ///
    /// A forward move NEVER replaces anything: if `dst` or either of its
    /// sidecar destinations already exists the call refuses before moving a
    /// byte. That is what makes the undo below sound — it is only ever
    /// undoing moves onto names that were empty.
    ///
    /// FM-12(B)/N1: if a sidecar rename or the chmod fails after the main
    /// file (or an earlier sidecar) already moved, the moves already made by
    /// THIS call are undone: the MAIN file first, then the sidecars. If the
    /// main file cannot be moved back, the sidecars are LEFT beside it at
    /// `dst` (moving a `-wal` away from its main file would strand it) and
    /// the error names every failure. The CALLER treats such an error as
    /// [`ShareError::SqliteSharedCommittedSlotsUnlinked`] since it cannot
    /// prove nothing happened. Test seam: `set_test_force_chmod_failure_at_call`.
    pub(super) fn rename_db_with_sidecars(src: &Path, dst: &Path) -> Result<(), ShareError> {
        forward_move(src, dst).1
    }

    /// EXACTLY what a forward move left at `dst`: the main file and which
    /// sidecars. It is the only input a restore needs — nothing is inferred
    /// from the filesystem. After a failure it holds what is STILL at `dst`
    /// once the undo has run (empty when the move was refused or fully undone).
    #[derive(Default, Clone, Debug)]
    pub(super) struct MoveRecord {
        pub(super) main_moved: bool,
        pub(super) sidecars: Vec<&'static str>,
    }

    /// [`rename_db_with_sidecars`] plus its [`MoveRecord`], on success and on
    /// failure.
    pub(super) fn forward_move(src: &Path, dst: &Path) -> (MoveRecord, Result<(), ShareError>) {
        let mut record = MoveRecord::default();
        for suffix in ["", "-wal", "-shm"] {
            let d = PathBuf::from(format!("{}{suffix}", dst.display()));
            if d.symlink_metadata().is_ok() {
                if !suffix.is_empty() && dst.symlink_metadata().is_err() {
                    return (
                        record,
                        Err(ShareError::SqliteStraySidecar {
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(dst)),
                            stray: PathBuf::from(crate::cli_deps::sanitize::redact_path(&d)),
                        }),
                    );
                }
                return (
                    record,
                    Err(ShareError::io(
                        &d,
                        io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "refusing to replace an existing file with a moved database",
                        ),
                    )),
                );
            }
        }
        run_test_before_forward_rename_hook(dst);
        if let Err(e) = rename_noreplace(src, dst) {
            return (record, Err(ShareError::io(src, e)));
        }
        record.main_moved = true;
        run_test_after_main_move_hook(dst);
        for suffix in ["-wal", "-shm"] {
            let src_side = PathBuf::from(format!("{}{suffix}", src.display()));
            if src_side.exists() {
                let dst_side = PathBuf::from(format!("{}{suffix}", dst.display()));
                if let Err(e) = rename_noreplace(&src_side, &dst_side) {
                    let problems = undo_move(src, dst, &mut record);
                    return (
                        record,
                        Err(ShareError::io(
                            &src_side,
                            io::Error::new(
                                e.kind(),
                                if problems.is_empty() {
                                    e.to_string()
                                } else {
                                    format!("{e}; undo also failed: {}", problems.join("; "))
                                },
                            ),
                        )),
                    );
                }
                record.sidecars.push(suffix);
            }
        }
        run_test_before_secure_hook(src, dst);
        if let Err(e) = secure_sqlite_paths(dst) {
            let problems = undo_move(src, dst, &mut record);
            if !problems.is_empty() {
                return (
                    record,
                    Err(ShareError::io(
                        dst,
                        io::Error::other(format!(
                            "chmod failed ({e}) AND undoing the rename back to {} also failed \
                             ({}) — the file may now be at either path; check both",
                            crate::cli_deps::sanitize::redact_path(src),
                            problems.join("; ")
                        )),
                    )),
                );
            }
            return (record, Err(e));
        }
        (record, Ok(()))
    }

    /// Renames `src` to `dst`, refusing (never replacing) if `dst` exists:
    /// the existence check and the rename are ONE atomic syscall where the
    /// platform has one (`renamex_np(RENAME_EXCL)` on macOS,
    /// `renameat2(RENAME_NOREPLACE)` on Linux, `MoveFileExW` without
    /// `MOVEFILE_REPLACE_EXISTING` on Windows — `std::fs::rename` replaces
    /// on Windows). Android keeps the fallback: libc types its
    /// `RENAME_NOREPLACE` differently and defines `SYS_renameat2` only for
    /// some architectures, and that target is not compile-checked here.
    /// Where the syscall or the filesystem lacks support
    /// (`ENOSYS`/`EINVAL`), or on another unix, it falls back to a
    /// check-then-rename, which can lose a race with a creator of `dst`
    /// between the two steps.
    fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let to_c = |p: &Path| {
                std::ffi::CString::new(p.as_os_str().as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
            };
            let (s, d) = (to_c(src)?, to_c(dst)?);
            #[cfg(target_os = "macos")]
            // SAFETY: both are valid NUL-terminated strings for the call.
            let rc = unsafe { libc::renamex_np(s.as_ptr(), d.as_ptr(), libc::RENAME_EXCL) };
            #[cfg(target_os = "linux")]
            // SAFETY: both are valid NUL-terminated strings for the call.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    s.as_ptr(),
                    libc::AT_FDCWD,
                    d.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as i32
            };
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                if rc == 0 {
                    return Ok(());
                }
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(c) if c == libc::ENOSYS || c == libc::EINVAL || c == libc::ENOTSUP => {}
                    _ => return Err(err),
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            let _ = (&s, &d);
            if dst.symlink_metadata().is_ok() {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            fs::rename(src, dst)
        }
        #[cfg(windows)]
        {
            let (s, d) = (windows_wide_path(src)?, windows_wide_path(dst)?);
            // SAFETY: both are valid NUL-terminated UTF-16 strings; flags 0 =
            // no MOVEFILE_REPLACE_EXISTING, so an existing `dst` is refused.
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::MoveFileExW(s.as_ptr(), d.as_ptr(), 0)
            };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// The verbatim (`\\?\`) form of a Win32 path, built from the ORIGINAL
    /// UTF-16 units (never via a lossy string), or `None` when the plain
    /// path must be used. Only an absolute drive (`C:\...`) or UNC
    /// (`\\server\share\...`) path longer than 259 UTF-16 units qualifies,
    /// and only when it is already in the form the verbatim prefix would
    /// leave unchanged: no `/`, no repeated separator, no `.`/`..`
    /// component, and no component ending in a space or dot (Win32 would
    /// have normalised those away; the verbatim form would not). Anything
    /// else is left to the plain call, which fails closed on a long path.
    #[cfg(any(windows, test))]
    pub(super) fn verbatim_wide(units: &[u16]) -> Option<Vec<u16>> {
        const MAX_PATH_NO_PREFIX: usize = 259;
        let bs = u16::from(b'\\');
        let enc = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        if units.len() <= MAX_PATH_NO_PREFIX
            || units.starts_with(&enc(r"\\?\"))
            || units.starts_with(&enc(r"\\.\"))
            || units.contains(&u16::from(b'/'))
        {
            return None;
        }
        let (rest, mut out): (&[u16], Vec<u16>) = if units.len() > 2
            && u8::try_from(units[0]).is_ok_and(|b| b.is_ascii_alphabetic())
            && units[1] == u16::from(b':')
            && units[2] == bs
        {
            (&units[3..], enc(r"\\?\"))
        } else if units.starts_with(&[bs, bs]) {
            (&units[2..], enc(r"\\?\UNC\"))
        } else {
            return None;
        };
        let comps: Vec<&[u16]> = rest.split(|u| *u == bs).collect();
        for (i, c) in comps.iter().enumerate() {
            let last = i + 1 == comps.len();
            let dot = [u16::from(b'.')];
            let bad = (c.is_empty() && !last)
                || *c == dot
                || *c == [dot[0], dot[0]]
                || c.last()
                    .is_some_and(|u| *u == dot[0] || *u == u16::from(b' '));
            if bad {
                return None;
            }
        }
        if out.ends_with(&enc("UNC\\")) {
            out.extend_from_slice(rest);
        } else {
            out.extend_from_slice(&units[..3]);
            out.extend_from_slice(rest);
        }
        Some(out)
    }

    /// NUL-terminated UTF-16 for a Win32 call: refuses a path with an
    /// embedded NUL (it would silently truncate the name) and uses
    /// [`verbatim_wide`] for long paths.
    #[cfg(windows)]
    fn windows_wide_path(p: &Path) -> io::Result<Vec<u16>> {
        use std::os::windows::ffi::OsStrExt;
        let units: Vec<u16> = p.as_os_str().encode_wide().collect();
        if units.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains an embedded NUL",
            ));
        }
        let mut out = verbatim_wide(&units).unwrap_or(units);
        out.push(0);
        Ok(out)
    }

    #[cfg(test)]
    type TestPathHook = std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>>;
    #[cfg(test)]
    type TestPathPairHook = std::cell::RefCell<Option<Box<dyn FnMut(&Path, &Path)>>>;

    #[cfg(test)]
    thread_local! {
        static TEST_BEFORE_FORWARD_RENAME_HOOK: TestPathHook = const { std::cell::RefCell::new(None) };
        static TEST_BEFORE_SECURE_HOOK: TestPathPairHook = const { std::cell::RefCell::new(None) };
        static TEST_BEFORE_ROLLBACK_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
    }

    /// Test seam: runs when a rollback starts, before any restore.
    fn run_test_before_rollback_hook() {
        #[cfg(test)]
        TEST_BEFORE_ROLLBACK_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook();
            }
        });
    }

    #[cfg(all(test, unix))]
    pub(super) fn set_test_before_rollback_hook(hook: impl FnMut() + 'static) {
        TEST_BEFORE_ROLLBACK_HOOK.with(|c| *c.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(all(test, unix))]
    pub(super) fn clear_test_before_rollback_hook() {
        TEST_BEFORE_ROLLBACK_HOOK.with(|c| *c.borrow_mut() = None);
    }

    /// Test seam: runs after a forward move's pre-check, before its rename.
    fn run_test_before_forward_rename_hook(_dst: &Path) {
        #[cfg(test)]
        TEST_BEFORE_FORWARD_RENAME_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_dst);
            }
        });
    }

    /// Test seam: runs after every move of a forward move, before the chmod.
    fn run_test_before_secure_hook(_src: &Path, _dst: &Path) {
        #[cfg(test)]
        TEST_BEFORE_SECURE_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_src, _dst);
            }
        });
    }

    #[cfg(test)]
    pub(super) fn set_test_before_forward_rename_hook(hook: impl FnMut(&Path) + 'static) {
        TEST_BEFORE_FORWARD_RENAME_HOOK.with(|c| *c.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn clear_test_before_forward_rename_hook() {
        TEST_BEFORE_FORWARD_RENAME_HOOK.with(|c| *c.borrow_mut() = None);
    }

    #[cfg(all(test, unix))]
    pub(super) fn set_test_before_secure_hook(hook: impl FnMut(&Path, &Path) + 'static) {
        TEST_BEFORE_SECURE_HOOK.with(|c| *c.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(all(test, unix))]
    pub(super) fn clear_test_before_secure_hook() {
        TEST_BEFORE_SECURE_HOOK.with(|c| *c.borrow_mut() = None);
    }

    #[cfg(test)]
    type TestAfterMainMoveHook = std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>>;

    #[cfg(test)]
    thread_local! {
        static TEST_AFTER_MAIN_MOVE_HOOK: TestAfterMainMoveHook = const { std::cell::RefCell::new(None) };
    }

    /// Test seam: runs right after a forward move's main-file rename.
    fn run_test_after_main_move_hook(_dst: &Path) {
        #[cfg(test)]
        TEST_AFTER_MAIN_MOVE_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_dst);
            }
        });
    }

    #[cfg(test)]
    pub(super) fn set_test_after_main_move_hook(hook: impl FnMut(&Path) + 'static) {
        TEST_AFTER_MAIN_MOVE_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn clear_test_after_main_move_hook() {
        TEST_AFTER_MAIN_MOVE_HOOK.with(|cell| *cell.borrow_mut() = None);
    }

    /// Undoes a forward move, updating `record` to what is STILL at `dst`:
    /// the MAIN file first (no-replace), then the sidecars in reverse. If the
    /// main file cannot be moved back, the sidecars stay beside it. Returns
    /// every problem.
    fn undo_move(src: &Path, dst: &Path, record: &mut MoveRecord) -> Vec<String> {
        let mut problems = Vec::new();
        if record.main_moved {
            match rename_noreplace(dst, src) {
                Ok(()) => record.main_moved = false,
                Err(e) => {
                    problems.push(format!("main file: {e}"));
                    if !record.sidecars.is_empty() {
                        problems.push(format!(
                            "sidecar(s) {} left beside the main file at {}",
                            record.sidecars.join(", "),
                            crate::cli_deps::sanitize::redact_path(dst)
                        ));
                    }
                    return problems;
                }
            }
        }
        for suffix in record.sidecars.clone().into_iter().rev() {
            let s = PathBuf::from(format!("{}{suffix}", src.display()));
            let d = PathBuf::from(format!("{}{suffix}", dst.display()));
            match rename_noreplace(&d, &s) {
                Ok(()) => record.sidecars.retain(|x| *x != suffix),
                Err(e) => problems.push(format!("{suffix}: {e}")),
            }
        }
        problems
    }

    /// The per-slot backup path `<original>.pre-share-<epoch>`, advancing
    /// `epoch` until neither it nor its sidecars exist, so a re-run in the
    /// same second never collides with an earlier backup. The suffix stays
    /// all-digit: recovery of stranded backups parses it as a bare epoch.
    pub(super) fn fresh_pre_share_path(original: &Path, epoch: u64) -> Result<PathBuf, ShareError> {
        fresh_pre_share_path_with_limit(original, epoch, FRESH_PRE_SHARE_MAX_ATTEMPTS)
    }

    /// Upper bound on how many names [`fresh_pre_share_path`] will try.
    const FRESH_PRE_SHARE_MAX_ATTEMPTS: u64 = 10_000;

    pub(super) fn fresh_pre_share_path_with_limit(
        original: &Path,
        epoch: u64,
        limit: u64,
    ) -> Result<PathBuf, ShareError> {
        for e in epoch..epoch.saturating_add(limit) {
            let candidate = PathBuf::from(format!("{}.pre-share-{e}", original.display()));
            let taken = ["", "-wal", "-shm"].iter().any(|sfx| {
                PathBuf::from(format!("{}{sfx}", candidate.display()))
                    .symlink_metadata()
                    .is_ok()
            });
            if !taken {
                return Ok(candidate);
            }
        }
        Err(ShareError::io(
            original,
            io::Error::other(format!(
                "no free `.pre-share-<epoch>` backup name after {limit} attempts"
            )),
        ))
    }

    // N1: a deterministic, cross-platform test seam for "chmod fails after
    // the rename already succeeded" — a genuine chmod failure (an
    // immutable-flag file, a foreign-owned file) is not reliably
    // reproducible in a test (and never reproducible at all when the test
    // runs as root, which ignores POSIX permission bits entirely), so this
    // flag lets a test FORCE `secure_sqlite_paths` to report failure
    // without touching the filesystem at all. COUNTED, not a blanket
    // on/off switch: `apply_basename_plan_with` calls `secure_sqlite_paths`
    // (via `copy_db_with_sidecars`/`rename_db_with_sidecars`) several times
    // in one run — the work-copy creation, the `tmp_shared` seed, the
    // first-creation rename, THEN the per-slot rename — so a blanket flag
    // would trip on the FIRST of these, never reaching the specific call a
    // test wants to target. Zero footprint outside `#[cfg(test)]` builds,
    // matching `force_list_running_processes`'s existing pattern for the
    // same class of otherwise-unreproducible failure.
    #[cfg(all(test, unix))]
    thread_local! {
        static TEST_CHMOD_CALL_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        static TEST_CHMOD_FAIL_AT_CALL: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    }

    /// Fails the `n`th call (1-indexed) to `secure_sqlite_paths` across the
    /// calling THREAD from this point on (the counters are thread-local);
    /// every other call succeeds
    /// normally. Resets the call counter, so tests do not have to account
    /// for calls made by earlier, unrelated test runs sharing this thread.
    #[cfg(all(test, unix))]
    pub(super) fn set_test_force_chmod_failure_at_call(n: u32) {
        TEST_CHMOD_CALL_COUNT.with(|c| c.set(0));
        TEST_CHMOD_FAIL_AT_CALL.with(|c| c.set(Some(n)));
    }

    #[cfg(all(test, unix))]
    pub(super) fn clear_test_force_chmod_failure() {
        TEST_CHMOD_FAIL_AT_CALL.with(|c| c.set(None));
        TEST_CHMOD_CALL_COUNT.with(|c| c.set(0));
    }

    // Only ever called from `secure_sqlite_paths`'s UNIX variant (Windows'
    // is a no-op that never calls it), so this is `#[cfg(unix)]` too —
    // otherwise a `cfg(test)` build on a non-Unix target would reference
    // `TEST_CHMOD_CALL_COUNT`/`TEST_CHMOD_FAIL_AT_CALL`, which only exist
    // under `cfg(all(test, unix))`.
    #[cfg(unix)]
    fn test_chmod_failure_forced() -> bool {
        #[cfg(test)]
        {
            let this_call = TEST_CHMOD_CALL_COUNT.with(|c| {
                let v = c.get() + 1;
                c.set(v);
                v
            });
            TEST_CHMOD_FAIL_AT_CALL.with(|c| c.get() == Some(this_call))
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// What a rollback could and could not put back.
    #[derive(Default)]
    struct RollbackReport {
        /// Each move that could NOT be undone, naming both paths and the
        /// error (already redacted).
        not_restored: Vec<String>,
        /// Things that were restored but with a problem (mode unconfirmed).
        caveats: Vec<String>,
    }

    /// Restores EXACTLY what `record` says was moved to `backup`, back to
    /// `original`, with no-replace moves: nothing already at `original` (a
    /// database, a sidecar) is ever replaced. An empty record (a refused or
    /// fully undone move) does nothing at all.
    ///
    /// Order: the MAIN file first, then the sidecars, and the sidecars only
    /// once the main file is back (otherwise they stay beside the backup's
    /// main file and are named). The one thing removed to make room is a
    /// symlink at `original` that points at `shared_path` — the link this
    /// run created — and only after the backup's main file is confirmed to
    /// exist; if the move then fails the link is put back with a real
    /// symlink (never a copy, never replacing anything). If that also fails
    /// the slot is named, so the outcome is always "back" or "named". A
    /// symlink pointing anywhere else is left alone and named.
    fn restore_one(
        original: &Path,
        backup: &Path,
        record: &MoveRecord,
        shared_path: &Path,
        report: &mut RollbackReport,
    ) {
        let red = crate::cli_deps::sanitize::redact_path;
        let mut main_ok = !record.main_moved;
        if record.main_moved {
            let mut removed_link = false;
            let mut blocked = false;
            if matches!(original.symlink_metadata(), Ok(m) if m.file_type().is_symlink()) {
                match fs::read_link(original) {
                    Ok(t) if same_link_target(&t, shared_path) => {
                        if backup.symlink_metadata().is_err() {
                            report.not_restored.push(format!(
                                "{} (the backup {} is missing; the link was left in place)",
                                red(original),
                                red(backup)
                            ));
                            blocked = true;
                        } else if let Err(e) = fs::remove_file(original) {
                            report.not_restored.push(format!(
                                "{} (could not remove its link: {e})",
                                red(original)
                            ));
                            blocked = true;
                        } else {
                            removed_link = true;
                            run_test_after_link_removed_hook(original);
                        }
                    }
                    _ => {
                        report.not_restored.push(format!(
                            "{} (a symlink that does not point at the shared index; left in place)",
                            red(original)
                        ));
                        blocked = true;
                    }
                }
            }
            if !blocked {
                match restore_rename(backup, original) {
                    Ok(()) => main_ok = true,
                    Err(e) => {
                        let mut msg = format!("{} (from {}): {e}", red(original), red(backup));
                        if removed_link {
                            match create_real_symlink(shared_path, original) {
                                Ok(()) => {
                                    msg.push_str("; its link to the shared index was put back")
                                }
                                Err(le) => msg.push_str(&format!(
                                    "; putting its link back ALSO failed: {le}"
                                )),
                            }
                        }
                        report.not_restored.push(msg);
                    }
                }
            }
        }
        for sfx in &record.sidecars {
            let (b, o) = (
                PathBuf::from(format!("{}{sfx}", backup.display())),
                PathBuf::from(format!("{}{sfx}", original.display())),
            );
            if !main_ok {
                report.not_restored.push(format!(
                    "{} (left beside the backup's main file at {}: the main file was not restored)",
                    red(&b),
                    red(backup)
                ));
            } else if let Err(e) = rename_noreplace(&b, &o) {
                report
                    .not_restored
                    .push(format!("{} (from {}): {e}", red(&o), red(&b)));
            }
        }
        if main_ok && record.main_moved {
            if let Err(e) = secure_sqlite_paths(original) {
                report.caveats.push(format!(
                    "{}: the restored file is in place but its owner-only mode (0600) could \
                     not be confirmed ({e})",
                    red(original)
                ));
            }
        }
    }

    /// Creates and removes a throwaway real symlink in `shared_dir` (pointing
    /// at a target that does not exist) to prove this host can make one.
    /// Refuses with the platform's own explanation (on Windows, Developer
    /// Mode / the symlink privilege) before anything has been written.
    pub(super) fn probe_symlink_capability(shared_dir: &Path) -> Result<(), ShareError> {
        fs::create_dir_all(shared_dir).map_err(|e| ShareError::io(shared_dir, e))?;
        // One fixed name, created and removed under the share lock, so a
        // probe link left behind by a run killed between the two steps is
        // reused rather than accumulating. Only a SYMLINK of that name is
        // ever removed; any other entry there is refused, never touched.
        let link = shared_dir.join(".csq-symlink-probe");
        let target = shared_dir.join(".csq-symlink-probe-target-absent");
        if let Ok(meta) = fs::symlink_metadata(&link) {
            let ours = meta.file_type().is_symlink()
                && fs::read_link(&link).is_ok_and(|t| same_link_target(&t, &target));
            if !ours {
                return Err(ShareError::io(
                    &link,
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "an entry that is not csq's own probe symlink occupies the probe \
                         name; move it aside and re-run",
                    ),
                ));
            }
            fs::remove_file(&link).map_err(|e| ShareError::io(&link, e))?;
        }
        #[cfg(test)]
        if TEST_FORCE_PROBE_FAILURE.with(|c| c.get()) {
            return Err(ShareError::io(
                shared_dir,
                io::Error::other("forced symlink-probe failure"),
            ));
        }
        create_real_symlink(&target, &link).map_err(|e| ShareError::io(shared_dir, e))?;
        fs::remove_file(&link).map_err(|e| ShareError::io(&link, e))
    }

    #[cfg(test)]
    thread_local! {
        static TEST_FORCE_PROBE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[cfg(test)]
    pub(super) fn set_test_force_probe_failure(on: bool) {
        TEST_FORCE_PROBE_FAILURE.with(|c| c.set(on));
    }

    /// A REAL symlink `link` → `target`, refusing an existing `link`, with no
    /// fallback: unlike `isolation::create_symlink_pub` on Windows it never
    /// degrades to a hard link or a COPY (a disconnected copy of the shared
    /// index would silently stop sharing). Without symlink permission on
    /// Windows the share is refused with a message saying what to enable.
    pub(super) fn create_real_symlink(target: &Path, link: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "could not create a symlink ({e}); sharing the codex index needs \
                         symlink permission on Windows — enable Developer Mode (or run with \
                         the symbolic-link privilege) and re-run"
                    ),
                )
            })
        }
    }

    /// String-level model of what [`same_link_target`] does on Windows:
    /// `\\?\C:\x` → `C:\x` and `\\?\UNC\s\x` → `\\s\x`, the form a Windows
    /// `read_link` may return. Test-only; production compares path
    /// components (no lossy strings) under `cfg(windows)`.
    #[cfg(test)]
    pub(super) fn normalize_verbatim(s: &str) -> String {
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{rest}")
        } else if let Some(rest) = s.strip_prefix(r"\\?\") {
            rest.to_string()
        } else {
            s.to_string()
        }
    }

    /// Whether a link's `read_link` target is `shared_path`, ignoring a
    /// verbatim prefix on either side.
    pub(super) fn same_link_target(a: &Path, b: &Path) -> bool {
        #[cfg(windows)]
        {
            use std::path::{Component, Prefix};
            // Compare OS-string components with a verbatim prefix mapped to
            // its plain form, so `\\?\C:\x` equals `C:\x`.
            let norm = |p: &Path| -> Vec<std::ffi::OsString> {
                p.components()
                    .map(|c| match c {
                        Component::Prefix(pc) => match pc.kind() {
                            Prefix::VerbatimDisk(d) | Prefix::Disk(d) => {
                                std::ffi::OsString::from(format!("{}:", d as char))
                            }
                            Prefix::VerbatimUNC(srv, sh) | Prefix::UNC(srv, sh) => {
                                let mut o = std::ffi::OsString::from(r"\\");
                                o.push(srv);
                                o.push(r"\");
                                o.push(sh);
                                o
                            }
                            _ => pc.as_os_str().to_os_string(),
                        },
                        other => other.as_os_str().to_os_string(),
                    })
                    .collect()
            };
            norm(a) == norm(b)
        }
        #[cfg(not(windows))]
        {
            a == b
        }
    }

    /// Test seam: runs right after the restore removed our link.
    fn run_test_after_link_removed_hook(_original: &Path) {
        #[cfg(test)]
        TEST_AFTER_LINK_REMOVED_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_original);
            }
        });
    }

    #[cfg(all(test, unix))]
    pub(super) fn set_test_after_link_removed_hook(hook: impl FnMut(&Path) + 'static) {
        TEST_AFTER_LINK_REMOVED_HOOK.with(|c| *c.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(all(test, unix))]
    pub(super) fn clear_test_after_link_removed_hook() {
        TEST_AFTER_LINK_REMOVED_HOOK.with(|c| *c.borrow_mut() = None);
    }

    /// The restore's main-file move (no-replace), with a test seam that can
    /// force it to fail.
    fn restore_rename(backup: &Path, original: &Path) -> io::Result<()> {
        #[cfg(test)]
        if TEST_FAIL_RESTORE_RENAME.with(|c| c.get()) {
            return Err(io::Error::other("forced restore failure"));
        }
        rename_noreplace(backup, original)
    }

    #[cfg(test)]
    thread_local! {
        static TEST_FAIL_RESTORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static TEST_AFTER_LINK_REMOVED_HOOK: TestPathHook = const { std::cell::RefCell::new(None) };
        static TEST_RECOVERY_FAIL_AT: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
        static TEST_RECOVERY_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    #[cfg(all(test, unix))]
    pub(super) fn set_test_fail_restore_rename(on: bool) {
        TEST_FAIL_RESTORE_RENAME.with(|c| c.set(on));
    }

    #[cfg(test)]
    pub(super) fn set_test_recovery_fail_at(calls: &[u32]) {
        TEST_RECOVERY_CALLS.with(|c| c.set(0));
        TEST_RECOVERY_FAIL_AT.with(|c| *c.borrow_mut() = calls.to_vec());
    }

    /// C-R4-12 / S-F6: the single rollback routine every error exit from
    /// the per-entry rename loop in `apply_basename_plan_with` goes through.
    /// Each entry carries the [`MoveRecord`] of what its forward move left at
    /// the backup path; `current` is the entry whose own move was attempted
    /// but whose link did not follow. Only recorded files are moved back,
    /// and a move that fails is named in the report, never retried or undone.
    fn rollback_renamed(
        renamed_so_far: &[(PathBuf, PathBuf, MoveRecord)],
        current: Option<(&Path, &Path, &MoveRecord)>,
        shared_path: &Path,
    ) -> RollbackReport {
        run_test_before_rollback_hook();
        let mut report = RollbackReport::default();
        if let Some((original, backup, record)) = current {
            restore_one(original, backup, record, shared_path, &mut report);
        }
        for (original, backup, record) in renamed_so_far.iter().rev() {
            restore_one(original, backup, record, shared_path, &mut report);
        }
        report
    }

    fn remove_db_with_sidecars(path: &Path) {
        let _ = fs::remove_file(path);
        for suffix in ["-wal", "-shm"] {
            let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", path.display())));
        }
    }

    /// M1: `<epoch>-<pid>`, so two `csq sessions share` invocations landing
    /// within the same wall-clock second never contend for the same
    /// `.pre-merge-<suffix>` backup path.
    fn backup_suffix() -> String {
        format!("{}-{}", now_epoch_secs(), std::process::id())
    }

    /// H3: creates `dir` with mode 0700, set ATOMICALLY as part of the
    /// `mkdir` syscall itself (`DirBuilder::mode`), never as a separate
    /// `chmod` after a default-mode `create_dir` — the latter leaves a real
    /// window, however short, during which the directory exists at a more
    /// permissive mode.
    /// `create_new`-style semantics come from the caller choosing a name
    /// `mkdir` has not seen before (see [`backup_via_vacuum_into`]); this
    /// function itself simply fails if `dir` already exists.
    #[cfg(unix)]
    fn create_private_dir(dir: &Path) -> Result<(), ShareError> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .map_err(|e| ShareError::io(dir, e))
    }
    #[cfg(windows)]
    fn create_private_dir(dir: &Path) -> Result<(), ShareError> {
        // Windows access control is ACL-based, not a POSIX mode. This
        // creates the directory with the parent directory's inherited
        // ACLs, which in the per-user share root make it user-private; it
        // is NOT process-private, and nothing here restricts it beyond
        // what the parent's ACLs already do.
        std::fs::create_dir(dir).map_err(|e| ShareError::io(dir, e))
    }

    /// H3: a TRANSACTIONALLY CONSISTENT backup of a live, possibly WAL-mode
    /// database, taken via `VACUUM INTO` — never a raw `fs::copy` of the
    /// main file plus its `-wal`/`-shm` sidecars, which can be TORN (a write
    /// landing between the individual file reads leaves `dst` reflecting
    /// neither the pre- nor the post-write state coherently).
    ///
    /// Measured against this module's own resolved `sqlite3`: `VACUUM INTO`
    /// REFUSES a target path that already exists, even an empty file
    /// pre-created for the purpose ("stepping, output file already
    /// exists") — so the create-then-`O_EXCL`-then-`VACUUM INTO` sequence
    /// this was originally going to use does not work. Instead: a fresh,
    /// pid-and-time-named, user-private directory is created next to `dst`
    /// (mode 0700 on unix, set by the `mkdir` call itself; inherited
    /// parent ACLs on Windows — see [`create_private_dir`]), so no other
    /// user can read or swap anything placed inside it; `VACUUM INTO`
    /// writes there (a path `sqlite3` has never seen, so the "already
    /// exists" refusal cannot fire) — the file it creates is NOT 0600 at
    /// creation, and the 0700 parent is what keeps it private until the
    /// result is chmod'd to 0600 afterwards
    /// (a FAILURE here is an error, not best-effort — H3) and integrity
    /// checked; only THEN is it hard-linked into its permanent `dst` path,
    /// atomically. The private directory is removed on every exit.
    pub(super) fn backup_via_vacuum_into(
        binary: &Path,
        basename: &str,
        src: &Path,
        dst: &Path,
    ) -> Result<(), ShareError> {
        ensure_safe_attach_path(dst)?;
        let parent = dst.parent().ok_or_else(|| {
            ShareError::io(
                dst,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "backup destination has no parent directory",
                ),
            )
        })?;
        // The private dir is named `<basename>.pre-merge-tmp-<pid>-<epoch>`
        // so [`sweep_stale_pre_merge_tmp_dirs`] can match exactly this db's.
        let tmp_dir = parent.join(format!(
            "{basename}.pre-merge-tmp-{}-{}",
            std::process::id(),
            now_epoch_secs()
        ));
        create_private_dir(&tmp_dir)?;
        struct RemoveDirOnDrop<'a>(&'a Path);
        impl Drop for RemoveDirOnDrop<'_> {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(self.0);
            }
        }
        let _cleanup = RemoveDirOnDrop(&tmp_dir);

        let tmp_file = tmp_dir.join("backup.sqlite");
        let quoted_tmp = sql_quote_path(&tmp_file)?;
        run_sqlite3(binary, src, &format!("VACUUM INTO '{quoted_tmp}';"))?;
        // T5: a deterministic seam for corrupting the freshly-VACUUMed file
        // BEFORE the integrity check — a genuinely corrupt `VACUUM INTO`
        // output is not something this module can provoke on demand, so a
        // test that wants to exercise the integrity-check failure path
        // (and confirm the private tmp dir is still cleaned up on it) hooks
        // in here instead.
        run_test_after_vacuum_hook(&tmp_file);
        secure_sqlite_paths(&tmp_file)?;
        integrity_check(binary, "pre-merge backup", &tmp_file)?;
        // LOW(b): `fs::rename` SILENTLY REPLACES an existing `dst` on every
        // platform this module supports (POSIX `rename(2)`'s own contract;
        // Windows via `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`, which is
        // what `std::fs::rename` uses there) — so a `dst` that already
        // exists for any reason (a second concurrent share invocation that
        // slipped past the share lock some other way, a leftover from a
        // prior run this module's own bookkeeping failed to notice) would
        // be silently clobbered by this backup, discarding whatever it
        // held. `fs::hard_link` has no such fallback: it FAILS with
        // `AlreadyExists` (`EEXIST` on POSIX, `ERROR_ALREADY_EXISTS` on
        // Windows) rather than replacing `dst`, so linking-then-unlinking
        // the private tmp copy achieves the same "one atomic rename" effect
        // while refusing outright on a `dst` collision instead of erasing
        // it. `tmp_file` still exists after the link (a hard link is a
        // second directory entry, not a move); the private directory's
        // `RemoveDirOnDrop` guard cleans it up on the way out either way,
        // so a failed `remove_file` here — link succeeded, so `dst` is
        // already the correct, final file — is not itself an error.
        hard_link_checked(&tmp_file, dst).map_err(|e| {
            if is_hard_link_unsupported(&e, &tmp_file, dst) {
                ShareError::SqliteBackupHardLinkUnsupported {
                    path: PathBuf::from(crate::cli_deps::sanitize::redact_path(dst)),
                }
            } else {
                ShareError::io(dst, e)
            }
        })?;
        let _ = fs::remove_file(&tmp_file);
        Ok(())
    }

    /// Whether `path` is writable by this process (`access(W_OK)`). Only
    /// the unix `EPERM` disambiguation needs it.
    #[cfg(unix)]
    fn writable_by_us(path: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(path.as_os_str().as_bytes())
            // SAFETY: `c` is a valid NUL-terminated string for the call.
            .map(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0)
            .unwrap_or(false)
    }

    /// Whether a failed `hard_link(src, dst)` means the filesystem has no
    /// hard links (as opposed to a collision or a permissions problem).
    /// `EPERM` is ambiguous (some filesystems report it for "no hard
    /// links", but so does a plain permission refusal), so it counts only
    /// once a permission problem is ruled out: the source and the
    /// destination's directory are both writable by us.
    pub(super) fn is_hard_link_unsupported(e: &io::Error, src: &Path, dst: &Path) -> bool {
        if e.kind() == io::ErrorKind::Unsupported {
            return true;
        }
        #[cfg(unix)]
        {
            match e.raw_os_error() {
                Some(c) if c == libc::ENOTSUP || c == libc::EOPNOTSUPP || c == libc::ENOSYS => true,
                Some(c) if c == libc::EPERM => {
                    writable_by_us(src) && dst.parent().is_some_and(writable_by_us)
                }
                _ => false,
            }
        }
        #[cfg(windows)]
        {
            // ERROR_INVALID_FUNCTION: the volume (FAT/exFAT) has no hard links.
            let _ = (src, dst);
            e.raw_os_error() == Some(1)
        }
    }

    #[cfg(test)]
    thread_local! {
        static TEST_FORCE_HARD_LINK_ERROR: std::cell::Cell<Option<io::ErrorKind>> = const { std::cell::Cell::new(None) };
    }

    /// Test seam: makes the backup's `hard_link` fail with this kind.
    #[cfg(test)]
    pub(super) fn set_test_force_hard_link_error(kind: Option<io::ErrorKind>) {
        TEST_FORCE_HARD_LINK_ERROR.with(|c| c.set(kind));
    }

    fn hard_link_checked(src: &Path, dst: &Path) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = TEST_FORCE_HARD_LINK_ERROR.with(|c| c.get()) {
            return Err(io::Error::from(kind));
        }
        fs::hard_link(src, dst)
    }

    /// A private backup temp dir older than this is stale regardless of
    /// whether its pid is alive (pid reuse).
    const PRE_MERGE_TMP_MAX_AGE_SECS: u64 = 3600;

    /// Removes `<basename>.pre-merge-tmp-<pid>-<epoch>` directories left in
    /// `dir` by a crashed run (the `RemoveDirOnDrop` guard in
    /// [`backup_via_vacuum_into`] does not run on a kill): a dir is stale
    /// when `is_alive(pid)` is false OR its epoch is more than
    /// [`PRE_MERGE_TMP_MAX_AGE_SECS`] before `now`. Only directories whose
    /// name is EXACTLY `<prefix><digits>-<digits>` are considered; anything
    /// else is left alone. Callers hold the share lock, so no live run of
    /// this module can own a dir that is swept here except one whose pid is
    /// still alive and recent.
    pub(super) fn sweep_stale_pre_merge_tmp_dirs(
        dir: &Path,
        basename: &str,
        now: u64,
        is_alive: impl Fn(u32) -> bool,
    ) {
        let prefix = format!("{basename}.pre-merge-tmp-");
        let all_digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            let Some((pid_str, epoch_str)) = suffix.split_once('-') else {
                continue;
            };
            if !all_digits(pid_str) || !all_digits(epoch_str) {
                continue;
            }
            let (Ok(pid), Ok(epoch)) = (pid_str.parse::<u32>(), epoch_str.parse::<u64>()) else {
                continue;
            };
            let path = dir.join(&name);
            // A real directory only: never follow a symlink named like one.
            if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            let too_old = now.saturating_sub(epoch) > PRE_MERGE_TMP_MAX_AGE_SECS;
            // pid 0 and pids above i32::MAX are never a real process, and
            // `kill(2)` would read them as a process group / "every
            // process" target (0, or a negative pid) and report alive.
            let alive = pid != 0 && i32::try_from(pid).is_ok() && is_alive(pid);
            if too_old || !alive {
                let _ = fs::remove_dir_all(&path);
            }
        }
    }

    #[cfg(test)]
    type TestAfterVacuumHook = std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>>;

    #[cfg(test)]
    thread_local! {
        static TEST_AFTER_VACUUM_HOOK: TestAfterVacuumHook = const { std::cell::RefCell::new(None) };
    }

    #[cfg(test)]
    thread_local! {
        static TEST_FORCE_SCRIPT_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Test seam: makes the merge script fail generically right after the
    /// guards (a failure that is not a guard refusal).
    #[cfg(test)]
    pub(super) fn set_test_force_script_failure(on: bool) {
        TEST_FORCE_SCRIPT_FAILURE.with(|c| c.set(on));
    }

    #[cfg(test)]
    type TestBeforeMergeHook = std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>>;

    #[cfg(test)]
    thread_local! {
        static TEST_BEFORE_MERGE_HOOK: TestBeforeMergeHook = const { std::cell::RefCell::new(None) };
    }

    /// Test seam: runs just before `merge_sources_into_guarded` against the
    /// LIVE shared DB — after its re-verify and backup, the one point a
    /// concurrent codex session could still change it.
    fn run_test_before_merge_hook(_shared: &Path) {
        #[cfg(test)]
        TEST_BEFORE_MERGE_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_shared);
            }
        });
    }

    #[cfg(test)]
    pub(super) fn set_test_before_merge_hook(hook: impl FnMut(&Path) + 'static) {
        TEST_BEFORE_MERGE_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn clear_test_before_merge_hook() {
        TEST_BEFORE_MERGE_HOOK.with(|cell| *cell.borrow_mut() = None);
    }

    fn run_test_after_vacuum_hook(_tmp_file: &Path) {
        #[cfg(test)]
        TEST_AFTER_VACUUM_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(_tmp_file);
            }
        });
    }

    #[cfg(test)]
    pub(super) fn set_test_after_vacuum_hook(hook: impl FnMut(&Path) + 'static) {
        TEST_AFTER_VACUUM_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn clear_test_after_vacuum_hook() {
        TEST_AFTER_VACUUM_HOOK.with(|cell| *cell.borrow_mut() = None);
    }

    /// H2: deletes every `<basename>.pre-merge-*` backup in `dir` except
    /// `just_created` and the `keep - 1` most recent others (so `keep`
    /// backups survive in total), ranked by `(epoch, mtime)` (both
    /// descending)
    /// — a backup is taken on EVERY merge into an already-existing shared
    /// database, so an unpruned directory accumulates one full-size backup
    /// per share run forever.
    ///
    /// `just_created` (this call's own fresh backup) is NEVER a deletion
    /// candidate, full stop, regardless of its rank: if the system clock
    /// moves backward between runs, a backup taken under the LATER clock
    /// reading could rank as "older" than one taken under the earlier,
    /// since-corrected reading — pruning by rank alone would then delete
    /// the backup this very call just made. Excluding it structurally
    /// (rather than trying to make the ranking clock-proof) is what makes
    /// "the new one survives" true regardless of clock behaviour.
    ///
    /// Two name shapes are recognised: `<epoch>-<pid>` (current) and the
    /// legacy bare `<epoch>` (a backup taken by an earlier release, before
    /// the pid suffix existed) — each component MUST be all-ASCII-digit and
    /// non-empty, or the whole name is left alone rather than guessed at. A
    /// `-wal`/`-shm` SIDECAR name is never itself counted as a backup (a
    /// legacy `fs::copy`-based backup could have sidecars; a `VACUUM INTO`
    /// one never does) — deleted only as part of its main file, via
    /// [`remove_db_with_sidecars`].
    ///
    /// T1: this early `-wal`/`-shm` exclusion is REDUNDANT against today's
    /// shape check — a sidecar's suffix (`<epoch>-wal`, or
    /// `<epoch>-<pid>-wal`) already fails the all-digit component check
    /// below (`"wal"` is not all-digit) and would be excluded either way,
    /// as `prune_old_naive_parser_would_have_wrongly_evicted_a_real_backup`
    /// demonstrates against the OLD, un-validated shape. It is kept
    /// anyway, deliberately, as an explicit statement of intent that
    /// survives a FUTURE change to the name shape (e.g. one that no longer
    /// happens to reject `-wal`/`-shm` as a side effect) — this exclusion
    /// is a named invariant of this function, not an accident of the
    /// current parsing rule.
    pub(super) fn prune_old_pre_merge_backups(
        dir: &Path,
        basename: &str,
        keep: usize,
        just_created: &Path,
    ) {
        let prefix = format!("{basename}.pre-merge-");
        let all_digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut backups: Vec<(u64, i128, PathBuf)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_string();
                if name.ends_with("-wal") || name.ends_with("-shm") {
                    return None;
                }
                let suffix = name.strip_prefix(&prefix)?;
                let epoch: u64 = match suffix.split_once('-') {
                    Some((epoch_str, pid_str)) if all_digits(epoch_str) && all_digits(pid_str) => {
                        epoch_str.parse().ok()?
                    }
                    Some(_) => return None,
                    None if all_digits(suffix) => suffix.parse().ok()?,
                    None => return None,
                };
                let path = dir.join(&name);
                let mtime = fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as i128)
                    .unwrap_or(0);
                Some((epoch, mtime, path))
            })
            .collect();
        backups.sort_by_key(|backup| std::cmp::Reverse((backup.0, backup.1)));
        let mut kept = 0usize;
        for (_, _, path) in backups {
            if path == just_created {
                continue;
            }
            if kept < keep.saturating_sub(1) {
                kept += 1;
                continue;
            }
            remove_db_with_sidecars(&path);
        }
    }

    /// `threads` column names, in schema order, excluding `id` — dynamically
    /// discovered so the merge does not need to hardcode every column
    /// codex-cli's schema happens to carry today.
    ///
    /// S-F8: `PRAGMA table_info` returns column names as plain text with no
    /// parameter-binding option, and they are interpolated directly into
    /// generated SQL by [`merge_sources_into`] — so every name is validated
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
    /// S-L3 extension: beyond conversation IDENTITY (`name`) and RECENCY
    /// (`updated_at_ms`, `created_at_ms`), every column here still describes
    /// the CONVERSATION rather than the per-account environment it runs
    /// in — `updated_at`, archival/pin state, its section placement, its
    /// display text, and its usage counters. Deliberately excluded (and
    /// left untouched by ANY merge, forever per-account):
    /// `cwd`, `sandbox_policy`, `approval_mode`, `model`, `model_provider`,
    /// `reasoning_effort` — HOW or WHERE a thread runs, which must never
    /// silently adopt another slot's working directory or model.
    ///
    /// `recency_at`/`recency_at_ms` take the MAX of both sides (see
    /// [`merge_threads`]) rather than following `updated_at_ms`'s
    /// newer-wins rule, because a thread can be VIEWED (bumping recency)
    /// on a slot without being edited there. `created_at_ms` takes the MIN
    /// (earliest) unconditionally — a thread's creation time cannot
    /// legitimately move forward just because one slot's copy is "newer".
    /// B2: `section_position` alone moved a thread's PLACE within a section
    /// while `thread_section_id` (WHICH section) and `section_entered_at_ms`
    /// (WHEN it entered that section) stayed behind — a half-merged
    /// placement, since a position is meaningless once detached from the
    /// section it is a position WITHIN. `project_id` was omitted entirely
    /// despite being repairable-on-dangling (see
    /// [`THREADS_NULLABLE_FK_COLUMNS`]) — a thread's project assignment is
    /// conversation identity exactly like `name`, not per-account
    /// environment. All three now follow the ordinary newer-wins rule.
    /// `created_at` (whole seconds) is added so it can be kept in step with
    /// `created_at_ms` (see [`threads_merge_set_clause`]) rather than the
    /// two silently disagreeing after a merge picks the earlier
    /// `created_at_ms` but leaves `created_at` on the newer-wins path.
    const THREADS_MERGE_ALLOWLIST: &[&str] = &[
        "name",
        "updated_at_ms",
        "created_at_ms",
        "created_at",
        "updated_at",
        "archived",
        "archived_at",
        "is_pinned",
        "section_position",
        "thread_section_id",
        "section_entered_at_ms",
        "project_id",
        "title",
        "preview",
        "first_user_message",
        "tokens_used",
        "has_user_event",
        "recency_at",
        "recency_at_ms",
    ];

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
    ///
    /// Read from a single REPRESENTATIVE database (`plan_one_basename`
    /// passes whichever of the shared DB or the first real copy is
    /// canonical) rather than intersected across every side: the caller has
    /// already required every side's `_sqlx_migrations` signature to match
    /// byte-for-byte before reaching this call, and two databases at the
    /// identical migration set have the identical `threads` schema by
    /// construction — so "exists in both" is already guaranteed, not
    /// merely assumed.
    /// The RAW, UNFILTERED `PRAGMA table_info(threads)` text — every column
    /// `threads` has, not just the [`THREADS_MERGE_ALLOWLIST`] subset
    /// [`threads_non_id_columns`] returns. Used ONLY as a plan-vs-apply
    /// schema-drift fingerprint (M1): an `ALTER TABLE threads ADD COLUMN`
    /// landing between planning and apply changes this text even when the
    /// added column is not itself on the allowlist, which
    /// `threads_non_id_columns`'s filtered comparison cannot see.
    pub(super) fn threads_schema_fingerprint(
        binary: &Path,
        db_path: &Path,
    ) -> Result<String, ShareError> {
        run_sqlite3_readonly(
            binary,
            db_path,
            &format!(
                "SELECT {THREADS_SCHEMA_ROW_EXPR} FROM pragma_table_info('threads') ORDER BY cid;"
            ),
        )
    }

    /// One `threads` column as text for the schema fingerprint: name, type
    /// and default are hex-encoded (a default of NULL is `N`, distinct from
    /// an empty-string default `V`), so no value can collide with the `|`
    /// separator. The merge transaction's guard rebuilds the same value.
    const THREADS_SCHEMA_ROW_EXPR: &str = "cid||'|'||hex(name)||'|'||hex(type)||'|'||\"notnull\"\
         ||'|'||CASE WHEN dflt_value IS NULL THEN 'N' ELSE 'V'||hex(dflt_value) END||'|'||pk";

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
    /// Builds the `threads` UPDATE SET clause shared by every source in a
    /// [`merge_sources_into`] script — identical regardless of which
    /// source's data is being merged, since it only ever references the
    /// per-statement subquery alias `s`, never the source's own ATTACH
    /// alias. Splitting this out lets [`merge_sources_into`] compute it
    /// ONCE per call and reuse it verbatim for every source.
    fn threads_merge_set_clause(columns: &[String]) -> String {
        let updated_q = quote_ident("updated_at_ms");
        let name_q = quote_ident("name");
        let created_ms_q = quote_ident("created_at_ms");
        columns
            .iter()
            .map(|c| {
                let cq = quote_ident(c);
                match c.as_str() {
                    "name" => format!(
                        "{name_q} = CASE \
                         WHEN s.{name_q} IS NOT NULL AND s.{name_q} <> '' \
                              AND (threads.{name_q} IS NULL OR threads.{name_q} = '' \
                                   OR s.{updated_q} > threads.{updated_q}) \
                         THEN s.{name_q} \
                         ELSE threads.{name_q} END"
                    ),
                    // `created_at_ms` takes the MIN (earliest) of the two
                    // sides UNCONDITIONALLY — never gated on
                    // `updated_at_ms`, since a thread's creation time
                    // does not move forward just because one slot's copy
                    // was edited more recently. SQLite's multi-arg
                    // `MIN`/`MAX` return NULL if EITHER argument is
                    // NULL, so the NULL sides are handled explicitly
                    // rather than relying on that behaviour.
                    "created_at_ms" => format!(
                        "{cq} = CASE \
                         WHEN s.{cq} IS NULL THEN threads.{cq} \
                         WHEN threads.{cq} IS NULL THEN s.{cq} \
                         ELSE MIN(s.{cq}, threads.{cq}) END"
                    ),
                    // B2: `created_at` (whole seconds) MUST track whichever
                    // side's `created_at_ms` the rule above actually picked
                    // — never its own independent newer-wins comparison —
                    // or the two columns can end up describing two
                    // DIFFERENT sides' creation times after a merge.
                    "created_at" => format!(
                        "{cq} = CASE \
                         WHEN s.{created_ms_q} IS NULL THEN threads.{cq} \
                         WHEN threads.{created_ms_q} IS NULL THEN s.{cq} \
                         WHEN s.{created_ms_q} <= threads.{created_ms_q} THEN s.{cq} \
                         ELSE threads.{cq} END"
                    ),
                    // `recency_at`/`recency_at_ms` take the MAX
                    // (latest) of the two sides UNCONDITIONALLY — a
                    // thread can be VIEWED (bumping recency) on a slot
                    // without being EDITED there, so recency does not
                    // follow the `updated_at_ms` newer-wins rule either.
                    "recency_at" | "recency_at_ms" => format!(
                        "{cq} = CASE \
                         WHEN s.{cq} IS NULL THEN threads.{cq} \
                         WHEN threads.{cq} IS NULL THEN s.{cq} \
                         ELSE MAX(s.{cq}, threads.{cq}) END"
                    ),
                    _ => format!(
                        "{cq} = CASE \
                         WHEN s.{updated_q} > threads.{updated_q} THEN s.{cq} \
                         ELSE threads.{cq} END"
                    ),
                }
            })
            .collect::<Vec<_>>()
            .join(",\n  ")
    }

    /// Tables never carried by [`merge_sources_into`] — per-DATABASE
    /// bookkeeping rather than session CONTENT. Each slot's own value is
    /// kept: `_sqlx_migrations` describes which upgrades THIS file has had
    /// applied (already required to match byte-for-byte before any merge
    /// reaches here); `backfill_state`/`rollout_migration_state`/
    /// `rollout_migration_skipped_rollouts` describe the progress of a
    /// ONE-TIME background migration codex-cli itself runs against this
    /// exact file, not a cross-slot fact to coalesce.
    const CODEX_MERGE_BOOKKEEPING_TABLES: &[&str] = &[
        "_sqlx_migrations",
        "backfill_state",
        "rollout_migration_state",
        "rollout_migration_skipped_rollouts",
    ];

    /// Every user table name in `db_path`, sorted — `sqlite_master`'s own
    /// `sqlite_*` bookkeeping tables (`sqlite_sequence`, etc.) excluded, as
    /// they are never real rows of `db_path`'s own schema.
    ///
    /// S-F8: every name is validated against [`is_safe_sql_identifier`]
    /// before being returned — it is interpolated directly into generated
    /// SQL by [`merge_sources_into`] and [`topo_sort_tables_by_fk`], so an
    /// unsafe identifier is refused here rather than silently dropped,
    /// matching [`threads_non_id_columns`]'s posture on column names.
    fn user_table_names(
        binary: &Path,
        basename: &str,
        db_path: &Path,
    ) -> Result<Vec<String>, ShareError> {
        let mut names: Vec<String> = table_set(binary, db_path)?
            .into_iter()
            .filter(|n| !n.starts_with("sqlite_"))
            .collect();
        for name in &names {
            if !is_safe_sql_identifier(name) {
                return Err(ShareError::SqliteUnsafeTableName {
                    basename: basename.to_string(),
                    path: PathBuf::from(crate::cli_deps::sanitize::redact_path(db_path)),
                    table: name.clone(),
                });
            }
        }
        names.sort();
        Ok(names)
    }

    /// The name of `table`'s single-column PRIMARY KEY, if it has exactly
    /// one — read from `PRAGMA table_info(table)`'s `pk` field (a positive
    /// ordinal for each column participating in the primary key; `0` for
    /// none). Used by [`threads_repairable_fk_targets`] (M4) to resolve a
    /// declared FK whose `to` column is empty: SQLite resolves such a FK
    /// against the target's ACTUAL primary key, which this module's own
    /// fixtures always name `id` but which is not guaranteed to be `id` in
    /// general — reading it directly, rather than assuming the name,
    /// closes that gap. A composite primary key (more than one column with
    /// `pk > 0`) is returned as `None` rather than guessing which column an
    /// empty `to` would resolve to.
    pub(super) fn table_primary_key_column(
        binary: &Path,
        db_path: &Path,
        table: &str,
    ) -> Result<Option<String>, ShareError> {
        // The column name is read hex-encoded: a name may contain `|` or a
        // newline, which would corrupt a `|`-split of `PRAGMA table_info`.
        let out = run_sqlite3_readonly(
            binary,
            db_path,
            &format!(
                "SELECT hex(name) FROM pragma_table_info('{}') WHERE pk > 0 ORDER BY pk;",
                sql_quote_str(table)
            ),
        )?;
        let mut pk_columns: Vec<String> = Vec::new();
        for line in out.lines().filter(|l| !l.trim().is_empty()) {
            let decoded = (0..line.len())
                .step_by(2)
                .map(|i| {
                    line.get(i..i + 2)
                        .and_then(|b| u8::from_str_radix(b, 16).ok())
                })
                .collect::<Option<Vec<u8>>>()
                .and_then(|bytes| String::from_utf8(bytes).ok());
            // An undecodable name cannot be matched to anything: treat the
            // key as unknown (`None`), which the caller skips and the
            // post-merge guard then fails closed on.
            let Some(name) = decoded else {
                return Ok(None);
            };
            pk_columns.push(name);
        }
        if pk_columns.len() != 1 {
            return Ok(None);
        }
        Ok(Some(pk_columns.remove(0)))
    }

    /// Every column name of `table`, in schema order — used by
    /// [`merge_sources_into`] (M2) to build an EXPLICIT column list for a
    /// carried table's `INSERT ... SELECT`, rather than `SELECT *`, so rows
    /// land in the correct destination column by NAME even when the
    /// source's physical column order differs. S-F8: each name is
    /// validated against [`is_safe_sql_identifier`] before being returned.
    fn table_column_names(
        binary: &Path,
        basename: &str,
        db_path: &Path,
        table: &str,
    ) -> Result<Vec<String>, ShareError> {
        let out = run_sqlite3_readonly(
            binary,
            db_path,
            &format!("PRAGMA table_info({});", quote_ident(table)),
        )?;
        let mut columns = Vec::new();
        for line in out.lines() {
            let mut fields = line.split('|');
            let Some(_cid) = fields.next() else { continue };
            let Some(name) = fields.next() else { continue };
            if !is_safe_sql_identifier(name) {
                return Err(ShareError::SqliteUnsafeColumnName {
                    basename: basename.to_string(),
                    column: name.to_string(),
                });
            }
            columns.push(name.to_string());
        }
        Ok(columns)
    }

    /// Parent tables (within `tables`) that `PRAGMA foreign_key_list(table)`
    /// says must be populated before `table`. A dependency on a table NOT in
    /// `tables` (chiefly `threads`, which [`merge_sources_into`] merges
    /// before carrying any OTHER table) is ignored — it is already
    /// satisfied by construction, not merely assumed to be.
    ///
    /// M4: this ordering is DEFENSIVE, not load-bearing for correctness —
    /// measured against this module's own resolved `sqlite3` binary,
    /// `PRAGMA foreign_keys;` reports `0` (foreign-key ENFORCEMENT is OFF by
    /// default in the sqlite3 CLI), so an `INSERT` that runs "out of order"
    /// relative to its declared parent would not itself fail or be refused
    /// at insert time. The real guard is the post-merge
    /// `pragma_foreign_key_check` scan in [`merge_sources_into`], which runs
    /// after every source's rows (parent and child tables alike, from every
    /// source) have landed — this ordering exists so a schema reader does
    /// not have to reason about apparent forward references, not because an
    /// out-of-order insert could otherwise corrupt anything.
    fn topo_sort_tables_by_fk(
        binary: &Path,
        db_path: &Path,
        tables: &[String],
    ) -> Result<Vec<String>, ShareError> {
        let set: HashSet<String> = tables.iter().cloned().collect();
        let mut deps: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::with_capacity(tables.len());
        for t in tables {
            deps.insert(t.clone(), fk_parents_within(binary, db_path, t, &set)?);
        }
        let mut ordered = Vec::with_capacity(tables.len());
        let mut placed: HashSet<String> = HashSet::with_capacity(tables.len());
        while ordered.len() < tables.len() {
            let mut progressed = false;
            for t in tables {
                if placed.contains(t) {
                    continue;
                }
                if deps[t].iter().all(|p| placed.contains(p)) {
                    ordered.push(t.clone());
                    placed.insert(t.clone());
                    progressed = true;
                }
            }
            if !progressed {
                for t in tables {
                    if !placed.contains(t) {
                        ordered.push(t.clone());
                        placed.insert(t.clone());
                    }
                }
                break;
            }
        }
        Ok(ordered)
    }

    fn fk_parents_within(
        binary: &Path,
        db_path: &Path,
        table: &str,
        tables: &HashSet<String>,
    ) -> Result<Vec<String>, ShareError> {
        let out = run_sqlite3_readonly(
            binary,
            db_path,
            &format!("PRAGMA foreign_key_list({});", quote_ident(table)),
        )?;
        let mut parents = Vec::new();
        for line in out.lines() {
            // id|seq|table|from|to|on_update|on_delete|match
            let fields: Vec<&str> = line.split('|').collect();
            let Some(parent) = fields.get(2) else {
                continue;
            };
            if tables.contains(*parent) && *parent != table {
                parents.push((*parent).to_string());
            }
        }
        Ok(parents)
    }

    /// `threads`' declared foreign keys, restricted to the columns this
    /// module knows how to REPAIR by NULLing a dangling reference —
    /// [`THREADS_NULLABLE_FK_COLUMNS`], codex's own `ON DELETE SET NULL`
    /// semantics for these two columns (see the fixture schema). Returns
    /// `(column, target_table)` pairs, both re-validated against
    /// [`is_safe_sql_identifier`] before [`merge_sources_into`]
    /// interpolates either into generated SQL — an unsafe identifier is
    /// SKIPPED here (not added to the returned list) rather than silently
    /// repaired against a name that cannot be trusted, matching this
    /// module's posture everywhere else it reads an identifier out of
    /// `PRAGMA` output; [`merge_sources_into`]'s post-merge guard is what
    /// actually REFUSES the whole merge if the resulting violation remains
    /// unrepaired. A declared FK whose `to` column is neither empty nor
    /// `id` (M4) is skipped the same way. Any OTHER `threads` foreign key
    /// relationship, or any foreign key on any OTHER table, is NOT repaired
    /// here either — the same post-merge guard is what actually refuses.
    pub(super) fn threads_repairable_fk_targets(
        binary: &Path,
        db_path: &Path,
    ) -> Result<Vec<(String, String)>, ShareError> {
        let out = run_sqlite3_readonly(binary, db_path, "PRAGMA foreign_key_list(threads);")?;
        let mut pairs = Vec::new();
        for line in out.lines() {
            // id|seq|table|from|to|on_update|on_delete|match
            let fields: Vec<&str> = line.split('|').collect();
            let (Some(target_table), Some(column), Some(to)) =
                (fields.get(2), fields.get(3), fields.get(4))
            else {
                continue;
            };
            if !THREADS_NULLABLE_FK_COLUMNS.contains(column) {
                continue;
            }
            // M4: this repair NULLs `column` when it is absent from
            // `SELECT id FROM target_table` — correct ONLY when the FK
            // actually targets `target_table`'s `id`. A non-empty `to`
            // names the target column explicitly. An EMPTY `to` means
            // SQLite resolved the FK against the target's PRIMARY KEY,
            // which this module's own fixtures always name `id` but is not
            // guaranteed to be in general — [`table_primary_key_column`]
            // reads the target's actual primary key rather than assuming
            // its name, so a table whose real primary key is some other
            // column is correctly skipped here instead of silently
            // repairing against the wrong one. A declared or resolved
            // target column other than `id` makes this repair's `SELECT
            // id FROM …` query the wrong column entirely — skip it (not
            // added to `pairs`) rather than repair against the wrong
            // target; the post-merge guard then fails closed on it like
            // any other unrecognised violation.
            let targets_id = if to.is_empty() {
                matches!(
                    table_primary_key_column(binary, db_path, target_table)?,
                    Some(ref pk) if pk.eq_ignore_ascii_case("id")
                )
            } else {
                to.eq_ignore_ascii_case("id")
            };
            if !targets_id {
                continue;
            }
            if !is_safe_sql_identifier(column) || !is_safe_sql_identifier(target_table) {
                continue;
            }
            pairs.push(((*column).to_string(), (*target_table).to_string()));
        }
        Ok(pairs)
    }

    /// `threads`' declared foreign-key columns this module knows how to
    /// REPAIR by setting NULL when a dangling reference is found —
    /// codex's own `ON DELETE SET NULL` semantics for these two columns
    /// (see the fixture schema), applied here because a cross-slot merge
    /// can bring in a `threads` row whose `project_id` or
    /// `thread_section_id` points at a `projects`/`thread_sections` row that
    /// (for whatever reason) this merge did not also carry. Any OTHER
    /// foreign-key violation this module does not recognise is refused
    /// rather than guessed at (guard-reader-writer-parity.md MUST-2: doubt
    /// refuses).
    const THREADS_NULLABLE_FK_COLUMNS: &[&str] = &["project_id", "thread_section_id"];

    /// The NAMED `CHECK` constraint [`merge_sources_into`]'s post-merge
    /// guard raises on — SQLite's failure message is `CHECK constraint
    /// failed: {this name}` for a NAMED constraint (measured against this
    /// module's own `sqlite3`), so [`remap_fk_guard_violation`] matches on
    /// this exact, deliberately unlikely identifier rather than a bare
    /// column name like `unresolved_foreign_keys` — a source database's own
    /// (legitimate or hostile) table could declare a column or constraint
    /// with THAT name and trip an unrelated `CHECK` failure whose message
    /// would then be misclassified as this guard.
    const FK_GUARD_CONSTRAINT_NAME: &str = "csq_merge_fk_guard_must_be_zero";

    /// Name of the aggregate gate every destination write is predicated on
    /// (see [`gate_exists`]).
    const MERGE_GATE: &str = "csq_merge_write_gate";

    /// Names of the destination guards [`merge_sources_into_guarded`] runs
    /// right after `BEGIN IMMEDIATE`; each is a NAMED `CHECK`, so a failure
    /// reads `CHECK constraint failed: <name>` (same mechanism as
    /// [`FK_GUARD_CONSTRAINT_NAME`]).
    const DEST_MIGRATIONS_TABLE_GUARD: &str = "csq_merge_dest_migrations_table_guard";
    const DEST_MIGRATIONS_GUARD: &str = "csq_merge_dest_migrations_guard";
    const DEST_THREADS_SCHEMA_GUARD: &str = "csq_merge_dest_threads_schema_guard";
    const DEST_SCHEMA_OBJECTS_GUARD: &str = "csq_merge_dest_schema_objects_guard";

    /// What the destination was verified to look like earlier in the apply
    /// step; [`merge_sources_into_guarded`] re-asserts it INSIDE its
    /// transaction, so a change landing between that verification and the
    /// transaction's lock is refused instead of merged into.
    pub(super) struct DestExpectation<'a> {
        /// [`migrations_signature`] of the destination as verified.
        pub(super) migrations_sig: &'a Option<String>,
        /// [`threads_schema_fingerprint`] of the destination as verified.
        pub(super) threads_schema: &'a str,
        /// The destination's trigger/view rows ([`SCHEMA_OBJECT_ROW_EXPR`]),
        /// as returned by [`forbid_untrusted_schema_objects`] when it
        /// verified them.
        pub(super) schema_objects: &'a [String],
    }

    /// SQL for a one-row temp table whose NAMED `CHECK` fails unless
    /// `condition` evaluates to 1. `IS 1`, not `= 1`: a `CHECK` passes NULL, so
    /// a condition that yielded NULL would otherwise insert a row and satisfy
    /// both the guard and [`gate_exists`].
    pub(super) fn named_guard_sql(name: &str, condition: &str) -> String {
        format!(
            "CREATE TEMP TABLE {name}(ok INTEGER CONSTRAINT {name} CHECK (ok IS 1));\n\
             INSERT INTO {name} SELECT ({condition});\n"
        )
    }

    /// SQL condition true only when EVERY named guard table (see
    /// [`named_guard_sql`]) holds its `ok IS 1` row, i.e. every guard's `INSERT`
    /// succeeded.
    /// A write predicate carrying it is a no-op after a failed guard even when
    /// the sqlite3 shell keeps executing past the failure. Never use
    /// `RAISE`/`INSERT OR ROLLBACK` for a guard that a WRITE follows: the
    /// statement after the rollback would autocommit. A guard followed only by
    /// `COMMIT` (the merge FK guard) may use it: that `COMMIT` then fails.
    pub(super) fn gate_exists(names: &[&str]) -> String {
        names
            .iter()
            .map(|n| format!("EXISTS (SELECT 1 FROM temp.{n} WHERE ok IS 1)"))
            .collect::<Vec<_>>()
            .join(" AND ")
    }

    /// SQL condition: the rows `row_expr` yields from `from_clause` are
    /// EXACTLY the set `expected` — equal row count, no expected row
    /// missing AND no current row unexpected. A set comparison on purpose: it does not depend on
    /// `group_concat` honouring a subquery's `ORDER BY` (which SQLite does
    /// not promise, and `group_concat(... ORDER BY ...)` needs 3.44+, newer
    /// than this module's minimum `sqlite3`). Rows are distinct by
    /// construction (primary key / column id).
    fn row_set_condition(row_expr: &str, from_clause: &str, expected: &[String]) -> String {
        let count = format!("(SELECT count(*) FROM {from_clause}) = {}", expected.len());
        if expected.is_empty() {
            return count;
        }
        let values = expected
            .iter()
            .map(|r| format!("('{}')", sql_quote_str(r)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{count} AND NOT EXISTS (SELECT column1 FROM (VALUES {values}) \
             EXCEPT SELECT {row_expr} FROM {from_clause}) \
             AND NOT EXISTS (SELECT {row_expr} FROM {from_clause} \
             EXCEPT SELECT column1 FROM (VALUES {values}))"
        )
    }

    /// Expected rows are hex digits and `|` only (see the `*_ROW_EXPR`
    /// constants); anything else means the verified value is not one this
    /// module produced, and cannot be embedded in a script.
    fn guard_rows(text: &str) -> Option<Vec<String>> {
        let rows: Vec<String> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect();
        rows.iter()
            .all(|r| r.chars().all(|c| c.is_ascii_alphanumeric() || c == '|'))
            .then_some(rows)
    }

    /// The guard statements for `expect`, or `None` when the expectation
    /// cannot be embedded safely (the caller refuses precisely).
    fn dest_guard_script(expect: &DestExpectation<'_>) -> Option<String> {
        let mut script = String::new();
        let mut names = vec![DEST_MIGRATIONS_TABLE_GUARD];
        let has_table = "(SELECT count(*) FROM sqlite_master WHERE type='table' \
                          AND name='_sqlx_migrations')";
        match expect.migrations_sig {
            None => script.push_str(&named_guard_sql(
                DEST_MIGRATIONS_TABLE_GUARD,
                &format!("{has_table} = 0"),
            )),
            Some(sig) => {
                script.push_str(&named_guard_sql(
                    DEST_MIGRATIONS_TABLE_GUARD,
                    &format!("{has_table} = 1"),
                ));
                let rows = guard_rows(sig)?;
                names.push(DEST_MIGRATIONS_GUARD);
                script.push_str(&named_guard_sql(
                    DEST_MIGRATIONS_GUARD,
                    &row_set_condition(MIGRATION_ROW_EXPR, "_sqlx_migrations", &rows),
                ));
            }
        }
        // Before any write: a trigger or view planted in the destination
        // after it was verified must be refused here, never fire.
        names.push(DEST_SCHEMA_OBJECTS_GUARD);
        names.push(DEST_THREADS_SCHEMA_GUARD);
        let object_rows = guard_rows(&expect.schema_objects.join("\n"))?;
        script.push_str(&named_guard_sql(
            DEST_SCHEMA_OBJECTS_GUARD,
            &row_set_condition(
                SCHEMA_OBJECT_ROW_EXPR,
                "sqlite_master WHERE type IN ('trigger','view')",
                &object_rows,
            ),
        ));
        let schema_rows = guard_rows(expect.threads_schema)?;
        script.push_str(&named_guard_sql(
            DEST_THREADS_SCHEMA_GUARD,
            &row_set_condition(
                THREADS_SCHEMA_ROW_EXPR,
                "pragma_table_info('threads')",
                &schema_rows,
            ),
        ));
        // One row only when EVERY guard above inserted its row; each merge
        // write carries `gate_exists(&[MERGE_GATE])`, so none lands after a failed guard.
        script.push_str(&format!(
            "CREATE TEMP TABLE {MERGE_GATE}(ok INTEGER);\nINSERT INTO {MERGE_GATE} SELECT 1 WHERE {};\n",
            gate_exists(&names)
        ));
        Some(script)
    }

    /// A destination guard tripping means the destination changed after it
    /// was verified: re-shape the failure into
    /// [`ShareError::SqliteChangedDuringMerge`] (the merge is one
    /// transaction that never wrote, so `dest` is unchanged).
    fn remap_dest_guard_violation(basename: &str, dest: &Path, err: ShareError) -> ShareError {
        if let ShareError::SqliteCommandFailed { detail, .. } = &err {
            if [
                DEST_MIGRATIONS_TABLE_GUARD,
                DEST_MIGRATIONS_GUARD,
                DEST_THREADS_SCHEMA_GUARD,
                DEST_SCHEMA_OBJECTS_GUARD,
            ]
            .iter()
            .any(|g| detail.contains(g))
            {
                return ShareError::SqliteChangedDuringMerge {
                    basename: basename.to_string(),
                    path: PathBuf::from(crate::cli_deps::sanitize::redact_path(dest)),
                };
            }
        }
        err
    }

    /// If `err` is a [`ShareError::SqliteCommandFailed`] whose detail names
    /// [`FK_GUARD_CONSTRAINT_NAME`] — [`merge_sources_into`]'s own
    /// post-merge guard tripping — re-shape it into
    /// [`ShareError::SqliteForeignKeyViolation`], which names the actual
    /// failure class rather than a generic SQL error. Any OTHER error (a
    /// genuinely failed SQL statement, an unrelated constraint) is returned
    /// unchanged.
    fn remap_fk_guard_violation(basename: &str, dest: &Path, err: ShareError) -> ShareError {
        if let ShareError::SqliteCommandFailed { detail, .. } = &err {
            if detail.contains(FK_GUARD_CONSTRAINT_NAME) {
                return ShareError::SqliteForeignKeyViolation {
                    basename: basename.to_string(),
                    path: PathBuf::from(crate::cli_deps::sanitize::redact_path(dest)),
                    detail: crate::error::redact_tokens(detail),
                };
            }
        }
        err
    }

    /// H1: builds the `note` for
    /// [`ShareError::SqliteSharedCommittedSlotsUnlinked`] — used for every
    /// refusal in `apply_basename_plan_with`'s per-slot rename-and-link loop,
    /// which runs ONLY after the shared index has already been durably
    /// updated. `rollback_renamed` restores every per-slot ORIGINAL this
    /// call's own loop touched (so ALL of `total_slots` end up back at their
    /// own real files, never partially linked), but the shared index itself
    /// keeps the merged content — hence "none of its slots could be linked",
    /// never "rolled back". `underlying` is folded into the note via its own
    /// `Display`, and the pre-merge backup path (already redacted by its
    /// caller) is named when one was taken.
    fn shared_committed_slots_unlinked_note(
        basename: &str,
        total_slots: usize,
        backup_path: &Option<PathBuf>,
        rollback: &RollbackReport,
        underlying: ShareError,
    ) -> ShareError {
        let backup_note = backup_path
            .as_ref()
            .map(|p| {
                format!(
                    " A pre-merge backup of the shared index is at {}.",
                    crate::cli_deps::sanitize::redact_path(p)
                )
            })
            .unwrap_or_default();
        // R3: "best-effort" is reported, not merely asserted — a NON-empty
        // `not_restored` means the rollback itself could not put every
        // touched original back, and that is named explicitly rather than
        // folded into the same sentence that claims restoration happened.
        let mut restore_note = String::new();
        if !rollback.not_restored.is_empty() {
            let paths = rollback.not_restored.join(", ");
            restore_note.push_str(&format!(
                " Restoring the following slot(s) to their own copy also failed — check them \
                 by hand: {paths}."
            ));
        }
        if !rollback.caveats.is_empty() {
            restore_note.push_str(&format!(
                " Restored, but with a problem to check by hand (mode/sidecar): {}.",
                rollback.caveats.join("; ")
            ));
        }
        ShareError::SqliteSharedCommittedSlotsUnlinked {
            basename: basename.to_string(),
            note: format!(
                "but the {total_slots} slot(s) this run was linking to it could not be linked \
                 ({underlying}) — any slot already linked from an EARLIER run is unaffected. \
                 The slot(s) this run was linking keep their own separate copies for now \
                 (restoration is best-effort; see below). Re-run `csq sessions share` once \
                 resolved to finish linking them.{backup_note}{restore_note}"
            ),
            cause: Box::new(underlying),
        }
    }

    /// B1: merges every `sources` entry's `threads` rows and every OTHER
    /// carried table into `dest`, repairs any dangling `threads` foreign key
    /// this module recognises, and refuses if any OTHER foreign-key
    /// violation remains — ALL of it in ONE sqlite3 process and ONE
    /// transaction. `sources` MAY be empty: the repair-and-guard phase still
    /// runs alone against `dest`'s own pre-existing content (e.g. a single
    /// seed slot's own dangling `project_id`).
    ///
    /// This replaces what were three separate sqlite3 processes — a
    /// `threads` merge per source, an other-tables carry per source, and a
    /// single foreign-key check-and-repair pass — each its own COMMIT. A
    /// refusal in the third left the first two durably committed to the
    /// LIVE shared database with no way back: an orphaned `project_roots`
    /// row from one slot would commit, then every SUBSEQUENT `csq sessions
    /// share` run would refuse at the (now-permanent) violation, wedging the
    /// shared store. Wrapping the whole thing in one script and one
    /// transaction (`ATTACH` before `BEGIN`, `DETACH` after `COMMIT` — a
    /// `BEGIN`-then-`ATTACH`-then-`DETACH`-before-`COMMIT` ordering fails
    /// with "database ... is locked", measured against this host's
    /// `sqlite3`) means a failure ANYWHERE — a bad source, a carried-table
    /// insert, or the final guard — rolls back EVERYTHING this call staged,
    /// and `dest` is unchanged.
    ///
    /// The gap on the LIVE shared database is closed by `expect`:
    /// `apply_basename_plan_with` re-verifies the shared DB in separate
    /// `sqlite3` invocations, and a codex session linked to it could migrate
    /// it between that re-verify and this call. So right after `BEGIN
    /// IMMEDIATE` (the write lock) and before any write, named `CHECK`
    /// guards re-assert the verified `_sqlx_migrations` signature and
    /// `threads` column fingerprint on `dest` itself; a mismatch aborts the
    /// script, rolls back, and maps to `SqliteChangedDuringMerge`.
    #[cfg(test)]
    pub(super) fn merge_sources_into(
        binary: &Path,
        basename: &str,
        dest: &Path,
        sources: &[PathBuf],
        columns: &[String],
    ) -> Result<(), ShareError> {
        merge_sources_into_guarded(binary, basename, dest, sources, columns, None)
    }

    /// [`merge_sources_into`], optionally re-asserting `expect` on `dest`
    /// inside the transaction (see [`DestExpectation`]).
    #[cfg(test)]
    pub(super) fn merge_sources_into_guarded(
        binary: &Path,
        basename: &str,
        dest: &Path,
        sources: &[PathBuf],
        columns: &[String],
        expect: Option<&DestExpectation<'_>>,
    ) -> Result<(), ShareError> {
        merge_sources_into_classified(binary, basename, dest, sources, columns, expect)
            .map_err(|f| f.err)
    }

    /// A failed merge, with whether it is POSITIVELY known to have happened
    /// before COMMIT. `pre_commit` is true for everything raised before the
    /// write script is sent to `sqlite3` and for the guard refusals that
    /// abort the script before any write; it is false for any other failure
    /// of the script itself, since a COMMIT can fail its fsync after the
    /// frame was written and a signal can land after COMMIT.
    pub(super) struct MergeFailure {
        pub(super) err: ShareError,
        pub(super) pre_commit: bool,
    }

    impl From<ShareError> for MergeFailure {
        fn from(err: ShareError) -> Self {
            MergeFailure {
                err,
                pre_commit: true,
            }
        }
    }

    pub(super) fn merge_sources_into_classified(
        binary: &Path,
        basename: &str,
        dest: &Path,
        sources: &[PathBuf],
        columns: &[String],
        expect: Option<&DestExpectation<'_>>,
    ) -> Result<(), MergeFailure> {
        for source in sources {
            ensure_safe_attach_path(source)?;
        }

        let dest_tables: HashSet<String> = user_table_names(binary, basename, dest)?
            .into_iter()
            .collect();

        // Per-source carry-table order is computed BEFORE the script is
        // built — each is its own read-only `sqlite3` invocation against
        // that SOURCE path directly, independent of the writable
        // connection this call is about to open against `dest`.
        let mut per_source_carry: Vec<Vec<String>> = Vec::with_capacity(sources.len());
        for source in sources {
            let mut carry: Vec<String> = user_table_names(binary, basename, source)?
                .into_iter()
                .filter(|t| t != "threads")
                .filter(|t| !CODEX_MERGE_BOOKKEEPING_TABLES.contains(&t.as_str()))
                .filter(|t| dest_tables.contains(t))
                .collect();
            carry.sort();
            per_source_carry.push(topo_sort_tables_by_fk(binary, source, &carry)?);
        }

        // Repair targets are read from `dest` itself, restricted to targets
        // `dest`'s OWN schema actually has (a target table `threads`
        // declares a FK to but that this particular database lacks is
        // skipped rather than generating a `no such table` script failure —
        // codex's real, single-origin schema never has this shape, but a
        // test fixture or a future schema variant might).
        let repair_targets: Vec<(String, String)> = threads_repairable_fk_targets(binary, dest)?
            .into_iter()
            .filter(|(_, target_table)| dest_tables.contains(target_table))
            .collect();

        let id_q = quote_ident("id");
        let set_clause = threads_merge_set_clause(columns);

        let mut script = format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};\n");
        let gate = if expect.is_some() {
            gate_exists(&[MERGE_GATE])
        } else {
            "1".to_owned()
        };
        let mut aliases: Vec<String> = Vec::with_capacity(sources.len());
        let mut dest_columns_cache: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for (i, source) in sources.iter().enumerate() {
            let alias = format!("src{i}");
            let quoted_source = sql_quote_path(source)?;
            script.push_str(&format!("ATTACH DATABASE '{quoted_source}' AS {alias};\n"));
            aliases.push(alias);
        }
        script.push_str("BEGIN IMMEDIATE;\n");
        // Right after the write lock is taken and before any write: the
        // destination must still be what the apply step verified. These
        // temp-table guards read `dest` under the lock, so nothing can
        // change it between the check and the writes below.
        if let Some(expect) = expect {
            let Some(guards) = dest_guard_script(expect) else {
                return Err(ShareError::SqliteGuardValueUnsafe {
                    basename: basename.to_string(),
                    path: PathBuf::from(crate::cli_deps::sanitize::redact_path(dest)),
                }
                .into());
            };
            script.push_str(&guards);
        }
        #[cfg(test)]
        // Not the first-creation seed merge into `.new-share`: tests arm
        // this for the merge into an EXISTING shared DB.
        if TEST_FORCE_SCRIPT_FAILURE.with(|c| c.get())
            && !dest.to_string_lossy().ends_with(".new-share")
        {
            // After the guards, before any write: a generic failure of the
            // script that is not a guard refusal.
            script.push_str("SELECT 1 FROM csq_forced_generic_failure_no_such_table;\n");
        }

        for (i, alias) in aliases.iter().enumerate() {
            script.push_str(&format!(
                "INSERT INTO threads SELECT * FROM {alias}.threads WHERE {id_q} NOT IN (SELECT {id_q} FROM threads) AND {gate};\n"
            ));
            if !columns.is_empty() {
                script.push_str(&format!(
                    "UPDATE threads SET\n  {set_clause}\n\
                     FROM (SELECT * FROM {alias}.threads) AS s\n\
                     WHERE threads.{id_q} = s.{id_q} AND {gate};\n"
                ));
            }
            for t in &per_source_carry[i] {
                // M2: an explicit, NAMED column list on both sides — never
                // `SELECT *` — so rows land in the correct destination
                // column even when the source's physical column order
                // differs from the destination's. The two sides' column
                // SETS must match exactly first; a set mismatch (a column
                // gained or dropped somewhere this module never directly
                // compares two databases' non-`threads` schemas) refuses
                // rather than silently dropping or misaligning data.
                // The destination's columns are the same for every source,
                // so they are read once per carried table per call.
                let dest_cols = match dest_columns_cache.get(t) {
                    Some(cols) => cols.clone(),
                    None => {
                        let cols = table_column_names(binary, basename, dest, t)?;
                        dest_columns_cache.insert(t.clone(), cols.clone());
                        cols
                    }
                };
                let source_cols = table_column_names(binary, basename, &sources[i], t)?;
                let dest_set: HashSet<&String> = dest_cols.iter().collect();
                let source_set: HashSet<&String> = source_cols.iter().collect();
                if dest_set != source_set {
                    return Err(ShareError::SqliteCarriedTableColumnMismatch {
                        basename: basename.to_string(),
                        table: t.clone(),
                        path: PathBuf::from(crate::cli_deps::sanitize::redact_path(&sources[i])),
                    }
                    .into());
                }
                let col_list = dest_cols
                    .iter()
                    .map(|c| quote_ident(c))
                    .collect::<Vec<_>>()
                    .join(", ");
                let tq = quote_ident(t);
                script.push_str(&format!(
                    "INSERT OR IGNORE INTO main.{tq} ({col_list}) SELECT {col_list} FROM {alias}.{tq} WHERE {gate};\n"
                ));
            }
        }

        for (column, target_table) in &repair_targets {
            let cq = quote_ident(column);
            let tq = quote_ident(target_table);
            script.push_str(&format!(
                "UPDATE threads SET {cq} = NULL WHERE {cq} IS NOT NULL AND {cq} NOT IN (SELECT {id_q} FROM {tq}) AND {gate};\n"
            ));
        }

        // The guard: any foreign-key violation left standing after the
        // repair above — an unrecognised `threads` column, a violation on
        // any OTHER table entirely — trips this NAMED `CHECK` and aborts
        // the script (`-bail`) before `COMMIT` is ever reached, so the
        // uncommitted transaction is discarded when this connection closes.
        // It is `INSERT OR ROLLBACK`: it necessarily follows the writes, so it
        // cannot be gated, and only `COMMIT` follows it. On a sqlite3 that
        // keeps executing past an error, the rollback has already ended the
        // transaction and that `COMMIT` fails ("no transaction is active")
        // instead of landing the violating rows (measured without `-bail` on
        // 3.45.1 and 3.50.4; Apple's /usr/bin/sqlite3 3.54.0 is covered by
        // `orphan_refusal_holds_on_a_sqlite3_that_does_not_bail`; stderr still
        // names the constraint). That holds when BEGIN IMMEDIATE succeeded; the
        // run is classed pre-commit only when stderr holds no other error
        // (`only_named_guard_failure`), and every write is refused up front
        // unless `ensure_stops_at_first_error` measured that this sqlite3
        // stops at the first error.
        // The constraint is NAMED (`CONSTRAINT <name> CHECK (...)`) rather
        // than bare specifically so `remap_fk_guard_violation` can match on
        // an identifier no source database's own schema could plausibly
        // also produce a `CHECK constraint failed:` message containing.
        // R2: the script deliberately ends at `COMMIT` — no `DETACH`
        // afterward. A `DETACH` failing (however unlikely) AFTER `COMMIT`
        // has already succeeded would make this whole `sqlite3` invocation
        // exit non-zero even though the data is durably committed, and
        // `run_sqlite3`'s caller has no way to tell "COMMIT itself failed"
        // apart from "COMMIT succeeded, something after it did not" — the
        // ENTIRE point of B1 was that a non-zero exit here means nothing
        // committed. Every attachment this script made is per-CONNECTION,
        // not per-transaction, so it is dropped automatically the moment
        // this `sqlite3` process exits — an explicit `DETACH` is
        // redundant for a one-shot script and only widens the post-COMMIT
        // failure surface. (The alternative the review offered — moving
        // `DETACH` to a second, separate `sqlite3` invocation — was
        // rejected: a second process is itself a second chance to fail
        // AFTER the first one's `COMMIT`, which is the exact class of
        // failure this is trying to eliminate, not relocate.)
        script.push_str(&format!(
            "CREATE TEMP TABLE fk_guard(n INTEGER CONSTRAINT {FK_GUARD_CONSTRAINT_NAME} CHECK (n = 0));\n\
             INSERT OR ROLLBACK INTO fk_guard SELECT count(*) FROM pragma_foreign_key_check;\n\
             COMMIT;\n"
        ));

        run_sqlite3(binary, dest, &script).map_err(|e| {
            let raw = match &e {
                ShareError::SqliteCommandFailed { detail, .. } => Some(detail.clone()),
                _ => None,
            };
            let e = remap_fk_guard_violation(
                basename,
                dest,
                remap_dest_guard_violation(basename, dest, e),
            );
            let pre_commit = merge_failure_is_pre_commit(&raw, &e);
            MergeFailure { err: e, pre_commit }
        })?;
        Ok(())
    }

    /// Escapes an arbitrary SQL string LITERAL for interpolation into a
    /// generated script by DOUBLING every embedded `'` (as opposed to
    /// [`sql_quote_path`], which does the identical doubling but is named
    /// for its one call site) — the script is sent as a single batch over
    /// `sqlite3`'s stdin ([`run_sqlite3_with`], `-batch -bail`), never as a
    /// bound parameter, so an unescaped `'` would close the literal early
    /// and let whatever follows execute as SQL. Shared by
    /// [`repair_dead_rollout_paths`] for the `id` / `rollout_path` values it
    /// interpolates — these are READ BACK out of the database before being
    /// written into a new statement, so they are NOT this module's own
    /// writes: they are whatever codex-cli itself wrote, or whatever another
    /// slot's row carried into this one through an earlier
    /// [`merge_threads`] cross-slot merge.
    fn sql_quote_str(s: &str) -> String {
        s.replace('\'', "''")
    }

    /// M1: a newline, carriage return, or NUL byte inside a value that is
    /// about to be single-quote-escaped and interpolated into a generated
    /// SQL script (never bound as a parameter — see [`run_sqlite3_with`]'s
    /// stdin-script transport) can desynchronize the script this module
    /// sends to `sqlite3`'s stdin, the same class [`ensure_safe_attach_path`]
    /// already refuses for `ATTACH DATABASE` paths. Used on every value
    /// [`repair_dead_rollout_paths`] reads back OUT of a database before
    /// writing it into a new statement — those values are not this
    /// process's own writes; they are whatever codex-cli, or a merge from
    /// another slot, put there.
    fn contains_sql_literal_control_byte(s: &str) -> bool {
        s.contains(['\n', '\r', '\0'])
    }

    /// T2: repairs `threads.rollout_path` rows left dangling by a deleted
    /// handle dir. `csq run`'s codex launch points `CODEX_HOME` at the
    /// EPHEMERAL `term-<pid>/` handle dir (`csq/src/cli/commands/run.rs`),
    /// so every rollout path codex-cli records while that dir is alive has
    /// the shape `<base>/term-<pid>/sessions/<rest>` — and the handle dir is
    /// removed once the session exits, even though the SAME rollout file
    /// also lives on, untouched, at
    /// `<base>/shared-state/codex/codex-sessions/<rest>` (the
    /// [`super::super::CODEX_SHARED`] symlink target every codex slot links
    /// its `codex-sessions` entry to). `resume` against the dead
    /// `term-<pid>` path then fails even though the transcript is fully
    /// intact under the shared root.
    ///
    /// A row is rewritten ONLY when its recorded path does not exist ON
    /// DISK and the computed shared-root replacement DOES: a row whose file
    /// is missing everywhere is left alone (that transcript is genuinely
    /// gone; inventing a target for it would point `resume` at nothing),
    /// and a row whose original path still resolves has nothing to repair.
    ///
    /// `db_path` MUST be the CANONICAL shared `threads` database — this is
    /// called only from [`share_codex_sqlite_locked`], on a
    /// basename it has already confirmed carries [`SqliteDbRole::State`],
    /// never on a per-slot working copy.
    fn repair_dead_rollout_paths(
        binary: &Path,
        db_path: &Path,
        base: &Path,
    ) -> Result<usize, ShareError> {
        let shared_root = PathBuf::from(format!(
            "{}/shared-state/codex/codex-sessions",
            base.display()
        ));
        repair_dead_rollout_paths_in(binary, db_path, base, &[shared_root])
    }

    /// Repairs dead `threads.rollout_path` rows (R9) in a slot's `state_5`
    /// database: a row is rewritten only when its old path is gone AND the same
    /// relative path exists as a regular file under one of `session_roots`.
    /// Returns the number of rows rewritten; `Ok(0)` when the database does not
    /// exist or has nothing to repair. The caller supplies the whole budget
    /// (`deadline`). It has no production caller: the launch repair is
    /// `repair_resume_all_before` / `repair_resume_target_before`, budgeted in
    /// `csq/src/cli/commands/run.rs`. Kept for the R9 fixtures and the run.rs
    /// launch tests that drive the rollout-path repair directly.
    pub fn repair_slot_rollout_paths_before(
        lock: &super::CodexShareLockGuard,
        base: &Path,
        state_db: &Path,
        session_roots: &[PathBuf],
        deadline: std::time::Instant,
    ) -> Result<usize, ShareError> {
        let _children = lock.hold_for_children();
        match state_db.symlink_metadata() {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(ShareError::io(state_db, e)),
        }
        let binary = resolve_sqlite3()?;
        repair_dead_rollout_paths_before(&binary, state_db, base, session_roots, Some(deadline))
    }

    /// `visited` counts rows OBSERVED: rows of a batch that held no UPDATE are
    /// read and counted but never committed or rechecked in a transaction.
    /// `rewritten` counts only rewrites whose transaction was acknowledged. An
    /// unacknowledged write is never included in `rewritten`, even if its
    /// transaction may have reached COMMIT (`in_flight_commit_unknown`).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PagedResumeProgress {
        pub visited: usize,
        pub rewritten: usize,
        pub databases_completed: usize,
        pub in_flight_commit_unknown: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PagedResumeOutcome {
        Complete(PagedResumeProgress),
        Partial {
            progress: PagedResumeProgress,
            reason: &'static str,
        },
    }

    struct ResumeFilenameIndex {
        roots: Vec<PathBuf>,
        names: std::collections::HashMap<std::ffi::OsString, Vec<(PathBuf, PathBuf)>>,
    }

    #[cfg(all(test, unix))]
    thread_local! {
        static TEST_PAGED_INDEX_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    #[cfg(all(test, unix))]
    pub(super) fn test_paged_index_builds(reset: bool) -> usize {
        TEST_PAGED_INDEX_BUILDS.with(|count| {
            let old = count.get();
            if reset {
                count.set(0);
            }
            old
        })
    }

    fn build_resume_filename_index(
        roots: &[PathBuf],
        deadline: std::time::Instant,
    ) -> Result<ResumeFilenameIndex, &'static str> {
        if std::time::Instant::now() >= deadline {
            return Err("persistent transcript index incomplete within budget");
        }
        #[cfg(all(test, unix))]
        TEST_PAGED_INDEX_BUILDS.with(|count| count.set(count.get() + 1));
        let mut index = ResumeFilenameIndex {
            roots: Vec::new(),
            names: std::collections::HashMap::new(),
        };
        for root in roots {
            if std::time::Instant::now() >= deadline {
                return Err("persistent transcript index incomplete within budget");
            }
            match root.canonicalize() {
                Ok(root) => {
                    if !index.roots.contains(&root) {
                        index.roots.push(root);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err("persistent transcript root unreadable"),
            }
        }
        let mut visited = 0usize;
        for root in &index.roots {
            let mut pending = vec![(PathBuf::new(), 0usize)];
            while let Some((rest, depth)) = pending.pop() {
                if depth > 64 || std::time::Instant::now() >= deadline {
                    return Err("persistent transcript index incomplete within budget");
                }
                for entry in fs::read_dir(root.join(&rest))
                    .map_err(|_| "persistent transcript directory unreadable")?
                {
                    visited += 1;
                    if visited > 20_000 || std::time::Instant::now() >= deadline {
                        return Err("persistent transcript index incomplete within budget");
                    }
                    let entry = entry.map_err(|_| "persistent transcript entry unreadable")?;
                    let child = rest.join(entry.file_name());
                    let meta = entry
                        .path()
                        .symlink_metadata()
                        .map_err(|_| "persistent transcript metadata unreadable")?;
                    #[cfg(windows)]
                    let linked = {
                        use std::os::windows::fs::MetadataExt;
                        meta.file_type().is_symlink() || meta.file_attributes() & 0x400 != 0
                    };
                    #[cfg(not(windows))]
                    let linked = meta.file_type().is_symlink();
                    if linked {
                        continue;
                    }
                    if meta.is_dir() {
                        pending.push((child, depth + 1));
                    } else if meta.is_file() {
                        index
                            .names
                            .entry(entry.file_name())
                            .or_default()
                            .push((root.clone(), child));
                    }
                }
            }
        }
        Ok(index)
    }

    fn indexed_resume_candidate(
        recorded: &str,
        index: &ResumeFilenameIndex,
    ) -> Result<Option<RepairCandidate>, &'static str> {
        let recorded = Path::new(recorded);
        if !recorded.is_absolute()
            || recorded.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("recorded transcript path is not admitted");
        }
        match recorded.canonicalize() {
            Ok(path) => {
                for root in &index.roots {
                    if let Ok(rest) = path.strip_prefix(root) {
                        return admit_rollout_candidate(root, rest)
                            .map_err(|_| "recorded transcript failed fresh no-follow admission")?
                            .map(Some)
                            .ok_or("recorded transcript is not an admitted regular file");
                    }
                }
                return Err("recorded transcript is outside persistent roots");
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err("recorded transcript metadata unreadable"),
        }
        let name = recorded
            .file_name()
            .ok_or("recorded transcript has no filename")?;
        let Some(candidates) = index.names.get(name) else {
            // Absence is meaningful only after the one complete index build.
            return Ok(None);
        };
        if candidates.len() != 1 {
            return Err("transcript filename has multiple persistent candidates");
        }
        let (root, rest) = &candidates[0];
        admit_rollout_candidate(root, rest)
            .map_err(|_| "indexed transcript failed fresh no-follow admission")?
            .map(Some)
            .ok_or("indexed transcript changed after discovery")
    }

    pub(super) struct PagedResumeRow {
        rowid: i64,
        id: String,
        old: String,
        new: Option<String>,
        _owner: Option<RepairCandidate>,
    }

    #[cfg(test)]
    impl PagedResumeRow {
        pub(super) fn for_test(n: i64, rewrite: bool) -> Self {
            Self {
                rowid: n + 1,
                id: format!("r{n}"),
                old: format!("/missing/r{n}.jsonl"),
                new: rewrite.then(|| format!("/persistent/r{n}.jsonl")),
                _owner: None,
            }
        }
    }

    /// Full resume repair traverses live rowid-keyset pages, not a global frozen
    /// database snapshot. In a write batch that holds at least one UPDATE, every
    /// row travelling with it is guarded, including canonical and
    /// absent-everywhere no-update rows, so a no-update row that changed voids
    /// that batch's UPDATEs. A batch that holds NO UPDATE spends no transaction
    /// and guards nothing: its rows are only observed (counted in `visited`,
    /// never in `rewritten`), so a retry after a partial run does not pay a
    /// commit per row it already repaired.
    pub fn repair_resume_all_before(
        lock: &super::CodexShareLockGuard,
        base: &Path,
        databases: &[PathBuf],
        roots: &[PathBuf],
        deadline: std::time::Instant,
    ) -> PagedResumeOutcome {
        // Every write batch's child inherits the caller's migration lock.
        let _children = lock.hold_for_children();
        let mut progress = PagedResumeProgress::default();
        let result = (|| {
            if !base.is_absolute() || ensure_safe_attach_path(base).is_err() {
                return Err("resume repair base is not admitted");
            }
            let index = build_resume_filename_index(roots, deadline)?;
            let binary = resolve_sqlite3().map_err(|_| "sqlite dependency unavailable")?;
            // The caller's deadline bounds admission, discovery and the index
            // walk above. Each database's repair is bounded by its OWN
            // windows, never by one coarse deadline over the whole walk:
            // every spawned sqlite3 child gets a fresh step window (see
            // `CODEX_REPAIR_STEP_BUDGET`) and the caller-side walk of each
            // returned page a fresh read-tolerance window (`page_budget`), so
            // a slow-but-progressing database completes and a child or page
            // that overruns its own window still refuses. A database that
            // returned Ok has finished every step inside its windows; its
            // committed work is NOT re-judged against a stale budget after
            // the fact. Only empty work is checked against the caller's
            // deadline, so an already-spent caller budget still ends Partial
            // with default progress rather than claiming Complete.
            //
            // ENFORCED WORST CASE (arithmetic over enforced mechanisms, never
            // a measurement). Per database, let R be the rows the walk visits.
            // Each is a distinct rowid strictly above the previous one (the
            // "cursor did not advance" refusal) and at or below the highwater
            // read before paging (the page SQL's `rowid<=highwater`), so R is
            // bounded by the distinct rowids at or below that highwater that
            // exist DURING the walk, not by a count captured before it: rows
            // inserted below the highwater mid-walk are visited too. Page
            // reads P <= R + 1 (at most 500 rows per page, at least one per
            // non-final page); flushed write batches B <= R (each holds at
            // least one row and spawns at most one child). Every re-arm
            // extends the budget by at most its own window past the moment it
            // is armed, so:
            //   (5 fixed reads + P page reads + B batches)
            //       x (STEP 9s + REPAIR_CHILD_CLEANUP_GRACE 100ms)
            //   + (P + B) x READ_TOLERANCE 4s
            // where the 4s windows are the walk window armed after each page
            // read and re-armed after each acknowledged batch, each
            // max(remaining window, 4s); plus the -bail probe's enforced
            // PROBE_BUDGET 5s + 100ms grace once per probe-cache key (binary
            // path, size, mtime) per process; summed over at most 1024
            // discovered databases (the caller's discovery cap), after the
            // caller's own 13s allowance.
            // NOT BOUNDED: one row's filesystem admission
            // (`indexed_resume_candidate` canonicalizes a database-supplied
            // path, then opens the candidate) runs between deadline checks and
            // no timer interrupts it, so a hung mount under a recorded path can
            // stall the launch indefinitely.
            if databases.is_empty() && std::time::Instant::now() >= deadline {
                return Err("shared resume repair deadline exhausted");
            }
            for db in databases {
                repair_resume_database_paged(
                    &binary,
                    db,
                    &index,
                    step_budget(deadline),
                    &mut progress,
                )?;
                progress.databases_completed += 1;
            }
            Ok(())
        })();
        match result {
            Ok(()) => PagedResumeOutcome::Complete(progress),
            Err(reason) => PagedResumeOutcome::Partial { progress, reason },
        }
    }

    // Bind each admitted schema row once. Repeating the large upstream
    // trigger projection per object can exhaust the write budget before a row.
    fn paged_schema_condition(objects: &[String]) -> String {
        let from = "sqlite_master WHERE type IN ('trigger','view')";
        if objects.is_empty() {
            return format!("(SELECT count(*) FROM {from})=0");
        }
        let values = objects
            .iter()
            .map(|row| format!("('{}')", sql_quote_str(row)))
            .collect::<Vec<_>>()
            .join(",");
        format!("(SELECT count(*) FROM {from})={} AND NOT EXISTS (SELECT {SCHEMA_OBJECT_ROW_EXPR} FROM {from} EXCEPT SELECT column1 FROM (VALUES {values}))", objects.len())
    }

    fn repair_resume_database_paged(
        binary: &Path,
        db: &Path,
        index: &ResumeFilenameIndex,
        deadline: std::time::Instant,
        progress: &mut PagedResumeProgress,
    ) -> Result<(), &'static str> {
        // Every read and every batch write below spawns one sqlite3 child:
        // each runs under a fresh step window (see `CODEX_REPAIR_STEP_BUDGET`)
        // so a slow but progressing host completes the repair.
        let budget = std::cell::Cell::new(deadline);
        let read = |sql: &str| {
            let next = step_budget(budget.get());
            budget.set(next);
            run_repair_sqlite_bounded(binary, db, sql, true, next)
                .map_err(|_| "bounded resume database read failed")
        };
        let schema = read(&format!(
            "SELECT {SCHEMA_OBJECT_ROW_EXPR} FROM sqlite_master WHERE type IN ('trigger','view');"
        ))?;
        let objects = validate_schema_objects("paged resume", db, &schema)
            .map_err(|_| "resume database schema objects are not admitted")?;
        let table = read("SELECT hex(coalesce(sql,'')) FROM sqlite_master WHERE type='table' AND name='threads' LIMIT 2;")?;
        let tables: Vec<_> = table.lines().collect();
        if tables.is_empty() {
            return Ok(());
        }
        if tables.len() != 1 {
            return Err("resume database table is ambiguous");
        }
        let table_sql = decode_resume_hex(tables[0])
            .map_err(|_| "resume table schema encoding is not admitted")?;
        if !table_sql
            .trim_start()
            .to_ascii_uppercase()
            .starts_with("CREATE TABLE")
        {
            return Err("resume cursor requires an ordinary SQLite table");
        }
        let columns = read("PRAGMA table_info(threads);")?;
        let names: Vec<_> = columns
            .lines()
            .filter_map(|line| line.split('|').nth(1))
            .collect();
        if !names.contains(&"rollout_path") {
            return Ok(()); // Valid legacy schema has no rollout projection.
        }
        if !names.contains(&"id")
            || names.iter().any(|name| {
                ["rowid", "_rowid_", "oid"]
                    .iter()
                    .any(|reserved| name.eq_ignore_ascii_case(reserved))
            })
        {
            return Err("resume database does not expose an unshadowed physical rowid");
        }
        // WITHOUT ROWID is conservatively unsupported; query also proves the
        // real physical cursor exists before interpreting any empty page.
        read("SELECT rowid FROM threads LIMIT 1;")
            .map_err(|_| "resume database does not expose a physical rowid")?;
        let mut header =
            format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};\nBEGIN IMMEDIATE;\n");
        header.push_str(&named_guard_sql(
            "csq_paged_schema_unchanged",
            &paged_schema_condition(&objects),
        ));
        header.push_str(&named_guard_sql("csq_paged_table_unchanged", &format!(
            "(SELECT count(*) FROM sqlite_master WHERE type='table' AND name='threads' AND hex(coalesce(sql,''))='{}')=1",
            sql_quote_str(tables[0]))));
        // Capture a finite per-database tail. Later appends are left to the
        // next launch; keyset traversal is not a globally frozen snapshot.
        let tail = read(
            "SELECT coalesce(max(rowid),'EMPTY') FROM threads WHERE rollout_path IS NOT NULL;",
        )?;
        if tail.trim() == "EMPTY" {
            return Ok(());
        }
        let highwater = tail
            .trim()
            .parse::<i64>()
            .map_err(|_| "invalid resume highwater cursor")?;
        let mut cursor: Option<i64> = None;
        loop {
            if std::time::Instant::now() >= budget.get() {
                return Err("shared resume repair deadline exhausted");
            }
            let after = cursor.map_or(String::new(), |rowid| format!(" AND rowid>{rowid}"));
            // The cumulative encoded payload is bounded independently of row
            // count. An individually oversized first row emits a short refusal
            // marker instead of impersonating end-of-table.
            let sql = format!("WITH candidates AS (SELECT rowid AS r,id,rollout_path FROM threads WHERE rollout_path IS NOT NULL AND rowid<={highwater}{after} ORDER BY rowid LIMIT 500), sized AS (SELECT r,id,rollout_path,SUM(length(hex(id))+length(hex(rollout_path))+32) OVER (ORDER BY r ROWS UNBOUNDED PRECEDING) AS bytes FROM candidates) SELECT payload FROM (SELECT r AS sequence,r||'|'||hex(id)||'|'||hex(rollout_path) AS payload FROM sized WHERE bytes<=524288 UNION ALL SELECT r AS sequence,'OVERSIZE' AS payload FROM sized WHERE bytes>524288 AND r=(SELECT min(r) FROM sized)) ORDER BY sequence;");
            let page = read(&sql)?;
            if page.is_empty() {
                return Ok(());
            }
            #[cfg(test)]
            test_paged_walk_point(PagedWalkPoint::PageRead);
            // The walk of this page is the caller's own work, not the read
            // child's: give it its own window from the moment the page arrived
            // (see `page_budget`).
            budget.set(page_budget(budget.get()));
            let mut batch = PagedBatch::new(&header);
            let mut pending = Vec::new();
            for line in page.lines() {
                #[cfg(test)]
                test_paged_walk_point(PagedWalkPoint::Row);
                if std::time::Instant::now() >= budget.get() {
                    return Err("shared resume repair deadline exhausted");
                }
                if line == "OVERSIZE" {
                    return Err("resume row exceeds bounded read payload");
                }
                let mut fields = line.split('|');
                let rowid = fields
                    .next()
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or("invalid resume row cursor")?;
                if cursor.is_some_and(|last| rowid <= last) {
                    return Err("resume physical cursor did not advance");
                }
                let id = decode_resume_hex(fields.next().ok_or("missing resume id")?)
                    .map_err(|_| "resume id encoding is not admitted")?;
                let old = decode_resume_hex(fields.next().ok_or("missing resume path")?)
                    .map_err(|_| "resume path encoding is not admitted")?;
                if fields.next().is_some()
                    || id.is_empty()
                    || contains_sql_literal_control_byte(&id)
                    || contains_sql_literal_control_byte(&old)
                {
                    return Err("resume row data is not admitted");
                }
                let candidate = indexed_resume_candidate(&old, index)?;
                let new = candidate
                    .as_ref()
                    .map(|candidate| {
                        candidate
                            .path
                            .to_str()
                            .ok_or("persistent transcript path is not UTF-8")
                    })
                    .transpose()?;
                if new.is_some_and(contains_sql_literal_control_byte) {
                    return Err("persistent transcript path contains control bytes");
                }
                let new = new.filter(|path| *path != old).map(str::to_owned);
                let row = PagedResumeRow {
                    rowid,
                    id,
                    old,
                    new,
                    _owner: candidate,
                };
                cursor = Some(rowid);
                let (guard, update) = paged_row_sql(&row);
                if (batch.projected_len(&guard, update.as_deref()) > PAGED_BATCH_BYTES
                    || pending.len() >= 32)
                    && !pending.is_empty()
                {
                    let next = step_budget(budget.get());
                    budget.set(next);
                    commit_resume_batch(binary, db, &batch, &pending, next, progress)?;
                    #[cfg(test)]
                    test_paged_walk_point(PagedWalkPoint::BatchCommitted);
                    // The rows after this batch are the caller's own work, not
                    // the batch child's: re-arm their walk window from the
                    // moment the batch was acknowledged (see `page_budget`).
                    budget.set(page_budget(budget.get()));
                    pending.clear();
                    batch = PagedBatch::new(&header);
                }
                if batch.projected_len(&guard, update.as_deref()) > PAGED_BATCH_BYTES {
                    return Err("resume row guard exceeds bounded write payload");
                }
                batch.push(&guard, update.as_deref());
                pending.push(row);
            }
            if !pending.is_empty() {
                let next = step_budget(budget.get());
                budget.set(next);
                commit_resume_batch(binary, db, &batch, &pending, next, progress)?;
                #[cfg(test)]
                test_paged_walk_point(PagedWalkPoint::BatchCommitted);
                // As above: the loop's own check before the next page read is
                // not charged to this batch child's window.
                budget.set(page_budget(budget.get()));
            }
        }
    }

    /// A point in the caller-side walk at which a test may spend time, to model
    /// a child that returned late inside its own window, or a slow walk.
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum PagedWalkPoint {
        /// A non-empty page read returned, before its walk window is armed.
        PageRead,
        /// The top of one row's walk, before its deadline check.
        Row,
        /// A write batch was acknowledged, before the walk window is re-armed.
        BatchCommitted,
        /// The exact route's target-row read returned, before its walk window.
        ExactRowsRead,
        /// The exact route's filename search pops one directory, before its
        /// deadline check.
        ExactSearchDir,
    }

    #[cfg(test)]
    type PagedWalkHook = Box<dyn FnMut(PagedWalkPoint)>;

    #[cfg(test)]
    thread_local! {
        static TEST_PAGED_WALK_HOOK: std::cell::RefCell<Option<PagedWalkHook>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Clears the walk hook on drop, including on a panicking test. Unix-only,
    /// like every test that installs a hook.
    #[cfg(all(test, unix))]
    pub(super) struct PagedWalkHookGuard;

    #[cfg(all(test, unix))]
    impl Drop for PagedWalkHookGuard {
        fn drop(&mut self) {
            TEST_PAGED_WALK_HOOK.with(|cell| *cell.borrow_mut() = None);
        }
    }

    #[cfg(all(test, unix))]
    pub(super) fn set_test_paged_walk_hook(
        hook: impl FnMut(PagedWalkPoint) + 'static,
    ) -> PagedWalkHookGuard {
        TEST_PAGED_WALK_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
        PagedWalkHookGuard
    }

    #[cfg(test)]
    fn test_paged_walk_point(point: PagedWalkPoint) {
        TEST_PAGED_WALK_HOOK.with(|cell| {
            if let Some(hook) = cell.borrow_mut().as_mut() {
                hook(point);
            }
        });
    }

    /// The row guard and, when the row needs rewriting, its UPDATE. The guard
    /// is a row in the batch's `csq_paged_rows` table, whose `CHECK` fails when
    /// the row changed since it was read; the UPDATE is predicated on the batch
    /// gate, which only holds when EVERY row guard (all emitted before the first
    /// UPDATE) and both header guards held.
    pub(super) fn paged_row_sql(row: &PagedResumeRow) -> (String, Option<String>) {
        let guard = format!(
            "INSERT INTO {PAGED_ROWS} SELECT ((SELECT count(*) FROM threads WHERE id='{}')=1 AND (SELECT count(*) FROM threads WHERE rowid={} AND id='{}' AND rollout_path='{}')=1);\n",
            sql_quote_str(&row.id), row.rowid, sql_quote_str(&row.id), sql_quote_str(&row.old));
        let update = row.new.as_ref().map(|new| format!("UPDATE threads SET rollout_path='{}' WHERE rowid={} AND id='{}' AND rollout_path='{}' AND {};\n",
            sql_quote_str(new), row.rowid, sql_quote_str(&row.id), sql_quote_str(&row.old),
            gate_exists(&[PAGED_BATCH_GATE])));
        (guard, update)
    }

    /// 10k UTF-8 script bytes keep one launch-time transaction small, far
    /// under the launch runner's `REPAIR_SCRIPT_CAP`.
    const PAGED_BATCH_BYTES: usize = 10_000;
    const COMMIT_SQL: &str = "COMMIT;\n";
    const PAGED_ROWS: &str = "csq_paged_rows";
    const PAGED_BATCH_GATE: &str = "csq_paged_batch_gate";
    const PAGED_HEADER_GUARDS: [&str; 2] =
        ["csq_paged_schema_unchanged", "csq_paged_table_unchanged"];

    /// One transaction's script, laid out as: header guards, the row-guard
    /// table, EVERY row guard, one batch gate that requires all of them, then
    /// the UPDATEs (each predicated on the batch gate), then `COMMIT`. A failed
    /// row guard therefore voids every UPDATE of the batch even on a sqlite3
    /// that keeps executing past an error, so a failed GUARD cannot leave a
    /// partly committed batch and is a known rollback. Failures that are not
    /// guards (a UNIQUE violation, a failed BEGIN) are not covered by the gate:
    /// they are stopped by `-bail`, which `ensure_stops_at_first_error` measures
    /// on the binary before any write, and are classed unknown by
    /// `only_named_guard_failure` if they do occur.
    pub(super) struct PagedBatch<'a> {
        header: &'a str,
        guards: String,
        updates: String,
        rows: usize,
    }

    impl<'a> PagedBatch<'a> {
        pub(super) fn new(header: &'a str) -> Self {
            Self {
                header,
                guards: String::new(),
                updates: String::new(),
                rows: 0,
            }
        }

        /// The text before the row guards and the gate that follows them, for a
        /// batch of `rows` rows.
        fn frame(&self, rows: usize) -> (String, String) {
            let header_terms = PAGED_HEADER_GUARDS
                .into_iter()
                .map(|n| format!("(SELECT count(*) FROM temp.{n} WHERE ok IS 1)=1"))
                .collect::<Vec<_>>()
                .join(" AND ");
            (
                format!(
                    "{}CREATE TEMP TABLE {PAGED_ROWS}(ok INTEGER CONSTRAINT {PAGED_ROWS} CHECK (ok IS 1));\n",
                    self.header
                ),
                named_guard_sql(
                    PAGED_BATCH_GATE,
                    &format!("(SELECT count(*) FROM temp.{PAGED_ROWS} WHERE ok IS 1)={rows} AND {header_terms}"),
                ),
            )
        }

        /// Exact byte length of the script after adding one more row.
        pub(super) fn projected_len(&self, guard: &str, update: Option<&str>) -> usize {
            let (pre, gate) = self.frame(self.rows + 1);
            pre.len()
                + self.guards.len()
                + guard.len()
                + gate.len()
                + self.updates.len()
                + update.map_or(0, str::len)
                + COMMIT_SQL.len()
        }

        pub(super) fn has_updates(&self) -> bool {
            !self.updates.is_empty()
        }

        pub(super) fn push(&mut self, guard: &str, update: Option<&str>) {
            self.guards.push_str(guard);
            if let Some(update) = update {
                self.updates.push_str(update);
            }
            self.rows += 1;
        }

        pub(super) fn script(&self) -> String {
            let (pre, gate) = self.frame(self.rows);
            format!("{pre}{}{gate}{}{COMMIT_SQL}", self.guards, self.updates)
        }
    }

    fn commit_resume_batch(
        binary: &Path,
        db: &Path,
        batch: &PagedBatch<'_>,
        rows: &[PagedResumeRow],
        deadline: std::time::Instant,
        progress: &mut PagedResumeProgress,
    ) -> Result<(), &'static str> {
        if std::time::Instant::now() >= deadline {
            return Err("shared resume repair deadline exhausted before write");
        }
        if !batch.has_updates() {
            // Nothing to write, so nothing to guard: no transaction.
            progress.visited += rows.len();
            return Ok(());
        }
        #[cfg(test)]
        TEST_REPAIR_BEFORE_WRITE.with(|cell| {
            if let Some(hook) = cell.borrow_mut().take() {
                hook();
            }
        });
        let script = batch.script();
        let mut commit_unknown = false;
        if run_repair_sqlite_bounded_tracking(
            binary,
            db,
            &script,
            false,
            deadline,
            &mut commit_unknown,
        )
        .is_err()
        {
            // A timeout/read failure may occur after COMMIT but before receipt.
            // No unacknowledged batch contributes to `rewritten`, the committed counter.
            progress.in_flight_commit_unknown = commit_unknown;
            return Err("resume write batch completion was not acknowledged");
        }
        progress.visited += rows.len();
        progress.rewritten += rows.iter().filter(|row| row.new.is_some()).count();
        Ok(())
    }

    /// Exact resume admission; unlike migration repair this never reads unrelated rows.
    /// Returns one when the target is admitted, zero when this database lacks it.
    pub fn repair_resume_target_before(
        lock: &super::CodexShareLockGuard,
        base: &Path,
        state_db: &Path,
        session_roots: &[PathBuf],
        target: &str,
        deadline: std::time::Instant,
    ) -> Result<usize, ShareError> {
        // The rewrite's child inherits the caller's migration lock.
        let _children = lock.hold_for_children();
        if target.is_empty()
            || target.len() > 128
            || !target
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(ShareError::CodexResumeTarget {
                reason: "invalid exact thread id",
            });
        }
        match state_db.symlink_metadata() {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(ShareError::io(state_db, e)),
        }
        let binary = resolve_sqlite3()?;
        repair_rollout_paths_selected(
            &binary,
            state_db,
            base,
            session_roots,
            Some(deadline),
            Some(target),
        )
    }

    /// True when `err` says the exact route's BOUNDED WORK BUDGET expired — the
    /// deadline class — rather than that the target is unadmittable. Three
    /// shapes carry it: the bounded runner's own deadline (a
    /// [`ShareError::SqliteCommandFailed`] whose detail IS exactly
    /// `ROLLOUT_REPAIR_DEADLINE_DETAIL`, emitted by both its pre-spawn
    /// refusal and its wait-loop kill), the row/root walk's `TimedOut` IO
    /// error, and the bounded filename search's budget refusal.
    ///
    /// The match is EXACT, never a substring: every other runner detail embeds
    /// the child's stderr, which quotes database content, so a `contains`
    /// match would let a `rollout_path` containing the word "deadline" pick
    /// the class an operator is told to act on.
    ///
    /// The caller must refuse for the RIGHT reason: a starved host is retryable
    /// and leaves persistent state untouched, while a damaged or ambiguous
    /// target needs an operator. Which leg spent the budget never changes the
    /// class — every deadline-expiry is the deadline class.
    pub fn is_bounded_deadline_refusal(err: &ShareError) -> bool {
        match err {
            ShareError::SqliteCommandFailed { detail, .. } => {
                detail == ROLLOUT_REPAIR_DEADLINE_DETAIL
            }
            ShareError::Io { source, .. } => source.kind() == io::ErrorKind::TimedOut,
            ShareError::CodexResumeTarget { reason } => {
                *reason == "target filename search exceeded its bounded budget"
            }
            _ => false,
        }
    }

    fn decode_resume_hex(value: &str) -> Result<String, ShareError> {
        let invalid = || ShareError::CodexResumeTarget {
            reason: "invalid target row encoding",
        };
        if !value.len().is_multiple_of(2) || value.len() > 131_072 {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for pair in value.as_bytes().as_chunks::<2>().0 {
            let high = (pair[0] as char).to_digit(16).ok_or_else(invalid)?;
            let low = (pair[1] as char).to_digit(16).ok_or_else(invalid)?;
            bytes.push((high * 16 + low) as u8);
        }
        String::from_utf8(bytes).map_err(|_| invalid())
    }

    fn resume_candidate(
        recorded: &str,
        roots: &[PathBuf],
        deadline: Option<std::time::Instant>,
    ) -> Result<RepairCandidate, ShareError> {
        let refuse = |reason| ShareError::CodexResumeTarget { reason };
        let recorded = Path::new(recorded);
        if !recorded.is_absolute()
            || recorded
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err(refuse(
                "target recorded path is relative or contains traversal components",
            ));
        }
        let mut canonical_roots = Vec::new();
        for root in roots {
            match root.canonicalize() {
                Ok(root) => {
                    if !canonical_roots.contains(&root) {
                        canonical_roots.push(root);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(ShareError::io(root, e)),
            }
        }
        // Resolving term aliases must be rewritten too: a later native activity
        // can re-record CODEX_HOME even after an earlier canonicalization.
        match recorded.canonicalize() {
            Ok(path) => {
                for root in &canonical_roots {
                    if let Ok(rest) = path.strip_prefix(root) {
                        if let Some(candidate) = admit_rollout_candidate(root, rest)? {
                            return Ok(candidate);
                        }
                    }
                }
                return Err(refuse("recorded rollout is outside the admitted persistent roots or not a regular file"));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(ShareError::io(recorded, e)),
        }
        if recorded.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(refuse("target recorded path contains traversal components"));
        }
        let filename = recorded
            .file_name()
            .ok_or_else(|| refuse("target rollout has no filename"))?;
        let mut found: Option<RepairCandidate> = None;
        let mut visited = 0usize;
        for root in &canonical_roots {
            let mut pending = vec![(PathBuf::new(), 0usize)];
            while let Some((rest, depth)) = pending.pop() {
                #[cfg(test)]
                test_paged_walk_point(PagedWalkPoint::ExactSearchDir);
                if depth > 64 || deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                    return Err(refuse("target filename search exceeded its bounded budget"));
                }
                for entry in fs::read_dir(root.join(&rest)).map_err(|e| ShareError::io(root, e))? {
                    visited += 1;
                    if visited > 20_000 || deadline.is_some_and(|d| std::time::Instant::now() >= d)
                    {
                        return Err(refuse("target filename search exceeded its bounded budget"));
                    }
                    let entry = entry.map_err(|e| ShareError::io(root, e))?;
                    let child = rest.join(entry.file_name());
                    let meta = entry
                        .path()
                        .symlink_metadata()
                        .map_err(|e| ShareError::io(&entry.path(), e))?;
                    #[cfg(windows)]
                    let linked = {
                        use std::os::windows::fs::MetadataExt;
                        meta.file_type().is_symlink() || meta.file_attributes() & 0x400 != 0
                    };
                    #[cfg(not(windows))]
                    let linked = meta.file_type().is_symlink();
                    if entry.file_name() == filename {
                        if let Some(candidate) = admit_rollout_candidate(root, &child)? {
                            if found.as_ref().is_some_and(|old| old.path != candidate.path) {
                                return Err(refuse(
                                    "target filename has multiple admissible transcripts",
                                ));
                            }
                            if found.is_none() {
                                found = Some(candidate);
                            }
                        }
                    }
                    if meta.is_dir() && !linked {
                        pending.push((child, depth + 1));
                    }
                }
            }
        }
        found.ok_or_else(|| refuse("target transcript is missing from persistent storage"))
    }

    #[cfg(test)]
    thread_local! {
        static TEST_REPAIR_BEFORE_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    #[cfg(test)]
    pub(super) fn set_test_repair_before_write(hook: impl FnOnce() + 'static) {
        TEST_REPAIR_BEFORE_WRITE.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn rollout_relative_tail(
        base: &str,
        recorded: &str,
        windows: bool,
    ) -> Option<String> {
        let normalize = |s: &str| {
            if windows {
                s.replace('\\', "/")
            } else {
                s.to_owned()
            }
        };
        let recorded = normalize(recorded);
        let prefix = format!("{}/term-", normalize(base));
        let after = recorded.strip_prefix(&prefix)?;
        let (pid, rest) = after.split_once("/sessions/")?;
        if pid.is_empty()
            || !pid.bytes().all(|b| b.is_ascii_digit())
            || rest.is_empty()
            || rest
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == ".." || (windows && p.contains(':')))
        {
            return None;
        }
        Some(rest.to_owned())
    }

    struct RepairCandidate {
        path: PathBuf,
        // Own the exact no-follow regular file during admission and selection.
        // This is not a lock against later namespace renames; callers require a
        // stable persistent-root namespace while staging and applying repair.
        _owner: fs::File,
    }

    fn recorded_rollout_is_missing(path: &Path) -> Result<bool, ShareError> {
        match path.symlink_metadata() {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(ShareError::io(path, e)),
        }
    }

    #[cfg(test)]
    thread_local! {
        static TEST_REPAIR_BEFORE_CANDIDATE_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    #[cfg(all(test, unix))]
    pub(super) fn set_test_repair_before_candidate_open(hook: impl FnOnce() + 'static) {
        TEST_REPAIR_BEFORE_CANDIDATE_OPEN.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    fn admit_rollout_candidate(
        root: &Path,
        rest: &Path,
    ) -> Result<Option<RepairCandidate>, ShareError> {
        let root = match root.canonicalize() {
            Ok(root) => root,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ShareError::io(root, e)),
        };
        let candidate = root.join(rest);
        // Root aliases are intentional; aliases in the untrusted suffix are not.
        let mut probe = root.clone();
        for part in rest.components() {
            probe.push(part);
            let meta = match probe.symlink_metadata() {
                Ok(meta) => meta,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(ShareError::io(&probe, e)),
            };
            #[cfg(not(windows))]
            let reparse = meta.file_type().is_symlink();
            #[cfg(windows)]
            let reparse = {
                use std::os::windows::fs::MetadataExt;
                meta.file_type().is_symlink() || meta.file_attributes() & 0x400 != 0
            };
            if reparse {
                return Err(ShareError::io(
                    &probe,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "rollout candidate suffix contains a symlink or reparse point",
                    ),
                ));
            }
        }
        let canonical = candidate
            .canonicalize()
            .map_err(|e| ShareError::io(&candidate, e))?;
        if !canonical.starts_with(&root) {
            return Err(ShareError::io(
                &candidate,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollout candidate escapes its persistent root",
                ),
            ));
        }
        #[cfg(test)]
        TEST_REPAIR_BEFORE_CANDIDATE_OPEN.with(|cell| {
            if let Some(hook) = cell.borrow_mut().take() {
                hook();
            }
        });
        let file = open_rollout_nofollow(&root, rest).map_err(|e| ShareError::io(&candidate, e))?;
        let meta = file.metadata().map_err(|e| ShareError::io(&candidate, e))?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Ok(None);
        }
        #[cfg(windows)]
        {
            use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
            use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
            let mut buf = vec![0u16; 32768];
            // SAFETY: file owns a live handle, and buf is writable for its length.
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle() as _,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    0,
                )
            };
            if n == 0 || n as usize >= buf.len() {
                return Err(ShareError::io(&candidate, io::Error::last_os_error()));
            }
            let opened = PathBuf::from(std::ffi::OsString::from_wide(&buf[..n as usize]));
            if opened != canonical || !opened.starts_with(&root) {
                return Err(ShareError::io(
                    &candidate,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "opened rollout candidate differs from its contained path",
                    ),
                ));
            }
        }
        Ok(Some(RepairCandidate {
            path: canonical,
            _owner: file,
        }))
    }

    #[cfg(unix)]
    fn open_rollout_nofollow(root: &Path, rest: &Path) -> io::Result<fs::File> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        };
        let mut dir = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        let parts: Vec<_> = rest.components().collect();
        for (index, part) in parts.iter().enumerate() {
            let name = std::ffi::CString::new(part.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "NUL in rollout suffix")
            })?;
            let final_part = index + 1 == parts.len();
            let flags = if final_part {
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
            };
            // SAFETY: dir owns a live descriptor, name is NUL-terminated, and
            // openat returns a new descriptor anchored beneath that directory.
            let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: this newly opened descriptor transfers exactly once.
            let file = unsafe { fs::File::from_raw_fd(fd) };
            if final_part {
                return Ok(file);
            }
            dir = file;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty rollout suffix",
        ))
    }

    #[cfg(windows)]
    fn open_rollout_nofollow(root: &Path, rest: &Path) -> io::Result<fs::File> {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(root.join(rest))
    }

    fn repair_dead_rollout_paths_in(
        binary: &Path,
        db_path: &Path,
        base: &Path,
        session_roots: &[PathBuf],
    ) -> Result<usize, ShareError> {
        repair_dead_rollout_paths_before(binary, db_path, base, session_roots, None)
    }

    fn repair_dead_rollout_paths_before(
        binary: &Path,
        db_path: &Path,
        base: &Path,
        session_roots: &[PathBuf],
        deadline: Option<std::time::Instant>,
    ) -> Result<usize, ShareError> {
        repair_rollout_paths_selected(binary, db_path, base, session_roots, deadline, None)
    }

    fn repair_rollout_paths_selected(
        binary: &Path,
        db_path: &Path,
        base: &Path,
        session_roots: &[PathBuf],
        deadline: Option<std::time::Instant>,
        target: Option<&str>,
    ) -> Result<usize, ShareError> {
        if !base.is_absolute() {
            // The prefix match below is meaningless against a relative
            // base, and could in principle match relative to sqlite3's own
            // (or this process's) working directory instead of the
            // intended one — refuse rather than guess.
            return Err(ShareError::io(
                base,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "rollout-path repair requires an absolute base",
                ),
            ));
        }
        // S-F8/S-F9 posture: `base` is this process's own configured root,
        // never externally supplied, but the newline/CR/NUL check costs
        // nothing and removes the question — same posture as every other
        // path this module interpolates into a SQL literal.
        ensure_safe_attach_path(base)?;

        // Launch-time repairs bypass the merge planner. Inspect the same exact
        // trigger/view allowlist here, before opening any writable connection.
        // Every call below spawns one sqlite3 child, so each one runs under a
        // fresh step window (see `CODEX_REPAIR_STEP_BUDGET`) — a slow but
        // progressing host completes the repair instead of refusing it.
        let budget = std::cell::Cell::new(deadline);
        let run = |sql: &str, readonly: bool| match budget.get() {
            Some(current) => {
                let next = step_budget(current);
                budget.set(Some(next));
                run_repair_sqlite_bounded(binary, db_path, sql, readonly, next)
            }
            None => run_sqlite3_with(binary, db_path, sql, readonly),
        };
        let schema = run(&format!("SELECT {SCHEMA_OBJECT_ROW_EXPR} FROM sqlite_master WHERE type IN ('trigger','view');"), true)?;
        let schema_objects = validate_schema_objects("rollout repair", db_path, &schema)?;
        let has_threads = run("SELECT name FROM sqlite_master WHERE type='table';", true)?
            .lines()
            .any(|name| name.trim() == "threads");
        if !has_threads {
            return Ok(0);
        }

        // `rollout_path` is a codex-cli schema addition, not a column every
        // `threads` table carries — an older codex-cli, or a test fixture
        // built before this column existed, has a `threads` table with no
        // such column at all. Querying it unconditionally turns "nothing to
        // repair" into a hard sqlite parse error (`no such column:
        // rollout_path`), which would fail this call over a column that was
        // simply never expected to be there. Check first, via
        // `PRAGMA table_info`, and skip cleanly when it is absent.
        let columns = run("PRAGMA table_info(threads);", true)?;
        let has_rollout_path = columns.lines().any(|line| {
            let mut fields = line.split('|');
            let _cid = fields.next();
            fields.next() == Some("rollout_path")
        });
        if !has_rollout_path {
            tracing::debug!(
                db = %crate::cli_deps::sanitize::redact_path(db_path),
                "codex sqlite rollout-path repair: no rollout_path column, nothing to repair"
            );
            return Ok(0);
        }

        let base_str = base.display().to_string();

        // Coarse pre-filter only — every candidate is re-verified in Rust
        // below against the EXACT `<base>/term-<digits>/sessions/` shape,
        // so a `%`/`_` occurring literally inside `base_str` can only widen
        // this SELECT's candidate set, never cause an incorrect REWRITE.
        let rows = if let Some(target) = target {
            run(
                &format!(
                    "SELECT hex(id), hex(rollout_path) FROM threads WHERE id='{}' LIMIT 2;",
                    sql_quote_str(target)
                ),
                true,
            )?
        } else {
            run(
                "SELECT id, rollout_path FROM threads WHERE rollout_path IS NOT NULL;",
                true,
            )?
        };
        #[cfg(test)]
        test_paged_walk_point(PagedWalkPoint::ExactRowsRead);
        // The row walk below, including the exact route's transcript filename
        // search, is the caller's own work, not the row read child's: give it
        // its own window from the moment the rows arrived (see `page_budget`).
        budget.set(budget.get().map(page_budget));
        let mut selected = Vec::new();
        for line in rows.lines() {
            if let Some((id, path)) = line.split_once('|') {
                selected.push(if target.is_some() {
                    (decode_resume_hex(id)?, decode_resume_hex(path)?)
                } else {
                    (id.to_owned(), path.to_owned())
                });
            } else if target.is_some() {
                return Err(ShareError::CodexResumeTarget {
                    reason: "invalid exact target row",
                });
            }
        }
        if let Some(target) = target {
            if selected.is_empty() {
                return Ok(0);
            }
            if selected.len() != 1 || selected[0].0 != target {
                return Err(ShareError::CodexResumeTarget {
                    reason: "ambiguous exact target row",
                });
            }
        }
        let mut updates: Vec<(String, String, String)> = Vec::new(); // (id, old, new)
        let mut target_owners = Vec::new();
        for (id, rollout_path) in &selected {
            if budget
                .get()
                .is_some_and(|limit| std::time::Instant::now() >= limit)
            {
                return Err(ShareError::io(
                    db_path,
                    io::Error::new(io::ErrorKind::TimedOut, "rollout repair deadline"),
                ));
            }
            // M1: `id`/`rollout_path` are read from the database this call is
            // about to WRITE BACK into via a generated SQL literal — a row
            // this module did not itself insert (a hand-modified or
            // maliciously merged `threads` table) could carry a control byte
            // that desynchronizes the generated script. Refuse rather than
            // interpolate, matching `ensure_safe_attach_path`'s posture on
            // every other value this module attaches into SQL.
            if contains_sql_literal_control_byte(id)
                || contains_sql_literal_control_byte(rollout_path)
            {
                if target.is_some() {
                    return Err(ShareError::CodexResumeTarget {
                        reason: "target row contains control bytes",
                    });
                }
                continue;
            }
            if target.is_some() {
                let candidate = resume_candidate(rollout_path, session_roots, budget.get())?;
                let new_path = candidate
                    .path
                    .to_str()
                    .ok_or(ShareError::CodexResumeTarget {
                        reason: "target path is not UTF-8",
                    })?;
                if contains_sql_literal_control_byte(new_path) {
                    return Err(ShareError::CodexResumeTarget {
                        reason: "target path contains control bytes",
                    });
                }
                if new_path != rollout_path {
                    updates.push((id.clone(), rollout_path.clone(), new_path.to_owned()));
                }
                target_owners.push(candidate);
                continue;
            }
            let Some(rest) = rollout_relative_tail(&base_str, rollout_path, cfg!(windows)) else {
                continue;
            };
            // M1: `rest` becomes a path SUFFIX appended onto
            // `shared_sessions_root` below — a `..` component (or an
            // absolute/prefix/`.` component `Path::join` would still resolve
            // against the filesystem root rather than the intended subtree)
            // lets a hand-modified `rollout_path` point the rewritten value
            // OUTSIDE `shared-state/codex/codex-sessions/` entirely, at a
            // path this call never verified. Every component must be a
            // plain (`Component::Normal`) segment.
            let rest_is_safe = Path::new(&rest)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
            if !rest_is_safe {
                continue;
            }
            if !recorded_rollout_is_missing(Path::new(rollout_path))? {
                continue;
            }
            let mut found: Option<RepairCandidate> = None;
            for root in session_roots {
                if budget
                    .get()
                    .is_some_and(|limit| std::time::Instant::now() >= limit)
                {
                    return Err(ShareError::io(
                        db_path,
                        io::Error::new(io::ErrorKind::TimedOut, "rollout repair deadline"),
                    ));
                }
                if let Some(candidate) = admit_rollout_candidate(root, Path::new(&rest))? {
                    if let Some(existing) = &found {
                        if existing.path != candidate.path {
                            return Err(ShareError::io(
                                db_path,
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "rollout repair found conflicting persistent candidates",
                                ),
                            ));
                        }
                    } else {
                        found = Some(candidate);
                    }
                }
            }
            if let Some(candidate) = found {
                let Some(new_path) = candidate.path.to_str() else {
                    return Err(ShareError::io(
                        &candidate.path,
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "rollout candidate path is not UTF-8",
                        ),
                    ));
                };
                if contains_sql_literal_control_byte(new_path) {
                    return Err(ShareError::io(
                        &candidate.path,
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "rollout candidate path contains SQL control bytes",
                        ),
                    ));
                }
                updates.push((
                    id.to_string(),
                    rollout_path.to_string(),
                    new_path.to_owned(),
                ));
            }
        }

        if updates.is_empty() && target.is_none() {
            return Ok(0);
        }

        // ead5c0cf8's trade, extended to the exact route: a target row that is
        // ALREADY canonical (the candidate resolved above, and it equals the
        // recorded path — so `updates` is empty) is admitted by the reads
        // alone. Everything below exists to carry UPDATES: `BEGIN IMMEDIATE` +
        // `busy_timeout` take a write lock on the SHARED database, and the two
        // named guards are emitted before the first UPDATE and gate every
        // UPDATE through `gate_exists` — with no UPDATE planned they write
        // nothing and guard nothing, while still spending a write-lock
        // acquisition inside the caller's bounded admission budget (the same
        // budget a starved host is already straining). The recheck this skips
        // is the no-update row's: a concurrent mutation landing between the
        // reads above and this line no longer turns the verdict into a
        // refusal. Nothing is written on this path, so the skipped recheck
        // cannot lose an integrity property; every guard stays in any run that
        // does write. `Ok(1)` is load-bearing: `Ok(0)` means "this database
        // lacks the target" to `run.rs`'s caller and would refuse a launch the
        // reads just admitted.
        if updates.is_empty() {
            return Ok(1);
        }

        // This is the SHARED database: another already-migrated slot's live
        // codex session can hold a brief write lock on it independent of
        // whatever guard gated the CALLER of this repair (`csq sessions
        // share`'s live-writer refusal covers slots not yet linked here, not
        // ordinary read/write traffic from slots that already ARE). A busy
        // timeout makes a transient collision wait and retry inside sqlite3
        // itself rather than surfacing as `SQLITE_BUSY`.
        #[cfg(test)]
        TEST_REPAIR_BEFORE_WRITE.with(|cell| {
            if let Some(hook) = cell.borrow_mut().take() {
                hook();
            }
        });
        let mut script =
            format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};\nBEGIN IMMEDIATE;\n");
        // The readonly inspection releases its lock. Recheck its exact SQL
        // snapshot under this write transaction, before the first UPDATE.
        script.push_str(&named_guard_sql(
            "csq_rollout_schema_unchanged",
            &row_set_condition(
                SCHEMA_OBJECT_ROW_EXPR,
                "sqlite_master WHERE type IN ('trigger','view')",
                &schema_objects,
            ),
        ));
        if let Some(target) = target {
            let old = &selected[0].1;
            script.push_str(&named_guard_sql("csq_resume_target_unchanged", &format!(
                "(SELECT count(*) FROM threads WHERE id='{}')=1 AND (SELECT count(*) FROM threads WHERE id='{}' AND rollout_path='{}')=1",
                sql_quote_str(target), sql_quote_str(target), sql_quote_str(old))));
        }
        let mut gates = vec!["csq_rollout_schema_unchanged"];
        if target.is_some() {
            gates.push("csq_resume_target_unchanged");
        }
        let gate = gate_exists(&gates);
        for (id, old, new) in &updates {
            script.push_str(&format!(
                "UPDATE threads SET rollout_path = '{}' WHERE id = '{}' AND rollout_path = '{}' AND {gate};\n",
                sql_quote_str(new),
                sql_quote_str(id),
                sql_quote_str(old),
            ));
        }
        script.push_str("COMMIT;\n");
        run(&script, false)?;
        Ok(if target.is_some() { 1 } else { updates.len() })
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
        /// allowlist (S-F8). `migrations_sig` is the common
        /// `_sqlx_migrations` signature every side agreed on during
        /// planning — re-compared against each WORK COPY at apply time (M1):
        /// plan and apply are two separate phases, and a TOCTOU window sits
        /// between them just like the one [`RealEntry::snapshot`] already
        /// guards on the file-fingerprint axis. `threads_schema` is the RAW
        /// (unfiltered) `PRAGMA table_info(threads)` text every side agreed
        /// on — re-compared the same way, so a schema drift NOT on
        /// [`THREADS_MERGE_ALLOWLIST`] (an `ALTER TABLE threads ADD COLUMN`
        /// landing between plan and apply, which `columns`/`migrations_sig`
        /// alone cannot see) still refuses rather than being silently
        /// merged as if nothing changed.
        ToMerge {
            real_paths: Vec<PathBuf>,
            columns: Vec<String>,
            migrations_sig: Option<String>,
            threads_schema: String,
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
        let share_lock = if dry_run {
            None
        } else {
            Some(super::acquire_codex_share_lock_exclusive_bounded_reporting(
                base,
            )?)
        };
        // Every writer sqlite3 child below inherits the lock (see `RepairChild`).
        let _children = share_lock
            .as_ref()
            .map(super::CodexShareLockGuard::hold_for_children);
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
    ///
    /// T2: after every basename this call finds in `SqliteDbRole::State`
    /// (merged just now, or already shared from a prior run), repairs any
    /// `threads.rollout_path` left dangling by a deleted handle dir — see
    /// [`repair_dead_rollout_paths`]. Skipped entirely on a dry run, which
    /// never mutates.
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

        // T2: repair dangling rollout paths on every State-role basename
        // this call touched — regardless of whether phase 2 found it
        // `AlreadyShared` (that report's `role` field always reads
        // `KeptPerSlot` for that outcome, since a no-op plan never checks
        // the true role) or freshly `Merged`, so role is re-derived here
        // directly from `basenames` rather than trusted from `databases`.
        //
        // ADVISORY ONLY, deliberately: by this point phase 2 has already
        // committed the merge (renamed originals to `.pre-share-*` backups
        // and linked the symlinks) — the merge's own result is already
        // durable and correct. A repair failure (role detection erroring,
        // or `repair_dead_rollout_paths` itself) MUST NOT turn that already-
        // successful merge into an `Err` for this call: doing so once made
        // `csq sessions share` report a hard failure on a host where
        // `threads` simply had no `rollout_path` column yet — the merge
        // had, in fact, already succeeded on disk. Every error here is
        // logged and swallowed.
        if !dry_run {
            for basename in &basenames {
                let shared_path = shared_dir.join(basename);
                if !shared_path.exists() {
                    continue;
                }
                match detect_role(&binary, &shared_path) {
                    Ok(SqliteDbRole::State) => {
                        if let Err(e) = repair_dead_rollout_paths(&binary, &shared_path, base) {
                            tracing::warn!(
                                basename = %basename,
                                error = %e,
                                "codex sqlite rollout-path repair failed (advisory only; \
                                 the merge itself is unaffected)"
                            );
                        }
                    }
                    Ok(SqliteDbRole::KeptPerSlot) => {}
                    Err(e) => {
                        tracing::warn!(
                            basename = %basename,
                            error = %e,
                            "codex sqlite rollout-path repair: could not determine role \
                             (advisory only; the merge itself is unaffected)"
                        );
                    }
                }
            }
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
    /// Moves a stranded `.pre-share-<epoch>` backup back to its slot path
    /// `p`, but ONLY in the clean case: `p` and its `-wal`/`-shm` are all
    /// absent. Then the backup and whatever sidecars it has move back as a
    /// set, each with a no-replace move. In every other case something at
    /// the slot may or may not belong to the backup and csq does not guess:
    /// it refuses with the full list of files on both sides and the exact
    /// commands for a manual recovery.
    /// A path as a POSIX-shell word: single-quoted with `'\''` escaping, and
    /// a leading `~/` (home-redacted) rewritten as `"$HOME"'/rest'` so the
    /// shell expands HOME but nothing else.
    #[cfg(unix)]
    fn sh_word(f: &Path) -> String {
        let quote = |t: &str| format!("'{}'", t.replace('\'', "'\\''"));
        let r = crate::cli_deps::sanitize::redact_path(f);
        match r.strip_prefix('~') {
            Some(rest) if rest.starts_with('/') => format!("\"$HOME\"{}", quote(rest)),
            _ => quote(&r),
        }
    }

    /// The manual-recovery instructions for moving `moves` (backup file →
    /// slot file) back to the slot `p`: on unix a POSIX command line that
    /// first requires every slot destination to be absent (`mv -n` exits 0
    /// when it skips, so it cannot be the guard) and then `mv -n`s each file,
    /// all joined by `&&`; elsewhere the same moves in words. A path that is
    /// not valid UTF-8 cannot be written as a command, so that case says so
    /// and points at `ls` instead of printing a wrong one.
    pub(super) fn manual_recovery_commands(p: &Path, moves: &[(PathBuf, PathBuf)]) -> String {
        let all: Vec<&Path> = moves
            .iter()
            .flat_map(|(a, b)| [a.as_path(), b.as_path()])
            .collect();
        if all.iter().any(|f| f.to_str().is_none()) {
            let lossy = all
                .iter()
                .map(|f| format!("{:?}", crate::cli_deps::sanitize::redact_path(f)))
                .collect::<Vec<_>>()
                .join(", ");
            return format!(
                "a path here is not valid UTF-8 and cannot be written as a command ({lossy}); \
                 list the directory with `ls` and move each backup file to the matching name \
                 at the slot by hand"
            );
        }
        #[cfg(unix)]
        {
            let side = |sfx: &str| PathBuf::from(format!("{}{sfx}", p.display()));
            let guard = ["", "-wal", "-shm"]
                .iter()
                .map(|sfx| {
                    let w = sh_word(&side(sfx));
                    // `-e` follows symlinks, so a dangling link needs `-L` too.
                    format!("test ! -e {w} && test ! -L {w}")
                })
                .collect::<Vec<_>>()
                .join(" && ");
            let mvs = moves
                .iter()
                .map(|(from, to)| format!("mv -n {} {}", sh_word(from), sh_word(to)))
                .collect::<Vec<_>>()
                .join(" && ");
            format!("{guard} && {mvs}")
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            moves
                .iter()
                .map(|(from, to)| {
                    format!(
                        "move {} to {}",
                        crate::cli_deps::sanitize::redact_path(from),
                        crate::cli_deps::sanitize::redact_path(to)
                    )
                })
                .collect::<Vec<_>>()
                .join(", then ")
        }
    }

    pub(super) fn recover_stranded_backup(backup: &Path, p: &Path) -> Result<(), ShareError> {
        let side = |b: &Path, sfx: &str| PathBuf::from(format!("{}{sfx}", b.display()));
        let present = |b: &Path, sfxs: &[&str]| -> Vec<PathBuf> {
            sfxs.iter()
                .map(|sfx| side(b, sfx))
                .filter(|f| f.symlink_metadata().is_ok())
                .collect()
        };
        let slot_files = present(p, &["", "-wal", "-shm"]);
        let backup_sidecars = present(backup, &["-wal", "-shm"]);
        if !slot_files.is_empty() {
            let red = crate::cli_deps::sanitize::redact_path;
            let list = |v: &[PathBuf]| v.iter().map(|f| red(f)).collect::<Vec<_>>().join(", ");
            let mut backup_files = vec![backup.to_path_buf()];
            backup_files.extend(backup_sidecars.iter().cloned());
            let moves: Vec<(PathBuf, PathBuf)> = backup_files
                .iter()
                .map(|f| {
                    let sfx = f
                        .to_string_lossy()
                        .strip_prefix(&*backup.to_string_lossy())
                        .unwrap_or("")
                        .to_string();
                    (f.clone(), side(p, &sfx))
                })
                .collect();
            let commands = manual_recovery_commands(p, &moves);
            let how = if cfg!(unix) {
                "POSIX shell commands"
            } else {
                "these moves, in this order"
            };
            return Err(ShareError::SqliteStrandedBackupNeedsManualRecovery {
                listing: format!(
                    "found at the slot: {}; found with the backup: {}. Close codex and KEEP \
                     all of these files. Once the slot files are cleared, move the backup \
                     set back by hand ({how}): {commands}. Remove a slot file only if you \
                     know it is not the backup's write-ahead file.",
                    list(&slot_files),
                    list(&backup_files),
                ),
                commands,
            });
        }
        // Sidecars FIRST and the main file LAST, so a partial recovery never
        // leaves a main file at the slot without its write-ahead file. A
        // failed sidecar move puts back the sidecars already moved.
        let sfx_of = |f: &Path| {
            f.to_string_lossy()
                .strip_prefix(&*backup.to_string_lossy())
                .unwrap_or("")
                .to_string()
        };
        let mut moved: Vec<PathBuf> = Vec::new();
        // Puts back every sidecar already moved; returns each one that could
        // NOT be (it is then left at the slot without a main file).
        let undo = |moved: &[PathBuf]| -> Vec<String> {
            let red = crate::cli_deps::sanitize::redact_path;
            moved
                .iter()
                .rev()
                .filter_map(|done| {
                    let at_slot = side(p, &sfx_of(done));
                    recovery_rename(&at_slot, done)
                        .err()
                        .map(|e| format!("{} (from {}): {e}", red(&at_slot), red(done)))
                })
                .collect()
        };
        let fail = |moved: &[PathBuf], from: &Path, e: io::Error| {
            let left = undo(moved);
            if left.is_empty() {
                ShareError::io(from, e)
            } else {
                ShareError::io(
                    from,
                    io::Error::new(
                        e.kind(),
                        format!(
                            "{e}; ALSO could not move back already-moved sidecar(s), which are \
                             now left at the slot without a main file: {}",
                            left.join("; ")
                        ),
                    ),
                )
            }
        };
        for sidecar in &backup_sidecars {
            let dest = side(p, &sfx_of(sidecar));
            if let Err(e) = recovery_rename(sidecar, &dest) {
                return Err(fail(&moved, sidecar, e));
            }
            moved.push(sidecar.clone());
        }
        recovery_rename(backup, p).map_err(|e| fail(&moved, backup, e))?;
        secure_sqlite_paths(p)
    }

    /// A recovery move (no-replace), with a test seam that fails the nth call.
    fn recovery_rename(src: &Path, dst: &Path) -> io::Result<()> {
        #[cfg(test)]
        {
            let n = TEST_RECOVERY_CALLS.with(|c| {
                c.set(c.get() + 1);
                c.get()
            });
            if TEST_RECOVERY_FAIL_AT.with(|c| c.borrow().contains(&n)) {
                return Err(io::Error::other("forced recovery failure"));
            }
        }
        rename_noreplace(src, dst)
    }

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
                            recover_stranded_backup(&backup, &p)?;
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
                let note = migrations_mismatch_note(first_path, path, &shared_path, first_sig, sig);
                return Err(ShareError::SqliteMigrationsMismatch {
                    basename: basename.to_string(),
                    a_path: PathBuf::from(crate::cli_deps::sanitize::redact_path(first_path)),
                    b_path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
                    note,
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
        let threads_schema = threads_schema_fingerprint(binary, repr_path)?;

        // Every side already agreed on this signature above (the mismatch
        // loop would have refused otherwise) — carried forward so apply-time
        // can re-compare it against each WORK COPY (M1: plan and apply are
        // separate phases with a TOCTOU window between them).
        let migrations_sig = signatures[0].1.clone();

        Ok(BasenamePlan::ToMerge {
            real_paths,
            columns,
            migrations_sig,
            threads_schema,
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
            create_real_symlink,
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
                backup_path: None,
            }),
            BasenamePlan::KeptPerSlot { slots } => Ok(SqliteDbReport {
                basename: basename.to_string(),
                role: SqliteDbRole::KeptPerSlot,
                outcome: SqliteDbOutcome::KeptPerSlot { slots },
                backup_path: None,
            }),
            BasenamePlan::ToMerge {
                real_paths,
                columns,
                migrations_sig,
                threads_schema,
            } => {
                if dry_run {
                    return Ok(SqliteDbReport {
                        basename: basename.to_string(),
                        role: SqliteDbRole::State,
                        outcome: SqliteDbOutcome::Merged {
                            slots_merged: real_paths.len(),
                        },
                        backup_path: None,
                    });
                }
                let shared_path = shared_dir.join(basename);

                // Before ANY backup, merge or move: the link step at the end
                // needs a real symlink, so find out now (not after the shared
                // index has been committed) whether this host can make one.
                probe_symlink_capability(shared_dir)?;

                // The caller holds the share lock, so a private backup dir
                // whose owner is dead (or ancient) is a crash leftover.
                sweep_stale_pre_merge_tmp_dirs(
                    shared_dir,
                    basename,
                    now_epoch_secs(),
                    crate::platform::process::is_pid_alive,
                );

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
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
                        });
                    }
                    checkpoint_truncate(binary, &work_copy)?;
                    integrity_check(binary, basename, &work_copy)?;
                    // M1 (security): plan-time verification
                    // (`plan_one_basename`) and this apply phase are two
                    // separate steps with a real TOCTOU window between them
                    // — a `--dry-run` planning pass, or another concurrent
                    // `csq sessions share`, could have observed one schema
                    // while THIS working copy now holds another. Re-run the
                    // same three checks the plan already ran, against the
                    // bytes this merge is actually about to consume, before
                    // any of them are seeded into the shared store.
                    forbid_untrusted_schema_objects(binary, basename, &work_copy)?;
                    let work_sig = migrations_signature(binary, &work_copy)?;
                    if work_sig != migrations_sig {
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
                        });
                    }
                    let work_columns = threads_non_id_columns(binary, basename, &work_copy)?;
                    if work_columns != columns {
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
                        });
                    }
                    // M1: the RAW schema fingerprint catches a drift the
                    // filtered `columns` comparison above cannot — e.g. an
                    // `ALTER TABLE threads ADD COLUMN` whose new column is
                    // not itself on `THREADS_MERGE_ALLOWLIST`.
                    let work_schema = threads_schema_fingerprint(binary, &work_copy)?;
                    if work_schema != threads_schema {
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(path)),
                        });
                    }
                    entries.push(RealEntry {
                        path: path.clone(),
                        work_copy,
                        snapshot: post_copy,
                    });
                }

                let shared_already_exists = shared_path.exists();
                // The trigger/view rows verified on whichever DB the merge
                // writes into; re-asserted inside the merge transaction.
                let mut shared_schema_objects: Vec<String> = Vec::new();
                let mut backup_path: Option<PathBuf> = None;
                if shared_already_exists {
                    // M1: re-verify `shared_path` FIRST — the same TOCTOU
                    // window the work copies above just narrowed applies
                    // here too: this module's own plan-time read of
                    // `shared_path` may be stale by the time this apply
                    // phase actually runs. Only once it passes is a backup
                    // taken and pruning performed — a REFUSED run (below)
                    // must not spend a backup slot or rotate the existing
                    // ones on content this call is about to reject anyway.
                    shared_schema_objects =
                        forbid_untrusted_schema_objects(binary, basename, &shared_path)?;
                    integrity_check(binary, basename, &shared_path)?;
                    let shared_sig = migrations_signature(binary, &shared_path)?;
                    if shared_sig != migrations_sig {
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(
                                &shared_path,
                            )),
                        });
                    }
                    let shared_schema = threads_schema_fingerprint(binary, &shared_path)?;
                    if shared_schema != threads_schema {
                        return Err(ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(
                                &shared_path,
                            )),
                        });
                    }
                    // FM-11 sibling: before mutating the EXISTING shared DB
                    // (which live sessions on already-migrated slots may
                    // have open — this is never renamed away, only merged
                    // into in place), take a durable, transactionally
                    // consistent backup (`VACUUM INTO`, never a raw
                    // `fs::copy` of a possibly-WAL file — see
                    // `backup_via_vacuum_into`). Pruning happens AFTER the
                    // merge below succeeds, not here — see that call site.
                    let suffix = backup_suffix();
                    let shared_backup =
                        PathBuf::from(format!("{}.pre-merge-{suffix}", shared_path.display()));
                    backup_via_vacuum_into(binary, basename, &shared_path, &shared_backup)?;
                    backup_path = Some(shared_backup);
                }
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
                    // `copy_db_with_sidecars` copies the WHOLE first entry's
                    // file, so every one of ITS other tables (`projects`,
                    // `thread_sections`, …) is already present in
                    // `tmp_shared` — only the REMAINING entries need their
                    // rows carried across explicitly, via ONE
                    // `merge_sources_into` call (B1: one process, one
                    // transaction, for every remaining entry at once).
                    copy_db_with_sidecars(&entries[0].work_copy, &tmp_shared)?;
                    let remaining: Vec<PathBuf> =
                        entries[1..].iter().map(|e| e.work_copy.clone()).collect();
                    // `tmp_shared` is a private copy of a verified work copy.
                    let tmp_objects =
                        forbid_untrusted_schema_objects(binary, basename, &tmp_shared)?;
                    merge_sources_into_classified(
                        binary,
                        basename,
                        &tmp_shared,
                        &remaining,
                        &columns,
                        Some(&DestExpectation {
                            migrations_sig: &migrations_sig,
                            threads_schema: &threads_schema,
                            schema_objects: &tmp_objects,
                        }),
                    )
                    .map_err(|f| f.err)?;
                    checkpoint_truncate(binary, &tmp_shared)?;
                    integrity_check(binary, basename, &tmp_shared)?;
                    // R2: N1's fix already makes an ORDINARY chmod failure
                    // here self-heal (the rename is undone, `shared_path`
                    // reverts to not existing) — so the only way this call
                    // can fail AFTER a genuine commit is the doubly-unlucky
                    // case where the undo-back-to-`src` attempt ALSO fails,
                    // leaving the file's true location ambiguous. Wrapping
                    // EVERY failure here conservatively (rather than trying
                    // to distinguish the two) costs at most a false-alarm
                    // "re-run to finish linking" on the ordinary,
                    // self-healed path — never a silent, unreported
                    // ambiguity on the rare one.
                    if let Err(e) = rename_db_with_sidecars(&tmp_shared, &shared_path) {
                        // The ordinary (self-healed) failure leaves no shared
                        // index at all: nothing was merged into anything, so
                        // report the plain error. Only when `shared_path`
                        // exists is the "merged into" wording true.
                        if shared_path.symlink_metadata().is_err() {
                            return Err(e);
                        }
                        return Err(shared_committed_slots_unlinked_note(
                            basename,
                            entries.len(),
                            &backup_path,
                            &RollbackReport::default(),
                            e,
                        ));
                    }
                } else {
                    // B1: every entry's `threads` merge, other-table carry,
                    // and the foreign-key repair-and-guard all run in the
                    // ONE `merge_sources_into` call below — one sqlite3
                    // process, one transaction against the LIVE shared
                    // database. A failure anywhere rolls back everything
                    // this call staged; `shared_path` is unchanged.
                    let sources: Vec<PathBuf> =
                        entries.iter().map(|e| e.work_copy.clone()).collect();
                    run_test_before_merge_hook(&shared_path);
                    if let Err(failure) = merge_sources_into_classified(
                        binary,
                        basename,
                        &shared_path,
                        &sources,
                        &columns,
                        Some(&DestExpectation {
                            migrations_sig: &migrations_sig,
                            threads_schema: &threads_schema,
                            schema_objects: &shared_schema_objects,
                        }),
                    ) {
                        // R1/M2: delete the backup ONLY for a failure that is
                        // positively pre-commit (a guard refusal, or anything
                        // raised before the write script ran): then
                        // `shared_path` is provably unchanged and the backup
                        // would leak, never pruned (pruning runs only after
                        // a SUCCESSFUL merge). Any other failure of the
                        // script is not provably pre-commit — COMMIT can
                        // fail its fsync after the frame was written, and a
                        // signal can land after COMMIT — so the backup is
                        // KEPT.
                        if failure.pre_commit {
                            if let Some(unused_backup) = &backup_path {
                                remove_db_with_sidecars(unused_backup);
                            }
                            return Err(failure.err);
                        }
                        return Err(match &backup_path {
                            Some(backup) => ShareError::SqliteMergeOutcomeUnknown {
                                basename: basename.to_string(),
                                backup: PathBuf::from(crate::cli_deps::sanitize::redact_path(
                                    backup,
                                )),
                                cause: Box::new(failure.err),
                            },
                            None => failure.err,
                        });
                    }
                    // M1: pruning happens ONLY after this merge has
                    // succeeded — a refused run must not rotate the backup
                    // set on content it just rejected.
                    if let Some(just_created) = &backup_path {
                        prune_old_pre_merge_backups(shared_dir, basename, 3, just_created);
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
                // H1: EVERY refusal from this point on happens AFTER the
                // shared index has already been durably updated (committed
                // by `merge_sources_into`, or — on first creation — already
                // renamed into place a few lines above). `rollback_renamed`
                // below still restores every per-slot ORIGINAL this loop
                // touched, but the shared index itself is NOT undone by it
                // — so every early return here is wrapped via
                // `shared_committed_slots_unlinked_note` rather than
                // returned bare, so the operator is told the true state
                // (shared index updated, slots not yet linked) instead of
                // the "rolled back" claim `SqliteChangedDuringMerge` makes
                // for the PRE-commit case.
                let mut renamed_so_far: Vec<(PathBuf, PathBuf, MoveRecord)> =
                    Vec::with_capacity(entries.len());
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
                        let not_restored = rollback_renamed(&renamed_so_far, None, &shared_path);
                        return Err(shared_committed_slots_unlinked_note(
                            basename,
                            entries.len(),
                            &backup_path,
                            &not_restored,
                            e,
                        ));
                    }
                    if fingerprint_db(&entry.path) != entry.snapshot {
                        let not_restored = rollback_renamed(&renamed_so_far, None, &shared_path);
                        let underlying = ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(
                                &entry.path,
                            )),
                        };
                        return Err(shared_committed_slots_unlinked_note(
                            basename,
                            entries.len(),
                            &backup_path,
                            &not_restored,
                            underlying,
                        ));
                    }
                    let backup = match fresh_pre_share_path(&entry.path, epoch) {
                        Ok(b) => b,
                        Err(e) => {
                            let not_restored =
                                rollback_renamed(&renamed_so_far, None, &shared_path);
                            return Err(shared_committed_slots_unlinked_note(
                                basename,
                                entries.len(),
                                &backup_path,
                                &not_restored,
                                e,
                            ));
                        }
                    };
                    let (record, moved) = forward_move(&entry.path, &backup);
                    if let Err(e) = moved {
                        // The record says exactly what is still at the
                        // backup path (nothing, for a refused move), and
                        // only that is moved back.
                        let not_restored = rollback_renamed(
                            &renamed_so_far,
                            Some((entry.path.as_path(), backup.as_path(), &record)),
                            &shared_path,
                        );
                        return Err(shared_committed_slots_unlinked_note(
                            basename,
                            entries.len(),
                            &backup_path,
                            &not_restored,
                            e,
                        ));
                    }
                    run_test_after_rename_hook(&backup);
                    let linked = create(&shared_path, &entry.path)
                        .map_err(|e| ShareError::io(&entry.path, e))
                        .and_then(|()| super::verify_is_symlink(&entry.path));
                    if let Err(e) = linked {
                        let not_restored = rollback_renamed(
                            &renamed_so_far,
                            Some((entry.path.as_path(), backup.as_path(), &record)),
                            &shared_path,
                        );
                        return Err(shared_committed_slots_unlinked_note(
                            basename,
                            entries.len(),
                            &backup_path,
                            &not_restored,
                            e,
                        ));
                    }
                    renamed_so_far.push((entry.path.clone(), backup, record));
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
                for (entry, (_original, backup, _record)) in entries.iter().zip(&renamed_so_far) {
                    if fingerprint_db(backup) != entry.snapshot {
                        let not_restored = rollback_renamed(&renamed_so_far, None, &shared_path);
                        let underlying = ShareError::SqliteChangedDuringMerge {
                            basename: basename.to_string(),
                            path: PathBuf::from(crate::cli_deps::sanitize::redact_path(
                                &entry.path,
                            )),
                        };
                        return Err(shared_committed_slots_unlinked_note(
                            basename,
                            entries.len(),
                            &backup_path,
                            &not_restored,
                            underlying,
                        ));
                    }
                }

                Ok(SqliteDbReport {
                    basename: basename.to_string(),
                    role: SqliteDbRole::State,
                    outcome: SqliteDbOutcome::Merged {
                        slots_merged: entries.len(),
                    },
                    backup_path,
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
    /// Hold a migration lock (on a scratch directory of its own) for the rest
    /// of the enclosing block, as every production writer path does, so a
    /// test driving an internal writer directly is not refused by
    /// `RepairChild::spawn`'s unlocked-writer guard.
    macro_rules! hold_test_migration_lock {
        () => {
            let _csq_test_lock_dir = tempfile::tempdir().expect("lock scratch dir");
            let _csq_test_lock =
                crate::session::shared_state::acquire_codex_share_lock_shared_bounded(
                    _csq_test_lock_dir.path(),
                    50,
                    std::time::Duration::from_millis(20),
                )
                .expect("migration lock io")
                .expect("migration lock admitted");
            let _csq_test_held = _csq_test_lock.hold_for_children();
        };
    }

    use super::*;
    use tempfile::TempDir;

    /// The share-lock refusals name every holder class and never assert that
    /// a share or a named session is the one running: a writer orphaned by an
    /// interrupted csq run holds the lock just as well. Falsifying result with
    /// the former wording: "migration is in progress" is present and
    /// "interrupted" absent.
    #[test]
    fn share_lock_refusals_do_not_assert_the_holder() {
        let contended = ShareError::CodexShareLockContended.to_string();
        let timed_out = ShareError::CodexShareLockTimedOut {
            bound_secs: 3,
            pids: format_live_writer_pids(&[]),
        }
        .to_string();
        for message in [&contended, &timed_out] {
            assert!(message.contains("interrupted"), "{message}");
            assert!(message.contains("`ps`"), "{message}");
            assert!(!message.contains("is in progress"), "{message}");
            assert!(!message.contains("Wait for the running"), "{message}");
        }
        assert!(timed_out.contains("running codex session"), "{timed_out}");
    }

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
        hold_test_migration_lock!();
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

    /// G2b item 2 — same class as the login lock: a forked child inherits
    /// the lock descriptor, and POSIX flock is released only when every
    /// descriptor to the open file description closes. Dropping the guard
    /// MUST release explicitly (LOCK_UN), or an EXCLUSIVE acquire inside
    /// that window still sees the SHARED lock held.
    #[cfg(unix)]
    #[test]
    fn fork_child_does_not_hold_the_share_lock_past_drop() {
        use crate::fork_harness::ForkedChild;

        let t = TempDir::new().unwrap();
        let base = t.path();

        let guard = acquire_codex_share_lock_shared_bounded(base, 1, std::time::Duration::ZERO)
            .unwrap()
            .expect("uncontended SHARED acquire");
        let child = ForkedChild::spawn();
        drop(guard);

        let outcome =
            acquire_codex_share_lock_exclusive_bounded(base, 1, std::time::Duration::ZERO).unwrap();
        assert!(
            outcome.is_some(),
            "an inherited duplicate kept the SHARED share lock alive past the guard's drop — \
             Drop must LOCK_UN, not rely on close"
        );
        drop(child);
    }

    /// An EXCLUSIVE holder (the migration side) must exclude a concurrent
    /// SHARED attempt (a launch) for as long as it is held, and release it
    /// on drop — the RED/GREEN pair this test proves in one run.
    #[test]
    fn codex_share_lock_exclusive_excludes_a_concurrent_shared_attempt() {
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
            Err(_) if cfg!(target_os = "macos") || sqlite3_required_in_ci() => panic!(
                "this test requires a `sqlite3` binary (macOS ships /usr/bin/sqlite3; CI must provide one) — see CSQ_SQLITE3"
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

    /// A skipped sqlite test reports `ok`, and libtest hides a passing test's
    /// output, so a CI log cannot tell "ran" from "skipped". Measured
    /// 2026-09-29: on a Linux host with no `sqlite3` (`CI=1`), 40 tests here
    /// passed without running and hid 12 real regressions. Under CI (`CI`
    /// set, as GitHub Actions does) a missing binary therefore fails
    /// instead. No `#[cfg(unix)]` needed: the body's own `cfg!(unix)` is a
    /// RUNTIME check, so this compiles (and simply reads `false`) on every
    /// platform, including the ordinary unconditional callers below and in
    /// `codex_sqlite_tests`. Unix only in EFFECT: the Windows CI leg keeps
    /// the skip (no pinned binary is provisioned there, and the share runs
    /// on the macOS/Linux legs).
    fn sqlite3_required_in_ci() -> bool {
        cfg!(unix) && std::env::var_os("CI").is_some_and(|v| !v.is_empty())
    }

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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        hold_test_migration_lock!();
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
        /// leg is where this suite's coverage is guaranteed. Under CI on any unix
        /// host it FAILS too (`sqlite3_required_in_ci`): a skipped test reports
        /// `ok` and libtest hides its output. Only outside CI (e.g. a Linux dev
        /// host without the sqlite3 CLI) is the test skipped, with a line on stderr.
        fn require_sqlite3() -> Option<PathBuf> {
            match codex_sqlite::resolve_sqlite3() {
                Ok(bin) => Some(bin),
                Err(_) if cfg!(target_os = "macos") || super::sqlite3_required_in_ci() => panic!(
                    "this suite requires a `sqlite3` binary (macOS ships /usr/bin/sqlite3; CI must provide one) — see CSQ_SQLITE3"
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

        /// sqlx's real `_sqlx_migrations` table, as codex-cli creates it. The
        /// fixtures used a two-column stand-in, so a comparison over
        /// `installed_on` / `execution_time` (different in every real
        /// database) could never be seen to fail.
        const SQLX_MIGRATIONS_DDL: &str = "CREATE TABLE _sqlx_migrations (\
             version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
             installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, \
             success BOOLEAN NOT NULL, checksum BLOB NOT NULL, \
             execution_time BIGINT NOT NULL);";

        /// Migrations `1..=n`, each with a checksum derived from its version
        /// (so two databases at the same `n` hold the same migrations) and the
        /// given install time.
        fn sqlx_migration_rows(n: u32, installed_on: &str) -> String {
            (1..=n)
                .map(|v| {
                    format!(
                        "INSERT INTO _sqlx_migrations VALUES ({v}, 'm{v}', '{installed_on}', 1, \
                         x'{v:08X}', {v});"
                    )
                })
                .collect()
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
                    &format!(
                        "{SQLX_MIGRATIONS_DDL}{}",
                        sqlx_migration_rows(1, "2026-01-01 00:00:00")
                    ),
                );
            }
        }

        /// codex-cli 0.159.2's real `threads` table, indexes and its five
        /// triggers. The original fixtures above build a minimal table with no
        /// triggers, which is why a refusal of every trigger passed them while
        /// refusing every real codex database.
        ///
        /// `.gitattributes` marks the fixture `-text`, so a Windows checkout under
        /// `core.autocrlf=true` keeps codex-cli's LF bytes and the triggers it creates hash
        /// to the values `CODEX_OWN_TRIGGERS` pins.
        const CODEX_THREADS_SCHEMA: &str =
            include_str!("../../tests/fixtures/codex-state5-threads-0.159.2.sql");

        fn create_codex_state_db(bin: &Path, path: &Path, rows: &[ThreadRow], migrations: u32) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let _ = fs::remove_file(path);
            sh(bin, path, CODEX_THREADS_SCHEMA);
            for row in rows {
                let insert = format!(
                    "INSERT INTO threads (id, rollout_path, created_at, updated_at, updated_at_ms, \
                       source, model_provider, cwd, title, sandbox_policy, approval_mode, name) \
                     VALUES ('{id}', '/r/{id}.jsonl', 1, 1, {ms}, 'cli', 'openai', '/work', \
                       'untitled', 'default', 'default', '{name}');",
                    id = row.id,
                    ms = row.updated_at_ms,
                    name = row.name
                );
                sh(bin, path, &insert);
            }
            sh(
                bin,
                path,
                &format!(
                    "{SQLX_MIGRATIONS_DDL}{}",
                    sqlx_migration_rows(migrations, "2026-01-01 00:00:00")
                ),
            );
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
            // `/usr/bin` is not absolute on Windows; use a platform-absolute dir.
            let abs_dir = std::env::temp_dir();
            let dirs = vec![
                PathBuf::from(""),
                PathBuf::from("relative/bin"),
                abs_dir.clone(),
            ];
            let found =
                codex_sqlite::find_executable_in_dirs(dirs.into_iter(), "sqlite3", |_| true);
            let filename = if cfg!(windows) {
                "sqlite3.exe"
            } else {
                "sqlite3"
            };
            assert_eq!(found, Some(abs_dir.join(filename)));
        }

        /// S-F10: with ONLY empty/relative entries present, nothing may be
        /// returned, even though `is_executable` would say yes for every one.
        #[test]
        fn path_lookup_finds_nothing_when_only_empty_or_relative_entries_present() {
            hold_test_migration_lock!();
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

        /// `share_codex_surface_and_sqlite` itself makes its EXCLUSIVE lock the
        /// one its merge writers inherit: driven through a real two-slot merge
        /// (so writer `sqlite3` children spawn) with NO test-held lock on this
        /// thread, it succeeds. Falsifying result with the fn's
        /// `hold_for_children` line deleted: the first writer spawn is refused
        /// ("migration lock not held") and the call returns `Err`.
        #[test]
        fn share_codex_surface_and_sqlite_merges_under_its_own_lock_scope() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            // Hermetic: the real live-writer guard runs (force=false).
            let _procs_guard = super::force_list_running_processes(vec![]);
            assert_eq!(
                crate::session::shared_state::held_child_lock(),
                None,
                "this test must start with no lock held on its thread"
            );
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            for (home, name, ms) in [(&home11, "", 100), (&home14, "py", 200)] {
                fs::create_dir_all(home).unwrap();
                create_state_db(
                    &bin,
                    &home.join("state_5.sqlite"),
                    &[ThreadRow {
                        id: "01a0d8a0-thread",
                        name,
                        updated_at_ms: ms,
                    }],
                    true,
                );
            }

            let result = super::share_codex_surface_and_sqlite(base, false, false);
            let (_, report) = result.expect("the merge must run under the fn's own scope");
            assert_eq!(report.databases.len(), 1, "{report:?}");
            assert!(
                matches!(
                    report.databases[0].outcome,
                    SqliteDbOutcome::Merged { slots_merged: 2 }
                ),
                "{:?}",
                report.databases[0].outcome
            );
            assert_eq!(
                thread_name(&bin, &home11.join("state_5.sqlite"), "01a0d8a0-thread"),
                "py"
            );
            assert_eq!(crate::session::shared_state::held_child_lock(), None);
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

        /// Every OTHER table `state_5.sqlite` carries — not just `threads` —
        /// must be carried across a merge. A `projects` row that exists ONLY
        /// on slot 14 must be visible from slot 11 after sharing, resolving
        /// THROUGH the now-shared symlink exactly like a `threads` rename.
        #[test]
        fn carries_non_threads_table_rows_across_a_merge() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 100,
                }],
                1,
            );
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 200,
                }],
                1,
            );
            // A `projects` row that exists ONLY on slot 14 — `threads` never
            // references it here, so this exercises `carry_other_tables`
            // alone, independent of the foreign-key repair path.
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "INSERT INTO projects (id, name, metadata, position, created_at_ms, updated_at_ms) \
                 VALUES ('proj-1', 'My Project', '{}', 0, 1, 1);",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                row_count(&bin, &merged, "projects"),
                1,
                "the projects row from slot 14 must have been carried into the shared store"
            );
            assert_eq!(
                sh_query(
                    &bin,
                    &merged,
                    "SELECT name FROM projects WHERE id = 'proj-1';"
                )
                .trim(),
                "My Project"
            );
        }

        /// A `threads.project_id` pointing at a `projects` row that exists
        /// NOWHERE — a merge must not simply carry the dangling reference
        /// forward. `PRAGMA foreign_key_check` after the merge finds it, and
        /// codex's own `ON DELETE SET NULL` semantics for this column are
        /// applied: the column is set NULL rather than the merge refusing
        /// outright, matching what codex-cli itself would do if the
        /// referenced project were deleted locally.
        #[test]
        fn dangling_threads_project_id_is_nulled_after_merge() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 100,
                }],
                1,
            );
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "UPDATE threads SET project_id = 'ghost-project' WHERE id = 't1';",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                thread_field(&bin, &merged, "t1", "project_id"),
                "",
                "a dangling project_id must be repaired to NULL, not carried forward"
            );
        }

        /// The S-L3 extension to `THREADS_MERGE_ALLOWLIST`: `archived` and
        /// `is_pinned` follow the ordinary newer-`updated_at_ms`-wins rule;
        /// `created_at_ms` takes the MIN (earliest) of the two sides
        /// UNCONDITIONALLY; `recency_at_ms` takes the MAX (latest)
        /// UNCONDITIONALLY — neither of the latter two is gated on which
        /// side has the newer `updated_at_ms`.
        #[test]
        fn extended_allowlist_columns_follow_their_own_merge_rules() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n1",
                    updated_at_ms: 100,
                }],
                1,
            );
            // `created_at_ms`/`recency_at_ms` are deliberately set so the
            // UNCONDITIONAL (MIN / MAX) rule and the ordinary
            // newer-`updated_at_ms`-wins rule pick DIFFERENT values here —
            // home11 (OLDER updated_at_ms) carries the earlier created_at_ms
            // (300) and the later recency_at_ms (900); home14 (NEWER
            // updated_at_ms) carries the later created_at_ms (500) and the
            // earlier recency_at_ms (100). A merge that (wrongly) applied
            // the generic newer-wins rule to these two columns would report
            // home14's values (500 / 100); the correct MIN/MAX rule reports
            // home11's (300 / 900) — the two rules disagree on every
            // assertion below, so this test cannot pass by coincidence.
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "UPDATE threads SET archived = 0, is_pinned = 0, created_at_ms = 300, \
                 recency_at_ms = 900 WHERE id = 't1';",
            );
            // Same id, NEWER updated_at_ms — the newer-wins columns must
            // take this side's values; created_at_ms/recency_at_ms follow
            // their own unconditional rules regardless.
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n1",
                    updated_at_ms: 200,
                }],
                1,
            );
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "UPDATE threads SET archived = 1, is_pinned = 1, created_at_ms = 500, \
                 recency_at_ms = 100 WHERE id = 't1';",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                thread_field(&bin, &merged, "t1", "archived"),
                "1",
                "archived follows the newer-updated_at_ms-wins rule"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "is_pinned"),
                "1",
                "is_pinned follows the newer-updated_at_ms-wins rule"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "created_at_ms"),
                "300",
                "created_at_ms takes the MIN of the two sides, unconditionally"
            );
            assert_eq!(
                thread_field(&bin, &merged, "t1", "recency_at_ms"),
                "900",
                "recency_at_ms takes the MAX of the two sides, unconditionally"
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

        // ── L2/(e): direct unit tests of migrations_mismatch_note ────────
        // No sqlite3 binary needed — these call the pure string-building
        // function directly with synthetic signatures.

        #[test]
        fn note_unit_none_vs_some_names_missing_table() {
            hold_test_migration_lock!();
            let shared = PathBuf::from("/shared/state_5.sqlite");
            let slot = PathBuf::from("/slot11/state_5.sqlite");
            let msg = codex_sqlite::migrations_mismatch_note(
                &slot,
                &shared,
                &shared,
                &None,
                &Some("1|abcd|1".to_string()),
            );
            assert!(msg.contains("no `_sqlx_migrations` table at all"), "{msg}");
            // The BEHIND side (None) is `slot`, not the shared index here.
            assert!(msg.contains("start codex once on that copy"), "{msg}");
        }

        #[test]
        fn note_unit_some_vs_none_is_symmetric() {
            hold_test_migration_lock!();
            let shared = PathBuf::from("/shared/state_5.sqlite");
            let slot = PathBuf::from("/slot11/state_5.sqlite");
            let msg = codex_sqlite::migrations_mismatch_note(
                &shared,
                &slot,
                &shared,
                &Some("1|abcd|1".to_string()),
                &None,
            );
            assert!(msg.contains("no `_sqlx_migrations` table at all"), "{msg}");
            // The BEHIND side (None) is `slot` again (it's `b` this time),
            // and `a` (the shared index) is NOT behind, so the hint still
            // names a per-slot copy, not the shared index.
            assert!(msg.contains("start codex once on that copy"), "{msg}");
        }

        #[test]
        fn note_unit_count_differs_slot_behind_names_that_copy() {
            hold_test_migration_lock!();
            let shared = PathBuf::from("/shared/state_5.sqlite");
            let slot = PathBuf::from("/slot11/state_5.sqlite");
            // `a` = slot (1 migration, behind), `b` = shared (2 migrations).
            let msg = codex_sqlite::migrations_mismatch_note(
                &slot,
                &shared,
                &shared,
                &Some("1|aa|1".to_string()),
                &Some("1|aa|1\n2|bb|1".to_string()),
            );
            assert!(msg.contains("1 vs 2 migrations applied"), "{msg}");
            assert!(msg.contains("start codex once on that copy"), "{msg}");
            assert!(!msg.contains("shared index"), "{msg}");
        }

        #[test]
        fn note_unit_count_differs_shared_behind_names_the_shared_index() {
            hold_test_migration_lock!();
            let shared = PathBuf::from("/shared/state_5.sqlite");
            let slot = PathBuf::from("/slot11/state_5.sqlite");
            // `a` = shared (1 migration, BEHIND), `b` = slot (2 migrations).
            let msg = codex_sqlite::migrations_mismatch_note(
                &shared,
                &slot,
                &shared,
                &Some("1|aa|1".to_string()),
                &Some("1|aa|1\n2|bb|1".to_string()),
            );
            assert!(msg.contains("1 vs 2 migrations applied"), "{msg}");
            assert!(msg.contains("the shared index"), "{msg}");
            assert!(!msg.contains("start codex once on that copy"), "{msg}");
        }

        #[test]
        fn note_unit_same_count_different_checksum_names_different_builds() {
            hold_test_migration_lock!();
            let shared = PathBuf::from("/shared/state_5.sqlite");
            let slot = PathBuf::from("/slot11/state_5.sqlite");
            let msg = codex_sqlite::migrations_mismatch_note(
                &slot,
                &shared,
                &shared,
                &Some("1|aaaa|1".to_string()),
                &Some("1|bbbb|1".to_string()),
            );
            assert!(msg.contains("different codex-cli BUILDS"), "{msg}");
            assert!(!msg.contains("migrations applied"), "{msg}");
            assert!(!msg.contains("start codex once"), "{msg}");
        }

        // ── L2: the mismatch NOTE names the actual cause ─────────────────

        /// (a) Both sides have a `_sqlx_migrations` table but a DIFFERENT
        /// NUMBER of migrations applied — the note must name both counts
        /// and the "start codex once" remediation.
        #[test]
        fn mismatch_note_names_both_counts_when_migration_counts_differ() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                1,
            );
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 2,
                }],
                2,
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("1 vs 2 migrations applied")
                    || msg.contains("2 vs 1 migrations applied"),
                "{msg}"
            );
            assert!(msg.contains("start codex once"), "{msg}");
            assert!(
                !msg.contains("different checksums"),
                "a plain count mismatch must not be described as a checksum/build mismatch: {msg}"
            );
        }

        /// (b) Both sides have applied the SAME NUMBER of migrations, but
        /// with a different checksum on at least one — the note must say
        /// these are different codex-cli BUILDS, and must NOT give the
        /// "fewer migrations" advice, since neither side has fewer.
        #[test]
        fn mismatch_note_describes_different_builds_when_counts_match_but_checksums_differ() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                1,
            );
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 2,
                }],
                1,
            );
            // Same COUNT (1) on both sides — but a different checksum for
            // the one migration each has applied.
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "UPDATE _sqlx_migrations SET checksum = x'FFFFFFFF' WHERE version = 1;",
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("different codex-cli BUILDS"), "{msg}");
            assert!(
                !msg.contains("fewer migrations"),
                "neither side has fewer migrations, so that advice does not apply: {msg}"
            );
            assert!(
                !msg.contains("vs") || !msg.contains("migrations applied"),
                "must not be phrased as a count mismatch: {msg}"
            );
        }

        /// (c) One side has NO `_sqlx_migrations` table at all — an older
        /// codex-cli generation that predates the table entirely — while the
        /// other has one. The note must name this as a missing table, not
        /// merely "fewer migrations".
        #[test]
        fn mismatch_note_names_a_missing_migrations_table() {
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
                true, // has _sqlx_migrations
            );
            create_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 2,
                }],
                false, // no _sqlx_migrations table at all
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("no `_sqlx_migrations` table at all"), "{msg}");
            assert!(msg.contains("comparable schema generations"), "{msg}");
        }

        /// (d) One side of the mismatch IS the existing canonical shared
        /// database. The note must say "the shared index", not "slot" —
        /// telling an operator to `csq run` the shared index is not
        /// actionable, since codex-cli never opens it directly.
        #[test]
        fn mismatch_note_names_the_shared_index_when_one_side_is_the_shared_db() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            // First run establishes the shared DB (1 migration) from slot 11.
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            // A new slot at a DIFFERENT migration count than the now-
            // established shared DB — home11 is a symlink now, so the
            // mismatch pair is (shared DB, home14), not (home11, home14).
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 5,
                }],
                2,
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("the shared index"), "{msg}");
            assert!(
                !msg.contains("on the copy with fewer migrations"),
                "once one side is the shared DB, the non-shared-index hint must be used: {msg}"
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
                     CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, \
                       description TEXT NOT NULL, installed_on TIMESTAMP NOT NULL DEFAULT \
                       CURRENT_TIMESTAMP, success BOOLEAN NOT NULL, checksum BLOB NOT NULL, \
                       execution_time BIGINT NOT NULL); \
                     INSERT INTO _sqlx_migrations VALUES (1, 'm1', '2026-01-01 00:00:00', 1, \
                       x'00000001', 1);",
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            assert!(
                matches!(
                    &err,
                    ShareError::SqliteSharedCommittedSlotsUnlinked { cause, .. }
                        if matches!(**cause, ShareError::Io { .. })
                ),
                "{err:?}"
            );

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
            hold_test_migration_lock!();
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
                matches!(
                    &err,
                    ShareError::SqliteSharedCommittedSlotsUnlinked { cause, .. }
                        if matches!(**cause, ShareError::SqliteChangedDuringMerge { .. })
                ),
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
            hold_test_migration_lock!();
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

        // ── M1: work-copy re-verification closes the plan/apply TOCTOU ──

        /// M1 (security): a disallowed trigger is planted on the ORIGINAL
        /// slot file AFTER `plan_one_basename` has already verified it clean
        /// — a genuine TOCTOU window, since planning and apply are two
        /// separate calls with real wall-clock time between them in
        /// production. `apply_basename_plan_with` makes its OWN work copy
        /// from the (now-mutated) original at apply time, so the FM-10
        /// pre/post-copy fingerprint check cannot see this: both reads
        /// happen AFTER the plant and are identical to each other. Only the
        /// work-copy re-verify (`forbid_untrusted_schema_objects` re-run on
        /// the work copy, post-checkpoint) can catch it — this test fails
        /// without it. The merge must refuse and leave the original
        /// completely untouched: still a real file, byte-identical, no
        /// symlink, no shared DB created.
        #[test]
        fn work_copy_reverify_refuses_a_trigger_planted_between_plan_and_apply() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
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
            assert!(matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }));

            // TOCTOU: planted on the ORIGINAL after planning already passed
            // `forbid_untrusted_schema_objects` clean.
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "CREATE TRIGGER evil_after_insert AFTER INSERT ON threads BEGIN SELECT 1; END;",
            );
            let planted_bytes = fs::read(home11.join("state_5.sqlite")).unwrap();

            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteUntrustedSchemaObject { .. }),
                "{err:?}"
            );

            let p = home11.join("state_5.sqlite");
            assert!(
                p.symlink_metadata().unwrap().file_type().is_file(),
                "the original must stay a real file, never renamed away"
            );
            assert_eq!(
                fs::read(&p).unwrap(),
                planted_bytes,
                "the original must be byte-identical to its state right before apply ran"
            );
            assert!(
                !shared_dir.join("state_5.sqlite").exists(),
                "no shared DB may be created from a work copy that failed re-verification"
            );
        }

        /// (a) M1: an extra `_sqlx_migrations` row landed on the ORIGINAL
        /// after planning passed clean — the migrations signature at apply
        /// time no longer matches the one planning recorded. Refuses with
        /// `SqliteChangedDuringMerge`, and nothing is merged.
        #[test]
        fn work_copy_reverify_refuses_an_extra_migration_planted_between_plan_and_apply() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
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
            assert!(matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }));

            // TOCTOU: a second migration lands on the ORIGINAL after
            // planning already recorded its 1-migration signature.
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "INSERT INTO _sqlx_migrations VALUES (2, 'm2', '2026-01-01 00:00:00', 1, \
                 x'00000002', 2);",
            );

            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );
            assert!(
                !shared_dir.join("state_5.sqlite").exists(),
                "nothing may be merged once the migrations signature has moved"
            );
        }

        /// (b) M1: `ALTER TABLE threads ADD COLUMN` landed on the ORIGINAL
        /// after planning — the new column is not itself on
        /// `THREADS_MERGE_ALLOWLIST`, so the filtered `columns` comparison
        /// alone cannot see it; the raw schema fingerprint catches it.
        #[test]
        fn work_copy_reverify_refuses_an_added_column_planted_between_plan_and_apply() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
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
            assert!(matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }));

            // TOCTOU: a new, non-allowlisted column lands on the ORIGINAL
            // after planning already recorded its column set.
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "ALTER TABLE threads ADD COLUMN unexpected_new_field TEXT;",
            );

            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );
            assert!(
                !shared_dir.join("state_5.sqlite").exists(),
                "nothing may be merged once the raw threads schema has moved"
            );
        }

        /// (c) M1: `CREATE VIEW` landed on the ORIGINAL after planning —
        /// caught by [`codex_sqlite::forbid_untrusted_schema_objects`]'s
        /// re-run on the work copy, the same as a planted trigger.
        #[test]
        fn work_copy_reverify_refuses_a_view_planted_between_plan_and_apply() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
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
            assert!(matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }));

            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "CREATE VIEW v AS SELECT 1;",
            );

            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteUntrustedSchemaObject { .. }),
                "{err:?}"
            );
            assert!(!shared_dir.join("state_5.sqlite").exists());
        }

        /// (d) M1: an existing shared DB's migrations are advanced AFTER
        /// planning a new slot's merge into it, but BEFORE apply runs. The
        /// merge refuses — and per M1's ordering (re-verify the shared DB
        /// FIRST, back it up only once that passes), this refusal is caught
        /// by the re-verify step itself, BEFORE any backup is attempted. No
        /// `.pre-merge-*` backup exists: a refused run must not spend a
        /// backup slot on content it never touched.
        #[test]
        fn plan_apply_gap_on_existing_shared_db_refuses_before_any_backup_is_taken() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            // Establish the shared DB from slot 11.
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 2,
                }],
                1,
            );

            let shared_dir = shared_root(base, Surface::Codex);
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
            assert!(matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }));

            // TOCTOU: the SHARED DB's own migrations advance between plan
            // and apply.
            let shared_path = shared_dir.join("state_5.sqlite");
            sh(
                &bin,
                &shared_path,
                "INSERT INTO _sqlx_migrations VALUES (2, 'm2', '2026-01-01 00:00:00', 1, \
                 x'00000002', 2);",
            );

            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );

            let backups: Vec<PathBuf> = fs::read_dir(&shared_dir)
                .unwrap()
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_str()?.to_string();
                    (name.starts_with("state_5.sqlite.pre-merge-")
                        && !name.ends_with("-wal")
                        && !name.ends_with("-shm"))
                    .then(|| shared_dir.join(name))
                })
                .collect();
            assert_eq!(
                backups.len(),
                0,
                "a refusal caught by the pre-backup re-verify must not have taken a backup: {backups:?}"
            );
        }

        /// Shared by the two in-transaction destination guard tests: shares
        /// slot 11, plans a merge of slot 14, then runs `change_shared` on the
        /// LIVE shared DB at the one point the apply step's own re-verify can
        /// no longer see it (just before `merge_sources_into_guarded`).
        /// Returns the apply error plus the shared DB's per-table row counts
        /// recorded right after the change and right after the refusal.
        fn apply_with_shared_changed_before_merge(
            change_shared: &'static str,
            extra_tables: &'static [&'static str],
        ) -> (ShareError, Vec<i64>, Vec<i64>, usize) {
            let bin = require_sqlite3().expect("sqlite3 required");
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 2,
                }],
                1,
            );
            let shared_dir = shared_root(base, Surface::Codex);
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
            assert!(matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }));

            let tables: Vec<&'static str> =
                ["threads", "projects", "project_roots", "_sqlx_migrations"]
                    .into_iter()
                    .chain(extra_tables.iter().copied())
                    .collect();
            let counts_after_change: std::rc::Rc<std::cell::RefCell<Vec<i64>>> = Default::default();
            let recorded = counts_after_change.clone();
            let hook_bin = bin.clone();
            let hook_tables = tables.clone();
            codex_sqlite::set_test_before_merge_hook(move |shared| {
                sh(&hook_bin, shared, change_shared);
                *recorded.borrow_mut() = hook_tables
                    .iter()
                    .map(|t| row_count(&hook_bin, shared, t))
                    .collect();
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
            codex_sqlite::clear_test_before_merge_hook();
            let err = result.unwrap_err();
            let shared_path = shared_dir.join("state_5.sqlite");
            let after: Vec<i64> = tables
                .iter()
                .map(|t| row_count(&bin, &shared_path, t))
                .collect();
            let before = counts_after_change.borrow().clone();
            let backups = fs::read_dir(&shared_dir)
                .unwrap()
                .flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n.starts_with("state_5.sqlite.pre-merge-")
                        && !n.contains("-tmp-")
                        && !n.ends_with("-wal")
                        && !n.ends_with("-shm")
                })
                .count();
            (err, before, after, backups)
        }

        /// The shared DB's migrations change AFTER the apply step's
        /// re-verify and BEFORE the merge transaction: the in-transaction
        /// migrations guard must refuse, writing nothing.
        #[test]
        fn shared_migrations_changed_between_reverify_and_merge_is_refused() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, before, after, backups) = apply_with_shared_changed_before_merge(
                "INSERT INTO _sqlx_migrations VALUES (2, 'm2', '2026-01-01 00:00:00', 1, \
                 x'00000002', 2);",
                &[],
            );
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );
            assert_eq!(
                before, after,
                "every shared-DB table's row count must be unchanged by the refused merge"
            );
            assert_eq!(
                backups, 0,
                "a guard refusal is pre-commit: no leaked backup"
            );
        }

        /// A failure of the write script that is NOT a guard refusal (forced
        /// by a seam that makes the script exit non-zero right after the
        /// guards) is not positively pre-commit, so the backup is KEPT.
        #[test]
        fn generic_merge_script_failure_keeps_the_backup() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            codex_sqlite::set_test_force_script_failure(true);
            let (err, _before, _after, backups) =
                apply_with_shared_changed_before_merge("SELECT 1;", &[]);
            codex_sqlite::set_test_force_script_failure(false);
            assert!(
                matches!(err, ShareError::SqliteMergeOutcomeUnknown { .. }),
                "{err:?}"
            );
            assert!(
                err.to_string().contains("state_5.sqlite.pre-merge-"),
                "the error must name the kept backup: {err}"
            );
            assert_eq!(backups, 1, "an uncertain outcome must keep its backup");
        }

        /// A trigger planted on the LIVE shared DB after the apply step's
        /// re-verify must be refused by the in-transaction schema-object
        /// guard BEFORE any INSERT, so it never fires (it would write a
        /// marker row) and nothing changes.
        #[test]
        fn trigger_planted_between_reverify_and_merge_is_refused_and_never_fires() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, before, after, backups) = apply_with_shared_changed_before_merge(
                "CREATE TABLE csq_marker(x INTEGER);\n\
                 CREATE TRIGGER csq_evil BEFORE INSERT ON threads \
                 BEGIN INSERT INTO csq_marker VALUES (1); END;",
                &["csq_marker"],
            );
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );
            assert_eq!(before, after, "no table may change");
            assert_eq!(
                *after.last().unwrap(),
                0,
                "the planted trigger must never fire"
            );
            assert_eq!(backups, 0, "a guard refusal is pre-commit");
        }

        /// The shared DB's `threads` schema changes in that same window: the
        /// in-transaction `threads` fingerprint guard must refuse.
        #[test]
        fn shared_threads_schema_changed_between_reverify_and_merge_is_refused() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, before, after, backups) = apply_with_shared_changed_before_merge(
                "ALTER TABLE threads ADD COLUMN csq_extra_col TEXT;",
                &[],
            );
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );
            assert_eq!(
                before, after,
                "every shared-DB table's row count must be unchanged by the refused merge"
            );
            assert_eq!(
                backups, 0,
                "a guard refusal is pre-commit: no leaked backup"
            );
        }

        /// (f) / B1: an existing shared DB merges a slot whose `project_roots`
        /// row references a `projects` id that exists NOWHERE (neither in
        /// that slot's own `projects` table nor the shared DB's) — an
        /// orphan on a table this module does NOT know how to repair (only
        /// `threads.project_id`/`thread_section_id` are repaired). The whole
        /// merge — `threads`, every carried table, AND the repair-and-guard
        /// — runs as ONE transaction against the LIVE shared DB, so this
        /// refusal must leave EVERY table's row count in the shared DB
        /// exactly as it was before this call.
        #[test]
        fn orphan_on_a_carried_table_refuses_and_leaves_the_shared_db_untouched() {
            hold_test_migration_lock!();
            orphan_refusal_fixture(false);
        }

        /// Same refusal on a sqlite3 that keeps executing past an error (the
        /// seam drops `-bail`): the post-write FK guard is `INSERT OR ROLLBACK`,
        /// so the following `COMMIT` fails and the shared DB is unchanged.
        /// Falsifying result with a plain `INSERT`: the orphan rows commit and
        /// the row counts change.
        #[test]
        fn orphan_refusal_holds_on_a_sqlite3_that_does_not_bail() {
            hold_test_migration_lock!();
            orphan_refusal_fixture(true);
        }

        fn orphan_refusal_fixture(continue_past_errors: bool) {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "INSERT INTO projects (id, name, metadata, position, created_at_ms, updated_at_ms) \
                 VALUES ('proj-real', 'Real', '{}', 0, 1, 1);",
            );
            // Establish the shared DB from slot 11 (carries `proj-real`).
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let shared_dir = shared_root(base, Surface::Codex);
            let shared_path = shared_dir.join("state_5.sqlite");
            let tables = [
                "threads",
                "thread_dynamic_tools",
                "backfill_state",
                "thread_spawn_edges",
                "remote_control_enrollments",
                "external_agent_config_imports",
                "thread_sections",
                "projects",
                "project_roots",
                "project_idempotency_keys",
                "thread_attachments",
            ];
            let counts_before: Vec<i64> = tables
                .iter()
                .map(|t| row_count(&bin, &shared_path, t))
                .collect();

            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 2,
                }],
                1,
            );
            // `project_roots.project_id` DOES have a `REFERENCES
            // projects(id)` in codex's own schema (verified against the
            // fixture) — but `threads_repairable_fk_targets` only reads
            // `PRAGMA foreign_key_list(threads)`, never `project_roots`, so
            // this module's repair never reaches ANY other table's foreign
            // keys regardless of what they declare. This orphan is
            // therefore one this module does NOT know how to repair — it
            // must refuse.
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "INSERT INTO project_roots (project_id, position, path) \
                 VALUES ('proj-ghost', 0, '/nowhere');",
            );

            let err = if continue_past_errors {
                codex_sqlite::with_continue_past_errors(|| {
                    codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err()
                })
            } else {
                codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err()
            };
            assert!(
                matches!(err, ShareError::SqliteForeignKeyViolation { .. }),
                "{err:?}"
            );

            let counts_after: Vec<i64> = tables
                .iter()
                .map(|t| row_count(&bin, &shared_path, t))
                .collect();
            assert_eq!(
                counts_before, counts_after,
                "every table's row count in the shared DB must be unchanged after a refusal"
            );

            // R1: this refusal is caught INSIDE `merge_sources_into` (the
            // post-merge guard), which is PRE-commit (B1) — `shared_path`
            // is provably unchanged, so the pre-merge backup taken before
            // this call is backing up content that was never at risk. It
            // is deleted before the error propagates, rather than leaked
            // as a full-size, never-pruned artifact (pruning only runs
            // after a SUCCESSFUL merge, per M1) — so NONE should remain.
            let backups: Vec<PathBuf> = fs::read_dir(&shared_dir)
                .unwrap()
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_str()?.to_string();
                    (name.starts_with("state_5.sqlite.pre-merge-")
                        && !name.ends_with("-wal")
                        && !name.ends_with("-shm"))
                    .then(|| shared_dir.join(name))
                })
                .collect();
            assert_eq!(
                backups.len(),
                0,
                "a pre-commit refusal must delete its now-redundant backup: {backups:?}"
            );
        }

        /// H1: with an EXISTING shared DB, a refusal in the per-slot
        /// rename-and-link loop happens AFTER `merge_sources_into` has
        /// already committed into the LIVE shared index. The error MUST be
        /// `SqliteSharedCommittedSlotsUnlinked` (not a bare
        /// `SqliteChangedDuringMerge`/`LiveWriters`/`Io`, none of which say
        /// what actually happened here), and its message MUST name the
        /// pre-merge backup this call took, since that backup is the
        /// operator's recovery path.
        #[test]
        fn existing_shared_db_refusal_in_rename_loop_names_the_backup() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            // Establish the shared DB from slot 11 FIRST.
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            // A NEW slot joining an ALREADY-established shared DB.
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 2,
                }],
                1,
            );

            let shared_dir = shared_root(base, Surface::Codex);
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
            assert!(matches!(plan, codex_sqlite::BasenamePlan::ToMerge { .. }));

            // A live-writer artifact planted BEFORE apply runs — the
            // rename loop's OWN `ensure_no_live_writers` re-check (which
            // runs regardless of the top-level guard `share_codex_sqlite`
            // would otherwise have performed) trips on its very first
            // iteration, for slot 14 (the only real copy in this plan —
            // slot 11 is already a symlink).
            let term = base.join("term-999");
            fs::create_dir_all(&term).unwrap();
            fs::write(term.join("auth.json"), b"x").unwrap();
            fs::write(term.join("config.toml"), b"x").unwrap();
            fs::write(term.join(".live-pid"), std::process::id().to_string()).unwrap();

            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                false,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteSharedCommittedSlotsUnlinked { .. }),
                "{err:?}"
            );
            let msg = err.to_string();
            assert!(msg.contains("was merged into"), "{msg}");
            assert!(msg.contains("pre-merge backup"), "{msg}");
            assert!(msg.contains("shared index"), "{msg}");
        }

        // ── H2: backup pruning ────────────────────────────────────────────

        /// H2: a clock-behind scenario. Two OLDER backups are stamped with
        /// epochs LARGER than the one this call is about to create (as if
        /// the system clock moved backward between runs) — a rank-only
        /// pruning policy would read the just-created backup as "oldest"
        /// and delete it. Excluding `just_created` structurally, regardless
        /// of rank, is what makes "the new one survives" true.
        #[test]
        fn prune_never_deletes_the_backup_this_run_just_made_even_under_clock_skew() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path();
            let basename = "state_5.sqlite";
            let make = |suffix: &str| {
                let p = dir.join(format!("{basename}.pre-merge-{suffix}"));
                fs::write(&p, b"x").unwrap();
                p
            };
            // Two "older" backups stamped with LATER epochs than the new
            // one (clock skew) — both must still be pruned as excess once
            // `keep = 1`, and the just-created one must survive regardless.
            let skewed_a = make("999999999-1");
            let skewed_b = make("999999998-2");
            let just_created = make("100-3");

            codex_sqlite::prune_old_pre_merge_backups(dir, basename, 1, &just_created);

            assert!(
                just_created.exists(),
                "the backup THIS call just made must never be pruned"
            );
            assert!(!skewed_a.exists());
            assert!(!skewed_b.exists());
        }

        /// H2/T1: a `-wal`/`-shm` sidecar name must never be counted as its
        /// OWN backup toward `keep` — only as part of its main file. The
        /// sidecars are deliberately placed on the SECOND-NEWEST backup
        /// (`300`), not the oldest: a parser that double-counts them as
        /// phantom extra "backups" tied at epoch 300 would fill the
        /// `keep`-slot budget with those phantoms and wrongly evict the
        /// genuinely-second-oldest real backup (`200`) instead of the
        /// actual oldest (`100`) — a bug that "sidecars get pruned
        /// alongside their main file" alone would not catch, since `100`
        /// has no sidecars to notice going missing. With `keep = 3`:
        /// `400` (just_created, exempt), `300` (with its sidecars), and
        /// `200` must all survive; only `100` is pruned.
        #[test]
        fn prune_never_counts_sidecar_names_as_their_own_backup() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path();
            let basename = "state_5.sqlite";
            let main = |suffix: &str| dir.join(format!("{basename}.pre-merge-{suffix}"));
            let write = |p: &Path| fs::write(p, b"x").unwrap();

            let oldest = main("100");
            write(&oldest);
            let mid = main("200");
            write(&mid);
            let newer = main("300");
            write(&newer);
            write(&PathBuf::from(format!("{}-wal", newer.display())));
            write(&PathBuf::from(format!("{}-shm", newer.display())));
            let just_created = main("400");
            write(&just_created);

            codex_sqlite::prune_old_pre_merge_backups(dir, basename, 3, &just_created);

            assert!(!oldest.exists(), "the oldest main file must be pruned");
            assert!(
                mid.exists(),
                "200 must survive — it is the SECOND oldest, not a phantom"
            );
            assert!(newer.exists());
            assert!(
                PathBuf::from(format!("{}-wal", newer.display())).exists(),
                "300's sidecars must survive together with its main file"
            );
            assert!(just_created.exists());
        }

        /// A private backup staging dir (`<db>.pre-merge-tmp-<pid>-<epoch>`)
        /// must never parse as a backup: `tmp` is not all-digit, so pruning
        /// leaves it alone no matter how many backups surround it.
        #[test]
        fn prune_ignores_private_tmp_dirs() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path();
            let basename = "state_5.sqlite";
            // A plain file of that name, not a dir: `remove_db_with_sidecars`
            // cannot delete a directory, so only a FILE lets this test see
            // whether the parser wrongly selected the name for pruning.
            let tmp_dir = dir.join(format!("{basename}.pre-merge-tmp-111-1"));
            fs::write(&tmp_dir, b"x").unwrap();
            let just_created = dir.join(format!("{basename}.pre-merge-500-9"));
            fs::write(&just_created, b"x").unwrap();

            codex_sqlite::prune_old_pre_merge_backups(dir, basename, 1, &just_created);

            assert!(tmp_dir.exists(), "prune must not select a private tmp name");
        }

        /// A crash-leftover private staging dir whose pid is dead is swept;
        /// a fresh dir owned by a live pid and a name that is not exactly
        /// `<digits>-<digits>` are kept. Liveness is injected: pid 999_999
        /// is "dead", this process's pid is "alive".
        #[test]
        fn sweep_removes_dead_pid_dir_keeps_live_and_non_matching() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path();
            let basename = "state_5.sqlite";
            let now = 1_000_000u64;
            let mk = |name: String| {
                let p = dir.join(name);
                fs::create_dir(&p).unwrap();
                fs::write(p.join("backup.sqlite"), b"x").unwrap();
                p
            };
            let live_pid = std::process::id();
            let dead = mk(format!("{basename}.pre-merge-tmp-999999-{now}"));
            let live = mk(format!("{basename}.pre-merge-tmp-{live_pid}-{now}"));
            let non_matching = [
                mk(format!("{basename}.pre-merge-tmp-abc-{now}")),
                mk(format!("{basename}.pre-merge-tmp-999999-{now}-x")),
                mk(format!("other.sqlite.pre-merge-tmp-999999-{now}")),
            ];

            codex_sqlite::sweep_stale_pre_merge_tmp_dirs(dir, basename, now, |p| p != 999_999);

            assert!(!dead.exists(), "dead-pid staging dir must be swept");
            assert!(live.exists(), "fresh live-pid staging dir must be kept");
            for p in &non_matching {
                assert!(p.exists(), "non-matching name must be kept: {p:?}");
            }
        }

        /// pid 0 and pids above i32::MAX are never real processes (`kill(2)`
        /// would read them as a process group / negative pid and say
        /// "alive"), so they are swept even when liveness claims otherwise.
        #[test]
        fn sweep_treats_out_of_range_pids_as_dead() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path();
            let basename = "state_5.sqlite";
            let now = 1_000_000u64;
            let dirs: Vec<PathBuf> = ["0", "4294967295"]
                .iter()
                .map(|pid| {
                    let p = dir.join(format!("{basename}.pre-merge-tmp-{pid}-{now}"));
                    fs::create_dir(&p).unwrap();
                    p
                })
                .collect();

            codex_sqlite::sweep_stale_pre_merge_tmp_dirs(dir, basename, now, |_| true);

            for p in &dirs {
                assert!(!p.exists(), "{p:?} must be swept");
            }
        }

        /// A staging dir older than the age bound is swept even when its pid
        /// is alive (pid reuse).
        #[test]
        fn sweep_removes_old_dir_even_when_pid_is_alive() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path();
            let basename = "state_5.sqlite";
            let now = 1_000_000u64;
            let old = dir.join(format!(
                "{basename}.pre-merge-tmp-{}-{}",
                std::process::id(),
                now - 3601
            ));
            fs::create_dir(&old).unwrap();

            codex_sqlite::sweep_stale_pre_merge_tmp_dirs(dir, basename, now, |_| true);

            assert!(!old.exists());
        }

        /// T1: the SAME scenario, replayed against the OLD (pre-fix) naive
        /// parser shape — `suffix.split('-').next()` for the epoch, with no
        /// full-shape validation and no early `-wal`/`-shm` exclusion. That
        /// shape genuinely double-counts `state_5.sqlite.pre-merge-300-wal`
        /// and `...-300-shm` as extra epoch-300 "backups", which is exactly
        /// what displaces the real `200` backup out of the keep-3 budget.
        #[test]
        fn prune_old_naive_parser_would_have_wrongly_evicted_a_real_backup() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path();
            let basename = "state_5.sqlite";
            let main = |suffix: &str| dir.join(format!("{basename}.pre-merge-{suffix}"));
            let prefix = format!("{basename}.pre-merge-");

            let oldest = main("100");
            let mid = main("200");
            let newer = main("300");
            let newer_wal = PathBuf::from(format!("{}-wal", newer.display()));
            let newer_shm = PathBuf::from(format!("{}-shm", newer.display()));
            let just_created = main("400");
            for p in [&oldest, &mid, &newer, &newer_wal, &newer_shm, &just_created] {
                fs::write(p, b"x").unwrap();
            }

            // The OLD shape: every directory entry whose suffix's FIRST
            // '-'-delimited component parses as a number is a "backup" —
            // sidecars included, no full `<epoch>-<pid>` shape check.
            let mut backups: Vec<(u64, PathBuf)> = fs::read_dir(dir)
                .unwrap()
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_str()?.to_string();
                    let suffix = name.strip_prefix(&prefix)?;
                    let epoch_str = suffix.split('-').next()?;
                    let epoch: u64 = epoch_str.parse().ok()?;
                    Some((epoch, dir.join(name)))
                })
                .collect();
            backups.sort_by_key(|backup| std::cmp::Reverse(backup.0));
            for (_, path) in backups.into_iter().skip(3) {
                let _ = fs::remove_file(&path);
            }

            assert!(
                !mid.exists(),
                "the OLD naive parser evicts the real `200` backup because the `300` \
                 sidecars occupy two of the three keep-slots as phantom duplicates"
            );
        }

        // ── M2: carried tables select/insert by NAME, not position ───────

        /// M2: a source whose `projects` table has the SAME columns as the
        /// destination's, but in a DIFFERENT physical order (a `DROP
        /// TABLE`/`CREATE TABLE` with `id` and `name` swapped) — a
        /// `SELECT *`-based carry would silently write `id`'s VALUE into
        /// the destination's `name` column and vice versa. Selecting and
        /// inserting by NAME must land each value in the correct column
        /// regardless of the source's physical order.
        #[test]
        fn carried_table_lands_rows_by_name_even_when_source_column_order_differs() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "a",
                    updated_at_ms: 1,
                }],
                1,
            );
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "b",
                    updated_at_ms: 2,
                }],
                1,
            );
            // Same COLUMN SET as the standard `projects` schema, but `id`
            // and `name` swapped in physical order.
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "DROP TABLE projects;\n\
                 CREATE TABLE projects (\n\
                   name TEXT NOT NULL,\n\
                   id TEXT PRIMARY KEY,\n\
                   metadata TEXT NOT NULL DEFAULT '{}',\n\
                   position INTEGER NOT NULL,\n\
                   created_at_ms INTEGER NOT NULL,\n\
                   updated_at_ms INTEGER NOT NULL\n\
                 );\n\
                 INSERT INTO projects (id, name, metadata, position, created_at_ms, \
                   updated_at_ms) VALUES ('proj-1', 'My Project', '{}', 0, 1, 1);",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                sh_query(
                    &bin,
                    &merged,
                    "SELECT id FROM projects WHERE name = 'My Project';"
                )
                .trim(),
                "proj-1",
                "the row must land by NAME, not by the source's physical column position"
            );
        }

        // ── M3: sqlite3 stderr never leaks the operator's home path ──────

        // T4: a PRIVATE $HOME for these tests — never the real one, so this
        // test never touches (or `remove_file`s anything under) the actual
        // operator's home directory. `std::env::set_var` is process-global,
        // so each test holds the crate-wide `platform::test_env::lock()` —
        // the SAME mutex every other HOME-mutating test in this crate
        // (`error.rs`, `cli_deps::*`, `accounts::login`, and the other
        // `shared_state` tests) holds. A module-local mutex here did NOT
        // serialize against those writers: a concurrent `set_var("HOME")`
        // changed what `redact_home_anywhere` read mid-call, so the raw
        // private path leaked into the error string.

        /// M3/T4: a failing sqlite3 invocation against a source path that
        /// does not exist. The failure is NOT `ATTACH DATABASE` — it is
        /// `merge_sources_into`'s own read-only PRE-READ of the source
        /// (`user_table_names`, computing the per-source carry-table
        /// order), which runs BEFORE the write script is even built, and
        /// which fails first because the path cannot be opened at all. That
        /// read-only failure's stderr names the path verbatim ("unable to
        /// open database file"). The resulting error string must contain
        /// NO raw occurrence of the operator's `$HOME` — and, so this test
        /// cannot pass by printing nothing at all, MUST contain the
        /// redacted `~/` form.
        #[test]
        fn failing_attach_stderr_never_leaks_the_home_path() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let _env_guard = crate::platform::test_env::lock();
            let private_home = TempDir::new().unwrap();
            let restore_home = HomeRestore(std::env::var_os("HOME"));
            std::env::set_var("HOME", private_home.path());

            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            // A source path under the PRIVATE $HOME that does not exist —
            // sqlite3 itself will name it verbatim in its "unable to open
            // database file" stderr line.
            let missing_source = private_home
                .path()
                .join(".csq-test-nonexistent-attach-source.sqlite");

            let err = codex_sqlite::merge_sources_into(
                &bin,
                "state_5.sqlite",
                &home11.join("state_5.sqlite"),
                &[missing_source],
                &[],
            )
            .unwrap_err();
            let msg = err.to_string();

            // Restore before diagnostics; Drop also covers earlier unwinds.
            drop(restore_home);

            let private_home_str = private_home.path().display().to_string();
            assert!(
                !msg.contains(&private_home_str),
                "error must not leak the raw $HOME path: {msg}"
            );
            assert!(
                msg.contains("~/"),
                "the redacted `~/` form must appear — otherwise this test cannot tell \
                 'redacted correctly' apart from 'printed nothing at all': {msg}"
            );
        }

        /// T4: the SAME scenario, with a `$HOME` containing a SPACE.
        /// `readonly_db_arg` names the source as a `file:`-URI
        /// (`sqlite_uri_path` percent-encodes it), so sqlite3's own stderr
        /// echoes the space back as `%20`, not a literal space — a
        /// literal-needle search for `$HOME` would silently miss it and
        /// leak the (percent-encoded) home path.
        #[test]
        fn failing_attach_stderr_never_leaks_a_home_path_containing_a_space() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let _env_guard = crate::platform::test_env::lock();
            let tmp_root = TempDir::new().unwrap();
            let private_home = tmp_root.path().join("home with space");
            fs::create_dir_all(&private_home).unwrap();
            let restore_home = HomeRestore(std::env::var_os("HOME"));
            std::env::set_var("HOME", &private_home);

            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            let missing_source = private_home.join(".csq-test-nonexistent-attach-source.sqlite");

            let err = codex_sqlite::merge_sources_into(
                &bin,
                "state_5.sqlite",
                &home11.join("state_5.sqlite"),
                &[missing_source],
                &[],
            )
            .unwrap_err();
            let msg = err.to_string();

            drop(restore_home);

            let private_home_str = private_home.display().to_string();
            assert!(
                !msg.contains(&private_home_str),
                "error must not leak the raw (space-containing) $HOME path: {msg}"
            );
            assert!(
                !msg.contains("home%20with%20space"),
                "error must not leak the PERCENT-ENCODED form of $HOME either: {msg}"
            );
            assert!(
                msg.contains("~/"),
                "the redacted `~/` form must appear: {msg}"
            );
        }

        // ── T5: missing-test items from round 5 ───────────────────────────

        /// T5(a): a source whose `projects` table has an EXTRA column
        /// relative to the destination's — the column SET differs, not
        /// just the order — must refuse with
        /// `SqliteCarriedTableColumnMismatch`, and the shared DB's row
        /// counts in every table must be unchanged.
        #[test]
        fn extra_source_column_on_a_carried_table_refuses_and_leaves_shared_db_unchanged() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "INSERT INTO projects (id, name, metadata, position, created_at_ms, \
                 updated_at_ms) VALUES ('proj-real', 'Real', '{}', 0, 1, 1);",
            );
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let shared_dir = shared_root(base, Surface::Codex);
            let shared_path = shared_dir.join("state_5.sqlite");
            let tables = ["threads", "projects", "project_roots"];
            let counts_before: Vec<i64> = tables
                .iter()
                .map(|t| row_count(&bin, &shared_path, t))
                .collect();

            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 2,
                }],
                1,
            );
            // An EXTRA column — the column SET now differs from the
            // destination's, not merely the order.
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "ALTER TABLE projects ADD COLUMN extra_col TEXT;\n\
                 INSERT INTO projects (id, name, metadata, position, created_at_ms, \
                 updated_at_ms, extra_col) VALUES ('proj-new', 'New', '{}', 0, 1, 1, 'x');",
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteCarriedTableColumnMismatch { .. }),
                "{err:?}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains("start codex once on the side that is behind"),
                "the mismatch error must carry the remediation hint: {msg}"
            );

            let counts_after: Vec<i64> = tables
                .iter()
                .map(|t| row_count(&bin, &shared_path, t))
                .collect();
            assert_eq!(counts_before, counts_after);
        }

        /// T5(b) / M4: `threads_repairable_fk_targets` must SKIP a `threads`
        /// foreign key whose `to` column is neither empty nor `id` — a
        /// standalone, minimal schema exercises this directly (the real
        /// codex schema always targets `id`, so this is not reachable
        /// through the normal fixtures at all).
        #[test]
        fn threads_repairable_fk_targets_skips_a_fk_targeting_a_non_id_column() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let db = t.path().join("mini.sqlite");
            sh(
                &bin,
                &db,
                "CREATE TABLE projects (id TEXT PRIMARY KEY, slug TEXT UNIQUE);\n\
                 CREATE TABLE thread_sections (id TEXT PRIMARY KEY);\n\
                 CREATE TABLE threads (\n\
                   id TEXT PRIMARY KEY,\n\
                   project_id TEXT REFERENCES projects(slug),\n\
                   thread_section_id TEXT REFERENCES thread_sections(id)\n\
                 );",
            );
            let pairs = codex_sqlite::threads_repairable_fk_targets(&bin, &db).unwrap();
            assert!(
                !pairs.iter().any(|(c, _)| c == "project_id"),
                "a FK targeting `slug`, not `id`, must be skipped: {pairs:?}"
            );
            assert!(
                pairs
                    .iter()
                    .any(|(c, tbl)| c == "thread_section_id" && tbl == "thread_sections"),
                "a FK targeting `id` must still be recognised: {pairs:?}"
            );
        }

        /// M4 (LOW-a): an EMPTY `to` column — SQLite's own shorthand for
        /// "resolve against the target's primary key" — must be resolved
        /// against the target's ACTUAL primary key column via
        /// [`table_primary_key_column`], not assumed to be `id`. A FK
        /// declared with no column list against a table whose real primary
        /// key is `slug` is skipped; the same shorthand against a table
        /// whose real primary key IS `id` is still recognised.
        #[test]
        fn threads_repairable_fk_targets_resolves_an_empty_to_against_the_real_primary_key() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let db = t.path().join("mini.sqlite");
            sh(
                &bin,
                &db,
                "CREATE TABLE projects (slug TEXT PRIMARY KEY, id TEXT UNIQUE);\n\
                 CREATE TABLE thread_sections (id TEXT PRIMARY KEY);\n\
                 CREATE TABLE threads (\n\
                   id TEXT PRIMARY KEY,\n\
                   project_id TEXT REFERENCES projects,\n\
                   thread_section_id TEXT REFERENCES thread_sections\n\
                 );",
            );
            let pairs = codex_sqlite::threads_repairable_fk_targets(&bin, &db).unwrap();
            assert!(
                !pairs.iter().any(|(c, _)| c == "project_id"),
                "an empty `to` against a table whose real primary key is \
                 `slug`, not `id`, must be skipped: {pairs:?}"
            );
            assert!(
                pairs
                    .iter()
                    .any(|(c, tbl)| c == "thread_section_id" && tbl == "thread_sections"),
                "an empty `to` against a table whose real primary key IS \
                 `id` must still be recognised: {pairs:?}"
            );
        }

        /// T5(c): the private staging directory `backup_via_vacuum_into`
        /// creates must be removed even when `VACUUM INTO` itself fails.
        #[test]
        fn private_tmp_dir_is_removed_when_vacuum_into_fails() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            // A path that EXISTS but is not a valid sqlite database at all
            // — a genuinely non-existent path is opened by `sqlite3` as a
            // brand-new, empty database (silently succeeding), so this is
            // the shape that actually makes `VACUUM INTO` fail.
            let garbage_src = t.path().join("garbage.sqlite");
            fs::write(&garbage_src, b"not a sqlite file at all").unwrap();
            let dst = t.path().join("state_5.sqlite.pre-merge-1-1");

            let err =
                codex_sqlite::backup_via_vacuum_into(&bin, "state_5.sqlite", &garbage_src, &dst)
                    .unwrap_err();
            assert!(!dst.exists(), "{err:?}");
            let leftover: Vec<_> = fs::read_dir(t.path())
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".pre-merge-tmp-"))
                .collect();
            assert!(
                leftover.is_empty(),
                "the private staging dir must not survive a VACUUM INTO failure: {leftover:?}"
            );
        }

        /// T5(c): the SAME private staging directory must ALSO be removed
        /// when `VACUUM INTO` succeeds but the subsequent integrity check
        /// fails — exercised via a seam that corrupts the freshly-VACUUMed
        /// file between the two steps.
        #[test]
        fn private_tmp_dir_is_removed_when_integrity_check_fails() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let src = t.path().join("src.sqlite");
            sh(&bin, &src, "CREATE TABLE t(id INTEGER);");
            let dst = t.path().join("state_5.sqlite.pre-merge-1-1");

            codex_sqlite::set_test_after_vacuum_hook(|tmp_file| {
                fs::write(tmp_file, b"not a valid sqlite file at all").unwrap();
            });
            let err = codex_sqlite::backup_via_vacuum_into(&bin, "state_5.sqlite", &src, &dst);
            codex_sqlite::clear_test_after_vacuum_hook();

            assert!(err.is_err());
            assert!(!dst.exists());
            let leftover: Vec<_> = fs::read_dir(t.path())
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".pre-merge-tmp-"))
                .collect();
            assert!(
                leftover.is_empty(),
                "the private staging dir must not survive an integrity-check failure: {leftover:?}"
            );
        }

        /// T5(d): a chmod failure on the freshly-VACUUMed staging file must
        /// be an ERROR (H3), and must leave NO backup at `dst` — the whole
        /// point of staging in a private directory first.
        #[test]
        #[cfg(unix)]
        fn chmod_failure_on_the_backup_is_an_error_and_leaves_no_backup() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let src = t.path().join("src.sqlite");
            sh(&bin, &src, "CREATE TABLE t(id INTEGER);");
            let dst = t.path().join("state_5.sqlite.pre-merge-1-1");

            codex_sqlite::set_test_force_chmod_failure_at_call(1);
            let err = codex_sqlite::backup_via_vacuum_into(&bin, "state_5.sqlite", &src, &dst);
            codex_sqlite::clear_test_force_chmod_failure();

            assert!(err.is_err());
            assert!(
                !dst.exists(),
                "no backup may exist at dst after a chmod failure"
            );
        }

        /// LOW(b): `backup_via_vacuum_into` must REFUSE a pre-existing
        /// `dst` rather than silently replacing it — `fs::rename` would
        /// clobber it; the link-then-unlink sequence this fixes it to use
        /// fails with `AlreadyExists` instead.
        #[test]
        fn backup_via_vacuum_into_refuses_a_pre_existing_dst() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let src = t.path().join("src.sqlite");
            sh(&bin, &src, "CREATE TABLE t(id INTEGER);");
            let dst = t.path().join("state_5.sqlite.pre-merge-1-1");
            let sentinel = b"a pre-existing backup that must not be replaced";
            fs::write(&dst, sentinel).unwrap();

            let err = codex_sqlite::backup_via_vacuum_into(&bin, "state_5.sqlite", &src, &dst)
                .unwrap_err();
            assert!(
                matches!(err, ShareError::Io { .. }),
                "expected an Io error on an AlreadyExists collision: {err:?}"
            );
            assert_eq!(
                fs::read(&dst).unwrap(),
                sentinel,
                "a pre-existing dst must be left completely untouched"
            );
            let leftover: Vec<_> = fs::read_dir(t.path())
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".pre-merge-tmp-"))
                .collect();
            assert!(
                leftover.is_empty(),
                "the private staging dir must not survive a dst collision: {leftover:?}"
            );
        }

        /// B2: `thread_section_id` and `section_entered_at_ms` must move
        /// TOGETHER with `section_position` — a thread's placement is
        /// meaningless split across two sides of a merge.
        #[test]
        fn section_placement_columns_move_together_on_the_newer_side() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();

            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n1",
                    updated_at_ms: 100,
                }],
                1,
            );
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "INSERT INTO thread_sections (id, name) VALUES ('sec-old', 'Old');\n\
                 UPDATE threads SET thread_section_id = 'sec-old', section_position = 1, \
                 section_entered_at_ms = 10 WHERE id = 't1';",
            );
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n1",
                    updated_at_ms: 200,
                }],
                1,
            );
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "INSERT INTO thread_sections (id, name) VALUES ('sec-new', 'New');\n\
                 UPDATE threads SET thread_section_id = 'sec-new', section_position = 9, \
                 section_entered_at_ms = 90 WHERE id = 't1';",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let merged = home11.join("state_5.sqlite");
            assert_eq!(
                thread_field(&bin, &merged, "t1", "thread_section_id"),
                "sec-new"
            );
            assert_eq!(thread_field(&bin, &merged, "t1", "section_position"), "9");
            assert_eq!(
                thread_field(&bin, &merged, "t1", "section_entered_at_ms"),
                "90"
            );
        }

        // ── C-R4-13 / S-F2: dry-run never mutates the pre-share repair ────

        /// `--dry-run` must NEVER rename a stranded `.pre-share-<epoch>`
        /// backup into place — only report what a real run would repair.
        #[test]
        fn dry_run_never_restores_a_stranded_pre_share_backup() {
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
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
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            // T2: without this, a REAL `codex`/`claude` process on the
            // host running this test could satisfy the live-writer check
            // BEFORE the planted `term-999` sentinel ever gets read,
            // making this test pass for the wrong reason (or fail
            // spuriously on a quiet host with none running).
            let _procs_guard = force_list_running_processes(vec![]);
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
            assert!(
                matches!(
                    &err,
                    ShareError::SqliteSharedCommittedSlotsUnlinked { cause, .. }
                        if matches!(**cause, ShareError::LiveWriters { .. })
                ),
                "{err:?}"
            );

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
            hold_test_migration_lock!();
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
            assert!(
                matches!(
                    &err,
                    ShareError::SqliteSharedCommittedSlotsUnlinked { cause, .. }
                        if matches!(**cause, ShareError::Io { .. })
                ),
                "{err:?}"
            );

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
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let base = t.path();
            let src = base.join("state_5.sqlite");
            let dst = base.join("state_5.sqlite.pre-share-1000");
            fs::write(&src, b"TEST INPUT: main db").unwrap();
            fs::write(format!("{}-wal", src.display()), b"TEST INPUT: wal").unwrap();
            // Poison dst's -wal as a DIRECTORY (after the move's own
            // pre-check, which refuses an existing dst), so renaming src's
            // real -wal sidecar onto it fails — the main file has already
            // moved to dst by then.
            codex_sqlite::set_test_after_main_move_hook(|dst| {
                fs::create_dir_all(format!("{}-wal", dst.display())).unwrap();
            });
            let result = codex_sqlite::rename_db_with_sidecars(&src, &dst);
            codex_sqlite::clear_test_after_main_move_hook();
            let err = result.unwrap_err();
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
            hold_test_migration_lock!();
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
                matches!(
                    &err,
                    ShareError::SqliteSharedCommittedSlotsUnlinked { cause, .. }
                        if matches!(**cause, ShareError::SqliteChangedDuringMerge { .. })
                ),
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

        // ── N1: a chmod failure after rename must self-heal ──────────────

        /// N1: a chmod failure on the per-slot rename-to-backup step, AFTER
        /// the rename itself already succeeded. Without the fix,
        /// `rename_db_with_sidecars` left `dst` renamed and returned an
        /// error without undoing it — the slot ends up with NEITHER a real
        /// `state_5.sqlite` NOR a symlink, so codex-cli creates a brand-new,
        /// empty database there and the thread list "looks wiped". The fix
        /// undoes the rename on a chmod failure, so the slot's original
        /// file must still be present, byte-identical, after this refusal.
        #[test]
        #[cfg(unix)]
        fn chmod_failure_after_per_slot_rename_self_heals() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
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

            // Calls to `secure_sqlite_paths` in order for this single-slot,
            // first-creation scenario: #1 the work-copy, #2 the tmp_shared
            // seed, #3 the first-creation rename into `shared_path`, #4 the
            // per-slot rename to `.pre-share-*`. This test targets #4.
            codex_sqlite::set_test_force_chmod_failure_at_call(4);
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
            codex_sqlite::clear_test_force_chmod_failure();

            let err = result.unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteSharedCommittedSlotsUnlinked { .. }),
                "{err:?}"
            );

            let p = home11.join("state_5.sqlite");
            assert!(
                p.symlink_metadata().unwrap().file_type().is_file(),
                "the slot must still have its own REAL file, not neither-file-nor-symlink"
            );
            assert_eq!(
                fs::read(&p).unwrap(),
                original_bytes,
                "the restored file must be byte-identical to the original"
            );
            // Unlike the sibling test below, this failure is AFTER the
            // first-creation rename (call #3) already durably committed
            // the shared index — that is exactly the H1 scenario this
            // seam targets. The shared index legitimately exists; only
            // the per-slot LINKING failed.
            assert!(
                shared_dir.join("state_5.sqlite").exists(),
                "the shared index itself was already committed before this call's own rename \
                 failed — it must still be there"
            );
        }

        /// N1/R2: the SAME chmod-failure seam, on the FIRST-CREATION path
        /// (`rename_db_with_sidecars(&tmp_shared, &shared_path)`). The fix
        /// must self-heal here too: `shared_path` must not exist, and the
        /// slot's own original file must still be present and untouched
        /// (this refusal happens before the per-slot rename loop even
        /// starts, since first creation renames the SHARED index, not any
        /// per-slot file, at this step).
        #[test]
        #[cfg(unix)]
        fn chmod_failure_on_first_creation_rename_self_heals() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
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

            // #3 in this scenario's call sequence — see the sibling test
            // above for the full numbering.
            codex_sqlite::set_test_force_chmod_failure_at_call(3);
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
            codex_sqlite::clear_test_force_chmod_failure();

            let err = result.unwrap_err();
            // Nothing was merged into any shared index (the rename was
            // undone), so this is the plain chmod error, not the
            // "shared index was merged into" wrapper.
            assert!(
                !matches!(err, ShareError::SqliteSharedCommittedSlotsUnlinked { .. }),
                "{err:?}"
            );
            assert!(
                !shared_dir.join("state_5.sqlite").exists(),
                "the shared index must not exist: the rename that would have created it was \
                 undone"
            );
            let p = home11.join("state_5.sqlite");
            assert!(
                p.symlink_metadata().unwrap().file_type().is_file(),
                "the slot's own original must be untouched by this attempt"
            );
            assert_eq!(fs::read(&p).unwrap(), original_bytes);
        }

        /// L3: a primary-key column whose name contains `|` is read intact
        /// (the old `|`-split of `PRAGMA table_info` could not), and an
        /// implicit FK target whose key is spelled `ID` still counts as `id`.
        #[test]
        fn primary_key_column_is_read_exactly_and_id_matches_case_insensitively() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let db = t.path().join("a.sqlite");
            sh(
                &bin,
                &db,
                "CREATE TABLE weird (\"A|b\" TEXT PRIMARY KEY);\n\
                 CREATE TABLE projects (\"ID\" TEXT PRIMARY KEY);\n\
                 CREATE TABLE threads (id TEXT PRIMARY KEY, \
                   project_id TEXT REFERENCES projects);",
            );
            assert_eq!(
                codex_sqlite::table_primary_key_column(&bin, &db, "weird").unwrap(),
                Some("A|b".to_string())
            );
            let targets = codex_sqlite::threads_repairable_fk_targets(&bin, &db).unwrap();
            assert_eq!(
                targets,
                vec![("project_id".to_string(), "projects".to_string())]
            );
        }

        /// A migration whose CHECKSUM changed (same row count, same
        /// versions) in the re-verify→merge window must be refused: the
        /// guard compares the row SET, not just the count.
        #[test]
        fn shared_migration_checksum_changed_between_reverify_and_merge_is_refused() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, before, after, backups) = apply_with_shared_changed_before_merge(
                "UPDATE _sqlx_migrations SET checksum = x'FFFFFFFF' WHERE version = 1;",
                &[],
            );
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );
            assert_eq!(before, after);
            assert_eq!(backups, 0);
        }

        /// An expectation holding a character the guard script will not
        /// embed gets its own precise refusal, not "changed during merge".
        #[test]
        fn unembeddable_guard_value_is_refused_precisely() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let db = t.path().join("d.sqlite");
            sh(&bin, &db, "CREATE TABLE threads (id TEXT PRIMARY KEY);");
            let sig: Option<String> = None;
            let err = codex_sqlite::merge_sources_into_guarded(
                &bin,
                "state_5.sqlite",
                &db,
                &[],
                &[],
                Some(&codex_sqlite::DestExpectation {
                    migrations_sig: &sig,
                    threads_schema: "0|id'; DROP TABLE threads; --|x",
                    schema_objects: &[],
                }),
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteGuardValueUnsafe { .. }),
                "{err:?}"
            );
            assert_eq!(row_count(&bin, &db, "threads"), 0);
        }

        /// Only a failure that means "this filesystem cannot hard-link" is
        /// reported as such; EPERM counts only when a plain permission
        /// problem is ruled out (source and destination directory writable).
        #[test]
        fn hard_link_unsupported_classifier() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let src = t.path().join("s");
            fs::write(&src, b"x").unwrap();
            let dst = t.path().join("d");
            let f = |e: io::Error| codex_sqlite::is_hard_link_unsupported(&e, &src, &dst);
            assert!(f(io::Error::from(io::ErrorKind::Unsupported)));
            assert!(!f(io::Error::from(io::ErrorKind::AlreadyExists)));
            assert!(!f(io::Error::from(io::ErrorKind::PermissionDenied)));
            #[cfg(unix)]
            {
                assert!(f(io::Error::from_raw_os_error(libc::EPERM)));
                // source missing => not writable by us => a permission
                // problem is NOT ruled out => plain Io, not "unsupported".
                let missing = t.path().join("nope");
                assert!(!codex_sqlite::is_hard_link_unsupported(
                    &io::Error::from_raw_os_error(libc::EPERM),
                    &missing,
                    &dst
                ));
            }
        }

        /// First creation of the shared DB with a stray `-wal` already beside
        /// the (absent) shared path: refused with the actionable stray-file
        /// error, nothing moved.
        #[test]
        fn stray_shared_sidecar_is_refused_with_an_actionable_error() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
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
            fs::write(shared_dir.join("state_5.sqlite-wal"), b"stray").unwrap();
            let err = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                crate::session::isolation::create_symlink_pub,
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteStraySidecar { .. }),
                "{err:?}"
            );
            assert!(err.to_string().contains("Move it aside"), "{err}");
            assert!(home11
                .join("state_5.sqlite")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_file());
        }

        /// Stranded-backup recovery in the CLEAN case (slot path and its
        /// sidecars all absent): the backup and its sidecars come back as a set.
        #[test]
        fn clean_stranded_backup_is_recovered_as_a_set() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let p = t.path().join("state_5.sqlite");
            let backup = t.path().join("state_5.sqlite.pre-share-1000");
            fs::write(&backup, b"main").unwrap();
            fs::write(format!("{}-wal", backup.display()), b"wal").unwrap();
            codex_sqlite::recover_stranded_backup(&backup, &p).unwrap();
            assert_eq!(fs::read(&p).unwrap(), b"main");
            assert_eq!(fs::read(format!("{}-wal", p.display())).unwrap(), b"wal");
            assert!(!backup.exists());
        }

        /// ANY stray at the slot (here a `-wal`, then a lone `-shm`) refuses
        /// with one error listing the actual files on both sides and the
        /// manual commands; nothing is touched.
        #[test]
        fn any_stray_at_the_slot_blocks_recovery_and_lists_every_file() {
            hold_test_migration_lock!();
            for stray_sfx in ["-wal", "-shm"] {
                let t = TempDir::new().unwrap();
                let p = t.path().join("state_5.sqlite");
                let backup = t.path().join("state_5.sqlite.pre-share-1000");
                fs::write(&backup, b"main").unwrap();
                fs::write(format!("{}-wal", backup.display()), b"backup wal").unwrap();
                let stray = PathBuf::from(format!("{}{stray_sfx}", p.display()));
                fs::write(&stray, b"stray").unwrap();
                let err = codex_sqlite::recover_stranded_backup(&backup, &p).unwrap_err();
                assert!(
                    matches!(
                        err,
                        ShareError::SqliteStrandedBackupNeedsManualRecovery { .. }
                    ),
                    "{err:?}"
                );
                let msg = err.to_string();
                assert!(msg.contains(&format!("state_5.sqlite{stray_sfx}")), "{msg}");
                assert!(msg.contains("state_5.sqlite.pre-share-1000"), "{msg}");
                assert!(msg.contains("pre-share-1000-wal"), "{msg}");
                // POSIX hosts get shell commands; elsewhere the same moves are
                // described in words (manual_recovery_commands' non-unix branch).
                #[cfg(unix)]
                assert!(msg.contains("mv "), "{msg}");
                #[cfg(not(unix))]
                assert!(msg.contains("move ") && !msg.contains("mv "), "{msg}");
                assert!(msg.contains("KEEP"), "{msg}");
                assert_eq!(fs::read(&backup).unwrap(), b"main");
                assert!(!p.exists());
                assert_eq!(fs::read(&stray).unwrap(), b"stray");
                assert_eq!(
                    fs::read(format!("{}-wal", backup.display())).unwrap(),
                    b"backup wal"
                );
            }
        }

        /// A file appearing at the backup path after the pre-check refuses
        /// the move with NOTHING moved: the slot's real database is
        /// byte-identical afterwards, a foreign file and a stray `-wal` at
        /// the backup path are never moved onto the slot, and the rollback
        /// has nothing to restore (so reports nothing).
        #[test]
        fn refused_forward_move_never_touches_the_slot() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
            );
            let original = fs::read(home11.join("state_5.sqlite")).unwrap();
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
            let planted: std::rc::Rc<std::cell::RefCell<Option<PathBuf>>> = Default::default();
            let p2 = planted.clone();
            codex_sqlite::set_test_before_forward_rename_hook(move |dst| {
                if dst.to_string_lossy().contains(".pre-share-") {
                    fs::write(dst, b"foreign").unwrap();
                    fs::write(format!("{}-wal", dst.display()), b"stray wal").unwrap();
                    *p2.borrow_mut() = Some(dst.to_path_buf());
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
            codex_sqlite::clear_test_before_forward_rename_hook();
            let err = result.unwrap_err();
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, cause, .. } = &err else {
                panic!("{err:?}");
            };
            assert!(matches!(**cause, ShareError::Io { .. }), "{cause:?}");
            assert!(!note.contains("check them by hand"), "{note}");
            assert_eq!(fs::read(home11.join("state_5.sqlite")).unwrap(), original);
            assert!(!home11.join("state_5.sqlite-wal").exists());
            let backup = planted.borrow().clone().unwrap();
            assert_eq!(fs::read(&backup).unwrap(), b"foreign");
            assert_eq!(
                fs::read(format!("{}-wal", backup.display())).unwrap(),
                b"stray wal"
            );
        }

        /// The restore never replaces anything at the original path: a
        /// regular file that appeared there (here, written by the failing link
        /// step) survives, the real database stays at the backup, and the
        /// slot is named for manual attention.
        #[test]
        fn restore_never_replaces_a_file_at_the_original_path() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
            );
            let original = fs::read(home11.join("state_5.sqlite")).unwrap();
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
            let result = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                |_src: &Path, dst: &Path| {
                    fs::write(dst, b"foreign").unwrap();
                    Err(io::Error::other("injected link failure"))
                },
            );
            let err = result.unwrap_err();
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert!(note.contains("check them by hand"), "{note}");
            assert_eq!(fs::read(home11.join("state_5.sqlite")).unwrap(), b"foreign");
            let backups: Vec<_> = fs::read_dir(&home11)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".pre-share-"))
                .collect();
            assert_eq!(backups.len(), 1);
            assert_eq!(fs::read(backups[0].path()).unwrap(), original);
        }

        /// One slot with a forward move that succeeds (optionally with a
        /// `-wal`) and a link step run by `create`; the restore's main move
        /// fails when `fail_restore` is set. Returns the error, the slot's
        /// home, the shared index path and the temp dir.
        #[cfg(unix)]
        fn one_slot_link_step_fails(
            create: impl FnMut(&Path, &Path) -> io::Result<()>,
            with_wal: bool,
            fail_restore: bool,
        ) -> (ShareError, PathBuf, PathBuf, TempDir) {
            let bin = require_sqlite3().expect("sqlite3 required");
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
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
            if with_wal {
                codex_sqlite::set_test_after_main_move_hook(|dst| {
                    let d = dst.to_string_lossy().to_string();
                    if let Some((o, _)) = d.split_once(".pre-share-") {
                        fs::write(format!("{o}-wal"), b"wal").unwrap();
                    }
                });
            }
            codex_sqlite::set_test_fail_restore_rename(fail_restore);
            let result = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                create,
            );
            codex_sqlite::set_test_fail_restore_rename(false);
            codex_sqlite::clear_test_after_main_move_hook();
            (
                result.unwrap_err(),
                home11,
                shared_dir.join("state_5.sqlite"),
                t,
            )
        }

        #[cfg(unix)]
        fn only_backup(home: &Path) -> PathBuf {
            fs::read_dir(home)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .find(|p| {
                    let n = p.file_name().unwrap().to_string_lossy().to_string();
                    n.contains(".pre-share-") && !n.ends_with("-wal") && !n.ends_with("-shm")
                })
                .expect("a backup")
        }

        /// The main restore fails while the record holds the main file AND
        /// its `-wal`: the `-wal` must stay beside the backup's main file,
        /// nothing may appear at the original `-wal`, and both are named.
        #[test]
        #[cfg(unix)]
        fn sidecars_are_not_restored_when_the_main_file_is_not() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, home, _shared, _t) = one_slot_link_step_fails(
                |_s: &Path, _d: &Path| Err(io::Error::other("injected link failure")),
                true,
                true,
            );
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            let backup = only_backup(&home);
            assert_eq!(
                fs::read(format!("{}-wal", backup.display())).unwrap(),
                b"wal"
            );
            assert!(!home.join("state_5.sqlite-wal").exists());
            assert!(note.contains("state_5.sqlite (from"), "{note}");
            assert!(note.contains("-wal (left beside the backup"), "{note}");
        }

        /// A symlink at the original path that does NOT point at the shared
        /// index is left alone and named; the backup stays put.
        #[test]
        #[cfg(unix)]
        fn a_foreign_symlink_at_the_original_path_survives_the_restore() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, home, _shared, t) = one_slot_link_step_fails(
                |_shared: &Path, link: &Path| {
                    std::os::unix::fs::symlink("/nonexistent-elsewhere", link)?;
                    Err(io::Error::other("injected link failure"))
                },
                false,
                false,
            );
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            let _ = &t;
            assert_eq!(
                fs::read_link(home.join("state_5.sqlite")).unwrap(),
                PathBuf::from("/nonexistent-elsewhere")
            );
            assert!(
                note.contains("does not point at the shared index"),
                "{note}"
            );
            assert!(only_backup(&home).exists());
        }

        /// The restore removes our own link, the main move then fails: the
        /// link is put back so the account keeps it, and the slot is named.
        #[test]
        #[cfg(unix)]
        fn a_failed_restore_puts_the_link_back() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, home, shared, _t) = one_slot_link_step_fails(
                |target: &Path, link: &Path| {
                    crate::session::isolation::create_symlink_pub(target, link)?;
                    Err(io::Error::other("injected verify failure"))
                },
                false,
                true,
            );
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert_eq!(fs::read_link(home.join("state_5.sqlite")).unwrap(), shared);
            assert!(
                note.contains("link to the shared index was put back"),
                "{note}"
            );
            assert!(note.contains("check them by hand"), "{note}");
        }

        /// A clean recovery whose SECOND sidecar move fails leaves the slot
        /// with no main file and no sidecar, and the backup set intact.
        #[test]
        fn failed_sidecar_move_in_recovery_leaves_no_main_file_at_the_slot() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let p = t.path().join("state_5.sqlite");
            let backup = t.path().join("state_5.sqlite.pre-share-1000");
            fs::write(&backup, b"main").unwrap();
            fs::write(format!("{}-wal", backup.display()), b"wal").unwrap();
            fs::write(format!("{}-shm", backup.display()), b"shm").unwrap();
            codex_sqlite::set_test_recovery_fail_at(&[2]);
            let result = codex_sqlite::recover_stranded_backup(&backup, &p);
            codex_sqlite::set_test_recovery_fail_at(&[]);
            assert!(result.is_err());
            assert!(!p.exists(), "no main file at the slot");
            assert!(!PathBuf::from(format!("{}-wal", p.display())).exists());
            assert!(!PathBuf::from(format!("{}-shm", p.display())).exists());
            assert_eq!(fs::read(&backup).unwrap(), b"main");
            assert_eq!(
                fs::read(format!("{}-wal", backup.display())).unwrap(),
                b"wal"
            );
            assert_eq!(
                fs::read(format!("{}-shm", backup.display())).unwrap(),
                b"shm"
            );
        }

        /// The second sidecar move fails AND the undo of the first fails: the
        /// error must name the sidecar left at the slot (both paths).
        #[test]
        fn failed_undo_in_recovery_names_the_sidecar_left_at_the_slot() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let p = t.path().join("state_5.sqlite");
            let backup = t.path().join("state_5.sqlite.pre-share-1000");
            fs::write(&backup, b"main").unwrap();
            fs::write(format!("{}-wal", backup.display()), b"wal").unwrap();
            fs::write(format!("{}-shm", backup.display()), b"shm").unwrap();
            // calls: 1 = -wal ok, 2 = -shm fails, 3 = undo of -wal fails
            codex_sqlite::set_test_recovery_fail_at(&[2, 3]);
            let result = codex_sqlite::recover_stranded_backup(&backup, &p);
            codex_sqlite::set_test_recovery_fail_at(&[]);
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("ALSO could not move back"), "{msg}");
            assert!(msg.contains("state_5.sqlite-wal (from"), "{msg}");
            assert!(msg.contains("pre-share-1000-wal"), "{msg}");
            assert_eq!(fs::read(format!("{}-wal", p.display())).unwrap(), b"wal");
            assert!(!p.exists());
        }

        /// The non-UTF-8 sentence redacts the home directory like every other
        /// operator-facing path.
        #[test]
        #[cfg(unix)]
        fn non_utf8_sentence_redacts_the_home_directory() {
            hold_test_migration_lock!();
            use std::os::unix::ffi::OsStrExt;
            let _g = crate::platform::test_env::lock();
            let home = TempDir::new().unwrap();
            let prior = std::env::var_os("HOME");
            std::env::set_var("HOME", home.path());
            let mut bytes = home.path().as_os_str().as_bytes().to_vec();
            bytes.extend_from_slice(b"/x\xff/state.pre-share-1");
            let bad = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes));
            let slot = home.path().join("state_5.sqlite");
            let text = codex_sqlite::manual_recovery_commands(&slot, &[(bad, slot.clone())]);
            match prior {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            assert!(text.contains("~/"), "{text}");
            assert!(
                !text.contains(&home.path().display().to_string()),
                "raw home leaked: {text}"
            );
        }

        /// A host that cannot make a symlink is refused BEFORE any backup,
        /// merge or move: no shared index, no `.pre-share` backup, and the
        /// slot's database is untouched.
        #[test]
        fn symlink_incapable_host_is_refused_before_anything_is_written() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
            );
            let original = fs::read(home11.join("state_5.sqlite")).unwrap();
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
            codex_sqlite::set_test_force_probe_failure(true);
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
            codex_sqlite::set_test_force_probe_failure(false);
            assert!(matches!(result, Err(ShareError::Io { .. })), "{result:?}");
            assert!(!shared_dir.join("state_5.sqlite").exists());
            assert!(!shared_dir.join("state_5.sqlite.new-share").exists());
            assert_eq!(fs::read(home11.join("state_5.sqlite")).unwrap(), original);
            let names: Vec<String> = fs::read_dir(&home11)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            assert!(
                names.iter().all(|n| !n.contains(".pre-share-")),
                "{names:?}"
            );
        }

        /// `create_real_symlink` refuses an existing path — a regular file or
        /// an existing symlink — with `AlreadyExists`, leaving it untouched.
        #[test]
        fn create_real_symlink_refuses_an_existing_path() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let target = t.path().join("target-absent");

            let file = t.path().join("a-file");
            fs::write(&file, b"keep").unwrap();
            let err = codex_sqlite::create_real_symlink(&target, &file).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err:?}");
            assert_eq!(fs::read(&file).unwrap(), b"keep");

            let link = t.path().join("a-link");
            if codex_sqlite::create_real_symlink(&t.path().join("first"), &link).is_err() {
                // No symlink permission on this host (Windows without
                // Developer Mode): the file case above is all that can run.
                return;
            }
            let err = codex_sqlite::create_real_symlink(&target, &link).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err:?}");
            assert_eq!(fs::read_link(&link).unwrap(), t.path().join("first"));
        }

        /// A verbatim prefix on either side does not hide our own link.
        #[test]
        fn normalize_verbatim_strips_the_prefix_forms() {
            hold_test_migration_lock!();
            assert_eq!(codex_sqlite::normalize_verbatim(r"\\?\C:\a\b"), r"C:\a\b");
            assert_eq!(
                codex_sqlite::normalize_verbatim(r"\\?\UNC\srv\share\b"),
                r"\\srv\share\b"
            );
            assert_eq!(codex_sqlite::normalize_verbatim(r"C:\a\b"), r"C:\a\b");
            assert_eq!(codex_sqlite::normalize_verbatim("/usr/x"), "/usr/x");
            assert!(!codex_sqlite::same_link_target(
                Path::new(r"C:\a\b"),
                Path::new(r"C:\a\c")
            ));
            // Off Windows a `\\?\`-prefixed target is a different name: exact match only.
            #[cfg(unix)]
            assert!(!codex_sqlite::same_link_target(
                Path::new(r"\\?\C:\a\b"),
                Path::new(r"C:\a\b")
            ));
            assert!(codex_sqlite::same_link_target(
                Path::new("/a/b"),
                Path::new("/a/b")
            ));
            // On Windows `read_link` can report our own link's target in
            // verbatim form; it must still match.
            #[cfg(windows)]
            {
                assert!(codex_sqlite::same_link_target(
                    Path::new(r"\\?\C:\a\b"),
                    Path::new(r"C:\a\b")
                ));
                assert!(codex_sqlite::same_link_target(
                    Path::new(r"\\?\UNC\srv\share\b"),
                    Path::new(r"\\srv\share\b")
                ));
            }
        }

        /// A probe symlink left behind by a killed run is reused, never
        /// accumulated; a non-symlink at the probe name is refused untouched.
        #[test]
        #[cfg(unix)]
        fn stale_probe_link_is_reused_and_a_foreign_entry_is_refused() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let dir = t.path().join("shared");
            fs::create_dir_all(&dir).unwrap();
            let probe = dir.join(".csq-symlink-probe");
            std::os::unix::fs::symlink(dir.join(".csq-symlink-probe-target-absent"), &probe)
                .unwrap();
            codex_sqlite::probe_symlink_capability(&dir).unwrap();
            assert!(
                fs::symlink_metadata(&probe).is_err(),
                "stale probe link removed"
            );
            assert_eq!(
                fs::read_dir(&dir).unwrap().count(),
                0,
                "nothing accumulates"
            );

            fs::write(&probe, b"not ours").unwrap();
            assert!(codex_sqlite::probe_symlink_capability(&dir).is_err());
            assert_eq!(fs::read(&probe).unwrap(), b"not ours");

            // A symlink of that name pointing anywhere else is not ours either.
            fs::remove_file(&probe).unwrap();
            std::os::unix::fs::symlink(dir.join("elsewhere"), &probe).unwrap();
            assert!(codex_sqlite::probe_symlink_capability(&dir).is_err());
            assert_eq!(fs::read_link(&probe).unwrap(), dir.join("elsewhere"));
        }

        /// A path that is not valid UTF-8 cannot become a command: the text
        /// says so and points at `ls`, with no `mv`.
        #[test]
        #[cfg(unix)]
        fn non_utf8_path_gets_a_sentence_not_a_wrong_command() {
            hold_test_migration_lock!();
            use std::os::unix::ffi::OsStrExt;
            let bad = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/x\xff/state.pre-share-1"));
            let slot = PathBuf::from("/tmp/x/state_5.sqlite");
            let text = codex_sqlite::manual_recovery_commands(&slot, &[(bad, slot.clone())]);
            assert!(text.contains("not valid UTF-8"), "{text}");
            assert!(text.contains("`ls`"), "{text}");
            assert!(!text.contains("mv "), "{text}");
        }

        /// The restore's link re-creation REFUSES an existing path: a file
        /// that appears where the link was removed is left untouched and the
        /// slot is named.
        #[test]
        #[cfg(unix)]
        fn link_recreation_never_replaces_a_file_that_appeared() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            codex_sqlite::set_test_after_link_removed_hook(|original| {
                fs::write(original, b"planted").unwrap();
            });
            let (err, home, _shared, _t) = one_slot_link_step_fails(
                |target: &Path, link: &Path| {
                    crate::session::isolation::create_symlink_pub(target, link)?;
                    Err(io::Error::other("injected verify failure"))
                },
                false,
                false,
            );
            codex_sqlite::clear_test_after_link_removed_hook();
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert_eq!(fs::read(home.join("state_5.sqlite")).unwrap(), b"planted");
            assert!(note.contains("putting its link back ALSO failed"), "{note}");
            assert!(note.contains("check them by hand"), "{note}");
        }

        /// The manual-recovery commands survive a path with `$`, a backtick and
        /// `'`: run through `sh -c` against a temp HOME they move exactly the
        /// intended files and nothing else appears.
        #[test]
        #[cfg(unix)]
        fn manual_recovery_commands_survive_hostile_paths_in_a_real_shell() {
            hold_test_migration_lock!();
            let _g = crate::platform::test_env::lock();
            let home = TempDir::new().unwrap();
            let restore_home = HomeRestore(std::env::var_os("HOME"));
            std::env::set_var("HOME", home.path());
            let dir = home.path().join(".claude").join("a$b`c'd $(touch pwned)");
            fs::create_dir_all(&dir).unwrap();
            let p = dir.join("state_5.sqlite");
            let backup = dir.join("state_5.sqlite.pre-share-1000");
            fs::write(&backup, b"main").unwrap();
            fs::write(format!("{}-wal", backup.display()), b"wal").unwrap();
            let stray = PathBuf::from(format!("{}-wal", p.display()));
            fs::write(&stray, b"stray").unwrap();
            let err = codex_sqlite::recover_stranded_backup(&backup, &p).unwrap_err();
            let ShareError::SqliteStrandedBackupNeedsManualRecovery { commands, .. } = &err else {
                panic!("{err:?}");
            };
            let run = |cmd: &str| {
                std::process::Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .env_clear()
                    .env("HOME", home.path())
                    .env("PATH", "/usr/bin:/bin")
                    .status()
                    .unwrap()
            };
            // With the stray still there the command must fail and move nothing.
            assert!(!run(commands).success(), "{commands}");
            assert_eq!(fs::read(&backup).unwrap(), b"main");
            assert_eq!(fs::read(&stray).unwrap(), b"stray");
            assert!(!p.exists());
            // A DANGLING symlink at the slot path: `-e` alone would pass.
            fs::remove_file(&stray).unwrap();
            std::os::unix::fs::symlink("/nonexistent-dangling", &p).unwrap();
            assert!(!run(commands).success(), "{commands}");
            assert_eq!(fs::read(&backup).unwrap(), b"main");
            assert_eq!(
                fs::read(format!("{}-wal", backup.display())).unwrap(),
                b"wal",
                "nothing may have been moved"
            );
            fs::remove_file(&p).unwrap();
            // "Once the slot files are cleared":
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(commands)
                .env_clear()
                .env("HOME", home.path())
                .env("PATH", "/usr/bin:/bin")
                .status()
                .unwrap();
            drop(restore_home);
            assert!(status.success(), "{commands}");
            assert_eq!(fs::read(&p).unwrap(), b"main");
            assert_eq!(fs::read(format!("{}-wal", p.display())).unwrap(), b"wal");
            let mut names: Vec<String> = fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            names.sort();
            assert_eq!(
                names,
                ["state_5.sqlite", "state_5.sqlite-wal"],
                "{commands}"
            );
        }

        /// A creator of `dst` that slips in AFTER the pre-check is still
        /// refused by the no-replace rename, and its file is untouched.
        #[test]
        fn dst_created_after_the_precheck_is_not_replaced() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let src = t.path().join("a.sqlite");
            let dst = t.path().join("b.sqlite.pre-share-1");
            fs::write(&src, b"new").unwrap();
            codex_sqlite::set_test_before_forward_rename_hook(|dst| {
                fs::write(dst, b"racer").unwrap();
            });
            let result = codex_sqlite::rename_db_with_sidecars(&src, &dst);
            codex_sqlite::clear_test_before_forward_rename_hook();
            assert!(result.is_err());
            assert_eq!(fs::read(&dst).unwrap(), b"racer");
            assert_eq!(fs::read(&src).unwrap(), b"new");
        }

        /// The backup-name search is bounded.
        #[test]
        fn fresh_pre_share_path_gives_up_after_the_limit() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let orig = t.path().join("state_5.sqlite");
            for e in 100..103 {
                fs::write(format!("{}.pre-share-{e}", orig.display()), b"x").unwrap();
            }
            assert!(codex_sqlite::fresh_pre_share_path_with_limit(&orig, 100, 3).is_err());
            assert!(codex_sqlite::fresh_pre_share_path_with_limit(&orig, 100, 4).is_ok());
        }

        /// The per-slot forward move fails (chmod) and the undo moves the
        /// main file home but cannot bring the `-wal` back: the slot's `-wal`
        /// is stranded at `<backup>-wal`, and the restore check must NAME it.
        #[test]
        #[cfg(unix)]
        fn stranded_wal_after_a_failed_forward_move_is_named() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
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
            let orig_of = |dst: &Path| {
                let d = dst.to_string_lossy().to_string();
                d.split(".pre-share-")
                    .next()
                    .map(str::to_string)
                    .filter(|_| d.contains(".pre-share-"))
            };
            codex_sqlite::set_test_after_main_move_hook(move |dst| {
                if let Some(o) = orig_of(dst) {
                    fs::write(format!("{o}-wal"), b"wal").unwrap();
                }
            });
            codex_sqlite::set_test_before_secure_hook(move |src, dst| {
                if dst.to_string_lossy().contains(".pre-share-") {
                    // The -wal has moved to dst; make src's -wal slot an
                    // un-replaceable non-empty directory so moving it back fails.
                    let blocker = PathBuf::from(format!("{}-wal", src.display()));
                    fs::create_dir(&blocker).unwrap();
                    fs::write(blocker.join("x"), b"x").unwrap();
                }
            });
            codex_sqlite::set_test_force_chmod_failure_at_call(4);
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
            codex_sqlite::clear_test_force_chmod_failure();
            codex_sqlite::clear_test_before_secure_hook();
            codex_sqlite::clear_test_after_main_move_hook();
            let err = result.unwrap_err();
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert!(note.contains("-wal"), "{note}");
            assert!(
                note.contains("check them by hand") || note.contains("check by hand"),
                "{note}"
            );
        }

        /// Verbatim-path conversion for long Windows paths, measured in
        /// UTF-16 units from the original units.
        #[test]
        fn verbatim_wide_handles_drive_unc_nonbmp_and_refusals() {
            hold_test_migration_lock!();
            let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
            let long = "a".repeat(300);
            assert_eq!(codex_sqlite::verbatim_wide(&w(r"C:\short")), None);
            assert_eq!(
                codex_sqlite::verbatim_wide(&w(&format!(r"C:\{long}"))),
                Some(w(&format!(r"\\?\C:\{long}")))
            );
            assert_eq!(
                codex_sqlite::verbatim_wide(&w(&format!(r"\\srv\share\{long}"))),
                Some(w(&format!(r"\\?\UNC\srv\share\{long}")))
            );
            // 130 non-BMP chars are 260 UTF-16 units: over the limit even
            // though they are only 130 chars.
            let astral = "\u{1D11E}".repeat(130);
            assert_eq!(
                codex_sqlite::verbatim_wide(&w(&format!(r"C:\{astral}"))),
                Some(w(&format!(r"\\?\C:\{astral}")))
            );
            for bad in [
                format!(r"C:\x\..\{long}"),
                format!(r"\\?\C:\{long}"),
                format!(r"C:\x\\{long}"),
                format!(r"C:\x.\{long}"),
                format!(r"C:\x \{long}"),
                format!("C:/x/{long}"),
            ] {
                assert_eq!(codex_sqlite::verbatim_wide(&w(&bad)), None, "{bad}");
            }
        }

        /// Shared setup for the forward-move-failure tests: one slot, first
        /// creation, the per-slot forward move's chmod (call 4) fails.
        #[cfg(unix)]
        fn one_slot_forward_chmod_failure(
            before_secure: impl FnMut(&Path, &Path) + 'static,
            before_rollback: impl FnMut() + 'static,
            with_wal: bool,
        ) -> (ShareError, PathBuf, TempDir) {
            let bin = require_sqlite3().expect("sqlite3 required");
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
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
            if with_wal {
                codex_sqlite::set_test_after_main_move_hook(|dst| {
                    let d = dst.to_string_lossy().to_string();
                    if let Some((o, _)) = d.split_once(".pre-share-") {
                        fs::write(format!("{o}-wal"), b"wal").unwrap();
                    }
                });
            }
            codex_sqlite::set_test_before_secure_hook(before_secure);
            codex_sqlite::set_test_before_rollback_hook(before_rollback);
            codex_sqlite::set_test_force_chmod_failure_at_call(4);
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
            codex_sqlite::clear_test_force_chmod_failure();
            codex_sqlite::clear_test_before_secure_hook();
            codex_sqlite::clear_test_before_rollback_hook();
            codex_sqlite::clear_test_after_main_move_hook();
            (result.unwrap_err(), home11, t)
        }

        /// The main rename succeeds, the chmod fails, the main-file undo
        /// FAILS (the slot path is now a non-empty directory) and there are
        /// no sidecars: the slot must still be listed as not restored.
        #[test]
        #[cfg(unix)]
        fn failed_main_undo_without_sidecars_is_named_not_dropped() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, _home, _t) = one_slot_forward_chmod_failure(
                |src, dst| {
                    if dst.to_string_lossy().contains(".pre-share-") {
                        fs::create_dir(src).unwrap();
                        fs::write(src.join("x"), b"x").unwrap();
                    }
                },
                || {},
                false,
            );
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert!(note.contains("check them by hand"), "{note}");
        }

        /// The obstacle that blocked the `-wal` undo is gone before the
        /// restore runs: the restore sees the main file already home and
        /// brings only the `-wal` back — a regular file, no caveat.
        #[test]
        #[cfg(unix)]
        fn restore_brings_back_only_the_wal_when_the_main_file_is_home() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let blocker_cell: std::rc::Rc<std::cell::RefCell<Option<PathBuf>>> = Default::default();
            let (b1, b2) = (blocker_cell.clone(), blocker_cell.clone());
            let (err, home, _t) = one_slot_forward_chmod_failure(
                move |src, dst| {
                    if dst.to_string_lossy().contains(".pre-share-") {
                        let blocker = PathBuf::from(format!("{}-wal", src.display()));
                        fs::create_dir(&blocker).unwrap();
                        fs::write(blocker.join("x"), b"x").unwrap();
                        *b1.borrow_mut() = Some(blocker);
                    }
                },
                move || {
                    if let Some(b) = b2.borrow().as_ref() {
                        fs::remove_dir_all(b).unwrap();
                    }
                },
                true,
            );
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            let wal = home.join("state_5.sqlite-wal");
            assert!(wal.symlink_metadata().unwrap().file_type().is_file());
            assert_eq!(fs::read(&wal).unwrap(), b"wal");
            assert!(!note.contains("Restored, but"), "{note}");
            assert!(!note.contains("check them by hand"), "{note}");
        }

        // ── restore direction never undoes; failures are checked ─────────

        /// Two slots, first creation of the shared index; the SECOND slot's
        /// link is made to fail, so the first slot (already linked) and the
        /// second (renamed, not linked) are both restored. `chmod_fail_at`
        /// fails that call of `secure_sqlite_paths`. Calls in order: #1/#2
        /// work copies, #3 tmp_shared seed, #4 shared rename, #5/#6 the
        /// per-slot forward renames, #7 the CURRENT entry's restore, #8 the
        /// sibling's restore. Returns the error and each slot's home plus
        /// its original bytes.
        #[cfg(unix)]
        fn two_slot_apply_second_link_fails(
            chmod_fail_at: u32,
        ) -> (ShareError, [(PathBuf, Vec<u8>); 2], TempDir) {
            let bin = require_sqlite3().expect("sqlite3 required");
            let t = TempDir::new().unwrap();
            let base = t.path().to_path_buf();
            let mut homes = Vec::new();
            for (n, id) in [(11u16, "t1"), (14u16, "t2")] {
                let home = slot_home(&base, Surface::Codex, slot_num(n)).unwrap();
                create_codex_state_db(
                    &bin,
                    &home.join("state_5.sqlite"),
                    &[ThreadRow {
                        id,
                        name: "n",
                        updated_at_ms: 1,
                    }],
                    1,
                );
                homes.push((slot_num(n), home));
            }
            let originals = [
                (
                    homes[0].1.join("state_5.sqlite"),
                    fs::read(homes[0].1.join("state_5.sqlite")).unwrap(),
                ),
                (
                    homes[1].1.join("state_5.sqlite"),
                    fs::read(homes[1].1.join("state_5.sqlite")).unwrap(),
                ),
            ];
            let shared_dir = shared_root(&base, Surface::Codex);
            fs::create_dir_all(&shared_dir).unwrap();
            let plan =
                codex_sqlite::plan_one_basename(&bin, &shared_dir, &homes, "state_5.sqlite", false)
                    .unwrap();
            let mut links = 0u32;
            codex_sqlite::set_test_force_chmod_failure_at_call(chmod_fail_at);
            let result = codex_sqlite::apply_basename_plan_with(
                &base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                move |src: &Path, dst: &Path| {
                    links += 1;
                    if links == 2 {
                        Err(io::Error::other("injected link failure"))
                    } else {
                        crate::session::isolation::create_symlink_pub(src, dst)
                    }
                },
            );
            codex_sqlite::clear_test_force_chmod_failure();
            (result.unwrap_err(), originals, t)
        }

        /// H1(a): a sibling was linked, a later entry fails, and the
        /// SIBLING's restore hits a chmod failure. The restore replaced the
        /// sibling's symlink, so it must NOT be undone: the original is a
        /// real file with its content, and the error names the mode problem.
        #[test]
        #[cfg(unix)]
        fn restore_chmod_failure_for_a_linked_sibling_keeps_the_restored_file() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, originals, _t) = two_slot_apply_second_link_fails(8);
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert!(note.contains("owner-only mode"), "{note}");
            for (path, bytes) in &originals {
                assert!(
                    path.symlink_metadata().unwrap().file_type().is_file(),
                    "{path:?} must be a real file"
                );
                assert_eq!(&fs::read(path).unwrap(), bytes);
            }
        }

        /// H1(b): the CURRENT entry's restore (rename done, link failed) hits
        /// a chmod failure: the file stays put, no undo.
        #[test]
        #[cfg(unix)]
        fn restore_chmod_failure_for_the_current_entry_keeps_the_restored_file() {
            hold_test_migration_lock!();
            if require_sqlite3().is_none() {
                return;
            }
            let (err, originals, _t) = two_slot_apply_second_link_fails(7);
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert!(note.contains("owner-only mode"), "{note}");
            for (path, bytes) in &originals {
                assert!(
                    path.symlink_metadata().unwrap().file_type().is_file(),
                    "{path:?} must be a real file"
                );
                assert_eq!(&fs::read(path).unwrap(), bytes);
            }
        }

        /// H2: when the CURRENT entry's restore fails outright (its backup
        /// has vanished), the slot is reported in the note rather than
        /// silently dropped.
        #[test]
        fn failed_current_entry_restore_is_named_in_the_note() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "n",
                    updated_at_ms: 1,
                }],
                1,
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
            codex_sqlite::set_test_after_rename_hook(|backup| {
                fs::remove_file(backup).unwrap();
            });
            let result = codex_sqlite::apply_basename_plan_with(
                base,
                &bin,
                &shared_dir,
                "state_5.sqlite",
                plan,
                false,
                true,
                |_src: &Path, _dst: &Path| Err(io::Error::other("injected link failure")),
            );
            codex_sqlite::clear_test_after_rename_hook();
            let err = result.unwrap_err();
            let ShareError::SqliteSharedCommittedSlotsUnlinked { note, .. } = &err else {
                panic!("{err:?}");
            };
            assert!(note.contains("check them by hand"), "{note}");
        }

        /// A forward move NEVER replaces anything: with `dst`, or only a
        /// sidecar destination, already present it refuses before moving a
        /// byte — the slot is untouched and the old file is byte-identical.
        #[test]
        fn forward_move_refuses_to_replace_an_existing_destination() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            for existing in ["", "-wal", "-shm"] {
                let src = t.path().join(format!("a{existing}.sqlite"));
                let dst = t.path().join(format!("b{existing}.sqlite.pre-share-1"));
                fs::write(&src, b"new").unwrap();
                let pre = PathBuf::from(format!("{}{existing}", dst.display()));
                fs::write(&pre, b"old backup").unwrap();

                let err = codex_sqlite::rename_db_with_sidecars(&src, &dst).unwrap_err();

                if existing.is_empty() {
                    assert!(matches!(err, ShareError::Io { .. }), "{err:?}");
                } else {
                    // A sidecar with no main file is a stray leftover.
                    assert!(
                        matches!(err, ShareError::SqliteStraySidecar { .. }),
                        "{err:?}"
                    );
                }
                assert_eq!(
                    fs::read(&src).unwrap(),
                    b"new",
                    "the slot must be untouched"
                );
                assert_eq!(fs::read(&pre).unwrap(), b"old backup");
                if !existing.is_empty() {
                    assert!(!dst.exists(), "nothing may have moved");
                }
            }
        }

        /// A same-second re-run gets a fresh per-slot backup name (still a
        /// bare all-digit epoch, which stranded-backup recovery parses).
        #[test]
        fn fresh_pre_share_path_skips_taken_names() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let orig = t.path().join("state_5.sqlite");
            fs::write(format!("{}.pre-share-100", orig.display()), b"x").unwrap();
            fs::write(format!("{}.pre-share-101-wal", orig.display()), b"x").unwrap();
            assert_eq!(
                codex_sqlite::fresh_pre_share_path(&orig, 100).unwrap(),
                PathBuf::from(format!("{}.pre-share-102", orig.display()))
            );
        }

        /// A sidecar rename fails AND the main-file undo fails: the sidecar
        /// that already moved stays beside the main file at dst (never moved
        /// away from it), and the error names both failures.
        #[test]
        fn failed_main_undo_leaves_sidecars_beside_it_and_names_both() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let src = t.path().join("a.sqlite");
            let dst = t.path().join("b.sqlite.pre-share-1");
            fs::write(&src, b"main").unwrap();
            fs::write(format!("{}-wal", src.display()), b"wal").unwrap();
            fs::write(format!("{}-shm", src.display()), b"shm").unwrap();
            // After the main move: block dst's -shm (so the -shm rename
            // fails) and remove dst's main file (so moving it back fails).
            codex_sqlite::set_test_after_main_move_hook(|dst| {
                let blocker = PathBuf::from(format!("{}-shm", dst.display()));
                fs::create_dir(&blocker).unwrap();
                fs::write(blocker.join("x"), b"x").unwrap();
                fs::remove_file(dst).unwrap();
            });
            let result = codex_sqlite::rename_db_with_sidecars(&src, &dst);
            codex_sqlite::clear_test_after_main_move_hook();
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("main file"), "{msg}");
            assert!(msg.contains("-wal"), "{msg}");
            assert_eq!(
                fs::read(format!("{}-wal", dst.display())).unwrap(),
                b"wal",
                "the moved -wal must stay beside the main file"
            );
            assert!(!PathBuf::from(format!("{}-wal", src.display())).exists());
        }

        /// A NULL migration checksum and an EMPTY one both hex to '' — the
        /// guard must still tell them apart. The destination holds a NULL
        /// checksum (`V31|N|V31`); the expectation is the signature of a
        /// second DB whose checksum is EMPTY (`V31|V|V31`). Under a hex-only
        /// encoding both sides read `31||31`, the guard passes, and this
        /// test fails.
        #[test]
        fn guard_distinguishes_null_from_empty_migration_checksum() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let ddl = "CREATE TABLE threads (id TEXT PRIMARY KEY);\n\
                       CREATE TABLE _sqlx_migrations \
                       (version BIGINT, checksum BLOB, success BOOLEAN);\n";
            let db = t.path().join("null.sqlite");
            sh(
                &bin,
                &db,
                &format!("{ddl}INSERT INTO _sqlx_migrations VALUES (1, NULL, 1);"),
            );
            let other = t.path().join("empty.sqlite");
            sh(
                &bin,
                &other,
                &format!("{ddl}INSERT INTO _sqlx_migrations VALUES (1, x'', 1);"),
            );
            let sig = codex_sqlite::migrations_signature(&bin, &other).unwrap();
            let schema = codex_sqlite::threads_schema_fingerprint(&bin, &db).unwrap();
            let err = codex_sqlite::merge_sources_into_guarded(
                &bin,
                "state_5.sqlite",
                &db,
                &[],
                &[],
                Some(&codex_sqlite::DestExpectation {
                    migrations_sig: &sig,
                    threads_schema: &schema,
                    schema_objects: &[],
                }),
            )
            .unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteChangedDuringMerge { .. }),
                "{err:?}"
            );
        }

        /// The fingerprint is read through the `-readonly` (`-safe`) path
        /// with `pragma_table_info(...)` as a table-valued function: it
        /// must actually return the columns there.
        #[test]
        fn pragma_table_info_works_on_the_readonly_path() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let db = t.path().join("d.sqlite");
            sh(
                &bin,
                &db,
                "CREATE TABLE threads (id TEXT PRIMARY KEY, name TEXT);",
            );
            let fp = codex_sqlite::threads_schema_fingerprint(&bin, &db).unwrap();
            assert_eq!(fp.lines().count(), 2, "{fp}");
        }

        /// A filesystem that cannot hard-link refuses the backup with its own
        /// error (forced through the link seam), and nothing is left at dst.
        #[test]
        fn backup_hard_link_unsupported_is_refused_precisely() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let src = t.path().join("src.sqlite");
            sh(&bin, &src, "CREATE TABLE t(id INTEGER);");
            let dst = t.path().join("state_5.sqlite.pre-merge-1-1");
            codex_sqlite::set_test_force_hard_link_error(Some(io::ErrorKind::Unsupported));
            let result = codex_sqlite::backup_via_vacuum_into(&bin, "state_5.sqlite", &src, &dst);
            codex_sqlite::set_test_force_hard_link_error(None);
            assert!(
                matches!(
                    result,
                    Err(ShareError::SqliteBackupHardLinkUnsupported { .. })
                ),
                "{result:?}"
            );
            assert!(!dst.exists());
        }

        // ── T2: dead rollout-path repair ──────────────────────────────

        /// A `threads` table with NO `rollout_path` column at all (the shape
        /// every fixture built with this suite's own [`create_state_db`]
        /// has, and the shape a pre-`rollout_path` codex-cli install has on a
        /// real host) must never fail the merge. Falsifying result named up
        /// front: before the `PRAGMA table_info` presence check, this exact
        /// scenario made `share_codex_sqlite_locked` return `Err`
        /// with `SqliteCommandFailed { ... "no such column: rollout_path" }`
        /// — on a database the merge itself had ALREADY committed
        /// successfully.
        #[test]
        fn merge_succeeds_when_threads_has_no_rollout_path_column() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home5 = slot_home(base, Surface::Codex, slot_num(5)).unwrap();
            create_state_db(
                &bin,
                &home5.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "no-rollout-column",
                    updated_at_ms: 1,
                }],
                true,
            );

            let report = codex_sqlite::share_codex_sqlite_locked(base, false, true)
                .expect("a merge must succeed regardless of whether rollout_path exists");
            assert!(
                report
                    .databases
                    .iter()
                    .any(|d| d.basename == "state_5.sqlite"
                        && matches!(d.role, SqliteDbRole::State)
                        && matches!(d.outcome, SqliteDbOutcome::Merged { slots_merged: 1 })),
                "{report:?}"
            );
            assert!(
                home5
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the merge's own effect must still land even though repair had nothing to touch"
            );
        }

        /// `state_N.sqlite` with a `threads.rollout_path` column — the shape
        /// this suite's [`create_state_db`] does not model, since T2's repair
        /// is the only production reader/writer of that column.
        fn create_state_db_with_rollout(bin: &Path, path: &Path, id: &str, rollout_path: &str) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let _ = fs::remove_file(path);
            sh(
                bin,
                path,
                "CREATE TABLE threads (\
                   id TEXT PRIMARY KEY, title TEXT NOT NULL, name TEXT, \
                   updated_at TEXT, updated_at_ms INTEGER, cwd TEXT, model_provider TEXT, \
                   rollout_path TEXT\
                 );",
            );
            let insert = format!(
                "INSERT INTO threads (id, title, name, updated_at, updated_at_ms, cwd, \
                 model_provider, rollout_path) \
                 VALUES ('{id}', 'untitled', 'n', 'ts', 1, '/work', 'anthropic', '{}');",
                rollout_path.replace('\'', "''"),
            );
            sh(bin, path, &insert);
            sh(
                bin,
                path,
                &format!(
                    "{SQLX_MIGRATIONS_DDL}{}",
                    sqlx_migration_rows(1, "2026-01-01 00:00:00")
                ),
            );
        }

        /// Falsifying result named up front: before T2's repair existed,
        /// `rollout_path` would still read the dead `term-<pid>` path after
        /// this merge — `resume` against it would fail even though the exact
        /// same transcript bytes are reachable at the shared-root path this
        /// test creates.
        #[test]
        fn rollout_path_repair_rewrites_a_dead_term_path_when_the_shared_file_exists() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home5 = slot_home(base, Surface::Codex, slot_num(5)).unwrap();

            let dead = base.join("term-55555/sessions/2026/09/29/rollout-abc.jsonl");
            let alive = base.join("shared-state/codex/codex-sessions/2026/09/29/rollout-abc.jsonl");
            fs::create_dir_all(alive.parent().unwrap()).unwrap();
            fs::write(&alive, b"TRANSCRIPT").unwrap();
            assert!(!dead.exists(), "fixture: the dead path must not exist");

            create_state_db_with_rollout(
                &bin,
                &home5.join("state_5.sqlite"),
                "t1",
                &dead.display().to_string(),
            );

            let report = codex_sqlite::share_codex_sqlite_locked(base, false, true).unwrap();
            assert!(
                report
                    .databases
                    .iter()
                    .any(|d| d.basename == "state_5.sqlite"),
                "{report:?}"
            );

            let shared_path = shared_root(base, Surface::Codex).join("state_5.sqlite");
            let repaired = thread_field(&bin, &shared_path, "t1", "rollout_path");
            assert_eq!(
                repaired,
                alive.canonicalize().unwrap().display().to_string(),
                "the dead term-<pid> path must be rewritten to the shared-root equivalent"
            );
        }

        #[cfg(unix)]
        fn r9_path_fixture(case: &str) {
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("real sqlite3 required");
            let t = TempDir::new().unwrap();
            let base = t.path().canonicalize().unwrap();
            let root = base.join("persistent");
            let second = base.join("other-persistent");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&second).unwrap();
            let nested = case == "parent_escape" || case == "candidate_metadata";
            let suffix = if nested {
                "nested/rollout.jsonl"
            } else {
                "rollout.jsonl"
            };
            let dead = base.join("term-123/sessions").join(suffix);
            let db = base.join("state_5.sqlite");
            r9_fixture_sql(&bin, &db, &format!(
                "CREATE TABLE threads(id TEXT PRIMARY KEY, rollout_path TEXT); INSERT INTO threads VALUES('t1','{}');", dead.display()));
            let outside = base.join("outside.jsonl");
            fs::write(&outside, b"outside").unwrap();
            let mut roots = vec![root.clone()];
            match case {
                "metadata" => {
                    fs::write(base.join("term-123"), b"not a directory").unwrap();
                    assert_eq!(
                        dead.symlink_metadata().unwrap_err().kind(),
                        io::ErrorKind::NotADirectory
                    );
                    fs::write(root.join(suffix), b"valid candidate").unwrap();
                }
                "leaf_escape" => std::os::unix::fs::symlink(&outside, root.join(suffix)).unwrap(),
                "parent_escape" => {
                    fs::write(second.join("rollout.jsonl"), b"outside root").unwrap();
                    std::os::unix::fs::symlink(&second, root.join("nested")).unwrap();
                }
                "candidate_metadata" => fs::write(root.join("nested"), b"not a directory").unwrap(),
                "conflicting" => {
                    fs::write(root.join(suffix), b"first transcript").unwrap();
                    fs::write(second.join(suffix), b"different transcript").unwrap();
                    roots.push(second);
                }
                "owned_open_race" => {
                    let candidate = root.join(suffix);
                    fs::write(&candidate, b"admitted transcript").unwrap();
                    codex_sqlite::set_test_repair_before_candidate_open(move || {
                        fs::remove_file(&candidate).unwrap();
                        std::os::unix::fs::symlink(&outside, candidate).unwrap();
                    });
                }
                "root_alias" => {
                    fs::write(root.join(suffix), b"valid transcript").unwrap();
                    let alias = base.join("intentional-root-alias");
                    std::os::unix::fs::symlink(&root, &alias).unwrap();
                    roots.insert(0, alias);
                }
                _ => panic!("unknown path fixture"),
            }
            let before = fs::read(&db).unwrap();
            let result = r9_repair_paths(&base, &db, &roots);
            if case == "root_alias" {
                assert_eq!(result.unwrap(), 1);
                assert_eq!(
                    r9_fixture_sql(&bin, &db, "SELECT rollout_path FROM threads WHERE id='t1';")
                        .trim(),
                    root.join(suffix).to_str().unwrap()
                );
                assert_eq!(r9_repair_paths(&base, &db, &roots).unwrap(), 0);
            } else {
                assert!(result.is_err(), "{case} must refuse: {result:?}");
                assert_eq!(
                    fs::read(&db).unwrap(),
                    before,
                    "{case}: refusal must not write database bytes"
                );
                assert_eq!(
                    r9_fixture_sql(&bin, &db, "SELECT rollout_path FROM threads WHERE id='t1';")
                        .trim(),
                    dead.to_str().unwrap()
                );
            }
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT count(*) FROM threads;").trim(),
                "1"
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9_paths_refuse_recorded_metadata_error() {
            hold_test_migration_lock!();
            r9_path_fixture("metadata");
        }
        #[cfg(unix)]
        #[test]
        fn r9_paths_refuse_leaf_symlink_escape() {
            hold_test_migration_lock!();
            r9_path_fixture("leaf_escape");
        }
        #[cfg(unix)]
        #[test]
        fn r9_paths_refuse_parent_symlink_escape() {
            hold_test_migration_lock!();
            r9_path_fixture("parent_escape");
        }
        #[cfg(unix)]
        #[test]
        fn r9_paths_refuse_candidate_metadata_error() {
            hold_test_migration_lock!();
            r9_path_fixture("candidate_metadata");
        }
        #[cfg(unix)]
        #[test]
        fn r9_paths_refuse_conflicting_real_roots() {
            hold_test_migration_lock!();
            r9_path_fixture("conflicting");
        }
        #[cfg(unix)]
        #[test]
        fn r9_paths_refuse_symlink_swap_at_owned_open() {
            hold_test_migration_lock!();
            r9_path_fixture("owned_open_race");
        }
        #[cfg(unix)]
        #[test]
        fn r9_paths_accept_intentional_root_aliases() {
            hold_test_migration_lock!();
            r9_path_fixture("root_alias");
        }

        #[cfg(unix)]
        #[test]
        fn r9_paths_refuse_database_metadata_error() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let t = TempDir::new().unwrap();
            let blocker = t.path().join("not-a-directory");
            fs::write(&blocker, b"file").unwrap();
            let db = blocker.join("state_5.sqlite");
            assert_eq!(
                db.symlink_metadata().unwrap_err().kind(),
                io::ErrorKind::NotADirectory
            );
            assert!(
                r9_repair_paths(t.path(), &db, &[]).is_err(),
                "unreadable database metadata must not report successful no-op"
            );
        }

        #[cfg(unix)]
        fn r9_disposition_fixture(no_cld_wait: bool, selected: &str) {
            use std::os::unix::fs::PermissionsExt;
            let _env = crate::platform::test_env::lock();
            const MODE: &str = "CSQ_R9_DISPOSITION_FIXTURE";
            if let Some(dir) = std::env::var_os(MODE) {
                let dir = PathBuf::from(dir);
                let bin = dir.join("owned-fixture");
                // The private control child cannot exit on its own between a
                // wait probe and kill: it publishes a canary then waits forever.
                // This avoids deliberately recreating PID reuse on the host.
                fs::write(&bin, format!("#!/usr/bin/python3\nimport time\nopen({:?},'w').write('spawned')\nwhile True: time.sleep(1)\n", dir.join("spawned").to_str().unwrap())).unwrap();
                fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
                struct Restore(libc::sigaction);
                impl Drop for Restore {
                    fn drop(&mut self) {
                        // SAFETY: isolated child restores its own saved policy.
                        unsafe {
                            libc::sigaction(libc::SIGCHLD, &self.0, std::ptr::null_mut());
                        }
                    }
                }
                let mut prior: libc::sigaction = unsafe { std::mem::zeroed() };
                // SAFETY: only the re-executed single-test child changes its own
                // process policy. The parent and other tests remain untouched.
                unsafe {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = if no_cld_wait {
                        libc::SIG_DFL
                    } else {
                        libc::SIG_IGN
                    };
                    action.sa_flags = if no_cld_wait { libc::SA_NOCLDWAIT } else { 0 };
                    libc::sigemptyset(&mut action.sa_mask);
                    assert_eq!(libc::sigaction(libc::SIGCHLD, &action, &mut prior), 0);
                }
                let restore = Restore(prior);
                let result = codex_sqlite::run_repair_sqlite_bounded(
                    &bin,
                    &dir.join("private.sqlite"),
                    "SELECT 1;",
                    false,
                    std::time::Instant::now() + std::time::Duration::from_millis(500),
                );
                drop(restore);
                let refused = matches!(result, Err(ShareError::SqliteCommandFailed { detail, .. })
                    if detail == "rollout repair unsafe SIGCHLD disposition");
                fs::write(
                    dir.join("result"),
                    format!("{refused} {}", dir.join("spawned").exists()),
                )
                .unwrap();
                return;
            }
            let t = TempDir::new().unwrap();
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", selected, "--test-threads=1"])
                .env_clear()
                .env("HOME", t.path())
                .env("CSQ_BASE_DIR", t.path().join("base"))
                .env("PATH", "/usr/bin:/bin")
                .env(MODE, t.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let (status, out, err) =
                r9_bounded_output(child, "isolated SIGCHLD fixture", R9_RUNNER_HANG_GUARD);
            assert!(
                out.len() <= 16384 && err.len() <= 16384 && status.success(),
                "isolated fixture failed: {out}{err}"
            );
            assert_eq!(
                fs::read_to_string(t.path().join("result")).unwrap(),
                "true false",
                "unsafe SIGCHLD must refuse before the actual child executes"
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9_disposition_ignored_refuses_before_spawn() {
            hold_test_migration_lock!();
            r9_disposition_fixture(false, "session::shared_state::tests::codex_sqlite_tests::r9_disposition_ignored_refuses_before_spawn");
        }
        #[cfg(unix)]
        #[test]
        fn r9_disposition_no_cld_wait_refuses_before_spawn() {
            hold_test_migration_lock!();
            r9_disposition_fixture(true, "session::shared_state::tests::codex_sqlite_tests::r9_disposition_no_cld_wait_refuses_before_spawn");
        }

        #[test]
        fn r9_platform_windows_exe_resolution() {
            hold_test_migration_lock!();
            let dir = std::env::temp_dir().join("r9-sqlite-exe");
            let expected = dir.join("sqlite3.exe");
            assert_eq!(
                codex_sqlite::find_executable_in_dirs_for_platform(
                    [PathBuf::new(), PathBuf::from("relative"), dir.clone()].into_iter(),
                    "sqlite3",
                    |p| p == expected,
                    true
                ),
                Some(expected)
            );
            assert_eq!(
                codex_sqlite::find_executable_in_dirs_for_platform(
                    [dir.clone()].into_iter(),
                    "sqlite3",
                    |p| p == dir.join("sqlite3"),
                    false
                ),
                Some(dir.join("sqlite3"))
            );
        }

        #[test]
        fn r9_platform_windows_rollout_separators() {
            hold_test_migration_lock!();
            assert_eq!(
                codex_sqlite::rollout_relative_tail(
                    r"C:\csq",
                    r"C:\csq\term-10\sessions\2026\rollout.jsonl",
                    true
                ),
                Some("2026/rollout.jsonl".into())
            );
            assert_eq!(
                codex_sqlite::rollout_relative_tail(
                    r"C:\csq",
                    r"C:\csq\term-10\sessions\..\escape.jsonl",
                    true
                ),
                None
            );
            assert_eq!(
                codex_sqlite::rollout_relative_tail(
                    "/csq",
                    "/csq/term-10/sessions/2026/rollout.jsonl",
                    false
                ),
                Some("2026/rollout.jsonl".into())
            );
            assert_eq!(
                codex_sqlite::rollout_relative_tail("/csq", "/csq/term-x/sessions/a", false),
                None
            );
            assert_eq!(
                codex_sqlite::rollout_relative_tail("/csq", "/csq/term-1/sessions/./a", false),
                None
            );
        }

        #[test]
        fn r9_platform_positive_known_upstream_schema() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("real sqlite3 required");
            let t = TempDir::new().unwrap();
            let base = t.path().canonicalize().unwrap();
            let root = base.join("codex-sessions");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("rollout.jsonl"), b"fixture").unwrap();
            let db = base.join("state_5.sqlite");
            r9_fixture_sql(&bin, &db, CODEX_THREADS_SCHEMA);
            let schema_before = r9_fixture_sql(
                &bin,
                &db,
                "SELECT hex(sql) FROM sqlite_master WHERE type='trigger' ORDER BY name;",
            );
            assert_eq!(
                schema_before.lines().count(),
                5,
                "fixture must contain all real upstream triggers"
            );
            let dead = base.join("term-123/sessions/rollout.jsonl");
            r9_fixture_sql(&bin, &db, &format!(
                "INSERT INTO threads(id,rollout_path,created_at,updated_at,source,model_provider,cwd,title,sandbox_policy,approval_mode) \
                 VALUES('t1','{}',1,1,'cli','openai','/work','fixture','default','default');", dead.display()));
            assert_eq!(
                r9_repair_paths(&base, &db, std::slice::from_ref(&root)).unwrap(),
                1
            );
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT rollout_path FROM threads WHERE id='t1';").trim(),
                root.join("rollout.jsonl").to_str().unwrap()
            );
            assert_eq!(
                r9_fixture_sql(
                    &bin,
                    &db,
                    "SELECT hex(sql) FROM sqlite_master WHERE type='trigger' ORDER BY name;"
                ),
                schema_before
            );
            assert_eq!(r9_repair_paths(&base, &db, &[root]).unwrap(), 0);
        }

        #[test]
        fn r9_platform_runner_refuses_expired_budget_and_oversized_sql() {
            hold_test_migration_lock!();
            let t = TempDir::new().unwrap();
            let absent = t.path().join("not-a-program");
            let db = t.path().join("private.sqlite");
            let result = codex_sqlite::run_repair_sqlite_bounded(
                &absent,
                &db,
                "SELECT 1;",
                false,
                std::time::Instant::now(),
            );
            assert!(
                matches!(result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail == "rollout repair deadline")
            );
            let result = codex_sqlite::run_repair_sqlite_bounded(
                &absent,
                &db,
                &"x".repeat(60001),
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            );
            assert!(
                matches!(result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail == "rollout repair SQL size limit")
            );
            assert!(!db.exists());
        }

        /// The launch runner never puts SQL in argv: the writer's argv holds
        /// only flags and the database, and the whole script arrives on stdin.
        /// Falsifying result with the former argv transport: the captured argv
        /// carries the `UPDATE` and the captured stdin is empty.
        #[cfg(unix)]
        #[test]
        fn r9_launch_runner_argv_carries_no_sql() {
            hold_test_migration_lock!();
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let bin = r9_native_fixture(t.path(), "argv-capture");
            let db = t.path().join("argv.sqlite");
            let script = "BEGIN IMMEDIATE;\nUPDATE threads SET rollout_path='csq-marker' WHERE rowid=1;\nCOMMIT;";
            let result = codex_sqlite::run_repair_sqlite_bounded(
                &bin,
                &db,
                script,
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            );
            assert!(result.is_ok(), "{result:?}");
            let argv = fs::read_to_string(t.path().join("captured-argv")).unwrap();
            let stdin = fs::read_to_string(t.path().join("captured-stdin")).unwrap();
            for token in ["UPDATE", "csq-marker", "BEGIN", "COMMIT", "PRAGMA"] {
                assert!(!argv.contains(token), "argv carries SQL ({token}): {argv}");
                assert!(stdin.contains(token), "stdin lacks {token}: {stdin}");
            }
            assert!(
                argv.lines()
                    .last()
                    .is_some_and(|last| last.ends_with("argv.sqlite")),
                "the database must be argv's last argument: {argv}"
            );
        }

        #[cfg(unix)]
        fn r9_native_fixture(base: &Path, mode: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            // TempDir permissions follow umask on this Darwin; pin this owned root.
            fs::set_permissions(base, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(base.join("fixture-mode"), mode).unwrap();
            let fixture = base.join("r9-sqlite-fixture");
            std::os::unix::fs::symlink(r9_stub_cli_binary(), &fixture).unwrap();
            // Not sqlite3 (hung, flooding, committing children): declared probed
            // so the runner under test spawns it. `continue` is a sqlite3 that
            // ignores -bail and must go through the real probe.
            if mode != "continue" {
                codex_sqlite::trust_bail_for_test(&fixture);
            }
            fixture
        }

        /// Resolve the `stub-cli` fixture binary beside the test executable,
        /// building it on demand when the active target profile has never seen
        /// an explicit `cargo build`.
        ///
        /// `stub-cli` is declared `test = false` in `csq-core/Cargo.toml`, so NO
        /// `cargo test` invocation builds it: a `cargo test --lib` run against a
        /// fresh target dir holds no binary, and both r9 fixture tests then die
        /// on the availability assert instead of testing the runner (run-1
        /// evidence: "R9 native fixture requires cargo build -p csq-core --bin
        /// stub-cli" from BOTH tests, while the immediately following run that
        /// reused a target dir carrying the binary passed). Build it once per
        /// test process into this very profile instead of depending on prior
        /// build history in a shared target directory.
        #[cfg(unix)]
        fn r9_stub_cli_binary() -> &'static Path {
            static BINARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
            BINARY
                .get_or_init(|| {
                    let executable = std::env::current_exe().unwrap();
                    let executable_dir = executable.parent().unwrap();
                    let profile = if executable_dir
                        .file_name()
                        .is_some_and(|name| name == "deps")
                    {
                        executable_dir.parent().unwrap()
                    } else {
                        executable_dir
                    };
                    let binary = profile.join("stub-cli");
                    // Always ask cargo: an existing binary may predate this
                    // source (the commit-unknown test reads a pid file only the
                    // current stub writes). An up-to-date build is a no-op.
                    let target_dir = profile.parent().expect("cargo target dir above profile");
                    let mut command = std::process::Command::new(
                        std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
                    );
                    command
                        .args(["build", "-p", "csq-core", "--bin", "stub-cli"])
                        .current_dir(crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR")))
                        .env("CARGO_TARGET_DIR", target_dir);
                    match profile.file_name().and_then(|name| name.to_str()) {
                        Some("release") => {
                            command.arg("--release");
                        }
                        Some("debug") | None => {}
                        Some(other) => {
                            command.args(["--profile", other]);
                        }
                    }
                    let output = command
                        .output()
                        .expect("run cargo build for the stub-cli fixture");
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(
                        output.status.success() && binary.is_file(),
                        "R9 native fixture requires cargo build -p csq-core --bin stub-cli \
                         (status {:?}; stderr: {stderr})",
                        output.status,
                    );
                    binary
                })
                .as_path()
        }

        #[cfg(unix)]
        #[test]
        fn r9_platform_runner_bounds_hung_and_flooding_children() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            for mode in ["hung", "stdout", "stderr"] {
                // Only the hung mode can pass VACUOUSLY on a pre-spawn refusal:
                // its expected detail ("deadline") is also what an expired
                // pre-spawn budget returns. The flooding modes expect an output
                // cap, which a pre-spawn refusal cannot produce, so their own
                // assertion already rejects it. The hung mode therefore retries
                // with fresh fixtures and FAILS as NOT EXERCISED when no
                // attempt actually spawned a child (D237 R2 follow-up, rule 6).
                let attempts = if mode == "hung" { 3 } else { 1 };
                let mut exercised = false;
                for attempt in 1..=attempts {
                    let t = tempfile::Builder::new()
                        .prefix("cr-")
                        .tempdir_in("/tmp")
                        .unwrap();
                    let lock = r9_test_lock(t.path());
                    let _held = lock.hold_for_children();
                    let bin = r9_native_fixture(t.path(), mode);
                    // Exercise the same deadline/output caps without executing a
                    // newly written shebang wrapper inside the short test budget.
                    let started = std::time::Instant::now();
                    let mut commit_unknown = false;
                    let result = codex_sqlite::run_repair_sqlite_bounded_tracking(
                        &bin,
                        &t.path().join("private.sqlite"),
                        "SELECT 1;",
                        false,
                        started + std::time::Duration::from_secs(1),
                        &mut commit_unknown,
                    );
                    // The pid comes from the RUNNER's spawn record, not from a
                    // file the child writes: a deadline can kill the child
                    // before its first scheduling, and then `owned-pid` never
                    // exists (the CI `fixture leader pid: NotFound` class).
                    let spawned = codex_sqlite::take_last_spawned_pid();
                    // A child that was spawned and never acknowledged may have
                    // committed: the classification must stay UNKNOWN on every
                    // post-spawn failure (deadline, output caps). With NO spawn
                    // (an expired pre-spawn budget) nothing could have
                    // committed.
                    if spawned.is_some() {
                        assert!(commit_unknown, "{mode}: post-spawn failure must be unknown");
                    } else {
                        assert!(
                            !commit_unknown,
                            "{mode}: a pre-spawn refusal cannot be unknown"
                        );
                    }
                    eprintln!(
                        "native fixture mode={mode} elapsed={:?} result={result:?}",
                        started.elapsed()
                    );
                    let expected = match mode {
                        "hung" => "deadline",
                        "stdout" => "stdout limit",
                        _ => "stderr limit",
                    };
                    assert!(
                        matches!(result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains(expected)),
                        "{mode}"
                    );
                    assert!(started.elapsed() < std::time::Duration::from_secs(2));
                    if let Some(pid) = spawned.map(|pid| pid as i32) {
                        assert!(pid > 1, "refusing to probe implausible fixture pid {pid}");
                        // SAFETY: signal zero only checks the pid the RUNNER
                        // recorded at spawn; it sends no signal. Drop already
                        // reaped the owned child.
                        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
                    }
                    if spawned.is_some() {
                        exercised = true;
                        break;
                    }
                    eprintln!(
                        "r9_platform_runner_bounds_hung_and_flooding_children mode={mode} \
                         attempt {attempt}/{attempts} did NOT exercise a SPAWNED child: \
                         pre-spawn deadline (the runner refused before spawning)"
                    );
                }
                assert!(
                    exercised,
                    "{mode}: spawn NOT EXERCISED in {attempts} attempts"
                );
            }
        }

        /// Hang guard for runner calls and fixture waits whose RESULT must never
        /// depend on host speed. Only a wedged child ever reaches it; a
        /// slow-but-finishing child (a measured slow host: fsync 180-300ms, a bare sqlite3
        /// write 1.1-1.4s) must not flip a classification, because a deadline
        /// that fires after the spawn is by design an UNKNOWN commit.
        const R9_RUNNER_HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(60);

        /// Wait for a fixture child to finish, bounded by a HANG GUARD (never a
        /// speed bound): a wedged child is killed and reds with the fixture's
        /// name instead of hanging the job. Each pipe is drained on its own
        /// thread, so a chatty child cannot block the wait; at most 16385 bytes
        /// of each are kept.
        fn r9_bounded_output(
            mut child: std::process::Child,
            what: &str,
            guard: std::time::Duration,
        ) -> (std::process::ExitStatus, String, String) {
            use std::io::Read;
            fn drain<R: Read + Send + 'static>(mut pipe: R) -> std::thread::JoinHandle<String> {
                std::thread::spawn(move || {
                    let mut kept = Vec::new();
                    let _ = (&mut pipe).take(16385).read_to_end(&mut kept);
                    let _ = std::io::copy(&mut pipe, &mut std::io::sink());
                    String::from_utf8_lossy(&kept).into_owned()
                })
            }
            let out = drain(child.stdout.take().unwrap());
            let err = drain(child.stderr.take().unwrap());
            let deadline = std::time::Instant::now() + guard;
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{what} exceeded hang guard ({guard:?})");
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            };
            (status, out.join().unwrap(), err.join().unwrap())
        }

        /// Run the rollout-path repair with a HANG GUARD as its budget. The
        /// repair spawns several default-durability sqlite3 children; these tests
        /// assert what it does, so its answer must not depend on how long fsync
        /// takes on the host (a measured slow host's stage disk: ~1s per commit under
        /// load, measured with a bare `sqlite3 x.db "create table t(a)"`).
        fn r9_repair_paths(base: &Path, db: &Path, roots: &[PathBuf]) -> Result<usize, ShareError> {
            codex_sqlite::repair_slot_rollout_paths_before(
                &r9_test_lock(base),
                base,
                db,
                roots,
                std::time::Instant::now() + std::time::Duration::from_secs(120),
            )
        }

        // Own only real sqlite3 children against private fixture files. Avoid
        // .sqliterc, inherited credentials and a host HOME in these new probes.
        fn r9_fixture_sql(bin: &Path, db: &Path, sql: &str) -> String {
            r9_fixture_sql_guarded(bin, db, sql, R9_RUNNER_HANG_GUARD)
        }

        fn r9_fixture_sql_guarded(
            bin: &Path,
            db: &Path,
            sql: &str,
            guard: std::time::Duration,
        ) -> String {
            let null_rc = if cfg!(windows) { "NUL" } else { "/dev/null" };
            let child = Command::new(bin)
                .args(["-init", null_rc, "-batch", "-bail", "-noheader", "-list"])
                .arg(db)
                .arg(format!(
                    "PRAGMA trusted_schema=OFF;\nPRAGMA synchronous=OFF;\n{sql}"
                ))
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", db.parent().unwrap())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let (status, out, err) = r9_bounded_output(child, "private sqlite fixture", guard);
            assert!(
                out.len() <= 16384 && err.len() <= 16384,
                "fixture output cap"
            );
            assert!(status.success(), "private sqlite fixture failed: {err}");
            out
        }

        /// The deadline classifier separates the runner's OWN deadline detail
        /// from every other runner detail — including one that quotes database
        /// content mentioning a "deadline" path — and catches the walk and IO
        /// shapes it must.
        ///
        /// Falsifying result for the loose rule (`detail.contains("deadline")`):
        /// the near-miss child failure below is classified as the deadline class
        /// and this test fails, so the assertion discriminates the exact match
        /// from the substring one.
        #[cfg(unix)]
        #[test]
        fn r9p_deadline_classifier_separates_the_runner_deadline_from_a_child_failure() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            // The runner's own deadline, taken from its PRE-SPAWN refusal: an
            // already-expired budget spawns nothing.
            let expired = codex_sqlite::run_repair_sqlite_bounded(
                &f.binary,
                &f.db,
                "SELECT 1;",
                true,
                std::time::Instant::now() - std::time::Duration::from_millis(1),
            )
            .unwrap_err();
            assert!(
                codex_sqlite::is_bounded_deadline_refusal(&expired),
                "the runner's own deadline must be the deadline class: {expired:?}"
            );
            // A child failure whose stderr quotes a path containing "deadline":
            // database content must not steer which class the operator is told.
            let near_miss = ShareError::SqliteCommandFailed {
                binary: f.binary.clone(),
                path: f.db.clone(),
                detail:
                    "rollout repair exit Some(1): no such table: /missing/deadline/rollout.jsonl"
                        .to_owned(),
            };
            assert!(
                !codex_sqlite::is_bounded_deadline_refusal(&near_miss),
                "a child failure quoting a 'deadline' path is not the deadline class: {near_miss:?}"
            );
            // The walk's two failure shapes: its budget refusal IS the class,
            // every other reason is not.
            assert!(codex_sqlite::is_bounded_deadline_refusal(
                &ShareError::CodexResumeTarget {
                    reason: "target filename search exceeded its bounded budget"
                }
            ));
            assert!(!codex_sqlite::is_bounded_deadline_refusal(
                &ShareError::CodexResumeTarget {
                    reason: "target filename search found conflicting transcripts"
                }
            ));
            // The row/root walk's TimedOut, against an ordinary IO failure.
            assert!(codex_sqlite::is_bounded_deadline_refusal(&ShareError::io(
                &f.db,
                std::io::Error::new(std::io::ErrorKind::TimedOut, "rollout repair deadline"),
            )));
            assert!(!codex_sqlite::is_bounded_deadline_refusal(&ShareError::io(
                &f.db,
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
            )));
        }

        /// The REWRITE path: the recorded path is missing but resolvable by
        /// filename under a persistent root, so the admission plans an UPDATE —
        /// and must not land it when the schema, the row, or the row's
        /// uniqueness changed after the read. Every named guard stays in the
        /// batch, so the UPDATE is voided and the refusal names the guard.
        ///
        /// The no-update case (an already-canonical target row) is no longer
        /// covered here: it spends no write transaction and therefore has no
        /// re-check to trip — see
        /// `r9p_canonical_exact_target_spends_no_write_transaction`, which pins
        /// that absence and its one-leg spawn difference.
        fn r9_exact_target_rewrite_race_voids_the_update(kind: &str) {
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("actual sqlite3 required");
            let temp = TempDir::new().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let root = base.join("codex-sessions");
            fs::create_dir(&root).unwrap();
            let rollout = root.join("rollout.jsonl");
            fs::write(&rollout, b"private canonical transcript").unwrap();
            // A missing recorded path whose FILENAME resolves to the candidate:
            // the admission plans the rewrite to `rollout` and takes the write
            // leg the guards below live in.
            let dead = base.join("missing/rollout.jsonl");
            let db = base.join("state_5.sqlite");
            r9_fixture_sql(&bin, &db, &format!("CREATE TABLE threads(id TEXT, rollout_path TEXT); INSERT INTO threads VALUES('target','{}');", dead.to_str().unwrap().replace('\'', "''")));
            let sql = match kind {
                "schema" => "CREATE VIEW planted AS SELECT * FROM threads;",
                "duplicate" => "INSERT INTO threads VALUES('target','/missing/other.jsonl');",
                _ => "UPDATE threads SET rollout_path='/missing/changed.jsonl' WHERE id='target';",
            };
            let selected_kind = kind.to_owned();
            let fixture_bin = bin.clone();
            let fixture_db = db.clone();
            codex_sqlite::set_test_repair_before_write(move || {
                r9_fixture_sql(&fixture_bin, &fixture_db, sql);
            });
            let result = codex_sqlite::repair_resume_target_before(
                &r9_test_lock(&base),
                &base,
                &db,
                &[root],
                "target",
                std::time::Instant::now() + std::time::Duration::from_secs(4),
            );
            let expected = if selected_kind == "schema" {
                "csq_rollout_schema_unchanged"
            } else {
                "csq_resume_target_unchanged"
            };
            assert!(
                matches!(&result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains(expected)),
                "exact-target guarded rewrite refusal: {result:?}"
            );
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT count(*) FROM threads;").trim(),
                if selected_kind == "duplicate" {
                    "2"
                } else {
                    "1"
                }
            );
            // The planned rewrite must not have landed on the changed row: the
            // candidate path is what the voided UPDATE would have written.
            assert_eq!(
                r9_fixture_sql(
                    &bin,
                    &db,
                    &format!(
                        "SELECT count(*) FROM threads WHERE rollout_path='{}';",
                        rollout.to_str().unwrap().replace('\'', "''")
                    )
                )
                .trim(),
                "0",
                "a voided guard must leave no rewrite behind"
            );
        }
        #[cfg(unix)]
        struct PagedRepairFixture {
            _temp: tempfile::TempDir,
            base: PathBuf,
            root: PathBuf,
            db: PathBuf,
            binary: PathBuf,
        }

        #[cfg(unix)]
        impl PagedRepairFixture {
            fn new() -> Self {
                // Keep fixture paths portable even when the caller inherits a deep TMPDIR.
                let temp = tempfile::Builder::new()
                    .prefix("cp-")
                    .tempdir_in("/tmp")
                    .unwrap();
                let base = temp.path().canonicalize().unwrap();
                let root = base.join("persistent");
                fs::create_dir(&root).unwrap();
                let db = base.join("state_5.sqlite");
                let binary = codex_sqlite::resolve_sqlite3()
                    .expect("private paged repair fixtures require real sqlite3");
                let f = Self {
                    _temp: temp,
                    base,
                    root,
                    db,
                    binary,
                };
                f.sql(
                    &f.db,
                    "CREATE TABLE threads(id TEXT PRIMARY KEY, rollout_path TEXT);",
                );
                f
            }
            fn sql(&self, db: &Path, sql: &str) -> String {
                let missing_prefix = format!(
                    "'{}/missing/",
                    self.base.to_str().unwrap().replace('\'', "''")
                );
                let sql = sql.replace("'/missing/", &missing_prefix);
                let output = std::process::Command::new(&self.binary)
                    .env_clear()
                    .env("HOME", &self.base)
                    .current_dir(&self.base)
                    .args([
                        "-init",
                        if cfg!(windows) { "NUL" } else { "/dev/null" },
                        "-batch",
                        "-bail",
                    ])
                    .arg(db)
                    .arg(format!("\n{sql}"))
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "private paged SQLite fixture: {output:?}"
                );
                String::from_utf8(output.stdout).unwrap()
            }
            fn run(&self, databases: &[PathBuf]) -> codex_sqlite::PagedResumeOutcome {
                codex_sqlite::repair_resume_all_before(
                    &r9_test_lock(&self.base),
                    &self.base,
                    databases,
                    std::slice::from_ref(&self.root),
                    std::time::Instant::now() + std::time::Duration::from_secs(12),
                )
            }
            fn candidate(&self, name: &str) -> PathBuf {
                let path = self.root.join(name);
                fs::write(&path, b"private transcript").unwrap();
                path
            }
        }

        #[cfg(unix)]
        #[test]
        fn r9p_full_paging_reaches_last_row_beyond_large_old_output() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.sql(&f.db, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<8228) INSERT INTO threads SELECT 'dead-'||i, '/missing/'||printf('%0200d',i)||'/absent.jsonl' FROM n;");
            let candidate = f.candidate("last.jsonl");
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('last','/missing/last.jsonl');",
            );
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(result, codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited==8229 && p.rewritten==1),
                "full paged last-row coverage: {result:?}"
            );
            assert_eq!(
                f.sql(&f.db, "SELECT rollout_path FROM threads WHERE id='last';")
                    .trim(),
                candidate.to_str().unwrap()
            );
            assert_eq!(f.sql(&f.db,"SELECT count(*) FROM threads WHERE id LIKE 'dead-%' AND rollout_path != '/missing/'||printf('%0200d',CAST(substr(id,6) AS INTEGER))||'/absent.jsonl';").trim(),"0");
        }

        #[cfg(unix)]
        #[test]
        fn r9p_one_complete_index_is_shared_across_all_databases() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            let other = f.base.join("state_6.sqlite");
            f.sql(&other,"CREATE TABLE threads(id TEXT PRIMARY KEY, rollout_path TEXT); INSERT INTO threads VALUES('two','/missing/one.jsonl');");
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/one.jsonl');",
            );
            let candidate = f.candidate("one.jsonl");
            codex_sqlite::test_paged_index_builds(true);
            assert!(
                matches!(f.run(&[f.db.clone(),other.clone()]),codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited==2 && p.rewritten==2 && p.databases_completed==2)
            );
            assert_eq!(
                codex_sqlite::test_paged_index_builds(false),
                1,
                "exactly one index for multiple database consumers"
            );
            assert_eq!(
                f.sql(&other, "SELECT rollout_path FROM threads;").trim(),
                candidate.to_str().unwrap()
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9p_read_pages_and_write_batches_are_byte_bounded() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            // Every component is below NAME_MAX and each full path below
            // macOS PATH_MAX. Long IDs plus three path components make the
            // first 500 rows exceed the runner's 1MiB output cap: paging by
            // row count alone must fail, while 512KiB read pages complete.
            // Every 7th row has a distinct basename with a candidate transcript, so
            // it IS rewritten; a batch that holds no UPDATE spends no transaction
            // (`has_updates`), so without these rows no long-row write batch runs.
            let rewritten_rows = (1..=600).filter(|i| i % 7 == 0).count();
            for i in (1..=600).filter(|i| i % 7 == 0) {
                f.candidate(&format!("cand-{i}.jsonl"));
            }
            f.sql(&f.db,"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<600) INSERT INTO threads SELECT 'long-'||printf('%0600d',i), '/missing/'||printf('%0180d',i)||'/'||printf('%0180d',i)||'/'||printf('%0180d',i)||'/'||CASE WHEN i%7=0 THEN 'cand-'||i||'.jsonl' ELSE 'absent.jsonl' END FROM n;");
            let payload: usize = f
                .sql(&f.db, "SELECT sum(length(hex(id))+length(hex(rollout_path))+32) FROM (SELECT id,rollout_path FROM threads ORDER BY rowid LIMIT 500);")
                .trim().parse().unwrap();
            assert!(payload > 1024 * 1024, "fixture read payload: {payload}");
            let longest_path: usize = f
                .sql(&f.db, "SELECT max(length(rollout_path)) FROM threads;")
                .trim()
                .parse()
                .unwrap();
            assert!(longest_path < 1024, "fixture path bytes: {longest_path}");
            codex_sqlite::take_recorded_scripts();
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(result,codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited==600 && p.rewritten==rewritten_rows),
                "byte-bounded read/write coverage: {result:?}"
            );
            let write_batches = codex_sqlite::take_recorded_scripts()
                .iter()
                .filter(|s| s.contains("BEGIN IMMEDIATE"))
                .count();
            // Arithmetic: 600 rows at the 32-row cap alone make ceil(600/32) = 19
            // batches, and every 7th row is rewritten so each of them would
            // write. Each rewrite row carries a >1200-byte hex id guard plus a
            // >1000-byte path guard, ~3KB against the 10_000-byte batch bound, so
            // a byte-bounded split puts at most 3 rewrite rows in a batch:
            // ceil(85/3) = 29 write batches. More than 19 can only come from the
            // byte bound; `>= 2` held under the row cap alone too.
            let row_cap_only = 600usize.div_ceil(32);
            assert!(
                write_batches > row_cap_only,
                "long-row rewrites must split by BYTES, not only the 32-row cap: \
                 {write_batches} write batches vs {row_cap_only} from the row cap alone"
            );
        }

        /// MED-R2-1: on a sqlite3 that keeps executing past an error, a failed
        /// guard of row 2 must void row 1's UPDATE too (every guard precedes
        /// every UPDATE and each UPDATE carries the aggregate gate), and the
        /// failure is a KNOWN rollback. Falsifying result with per-row gating:
        /// row `one` is rewritten while row `two` is not.
        #[cfg(unix)]
        #[test]
        fn r9p_two_row_batch_with_a_failed_second_guard_commits_no_row_on_a_continuing_sqlite3() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.candidate("one.jsonl");
            f.candidate("two.jsonl");
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/one.jsonl');INSERT INTO threads VALUES('two','/missing/two.jsonl');",
            );
            let binary = f.binary.clone();
            let db = f.db.clone();
            codex_sqlite::set_test_repair_before_write(move || {
                let output = std::process::Command::new(binary)
                    .env_clear()
                    .args(["-init", if cfg!(windows) { "NUL" } else { "/dev/null" }])
                    .arg(db)
                    .arg("UPDATE threads SET rollout_path='/changed/two.jsonl' WHERE id='two';")
                    .output()
                    .unwrap();
                assert!(output.status.success());
            });
            let result =
                codex_sqlite::with_continue_past_errors(|| f.run(std::slice::from_ref(&f.db)));
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress.visited==0 && progress.rewritten==0 && !progress.in_flight_commit_unknown),
                "failed guard is a known rollback: {result:?}"
            );
            assert_eq!(
                f.sql(
                    &f.db,
                    "SELECT count(*) FROM threads WHERE id='one' AND rollout_path='/missing/one.jsonl';"
                )
                .trim(),
                "1",
                "row one must not be rewritten when row two's guard failed"
            );
        }

        /// sqlite3 children one full resume repair spawns for `rows` rows:
        /// (read spawns, write transactions). `rewrite` makes every row's old
        /// path repairable, otherwise no row needs an UPDATE.
        #[cfg(unix)]
        fn resume_repair_spawns(rows: usize, rewrite: bool) -> (usize, usize) {
            let f = PagedRepairFixture::new();
            let mut sql = String::new();
            for i in 0..rows {
                if rewrite {
                    f.candidate(&format!("r{i}.jsonl"));
                }
                sql.push_str(&format!(
                    "INSERT INTO threads VALUES('r{i}','/missing/r{i}.jsonl');"
                ));
            }
            f.sql(&f.db, &sql);
            codex_sqlite::take_recorded_scripts();
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited == rows),
                "{result:?}"
            );
            let scripts = codex_sqlite::take_recorded_scripts();
            let writes = scripts
                .iter()
                .filter(|s| s.contains("BEGIN IMMEDIATE"))
                .count();
            (scripts.len() - writes, writes)
        }

        /// `projected_len` is the exact length of the script `push` then builds, so
        /// the byte bound neither over-reserves (more transactions) nor
        /// under-reserves (an oversize script).
        #[test]
        fn paged_batch_projection_is_exact() {
            hold_test_migration_lock!();
            let header = "BEGIN IMMEDIATE;\n".to_owned();
            let mut batch = codex_sqlite::PagedBatch::new(&header);
            for i in 0..12 {
                let guard = "INSERT INTO csq_paged_rows SELECT (1 = 1);\n".to_owned();
                let update = (i % 2 == 0).then(|| format!("UPDATE threads SET a = {i};\n"));
                let projected = batch.projected_len(&guard, update.as_deref());
                batch.push(&guard, update.as_deref());
                assert_eq!(projected, batch.script().len(), "row {i}");
            }
        }

        /// Write transactions one full resume repair needs. Measured after the
        /// single-table row guards: 15 on Linux and 16 on darwin (longer
        /// canonical /tmp) for 300 rewritable rows, against 21 on Linux before;
        /// the byte bound is what limits a batch, and each transaction costs an
        /// fsync on the launch budget.
        #[cfg(unix)]
        #[test]
        fn r9p_resume_repair_write_transactions_stay_within_the_measured_bounds() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            for (rows, rewrite, max_writes) in [
                (32, true, 2),
                (32, false, 0),
                (96, true, 5),
                (300, true, 17),
                (300, false, 0),
            ] {
                let (reads, writes) = resume_repair_spawns(rows, rewrite);
                eprintln!("SPAWNS rows={rows} rewrite={rewrite} reads={reads} write_txns={writes}");
                assert!(
                    writes <= max_writes,
                    "rows={rows} rewrite={rewrite}: {writes} write transactions > {max_writes}"
                );
            }
        }

        /// A retry after a partial run must not spend write transactions on rows
        /// the first run already repaired. Falsifying result (before the
        /// skip): the second run re-walks every repaired row in guard-only
        /// batches, so its write transactions scale with the table, not with
        /// the rows still to do.
        #[cfg(unix)]
        #[test]
        fn r9p_retry_after_a_partial_run_spends_no_transaction_on_repaired_rows() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            let mut sql = String::new();
            for i in 0..200 {
                f.candidate(&format!("r{i}.jsonl"));
                sql.push_str(&format!(
                    "INSERT INTO threads VALUES('r{i}','/missing/r{i}.jsonl');"
                ));
            }
            sql.push_str("INSERT INTO threads VALUES('zz','/missing/zz.jsonl');");
            f.sql(&f.db, &sql);
            f.candidate("zz.jsonl");
            let nested = f.root.join("nested");
            fs::create_dir(&nested).unwrap();
            fs::write(nested.join("zz.jsonl"), b"other transcript").unwrap();
            codex_sqlite::take_recorded_scripts();
            let first = f.run(std::slice::from_ref(&f.db));
            let done = match &first {
                codex_sqlite::PagedResumeOutcome::Partial { progress, .. } => progress.rewritten,
                other => panic!("the ambiguous last row must stop the first run: {other:?}"),
            };
            assert!(done >= 150, "the first run must repair most rows: {done}");
            let first_writes = codex_sqlite::take_recorded_scripts()
                .iter()
                .filter(|s| s.contains("BEGIN IMMEDIATE"))
                .count();
            fs::remove_file(nested.join("zz.jsonl")).unwrap();
            let second = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(&second, codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited == 201),
                "{second:?}"
            );
            let second_writes = codex_sqlite::take_recorded_scripts()
                .iter()
                .filter(|s| s.contains("BEGIN IMMEDIATE"))
                .count();
            eprintln!("RETRY first_writes={first_writes} second_writes={second_writes}");
            assert!(
                second_writes <= 2,
                "retry re-walked repaired rows: {second_writes} write transactions (first run {first_writes})"
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9p_no_update_row_changed_in_a_writing_batch_voids_its_updates() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.candidate("two.jsonl");
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/absent.jsonl');INSERT INTO threads VALUES('two','/missing/two.jsonl');",
            );
            let binary = f.binary.clone();
            let db = f.db.clone();
            codex_sqlite::set_test_repair_before_write(move || {
                let output = std::process::Command::new(binary)
                    .env_clear()
                    .args(["-init", if cfg!(windows) { "NUL" } else { "/dev/null" }])
                    .arg(db)
                    .arg("UPDATE threads SET rollout_path='/changed/absent.jsonl' WHERE id='one';")
                    .output()
                    .unwrap();
                assert!(output.status.success());
            });
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(result,codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress.visited==0 && progress.rewritten==0 && !progress.in_flight_commit_unknown),
                "a changed no-update row must void the batch's UPDATE: {result:?}"
            );
            assert_eq!(
                f.sql(
                    &f.db,
                    "SELECT count(*) FROM threads WHERE id='two' AND rollout_path='/missing/two.jsonl';"
                )
                .trim(),
                "1"
            );
        }

        /// A batch with no UPDATE needs no transaction: the table is walked by
        /// reads alone.
        #[cfg(unix)]
        #[test]
        fn r9p_a_batch_without_updates_spends_no_write_transaction() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/absent.jsonl');",
            );
            codex_sqlite::take_recorded_scripts();
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited == 1 && p.rewritten == 0),
                "{result:?}"
            );
            assert!(codex_sqlite::take_recorded_scripts()
                .iter()
                .all(|s| !s.contains("BEGIN IMMEDIATE")));
        }

        #[cfg(unix)]
        #[test]
        fn r9p_duplicate_id_and_schema_changes_refuse_before_rewrite() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            for mutation in [
                "INSERT INTO threads VALUES('one','/other/one.jsonl');",
                "CREATE VIEW foreign_view AS SELECT id FROM threads;",
            ] {
                let f = PagedRepairFixture::new();
                f.candidate("one.jsonl");
                f.sql(&f.db,"DROP TABLE threads;CREATE TABLE threads(id TEXT,rollout_path TEXT);INSERT INTO threads VALUES('one','/missing/one.jsonl');");
                let binary = f.binary.clone();
                let db = f.db.clone();
                codex_sqlite::set_test_repair_before_write(move || {
                    let output = std::process::Command::new(binary)
                        .env_clear()
                        .args(["-init", if cfg!(windows) { "NUL" } else { "/dev/null" }])
                        .arg(db)
                        .arg(mutation)
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                });
                let result = f.run(std::slice::from_ref(&f.db));
                assert!(
                    matches!(result,codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress.visited==0 && progress.rewritten==0 && !progress.in_flight_commit_unknown),
                    "paged transaction must refuse changed row/schema: {result:?}"
                );
                assert_eq!(
                    f.sql(
                        &f.db,
                        "SELECT count(*) FROM threads WHERE rollout_path='/missing/one.jsonl';"
                    )
                    .trim(),
                    "1"
                );
            }
        }

        #[cfg(unix)]
        #[test]
        fn r9p_partial_budget_and_unsupported_cursor_are_typed() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            let result = codex_sqlite::repair_resume_all_before(
                &r9_test_lock(&f.base),
                &f.base,
                std::slice::from_ref(&f.db),
                std::slice::from_ref(&f.root),
                std::time::Instant::now(),
            );
            assert!(
                matches!(result,codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress==codex_sqlite::PagedResumeProgress::default())
            );
            assert!(
                matches!(codex_sqlite::repair_resume_all_before(&r9_test_lock(&f.base), &f.base,&[],&[],std::time::Instant::now()),codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress==codex_sqlite::PagedResumeProgress::default()),
                "expired empty work must not claim complete"
            );
            f.sql(&f.db,"DROP TABLE threads;CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT) WITHOUT ROWID;");
            assert!(
                matches!(f.run(std::slice::from_ref(&f.db)),codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress.visited==0)
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9p_partial_reports_only_acknowledged_batches() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.sql(&f.db,"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<40) INSERT INTO threads SELECT 'dead-'||i,'/missing/one.jsonl' FROM n; INSERT INTO threads VALUES('ambiguous','/missing/ambiguous.jsonl');");
            let canonical = f.candidate("one.jsonl");
            f.candidate("ambiguous.jsonl");
            let nested = f.root.join("nested");
            fs::create_dir(&nested).unwrap();
            fs::write(nested.join("ambiguous.jsonl"), b"other transcript").unwrap();
            let result = f.run(std::slice::from_ref(&f.db));
            let confirmed = f
                .sql(
                    &f.db,
                    &format!(
                        "SELECT count(*) FROM threads WHERE rollout_path='{}';",
                        canonical.to_str().unwrap().replace('\'', "''")
                    ),
                )
                .trim()
                .parse::<usize>()
                .unwrap();
            assert!(
                confirmed > 0 && confirmed < 40,
                "private database must expose only previously committed batches"
            );
            assert!(
                matches!(result,codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress.visited==confirmed && progress.rewritten==confirmed && !progress.in_flight_commit_unknown),
                "confirmed partial counters exclude pending batch: {result:?}"
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9p_indexed_candidate_requires_fresh_nofollow_admission() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            let candidate = f.candidate("swap.jsonl");
            let outside = f.base.join("outside.jsonl");
            fs::write(&outside, b"outside persistent root").unwrap();
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/swap.jsonl');",
            );
            codex_sqlite::set_test_repair_before_candidate_open(move || {
                fs::remove_file(&candidate).unwrap();
                std::os::unix::fs::symlink(&outside, &candidate).unwrap();
            });
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(result,codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress.visited==0 && progress.rewritten==0),
                "fresh owned admission must reject index-to-symlink race: {result:?}"
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9p_full_paging_supports_actual_upstream_schema_guard_budget() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.sql(&f.db, "DROP TABLE threads;");
            f.sql(&f.db, CODEX_THREADS_SCHEMA);
            let before = f.sql(
                &f.db,
                "SELECT hex(sql) FROM sqlite_master WHERE type='trigger' ORDER BY name;",
            );
            assert_eq!(
                before.lines().count(),
                5,
                "actual upstream trigger denominator"
            );
            let candidate = f.candidate("real.jsonl");
            let missing = f
                .base
                .join("missing")
                .join("x".repeat(200))
                .join("y".repeat(200))
                .join("z".repeat(200))
                .join("w".repeat(200))
                .join("real.jsonl");
            assert!(
                missing.to_str().unwrap().len() < 1024,
                "fixture path must remain below macOS PATH_MAX"
            );
            f.sql(&f.db,&format!("INSERT INTO threads(id,rollout_path,created_at,updated_at,source,model_provider,cwd,title,sandbox_policy,approval_mode) VALUES('99999999-9999-4999-8999-999999999999','{}',1,1,'cli','openai','/private-work','fixture','default','default');",missing.to_str().unwrap().replace('\'',"''")));
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(result,codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited==1 && p.rewritten==1),
                "real upstream schema fits bounded write guard: {result:?}"
            );
            assert_eq!(
                f.sql(&f.db, "SELECT rollout_path FROM threads;").trim(),
                candidate.to_str().unwrap()
            );
            assert_eq!(
                f.sql(
                    &f.db,
                    "SELECT hex(sql) FROM sqlite_master WHERE type='trigger' ORDER BY name;"
                ),
                before
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9p_captured_tail_does_not_chase_new_appends() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/one.jsonl');",
            );
            f.candidate("one.jsonl");
            let binary = f.binary.clone();
            let db = f.db.clone();
            let appended = f
                .base
                .join("missing/one.jsonl")
                .to_str()
                .unwrap()
                .replace('\'', "''");
            codex_sqlite::set_test_repair_before_write(move || {
                let output = std::process::Command::new(binary)
                    .env_clear()
                    .args([
                        "-init",
                        if cfg!(windows) { "NUL" } else { "/dev/null" },
                        "-batch",
                        "-bail",
                    ])
                    .arg(db)
                    .arg(format!("INSERT INTO threads VALUES('late','{appended}');"))
                    .output()
                    .unwrap();
                assert!(output.status.success());
            });
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(result, codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited==1 && p.rewritten==1),
                "finite captured tail must exclude later append: {result:?}"
            );
            assert_eq!(f.sql(&f.db,"SELECT count(*) FROM threads WHERE id='late' AND rollout_path='/missing/one.jsonl';").trim(),"1");
        }

        #[cfg(unix)]
        fn r9p_assert_pre_spawn_refusal_and_known_rollback(binary: &Path, db: &Path) {
            let deadline = || std::time::Instant::now() + R9_RUNNER_HANG_GUARD;
            let mut unknown = true;
            assert!(codex_sqlite::run_repair_sqlite_bounded_tracking(
                binary,
                db,
                &"x".repeat(60_001),
                false,
                deadline(),
                &mut unknown
            )
            .is_err());
            assert!(!unknown, "pre-spawn refusal has no unknown commit");
            assert!(codex_sqlite::run_repair_sqlite_bounded_tracking(binary,db,
                "BEGIN IMMEDIATE;CREATE TEMP TABLE csq_paged_fixture(ok INTEGER CONSTRAINT csq_paged_fixture CHECK(ok=1));INSERT INTO csq_paged_fixture VALUES(0);COMMIT;",
                false,deadline(),&mut unknown).is_err());
            assert!(!unknown, "named guard failure is a known rollback");
        }

        /// The classification holds when the child needs far longer than the old
        /// 2s deadline: the sqlite3 is started 3s late by the `delayed` fixture.
        /// Falsifying result with a 2s deadline: the deadline fires after the
        /// spawn, `unknown` is true, and the known-rollback assertion fails.
        #[cfg(unix)]
        #[test]
        fn r9p_known_rollback_classification_holds_when_the_child_is_slow() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            let wrapper = r9_native_fixture(&f.base, "delayed");
            fs::write(
                f.base.join("fixture-exec"),
                format!("3000\n{}", f.binary.display()),
            )
            .unwrap();
            r9p_assert_pre_spawn_refusal_and_known_rollback(&wrapper, &f.db);
        }

        /// Run the full paged repair with an already-short caller deadline, so
        /// every window under test is one the walk armed itself.
        #[cfg(unix)]
        fn r9p_run_short(f: &PagedRepairFixture) -> codex_sqlite::PagedResumeOutcome {
            codex_sqlite::repair_resume_all_before(
                &r9_test_lock(&f.base),
                &f.base,
                std::slice::from_ref(&f.db),
                std::slice::from_ref(&f.root),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
        }

        /// Install a walk hook that sleeps `late` at the first `late_at` point
        /// (a child that returned late inside its own 9s window) and `walk` at
        /// the `walk_nth` (0-based) `walk_at` point (a slow caller-side walk).
        #[cfg(unix)]
        fn r9p_slow_walk(
            late_at: codex_sqlite::PagedWalkPoint,
            late: std::time::Duration,
            walk_at: codex_sqlite::PagedWalkPoint,
            walk_nth: usize,
            walk: std::time::Duration,
        ) -> codex_sqlite::PagedWalkHookGuard {
            let mut late_done = false;
            let mut seen = 0usize;
            codex_sqlite::set_test_paged_walk_hook(move |point| {
                if point == late_at && !late_done {
                    late_done = true;
                    std::thread::sleep(late);
                }
                if point == walk_at {
                    if seen == walk_nth {
                        std::thread::sleep(walk);
                    }
                    seen += 1;
                }
            })
        }

        /// A page read that returns 7.5s into its 9s step window, followed by a
        /// 2.5s walk, completes: the walk gets its own 4s window. Falsifying
        /// result without the post-read `page_budget`: the walk inherits the
        /// ~1.5s leftover and the row check refuses (Partial).
        #[cfg(unix)]
        #[test]
        fn r9p_a_late_page_read_followed_by_a_short_walk_completes() {
            hold_test_migration_lock!();
            use codex_sqlite::PagedWalkPoint::{PageRead, Row};
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/one.jsonl');",
            );
            let candidate = f.candidate("one.jsonl");
            let ms = std::time::Duration::from_millis;
            let _hook = r9p_slow_walk(PageRead, ms(7500), Row, 0, ms(2500));
            let result = r9p_run_short(&f);
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited == 1 && p.rewritten == 1),
                "late page read then short walk: {result:?}"
            );
            assert_eq!(
                f.sql(&f.db, "SELECT rollout_path FROM threads WHERE id='one';")
                    .trim(),
                candidate.to_str().unwrap()
            );
        }

        /// A walk that runs 5.5s past its re-armed 4s window refuses. Falsifying
        /// result without the per-row deadline check: the row is walked and its
        /// batch commits under a fresh step window (Complete).
        #[cfg(unix)]
        #[test]
        fn r9p_a_walk_exceeding_its_rearmed_window_refuses() {
            hold_test_migration_lock!();
            use codex_sqlite::PagedWalkPoint::{PageRead, Row};
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('one','/missing/one.jsonl');",
            );
            f.candidate("one.jsonl");
            let ms = std::time::Duration::from_millis;
            let _hook = r9p_slow_walk(PageRead, ms(7500), Row, 0, ms(5500));
            let result = r9p_run_short(&f);
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Partial { progress, reason }
                    if *reason == "shared resume repair deadline exhausted" && progress.visited == 0 && progress.rewritten == 0),
                "walk past its window: {result:?}"
            );
            assert_eq!(
                f.sql(&f.db, "SELECT rollout_path FROM threads WHERE id='one';")
                    .trim(),
                format!("{}/missing/one.jsonl", f.base.display())
            );
        }

        /// 34 rewriting rows flush one batch mid-page (the flush is driven by
        /// `PAGED_BATCH_BYTES`, the projected script size, not the 32-row cap);
        /// that batch is acknowledged 7.5s into its 9s step window and row 34
        /// then takes 2.5s. The page completes, and the late batch is the ONLY
        /// commit before row 34's walk, so the 2.5s is charged to the window
        /// that batch re-armed. Falsifying result without the post-batch
        /// re-arm: row 34 inherits the batch's ~1.5s leftover and refuses with
        /// the first batch committed (Partial).
        #[cfg(unix)]
        #[test]
        fn r9p_rows_after_a_late_mid_page_batch_get_their_own_window() {
            hold_test_migration_lock!();
            use codex_sqlite::PagedWalkPoint::{BatchCommitted, Row};
            use std::sync::atomic::{AtomicUsize, Ordering};
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            for i in 0..34 {
                f.sql(
                    &f.db,
                    &format!("INSERT INTO threads VALUES('t{i}','/missing/t{i}.jsonl');"),
                );
                f.candidate(&format!("t{i}.jsonl"));
            }
            let ms = std::time::Duration::from_millis;
            let commits = std::sync::Arc::new(AtomicUsize::new(0));
            let commits_before_row_33 = std::sync::Arc::new(AtomicUsize::new(usize::MAX));
            let (counted, observed) = (commits.clone(), commits_before_row_33.clone());
            let mut rows = 0usize;
            let _hook = codex_sqlite::set_test_paged_walk_hook(move |point| match point {
                BatchCommitted => {
                    // The first commit is the late one.
                    if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                        std::thread::sleep(ms(7500));
                    }
                }
                Row => {
                    if rows == 33 {
                        observed.store(counted.load(Ordering::SeqCst), Ordering::SeqCst);
                        std::thread::sleep(ms(2500));
                    }
                    rows += 1;
                }
                _ => {}
            });
            let result = r9p_run_short(&f);
            assert_eq!(
                commits_before_row_33.load(Ordering::SeqCst),
                1,
                "the late batch must be the only commit before row 33"
            );
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Complete(p) if p.visited == 34 && p.rewritten == 34),
                "rows after a late mid-page batch: {result:?}"
            );
        }

        /// The exact route's row read returns 7.5s into its 9s window and the
        /// transcript filename search then takes 2.5s: the target is admitted
        /// and rewritten. Falsifying result without the exact route's walk
        /// window: the search inherits the ~1.5s leftover and refuses with
        /// "target filename search exceeded its bounded budget".
        #[cfg(unix)]
        #[test]
        fn r9_exact_target_search_gets_its_own_window() {
            hold_test_migration_lock!();
            use codex_sqlite::PagedWalkPoint::{ExactRowsRead, ExactSearchDir};
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("actual sqlite3 required");
            let temp = TempDir::new().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let root = base.join("codex-sessions");
            fs::create_dir(&root).unwrap();
            let rollout = root.join("rollout.jsonl");
            fs::write(&rollout, b"private canonical transcript").unwrap();
            let dead = base.join("missing/rollout.jsonl");
            let db = base.join("state_5.sqlite");
            r9_fixture_sql(&bin, &db, &format!("CREATE TABLE threads(id TEXT, rollout_path TEXT); INSERT INTO threads VALUES('target','{}');", dead.to_str().unwrap().replace('\'', "''")));
            let ms = std::time::Duration::from_millis;
            let _hook = r9p_slow_walk(ExactRowsRead, ms(7500), ExactSearchDir, 0, ms(2500));
            let result = codex_sqlite::repair_resume_target_before(
                &r9_test_lock(&base),
                &base,
                &db,
                &[root],
                "target",
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            );
            assert!(matches!(result, Ok(1)), "exact search window: {result:?}");
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT rollout_path FROM threads;").trim(),
                rollout.to_str().unwrap()
            );
        }

        /// True once `pid` no longer runs: gone (ESRCH), or on Linux a zombie
        /// left for a non-reaping init to collect.
        #[cfg(unix)]
        fn r9_descendant_gone(pid: i32) -> bool {
            // kill(-1) probes every process the caller may signal, and kill(0)
            // its own group: a test must never probe either.
            assert!(pid > 1, "refusing to probe implausible fixture pid {pid}");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                // SAFETY: signal zero sends nothing; it only probes `pid`.
                let alive = unsafe { libc::kill(pid, 0) } == 0;
                let zombie = fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                    stat.rsplit_once(") ")
                        .is_some_and(|(_, rest)| rest.starts_with('Z'))
                });
                if !alive || zombie {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        /// Read the fixture descendant's pid and assert it is dead; returns
        /// whether the fixture FORKED (false when the child died before it
        /// wrote the pid file). It is NEVER signalled: the group kill lands it,
        /// init reaps the orphan, and a reaped pid can be REUSED — signalling
        /// it could hit an unrelated process. A false result does NOT pass on
        /// its own: each caller retries with a fresh fixture and FAILS as NOT
        /// EXERCISED when no attempt forked. The descendant's 30 s sleep bounds
        /// the orphan if this assertion ever fails.
        #[cfg(unix)]
        fn r9_assert_descendant_gone(base: &Path) -> bool {
            let pid: i32 = match fs::read_to_string(base.join("descendant-pid")) {
                Ok(raw) => raw.trim().parse().expect("fixture descendant pid"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
                Err(error) => panic!("fixture descendant pid: {error}"),
            };
            assert!(
                pid > 1,
                "refusing to probe implausible fixture descendant pid {pid}"
            );
            let gone = r9_descendant_gone(pid);
            assert!(
                gone,
                "the fixture descendant (pid {pid}) is still alive; it is an \
                 orphan bounded by its 30 s sleep"
            );
            true
        }

        /// A step whose shell exits but leaves a forked descendant holding
        /// stdout times out, and the descendant dies with the step's process
        /// group. Falsifying result without `process_group(0)`: the leader's
        /// pid is no group id, the group kill finds nothing, and the descendant
        /// is still sleeping.
        #[cfg(unix)]
        #[test]
        fn r9_platform_runner_kills_the_step_process_group() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            const ATTEMPTS: usize = 3;
            let mut exercised = false;
            for attempt in 1..=ATTEMPTS {
                let t = tempfile::Builder::new()
                    .prefix("cr-")
                    .tempdir_in("/tmp")
                    .unwrap();
                let bin = r9_native_fixture(t.path(), "forked");
                let started = std::time::Instant::now();
                let result = codex_sqlite::run_repair_sqlite_bounded(
                    &bin,
                    &t.path().join("private.sqlite"),
                    "SELECT 1;",
                    true,
                    started + std::time::Duration::from_secs(1),
                );
                let spawned = codex_sqlite::take_last_spawned_pid();
                let forked = r9_assert_descendant_gone(t.path());
                assert!(
                    matches!(&result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains("deadline")),
                    "{result:?}"
                );
                if forked {
                    exercised = true;
                    break;
                }
                let cause = match spawned {
                    Some(_) => "spawned-but-pid-unwritten (the child died before it forked)",
                    None => "pre-spawn deadline (the runner refused before spawning)",
                };
                eprintln!(
                    "r9_platform_runner_kills_the_step_process_group attempt \
                     {attempt}/{ATTEMPTS} did NOT exercise the group kill: {cause}"
                );
            }
            assert!(
                exercised,
                "group-kill property NOT EXERCISED in {ATTEMPTS} attempts"
            );
        }

        /// The -bail probe's stdout drain is bounded by its own 5s deadline: a
        /// probed shell that forks a descendant holding stdout fails the probe
        /// in well under the descendant's 30s, and the descendant dies with the
        /// group. Falsifying result with a blocking drain: the probe returns
        /// only when the descendant exits after 30s.
        #[cfg(unix)]
        #[test]
        fn r9_bail_probe_drain_is_bounded_against_a_descendant_holding_stdout() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            const ATTEMPTS: usize = 3;
            let mut exercised = false;
            for attempt in 1..=ATTEMPTS {
                let t = tempfile::Builder::new()
                    .prefix("cr-")
                    .tempdir_in("/tmp")
                    .unwrap();
                let bin = r9_native_fixture(t.path(), "forked");
                let started = std::time::Instant::now();
                let stops = codex_sqlite::probe_stops_at_first_error(&bin);
                let elapsed = started.elapsed();
                let started_child = t.path().join("owned-pid").exists();
                let forked = r9_assert_descendant_gone(t.path());
                assert!(!stops, "a shell that exits 0 never passes the probe");
                assert!(
                    elapsed < std::time::Duration::from_secs(10),
                    "probe drain was not bounded: {elapsed:?}"
                );
                if forked {
                    exercised = true;
                    break;
                }
                // The probe spawns outside the runner spawn record, so the
                // distinction comes from the fixture's own startup file:
                // `owned-pid` is written before the mode forks.
                let cause = if started_child {
                    "spawned-but-pid-unwritten (the child started but died before it forked)"
                } else {
                    "never scheduled (the probe window ended before the child ran)"
                };
                eprintln!(
                    "r9_bail_probe_drain_is_bounded_against_a_descendant_holding_stdout \
                     attempt {attempt}/{ATTEMPTS} did NOT exercise the group kill: {cause}"
                );
            }
            assert!(
                exercised,
                "group-kill property NOT EXERCISED in {ATTEMPTS} attempts"
            );
        }

        /// The migration lock writer repair children inherit, held SHARED as
        /// the launch routes hold it.
        fn r9_test_lock(base: &Path) -> crate::session::shared_state::CodexShareLockGuard {
            crate::session::shared_state::acquire_codex_share_lock_shared_bounded(
                base,
                50,
                std::time::Duration::from_millis(20),
            )
            .expect("migration lock io")
            .expect("migration lock admitted")
        }

        /// Child half of `r9_writer_child_holds_the_migration_lock_after_csq_dies`:
        /// take the lock EXCLUSIVE, spawn a writer child that sleeps 20s, print
        /// its pid, then wait to be SIGKILLed (the "csq dies" step). The child
        /// is deliberately left unreaped: the parent kills its group.
        #[cfg(unix)]
        fn r9_lock_holder_child(base: std::ffi::OsString) -> ! {
            use std::io::Write as _;
            let base = PathBuf::from(base);
            let Ok(Some(lock)) =
                crate::session::shared_state::acquire_codex_share_lock_exclusive_bounded(
                    &base,
                    50,
                    std::time::Duration::from_millis(20),
                )
            else {
                std::process::exit(3);
            };
            let _held = lock.hold_for_children();
            let mut command = std::process::Command::new("/bin/sleep");
            command
                .arg("20")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let Ok(child) =
                codex_sqlite::RepairChild::spawn(&mut command, codex_sqlite::ChildRole::Writer)
            else {
                std::process::exit(4);
            };
            let mut stdout = std::io::stdout();
            let _ = writeln!(stdout, "CSQ_R9_LOCK_CHILD_PID={}", child.id());
            let _ = stdout.flush();
            std::mem::forget(child);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }

        /// Spawn this test binary as the lock holder (`r9_lock_holder_child`)
        /// for the test named `test`, then SIGKILL it ("csq dies") once it has
        /// reported its writer child. Returns the writer's pid.
        #[cfg(unix)]
        fn r9_kill_lock_holder_after_its_writer_spawns(test: &str, base: &Path) -> libc::pid_t {
            use std::io::BufRead as _;
            let name = format!(
                "{}::{test}",
                module_path!()
                    .split_once("::")
                    .expect("crate-qualified path")
                    .1
            );
            let mut holder = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture", "--test-threads=1"])
                .env(R9_LOCK_HOLDER_CHILD, base)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let stdout = holder.stdout.take().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                {
                    // libtest may print "test <name> ... " before the body's output
                    // on the same line.
                    if let Some((_, pid)) = line.split_once("CSQ_R9_LOCK_CHILD_PID=") {
                        let _ = tx.send(pid.trim().parse::<libc::pid_t>().ok());
                    }
                }
            });
            let pid = rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .ok()
                .flatten();
            // "csq dies": SIGKILL, which no handler can catch, then reap it.
            let _ = holder.kill();
            let holder_status = holder.wait();
            let Some(pid) = pid else {
                panic!("lock holder never reported its writer child: {holder_status:?}");
            };
            pid
        }

        /// The env var that turns a re-invoked test binary into the lock holder.
        #[cfg(unix)]
        const R9_LOCK_HOLDER_CHILD: &str = "CSQ_R9_LOCK_HOLDER_CHILD";

        /// One non-blocking exclusive attempt on `base`'s migration lock.
        #[cfg(unix)]
        fn r9_try_exclusive(base: &Path) -> bool {
            crate::session::shared_state::acquire_codex_share_lock_exclusive_bounded(
                base,
                1,
                std::time::Duration::from_millis(0),
            )
            .expect("lock io")
            .is_some()
        }

        /// SIGKILL `pid`'s process group if `pid` still leads one.
        #[cfg(unix)]
        fn r9_kill_group_if_leader(pid: libc::pid_t) {
            // SAFETY: getpgid only queries; the negative pid targets only the
            // group `pid` was just re-proved to lead (the orphaned writer).
            if unsafe { libc::getpgid(pid) } == pid {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
        }

        /// macOS and other non-Linux Unix: a writer repair child keeps the
        /// migration lock held after csq dies by SIGKILL (no death signal
        /// exists there; the lock stays held = fail-closed), and releases it
        /// when the child itself dies. Runs the lock holder in a subprocess of
        /// this test binary. Falsifying result without the inherited
        /// descriptor (`F_DUPFD_CLOEXEC`): the holder's death closes the only
        /// description and a fresh exclusive attempt succeeds while the child
        /// is still alive.
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        #[test]
        fn r9_writer_child_holds_the_migration_lock_after_csq_dies() {
            if let Some(base) = std::env::var_os(R9_LOCK_HOLDER_CHILD) {
                r9_lock_holder_child(base);
            }
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let pid = r9_kill_lock_holder_after_its_writer_spawns(
                "r9_writer_child_holds_the_migration_lock_after_csq_dies",
                t.path(),
            );
            // Proof of ownership before any kill: the pid leads its own group.
            // SAFETY: getpgid only queries.
            assert_eq!(
                unsafe { libc::getpgid(pid) },
                pid,
                "writer child is not its own group leader"
            );
            let acquired_while_child_lived = r9_try_exclusive(t.path());
            r9_kill_group_if_leader(pid);
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut acquired_after_child_died = false;
            while std::time::Instant::now() < until {
                if r9_try_exclusive(t.path()) {
                    acquired_after_child_died = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                !acquired_while_child_lived,
                "the exclusive lock was free while the orphaned writer still ran"
            );
            assert!(
                acquired_after_child_died,
                "the lock stayed held after the writer child was killed"
            );
        }

        /// Linux: when csq dies by SIGKILL, its writer child (a 20s sleeper
        /// holding the inherited lock) is killed by `PR_SET_PDEATHSIG` and the
        /// exclusive lock becomes acquirable well before the sleeper would have
        /// exited on its own. Falsifying result without the `prctl`: the
        /// orphan keeps running and holding the lock for the rest of its 20s
        /// (the holder is killed as soon as it reports the writer), so no
        /// exclusive attempt succeeds within the 10s window.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn r9_writer_child_dies_with_csq_and_releases_the_lock() {
            if let Some(base) = std::env::var_os(R9_LOCK_HOLDER_CHILD) {
                r9_lock_holder_child(base);
            }
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let pid = r9_kill_lock_holder_after_its_writer_spawns(
                "r9_writer_child_dies_with_csq_and_releases_the_lock",
                t.path(),
            );
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut acquired = false;
            while std::time::Instant::now() < until {
                if r9_try_exclusive(t.path()) {
                    acquired = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // Dead means gone or a zombie awaiting its new parent's reap; a
            // zombie has closed every descriptor already.
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok();
            let running = state.as_deref().is_some_and(|stat| {
                stat.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next())
                    .is_some_and(|code| code != "Z" && code != "X")
            });
            if running {
                r9_kill_group_if_leader(pid);
            }
            assert!(
                acquired,
                "the exclusive lock stayed held after csq died (writer pid {pid})"
            );
            assert!(!running, "the orphaned writer {pid} survived csq's death");
        }

        /// A writer spawn on a thread holding no migration lock is refused with
        /// the fixed detail, and the same spawn under a held lock runs.
        /// Falsifying result without the refusal: the unlocked writer spawns.
        #[cfg(unix)]
        #[test]
        fn r9_writer_spawn_without_the_migration_lock_is_refused() {
            let sleeper = || {
                let mut command = std::process::Command::new("/bin/sleep");
                command
                    .arg("5")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                command
            };
            let unlocked =
                codex_sqlite::RepairChild::spawn(&mut sleeper(), codex_sqlite::ChildRole::Writer);
            let refused = matches!(&unlocked, Err(e) if e.to_string() == codex_sqlite::UNLOCKED_WRITER_DETAIL);
            drop(unlocked);
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let lock = r9_test_lock(t.path());
            let held = lock.hold_for_children();
            let locked =
                codex_sqlite::RepairChild::spawn(&mut sleeper(), codex_sqlite::ChildRole::Writer);
            let spawned = locked.is_ok();
            drop(locked);
            drop(held);
            assert!(refused, "an unlocked writer spawn was not refused");
            assert!(spawned, "a writer spawn under a held lock failed");
        }

        /// A sleeper command for the lock-token refusal tests.
        #[cfg(unix)]
        fn r9_token_sleeper() -> std::process::Command {
            let mut command = std::process::Command::new("/bin/sleep");
            command
                .arg("5")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            command
        }

        /// A lock token naming a standard-stream descriptor (0-2) is refused
        /// before fork: the child's stdio setup overwrites 0-2 before `exec`,
        /// so the writer would inherit a pipe in place of the lock. Falsifying
        /// result without the `fd <= 2` refusal: the spawn succeeds.
        #[cfg(unix)]
        #[test]
        fn r9_writer_spawn_refuses_a_standard_stream_lock_descriptor() {
            let identity = crate::session::shared_state::fd_identity(2);
            assert!(identity.is_some(), "fstat(2) must succeed for this test");
            let token = crate::session::shared_state::ChildLockToken { fd: 2, identity };
            let result =
                crate::session::shared_state::with_child_lock_token_for_test(token, || {
                    codex_sqlite::RepairChild::spawn(
                        &mut r9_token_sleeper(),
                        codex_sqlite::ChildRole::Writer,
                    )
                    .map(drop)
                });
            assert!(
                matches!(&result, Err(e) if e.to_string() == codex_sqlite::UNUSABLE_LOCK_DETAIL),
                "{result:?}"
            );
        }

        /// A lock token whose recorded `(st_dev, st_ino)` no longer matches
        /// the descriptor is refused in the child BEFORE `F_DUPFD`, and the
        /// same descriptor with its true identity spawns. Falsifying result
        /// without the `fstat` comparison: the mismatched spawn succeeds.
        #[cfg(unix)]
        #[test]
        fn r9_writer_spawn_refuses_a_lock_descriptor_whose_identity_changed() {
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let lock = r9_test_lock(t.path());
            let held = lock.hold_for_children();
            let real = crate::session::shared_state::held_child_lock().expect("scope installed");
            let (dev, ino) = real.identity.expect("identity recorded");
            let wrong = crate::session::shared_state::ChildLockToken {
                fd: real.fd,
                identity: Some((dev, ino.wrapping_add(1))),
            };
            let mismatched =
                crate::session::shared_state::with_child_lock_token_for_test(wrong, || {
                    codex_sqlite::RepairChild::spawn(
                        &mut r9_token_sleeper(),
                        codex_sqlite::ChildRole::Writer,
                    )
                    .map(drop)
                });
            let matched = codex_sqlite::RepairChild::spawn(
                &mut r9_token_sleeper(),
                codex_sqlite::ChildRole::Writer,
            )
            .map(drop);
            drop(held);
            assert!(
                matches!(&mismatched, Err(e) if e.to_string() == codex_sqlite::LOCK_IDENTITY_MISMATCH_DETAIL),
                "{mismatched:?}"
            );
            assert!(matched.is_ok(), "the true identity must spawn: {matched:?}");
        }

        /// A scope dropped out of order clears the slot rather than restoring
        /// a token it did not install over a still-live scope's. Falsifying
        /// result with the unconditional restore: after the outer scope drops
        /// first and then the inner, the inner restores its `previous` and the
        /// slot names the outer scope's token although that scope is gone.
        #[cfg(unix)]
        #[test]
        fn r9_child_lock_scope_out_of_order_drop_never_leaves_a_foreign_token() {
            let a = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let b = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let outer_lock = r9_test_lock(a.path());
            let inner_lock = r9_test_lock(b.path());
            assert_eq!(crate::session::shared_state::held_child_lock(), None);
            let outer = outer_lock.hold_for_children();
            let outer_token = crate::session::shared_state::held_child_lock();
            let inner = inner_lock.hold_for_children();
            let inner_token = crate::session::shared_state::held_child_lock();
            assert_ne!(outer_token, inner_token);
            drop(outer);
            let after_outer = crate::session::shared_state::held_child_lock();
            drop(inner);
            let after_inner = crate::session::shared_state::held_child_lock();
            assert_eq!(after_outer, None, "out-of-order drop left a token");
            assert_eq!(
                after_inner, None,
                "the inner drop restored a dropped scope's token"
            );
            // Properly nested scopes still restore.
            let outer = outer_lock.hold_for_children();
            let inner = inner_lock.hold_for_children();
            drop(inner);
            assert_eq!(crate::session::shared_state::held_child_lock(), outer_token);
            drop(outer);
            assert_eq!(crate::session::shared_state::held_child_lock(), None);
        }

        /// M1: a writer that exits 0 without running its script (the stub
        /// sleeps, never reads stdin, exits 0; the script fits the pipe buffer
        /// so every write succeeded) is NOT reported as applied by either
        /// runner, and the launch runner keeps the commit unknown. Falsifying
        /// result with the delivery-only check (`StdinFeeder::finish`): both
        /// runners return `Ok` and `commit_unknown` is cleared.
        #[cfg(unix)]
        #[test]
        fn r9_writer_exiting_0_without_its_end_marker_is_not_applied() {
            hold_test_migration_lock!();
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let bin = r9_native_fixture(t.path(), "exit-early");
            let db = t.path().join("early.sqlite");
            let mut unknown = false;
            let launch = codex_sqlite::run_repair_sqlite_bounded_tracking(
                &bin,
                &db,
                "BEGIN IMMEDIATE;\nCOMMIT;",
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
                &mut unknown,
            );
            assert!(
                matches!(&launch, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail == codex_sqlite::WRITER_NOT_FULLY_EXECUTED_DETAIL),
                "{launch:?}"
            );
            assert!(
                unknown,
                "an unexecuted script must leave the commit unknown"
            );
            let merge = codex_sqlite::run_sqlite3(&bin, &db, "BEGIN IMMEDIATE;\nCOMMIT;");
            assert!(
                matches!(&merge, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail == codex_sqlite::WRITER_NOT_FULLY_EXECUTED_DETAIL),
                "{merge:?}"
            );
        }

        /// The end marker is accepted only as stdout's exact final line, and
        /// is stripped from what the caller sees. Falsifying result with a
        /// substring check: the lookalike and not-last cases are accepted.
        #[test]
        fn writer_end_marker_must_be_the_exact_final_line() {
            let marker = codex_sqlite::writer_end_marker();
            assert!(
                marker.starts_with("csq-end-") && marker.len() == 24,
                "{marker}"
            );
            assert_ne!(marker, codex_sqlite::writer_end_marker(), "fresh per run");
            let strip = |out: &str| codex_sqlite::strip_writer_end_marker(out, &marker);
            assert_eq!(strip(&format!("{marker}\n")), Some(String::new()));
            assert_eq!(strip(&format!("a|b\n{marker}\n")), Some("a|b\n".to_owned()));
            assert_eq!(
                strip(&format!("x\r\n{marker}\r\n")),
                Some("x\r\n".to_owned())
            );
            assert_eq!(strip(""), None);
            assert_eq!(strip(&format!("{marker}\nlater\n")), None, "not last");
            assert_eq!(strip(&format!("{marker}0\n")), None, "lookalike");
            assert_eq!(strip(&format!("x{marker}\n")), None, "lookalike");
        }

        /// L1: the launch runner reports `RepairChild::spawn`'s own lock
        /// refusals with their fixed details, not the generic spawn failure.
        /// Falsifying result with the former blanket mapping: both details are
        /// "rollout repair spawn failed".
        #[cfg(unix)]
        #[test]
        fn r9_launch_runner_names_lock_descriptor_refusals() {
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let bin = r9_native_fixture(t.path(), "argv-capture");
            let db = t.path().join("refused.sqlite");
            let run = || {
                codex_sqlite::run_repair_sqlite_bounded(
                    &bin,
                    &db,
                    "SELECT 1;",
                    false,
                    std::time::Instant::now() + std::time::Duration::from_secs(30),
                )
            };
            let detail_of = |result: Result<String, ShareError>| match result {
                Err(ShareError::SqliteCommandFailed { detail, .. }) => detail,
                other => panic!("expected a refusal, got {other:?}"),
            };
            let stdio = crate::session::shared_state::ChildLockToken {
                fd: 2,
                identity: crate::session::shared_state::fd_identity(2),
            };
            let unusable =
                detail_of(crate::session::shared_state::with_child_lock_token_for_test(stdio, run));
            let lock_dir = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let lock = r9_test_lock(lock_dir.path());
            let held = lock.hold_for_children();
            let real = crate::session::shared_state::held_child_lock().expect("scope installed");
            let (dev, ino) = real.identity.expect("identity recorded");
            let wrong = crate::session::shared_state::ChildLockToken {
                fd: real.fd,
                identity: Some((dev, ino.wrapping_add(1))),
            };
            let mismatched =
                detail_of(crate::session::shared_state::with_child_lock_token_for_test(wrong, run));
            drop(held);
            assert_eq!(unusable, codex_sqlite::UNUSABLE_LOCK_DETAIL);
            assert_eq!(mismatched, codex_sqlite::LOCK_IDENTITY_MISMATCH_DETAIL);
        }

        /// Windows runtime check of the suspended-writer path (runs only on a
        /// Windows host; csq's is the GitHub Windows CI leg). Step view: the
        /// writer is in its kill-on-close job while still suspended and has
        /// not run, then after resume it is still in the job and exits 0.
        /// Full path: `RepairChild::spawn` of a Writer under a real held lock
        /// yields a child in its job that runs and exits 0. Falsifying result
        /// with an unconfined spawn: `IsProcessInJob` is false; with no
        /// resume: the child never exits.
        #[cfg(windows)]
        #[test]
        fn windows_writer_runs_only_inside_its_kill_on_close_job() {
            let t = TempDir::new().unwrap();
            let lock = crate::session::shared_state::acquire_codex_share_lock_shared_bounded(
                t.path(),
                50,
                std::time::Duration::from_millis(20),
            )
            .expect("migration lock io")
            .expect("migration lock admitted");
            let _held = lock.hold_for_children();
            let harmless = || {
                let mut command = Command::new("cmd");
                command
                    .args(["/c", "exit", "0"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                command
            };
            let (mut child, job) = codex_sqlite::spawn_suspended_in_job(&mut harmless()).unwrap();
            assert!(
                job.contains(&child).unwrap(),
                "suspended writer outside its job"
            );
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                child.try_wait().unwrap().is_none(),
                "a suspended writer ran"
            );
            codex_sqlite::resume_threads(&child).unwrap();
            assert!(job.contains(&child).unwrap(), "resumed writer left its job");
            assert!(
                child.wait().unwrap().success(),
                "resumed writer did not exit 0"
            );

            let mut writer =
                codex_sqlite::RepairChild::spawn(&mut harmless(), codex_sqlite::ChildRole::Writer)
                    .unwrap();
            assert!(
                writer.in_writer_job().unwrap(),
                "spawned writer outside its job"
            );
            let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !writer.exited().unwrap() {
                assert!(std::time::Instant::now() < until, "writer never exited");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(writer.wait().unwrap().success(), "writer did not exit 0");
        }

        /// ESTALE maps to the lock-identity refusal only when the descriptor's
        /// identity re-read in the parent has changed; an ESTALE with the lock
        /// intact (a generic spawn/execve failure) or another errno is not
        /// mapped, and the runner's detail mapping no longer keys on the
        /// errno. Falsifying result with the former errno-only mapping: the
        /// bare ESTALE maps to the identity detail.
        #[cfg(unix)]
        #[test]
        fn lock_identity_refusal_maps_estale_only_from_the_identity_check() {
            let recorded = Some((7 as libc::dev_t, 11 as libc::ino_t));
            let other = Some((7 as libc::dev_t, 12 as libc::ino_t));
            let estale = Some(codex_sqlite::LOCK_IDENTITY_MISMATCH_ERRNO);
            let refusal = codex_sqlite::lock_identity_refusal;
            assert!(refusal(estale, recorded, other));
            assert!(refusal(estale, recorded, None));
            assert!(!refusal(estale, recorded, recorded), "execve ESTALE");
            assert!(!refusal(Some(libc::ENOENT), recorded, other));
            assert!(!refusal(estale, None, other));
            let bare =
                std::io::Error::from_raw_os_error(codex_sqlite::LOCK_IDENTITY_MISMATCH_ERRNO);
            assert_eq!(codex_sqlite::writer_spawn_refusal_detail(&bare), None);
            let confirmed = std::io::Error::other(codex_sqlite::LOCK_IDENTITY_MISMATCH_DETAIL);
            assert_eq!(
                codex_sqlite::writer_spawn_refusal_detail(&confirmed),
                Some(codex_sqlite::LOCK_IDENTITY_MISMATCH_DETAIL)
            );
        }

        /// The Windows suspended-writer resume verdict: runnable only when at
        /// least one thread was found and every one resumed from a suspend
        /// count of exactly 1. Falsifying result with an `all`-only check: the
        /// empty list (no thread found) is admitted.
        #[test]
        fn windows_resumed_writer_verdict_fails_closed() {
            assert!(codex_sqlite::resumed_writer_may_run(&[1]));
            assert!(codex_sqlite::resumed_writer_may_run(&[1, 1, 1]));
            let refused = |counts: &[u32]| !codex_sqlite::resumed_writer_may_run(counts);
            assert!(refused(&[]), "no thread found");
            assert!(refused(&[1, u32::MAX]), "a failed resume");
            assert!(refused(&[0]), "a thread that was not suspended");
            assert!(refused(&[2]), "still suspended after resume");
        }

        /// Dropping a child after `wait()` reaped it reaches no waitid/kill
        /// path; dropping an unreaped one does (the counter discriminates).
        /// Falsifying result without the `reaped` flag: the post-reap drop is
        /// counted.
        #[cfg(unix)]
        #[test]
        fn r9_drop_after_wait_sends_no_signal() {
            hold_test_migration_lock!();
            let quick = || {
                let mut command = std::process::Command::new("/bin/sh");
                command
                    .args(["-c", "exit 0"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                command
            };
            let mut child =
                codex_sqlite::RepairChild::spawn(&mut quick(), codex_sqlite::ChildRole::Reader)
                    .unwrap();
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !child.exited().unwrap() {
                assert!(std::time::Instant::now() < until, "child never exited");
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            child.wait().unwrap();
            let before = codex_sqlite::drop_signal_paths();
            drop(child);
            let after_reaped = codex_sqlite::drop_signal_paths();
            let unreaped =
                codex_sqlite::RepairChild::spawn(&mut quick(), codex_sqlite::ChildRole::Reader)
                    .unwrap();
            drop(unreaped);
            let after_unreaped = codex_sqlite::drop_signal_paths();
            assert_eq!(
                after_reaped, before,
                "a reaped child's drop reached waitid/kill"
            );
            assert_eq!(
                after_unreaped,
                after_reaped + 1,
                "the counter does not discriminate"
            );
        }

        /// A `-safe` probe that did not complete (timeout, spawn failure:
        /// `None`) is attempted at most once per process: it is recorded as
        /// `Unknown` (never as a completed answer) and no later call probes
        /// again. Falsifying result with the former retry-on-next-call cache:
        /// the second call runs its probe (and panics). A completed answer is
        /// cached as `Completed` and likewise never re-probed.
        #[test]
        fn r9_safe_flag_probe_timeout_is_attempted_once_and_never_completed() {
            let cache = std::sync::OnceLock::new();
            let first = codex_sqlite::supports_safe_flag_cached(&cache, || None);
            let second = codex_sqlite::supports_safe_flag_cached(&cache, || -> Option<bool> {
                unreachable!("a non-completed probe was retried in the same process")
            });
            assert_eq!((first, second), (false, false));
            assert_eq!(cache.get(), Some(&codex_sqlite::SafeFlagProbe::Unknown));

            let completed = std::sync::OnceLock::new();
            let first = codex_sqlite::supports_safe_flag_cached(&completed, || Some(true));
            let second = codex_sqlite::supports_safe_flag_cached(&completed, || -> Option<bool> {
                unreachable!("a completed answer was re-probed")
            });
            assert_eq!((first, second), (true, true));
            assert_eq!(
                completed.get(),
                Some(&codex_sqlite::SafeFlagProbe::Completed(true))
            );
        }

        /// The merge runner's stdin delivery and wait are bounded: a child that
        /// never reads stdin, fed a script larger than any pipe buffer, fails at
        /// the deadline — and the child was SPAWNED (the runner's own record).
        /// Falsifying result with the former blocking `write_all` +
        /// `wait_with_output`: the call blocks until the hung child exits after
        /// 10s, then fails with a write error.
        ///
        /// Group kill is NOT this row's property, and the mechanism is shared:
        /// BOTH runners return at the deadline and DROP the child, and
        /// `RepairChild::drop` performs the group kill. That is why a fixture
        /// which never forks cannot observe it here, and why
        /// `r9_platform_runner_kills_the_step_process_group` — whose fixture
        /// forks a descendant — covers the property.
        #[cfg(unix)]
        #[test]
        fn r9_merge_runner_stdin_write_is_bounded() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            const ATTEMPTS: usize = 3;
            let script = "SELECT 1;".repeat(120_000);
            let mut exercised = false;
            for attempt in 1..=ATTEMPTS {
                let t = tempfile::Builder::new()
                    .prefix("cr-")
                    .tempdir_in("/tmp")
                    .unwrap();
                let lock = r9_test_lock(t.path());
                let _held = lock.hold_for_children();
                let bin = r9_native_fixture(t.path(), "hung-late-start");
                let started = std::time::Instant::now();
                let result = codex_sqlite::run_sqlite3_with_deadline(
                    &bin,
                    &t.path().join("private.sqlite"),
                    &script,
                    false,
                    started + std::time::Duration::from_secs(1),
                );
                let elapsed = started.elapsed();
                assert!(
                    matches!(&result, Err(ShareError::SqliteCommandFailed { detail, .. })
                        if detail == codex_sqlite::MERGE_SQLITE_DEADLINE_DETAIL),
                    "{result:?}"
                );
                assert!(
                    elapsed < std::time::Duration::from_secs(5),
                    "merge runner was not bounded: {elapsed:?}"
                );
                // The pid comes from the RUNNER's own spawn record, never from
                // a file the child writes: `hung-late-start` sleeps before
                // writing `owned-pid`, so under the 1s deadline that file can
                // never exist — the exact CI shape, deterministic. The row
                // needs a SPAWNED child; it never signals the leader (the
                // runner has already reaped it, so a live pid there would be
                // someone else's).
                let Some(_pid) = codex_sqlite::take_last_spawned_pid() else {
                    eprintln!(
                        "r9_merge_runner_stdin_write_is_bounded attempt \
                         {attempt}/{ATTEMPTS} did NOT exercise the bounded stdin \
                         write of a SPAWNED child: pre-spawn deadline (the runner \
                         refused before spawning, at the check after the 1.08 MB \
                         statement split; no child existed)"
                    );
                    continue;
                };
                exercised = true;
                break;
            }
            assert!(
                exercised,
                "spawned bounded-stdin-write property NOT EXERCISED in {ATTEMPTS} attempts"
            );
        }

        /// The fixture helper waits for the child's completion, not a deadline: a
        /// sqlite3 that starts 11s late (past the former 10s guard) still returns
        /// its output.
        #[cfg(unix)]
        #[test]
        fn r9_fixture_sql_waits_for_the_child_not_a_deadline() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            let wrapper = r9_native_fixture(&f.base, "delayed");
            fs::write(
                f.base.join("fixture-exec"),
                format!("11000\n{}", f.binary.display()),
            )
            .unwrap();
            assert_eq!(
                r9_fixture_sql(&wrapper, &f.db, "SELECT count(*) FROM threads;").trim(),
                "0"
            );
        }

        /// A child that never exits reds with the fixture's name inside the hang
        /// guard instead of hanging. Falsifying result with an unbounded
        /// `wait_with_output`: the child sleeps 30s, the call returns "0" after
        /// that wait and the test fails with "did not panic".
        #[cfg(unix)]
        #[test]
        #[should_panic(expected = "private sqlite fixture exceeded hang guard")]
        fn r9_fixture_sql_hang_guard_names_the_fixture() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            let wrapper = r9_native_fixture(&f.base, "delayed");
            fs::write(
                f.base.join("fixture-exec"),
                format!("30000\n{}", f.binary.display()),
            )
            .unwrap();
            r9_fixture_sql_guarded(
                &wrapper,
                &f.db,
                "SELECT count(*) FROM threads;",
                std::time::Duration::from_secs(1),
            );
        }

        #[cfg(unix)]
        #[test]
        fn r9p_write_outcome_separates_pre_spawn_rollback_and_unknown() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            r9p_assert_pre_spawn_refusal_and_known_rollback(&f.binary, &f.db);
            // The native child really commits with SQLite in its own PID, then
            // withholds acknowledgement. Ordering, not elapsed time: the runner
            // gets a hang-guard deadline, this thread waits for the child's
            // "committed" marker (written after the COMMIT returned) and only
            // then kills the child by the PID it recorded.
            let wrapper = r9_native_fixture(&f.base, "commit");
            let marker = f.base.join("committed");
            let pid_file = f.base.join("commit.pid");
            let runner = {
                let db = f.db.clone();
                let base = f.base.clone();
                std::thread::spawn(move || {
                    let lock = r9_test_lock(&base);
                    let _held = lock.hold_for_children();
                    let mut unknown = true;
                    let result = codex_sqlite::run_repair_sqlite_bounded_tracking(&wrapper,&db,
                        "BEGIN IMMEDIATE;INSERT INTO threads VALUES('committed','/missing/absent.jsonl');COMMIT;",
                        false,std::time::Instant::now()+R9_RUNNER_HANG_GUARD,&mut unknown);
                    (result.is_err(), unknown)
                })
            };
            let guard = std::time::Instant::now() + R9_RUNNER_HANG_GUARD
                - std::time::Duration::from_secs(10);
            while !marker.exists() {
                assert!(
                    std::time::Instant::now() < guard && !runner.is_finished(),
                    "native fixture never reported its COMMIT"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let pid: libc::pid_t = fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            // SAFETY: the PID was written by our own owned fixture child, which is
            // still sleeping inside the runner's wait loop (it has not been reaped).
            assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
            let (failed, unknown) = runner.join().unwrap();
            assert!(failed, "an unacknowledged killed child is a runner error");
            assert!(unknown, "post-spawn unacknowledged commit remains unknown");
            assert_eq!(
                fs::read_to_string(f.base.join("committed")).unwrap(),
                "committed\n"
            );
            assert_eq!(
                f.sql(&f.db, "SELECT count(*) FROM threads WHERE id='committed';")
                    .trim(),
                "1"
            );
        }

        #[test]
        fn r9_exact_target_rewrite_guards_row_race() {
            hold_test_migration_lock!();
            r9_exact_target_rewrite_race_voids_the_update("row");
        }
        #[test]
        fn r9_exact_target_rewrite_guards_schema_race() {
            hold_test_migration_lock!();
            r9_exact_target_rewrite_race_voids_the_update("schema");
        }
        #[test]
        fn r9_exact_target_rewrite_guards_duplicate_id_race() {
            hold_test_migration_lock!();
            r9_exact_target_rewrite_race_voids_the_update("duplicate");
        }

        /// A canonical exact target row is admitted by the READS alone: no
        /// write transaction, and exactly one fewer sqlite3 child than the same
        /// admission with a rewrite planned (the write leg is the difference,
        /// so this is a spawn-count compare, not an assumption about which
        /// scripts were recorded).
        ///
        /// Falsifying result pre-fix: the canonical admission spends a
        /// guard-only `BEGIN IMMEDIATE` batch, so the write-transaction scan
        /// finds one and the spawn counts are equal.
        #[cfg(unix)]
        #[test]
        fn r9p_canonical_exact_target_spends_no_write_transaction() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("actual sqlite3 required");
            // Keep fixture paths portable even when the caller inherits a deep TMPDIR.
            let temp = tempfile::Builder::new()
                .prefix("cp-")
                .tempdir_in("/tmp")
                .unwrap();
            let base = temp.path().canonicalize().unwrap();
            let root = base.join("codex-sessions");
            fs::create_dir(&root).unwrap();
            let rollout = root.join("rollout.jsonl");
            fs::write(&rollout, b"private canonical transcript").unwrap();
            let db = base.join("state_5.sqlite");
            r9_fixture_sql(&bin, &db, &format!("CREATE TABLE threads(id TEXT, rollout_path TEXT); INSERT INTO threads VALUES('target','{}');", rollout.to_str().unwrap().replace('\'', "''")));

            codex_sqlite::take_recorded_scripts();
            let canonical = codex_sqlite::repair_resume_target_before(
                &r9_test_lock(&base),
                &base,
                &db,
                std::slice::from_ref(&root),
                "target",
                std::time::Instant::now() + std::time::Duration::from_secs(4),
            );
            assert!(
                matches!(canonical, Ok(1)),
                "a canonical target must be admitted (Ok(1), never Ok(0)): {canonical:?}"
            );
            let canonical_scripts = codex_sqlite::take_recorded_scripts();
            assert!(
                canonical_scripts
                    .iter()
                    .all(|script| !script.contains("BEGIN IMMEDIATE")),
                "the canonical admission spent a write transaction: {canonical_scripts:?}"
            );

            // The identical admission with a rewrite planned still spends
            // exactly one guarded write transaction, so the leg difference is
            // the write leg itself and the recording is not simply silent.
            let dead = base.join("missing/rollout.jsonl");
            r9_fixture_sql(
                &bin,
                &db,
                &format!(
                    "UPDATE threads SET rollout_path='{}' WHERE id='target';",
                    dead.to_str().unwrap().replace('\'', "''")
                ),
            );
            codex_sqlite::take_recorded_scripts();
            let rewrite = codex_sqlite::repair_resume_target_before(
                &r9_test_lock(&base),
                &base,
                &db,
                std::slice::from_ref(&root),
                "target",
                std::time::Instant::now() + std::time::Duration::from_secs(4),
            );
            assert!(matches!(rewrite, Ok(1)), "{rewrite:?}");
            let rewrite_scripts = codex_sqlite::take_recorded_scripts();
            assert_eq!(
                rewrite_scripts
                    .iter()
                    .filter(|script| script.contains("BEGIN IMMEDIATE"))
                    .count(),
                1,
                "the rewrite path must still spend exactly one guarded write transaction"
            );
            assert_eq!(
                r9_fixture_sql(
                    &bin,
                    &db,
                    "SELECT rollout_path FROM threads WHERE id='target';"
                )
                .trim(),
                rollout.to_str().unwrap()
            );
            assert_eq!(
                canonical_scripts.len() + 1,
                rewrite_scripts.len(),
                "spawn count: canonical must spend exactly the write leg less: {canonical_scripts:?} vs {rewrite_scripts:?}"
            );
        }

        fn split_ok(script: &str) -> Vec<String> {
            codex_sqlite::split_sql_statements(script).unwrap()
        }

        #[test]
        fn repair_runner_splits_statements_outside_quotes_only() {
            hold_test_migration_lock!();
            let parts = split_ok(
                "PRAGMA a;\nUPDATE t SET p = 'x;''y\n;z--w' WHERE id = \"a;b\";\n\nCOMMIT;\n",
            );
            assert_eq!(
                parts,
                vec![
                    "PRAGMA a;".to_owned(),
                    "\nUPDATE t SET p = 'x;''y\n;z--w' WHERE id = \"a;b\";".to_owned(),
                    "\n\nCOMMIT;".to_owned(),
                ]
            );
            // backtick and bracket quoting, `;;`, and trailing text without `;`.
            assert_eq!(
                split_ok("SELECT `a;b`;;SELECT [c;d] FROM t;SELECT 1"),
                vec![
                    "SELECT `a;b`;".to_owned(),
                    "SELECT [c;d] FROM t;".to_owned(),
                    "SELECT 1".to_owned()
                ]
            );
        }

        #[test]
        fn repair_runner_splitter_refuses_what_it_cannot_split_safely() {
            hold_test_migration_lock!();
            for (script, why) in [
                ("SELECT 1; -- don't\nSELECT 2;", "line comment"),
                ("SELECT 1 /* x; */;", "block comment"),
                ("SELECT 'open;", "unterminated quote"),
                ("SELECT \"open;", "unterminated double quote"),
                ("SELECT `open;", "unterminated backtick"),
                ("SELECT [open;", "unterminated bracket"),
                ("SELECT 1;\n.print X\n", "dot command after statement"),
                ("SELECT 1;\n  .shell id", "indented dot command"),
                (".system id;", "leading dot command"),
                ("SELECT 1\ngo\n.shell id;", "go terminator line"),
                ("SELECT 1\nGO\n.shell id;", "GO terminator line"),
                ("SELECT 1\n/\n.shell id;", "slash terminator line"),
                ("SELECT 1;\n  /  \n", "indented slash terminator"),
                (
                    "SELECT 1;\n# it's a comment\nSELECT 2;",
                    "hash comment line",
                ),
                ("SELECT 1;\ngo", "trailing go line"),
                ("SELECT 1;#x\n.shell id;", "hash after a semicolon on the same line"),
                ("SELECT 1;go\n.shell id;", "go after a semicolon on the same line"),
                ("SELECT 1; /\n.shell id;", "slash after a semicolon on the same line"),
                ("EXPLAIN CREATE TRIGGER t AFTER UPDATE ON x BEGIN DELETE FROM x; END;", "explain trigger"),
                ("explain  query\tplan CREATE TEMP TRIGGER t AFTER UPDATE ON x BEGIN DELETE FROM x; END;", "explain query plan trigger"),
                (
                    "CREATE TRIGGER t AFTER UPDATE ON x BEGIN DELETE FROM x; END;",
                    "trigger body",
                ),
                (
                    "create  temp  trigger t AFTER UPDATE ON x BEGIN DELETE FROM x; END;",
                    "temp trigger body",
                ),
                (
                    "SELECT 1;\nCREATE TEMPORARY TRIGGER t AFTER UPDATE ON x BEGIN SELECT 1; END;",
                    "temporary trigger later piece",
                ),
            ] {
                assert!(
                    codex_sqlite::split_sql_statements(script).is_err(),
                    "must refuse {why}: {script:?}"
                );
            }
        }

        /// A sqlite3 that ignores `-bail` is refused before ANY write, on both
        /// runner shapes, and nothing is written. Falsifying result without the
        /// probe: the CREATE TABLE lands in the database file.
        #[cfg(unix)]
        #[test]
        fn a_sqlite3_that_does_not_stop_at_the_first_error_is_refused_before_any_write() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let real = codex_sqlite::resolve_sqlite3().expect("real sqlite3 required");
            let t = tempfile::Builder::new()
                .prefix("cr-")
                .tempdir_in("/tmp")
                .unwrap();
            let stub = r9_native_fixture(t.path(), "continue");
            fs::write(t.path().join("real-sqlite3"), real.to_str().unwrap()).unwrap();
            let script = "BEGIN IMMEDIATE;CREATE TABLE written(a);COMMIT;";
            let db = t.path().join("argv.sqlite");
            let mut unknown = true;
            let argv = codex_sqlite::run_repair_sqlite_bounded_tracking(
                &stub,
                &db,
                script,
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
                &mut unknown,
            );
            assert!(
                matches!(&argv, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains("does not stop at the first error")),
                "{argv:?}"
            );
            assert!(!unknown, "a pre-spawn refusal is a known non-commit");
            assert!(
                !db.exists(),
                "the launch runner wrote through a continuing sqlite3"
            );
            let db = t.path().join("stdin.sqlite");
            let stdin = codex_sqlite::run_sqlite3(&stub, &db, script);
            assert!(
                matches!(&stdin, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains("does not stop at the first error")),
                "{stdin:?}"
            );
            assert!(
                !db.exists(),
                "the stdin runner wrote through a continuing sqlite3"
            );
        }

        /// Only the named guard may appear on stderr for a run to count as a
        /// known rollback; a failed BEGIN or any other error line means a write
        /// may have landed.
        #[test]
        fn only_named_guard_failure_rejects_any_other_error_line() {
            hold_test_migration_lock!();
            let guard = "Runtime error near line 5: CHECK constraint failed: csq_paged_rows (19)";
            assert!(codex_sqlite::only_named_guard_failure(
                guard,
                "csq_paged_",
                false
            ));
            let nothing = "";
            assert!(!codex_sqlite::only_named_guard_failure(
                nothing,
                "csq_paged_",
                false
            ));
            let begin_failed = "Runtime error near line 2: database is locked (5)";
            assert!(!codex_sqlite::only_named_guard_failure(
                begin_failed,
                "csq_paged_",
                false
            ));
            let mixed = format!("{begin_failed}\n{guard}");
            assert!(!codex_sqlite::only_named_guard_failure(
                &mixed,
                "csq_paged_",
                false
            ));
            let write_error = format!("{guard}\nRuntime error near line 9: UNIQUE constraint failed: threads.rollout_path (19)");
            assert!(!codex_sqlite::only_named_guard_failure(
                &write_error,
                "csq_paged_",
                false
            ));
            let other_prefix = "Runtime error: CHECK constraint failed: csq_other (19)";
            assert!(!codex_sqlite::only_named_guard_failure(
                other_prefix,
                "csq_paged_",
                false
            ));
            let rolled_back = "Runtime error near line 5: CHECK constraint failed: csq_merge_fk_guard_must_be_zero (19)\nRuntime error near line 6: cannot commit - no transaction is active";
            assert!(codex_sqlite::only_named_guard_failure(
                rolled_back,
                "csq_merge_",
                true
            ));
            assert!(!codex_sqlite::only_named_guard_failure(
                rolled_back,
                "csq_merge_",
                false
            ));
        }

        /// The merge's pre-commit verdict needs the guard to be the only error.
        #[test]
        fn merge_pre_commit_verdict_requires_a_guard_only_stderr() {
            hold_test_migration_lock!();
            let fk = || ShareError::SqliteForeignKeyViolation {
                basename: "state_5.sqlite".to_owned(),
                path: PathBuf::from("/x"),
                detail: String::new(),
            };
            let guard = "exit Some(1): Runtime error near line 9: CHECK constraint failed: csq_merge_fk_guard_must_be_zero (19)".to_owned();
            assert!(codex_sqlite::merge_failure_is_pre_commit(
                &Some(guard.clone()),
                &fk()
            ));
            let begin_failed =
                format!("exit Some(1): Runtime error near line 2: database is locked (5)\n{guard}");
            assert!(!codex_sqlite::merge_failure_is_pre_commit(
                &Some(begin_failed),
                &fk()
            ));
            assert!(!codex_sqlite::merge_failure_is_pre_commit(&None, &fk()));
            let other = ShareError::SqliteUnsafeAttachPath {
                path: PathBuf::from("/x"),
            };
            assert!(!codex_sqlite::merge_failure_is_pre_commit(
                &Some(guard),
                &other
            ));
        }

        /// A non-guard statement failure on a shell that keeps going part-commits
        /// the batch (the hazard the bail probe prevents); the classification must
        /// stay UNKNOWN, never a known rollback.
        #[cfg(unix)]
        #[test]
        fn r9p_a_non_guard_write_error_is_classed_commit_unknown() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            f.candidate("same.jsonl");
            f.sql(
                &f.db,
                "CREATE UNIQUE INDEX u ON threads(rollout_path);INSERT INTO threads VALUES('a','/missing/x/same.jsonl');INSERT INTO threads VALUES('b','/missing/y/same.jsonl');",
            );
            let result =
                codex_sqlite::with_continue_past_errors(|| f.run(std::slice::from_ref(&f.db)));
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Partial{progress,..} if progress.in_flight_commit_unknown && progress.visited == 0),
                "a UNIQUE failure is not a known rollback: {result:?}"
            );
        }

        /// Lines that merely look like the refused shapes inside a literal or
        /// as part of a longer token are not refused.
        #[test]
        fn repair_runner_splitter_admits_lookalikes() {
            hold_test_migration_lock!();
            for script in [
                "SELECT 'go\n/\n#x';",
                "SELECT 1 AS gold;\nSELECT 2;",
                "CREATE TABLE trigger_log(a);\nCREATE TEMP TABLE t(a);",
            ] {
                assert!(
                    codex_sqlite::split_sql_statements(script).is_ok(),
                    "must admit {script:?}"
                );
            }
        }

        /// A guard condition that yields NULL must NOT satisfy the guard (a bare
        /// `CHECK (ok = 1)` passes NULL). Falsifying result without `IS 1`: the
        /// INSERT succeeds and the process exits 0.
        #[test]
        fn named_guard_refuses_a_null_condition() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let run = |condition: &str| {
                std::process::Command::new(&bin)
                    .env_clear()
                    .args([
                        "-init",
                        if cfg!(windows) { "NUL" } else { "/dev/null" },
                        "-batch",
                        "-bail",
                    ])
                    .arg(t.path().join(format!("g{}.sqlite", condition.len())))
                    .arg(codex_sqlite::named_guard_sql("csq_null_probe", condition))
                    .output()
                    .unwrap()
            };
            let null = run("NULL");
            assert!(!null.status.success(), "NULL satisfied the guard: {null:?}");
            assert!(
                String::from_utf8_lossy(&null.stderr)
                    .contains("CHECK constraint failed: csq_null_probe"),
                "{null:?}"
            );
            assert!(run("1 = 1").status.success());
            assert!(!run("1 = 0").status.success());
        }

        /// Every generated write carries the gate. Returns (write count,
        /// writes without it). Guard and gate INSERTs target `csq_*` / `fk_guard`
        /// temp tables and are not writes to the database under repair.
        fn write_gate_audit(scripts: &[String]) -> (usize, Vec<String>) {
            let mut writes = 0;
            let mut ungated = Vec::new();
            for script in scripts {
                for piece in codex_sqlite::split_sql_statements(script)
                    .expect("a generated script must split")
                {
                    let piece = piece.trim();
                    let upper = piece.to_ascii_uppercase();
                    if !["UPDATE ", "DELETE ", "REPLACE ", "INSERT "]
                        .iter()
                        .any(|verb| upper.starts_with(verb))
                    {
                        continue;
                    }
                    if upper.starts_with("INSERT") {
                        let target = piece
                            .split_whitespace()
                            .skip_while(|word| !word.eq_ignore_ascii_case("INTO"))
                            .nth(1)
                            .unwrap_or("");
                        if target.starts_with("csq_") || target == "fk_guard" {
                            continue;
                        }
                    }
                    writes += 1;
                    if !(piece.contains("EXISTS (SELECT 1 FROM temp.")
                        && piece.contains("WHERE ok IS 1)"))
                    {
                        ungated.push(piece.to_owned());
                    }
                }
            }
            (writes, ungated)
        }

        /// The real paged-resume generator gates every UPDATE. Platform
        /// independent: the audit reads the generated text, so it reds on Linux
        /// as well as Apple sqlite3. Falsifying result: removing `AND {gate}`
        /// from `paged_row_sql` leaves `ungated` non-empty.
        #[cfg(unix)]
        #[test]
        fn r9p_generated_paged_script_gates_every_write() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let f = PagedRepairFixture::new();
            for i in 1..=3 {
                f.candidate(&format!("w{i}.jsonl"));
                f.sql(
                    &f.db,
                    &format!("INSERT INTO threads VALUES('w{i}','/missing/w{i}.jsonl');"),
                );
            }
            f.sql(
                &f.db,
                "INSERT INTO threads VALUES('keep','/missing/none.jsonl');",
            );
            codex_sqlite::take_recorded_scripts();
            let result = f.run(std::slice::from_ref(&f.db));
            assert!(
                matches!(&result, codex_sqlite::PagedResumeOutcome::Complete(p) if p.rewritten == 3),
                "{result:?}"
            );
            let scripts = codex_sqlite::take_recorded_scripts();
            assert_one_statement_per_line(&scripts);
            let (writes, ungated) = write_gate_audit(&scripts);
            assert_eq!(writes, 3, "the audit must see the three UPDATEs");
            assert!(ungated.is_empty(), "ungated writes: {ungated:?}");
        }

        /// Same audit for the rollout-path repair script.
        #[cfg(unix)]
        #[test]
        fn r9_generated_rollout_script_gates_every_write() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("real sqlite3 required");
            let t = TempDir::new().unwrap();
            let base = t.path().canonicalize().unwrap();
            let root = base.join("persistent");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("rollout.jsonl"), b"valid").unwrap();
            let db = base.join("state_5.sqlite");
            let dead = base.join("term-123/sessions/rollout.jsonl");
            r9_fixture_sql(&bin, &db, &format!(
                "CREATE TABLE threads(id TEXT PRIMARY KEY, rollout_path TEXT); INSERT INTO threads VALUES('t1','{}');", dead.display()));
            codex_sqlite::take_recorded_scripts();
            assert_eq!(r9_repair_paths(&base, &db, &[root]).unwrap(), 1);
            let scripts = codex_sqlite::take_recorded_scripts();
            assert_one_statement_per_line(&scripts);
            let (writes, ungated) = write_gate_audit(&scripts);
            assert!(writes >= 1, "the audit must see the rollout UPDATE");
            assert!(ungated.is_empty(), "ungated writes: {ungated:?}");
        }

        /// Same audit for the destination-guarded merge script.
        #[test]
        fn generated_merge_script_gates_every_write() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t1",
                    name: "orig",
                    updated_at_ms: 1,
                }],
                1,
            );
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[ThreadRow {
                    id: "t2",
                    name: "new",
                    updated_at_ms: 2,
                }],
                1,
            );
            codex_sqlite::take_recorded_scripts();
            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();
            let scripts = codex_sqlite::take_recorded_scripts();
            assert!(
                scripts
                    .iter()
                    .any(|script| script.contains("csq_merge_write_gate")),
                "the second share must run the destination-guarded merge"
            );
            assert_one_statement_per_line(&scripts);
            let (writes, ungated) = write_gate_audit(&scripts);
            assert!(writes >= 1, "the audit must see merge writes");
            assert!(ungated.is_empty(), "ungated writes: {ungated:?}");
        }

        /// The production generators end every statement at the end of its line
        /// (a statement may span lines, two never share one), so each lands on
        /// its own stdin line: the piece count equals the number of lines that
        /// end in `;`.
        fn assert_one_statement_per_line(scripts: &[String]) {
            assert!(!scripts.is_empty(), "no script was recorded");
            for script in scripts {
                let pieces = split_ok(script);
                let terminated = script
                    .lines()
                    .filter(|l| l.trim_end().ends_with(';'))
                    .count();
                assert_eq!(
                    pieces.len(),
                    terminated,
                    "pieces != terminated lines in {script:?}"
                );
            }
        }

        /// The real paged batch builder: header, row-guard table, one guard per
        /// row, two gate statements, one UPDATE per rewritten row, COMMIT.
        #[test]
        fn repair_runner_argv_count_matches_generated_statements() {
            hold_test_migration_lock!();
            let header = "BEGIN IMMEDIATE;\n".to_owned();
            let mut batch = codex_sqlite::PagedBatch::new(&header);
            let rows: Vec<_> = (0..4)
                .map(|i| codex_sqlite::PagedResumeRow::for_test(i, i % 2 == 0))
                .collect();
            for row in &rows {
                let (guard, update) = codex_sqlite::paged_row_sql(row);
                batch.push(&guard, update.as_deref());
            }
            let script = batch.script();
            assert_eq!(split_ok(&script).len(), 1 + 1 + 4 + 2 + 2 + 1, "{script}");
            assert_one_statement_per_line(&[script]);
        }

        /// A runner that does not stop after a failed guard must still write
        /// nothing: the write predicate carries the gate. Falsifying result:
        /// the id changes to 'x' (gate removed, Apple sqlite3 3.54.0).
        #[cfg(unix)]
        #[test]
        fn gated_write_is_a_noop_after_a_failed_guard_in_one_argument() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("fixture requires real sqlite3");
            let t = TempDir::new().unwrap();
            let db = t.path().canonicalize().unwrap().join("gate.sqlite");
            r9_fixture_sql(
                &bin,
                &db,
                "CREATE TABLE threads(id TEXT PRIMARY KEY); INSERT INTO threads VALUES('t1');",
            );
            let script = format!(
                "BEGIN IMMEDIATE;\n{}UPDATE threads SET id = 'x' WHERE {};\nCOMMIT;\n",
                codex_sqlite::named_guard_sql("csq_gate_probe", "0 = 1"),
                codex_sqlite::gate_exists(&["csq_gate_probe"]),
            );
            let out = std::process::Command::new(&bin)
                .env_clear()
                .args([
                    "-init",
                    if cfg!(windows) { "NUL" } else { "/dev/null" },
                    "-batch",
                    "-bail",
                ])
                .arg(&db)
                .arg(&script)
                .output()
                .unwrap();
            assert!(!out.status.success(), "guard must fail: {out:?}");
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT id FROM threads;").trim(),
                "t1"
            );
        }

        /// Two statements on one line: Apple sqlite3 3.54.0 keeps executing the
        /// rest of the line after a failed CHECK, so the stdin runner puts every
        /// statement on its own line. Falsifying result: count 0 (DELETE ran).
        #[test]
        fn stdin_runner_failed_guard_with_two_statements_on_one_line_runs_nothing_after() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("fixture requires real sqlite3");
            let t = TempDir::new().unwrap();
            let db = t.path().canonicalize().unwrap().join("line.sqlite");
            r9_fixture_sql(
                &bin,
                &db,
                "CREATE TABLE threads(id TEXT PRIMARY KEY); INSERT INTO threads VALUES('t1');",
            );
            let result = codex_sqlite::run_sqlite3(
                &bin,
                &db,
                "BEGIN IMMEDIATE; CREATE TEMP TABLE g(ok INTEGER CONSTRAINT g CHECK (ok = 1)); \
                 INSERT INTO g SELECT (0); DELETE FROM threads; COMMIT;",
            );
            assert!(
                matches!(&result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains("CHECK constraint failed: g")),
                "guard must fail: {result:?}"
            );
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT count(*) FROM threads;").trim(),
                "1"
            );
        }

        #[test]
        fn runners_refuse_a_dot_command_before_spawning() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("fixture requires real sqlite3");
            let t = TempDir::new().unwrap();
            let base = t.path().canonicalize().unwrap();
            let db = base.join("dot.sqlite");
            let marker = base.join("shell-ran");
            let script = format!("SELECT 1;\n.shell touch {}\n", marker.display());
            let stdin_result = codex_sqlite::run_sqlite3(&bin, &db, &script);
            assert!(
                matches!(&stdin_result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains("dot-command")),
                "{stdin_result:?}"
            );
            let argv_result = codex_sqlite::run_repair_sqlite_bounded(
                &bin,
                &db,
                &script,
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            );
            assert!(
                matches!(&argv_result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains("dot-command")),
                "{argv_result:?}"
            );
            assert!(!marker.exists(), "no dot-command may have run");
            assert!(
                !db.exists(),
                "refused before spawn: sqlite3 never opened the db"
            );
        }

        /// A failed named guard MUST stop every later statement of the same
        /// script. On macOS sqlite3 3.54.0 `-bail` does not stop inside one
        /// multi-statement line, so the runner sends one stdin line per
        /// statement. Falsifying result: the row count is 0 (DELETE ran).
        #[test]
        fn repair_runner_failed_guard_runs_no_later_statement() {
            hold_test_migration_lock!();
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("fixture requires real sqlite3");
            let t = TempDir::new().unwrap();
            let db = t.path().canonicalize().unwrap().join("g.sqlite");
            r9_fixture_sql(
                &bin,
                &db,
                "CREATE TABLE threads(id TEXT PRIMARY KEY); INSERT INTO threads VALUES('t1');",
            );
            let result = codex_sqlite::run_repair_sqlite_bounded(
                &bin,
                &db,
                "BEGIN IMMEDIATE;\nCREATE TEMP TABLE g(ok INTEGER CONSTRAINT g CHECK (ok = 1));\n\
                 INSERT INTO g SELECT (0);\nDELETE FROM threads;\nCOMMIT;\n",
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            );
            assert!(
                matches!(&result, Err(ShareError::SqliteCommandFailed { detail, .. }) if detail.contains("CHECK constraint failed: g")),
                "guard must fail: {result:?}"
            );
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT count(*) FROM threads;").trim(),
                "1"
            );
        }

        fn r9_schema_fixture(object: &str, race: bool) {
            let _env = crate::platform::test_env::lock();
            let bin = codex_sqlite::resolve_sqlite3().expect("R9 fixture requires real sqlite3");
            let t = TempDir::new().unwrap();
            let base = t.path().canonicalize().unwrap();
            let root = base.join("codex-sessions");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("rollout.jsonl"), b"private transcript").unwrap();
            let dead = base.join("term-2776/sessions/rollout.jsonl");
            let db = base.join("state_5.sqlite");
            r9_fixture_sql(
                &bin,
                &db,
                &format!(
                    "CREATE TABLE threads(id TEXT PRIMARY KEY, rollout_path TEXT); \
                 INSERT INTO threads VALUES('t1','{}');",
                    dead.display()
                ),
            );
            let before = fs::read(&db).unwrap();
            let sql = match object {
                "view" => "CREATE VIEW planted AS SELECT * FROM threads;",
                "spoofed" => "CREATE TRIGGER threads_recency_at_after_insert AFTER UPDATE ON threads BEGIN DELETE FROM threads; END;",
                _ => "CREATE TRIGGER planted AFTER UPDATE ON threads BEGIN DELETE FROM threads; END;",
            };
            let before = if race {
                let bin = bin.clone();
                let db = db.clone();
                let sql = sql.to_owned();
                codex_sqlite::set_test_repair_before_write(move || {
                    r9_fixture_sql(&bin, &db, &sql);
                });
                before
            } else {
                r9_fixture_sql(&bin, &db, sql);
                fs::read(&db).unwrap()
            };
            let result = r9_repair_paths(&base, &db, &[root]);
            if race {
                assert!(
                    matches!(&result, Err(ShareError::SqliteCommandFailed { detail, .. })
                    if detail.contains("csq_rollout_schema_unchanged")),
                    "race guard: {result:?}"
                );
            } else {
                assert!(
                    matches!(&result, Err(ShareError::SqliteUntrustedSchemaObject { .. })),
                    "readonly schema refusal: {result:?}"
                );
                assert_eq!(
                    fs::read(&db).unwrap(),
                    before,
                    "refusal writes no database bytes"
                );
            }
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT count(*) FROM threads;").trim(),
                "1"
            );
            assert_eq!(
                r9_fixture_sql(&bin, &db, "SELECT rollout_path FROM threads WHERE id='t1';").trim(),
                dead.to_str().unwrap()
            );
        }

        #[test]
        fn r9_schema_refuses_trigger_before_write() {
            hold_test_migration_lock!();
            r9_schema_fixture("trigger", false);
        }
        #[test]
        fn r9_schema_refuses_view_before_write() {
            hold_test_migration_lock!();
            r9_schema_fixture("view", false);
        }
        #[test]
        fn r9_schema_refuses_spoofed_upstream_trigger() {
            hold_test_migration_lock!();
            r9_schema_fixture("spoofed", false);
        }
        #[test]
        fn r9_schema_transaction_refuses_new_trigger() {
            hold_test_migration_lock!();
            r9_schema_fixture("trigger", true);
        }
        #[test]
        fn r9_schema_transaction_refuses_new_view() {
            hold_test_migration_lock!();
            r9_schema_fixture("view", true);
        }

        /// R9: the launch-time repair rewrites a reaped handle-dir path to the
        /// SLOT's own persistent sessions root (a slot not yet shared — its
        /// `codex-sessions` is a real directory, not the shared root), leaves a
        /// row whose recorded path still exists untouched, and is idempotent.
        #[test]
        fn slot_repair_rewrites_reaped_handle_path_to_slot_sessions_root() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home = slot_home(base, Surface::Codex, slot_num(12)).unwrap();
            let slot_sessions = home.join("codex-sessions");
            let shared = base.join("shared-state/codex/codex-sessions");
            let file = slot_sessions.join("2026/10/06/rollout-01a10f3a.jsonl");
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(&file, b"TRANSCRIPT").unwrap();

            let dead = base.join("term-2776/sessions/2026/10/06/rollout-01a10f3a.jsonl");
            let db = home.join("state_5.sqlite");
            create_state_db_with_rollout(&bin, &db, "dead", &dead.display().to_string());
            // A second row whose recorded path still resolves must not move.
            let live = base.join("term-9/sessions/x.jsonl");
            fs::create_dir_all(live.parent().unwrap()).unwrap();
            fs::write(&live, b"LIVE").unwrap();
            sh(
                &bin,
                &db,
                &format!(
                    "INSERT INTO threads (id, title, name, updated_at, updated_at_ms, cwd, \
                     model_provider, rollout_path) VALUES ('live', 't', 'n', 'ts', 1, '/w', \
                     'a', '{}');",
                    live.display()
                ),
            );

            let roots = vec![slot_sessions.canonicalize().unwrap(), shared];
            let n = r9_repair_paths(base, &db, &roots).unwrap();
            assert_eq!(n, 1, "exactly the dead row is repaired");
            assert_eq!(
                thread_field(&bin, &db, "dead", "rollout_path"),
                slot_sessions
                    .canonicalize()
                    .unwrap()
                    .join("2026/10/06/rollout-01a10f3a.jsonl")
                    .display()
                    .to_string(),
            );
            assert_eq!(
                thread_field(&bin, &db, "live", "rollout_path"),
                live.display().to_string(),
                "a row whose recorded path still exists must not be rewritten"
            );
            let again = r9_repair_paths(base, &db, &roots).unwrap();
            assert_eq!(again, 0, "second pass is a no-op");
        }

        /// A row whose file is missing EVERYWHERE (neither the recorded
        /// `term-<pid>` path nor its shared-root equivalent exists) must be
        /// left exactly as recorded — rewriting it would invent a resume
        /// target with no transcript behind it.
        #[test]
        fn rollout_path_repair_leaves_a_row_alone_when_the_file_is_missing_everywhere() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home5 = slot_home(base, Surface::Codex, slot_num(5)).unwrap();

            let dead = base.join("term-55556/sessions/2026/09/29/rollout-def.jsonl");
            // Deliberately never created anywhere — neither `dead` nor its
            // shared-root equivalent exists on disk.

            create_state_db_with_rollout(
                &bin,
                &home5.join("state_5.sqlite"),
                "t2",
                &dead.display().to_string(),
            );

            codex_sqlite::share_codex_sqlite_locked(base, false, true).unwrap();

            let shared_path = shared_root(base, Surface::Codex).join("state_5.sqlite");
            let unchanged = thread_field(&bin, &shared_path, "t2", "rollout_path");
            assert_eq!(
                unchanged,
                dead.display().to_string(),
                "a row with no surviving file anywhere must never be rewritten"
            );
        }

        /// A row whose recorded path STILL resolves has nothing to repair —
        /// it must be left byte-for-byte as recorded, even though a
        /// shared-root file of the same name also happens to exist.
        #[test]
        fn rollout_path_repair_leaves_a_still_resolving_path_alone() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home5 = slot_home(base, Surface::Codex, slot_num(5)).unwrap();

            let still_alive = base.join("term-55557/sessions/2026/09/29/rollout-ghi.jsonl");
            fs::create_dir_all(still_alive.parent().unwrap()).unwrap();
            fs::write(&still_alive, b"TRANSCRIPT").unwrap();
            let shared_equivalent =
                base.join("shared-state/codex/codex-sessions/2026/09/29/rollout-ghi.jsonl");
            fs::create_dir_all(shared_equivalent.parent().unwrap()).unwrap();
            fs::write(&shared_equivalent, b"TRANSCRIPT").unwrap();

            create_state_db_with_rollout(
                &bin,
                &home5.join("state_5.sqlite"),
                "t3",
                &still_alive.display().to_string(),
            );

            codex_sqlite::share_codex_sqlite_locked(base, false, true).unwrap();

            let shared_path = shared_root(base, Surface::Codex).join("state_5.sqlite");
            let unchanged = thread_field(&bin, &shared_path, "t3", "rollout_path");
            assert_eq!(
                unchanged,
                still_alive.display().to_string(),
                "a path that still resolves has nothing to repair"
            );
        }

        /// M1: a `rest` containing `..` must never be rewritten, even when
        /// the path it traverses to actually exists — rewriting it would
        /// point `resume` at a file OUTSIDE
        /// `shared-state/codex/codex-sessions/` that this call never
        /// verified belongs to this thread at all.
        ///
        /// Falsifying result named up front (and VERIFIED by temporarily
        /// commenting out the `rest_is_safe` check and re-running only this
        /// test, 2026-09-29): without the check, `rest = "../../x"` passes
        /// every other filter (`old_exists` is false because
        /// `term-99999/sessions/` was never created, so the OS cannot even
        /// resolve the `..` components to stat it; `new_exists` is true
        /// because this test plants a file at the traversed-to location),
        /// so the row gets rewritten to
        /// `<base>/shared-state/x` — two levels OUTSIDE the
        /// `codex-sessions` subtree.
        #[test]
        fn rollout_path_repair_refuses_a_traversal_rest_even_when_the_target_exists() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home5 = slot_home(base, Surface::Codex, slot_num(5)).unwrap();

            // Never created on disk — `term-99999/sessions/` does not exist,
            // so the OS cannot resolve the `..` components to stat it, and
            // `old_exists` is false purely from that (not from any check
            // this fix adds).
            let traversal_old = base.join("term-99999/sessions/../../x");
            // `codex-sessions/` must exist as a REAL directory for the OS to
            // resolve `..` through it at all — otherwise `new_exists` below
            // is false for the wrong reason (ENOENT on an intermediate
            // component) and this test would pass even with the check
            // removed, proving nothing.
            fs::create_dir_all(shared_root(base, Surface::Codex).join("codex-sessions")).unwrap();
            // The traversed-to target DOES exist: two levels above
            // `codex-sessions/`, i.e. `<base>/shared-state/x`.
            let traversal_target = base.join("shared-state/x");
            fs::write(&traversal_target, b"OUTSIDE THE SHARED SESSIONS TREE").unwrap();

            create_state_db_with_rollout(
                &bin,
                &home5.join("state_5.sqlite"),
                "t4",
                &traversal_old.display().to_string(),
            );

            codex_sqlite::share_codex_sqlite_locked(base, false, true).unwrap();

            let shared_path = shared_root(base, Surface::Codex).join("state_5.sqlite");
            let unchanged = thread_field(&bin, &shared_path, "t4", "rollout_path");
            assert_eq!(
                unchanged,
                traversal_old.display().to_string(),
                "a `..`-containing rest must never be rewritten, regardless of what it resolves to"
            );
        }

        /// A `rest` with a trailing `/` survives the component check (which
        /// drops it) and names a DIRECTORY in the shared root. A rollout path
        /// must name a transcript file, so the row is left alone. Falsifying
        /// result: the row rewritten to `.../codex-sessions/2026/09/`, which is
        /// what an existence-only check produced.
        #[test]
        fn rollout_path_repair_never_points_a_thread_at_a_directory() {
            hold_test_migration_lock!();
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home5 = slot_home(base, Surface::Codex, slot_num(5)).unwrap();
            fs::create_dir_all(shared_root(base, Surface::Codex).join("codex-sessions/2026/09"))
                .unwrap();
            let dir_old = format!("{}/", base.join("term-99998/sessions/2026/09").display());
            create_state_db_with_rollout(&bin, &home5.join("state_5.sqlite"), "t5", &dir_old);

            codex_sqlite::share_codex_sqlite_locked(base, false, true).unwrap();

            let shared_path = shared_root(base, Surface::Codex).join("state_5.sqlite");
            assert_eq!(
                thread_field(&bin, &shared_path, "t5", "rollout_path"),
                dir_old
            );
        }

        /// Real codex databases carry codex's own five triggers; the merge must
        /// accept them. Falsifying result: `SqliteUntrustedSchemaObject` naming
        /// `threads_created_at_ms_after_insert`, which is what every real host
        /// got from v2.20.0.
        #[test]
        fn real_codex_databases_with_their_own_triggers_merge() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            let row = |id, name| ThreadRow {
                id,
                name,
                updated_at_ms: 5,
            };
            create_codex_state_db(
                &bin,
                &home11.join("state_5.sqlite"),
                &[row("a", "from-11")],
                58,
            );
            create_codex_state_db(
                &bin,
                &home14.join("state_5.sqlite"),
                &[row("b", "from-14")],
                58,
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let shared = shared_root(base, Surface::Codex).join("state_5.sqlite");
            assert_eq!(thread_name(&bin, &shared, "a"), "from-11");
            assert_eq!(thread_name(&bin, &shared, "b"), "from-14");
            for home in [&home11, &home14] {
                assert!(home
                    .join("state_5.sqlite")
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink());
            }
        }

        /// codex's databases are WAL-mode, and SQLite removes `-wal`/`-shm`
        /// when the last connection closes — the state every slot is in when
        /// no codex session runs, which is when a share is supposed to run.
        /// Falsifying result: `SqliteCommandFailed` "unable to open database
        /// file", which a plain `-readonly` open returns without `-shm`.
        #[test]
        fn closed_wal_mode_databases_with_no_sidecars_merge() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            let row = |id, name| ThreadRow {
                id,
                name,
                updated_at_ms: 5,
            };
            for (home, r) in [
                (&home11, row("a", "from-11")),
                (&home14, row("b", "from-14")),
            ] {
                let db = home.join("state_5.sqlite");
                create_codex_state_db(&bin, &db, &[r], 58);
                sh(&bin, &db, "PRAGMA journal_mode=WAL;");
                for suffix in ["-wal", "-shm"] {
                    let mut side = db.as_os_str().to_os_string();
                    side.push(suffix);
                    assert!(
                        !PathBuf::from(side).exists(),
                        "fixture must reproduce a cleanly closed WAL database"
                    );
                }
            }

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let shared = shared_root(base, Surface::Codex).join("state_5.sqlite");
            assert_eq!(thread_name(&bin, &shared, "a"), "from-11");
            assert_eq!(thread_name(&bin, &shared, "b"), "from-14");
        }

        /// Two databases that applied the SAME migrations at different times
        /// hold the same schema. Falsifying result: `SqliteMigrationsMismatch`,
        /// which comparing `installed_on` / `execution_time` produced for every
        /// pair of real databases (slots 12 and 13 on the maintainer host, both
        /// at 58 identical migrations).
        #[test]
        fn identical_migrations_applied_at_different_times_merge() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            let row = |id, name| ThreadRow {
                id,
                name,
                updated_at_ms: 5,
            };
            create_codex_state_db(&bin, &home11.join("state_5.sqlite"), &[row("a", "x")], 58);
            create_codex_state_db(&bin, &home14.join("state_5.sqlite"), &[row("b", "y")], 58);
            sh(
                &bin,
                &home14.join("state_5.sqlite"),
                "UPDATE _sqlx_migrations SET installed_on = '2026-09-29 10:00:00', \
                   execution_time = execution_time + 999;",
            );

            codex_sqlite::share_codex_sqlite(base, false, true).unwrap();

            let shared = shared_root(base, Surface::Codex).join("state_5.sqlite");
            assert_eq!(thread_name(&bin, &shared, "a"), "x");
            assert_eq!(thread_name(&bin, &shared, "b"), "y");
        }

        /// The allowlist is name AND exact body: a trigger that keeps a codex
        /// name but changes what it does is refused before any mutation.
        #[test]
        fn a_codex_trigger_name_with_a_different_body_is_refused() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            let row = |id, name| ThreadRow {
                id,
                name,
                updated_at_ms: 5,
            };
            create_codex_state_db(&bin, &home11.join("state_5.sqlite"), &[row("a", "x")], 58);
            create_codex_state_db(&bin, &home14.join("state_5.sqlite"), &[row("b", "y")], 58);
            sh(
                &bin,
                &home11.join("state_5.sqlite"),
                "DROP TRIGGER threads_recency_at_after_insert; \
                 CREATE TRIGGER threads_recency_at_after_insert AFTER INSERT ON threads \
                 BEGIN DELETE FROM threads; END;",
            );

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            assert!(
                matches!(err, ShareError::SqliteUntrustedSchemaObject { .. }),
                "{err:?}"
            );
            assert!(!home11
                .join("state_5.sqlite")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
        }

        /// Slots at different codex schema versions refuse, and the message
        /// names both counts and the fix (open codex on the stale slot) — the
        /// maintainer host had two slots at 54 migrations and two at 58.
        #[test]
        fn a_stale_codex_schema_names_both_counts_and_the_fix() {
            let Some(bin) = require_sqlite3() else {
                return;
            };
            let t = TempDir::new().unwrap();
            let base = t.path();
            let home11 = slot_home(base, Surface::Codex, slot_num(11)).unwrap();
            let home14 = slot_home(base, Surface::Codex, slot_num(14)).unwrap();
            let row = |id, name| ThreadRow {
                id,
                name,
                updated_at_ms: 5,
            };
            create_codex_state_db(&bin, &home11.join("state_5.sqlite"), &[row("a", "x")], 54);
            create_codex_state_db(&bin, &home14.join("state_5.sqlite"), &[row("b", "y")], 58);

            let err = codex_sqlite::share_codex_sqlite(base, false, true).unwrap_err();
            let msg = err.to_string();
            assert!(
                matches!(err, ShareError::SqliteMigrationsMismatch { .. }),
                "{err:?}"
            );
            // Both slots are named so the operator can tell which one is stale.
            // (Paths go through `redact_path`, which shortens `$HOME` to `~`;
            // this temp base is outside `$HOME`, so it prints in full here.)
            for needle in ["54", "58", "csq run", "config-11", "config-14"] {
                assert!(msg.contains(needle), "missing {needle:?} in: {msg}");
            }
        }
    }
}
